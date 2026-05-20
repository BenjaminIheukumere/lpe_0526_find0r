#!/usr/bin/env python3
import argparse
import ipaddress
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from datetime import datetime, timezone
from getpass import getpass
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple, Union

try:
    import paramiko
except Exception:
    paramiko = None


SCRIPT_VERSION = "1.0.0"
MIN_WORKER_THREADS = 32
DEFAULT_REPORT_PREFIX = "lpe_scan_report"
REPORT_EXTENSION = ".txt"
TODO_STATUS = "LIKELY_VULNERABLE"
DEFAULT_PASSWORD_ENV = "LPE_SCAN_PASSWORD"
DEFAULT_KEY_PASSPHRASE_ENV = "LPE_SCAN_KEY_PASSPHRASE"
MAX_LIVE_HOST_ROWS = 12
Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"


def configure_color(enabled: bool) -> None:
    if enabled:
        return
    for name in ("RESET", "BOLD", "RED", "GREEN", "YELLOW", "BLUE", "CYAN"):
        setattr(C, name, "")


def clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")


# Shared result structures keep worker output consistent and easy to report.
@dataclass
class Finding:
    vuln: str
    status: str
    confidence: str
    reason: str


@dataclass
class HostResult:
    host: str
    reachable: bool
    uname: str = ""
    packagekit_version: str = "not_found"
    os_release: str = "unknown"
    kernel_package: str = "not_found"
    findings: List[Finding] = field(default_factory=list)


@dataclass
class ScanOutcome:
    results: List[HostResult]
    interrupted: bool = False


@dataclass
class TargetSpec:
    label: str
    hosts: List[str]


@dataclass
class ScanConfig:
    workers: int
    probe_timeout: float
    ssh_timeout: float
    command_timeout: float
    strict_host_key: bool
    live: bool
    key_file: Optional[Path] = None
    key_passphrase: Optional[str] = None


def parse_version_tuple(v: str) -> Tuple[int, ...]:
    nums = re.findall(r"\d+", v or "")
    return tuple(int(x) for x in nums[:6]) if nums else (0,)


def version_in_range(v: str, low: str, high: str) -> bool:
    return parse_version_tuple(low) <= parse_version_tuple(v) <= parse_version_tuple(high)


def version_at_least(v: str, minimum: str) -> bool:
    return parse_version_tuple(v) >= parse_version_tuple(minimum)


def positive_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return parsed


def worker_count(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed < MIN_WORKER_THREADS:
        raise argparse.ArgumentTypeError(f"must be at least {MIN_WORKER_THREADS}")
    return parsed


def parse_network(value: str) -> Network:
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise SystemExit(f"Invalid CIDR target '{value}': {exc}") from exc


def parse_ip_range(value: str) -> TargetSpec:
    parts = [part.strip() for part in value.split("-", 1)]
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise SystemExit(f"Invalid IP range '{value}'. Expected format: 10.215.0.0-10.215.5.254")

    try:
        start_ip = ipaddress.ip_address(parts[0])
        end_ip = ipaddress.ip_address(parts[1])
    except ValueError as exc:
        raise SystemExit(f"Invalid IP range '{value}': {exc}") from exc

    if start_ip.version != end_ip.version:
        raise SystemExit(f"Invalid IP range '{value}': start and end IP versions differ")
    if int(start_ip) > int(end_ip):
        raise SystemExit(f"Invalid IP range '{value}': start IP is greater than end IP")

    hosts = [str(ipaddress.ip_address(ip_int)) for ip_int in range(int(start_ip), int(end_ip) + 1)]
    return TargetSpec(label=f"{start_ip}-{end_ip}", hosts=hosts)


def parse_target_spec(value: str) -> TargetSpec:
    if "-" in value:
        return parse_ip_range(value)

    network = parse_network(value)
    return TargetSpec(label=str(network), hosts=expand_network(network))


def os_release_parts(value: str) -> Tuple[str, str, str]:
    parts = (value or "unknown:unknown:").split(":", 2)
    while len(parts) < 3:
        parts.append("")
    return parts[0].strip().lower(), parts[1].strip().strip('"'), parts[2].strip().lower()


def print_banner() -> None:
    art = r'''
 /$$       /$$$$$$$  /$$$$$$$$        /$$$$$$  /$$$$$$$   /$$$$$$   /$$$$$$       
| $$      | $$__  $$| $$_____/       /$$$_  $$| $$____/  /$$__  $$ /$$__  $$      
| $$      | $$  \ $$| $$            | $$$$\ $$| $$      |__/  \ $$| $$  \__/      
| $$      | $$$$$$$/| $$$$$         | $$ $$ $$| $$$$$$$   /$$$$$$/| $$$$$$$       
| $$      | $$____/ | $$__/         | $$\ $$$$|_____  $$ /$$____/ | $$__  $$      
| $$      | $$      | $$            | $$ \ $$$ /$$  \ $$| $$      | $$  \ $$      
| $$$$$$$$| $$      | $$$$$$$$      |  $$$$$$/|  $$$$$$/| $$$$$$$$|  $$$$$$/      
|________/|__/      |________/       \______/  \______/ |________/ \______/       
                                                                                                                                                                  
                                                                                  
       /$$$$$$$$ /$$                 /$$  /$$$$$$                                 
      | $$_____/|__/                | $$ /$$$_  $$                                
      | $$       /$$ /$$$$$$$   /$$$$$$$| $$$$\ $$  /$$$$$$                       
      | $$$$$   | $$| $$__  $$ /$$__  $$| $$ $$ $$ /$$__  $$                      
      | $$__/   | $$| $$  \ $$| $$  | $$| $$\ $$$$| $$  \__/                      
      | $$      | $$| $$  | $$| $$  | $$| $$ \ $$$| $$                            
      | $$      | $$| $$  | $$|  $$$$$$$|  $$$$$$/| $$                            
      |__/      |__/|__/  |__/ \_______/ \______/ |__/                            
                                                                                  
  Authenticated scans for DirtyFrag | Fragnesia | DirtyDecrypt | PinTheft | SSH Keysign Pwn | CopyFail | Pack2TheRoot Linux LPE vulns
  by Benjamin Iheukumere | SafeLink IT 
                                                                                  
'''
    print(f"{C.GREEN}{art}{C.RESET}")
    print()


def expand_network(network: Network) -> List[str]:
    return [str(ip) for ip in network.hosts()]


def ping_command(host: str, timeout: float) -> List[str]:
    if platform.system().lower().startswith("win"):
        return ["ping", "-n", "1", "-w", str(int(timeout * 1000)), host]
    return ["ping", "-c", "1", "-W", str(max(1, int(timeout))), host]


# Use a quick network probe before spending time on SSH connection setup.
def ping_host(host: str, timeout: float) -> bool:
    try:
        p = subprocess.run(
            ping_command(host, timeout),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 1,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return p.returncode == 0


def tcp_open(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def kernel_config_cmd(option: str) -> str:
    # Search the common kernel config locations without letting missing files hide real matches.
    return (
        "kr=$(uname -r); found=''; "
        "for f in /proc/config.gz /boot/config-$kr /lib/modules/$kr/build/.config /lib/modules/$kr/source/.config; do "
        "if [ -r \"$f\" ]; then "
        f"case \"$f\" in *.gz) line=$(zgrep -h '^{option}=' \"$f\" 2>/dev/null | tail -n1);; "
        f"*) line=$(grep -h '^{option}=' \"$f\" 2>/dev/null | tail -n1);; esac; "
        "if [ -n \"$line\" ]; then found=\"$line\"; fi; "
        "fi; "
        "done; "
        "printf '%s\\n' \"${found:-unknown}\""
    )


# Collect only the remote facts needed for the local privilege escalation checks.
def ssh_collect(host: str, user: str, password: Optional[str], config: ScanConfig) -> Dict[str, str]:
    client = paramiko.SSHClient()
    if config.strict_host_key:
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
    else:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    connect_kwargs = {
        "hostname": host,
        "username": user,
        "timeout": config.ssh_timeout,
        "auth_timeout": config.ssh_timeout,
        "banner_timeout": config.ssh_timeout,
        "look_for_keys": False,
        "allow_agent": False,
    }
    if config.key_file:
        connect_kwargs["key_filename"] = str(config.key_file)
        if config.key_passphrase:
            connect_kwargs["passphrase"] = config.key_passphrase
    else:
        connect_kwargs["password"] = password

    client.connect(**connect_kwargs)

    cmds = {
        "uname": "uname -r",
        "os_release": ". /etc/os-release 2>/dev/null; echo ${ID:-unknown}:${VERSION_ID:-unknown}:${ID_LIKE:-}",
        "os_codename": ". /etc/os-release 2>/dev/null; echo ${VERSION_CODENAME:-unknown}",
        "mod_rxrpc": "test -d /sys/module/rxrpc && echo 1 || echo 0",
        "rxrpc_available": "modinfo rxrpc >/dev/null 2>&1 && echo 1 || echo 0",
        "config_rxgk": kernel_config_cmd("CONFIG_RXGK"),
        "mod_rds": "test -d /sys/module/rds && echo 1 || echo 0",
        "mod_rds_tcp": "test -d /sys/module/rds_tcp && echo 1 || echo 0",
        "rds_available": "modinfo rds >/dev/null 2>&1 && echo 1 || echo 0",
        "rds_tcp_available": "modinfo rds_tcp >/dev/null 2>&1 && echo 1 || echo 0",
        "config_rds": kernel_config_cmd("CONFIG_RDS"),
        "config_rds_tcp": kernel_config_cmd("CONFIG_RDS_TCP"),
        "config_io_uring": kernel_config_cmd("CONFIG_IO_URING"),
        "mod_esp4": "test -d /sys/module/esp4 && echo 1 || echo 0",
        "mod_esp6": "test -d /sys/module/esp6 && echo 1 || echo 0",
        "module_mitigation": "grep -RhsE '^(install|blacklist)[[:space:]]+(esp4|esp6|rxrpc|rds|rds_tcp)([[:space:]]|$)' /etc/modprobe.d /run/modprobe.d /usr/lib/modprobe.d 2>/dev/null | tr '\\n' ';' | head -c 500 || true",
        "rxgk_ioc": "dmesg 2>/dev/null | grep -Ei 'rxgk_decrypt_skb|rxgk_verify_response|__skb_to_sgvec|DirtyDecrypt|DirtyCBC' | tail -n3 | tr '\\n' ';' | head -c 500 || true",
        "io_uring_disabled": "cat /proc/sys/kernel/io_uring_disabled 2>/dev/null || echo unknown",
        "readable_suid_targets": "for p in /usr/bin/su /bin/su /usr/bin/passwd /bin/passwd /usr/bin/sudo /usr/bin/mount /usr/bin/umount /usr/bin/chsh /usr/bin/chfn /usr/bin/newgrp /usr/bin/gpasswd /usr/lib/openssh/ssh-keysign /usr/libexec/openssh/ssh-keysign /usr/lib/ssh/ssh-keysign /mnt/suid_helper; do if [ -r \"$p\" ] && [ -u \"$p\" ]; then printf '%s;' \"$p\"; fi; done | head -c 500 || true",
        "ptrace_scope": "cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo unknown",
        "ssh_keysign": "for p in /usr/lib/openssh/ssh-keysign /usr/libexec/openssh/ssh-keysign /usr/lib/ssh/ssh-keysign; do if [ -e \"$p\" ]; then stat -c '%n:%U:%G:%a:%A' \"$p\"; fi; done | tr '\\n' ';' | head -c 500 || echo not_found",
        "chage": "if command -v chage >/dev/null 2>&1; then p=$(command -v chage); stat -c '%n:%U:%G:%a:%A' \"$p\"; else echo not_found; fi",
        "kernel_package": "kr=$(uname -r); (dpkg-query -W -f='${Version}' linux-image-$kr 2>/dev/null || rpm -q kernel-core-$kr 2>/dev/null || rpm -q kernel-$kr 2>/dev/null || echo not_found) | head -n1",
        "packagekit": "(dpkg-query -W -f='${Version}' packagekit 2>/dev/null || rpm -q --qf '%{VERSION}-%{RELEASE}' PackageKit 2>/dev/null || rpm -q --qf '%{VERSION}-%{RELEASE}' packagekit 2>/dev/null || echo not_found) | head -n1",
    }

    out: Dict[str, str] = {}
    try:
        for key, cmd in cmds.items():
            _, stdout, _ = client.exec_command(cmd, timeout=config.command_timeout)
            stdout.channel.settimeout(config.command_timeout)
            out[key] = stdout.read().decode(errors="replace").strip()
    finally:
        client.close()
    return out


def module_blocked(module: str, mitigation_text: str) -> bool:
    text = mitigation_text or ""
    blacklist_pattern = rf"(^|;)\s*blacklist\s+{re.escape(module)}(\s|;|$)"
    install_pattern = rf"(^|;)\s*install\s+{re.escape(module)}\s+(/usr)?/bin/(false|true)(\s|;|$)"
    return (
        re.search(blacklist_pattern, text, re.IGNORECASE) is not None
        or re.search(install_pattern, text, re.IGNORECASE) is not None
    )


def mitigation_summary(mitigation_text: str) -> str:
    blocked = [module for module in ("esp4", "esp6", "rxrpc") if module_blocked(module, mitigation_text)]
    if len(blocked) == 3:
        return "esp4/esp6/rxrpc blocked"
    if blocked:
        return f"partial block: {','.join(blocked)}"
    return "none detected"


def almalinux_fragnesia_patched(kernel: str, os_release: str) -> bool:
    distro_id, version_id, id_like = os_release_parts(os_release)
    if distro_id != "almalinux" and "almalinux" not in id_like:
        return False

    baselines = {
        "8": "4.18.0-553.124.3",
        "9": "5.14.0-611.54.5",
        "10": "6.12.0-124.56.3",
    }
    major = version_id.split(".", 1)[0]
    minimum = baselines.get(major)
    return bool(minimum and version_at_least(kernel, minimum))


def ptrace_scope_mitigated(value: str) -> bool:
    try:
        return int((value or "").strip()) >= 2
    except ValueError:
        return False


def helper_surface_detected(value: str) -> bool:
    normalized = (value or "").strip().lower()
    return bool(normalized and normalized != "not_found")


def kernel_config_enabled(value: str) -> bool:
    normalized = (value or "").strip().lower()
    return normalized.endswith("=y") or normalized.endswith("=m")


def io_uring_enabled(config_value: str, disabled_value: str) -> bool:
    normalized = (disabled_value or "").strip().lower()
    if normalized in {"1", "2", "3", "y", "yes", "true"}:
        return False
    if normalized == "0":
        return True
    return kernel_config_enabled(config_value)


def pin_theft_kernel_patched(kernel: str) -> bool:
    parts = parse_version_tuple(kernel)
    if len(parts) < 2:
        return False

    major, minor = parts[0], parts[1]
    patch = parts[2] if len(parts) > 2 else 0
    if major > 7 or (major == 7 and minor >= 1):
        return True
    if major == 7 and minor == 0 and patch >= 7:
        return True
    if major == 6 and minor == 12 and patch >= 88:
        return True
    if major == 6 and minor == 18 and patch >= 30:
        return True
    if major == 6 and minor == 6 and patch >= 140:
        return True
    return False


def pin_theft_kernel_in_window(kernel: str) -> bool:
    # PinTheft depends on the RDS zerocopy path, which is present in modern kernels.
    return version_in_range(kernel, "4.19", "7.0.99") and not pin_theft_kernel_patched(kernel)


def dirtydecrypt_distro_not_affected_or_patched(kernel_package: str, os_release: str, os_codename: str) -> bool:
    distro_id, version_id, id_like = os_release_parts(os_release)
    if distro_id != "debian" and "debian" not in id_like:
        return False

    codename = (os_codename or "").strip().lower()
    major = version_id.split(".", 1)[0]

    # Debian stable trackers mark bullseye/bookworm/trixie as not affected for CVE-2026-31635.
    if codename in {"bullseye", "bookworm", "trixie"} or major in {"11", "12", "13"}:
        return True

    fixed_baselines = {
        "forky": "7.0.7-1",
        "sid": "7.0.7-1",
    }
    minimum = fixed_baselines.get(codename)
    return bool(minimum and version_at_least(kernel_package, minimum))


def dirtydecrypt_kernel_affected(kernel: str) -> bool:
    parts = parse_version_tuple(kernel)
    if len(parts) < 2:
        return False

    major, minor = parts[0], parts[1]
    patch = parts[2] if len(parts) > 2 else 0
    rc_match = re.search(r"7\.0(?:\.0)?-rc(\d+)", kernel)
    if rc_match:
        return 1 <= int(rc_match.group(1)) <= 7

    if major != 6:
        return False
    if minor == 16:
        return True
    if minor == 17:
        return True
    if minor == 18:
        return patch < 23
    if minor == 19:
        return patch < 13
    return False


def debian_ssh_keysign_pwn_patched(kernel_package: str, os_release: str, os_codename: str) -> bool:
    distro_id, version_id, id_like = os_release_parts(os_release)
    if distro_id != "debian" and "debian" not in id_like:
        return False

    codename = (os_codename or "").strip().lower()
    major = version_id.split(".", 1)[0]
    baselines = {
        "11": "5.10.251-5",
        "bullseye": "5.10.251-5",
        "12": "6.1.172-1",
        "bookworm": "6.1.172-1",
        "13": "6.12.88-1",
        "trixie": "6.12.88-1",
        "forky": "7.0.7-1",
        "sid": "7.0.7-1",
    }
    minimum = baselines.get(codename) or baselines.get(major)
    return bool(minimum and version_at_least(kernel_package, minimum))


def almalinux_ssh_keysign_pwn_patched(kernel: str, os_release: str) -> bool:
    distro_id, version_id, id_like = os_release_parts(os_release)
    if distro_id != "almalinux" and "almalinux" not in id_like:
        return False

    baselines = {
        "8": "4.18.0-553.124.4",
        "9": "5.14.0-611.54.6",
        "10": "6.12.0-124.56.5",
    }
    major = version_id.split(".", 1)[0]
    minimum = baselines.get(major)
    return bool(minimum and version_at_least(kernel, minimum))


def ssh_keysign_pwn_patched(kernel: str, kernel_package: str, os_release: str, os_codename: str) -> bool:
    return (
        debian_ssh_keysign_pwn_patched(kernel_package, os_release, os_codename)
        or almalinux_ssh_keysign_pwn_patched(kernel, os_release)
    )


# Convert raw host facts into vulnerability findings.
def assess(collected: Dict[str, str]) -> List[Finding]:
    kernel = collected.get("uname", "")
    pkg = collected.get("packagekit", "not_found")
    os_release = collected.get("os_release", "unknown:unknown:")
    os_codename = collected.get("os_codename", "unknown")
    kernel_pkg = collected.get("kernel_package", "not_found")
    rxrpc = collected.get("mod_rxrpc") == "1"
    rxrpc_available = collected.get("rxrpc_available") == "1"
    config_rxgk = collected.get("config_rxgk", "unknown")
    rds = collected.get("mod_rds") == "1"
    rds_tcp = collected.get("mod_rds_tcp") == "1"
    rds_available = collected.get("rds_available") == "1"
    rds_tcp_available = collected.get("rds_tcp_available") == "1"
    config_rds = collected.get("config_rds", "unknown")
    config_rds_tcp = collected.get("config_rds_tcp", "unknown")
    config_io_uring = collected.get("config_io_uring", "unknown")
    esp4 = collected.get("mod_esp4") == "1"
    esp6 = collected.get("mod_esp6") == "1"
    mitigation = collected.get("module_mitigation", "")
    rxgk_ioc = collected.get("rxgk_ioc", "")
    io_uring_disabled = collected.get("io_uring_disabled", "unknown")
    readable_suid_targets = collected.get("readable_suid_targets", "")
    ptrace_scope = collected.get("ptrace_scope", "unknown")
    ssh_keysign = collected.get("ssh_keysign", "not_found")
    chage = collected.get("chage", "not_found")
    fragnesia_mitigation = mitigation_summary(mitigation)
    findings: List[Finding] = []

    if version_in_range(kernel, "4.10", "7.0.99") or (version_in_range(kernel, "6.4", "7.0.99") and rxrpc):
        findings.append(Finding("Dirty Frag (CVE-2026-43284/43500)", TODO_STATUS, "medium", f"Kernel {kernel}, rxrpc_loaded={rxrpc}."))
    else:
        findings.append(Finding("Dirty Frag (CVE-2026-43284/43500)", "NO_DIRECT_INDICATOR", "low", f"Kernel {kernel} outside coarse window."))

    fragnesia_reason = (
        f"Kernel {kernel}, kernel_pkg={kernel_pkg}, esp4_loaded={esp4}, "
        f"esp6_loaded={esp6}, rxrpc_loaded={rxrpc}, mitigation={fragnesia_mitigation}."
    )
    all_fragnesia_modules_blocked = all(module_blocked(module, mitigation) for module in ("esp4", "esp6", "rxrpc"))
    if almalinux_fragnesia_patched(kernel, os_release):
        findings.append(Finding("Fragnesia (CVE-2026-46300)", "POSSIBLY_PATCHED", "medium", f"{fragnesia_reason} AlmaLinux kernel baseline indicates published Fragnesia fix."))
    elif version_in_range(kernel, "4.10", "7.0.99") and not all_fragnesia_modules_blocked:
        confidence = "high" if esp4 or esp6 or rxrpc else "medium"
        findings.append(Finding("Fragnesia (CVE-2026-46300)", TODO_STATUS, confidence, f"{fragnesia_reason} Kernel is in the coarse affected window and complete esp4/esp6/rxrpc mitigation was not detected."))
    elif version_in_range(kernel, "4.10", "7.0.99"):
        findings.append(Finding("Fragnesia (CVE-2026-46300)", "POSSIBLY_PATCHED", "medium", f"{fragnesia_reason} Complete modprobe mitigation appears present; verify loaded modules are removed/rebooted."))
    else:
        findings.append(Finding("Fragnesia (CVE-2026-46300)", "NO_DIRECT_INDICATOR", "low", f"{fragnesia_reason} Kernel outside coarse window."))

    rxgk_enabled = kernel_config_enabled(config_rxgk)
    rxrpc_blocked = module_blocked("rxrpc", mitigation)
    dirtydecrypt_reason = (
        f"Kernel {kernel}, kernel_pkg={kernel_pkg}, os={os_release}, codename={os_codename}, "
        f"CONFIG_RXGK={config_rxgk}, rxrpc_loaded={rxrpc}, rxrpc_available={rxrpc_available}, "
        f"rxrpc_blocked={rxrpc_blocked}, ioc={rxgk_ioc or 'none'}."
    )
    dirtydecrypt_affected_kernel = dirtydecrypt_kernel_affected(kernel)
    if dirtydecrypt_distro_not_affected_or_patched(kernel_pkg, os_release, os_codename):
        findings.append(Finding("DirtyDecrypt / DirtyCBC (CVE-2026-31635)", "POSSIBLY_PATCHED", "medium", f"{dirtydecrypt_reason} Distro tracker indicates this kernel line is not affected or fixed."))
    elif rxgk_ioc:
        findings.append(Finding("DirtyDecrypt / DirtyCBC (CVE-2026-31635)", TODO_STATUS, "high", f"{dirtydecrypt_reason} Kernel log contains RxGK/DirtyDecrypt indicators; investigate immediately."))
    elif dirtydecrypt_affected_kernel and rxgk_enabled and not rxrpc_blocked:
        confidence = "high" if rxrpc or rxrpc_available else "medium"
        findings.append(Finding("DirtyDecrypt / DirtyCBC (CVE-2026-31635)", TODO_STATUS, confidence, f"{dirtydecrypt_reason} Kernel is in the coarse affected window, RxGK is enabled, and rxrpc module mitigation was not detected."))
    elif dirtydecrypt_affected_kernel and config_rxgk == "unknown" and not rxrpc_blocked:
        findings.append(Finding("DirtyDecrypt / DirtyCBC (CVE-2026-31635)", TODO_STATUS, "medium", f"{dirtydecrypt_reason} Kernel is in the affected CVE-2026-31635 range but CONFIG_RXGK could not be read; verify kernel config or patch status."))
    elif dirtydecrypt_affected_kernel:
        findings.append(Finding("DirtyDecrypt / DirtyCBC (CVE-2026-31635)", "POSSIBLY_PATCHED", "medium", f"{dirtydecrypt_reason} rxrpc mitigation appears present or RxGK is disabled; verify kernel patch level."))
    else:
        findings.append(Finding("DirtyDecrypt / DirtyCBC (CVE-2026-31635)", "NO_DIRECT_INDICATOR", "low", f"{dirtydecrypt_reason} Kernel outside known affected CVE-2026-31635 ranges."))

    rds_blocked = module_blocked("rds", mitigation)
    rds_tcp_blocked = module_blocked("rds_tcp", mitigation)
    rds_surface = (kernel_config_enabled(config_rds) or rds or rds_available) and not rds_blocked
    rds_tcp_surface = (kernel_config_enabled(config_rds_tcp) or rds_tcp or rds_tcp_available) and not rds_tcp_blocked
    io_uring_surface = io_uring_enabled(config_io_uring, io_uring_disabled)
    suid_surface = bool(readable_suid_targets.strip())
    pin_theft_reason = (
        f"Kernel {kernel}, kernel_pkg={kernel_pkg}, os={os_release}, "
        f"CONFIG_RDS={config_rds}, CONFIG_RDS_TCP={config_rds_tcp}, "
        f"CONFIG_IO_URING={config_io_uring}, rds_loaded={rds}, rds_tcp_loaded={rds_tcp}, "
        f"rds_available={rds_available}, rds_tcp_available={rds_tcp_available}, "
        f"io_uring_disabled={io_uring_disabled}, rds_blocked={rds_blocked}, "
        f"rds_tcp_blocked={rds_tcp_blocked}, readable_suid_targets={readable_suid_targets or 'none'}."
    )
    if pin_theft_kernel_patched(kernel):
        findings.append(Finding("PinTheft (RDS zcopy double-free)", "POSSIBLY_PATCHED", "medium", f"{pin_theft_reason} Kernel version is at or above a known fixed upstream/stable baseline."))
    elif pin_theft_kernel_in_window(kernel) and rds_surface and rds_tcp_surface and io_uring_surface:
        confidence = "high" if suid_surface else "medium"
        findings.append(Finding("PinTheft (RDS zcopy double-free)", TODO_STATUS, confidence, f"{pin_theft_reason} RDS/RDS_TCP and io_uring prerequisites are present without detected module/sysctl mitigation."))
    elif pin_theft_kernel_in_window(kernel) and (rds_surface or rds_tcp_surface) and io_uring_surface:
        findings.append(Finding("PinTheft (RDS zcopy double-free)", TODO_STATUS, "medium", f"{pin_theft_reason} Partial RDS surface plus enabled io_uring detected; verify kernel fix and RDS module policy."))
    elif pin_theft_kernel_in_window(kernel):
        findings.append(Finding("PinTheft (RDS zcopy double-free)", "POSSIBLY_PATCHED", "medium", f"{pin_theft_reason} Known exploit prerequisites appear disabled or blocked; keep kernel patch tracking in place."))
    else:
        findings.append(Finding("PinTheft (RDS zcopy double-free)", "NO_DIRECT_INDICATOR", "low", f"{pin_theft_reason} Kernel outside coarse affected window or above known fixed baseline."))

    helper_surface = helper_surface_detected(ssh_keysign) or helper_surface_detected(chage)
    ptrace_mitigated = ptrace_scope_mitigated(ptrace_scope)
    ssh_keysign_reason = (
        f"Kernel {kernel}, kernel_pkg={kernel_pkg}, os={os_release}, codename={os_codename}, "
        f"ptrace_scope={ptrace_scope}, ssh_keysign={ssh_keysign or 'not_found'}, chage={chage or 'not_found'}."
    )
    if ssh_keysign_pwn_patched(kernel, kernel_pkg, os_release, os_codename):
        findings.append(Finding("SSH Keysign Pwn (CVE-2026-46333)", "POSSIBLY_PATCHED", "medium", f"{ssh_keysign_reason} Kernel package baseline indicates published CVE-2026-46333 fix."))
    elif version_in_range(kernel, "4.18", "7.0.99") and not ptrace_mitigated:
        confidence = "high" if helper_surface else "medium"
        findings.append(Finding("SSH Keysign Pwn (CVE-2026-46333)", TODO_STATUS, confidence, f"{ssh_keysign_reason} Kernel is in the coarse affected window and ptrace_scope mitigation 2/3 is not active."))
    elif version_in_range(kernel, "4.18", "7.0.99"):
        findings.append(Finding("SSH Keysign Pwn (CVE-2026-46333)", "POSSIBLY_PATCHED", "medium", f"{ssh_keysign_reason} ptrace_scope mitigation appears active; apply kernel fix to remove exposure."))
    else:
        findings.append(Finding("SSH Keysign Pwn (CVE-2026-46333)", "NO_DIRECT_INDICATOR", "low", f"{ssh_keysign_reason} Kernel outside coarse affected window."))

    if version_in_range(kernel, "4.10", "7.0.99"):
        findings.append(Finding("Copy Fail (CVE-2026-31431)", TODO_STATUS, "medium", f"Kernel {kernel} likely affected unless backported fix present."))
    else:
        findings.append(Finding("Copy Fail (CVE-2026-31431)", "NO_DIRECT_INDICATOR", "low", f"Kernel {kernel} outside coarse window."))

    if pkg != "not_found" and version_in_range(pkg, "1.0.2", "1.3.4"):
        findings.append(Finding("Pack2TheRoot (CVE-2026-41651)", TODO_STATUS, "high", f"PackageKit {pkg} in vulnerable range."))
    elif pkg == "not_found":
        findings.append(Finding("Pack2TheRoot (CVE-2026-41651)", "NOT_APPLICABLE_OR_UNKNOWN", "medium", "PackageKit not found."))
    else:
        findings.append(Finding("Pack2TheRoot (CVE-2026-41651)", "POSSIBLY_PATCHED", "medium", f"PackageKit {pkg} seems patched/backported."))
    return findings


def report_header(mode: str, target: str, workers: int) -> str:
    return "\n".join([
        "Linux LPE Exposure Scan Report",
        f"Generated: {utc_timestamp()}",
        f"Target: {target}",
        f"Mode: {mode}",
        f"Workers: {workers}",
        "Scope: only hosts with at least one LIKELY_VULNERABLE finding are logged",
        "",
    ]) + "\n"


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def safe_filename_part(value: str) -> str:
    # CIDR values contain slashes, so normalize them before using them in filenames.
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
    return safe.strip("._") or "target"


def report_path_for_target(output_dir: Path, prefix: str, target: str) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir / f"{prefix}_{safe_filename_part(target)}{REPORT_EXTENSION}"


# Build the persisted report block for one actionable host.
def host_report_block(result: HostResult) -> str:
    lines = [
        f"Host: {result.host} | reachable={result.reachable} | kernel={result.uname or '-'} | "
        f"kernel_package={result.kernel_package} | os={result.os_release} | packagekit={result.packagekit_version}"
    ]
    for finding in result.findings:
        lines.append(f"  - {finding.vuln}: {finding.status} ({finding.confidence}) -> {finding.reason}")
    lines.append("")
    return "\n".join(lines)


def has_todo_finding(result: HostResult) -> bool:
    return any(finding.status == TODO_STATUS for finding in result.findings)


# Keep the report focused on hosts that create work for the team.
def write_host_result(report_file, result: HostResult) -> bool:
    if not has_todo_finding(result):
        return False

    report_file.write(host_report_block(result))
    report_file.write("\n")
    report_file.flush()
    return True


def scan_host(host: str, user: str, password: Optional[str], config: ScanConfig) -> HostResult:
    reachable = ping_host(host, config.probe_timeout) or tcp_open(host, 22, config.probe_timeout)
    result = HostResult(host=host, reachable=reachable)
    if not reachable:
        result.findings.append(Finding("ALL", "NO_RESPONSE", "low", "Host unreachable."))
        return result

    try:
        data = ssh_collect(host, user, password, config)
        result.uname = data.get("uname", "")
        result.os_release = data.get("os_release", "unknown")
        result.kernel_package = data.get("kernel_package", "not_found")
        result.packagekit_version = data.get("packagekit", "not_found")
        result.findings = assess(data)
    except Exception as exc:
        result.findings.append(Finding("ALL", "ERROR", "low", f"SSH failed: {exc}"))
    return result


# Track active worker state separately so the terminal UI can refresh in place.
def scan_host_tracked(
    host: str,
    user: str,
    password: Optional[str],
    config: ScanConfig,
    active_hosts: Dict[str, float],
    active_lock: threading.Lock,
) -> HostResult:
    with active_lock:
        active_hosts[host] = time.monotonic()
    try:
        return scan_host(host, user, password, config)
    finally:
        with active_lock:
            active_hosts.pop(host, None)


def format_duration(seconds: Optional[float]) -> str:
    if seconds is None:
        return "--:--"

    seconds_i = max(0, int(seconds))
    hours, remainder = divmod(seconds_i, 3600)
    minutes, seconds_i = divmod(remainder, 60)
    if hours:
        return f"{hours:02d}:{minutes:02d}:{seconds_i:02d}"
    return f"{minutes:02d}:{seconds_i:02d}"


def truncate_cell(text: str, width: int) -> str:
    if len(text) <= width:
        return text.ljust(width)
    if width <= 3:
        return text[:width]
    return (text[: width - 3] + "...").ljust(width)


def result_badge(result: HostResult) -> Tuple[str, str]:
    statuses = {finding.status for finding in result.findings}
    if "ERROR" in statuses:
        return "ERROR", C.RED
    if TODO_STATUS in statuses:
        return "VULNERABLE", C.RED
    if "NO_RESPONSE" in statuses or not result.reachable:
        return "NO REPLY", C.YELLOW
    return "OK", C.GREEN


# Owns the fixed terminal display: progress bar, timing, and active worker table.
class LiveProgress:
    def __init__(self, total: int, workers: int, header_lines: Optional[List[str]] = None):
        self.total = total
        self.workers = workers
        self.header_lines = header_lines or []
        self.started_at = time.monotonic()

    def hide_cursor(self) -> None:
        print("\033[?25l", end="", flush=True)

    def show_cursor(self) -> None:
        print("\033[?25h", end="", flush=True)

    def render(self, completed: int, active_snapshot: List[Tuple[str, float]], last_result: Optional[HostResult] = None) -> None:
        lines = self._build_lines(completed, active_snapshot, last_result)
        print("\033[H\033[J" + "\n".join(lines), flush=True)

    def _build_lines(self, completed: int, active_snapshot: List[Tuple[str, float]], last_result: Optional[HostResult] = None) -> List[str]:
        elapsed = time.monotonic() - self.started_at
        percent = (completed / self.total) if self.total else 1
        remaining = None if completed == 0 else (elapsed / completed) * (self.total - completed)
        bar_width = 42
        filled = int(bar_width * percent)
        bar = f"{C.GREEN}{'#' * filled}{C.YELLOW}{'.' * (bar_width - filled)}{C.RESET}"
        active_count = len(active_snapshot)

        lines = list(self.header_lines)
        if lines:
            lines.append("")

        lines.extend([
            f"{C.BOLD}{C.BLUE}Scan Progress{C.RESET} [{bar}] {completed}/{self.total} ({percent * 100:5.1f}%)",
            f"{C.CYAN}Elapsed:{C.RESET} {format_duration(elapsed)}  "
            f"{C.CYAN}ETA:{C.RESET} {format_duration(remaining)}  "
            f"{C.CYAN}Active:{C.RESET} {active_count}/{self.workers}",
        ])

        if last_result is not None:
            label, color = result_badge(last_result)
            lines.append(f"{C.CYAN}Last Result:{C.RESET} {last_result.host} -> {color}{label}{C.RESET}")
        else:
            lines.append(f"{C.CYAN}Last Result:{C.RESET} -")

        lines.extend(self._active_host_table(active_snapshot))
        return lines

    def _active_host_table(self, active_snapshot: List[Tuple[str, float]]) -> List[str]:
        host_width = 22
        status_width = 12
        duration_width = 10
        border = "+" + "-" * (host_width + 2) + "+" + "-" * (status_width + 2) + "+" + "-" * (duration_width + 2) + "+"
        rows = [
            border,
            f"| {C.BOLD}{truncate_cell('Host', host_width)}{C.RESET} | "
            f"{C.BOLD}{truncate_cell('Status', status_width)}{C.RESET} | "
            f"{C.BOLD}{truncate_cell('Runtime', duration_width)}{C.RESET} |",
            border,
        ]

        now = time.monotonic()
        if not active_snapshot:
            rows.append(f"| {truncate_cell('-', host_width)} | {C.GREEN}{truncate_cell('IDLE', status_width)}{C.RESET} | {truncate_cell('-', duration_width)} |")
        else:
            max_rows = self._max_active_rows()
            visible_hosts = active_snapshot[:max_rows]
            for host, started_at in visible_hosts:
                rows.append(
                    f"| {C.CYAN}{truncate_cell(host, host_width)}{C.RESET} | "
                    f"{C.YELLOW}{truncate_cell('RUNNING', status_width)}{C.RESET} | "
                    f"{truncate_cell(format_duration(now - started_at), duration_width)} |"
                )
            hidden_count = len(active_snapshot) - len(visible_hosts)
            if hidden_count > 0:
                hidden_label = f"+ {hidden_count} more active"
                rows.append(f"| {truncate_cell(hidden_label, host_width)} | {truncate_cell('RUNNING', status_width)} | {truncate_cell('-', duration_width)} |")

        rows.append(border)
        return rows

    def _max_active_rows(self) -> int:
        terminal_height = shutil.get_terminal_size(fallback=(100, 32)).lines
        reserved_lines = len(self.header_lines) + 9
        return max(1, min(MAX_LIVE_HOST_ROWS, terminal_height - reserved_lines))


def submit_next(
    executor: ThreadPoolExecutor,
    hosts_iter: Iterator[str],
    pending: Dict[Future, str],
    user: str,
    password: Optional[str],
    config: ScanConfig,
    active_hosts: Dict[str, float],
    active_lock: threading.Lock,
) -> bool:
    try:
        host = next(hosts_iter)
    except StopIteration:
        return False
    future = executor.submit(scan_host_tracked, host, user, password, config, active_hosts, active_lock)
    pending[future] = host
    return True


def scan_hosts(hosts: List[str], user: str, password: Optional[str], mode: str, target: str, report_path: Path, config: ScanConfig) -> ScanOutcome:
    # Run host checks in parallel while streaming actionable findings into the report file.
    results_by_host: Dict[str, HostResult] = {}
    active_hosts: Dict[str, float] = {}
    active_lock = threading.Lock()
    progress = LiveProgress(
        len(hosts),
        config.workers,
        [
            f"{C.CYAN}Target:{C.RESET} {target} ({len(hosts)} host(s))",
            f"{C.CYAN}Workers:{C.RESET} {config.workers}",
            f"{C.CYAN}SSH Auth:{C.RESET} {'private key' if config.key_file else 'password'}",
            f"{C.CYAN}Report:{C.RESET} {report_path}",
        ],
    )
    interrupted = False

    with report_path.open("w", encoding="utf-8", buffering=1) as report_file:
        report_file.write(report_header(mode, target, config.workers))
        report_file.flush()

        # Keep only one batch of futures in memory; the executor enforces the worker limit.
        executor = ThreadPoolExecutor(max_workers=config.workers)
        try:
            hosts_iter = iter(hosts)
            pending: Dict[Future, str] = {}
            for _ in range(min(config.workers, len(hosts))):
                submit_next(executor, hosts_iter, pending, user, password, config, active_hosts, active_lock)

            completed = 0
            last_result: Optional[HostResult] = None
            cursor_hidden = False
            if config.live:
                progress.hide_cursor()
                cursor_hidden = True
                progress.render(completed, [], last_result)

            try:
                while pending:
                    # Poll briefly so the live progress table keeps moving while scans run.
                    done, _ = wait(set(pending), timeout=0.25, return_when=FIRST_COMPLETED)
                    for future in done:
                        host = pending.pop(future)
                        try:
                            result = future.result()
                        except Exception as exc:
                            result = HostResult(host=host, reachable=False)
                            result.findings.append(Finding("ALL", "ERROR", "low", f"Scan failed: {exc}"))

                        results_by_host[result.host] = result
                        write_host_result(report_file, result)
                        completed += 1
                        last_result = result
                        submit_next(executor, hosts_iter, pending, user, password, config, active_hosts, active_lock)

                    if config.live:
                        with active_lock:
                            active_snapshot = sorted(active_hosts.items())
                        progress.render(completed, active_snapshot, last_result)
            except KeyboardInterrupt:
                interrupted = True
                for future in pending:
                    future.cancel()
                report_file.write(f"\nScan interrupted by operator: {utc_timestamp()}\n")
                report_file.flush()
                if cursor_hidden:
                    progress.show_cursor()
                    cursor_hidden = False
                print(f"\n{C.YELLOW}[!] Ctrl+C received. Cancelling queued work and waiting for in-flight checks to stop cleanly...{C.RESET}", file=sys.stderr, flush=True)
            finally:
                if cursor_hidden:
                    progress.show_cursor()
        finally:
            executor.shutdown(wait=True, cancel_futures=True)

    return ScanOutcome(
        results=[results_by_host[host] for host in hosts if host in results_by_host],
        interrupted=interrupted,
    )


def print_summary_table(results: List[HostResult]) -> None:
    todo_results = [result for result in results if has_todo_finding(result)]
    headers = ["Host", "Reachable", "Kernel", "To-Do: Probably Vulnerable To"]
    rows = []
    for result in todo_results:
        vulns = [finding.vuln for finding in result.findings if finding.status == TODO_STATUS]
        rows.append([result.host, str(result.reachable), result.uname or "-", ", ".join(vulns)])

    if not rows:
        print(f"\n{C.BOLD}{C.GREEN}To-Do Summary{C.RESET}")
        print("+--------------------------------------+")
        print("| No probably vulnerable hosts found.  |")
        print("+--------------------------------------+")
        return

    widths = [max(len(str(row[i])) for row in ([headers] + rows)) for i in range(4)]
    line = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    print(f"\n{C.BOLD}{C.BLUE}To-Do Summary{C.RESET}")
    print(line)
    print("| " + " | ".join(headers[i].ljust(widths[i]) for i in range(4)) + " |")
    print(line)
    for row in rows:
        colored = [row[0], row[1], row[2], f"{C.RED}{row[3]}{C.RESET}"]
        print("| " + " | ".join(colored[i].ljust(widths[i]) if i < 3 else colored[i] for i in range(4)) + " |")
    print(line)


def prompt_required(prompt: str, secret: bool = False, redraw_banner: bool = False) -> str:
    # Keep prompting until the operator provides a non-empty value.
    while True:
        if redraw_banner:
            clear_screen()
            print_banner()
        try:
            raw_value = getpass(prompt) if secret else input(prompt)
        except EOFError as exc:
            raise SystemExit(f"Missing required value for: {prompt.strip()}") from exc
        if raw_value.strip():
            return raw_value if secret else raw_value.strip()
        print(f"{C.YELLOW}[!] This field is required.{C.RESET}")


def prompt_optional(prompt: str, secret: bool = False, redraw_banner: bool = False) -> Optional[str]:
    if redraw_banner:
        clear_screen()
        print_banner()
    try:
        raw_value = getpass(prompt) if secret else input(prompt)
    except EOFError:
        return None
    if not raw_value.strip():
        return None
    return raw_value if secret else raw_value.strip()


def resolve_target(args: argparse.Namespace) -> str:
    target = args.subnet_option or args.subnet
    if args.subnet_option and args.subnet and args.subnet_option != args.subnet:
        raise SystemExit("Provide the scan target either positionally or with --target/--subnet, not both with different values.")
    if target:
        return target.strip()
    return prompt_required("Target to scan (CIDR or range, e.g. 10.0.10.0/24 or 10.215.0.0-10.215.5.254): ", redraw_banner=True)


def resolve_key_file(args: argparse.Namespace) -> Optional[Path]:
    if not args.key_file:
        return None

    key_file = Path(args.key_file).expanduser()
    if not key_file.is_file():
        raise SystemExit(f"SSH private key file not found: {key_file}")
    return key_file


def resolve_key_passphrase(args: argparse.Namespace, key_file: Optional[Path]) -> Optional[str]:
    if not key_file:
        if args.key_passphrase is not None:
            raise SystemExit("--key-passphrase requires --key-file")
        if args.key_passphrase_env is not None:
            raise SystemExit("--key-passphrase-env requires --key-file")
        if args.ask_key_passphrase:
            raise SystemExit("--ask-key-passphrase requires --key-file")
        return None

    if args.key_passphrase is not None:
        if not args.key_passphrase:
            raise SystemExit("--key-passphrase cannot be empty")
        return args.key_passphrase

    env_name = args.key_passphrase_env or DEFAULT_KEY_PASSPHRASE_ENV
    env_value = os.environ.get(env_name)
    if env_value:
        return env_value

    if args.ask_key_passphrase:
        return prompt_optional(f"SSH key passphrase [{env_name} not set, empty for none]: ", secret=True, redraw_banner=True)
    return None


def resolve_password(args: argparse.Namespace, key_file: Optional[Path]) -> Optional[str]:
    if key_file:
        if args.password is not None:
            raise SystemExit("--password cannot be used together with --key-file")
        return None

    if args.password is not None:
        if not args.password:
            raise SystemExit("--password cannot be empty")
        return args.password

    env_name = args.password_env or DEFAULT_PASSWORD_ENV
    env_value = os.environ.get(env_name)
    if env_value:
        return env_value

    return prompt_required(f"SSH password [{env_name} not set]: ", secret=True, redraw_banner=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Authenticated Linux LPE exposure scanner for Dirty Frag, Fragnesia, DirtyDecrypt, PinTheft, SSH Keysign Pwn, Copy Fail, and Pack2TheRoot.",
    )
    parser.add_argument("subnet", nargs="?", help="CIDR or inclusive IP range to scan, e.g. 10.0.10.0/24 or 10.215.0.0-10.215.5.254")
    parser.add_argument("--subnet", dest="subnet_option", help="CIDR or inclusive IP range to scan; alternative to the positional target")
    parser.add_argument("--target", dest="subnet_option", help="CIDR or inclusive IP range to scan; alternative to the positional target")
    parser.add_argument("-u", "--username", help="SSH username. If omitted, you will be prompted.")
    parser.add_argument("--password", help="SSH password. Prefer the prompt or --password-env for shell history safety.")
    parser.add_argument("--password-env", help=f"Environment variable containing the SSH password. Defaults to {DEFAULT_PASSWORD_ENV}.")
    parser.add_argument("--key-file", help="SSH private key file for key-based authentication. When set, password authentication is not used.")
    parser.add_argument("--key-passphrase", help="Passphrase for an encrypted SSH private key. Prefer --key-passphrase-env or --ask-key-passphrase for shell history safety.")
    parser.add_argument("--key-passphrase-env", help=f"Environment variable containing the SSH private key passphrase. Defaults to {DEFAULT_KEY_PASSPHRASE_ENV}.")
    parser.add_argument("--ask-key-passphrase", action="store_true", help="Prompt for the SSH private key passphrase. Leave empty for an unencrypted key.")
    parser.add_argument("--workers", type=worker_count, default=MIN_WORKER_THREADS, help=f"Parallel worker threads. Minimum/default: {MIN_WORKER_THREADS}.")
    parser.add_argument("--output-dir", type=Path, default=Path("."), help="Directory for report output. Default: current directory.")
    parser.add_argument("--report-prefix", default=DEFAULT_REPORT_PREFIX, help=f"Report filename prefix. Default: {DEFAULT_REPORT_PREFIX}.")
    parser.add_argument("--probe-timeout", type=positive_float, default=1.0, help="Ping/TCP reachability timeout in seconds. Default: 1.0.")
    parser.add_argument("--ssh-timeout", type=positive_float, default=6.0, help="SSH connect/auth/banner timeout in seconds. Default: 6.0.")
    parser.add_argument("--command-timeout", type=positive_float, default=8.0, help="Remote command timeout in seconds. Default: 8.0.")
    parser.add_argument("--strict-host-key", action="store_true", help="Reject unknown SSH host keys instead of auto-adding them.")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors.")
    parser.add_argument("--no-live", action="store_true", help="Disable the fixed live progress display.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {SCRIPT_VERSION}")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    configure_color(not args.no_color and sys.stdout.isatty())
    clear_screen()
    print_banner()

    if paramiko is None:
        raise SystemExit("Please install Paramiko first: pip install -r requirements.txt")

    target = resolve_target(args)
    target_spec = parse_target_spec(target)
    hosts = target_spec.hosts
    if not hosts:
        raise SystemExit(f"No usable hosts found in target: {target_spec.label}")

    user = args.username.strip() if args.username else prompt_required("SSH username: ", redraw_banner=True)
    if not user:
        raise SystemExit("SSH username cannot be empty")
    key_file = resolve_key_file(args)
    key_passphrase = resolve_key_passphrase(args, key_file)
    password = resolve_password(args, key_file)

    config = ScanConfig(
        workers=args.workers,
        probe_timeout=args.probe_timeout,
        ssh_timeout=args.ssh_timeout,
        command_timeout=args.command_timeout,
        strict_host_key=args.strict_host_key,
        live=not args.no_live and sys.stdout.isatty(),
        key_file=key_file,
        key_passphrase=key_passphrase,
    )

    report_path = report_path_for_target(args.output_dir, args.report_prefix, target_spec.label)
    if not config.live:
        print(f"{C.CYAN}Target:{C.RESET} {target_spec.label} ({len(hosts)} host(s))")
        print(f"{C.CYAN}Workers:{C.RESET} {config.workers}")
        print(f"{C.CYAN}SSH Auth:{C.RESET} {'private key' if config.key_file else 'password'}")
        print(f"{C.CYAN}Report:{C.RESET} {report_path}\n")

    outcome = scan_hosts(hosts, user, password, "authenticated", target_spec.label, report_path, config)

    if outcome.interrupted:
        print(f"\n{C.YELLOW}[!] Scan interrupted by operator. Partial results are shown below.{C.RESET}")

    print_summary_table(outcome.results)
    todo_count = sum(1 for result in outcome.results if has_todo_finding(result))
    print(f"\n{C.BOLD}{C.GREEN}[+] Report written: {report_path} ({todo_count} To-Do Host(s)){C.RESET}")
    return 130 if outcome.interrupted else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}[!] Aborted by operator.{C.RESET}", file=sys.stderr)
        raise SystemExit(130)
