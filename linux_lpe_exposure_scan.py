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


def parse_version_tuple(v: str) -> Tuple[int, ...]:
    nums = re.findall(r"\d+", v or "")
    return tuple(int(x) for x in nums[:6]) if nums else (0,)


def version_in_range(v: str, low: str, high: str) -> bool:
    return parse_version_tuple(low) <= parse_version_tuple(v) <= parse_version_tuple(high)


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
                                                                                  
  Authenticated scans for DirtyFrag | CopyFail | Pack2TheRoot Linux LPE vulns
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


# Collect only the remote facts needed for the three local privilege escalation checks.
def ssh_collect(host: str, user: str, password: str, config: ScanConfig) -> Dict[str, str]:
    client = paramiko.SSHClient()
    if config.strict_host_key:
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
    else:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    client.connect(
        host,
        username=user,
        password=password,
        timeout=config.ssh_timeout,
        auth_timeout=config.ssh_timeout,
        banner_timeout=config.ssh_timeout,
        look_for_keys=False,
        allow_agent=False,
    )

    cmds = {
        "uname": "uname -r",
        "mod_rxrpc": "test -d /sys/module/rxrpc && echo 1 || echo 0",
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


# Convert raw host facts into vulnerability findings.
def assess(collected: Dict[str, str]) -> List[Finding]:
    kernel = collected.get("uname", "")
    pkg = collected.get("packagekit", "not_found")
    rxrpc = collected.get("mod_rxrpc") == "1"
    findings: List[Finding] = []

    if version_in_range(kernel, "4.10", "7.0.99") or (version_in_range(kernel, "6.4", "7.0.99") and rxrpc):
        findings.append(Finding("Dirty Frag (CVE-2026-43284/43500)", TODO_STATUS, "medium", f"Kernel {kernel}, rxrpc_loaded={rxrpc}."))
    else:
        findings.append(Finding("Dirty Frag (CVE-2026-43284/43500)", "NO_DIRECT_INDICATOR", "low", f"Kernel {kernel} outside coarse window."))

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
    lines = [f"Host: {result.host} | reachable={result.reachable} | kernel={result.uname or '-'} | packagekit={result.packagekit_version}"]
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


def scan_host(host: str, user: str, password: str, config: ScanConfig) -> HostResult:
    reachable = ping_host(host, config.probe_timeout) or tcp_open(host, 22, config.probe_timeout)
    result = HostResult(host=host, reachable=reachable)
    if not reachable:
        result.findings.append(Finding("ALL", "NO_RESPONSE", "low", "Host unreachable."))
        return result

    try:
        data = ssh_collect(host, user, password, config)
        result.uname = data.get("uname", "")
        result.packagekit_version = data.get("packagekit", "not_found")
        result.findings = assess(data)
    except Exception as exc:
        result.findings.append(Finding("ALL", "ERROR", "low", f"SSH failed: {exc}"))
    return result


# Track active worker state separately so the terminal UI can refresh in place.
def scan_host_tracked(
    host: str,
    user: str,
    password: str,
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
    password: str,
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


def scan_hosts(hosts: List[str], user: str, password: str, mode: str, target: str, report_path: Path, config: ScanConfig) -> ScanOutcome:
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


def resolve_target(args: argparse.Namespace) -> str:
    target = args.subnet_option or args.subnet
    if args.subnet_option and args.subnet and args.subnet_option != args.subnet:
        raise SystemExit("Provide the scan target either positionally or with --target/--subnet, not both with different values.")
    if target:
        return target.strip()
    return prompt_required("Target to scan (CIDR or range, e.g. 10.0.10.0/24 or 10.215.0.0-10.215.5.254): ", redraw_banner=True)


def resolve_password(args: argparse.Namespace) -> str:
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
        description="Authenticated Linux LPE exposure scanner for Dirty Frag, Copy Fail, and Pack2TheRoot.",
    )
    parser.add_argument("subnet", nargs="?", help="CIDR or inclusive IP range to scan, e.g. 10.0.10.0/24 or 10.215.0.0-10.215.5.254")
    parser.add_argument("--subnet", dest="subnet_option", help="CIDR or inclusive IP range to scan; alternative to the positional target")
    parser.add_argument("--target", dest="subnet_option", help="CIDR or inclusive IP range to scan; alternative to the positional target")
    parser.add_argument("-u", "--username", help="SSH username. If omitted, you will be prompted.")
    parser.add_argument("--password", help="SSH password. Prefer the prompt or --password-env for shell history safety.")
    parser.add_argument("--password-env", help=f"Environment variable containing the SSH password. Defaults to {DEFAULT_PASSWORD_ENV}.")
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
    password = resolve_password(args)

    config = ScanConfig(
        workers=args.workers,
        probe_timeout=args.probe_timeout,
        ssh_timeout=args.ssh_timeout,
        command_timeout=args.command_timeout,
        strict_host_key=args.strict_host_key,
        live=not args.no_live and sys.stdout.isatty(),
    )

    report_path = report_path_for_target(args.output_dir, args.report_prefix, target_spec.label)
    if not config.live:
        print(f"{C.CYAN}Target:{C.RESET} {target_spec.label} ({len(hosts)} host(s))")
        print(f"{C.CYAN}Workers:{C.RESET} {config.workers}")
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
