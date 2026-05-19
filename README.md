# Linux LPE Exposure Scan

Linux LPE Exposure Scan is a fast, authenticated SSH scanner for identifying Linux hosts that probably need follow-up for local privilege escalation exposure checks:

* Dirty Frag (CVE-2026-43284 / CVE-2026-43500)
* Fragnesia (CVE-2026-46300)
* DirtyDecrypt / DirtyCBC (CVE-2026-31635)
* SSH Keysign Pwn (CVE-2026-46333)
* Copy Fail (CVE-2026-31431)
* Pack2TheRoot (CVE-2026-41651)

The tool runs with at least 32 parallel worker threads, shows a colored live progress table, and writes actionable report entries as soon as each vulnerable host is identified.

* * *

## Features

  * Authenticated SSH collection for local host facts
  * Fragnesia exposure check using kernel, distro, ESP/RXRPC module, and modprobe mitigation indicators
  * DirtyDecrypt / DirtyCBC exposure check using kernel, distro, `CONFIG_RXGK`, RxRPC module, mitigation, and kernel-log indicators
  * SSH Keysign Pwn exposure check using kernel package, distro, `ptrace_scope`, `ssh-keysign`, and `chage` indicators
  * Parallel scanning with a minimum of 32 worker threads
  * Accepts CIDR targets and inclusive IP ranges
  * Live progress bar with elapsed time, ETA, and currently checked hosts
  * Colored terminal output for quick triage
  * Report output is streamed while the scan runs
  * Report files include the scanned target in the filename
  * Report files only contain To-Do entries: hosts with at least one `LIKELY_VULNERABLE` finding
  * Configurable SSH, command, and reachability timeouts
  * Clean Ctrl+C handling with cursor restore and partial results
  * Password input via hidden prompt, environment variable, or CLI argument
  * Optional strict SSH host key validation

* * *

## Installation

  1. Install dependencies

    pip install -r requirements.txt

  2. Clone this repository:

    git clone https://github.com/BenjaminIheukumere/lpe_0526_find0r
    cd lpe_0526_find0r
    chmod +x linux_lpe_exposure_scan.py

## Usage

    ./linux_lpe_exposure_scan.py <CIDR_OR_RANGE> -u <SSH_USER>

Username and password are mandatory. If the password is not supplied through an environment variable or CLI option, the script prompts for it securely.

## Examples

Interactive password prompt:

    ./linux_lpe_exposure_scan.py 10.0.10.0/24 -u audituser

Inclusive IP range:

    ./linux_lpe_exposure_scan.py 10.215.0.0-10.215.5.254 -u audituser

Password from environment variable:

    export LPE_SCAN_PASSWORD='SuperSecretPassword'
    ./linux_lpe_exposure_scan.py 10.0.10.0/24 -u audituser

Custom output directory:

    ./linux_lpe_exposure_scan.py 10.0.10.0/24 -u audituser --output-dir reports

More worker threads:

    ./linux_lpe_exposure_scan.py 10.0.10.0/24 -u audituser --workers 64

Strict SSH host key checking:

    ./linux_lpe_exposure_scan.py 10.0.10.0/24 -u audituser --strict-host-key

Disable colors and the live terminal UI:

    ./linux_lpe_exposure_scan.py 10.0.10.0/24 -u audituser --no-color --no-live

## Options

  * `--workers`: Parallel worker threads. Minimum/default is `32`.
  * `--target` / `--subnet`: CIDR target or inclusive IP range if you do not use the positional argument.
  * `--output-dir`: Directory for report output. Default is the current directory.
  * `--report-prefix`: Prefix for report filenames. Default is `lpe_scan_report`.
  * `--probe-timeout`: Ping/TCP reachability timeout in seconds. Default is `1.0`.
  * `--ssh-timeout`: SSH connect/auth/banner timeout in seconds. Default is `6.0`.
  * `--command-timeout`: Remote command timeout in seconds. Default is `8.0`.
  * `--password-env`: Environment variable containing the SSH password. Default lookup is `LPE_SCAN_PASSWORD`.
  * `--password`: SSH password as an argument. Use the prompt or environment variable instead when shell history matters.
  * `--strict-host-key`: Reject unknown SSH host keys.
  * `--no-color`: Disable ANSI colors.
  * `--no-live`: Disable the fixed live progress display.

## Output

Reports are written to files named after the scanned target:

    lpe_scan_report_10.0.10.0_24.txt
    lpe_scan_report_10.215.0.0-10.215.5.254.txt

Only hosts with at least one `LIKELY_VULNERABLE` finding are written to the report. Non-actionable entries such as unreachable hosts, SSH errors, patched-looking systems, or hosts without direct indicators are not logged as To-Do items.

The final terminal summary also shows only probably vulnerable hosts.

## Notes

  * This scanner does not exploit any vulnerability.
  * Authenticated SSH access is required because local LPE exposure cannot be assessed reliably without host facts.
  * Fragnesia checks are defensive exposure indicators only. They look at the running kernel, distribution hints, ESP/RXRPC module state, and modprobe mitigations.
  * DirtyDecrypt / DirtyCBC checks are defensive exposure indicators only. They look at the running kernel, distro fix hints, `CONFIG_RXGK`, RxRPC module availability, RxRPC mitigation, and available kernel-log indicators.
  * SSH Keysign Pwn checks are defensive exposure indicators only. They look at the running kernel, distro fix baselines, public helper surfaces, and the `kernel.yama.ptrace_scope` mitigation.
  * Kernel and package version checks are coarse indicators. Distribution backports may change the real patch status.
  * Default SSH host key behavior accepts unknown host keys for scan practicality. Use `--strict-host-key` in environments where known-hosts enforcement is required.
  * Press `Ctrl+C` to stop a running scan cleanly. Queued hosts are cancelled, in-flight checks are allowed to release, and partial To-Do results are printed.
  * Python 3.9 or newer is recommended.

## Modification

If you want to change the default thread count, edit `MIN_WORKER_THREADS` in `linux_lpe_exposure_scan.py`. You can also set the runtime worker count with `--workers`, but values below `32` are rejected.

## Disclaimer

This tool is intended for authorized security testing and defensive exposure assessment only. Use it only in environments where you have explicit permission. The author is not responsible for any misuse or damage caused by this tool.

## About

Linux LPE Exposure Scan is a multithreaded authenticated scanner for quickly identifying Linux hosts that probably need follow-up for selected local privilege escalation exposures, including Dirty Frag, Fragnesia, DirtyDecrypt / DirtyCBC, SSH Keysign Pwn, Copy Fail, and Pack2TheRoot.
