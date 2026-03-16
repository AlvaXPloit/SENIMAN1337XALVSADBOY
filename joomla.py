#!/usr/bin/python
# -*- coding: utf-8 -*-
# Joomla Checker Login - Cek hak akses Administrator atau User
# Author: YamiFool - Royal Fool
# Requirements: pip install requests beautifulsoup4

import requests
from bs4 import BeautifulSoup
import re
import sys
import argparse
import warnings
from urllib.parse import urlparse

if not sys.warnoptions:
    warnings.simplefilter("ignore")

print('''
╔══════════════════════════════════════════════════════════╗
║           Joomla Checker Login v1.0                      ║
║        Cek Hak Akses Administrator atau User             ║
║              Author: YamiFool - Royal Fool               ║
╚══════════════════════════════════════════════════════════╝
''')

def check_joomla_login(url, username, password):
    """Fungsi untuk mengecek login Joomla dan hak aksesnya"""
    
    # Normalisasi URL
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    # Pastikan URL mengarah ke administrator
    if not url.endswith('/administrator'):
        if '/administrator' not in url:
            url = url.rstrip('/') + '/administrator'
    
    # Session untuk menyimpan cookie
    session = requests.Session()
    session.verify = False
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    })
    
    try:
        # Ambil halaman login untuk mendapatkan token
        response = session.get(url, timeout=10)
        
        if response.status_code != 200:
            return {'success': False, 'error': f'HTTP {response.status_code}'}
        
        # Parse HTML untuk mencari token
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Cari input token (biasanya name="return" atau yang mengandung token)
        token_inputs = soup.find_all('input', {'type': 'hidden'})
        token = None
        
        for inp in token_inputs:
            if inp.get('name') and ('token' in inp.get('name') or 'return' in inp.get('name')):
                token = inp.get('value')
                break
        
        # Data login
        login_data = {
            'username': username,
            'passwd': password,
            'task': 'login',
            'option': 'com_login'
        }
        
        if token:
            login_data['return'] = token
        
        # Login attempt
        login_response = session.post(url, data=login_data, allow_redirects=True, timeout=10)
        
        # Cek apakah login berhasil
        if 'mod_login' in login_response.text or 'username" required' in login_response.text:
            return {'success': False, 'error': 'Login gagal'}
        
        # Cek hak akses berdasarkan konten yang muncul
        if 'control panel' in login_response.text.lower() or 'cpanel' in login_response.text.lower():
            if 'super user' in login_response.text.lower() or 'super administrator' in login_response.text.lower():
                role = 'Super Administrator'
            elif 'administrator' in login_response.text.lower():
                role = 'Administrator'
            elif 'manager' in login_response.text.lower():
                role = 'Manager'
            else:
                role = 'Administrator (akses penuh)'
        elif 'com_content' in login_response.text.lower() or 'article' in login_response.text.lower():
            # Mungkin user biasa dengan akses terbatas
            if 'edit own' in login_response.text.lower():
                role = 'Author'
            else:
                role = 'Registered User'
        else:
            role = 'Tidak diketahui (mungkin user biasa)'
        
        return {
            'success': True,
            'role': role,
            'url': url,
            'username': username,
            'password': password
        }
        
    except requests.exceptions.ConnectionError:
        return {'success': False, 'error': 'Koneksi gagal'}
    except requests.exceptions.Timeout:
        return {'success': False, 'error': 'Timeout'}
    except Exception as e:
        return {'success': False, 'error': str(e)}

def parse_list_file(file_path):
    """Parse file list.txt dengan format url:username:password"""
    credentials = []
    
    try:
        with open(file_path, 'r') as f:
            lines = f.readlines()
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # Parse format url:username:password
            parts = line.split(':')
            if len(parts) >= 3:
                # URL bisa mengandung : jadi kita gabungkan kembali
                url = parts[0]
                username = parts[1]
                password = ':'.join(parts[2:])  # Gabungkan sisa sebagai password
                
                # Bersihkan URL
                url = url.strip()
                username = username.strip()
                password = password.strip()
                
                credentials.append({
                    'url': url,
                    'username': username,
                    'password': password
                })
    
    except FileNotFoundError:
        print(f"[!] File {file_path} tidak ditemukan!")
        sys.exit(1)
    
    return credentials

def main():
    parser = argparse.ArgumentParser(
        description='Joomla Checker Login - Cek hak akses Administrator atau User',
        epilog='Contoh: python joomla_checker.py --list list.txt'
    )
    
    parser.add_argument(
        '--list', '-l',
        type=str,
        required=True,
        help='File list.txt dengan format url:username:password'
    )
    
    parser.add_argument(
        '--output', '-o',
        type=str,
        help='File output untuk menyimpan hasil'
    )
    
    args = parser.parse_args()
    
    print(f"[+] Membaca file: {args.list}")
    credentials = parse_list_file(args.list)
    print(f"[+] Ditemukan {len(credentials)} target\n")
    
    results = []
    
    for i, cred in enumerate(credentials, 1):
        print(f"[{i}/{len(credentials)}] Mencoba: {cred['url']}")
        print(f"    Username: {cred['username']}")
        print(f"    Password: {cred['password']}")
        
        result = check_joomla_login(
            cred['url'],
            cred['username'],
            cred['password']
        )
        
        if result['success']:
            print(f"    [✓] BERHASIL LOGIN!")
            print(f"    [✓] Hak Akses: {result['role']}")
            print(f"    [✓] URL Admin: {result['url']}\n")
            
            results.append({
                'status': 'BERHASIL',
                'url': result['url'],
                'username': result['username'],
                'password': result['password'],
                'role': result['role']
            })
        else:
            print(f"    [✗] GAGAL: {result.get('error', 'Unknown error')}\n")
            
            results.append({
                'status': 'GAGAL',
                'url': cred['url'],
                'username': cred['username'],
                'password': cred['password'],
                'error': result.get('error', 'Unknown error')
            })
    
    # Tampilkan ringkasan
    print("\n" + "="*60)
    print("RINGKASAN HASIL:")
    print("="*60)
    
    successful = [r for r in results if r['status'] == 'BERHASIL']
    
    if successful:
        print(f"\n[✓] BERHASIL ({len(successful)}):")
        for r in successful:
            print(f"    - {r['url']}")
            print(f"      Username: {r['username']}")
            print(f"      Password: {r['password']}")
            print(f"      Hak Akses: {r['role']}\n")
    else:
        print("\n[✗] Tidak ada yang berhasil login")
    
    # Simpan ke file jika diminta
    if args.output:
        with open(args.output, 'w') as f:
            for r in results:
                if r['status'] == 'BERHASIL':
                    f.write(f"[BERHASIL] {r['url']} | {r['username']} | {r['password']} | Role: {r['role']}\n")
                else:
                    f.write(f"[GAGAL] {r['url']} | {r['username']} | {r['password']} | Error: {r['error']}\n")
        
        print(f"\n[+] Hasil disimpan ke: {args.output}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Dihentikan oleh user")
        sys.exit(0)
