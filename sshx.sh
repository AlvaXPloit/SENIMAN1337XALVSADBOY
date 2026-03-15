#!/bin/bash

# ============================================
# SSHX TELEGRAM MONITOR - FINAL VERSION
# PASTI KIRIM OUTPUT SSHX + LINK KE TELEGRAM
# ============================================

# Konfigurasi Telegram
BOT_TOKEN="8388395050:AAF6ReXoj_FRS7d0AMoxoO-w0YNuKIB2rKA"
CHAT_ID="-1003847935504"

# Warna output
NC='\033[0m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'

# ============================================
# FUNGSI UTILITY
# ============================================
print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_step() {
    echo -e "${BLUE}[→]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# ============================================
# CEK DAN INSTALL DEPENDENCIES
# ============================================
install_dependencies() {
    print_step "Mengecek dependencies..."
    
    # Deteksi OS
    if [ -f /etc/debian_version ]; then
        PKG_MANAGER="apt-get"
        INSTALL_CMD="apt-get install -y"
    elif [ -f /etc/redhat-release ]; then
        PKG_MANAGER="yum"
        INSTALL_CMD="yum install -y"
    else
        PKG_MANAGER="apt-get"
        INSTALL_CMD="apt-get install -y"
    fi
    
    # Update dan install curl
    if ! command -v curl &> /dev/null; then
        print_step "Menginstall curl..."
        $PKG_MANAGER update -y > /dev/null 2>&1
        $INSTALL_CMD curl > /dev/null 2>&1
        print_status "Curl terinstall"
    fi
    
    # Install tmux
    if ! command -v tmux &> /dev/null; then
        print_step "Menginstall tmux..."
        $INSTALL_CMD tmux > /dev/null 2>&1
        print_status "Tmux terinstall"
    fi
    
    # Install sshx
    if ! command -v sshx &> /dev/null; then
        print_step "Menginstall sshx..."
        curl -fsSL https://sshx.io/get | bash > /dev/null 2>&1
        export PATH=$PATH:$HOME/.sshx/bin
        print_status "SSHX terinstall"
    fi
    
    print_status "Semua dependencies siap"
}

# ============================================
# FUNGSI KIRIM TELEGRAM
# ============================================
send_telegram() {
    local message="$1"
    curl -s -X POST "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" \
        -d "chat_id=$CHAT_ID" \
        -d "text=$message" \
        -d "parse_mode=HTML" > /dev/null
}

# ============================================
# TEST SSHX
# ============================================
test_sshx() {
    print_step "Testing SSHX..."
    
    # Test dengan timeout 5 detik
    SSHX_TEST=$(timeout 5 sshx 2>&1)
    SSHX_LINK=$(echo "$SSHX_TEST" | grep -o 'https://sshx.io/s/[^ ]*' | head -1)
    
    if [ -n "$SSHX_LINK" ]; then
        print_status "SSHX bekerja! Link: $SSHX_LINK"
        return 0
    else
        print_warn "SSHX mungkin butuh waktu lebih lama"
        return 1
    fi
}

# ============================================
# BUAT SCRIPT MONITOR
# ============================================
create_monitor_script() {
    print_step "Membuat script monitor..."
    
    cat > /usr/local/bin/sshx-monitor.sh << 'EOF'
#!/bin/bash

# ============================================
# SSHX MONITOR CORE - PASTI KIRIM OUTPUT
# ============================================

BOT_TOKEN="8388395050:AAF6ReXoj_FRS7d0AMoxoO-w0YNuKIB2rKA"
CHAT_ID="-1003847935504"

# File untuk menyimpan link terakhir
LAST_LINK_FILE="/tmp/sshx_last_link.txt"
COUNTER_FILE="/tmp/sshx_counter.txt"
FIRST_RUN_FILE="/tmp/sshx_first_done.txt"

# Initialize
echo "0" > $COUNTER_FILE

# ============================================
# FUNGSI KIRIM TELEGRAM
# ============================================
send_telegram() {
    curl -s -X POST "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" \
        -d "chat_id=$CHAT_ID" \
        -d "text=$1" \
        -d "parse_mode=HTML" > /dev/null
}

# ============================================
# FUNGSI DAPATKAN OUTPUT SSHX LENGKAP
# ============================================
get_sshx_output() {
    # Jalankan sshx selama 3 detik untuk dapat output
    OUTPUT=$(timeout 3 sshx 2>&1)
    echo "$OUTPUT"
}

# ============================================
# FUNGSI DAPATKAN INFO SERVER
# ============================================
get_server_info() {
    HOSTNAME=$(hostname)
    IP_PUBLIC=$(curl -s ifconfig.me 2>/dev/null || echo "Unknown")
    UPTIME=$(uptime | sed 's/.*up //; s/,.*//')
    DISK=$(df -h / | awk 'NR==2 {print $5 " used of " $2}')
    DATE=$(date "+%Y-%m-%d %H:%M:%S")
    
    echo "━━━━━━━━━━━━━━━━━━━━━"
    echo "🖥️  Host: $HOSTNAME"
    echo "🌐 IP: $IP_PUBLIC"
    echo "⏰ Waktu: $DATE"
    echo "📊 Uptime: $UPTIME"
    echo "💾 Disk: $DISK"
}

# ============================================
# MAIN LOOP
# ============================================
main() {
    local counter=0
    local first_run=1
    
    # Kirim notifikasi start
    START_MSG="🚀 <b>SSHX MONITOR DIMULAI</b>%0A"
    START_MSG+="$(get_server_info | sed 's/━//g' | sed ':a;N;$!ba;s/\n/%0A/g')%0A"
    START_MSG+="━━━━━━━━━━━━━━━━━━━━━%0A"
    START_MSG+="⏳ Menunggu 10 detik untuk output pertama..."
    
    send_telegram "$START_MSG"
    
    while true; do
        # 10 DETIK PERTAMA - KIRIM OUTPUT LENGKAP
        if [ $first_run -eq 1 ]; then
            sleep 10
            
            # Ambil output sshx
            SSHX_OUTPUT=$(get_sshx_output)
            SSHX_LINK=$(echo "$SSHX_OUTPUT" | grep -o 'https://sshx.io/s/[^ ]*' | head -1)
            
            # Simpan link
            echo "$SSHX_LINK" > "$LAST_LINK_FILE"
            
            # Format pesan untuk Telegram
            PESAN="🔥 <b>SSHX OUTPUT LENGKAP</b>%0A"
            PESAN+="━━━━━━━━━━━━━━━━━━━━━%0A"
            PESAN+="$(get_server_info | sed 's/━//g' | sed ':a;N;$!ba;s/\n/%0A/g')%0A"
            PESAN+="━━━━━━━━━━━━━━━━━━━━━%0A"
            PESAN+="<b>📟 OUTPUT SSHX:</b>%0A"
            PESAN+="<code>${SSHX_OUTPUT}</code>%0A"
            PESAN+="━━━━━━━━━━━━━━━━━━━━━%0A"
            PESAN+="<b>🔗 LINK:</b> <code>${SSHX_LINK}</code>%0A"
            PESAN+="━━━━━━━━━━━━━━━━━━━━━%0A"
            PESAN+="⏱️ Report berikutnya: 1 jam lagi"
            
            send_telegram "$PESAN"
            
            first_run=0
            counter=0
            continue
        fi
        
        # SETIAP 1 JAM
        if [ $counter -ge 3600 ]; then
            # Ambil output sshx terbaru
            SSHX_OUTPUT=$(get_sshx_output)
            SSHX_LINK=$(echo "$SSHX_OUTPUT" | grep -o 'https://sshx.io/s/[^ ]*' | head -1)
            
            if [ -n "$SSHX_LINK" ]; then
                echo "$SSHX_LINK" > "$LAST_LINK_FILE"
                LINK_STATUS="$SSHX_LINK"
            else
                LINK_STATUS=$(cat "$LAST_LINK_FILE" 2>/dev/null || echo "Tidak ada link")
            fi
            
            # Ambil info tambahan
            LOAD=$(uptime | awk -F'load average:' '{print $2}')
            MEMORY=$(free -h | grep Mem | awk '{print $3 "/" $2}')
            
            PESAN="📊 <b>LAPORAN 1 JAM</b>%0A"
            PESAN+="━━━━━━━━━━━━━━━━━━━━━%0A"
            PESAN+="$(get_server_info | sed 's/━//g' | sed ':a;N;$!ba;s/\n/%0A/g')%0A"
            PESAN+="📈 Load: $LOAD%0A"
            PESAN+="🧠 RAM: $MEMORY%0A"
            PESAN+="━━━━━━━━━━━━━━━━━━━━━%0A"
            PESAN+="<b>📟 OUTPUT SSHX:</b>%0A"
            PESAN+="<code>${SSHX_OUTPUT:-Output tidak tersedia}</code>%0A"
            PESAN+="━━━━━━━━━━━━━━━━━━━━━%0A"
            PESAN+="<b>🔗 LINK:</b> <code>$LINK_STATUS</code>%0A"
            PESAN+="━━━━━━━━━━━━━━━━━━━━━%0A"
            PESAN+="⏱️ Next report: +1 jam"
            
            send_telegram "$PESAN"
            counter=0
        fi
        
        sleep 10
        counter=$((counter + 10))
    done
}

# Trap untuk exit
trap 'send_telegram "⚠️ <b>SSHX MONITOR STOPPED</b> $(date)"' EXIT

# Jalankan main
main
EOF

    chmod +x /usr/local/bin/sshx-monitor.sh
    print_status "Script monitor dibuat di /usr/local/bin/sshx-monitor.sh"
}

# ============================================
# SETUP TMUX
# ============================================
setup_tmux() {
    print_step "Setup tmux..."
    
    # Kill session lama jika ada
    tmux kill-session -t sshx-monitor 2>/dev/null || true
    
    # Buat session baru
    tmux new-session -d -s sshx-monitor
    
    # Jalankan script
    tmux send-keys -t sshx-monitor "bash /usr/local/bin/sshx-monitor.sh" C-m
    
    print_status "Tmux session 'sshx-monitor' dibuat"
    
    # Setup auto-start di cron (optional)
    (crontab -l 2>/dev/null | grep -v "sshx-monitor"; echo "@reboot sleep 10 && tmux new-session -d -s sshx-monitor 'bash /usr/local/bin/sshx-monitor.sh'") | crontab - 2>/dev/null || true
    print_status "Auto-start via crontab ditambahkan"
}

# ============================================
# TEST KIRIM TELEGRAM
# ============================================
test_telegram() {
    print_step "Mengirim test message ke Telegram..."
    
    HOSTNAME=$(hostname)
    IP=$(curl -s ifconfig.me 2>/dev/null || echo "Unknown")
    
    TEST_MSG="✅ <b>INSTALASI SSHX MONITOR BERHASIL</b>%0A"
    TEST_MSG+="━━━━━━━━━━━━━━━━━━━━━%0A"
    TEST_MSG+="• Hostname: $HOSTNAME%0A"
    TEST_MSG+="• IP: $IP%0A"
    TEST_MSG+="• Waktu: $(date)%0A"
    TEST_MSG+="━━━━━━━━━━━━━━━━━━━━━%0A"
    TEST_MSG+="⏳ Dalam 10 detik...%0A"
    TEST_MSG+="Output SSHX LENGKAP akan dikirim!"
    
    send_telegram "$TEST_MSG"
    print_status "Test message terkirim"
}

# ============================================
# TAMPILAN INFO
# ============================================
show_info() {
    echo ""
    echo "${GREEN}╔════════════════════════════════════════════════════════╗${NC}"
    echo "${GREEN}║         INSTALASI SELESAI! 🎉                          ║${NC}"
    echo "${GREEN}║   OUTPUT SSHX AKAN DIKIRIM KE TELEGRAM                 ║${NC}"
    echo "${GREEN}╚════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "${YELLOW}📋 INFORMASI MONITOR:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "📌 Tmux session: ${BLUE}sshx-monitor${NC}"
    echo "📌 Script utama: ${BLUE}/usr/local/bin/sshx-monitor.sh${NC}"
    echo ""
    echo "${GREEN}✅ PERINTAH PENTING:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "• Lihat proses langsung: ${YELLOW}tmux attach -t sshx-monitor${NC}"
    echo "• Keluar tmux (tanpa stop): ${YELLOW}Ctrl+B lalu D${NC}"
    echo "• Stop monitor: ${YELLOW}tmux kill-session -t sshx-monitor${NC}"
    echo "• Restart monitor: ${YELLOW}tmux new-session -d -s sshx-monitor 'bash /usr/local/bin/sshx-monitor.sh'${NC}"
    echo "• Lihat log: ${YELLOW}tail -f /tmp/sshx_*.txt${NC}"
    echo ""
    echo "${GREEN}✅ CEK TELEGRAM ANDA!${NC}"
    echo "Pesan test sudah dikirim. Tunggu 10 detik untuk output SSHX pertama."
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# ============================================
# MAIN FUNCTION
# ============================================
main() {
    clear
    echo "${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
    echo "${BLUE}║     SSHX TELEGRAM MONITOR - FINAL VERSION              ║${NC}"
    echo "${BLUE}║     PASTI KIRIM OUTPUT SSHX LENGKAP                    ║${NC}"
    echo "${BLUE}╚════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Install dependencies
    install_dependencies
    
    # Test SSHX
    test_sshx
    
    # Buat script monitor
    create_monitor_script
    
    # Setup tmux
    setup_tmux
    
    # Test kirim Telegram
    test_telegram
    
    # Tampilkan info
    show_info
}

# Jalankan main
main
exit 0
