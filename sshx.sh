#!/bin/bash

# ============================================
# SSHX Telegram Monitor - Auto Installer
# DENGAN OUTPUT SSHX LENGKAP SEPERTI DI TERMINAL
# ============================================

set -e

# Warna
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# ============================================
# Konfigurasi Telegram
# ============================================
BOT_TOKEN="8388395050:AAF6ReXoj_FRS7d0AMoxoO-w0YNuKIB2rKA"
CHAT_ID="-1003847935504"
REPORT_INTERVAL=3600

# ============================================
# Fungsi Logging
# ============================================
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "${BLUE}[STEP]${NC} $1"; }

# ============================================
# Fungsi Deteksi OS
# ============================================
detect_os() {
    log_step "Mendeteksi sistem operasi..."
    
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
    else
        OS=$(uname -s)
        VER=$(uname -r)
    fi
    
    case $OS in
        ubuntu|debian)
            PKG_MANAGER="apt-get"
            INSTALL_CMD="apt-get install -y"
            log_info "Deteksi: Ubuntu/Debian"
            ;;
        centos|rhel|fedora)
            PKG_MANAGER="yum"
            INSTALL_CMD="yum install -y"
            [ -f /etc/fedora-release ] && PKG_MANAGER="dnf" && INSTALL_CMD="dnf install -y"
            log_info "Deteksi: CentOS/RHEL/Fedora"
            ;;
        alpine)
            PKG_MANAGER="apk"
            INSTALL_CMD="apk add"
            log_info "Deteksi: Alpine Linux"
            ;;
        arch)
            PKG_MANAGER="pacman"
            INSTALL_CMD="pacman -S --noconfirm"
            log_info "Deteksi: Arch Linux"
            ;;
        *)
            log_error "OS tidak dikenal: $OS"
            exit 1
            ;;
    esac
    
    echo "OS=$OS" > /tmp/sshx_os_detected
    echo "PKG_MANAGER=$PKG_MANAGER" >> /tmp/sshx_os_detected
}

# ============================================
# Fungsi Install Dependencies
# ============================================
install_dependencies() {
    log_step "Menginstall dependencies..."
    
    if [ "$PKG_MANAGER" = "apt-get" ]; then
        apt-get update -y
    elif [ "$PKG_MANAGER" = "yum" ] || [ "$PKG_MANAGER" = "dnf" ]; then
        $PKG_MANAGER update -y
    fi
    
    command -v curl &> /dev/null || $INSTALL_CMD curl
    command -v tmux &> /dev/null || $INSTALL_CMD tmux
    command -v jq &> /dev/null || $INSTALL_CMD jq
    command -v script &> /dev/null || $INSTALL_CMD util-linux  # untuk script command
    
    if ! command -v sshx &> /dev/null; then
        log_info "Menginstall sshx..."
        curl -fsSL https://sshx.io/get | bash
        export PATH=$PATH:$HOME/.sshx/bin
    fi
    
    log_info "Semua dependencies terinstall"
}

# ============================================
# Fungsi Kirim ke Telegram
# ============================================
send_telegram() {
    curl -s -X POST "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" \
        -d "chat_id=$CHAT_ID" \
        -d "text=$1" \
        -d "parse_mode=HTML" > /dev/null
}

# ============================================
# Fungsi Buat Script Monitor
# ============================================
create_monitor_script() {
    log_step "Membuat script monitor dengan output SSHX LENGKAP..."
    
    cat > /usr/local/bin/sshx-telegram-monitor.sh << 'EOF'
#!/bin/bash

# ============================================
# SSHX Telegram Monitor - CORE SCRIPT
# DENGAN OUTPUT SSHX LENGKAP SEPERTI DI TERMINAL
# ============================================

BOT_TOKEN="8388395050:AAF6ReXoj_FRS7d0AMoxoO-w0YNuKIB2rKA"
CHAT_ID="-1003847935504"
REPORT_INTERVAL=3600

# Temporary files
TEMP_DIR="/tmp/sshx-monitor"
mkdir -p $TEMP_DIR
SSHX_OUTPUT_FILE="$TEMP_DIR/sshx_output.txt"
LINK_FILE="$TEMP_DIR/link.txt"
COUNTER_FILE="$TEMP_DIR/counter"
FIRST_DONE_FILE="$TEMP_DIR/first_done"

# Initialize
echo "0" > $COUNTER_FILE

# ============================================
# Fungsi Kirim Telegram
# ============================================
send_telegram() {
    curl -s -X POST "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" \
        -d "chat_id=$CHAT_ID" \
        -d "text=$1" \
        -d "parse_mode=HTML" > /dev/null
}

# ============================================
# Fungsi Capture Output SSHX LENGKAP
# ============================================
capture_sshx_output() {
    local output_file="$TEMP_DIR/sshx_capture_$$.txt"
    local timeout_duration=3
    
    echo "📡 Mengcapture output sshx..." > "$output_file"
    echo "" >> "$output_file"
    
    # Gunakan 'script' untuk capture output persis seperti terminal
    script -q -c "timeout $timeout_duration sshx" "$output_file" > /dev/null 2>&1
    
    # Baca file dan filter
    if [ -f "$output_file" ]; then
        # Hapus karakter control dan simpan output bersih
        cat "$output_file" | strings > "${output_file}.clean"
        cat "${output_file}.clean"
        rm -f "$output_file" "${output_file}.clean"
    fi
}

# ============================================
# Fungsi Dapatkan Link SSHX
# ============================================
get_sshx_link() {
    sshx --quiet 2>&1 | grep -o 'https://sshx.io/s/[^ ]*' | head -1
}

# ============================================
# Fungsi Dapatkan Info Sistem
# ============================================
get_system_info() {
    HOSTNAME=$(hostname)
    IP_PUBLIC=$(curl -s ifconfig.me || echo "Unknown")
    DATE=$(date "+%Y-%m-%d %H:%M:%S")
    UNAME=$(uname -a)
    
    echo "━━━━━━━━━━━━━━━━━━━━━
🖥️ HOST: $HOSTNAME | IP: $IP_PUBLIC
📅 WAKTU: $DATE
🔧 UNAME: $UNAME"
}

# ============================================
# MAIN LOOP
# ============================================
main() {
    local counter=0
    local first_run=1
    
    # Kirim notifikasi start
    send_telegram "🚀 <b>SSHX MONITOR START</b>
$(get_system_info)
⏳ Menunggu 10 detik untuk capture output SSHX..."
    
    while true; do
        # 10 DETIK PERTAMA - CAPTURE OUTPUT SSHX LENGKAP
        if [ $first_run -eq 1 ]; then
            sleep 10
            
            log_info "10 detik pertama - Mengcapture output sshx..."
            
            # Capture output sshx persis seperti di terminal
            SSHX_FULL_OUTPUT=$(capture_sshx_output)
            
            # Dapatkan link dari output
            SSHX_LINK=$(echo "$SSHX_FULL_OUTPUT" | grep -o 'https://sshx.io/s/[^ ]*' | head -1)
            echo "$SSHX_LINK" > "$LINK_FILE"
            
            # Format pesan untuk Telegram
            DETAIL_MSG="🔥 <b>SSHX OUTPUT LENGKAP (10 DETIK PERTAMA)</b>
$(get_system_info)

━━━━━━━━━━━━━━━━━━━━━
<b>📟 OUTPUT SSHX:</b>
<code>${SSHX_FULL_OUTPUT:-Tidak ada output}</code>

━━━━━━━━━━━━━━━━━━━━━
<b>🔗 LINK:</b> <code>${SSHX_LINK:-Tidak dapat link}</code>
━━━━━━━━━━━━━━━━━━━━━
⏱️ Selanjutnya: Report setiap 1 jam"
            
            # Kirim ke Telegram
            send_telegram "$DETAIL_MSG"
            
            first_run=0
            counter=0
            continue
        fi
        
        # REPORT SETIAP 1 JAM
        if [ $counter -ge 3600 ]; then
            # Capture output sshx terbaru
            SSHX_OUTPUT=$(capture_sshx_output)
            SSHX_LINK=$(echo "$SSHX_OUTPUT" | grep -o 'https://sshx.io/s/[^ ]*' | head -1)
            
            if [ -n "$SSHX_LINK" ]; then
                echo "$SSHX_LINK" > "$LINK_FILE"
                LINK_STATUS="$SSHX_LINK"
            else
                LINK_STATUS=$(cat "$LINK_FILE" 2>/dev/null || echo "Tidak ada link")
            fi
            
            # Ambil informasi tambahan
            UPTIME=$(uptime)
            DF_OUTPUT=$(df -h | grep -E '^/dev/' | head -3)
            FREE_OUTPUT=$(free -h)
            
            HOURLY_MSG="📊 <b>LAPORAN PER JAM</b>
$(get_system_info)

━━━━━━━━━━━━━━━━━━━━━
<b>🔗 LINK SSHX:</b> <code>$LINK_STATUS</code>

<b>📟 OUTPUT SSHX:</b>
<code>${SSHX_OUTPUT:-Output tidak tersedia}</code>

━━━━━━━━━━━━━━━━━━━━━
<b>⏰ UPTIME:</b> $UPTIME

<b>💾 DISK:</b>
<code>$DF_OUTPUT</code>

<b>🧠 MEMORY:</b>
<code>$FREE_OUTPUT</code>
━━━━━━━━━━━━━━━━━━━━━
⏱️ Next report: +1 jam"
            
            send_telegram "$HOURLY_MSG"
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

    chmod +x /usr/local/bin/sshx-telegram-monitor.sh
    log_info "Script monitor dibuat di /usr/local/bin/sshx-telegram-monitor.sh"
}

# ============================================
# Fungsi Setup Tmux
# ============================================
setup_tmux_and_start() {
    log_step "Setup tmux..."
    
    tmux kill-session -t sshx-monitor 2>/dev/null || true
    tmux new-session -d -s sshx-monitor
    tmux send-keys -t sshx-monitor "bash /usr/local/bin/sshx-telegram-monitor.sh" C-m
    
    # Auto-start on boot
    (crontab -l 2>/dev/null | grep -v "sshx-telegram-monitor"; echo "@reboot sleep 10 && tmux new-session -d -s sshx-monitor 'bash /usr/local/bin/sshx-telegram-monitor.sh'") | crontab -
    
    log_info "Tmux session 'sshx-monitor' created"
}

# ============================================
# Main Execution
# ============================================
main() {
    clear
    echo "${BLUE}╔════════════════════════════════════════════════════════╗"
    echo "║     SSHX MONITOR - OUTPUT LENGKAP KE TELEGRAM          ║"
    echo "║     Format: Seperti yang Anda lihat di terminal!       ║"
    echo "╚════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    detect_os
    install_dependencies
    create_monitor_script
    setup_tmux_and_start
    
    # Kirim notifikasi
    HOSTNAME=$(hostname)
    IP=$(curl -s ifconfig.me)
    
    send_telegram "✅ <b>SSHX MONITOR TERINSTAL</b>
• Hostname: $HOSTNAME
• IP: $IP
• Waktu: $(date)
━━━━━━━━━━━━━━━━━━━━━
⏳ Tunggu 10 detik...
Output SSHX LENGKAP akan dikirim!"
    
    show_usage_info
}

# ============================================
# Info Penggunaan
# ============================================
show_usage_info() {
    cat << EOF

${GREEN}╔════════════════════════════════════════════════════════╗
║         INSTALASI SELESAI! 🎉                          ║
║   OUTPUT SSHX LENGKAP AKAN DIKIRIM KE TELEGRAM         ║
╚════════════════════════════════════════════════════════╝${NC}

${BLUE}📌 STATUS:${NC}
• Monitor berjalan di tmux session: ${YELLOW}sshx-monitor${NC}
• Akan mengirim output SSHX persis seperti di terminal:
  ${YELLOW}sshx v0.4.1
  ➜ Link: https://sshx.io/s/xxxx
  ➜ Shell: /bin/bash${NC}

${GREEN}✅ CEK TELEGRAM ANDA!${NC}
Dalam 10 detik akan menerima output SSHX LENGKAP.

${BLUE}📋 PERINTAH:${NC}
• Lihat langsung: ${YELLOW}tmux attach -t sshx-monitor${NC}
• Keluar tmux: ${YELLOW}Ctrl+B lalu D${NC}
• Stop monitor: ${YELLOW}tmux kill-session -t sshx-monitor${NC}
• Restart: ${YELLOW}tmux new-session -d -s sshx-monitor 'bash /usr/local/bin/sshx-telegram-monitor.sh'${NC}

EOF
}

# Jalankan
main
exit 0
