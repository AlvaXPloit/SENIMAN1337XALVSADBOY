#!/bin/bash

# ============================================
# SSHX Telegram Monitor - SIMPLE VERSION
# PASTI KIRIM OUTPUT SSHX KE TELEGRAM
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

# ============================================
# Fungsi Logging
# ============================================
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_step() { echo -e "${BLUE}[STEP]${NC} $1"; }

# ============================================
# Fungsi Deteksi OS
# ============================================
detect_os() {
    log_step "Mendeteksi sistem operasi..."
    
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
    fi
    
    case $OS in
        ubuntu|debian)
            PKG_MANAGER="apt-get"
            INSTALL_CMD="apt-get install -y"
            ;;
        centos|rhel|fedora)
            PKG_MANAGER="yum"
            INSTALL_CMD="yum install -y"
            [ -f /etc/fedora-release ] && PKG_MANAGER="dnf" && INSTALL_CMD="dnf install -y"
            ;;
        alpine)
            PKG_MANAGER="apk"
            INSTALL_CMD="apk add"
            ;;
        arch)
            PKG_MANAGER="pacman"
            INSTALL_CMD="pacman -S --noconfirm"
            ;;
        *)
            PKG_MANAGER="apt-get"
            INSTALL_CMD="apt-get install -y"
            ;;
    esac
    
    log_info "OS: $OS, Package Manager: $PKG_MANAGER"
}

# ============================================
# Fungsi Install Dependencies
# ============================================
install_dependencies() {
    log_step "Menginstall dependencies..."
    
    if [ "$PKG_MANAGER" = "apt-get" ]; then
        apt-get update -y
    fi
    
    command -v curl &> /dev/null || $INSTALL_CMD curl
    command -v tmux &> /dev/null || $INSTALL_CMD tmux
    command -v sshx &> /dev/null || curl -fsSL https://sshx.io/get | bash
    
    # Pastikan sshx di PATH
    export PATH=$PATH:$HOME/.sshx/bin
    
    log_info "Dependencies selesai"
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
# BUAT SCRIPT MONITOR SEDERHANA
# ============================================
create_monitor_script() {
    log_step "Membuat script monitor SIMPLE..."
    
    cat > /usr/local/bin/sshx-simple-monitor.sh << 'EOF'
#!/bin/bash

# ============================================
# SSHX SIMPLE MONITOR - PASTI JALAN
# ============================================

BOT_TOKEN="8388395050:AAF6ReXoj_FRS7d0AMoxoO-w0YNuKIB2rKA"
CHAT_ID="-1003847935504"

# Fungsi kirim Telegram
send_telegram() {
    curl -s -X POST "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" \
        -d "chat_id=$CHAT_ID" \
        -d "text=$1" \
        -d "parse_mode=HTML" > /dev/null
}

# Fungsi dapatkan output sshx
get_sshx_output() {
    # Method 1: Langsung dengan timeout
    OUTPUT=$(timeout 3 sshx 2>&1)
    echo "$OUTPUT"
}

# Fungsi dapatkan link sshx
get_sshx_link() {
    sshx --quiet 2>&1 | grep -o 'https://sshx.io/s/[^ ]*' | head -1
}

# Kirim test dulu
send_telegram "🔧 <b>SSHX MONITOR DIMULAI</b>
Host: $(hostname)
Waktu: $(date)"

# Loop utama
COUNTER=0
FIRST=1

while true; do
    # 10 DETIK PERTAMA - KIRIM OUTPUT LENGKAP
    if [ $FIRST -eq 1 ]; then
        sleep 10
        
        # Ambil output sshx
        SSHX_OUTPUT=$(get_sshx_output)
        SSHX_LINK=$(get_sshx_link)
        
        # Format pesan
        PESAN="🔥 <b>SSHX OUTPUT ($(hostname))</b>
━━━━━━━━━━━━━━━━━━━━━
Waktu: $(date)
IP: $(curl -s ifconfig.me)

━━━━━━━━━━━━━━━━━━━━━
<b>📟 OUTPUT SSHX:</b>
<code>${SSHX_OUTPUT}</code>

━━━━━━━━━━━━━━━━━━━━━
<b>🔗 LINK:</b> <code>${SSHX_LINK}</code>
━━━━━━━━━━━━━━━━━━━━━"

        # Kirim
        send_telegram "$PESAN"
        
        FIRST=0
        COUNTER=0
    fi
    
    # SETIAP 1 JAM
    if [ $COUNTER -ge 3600 ]; then
        SSHX_OUTPUT=$(get_sshx_output)
        SSHX_LINK=$(get_sshx_link)
        
        PESAN="📊 <b>LAPORAN 1 JAM ($(hostname))</b>
━━━━━━━━━━━━━━━━━━━━━
Waktu: $(date)

<b>📟 OUTPUT SSHX:</b>
<code>${SSHX_OUTPUT}</code>

<b>🔗 LINK:</b> <code>${SSHX_LINK}</code>

<b>📈 SYSTEM:</b>
$(uptime)
$(df -h / | tail -1)
━━━━━━━━━━━━━━━━━━━━━"

        send_telegram "$PESAN"
        COUNTER=0
    fi
    
    sleep 10
    COUNTER=$((COUNTER + 10))
done
EOF

    chmod +x /usr/local/bin/sshx-simple-monitor.sh
    log_info "Script monitor dibuat"
}

# ============================================
# Setup Tmux
# ============================================
setup_tmux() {
    log_step "Setup tmux..."
    
    # Kill session lama jika ada
    tmux kill-session -t sshx-simple 2>/dev/null || true
    
    # Buat session baru
    tmux new-session -d -s sshx-simple
    
    # Jalankan script
    tmux send-keys -t sshx-simple "bash /usr/local/bin/sshx-simple-monitor.sh" C-m
    
    log_info "Tmux session 'sshx-simple' dibuat"
}

# ============================================
# Test Langsung
# ============================================
test_sshx() {
    log_step "Test sshx langsung..."
    
    # Coba jalankan sshx dan capture
    SSHX_TEST=$(timeout 3 sshx 2>&1)
    SSHX_LINK=$(echo "$SSHX_TEST" | grep -o 'https://sshx.io/s/[^ ]*' | head -1)
    
    log_info "Test output: $SSHX_TEST"
    
    if [ -n "$SSHX_LINK" ]; then
        log_info "✅ SSHX bekerja! Link: $SSHX_LINK"
    else
        log_warn "⚠️ SSHX mungkin perlu waktu lebih lama"
    fi
}

# ============================================
# Main
# ============================================
main() {
    clear
    echo "${BLUE}╔════════════════════════════════════════════════════════╗"
    echo "║        SSHX MONITOR - SIMPLE & PASTI JALAN             ║"
    echo "╚════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    detect_os
    install_dependencies
    test_sshx
    create_monitor_script
    setup_tmux
    
    # Kirim notifikasi
    HOSTNAME=$(hostname)
    IP=$(curl -s ifconfig.me)
    
    send_telegram "✅ <b>SSHX MONITOR SIAP</b>
• Hostname: $HOSTNAME
• IP: $IP
• Waktu: $(date)
━━━━━━━━━━━━━━━━━━━━━
⏳ Dalam 10 detik...
Output SSHX akan dikirim!"
    
    # Info
    echo ""
    echo "${GREEN}══════════════════════════════════════════════════════════${NC}"
    echo "${YELLOW}✅ MONITOR BERJALAN DI BACKGROUND${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "📌 Tmux session: ${BLUE}sshx-simple${NC}"
    echo "📌 Lihat langsung: ${GREEN}tmux attach -t sshx-simple${NC}"
    echo "📌 Keluar tmux: Ctrl+B lalu D"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "${GREEN}✅ CEK TELEGRAM ANDA!${NC}"
    echo "${GREEN}══════════════════════════════════════════════════════════${NC}"
}

# Jalankan
main
exit 0
