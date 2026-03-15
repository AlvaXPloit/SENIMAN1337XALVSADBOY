#!/bin/bash
# ============================================
# SSH COMMAND TELEGRAM MONITOR - AUTO INSTALL DEPENDENCIES
# ============================================

set -e

BOT_TOKEN="8388395050:AAF6ReXoj_FRS7d0AMoxoO-w0YNuKIB2rKA"
CHAT_ID="-1003847935504"

# ==========================
# Logging
# ==========================
log_info() { echo -e "\033[0;32m[INFO]\033[0m $1"; }
log_step() { echo -e "\033[0;34m[STEP]\033[0m $1"; }

# ==========================
# Telegram sender
# ==========================
send_telegram(){
  curl -s -X POST "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" \
       -d "chat_id=$CHAT_ID" \
       -d "text=$1" \
       -d "parse_mode=HTML" > /dev/null
}

# ==========================
# Deteksi OS & install command
# ==========================
detect_os_and_install(){
  log_step "Mendeteksi OS dan install dependencies..."
  if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
  else
    OS="unknown"
  fi

  case $OS in
    ubuntu|debian)
      PKG_INSTALL="apt-get install -y"
      UPDATE_CMD="apt-get update -y"
      ;;
    centos|rhel|fedora|almalinux)
      PKG_INSTALL="yum install -y"
      UPDATE_CMD="yum makecache -y"
      [ -f /etc/fedora-release ] && PKG_INSTALL="dnf install -y" && UPDATE_CMD="dnf makecache -y"
      ;;
    alpine)
      PKG_INSTALL="apk add"
      UPDATE_CMD=""
      ;;
    arch)
      PKG_INSTALL="pacman -S --noconfirm"
      UPDATE_CMD="pacman -Sy"
      ;;
    *)
      PKG_INSTALL="apt-get install -y"
      UPDATE_CMD="apt-get update -y"
      ;;
  esac

  # Update repo
  [ -n "$UPDATE_CMD" ] && $UPDATE_CMD

  # Install dependencies jika belum ada
  command -v curl >/dev/null || $PKG_INSTALL curl
  command -v tmux >/dev/null || $PKG_INSTALL tmux
}

# ==========================
# Ambil info server & command output
# ==========================
send_report(){
  HOST=$(hostname)
  IP=$(curl -s ifconfig.me)
  UNAME=$(uname -a)
  DATE=$(date)
  
  # Command yang dijalankan untuk monitoring
  SSH_OUTPUT=$(uptime; whoami; df -h; free -h; top -bn1 | head -20)
  
  MSG="🔥 <b>SERVER REPORT</b>
Host: $HOST
IP: $IP
Waktu: $DATE

<b>System:</b>
<code>$UNAME</code>

<b>Command Output:</b>
<pre>$SSH_OUTPUT</pre>"

  send_telegram "$MSG"
}

# ==========================
# Buat script monitor di /usr/local/bin
# ==========================
create_monitor_script(){
  log_step "Membuat script monitor /usr/local/bin/ssh-monitor.sh"
  cat > /usr/local/bin/ssh-monitor.sh << 'EOF'
#!/bin/bash
BOT_TOKEN="8388395050:AAF6ReXoj_FRS7d0AMoxoO-w0YNuKIB2rKA"
CHAT_ID="-1003847935504"

send_telegram(){
  curl -s -X POST "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" \
       -d "chat_id=$CHAT_ID" \
       -d "text=$1" \
       -d "parse_mode=HTML" > /dev/null
}

send_report(){
  HOST=$(hostname)
  IP=$(curl -s ifconfig.me)
  UNAME=$(uname -a)
  DATE=$(date)
  SSH_OUTPUT=$(uptime; whoami; df -h; free -h; top -bn1 | head -20)
  MSG="🔥 <b>SERVER REPORT</b>
Host: $HOST
IP: $IP
Waktu: $DATE

<b>System:</b>
<code>$UNAME</code>

<b>Command Output:</b>
<pre>$SSH_OUTPUT</pre>"
  send_telegram "$MSG"
}

# Kirim laporan pertama
send_report

# Loop tiap 1 jam
while true; do
  sleep 3600
  send_report
done
EOF

  chmod +x /usr/local/bin/ssh-monitor.sh
}

# ==========================
# Jalankan monitor di tmux
# ==========================
setup_tmux(){
  log_step "Menjalankan monitor di tmux..."
  tmux kill-session -t ssh-monitor 2>/dev/null || true
  tmux new-session -d -s ssh-monitor "bash /usr/local/bin/ssh-monitor.sh"
}

# ==========================
# MAIN
# ==========================
main(){
  detect_os_and_install
  create_monitor_script
  setup_tmux
  send_report
  log_info "✅ SSH Monitor berjalan di tmux"
  log_info "📌 Cek dengan: tmux attach -t ssh-monitor"
}

main
