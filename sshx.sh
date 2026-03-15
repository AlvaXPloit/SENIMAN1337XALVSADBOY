#!/bin/bash
# ============================================
# SSH COMMAND TELEGRAM MONITOR - FINAL
# ============================================

set -e

BOT_TOKEN="8388395050:AAF6ReXoj_FRS7d0AMoxoO-w0YNuKIB2rKA"
CHAT_ID="-1003847935504"

# Kirim pesan ke Telegram
send_telegram(){
  curl -s -X POST "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" \
       -d "chat_id=$CHAT_ID" \
       -d "text=$1" \
       -d "parse_mode=HTML" > /dev/null
}

# Ambil info server + output command
send_report(){
  HOST=$(hostname)
  IP=$(curl -s ifconfig.me)
  UNAME=$(uname -a)
  DATE=$(date)
  
  # Jalankan perintah SSH/Command di server ini
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

# Loop setiap 1 jam
while true; do
  sleep 3600
  send_report
done
