#!/bin/bash

echo "======================================"
echo " UNIVERSAL DOMAIN + PATH CHECKER"
echo "======================================"

SERVER_IP=$(curl -s ifconfig.me)

echo "Server IP : $SERVER_IP"
echo ""

TMPFILE=$(mktemp)

# =========================
# NGiNX
# =========================
grep -R "server_name" /etc/nginx 2>/dev/null | while read line
do
domain=$(echo $line | awk '{print $2}' | sed 's/;//')

conf=$(echo $line | cut -d: -f1)

path=$(grep root $conf | head -n1 | awk '{print $2}' | sed 's/;//')

echo "$domain|$path" >> $TMPFILE

done


# =========================
# APACHE
# =========================
grep -R "ServerName" /etc/apache2 /etc/httpd 2>/dev/null | while read line
do
domain=$(echo $line | awk '{print $2}')

conf=$(echo $line | cut -d: -f1)

path=$(grep DocumentRoot $conf | awk '{print $2}')

echo "$domain|$path" >> $TMPFILE

done


# =========================
# OPENLITESPEED
# =========================
grep -R "vhDomain" /usr/local/lsws 2>/dev/null | while read line
do

domain=$(echo $line | awk '{print $2}')

conf=$(echo $line | cut -d: -f1)

path=$(grep vhRoot $conf | awk '{print $2}')

echo "$domain|$path" >> $TMPFILE

done


echo "============= DOMAIN FOUND ============="
cat $TMPFILE | sort -u
echo "========================================"
echo ""

while IFS="|" read domain path
do

echo "----------------------------------------"
echo "[*] DOMAIN : $domain"
echo "[+] PATH   : $path"

IP=$(dig +short $domain | head -n1)

echo "[+] DOMAIN IP : $IP"

if [ "$IP" == "$SERVER_IP" ]; then
echo "[✓] DOMAIN ADA DI SERVER INI"
else
echo "[!] DOMAIN DI SERVER LAIN"
fi

STATUS=$(curl -m 5 -o /dev/null -s -w "%{http_code}" http://$domain)

echo "[+] HTTP STATUS : $STATUS"

echo ""

done < <(cat $TMPFILE | sort -u)

rm -f $TMPFILE

echo "======================================"
echo "SCAN COMPLETE"
echo "======================================"
