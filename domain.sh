#!/bin/bash

echo "================================================="
echo "        UNIVERSAL SERVER DOMAIN ENUMERATOR"
echo "================================================="

SERVER_IP=$(curl -s ifconfig.me)
HOSTNAME=$(hostname)

echo "[+] Hostname : $HOSTNAME"
echo "[+] Server IP: $SERVER_IP"
echo ""

TMP=$(mktemp)

#################################################
# DETECT PANEL
#################################################

echo "[+] Detect panel hosting..."

[ -d "/usr/local/cpanel" ] && echo "Panel : cPanel"
[ -d "/usr/local/psa" ] && echo "Panel : Plesk"
[ -d "/usr/local/CyberCP" ] && echo "Panel : CyberPanel"

echo ""

#################################################
# SCAN CONF FILES
#################################################

echo "[+] Scan config server..."

find /etc /usr/local /var -type f -name "*.conf" 2>/dev/null | while read conf
do

grep -E "server_name|ServerName|ServerAlias|vhDomain|domain" $conf 2>/dev/null \
| sed -E 's/.*(server_name|ServerName|ServerAlias|vhDomain)[[:space:]]+//' \
| sed 's/;//g' \
>> $TMP

done

#################################################
# NGINX
#################################################

grep -R "server_name" /etc/nginx 2>/dev/null \
| awk '{print $2}' | sed 's/;//' >> $TMP

#################################################
# APACHE
#################################################

grep -R "ServerName" /etc/apache2 /etc/httpd 2>/dev/null \
| awk '{print $2}' >> $TMP

grep -R "ServerAlias" /etc/apache2 /etc/httpd 2>/dev/null \
| awk '{print $2}' >> $TMP

#################################################
# OPENLITESPEED
#################################################

grep -R "vhDomain" /usr/local/lsws 2>/dev/null \
| awk '{print $2}' >> $TMP

#################################################
# CPANEL DOMAIN
#################################################

if [ -d "/var/cpanel/users" ]; then

for f in /var/cpanel/users/*; do
grep DNS $f 2>/dev/null | awk '{print $2}' >> $TMP
done

fi

#################################################
# PLESK DOMAIN
#################################################

ls /var/www/vhosts 2>/dev/null >> $TMP

#################################################
# USER WEBROOT
#################################################

for d in /home/*/public_html; do
domain=$(basename $(dirname $d))
echo "$domain" >> $TMP
done

#################################################
# CLEAN DOMAIN LIST
#################################################

DOMAINS=$(cat $TMP | tr ' ' '\n' | sed '/^$/d' | sort -u)

echo ""
echo "================================================="
echo "                DOMAIN FOUND"
echo "================================================="

echo "$DOMAINS"

echo ""
echo "================================================="
echo "              DOMAIN CHECK RESULT"
echo "================================================="

for domain in $DOMAINS
do

[ -z "$domain" ] && continue

echo ""
echo "----------------------------------------------"
echo "[*] DOMAIN : $domain"

IP=$(dig +short $domain | head -n1)

echo "[+] DOMAIN IP : $IP"

if [ "$IP" == "$SERVER_IP" ]; then
echo "[✓] DOMAIN ADA DI SERVER INI"
else
echo "[!] DOMAIN DI SERVER LAIN"
fi

STATUS=$(curl -m 5 -o /dev/null -s -w "%{http_code}" http://$domain)

echo "[+] HTTP STATUS : $STATUS"

done

rm -f $TMP

echo ""
echo "================================================="
echo "                 SCAN COMPLETE"
echo "================================================="
