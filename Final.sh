#!/bin/bash

# Stop script on error
set -e

# Check if running as root (غير مطلوب على Render)
if [ "$(id -u)" -ne 0 ] && [ -z "$RENDER" ]; then
  echo "This script must be run as root on non-Render servers" >&2
  exit 1
fi

# ---- [1] إعدادات أولية ----
IS_RENDER=${RENDER:+true}
CONFIG_DIR="/etc/3proxy"
LOG_DIR="/var/log/3proxy"
BIN_DIR="/usr/local/bin"
[ "$IS_RENDER" = true ] && CONFIG_DIR="$HOME/.3proxy" && LOG_DIR="$CONFIG_DIR/logs"

# ---- [2] توليد بيانات عشوائية ----
RANDOM_PORT=$(shuf -i 30000-60000 -n 1)
HTTP_PORT=$(shuf -i 30000-60000 -n 1)
HTTPS_PORT=$(shuf -i 30000-60000 -n 1)
PROXY_USER="u$(openssl rand -hex 3)"
PROXY_PASS=$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9!@#' | head -c 20)

# ---- [3] تثبيت التبعيات ----
echo "Installing dependencies..."
if [ "$IS_RENDER" = true ]; then
  # إعدادات خاصة بـ Render
  sudo apt-get update
  sudo apt-get install -y build-essential openssl libssl-dev wget unzip iptables
else
  # إعدادات الخادم العادي
  apt-get update
  apt-get install -y build-essential openssl libssl-dev wget iptables-persistent unzip
fi

# ---- [4] تنزيل وتجميع 3proxy ----
echo "Downloading and compiling 3proxy..."
wget -q https://github.com/3proxy/3proxy/archive/refs/heads/master.zip -O /tmp/3proxy.zip
unzip -q /tmp/3proxy.zip -d /tmp
cd /tmp/3proxy-master

# تطبيق تصحيحات الأمان
sed -i 's/CFLAGS =/CFLAGS = -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE/' Makefile.Linux
sed -i 's/LDFLAGS =/LDFLAGS = -Wl,-z,now -Wl,-z,relro -pie/' Makefile.Linux

make -f Makefile.Linux
sudo cp src/3proxy "$BIN_DIR"

# ---- [5] شهادة TLS متقدمة ----
echo "Generating stealth SSL certificate..."
mkdir -p "$CONFIG_DIR"
openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
  -keyout "$CONFIG_DIR/key.pem" \
  -out "$CONFIG_DIR/cert.pem" \
  -subj "/CN=cloudflare.com" \
  -addext "subjectAltName=DNS:google.com,DNS:facebook.com"

# ---- [6] تكوين البروكسي ----
cat > "$CONFIG_DIR/3proxy.cfg" <<EOL
daemon
nolog
nscache 65536
nserver 1.1.1.1
nserver 9.9.9.9
dnspr

# إخفاء الهوية
header "Via:"
header "Proxy-Connection:"
header "X-Forwarded-For:"

# SOCKS5 مع تشفير DNS
socks -p$RANDOM_PORT -a -n -i0.0.0.0 --socks -dns

# HTTPS Proxy مع TLS خادع
https -p$HTTPS_PORT -a -c"$CONFIG_DIR/cert.pem" -k"$CONFIG_DIR/key.pem" -n -i0.0.0.0

# HTTP (اختياري)
proxy -p$HTTP_PORT -a -n -i0.0.0.0

# حماية متقدمة
auth strong
users $PROXY_USER:CL:$PROXY_PASS
deny * * 22,53,80,443,8080
acl {
    deny * * *proxy*,*scan*,*detect*
}
limit req * * * 5
maxconn 100
EOL

# ---- [7] إعدادات Render الخاصة ----
if [ "$IS_RENDER" = true ]; then
  # تمويه كخدمة ويب
  echo "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>404 Not Found</body></html>" > "$CONFIG_DIR/fake_response"
  socat TCP-LISTEN:80,fork,reuseaddr FILE:"$CONFIG_DIR/fake_response" &
  
  # تشغيل مباشر (بدون systemd)
  nohup "$BIN_DIR/3proxy" "$CONFIG_DIR/3proxy.cfg" > "$LOG_DIR/proxy.log" 2>&1 &
else
  # ---- [8] إعدادات الخادم العادي ----
  # الجدار الناري
  iptables -A INPUT -p tcp --dport "$RANDOM_PORT" -j ACCEPT
  iptables -A INPUT -p tcp --dport "$HTTP_PORT" -j ACCEPT
  iptables -A INPUT -p tcp --dport "$HTTPS_PORT" -j ACCEPT
  iptables -A INPUT -p tcp -m multiport ! --dports "$RANDOM_PORT,$HTTP_PORT,$HTTPS_PORT" -j DROP
  iptables-save > /etc/iptables/rules.v4

  # خدمة systemd
  cat > /etc/systemd/system/3proxy.service <<EOL
[Unit]
Description=3Proxy Stealth Proxy Server
After=network.target

[Service]
Type=simple
ExecStart=$BIN_DIR/3proxy $CONFIG_DIR/3proxy.cfg
Restart=always
User=nobody
Group=nogroup
LimitNOFILE=65535
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
PrivateTmp=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOL

  systemctl daemon-reload
  systemctl enable 3proxy
  systemctl start 3proxy

  # تعطيل ICMP
  echo "net.ipv4.icmp_echo_ignore_all = 1" >> /etc/sysctl.conf
  sysctl -p
fi

# ---- [9] عرض المعلومات ----
PUBLIC_IP=$(curl -s ifconfig.me)
clear
echo -e "\e[32m✅ البروكسي الخفي يعمل الآن!\e[0m"
echo -e "\e[36m🌍 عنوان السيرفر:\e[0m $PUBLIC_IP"
echo -e "\e[36m🔒 SOCKS5:\e[0m $PUBLIC_IP:$RANDOM_PORT"
echo -e "\e[36m🔐 HTTPS:\e[0m $PUBLIC_IP:$HTTPS_PORT"
echo -e "\e[36m👤 المستخدم:\e[0m $PROXY_USER"
echo -e "\e[36m🔑 كلمة المرور:\e[0m $PROXY_PASS"
echo -e "\n\e[33m🔍 نصائح الأمان:\e[0m"
echo -e "1. استخدم HTTPS Proxy دائمًا للاتصالات المهمة"
echo -e "2. غير المنافذ والبيانات كل أسبوع"
echo -e "3. على Render، استخدم منفذًا بين 10000-65535"

# التنظيف
rm -rf /tmp/3proxy-master /tmp/3proxy.zip