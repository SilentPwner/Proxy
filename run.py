#!/usr/bin/env python3
import os
import sys
import subprocess
import random
import secrets
import string
from pathlib import Path

def run_cmd(cmd, check=True, capture_output=False, text=True):
    """تشغيل أمر shell مع طباعة مخرجاته في الوقت الحقيقي"""
    if capture_output:
        result = subprocess.run(cmd, shell=True, check=check, capture_output=True, text=text)
        return result.stdout.strip()
    else:
        # طباعة stdout و stderr بشكل مباشر
        process = subprocess.Popen(cmd, shell=True)
        process.communicate()
        if check and process.returncode != 0:
            raise subprocess.CalledProcessError(process.returncode, cmd)

def is_root():
    return os.geteuid() == 0

def main():
    # ---- [0] تحقق صلاحية root (غير مطلوب في Render) ----
    IS_RENDER = bool(os.environ.get("RENDER"))
    if not is_root() and not IS_RENDER:
        print("This script must be run as root on non-Render servers", file=sys.stderr)
        sys.exit(1)

    # ---- [1] إعدادات أولية ----
    CONFIG_DIR = "/etc/3proxy"
    LOG_DIR = "/var/log/3proxy"
    BIN_DIR = "/usr/local/bin"

    if IS_RENDER:
        home = os.environ.get("HOME", "/tmp")
        CONFIG_DIR = os.path.join(home, ".3proxy")
        LOG_DIR = os.path.join(CONFIG_DIR, "logs")

    Path(CONFIG_DIR).mkdir(parents=True, exist_ok=True)
    Path(LOG_DIR).mkdir(parents=True, exist_ok=True)

    # ---- [2] توليد بيانات عشوائية ----
    RANDOM_PORT = random.randint(30000, 60000)
    HTTP_PORT = random.randint(30000, 60000)
    HTTPS_PORT = random.randint(30000, 60000)

    # توليد اسم مستخدم وكلمة مرور Proxy
    PROXY_USER = "u" + secrets.token_hex(3)
    allowed_chars = string.ascii_letters + string.digits + "!@#"
    PROXY_PASS = ''.join(secrets.choice(allowed_chars) for _ in range(20))

    print(f"Generated ports and credentials:")
    print(f"SOCKS5 port: {RANDOM_PORT}")
    print(f"HTTP port: {HTTP_PORT}")
    print(f"HTTPS port: {HTTPS_PORT}")
    print(f"Proxy user: {PROXY_USER}")
    print(f"Proxy password: {PROXY_PASS}")

    # ---- [3] تثبيت التبعيات ----
    print("Installing dependencies...")
    if IS_RENDER:
        run_cmd("apt-get update")
        run_cmd("apt-get install -y build-essential openssl libssl-dev wget unzip iptables")
    else:
        run_cmd("apt-get update")
        run_cmd("apt-get install -y build-essential openssl libssl-dev wget iptables-persistent unzip")

    # ---- [4] تنزيل وتجميع 3proxy ----
    print("Downloading and compiling 3proxy...")
    run_cmd("wget -q https://github.com/3proxy/3proxy/archive/refs/heads/master.zip -O /tmp/3proxy.zip")
    run_cmd("unzip -q /tmp/3proxy.zip -d /tmp")
    os.chdir("/tmp/3proxy-master")

    # تعديل Makefile لتحسين الأمان (مثل في bash)
    run_cmd("sed -i 's/CFLAGS =/CFLAGS = -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE/' Makefile.Linux")
    run_cmd("sed -i 's/LDFLAGS =/LDFLAGS = -Wl,-z,now -Wl,-z,relro -pie/' Makefile.Linux")

    # تجميع
    run_cmd("make -f Makefile.Linux")

    # نسخ الملف التنفيذي
    run_cmd(f"sudo cp src/3proxy {BIN_DIR}")

    # ---- [5] شهادة TLS متقدمة ----
    print("Generating stealth SSL certificate...")
    key_path = os.path.join(CONFIG_DIR, "key.pem")
    cert_path = os.path.join(CONFIG_DIR, "cert.pem")
    Path(CONFIG_DIR).mkdir(parents=True, exist_ok=True)

    openssl_cmd = (
        f"openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes "
        f"-keyout {key_path} "
        f"-out {cert_path} "
        f"-subj \"/CN=cloudflare.com\" "
        f"-addext \"subjectAltName=DNS:google.com,DNS:facebook.com\""
    )
    run_cmd(openssl_cmd)

    # ---- [6] تكوين البروكسي ----
    config_file_path = os.path.join(CONFIG_DIR, "3proxy.cfg")
    config_content = f"""daemon
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
socks -p{RANDOM_PORT} -a -n -i0.0.0.0 --socks -dns

# HTTPS Proxy مع TLS خادع
https -p{HTTPS_PORT} -a -c"{cert_path}" -k"{key_path}" -n -i0.0.0.0

# HTTP (اختياري)
proxy -p{HTTP_PORT} -a -n -i0.0.0.0

# حماية متقدمة
auth strong
users {PROXY_USER}:CL:{PROXY_PASS}
deny * * 22,53,80,443,8080
acl {{
    deny * * *proxy*,*scan*,*detect*
}}
limit req * * * 5
maxconn 100
"""

    with open(config_file_path, "w", encoding="utf-8") as f:
        f.write(config_content)

    # ---- [7] إعدادات Render الخاصة ----
    if IS_RENDER:
        print("Setting up Render-specific settings...")
        fake_response_path = os.path.join(CONFIG_DIR, "fake_response")
        fake_response_content = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>404 Not Found</body></html>"
        with open(fake_response_path, "w", encoding="utf-8") as f:
            f.write(fake_response_content)

        # تشغيل socat لخدمة التمويه
        subprocess.Popen(
            ["socat", f"TCP-LISTEN:80,fork,reuseaddr", f"FILE:{fake_response_path}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # تشغيل 3proxy في الخلفية (بدون systemd)
        # استخدم nohup و redirct الإخراج إلى ملف اللوج
        proxy_log = os.path.join(LOG_DIR, "proxy.log")
        run_cmd(f"nohup {BIN_DIR}/3proxy {config_file_path} > {proxy_log} 2>&1 &")

    else:
        # ---- [8] إعدادات الخادم العادي ----
        print("Setting up firewall and systemd service for normal server...")

        run_cmd(f"iptables -A INPUT -p tcp --dport {RANDOM_PORT} -j ACCEPT")
        run_cmd(f"iptables -A INPUT -p tcp --dport {HTTP_PORT} -j ACCEPT")
        run_cmd(f"iptables -A INPUT -p tcp --dport {HTTPS_PORT} -j ACCEPT")
        run_cmd(f"iptables -A INPUT -p tcp -m multiport ! --dports {RANDOM_PORT},{HTTP_PORT},{HTTPS_PORT} -j DROP")
        run_cmd("iptables-save > /etc/iptables/rules.v4")

        systemd_service_content = f"""[Unit]
Description=3Proxy Stealth Proxy Server
After=network.target

[Service]
Type=simple
ExecStart={BIN_DIR}/3proxy {config_file_path}
Restart=always
User=nobody
Group=nogroup
LimitNOFILE=65535
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
PrivateTmp=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
"""

        systemd_service_path = "/etc/systemd/system/3proxy.service"
        with open(systemd_service_path, "w", encoding="utf-8") as f:
            f.write(systemd_service_content)

        run_cmd("systemctl daemon-reload")
        run_cmd("systemctl enable 3proxy")
        run_cmd("systemctl start 3proxy")

        # تعطيل ICMP
        with open("/etc/sysctl.conf", "a", encoding="utf-8") as f:
            f.write("\nnet.ipv4.icmp_echo_ignore_all = 1\n")
        run_cmd("sysctl -p")

    # ---- [9] عرض المعلومات ----
    print("Fetching public IP...")
    PUBLIC_IP = run_cmd("curl -s ifconfig.me", capture_output=True)

    # تنظيف الشاشة (اختياري)
    run_cmd("clear")

    print(f"\033[32m✅ البروكسي الخفي يعمل الآن!\033[0m")
    print(f"\033[36m🌍 عنوان السيرفر:\033[0m {PUBLIC_IP}")
    print(f"\033[36m🔒 SOCKS5:\033[0m {PUBLIC_IP}:{RANDOM_PORT}")
    print(f"\033[36m🔐 HTTPS:\033[0m {PUBLIC_IP}:{HTTPS_PORT}")
    print(f"\033[36m👤 المستخدم:\033[0m {PROXY_USER}")
    print(f"\033[36m🔑 كلمة المرور:\033[0m {PROXY_PASS}")
    print()
    print(f"\033[33m🔍 نصائح الأمان:\033[0m")
    print("1. استخدم HTTPS Proxy دائمًا للاتصالات المهمة")
    print("2. غير المنافذ والبيانات كل أسبوع")
    print("3. على Render، استخدم منفذًا بين 10000-65535")

    # ---- التنظيف ----
    run_cmd("rm -rf /tmp/3proxy-master /tmp/3proxy.zip")

if __name__ == "__main__":
    main()
