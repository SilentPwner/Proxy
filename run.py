import os
import sys
import subprocess
import random
import string
import secrets
import shutil
import zipfile
import urllib.request
import http.server
import socketserver
import threading
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta

# ---- [1] إعدادات أولية ----
IS_RENDER = bool(os.environ.get("RENDER"))
HOME = os.environ.get("HOME", "/tmp")
CONFIG_DIR = os.path.join(HOME, ".3proxy") if IS_RENDER else "/etc/3proxy"
LOG_DIR = os.path.join(CONFIG_DIR, "logs") if IS_RENDER else "/var/log/3proxy"
BIN_DIR = "/usr/local/bin"
os.makedirs(CONFIG_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

# ---- [2] توليد بيانات عشوائية ----
def random_port():
    return random.randint(30000, 60000)

def random_user():
    return "u" + secrets.token_hex(3)

def random_pass(length=20):
    chars = string.ascii_letters + string.digits + "!@#"
    return ''.join(secrets.choice(chars) for _ in range(length))

RANDOM_PORT = random_port()
HTTP_PORT = random_port()
HTTPS_PORT = random_port()
PROXY_USER = random_user()
PROXY_PASS = random_pass()

print("Generated ports and credentials:")
print(f"SOCKS5 port: {RANDOM_PORT}")
print(f"HTTP port: {HTTP_PORT}")
print(f"HTTPS port: {HTTPS_PORT}")
print(f"Proxy user: {PROXY_USER}")
print(f"Proxy password: {PROXY_PASS}")

# ---- [3] تثبيت التبعيات ----
# في بيئة Render لا يمكن تثبيت الحزم باستخدام apt أو sudo
print("\n[INFO] تأكد من أن التبعيات مثل gcc وopenssl مثبتة مسبقًا على النظام.")
print("[INFO] لا يمكن تثبيت الحزم تلقائياً في هذا السكربت بدون صلاحيات root.\n")

# ---- [4] تنزيل وتجميع 3proxy ----
TMP_DIR = "/tmp"
ZIP_PATH = os.path.join(TMP_DIR, "3proxy.zip")
SRC_DIR = os.path.join(TMP_DIR, "3proxy-master")

print("Downloading 3proxy source...")
urllib.request.urlretrieve(
    "https://github.com/3proxy/3proxy/archive/refs/heads/master.zip",
    ZIP_PATH
)

print("Extracting 3proxy...")
with zipfile.ZipFile(ZIP_PATH, 'r') as zip_ref:
    zip_ref.extractall(TMP_DIR)

# تطبيق تصحيحات الأمان على Makefile.Linux
makefile_path = os.path.join(SRC_DIR, "Makefile.Linux")

print("Patching Makefile for security flags...")
with open(makefile_path, "r", encoding="utf-8") as f:
    lines = f.readlines()

with open(makefile_path, "w", encoding="utf-8") as f:
    for line in lines:
        if line.startswith("CFLAGS ="):
            f.write("CFLAGS = -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE\n")
        elif line.startswith("LDFLAGS ="):
            f.write("LDFLAGS = -Wl,-z,now -Wl,-z,relro -pie\n")
        else:
            f.write(line)

print("Compiling 3proxy...")
# تشغيل make
# **هنا لا يمكن استخدام sudo، لذا تأكد أن المستخدم لديه صلاحيات كافية**
make_cmd = ["make", "-f", "Makefile.Linux"]
try:
    subprocess.run(make_cmd, cwd=SRC_DIR, check=True)
except subprocess.CalledProcessError as e:
    print("Error during compilation:", e)
    sys.exit(1)

# نسخ الملف التنفيذي
src_bin = os.path.join(SRC_DIR, "src", "3proxy")
dst_bin = os.path.join(BIN_DIR, "3proxy")

try:
    shutil.copy2(src_bin, dst_bin)
    print(f"Copied 3proxy binary to {dst_bin}")
except PermissionError:
    print(f"Permission denied copying binary to {dst_bin}. Please copy manually if needed.")
except Exception as e:
    print(f"Error copying binary: {e}")

# ---- [5] شهادة TLS متقدمة ----
print("Generating stealth SSL certificate...")

def generate_self_signed_cert(cert_path, key_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"cloudflare.com"),
    ])

    san = x509.SubjectAlternativeName([
        x509.DNSName(u"google.com"),
        x509.DNSName(u"facebook.com"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(san, critical=False)
        .sign(key, hashes.SHA256())
    )

    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

cert_file = os.path.join(CONFIG_DIR, "cert.pem")
key_file = os.path.join(CONFIG_DIR, "key.pem")
os.makedirs(CONFIG_DIR, exist_ok=True)
generate_self_signed_cert(cert_file, key_file)

# ---- [6] تكوين البروكسي ----
config_content = f"""\
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
socks -p{RANDOM_PORT} -a -n -i0.0.0.0 --socks -dns

# HTTPS Proxy مع TLS خادع
https -p{HTTPS_PORT} -a -c"{cert_file}" -k"{key_file}" -n -i0.0.0.0

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

config_path = os.path.join(CONFIG_DIR, "3proxy.cfg")
with open(config_path, "w", encoding="utf-8") as f:
    f.write(config_content)

print(f"3proxy configuration saved to {config_path}")

# ---- [7] تمويه HTTP بدل socat باستخدام خادم بايثون بسيط ----
class FakeHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(404)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body>404 Not Found</body></html>")

def run_fake_http_server():
    try:
        with socketserver.TCPServer(("", 80), FakeHandler) as httpd:
            print("Fake HTTP server running on port 80 (to mimic socat)...")
            httpd.serve_forever()
    except PermissionError:
        print("Cannot bind to port 80: Permission denied. Fake HTTP server will not run.")
    except Exception as e:
        print(f"Fake HTTP server error: {e}")

# ---- [8] تشغيل 3proxy بدون systemd وبدون iptables ----
print("\n[INFO] تشغيل 3proxy بدون systemd وبدون iptables (يجب تشغيل السكربت كمستخدم يملك صلاحيات كافية).")

def start_3proxy():
    try:
        log_file = os.path.join(LOG_DIR, "proxy.log")
        with open(log_file, "a") as logf:
            proc = subprocess.Popen(
                [dst_bin, config_path],
                stdout=logf,
                stderr=logf,
                preexec_fn=os.setpgrp  # تشغيل في مجموعة جديدة (اختياري)
            )
        print(f"3proxy started with PID {proc.pid}, logs: {log_file}")
    except Exception as e:
        print(f"Failed to start 3proxy: {e}")

# ---- [9] عرض المعلومات ----
def print_info():
    try:
        import requests
        public_ip = requests.get("https://ifconfig.me").text.strip()
    except Exception:
        public_ip = "Unavailable"

    print("\n✅ البروكسي الخفي يعمل الآن!")
    print(f"🌍 عنوان السيرفر: {public_ip}")
    print(f"🔒 SOCKS5: {public_ip}:{RANDOM_PORT}")
    print(f"🔐 HTTPS: {public_ip}:{HTTPS_PORT}")
    print(f"👤 المستخدم: {PROXY_USER}")
    print(f"🔑 كلمة المرور: {PROXY_PASS}")
    print("\n🔍 نصائح الأمان:")
    print("1. استخدم HTTPS Proxy دائمًا للاتصالات المهمة")
    print("2. غير المنافذ والبيانات كل أسبوع")
    print("3. على Render، استخدم منفذًا بين 10000-65535")

if __name__ == "__main__":
    # تشغيل تمويه HTTP في ثريد منفصل
    threading.Thread(target=run_fake_http_server, daemon=True).start()

    start_3proxy()
    print_info()

    # التنظيف مؤجلًا يمكن حذفه يدوياً بعد التشغيل
    shutil.rmtree(SRC_DIR, ignore_errors=True)
    try:
        os.remove(ZIP_PATH)
    except FileNotFoundError:
        pass
