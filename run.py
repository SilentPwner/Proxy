#!/usr/bin/env python3
import os
import sys
import shutil
import subprocess
import random
import string
import base64
import tempfile
import zipfile
import http.server
import socketserver
import threading
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import requests

# ==== إعدادات أولية ====
IS_RENDER = bool(os.environ.get("RENDER"))
HOME = os.environ.get("HOME", "/root")

CONFIG_DIR = Path("/etc/3proxy")
LOG_DIR = Path("/var/log/3proxy")
BIN_DIR = Path("/usr/local/bin")

if IS_RENDER:
    CONFIG_DIR = Path(HOME) / ".3proxy"
    LOG_DIR = CONFIG_DIR / "logs"

# ==== توليد بيانات عشوائية ====

def random_port():
    return random.randint(30000, 60000)

def random_username():
    return "u" + ''.join(random.choices(string.hexdigits.lower(), k=6))

def random_password():
    allowed = string.ascii_letters + string.digits + "!@#"
    raw = base64.b64encode(os.urandom(24)).decode('ascii')
    filtered = ''.join(c for c in raw if c in allowed)
    return filtered[:20]

RANDOM_PORT = random_port()
HTTP_PORT = random_port()
HTTPS_PORT = random_port()
PROXY_USER = random_username()
PROXY_PASS = random_password()

# ==== تنزيل وتجميع 3proxy ====

def download_and_extract_3proxy():
    tmp_dir = tempfile.mkdtemp()
    zip_path = Path(tmp_dir) / "3proxy.zip"
    print("[*] Downloading 3proxy source code...")
    url = "https://github.com/3proxy/3proxy/archive/refs/heads/master.zip"
    resp = requests.get(url)
    resp.raise_for_status()
    with open(zip_path, "wb") as f:
        f.write(resp.content)
    print("[*] Extracting...")
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(tmp_dir)
    src_dir = Path(tmp_dir) / "3proxy-master"
    return tmp_dir, src_dir

def apply_security_patches(makefile_path):
    print("[*] Applying security patches to Makefile.Linux...")
    with open(makefile_path, "r") as f:
        content = f.read()
    content = content.replace("CFLAGS =", "CFLAGS = -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE")
    content = content.replace("LDFLAGS =", "LDFLAGS = -Wl,-z,now -Wl,-z,relro -pie")
    with open(makefile_path, "w") as f:
        f.write(content)

def compile_3proxy(src_dir):
    print("[*] Compiling 3proxy...")
    makefile = src_dir / "Makefile.Linux"
    apply_security_patches(makefile)
    # Run make
    result = subprocess.run(["make", "-f", str(makefile)], cwd=src_dir)
    if result.returncode != 0:
        raise RuntimeError("make failed")
    # Copy binary
    src_bin = src_dir / "src" / "3proxy"
    if not src_bin.exists():
        raise FileNotFoundError("Compiled 3proxy binary not found!")
    dest_bin = BIN_DIR / "3proxy"
    print(f"[*] Copying 3proxy binary to {dest_bin} ...")
    dest_bin.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src_bin, dest_bin)
    os.chmod(dest_bin, 0o755)

# ==== إنشاء شهادة TLS خادعة ====

def generate_tls_cert(cert_path: Path, key_path: Path):
    print("[*] Generating stealth SSL certificate...")
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"cloudflare.com"),
    ])
    alt_names = x509.SubjectAlternativeName([
        x509.DNSName(u"google.com"),
        x509.DNSName(u"facebook.com"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(x509.datetime.datetime.utcnow())
        .not_valid_after(x509.datetime.datetime.utcnow() + x509.datetime.timedelta(days=365))
        .add_extension(alt_names, critical=False)
        .sign(key, hashes.SHA256(), default_backend())
    )
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

# ==== إعداد ملف تكوين 3proxy ====

def write_3proxy_config(config_path: Path, user: str, password: str):
    print("[*] Writing 3proxy configuration...")
    content = f"""daemon
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
https -p{HTTPS_PORT} -a -c"{CONFIG_DIR}/cert.pem" -k"{CONFIG_DIR}/key.pem" -n -i0.0.0.0

# HTTP (اختياري)
proxy -p{HTTP_PORT} -a -n -i0.0.0.0

# حماية متقدمة
auth strong
users {user}:CL:{password}
deny * * 22,53,80,443,8080
acl {{
    deny * * *proxy*,*scan*,*detect*
}}
limit req * * * 5
maxconn 100
"""
    config_path.parent.mkdir(parents=True, exist_ok=True)
    with open(config_path, "w") as f:
        f.write(content)

# ==== تمويه HTTP بسيط ====

class FakeHTTPHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(404)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body>404 Not Found</body></html>")

def start_fake_http_server():
    try:
        server = socketserver.TCPServer(("", 80), FakeHTTPHandler)
    except OSError as e:
        print(f"[!] Failed to bind to port 80 for fake HTTP server: {e}")
        return None
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print("[*] Fake HTTP server started on port 80")
    return server

# ==== تشغيل 3proxy ====

def run_3proxy():
    bin_path = BIN_DIR / "3proxy"
    config_path = CONFIG_DIR / "3proxy.cfg"
    log_path = LOG_DIR / "proxy.log"
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    print("[*] Starting 3proxy...")
    # nohup-like launch
    with open(log_path, "a") as log_file:
        process = subprocess.Popen(
            [str(bin_path), str(config_path)],
            stdout=log_file,
            stderr=log_file,
            preexec_fn=os.setpgrp
        )
    print(f"[*] 3proxy is running with PID {process.pid}")
    return process

# ==== الحصول على IP عام ====

def get_public_ip():
    try:
        ip = requests.get("https://ifconfig.me", timeout=10).text.strip()
        return ip
    except Exception:
        return "Unknown"

# ==== البرنامج الرئيسي ====

def main():
    # تأكد من الصلاحيات (غير مطلوب على Render)
    if (os.geteuid() != 0) and (not IS_RENDER):
        print("[!] This script must be run as root on non-Render servers.", file=sys.stderr)
        sys.exit(1)

    print("[*] Using Render environment:", IS_RENDER)
    print(f"[*] Ports: SOCKS5={RANDOM_PORT}, HTTP={HTTP_PORT}, HTTPS={HTTPS_PORT}")
    print(f"[*] Proxy credentials: user={PROXY_USER}, pass={PROXY_PASS}")

    # تحميل وتجميع 3proxy
    tmp_dir, src_dir = download_and_extract_3proxy()
    try:
        compile_3proxy(src_dir)
    except Exception as e:
        print("[!] Failed to compile 3proxy:", e)
        print("[!] You may want to manually install 3proxy binary and place it in", BIN_DIR)
        # محاولة تحميل مسبق بديل يمكن اضافته هنا إذا ترغب
        sys.exit(1)
    finally:
        shutil.rmtree(tmp_dir)

    # إنشاء الشهادات
    generate_tls_cert(CONFIG_DIR / "cert.pem", CONFIG_DIR / "key.pem")

    # كتابة ملف التكوين
    write_3proxy_config(CONFIG_DIR / "3proxy.cfg", PROXY_USER, PROXY_PASS)

    # تمويه HTTP (بديل socat)
    fake_http_server = None
    if IS_RENDER:
        fake_http_server = start_fake_http_server()

    # تشغيل 3proxy
    proxy_process = run_3proxy()

    # تعطيل ICMP (اختياري)
    # يمكن إلغاء التعليق إذا تريد تنفيذ ذلك:
    # subprocess.run(["sysctl", "-w", "net.ipv4.icmp_echo_ignore_all=1"], check=True)

    # عرض المعلومات
    public_ip = get_public_ip()
    os.system('clear' if os.name == 'posix' else 'cls')
    print(f"\033[32m✅ البروكسي الخفي يعمل الآن!\033[0m")
    print(f"\033[36m🌍 عنوان السيرفر:\033[0m {public_ip}")
    print(f"\033[36m🔒 SOCKS5:\033[0m {public_ip}:{RANDOM_PORT}")
    print(f"\033[36m🔐 HTTPS:\033[0m {public_ip}:{HTTPS_PORT}")
    print(f"\033[36m👤 المستخدم:\033[0m {PROXY_USER}")
    print(f"\033[36m🔑 كلمة المرور:\033[0m {PROXY_PASS}")
    print("\n\033[33m🔍 نصائح الأمان:\033[0m")
    print("1. استخدم HTTPS Proxy دائمًا للاتصالات المهمة")
    print("2. غير المنافذ والبيانات كل أسبوع")
    print("3. على Render، استخدم منفذًا بين 10000-65535")

    # بقاء البرنامج يعمل لمنع خروج خادم HTTP الوهمي و3proxy
    if IS_RENDER and fake_http_server is not None:
        try:
            print("\n[*] Press Ctrl+C to exit and stop the proxy...")
            while True:
                proxy_process.poll()
                if proxy_process.returncode is not None:
                    print("[!] 3proxy process exited unexpectedly!")
                    break
                threading.Event().wait(1)
        except KeyboardInterrupt:
            print("\n[*] Shutting down...")
            proxy_process.terminate()
            fake_http_server.shutdown()
    else:
        print("[*] Proxy started. To stop, kill the process manually.")

if __name__ == "__main__":
    main()
