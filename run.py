#!/usr/bin/env python3
import os
import sys
import subprocess
import random
import secrets
import string
from pathlib import Path
import requests
import zipfile
import stat
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import datetime
import shutil

def run_cmd(cmd, check=True, capture_output=False, text=True):
    """تشغيل أمر shell مع طباعة مخرجاته في الوقت الحقيقي"""
    if capture_output:
        result = subprocess.run(cmd, shell=True, check=check, capture_output=True, text=text)
        return result.stdout.strip()
    else:
        process = subprocess.Popen(cmd, shell=True)
        process.communicate()
        if check and process.returncode != 0:
            raise subprocess.CalledProcessError(process.returncode, cmd)

def is_root():
    return os.geteuid() == 0

def generate_self_signed_cert(cert_path, key_path):
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
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(alt_names, critical=False)
        .sign(key, hashes.SHA256(), default_backend())
    )

    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def download_file(url, output_path):
    print(f"Downloading {url} ...")
    r = requests.get(url, stream=True)
    r.raise_for_status()
    with open(output_path, "wb") as f:
        for chunk in r.iter_content(chunk_size=8192):
            f.write(chunk)
    print(f"Saved to {output_path}")

def extract_zip(zip_path, extract_to):
    print(f"Extracting {zip_path} ...")
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_to)
    print(f"Extracted to {extract_to}")

def make_executable(path):
    st = os.stat(path)
    os.chmod(path, st.st_mode | stat.S_IEXEC)

def main():
    IS_RENDER = bool(os.environ.get("RENDER"))
    if not is_root() and not IS_RENDER:
        print("This script must be run as root on non-Render servers", file=sys.stderr)
        sys.exit(1)

    CONFIG_DIR = "/etc/3proxy"
    LOG_DIR = "/var/log/3proxy"
    BIN_DIR = "/usr/local/bin"

    if IS_RENDER:
        home = os.environ.get("HOME", "/tmp")
        CONFIG_DIR = os.path.join(home, ".3proxy")
        LOG_DIR = os.path.join(CONFIG_DIR, "logs")

    Path(CONFIG_DIR).mkdir(parents=True, exist_ok=True)
    Path(LOG_DIR).mkdir(parents=True, exist_ok=True)
    Path(BIN_DIR).mkdir(parents=True, exist_ok=True)

    RANDOM_PORT = random.randint(30000, 60000)
    HTTP_PORT = random.randint(30000, 60000)
    HTTPS_PORT = random.randint(30000, 60000)

    PROXY_USER = "u" + secrets.token_hex(3)
    allowed_chars = string.ascii_letters + string.digits + "!@#"
    PROXY_PASS = ''.join(secrets.choice(allowed_chars) for _ in range(20))

    print(f"Generated ports and credentials:")
    print(f"SOCKS5 port: {RANDOM_PORT}")
    print(f"HTTP port: {HTTP_PORT}")
    print(f"HTTPS port: {HTTPS_PORT}")
    print(f"Proxy user: {PROXY_USER}")
    print(f"Proxy password: {PROXY_PASS}")

    # ======= تحميل نسخة 3proxy جاهزة للينكس 64 بت =======
    # يمكنك تغيير الرابط إلى نسخة أخرى إذا أردت
    url = "https://github.com/3proxy/3proxy/releases/latest/download/3proxy-linux-x64.zip"
    tmp_zip = "/tmp/3proxy-linux-x64.zip"
    tmp_extract_dir = "/tmp/3proxy-linux-x64"

    download_file(url, tmp_zip)

    # إزالة مجلد فك الضغط إذا موجود
    if os.path.exists(tmp_extract_dir):
        shutil.rmtree(tmp_extract_dir)

    extract_zip(tmp_zip, tmp_extract_dir)

    # النسخ إلى BIN_DIR
    src_binary = os.path.join(tmp_extract_dir, "3proxy")
    if not os.path.isfile(src_binary):
        print("ERROR: 3proxy binary not found in extracted files.")
        sys.exit(1)

    dst_binary = os.path.join(BIN_DIR, "3proxy")
    shutil.copy2(src_binary, dst_binary)
    make_executable(dst_binary)

    # توليد شهادة TLS
    print("Generating stealth SSL certificate...")
    key_path = os.path.join(CONFIG_DIR, "key.pem")
    cert_path = os.path.join(CONFIG_DIR, "cert.pem")
    generate_self_signed_cert(cert_path, key_path)

    # تكوين البروكسي
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

    # إعدادات Render الخاصة
    if IS_RENDER:
        print("Setting up Render-specific settings...")
        fake_response_path = os.path.join(CONFIG_DIR, "fake_response")
        fake_response_content = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>404 Not Found</body></html>"
        with open(fake_response_path, "w", encoding="utf-8") as f:
            f.write(fake_response_content)

        subprocess.Popen(
            ["socat", f"TCP-LISTEN:80,fork,reuseaddr", f"FILE:{fake_response_path}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        proxy_log = os.path.join(LOG_DIR, "proxy.log")
        run_cmd(f"nohup {dst_binary} {config_file_path} > {proxy_log} 2>&1 &")
    else:
        print("Skipping iptables and systemd setup since this is not Render environment.")

    # عرض المعلومات
    print("Fetching public IP...")
    try:
        PUBLIC_IP = requests.get("https://ifconfig.me").text.strip()
    except Exception:
        PUBLIC_IP = "Unavailable"

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

    # تنظيف الملفات المؤقتة
    try:
        os.remove(tmp_zip)
        shutil.rmtree(tmp_extract_dir)
    except Exception:
        pass

if __name__ == "__main__":
    main()
