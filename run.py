#!/usr/bin/env python3
import asyncio
import socket
import ssl
import random
import secrets
import base64
import threading
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from flask import Flask, jsonify, request

# === [1] إعدادات عشوائية ===
def rand_port(): return random.randint(30000, 60000)

HTTP_PORT = rand_port()
SOCKS5_PORT = rand_port()
HTTPS_PORT = rand_port()

PROXY_USER = "u" + secrets.token_hex(3)
PROXY_PASS = ''.join(secrets.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#") for _ in range(20))

print(f"""
Proxy Credentials:
HTTP Proxy on port: {HTTP_PORT}
SOCKS5 Proxy on port: {SOCKS5_PORT}
Username: {PROXY_USER}
Password: {PROXY_PASS}
""")

# === [2] توليد شهادة TLS ذاتية ===
def gen_cert():
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"cloudflare.com")])
    san = x509.SubjectAlternativeName([x509.DNSName(u"google.com"), x509.DNSName(u"facebook.com")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(san, critical=False)
        .sign(key, hashes.SHA256(), backend=default_backend())
    )
    with open("key.pem", "wb") as f: f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    with open("cert.pem", "wb") as f: f.write(cert.public_bytes(serialization.Encoding.PEM))

gen_cert()

# === [3] HTTP 404 تمويه ===
class Fake404(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(404)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body>404 Not Found</body></html>")

def run_fake_http():
    try:
        HTTPServer(('0.0.0.0', 80), Fake404).serve_forever()
    except Exception as e:
        print("[Fake HTTP Server] Failed to bind to port 80:", e)

threading.Thread(target=run_fake_http, daemon=True).start()

# === [4] check_auth ===
def check_auth(hdr):
    if not hdr or not hdr.lower().startswith("basic "): return False
    try:
        _, enc = hdr.split(" ", 1)
        u, p = base64.b64decode(enc).decode().split(":", 1)
        return u == PROXY_USER and p == PROXY_PASS
    except:
        return False

# === [5] HTTP Proxy Protocol ===
class HTTPProxy(asyncio.Protocol):
    def __init__(self):
        self.transport = None
        self.buf = b""
        self.auth = False

    def connection_made(self, t):
        self.transport = t
        print("[HTTP] Conn from", t.get_extra_info('peername'))

    def data_received(self, data):
        self.buf += data
        if b"\r\n\r\n" not in self.buf: return
        hdr, body = self.buf.split(b"\r\n\r\n", 1)
        self.buf = b""
        lines = hdr.decode(errors="ignore").split("\r\n")
        req = lines[0]
        headers = {l.split(": ",1)[0].lower(): l.split(": ",1)[1] for l in lines[1:] if ": " in l}
        if not self.auth:
            if not check_auth(headers.get("proxy-authorization", "")):
                self.transport.write(b"HTTP/1.1 407 Proxy Auth Required\r\nProxy-Authenticate: Basic realm=\"3proxy\"\r\nContent-Length:0\r\n\r\n")
                self.transport.close()
                return
            self.auth = True
        if req.startswith("CONNECT"):
            host, port = req.split(" ")[1].split(":")
            asyncio.create_task(self.handle_connect(host, int(port)))
        else:
            asyncio.create_task(self.handle_http(req, headers, body))

    async def handle_connect(self, host, port):
        try:
            r, w = await asyncio.open_connection(host, port)
            self.transport.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await asyncio.gather(self.pipe(self.transport, w), self.pipe(r, self.transport))
        except Exception as e:
            print("[HTTP CONNECT error]", e)
            self.transport.close()

    async def handle_http(self, req, headers, body):
        m, path, v = req.split(" ")
        host = headers.get("host")
        if not host:
            return self.transport.close()
        try:
            r, w = await asyncio.open_connection(host, 80)
        except:
            self.transport.close(); return
        req_hdr = f"{m} {path} {v}\r\n"
        for k, v in headers.items():
            if k not in ("proxy-authorization", "via", "x-forwarded-for", "proxy-connection"):
                req_hdr += f"{k}: {v}\r\n"
        req_hdr += "\r\n"
        w.write(req_hdr.encode() + body)
        await w.drain()
        while True:
            chunk = await r.read(4096)
            if not chunk: break
            self.transport.write(chunk)
        w.close()
        await w.wait_closed()
        self.transport.close()

    async def pipe(self, reader, writer):
        loop = asyncio.get_running_loop()
        while True:
            data = await loop.run_in_executor(None, reader.read, 4096)
            if not data: break
            writer.write(data)
            await writer.drain()

# === [6] SOCKS5 Proxy Protocol ===
class SOCKS5Proto(asyncio.Protocol):
    def __init__(self):
        self.transport = None
        self.buf = b""
        self.stage = "NEG"
        self.auth_ok = False

    def connection_made(self, t):
        self.transport = t
        print("[SOCKS5] Conn from", t.get_extra_info('peername'))

    def data_received(self, data):
        self.buf += data
        if self.stage == "NEG": self.handle_neg(); return
        if self.stage == "AUTH": self.handle_auth(); return
        if self.stage == "REQ": self.handle_req()

    def handle_neg(self):
        if len(self.buf) < 2: return
        n = self.buf[1]
        if len(self.buf) < 2 + n: return
        self.buf = self.buf[2 + n:]
        self.transport.write(b"\x05\x02")
        self.stage = "AUTH"

    def handle_auth(self):
        if len(self.buf) < 2: return
        ulen = self.buf[1]
        if len(self.buf) < 2 + ulen: return
        user = self.buf[2:2 + ulen].decode()
        plen_start = 2 + ulen
        plen = self.buf[plen_start]
        if len(self.buf) < plen_start + 1 + plen: return
        pwd = self.buf[plen_start + 1:plen_start + 1 + plen].decode()
        self.buf = self.buf[plen_start + 1 + plen:]
        if user == PROXY_USER and pwd == PROXY_PASS:
            self.auth_ok = True
            self.transport.write(b"\x05\x00")
            self.stage = "REQ"
        else:
            self.transport.write(b"\x05\x01")
            self.transport.close()

    def handle_req(self):
        if len(self.buf) < 4: return
        cmd = self.buf[1]
        atype = self.buf[3]
        if atype == 1 and len(self.buf) >= 10:
            addr = socket.inet_ntoa(self.buf[4:8])
            port = int.from_bytes(self.buf[8:10], "big")
            self.buf = self.buf[10:]
        elif atype == 3:
            l = self.buf[4]
            addr = self.buf[5:5 + l].decode()
            port = int.from_bytes(self.buf[5 + l:5 + l + 2], "big")
            self.buf = self.buf[5 + l + 2:]
        else:
            return self.transport.close()
        if cmd != 1:
            return self.transport.close()
        asyncio.create_task(self.handle_socks(addr, port))

    async def handle_socks(self, addr, port):
        try:
            r, w = await asyncio.open_connection(addr, port)
            self.transport.write(b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + b"\x00\x00")
            await asyncio.gather(self.pipe(self.transport, w), self.pipe(r, self.transport))
        except Exception as e:
            print("[SOCKS5 error]", e)
            self.transport.close()

    async def pipe(self, reader, writer):
        loop = asyncio.get_running_loop()
        while True:
            data = await loop.run_in_executor(None, reader.read, 4096)
            if not data: break
            writer.write(data)
            await writer.drain()

# === [7] Flask Info واجهة عرض معلومات البروكسي ===
app = Flask(__name__)

@app.route("/", methods=["GET", "HEAD"])
def index():
    return "Welcome to your API testing platform!", 200

@app.route("/info", methods=["GET"])
def proxy_info():
    client_ip = request.remote_addr
    return jsonify({
        "client_ip": client_ip,
        "http_proxy": f"http://{client_ip}:{HTTP_PORT}",
        "socks5_proxy": f"socks5://{client_ip}:{SOCKS5_PORT}",
        "username": PROXY_USER,
        "password": PROXY_PASS,
        "status": "running"
    })

def run_info():
    app.run(host="0.0.0.0", port=5000)

threading.Thread(target=run_info, daemon=True).start()

# === [8] main ===
async def main():
    loop = asyncio.get_running_loop()
    s1 = await loop.create_server(lambda: HTTPProxy(), host='0.0.0.0', port=HTTP_PORT)
    s2 = await loop.create_server(lambda: SOCKS5Proto(), host='0.0.0.0', port=SOCKS5_PORT)
    print(f"[+] HTTP Proxy on port {HTTP_PORT}")
    print(f"[+] SOCKS5 Proxy on port {SOCKS5_PORT}")
    await asyncio.gather(s1.serve_forever(), s2.serve_forever())

if __name__ == "__main__":
    asyncio.run(main())
