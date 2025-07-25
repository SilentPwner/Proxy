import asyncio
import socket
import ssl
import random
import secrets
import base64
from datetime import datetime, timedelta
from threading import Thread
from http.server import HTTPServer, BaseHTTPRequestHandler

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# --- [1] إعدادات عشوائية ---
def random_port():
    return random.randint(30000, 60000)

RANDOM_SOCKS5_PORT = random_port()
RANDOM_HTTP_PORT = random_port()
RANDOM_HTTPS_PORT = random_port()

PROXY_USER = "u" + secrets.token_hex(3)
PROXY_PASS = ''.join(secrets.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#") for _ in range(20))

print(f"""
Proxy Credentials and Ports:
SOCKS5 port: {RANDOM_SOCKS5_PORT}
HTTP port: {RANDOM_HTTP_PORT}
HTTPS port: {RANDOM_HTTPS_PORT}
User: {PROXY_USER}
Pass: {PROXY_PASS}
""")

# --- [2] توليد شهادة TLS برمجياً ---
def generate_self_signed_cert():
    key = rsa.generate_private_key(
        public_exponent=65537, key_size=4096, backend=default_backend()
    )
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
        .sign(key, hashes.SHA256(), default_backend())
    )
    private_key = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    certificate = cert.public_bytes(serialization.Encoding.PEM)
    return private_key, certificate

key_pem, cert_pem = generate_self_signed_cert()

with open("key.pem", "wb") as f:
    f.write(key_pem)
with open("cert.pem", "wb") as f:
    f.write(cert_pem)

# --- [3] تمويه HTTP 404 على المنفذ 80 ---
class Fake404Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(404)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body>404 Not Found</body></html>")

def run_fake_404_server():
    server = HTTPServer(("0.0.0.0", 80), Fake404Handler)
    print("[*] Running fake HTTP 404 server on port 80")
    server.serve_forever()

Thread(target=run_fake_404_server, daemon=True).start()

# --- [4] مصادقة المستخدم (HTTP Basic Auth) ---
def check_auth(auth_header: str) -> bool:
    if not auth_header or not auth_header.lower().startswith("basic "):
        return False
    encoded = auth_header.split(" ", 1)[1]
    try:
        decoded = base64.b64decode(encoded).decode()
        username, password = decoded.split(":", 1)
        return username == PROXY_USER and password == PROXY_PASS
    except Exception:
        return False

# --- [5] بروكسي HTTP و HTTPS بسيط مع TLS ---

class ProxyProtocolError(Exception):
    pass

class HTTPProxyProtocol(asyncio.Protocol):
    def __init__(self):
        self.transport = None
        self.buffer = b""
        self.authenticated = False

    def connection_made(self, transport):
        self.transport = transport
        peer = transport.get_extra_info('peername')
        print(f"[HTTP Proxy] Connection from {peer}")

    def data_received(self, data):
        self.buffer += data
        if b"\r\n\r\n" not in self.buffer:
            return  # انتظار انتهاء رأس HTTP

        headers_end = self.buffer.index(b"\r\n\r\n") + 4
        header_bytes = self.buffer[:headers_end]
        self.buffer = self.buffer[headers_end:]
        headers_str = header_bytes.decode(errors="ignore")
        headers_lines = headers_str.split("\r\n")
        request_line = headers_lines[0]
        headers = {}
        for line in headers_lines[1:]:
            if ": " in line:
                k, v = line.split(": ", 1)
                headers[k.lower()] = v

        # التحقق من المصادقة
        auth_header = headers.get("proxy-authorization")
        if not self.authenticated:
            if not check_auth(auth_header):
                resp = (
                    "HTTP/1.1 407 Proxy Authentication Required\r\n"
                    "Proxy-Authenticate: Basic realm=\"3proxy\"\r\n"
                    "Content-Length: 0\r\n\r\n"
                )
                self.transport.write(resp.encode())
                self.transport.close()
                return
            else:
                self.authenticated = True

        # إزالة رؤوس إخفاء الهوية
        for h in ["via", "proxy-connection", "x-forwarded-for"]:
            if h in headers:
                headers.pop(h)

        # التعامل مع CONNECT (لـ HTTPS)
        if request_line.startswith("CONNECT"):
            target = request_line.split(" ")[1]
            asyncio.create_task(self.handle_connect(target))
        else:
            asyncio.create_task(self.handle_http(request_line, headers, self.buffer))

    async def handle_connect(self, target):
        try:
            target_host, target_port = target.split(":")
            target_port = int(target_port)
            remote_reader, remote_writer = await asyncio.open_connection(target_host, target_port, ssl=None)
            self.transport.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")

            loop = asyncio.get_event_loop()
            # ربط الترافيك بين العميل والخادم
            await asyncio.gather(
                self.pipe_streams(self.transport, remote_writer),
                self.pipe_streams(remote_reader, self.transport)
            )
        except Exception as e:
            print(f"[HTTP Proxy] CONNECT error: {e}")
            self.transport.close()

    async def handle_http(self, request_line, headers, body):
        # بساطة: إعادة توجيه الطلب بدون تعديل (يمكن تحسين)
        try:
            method, path, version = request_line.split(" ")
            host = headers.get("host")
            if not host:
                self.transport.close()
                return
            url = f"http://{host}{path}"
            reader, writer = await asyncio.open_connection(host, 80)
            # إعادة بناء طلب HTTP مع حذف رؤوس الإخفاء
            request_headers = [f"{method} {path} {version}"]
            for k, v in headers.items():
                if k not in ["via", "proxy-connection", "x-forwarded-for", "proxy-authorization"]:
                    request_headers.append(f"{k}: {v}")
            request_headers.append("\r\n")
            request_data = "\r\n".join(request_headers).encode() + body
            writer.write(request_data)
            await writer.drain()
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                self.transport.write(data)
            writer.close()
            await writer.wait_closed()
            self.transport.close()
        except Exception as e:
            print(f"[HTTP Proxy] Error: {e}")
            self.transport.close()

    async def pipe_streams(self, source, dest):
        try:
            while True:
                data = await asyncio.get_event_loop().run_in_executor(None, source.read, 4096)
                if not data:
                    break
                dest.write(data)
                await dest.drain()
        except Exception as e:
            pass

# --- [6] بروكسي SOCKS5 بسيط مع مصادقة ---

class SOCKS5Protocol(asyncio.Protocol):
    def __init__(self):
        self.transport = None
        self.state = "NEGOTIATION"
        self.user_authenticated = False
        self.buffer = b""

    def connection_made(self, transport):
        self.transport = transport
        peer = transport.get_extra_info('peername')
        print(f"[SOCKS5 Proxy] Connection from {peer}")

    def data_received(self, data):
        self.buffer += data
        if self.state == "NEGOTIATION":
            self.handle_negotiation()
        elif self.state == "AUTHENTICATION":
            self.handle_auth()
        elif self.state == "REQUEST":
            self.handle_request()

    def handle_negotiation(self):
        if len(self.buffer) < 2:
            return
        ver, nmethods = self.buffer[0], self.buffer[1]
        if len(self.buffer) < 2 + nmethods:
            return
        methods = self.buffer[2:2 + nmethods]
        # نعلن أننا ندعم فقط username/password (0x02)
        self.transport.write(b"\x05\x02")
        self.buffer = self.buffer[2 + nmethods:]
        self.state = "AUTHENTICATION"

    def handle_auth(self):
        if len(self.buffer) < 2:
            return
        ver = self.buffer[0]
        ulen = self.buffer[1]
        if len(self.buffer) < 2 + ulen:
            return
        uname = self.buffer[2:2 + ulen].decode()
        plen_start = 2 + ulen
        if len(self.buffer) < plen_start + 1:
            return
        plen = self.buffer[plen_start]
        if len(self.buffer) < plen_start + 1 + plen:
            return
        passwd = self.buffer[plen_start + 1: plen_start + 1 + plen].decode()
        self.buffer = self.buffer[plen_start + 1 + plen:]
        # التحقق من المستخدم
        if uname == PROXY_USER and passwd == PROXY_PASS:
            self.user_authenticated = True
            self.transport.write(b"\x05\x00")  # نجاح
            self.state = "REQUEST"
        else:
            self.transport.write(b"\x05\x01")  # فشل
            self.transport.close()

    def handle_request(self):
        if len(self.buffer) < 4:
            return
        ver, cmd, _, atyp = self.buffer[0], self.buffer[1], self.buffer[2], self.buffer[3]
        if ver != 5:
            self.transport.close()
            return
        addr = None
        port = None
        addr_len = 0
        if atyp == 1:  # IPv4
            if len(self.buffer) < 10:
                return
            addr = socket.inet_ntoa(self.buffer[4:8])
            port = int.from_bytes(self.buffer[8:10], "big")
            addr_len = 10
        elif atyp == 3:  # Domain name
            domain_len = self.buffer[4]
            if len(self.buffer) < 5 + domain_len + 2:
                return
            addr = self.buffer[5:5+domain_len].decode()
            port = int.from_bytes(self.buffer[5+domain_len:5+domain_len+2], "big")
            addr_len = 5 + domain_len + 2
        else:
            # لا ندعم IPv6 حالياً
            self.transport.close()
            return
        self.buffer = self.buffer[addr_len:]

        if cmd == 1:  # CONNECT
            asyncio.create_task(self.handle_connect(addr, port))
        else:
            # أوامر أخرى غير مدعومة
            self.transport.close()

    async def handle_connect(self, addr, port):
        try:
            reader, writer = await asyncio.open_connection(addr, port)
            # رد نجاح
            reply = b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + (0).to_bytes(2, "big")
            self.transport.write(reply)

            # ربط الترافيك
            async def relay(reader, writer):
                try:
                    while True:
                        data = await reader.read(4096)
                        if not data:
                            break
                        writer.write(data)
                        await writer.drain()
                except Exception:
                    pass

            await asyncio.gather(
                relay(self.transport._protocol._stream_reader, writer),
                relay(reader, self.transport)
            )
        except Exception as e:
            print(f"[SOCKS5 Proxy] Connection error: {e}")
            self.transport.close()

# --- [7] تشغيل الخوادم مع asyncio ---

async def main():
    loop = asyncio.get_running_loop()

    # بدء بروكسي HTTP + HTTPS
    http_server = await loop.create_server(
        lambda: HTTPProxyProtocol(), host="0.0.0.0", port=RANDOM_HTTP_PORT
    )
    print(f"HTTP Proxy running on port {RANDOM_HTTP_PORT}")

    # بدء بروكسي SOCKS5
    socks5_server = await loop.create_server(
        lambda: SOCKS5Protocol(), host="0.0.0.0", port=RANDOM_SOCKS5_PORT
    )
    print(f"SOCKS5 Proxy running on port {RANDOM_SOCKS5_PORT}")

    # --- ملاحظة: دعم HTTPS كامل عبر CONNECT في HTTPProxyProtocol ---

    await asyncio.gather(http_server.serve_forever(), socks5_server.serve_forever())

if __name__ == "__main__":
    import threading
    # بدء خادم تمويه 404 في الخلفية
    threading.Thread(target=run_fake_404_server, daemon=True).start()

    print("Starting proxy servers...")
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Shutting down proxies.")
