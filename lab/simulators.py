#!/usr/bin/env python3
"""Deliberately weak service simulators for testing Network Scope. Standard library only.

These emulate only what a scanner can observe (banners and a few protocol replies). They are not
real vulnerable software and they never execute anything received from the network.

  python simulators.py --bind 127.0.0.1 --offset 20000   # unprivileged ports 20021, 20022, ...
  python simulators.py --bind 0.0.0.0                    # standard ports (needs root on Linux)
"""
import argparse
import socket
import socketserver
import struct
import threading


def kexinit(lists):
    payload = bytes([20]) + b"\x07" * 16
    for item in lists:
        data = item.encode()
        payload += struct.pack(">I", len(data)) + data
    payload += b"\x00" * 5
    pad = 8 - (len(payload) + 5) % 8
    return struct.pack(">IB", len(payload) + pad + 1, pad) + payload + b"\x00" * pad


WEAK_KEX = kexinit([
    "diffie-hellman-group1-sha1,diffie-hellman-group14-sha1",
    "ssh-rsa,ssh-dss",
    "aes128-cbc,3des-cbc,chacha20-poly1305@openssh.com",
    "aes128-cbc,3des-cbc,chacha20-poly1305@openssh.com",
    "hmac-md5,hmac-sha1",
    "hmac-md5,hmac-sha1",
    "none", "none", "", "",
])


def read_some(conn, n=4096):
    conn.settimeout(2)
    try:
        return conn.recv(n)
    except OSError:
        return b""


def ssh(conn):
    conn.sendall(b"SSH-2.0-OpenSSH_7.4\r\n" + WEAK_KEX)
    read_some(conn)


def ftp(conn):
    conn.sendall(b"220 (vsFTPd 2.3.4)\r\n")
    while True:
        data = read_some(conn)
        if not data:
            return
        conn.sendall(b"530 Please login with USER and PASS.\r\n")


def telnet(conn):
    conn.sendall(bytes([255, 253, 24, 255, 253, 31]) + b"\r\nlab-router login: ")
    read_some(conn)


def http(conn):
    read_some(conn)
    body = b"<html><title>Lab admin</title></html>"
    head = (b"HTTP/1.1 401 Unauthorized\r\nServer: Apache/2.4.49 (Unix)\r\n"
            b"WWW-Authenticate: Basic realm=\"lab\"\r\nContent-Type: text/html\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n")
    conn.sendall(head + body)


def redis(conn):
    while True:
        data = read_some(conn)
        if not data:
            return
        up = data.upper()
        if b"INFO" in up:
            info = b"# Server\r\nredis_version:5.0.7\r\nos:Linux\r\n"
            conn.sendall(b"$" + str(len(info)).encode() + b"\r\n" + info + b"\r\n")
        else:
            conn.sendall(b"+PONG\r\n")


def modbus(conn):
    """Read-only Modbus/TCP: Read Holding Registers (3), Report Server ID (17), Device ID (43)."""
    while True:
        data = read_some(conn)
        if len(data) < 8:
            return
        tid, _, _, unit, fc = struct.unpack(">HHHBB", data[:8])
        if fc == 3:
            pdu = bytes([3, 4, 0, 1, 0, 2])
        elif fc == 17:
            pdu = bytes([17, 12]) + b"\xff" + b"\xffLabPLC-1000"[:11]
        elif fc == 43:
            objs = [(0, b"LabWorks"), (1, b"PLC-1000"), (2, b"V1.2.3")]
            pdu = bytes([43, 14, 1, 1, 0, 0, len(objs)])
            for oid, val in objs:
                pdu += bytes([oid, len(val)]) + val
        else:
            pdu = bytes([fc | 0x80, 1])
        conn.sendall(struct.pack(">HHHB", tid, 0, len(pdu) + 1, unit) + pdu)


def enip_identity(context):
    v = struct.pack("<H", 1)  # encapsulation protocol version
    v += b"\x00" * 16  # socket address
    v += struct.pack("<HHH", 1, 14, 166)  # vendor Rockwell, device type, product code
    v += bytes([20, 11]) + b"\x00\x00" + struct.pack("<I", 0xC0FFEE01)
    v += bytes([10]) + b"1756-L81E " + bytes([3])
    item = struct.pack("<HH", 0x0C, len(v)) + v
    data = struct.pack("<H", 1) + item
    return struct.pack("<HHII", 0x63, len(data), 0, 0) + context + b"\x00" * 4 + data


def enip(conn):
    data = read_some(conn)
    if len(data) >= 24 and data[0] == 0x63:
        conn.sendall(enip_identity(data[12:20]))


TCP = {
    21: ftp, 22: ssh, 23: telnet, 80: http, 8080: http, 502: modbus, 6379: redis, 44818: enip,
}


def ssh_debian(conn):
    """SSH banner that names a Linux distribution (used by the accuracy benchmark)."""
    conn.sendall(b"SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1\r\n" + WEAK_KEX)
    read_some(conn)


def web_server(server, powered_by=None):
    """HTTP 200 handler that sends a fixed Server header (and X-Powered-By)."""
    def handler(conn):
        read_some(conn)
        body = b"<html><title>Lab page</title></html>"
        head = b"HTTP/1.1 200 OK\r\nServer: " + server.encode() + b"\r\n"
        if powered_by:
            head += b"X-Powered-By: " + powered_by.encode() + b"\r\n"
        head += (b"Content-Type: text/html\r\nContent-Length: " + str(len(body)).encode()
                 + b"\r\nConnection: close\r\n\r\n")
        conn.sendall(head + body)
    return handler


def http_debian(conn):
    web_server("Apache/2.4.56 (Debian)")(conn)


def http_iis(conn):
    web_server("Microsoft-IIS/10.0", "ASP.NET")(conn)


# Extra handlers that main() and the Docker lab do not serve. The accuracy benchmark
# (benchmark.py) puts them on their own loopback addresses.
VARIANTS = {"ssh_debian": ssh_debian, "http_debian": http_debian, "http_iis": http_iis}


class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def serve_tcp(bind, port, handler):
    class H(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                handler(self.request)
            except OSError:
                pass

    Server((bind, port), H).serve_forever()


def bacnet(bind, port):
    """Answers a unicast Who-Is with an I-Am (device 1000, vendor 15)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((bind, port))
    iam = bytes([0x10, 0x00, 0xC4, 0x02, 0x00, 0x03, 0xE8, 0x22, 0x05, 0xC4, 0x91, 0x00, 0x21, 0x0F])
    body = bytes([1, 0]) + iam
    reply = bytes([0x81, 0x0A]) + struct.pack(">H", 4 + len(body)) + body
    while True:
        data, addr = sock.recvfrom(1500)
        if data[:2] in (b"\x81\x0a", b"\x81\x0b"):
            sock.sendto(reply, addr)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--offset", type=int, default=0, help="added to every port")
    ap.add_argument("--skip", type=int, nargs="*", default=[], help="ports to leave out (e.g. 80 when the host already serves it)")
    args = ap.parse_args()
    for port, handler in TCP.items():
        if port in args.skip:
            continue
        threading.Thread(target=serve_tcp, args=(args.bind, port + args.offset, handler), daemon=True).start()
    threading.Thread(target=bacnet, args=(args.bind, 47808 + args.offset), daemon=True).start()
    print("lab simulators listening on", args.bind, "ports", sorted(p + args.offset for p in TCP if p not in args.skip), "and udp", 47808 + args.offset, flush=True)
    threading.Event().wait()


if __name__ == "__main__":
    main()
