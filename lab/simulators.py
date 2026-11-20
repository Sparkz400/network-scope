#!/usr/bin/env python3
"""Deliberately weak service simulators for testing Network Scope. Standard library only.

These emulate only what a scanner can observe (banners and a few protocol replies). They are not
real vulnerable software and they never execute anything received from the network.

  python simulators.py --bind 127.0.0.1 --offset 20000   # unprivileged ports 20021, 20022, ...
  python simulators.py --bind 0.0.0.0                    # standard ports (needs root on Linux)

Scenarios (--scenario) make the network or the devices behave badly; lab/verify.py checks them:

  slow-wan    every reply is delayed by 150-300 ms (--delay-min-ms / --delay-max-ms)
  lossy       a seeded, exact fraction (--loss, default 0.3) of the TCP connections per port is
              reset right after the connect and of the UDP requests is left unanswered
  fragile-ot  Modbus (502), EtherNet/IP (44818) and S7 (102) count what they receive and "crash"
              (close their listener for good) on a write or control request, or on more than
              --conn-limit new connections within one second; --stats FILE gets the counters
"""
import argparse
import collections
import functools
import hashlib
import hmac
import json
import os
import random
import socket
import socketserver
import struct
import threading
import time


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

SCENARIOS = ("normal", "slow-wan", "lossy", "fragile-ot")


class Scenario:
    """The network conditions of one simulator process."""

    def __init__(self, name="normal", seed=1, loss=0.3, delay=(0.150, 0.300)):
        self.name = name
        self.seed = seed
        self.loss = loss
        self.delay = delay
        self.rng = random.Random(seed)
        self._blocks = {}
        self._lock = threading.Lock()

    def pause(self):
        """Latency of one reply (slow-wan)."""
        if self.name == "slow-wan":
            time.sleep(self.rng.uniform(*self.delay))

    def drop(self, key):
        """True for a seeded, exact fraction of the events of one source (lossy).

        Events are taken in blocks of ten; round(loss * 10) of them are dropped, in an order that
        depends on the seed and the key. So 10 connections to one port always lose the same number.
        """
        if self.name != "lossy":
            return False
        with self._lock:
            rng, block = self._blocks.setdefault(key, (random.Random(f"{self.seed}:{key}"), []))
            if not block:
                block.extend([True] * round(self.loss * 10) + [False] * (10 - round(self.loss * 10)))
                rng.shuffle(block)
            return block.pop()


SCENARIO = Scenario()


class Conn:
    """A connection whose replies wait for the scenario's latency."""

    def __init__(self, sock):
        self.sock = sock

    def sendall(self, data):
        SCENARIO.pause()
        self.sock.sendall(data)

    def __getattr__(self, name):
        return getattr(self.sock, name)


class Stats:
    """The counters of the fragile devices, rewritten to --stats FILE after every event."""

    def __init__(self, path):
        self.path = path
        self.devices = {}
        self.lock = threading.Lock()

    def save(self):
        if not self.path:
            return
        with self.lock:
            doc = {name: device.snapshot() for name, device in self.devices.items()}
            tmp = self.path + ".tmp"
            try:
                with open(tmp, "w") as handle:
                    json.dump(doc, handle)
                os.replace(tmp, self.path)
            except OSError:
                pass  # a reader holds the file (Windows); the next event writes it again


class Fragile:
    """An OT device that is easy to knock over.

    It counts connections and requests. A write or control request, or more than `limit` new
    connections within one second, makes it crash: the listener is closed and stays closed.
    """

    def __init__(self, name, port, limit, stats):
        self.name, self.port, self.limit, self.stats = name, port, limit, stats
        self.server = None
        self.crashed = None  # reason
        self.connections = self.requests = self.writes = self.max_per_second = 0
        self.recent = collections.deque()
        self.lock = threading.Lock()
        stats.devices[name] = self

    def snapshot(self):
        return {"port": self.port, "connections": self.connections, "requests": self.requests,
                "writes": self.writes, "max_connections_per_second": self.max_per_second,
                "limit": self.limit, "crashed": self.crashed}

    def connection(self):
        """Records a new connection; False when the device is (now) down."""
        with self.lock:
            if self.crashed:
                return False
            now = time.monotonic()
            self.connections += 1
            self.recent.append(now)
            while now - self.recent[0] > 1.0:
                self.recent.popleft()
            self.max_per_second = max(self.max_per_second, len(self.recent))
            if len(self.recent) > self.limit:
                self._crash(f"{len(self.recent)} connections within 1 s, limit {self.limit}")
        self.stats.save()
        return not self.crashed

    def request(self):
        with self.lock:
            self.requests += 1
        self.stats.save()

    def write(self, what):
        """A write or control request arrived: the device crashes."""
        with self.lock:
            self.writes += 1
            self._crash(what)
        self.stats.save()

    def _crash(self, reason):
        if not self.crashed:
            self.crashed = reason
            threading.Thread(target=self._close, daemon=True).start()

    def _close(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()


# How long a handler waits for the client to speak before it gives up. A real server that waits for
# the client (Redis, Modbus) keeps an idle connection open much longer than this: scanners that
# wait for a banner first (nmap's NULL probe waits several seconds) would otherwise see the
# connection close without data and report "tcpwrapped". lab/nmap_compare.py raises it.
IDLE_TIMEOUT = 2


def read_some(conn, n=4096):
    conn.settimeout(IDLE_TIMEOUT)
    try:
        return conn.recv(n)
    except OSError:
        return b""


def read_exact(conn, n):
    conn.settimeout(2)
    data = b""
    try:
        while len(data) < n:
            chunk = conn.recv(n - len(data))
            if not chunk:
                return b""
            data += chunk
    except OSError:
        return b""
    return data


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


# A made-up icon (an ICO header and filler): the lab web server answers GET /favicon.ico with it,
# so that `scan --favicon` has something to hash (lab/verify.py computes the Shodan hash itself).
FAVICON = b"\x00\x00\x01\x00\x01\x00\x10\x10\x00\x00\x01\x00\x20\x00" + bytes(range(1, 97))


def http(conn):
    request = read_some(conn)
    if request.startswith(b"GET /favicon.ico "):
        conn.sendall(b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.49 (Unix)\r\nContent-Type: image/x-icon\r\n"
                     b"Content-Length: " + str(len(FAVICON)).encode() + b"\r\nConnection: close\r\n\r\n" + FAVICON)
        return
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


# Modbus function codes that change state or restart the device: coils and registers (5, 6, 15,
# 16, 22, 23), file records (21) and diagnostics (8). Network Scope sends only 3, 17 and 43.
MODBUS_WRITES = {5, 6, 8, 15, 16, 21, 22, 23}


def modbus_pdu(fc):
    if fc == 3:
        return bytes([3, 4, 0, 1, 0, 2])
    if fc == 17:
        return bytes([17, 12]) + b"\xff" + b"\xffLabPLC-1000"[:11]
    if fc == 43:
        objs = [(0, b"LabWorks"), (1, b"PLC-1000"), (2, b"V1.2.3")]
        pdu = bytes([43, 14, 1, 1, 0, 0, len(objs)])
        for oid, val in objs:
            pdu += bytes([oid, len(val)]) + val
        return pdu
    return bytes([fc | 0x80, 1])


def modbus(conn, device=None):
    """Read-only Modbus/TCP: Read Holding Registers (3), Report Server ID (17), Device ID (43).

    With a `device` (fragile-ot) a write or control function code crashes it.
    """
    while not (device and device.crashed):
        data = read_some(conn)
        if len(data) < 8:
            return
        tid, _, _, unit, fc = struct.unpack(">HHHBB", data[:8])
        if device:
            if fc in MODBUS_WRITES:
                device.write(f"Modbus write/control function {fc}")
                return
            device.request()
        pdu = modbus_pdu(fc)
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


# EtherNet/IP encapsulation commands that carry CIP services (SendRRData, SendUnitData): those
# can write. Network Scope sends only List Identity (0x63).
ENIP_WRITES = {0x6F, 0x70}


def enip(conn, device=None):
    data = read_some(conn)
    if device and len(data) >= 2:
        if struct.unpack("<H", data[:2])[0] in ENIP_WRITES:
            device.write("EtherNet/IP SendRRData/SendUnitData")
            return
        device.request()
    if len(data) >= 24 and data[0] == 0x63:
        conn.sendall(enip_identity(data[12:20]))


# S7comm job functions that write or control: write variable (0x05), block download and upload
# (0x1a-0x1f), PI service such as start/stop (0x28), PLC stop (0x29). Network Scope sends only
# Setup communication (0xf0) and SZL reads (user data).
S7_WRITES = {0x05, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x28, 0x29}


def tpkt(conn):
    head = read_exact(conn, 4)
    if len(head) < 4 or head[:2] != b"\x03\x00":
        return b""
    rest = read_exact(conn, struct.unpack(">H", head[2:4])[0] - 4)
    return head + rest


def s7_frame(payload):
    return struct.pack(">BBH", 3, 0, len(payload) + 7) + bytes([2, 0xF0, 0x80]) + payload


def s7_szl(request):
    """The SZL read reply (ids 0x11 and 0x1c) to a user-data request."""
    seq, szl_id = request[12], request[29] << 8 | request[30]
    if szl_id == 0x11:
        size = 28
        records = [struct.pack(">H", 1) + b"6ES7 315-2EH14-0AB0 " + bytes(6),
                   struct.pack(">H", 7) + bytes(23) + bytes([3, 2, 1])]
    elif szl_id == 0x1C:
        size = 34
        records = [struct.pack(">H", i) + text.ljust(32, b"\x00")
                   for i, text in ((1, b"LabPLC"), (2, b"CPU 315-2 PN/DP"), (5, b"S C-LAB000001"), (7, b"CPU 315-2 PN/DP"))]
    else:
        return b""
    data = (bytes([0xFF, 9]) + struct.pack(">H", 8 + size * len(records)) + struct.pack(">HHHH", szl_id, 1, size, len(records))
            + b"".join(records))
    params = bytes([0, 1, 0x12, 8, 0x12, 0x84, 1, seq, 0, 0, 0, 0])
    header = bytes([0x32, 7, 0, 0]) + request[11:13] + struct.pack(">HH", len(params), len(data))
    return s7_frame(header + params + data)


def s7(conn, device=None):
    """S7comm identification only: COTP connect, Setup communication, SZL reads 0x11 and 0x1c."""
    request = tpkt(conn)
    if len(request) < 6 or request[5] != 0xE0:
        return
    conn.sendall(bytes([3, 0, 0, 22, 17, 0xD0, 0, 0, 0, 1, 0, 0xC1, 2, 1, 0, 0xC2, 2, 1, 2, 0xC0, 1, 10]))
    while not (device and device.crashed):
        request = tpkt(conn)
        if len(request) < 19:
            return
        if device:
            if request[8] == 1 and request[17] in S7_WRITES:
                device.write(f"S7 job function {request[17]:#x}")
                return
            device.request()
        if request[8] == 1 and request[17] == 0xF0:
            conn.sendall(s7_frame(bytes([0x32, 3, 0, 0]) + request[11:13] + bytes([0, 8, 0, 0, 0, 0, 0xF0, 0, 0, 1, 0, 1, 1, 0xE0])))
        elif request[8] == 7 and len(request) >= 31:
            reply = s7_szl(request)
            if not reply:
                return
            conn.sendall(reply)
        else:
            return


TCP = {
    21: ftp, 22: ssh, 23: telnet, 80: http, 8080: http, 502: modbus, 6379: redis, 44818: enip,
}
# Only in the fragile-ot scenario (the default lab has no S7 simulator).
FRAGILE = {502: ("modbus", modbus), 44818: ("enip", enip), 102: ("s7", s7)}


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


# lossy: how long a dropped connection stays open before the reset (see serve_tcp).
RESET_AFTER = 0.05


def reset(sock):
    """Close with a TCP reset instead of a FIN: the peer sees the connection lost."""
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    except OSError:
        pass
    sock.close()


def serve_tcp(bind, port, handler, device=None):
    class H(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                if device and not device.connection():
                    return
                if SCENARIO.drop(port):
                    # Reset only after the client has seen its connect succeed. Reset at once,
                    # the RST can reach a fast client (Linux loopback) before its non-blocking
                    # connect has been polled, and the port check then sees a reset instead of
                    # an open port: the scenario is "connections lost after the connect".
                    time.sleep(RESET_AFTER)
                    reset(self.request)
                    return
                handler(Conn(self.request))
            except OSError:
                pass

    server = Server((bind, port), H)
    if device:
        device.server = server
    server.serve_forever()


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
            if SCENARIO.drop(port):
                continue
            SCENARIO.pause()
            sock.sendto(reply, addr)


# ---- SNMP agent: v1/v2c with a community, v3 authNoPriv (HMAC-SHA-1-96 and HMAC-MD5-96), read-only --
# A switch with three ports, two addresses and two LLDP neighbours. It answers only GetRequest,
# GetNextRequest and GetBulkRequest; any other PDU (a SetRequest, say) is counted and ignored, and
# `--snmp-stats FILE` records the PDU tags it saw, so lab/verify.py can show the scanner sent no
# write. Like a real agent it stays silent for a wrong community: the community "public" is NOT
# accepted, so the accuracy checks (and the snmp-public finding) are unchanged by this agent.
# Written independently of the Rust implementation (BER, key localisation and HMAC here come from
# the standard library) so that the lab cross-checks the scanner's SNMPv3 message layout.
SNMP_COMMUNITY = b"lab-community"
SNMP_USER = b"labuser"
# a second user with the weak HMAC-MD5-96 (the same passphrase), for `--snmp-v3 labuser-md5:md5:ENV`
SNMP_USERS = {b"labuser": hashlib.sha1, b"labuser-md5": hashlib.md5}
SNMP_AUTH_PASSPHRASE = b"lab-snmp-auth-pass"
SNMP_ENGINE_ID = bytes.fromhex("80001f88801a2b3c4d5e6f7081")
SNMP_STATS = {"datagrams": 0, "pdu_tags": {}, "other_pdus": 0}


def ber(tag, content):
    n = len(content)
    if n < 128:
        length = bytes([n])
    elif n < 256:
        length = bytes([0x81, n])
    else:
        length = bytes([0x82, n >> 8, n & 255])
    return bytes([tag]) + length + content


def ber_read(data, i=0):
    tag, n, i = data[i], data[i + 1], i + 2
    if n & 0x80:
        count = n & 0x7F
        n, i = int.from_bytes(data[i:i + count], "big"), i + count
    if i + n > len(data):
        raise ValueError("truncated")
    return tag, data[i:i + n], i + n


def ber_int(value):
    length = ((value if value >= 0 else ~value).bit_length() // 8) + 1
    return ber(2, value.to_bytes(length, "big", signed=True))


def oid_encode(arcs):
    body = bytearray([arcs[0] * 40 + arcs[1]])
    for arc in arcs[2:]:
        parts = [arc & 0x7F]
        arc >>= 7
        while arc:
            parts.append((arc & 0x7F) | 0x80)
            arc >>= 7
        body += bytes(reversed(parts))
    return ber(6, bytes(body))


def oid_decode(body):
    arcs, n = [body[0] // 40, body[0] % 40], 0
    for byte in body[1:]:
        n = (n << 7) | (byte & 0x7F)
        if not byte & 0x80:
            arcs.append(n)
            n = 0
    return tuple(arcs)


def snmp_value(kind, value):
    if kind == "s":
        return ber(4, value)
    if kind == "i":
        return ber_int(value)
    if kind == "oid":
        return oid_encode(value)
    if kind == "ticks":
        return ber(0x43, value.to_bytes(4, "big").lstrip(b"\x00").rjust(1, b"\x00") if value < 0x80000000 else b"\x00" + value.to_bytes(4, "big"))
    if kind == "ip":
        return ber(0x40, value)
    raise ValueError(kind)


def snmp_mib():
    def o(text):
        return tuple(int(part) for part in text.split("."))

    mib = {
        o("1.3.6.1.2.1.1.1.0"): ("s", b"Lab Switch 24G (LabOS 3.1.4)"),
        o("1.3.6.1.2.1.1.2.0"): ("oid", o("1.3.6.1.4.1.8072.3.2.10")),
        o("1.3.6.1.2.1.1.3.0"): ("ticks", 12345600),
        o("1.3.6.1.2.1.1.4.0"): ("s", b"lab@example.invalid"),
        o("1.3.6.1.2.1.1.5.0"): ("s", b"lab-sw1"),
        o("1.3.6.1.2.1.1.6.0"): ("s", b"Rack 4"),
        o("1.3.6.1.2.1.1.7.0"): ("i", 72),
    }
    for n, (name, mac, status) in enumerate([("Gi1/0/1", "001b210a0b01", 1), ("Gi1/0/2", "001b210a0b02", 2), ("Vlan1", "001b210a0bff", 1)], 1):
        mib[o(f"1.3.6.1.2.1.2.2.1.1.{n}")] = ("i", n)
        mib[o(f"1.3.6.1.2.1.2.2.1.2.{n}")] = ("s", name.encode())
        mib[o(f"1.3.6.1.2.1.2.2.1.6.{n}")] = ("s", bytes.fromhex(mac))
        mib[o(f"1.3.6.1.2.1.2.2.1.8.{n}")] = ("i", status)
        mib[o(f"1.3.6.1.2.1.31.1.1.1.1.{n}")] = ("s", name.encode())  # ifName
    for address, index, mask in (("10.77.0.2", 3, bytes([255, 255, 255, 0])), ("192.168.77.1", 3, bytes([255, 255, 255, 128]))):
        mib[o(f"1.3.6.1.2.1.4.20.1.1.{address}")] = ("ip", bytes(int(p) for p in address.split(".")))
        mib[o(f"1.3.6.1.2.1.4.20.1.2.{address}")] = ("i", index)
        mib[o(f"1.3.6.1.2.1.4.20.1.3.{address}")] = ("ip", mask)
    # ipAddressTable: ipAddressIfIndex.<type>.<length>.<address octets> (IPv4 again, IPv6 global)
    mib[o("1.3.6.1.2.1.4.34.1.3.1.4.10.77.0.2")] = ("i", 3)
    mib[o("1.3.6.1.2.1.4.34.1.3.2.16.253.0.0.0.0.0.0.119.0.0.0.0.0.0.0.2")] = ("i", 3)
    for row, chassis, port, name in (("0.1.1", "001b21770001", b"Gi0/24", b"dist-sw2"), ("0.2.1", "525400123456", b"eth0", b"lab-ap")):
        mib[o(f"1.0.8802.1.1.2.1.4.1.1.4.{row}")] = ("i", 4)
        mib[o(f"1.0.8802.1.1.2.1.4.1.1.5.{row}")] = ("s", bytes.fromhex(chassis))
        mib[o(f"1.0.8802.1.1.2.1.4.1.1.6.{row}")] = ("i", 5)
        mib[o(f"1.0.8802.1.1.2.1.4.1.1.7.{row}")] = ("s", port)
        mib[o(f"1.0.8802.1.1.2.1.4.1.1.8.{row}")] = ("s", port + b" uplink")
        mib[o(f"1.0.8802.1.1.2.1.4.1.1.9.{row}")] = ("s", name)
    return mib


SNMP_MIB = snmp_mib()
SNMP_OIDS = sorted(SNMP_MIB)


def snmp_walk(tag, oids, non_repeaters, max_repetitions, v1):
    """The variable bindings for a Get (0xA0), GetNext (0xA1) or GetBulk (0xA5); None = noSuchName."""
    def after(oid):
        return next((o for o in SNMP_OIDS if o > oid), None)

    out = []
    if tag == 0xA0:
        for oid in oids:
            if oid in SNMP_MIB:
                out.append((oid, SNMP_MIB[oid]))
            elif v1:
                return None
            else:
                out.append((oid, ("raw", b"\x81\x00")))  # noSuchInstance
    elif tag == 0xA1:
        for oid in oids:
            nxt = after(oid)
            if nxt is not None:
                out.append((nxt, SNMP_MIB[nxt]))
            elif v1:
                return None
            else:
                out.append((oid, ("raw", b"\x82\x00")))  # endOfMibView
    else:
        cursors = list(oids[non_repeaters:])
        for oid in oids[:non_repeaters]:
            nxt = after(oid)
            out.append((nxt, SNMP_MIB[nxt]) if nxt else (oid, ("raw", b"\x82\x00")))
        for _ in range(min(max_repetitions, 50)):
            moved = False
            for i, cursor in enumerate(cursors):
                nxt = after(cursor)
                if nxt is None:
                    out.append((cursor, ("raw", b"\x82\x00")))
                else:
                    cursors[i] = nxt
                    out.append((nxt, SNMP_MIB[nxt]))
                    moved = True
            if not moved:
                break
    return out


def snmp_varbinds(binds):
    items = b""
    for oid, (kind, value) in binds:
        encoded = ber(value[0], value[1:]) if kind == "raw" else snmp_value(kind, value)
        items += ber(0x30, oid_encode(oid) + encoded)
    return ber(0x30, items)


def snmp_request(pdu):
    """(request-id, a, b, [oids]) of a request PDU body."""
    _, rid, i = ber_read(pdu, 0)
    _, a, i = ber_read(pdu, i)
    _, b, i = ber_read(pdu, i)
    _, binds, _ = ber_read(pdu, i)
    oids, j = [], 0
    while j < len(binds):
        _, vb, j = ber_read(binds, j)
        _, name, _ = ber_read(vb, 0)
        oids.append(oid_decode(name))
    return (int.from_bytes(rid, "big", signed=True), int.from_bytes(a, "big", signed=True),
            int.from_bytes(b, "big", signed=True), oids)


def snmp_count(tag):
    SNMP_STATS["pdu_tags"][hex(tag)] = SNMP_STATS["pdu_tags"].get(hex(tag), 0) + 1
    if tag not in (0xA0, 0xA1, 0xA5):
        SNMP_STATS["other_pdus"] += 1


def snmp_localized_key(passphrase, engine_id, hash_function=hashlib.sha1):
    block = (passphrase * (1048576 // len(passphrase) + 1))[:1048576]
    ku = hash_function(block).digest()
    return hash_function(ku + engine_id + ku).digest()


def snmp_v3(data, started):
    _, msg, _ = ber_read(data)
    _, _, i = ber_read(msg, 0)
    _, glob, i = ber_read(msg, i)
    _, sec, i = ber_read(msg, i)
    _, scoped, _ = ber_read(msg, i)
    _, msg_id, j = ber_read(glob, 0)
    _, _, j = ber_read(glob, j)
    _, flags, _ = ber_read(glob, j)
    flags = flags[0]
    _, params, _ = ber_read(sec, 0)
    _, engine, j = ber_read(params, 0)
    _, _, j = ber_read(params, j)
    _, _, j = ber_read(params, j)
    _, user, j = ber_read(params, j)
    _, auth, j = ber_read(params, j)
    msg_id = int.from_bytes(msg_id, "big", signed=True)
    now = int(time.monotonic() - started) + 1000
    hash_function = SNMP_USERS.get(user, hashlib.sha1)
    key = snmp_localized_key(SNMP_AUTH_PASSPHRASE, SNMP_ENGINE_ID, hash_function)

    def message(flags_byte, rid, tag, status, binds, user_name, authenticated):
        pdu = ber(tag, ber_int(rid) + ber_int(status) + ber_int(0) + binds)
        scoped_pdu = ber(0x30, ber(4, SNMP_ENGINE_ID) + ber(4, b"") + pdu)

        def build(auth_bytes):
            usm = ber(4, ber(0x30, ber(4, SNMP_ENGINE_ID) + ber_int(7) + ber_int(now) + ber(4, user_name) + ber(4, auth_bytes) + ber(4, b"")))
            head = ber(0x30, ber_int(msg_id) + ber_int(1472) + ber(4, bytes([flags_byte])) + ber_int(3))
            return ber(0x30, ber_int(3) + head + usm + scoped_pdu)
        if not authenticated:
            return build(b"")
        zeroed = build(b"\x00" * 12)
        return build(hmac.new(key, zeroed, hash_function).digest()[:12])

    def report(counter):
        binds = ber(0x30, ber(0x30, oid_encode((1, 3, 6, 1, 6, 3, 15, 1, 1, counter, 0)) + ber(0x41, b"\x01")))
        return message(0, 0, 0xA8, 0, binds, b"", False)

    if engine != SNMP_ENGINE_ID:
        return report(4)  # usmStatsUnknownEngineIDs: how a manager discovers the engine
    if user not in SNMP_USERS:
        return report(3)  # usmStatsUnknownUserNames
    if flags & 0x03 == 0x01:  # authNoPriv
        zeroed = bytearray(data)
        at = data.find(auth)
        if len(auth) != 12 or at < 0:
            return report(5)
        zeroed[at:at + 12] = b"\x00" * 12
        if not hmac.compare_digest(hmac.new(key, bytes(zeroed), hash_function).digest()[:12], auth):
            return report(5)  # usmStatsWrongDigests
    else:
        return report(1)  # the user needs authentication, and there is no privacy: usmStatsUnsupportedSecLevels
    _, ctx_engine, j = ber_read(scoped, 0)
    _, _, j = ber_read(scoped, j)
    tag, pdu, _ = ber_read(scoped, j)
    snmp_count(tag)
    if tag not in (0xA0, 0xA1, 0xA5):
        return None
    rid, a, b, oids = snmp_request(pdu)
    binds = snmp_walk(tag, oids, a, b, False)
    return message(flags & 0x01, rid, 0xA2, 0, snmp_varbinds(binds), user, bool(flags & 1))


def snmp_handle(data, started):
    try:
        _, msg, _ = ber_read(data)
        _, version, i = ber_read(msg, 0)
        version = version[0]
        if version == 3:
            return snmp_v3(data, started)
        _, community, i = ber_read(msg, i)
        if community != SNMP_COMMUNITY:
            return None  # silence, like a real agent
        tag, pdu, _ = ber_read(msg, i)
        snmp_count(tag)
        if tag not in (0xA0, 0xA1, 0xA5):
            return None
        rid, a, b, oids = snmp_request(pdu)
        binds = snmp_walk(tag, oids, a, b, version == 0)
        if binds is None:
            body = ber_int(rid) + ber_int(2) + ber_int(1) + snmp_varbinds([(o, ("raw", b"\x05\x00")) for o in oids])
        else:
            body = ber_int(rid) + ber_int(0) + ber_int(0) + snmp_varbinds(binds)
        return ber(0x30, ber(2, bytes([version])) + ber(4, community) + ber(0xA2, body))
    except (ValueError, IndexError):
        return None


def snmp_agent(bind, port, stats_path=None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((bind, port))
    started = time.monotonic()
    while True:
        data, addr = sock.recvfrom(9000)
        SNMP_STATS["datagrams"] += 1
        reply = snmp_handle(data, started)
        if stats_path:
            try:
                with open(stats_path + ".tmp", "w") as handle:
                    json.dump(SNMP_STATS, handle)
                os.replace(stats_path + ".tmp", stats_path)
            except OSError:
                pass
        if reply is not None and not SCENARIO.drop(port):
            SCENARIO.pause()
            sock.sendto(reply, addr)


# ---- FINS/UDP, MQTT, KNXnet/IP and Niagara Fox: identification only -----------------------------
# Each device answers only the one read-only request Network Scope sends (FINS Controller Data
# Read, MQTT CONNECT, KNX DESCRIPTION_REQUEST, the Fox hello) and counts what it receives, so
# lab/verify.py can show that nothing else arrives (`--ot-stats FILE`). Anything else is counted
# under "other" and ignored.
OT_STATS = {"fins": {}, "mqtt": {}, "knx": {}, "fox": {}, "fins_tcp": {}, "mc": {}, "dnp3": {}}
OT_STATS_PATH = None
# the MELSEC MC protocol has no standard port: the lab device listens on one that only the
# command line of the test gives (`--melsec-port 15007`), and a scan without it must never send there
MC_PORT = 15007
DNP3_OUTSTATION = 10


def ot_count(protocol, key):
    OT_STATS[protocol][key] = OT_STATS[protocol].get(key, 0) + 1
    if OT_STATS_PATH:
        try:
            with open(OT_STATS_PATH + ".tmp", "w") as handle:
                json.dump(OT_STATS, handle)
            os.replace(OT_STATS_PATH + ".tmp", OT_STATS_PATH)
        except OSError:
            pass


def fins_reply(request):
    """Controller Data Read response: model, version, system use and area data (92 bytes)."""
    header = bytes([0xC0, 0, 2, 0, request[7], 0, 0, 0xC8, 0, request[9], 5, 1, 0, 0])
    data = b"LabPLC-FINS".ljust(20, b" ") + b"01.00".ljust(20, b"\x00") + bytes(40) + bytes(12)
    return header + data


def fins_agent(bind, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((bind, port))
    while True:
        data, addr = sock.recvfrom(2048)
        if len(data) == 13 and data[0] == 0x80 and data[10:12] == b"\x05\x01":
            ot_count("fins", "0501")
            if not SCENARIO.drop(port):
                SCENARIO.pause()
                sock.sendto(fins_reply(data), addr)
        else:
            ot_count("fins", "other")


FINS_TCP_NODE_REQUEST = b"FINS" + bytes([0, 0, 0, 12]) + bytes(12)
FINS_SERVER_NODE = 0xC8
FINS_CLIENT_NODE = 0xFB


def fins_tcp(conn):
    """FINS/TCP: the node address exchange, then one Controller Data Read (the frames of
    omron_test.pcap). Anything else is counted as "other" and ends the connection."""
    first = read_exact(conn, 20)
    if not first:
        return  # the port check opened and closed a connection without a byte: not a request
    if first != FINS_TCP_NODE_REQUEST:
        ot_count("fins_tcp", "other")
        return
    ot_count("fins_tcp", "node-address")
    conn.sendall(b"FINS" + bytes([0, 0, 0, 16, 0, 0, 0, 1, 0, 0, 0, 0]) + bytes([0, 0, 0, FINS_CLIENT_NODE, 0, 0, 0, FINS_SERVER_NODE]))
    second = read_exact(conn, 29)
    # command 2 (FINS frame send), a command frame to our node asking for 0x0501
    if (second is None or second[:12] != b"FINS" + bytes([0, 0, 0, 21, 0, 0, 0, 2]) or second[12:16] != bytes(4)
            or second[16] != 0x80 or second[20] != FINS_SERVER_NODE or second[26:28] != b"\x05\x01"):
        ot_count("fins_tcp", "other")
        return
    ot_count("fins_tcp", "0501")
    inner = second[16:29]
    header = bytes([0xC0, 0, 2, 0, FINS_CLIENT_NODE, inner[8], 0, FINS_SERVER_NODE, 0, inner[9], 5, 1, 0, 0])
    data = b"LabPLC-FINS".ljust(20, b" ") + b"01.00".ljust(20, b"\x00") + bytes(40) + bytes(12)
    body = header + data
    conn.sendall(b"FINS" + struct.pack(">I", 8 + len(body)) + bytes([0, 0, 0, 2, 0, 0, 0, 0]) + body)
    # the client closes; anything more is counted
    more = read_some(conn)
    if more:
        ot_count("fins_tcp", "other")


def mc(conn):
    """MELSEC MC protocol 3E, binary: answers Read CPU Model Name (0x0101) with a model name
    and counts every request by its command; anything else is "other"."""
    request = read_exact(conn, 15)
    if not request:
        return  # the port check opened and closed a connection without a byte: not a request
    expected = bytes([0x50, 0, 0, 0xFF, 0xFF, 3, 0, 6, 0, 0x10, 0, 1, 1, 0, 0])
    if request != expected:
        ot_count("mc", "other")
        return
    ot_count("mc", "0101")
    data = b"LabQ03UDE".ljust(16, b" ") + bytes([0x68, 0x02])
    conn.sendall(bytes([0xD0, 0, 0, 0xFF, 0xFF, 3, 0]) + struct.pack("<H", 2 + len(data)) + bytes([0, 0]) + data)
    more = read_some(conn)
    if more:
        ot_count("mc", "other")


def dnp3_crc(data):
    """CRC-16/DNP (IEEE 1815): written here from the standard's polynomial, independently of the Rust code."""
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
    return (~crc) & 0xFFFF


def dnp3_frame(control, destination, source, user_data):
    header = bytes([0x05, 0x64, 5 + len(user_data), control]) + struct.pack("<HH", destination, source)
    out = header + struct.pack("<H", dnp3_crc(header))
    for i in range(0, len(user_data), 16):
        block = user_data[i:i + 16]
        out += block + struct.pack("<H", dnp3_crc(block))
    return out


def dnp3(conn):
    """A DNP3 outstation (address 10): answers only a link frame whose two CRCs verify, that is
    unconfirmed user data to its address with Read (function 1) of class 0 (g60 v1). Anything
    else is counted and ignored; a broadcast address would be counted as "broadcast"."""
    data = read_exact(conn, 18)
    if not data:
        return  # the port check opened and closed a connection without a byte: not a request
    if data[:2] != b"\x05\x64":
        ot_count("dnp3", "other")
        return
    header_ok = dnp3_crc(data[:8]) == struct.unpack("<H", data[8:10])[0]
    block_ok = dnp3_crc(data[10:16]) == struct.unpack("<H", data[16:18])[0]
    destination, source = struct.unpack("<HH", data[4:8])
    if destination >= 0xFFFC:
        ot_count("dnp3", "broadcast")
        return
    if not (header_ok and block_ok):
        ot_count("dnp3", "bad-crc")
        return
    # control 0xC4 = primary, from the master, unconfirmed user data; transport and application
    # headers FIR+FIN, function 1 (Read), object g60 v1 qualifier 6 (class 0)
    if data[3] == 0xC4 and data[10:16] == bytes([0xC0, 0xC0, 0x01, 0x3C, 0x01, 0x06]) and destination == DNP3_OUTSTATION:
        ot_count("dnp3", "read-class0")
        # Response (129), IIN 0000, no objects
        conn.sendall(dnp3_frame(0x44, source, DNP3_OUTSTATION, bytes([0xC0, 0xC0, 0x81, 0x00, 0x00])))
    else:
        ot_count("dnp3", "other")
        return
    more = read_some(conn)
    if more:
        ot_count("dnp3", "other")


def mqtt(conn):
    """Answers a CONNECT with a CONNACK "not authorized" (like a broker that wants credentials)."""
    data = read_some(conn)
    if not data:
        return
    ot_count("mqtt", str(data[0] >> 4))
    if data[0] == 0x10:
        conn.sendall(bytes([0x20, 2, 0, 5]))
        while True:  # the DISCONNECT, then the end of the stream
            more = read_some(conn)
            if not more:
                return
            ot_count("mqtt", str(more[0] >> 4))


def fox(conn):
    """Answers the Fox hello with a station hello."""
    data = b""
    conn.settimeout(IDLE_TIMEOUT)
    try:
        while b"};;" not in data and len(data) < 4096:
            chunk = conn.recv(1024)
            if not chunk:
                return
            data += chunk
    except OSError:
        return
    ot_count("fox", "hello" if data.startswith(b"fox a 1 -1 fox hello\n") else "other")
    if not data.startswith(b"fox a 1 -1 fox hello\n"):
        return
    body = ("fox.version=s:1.0\nid=i:2\nhostName=s:lab-jace\nhostAddress=s:127.0.0.1\napp.name=s:Station\n"
            "app.version=s:4.8.0.1\nvm.name=s:J9\nvm.version=s:2.9\nos.name=s:QNX\nos.version=s:6.5\n"
            "station.name=s:LabStation\nlang=s:en\nhostId=s:Qnx-LAB-0000-0000-0001\nbrandId=s:lab\n")
    conn.sendall(("fox a 0 -1 fox hello\n{\n" + body + "};;\n").encode())


def knx_description():
    """A DESCRIPTION_RESPONSE: device information DIB (54 bytes) and supported service families."""
    dib = bytes([54, 1, 0x02, 0]) + bytes([0x11, 0xFA]) + bytes([0, 1]) + bytes.fromhex("008300112233")
    dib += bytes([224, 0, 23, 12]) + bytes.fromhex("001b21aabbcc") + b"Lab KNX IP Router".ljust(30, b"\x00")
    families = bytes([10, 2, 2, 1, 3, 1, 4, 1, 5, 1])
    body = dib + families
    return bytes([6, 0x10, 2, 4]) + struct.pack(">H", 6 + len(body)) + body


def knx_agent(bind, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((bind, port))
    while True:
        data, addr = sock.recvfrom(2048)
        service = struct.unpack(">H", data[2:4])[0] if len(data) >= 4 and data[:2] == b"\x06\x10" else None
        ot_count("knx", hex(service) if service is not None else "other")
        if service == 0x0203 and not SCENARIO.drop(port):
            SCENARIO.pause()
            sock.sendto(knx_description(), addr)


def main():
    global SCENARIO, OT_STATS_PATH
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--offset", type=int, default=0, help="added to every port")
    ap.add_argument("--skip", type=int, nargs="*", default=[], help="ports to leave out (e.g. 80 when the host already serves it)")
    ap.add_argument("--scenario", choices=SCENARIOS, default="normal", help="network conditions, see the module help")
    ap.add_argument("--seed", type=int, default=1, help="seed of the lossy and slow-wan scenarios")
    ap.add_argument("--loss", type=float, default=0.3, help="lossy: fraction of connections and UDP replies lost (0-1, in tenths)")
    ap.add_argument("--delay-min-ms", type=int, default=150, help="slow-wan: shortest reply delay")
    ap.add_argument("--delay-max-ms", type=int, default=300, help="slow-wan: longest reply delay")
    ap.add_argument("--conn-limit", type=int, default=4, help="fragile-ot: new connections per second that crash a device")
    ap.add_argument("--stats", help="fragile-ot: JSON file for the device counters")
    ap.add_argument("--snmp-stats", help="JSON file for the SNMP agent's counters (the PDU tags it received)")
    ap.add_argument("--ot-stats", help="JSON file for the counters of the FINS (UDP and TCP), MQTT, KNX, Fox, MELSEC MC and DNP3 devices (what they received)")
    args = ap.parse_args()
    SCENARIO = Scenario(args.scenario, args.seed, args.loss, (args.delay_min_ms / 1000, args.delay_max_ms / 1000))

    tcp = {port: (handler, None) for port, handler in TCP.items()}
    tcp[1883] = (mqtt, None)
    tcp[1911] = (fox, None)
    tcp[9600] = (fins_tcp, None)
    tcp[20000] = (dnp3, None)
    tcp[MC_PORT] = (mc, None)
    if args.scenario == "fragile-ot":
        stats = Stats(args.stats)
        for port, (name, handler) in FRAGILE.items():
            device = Fragile(name, port + args.offset, args.conn_limit, stats)
            tcp[port] = (functools.partial(handler, device=device), device)
        stats.save()
    for port, (handler, device) in tcp.items():
        if port in args.skip:
            continue
        threading.Thread(target=serve_tcp, args=(args.bind, port + args.offset, handler, device), daemon=True).start()
    threading.Thread(target=bacnet, args=(args.bind, 47808 + args.offset), daemon=True).start()
    threading.Thread(target=snmp_agent, args=(args.bind, 161 + args.offset, args.snmp_stats), daemon=True).start()
    OT_STATS_PATH = args.ot_stats
    threading.Thread(target=fins_agent, args=(args.bind, 9600 + args.offset), daemon=True).start()
    threading.Thread(target=knx_agent, args=(args.bind, 3671 + args.offset), daemon=True).start()
    print("lab simulators listening on", args.bind, "ports", sorted(p + args.offset for p in tcp if p not in args.skip), "and udp", 47808 + args.offset, 161 + args.offset, 9600 + args.offset, 3671 + args.offset, "scenario", args.scenario, flush=True)
    threading.Event().wait()


if __name__ == "__main__":
    main()
