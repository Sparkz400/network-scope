"""Unit tests of lab/real_servers_check.py: no servers needed (fake in-process peers, synthetic scan
results). The real servers are only available in CI (job `real-servers`).

  python -I -m unittest discover -s lab -p "test_*.py"
"""
import hashlib
import os
import socket
import struct
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import real_servers_check as rs  # noqa: E402

LISTS = [
    "curve25519-sha256,ext-info-s,kex-strict-s-v00@openssh.com",
    "ssh-ed25519",
    "chacha20-poly1305@openssh.com",
    "chacha20-poly1305@openssh.com,aes128-ctr",
    "umac-64-etm@openssh.com",
    "umac-64-etm@openssh.com,hmac-sha2-256",
    "none",
    "none,zlib@openssh.com",
    "",
    "",
]


def kexinit_packet(lists):
    payload = b"\x14" + os.urandom(16)
    for item in lists:
        payload += struct.pack(">I", len(item)) + item.encode()
    payload += b"\x00" + struct.pack(">I", 0)
    pad = 8 - ((len(payload) + 5) % 8)
    pad = pad + 8 if pad < 4 else pad
    return struct.pack(">IB", len(payload) + pad + 1, pad) + payload + b"\x00" * pad


def serve_once(data):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)

    def run():
        conn, _ = listener.accept()
        conn.settimeout(5)
        try:
            conn.recv(4096)
            conn.sendall(data)
            conn.recv(4096)
        except OSError:
            pass
        finally:
            conn.close()
            listener.close()

    threading.Thread(target=run, daemon=True).start()
    return listener.getsockname()[1]


def server_hello(cipher, exts, version=0x0303, alpn=None):
    ext_bytes = b""
    for kind in exts:
        data = {0x002B: b"\x03\x04", 0x0033: b"\x00\x1d\x00\x20" + b"\x01" * 32}.get(kind, b"")
        if kind == 0x0010:
            data = struct.pack(">HB", len(alpn) + 1, len(alpn)) + alpn.encode()
        ext_bytes += struct.pack(">HH", kind, len(data)) + data
    body = struct.pack(">H", version) + b"\x07" * 32 + b"\x20" + b"\x09" * 32 + struct.pack(">HB", cipher, 0)
    body += struct.pack(">H", len(ext_bytes)) + ext_bytes
    handshake = b"\x02" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x03" + struct.pack(">H", len(handshake)) + handshake


class Independent(unittest.TestCase):
    def test_hassh_is_md5_of_kex_enc_mac_comp_server_to_client(self):
        value, text = rs.hassh_server(LISTS)
        self.assertEqual(text, ";".join([LISTS[0], LISTS[3], LISTS[5], LISTS[7]]))
        self.assertEqual(value, hashlib.md5(text.encode()).hexdigest())

    def test_a_kexinit_is_read_from_a_raw_connection(self):
        packet = kexinit_packet(LISTS)
        port = serve_once(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n" + packet)
        value, text = rs.server_hassh("127.0.0.1", port, timeout=5)
        self.assertEqual((value, text), rs.hassh_server(LISTS))
        self.assertEqual(rs.parse_kexinit(packet[5:5 + struct.unpack(">I", packet[:4])[0] - 1 - packet[4]]), LISTS)
        with self.assertRaises(ValueError):
            rs.parse_kexinit(b"\x15" + b"\x00" * 40)

    def test_ja4s_follows_the_published_foxio_examples(self):
        # Published in the FoxIO JA4+ README; the extension lists are the ones that reproduce the hash.
        self.assertEqual(rs.ja4s(0x0303, 0x1301, [0x002B, 0x0033], 0x0304, None), "t130200_1301_a56c5b993250")
        self.assertEqual(rs.ja4s(0x0303, 0x1302, [0x002B, 0x0033], 0x0304, None), "t130200_1302_a56c5b993250")
        self.assertEqual(rs.ja4s(0x0303, 0xC030, [0xFF01, 0x0023, 0x0017], None, None), "t120300_c030_5e2616a54c73")
        self.assertEqual(rs.ja4s(0x0303, 0x1301, [0x0033, 0x002B], 0x0304, None), "t130200_1301_234ea6891581")
        self.assertEqual(rs.ja4s(0x0303, 0x002F, [], None, None), "t120000_002f_000000000000")
        for alpn, want in (("h2", "h2"), ("http/1.1", "h1"), ("x", "xx"), ("éx", "9x"), ("xé", "x9")):
            self.assertEqual(rs.ja4s(0x0303, 0xC02F, [0x0010], None, alpn)[5:7], want)

    def test_a_server_hello_is_parsed_and_hashed_from_a_raw_connection(self):
        record = server_hello(0x1303, [0x002B, 0x0033])
        self.assertEqual(rs.parse_server_hello(record), (0x0303, 0x1303, [0x002B, 0x0033], 0x0304, None))
        port = serve_once(record)
        self.assertEqual(rs.server_ja4s("127.0.0.1", port, timeout=5), "t130200_1303_a56c5b993250")
        hello = rs.client_hello13()
        self.assertEqual(hello[:3], b"\x16\x03\x01")
        self.assertEqual(struct.unpack(">H", hello[3:5])[0], len(hello) - 5)
        self.assertIn(b"".join(struct.pack(">H", s) for s in rs.TLS13_OFFER), hello)
        with self.assertRaises(ValueError):
            rs.parse_server_hello(b"\x15\x03\x03\x00\x02\x02\x28")


def host_with(**extra):
    cfg = rs.LAB
    a, b, n, s, m = cfg["TLS_A_PORT"], cfg["TLS_B_PORT"], cfg["NGINX_PORT"], cfg["SSH_PORT"], cfg["SMB_PORT"]
    identity = {
        f"svc.{m}": "microsoft-ds SMB 3.1.1 (signing required)", f"svc.{m}.product": "SMB", f"svc.{m}.version": "3.1.1",
        f"smb.{m}.dialect": "3.1.1", f"smb.{m}.smb1": "refused", f"smb.{m}.encryption": cfg["SMB_ENCRYPTION"],
        f"smb.{m}.netbios_name": cfg["SMB_NETBIOS"],
        f"svc.{s}.product": "OpenSSH", f"svc.{s}.cpe": "cpe:2.3:a:openbsd:openssh:9.6:p1:*:*:*:*:*:*",
        f"ssh.{s}.hassh": rs.hassh_server(LISTS)[0], f"ssh.{s}.hassh_algorithms": rs.hassh_server(LISTS)[1],
        f"tls.{a}.tls13_suites": "TLS_CHACHA20_POLY1305_SHA256, TLS_AES_256_GCM_SHA384",
        f"tls.{a}.ciphers": "TLS1.3: TLS_CHACHA20_POLY1305_SHA256, TLS_AES_256_GCM_SHA384",
        f"tls.{a}.versions": "TLS1.3", f"tls.{a}.ja4s": "t130200_1303_a56c5b993250", f"tls.{a}.self_signed": "true",
        f"tls.{a}.cn": cfg["CERT_CN"], f"tls.{a}.key": "RSA 2048",
        f"tls.{b}.tls13_suites": "TLS_AES_128_GCM_SHA256",
        f"tls.{b}.ciphers": "TLS1.3: TLS_AES_128_GCM_SHA256 | TLS1.2: ECDHE_RSA_AES_256_GCM_SHA384",
        f"tls.{b}.versions": "TLS1.3, TLS1.2", f"tls.{b}.self_signed": "true",
        f"tls.{n}.tls13_suites": "TLS_AES_256_GCM_SHA384, TLS_AES_128_GCM_SHA256",
        f"tls.{n}.ciphers": "TLS1.3: TLS_AES_256_GCM_SHA384, TLS_AES_128_GCM_SHA256 | TLS1.2: ECDHE_RSA_AES_128_GCM_SHA256",
        f"tls.{n}.versions": "TLS1.3, TLS1.2", f"tls.{n}.self_signed": "true",
        f"svc.{n}.product": "nginx", f"svc.{n}.cpe": "cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*",
    }
    identity.update(extra)
    return {"ip": "127.0.0.1", "open": [m, s, a, b, n], "identity": identity}


class Expectations(unittest.TestCase):
    ALL = ["smb", "ssh", "tls", "nginx"]

    def run_checks(self, host):
        return rs.check_scan(host, rs.LAB, self.ALL, rs.hassh_server(LISTS), "t130200_1303_a56c5b993250")

    def test_a_scan_that_matches_the_configuration_passes(self):
        self.assertEqual(self.run_checks(host_with()), [])

    def test_each_kind_of_difference_is_reported(self):
        cfg = rs.LAB
        a, s, m = cfg["TLS_A_PORT"], cfg["SSH_PORT"], cfg["SMB_PORT"]
        cases = [
            ({f"smb.{m}.dialect": "3.0.2"}, "smb.445.dialect"),
            ({f"smb.{m}.netbios_name": "OTHER"}, "netbios_name"),
            ({f"svc.{m}": "microsoft-ds SMB 3.1.1 (signing enabled, not required)"}, "signing"),
            ({f"ssh.{s}.hassh": "0" * 32}, "HASSHServer"),
            ({f"tls.{a}.tls13_suites": "TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256"}, "in this order"),
            ({f"tls.{a}.tls13_suites": "TLS_AES_256_GCM_SHA384"}, "TLS 1.3 suites"),
            ({f"tls.{a}.ja4s": "t130200_1301_000000000000"}, "JA4S"),
            ({f"tls.{a}.versions": "TLS1.3, TLS1.2"}, "TLS 1.3 only"),
            ({f"tls.{a}.suites_truncated": "true"}, "truncated"),
            ({f"tls.{a}.weak": "TLS1.2: x"}, "weak"),
            ({f"svc.{cfg['NGINX_PORT']}.cpe": "cpe:2.3:a:other:nginx:1"}, "cpe"),
        ]
        for change, want in cases:
            failures = self.run_checks(host_with(**change))
            self.assertTrue(any(want in f for f in failures), f"{change}: {failures}")
        host = host_with()
        host["open"].remove(cfg["NGINX_PORT"])
        self.assertTrue(any("not found open" in f for f in self.run_checks(host)))

    def test_parts_can_be_checked_separately(self):
        host = host_with()
        host["identity"] = {k: v for k, v in host["identity"].items() if k.startswith(("tls.", "svc.8443"))}
        host["open"] = [rs.LAB["TLS_A_PORT"], rs.LAB["TLS_B_PORT"]]
        self.assertEqual(rs.check_scan(host, rs.LAB, ["tls"], None, "t130200_1303_a56c5b993250"), [])

    def test_the_lab_constants_agree_with_each_other(self):
        env = rs.shell_env()
        self.assertIn("export TLS_A_PORT='8443'", env)
        # Every TLS 1.2 suite the lab configures has a printed name; ports are distinct and not 22/2222.
        for key in ("TLS_B_12", "NGINX_12"):
            self.assertIn(rs.LAB[key], rs.TLS12_NAMES)
        ports = [rs.LAB[k] for k in rs.LAB if k.endswith("_PORT")]
        self.assertEqual(len(ports), len(set(ports)))
        self.assertTrue(set(ports).isdisjoint({22, 2222}))
        # Every TLS 1.3 suite named in the lab is one Network Scope offers.
        offered = {"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"}
        for key in ("TLS_A_SUITES", "TLS_B_13", "NGINX_13"):
            self.assertTrue(set(rs.split(rs.LAB[key])) <= offered, key)


if __name__ == "__main__":
    unittest.main()
