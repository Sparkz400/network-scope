#!/usr/bin/env python3
"""Checks a Network Scope scan of REAL servers (Samba, OpenSSH, OpenSSL s_server, nginx) against
what those servers were configured to do. Python standard library only. Used by
lab/real_servers.sh (CI job `real-servers`); see docs/src/lab-and-testing.md.

  python -I lab/real_servers_check.py --scan scan.json [--only smb,ssh,tls,nginx]
  python -I lab/real_servers_check.py --shell-env      # the lab constants for real_servers.sh

The lab constants below are the single source of the servers' configuration AND of the expected
results: real_servers.sh reads them with --shell-env, so a value cannot differ between what a
server was told and what the scan is expected to find. Two values are computed here from the
server itself, independently of Network Scope:

  - HASSHServer: the server's SSH_MSG_KEXINIT is read over a raw socket and hashed with
    hashlib.md5 as the HASSH definition says (kex;enc_s2c;mac_s2c;comp_s2c).
  - JA4S: a TLS 1.3 ClientHello is sent and the ServerHello hashed with hashlib.sha256 as the
    JA4S definition says. This is a re-implementation written from the documented algorithm,
    not FoxIO's reference implementation (which needs tshark and pcaps); the Rust unit tests
    check the algorithm against the published FoxIO examples.
"""
import argparse
import hashlib
import json
import os
import socket
import struct
import sys

HOST = "127.0.0.1"
LAB = {
    # Samba (smbd must run as root to bind 445: Network Scope runs the SMB negotiate on 445 only)
    "SMB_PORT": 445,
    "SMB_NETBIOS": "NSLABSMB",
    "SMB_WORKGROUP": "LABGROUP",
    "SMB_ENCRYPTION": "AES-128-GCM",
    # OpenSSH on a port that is neither 22 nor 2222 (2222 is probed listen-only)
    "SSH_PORT": 2200,
    # openssl s_server A: TLS 1.3 only, two suites, the server's order is used (-serverpref)
    "TLS_A_PORT": 8443,
    "TLS_A_SUITES": "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384",
    # openssl s_server B: TLS 1.2 and 1.3, one suite each
    "TLS_B_PORT": 9443,
    "TLS_B_13": "TLS_AES_128_GCM_SHA256",
    "TLS_B_12": "ECDHE-RSA-AES256-GCM-SHA384",
    # nginx with TLS 1.2 and 1.3
    "NGINX_PORT": 6443,
    "NGINX_13": "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384",
    "NGINX_12": "ECDHE-RSA-AES128-GCM-SHA256",
    "CERT_CN": "ns-lab.invalid",
}
# OpenSSL names of TLS 1.2 suites -> the names Network Scope prints.
TLS12_NAMES = {
    "ECDHE-RSA-AES256-GCM-SHA384": "ECDHE_RSA_AES_256_GCM_SHA384",
    "ECDHE-RSA-AES128-GCM-SHA256": "ECDHE_RSA_AES_128_GCM_SHA256",
}
# The TLS 1.3 suites Network Scope offers, in its order (core/src/tls.rs TLS13_SUITES).
TLS13_OFFER = [0x1301, 0x1302, 0x1303, 0x1304, 0x1305]
# A valid X25519 public value (u = 9). Windows Schannel rejects random 32 bytes with a decode_error.
X25519_BASE_POINT = b"\x09" + b"\x00" * 31


def shell_env():
    return "\n".join(f"export {k}='{v}'" for k, v in LAB.items())


# ---- independent computations from the live server ---------------------------------------

def _read_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise OSError(f"connection closed after {len(data)} of {n} bytes")
        data += chunk
    return data


def parse_kexinit(payload):
    """The ten name-lists of an SSH_MSG_KEXINIT payload (message number 20, 16 cookie bytes)."""
    if not payload or payload[0] != 20:
        raise ValueError("not a KEXINIT")
    pos, lists = 17, []
    for _ in range(10):
        (n,) = struct.unpack(">I", payload[pos:pos + 4])
        lists.append(payload[pos + 4:pos + 4 + n].decode("ascii"))
        pos += 4 + n
    return lists


def hassh_server(lists):
    """HASSHServer (Salesforce): md5 of kex;enc_s2c;mac_s2c;comp_s2c."""
    text = ";".join([lists[0], lists[3], lists[5], lists[7]])
    return hashlib.md5(text.encode()).hexdigest(), text


def server_hassh(host, port, timeout=10):
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(b"SSH-2.0-network-scope-lab-check\r\n")
        buf = b""
        while b"\n" not in buf:  # the server's identification line
            buf += s.recv(1)
        banner_end = buf.index(b"\n") + 1
        rest = buf[banner_end:]
        while len(rest) < 5:
            rest += s.recv(5 - len(rest))
        length, pad = struct.unpack(">IB", rest[:5])
        body = rest[5:]
        while len(body) < length - 1:
            body += s.recv(length - 1 - len(body))
        payload = body[: length - 1 - pad]
    return hassh_server(parse_kexinit(payload))


def client_hello13():
    ext = lambda kind, data: struct.pack(">HH", kind, len(data)) + data  # noqa: E731
    suites = b"".join(struct.pack(">H", s) for s in TLS13_OFFER)
    extensions = (
        ext(0x002B, b"\x02\x03\x04")
        + ext(0x000A, struct.pack(">HH", 2, 0x001D))
        + ext(0x000D, struct.pack(">H", 10) + b"".join(struct.pack(">H", a) for a in (0x0804, 0x0805, 0x0806, 0x0401, 0x0403)))
        + ext(0x0033, struct.pack(">H", 36) + struct.pack(">HH", 0x001D, 32) + X25519_BASE_POINT)
    )
    body = (
        b"\x03\x03" + os.urandom(32) + b"\x20" + os.urandom(32)
        + struct.pack(">H", len(suites)) + suites + b"\x01\x00"
        + struct.pack(">H", len(extensions)) + extensions
    )
    handshake = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


def parse_server_hello(record):
    """(legacy_version, cipher, [extension types], selected_version or None, alpn or None)."""
    if record[0] != 22 or record[5] != 2:
        raise ValueError("not a ServerHello")
    body = record[9:]
    version = struct.unpack(">H", body[:2])[0]
    pos = 2 + 32
    pos += 1 + body[pos]
    (cipher,) = struct.unpack(">H", body[pos:pos + 2])
    pos += 3
    exts, selected, alpn = [], None, None
    if pos < len(body):
        (total,) = struct.unpack(">H", body[pos:pos + 2])
        data, i = body[pos + 2:pos + 2 + total], 0
        while i + 4 <= len(data):
            kind, n = struct.unpack(">HH", data[i:i + 4])
            value = data[i + 4:i + 4 + n]
            exts.append(kind)
            if kind == 0x002B and len(value) >= 2:
                selected = struct.unpack(">H", value[:2])[0]
            if kind == 0x0010 and len(value) >= 3:
                alpn = value[3:3 + value[2]].decode("latin-1")
            i += 4 + n
    return version, cipher, exts, selected, alpn


def ja4s(version, cipher, exts, selected, alpn):
    """JA4S from the documented algorithm: t<ver><ext count><alpn>_<cipher>_<sha256(exts)[:12]>."""
    ver = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3"}.get(selected or version, "00")
    if alpn:
        first = alpn[0] if ord(alpn[0]) < 128 else "9"
        last = alpn[-1] if ord(alpn[-1]) < 128 else "9"
        a = first + last
    else:
        a = "00"
    digest = hashlib.sha256(",".join(f"{e:04x}" for e in exts).encode()).hexdigest()[:12] if exts else "000000000000"
    return f"t{ver}{min(len(exts), 99):02}{a}_{cipher:04x}_{digest}"


def server_ja4s(host, port, timeout=10):
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(client_hello13())
        head = _read_exact(s, 5)
        record = head + _read_exact(s, struct.unpack(">H", head[3:5])[0])
    return ja4s(*parse_server_hello(record))


# ---- expectations -------------------------------------------------------------------------

def split(text):
    return [t for t in text.split(":") if t]


def expect_smb(identity, cfg, fail):
    p = cfg["SMB_PORT"]
    checks = [
        ("svc.%d.product" % p, "SMB"),
        ("svc.%d.version" % p, "3.1.1"),
        ("smb.%d.dialect" % p, "3.1.1"),
        ("smb.%d.smb1" % p, "refused"),
        ("smb.%d.encryption" % p, cfg["SMB_ENCRYPTION"]),
        ("smb.%d.netbios_name" % p, cfg["SMB_NETBIOS"]),
    ]
    for key, want in checks:
        if identity.get(key) != want:
            fail(f"smb: {key} is {identity.get(key)!r}, expected {want!r}")
    summary = identity.get("svc.%d" % p, "")
    if "signing required" not in summary:
        fail(f"smb: signing was configured as mandatory, but svc.{p} is {summary!r}")


def expect_ssh(identity, cfg, fail, hassh):
    p = cfg["SSH_PORT"]
    product = identity.get(f"svc.{p}.product")
    if product != "OpenSSH":
        fail(f"ssh: svc.{p}.product is {product!r}, expected 'OpenSSH'")
    cpe = identity.get(f"svc.{p}.cpe", "")
    if not cpe.startswith("cpe:2.3:a:openbsd:openssh:"):
        fail(f"ssh: svc.{p}.cpe is {cpe!r}")
    want, text = hassh
    got = identity.get(f"ssh.{p}.hassh")
    if got != want:
        fail(f"ssh: HASSHServer is {got!r}, the reference computation gives {want!r} for {text!r}")
    algorithms = identity.get(f"ssh.{p}.hassh_algorithms")
    if algorithms != text:
        fail(f"ssh: hassh_algorithms {algorithms!r} != {text!r}")


def tls_suites(identity, port):
    """({version: [suites]}) from the `ciphers` field (`TLS1.3: a, b | TLS1.2: c`)."""
    out = {}
    for part in identity.get(f"tls.{port}.ciphers", "").split(" | "):
        version, _, names = part.partition(": ")
        out[version] = [n for n in names.split(", ") if n]
    return out


def expect_tls(identity, port, fail, label, want13, want12=None, ordered=False, ja4s_value=None):
    """`want13` and `want12` are the exact suites the server was configured with."""
    got13 = split(identity.get(f"tls.{port}.tls13_suites", "").replace(", ", ":"))
    ok = got13 == want13 if ordered else sorted(got13) == sorted(want13)
    if not ok:
        fail(f"{label}: TLS 1.3 suites are {got13}, the server was configured with {want13}"
             + (" (in this order)" if ordered else ""))
    suites = tls_suites(identity, port)
    if sorted(suites.get("TLS1.3", [])) != sorted(want13):
        fail(f"{label}: ciphers field {suites} does not list the TLS 1.3 suites {want13}")
    versions = identity.get(f"tls.{port}.versions", "")
    if want12 is None:
        if versions != "TLS1.3":
            fail(f"{label}: versions are {versions!r}, the server was TLS 1.3 only")
    else:
        names = sorted(TLS12_NAMES[s] for s in want12)
        if sorted(suites.get("TLS1.2", [])) != names:
            fail(f"{label}: TLS 1.2 suites are {suites.get('TLS1.2')}, the server was configured with {names}")
        if "TLS1.2" not in versions or "TLS1.3" not in versions or "deprecated" in versions:
            fail(f"{label}: versions are {versions!r}, expected TLS1.2 and TLS1.3 only")
    if identity.get(f"tls.{port}.suites_truncated"):
        fail(f"{label}: the suite lists were truncated by the round budget")
    weak = identity.get(f"tls.{port}.weak")
    if weak:
        fail(f"{label}: unexpected weak-suite note {weak!r}")
    ja4s_got = identity.get(f"tls.{port}.ja4s")
    if ja4s_value is not None and ja4s_got != ja4s_value:
        fail(f"{label}: JA4S is {ja4s_got!r}, the independent computation gives {ja4s_value!r}")
    self_signed = identity.get(f"tls.{port}.self_signed")
    if self_signed != "true":
        fail(f"{label}: the lab certificate is self-signed, got {self_signed!r}")


def check_scan(host, cfg, only, ssh_hassh=None, ja4s_a=None):
    """Failure messages (empty: all checks passed) for the scan result of one host."""
    failures = []
    fail = failures.append
    identity = host.get("identity", {})
    wanted = {"smb": cfg["SMB_PORT"], "ssh": cfg["SSH_PORT"], "tls": cfg["TLS_A_PORT"], "nginx": cfg["NGINX_PORT"]}
    ports = [wanted[k] for k in only] + ([cfg["TLS_B_PORT"]] if "tls" in only else [])
    for port in ports:
        if port not in host.get("open", []):
            fail(f"port {port} was not found open (open: {host.get('open')})")
    if "smb" in only:
        expect_smb(identity, cfg, fail)
    if "ssh" in only:
        expect_ssh(identity, cfg, fail, ssh_hassh)
    if "tls" in only:
        expect_tls(identity, cfg["TLS_A_PORT"], fail, "s_server A", split(cfg["TLS_A_SUITES"]), ordered=True, ja4s_value=ja4s_a)
        expect_tls(identity, cfg["TLS_B_PORT"], fail, "s_server B", split(cfg["TLS_B_13"]), [cfg["TLS_B_12"]])
        pa = cfg["TLS_A_PORT"]
        for key, want in ((f"tls.{pa}.cn", cfg["CERT_CN"]), (f"tls.{pa}.key", "RSA 2048")):
            if identity.get(key) != want:
                fail(f"s_server A: {key} is {identity.get(key)!r}, expected {want!r}")
    if "nginx" in only:
        p = cfg["NGINX_PORT"]
        expect_tls(identity, p, fail, "nginx", split(cfg["NGINX_13"]), [cfg["NGINX_12"]])
        product, cpe = identity.get(f"svc.{p}.product"), identity.get(f"svc.{p}.cpe", "")
        if product != "nginx":
            fail(f"nginx: svc.{p}.product is {product!r}")
        if not cpe.startswith("cpe:2.3:a:f5:nginx:"):
            fail(f"nginx: svc.{p}.cpe is {cpe!r}")
    return failures


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--scan", help="the JSON scan result of 127.0.0.1")
    ap.add_argument("--only", default="smb,ssh,tls,nginx", help="comma-separated parts to check")
    ap.add_argument("--shell-env", action="store_true", help="print the lab constants as shell exports")
    ap.add_argument("--host", default=HOST)
    args = ap.parse_args(argv)
    if args.shell_env:
        print(shell_env())
        return 0
    if not args.scan:
        ap.error("--scan is required")
    only = [part for part in args.only.split(",") if part]
    unknown = set(only) - {"smb", "ssh", "tls", "nginx"}
    if unknown:
        ap.error(f"unknown part(s): {sorted(unknown)}")
    with open(args.scan, encoding="utf-8") as f:
        hosts = json.load(f)["hosts"]
    host = next((h for h in hosts if h["ip"] == args.host), None)
    if host is None:
        print(f"FAIL: {args.host} is not in the scan result", file=sys.stderr)
        return 1
    hassh = ja4s_a = None
    if "ssh" in only:
        hassh = server_hassh(args.host, LAB["SSH_PORT"])
        print(f"reference HASSHServer of {args.host}:{LAB['SSH_PORT']}: {hassh[0]} ({hassh[1][:60]}...)")
    if "tls" in only:
        ja4s_a = server_ja4s(args.host, LAB["TLS_A_PORT"])
        print(f"independent JA4S of {args.host}:{LAB['TLS_A_PORT']}: {ja4s_a}")
    failures = check_scan(host, LAB, only, hassh, ja4s_a)
    for line in failures:
        print("FAIL:", line, file=sys.stderr)
    print(f"{'FAILED' if failures else 'OK'}: {len(failures)} problem(s) in {', '.join(only)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
