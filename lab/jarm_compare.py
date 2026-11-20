#!/usr/bin/env python3
"""Compares the JARM fingerprints of Network Scope with the reference implementation, against
live TLS servers on loopback. Exit code 0: every server gave the same fingerprint in both.

  python -I lab/jarm_compare.py --jarm-py PATH/TO/jarm.py --cli target/release/network-scope-cli[.exe]
                                [--schannel] [--keep-going]

`jarm.py` is the reference (https://github.com/salesforce/jarm, BSD-3-Clause); it is not part of
this repository: download it into a folder of its own and pass its path (the commit that was
compared last is in docs/src/detection.md). Needs `openssl` on PATH (Git for Windows ships one)
and Python's `ssl`. The servers (all on 127.0.0.1):

  openssl s_server A/B   the lab servers of lab/real_servers.sh (constants from real_servers_check.py)
  openssl s_server C     TLS 1.2 only, an RSA key exchange suite, no server preference. Served on 5671,
                         and "python ssl RSA kex" on 5061: Network Scope's service detection (rustls
                         first) recognises a TLS server that offers no modern suite only on the
                         well-known TLS ports
  python ssl default     OpenSSL defaults of the running Python, ALPN h2 and http/1.1
  python ssl 1.2 chacha  TLS 1.2 only, one ChaCha20 suite, ALPN http/1.1
  python ssl legacy      TLS 1.0 to 1.3 with security level 0 and the old suites (when this
                         OpenSSL still has them)
  schannel               Windows Schannel via lab/schannel_server.ps1 (with --schannel)
  plain http             answers every hello with an HTTP 400 (no ServerHello: 62 zeros)
  closes                 accepts and closes at once (62 zeros)
  silent                 accepts and never answers (the reference times out after 20 s: zeros)

The reference is run with `-v`, so a difference shows the raw per-probe results of `jarm.py`.
Network Scope is run as `scan --services --fast --jarm --format json` (with a database of its own); ports that Network Scope does
not recognise as TLS get no JARM from it (compared as "not fingerprinted").
"""
import argparse
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import real_servers_check as lab  # noqa: E402  (constants of the lab servers)

ZEROS = "0" * 62


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_port(port, seconds=10):
    end = time.time() + seconds
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


class Servers:
    def __init__(self, work, schannel):
        self.work = work
        self.procs = []
        self.threads = []
        self.stop = threading.Event()
        self.listeners = []
        self.cert = os.path.join(work, "cert.pem")
        self.key = os.path.join(work, "key.pem")
        self.schannel = schannel
        self.list = []  # (name, port)

    def openssl(self, name, *args, public=0):
        port = free_port()
        cmd = ["openssl", "s_server", "-accept", f"127.0.0.1:{port}", "-cert", self.cert, "-key", self.key, "-www", "-quiet", *args]
        self.procs.append(subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL))
        assert wait_port(port), f"{name} did not start"
        # openssl s_server serves one connection at a time and Network Scope opens several at
        # once (a connection that waits for a banner would block the TLS inspection), so it is
        # reached through a proxy that connects to the server only when the client sends bytes.
        self.serve(name, lambda conn, up=port: self.lazy_proxy(conn, up), public)

    @staticmethod
    def lazy_proxy(conn, upstream):
        try:
            conn.settimeout(30)
            first = conn.recv(65536)
            if not first:
                return
            up = socket.create_connection(("127.0.0.1", upstream), timeout=10)
            up.sendall(first)

            def pump(a, b):
                try:
                    while True:
                        data = a.recv(65536)
                        if not data:
                            break
                        b.sendall(data)
                except OSError:
                    pass
                finally:
                    for x in (a, b):
                        try:
                            x.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass

            t = threading.Thread(target=pump, args=(up, conn), daemon=True)
            t.start()
            pump(conn, up)
            t.join(5)
        except OSError:
            pass
        finally:
            conn.close()

    def py_tls(self, name, configure, port=0):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.cert, self.key)
        configure(ctx)
        self.serve(name, lambda conn: self.tls_session(ctx, conn), port)

    def tls_session(self, ctx, conn):
        try:
            conn.settimeout(3)
            tls = ctx.wrap_socket(conn, server_side=True)
            tls.recv(1)
            tls.close()
        except Exception:
            pass

    def serve(self, name, handler, port=0):
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listener.bind(("127.0.0.1", port))
        except OSError:
            listener.bind(("127.0.0.1", 0))
        listener.listen(16)
        listener.settimeout(0.2)
        port = listener.getsockname()[1]
        self.listeners.append(listener)

        def run():
            held = []
            while not self.stop.is_set():
                try:
                    conn, _ = listener.accept()
                except OSError:
                    continue
                if handler is None:
                    held.append(conn)  # silent: keep it open
                else:
                    threading.Thread(target=handler, args=(conn,), daemon=True).start()

        t = threading.Thread(target=run, daemon=True)
        t.start()
        self.threads.append(t)
        self.list.append((name, port))

    def start(self):
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", self.key, "-out", self.cert, "-days", "2",
             "-subj", "/CN=jarm.invalid", "-addext", "subjectAltName=DNS:jarm.invalid,IP:127.0.0.1"],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        L = lab.LAB
        self.openssl("openssl A: TLS 1.3 only, 2 suites", "-tls1_3", "-ciphersuites", L["TLS_A_SUITES"], "-serverpref")
        self.openssl("openssl B: TLS 1.2 + 1.3, 1 suite each", "-cipher", L["TLS_B_12"], "-ciphersuites", L["TLS_B_13"], "-serverpref")
        self.openssl("openssl C: TLS 1.2 only, RSA kex", "-tls1_2", "-cipher", "AES256-GCM-SHA384", public=5671)
        self.openssl("openssl D: TLS 1.2 + 1.3, defaults")

        def default(ctx):
            ctx.set_alpn_protocols(["h2", "http/1.1"])

        def chacha(ctx):
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2
            ctx.set_ciphers("ECDHE-RSA-CHACHA20-POLY1305")
            ctx.set_alpn_protocols(["http/1.1"])

        def rsa_kex(ctx):
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2
            ctx.set_ciphers("AES256-GCM-SHA384")

        def legacy(ctx):
            ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
            ctx.set_ciphers("ALL:@SECLEVEL=0")

        def tls13_only(ctx):
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3

        self.py_tls("python ssl: defaults, ALPN h2/http1.1", default)
        self.py_tls("python ssl: TLS 1.2 only, ChaCha20", chacha)
        self.py_tls("python ssl: TLS 1.3 only", tls13_only)
        self.py_tls("python ssl: TLS 1.2, RSA key exchange", rsa_kex, 5061)
        try:
            self.py_tls("python ssl: legacy TLS 1.0+, seclevel 0", legacy)
        except ssl.SSLError as e:
            print("skipped the legacy server:", e)
        if self.schannel:
            self.start_schannel()
        self.serve("plain http (400)", lambda c: (c.recv(2048), c.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"), c.close()))
        self.serve("closes at once", lambda c: c.close())
        self.serve("silent (never answers)", None)

    def start_schannel(self):
        stop = os.path.join(self.work, "schannel.stop")
        p = subprocess.Popen(
            ["pwsh", "-NoProfile", "-File", os.path.join(HERE, "schannel_server.ps1"), "-Seconds", "300", "-StopFile", stop],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        self.procs.append(p)
        self.schannel_stop = stop
        line = p.stdout.readline().strip()
        assert line.startswith("READY "), line
        self.list.append(("schannel (Windows .NET SslStream)", int(line.split()[1])))

    def close(self):
        self.stop.set()
        if self.schannel and hasattr(self, "schannel_stop"):
            open(self.schannel_stop, "w").close()
            time.sleep(1.5)
        for p in self.procs:
            p.kill()
        for l in self.listeners:
            l.close()


def reference(jarm_py, port, out):
    r = subprocess.run([sys.executable, "-I", jarm_py, "127.0.0.1", "-p", str(port), "-v"], capture_output=True, text=True, timeout=300)
    m = re.search(r"^JARM: (\w+)$", r.stdout, re.M)
    out[port] = (m.group(1) if m else f"no result: {r.stdout!r} {r.stderr!r}", r.stdout)


def ours(cli, ports, db):
    cmd = [cli, "scan", "127.0.0.1", "--ports", ",".join(str(p) for p in ports), "--services", "--fast", "--jarm",
           "--db", db, "--format", "json"]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if r.returncode not in (0, 1, 2):
        print(r.stdout, r.stderr)
    text = r.stdout
    found = {}
    for m in re.finditer(r'"tls\.(\d+)\.jarm"\s*:\s*"(\w+)"', text):
        found[int(m.group(1))] = m.group(2)
    return found, text


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--jarm-py", required=True)
    ap.add_argument("--cli", required=True)
    ap.add_argument("--schannel", action="store_true")
    ap.add_argument("--keep-going", action="store_true")
    a = ap.parse_args()
    a.cli = os.path.abspath(a.cli)
    a.jarm_py = os.path.abspath(a.jarm_py)
    if not shutil.which("openssl"):
        sys.exit("openssl is not on PATH")
    work = tempfile.mkdtemp(prefix="ns-jarm-")
    servers = Servers(work, a.schannel)
    try:
        servers.start()
        refs = {}
        # The reference one server after the other (Schannel and openssl s_server are serial and
        # drop hellos under parallel load); only the servers that never answer wait in the
        # background, the reference gives up on them after 20 seconds.
        slow = [(n, p) for n, p in servers.list if n.startswith("silent")]
        threads = [threading.Thread(target=reference, args=(a.jarm_py, port, refs)) for _, port in slow]
        for t in threads:
            t.start()
        for _, port in servers.list:
            if (_, port) not in slow:
                reference(a.jarm_py, port, refs)
        # One after the other: openssl s_server serves one connection at a time.
        mine, text = ours(a.cli, [p for _, p in servers.list], os.path.join(work, "inventory.sqlite"))
        for t in threads:
            t.join()
        bad = 0
        print(f"{'server':44} {'reference jarm.py':64} {'network-scope':64} same")
        for name, port in servers.list:
            ref = refs[port][0]
            got = mine.get(port)
            if got is None:
                # Not recognised as TLS by Network Scope: only meaningful when the reference says zeros.
                same = "n/a (not TLS)" if ref == ZEROS else "NO (not fingerprinted)"
                bad += ref != ZEROS
            else:
                same = "yes" if got == ref else "NO"
                bad += got != ref
            print(f"{name:44} {ref:64} {str(got):64} {same}")
            if got is not None and got != ref:
                print(refs[port][1])
        print("all equal" if not bad else f"{bad} server(s) differ")
        sys.exit(1 if bad else 0)
    finally:
        servers.close()
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
