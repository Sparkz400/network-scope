#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright the Network Scope contributors
# SPDX-License-Identifier: MIT
"""Reference vectors for core/src/jarm.rs, produced by the reference implementation.

JARM is only comparable with public JARM databases if our ClientHellos, our reading of the
ServerHellos and our hash are the reference's. This tool loads the reference `jarm.py`
(https://github.com/salesforce/jarm, BSD-3-Clause; NOT part of this repository, download it
yourself and pass its path) and writes two files that the unit tests of core/src/jarm.rs check
byte for byte:

  core/src/jarm_reference_hellos.txt    the ten ClientHellos `jarm.py` builds for 127.0.0.1, with the
                                        client random, session id and key share replaced by fixed
                                        bytes (1s, 2s, 3s) and every GREASE value by 0x0a0a
  core/src/jarm_reference_replies.txt   ServerHello variants (and every truncation of a typical one)
                                        run through the reference `read_packet` and `jarm_hash`

  python -I lab/jarm_reference.py PATH/TO/jarm.py            # write both files
  python -I lab/jarm_reference.py PATH/TO/jarm.py --check    # compare with the files, write nothing

Only the functions of the reference are used (its module-level code after the function
definitions, which scans, is cut off); nothing is sent to the network.
"""
import argparse
import hashlib
import os
import random
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(os.path.dirname(HERE), "core", "src")
HELLOS = os.path.join(OUT, "jarm_reference_hellos.txt")
REPLIES = os.path.join(OUT, "jarm_reference_replies.txt")


def load(jarm_py):
    """The reference's functions in a namespace (its scanning code at the bottom is not run)."""
    src = open(jarm_py, encoding="utf-8").read()
    head = src.split("#set proxy")[0]
    ns = {"__name__": "jarm_reference"}
    argv = sys.argv
    sys.argv = ["jarm.py", "127.0.0.1"]
    try:
        exec(compile(head, jarm_py, "exec"), ns)
    finally:
        sys.argv = argv
    return ns


def sha256_of(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def reference_hellos(ns):
    """The ten hellos, in the reference's order, with fixed randomness."""
    calls = [0]

    def urandom(n):
        k = calls[0] % 3  # client random, session id, key share: the order the reference asks
        calls[0] += 1
        return bytes([k + 1]) * n

    ns["os"] = types.SimpleNamespace(urandom=urandom)
    ns["random"] = types.SimpleNamespace(choice=lambda items: items[0])  # 0x0a0a
    ns["destination_host"] = "127.0.0.1"
    ns["destination_port"] = 443
    sent = []

    def capture(packet):
        sent.append(bytes(packet))
        return None, "127.0.0.1"

    ns["send_packet"] = capture
    ns["args"].output = None
    ns["args"].verbose = False
    ns["args"].json = False
    out = []
    import io
    import contextlib

    with contextlib.redirect_stdout(io.StringIO()):
        ns["main"]()
    out.extend(sent)
    assert len(out) == 10, len(out)
    return out


NAMES = [
    "tls1_2_forward",
    "tls1_2_reverse",
    "tls1_2_top_half",
    "tls1_2_bottom_half",
    "tls1_2_middle_out",
    "tls1_1_middle_out",
    "tls1_3_forward",
    "tls1_3_reverse",
    "tls1_3_invalid",
    "tls1_3_middle_out",
]


def ext(kind, data):
    return kind.to_bytes(2, "big") + len(data).to_bytes(2, "big") + data


def server_hello(cipher, version=b"\x03\x03", sid=b"", exts=None, record=b"\x16\x03\x03", tail=b""):
    """A ServerHello record. `exts` None: no extensions field at all (TLS 1.2 without any)."""
    body = version + bytes([7] * 32) + bytes([len(sid)]) + sid + cipher + b"\x00"
    if exts is not None:
        body += len(exts).to_bytes(2, "big") + exts
    hs = b"\x02" + len(body).to_bytes(3, "big") + body + tail
    return record + len(hs).to_bytes(2, "big") + hs


def alpn_ext(name):
    return ext(0x0010, (len(name) + 1).to_bytes(2, "big") + bytes([len(name)]) + name)


def variants():
    """Named replies: what real servers send, and the odd cases the reference handles."""
    v = {}
    reneg = ext(0xFF01, b"\x00")
    v["tls12_ecdhe_rsa_gcm_h2"] = server_hello(
        b"\xc0\x2f", exts=reneg + ext(0x000B, b"\x01\x00") + alpn_ext(b"h2") + ext(0x0017, b"")
    )
    v["tls12_chacha_http11"] = server_hello(b"\xcc\xa8", exts=reneg + alpn_ext(b"http/1.1"))
    v["tls12_no_alpn_sid32"] = server_hello(b"\xc0\x30", sid=bytes(range(32)), exts=reneg + ext(0x0017, b""))
    v["tls13_aes128"] = server_hello(
        b"\x13\x01", sid=bytes(range(32)), exts=ext(0x002B, b"\x03\x04") + ext(0x0033, b"\x00\x1d\x00\x20" + bytes(32))
    )
    v["tls13_chacha"] = server_hello(
        b"\x13\x03", sid=bytes(32), exts=ext(0x002B, b"\x03\x04") + ext(0x0033, b"\x00\x1d\x00\x20" + bytes(32))
    )
    v["tls11_aes_cbc"] = server_hello(b"\x00\x2f", version=b"\x03\x02", exts=reneg, record=b"\x16\x03\x02")
    v["tls10_rc4"] = server_hello(b"\x00\x05", version=b"\x03\x01", exts=reneg, record=b"\x16\x03\x01")
    v["ssl3"] = server_hello(b"\x00\x0a", version=b"\x03\x00", exts=None, record=b"\x16\x03\x00", tail=b"\x0b\x00\x00\x00")
    # No extensions at all: the next handshake message (Certificate, type 11) follows directly.
    v["tls12_no_extensions"] = server_hello(b"\x00\x9c", exts=None, tail=b"\x0b\x00\x00\x03\x00\x00\x00")
    v["tls12_no_extensions_sid32"] = server_hello(b"\xc0\x2b", sid=bytes(32), exts=None, tail=b"\x0b\x00\x00\x03\x00\x00\x00")
    v["unknown_cipher"] = server_hello(b"\xc0\xff", exts=reneg)
    v["null_cipher"] = server_hello(b"\x00\x00", exts=reneg)
    v["alpn_zero_length"] = server_hello(b"\xc0\x2f", exts=ext(0x0010, b""))
    v["alpn_not_utf8"] = server_hello(b"\xc0\x2f", exts=ext(0x0010, b"\x00\x03\x02\xff\xfe"))
    v["alpn_short_value"] = server_hello(b"\xc0\x2f", exts=ext(0x0010, b"\x00"))
    v["alpn_spdy"] = server_hello(b"\xc0\x2f", exts=alpn_ext(b"spdy/3") + reneg)
    v["only_zero_length_extensions"] = server_hello(b"\xc0\x2f", exts=ext(0x0017, b"") + ext(0x0023, b""))
    v["ext_length_past_end"] = server_hello(b"\xc0\x2f", exts=reneg)[:-2]
    v["many_extensions"] = server_hello(b"\xc0\x2f", exts=b"".join(ext(0x0017 + i, b"\x01") for i in range(20)))
    v["hack_0eac0b"] = server_hello(b"\xc0\x2f", exts=None, tail=b"")  # patched below
    v["alert_handshake_failure"] = b"\x15\x03\x03\x00\x02\x02\x28"
    v["alert_protocol_version"] = b"\x15\x03\x03\x00\x02\x02\x46"
    v["http_400"] = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"
    v["certificate_first"] = b"\x16\x03\x03\x00\x07\x0b\x00\x00\x03\x00\x00\x00"
    v["empty"] = b""
    v["one_byte"] = b"\x16"
    # A record that claims to be shorter than the ServerHello inside it.
    hello = server_hello(b"\xc0\x2f", exts=reneg + alpn_ext(b"h2"))
    v["short_record_length"] = hello[:3] + b"\x00\x10" + hello[5:]
    # The reference's second hack: bytes 82..85 are 0f f0 0b.
    h = bytearray(server_hello(b"\xc0\x2f", sid=bytes(32), exts=reneg + alpn_ext(b"h2") + ext(0x0017, b"") + bytes(8)))
    h[82:85] = b"\x0f\xf0\x0b"
    v["hack_0ff00b"] = bytes(h)
    h = bytearray(server_hello(b"\xc0\x2f", exts=reneg + alpn_ext(b"h2") + ext(0x0017, b"") + bytes(8)))
    c = h[43]
    h[c + 50 : c + 53] = b"\x0e\xac\x0b"
    v["hack_0eac0b"] = bytes(h)
    return {k: bytes(b) for k, b in v.items()}


def reply_lines(ns):
    base = variants()
    names = list(base)
    lines = []
    rng = random.Random(1)

    def hash_of(replies):
        """`replies`: ten byte strings or None, run through the reference."""
        raws = []
        for r in replies:
            raws.append(ns["read_packet"](None if r is None else bytearray(r), None))
        return ns["jarm_hash"](",".join(raws)), ",".join(raws)

    def emit(label, replies):
        h, raw = hash_of(replies)
        # "*HEX" is ten copies of one reply, "-" is no reply at all, "~" an empty reply.
        if all(r == replies[0] for r in replies) and replies[0] is not None:
            hexes = "*" + (replies[0].hex() or "~")
        else:
            hexes = ",".join("-" if r is None else (r.hex() or "~") for r in replies)
        lines.append(f"{label} {h} {hexes}")

    emit("silent", [None] * 10)
    for n in names:
        emit(f"all_{n}", [base[n]] * 10)
    good = [n for n in names if n.startswith(("tls12", "tls13", "tls11", "tls10", "alpn_spdy"))]
    for i in range(40):
        picks = [rng.choice([None] + good + names) for _ in range(10)]
        emit(f"mixed_{i}", [None if p is None else base[p] for p in picks])
    # Every truncation of a typical reply, repeated ten times.
    typical = base["tls12_ecdhe_rsa_gcm_h2"]
    for cut in range(len(typical) + 1):
        emit(f"cut_{cut}", [typical[:cut]] * 10)
    typical = base["tls13_aes128"]
    for cut in range(len(typical) + 1):
        emit(f"cut13_{cut}", [typical[:cut]] * 10)
    return lines


def cipher_table(ns):
    """The reference's cipher table as `index:cipher` pairs, read back through `cipher_bytes`:
    every 16-bit value not in the table maps to the same "not found" index."""
    found = {}
    for c in range(0x10000):
        idx = ns["cipher_bytes"]("%04x" % c)
        found.setdefault(idx, []).append(c)
    unknown = max(found, key=lambda k: len(found[k]))
    pairs = sorted((int(k, 16), v[0]) for k, v in found.items() if k != unknown and len(v) == 1)
    assert all(len(v) == 1 for k, v in found.items() if k != unknown), "a table entry twice"
    return unknown, pairs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("jarm_py")
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args()
    ns = load(a.jarm_py)
    hellos = reference_hellos(ns)
    header = (
        "# Generated by lab/jarm_reference.py from the reference jarm.py (sha256 {}); do not edit.\n"
    ).format(sha256_of(a.jarm_py))
    hello_text = header + "".join(f"{n} {h.hex()}\n" for n, h in zip(NAMES, hellos))
    ns = load(a.jarm_py)
    unknown, pairs = cipher_table(ns)
    reply_text = header + f"cipher_table unknown={unknown} " + " ".join(f"{i}:{c:04x}" for i, c in pairs) + "\n"
    reply_text += "".join(l + "\n" for l in reply_lines(ns))
    if a.check:
        ok = open(HELLOS, encoding="utf-8").read() == hello_text and open(REPLIES, encoding="utf-8").read() == reply_text
        print("up to date" if ok else "DIFFERENT")
        sys.exit(0 if ok else 1)
    for path, text in ((HELLOS, hello_text), (REPLIES, reply_text)):
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        print(path, len(text), "bytes")


if __name__ == "__main__":
    main()
