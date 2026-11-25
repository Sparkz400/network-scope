#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright the Network Scope contributors
# SPDX-License-Identifier: MIT
"""Checks the CPE names Network Scope derives (the `cpe` table of data/cves.json, which produces
the `svc.<port>.cpe` identity values) against the official NVD CPE dictionary. Python standard
library only.

  python -I lab/check_cpe.py                        # format check only, no network, no files
  python -I lab/check_cpe.py --download feed.tar.gz # fetch the pinned NVD CPE 2.0 feed (CI)
  python -I lab/check_cpe.py --dictionary feed.tar.gz [--dictionary more ...]

Without --dictionary only the format is checked: every template is a 13-part CPE 2.3 formatted
string with a lower-case vendor and product, and the placeholders {version}, {base} and {update}
only where a version belongs. With --dictionary every vendor:product pair must exist in the
dictionary as a current (not deprecated) name; a pair that is missing, or that exists only as a
deprecated name, fails the check (exit status 1). The dictionary can be:

  - the NVD CPE 2.0 feed (nvdcpe-2.0.tar.gz or nvdcpe-2.0.zip, JSON chunks), the pinned source,
  - a single JSON chunk or the answer of the NVD CPE API 2.0, or
  - the older XML dictionary (official-cpe-dictionary_v2.3.xml, also .gz).

The files are scanned as bytes, one archive member at a time in blocks, for the names
`cpe:2.3:<part>:<vendor>:<product>:`; nothing is extracted to disk and no JSON is parsed, so the
feed's inner layout only matters for the deprecation flag (`"deprecated":false,"cpeName":"..."`
in the JSON feeds).
"""
import argparse
import gzip
import io
import json
import os
import re
import sys
import tarfile
import time
import urllib.request
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CVES = os.path.join(HERE, "..", "data", "cves.json")

# The pinned source: the NVD CPE 2.0 feed (the dictionary as JSON chunks, rebuilt daily).
# https://nvd.nist.gov/products/cpe lists it; the older XML dictionary and the 1.x feeds have
# been retired by NVD. The name is stable, the content is not: the check therefore asks for
# "this pair exists today", not for a hash of the file.
NVD_CPE_FEED_URL = "https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.tar.gz"

# A real dictionary has over a million names; a download that was cut short or replaced by an
# error page must not pass vacuously.
MIN_NAMES = 100_000

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.\-~]*$")
PLACEHOLDERS = ("{version}", "{base}", "{update}")
BLOCK = 8 * 1024 * 1024
OVERLAP = 512


class Problem(Exception):
    pass


def load_pairs(path):
    """[(id, part, vendor, product, template)] from the `cpe` table, after the format check."""
    with open(path, encoding="utf-8") as f:
        table = json.load(f).get("cpe", [])
    pairs, seen = [], set()
    for rule in table:
        rid, template = rule.get("id", ""), rule.get("template", "")
        fields = template.split(":")
        where = f"cpe rule {rid!r}"
        if not rid or rid in seen:
            raise Problem(f"{where}: empty or duplicate id")
        seen.add(rid)
        if len(fields) != 13 or fields[:2] != ["cpe", "2.3"]:
            raise Problem(f"{where}: {template!r} is not a 13-part cpe:2.3 name")
        part, vendor, product = fields[2], fields[3], fields[4]
        if part not in ("a", "o", "h"):
            raise Problem(f"{where}: part {part!r} is not a, o or h")
        for label, value in (("vendor", vendor), ("product", product)):
            if not NAME_RE.match(value):
                raise Problem(f"{where}: {label} {value!r} is not a lower-case CPE name")
        if not any(p in fields[5] for p in PLACEHOLDERS):
            raise Problem(f"{where}: the version field {fields[5]!r} has no placeholder")
        for i, field in enumerate(fields):
            if i not in (5, 6) and any(p in field for p in PLACEHOLDERS):
                raise Problem(f"{where}: a placeholder in field {i} ({field!r})")
        if not rule.get("products"):
            raise Problem(f"{where}: no products")
        pairs.append((rid, part, vendor, product, template))
    if not pairs:
        raise Problem("the cpe table is empty")
    return pairs


class Scan:
    """What a dictionary says about the needed names."""

    def __init__(self, pairs):
        self.names = 0
        self.needles = {}
        for _rid, part, vendor, product, _t in pairs:
            self.needles[f"cpe:2.3:{part}:{vendor}:{product}:".encode()] = {"current": 0, "deprecated": 0, "other": 0}
        self.tail = b""

    def feed(self, block):
        """Scans `block` (continuing the previous one)."""
        data = self.tail + block
        old = len(self.tail)
        self.names += data.count(b"cpe:2.3:") - self.tail.count(b"cpe:2.3:")
        for needle, hits in self.needles.items():
            at = data.find(needle)
            while at != -1:
                # A hit that ends inside the old tail was counted with the previous block.
                if at + len(needle) > old:
                    hits[self.classify(data[max(0, at - 80):at])] += 1
                at = data.find(needle, at + 1)
        self.tail = data[-OVERLAP:]

    @staticmethod
    def classify(before):
        if re.search(rb'"deprecated"\s*:\s*false\s*,\s*"cpeName"\s*:\s*"$', before):
            return "current"
        if re.search(rb'"deprecated"\s*:\s*true\s*,\s*"cpeName"\s*:\s*"$', before):
            return "deprecated"
        # The XML dictionary: <cpe-23:cpe23-item name="...">, current unless the item says so.
        if before.endswith(b'cpe23-item name="'):
            return "current"
        # A name quoted somewhere else (the "deprecates" list of another entry, a match string).
        return "other"

    def finish_member(self):
        self.tail = b""


def read_blocks(stream):
    while True:
        block = stream.read(BLOCK)
        if not block:
            return
        yield block


def scan_stream(scan, stream):
    for block in read_blocks(stream):
        scan.feed(block)
    scan.finish_member()


def scan_file(scan, path):
    """Scans a dictionary file: tar.gz/tar, zip, gz, or a plain JSON/XML file."""
    with open(path, "rb") as f:
        magic = f.read(4)
    if magic[:2] == b"PK":
        with zipfile.ZipFile(path) as z:
            for info in z.infolist():
                if not info.is_dir():
                    with z.open(info) as member:
                        scan_stream(scan, member)
    elif magic[:2] == b"\x1f\x8b":
        # tar.gz (the feed) or a plain gzip (the XML dictionary).
        try:
            with tarfile.open(path, "r|gz") as t:
                for info in t:
                    if info.isfile():
                        scan_stream(scan, t.extractfile(info))
            return
        except tarfile.ReadError:
            pass
        with gzip.open(path, "rb") as member:
            scan_stream(scan, member)
    elif tarfile.is_tarfile(path):
        with tarfile.open(path, "r|") as t:
            for info in t:
                if info.isfile():
                    scan_stream(scan, t.extractfile(info))
    else:
        with open(path, "rb") as member:
            scan_stream(scan, member)


def judge(pairs, scan, min_names):
    """[(status, message)] per pair; status is ok, missing or deprecated."""
    if scan.names < min_names:
        raise Problem(
            f"the dictionary has only {scan.names} CPE names (expected over {min_names}); "
            "the download is incomplete or is not the CPE dictionary"
        )
    out = []
    # Did any needed name carry a deprecation flag we understand? If none did, the layout of the
    # file is not the one this script knows and "other" hits are the normal current entries.
    flags_understood = any(h["current"] or h["deprecated"] for h in scan.needles.values())
    for rid, part, vendor, product, _t in pairs:
        hits = scan.needles[f"cpe:2.3:{part}:{vendor}:{product}:".encode()]
        name = f"{part}:{vendor}:{product}"
        if hits["current"]:
            out.append(("ok", f"{rid}: {name} ({hits['current']} current names)"))
        elif hits["other"] and not flags_understood:
            out.append(("ok", f"{rid}: {name} ({hits['other']} names; deprecation flags not recognised in this file)"))
        elif hits["deprecated"] or hits["other"]:
            out.append(("deprecated", f"{rid}: {name} exists only as a deprecated name"))
        else:
            out.append(("missing", f"{rid}: {name} is not in the dictionary"))
    return out


def download(url, dest, attempts=5):
    last = None
    for attempt in range(attempts):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "network-scope-cpe-check"})
            with urllib.request.urlopen(request, timeout=120) as r, open(dest, "wb") as f:
                size = 0
                while True:
                    block = r.read(1 << 20)
                    if not block:
                        break
                    f.write(block)
                    size += len(block)
            if size < 1 << 20:
                raise OSError(f"only {size} bytes")
            return size
        except OSError as e:
            last = e
            time.sleep(5 * (attempt + 1))
    raise Problem(f"could not download {url}: {last}")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--cves", default=DEFAULT_CVES, help="cves.json (default: data/cves.json)")
    ap.add_argument("--dictionary", action="append", default=[], help="NVD CPE feed or dictionary file")
    ap.add_argument("--download", metavar="FILE", help="download the pinned NVD CPE 2.0 feed to FILE and check against it")
    ap.add_argument("--min-names", type=int, default=MIN_NAMES, help="fail if the dictionary has fewer names")
    ap.add_argument("--print-feed-url", action="store_true")
    args = ap.parse_args(argv)
    if args.print_feed_url:
        print(NVD_CPE_FEED_URL)
        return 0
    try:
        pairs = load_pairs(args.cves)
        print(f"format ok: {len(pairs)} CPE templates ({', '.join(sorted({f'{p[2]}:{p[3]}' for p in pairs}))})")
        if args.download:
            print(f"downloading {NVD_CPE_FEED_URL} ...")
            print(f"{download(NVD_CPE_FEED_URL, args.download)} bytes")
            args.dictionary.append(args.download)
        if not args.dictionary:
            print("no dictionary given: the names were NOT compared with the NVD dictionary")
            return 0
        scan = Scan(pairs)
        for path in args.dictionary:
            scan_file(scan, path)
        results = judge(pairs, scan, args.min_names)
    except (Problem, OSError, tarfile.TarError, zipfile.BadZipFile, json.JSONDecodeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    bad = 0
    for status, message in results:
        print(f"{status.upper():10} {message}")
        bad += status != "ok"
    print(f"{scan.names} names scanned; {len(results) - bad} of {len(results)} pairs are current dictionary names")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
