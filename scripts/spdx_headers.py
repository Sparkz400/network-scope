#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright the Network Scope contributors
# SPDX-License-Identifier: MIT
"""Check or add the SPDX copyright and license header of every source file.

OpenSSF Best Practices (gold) asks for a copyright and a license statement in each source file.
Every tracked .rs, .py, .sh, .ps1 and .iss file starts with these two comment lines (after a
shebang, if any):

  // SPDX-FileCopyrightText: Copyright the Network Scope contributors
  // SPDX-License-Identifier: MIT

Files derived from third-party code name their extra holder and license in EXTRA below.
Standard library only; run it isolated from the repository root:

  python -I scripts/spdx_headers.py          # check, exit 1 if a file lacks its header
  python -I scripts/spdx_headers.py --fix    # add missing headers, keeping each file's line ends
"""

import subprocess
import sys

HOLDER = "Copyright the Network Scope contributors"
LICENSE = "MIT"
COMMENT = {".rs": "//", ".py": "#", ".sh": "#", ".ps1": "#", ".iss": ";"}
SKIP_PREFIXES = ("fuzz/corpus/", "target/")
# Path -> (extra copyright holder, SPDX license expression of the file).
EXTRA = {
    "core/src/jarm.rs": ("Copyright (c) 2020, Salesforce.com, Inc.", "MIT AND BSD-3-Clause"),
}


def header(path):
    """The header lines (without line ends) a file must start with."""
    c = COMMENT["." + path.rsplit(".", 1)[-1]]
    extra, license_ = EXTRA.get(path, (None, LICENSE))
    lines = [f"{c} SPDX-FileCopyrightText: {HOLDER}"]
    if extra:
        lines.append(f"{c} SPDX-FileCopyrightText: {extra}")
    lines.append(f"{c} SPDX-License-Identifier: {license_}")
    return lines


def newline(text):
    """The file's own line end, kept on insert (Windows checkouts with autocrlf use CRLF)."""
    return "\r\n" if "\r\n" in text else "\n"


def split_prolog(text):
    """Lines that must stay above the header: a shebang and a Python encoding line."""
    lines = text.split(newline(text))
    n = 0
    if lines and lines[0].startswith("#!"):
        n = 1
    if len(lines) > n and lines[n].startswith("#") and "coding" in lines[n] and n < 2:
        n += 1
    return lines[:n], lines[n:]


def has_header(path, text):
    _, body = split_prolog(text)
    want = header(path)
    return body[: len(want)] == want


def add_header(path, text):
    """The text with the header inserted; unchanged if it is already there."""
    if has_header(path, text):
        return text
    prolog, body = split_prolog(text)
    return newline(text).join(prolog + header(path) + body)


def source_files():
    out = subprocess.run(["git", "ls-files", "-z"], capture_output=True, check=True).stdout
    for p in out.decode("utf-8").split("\0"):
        if p and "." + p.rsplit(".", 1)[-1] in COMMENT and not p.startswith(SKIP_PREFIXES):
            yield p


def main(argv):
    fix = "--fix" in argv
    missing = []
    for path in source_files():
        with open(path, "rb") as f:
            raw = f.read()
        text = raw.decode("utf-8")
        if has_header(path, text):
            continue
        missing.append(path)
        if fix:
            with open(path, "wb") as f:
                f.write(add_header(path, text).encode("utf-8"))
    if fix:
        print(f"added the SPDX header to {len(missing)} files")
        return 0
    for path in missing:
        print(f"{path}: missing SPDX header, run python -I scripts/spdx_headers.py --fix")
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
