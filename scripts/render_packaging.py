"""Fills the package-manager templates in packaging/ (winget, Scoop, Chocolatey, Homebrew, AUR)
with a release's version and SHA-256 hashes, ready to submit (roadmap I56). release.yml runs it
and attaches the result as network-scope-<version>-packaging.tar.gz.

    python -I scripts/render_packaging.py VERSION DIST_DIR SOURCE_SHA256 OUT_DIR [RELEASE_DATE]

DIST_DIR holds the release files (the hashes are computed from them); SOURCE_SHA256 is the hash
of GitHub's tag archive (archive/refs/tags/vVERSION.tar.gz), which the Homebrew formula builds.
"""

import datetime
import hashlib
import json
import os
import re
import sys
import xml.etree.ElementTree as ET

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "packaging")
TEMPLATES = ["winget", "scoop", "chocolatey", "homebrew", "aur"]
HASH = re.compile(r"^[0-9a-f]{64}$")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def values(version, dist, source_sha256, release_date):
    files = {
        "SHA256_WINDOWS_SETUP": f"NetworkScope-{version}-setup.exe",
        "SHA256_WINDOWS_ZIP": f"network-scope-{version}-windows-x64.zip",
        "SHA256_LINUX": f"network-scope-{version}-linux-x86_64.tar.gz",
    }
    out = {name: sha256(os.path.join(dist, file)) for name, file in files.items()}
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError(f"version {version!r} is not MAJOR.MINOR.PATCH")
    if not HASH.match(source_sha256):
        raise ValueError("SOURCE_SHA256 is not a lowercase SHA-256 hex digest")
    datetime.date.fromisoformat(release_date)
    out.update(VERSION=version, SHA256_SOURCE=source_sha256, RELEASE_DATE=release_date)
    return out


def render(vals, out_dir):
    written = []
    for name in TEMPLATES:
        for folder, _, files in os.walk(os.path.join(ROOT, name)):
            for file in files:
                src = os.path.join(folder, file)
                dst = os.path.join(out_dir, os.path.relpath(src, ROOT))
                with open(src, encoding="utf-8", newline="") as f:
                    text = f.read()
                text = re.sub(r"@([A-Z0-9_]+)@", lambda m: vals[m.group(1)], text)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                with open(dst, "w", encoding="utf-8", newline="") as f:
                    f.write(text)
                written.append(dst)
    # Syntax checks of what Python can parse without extra packages.
    for path in written:
        if path.endswith(".json"):
            with open(path, encoding="utf-8") as f:
                json.load(f)
        elif path.endswith(".nuspec"):
            ET.parse(path)
    return written


def main():
    if len(sys.argv) not in (5, 6):
        sys.exit(__doc__)
    version, dist, source_sha256, out_dir = sys.argv[1:5]
    release_date = sys.argv[5] if len(sys.argv) == 6 else datetime.date.today().isoformat()
    for path in render(values(version, dist, source_sha256, release_date), out_dir):
        print(path)


if __name__ == "__main__":
    main()
