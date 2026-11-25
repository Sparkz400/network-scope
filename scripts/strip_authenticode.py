# SPDX-FileCopyrightText: Copyright the Network Scope contributors
# SPDX-License-Identifier: MIT
"""Removes the Authenticode signature from a Windows PE file (.exe), to compare a rebuild with a
signed release binary (docs/src/supply-chain.md#code-signing).

    python -I scripts/strip_authenticode.py SIGNED_OR_UNSIGNED.exe OUT.exe

Signing changes three things, all undone here: the attribute certificate table appended to the
file (cut off), its entry in the data directory and the PE checksum (both zeroed). Trailing zero
bytes are cut too, because signtool pads the file to 8 bytes before the table. Run it on both
files, the signed release binary and your unsigned rebuild, and compare the SHA-256 printed.
"""

import hashlib
import struct
import sys


def strip(data: bytes) -> bytes:
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[:2] != b"MZ" or data[pe : pe + 4] != b"PE\0\0":
        raise ValueError("not a PE file")
    opt = pe + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    directories = opt + {0x10B: 96, 0x20B: 112}[magic]  # PE32, PE32+
    cert_entry = directories + 4 * 8  # IMAGE_DIRECTORY_ENTRY_SECURITY
    cert_offset, cert_size = struct.unpack_from("<II", data, cert_entry)
    out = bytearray(data[:cert_offset] if cert_size else data)
    struct.pack_into("<I", out, opt + 64, 0)  # CheckSum
    struct.pack_into("<II", out, cert_entry, 0, 0)
    return bytes(out).rstrip(b"\0")


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    with open(sys.argv[1], "rb") as f:
        out = strip(f.read())
    with open(sys.argv[2], "wb") as f:
        f.write(out)
    print(hashlib.sha256(out).hexdigest(), sys.argv[2])


if __name__ == "__main__":
    main()
