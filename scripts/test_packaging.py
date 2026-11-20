import importlib.util
import os
import re
import struct
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


render = load("render_packaging")
strip = load("strip_authenticode")


class RenderPackaging(unittest.TestCase):
    def test_every_placeholder_is_filled_and_hashes_match_the_files(self):
        with tempfile.TemporaryDirectory() as dist, tempfile.TemporaryDirectory() as out:
            for name in ("NetworkScope-9.8.7-setup.exe", "network-scope-9.8.7-windows-x64.zip",
                         "network-scope-9.8.7-linux-x86_64.tar.gz"):
                with open(os.path.join(dist, name), "wb") as f:
                    f.write(name.encode())
            vals = render.values("9.8.7", dist, "a" * 64, "2026-11-20")
            written = render.render(vals, out)
            self.assertEqual(len(written), 9)
            setup_hash = render.sha256(os.path.join(dist, "NetworkScope-9.8.7-setup.exe"))
            for path in written:
                with open(path, encoding="utf-8") as f:
                    text = f.read()
                self.assertIsNone(re.search(r"@[A-Z0-9_]+@", text), path)
                self.assertIn("9.8.7", text, path)
            with open(os.path.join(out, "chocolatey", "tools", "chocolateyinstall.ps1")) as f:
                self.assertIn(setup_hash, f.read())

    def test_a_bad_version_or_source_hash_is_refused(self):
        with tempfile.TemporaryDirectory() as dist:
            for name in ("NetworkScope-1.0.0-setup.exe", "network-scope-1.0.0-windows-x64.zip",
                         "network-scope-1.0.0-linux-x86_64.tar.gz"):
                open(os.path.join(dist, name), "wb").close()
            with self.assertRaises(ValueError):
                render.values("1.0.0", dist, "not-a-hash", "2026-11-20")
            with self.assertRaises(FileNotFoundError):
                render.values("1.0.1", dist, "a" * 64, "2026-11-20")


def fake_pe(signature=b""):
    """Minimal PE32+ layout: DOS header, PE signature, COFF header, optional header with the
    data directories, 512 bytes of section data, then the certificate table if any."""
    data = bytearray(1024)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    opt = 0x80 + 24
    struct.pack_into("<H", data, opt, 0x20B)
    data[512:1024] = bytes(range(256)) * 2
    if signature:
        struct.pack_into("<I", data, opt + 64, 0x1234)  # checksum written by signtool
        struct.pack_into("<II", data, opt + 112 + 32, len(data), len(signature))
        data += signature
    return bytes(data)


class StripAuthenticode(unittest.TestCase):
    def test_a_signed_and_an_unsigned_build_strip_to_the_same_bytes(self):
        unsigned, signed = fake_pe(), fake_pe(b"\x30\x82" + b"\x01" * 100)
        self.assertNotEqual(unsigned, signed)
        self.assertEqual(strip.strip(unsigned), strip.strip(signed))

    def test_other_files_are_refused(self):
        with self.assertRaises(ValueError):
            strip.strip(b"\x7fELF" + bytes(200))


if __name__ == "__main__":
    unittest.main()
