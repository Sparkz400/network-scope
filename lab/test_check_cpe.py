"""Unit tests of lab/check_cpe.py with small synthetic dictionaries (no network).

  python -I -m unittest discover -s lab -p "test_*.py"
"""
import gzip
import io
import json
import os
import sys
import tarfile
import tempfile
import unittest
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import check_cpe  # noqa: E402


def entry(name, deprecated=False):
    # The shape of one product in the NVD CPE API 2.0 and in the feed built from it.
    return json.dumps({"cpe": {"deprecated": deprecated, "cpeName": name, "cpeNameId": "X", "titles": []}})


def dictionary(pairs, skip=(), deprecated=(), filler=0):
    """A JSON chunk with every needed pair (except `skip`), plus `filler` unrelated names."""
    items = []
    for _rid, part, vendor, product, _t in pairs:
        key = f"{vendor}:{product}"
        if key in skip:
            continue
        items.append(entry(f"cpe:2.3:{part}:{vendor}:{product}:1.0:*:*:*:*:*:*:*", key in deprecated))
    items += [entry(f"cpe:2.3:a:filler:thing{i}:1:*:*:*:*:*:*:*") for i in range(filler)]
    return ('{"resultsPerPage":%d,"products":[' % len(items) + ",".join(items) + "]}").encode()


class CpeCheck(unittest.TestCase):
    def setUp(self):
        self.pairs = check_cpe.load_pairs(check_cpe.DEFAULT_CVES)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def path(self, name):
        return os.path.join(self.tmp.name, name)

    def run_check(self, path, min_names=1):
        scan = check_cpe.Scan(self.pairs)
        check_cpe.scan_file(scan, path)
        return check_cpe.judge(self.pairs, scan, min_names)

    def write(self, name, data):
        with open(self.path(name), "wb") as f:
            f.write(data)
        return self.path(name)

    def statuses(self, results):
        return sorted({status for status, _ in results})

    def test_the_shipped_table_passes_the_format_check(self):
        self.assertGreaterEqual(len(self.pairs), 10)
        for _rid, part, vendor, product, template in self.pairs:
            self.assertEqual(part, "a")
            self.assertRegex(vendor + product, r"^[a-z0-9_.\-]+$")
            self.assertEqual(len(template.split(":")), 13)
        # The names cross-checked against the NVD CPE API on 2026-11-19.
        known = {f"{p[2]}:{p[3]}" for p in self.pairs}
        self.assertIn("vsftpd_project:vsftpd", known)
        self.assertNotIn("beasts:vsftpd", known, "that vendor is not in the dictionary")

    def test_format_errors_are_reported(self):
        def table(**rule):
            base = {"id": "x", "products": ["x"], "template": "cpe:2.3:a:v:p:{version}:*:*:*:*:*:*:*"}
            base.update(rule)
            return self.write("cves.json", json.dumps({"cpe": [base]}).encode())

        self.assertEqual(len(check_cpe.load_pairs(table())), 1)
        for rule, want in [
            ({"template": "cpe:2.3:a:v:p:{version}"}, "13-part"),
            ({"template": "cpe:/a:v:p:{version}"}, "13-part"),
            ({"template": "cpe:2.3:x:v:p:{version}:*:*:*:*:*:*:*"}, "part"),
            ({"template": "cpe:2.3:a:V:p:{version}:*:*:*:*:*:*:*"}, "vendor"),
            ({"template": "cpe:2.3:a:v:p q:{version}:*:*:*:*:*:*:*"}, "product"),
            ({"template": "cpe:2.3:a:v:p:1.0:*:*:*:*:*:*:*"}, "placeholder"),
            ({"template": "cpe:2.3:a:v:p:{version}:*:*:{update}:*:*:*:*"}, "placeholder in field"),
            ({"products": []}, "no products"),
            ({"id": ""}, "empty or duplicate"),
        ]:
            with self.assertRaises(check_cpe.Problem, msg=str(rule)) as cm:
                check_cpe.load_pairs(table(**rule))
            self.assertIn(want, str(cm.exception))
        with self.assertRaises(check_cpe.Problem):
            check_cpe.load_pairs(self.write("empty.json", b'{"cpe":[]}'))

    def test_every_pair_present_is_ok_in_every_container_format(self):
        chunk = dictionary(self.pairs, filler=50)
        files = {}
        files["plain.json"] = self.write("plain.json", chunk)
        files["feed.tar.gz"] = self.path("feed.tar.gz")
        with tarfile.open(files["feed.tar.gz"], "w:gz") as t:
            for i in range(2):
                info = tarfile.TarInfo(f"nvdcpe-2.0-chunks/nvdcpe-2.0-chunk-{i:05}.json")
                data = chunk if i else b'{"products":[]}'
                info.size = len(data)
                t.addfile(info, io.BytesIO(data))
        files["feed.zip"] = self.path("feed.zip")
        with zipfile.ZipFile(files["feed.zip"], "w") as z:
            z.writestr("nvdcpe-2.0-chunks/c1.json", chunk)
        files["dict.json.gz"] = self.write("dict.json.gz", gzip.compress(chunk))
        xml = "".join(
            f'<cpe-item name="cpe:/{p[1]}:{p[2]}:{p[3]}"><cpe-23:cpe23-item name="cpe:2.3:{p[1]}:{p[2]}:{p[3]}:1.0:*:*:*:*:*:*:*"/></cpe-item>'
            for p in self.pairs
        ).encode()
        files["dict.xml"] = self.write("dict.xml", xml)
        for name, path in files.items():
            results = self.run_check(path)
            self.assertEqual(self.statuses(results), ["ok"], f"{name}: {results}")
            self.assertEqual(len(results), len(self.pairs))

    def test_missing_and_deprecated_names_fail(self):
        results = self.run_check(self.write("a.json", dictionary(self.pairs, skip={"f5:nginx"}, deprecated={"openbsd:openssh"})))
        by_status = {}
        for status, message in results:
            by_status.setdefault(status, []).append(message)
        self.assertEqual(len(by_status["missing"]), 1)
        self.assertIn("f5:nginx", by_status["missing"][0])
        self.assertEqual(len(by_status["deprecated"]), 1)
        self.assertIn("openbsd:openssh", by_status["deprecated"][0])
        self.assertEqual(len(by_status["ok"]), len(self.pairs) - 2)
        # A wrong vendor (the name this check found wrong in data/cves.json) is a missing pair.
        wrong = dictionary(self.pairs, skip={"vsftpd_project:vsftpd"}) + b'"cpeName":"cpe:2.3:a:beasts:vsftpd:2.3.4:*"'
        results = self.run_check(self.write("b.json", wrong))
        self.assertEqual([s for s, m in results if "vsftpd" in m], ["missing"])

    def test_a_name_that_only_appears_in_another_entries_deprecates_list_is_not_current(self):
        pairs = [p for p in self.pairs if p[3] == "nginx"]
        data = (
            '{"products":[{"cpe":{"deprecated":false,"cpeName":"cpe:2.3:a:other:thing:1:*","deprecates":'
            '[{"cpeName":"cpe:2.3:a:f5:nginx:0.1.0:*:*:*:*:*:*:*"}]}}]}'
        ).encode()
        scan = check_cpe.Scan(pairs)
        scan.feed(data)
        status = check_cpe.judge(pairs, scan, 1)[0][0]
        # No flag of a needed name was understood, so the file counts as an unknown layout.
        self.assertEqual(status, "ok")
        scan = check_cpe.Scan(pairs)
        scan.feed(data + entry("cpe:2.3:a:f5:nginx:2:*:*:*:*:*:*:*", deprecated=True).encode())
        self.assertEqual(check_cpe.judge(pairs, scan, 1)[0][0], "deprecated")

    def test_names_on_a_block_boundary_are_found_once(self):
        pairs = [p for p in self.pairs if p[3] == "nginx"]
        name = b'"deprecated":false,"cpeName":"cpe:2.3:a:f5:nginx:1.0:*:*:*:*:*:*:*"'
        data = b"x" * 1000 + name + b"y" * 1000
        for cut in range(990, 1000 + len(name) + 10, 7):
            scan = check_cpe.Scan(pairs)
            scan.feed(data[:cut])
            scan.feed(data[cut:])
            hits = scan.needles[b"cpe:2.3:a:f5:nginx:"]
            self.assertEqual(hits["current"], 1, f"cut at {cut}: {hits}")
            self.assertEqual(scan.names, 1, f"cut at {cut}")

    def test_a_truncated_or_wrong_download_does_not_pass(self):
        path = self.write("small.json", dictionary(self.pairs))
        with self.assertRaises(check_cpe.Problem) as cm:
            self.run_check(path, min_names=check_cpe.MIN_NAMES)
        self.assertIn("incomplete", str(cm.exception))
        with self.assertRaises(check_cpe.Problem):
            self.run_check(self.write("error.html", b"<html>403 Forbidden</html>"), min_names=check_cpe.MIN_NAMES)

    def test_command_line(self):
        out = io.StringIO()
        real, sys.stdout = sys.stdout, out
        try:
            self.assertEqual(check_cpe.main([]), 0)
            self.assertIn("NOT compared", out.getvalue())
            path = self.write("full.json", dictionary(self.pairs))
            self.assertEqual(check_cpe.main(["--dictionary", path, "--min-names", "1"]), 0)
            bad = self.write("bad.json", dictionary(self.pairs, skip={"redis:redis"}))
            self.assertEqual(check_cpe.main(["--dictionary", bad, "--min-names", "1"]), 1)
            self.assertIn("MISSING", out.getvalue())
            sys.stdout = out = io.StringIO()
            self.assertEqual(check_cpe.main(["--print-feed-url"]), 0)
            self.assertEqual(out.getvalue().strip(), check_cpe.NVD_CPE_FEED_URL)
        finally:
            sys.stdout = real
        self.assertTrue(check_cpe.NVD_CPE_FEED_URL.startswith("https://nvd.nist.gov/feeds/json/cpe/2.0/"))


if __name__ == "__main__":
    unittest.main()
