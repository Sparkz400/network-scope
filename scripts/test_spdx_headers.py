"""Unit tests of scripts/spdx_headers.py (standard library only).

  python -I -m unittest discover -s scripts -p "test_*.py"
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import spdx_headers as s  # noqa: E402


class SpdxHeaderTests(unittest.TestCase):
    def test_rust_file_gets_two_lines_on_top(self):
        out = s.add_header("core/src/x.rs", "//! Docs\nfn main() {}\n")
        self.assertEqual(
            out,
            "// SPDX-FileCopyrightText: Copyright the Network Scope contributors\n"
            "// SPDX-License-Identifier: MIT\n//! Docs\nfn main() {}\n",
        )
        self.assertTrue(s.has_header("core/src/x.rs", out))

    def test_shebang_and_encoding_stay_first(self):
        text = "#!/usr/bin/env python3\n# -*- coding: utf-8 -*-\nprint(1)\n"
        out = s.add_header("scripts/x.py", text).split("\n")
        self.assertEqual(out[0], "#!/usr/bin/env python3")
        self.assertEqual(out[1], "# -*- coding: utf-8 -*-")
        self.assertEqual(out[2], "# SPDX-FileCopyrightText: Copyright the Network Scope contributors")
        self.assertEqual(out[4], "print(1)")

    def test_comment_style_per_extension(self):
        self.assertTrue(s.add_header("a.iss", "x\n").startswith("; SPDX-"))
        self.assertTrue(s.add_header("a.ps1", "x\n").startswith("# SPDX-"))
        self.assertTrue(s.add_header("a.sh", "#!/bin/bash\nx\n").startswith("#!/bin/bash\n# SPDX-"))

    def test_idempotent(self):
        once = s.add_header("a.rs", "fn f() {}\n")
        self.assertEqual(s.add_header("a.rs", once), once)

    def test_crlf_file_keeps_crlf(self):
        out = s.add_header("a.rs", "fn f() {}\r\n")
        self.assertNotIn("\n", out.replace("\r\n", ""))
        self.assertTrue(s.has_header("a.rs", out))

    def test_third_party_file_names_both_holders_and_licenses(self):
        out = s.add_header("core/src/jarm.rs", "//! JARM\n")
        self.assertIn("Salesforce.com", out)
        self.assertIn("SPDX-License-Identifier: MIT AND BSD-3-Clause", out)

    def test_partial_header_is_missing(self):
        self.assertFalse(s.has_header("a.rs", "// SPDX-License-Identifier: MIT\nfn f() {}\n"))


if __name__ == "__main__":
    unittest.main()
