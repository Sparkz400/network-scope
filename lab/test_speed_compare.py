"""Unit tests of lab/speed_compare.py's parsers and regression gate (no network, no tools).

  python -I -m unittest discover -s lab -p "test_*.py"
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import speed_compare as sc  # noqa: E402


class Parsers(unittest.TestCase):
    def test_port_spec_and_nmap_header(self):
        self.assertEqual(sc.parse_port_spec("1,3-4,7"), [1, 3, 4, 7])
        text = "# Nmap 7.94 scan initiated ...\n# Ports scanned: TCP(4;1,3-4,7) UDP(0;) SCTP(0;) PROTOCOLS(0;)\n"
        self.assertEqual(sc.nmap_ports_from_grepable(text), [1, 3, 4, 7])
        with self.assertRaises(ValueError):
            sc.nmap_ports_from_grepable("# Ports scanned: TCP(5;1,3-4,7)")
        with self.assertRaises(ValueError):
            sc.nmap_ports_from_grepable("nothing")

    def test_builtin_top100(self):
        ports = sc.builtin_top100()
        self.assertEqual(len(ports), 100)
        self.assertEqual(ports[:3], [80, 23, 443])

    def test_proc_net(self):
        tcp = ("  sl  local_address rem_address   st\n"
               "   0: 0100007F:1F90 00000000:0000 0A 0\n"     # 127.0.0.1:8080 listen
               "   1: 00000000:0016 00000000:0000 0A 0\n"     # 0.0.0.0:22 listen
               "   2: 3500007F:0035 00000000:0000 0A 0\n"     # 127.0.0.53:53 listen
               "   3: 0100007F:1F90 0100007F:C350 01 0\n")    # established, skipped
        self.assertEqual(sc.proc_net_listeners(tcp),
                         {("127.0.0.1", 8080), ("*", 22), ("127.0.0.53", 53)})
        tcp6 = ("  sl  local_address rem_address st\n"
                "   0: 00000000000000000000000000000000:0277 00000000000000000000000000000000:0000 0A 0\n"
                "   1: 0000000000000000FFFF00000A00007F:0015 00000000000000000000000000000000:0000 0A 0\n"
                "   2: 00000000000000000000000001000000:0019 00000000000000000000000000000000:0000 0A 0\n")
        self.assertEqual(sc.proc_net_listeners(tcp6, v6=True), {("*", 631), ("127.0.0.10", 21)})

    def test_netstat(self):
        windows = ("  Proto  Lokale Adresse         Remoteadresse          Status\n"
                   "  TCP    0.0.0.0:135            0.0.0.0:0              ABHÖREN\n"
                   "  TCP    127.0.10.1:21          0.0.0.0:0              LISTENING\n"
                   "  TCP    127.0.0.1:50000        127.0.0.1:50001        HERGESTELLT\n"
                   "  TCP    [::]:445               [::]:0                 ABHÖREN\n"
                   "  UDP    0.0.0.0:53             *:*\n")
        self.assertEqual(sc.netstat_listeners(windows), {("*", 135), ("127.0.10.1", 21)})
        macos = ("tcp4       0      0  127.0.0.1.631          *.*                    LISTEN\n"
                 "tcp46      0      0  *.22                   *.*                    LISTEN\n"
                 "tcp4       0      0  127.0.0.1.5000         127.0.0.1.6000         ESTABLISHED\n")
        self.assertEqual(sc.netstat_listeners(macos), {("127.0.0.1", 631), ("*", 22)})

    def test_expected_open(self):
        hosts = {"127.0.10.1", "127.0.10.2"}
        listening = {("127.0.10.1", 21), ("127.0.10.1", 9999), ("127.0.0.53", 53), ("*", 22)}
        self.assertEqual(sc.expected_open(listening, hosts, [21, 22, 53]),
                         {("127.0.10.1", 21), ("127.0.10.1", 22), ("127.0.10.2", 22)})

    def test_tool_outputs(self):
        self.assertEqual(sc.rustscan_open("Open 127.0.10.1:21\n127.0.10.1 -> [21,22]\n127.0.10.5 -> [6379]\n"),
                         {("127.0.10.1", 21), ("127.0.10.1", 22), ("127.0.10.5", 6379)})
        snapshot = {"hosts": [{"ip": "127.0.10.1", "open": [21, 22]}, {"ip": "127.0.10.7"}]}
        self.assertEqual(sc.ns_open(snapshot), {("127.0.10.1", 21), ("127.0.10.1", 22)})


class Memory(unittest.TestCase):
    def test_gnu_time_output(self):
        self.assertEqual(sc.gnu_time_peak("2048\n"), 2048 * 1024)
        self.assertEqual(sc.gnu_time_peak("Command exited with non-zero status 1\n512\n"), 512 * 1024)
        self.assertIsNone(sc.gnu_time_peak(""))
        self.assertIsNone(sc.gnu_time_peak("Command terminated by signal 9\n"))

    @unittest.skipUnless(sc.GNU_TIME, "Linux with /usr/bin/time only")
    def test_small_tool_is_not_given_the_harness_size(self):
        # The control: a trivial command must measure far below this Python process.
        _, peak, _, _, code = sc.run(["sleep", "0"], 10)
        self.assertEqual(code, 0)
        self.assertLess(peak, 10 * 1024 * 1024)


class Lan(unittest.TestCase):
    def test_only_small_private_ranges(self):
        self.assertEqual(sc.lan_network("192.168.178.0/24"), "192.168.178.0/24")
        self.assertEqual(sc.lan_network("10.1.2.0/28"), "10.1.2.0/28")
        for bad in ("100.64.0.0/24", "8.8.8.0/24", "192.168.0.0/16", "127.0.0.0/24", "169.254.1.0/24",
                    "192.168.178.1/24", "nonsense"):
            with self.assertRaises(ValueError, msg=bad):
                sc.lan_network(bad)


class Gate(unittest.TestCase):
    def test_regressions(self):
        failures, notices = sc.regressions({"24-top100": 1.4, "24-top1000": 3.1, "16-top100": 9.0},
                                           {"24-top100": 1.0, "24-top1000": 2.0}, 0.5)
        self.assertEqual(len(failures), 1)
        self.assertIn("24-top1000", failures[0])
        self.assertEqual(len(notices), 1)
        self.assertIn("16-top100", notices[0])

    def test_regressions_relative_to_the_reference_tool(self):
        base = {"24-top100": {"seconds": 0.17, "reference_seconds": 0.20}}
        # A runner twice as slow for every tool: no regression.
        self.assertEqual(sc.regressions({"24-top100": 0.34}, base, 0.5, {"24-top100": 0.40})[0], [])
        # Slower than the reference by more than the tolerance: a regression.
        failures, _ = sc.regressions({"24-top100": 0.34}, base, 0.5, {"24-top100": 0.20})
        self.assertEqual(len(failures), 1)
        self.assertIn("nmap -sT", failures[0])
        # Without the reference in this run, the seconds are compared.
        self.assertEqual(len(sc.regressions({"24-top100": 0.34}, base, 0.5)[0]), 1)
        self.assertEqual(sc.regressions({"24-top100": 0.20}, base, 0.5)[0], [])


if __name__ == "__main__":
    unittest.main()
