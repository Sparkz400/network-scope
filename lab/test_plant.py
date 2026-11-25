# SPDX-FileCopyrightText: Copyright the Network Scope contributors
# SPDX-License-Identifier: MIT
"""Tests of the plant scripts (standard library only): python -I -m unittest discover -s lab -p "test_*.py"

They check the ground truth, the traffic generator and the plant devices (on loopback, with a real
Modbus and S7 exchange) without the CLI.
"""
import importlib.util
import json
import os
import socket
import struct
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name, filename):
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


plant = load("lab_plant", "plant.py")
traffic = load("lab_plant_traffic", "plant_traffic.py")
bench = load("lab_plant_benchmark", "plant_benchmark.py")


def read_file(path):
    with open(path, "rb") as f:
        return f.read()


def read_pcap(data):
    """(timestamp, source ip, destination ip, destination port, payload) of every frame."""
    magic, _, _, _, _, _, linktype = struct.unpack("<IHHiIII", data[:24])
    assert magic == 0xA1B2C3D4 and linktype == 1
    out, offset = [], 24
    while offset < len(data):
        ts, _, caplen, wirelen = struct.unpack("<IIII", data[offset:offset + 16])
        assert caplen == wirelen
        frame = data[offset + 16:offset + 16 + caplen]
        offset += 16 + caplen
        assert frame[12:14] == b"\x08\x00"
        ihl = (frame[14] & 15) * 4
        tcp = 14 + ihl
        source, destination = ".".join(map(str, frame[26:30])), ".".join(map(str, frame[30:34]))
        port = struct.unpack(">H", frame[tcp + 2:tcp + 4])[0]
        payload = frame[tcp + (frame[tcp + 12] >> 4) * 4:]
        out.append((ts, source, destination, port, payload))
    return out


class Truth(unittest.TestCase):
    def test_every_address_is_loopback_and_every_weakness_names_a_served_port(self):
        truth = plant.load_truth()
        weaknesses = bench.check_truth(truth)
        served = {(d["address"], s["port"]) for d in truth["devices"] for s in d["tcp"]}
        self.assertGreaterEqual(len(weaknesses), 10)
        for w in weaknesses:
            self.assertIn((w["address"], w["port"]), served, w["id"])
        handlers = plant.make_handlers(plant.Device("x", "127.0.20.9"))
        for d in truth["devices"]:
            for s in d["tcp"]:
                self.assertIn(s["handler"], handlers)
                self.assertIn(s["port"], truth["scan"]["ports"])

    def test_a_non_loopback_address_or_a_duplicate_is_refused(self):
        truth = plant.load_truth()
        bad = json.loads(json.dumps(truth))
        bad["devices"][0]["address"] = "10.0.0.1"
        with self.assertRaises(bench.LabError):
            bench.check_truth(bad)
        bad = json.loads(json.dumps(truth))
        bad["weaknesses"].append(dict(bad["weaknesses"][0]))
        with self.assertRaises(bench.LabError):
            bench.check_truth(bad)

    def test_recall_counts_expected_findings_and_lists_the_rest(self):
        weaknesses = [{"id": "A", "address": "127.0.20.1", "port": 102, "finding": "x"},
                      {"id": "B", "address": "127.0.20.1", "port": 23, "finding": "y"}]
        findings = [{"ip": "127.0.20.1", "port": 102, "id": "x"}, {"ip": "127.0.20.1", "port": None, "id": "z"}]
        found, missed, extra = bench.weakness_recall(weaknesses, findings)
        self.assertEqual((found, missed, extra), (["A"], ["B"], ["z@127.0.20.1"]))
        want, regressed = bench.regressions({"weakness_recall": 0.5}, "nowhere", os.path.join(HERE, "none.json"))
        self.assertEqual((want, regressed), (None, False))


class Traffic(unittest.TestCase):
    def test_the_captures_differ_by_exactly_the_injected_event(self):
        with tempfile.TemporaryDirectory() as directory:
            expected = traffic.generate(directory)
            normal = read_pcap(read_file(os.path.join(directory, "normal.pcap")))
            one = read_pcap(read_file(os.path.join(directory, "replay-one-write.pcap")))
            stop = read_pcap(read_file(os.path.join(directory, "replay-stop-outside.pcap")))
        self.assertEqual(len(one), len(normal) + 1)
        self.assertEqual(len(stop), len(normal) + 1)
        injected = [f for f in one if f not in normal]
        self.assertEqual(len(injected), 1)
        ts, source, destination, port, payload = injected[0]
        self.assertEqual((source, destination, port), (traffic.ROGUE, traffic.PLC_MODBUS, 502))
        self.assertEqual(payload[7], 6, "Write Single Register")
        self.assertTrue(all(f[1] != traffic.ROGUE for f in normal), "the rogue station is new")
        stopped = [f for f in stop if f not in normal][0]
        self.assertEqual((stopped[1], stopped[2], stopped[3]), (traffic.ENGINEERING, traffic.PLC_S7, 102))
        self.assertEqual(stopped[4][17], 0x29, "PLC Stop")
        # time order, and the injected write inside hour two
        self.assertEqual([f[0] for f in one], sorted(f[0] for f in one))
        self.assertTrue(traffic.START < ts < traffic.START + 2 * 3600)
        self.assertEqual(expected["replays"]["normal.pcap"]["alerts"], [])
        self.assertEqual(len(expected["replays"]["replay-one-write.pcap"]["alerts"]), 1)

    def test_too_few_hours_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                traffic.generate(directory, hours=2)


def free(truth):
    for d in truth["devices"]:
        for s in d["tcp"]:
            try:
                with socket.create_connection((d["address"], s["port"]), timeout=0.3):
                    return False
            except OSError:
                pass
    return True


class Devices(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        truth = plant.load_truth()
        if not free(truth):
            raise unittest.SkipTest("a plant port is already in use on this machine")
        cls.plant = plant.Plant(truth)
        try:
            cls.plant.start()
        except RuntimeError as e:
            raise unittest.SkipTest(str(e))

    def exchange(self, address, port, data, read=1):
        with socket.create_connection((address, port), timeout=3) as s:
            s.sendall(data)
            return s.recv(4096) if read else b""

    def test_modbus_reads_are_answered_and_writes_are_accepted_and_counted(self):
        device = self.plant.devices["127.0.20.2"]
        before = device.writes
        read = struct.pack(">HHHBBHH", 1, 0, 6, 1, 3, 0, 2)
        reply = self.exchange("127.0.20.2", 502, read)
        self.assertEqual(reply[7], 3)
        self.assertEqual(device.writes, before)
        write = struct.pack(">HHHBBHH", 2, 0, 6, 1, 6, 5, 77)
        reply = self.exchange("127.0.20.2", 502, write)
        self.assertEqual(reply[7], 6, "the write is accepted")
        self.assertEqual(device.writes, before + 1)
        self.assertIn("Modbus function 6", device.write_log[-1])
        # the register really changed
        reply = self.exchange("127.0.20.2", 502, struct.pack(">HHHBBHH", 3, 0, 6, 1, 3, 5, 1))
        self.assertEqual(struct.unpack(">H", reply[9:11])[0], 77)
        # read device identification and report server id are not writes
        before = device.writes
        self.exchange("127.0.20.2", 502, struct.pack(">HHHBBBBB", 4, 0, 5, 1, 43, 14, 1, 0))
        self.exchange("127.0.20.2", 502, struct.pack(">HHHBB", 5, 0, 2, 1, 17))
        self.assertEqual(device.writes, before)

    def test_the_s7_cpu_reports_its_firmware_and_a_write_job_is_counted(self):
        device = self.plant.devices["127.0.20.1"]
        before = device.writes
        with socket.create_connection(("127.0.20.1", 102), timeout=3) as s:
            s.sendall(bytes([3, 0, 0, 22, 17, 0xE0, 0, 0, 0, 1, 0, 0xC1, 2, 1, 0, 0xC2, 2, 1, 2, 0xC0, 1, 10]))
            self.assertEqual(s.recv(4096)[5], 0xD0)
            # SZL 0x11 read (user data): the order code and the firmware record
            request = bytearray(31)
            request[0:4] = bytes([3, 0, 0, 31])
            request[4:7] = bytes([2, 0xF0, 0x80])
            request[7] = 0x32
            request[8] = 7
            request[12] = 1
            request[29], request[30] = 0, 0x11
            s.sendall(bytes(request))
            reply = s.recv(4096)
        self.assertIn(b"6ES7 214-1AG40-0XB0", reply)
        self.assertIn(bytes([4, 2, 3]), reply)
        self.assertEqual(device.writes, before)
        with socket.create_connection(("127.0.20.1", 102), timeout=3) as s:
            s.sendall(bytes([3, 0, 0, 22, 17, 0xE0, 0, 0, 0, 1, 0, 0xC1, 2, 1, 0, 0xC2, 2, 1, 2, 0xC0, 1, 10]))
            s.recv(4096)
            job = bytearray(25)
            job[0:4] = bytes([3, 0, 0, 25])
            job[4:7] = bytes([2, 0xF0, 0x80])
            job[7], job[8] = 0x32, 1
            job[17] = 0x29  # PLC Stop
            s.sendall(bytes(job))
            s.settimeout(1)
            try:
                s.recv(10)
            except OSError:
                pass
        self.assertEqual(device.writes, before + 1)

    def test_the_console_names_the_default_credentials(self):
        banner = self.exchange("127.0.20.2", 23, b"")
        self.assertIn(b"factory defaults", banner)


if __name__ == "__main__":
    unittest.main()
