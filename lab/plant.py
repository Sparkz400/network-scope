#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright the Network Scope contributors
# SPDX-License-Identifier: MIT
"""A small test plant with planted weaknesses (ROADMAP L74). Python standard library only.

Four fake devices on loopback addresses (127.0.20.1-4), served by the handlers of simulators.py plus
the ones below, with the weaknesses written down in lab/plant_truth.json:

  plc-s7      S7 CPU 1214C with old firmware 4.2.3 (the advisory in tests/fixtures/csaf), engineering
              port 102 exposed
  plc-modbus  Modbus/TCP with writable registers (a trap: the scanner must never write), a Telnet
              console that hints at default credentials, a cleartext web admin page
  plc-enip    ControlLogix 1756-L81E with firmware 20.11 (the second advisory), EtherNet/IP exposed
  hmi         vsFTPd 2.3.4, OpenSSH 7.4 with weak algorithms, Apache 2.4.49 with Basic authentication

The devices only emulate what a scanner can observe; they never execute anything they receive.
Every write or control request that reaches a device is counted (the `writes` of `Plant.stats`);
lab/plant_benchmark.py fails when the count is not zero.

  python lab/plant.py                      # serve the plant until Ctrl+C (loopback only)
  python lab/plant_benchmark.py --cli /abs/path/to/network-scope-cli [--check]
"""
import argparse
import importlib.util
import json
import os
import socket
import struct
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
TRUTH = os.path.join(HERE, "plant_truth.json")


def load_simulators():
    # `python -I` keeps the script folder off sys.path, so load the module by path.
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("lab_simulators", os.path.join(HERE, "simulators.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sim = load_simulators()

# S7 SZL identity of the planted CPU (the default simulator reports a CPU 315 with firmware 3.2.1).
S7_1214C = {
    "order": b"6ES7 214-1AG40-0XB0 ",  # 20 bytes
    "firmware": (4, 2, 3),
    "names": ((1, b"LabPLC-S7"), (2, b"CPU 1214C DC/DC/DC"), (5, b"S C-PLANT0001"), (7, b"CPU 1214C DC/DC/DC")),
}


def s7_szl(request, identity):
    """The SZL read reply (ids 0x11 and 0x1c) for `identity`; same layout as simulators.s7_szl."""
    seq, szl_id = request[12], request[29] << 8 | request[30]
    if szl_id == 0x11:
        size = 28
        records = [struct.pack(">H", 1) + identity["order"] + bytes(6),
                   struct.pack(">H", 7) + bytes(23) + bytes(identity["firmware"])]
    elif szl_id == 0x1C:
        size = 34
        records = [struct.pack(">H", i) + text.ljust(32, b"\x00") for i, text in identity["names"]]
    else:
        return b""
    data = (bytes([0xFF, 9]) + struct.pack(">H", 8 + size * len(records)) + struct.pack(">HHHH", szl_id, 1, size, len(records))
            + b"".join(records))
    params = bytes([0, 1, 0x12, 8, 0x12, 0x84, 1, seq, 0, 0, 0, 0])
    header = bytes([0x32, 7, 0, 0]) + request[11:13] + struct.pack(">HH", len(params), len(data))
    return sim.s7_frame(header + params + data)


class Device:
    """Counters of one plant device. A write or control request is counted, never executed."""

    def __init__(self, name, address):
        self.name, self.address = name, address
        self.connections = 0
        self.requests = 0
        self.writes = 0
        self.write_log = []
        self.lock = threading.Lock()

    def connection(self):
        with self.lock:
            self.connections += 1

    def request(self):
        with self.lock:
            self.requests += 1

    def write(self, what):
        with self.lock:
            self.writes += 1
            self.write_log.append(what)


def s7_plc(device, identity=S7_1214C):
    """S7comm identification for the planted CPU; any write or control job is counted."""
    def handler(conn):
        request = sim.tpkt(conn)
        if len(request) < 6 or request[5] != 0xE0:
            return
        conn.sendall(bytes([3, 0, 0, 22, 17, 0xD0, 0, 0, 0, 1, 0, 0xC1, 2, 1, 0, 0xC2, 2, 1, 2, 0xC0, 1, 10]))
        while True:
            request = sim.tpkt(conn)
            if len(request) < 19:
                return
            if request[8] == 1 and request[17] in sim.S7_WRITES:
                device.write(f"S7 job function {request[17]:#x}")
                return
            device.request()
            if request[8] == 1 and request[17] == 0xF0:
                conn.sendall(sim.s7_frame(bytes([0x32, 3, 0, 0]) + request[11:13]
                                          + bytes([0, 8, 0, 0, 0, 0, 0xF0, 0, 0, 1, 0, 1, 1, 0xE0])))
            elif request[8] == 7 and len(request) >= 31:
                reply = s7_szl(request, identity)
                if not reply:
                    return
                conn.sendall(reply)
            else:
                return
    return handler


# Modbus function codes that change a register or the device (coils, registers, file records,
# diagnostics): the scanner sends none of them, so each one is a failure of the scanner.
MODBUS_WRITE_CODES = {5, 6, 8, 15, 16, 21, 22, 23}


def modbus_writable(device):
    """Modbus/TCP with writable holding registers: a trap for scanners that write.

    Reads (3), Report Server ID (17) and Device Identification (43) are answered like the lab
    PLC. A write function code is *accepted* (the register changes, as on a careless device) and
    counted in `device.writes`.
    """
    registers = {}

    def handler(conn):
        while True:
            data = sim.read_some(conn)
            if len(data) < 8:
                return
            tid, _, _, unit, fc = struct.unpack(">HHHBB", data[:8])
            device.request()
            if fc in MODBUS_WRITE_CODES:
                device.write(f"Modbus function {fc}")
                if fc == 6 and len(data) >= 12:
                    registers[struct.unpack(">H", data[8:10])[0]] = struct.unpack(">H", data[10:12])[0]
                pdu = data[7:12]  # the usual echo of a write
            elif fc == 3 and len(data) >= 12:
                start, count = struct.unpack(">HH", data[8:12])
                count = min(count, 8)
                pdu = bytes([3, count * 2]) + b"".join(struct.pack(">H", registers.get(start + i, 0)) for i in range(count))
            else:
                pdu = sim.modbus_pdu(fc)
            conn.sendall(struct.pack(">HHHB", tid, 0, len(pdu) + 1, unit) + pdu)
    return handler


def enip_plc(device):
    """EtherNet/IP List Identity only; CIP services that carry a write are counted."""
    def handler(conn):
        data = sim.read_some(conn)
        if len(data) >= 2:
            if struct.unpack("<H", data[:2])[0] in sim.ENIP_WRITES:
                device.write("EtherNet/IP SendRRData/SendUnitData")
                return
            device.request()
        if len(data) >= 24 and data[0] == 0x63:
            conn.sendall(sim.enip_identity(data[12:20]))
    return handler


def telnet_default_credentials(conn):
    """A console that tells the visitor the default credentials (a common field finding)."""
    conn.sendall(bytes([255, 253, 24, 255, 253, 31])
                 + b"\r\nPLC-GW console (factory defaults: user admin, password admin)\r\nlogin: ")
    sim.read_some(conn)


def make_handlers(device):
    """Handler name (as used in plant_truth.json) to a function(conn)."""
    return {
        "s7_plc": s7_plc(device),
        "modbus_writable": modbus_writable(device),
        "enip_plc": enip_plc(device),
        "telnet_default_credentials": telnet_default_credentials,
        "ftp": sim.ftp,
        "ssh": sim.ssh,
        "http": sim.http,
    }


def counted(device, handler):
    """The handler, counting every connection that reaches it (the benchmark checks the scan did)."""
    def wrapper(conn):
        device.connection()
        handler(conn)
    return wrapper


def load_truth(path=TRUTH):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


class Plant:
    """The plant: starts every device of the ground truth on its loopback address."""

    def __init__(self, truth=None, idle_timeout=None):
        self.truth = truth or load_truth()
        if idle_timeout is not None:
            sim.IDLE_TIMEOUT = idle_timeout
        self.devices = {d["address"]: Device(d["name"], d["address"]) for d in self.truth["devices"]}
        self.errors = []

    def start(self):
        for spec in self.truth["devices"]:
            device = self.devices[spec["address"]]
            handlers = make_handlers(device)
            for service in spec["tcp"]:
                handler = counted(device, handlers[service["handler"]])
                threading.Thread(target=self._serve, args=(spec["address"], service["port"], handler), daemon=True).start()
        deadline = time.time() + 5
        pending = {(d["address"], s["port"]) for d in self.truth["devices"] for s in d["tcp"]}
        while pending and time.time() < deadline:
            for address, port in sorted(pending):
                try:
                    with socket.create_connection((address, port), timeout=0.5):
                        pending.discard((address, port))
                except OSError:
                    pass
            time.sleep(0.1)
        if pending or self.errors:
            raise RuntimeError("the plant did not start: " + ", ".join(sorted(f"{a}:{p}" for a, p in pending) + self.errors))
        # the start-up probes above were plain connects: forget them
        for device in self.devices.values():
            device.connections = device.requests = device.writes = 0
            device.write_log = []

    def _serve(self, address, port, handler):
        try:
            sim.serve_tcp(address, port, handler)
        except Exception as e:  # a bind failure must not stay silent in a daemon thread
            self.errors.append(f"{address}:{port}: {e}")

    @property
    def writes(self):
        return sum(d.writes for d in self.devices.values())

    def write_log(self):
        return {a: list(d.write_log) for a, d in self.devices.items() if d.write_log}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.parse_args()
    plant = Plant()
    plant.start()
    print("test plant listening:", ", ".join(f"{d['name']} {d['address']}" for d in plant.truth["devices"]), flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("writes received:", plant.writes, plant.write_log())


if __name__ == "__main__":
    main()
