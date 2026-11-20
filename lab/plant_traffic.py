#!/usr/bin/env python3
"""A replayable traffic generator for the test plant (ROADMAP L74, for L69). Standard library only.

It writes capture files of synthetic industrial traffic between two operator stations and two PLCs;
nothing is sent on any network. The files feed `ot-learn` and `ot-listen --model`:

  normal.pcap               six hours of normal traffic: an HMI polls both PLCs, an engineering
                            station writes now and then and stops the S7 PLC once, inside the
                            maintenance window (Saturday 02:00-04:00 UTC)
  replay-one-write.pcap     the same traffic with ONE Modbus write injected from a station that
                            never appears in normal.pcap (10.20.0.99)
  replay-stop-outside.pcap  the same traffic with ONE S7 PLC Stop from the engineering station at
                            05:00, outside the window
  expected.json             what `ot-listen` must report for each file

  python lab/plant_traffic.py --out DIR [--hours 6]

The frames are Ethernet/IPv4/TCP with Modbus/TCP and S7comm requests in the layout the passive
decoders read (they are requests only: a decoder learns peers, functions and rates from them).
Stations and PLCs have the addresses below; the times are synthetic, in the capture file.
"""
import argparse
import json
import os
import struct

HMI = "10.20.0.50"
ENGINEERING = "10.20.0.60"
ROGUE = "10.20.0.99"
PLC_S7 = "10.20.0.10"
PLC_MODBUS = "10.20.0.11"
# Saturday 2026-11-21 00:00:00 UTC
START = 1_795_219_200
MAINTENANCE = "Sat 02:00-04:00"


def ip4(text):
    return bytes(int(p) for p in text.split("."))


class Flow:
    """One TCP connection: source port and a sequence number that advances with the payload."""

    def __init__(self, src, sport, dst, dport):
        self.src, self.sport, self.dst, self.dport = src, sport, dst, dport
        self.seq = 1000

    def frame(self, payload):
        tcp = struct.pack(">HHIIBBHHH", self.sport, self.dport, self.seq, 0, 5 << 4, 0x18, 65535, 0, 0)
        self.seq = (self.seq + len(payload)) & 0xFFFFFFFF
        total = 20 + len(tcp) + len(payload)
        ip = struct.pack(">BBHHHBBH", 0x45, 0, total, 0, 0, 64, 6, 0) + ip4(self.src) + ip4(self.dst)
        eth = bytes.fromhex("020000000002") + bytes.fromhex("020000000001") + b"\x08\x00"
        return eth + ip + tcp + payload


def modbus(transaction, function, body, unit=1):
    pdu = bytes([function]) + body
    return struct.pack(">HHHB", transaction & 0xFFFF, 0, len(pdu) + 1, unit) + pdu


def modbus_read(transaction):  # Read Holding Registers, address 0, 2 registers
    return modbus(transaction, 3, struct.pack(">HH", 0, 2))


def modbus_write(transaction):  # Write Single Register, address 5, value 9
    return modbus(transaction, 6, struct.pack(">HH", 5, 9))


def s7(function):
    """A TPKT/COTP data unit with an S7 job of the given function code."""
    body = bytes([0x32, 1, 0, 0, 0, 1, 0, 2, 0, 0, function, 1])
    return struct.pack(">BBH", 3, 0, 4 + 3 + len(body)) + bytes([2, 0xF0, 0x80]) + body


S7_READ, S7_WRITE, S7_STOP = 0x04, 0x05, 0x29


def timeline(hours):
    """The normal traffic as (seconds since START, source, destination, port, payload factory)."""
    events = []
    transaction = 0
    for t in range(0, hours * 3600, 10):
        transaction += 1
        events.append((t, HMI, PLC_MODBUS, 502, modbus_read(transaction)))
        events.append((t + 1, HMI, PLC_S7, 102, s7(S7_READ)))
    for hour in range(hours):
        # the engineering station reads and writes once an hour
        events.append((hour * 3600 + 600, ENGINEERING, PLC_S7, 102, s7(S7_READ)))
        events.append((hour * 3600 + 601, ENGINEERING, PLC_S7, 102, s7(S7_WRITE)))
        events.append((hour * 3600 + 660, ENGINEERING, PLC_MODBUS, 502, modbus_write(900 + hour)))
    # one Stop of the S7 PLC at 02:30, inside the maintenance window
    events.append((2 * 3600 + 1800, ENGINEERING, PLC_S7, 102, s7(S7_STOP)))
    return events


def pcap(frames):
    """A classic pcap file (Ethernet) from (unix seconds, frame) pairs, in time order."""
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for ts, frame in sorted(frames, key=lambda f: f[0]):
        out += struct.pack("<IIII", ts, 0, len(frame), len(frame)) + frame
    return out


def build(events):
    flows = {}
    frames = []
    for t, src, dst, port, payload in events:
        flow = flows.setdefault((src, dst, port), Flow(src, 40000 + len(flows), dst, port))
        frames.append((START + t, flow.frame(payload)))
    return pcap(frames)


def generate(out_dir, hours=6):
    if hours < 3:
        raise ValueError("at least 3 hours (the maintenance Stop is at 02:30)")
    os.makedirs(out_dir, exist_ok=True)
    normal = timeline(hours)
    # one write from a station that never talks in normal.pcap
    one_write = normal + [(1 * 3600 + 17 * 60 + 3, ROGUE, PLC_MODBUS, 502, modbus_write(7777))]
    # one Stop outside the maintenance window (05:00 needs 6 hours of traffic)
    stop_outside = normal + [(5 * 3600, ENGINEERING, PLC_S7, 102, s7(S7_STOP))]
    files = {
        "normal.pcap": build(normal),
        "replay-one-write.pcap": build(one_write),
        "replay-stop-outside.pcap": build(stop_outside),
    }
    for name, data in files.items():
        with open(os.path.join(out_dir, name), "wb") as f:
            f.write(data)
    expected = {
        "maintenance": MAINTENANCE,
        "learn": {"file": "normal.pcap", "assets": [PLC_S7, PLC_MODBUS], "peers": {PLC_S7: [HMI, ENGINEERING], PLC_MODBUS: [HMI, ENGINEERING]}},
        "replays": {
            "normal.pcap": {"alerts": []},
            "replay-one-write.pcap": {"alerts": [{"kind": "new-station", "client": ROGUE, "server": PLC_MODBUS,
                                                  "function": "Write Single Register"}]},
            "replay-stop-outside.pcap": {"alerts": [{"kind": "stop-outside-window", "client": ENGINEERING, "server": PLC_S7,
                                                     "function": "PLC Stop"}]},
        },
    }
    with open(os.path.join(out_dir, "expected.json"), "w", encoding="utf-8") as f:
        json.dump(expected, f, indent=2)
    return expected


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True, help="directory for the capture files")
    ap.add_argument("--hours", type=int, default=6, help="hours of traffic (default 6, at least 3 — the Stop outside the window is at 05:00 and needs 6)")
    args = ap.parse_args()
    generate(args.out, args.hours)
    print("wrote normal.pcap, replay-one-write.pcap, replay-stop-outside.pcap and expected.json to", args.out)


if __name__ == "__main__":
    main()
