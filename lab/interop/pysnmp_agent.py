#!/usr/bin/env python3
"""An SNMP agent made with pysnmp, an independent implementation of SNMPv1/v2c/v3 (USM), for
checking Network Scope's SNMPv3 message layer against code it does not share.

Not part of the normal test run (it needs `pip install pysnmp`, see docs/src/snmp.md). It serves
the standard MIB-II tree that pysnmp has (the system group, snmp group) on 127.0.0.1 to these
users, every one with the passphrase `authpass-1234` and, when it has privacy, `privpass-5678`:

    u-none                              noAuthNoPriv
    u-<auth>                            authNoPriv           auth: md5, sha, sha256
    u-<auth>-<priv>                     authPriv             priv: aes, des

and the v2c community `lab-community`. Every request PDU it receives is counted by type and
security level; the counts are written to --stats (JSON) after each request, so a test can show
what the scanner sent (and that it never sent a SetRequest).

    python lab/interop/pysnmp_agent.py --port 16161 --stats stats.json

It prints `READY <port>` when it listens. It runs until killed.
"""
import argparse
import asyncio
import json
import sys

from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.entity import config, engine
from pysnmp.entity.rfc3413 import cmdrsp, context

AUTH = {
    "md5": config.USM_AUTH_HMAC96_MD5,
    "sha": config.USM_AUTH_HMAC96_SHA,
    "sha256": config.USM_AUTH_HMAC192_SHA256,
}
PRIV = {"aes": config.USM_PRIV_CFB128_AES, "des": config.USM_PRIV_CBC56_DES}
AUTH_PASS = "authpass-1234"
PRIV_PASS = "privpass-5678"
COMMUNITY = "lab-community"
MIB2 = (1, 3, 6, 1, 2, 1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--stats", required=True)
    args = parser.parse_args()

    snmp_engine = engine.SnmpEngine()
    config.add_transport(
        snmp_engine, udp.DOMAIN_NAME, udp.UdpTransport().open_server_mode(("127.0.0.1", args.port))
    )

    config.add_v3_user(snmp_engine, "u-none")
    config.add_vacm_user(snmp_engine, 3, "u-none", "noAuthNoPriv", MIB2)
    for auth_name, auth in AUTH.items():
        user = f"u-{auth_name}"
        config.add_v3_user(snmp_engine, user, auth, AUTH_PASS)
        config.add_vacm_user(snmp_engine, 3, user, "authNoPriv", MIB2)
        for priv_name, priv in PRIV.items():
            user = f"u-{auth_name}-{priv_name}"
            config.add_v3_user(snmp_engine, user, auth, AUTH_PASS, priv, PRIV_PASS)
            config.add_vacm_user(snmp_engine, 3, user, "authPriv", MIB2)
    config.add_v1_system(snmp_engine, "lab-area", COMMUNITY)
    for model in (1, 2):  # SNMPv1 and v2c
        config.add_vacm_user(snmp_engine, model, "lab-area", "noAuthNoPriv", MIB2)

    stats = {"requests": 0, "pdu_types": {}, "by_user_level": {}, "engine_id": snmp_engine.snmpEngineID.prettyPrint()}

    def observe(_engine, _execpoint, variables, _ctx):
        pdu_type = type(variables["pdu"]).__name__
        key = f"{variables['securityName']} {variables['securityLevel']}"
        stats["requests"] += 1
        stats["pdu_types"][pdu_type] = stats["pdu_types"].get(pdu_type, 0) + 1
        stats["by_user_level"][key] = stats["by_user_level"].get(key, 0) + 1
        with open(args.stats, "w") as f:
            json.dump(stats, f)

    snmp_engine.observer.register_observer(observe, "rfc3412.receiveMessage:request")

    snmp_context = context.SnmpContext(snmp_engine)
    cmdrsp.GetCommandResponder(snmp_engine, snmp_context)
    cmdrsp.NextCommandResponder(snmp_engine, snmp_context)
    cmdrsp.BulkCommandResponder(snmp_engine, snmp_context)
    # no SetCommandResponder: this agent cannot be written to, whatever a manager sends

    with open(args.stats, "w") as f:
        json.dump(stats, f)
    print(f"READY {args.port}", flush=True)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    snmp_engine.open_dispatcher()
    loop.run_forever()


if __name__ == "__main__":
    sys.exit(main())
