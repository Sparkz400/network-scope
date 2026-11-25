# SPDX-FileCopyrightText: Copyright the Network Scope contributors
# SPDX-License-Identifier: MIT
"""Checks alert delivery to REAL receivers (issue 12): what rsyslog parsed from the syslog
messages and what nginx received as webhook bodies, against the alerts `monitor` wrote to
`--alerts FILE`. Run by lab/alert_receivers.sh after a two-cycle `monitor` run:

    python -I lab/alert_receivers_check.py WORK

Expected files in WORK:
- alerts.jsonl: the alerts as JSON lines (the same text the webhook POSTs).
- syslog.tsv: one line per message rsyslog received, written by its template "fields":
  input, facility, severity, app-name, msgid, msg (tab separated, msg last).
- webhook-http.log, webhook-https.log: nginx access log lines (JSON, format "hook") of the
  plain and the TLS webhook, with the body of each POST.
- webhook-untrusted.log: the same for a TLS server whose certificate is NOT trusted; it must
  stay empty, and monitor.err must report the failed delivery.
"""

import json
import sys
from pathlib import Path

# notify.rs, syslog_severity: the RFC 5424 severity of each alert severity, as rsyslog names it.
SYSLOG_SEVERITY = {
    "critical": "crit",
    "high": "err",
    "medium": "warning",
    "low": "notice",
    "info": "info",
}


def load_alerts(path: Path) -> list[str]:
    return [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def syslog_records(path: Path) -> list[dict]:
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        parts = line.split("\t", 5)
        if len(parts) != 6:
            raise ValueError(f"syslog.tsv: not 6 fields: {line!r}")
        name, facility, severity, app, msgid, msg = parts
        records.append(
            {
                "input": name,
                "facility": facility,
                "severity": severity,
                "app": app,
                "msgid": msgid,
                # rsyslog keeps the space between the header and MSG in some versions.
                "msg": msg.strip(),
            }
        )
    return records


def webhook_bodies(path: Path) -> list[dict]:
    if not path.exists():
        return []
    entries = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            entries.append(json.loads(line))
    return entries


def expected_syslog(alert: dict) -> dict:
    return {
        "facility": "local0",
        "severity": SYSLOG_SEVERITY[alert["severity"]],
        "app": "network-scope",
        "msgid": alert["kind"],
        "msg": f"{alert['severity']} {alert['subject']}: {alert['message']}",
    }


def check(work: Path) -> list[str]:
    """The problems found; empty when delivery is correct."""
    problems = []
    lines = load_alerts(work / "alerts.jsonl")
    alerts = [json.loads(line) for line in lines]
    if not alerts:
        return ["monitor raised no alert in its second cycle (expected port-opened)"]
    if not any(a["kind"] == "port-opened" for a in alerts):
        problems.append(f"no port-opened alert among {[a['kind'] for a in alerts]}")

    # Syslog: every alert once over UDP and once over TCP (octet counting), parsed by rsyslog
    # into the same fields Network Scope put in the RFC 5424 header.
    records = syslog_records(work / "syslog.tsv")
    for transport in ("imudp", "imtcp"):
        got = [{k: v for k, v in r.items() if k != "input"} for r in records if r["input"] == transport]
        want = [expected_syslog(a) for a in alerts]
        for w in want:
            if w not in got:
                problems.append(f"syslog {transport}: missing {w}; got {got}")
        if len(got) != len(want):
            problems.append(f"syslog {transport}: {len(got)} messages for {len(want)} alerts")

    # Webhooks: nginx received each alert line as the body of a POST with the JSON type.
    for name in ("http", "https"):
        entries = webhook_bodies(work / f"webhook-{name}.log")
        bodies = [e.get("body", "") for e in entries]
        if sorted(bodies) != sorted(lines):
            problems.append(f"webhook {name}: bodies {bodies} differ from the alerts {lines}")
        for e in entries:
            if e.get("method") != "POST" or e.get("uri") != "/hook":
                problems.append(f"webhook {name}: unexpected request {e}")
            if not e.get("type", "").startswith("application/json"):
                problems.append(f"webhook {name}: content type {e.get('type')!r}")
            if e.get("agent") != "network-scope":
                problems.append(f"webhook {name}: user agent {e.get('agent')!r}")
            if e.get("scheme") != name:
                problems.append(f"webhook {name}: scheme {e.get('scheme')!r}")

    # A certificate that is not trusted: nothing is sent, and monitor says why.
    if webhook_bodies(work / "webhook-untrusted.log"):
        problems.append("the webhook with an untrusted certificate received alerts")
    err = (work / "monitor.err").read_text(encoding="utf-8", errors="replace")
    failed = [l for l in err.splitlines() if "alert delivery failed" in l and "18444" in l]
    if not failed:
        problems.append("monitor did not report the failed delivery to the untrusted webhook")
    elif not any("UnknownIssuer" in l for l in failed):
        # The certificate is an ordinary server certificate: the only thing wrong with it is
        # that no trusted CA issued it.
        problems.append(f"the untrusted webhook was rejected for another reason: {failed}")
    return problems


def main() -> int:
    work = Path(sys.argv[1])
    problems = check(work)
    alerts = load_alerts(work / "alerts.jsonl")
    if problems:
        for p in problems:
            print(f"FAIL: {p}")
        return 1
    print(
        f"OK: {len(alerts)} alert(s) reached rsyslog over UDP and TCP with the right facility, "
        "severity, app-name and msgid, and nginx over HTTP and HTTPS (private CA through "
        "SSL_CERT_FILE) with the exact JSON body; the untrusted HTTPS webhook got nothing."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
