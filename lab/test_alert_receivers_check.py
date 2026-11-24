"""Unit tests of lab/alert_receivers_check.py with recorded receiver output (no servers)."""

import json
import tempfile
import unittest
from pathlib import Path

import alert_receivers_check as check

ALERT = {
    "schema": "https://example.invalid/alert",
    "timestamp": 1795000000,
    "severity": "high",
    "kind": "port-opened",
    "subject": "127.0.0.1:18090",
    "message": "TCP port 18090 is open now",
}


def write_work(tmp: Path, *, drop_tcp=False, bad_body=False, untrusted=False, no_warning=False):
    line = json.dumps(ALERT)
    (tmp / "alerts.jsonl").write_text(line + "\n", encoding="utf-8")
    msg = "high 127.0.0.1:18090: TCP port 18090 is open now"
    rows = [f"imudp\tlocal0\terr\tnetwork-scope\tport-opened\t {msg}"]
    if not drop_tcp:
        rows.append(f"imtcp\tlocal0\terr\tnetwork-scope\tport-opened\t{msg}")
    (tmp / "syslog.tsv").write_text("\n".join(rows) + "\n", encoding="utf-8")
    for name in ("http", "https"):
        entry = {
            "scheme": name,
            "method": "POST",
            "uri": "/hook",
            "type": "application/json",
            "agent": "network-scope",
            "body": line if not bad_body else line.replace("high", "low"),
        }
        (tmp / f"webhook-{name}.log").write_text(json.dumps(entry) + "\n", encoding="utf-8")
    (tmp / "webhook-untrusted.log").write_text(
        (json.dumps({"body": line}) + "\n") if untrusted else "", encoding="utf-8"
    )
    warning = "" if no_warning else (
        "Cycle 2: alert delivery failed: webhook https://127.0.0.1:18444/hook: TLS certificate of "
        "127.0.0.1 rejected (invalid peer certificate: UnknownIssuer)\n"
    )
    (tmp / "monitor.err").write_text("Cycle 1: scan #1\n" + warning, encoding="utf-8")


class AlertReceiversCheck(unittest.TestCase):
    def run_check(self, **kw):
        with tempfile.TemporaryDirectory() as d:
            write_work(Path(d), **kw)
            return check.check(Path(d))

    def test_correct_delivery_passes(self):
        self.assertEqual(self.run_check(), [])

    def test_a_missing_tcp_message_fails(self):
        self.assertTrue(any("imtcp" in p for p in self.run_check(drop_tcp=True)))

    def test_a_changed_webhook_body_fails(self):
        self.assertTrue(any("webhook" in p for p in self.run_check(bad_body=True)))

    def test_the_untrusted_webhook_must_get_nothing(self):
        problems = self.run_check(untrusted=True)
        self.assertTrue(any("untrusted" in p for p in problems))

    def test_the_failed_delivery_must_be_reported(self):
        problems = self.run_check(no_warning=True)
        self.assertTrue(any("did not report" in p for p in problems))

    def test_a_rejection_for_another_reason_fails(self):
        with tempfile.TemporaryDirectory() as d:
            write_work(Path(d))
            err = Path(d) / "monitor.err"
            err.write_text(err.read_text().replace("UnknownIssuer", "Other(CaUsedAsEndEntity)"))
            self.assertTrue(any("another reason" in p for p in check.check(Path(d))))

    def test_severity_names_follow_rfc_5424(self):
        self.assertEqual(check.SYSLOG_SEVERITY["critical"], "crit")
        self.assertEqual(check.SYSLOG_SEVERITY["info"], "info")


if __name__ == "__main__":
    unittest.main()
