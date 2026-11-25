#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright the Network Scope contributors
# SPDX-License-Identifier: MIT
"""Check that every finding rule id in core/src/risk.rs has a documentation page.

Run from anywhere (the paths are derived from this file):

    python -I docs/check_finding_pages.py

It reads the rule ids out of core/src/risk.rs (the literal ids of the `o.add(` calls and of
`Finding { id: "..." }` constructions, nothing is compiled) and fails when

- a rule id has no page docs/src/findings/<id>.md, or a page has no matching rule id;
- a page is missing from docs/src/SUMMARY.md or from docs/src/findings/index.md
  (mdBook does not render pages that SUMMARY.md leaves out);
- a page lacks one of the template sections, or its Severity row disagrees with the
  severity the code assigns;
- a relative link inside a page points at a file that does not exist;
- a page's "How to fix" has no bullet point, or its "References" no https:// link (except
  the pages in NO_EXTERNAL_REFERENCE, whose rules the user writes);
- risk.rs contains an id expression this script does not understand (it fails rather than
  silently skipping the new rule).

Two id families are built at run time and share one generic page each, listed in GENERIC.
Standard library only.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RISK = ROOT / "core" / "src" / "risk.rs"
PAGES = ROOT / "docs" / "src" / "findings"
SUMMARY = ROOT / "docs" / "src" / "SUMMARY.md"

# id prefix built with format!() in risk.rs -> the page that covers the whole family
GENERIC = {
    "cve-": "cve-hints",  # cve-<first CVE id of a rule in data/cves.json>
    "script-": "script-findings",  # script-<id given to h.finding() by a user script>
}
SECTIONS = [
    "What it means",
    "Why it matters",
    "How it is detected",
    "Possible false positives",
    "How to fix",
    "References",
]
SEVERITIES = {"info", "low", "medium", "high", "critical"}
# user scripts define these findings, so there is no external source to cite
NO_EXTERNAL_REFERENCE = {"script-findings"}

ADD_CALL = re.compile(r"\bo\.add\(\s*([A-Za-z_:.]+)\s*,\s*(.{0,60})", re.S)
LITERAL_ID = re.compile(r'"([a-z0-9][a-z0-9-]*)"')
FORMAT_ID = re.compile(r'&format!\(\s*"([a-z]+-)')
FINDING_ID = re.compile(r'\bid:\s*"([a-z0-9][a-z0-9-]*)"\s*\.into\(\)')


def rule_ids(text):
    """Returns (literal ids -> set of severities, generic pages needed, errors)."""
    # The unit tests (a top-level `#[cfg(test)] mod tests`) come last in the file.
    text = re.split(r"^#\[cfg\(test\)\]", text, maxsplit=1, flags=re.M)[0]
    ids = {}
    generic = set()
    errors = []
    calls = [m for m in re.finditer(r"\bo\.add\(", text)]
    for m in calls:
        call = ADD_CALL.match(text, m.start())
        if not call:
            errors.append("unparsable o.add( call at offset %d" % m.start())
            continue
        severity, rest = call.group(1), call.group(2)
        literal = LITERAL_ID.match(rest)
        formatted = FORMAT_ID.match(rest)
        if literal:
            sev = severity.removeprefix("Severity::").lower()
            ids.setdefault(literal.group(1), set()).add(sev if sev in SEVERITIES else None)
        elif formatted and formatted.group(1) in GENERIC:
            generic.add(GENERIC[formatted.group(1)])
        else:
            errors.append(
                "o.add( with an id expression this script does not know: %r; "
                "add a page and teach docs/check_finding_pages.py" % rest[:40].strip()
            )
    # Findings built by hand: `Finding {` that is neither the type nor its impl.
    constructions = [
        m
        for m in re.finditer(r"\bFinding\s*\{", text)
        if not re.search(r"(struct|impl)\s+$", text[max(0, m.start() - 8) : m.start()])
    ]
    literal_findings = FINDING_ID.findall(text)
    # One construction is Out::add itself (its id is a variable).
    if len(constructions) != len(literal_findings) + 1:
        errors.append(
            "found %d Finding { } constructions but %d literal ids (expected one more "
            "construction, Out::add); a new construction needs a page" % (len(constructions), len(literal_findings))
        )
    for fid in literal_findings:
        ids.setdefault(fid, set()).add(None)  # severity is computed at run time
    return ids, generic, errors


def section(body, name):
    """The text of the `## name` section, up to the next level-2 heading."""
    parts = re.split(r"^## " + re.escape(name) + r"\s*$", body, maxsplit=1, flags=re.M)
    return re.split(r"^## ", parts[1], maxsplit=1, flags=re.M)[0] if len(parts) == 2 else ""


def read(path):
    return path.read_text(encoding="utf-8")


def main():
    errors = []
    ids, generic, e = rule_ids(read(RISK))
    errors += e
    expected = set(ids) | generic
    if not ids or not generic:
        errors.append("no rule ids found in core/src/risk.rs; the parser needs an update")

    pages = {p.stem for p in PAGES.glob("*.md") if p.name != "index.md"}
    for missing in sorted(expected - pages):
        errors.append("rule id %r has no page docs/src/findings/%s.md" % (missing, missing))
    for orphan in sorted(pages - expected):
        errors.append("page docs/src/findings/%s.md has no rule id in core/src/risk.rs" % orphan)

    summary = read(SUMMARY)
    index = read(PAGES / "index.md") if (PAGES / "index.md").exists() else ""
    if not index:
        errors.append("docs/src/findings/index.md is missing")
    if "findings/index.md" not in summary:
        errors.append("docs/src/SUMMARY.md does not list findings/index.md")

    for pid in sorted(pages & expected):
        path = PAGES / (pid + ".md")
        body = read(path)
        if "(findings/%s.md)" % pid not in summary:
            errors.append("%s is not listed in docs/src/SUMMARY.md (mdBook would not publish it)" % pid)
        if "(%s.md)" % pid not in index:
            errors.append("%s is not listed in docs/src/findings/index.md" % pid)
        if not body.startswith("# "):
            errors.append("%s.md does not start with a level-1 heading" % pid)
        headings = re.findall(r"^## (.+?)\s*$", body, re.M)
        if headings != SECTIONS:
            errors.append("%s.md sections are %s, expected %s" % (pid, headings, SECTIONS))
        fix = section(body, "How to fix")
        if not re.search(r"^- \S", fix, re.M):
            errors.append("%s.md has no fix steps (bullet points) under How to fix" % pid)
        if pid not in NO_EXTERNAL_REFERENCE and "](https://" not in section(body, "References"):
            errors.append("%s.md has no https:// reference link under References" % pid)
        row = re.search(r"^\| Severity \| (.+?) \|\s*$", body, re.M)
        if not row:
            errors.append("%s.md has no '| Severity | ... |' row" % pid)
        elif pid in ids and None not in ids[pid]:
            shown = {w.lower() for w in re.findall(r"[A-Za-z]+", row.group(1))} & SEVERITIES
            if shown != ids[pid]:
                errors.append(
                    "%s.md says severity %s, the code assigns %s"
                    % (pid, sorted(shown), sorted(ids[pid]))
                )
        for target in re.findall(r"\]\(([^)#\s]+\.md)(?:#[^)]*)?\)", body):
            if "://" not in target and not (path.parent / target).resolve().exists():
                errors.append("%s.md links to %s, which does not exist" % (pid, target))

    if errors:
        print("Finding documentation is out of date:")
        for line in errors:
            print("  - " + line)
        return 1
    print(
        "ok: %d rule ids + %d generic pages = %d pages, all registered"
        % (len(ids), len(generic), len(expected))
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
