// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! Safety linter for probe files (roadmap K65): `probes lint` and `probes validate` in the CLI,
//! and a CI step on `data/probes.json`. A pull request that adds a probe is reviewed by a person;
//! this catches the mistakes a review should not have to find by eye.
//!
//! It checks what the probe would send and what its rules cost, without sending anything:
//!
//! - `ot-port`: a probe with a payload for an industrial or printer port. The list is the one the
//!   engine already uses (`is_ot_udp_port`, which includes `is_ot_port_candidate`); there is no
//!   second deny list.
//! - `write-payload`: a payload that starts a line with a verb that writes, deletes, runs or mails
//!   (`PUT`, `DELETE`, `STOR`, `SET`, `FLUSHALL`, `DROP`, `MAIL`, ...). Probes only ask.
//! - `payload-too-long`: more than [`MAX_PAYLOAD`] bytes.
//! - `regex-too-long`, `regex-too-big`, `regex-nested-quantifier`, `bad-regex`: the `regex` crate
//!   matches in linear time, so a rule cannot hang this program, but a probe file is also read by
//!   people and by other tools, a huge pattern compiles into a large automaton, and a nested
//!   unbounded quantifier such as `(a+)+` is the classic catastrophic pattern in any backtracking
//!   engine. The nested-quantifier check is a heuristic: it does not look for overlapping
//!   alternatives such as `(a|a)*`.
//! - `wait-too-long`, `bad-payload`, `bad-capture` (a `$n` in a rule that the pattern does not
//!   capture), `duplicate-name`, `empty-name` and `unused-payload` are correctness findings.
use super::{
    is_ot_udp_port,
    probes::{RawDb, RawProbe, unhex},
};
use regex::bytes::RegexBuilder;
use std::fmt;

/// Longest payload a probe may send (the longest built-in one is 52 bytes).
pub const MAX_PAYLOAD: usize = 512;
/// Longest regular expression of a rule, in characters (the longest built-in one is 129).
pub const MAX_PATTERN: usize = 512;
/// Longest time a probe may wait for the reply, in milliseconds (the null probe uses 2500).
pub const MAX_WAIT_MS: u64 = 10_000;
/// Limit on the compiled size of one rule (the `regex` default is 10 MiB).
const REGEX_SIZE_LIMIT: usize = 256 * 1024;

/// Verbs that open a payload line and mean "change something", "run something" or "send mail":
/// HTTP/WebDAV methods, FTP, SMTP, Redis, SQL and shell-like commands.
const WRITE_VERBS: &[&str] = &[
    // HTTP, WebDAV
    "PUT",
    "POST",
    "DELETE",
    "PATCH",
    "MKCOL",
    "MOVE",
    "COPY",
    "PROPPATCH",
    "LOCK",
    "UNLOCK",
    "CONNECT",
    // FTP
    "STOR",
    "STOU",
    "APPE",
    "DELE",
    "MKD",
    "RMD",
    "RNFR",
    "RNTO",
    "SITE",
    // SMTP
    "MAIL",
    "RCPT",
    "DATA",
    // Redis and other key-value stores
    "SET",
    "SETEX",
    "DEL",
    "FLUSHALL",
    "FLUSHDB",
    "CONFIG",
    "SLAVEOF",
    "REPLICAOF",
    "EVAL",
    "EVALSHA",
    "SCRIPT",
    "MODULE",
    "SAVE",
    "BGSAVE",
    "BGREWRITEAOF",
    "DEBUG",
    "MIGRATE",
    "RESTORE",
    "RENAME",
    "SHUTDOWN",
    "FUNCTION",
    // SQL
    "INSERT",
    "UPDATE",
    "CREATE",
    "ALTER",
    "DROP",
    "TRUNCATE",
    "GRANT",
    "REVOKE",
    "REPLACE",
    "MERGE",
    // shells and device consoles
    "WRITE",
    "ERASE",
    "FORMAT",
    "REBOOT",
    "RESTART",
    "HALT",
    "STOP",
    "START",
    "KILL",
    "EXEC",
    "EXECUTE",
    "SYSTEM",
    "RM",
    "UPLOAD",
    "DOWNLOAD",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    /// The file must not be merged.
    Error,
    /// Worth a look; does not fail the check.
    Warning,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Issue {
    pub level: Level,
    /// The probe the issue is about.
    pub probe: String,
    /// A stable short code (see the module documentation).
    pub code: &'static str,
    pub message: String,
}
impl fmt::Display for Issue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let level = match self.level {
            Level::Error => "error",
            Level::Warning => "warning",
        };
        write!(
            f,
            "{level}: {}: [{}] {}",
            self.probe, self.code, self.message
        )
    }
}

/// Number of [`Level::Error`] issues.
pub fn error_count(issues: &[Issue]) -> usize {
    issues.iter().filter(|i| i.level == Level::Error).count()
}

/// What the scan of a group knows so far.
#[derive(Clone, Copy, Default)]
struct Group {
    /// The group contains an unbounded quantifier (`*`, `+`, `{n,}`).
    unbounded: bool,
    /// The last thing in the group is a quantified atom (`a+`, `b?`, `(..)*`), so the group can
    /// end with a different amount of text and a following repeat of the group is ambiguous.
    flexible_tail: bool,
}

/// True for the shape of catastrophic backtracking: a group that contains an unbounded
/// quantifier, ends in a quantified atom, and is itself repeated without bound: `(a+)+`,
/// `(.*)*x`, `((ab)+c*)+`. A delimiter after the inner repeat makes the split unambiguous and is
/// accepted: `(?:[^\r\n]+\r\n)*` (a header line loop) is not flagged. Escapes and character
/// classes are skipped. A heuristic, see the module documentation.
pub fn has_nested_quantifier(pattern: &str) -> bool {
    let chars: Vec<char> = pattern.chars().collect();
    let mut stack: Vec<Group> = vec![Group::default()];
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '\\' => {
                i += 1;
                stack.last_mut().expect("root group").flexible_tail = false;
            }
            '[' => {
                // A class: skip to its closing bracket (a leading ] or ^] is a literal).
                i += 1;
                if chars.get(i) == Some(&'^') {
                    i += 1;
                }
                if chars.get(i) == Some(&']') {
                    i += 1;
                }
                let mut depth = 0;
                while i < chars.len() {
                    match chars[i] {
                        '\\' => i += 1,
                        '[' => depth += 1,
                        ']' if depth == 0 => break,
                        ']' => depth -= 1,
                        _ => {}
                    }
                    i += 1;
                }
                stack.last_mut().expect("root group").flexible_tail = false;
            }
            '(' => stack.push(Group::default()),
            ')' if stack.len() > 1 => {
                let inner = stack.pop().expect("checked");
                if inner.unbounded && inner.flexible_tail && unbounded_at(&chars, i + 1) {
                    return true;
                }
                let parent = stack.last_mut().expect("root group");
                parent.unbounded |= inner.unbounded;
                // The quantifier after the group, if any, sets the tail flexible again.
                parent.flexible_tail = inner.flexible_tail;
            }
            '*' | '+' => {
                let top = stack.last_mut().expect("root group");
                top.unbounded = true;
                top.flexible_tail = true;
            }
            '?' => stack.last_mut().expect("root group").flexible_tail = true,
            '{' => match counted_repeat(&chars, i) {
                Some((end, unbounded)) => {
                    let top = stack.last_mut().expect("root group");
                    top.unbounded |= unbounded;
                    top.flexible_tail = true;
                    i = end;
                }
                None => stack.last_mut().expect("root group").flexible_tail = false,
            },
            _ => stack.last_mut().expect("root group").flexible_tail = false,
        }
        i += 1;
    }
    false
}
/// A counted repeat `{n}`, `{n,}` or `{n,m}` at `chars[at]`: the index of its `}` and whether it
/// is unbounded (`{n,}`).
fn counted_repeat(chars: &[char], at: usize) -> Option<(usize, bool)> {
    let close = at + chars[at..].iter().take(16).position(|c| *c == '}')?;
    let body: String = chars[at + 1..close].iter().collect();
    let digits = |t: &str| !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit());
    match body.split_once(',') {
        None => digits(&body).then_some((close, false)),
        Some((lo, hi)) => {
            (digits(lo) && (hi.is_empty() || digits(hi))).then_some((close, hi.is_empty()))
        }
    }
}
/// Is there an unbounded quantifier (`*`, `+`, `{n,}`) at `chars[at]`?
fn unbounded_at(chars: &[char], at: usize) -> bool {
    match chars.get(at) {
        Some('*' | '+') => true,
        Some('{') => counted_repeat(chars, at).is_some_and(|(_, unbounded)| unbounded),
        _ => false,
    }
}

/// The first write-like verb that starts a line of `payload`.
fn write_verb(payload: &[u8]) -> Option<&'static str> {
    let text = String::from_utf8_lossy(payload);
    text.split('\n').find_map(|line| {
        let first = line.split_whitespace().next()?.to_ascii_uppercase();
        WRITE_VERBS.iter().find(|v| **v == first).copied()
    })
}

fn lint_probe(p: &RawProbe, issues: &mut Vec<Issue>) {
    let mut add = |level, code, message: String| {
        issues.push(Issue {
            level,
            probe: p.name.clone(),
            code,
            message,
        })
    };
    let mut payload = p.send.clone().into_bytes();
    match unhex(&p.send_hex) {
        Ok(bytes) => payload.extend(bytes),
        Err(e) => add(Level::Error, "bad-payload", e),
    }
    if !payload.is_empty() {
        for port in p.ports.iter().filter(|port| is_ot_udp_port(**port)) {
            add(
                Level::Error,
                "ot-port",
                format!(
                    "port {port} is an industrial or printer port; probes never send there \
                     (see CONTRIBUTING.md, safety rule 4)"
                ),
            );
        }
        if p.ports.is_empty() {
            add(
                Level::Warning,
                "unused-payload",
                "has a payload but no ports, so it is never sent".into(),
            );
        }
        if let Some(verb) = write_verb(&payload) {
            add(
                Level::Error,
                "write-payload",
                format!("the payload starts a line with {verb}, a verb that changes state"),
            );
        }
    }
    if payload.len() > MAX_PAYLOAD {
        add(
            Level::Error,
            "payload-too-long",
            format!("{} bytes (limit {MAX_PAYLOAD})", payload.len()),
        );
    }
    if p.wait_ms > MAX_WAIT_MS {
        add(
            Level::Error,
            "wait-too-long",
            format!("wait_ms {} (limit {MAX_WAIT_MS})", p.wait_ms),
        );
    }
    for rule in &p.rules {
        let shown: String = rule.re.chars().take(40).collect();
        if rule.re.chars().count() > MAX_PATTERN {
            add(
                Level::Error,
                "regex-too-long",
                format!(
                    "pattern {shown:?}... has {} characters (limit {MAX_PATTERN})",
                    rule.re.chars().count()
                ),
            );
            continue;
        }
        if has_nested_quantifier(&rule.re) {
            add(
                Level::Error,
                "regex-nested-quantifier",
                format!(
                    "pattern {shown:?} repeats a group that already repeats; this is the shape \
                     of catastrophic backtracking in other regex engines. Rewrite it with a \
                     single quantifier or a bounded count"
                ),
            );
        }
        // The same options as the scanner uses, with a tighter size limit.
        match RegexBuilder::new(&rule.re)
            .unicode(false)
            .dot_matches_new_line(true)
            .size_limit(REGEX_SIZE_LIMIT)
            .build()
        {
            Err(regex::Error::CompiledTooBig(_)) => add(
                Level::Error,
                "regex-too-big",
                format!(
                    "pattern {shown:?} compiles to more than {} KiB; use smaller repeat counts",
                    REGEX_SIZE_LIMIT / 1024
                ),
            ),
            Err(e) => add(Level::Error, "bad-regex", format!("pattern {shown:?}: {e}")),
            Ok(re) => {
                let groups = re.captures_len() - 1;
                for template in [&rule.service, &rule.product, &rule.version, &rule.info] {
                    for n in capture_refs(template).filter(|n| *n > groups) {
                        add(
                            Level::Warning,
                            "bad-capture",
                            format!(
                                "${n} in {template:?} but pattern {shown:?} has {groups} group(s)"
                            ),
                        );
                    }
                }
            }
        }
    }
}
/// The `$n` references (single digit, like `ProbeDb` expands them) in a rule template.
fn capture_refs(template: &str) -> impl Iterator<Item = usize> + '_ {
    let mut chars = template.chars().peekable();
    std::iter::from_fn(move || {
        while let Some(c) = chars.next() {
            if c == '$'
                && let Some(d) = chars.peek().and_then(|d| d.to_digit(10))
            {
                chars.next();
                return Some(d as usize);
            }
        }
        None
    })
}

/// Lints the text of a probe file. `Err` is a file that is not even valid JSON in the probe
/// format (the scanner would refuse it too); everything else is reported as issues.
pub fn lint(json: &str) -> Result<Vec<Issue>, String> {
    let db: RawDb = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let mut issues = vec![];
    let mut seen = std::collections::BTreeSet::new();
    for p in &db.probes {
        if p.name.trim().is_empty() {
            issues.push(Issue {
                level: Level::Error,
                probe: "(unnamed)".into(),
                code: "empty-name",
                message: "a probe has an empty name".into(),
            });
        } else if !seen.insert(p.name.clone()) {
            issues.push(Issue {
                level: Level::Warning,
                probe: p.name.clone(),
                code: "duplicate-name",
                message: "the name is used twice in this file".into(),
            });
        }
        lint_probe(p, &mut issues);
    }
    Ok(issues)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::ProbeDb;

    fn codes(json: &str) -> Vec<&'static str> {
        lint(json).unwrap().iter().map(|i| i.code).collect()
    }
    fn probe(extra: &str) -> String {
        format!(r#"{{"probes":[{{"name":"t",{extra}}}]}}"#)
    }

    #[test]
    fn the_builtin_probe_database_passes_without_any_issue() {
        let issues = lint(ProbeDb::builtin_json()).unwrap();
        assert!(
            issues.is_empty(),
            "{}",
            issues
                .iter()
                .map(Issue::to_string)
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    #[test]
    fn a_payload_for_an_industrial_or_printer_port_is_an_error() {
        for port in [502, 102, 44818, 2222, 47808, 9100, 515, 1089, 34964] {
            let c = codes(&probe(&format!(r#""ports":[{port}],"send":"hello""#)));
            assert_eq!(c, ["ot-port"], "port {port}");
        }
        // Both protocols are checked, not only UDP.
        let c = codes(&probe(
            r#""proto":"udp","ports":[5060,502],"send_hex":"01""#,
        ));
        assert_eq!(c, ["ot-port"]);
        // A probe that sends nothing never harms a port.
        assert!(codes(&probe(r#""ports":[502],"rules":[]"#)).is_empty());
        assert!(codes(&probe(r#""ports":[8080],"send":"GET / HTTP/1.0\r\n\r\n""#)).is_empty());
    }

    #[test]
    fn write_like_payloads_are_errors() {
        for send in [
            "PUT /x HTTP/1.1\\r\\n\\r\\n",
            "post /x HTTP/1.1",
            "DELETE /x HTTP/1.1",
            "FLUSHALL\\r\\n",
            "INFO\\r\\nSET a b\\r\\n",
            "STOR file\\r\\n",
            "DROP TABLE x;",
            "MAIL FROM:<a@b>\\r\\n",
        ] {
            let c = codes(&probe(&format!(r#""ports":[7000],"send":"{send}""#)));
            assert_eq!(c, ["write-payload"], "{send}");
        }
        // Hex payloads are decoded first: 50 55 54 20 = "PUT ".
        let c = codes(&probe(r#""ports":[7000],"send_hex":"50 55 54 20 2f""#));
        assert_eq!(c, ["write-payload"]);
        for ok in [
            "INFO server\\r\\n",
            "version\\r\\n",
            "OPTIONS * RTSP/1.0",
            "HEAD / HTTP/1.0",
        ] {
            assert!(codes(&probe(&format!(r#""ports":[7000],"send":"{ok}""#))).is_empty());
        }
    }

    #[test]
    fn long_payloads_and_waits_are_errors() {
        let long = "41".repeat(MAX_PAYLOAD + 1);
        let c = codes(&probe(&format!(r#""ports":[7000],"send_hex":"{long}""#)));
        assert_eq!(c, ["payload-too-long"]);
        let ok = "41".repeat(MAX_PAYLOAD);
        assert!(codes(&probe(&format!(r#""ports":[7000],"send_hex":"{ok}""#))).is_empty());
        assert_eq!(
            codes(&probe(r#""wait_ms":10001"#)),
            ["wait-too-long"],
            "a probe may not hold a connection open for long"
        );
        assert!(codes(&probe(r#""wait_ms":10000"#)).is_empty());
        assert_eq!(
            codes(&probe(r#""ports":[7000],"send_hex":"4""#)),
            ["bad-payload"]
        );
    }

    #[test]
    fn regex_limits_and_catastrophic_shapes_are_errors() {
        let rule = |re: &str| {
            probe(&format!(
                r#""rules":[{{"re":{},"service":"x"}}]"#,
                serde_json::to_string(re).unwrap()
            ))
        };
        assert!(codes(&rule(r"^SSH-([\d.]+)-OpenSSH_([\w.]+)")).is_empty());
        assert_eq!(
            codes(&rule(&"a".repeat(MAX_PATTERN + 1))),
            ["regex-too-long"]
        );
        assert!(codes(&rule(&"a".repeat(MAX_PATTERN))).is_empty());
        // Bounded repeats multiply: this compiles to far more than the size limit.
        assert_eq!(codes(&rule(r"(?:[a-z]{1,200}){1,200}")), ["regex-too-big"]);
        assert_eq!(codes(&rule("(")), ["bad-regex"]);
        for bad in [
            "(a+)+",
            "(a*)*",
            "(.*)*x",
            "(a+)*",
            "((ab)+c*)+",
            "(a{2,})+",
            "(?:x+y?)*",
            "(a+){2,}",
            "(a+?)+",
        ] {
            assert_eq!(codes(&rule(bad)), ["regex-nested-quantifier"], "{bad}");
        }
        for fine in [
            "(a+)",
            "(ab)+",
            "a+b+",
            r"\(a+\)+",
            "[(a+]+",
            "(a|b)*c",
            "(a{2,3})+",
            "(a+)?",
            r"(?:[^\r\n]+\r\n)*?Server: ",
            "(a+b)+",
            "x{2}",
            r"(?i)^220[ -][^\r\n]*Exim ([\d.]+)",
            "((a)b)+",
        ] {
            assert!(!has_nested_quantifier(fine), "{fine}");
        }
    }

    #[test]
    fn correctness_findings_are_warnings_or_errors() {
        let json = r#"{"probes":[
            {"name":"a","rules":[{"re":"^x(\\d)","service":"s","product":"$2"}]},
            {"name":"a","ports":[9999],"send":"hi"},
            {"name":"b","send":"hi"},
            {"name":" "}]}"#;
        let issues = lint(json).unwrap();
        let got: Vec<(Level, &str)> = issues.iter().map(|i| (i.level, i.code)).collect();
        assert_eq!(
            got,
            [
                (Level::Warning, "bad-capture"),
                (Level::Warning, "duplicate-name"),
                (Level::Warning, "unused-payload"),
                (Level::Error, "empty-name"),
            ]
        );
        assert_eq!(error_count(&issues), 1);
        assert!(
            issues[0]
                .to_string()
                .starts_with("warning: a: [bad-capture]")
        );
        assert!(lint("not json").is_err());
        assert!(
            lint(r#"{"probes":[{"rules":[]}]}"#).is_err(),
            "name is required"
        );
    }
}
