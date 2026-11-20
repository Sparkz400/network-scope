// name: weak-tls-summary
// description: One finding per host that lists every TLS port with weak protocols or cipher suites.
// safety: Reads the scan result only. Sends nothing, opens no files, makes no login attempts.
// kind: host
//
// Use: network-scope scan 10.0.0.0/24 --services --script library:weak-tls-summary
// Reads tls.<port>.weak and tls.<port>.versions. Severity is high when SSLv3, RC4, export-grade
// or anonymous suites are accepted, otherwise medium. The built-in rules report each weakness
// separately; this gives a per-host overview for a report.

fn on_host(h) {
    let summary = "";
    let severe = false;
    for p in h.open {
        let weak = h.identity("tls." + p + ".weak");
        if weak != "" {
            if summary != "" { summary += " | "; }
            summary += p + ": " + weak;
            if weak.contains("SSLv3") || weak.contains("RC4") || weak.contains("export-grade") || weak.contains("anonymous") {
                severe = true;
            }
        }
    }
    if summary != "" {
        h.finding(if severe { "high" } else { "medium" }, "weak-tls-summary", "Weak TLS configuration", summary);
        h.set("weak_tls", "yes");
    }
}
