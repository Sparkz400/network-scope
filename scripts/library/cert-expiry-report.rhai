// name: cert-expiry-report
// description: Reports TLS certificates that have expired or expire within 60 days, and records the days left.
// safety: Reads the scan result only. Sends nothing, opens no files, makes no login attempts.
// kind: host
//
// Use: network-scope scan 10.0.0.0/24 --services --script library:cert-expiry-report
// Reads tls.<port>.expired and tls.<port>.days_left. The built-in rules already flag 30 days;
// this one widens the window and sets the field script.cert_days_left for reports.

fn on_host(h) {
    let expired = "";
    let soonest = 1000000;
    let soonest_port = 0;
    for p in h.open {
        if h.identity("tls." + p + ".expired") == "true" {
            expired += " " + p;
        }
        let left = h.identity("tls." + p + ".days_left");
        if left != "" {
            try {
                let days = parse_int(left);
                if days >= 0 && days < soonest {
                    soonest = days;
                    soonest_port = p;
                }
            } catch {
            }
        }
    }
    if expired != "" {
        h.finding("high", "cert-expired-report", "TLS certificate has expired", "expired on port" + expired);
    }
    if soonest_port != 0 {
        h.set("cert_days_left", soonest.to_string());
        if soonest <= 60 {
            h.finding("low", "cert-expiry-60d", "TLS certificate expires within 60 days", soonest + " days left on port " + soonest_port);
        }
    }
}
