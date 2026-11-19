// name: service-baseline
// description: Flags every open TCP port that is not on a baseline list you maintain in the script.
// safety: Reads the scan result only. Sends nothing, opens no files, makes no login attempts.
// kind: host
//
// Use: copy the script, put the ports you expect into `baseline`, then
//      network-scope scan 192.168.1.0/24 --script my-baseline.rhai
// For "which service is new since the last scan" use `monitor`: it raises a port-opened alert
// from the stored scans, and scripts/library/on-alert/new-service-log.rhai records those.

fn on_host(h) {
    // Edit this list. Ports not in it are reported.
    let baseline = [22, 80, 443];
    let extra = "";
    for p in h.open {
        if !(p in baseline) {
            extra += " " + p;
        }
    }
    if extra != "" {
        h.finding("low", "service-not-in-baseline", "Open ports outside the baseline", "not in baseline:" + extra);
        h.set("extra_ports", extra);
    }
}
