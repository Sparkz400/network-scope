// name: log-alerts
// description: Appends every alert as one line to alerts.log in the alert-script directory.
// safety: Runs only when a monitor alert fires. No network, no processes. It can write only below --on-alert-dir, only a file name without a path, at most 64 KB per call and 1 MB per file. It changes nothing on any device.
// kind: alert
//
// Use: network-scope monitor 192.168.1.0/24 --interval 300 --on-alert scripts/library/on-alert/log-alerts.rhai
// The alert has: a.kind, a.severity (info..critical), a.host, a.details, a.timestamp.
// API: log(text)  append_file(name, text)  write_file(name, text)

fn on_alert(a) {
    let line = `${a.timestamp} ${a.severity} ${a.kind} ${a.host} ${a.details}`;
    log(line);
    append_file("alerts.log", line + "\n");
}
