// name: new-service-log
// description: Records every newly opened port (a service that was not there in the previous scan) in new-services.log.
// safety: Runs only when a monitor alert fires. No network, no processes. It can write only below --on-alert-dir, only a file name without a path, at most 64 KB per call and 1 MB per file. It changes nothing on any device.
// kind: alert
//
// Use: network-scope monitor 192.168.1.0/24 --interval 300 --on-alert scripts/library/on-alert/new-service-log.rhai
// monitor compares each scan with the previous one of the same targets and raises port-opened;
// the baseline is that previous scan, so this is "new service since the last scan".

fn on_alert(a) {
    if a.kind == "port-opened" {
        append_file("new-services.log", `${a.timestamp} ${a.host} ${a.details}` + "\n");
        log("new service: " + a.details);
    }
}
