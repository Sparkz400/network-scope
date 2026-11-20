// name: smbv1-hosts
// description: Lists hosts that accept the obsolete SMBv1 protocol (needs a scan with --services).
// safety: Reads the scan result only. Sends nothing, opens no files, makes no login attempts.
// kind: host
//
// Use: network-scope scan 192.168.1.0/24 --services --script library:smbv1-hosts
// Reads identity keys smb.<port>.smb1 ("accepted"/"refused") and the service summary.

fn on_host(h) {
    let ports = "";
    for p in h.open {
        if h.identity("smb." + p + ".smb1") == "accepted" || h.service(p).contains("SMBv1") {
            ports += " " + p;
        }
    }
    if ports != "" {
        h.finding("high", "smbv1-host", "Host accepts SMBv1", "SMBv1 accepted on port" + ports);
        h.set("smbv1", "yes");
    }
}
