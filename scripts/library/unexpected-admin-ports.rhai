// name: unexpected-admin-ports
// description: Flags remote-administration ports (Telnet, RDP, VNC, WinRM, Docker, WinBox, Webmin) that are open.
// safety: Reads the scan result only. Sends nothing, opens no files, makes no login attempts.
// kind: host
//
// Use: network-scope scan 192.168.1.0/24 --script library:unexpected-admin-ports
// Edit the names table to match what is allowed on your network (for example remove 3389
// when RDP is expected on this segment).

fn on_host(h) {
    let names = #{
        "23": "Telnet",
        "3389": "RDP",
        "5900": "VNC",
        "5985": "WinRM",
        "5986": "WinRM TLS",
        "2375": "Docker API",
        "8291": "MikroTik WinBox",
        "10000": "Webmin"
    };
    let found = "";
    for p in h.open {
        let key = p.to_string();
        if names.contains(key) {
            if found != "" { found += ", "; }
            found += names[key] + " (" + p + ")";
        }
    }
    if found != "" {
        h.finding("medium", "admin-ports-open", "Remote administration ports are open", found);
        h.set("admin_ports", found);
    }
}
