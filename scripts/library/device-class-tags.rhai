// name: device-class-tags
// description: Tags every host with a class (ot, printer, camera, network, server, workstation, other) in script.class.
// safety: Reads the scan result only. Sends nothing, opens no files, makes no login attempts.
// kind: host
//
// Use: network-scope scan 192.168.1.0/24 --deep --script library:device-class-tags
// The class comes from the device type guess and the open ports, so a report can be grouped by
// it. The tag is stored with the scan; it adds no findings.

fn on_host(h) {
    let kind = h.device.to_lower();
    let cls = "other";
    if kind.contains("industrial") || h.has_port(502) || h.has_port(102) || h.has_port(44818) || h.has_port(4840) {
        cls = "ot";
    } else if kind.contains("printer") || h.has_port(9100) || h.has_port(631) {
        cls = "printer";
    } else if kind.contains("camera") || h.has_port(554) {
        cls = "camera";
    } else if kind.contains("router") || kind.contains("switch") || kind.contains("access point") || kind.contains("gateway") {
        cls = "network";
    } else if kind.contains("server") || h.has_port(22) || h.has_port(445) || h.has_port(3306) {
        cls = "server";
    } else if kind.contains("windows") || kind.contains("workstation") || kind.contains("laptop") || h.has_port(3389) {
        cls = "workstation";
    }
    h.set("class", cls);
}
