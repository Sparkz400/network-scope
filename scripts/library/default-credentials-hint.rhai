// name: default-credentials-hint
// description: Hints at devices that commonly ship with default passwords. It only reads the scan result; it never tries a login.
// safety: Reads the scan result only. Sends nothing, opens no files and makes NO login attempts: the finding is a prompt to check the device by hand.
// kind: host
//
// Use: network-scope scan 192.168.1.0/24 --services --script library:default-credentials-hint
// A hint is not a finding about a weakness: it says "this kind of device is often left with a
// factory password, check it". Vendors and ports are a short, editable list.

fn on_host(h) {
    let vendors = ["Hikvision", "Dahua", "TP-Link", "D-Link", "Netgear", "Zyxel", "MikroTik", "Ubiquiti", "Axis", "Ruckus"];
    let reasons = "";
    if h.has_port(23) {
        reasons += "Telnet is open; embedded devices often keep the factory login. ";
    }
    if h.has_port(5900) {
        reasons += "VNC is open; check that a password is set. ";
    }
    let web = h.has_port(80) || h.has_port(8080) || h.has_port(443) || h.has_port(8443);
    if web {
        let vendor = h.vendor;
        for name in vendors {
            if vendor.contains(name) {
                reasons += name + " device with a web interface; check the admin password was changed. ";
                break;
            }
        }
    }
    if h.udp.contains(161) {
        reasons += "SNMP answers; check the community string is not the default. ";
    }
    if reasons != "" {
        h.finding("info", "default-credentials-hint", "Device may still use default credentials (hint, not tested)", reasons);
    }
}
