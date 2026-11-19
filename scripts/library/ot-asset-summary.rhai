// name: ot-asset-summary
// description: Summarises what read-only OT identification found (vendor, product, firmware) as one line per host.
// safety: Reads the scan result only. Sends nothing, opens no files, makes no login attempts.
// kind: host
//
// Use: network-scope scan 10.10.0.0/24 --ot --script library:ot-asset-summary
// Reads the identity keys <Protocol>.<field> that the OT identification stored
// (Modbus, S7, OPC UA, EtherNet/IP, BACnet). Sets script.ot_protocols and script.ot_summary
// and adds an informational finding so the asset shows up in finding lists.

fn on_host(h) {
    let protocols = ["Modbus", "S7", "OPC UA", "EtherNet/IP", "BACnet"];
    let fields = ["vendor", "product", "name", "device_type", "product_code", "firmware", "serial"];
    let seen = "";
    let summary = "";
    for protocol in protocols {
        let part = "";
        for field in fields {
            let value = h.identity(protocol + "." + field);
            if value != "" {
                if part != "" { part += ", "; }
                part += field + " " + value;
            }
        }
        if part != "" {
            if seen != "" { seen += ", "; }
            seen += protocol;
            if summary != "" { summary += "; "; }
            summary += protocol + ": " + part;
        }
    }
    if seen != "" {
        h.set("ot_protocols", seen);
        h.set("ot_summary", summary);
        h.finding("info", "ot-asset-summary", "OT asset identified", summary);
    }
}
