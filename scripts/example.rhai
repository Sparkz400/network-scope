// Example Network Scope script. Check it with:  network-scope scripts scripts/example.rhai
// Use it with:                                   network-scope scan 192.168.1.0/24 --deep --script scripts/example.rhai
//
// Host API: h.ip h.hostname h.mac h.ttl h.ping h.open h.udp h.os h.vendor h.device
//           h.has_port(n)  h.has_service("name")  h.service(port)  h.identity("key")
//           h.set("key", "value")    adds field script.<key>
//           h.finding("low|medium|high|critical|info", "id", "title", "evidence")
//           h.note("text")
// Scripts cannot read files, use the network or start processes, and are stopped after 250 ms.

fn on_host(h) {
    if h.has_port(23) {
        h.finding("high", "policy-telnet", "Telnet is not allowed by policy", "port 23 open on " + h.ip);
    }
    if h.has_port(3389) && !h.has_port(443) {
        h.finding("low", "policy-rdp", "RDP exposed without a web front end", "port 3389 open");
    }
    h.set("zone", if h.ip.starts_with("10.") { "internal" } else { "other" });
}
