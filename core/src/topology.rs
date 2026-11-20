//! Network path map built from traceroute data: scanner -> routers -> hosts.
use crate::scan::Host;
use std::collections::{BTreeMap, BTreeSet, HashMap};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Source,
    Router,
    Host,
    Unknown,
}
#[derive(Clone, Debug)]
pub struct Node {
    pub id: String,
    pub label: String,
    pub detail: String,
    pub kind: Kind,
    pub depth: usize,
}
#[derive(Default, Debug)]
pub struct Graph {
    pub nodes: Vec<Node>,
    pub edges: Vec<(usize, usize)>,
    /// Layer-2 links between devices that are not traceroute hops: what the devices say about
    /// each other (LLDP over SNMP, `snmp.lldp.<n>.*` in the host identity).
    pub links: Vec<Link>,
}

/// A link between two nodes with the port at each end. Undirected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Link {
    pub a: usize,
    pub b: usize,
    pub a_port: String,
    pub b_port: String,
    /// Where the link comes from (`"lldp"`).
    pub source: &'static str,
}

fn host_detail(h: &Host) -> (String, String) {
    let mut label = h.ip.to_string();
    let name = if !h.hostname.is_empty() {
        h.hostname.clone()
    } else {
        h.identity.get("mac.vendor").cloned().unwrap_or_default()
    };
    if !name.is_empty() {
        label = format!("{label} ({name})");
    }
    let ports = h
        .open
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let mut detail = String::new();
    if !ports.is_empty() {
        detail.push_str(&format!("ports {ports}"));
    }
    if let Some(os) = h.identity.get("os.guess") {
        detail.push_str(&format!(
            "{}{os}",
            if detail.is_empty() { "" } else { "; " }
        ));
    }
    (label, detail)
}

pub fn build(hosts: &[Host]) -> Graph {
    let mut g = Graph::default();
    let mut index: HashMap<String, usize> = HashMap::new();
    let mut add = |g: &mut Graph, node: Node| -> usize {
        if let Some(&i) = index.get(&node.id) {
            let n = &mut g.nodes[i];
            n.depth = n.depth.min(node.depth);
            if node.kind == Kind::Host {
                n.kind = Kind::Host;
                n.label = node.label;
                n.detail = node.detail;
            }
            return i;
        }
        g.nodes.push(node.clone());
        index.insert(node.id, g.nodes.len() - 1);
        g.nodes.len() - 1
    };
    let root = add(
        &mut g,
        Node {
            id: "scanner".into(),
            label: "This scanner".into(),
            detail: String::new(),
            kind: Kind::Source,
            depth: 0,
        },
    );
    let mut edges = BTreeSet::new();
    for h in hosts.iter().filter(|h| h.responding || !h.trace.is_empty()) {
        let mut prev = root;
        let mut depth = 0;
        for hop in &h.trace {
            if hop.ip == Some(h.ip) {
                break;
            }
            depth = usize::from(hop.ttl);
            let (id, label, kind) = match hop.ip {
                Some(ip) => (ip.to_string(), ip.to_string(), Kind::Router),
                None => (
                    format!("?{}#{}", g.nodes[prev].id, hop.ttl),
                    "* (no reply)".to_string(),
                    Kind::Unknown,
                ),
            };
            let n = add(
                &mut g,
                Node {
                    id,
                    label,
                    detail: hop.rtt.map(|r| format!("{r} ms")).unwrap_or_default(),
                    kind,
                    depth,
                },
            );
            edges.insert((prev, n));
            prev = n;
        }
        let (label, detail) = host_detail(h);
        let n = add(
            &mut g,
            Node {
                id: h.ip.to_string(),
                label,
                detail,
                kind: Kind::Host,
                depth: depth + 1,
            },
        );
        if n != prev {
            edges.insert((prev, n));
        }
    }
    g.edges = edges.into_iter().collect();
    add_lldp_links(&mut g, hosts);
    g
}

/// The MACs a host is known by: its own and those of its SNMP-reported interfaces.
fn macs_of(h: &Host) -> Vec<String> {
    let mut out = vec![];
    let mac = h.mac.to_ascii_uppercase().replace('-', ":");
    if !mac.is_empty() {
        out.push(mac);
    }
    for (k, v) in &h.identity {
        if k.starts_with("snmp.if.")
            && let Some(m) = v
                .split("; ")
                .nth(1)
                .filter(|m| m.len() == 17 && m.contains(':'))
        {
            out.push(m.to_ascii_uppercase());
        }
    }
    out
}

/// Most LLDP links read from the hosts of one scan.
const MAX_LINKS: usize = 2048;

/// Turns the LLDP neighbour tables read over SNMP into links. A neighbour is matched to a
/// scanned host by chassis MAC (the host's own or one of its interfaces), else by system name
/// (SNMP `sysName` or host name); a neighbour that no scanned host matches becomes a node of its
/// own. The two ends of a link usually report each other: the pair is kept once.
///
/// The local port is named from `lldpLocPortDesc` when the agent reported it, else from the
/// short name (`ifName`) or the description (`ifDescr`) of the interface with the same number
/// (the port number of the LLDP-MIB is usually, but not necessarily, the `ifIndex`), else it is
/// `port N`.
fn add_lldp_links(g: &mut Graph, hosts: &[Host]) {
    let responding: Vec<&Host> = hosts.iter().filter(|h| h.responding).collect();
    if !responding
        .iter()
        .any(|h| h.identity.contains_key("snmp.lldp.0.local_port"))
    {
        return;
    }
    // One index per scan instead of a scan of every host per neighbour.
    let mut node_of: HashMap<String, usize> = g
        .nodes
        .iter()
        .enumerate()
        .map(|(i, n)| (n.id.clone(), i))
        .collect();
    let mut by_mac: HashMap<String, usize> = HashMap::new();
    let mut by_name: HashMap<String, usize> = HashMap::new();
    for (i, h) in responding.iter().enumerate() {
        for mac in macs_of(h) {
            by_mac.entry(mac).or_insert(i);
        }
        for name in [h.identity.get("snmp.sysname"), Some(&h.hostname)]
            .into_iter()
            .flatten()
            .filter(|n| !n.is_empty())
        {
            by_name.entry(name.to_ascii_lowercase()).or_insert(i);
        }
    }
    let mut seen = BTreeSet::new();
    for (me, h) in responding.iter().enumerate() {
        let Some(&this) = node_of.get(&h.ip.to_string()) else {
            continue;
        };
        for n in 0.. {
            let Some(local) = h.identity.get(&format!("snmp.lldp.{n}.local_port")) else {
                break;
            };
            let field = |name: &str| {
                h.identity
                    .get(&format!("snmp.lldp.{n}.{name}"))
                    .cloned()
                    .unwrap_or_default()
            };
            let (sys, chassis, port) = (field("sys_name"), field("chassis_id"), field("port_id"));
            let local_port = Some(field("local_port_desc"))
                .filter(|d| !d.is_empty())
                .or_else(|| {
                    h.identity
                        .get(&format!("snmp.ifname.{local}"))
                        .filter(|n| !n.is_empty())
                        .cloned()
                })
                .or_else(|| {
                    h.identity
                        .get(&format!("snmp.if.{local}"))
                        .and_then(|v| v.split("; ").next())
                        .map(str::to_string)
                })
                .unwrap_or_else(|| format!("port {local}"));
            let matched = by_mac
                .get(&chassis.to_ascii_uppercase())
                .or_else(|| by_name.get(&sys.to_ascii_lowercase()))
                .copied()
                .filter(|other| *other != me && !(chassis.is_empty() && sys.is_empty()))
                .and_then(|other| node_of.get(&responding[other].ip.to_string()).copied());
            let other = match matched {
                Some(i) => i,
                None => {
                    let key = if chassis.is_empty() { &sys } else { &chassis };
                    if key.is_empty() {
                        continue;
                    }
                    let id = format!("lldp:{}", key.to_ascii_lowercase());
                    match node_of.get(&id) {
                        Some(&i) => i,
                        None => {
                            g.nodes.push(Node {
                                id: id.clone(),
                                label: if sys.is_empty() {
                                    chassis.clone()
                                } else {
                                    sys.clone()
                                },
                                detail: format!("LLDP neighbour {chassis}").trim().to_string(),
                                kind: Kind::Host,
                                depth: g.nodes[this].depth + 1,
                            });
                            node_of.insert(id, g.nodes.len() - 1);
                            g.nodes.len() - 1
                        }
                    }
                }
            };
            if other == this || g.links.len() >= MAX_LINKS {
                continue;
            }
            // one entry per pair of ends, whichever side reported it
            let (a, b, a_port, b_port) = if this < other {
                (this, other, local_port, port)
            } else {
                (other, this, port, local_port)
            };
            if seen.insert((a, b, a_port.clone(), b_port.clone())) {
                g.links.push(Link {
                    a,
                    b,
                    a_port,
                    b_port,
                    source: "lldp",
                });
                // The same link is an edge too, so anything that draws `edges` (the network
                // map, the layers of the HTML report) shows it; the ports stay in `links`.
                if !g.edges.contains(&(a, b)) && !g.edges.contains(&(b, a)) {
                    g.edges.push((a, b));
                }
            }
        }
    }
}

pub fn layers(g: &Graph) -> Vec<Vec<usize>> {
    let max = g.nodes.iter().map(|n| n.depth).max().unwrap_or(0);
    let mut layers = vec![vec![]; max + 1];
    for (i, n) in g.nodes.iter().enumerate() {
        layers[n.depth].push(i);
    }
    layers
}

fn children(g: &Graph) -> BTreeMap<usize, Vec<usize>> {
    let mut map: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for &(a, b) in &g.edges {
        map.entry(a).or_default().push(b);
    }
    for list in map.values_mut() {
        list.sort_by(|a, b| g.nodes[*a].id.cmp(&g.nodes[*b].id));
    }
    map
}

pub fn ascii(g: &Graph) -> String {
    let kids = children(g);
    let mut out = String::new();
    let mut seen = BTreeSet::new();
    #[allow(clippy::too_many_arguments)]
    fn walk(
        g: &Graph,
        kids: &BTreeMap<usize, Vec<usize>>,
        node: usize,
        prefix: &str,
        last: bool,
        root: bool,
        seen: &mut BTreeSet<usize>,
        out: &mut String,
    ) {
        let n = &g.nodes[node];
        let again = !seen.insert(node);
        let tag = match n.kind {
            Kind::Host => "",
            Kind::Router => "[router] ",
            Kind::Unknown => "",
            Kind::Source => "",
        };
        let detail = if n.detail.is_empty() {
            String::new()
        } else {
            format!("  [{}]", n.detail)
        };
        if root {
            out.push_str(&format!("{}\n", n.label));
        } else {
            out.push_str(&format!(
                "{prefix}{}{tag}{}{detail}{}\n",
                if last { "`-- " } else { "|-- " },
                n.label,
                if again { "  (shown above)" } else { "" }
            ));
        }
        if again {
            return;
        }
        let next = if root {
            String::new()
        } else {
            format!("{prefix}{}", if last { "   " } else { "|   " })
        };
        if let Some(list) = kids.get(&node) {
            for (i, c) in list.iter().enumerate() {
                walk(g, kids, *c, &next, i + 1 == list.len(), false, seen, out);
            }
        }
    }
    walk(g, &kids, 0, "", true, true, &mut seen, &mut out);
    if !g.links.is_empty() {
        out.push_str("\nLinks (LLDP, as reported by the devices):\n");
        for l in &g.links {
            let end = |node: usize, port: &str| {
                if port.is_empty() {
                    g.nodes[node].label.clone()
                } else {
                    format!("{} [{port}]", g.nodes[node].label)
                }
            };
            out.push_str(&format!(
                "  {} <-> {}\n",
                end(l.a, &l.a_port),
                end(l.b, &l.b_port)
            ));
        }
    }
    out
}

pub fn dot(g: &Graph) -> String {
    let esc = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
    let mut out = String::from(
        "digraph topology {\n  rankdir=LR;\n  node [fontname=\"Segoe UI\", fontsize=10];\n",
    );
    for (i, n) in g.nodes.iter().enumerate() {
        let (shape, color) = match n.kind {
            Kind::Source => ("doublecircle", "#2b6cb0"),
            Kind::Router => ("box", "#718096"),
            Kind::Host => ("ellipse", "#2f855a"),
            Kind::Unknown => ("plaintext", "#a0aec0"),
        };
        let label = if n.detail.is_empty() {
            esc(&n.label)
        } else {
            format!("{}\\n{}", esc(&n.label), esc(&n.detail))
        };
        out.push_str(&format!(
            "  n{i} [label=\"{label}\", shape={shape}, color=\"{color}\"];\n"
        ));
    }
    // an edge that is an LLDP link is drawn once, as the dashed link below
    let is_link = |a: usize, b: usize| {
        g.links
            .iter()
            .any(|l| (l.a, l.b) == (a, b) || (l.a, l.b) == (b, a))
    };
    for (a, b) in g.edges.iter().filter(|(a, b)| !is_link(*a, *b)) {
        out.push_str(&format!("  n{a} -> n{b};\n"));
    }
    for l in &g.links {
        let ports = if l.a_port.is_empty() && l.b_port.is_empty() {
            String::new()
        } else {
            format!(
                ", taillabel=\"{}\", headlabel=\"{}\"",
                esc(&l.a_port),
                esc(&l.b_port)
            )
        };
        out.push_str(&format!(
            "  n{} -> n{} [dir=none, style=dashed, color=\"#975a16\"{ports}];\n",
            l.a, l.b
        ));
    }
    out.push_str("}\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::Hop;

    fn host(ip: &str, open: &[u16], trace: &[(u8, Option<&str>)]) -> Host {
        Host {
            ip: ip.parse().unwrap(),
            responding: true,
            ping: None,
            ttl: None,
            hostname: String::new(),
            mac: String::new(),
            open: open.to_vec(),
            closed: 0,
            unanswered: 0,
            errors: vec![],
            ports_checked: true,
            identity: Default::default(),
            udp_open: vec![],
            trace: trace
                .iter()
                .map(|(ttl, ip)| Hop {
                    ttl: *ttl,
                    ip: ip.map(|s| s.parse().unwrap()),
                    rtt: Some(2),
                })
                .collect(),
        }
    }

    fn sample() -> Vec<Host> {
        vec![
            host(
                "10.0.1.5",
                &[22],
                &[
                    (1, Some("10.0.0.1")),
                    (2, Some("10.0.1.1")),
                    (3, Some("10.0.1.5")),
                ],
            ),
            host(
                "10.0.1.6",
                &[80, 443],
                &[
                    (1, Some("10.0.0.1")),
                    (2, Some("10.0.1.1")),
                    (3, Some("10.0.1.6")),
                ],
            ),
            host(
                "10.0.2.9",
                &[],
                &[(1, Some("10.0.0.1")), (2, None), (3, Some("10.0.2.1"))],
            ),
            host("10.0.0.77", &[], &[]),
        ]
    }

    #[test]
    fn shared_hops_are_merged() {
        let g = build(&sample());
        let ids: Vec<_> = g.nodes.iter().map(|n| n.id.as_str()).collect();
        assert_eq!(ids.iter().filter(|i| **i == "10.0.0.1").count(), 1);
        assert_eq!(ids.iter().filter(|i| **i == "10.0.1.1").count(), 1);
        assert!(ids.contains(&"10.0.1.5") && ids.contains(&"10.0.1.6"));
        let hosts = g.nodes.iter().filter(|n| n.kind == Kind::Host).count();
        assert_eq!(hosts, 4);
        assert!(g.nodes.iter().any(|n| n.kind == Kind::Unknown));
        let depth = |id: &str| g.nodes.iter().find(|n| n.id == id).unwrap().depth;
        assert_eq!(
            (
                depth("10.0.0.1"),
                depth("10.0.1.1"),
                depth("10.0.1.5"),
                depth("10.0.0.77")
            ),
            (1, 2, 3, 1)
        );
        assert_eq!(layers(&g).len(), 5);
    }

    #[test]
    fn ascii_tree_and_dot() {
        let g = build(&sample());
        let text = ascii(&g);
        assert!(text.starts_with("This scanner\n"), "{text}");
        assert!(
            text.contains("`-- [router] 10.0.1.1") || text.contains("|-- [router] 10.0.1.1"),
            "{text}"
        );
        assert!(text.contains("10.0.1.5  [ports 22]"), "{text}");
        assert!(text.contains("* (no reply)"));
        assert_eq!(
            text.matches("10.0.0.1").count(),
            1,
            "shared router listed once:\n{text}"
        );
        let d = dot(&g);
        assert!(d.starts_with("digraph topology {") && d.trim_end().ends_with('}'));
        assert_eq!(d.matches("->").count(), g.edges.len());
    }

    #[test]
    fn a_router_that_is_also_a_host_becomes_a_host() {
        let hosts = vec![
            host("10.0.0.1", &[80], &[(1, Some("10.0.0.1"))]),
            host(
                "10.0.1.5",
                &[22],
                &[(1, Some("10.0.0.1")), (2, Some("10.0.1.5"))],
            ),
        ];
        let g = build(&hosts);
        let gw = g.nodes.iter().find(|n| n.id == "10.0.0.1").unwrap();
        assert_eq!(gw.kind, Kind::Host);
        assert_eq!(g.nodes.len(), 3);
        assert!(!ascii(&g).is_empty());
    }

    fn with_identity(mut h: Host, mac: &str, pairs: &[(&str, &str)]) -> Host {
        h.mac = mac.into();
        for (k, v) in pairs {
            h.identity.insert((*k).into(), (*v).into());
        }
        h
    }

    /// Without `lldpLocPortDesc` the port is named by `ifName`, then `ifDescr`.
    #[test]
    fn the_local_port_is_named_from_ifname_before_ifdescr() {
        let make = |with_name: bool| {
            let mut pairs = vec![
                ("snmp.sysname", "core-sw1"),
                ("snmp.if.1", "GigabitEthernet1/0/1; 00:1B:21:0A:0B:01; up"),
                ("snmp.lldp.0.local_port", "1"),
                ("snmp.lldp.0.sys_name", "dist-sw2"),
                ("snmp.lldp.0.chassis_id", "00:1B:21:77:00:01"),
            ];
            if with_name {
                pairs.push(("snmp.ifname.1", "Gi1/0/1"));
            }
            with_identity(host("10.0.0.2", &[], &[]), "00:1B:21:0A:0B:FF", &pairs)
        };
        assert_eq!(build(&[make(true)]).links[0].a_port, "Gi1/0/1");
        assert_eq!(
            build(&[make(false)]).links[0].a_port,
            "GigabitEthernet1/0/1"
        );
    }

    #[test]
    fn lldp_neighbours_become_links_between_scanned_hosts_and_new_nodes() {
        // core-sw1 (10.0.0.2) sees dist-sw2 (scanned, matched by chassis MAC) on port 1 and an
        // unscanned AP (a node of its own) on port 2; dist-sw2 reports core-sw1 back.
        let core = with_identity(
            host("10.0.0.2", &[], &[]),
            "00:1B:21:0A:0B:FF",
            &[
                ("snmp.sysname", "core-sw1"),
                ("snmp.if.1", "Gi1/0/1; 00:1B:21:0A:0B:01; up"),
                ("snmp.if.2", "Gi1/0/2; 00:1B:21:0A:0B:02; up"),
                ("snmp.lldp.0.local_port", "1"),
                ("snmp.lldp.0.sys_name", "dist-sw2"),
                ("snmp.lldp.0.port_id", "Gi0/24"),
                ("snmp.lldp.0.chassis_id", "00:1B:21:77:00:01"),
                ("snmp.lldp.1.local_port", "2"),
                ("snmp.lldp.1.sys_name", "lab-ap"),
                ("snmp.lldp.1.port_id", "eth0"),
                ("snmp.lldp.1.chassis_id", "52:54:00:12:34:56"),
            ],
        );
        let dist = with_identity(
            host("10.0.0.3", &[], &[]),
            "00:1B:21:77:00:FF",
            &[
                ("snmp.sysname", "dist-sw2"),
                ("snmp.if.24", "Gi0/24; 00:1B:21:77:00:01; up"),
                ("snmp.lldp.0.local_port", "24"),
                ("snmp.lldp.0.sys_name", "core-sw1"),
                ("snmp.lldp.0.port_id", "Gi1/0/1"),
                ("snmp.lldp.0.chassis_id", "00:1B:21:0A:0B:01"),
            ],
        );
        let g = build(&[core, dist]);
        // the pair is reported by both ends and kept once; the AP is the second link
        assert_eq!(g.links.len(), 2, "{:?}", g.links);
        // every link is also an edge (once), for whatever draws the edges
        for l in &g.links {
            let n = g
                .edges
                .iter()
                .filter(|e| **e == (l.a, l.b) || **e == (l.b, l.a))
                .count();
            assert_eq!(n, 1, "{l:?} in {:?}", g.edges);
        }
        let label = |i: usize| g.nodes[i].label.as_str();
        let wired: Vec<(String, String, String, String)> = g
            .links
            .iter()
            .map(|l| {
                (
                    label(l.a).to_string(),
                    l.a_port.clone(),
                    label(l.b).to_string(),
                    l.b_port.clone(),
                )
            })
            .collect();
        assert!(
            wired.iter().any(|w| w
                == &(
                    "10.0.0.2".to_string(),
                    "Gi1/0/1".to_string(),
                    "10.0.0.3".to_string(),
                    "Gi0/24".to_string()
                )),
            "{wired:?}"
        );
        let ap = g
            .nodes
            .iter()
            .find(|n| n.id == "lldp:52:54:00:12:34:56")
            .unwrap();
        assert_eq!(ap.label, "lab-ap");
        assert!(g.links.iter().all(|l| l.source == "lldp"));
        let text = ascii(&g);
        assert!(text.contains("Links (LLDP"), "{text}");
        assert!(
            text.contains("[Gi1/0/1]") && text.contains("lab-ap [eth0]"),
            "{text}"
        );
        let d = dot(&g);
        assert_eq!(
            d.matches("->").count(),
            g.edges.len(),
            "a link is drawn once, dashed"
        );
        assert!(
            d.contains("dir=none") && d.contains("taillabel=\"Gi1/0/1\""),
            "{d}"
        );
        // no LLDP data, no links
        assert!(build(&sample()).links.is_empty());
        // a neighbour with neither name nor chassis id is skipped
        let odd = with_identity(
            host("10.0.0.9", &[], &[]),
            "",
            &[("snmp.lldp.0.local_port", "1")],
        );
        assert!(build(&[odd]).links.is_empty());
    }

    #[test]
    fn empty_input() {
        let g = build(&[]);
        assert_eq!(g.nodes.len(), 1);
        assert_eq!(ascii(&g), "This scanner\n");
    }
}
