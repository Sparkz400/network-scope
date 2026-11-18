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
    g
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
    for (a, b) in &g.edges {
        out.push_str(&format!("  n{a} -> n{b};\n"));
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

    #[test]
    fn empty_input() {
        let g = build(&[]);
        assert_eq!(g.nodes.len(), 1);
        assert_eq!(ascii(&g), "This scanner\n");
    }
}
