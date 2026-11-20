//! Layout of the network map (ROADMAP F37): positions for the nodes of a [`topology::Graph`],
//! computed in plain Rust with no drawing code, so the desktop map and any other front end can
//! use it.
//!
//! The nodes start on rings around the scanner, one ring per hop count (the layered view of the
//! path map), wide enough that neighbours do not overlap. A Fruchterman-Reingold force pass then
//! relaxes the picture: every pair of nodes repels, every link pulls its two ends together, and the
//! scanner stays at the origin. Whatever kind of link or node the topology builders add later is
//! laid out the same way, because only the node list and the edge list are read.
//!
//! The result is deterministic (no random numbers), and bounded in time: the number of passes
//! shrinks as the graph grows, and a graph of more than [`FORCE_LIMIT`] nodes keeps its ring
//! layout.
use crate::topology::Graph;

/// Graphs with more nodes than this keep the ring layout (the pairwise repulsion would be slow).
pub const FORCE_LIMIT: usize = 800;
/// The distance a link tries to keep between its ends.
pub const LINK_LENGTH: f32 = 80.0;
/// The smallest gap between neighbours on a ring.
const RING_SPACING: f32 = 46.0;
/// The distance between the rings.
const RING_STEP: f32 = 110.0;

/// Positions of the nodes of `g`, in the same order, in map units. Node 0 (the scanner, when the
/// graph was built by `topology::build`) is at `[0, 0]`.
pub fn layout(g: &Graph) -> Vec<[f32; 2]> {
    let n = g.nodes.len();
    match n {
        0 => return vec![],
        1 => return vec![[0.0, 0.0]],
        _ => {}
    }
    let mut pos = rings(g);
    if n <= FORCE_LIMIT {
        relax(g, &mut pos);
    }
    pos
}

/// The starting layout: a radial tree. The scanner is the root; every other node hangs below the
/// node it was first reached from (breadth first over the links), on a ring for its distance from
/// the root, inside the wedge of angles that its parent gives it, in proportion to the number of
/// leaves below it. So the hosts of one router sit together around that router instead of
/// spreading over one big ring. A ring is made wider when its nodes would not fit; nodes that are
/// not linked to the scanner at all go on an outer ring.
fn rings(g: &Graph) -> Vec<[f32; 2]> {
    let n = g.nodes.len();
    let mut adjacent: Vec<Vec<usize>> = vec![vec![]; n];
    for &(a, b) in &g.edges {
        if a < n && b < n && a != b {
            adjacent[a].push(b);
            adjacent[b].push(a);
        }
    }
    for list in &mut adjacent {
        list.sort_unstable();
        list.dedup();
    }
    // Breadth first from the root: parent, distance and visiting order.
    let mut parent = vec![usize::MAX; n];
    let mut distance = vec![usize::MAX; n];
    let mut order = vec![0usize];
    distance[0] = 0;
    let mut head = 0;
    while head < order.len() {
        let node = order[head];
        head += 1;
        for &next in &adjacent[node] {
            if distance[next] == usize::MAX {
                distance[next] = distance[node] + 1;
                parent[next] = node;
                order.push(next);
            }
        }
    }
    // Leaves below each node (a node without children counts as one), children before parents.
    let mut below = vec![0usize; n];
    for &node in order.iter().rev() {
        if below[node] == 0 {
            below[node] = 1;
        }
        if parent[node] != usize::MAX {
            below[parent[node]] += below[node];
        }
    }
    // Ring radii: one step per distance, wider where the nodes of a distance would not fit.
    let deepest = order.iter().map(|&i| distance[i]).max().unwrap_or(0);
    let mut per_ring = vec![0usize; deepest + 1];
    for &node in &order {
        per_ring[distance[node]] += 1;
    }
    let mut radius = vec![0.0f32; deepest + 1];
    for d in 1..=deepest {
        let wanted = per_ring[d] as f32 * RING_SPACING / std::f32::consts::TAU;
        radius[d] = (radius[d - 1] + RING_STEP).max(wanted);
    }
    // Wedges: the root owns the whole circle and divides it among its children by weight.
    let mut wedge = vec![(0.0f32, std::f32::consts::TAU); n];
    let mut pos = vec![[0.0f32; 2]; n];
    for &node in &order {
        let (from, to) = wedge[node];
        let angle = (from + to) / 2.0;
        let r = radius[distance[node]];
        pos[node] = [r * angle.cos(), r * angle.sin()];
        let total: f32 = adjacent[node]
            .iter()
            .filter(|&&c| parent[c] == node)
            .map(|&c| below[c] as f32)
            .sum();
        let mut start = from;
        for &child in adjacent[node].iter().filter(|&&c| parent[c] == node) {
            let share = (to - from) * below[child] as f32 / total.max(1.0);
            wedge[child] = (start, start + share);
            start += share;
        }
    }
    // Nodes that cannot be reached from the scanner: an outer ring.
    let lost: Vec<usize> = (0..n).filter(|&i| distance[i] == usize::MAX).collect();
    if !lost.is_empty() {
        let outer = (radius[deepest] + RING_STEP)
            .max(lost.len() as f32 * RING_SPACING / std::f32::consts::TAU);
        for (k, &node) in lost.iter().enumerate() {
            let angle = std::f32::consts::TAU * k as f32 / lost.len() as f32;
            pos[node] = [outer * angle.cos(), outer * angle.sin()];
        }
    }
    pos
}

/// Passes of the force layout for a graph of `n` nodes.
fn passes(n: usize) -> usize {
    match n {
        0..=150 => 160,
        151..=400 => 70,
        _ => 25,
    }
}

fn relax(g: &Graph, pos: &mut [[f32; 2]]) {
    let n = pos.len();
    let k = LINK_LENGTH;
    let iterations = passes(n);
    let start_temperature = RING_STEP * 0.3;
    let mut disp = vec![[0.0f32; 2]; n];
    for step in 0..iterations {
        let temperature = start_temperature * (1.0 - step as f32 / iterations as f32).max(0.02);
        disp.iter_mut().for_each(|d| *d = [0.0, 0.0]);
        for i in 0..n {
            for j in (i + 1)..n {
                let mut dx = pos[i][0] - pos[j][0];
                let mut dy = pos[i][1] - pos[j][1];
                let mut d2 = dx * dx + dy * dy;
                if d2 < 0.01 {
                    // Two nodes on the same spot: push them apart in a fixed direction.
                    dx = 0.1 * (1.0 + (i + j) as f32 % 7.0);
                    dy = 0.1;
                    d2 = dx * dx + dy * dy;
                }
                let force = k * k / d2;
                disp[i][0] += dx * force;
                disp[i][1] += dy * force;
                disp[j][0] -= dx * force;
                disp[j][1] -= dy * force;
            }
        }
        for &(a, b) in &g.edges {
            if a >= n || b >= n || a == b {
                continue;
            }
            let dx = pos[a][0] - pos[b][0];
            let dy = pos[a][1] - pos[b][1];
            let d = (dx * dx + dy * dy).sqrt().max(0.01);
            let force = d / k;
            disp[a][0] -= dx * force;
            disp[a][1] -= dy * force;
            disp[b][0] += dx * force;
            disp[b][1] += dy * force;
        }
        for (i, d) in disp.iter().enumerate() {
            if i == 0 {
                continue; // the scanner stays at the origin
            }
            let len = (d[0] * d[0] + d[1] * d[1]).sqrt();
            if len > 0.0 {
                let scale = len.min(temperature) / len;
                pos[i][0] += d[0] * scale;
                pos[i][1] += d[1] * scale;
            }
        }
    }
}

/// The smallest rectangle `[min_x, min_y, max_x, max_y]` around the positions, grown by
/// `margin`. An empty list gives a unit square around the origin.
pub fn bounds(positions: &[[f32; 2]], margin: f32) -> [f32; 4] {
    let mut b = [f32::MAX, f32::MAX, f32::MIN, f32::MIN];
    for p in positions {
        b = [
            b[0].min(p[0]),
            b[1].min(p[1]),
            b[2].max(p[0]),
            b[3].max(p[1]),
        ];
    }
    if positions.is_empty() {
        return [-1.0 - margin, -1.0 - margin, 1.0 + margin, 1.0 + margin];
    }
    [b[0] - margin, b[1] - margin, b[2] + margin, b[3] + margin]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{scan::Host, topology};

    fn host(ip: String, trace: &[(u8, Option<String>)]) -> Host {
        Host {
            ip: ip.parse().unwrap(),
            responding: true,
            ping: None,
            ttl: None,
            hostname: String::new(),
            mac: String::new(),
            open: vec![],
            closed: 0,
            unanswered: 0,
            errors: vec![],
            ports_checked: true,
            identity: Default::default(),
            udp_open: vec![],
            trace: trace
                .iter()
                .map(|(ttl, ip)| crate::trace::Hop {
                    ttl: *ttl,
                    ip: ip.as_ref().map(|s| s.parse().unwrap()),
                    rtt: Some(1),
                })
                .collect(),
        }
    }

    /// `n` hosts behind `routers` routers (a three-level tree), plus the scanner.
    fn tree(n: usize, routers: usize) -> Graph {
        let hosts: Vec<Host> = (0..n)
            .map(|i| {
                let ip = format!("10.{}.{}.{}", 1 + i / 65_025, (i / 255) % 255, 1 + i % 254);
                let router = format!("10.0.{}.1", i % routers.max(1));
                host(
                    ip.clone(),
                    &[
                        (1, Some("10.0.0.1".into())),
                        (2, Some(router)),
                        (3, Some(ip)),
                    ],
                )
            })
            .collect();
        topology::build(&hosts)
    }

    fn assert_sane(g: &Graph, pos: &[[f32; 2]]) {
        assert_eq!(pos.len(), g.nodes.len());
        assert!(pos.iter().flatten().all(|v| v.is_finite()));
    }

    #[test]
    fn zero_one_and_two_nodes() {
        let none = Graph::default();
        assert!(layout(&none).is_empty());
        let b = bounds(&[], 10.0);
        assert!(b[0] < b[2] && b[1] < b[3], "an empty map still has a size");
        let one = topology::build(&[]);
        assert_eq!(layout(&one), [[0.0, 0.0]]);
        let two = topology::build(&[host("10.0.0.5".into(), &[])]);
        let pos = layout(&two);
        assert_eq!(pos.len(), 2);
        assert_eq!(pos[0], [0.0, 0.0]);
        let d = (pos[1][0].powi(2) + pos[1][1].powi(2)).sqrt();
        assert!(
            d > 10.0 && d < 400.0,
            "linked nodes end up at a sensible distance: {d}"
        );
    }

    #[test]
    fn the_layout_is_deterministic_and_keeps_the_scanner_at_the_origin() {
        let g = tree(40, 4);
        let a = layout(&g);
        assert_eq!(a, layout(&g));
        assert_eq!(a[0], [0.0, 0.0]);
        assert_sane(&g, &a);
    }

    #[test]
    fn three_hundred_nodes_do_not_pile_up() {
        let g = tree(300, 6);
        assert!(g.nodes.len() > 300);
        let pos = layout(&g);
        assert_sane(&g, &pos);
        // No two nodes on (almost) the same spot, so every one stays clickable.
        let mut closest = f32::MAX;
        for i in 0..pos.len() {
            for j in (i + 1)..pos.len() {
                let d = ((pos[i][0] - pos[j][0]).powi(2) + (pos[i][1] - pos[j][1]).powi(2)).sqrt();
                closest = closest.min(d);
            }
        }
        assert!(closest > 3.0, "closest pair {closest}");
        let b = bounds(&pos, 20.0);
        assert!(b[2] - b[0] > 100.0 && b[3] - b[1] > 100.0);
    }

    #[test]
    fn a_very_large_graph_keeps_the_fast_ring_layout() {
        let g = tree(FORCE_LIMIT + 100, 20);
        let pos = layout(&g);
        assert_sane(&g, &pos);
        assert_eq!(pos, rings(&g), "no force pass above the limit");
    }

    #[test]
    fn hosts_are_placed_around_their_own_router_before_and_after_the_force_pass() {
        let g = tree(80, 4);
        let router = |i: usize| {
            g.edges
                .iter()
                .find(|&&(_, b)| b == i)
                .map(|&(a, _)| a)
                .unwrap()
        };
        for pos in [rings(&g), layout(&g)] {
            let dist = |a: usize, b: usize| {
                ((pos[a][0] - pos[b][0]).powi(2) + (pos[a][1] - pos[b][1]).powi(2)).sqrt()
            };
            let hosts: Vec<usize> = (0..g.nodes.len())
                .filter(|&i| {
                    g.nodes[i].kind == crate::topology::Kind::Host && g.nodes[i].depth == 3
                })
                .collect();
            assert!(hosts.len() >= 60);
            let routers: Vec<usize> = {
                let mut r: Vec<usize> = hosts.iter().map(|&h| router(h)).collect();
                r.sort_unstable();
                r.dedup();
                r
            };
            assert!(routers.len() >= 2);
            let (mut own, mut other, mut n_other) = (0.0, 0.0, 0.0);
            for &h in &hosts {
                own += dist(h, router(h));
                for &r in routers.iter().filter(|&&r| r != router(h)) {
                    other += dist(h, r);
                    n_other += 1.0;
                }
            }
            let (own, other) = (own / hosts.len() as f32, other / n_other);
            assert!(own * 1.5 < other, "own {own} vs other {other}");
        }
    }

    #[test]
    fn nodes_without_a_link_to_the_scanner_still_get_a_place() {
        let mut g = tree(10, 2);
        let lost = g.nodes[1].clone();
        g.nodes.push(crate::topology::Node {
            id: "10.9.9.9".into(),
            label: "lost".into(),
            ..lost
        });
        let pos = layout(&g);
        assert_eq!(pos.len(), g.nodes.len());
        assert!(pos.iter().flatten().all(|v| v.is_finite()));
    }

    #[test]
    fn links_to_missing_nodes_are_ignored() {
        let mut g = tree(5, 1);
        g.edges.push((0, 9_999));
        g.edges.push((3, 3));
        assert_sane(&g, &layout(&g));
    }

    #[test]
    fn linked_nodes_end_up_closer_than_unlinked_ones_on_average() {
        let g = tree(60, 3);
        let pos = layout(&g);
        let dist = |a: usize, b: usize| {
            ((pos[a][0] - pos[b][0]).powi(2) + (pos[a][1] - pos[b][1]).powi(2)).sqrt()
        };
        let linked: f32 =
            g.edges.iter().map(|&(a, b)| dist(a, b)).sum::<f32>() / g.edges.len() as f32;
        let mut all = 0.0;
        let mut pairs = 0;
        for a in 0..pos.len() {
            for b in (a + 1)..pos.len() {
                all += dist(a, b);
                pairs += 1;
            }
        }
        assert!(
            linked < all / pairs as f32,
            "linked {linked} vs all {}",
            all / pairs as f32
        );
    }
}
