//! The order in which one host's TCP ports are probed (ROADMAP B13), and the optional early stop.
//!
//! The scan only ever **reorders the ports the user asked for**; this module never adds a port, so
//! the set of probes (and what the dry run lists) is the same in every order, and so are the
//! results: a host's result is sorted by port at the end.
//!
//! # Order
//!
//! - By default the likeliest ports go first: the order of [`crate::scan::TOP_PORTS`] (most
//!   frequently open first), then the remaining ports by number.
//! - A *device class* (`data/port_classes.json`: printer, controller, Windows, Unix, camera,
//!   network device) moves its own priority ports to the front once there is evidence for it:
//!   the MAC vendor (OUI), the initial TTL, and the ports found open so far. The evidence is
//!   collected while the scan runs, so the order adapts to what the host turns out to be.
//!
//! # Early stop
//!
//! With `--early-stop` ([`crate::scan::Settings::early_stop`]) the host's remaining ports are
//! skipped once [`HostOrder::identified`] says the class is certain (two of its signature ports
//! open, or one plus a vendor match), the device classifier agrees, and every priority port of the
//! class that was asked for has been probed. That trades completeness for speed, so such a host
//! is marked `ports_checked = false` with a note: the unprobed ports are unknown, not closed.
use serde::Deserialize;
use std::{
    collections::{BTreeSet, VecDeque},
    sync::OnceLock,
};

/// One device class of `data/port_classes.json`.
#[derive(Clone, Debug, Deserialize)]
pub struct Class {
    pub id: String,
    pub label: String,
    /// Tried first, in this order.
    pub ports: Vec<u16>,
    /// Ports that identify the class.
    pub signature: Vec<u16>,
    /// Lower-case fragments of the MAC vendor name.
    #[serde(default)]
    pub vendors: Vec<String>,
    /// Initial TTLs that weakly suggest the class.
    #[serde(default)]
    pub ttl: Vec<u8>,
}

#[derive(Deserialize)]
struct File {
    classes: Vec<Class>,
}

/// The classes, in priority order (ties go to the earlier class).
#[derive(Clone, Debug)]
pub struct ClassTable {
    classes: Vec<Class>,
}

static BUILTIN: OnceLock<ClassTable> = OnceLock::new();

impl ClassTable {
    pub fn parse(json: &str) -> Result<Self, String> {
        let file: File = serde_json::from_str(json).map_err(|e| format!("port classes: {e}"))?;
        for c in &file.classes {
            if c.ports.is_empty() || c.signature.is_empty() {
                return Err(format!("port classes: {} needs ports and signature", c.id));
            }
        }
        Ok(Self {
            classes: file.classes,
        })
    }
    /// The table embedded from `data/port_classes.json`.
    pub fn builtin() -> &'static ClassTable {
        BUILTIN.get_or_init(|| {
            Self::parse(include_str!("../../data/port_classes.json"))
                .expect("data/port_classes.json is valid (a test checks it)")
        })
    }
    pub fn classes(&self) -> &[Class] {
        &self.classes
    }
}

/// Position of a port in the frequency order; ports that are not listed come after all listed ones.
pub fn frequency_rank(port: u16) -> usize {
    crate::scan::TOP_PORTS
        .iter()
        .position(|&p| p == port)
        .unwrap_or(crate::scan::TOP_PORTS.len())
}

/// What is known about the host before its first port is probed.
#[derive(Clone, Copy, Debug, Default)]
pub struct Hints<'a> {
    /// The MAC vendor from the OUI registry (empty when unknown).
    pub vendor: &'a str,
    pub ttl: Option<u8>,
}

/// The probe order of one host, adapting to the ports found open.
#[derive(Debug)]
pub struct HostOrder<'a> {
    table: &'a ClassTable,
    pending: VecDeque<u16>,
    requested: BTreeSet<u16>,
    open: BTreeSet<u16>,
    done: BTreeSet<u16>,
    /// Per class: evidence points from the vendor and TTL.
    prior: Vec<u32>,
    vendor_hit: Vec<bool>,
    active: Option<usize>,
}

impl<'a> HostOrder<'a> {
    pub fn new(table: &'a ClassTable, ports: &[u16], hints: Hints) -> Self {
        let vendor = hints.vendor.to_ascii_lowercase();
        let vendor_hit: Vec<bool> = table
            .classes
            .iter()
            .map(|c| !vendor.is_empty() && c.vendors.iter().any(|v| vendor.contains(v.as_str())))
            .collect();
        let prior = table
            .classes
            .iter()
            .zip(&vendor_hit)
            .map(|(c, hit)| {
                2 * u32::from(*hit) + u32::from(hints.ttl.is_some_and(|t| c.ttl.contains(&t)))
            })
            .collect();
        let mut order = Self {
            table,
            pending: VecDeque::new(),
            requested: ports.iter().copied().collect(),
            open: BTreeSet::new(),
            done: BTreeSet::new(),
            prior,
            vendor_hit,
            active: None,
        };
        let mut sorted: Vec<u16> = order.requested.iter().copied().collect();
        order.active = order.pick_class();
        order.sort(&mut sorted);
        order.pending = sorted.into();
        order
    }

    fn votes(&self, class: usize) -> u32 {
        let c = &self.table.classes[class];
        self.prior[class]
            + self
                .open
                .iter()
                .map(|p| {
                    if c.signature.contains(p) {
                        2
                    } else {
                        u32::from(c.ports.contains(p))
                    }
                })
                .sum::<u32>()
    }
    /// The class with the most evidence, at least two points (a lone TTL or a lone shared port
    /// such as 80 is not enough).
    fn pick_class(&self) -> Option<usize> {
        (0..self.table.classes.len())
            .map(|i| (self.votes(i), std::cmp::Reverse(i)))
            .max()
            .filter(|(v, _)| *v >= 2)
            .map(|(_, std::cmp::Reverse(i))| i)
    }
    fn key(&self, port: u16) -> (usize, usize, u16) {
        let class_rank = self
            .active
            .and_then(|a| self.table.classes[a].ports.iter().position(|&p| p == port))
            .unwrap_or(usize::MAX);
        (class_rank, frequency_rank(port), port)
    }
    fn sort(&self, ports: &mut [u16]) {
        ports.sort_by_key(|&p| self.key(p));
    }

    /// The next port to probe, or `None` when every port was handed out.
    pub fn next_port(&mut self) -> Option<u16> {
        self.pending.pop_front()
    }
    /// Ports not handed out yet.
    pub fn remaining(&self) -> usize {
        self.pending.len()
    }
    /// A probe finished: `open` is whether the port accepted the connection.
    pub fn observe(&mut self, port: u16, open: bool) {
        self.done.insert(port);
        if !open {
            return;
        }
        self.open.insert(port);
        let active = self.pick_class();
        if active != self.active {
            self.active = active;
            let mut rest: Vec<u16> = self.pending.drain(..).collect();
            self.sort(&mut rest);
            self.pending = rest.into();
        }
    }
    /// The class the order currently favours.
    pub fn class(&self) -> Option<&Class> {
        self.active.map(|i| &self.table.classes[i])
    }
    /// The class the host is certain enough to be for an early stop: two signature ports open (or
    /// one plus a vendor match), and every priority port of the class that was requested has
    /// finished. The caller still asks the device classifier before it stops.
    pub fn identified(&self) -> Option<&Class> {
        let i = self.active?;
        let c = &self.table.classes[i];
        let signature = self.open.iter().filter(|p| c.signature.contains(p)).count();
        let certain = signature >= 2 || (signature >= 1 && self.vendor_hit[i]);
        let priority_done = c
            .ports
            .iter()
            .filter(|p| self.requested.contains(p))
            .all(|p| self.done.contains(p));
        (certain && priority_done).then_some(c)
    }
    /// The ports found open so far.
    pub fn open(&self) -> Vec<u16> {
        self.open.iter().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drain(order: &mut HostOrder) -> Vec<u16> {
        std::iter::from_fn(|| order.next_port()).collect()
    }
    fn table() -> &'static ClassTable {
        ClassTable::builtin()
    }

    #[test]
    fn the_embedded_table_is_valid_and_signatures_are_priority_ports() {
        assert!(table().classes().len() >= 6);
        for c in table().classes() {
            for s in &c.signature {
                assert!(c.ports.contains(s), "{}: signature {s} not in ports", c.id);
            }
            let unique: BTreeSet<_> = c.ports.iter().collect();
            assert_eq!(unique.len(), c.ports.len(), "{}: duplicate port", c.id);
        }
    }

    #[test]
    fn the_default_order_is_by_frequency_and_never_changes_the_set() {
        let requested = [8080, 22, 445, 9100, 1, 443, 80, 65000, 4444];
        let mut order = HostOrder::new(table(), &requested, Hints::default());
        let got = drain(&mut order);
        assert_eq!(got, [80, 443, 22, 445, 8080, 9100, 1, 4444, 65000]);
        let mut a = got.clone();
        a.sort_unstable();
        let mut b = requested.to_vec();
        b.sort_unstable();
        assert_eq!(a, b, "same ports, different order");
    }

    #[test]
    fn ports_are_not_added_for_a_class() {
        // A printer vendor makes 9100/631/515 first, but only if they were requested.
        let hints = Hints {
            vendor: "Hewlett Packard",
            ttl: None,
        };
        let mut order = HostOrder::new(table(), &[22, 80], hints);
        assert_eq!(order.class().unwrap().id, "printer");
        assert_eq!(drain(&mut order), [80, 22]);
        let mut order = HostOrder::new(table(), &[22, 80, 515, 9100, 631], hints);
        assert_eq!(drain(&mut order), [9100, 631, 515, 80, 22]);
    }

    #[test]
    fn open_ports_reorder_what_is_still_pending() {
        // Nothing known at first: frequency order. Then 3389 answers: Windows ports first.
        let requested = [21, 22, 23, 25, 80, 135, 443, 445, 3389, 5985];
        let mut order = HostOrder::new(table(), &requested, Hints::default());
        for expected in [80, 23, 443, 21, 22, 25, 3389] {
            assert_eq!(order.next_port(), Some(expected));
        }
        order.observe(3389, true);
        assert_eq!(order.class().unwrap().id, "windows");
        // Windows priority list: 445, 135, 3389, 139, 5985, 80, 443.
        assert_eq!(drain(&mut order), [445, 135, 5985]);
    }

    #[test]
    fn ttl_alone_is_not_enough_but_adds_to_other_evidence() {
        let hints = Hints {
            vendor: "",
            ttl: Some(128),
        };
        let order = HostOrder::new(table(), &[22, 80, 445], hints);
        assert!(order.class().is_none(), "one point is no class");
        let mut order = HostOrder::new(table(), &[22, 80, 445], hints);
        order.observe(80, true); // shared by several classes, one point each
        assert_eq!(
            order.class().unwrap().id,
            "windows",
            "TTL 128 breaks the tie"
        );
    }

    #[test]
    fn early_stop_needs_two_signature_ports_or_one_plus_the_vendor_and_the_priority_ports() {
        let ports = [9100, 631, 515, 80, 22, 8081];
        let mut order = HostOrder::new(table(), &ports, Hints::default());
        order.observe(9100, true);
        assert!(
            order.identified().is_none(),
            "one signature port, no vendor"
        );
        order.observe(515, true);
        assert!(order.identified().is_none(), "631, 80 still unfinished");
        order.observe(631, true);
        order.observe(80, false);
        assert_eq!(order.identified().unwrap().id, "printer");
        // The vendor stands in for the second signature port.
        let hints = Hints {
            vendor: "Brother Industries",
            ttl: None,
        };
        let mut order = HostOrder::new(table(), &[9100, 80], hints);
        order.observe(9100, true);
        order.observe(80, false);
        assert_eq!(order.identified().unwrap().id, "printer");
        // Nothing open: never identified.
        let mut order = HostOrder::new(table(), &ports, hints);
        for p in ports {
            order.observe(p, false);
        }
        assert!(order.identified().is_none());
    }

    #[test]
    fn a_large_port_range_is_ordered_without_quadratic_work() {
        let all: Vec<u16> = (1..=65535).collect();
        let mut order = HostOrder::new(table(), &all, Hints::default());
        order.observe(502, true);
        order.observe(102, true);
        assert_eq!(order.class().unwrap().id, "plc");
        assert_eq!(drain(&mut order).len(), 65535);
    }
}
