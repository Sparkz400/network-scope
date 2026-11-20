//! The Network Scope engine: scanning, parsers, risk analysis and the inventory store, without any
//! GUI. The desktop app, the CLI and the TUI of the `network-scope` package are built on it, and
//! so can other tools.
//!
//! The crate reads the data files in the repository's `data/` folder at compile time, so it is
//! used as a path or git dependency of a checkout, not from crates.io.
//!
//! # Main entry points
//!
//! - **Scan a target list.** [`scan::parse_targets`] and [`scan::parse_ports`] expand the usual
//!   target and port syntax (`10.0.0.0/24`, `10.0.0.1-20`, `80,443,8000-8100`, `top:100`);
//!   [`scan::start_stream`] runs the scan on its own threads and returns a [`scan::Running`] whose
//!   `receiver` delivers one [`scan::Event`] per host. [`scan::Settings`] carries every option;
//!   Safe Mode (`safe`) is on by default and limits the traffic as documented for the CLI.
//! - **Parse and import.** [`nmap::import`] reads nmap XML into a [`store::Snapshot`] (and
//!   [`nmap::export`] writes it back); [`pcapfile`] and [`otpassive`] read captures (passive OT
//!   discovery, no packets are sent); [`passive`] decodes broadcast and discovery protocols;
//!   [`feeds`] loads offline CISA KEV and EPSS data; [`script`] runs Rhai scripts against hosts.
//! - **Analyze risk.** [`risk::analyze_host`] and [`risk::analyze_snapshot`] return
//!   [`risk::Finding`]s (weak TLS and SSH, risky services, CVE hints); [`devices::merge`] joins
//!   active and passive results into one record per device; [`report`] renders HTML and Markdown;
//!   [`store::diff_report`] compares two scans.
//! - **Open the store.** [`store::save`], [`store::load`], [`store::list`] and [`store::timestamp`]
//!   work on an SQLite inventory file ([`store::default_path`] is the location the apps use).
//! - **Monitor.** [`monitor`] repeats scans and raises alerts; [`notify`] sends them to webhooks
//!   and syslog.
//!
//! Read-only industrial protocol requests are built only from the allow-listed types in
//! [`ot::readonly`]; there is no way to construct a write or control request.
//!
//! A program that starts scans should call [`scope::enforce`] with the addresses first: it
//! refuses public addresses and addresses outside a declared scope unless the user confirmed.
//!
//! # Example
//!
//! Import an nmap scan, analyze it, keep it in an inventory file and read it back:
//!
//! ```
//! use network_scope_core::{nmap, risk, store};
//!
//! let xml = r#"<nmaprun args="nmap -sV 10.0.0.5"><host><status state="up"/>
//!   <address addr="10.0.0.5" addrtype="ipv4"/>
//!   <ports><port protocol="tcp" portid="23"><state state="open"/>
//!   <service name="telnet"/></port></ports></host></nmaprun>"#;
//! let snapshot = nmap::import(xml)?;
//! assert_eq!(snapshot.hosts.len(), 1);
//!
//! // Telnet is an open, unencrypted remote login: at least one finding.
//! let findings = risk::analyze_snapshot(&snapshot);
//! assert!(findings.iter().any(|f| f.port == Some(23)));
//!
//! let db = std::env::temp_dir().join(format!("ns-core-doc-{}.sqlite", std::process::id()));
//! let id = store::save(&db, &snapshot)?;
//! assert_eq!(store::load(&db, id)?.hosts[0].open, [23]);
//! assert_eq!(store::list(&db)?.len(), 1);
//! # let _ = std::fs::remove_file(&db);
//! # Ok::<(), String>(())
//! ```
//!
//! Scanning needs a network, so this example is only compiled:
//!
//! ```no_run
//! use network_scope_core::scan::{self, Event, Settings};
//!
//! let settings = Settings {
//!     ports: "22,80,443".into(),
//!     scan_nonresponders: true,
//!     ..Settings::default()
//! };
//! let hosts = scan::parse_targets("192.168.1.0/28", settings.skip_edges, scan::MAX_STREAM)?;
//! let ports = scan::parse_ports(&settings.ports)?;
//! let total = hosts.count() as usize;
//! let run = scan::start_stream(Box::new(hosts.iter()), total, ports, settings);
//! while let Ok(event) = run.receiver.recv() {
//!     match event {
//!         Event::Host(h) if h.responding => println!("{} open: {:?}", h.ip, h.open),
//!         Event::Host(_) => {}
//!         Event::Error(e) => eprintln!("{e}"),
//!         Event::Done => break,
//!     }
//! }
//! # Ok::<(), String>(())
//! ```
//!
//! # Modules
//!
//! The public modules above are the supported surface. `core` is the bounded async scheduler and
//! rate gate, `syn` the Npcap SYN engine and `capture` the runtime-loaded capture driver. The
//! protocol engines (`arp`, `udp`, `tls`, `fingerprint`, `osfp`, `rtt`, `platform`, `oui`) are
//! internal.
//! Network Scope engine.
pub mod alertscript;
pub(crate) mod arp;
pub mod backoff;
pub mod baseline;
pub mod capture;
pub mod changes;
pub mod compliance;
pub mod core;
pub mod devices;
pub mod evidence;
pub mod feeds;
pub(crate) mod fingerprint;
pub mod identity;
pub mod import;
pub mod jarm;
pub mod mcp;
pub mod monitor;
pub mod nmap;
pub mod notify;
pub mod nvd;
pub mod observations;
pub(crate) mod osfp;
pub mod ot;
pub mod otpassive;
pub(crate) mod oui;
pub mod passive;
pub mod pcapfile;
pub mod plan;
pub(crate) mod platform;
pub(crate) mod probes;
pub mod report;
pub mod risk;
pub(crate) mod rtt;
pub mod scan;
pub mod schedule;
pub mod schema;
pub mod scope;
pub mod score;
pub mod script;
pub mod sendlog;
pub mod service;
pub mod snmp;
pub mod store;
pub mod syn;
pub mod sync;
pub(crate) mod tls;
pub mod topology;
pub mod trace;
pub(crate) mod udp;
pub mod update;

#[doc(hidden)]
pub mod fuzz;

#[doc(hidden)]
pub use ot::readonly as ot_readonly;
