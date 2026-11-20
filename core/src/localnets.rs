//! The IPv4 networks this machine is connected to, and which of them "Scan my network" scans.
//!
//! [`detect`] reads the addresses and prefix lengths of the local interfaces from the operating
//! system (`ip -4 -o addr` on Linux, `ifconfig` on macOS and the BSDs, PowerShell's
//! `Get-NetIPAddress` or `route print` on Windows; fixed commands, no user input, no packets sent
//! to the network). [`classify`] decides for each network whether a one-click scan may include it:
//!
//! - **scanned**: a private (RFC 1918) on-link network of a real-looking interface, at most a /22
//!   (1,022 hosts);
//! - **needs confirmation**: a private network larger than a /22 (a /16 has 65,534 hosts);
//! - **skipped**: loopback, link-local (169.254/16), non-private (public or CGNAT) networks,
//!   single-address and point-to-point networks (/31, /32: what a VPN client usually adds), and
//!   interfaces whose name looks virtual or like a VPN (docker, vmnet, tun, wg, ...).
//!
//! The text parsers are separate functions so they can be tested with sample output.
use std::net::Ipv4Addr;

/// The largest network scanned without a confirmation: a /22 has 1,022 usable hosts.
pub const LARGE_PREFIX: u8 = 22;

/// One IPv4 address of an interface with its prefix length.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalNet {
    /// The interface name (`eth0`, `Ethernet`, `en0`); empty when the source gives none.
    pub interface: String,
    pub ip: Ipv4Addr,
    pub prefix: u8,
}

impl LocalNet {
    /// The first address of the network (`192.168.1.0` for `192.168.1.5/24`).
    pub fn network(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.ip) & mask(self.prefix))
    }
    /// `192.168.1.0/24`.
    pub fn cidr(&self) -> String {
        format!("{}/{}", self.network(), self.prefix)
    }
    /// Addresses in the network (including network and broadcast address).
    pub fn size(&self) -> u64 {
        1u64 << (32 - u32::from(self.prefix.min(32)))
    }
}

fn mask(prefix: u8) -> u32 {
    match prefix {
        0 => 0,
        1..=31 => u32::MAX << (32 - u32::from(prefix)),
        _ => u32::MAX,
    }
}

/// What "Scan my network" does with a network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Included in the one-click scan.
    Scan,
    /// Included only after the user confirmed; the text says why (its size).
    Confirm(String),
    /// Left out; the text says why.
    Skip(String),
}

/// A network with the decision about it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub net: LocalNet,
    pub decision: Decision,
}

fn private_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 10 || (o[0] == 172 && (16..=31).contains(&o[1])) || (o[0] == 192 && o[1] == 168)
}

/// Whether an interface name looks like a VPN, tunnel, container or virtual-machine adapter.
pub fn virtual_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    if [
        "vmware",
        "virtualbox",
        "hyper-v",
        "wireguard",
        "openvpn",
        "zerotier",
        "anyconnect",
        "nordlynx",
        "loopback",
        "pseudo",
        "bluetooth",
    ]
    .iter()
    .any(|k| lower.contains(k))
    {
        return true;
    }
    // Docker's user-defined bridges are `br-<hex>`; a plain `br0` is often the real LAN.
    if lower.starts_with("br-") {
        return true;
    }
    lower
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| !t.is_empty())
        .any(|t| {
            let stem = t.trim_end_matches(|c: char| c.is_ascii_digit());
            [
                "docker",
                "veth",
                "virbr",
                "vmnet",
                "vboxnet",
                "vethernet",
                "utun",
                "tailscale",
                "wsl",
            ]
            .iter()
            .any(|p| t.starts_with(p))
                || [
                    "vpn", "tun", "tap", "wg", "ppp", "zt", "lo", "awdl", "llw", "gif", "stf",
                ]
                .contains(&stem)
        })
}

/// Decides for each network; duplicates (the same network on two interfaces) are listed once.
/// The result is sorted by network.
pub fn classify(nets: &[LocalNet]) -> Vec<Candidate> {
    let mut out: Vec<Candidate> = vec![];
    for net in nets {
        let size = net.size();
        let decision = if net.ip.is_loopback() || net.ip.octets()[0] == 127 {
            Decision::Skip("loopback".into())
        } else if net.ip.is_link_local() {
            Decision::Skip("link-local (169.254.x.x): no DHCP answer on this interface".into())
        } else if net.ip.is_unspecified() || net.ip.is_multicast() || net.ip.is_broadcast() {
            Decision::Skip("not a unicast address".into())
        } else if net.prefix >= 31 {
            Decision::Skip(format!(
                "/{}: a single address or point-to-point link (typical for a VPN)",
                net.prefix
            ))
        } else if net.prefix == 0 {
            Decision::Skip("a network with no prefix".into())
        } else if !private_v4(net.ip) {
            Decision::Skip("not a private (RFC 1918) network".into())
        } else if virtual_name(&net.interface) {
            Decision::Skip(format!(
                "{} looks like a virtual or VPN adapter",
                net.interface
            ))
        } else if net.prefix < LARGE_PREFIX {
            Decision::Confirm(format!("{size} addresses"))
        } else {
            Decision::Scan
        };
        let key = (net.network(), net.prefix);
        match out
            .iter_mut()
            .find(|c| (c.net.network(), c.net.prefix) == key)
        {
            // A usable decision wins over a skip for the same network seen on another interface.
            Some(existing) => {
                if matches!(existing.decision, Decision::Skip(_))
                    && !matches!(decision, Decision::Skip(_))
                {
                    *existing = Candidate {
                        net: net.clone(),
                        decision,
                    };
                }
            }
            None => out.push(Candidate {
                net: net.clone(),
                decision,
            }),
        }
    }
    out.sort_by_key(|c| (u32::from(c.net.network()), c.net.prefix));
    out
}

/// The networks to scan: those decided `Scan`, and the `Confirm` ones when `confirmed_large`.
pub fn selected(candidates: &[Candidate], confirmed_large: bool) -> Vec<String> {
    candidates
        .iter()
        .filter(|c| match c.decision {
            Decision::Scan => true,
            Decision::Confirm(_) => confirmed_large,
            Decision::Skip(_) => false,
        })
        .map(|c| c.net.cidr())
        .collect()
}

/// The directed broadcast address of the network that contains `ip`, among `nets`.
pub fn broadcast_for(nets: &[LocalNet], ip: Ipv4Addr) -> Option<Ipv4Addr> {
    nets.iter()
        .filter(|n| n.prefix <= 30 && u32::from(n.network()) == u32::from(ip) & mask(n.prefix))
        .max_by_key(|n| n.prefix)
        .and_then(|n| crate::wol::directed_broadcast(n.ip, n.prefix))
}

// ---- parsers ---------------------------------------------------------------------------

fn prefix_of_mask(m: u32) -> Option<u8> {
    let ones = m.count_ones();
    (m.leading_ones() == ones).then_some(ones as u8)
}

/// `ip -4 -o addr show`: `2: eth0    inet 192.168.1.5/24 brd 192.168.1.255 scope global eth0`.
pub fn parse_ip_addr(text: &str) -> Vec<LocalNet> {
    let mut out = vec![];
    for line in text.lines() {
        let t: Vec<&str> = line.split_whitespace().collect();
        let Some(i) = t.iter().position(|w| *w == "inet") else {
            continue;
        };
        let (Some(name), Some(addr)) = (t.get(1), t.get(i + 1)) else {
            continue;
        };
        let Some((ip, prefix)) = addr.split_once('/') else {
            continue;
        };
        if let (Ok(ip), Ok(prefix)) = (ip.parse(), prefix.parse::<u8>())
            && prefix <= 32
        {
            out.push(LocalNet {
                interface: name.trim_end_matches(':').to_string(),
                ip,
                prefix,
            });
        }
    }
    out
}

fn parse_mask(text: &str) -> Option<u8> {
    if let Some(hex) = text.strip_prefix("0x") {
        return u32::from_str_radix(hex, 16).ok().and_then(prefix_of_mask);
    }
    text.parse::<Ipv4Addr>()
        .ok()
        .and_then(|m| prefix_of_mask(u32::from(m)))
}

/// `ifconfig`: macOS and the BSDs (`inet 192.168.1.5 netmask 0xffffff00 broadcast ...`), net-tools
/// on Linux (`inet 192.168.1.5  netmask 255.255.255.0`, or the old `inet addr:... Mask:...`).
pub fn parse_ifconfig(text: &str) -> Vec<LocalNet> {
    let mut out = vec![];
    let mut interface = String::new();
    for line in text.lines() {
        if !line.starts_with([' ', '\t']) && !line.trim().is_empty() {
            // `en0: flags=...` (BSD) or `eth0      Link encap:...` (old net-tools).
            interface = line
                .split(|c: char| c == ':' || c.is_whitespace())
                .next()
                .unwrap_or("")
                .to_string();
        }
        let t: Vec<&str> = line.split_whitespace().collect();
        let Some(i) = t.iter().position(|w| *w == "inet") else {
            continue;
        };
        let value = |key: &str| -> Option<&str> {
            for (j, w) in t.iter().enumerate() {
                if *w == key {
                    return t.get(j + 1).copied();
                }
                if let Some(rest) = w.strip_prefix(key).and_then(|r| r.strip_prefix(':')) {
                    return Some(rest);
                }
            }
            None
        };
        let ip = t
            .get(i + 1)
            .map(|w| w.trim_start_matches("addr:"))
            .and_then(|w| w.parse::<Ipv4Addr>().ok());
        let prefix = value("netmask")
            .or_else(|| value("Mask"))
            .and_then(parse_mask);
        if let (Some(ip), Some(prefix)) = (ip, prefix) {
            out.push(LocalNet {
                interface: interface.clone(),
                ip,
                prefix,
            });
        }
    }
    out
}

/// PowerShell output of `{alias}|{address}|{prefix}` lines (see [`detect`]).
pub fn parse_pipe_lines(text: &str) -> Vec<LocalNet> {
    text.lines()
        .filter_map(|line| {
            let mut parts = line.trim().rsplitn(3, '|');
            let prefix = parts.next()?.trim().parse::<u8>().ok()?;
            let ip = parts.next()?.trim().parse::<Ipv4Addr>().ok()?;
            let interface = parts.next().unwrap_or("").trim().to_string();
            (prefix <= 32).then_some(LocalNet {
                interface,
                ip,
                prefix,
            })
        })
        .collect()
}

/// Windows `route print -4`: the on-link rows of the active routes (the gateway column holds
/// "On-link", or the same words in the system language, instead of an address). The network and
/// mask columns give the subnet, the interface column the address of this machine in it.
pub fn parse_route_print(text: &str) -> Vec<LocalNet> {
    let mut out: Vec<LocalNet> = vec![];
    for line in text.lines() {
        let t: Vec<&str> = line.split_whitespace().collect();
        if t.len() < 5 {
            continue;
        }
        let (Ok(dest), Ok(netmask)) = (t[0].parse::<Ipv4Addr>(), t[1].parse::<Ipv4Addr>()) else {
            continue;
        };
        let (Ok(own), Some(_metric)) = (
            t[t.len() - 2].parse::<Ipv4Addr>(),
            t[t.len() - 1].parse::<u32>().ok(),
        ) else {
            continue;
        };
        // Anything between the mask and the interface is the gateway: an address for a routed
        // row, words for an on-link one.
        let gateway = t[2..t.len() - 2].join(" ");
        if gateway.parse::<Ipv4Addr>().is_ok() {
            continue;
        }
        let Some(prefix) = prefix_of_mask(u32::from(netmask)) else {
            continue;
        };
        if prefix == 0 || prefix >= 32 || dest.is_multicast() || dest.is_loopback() {
            continue;
        }
        let net = LocalNet {
            interface: String::new(),
            ip: own,
            prefix,
        };
        if net.network() == dest && !out.contains(&net) {
            out.push(net);
        }
    }
    out
}

#[cfg(windows)]
fn run_hidden(program: &str, args: &[&str]) -> Result<String, String> {
    use std::os::windows::process::CommandExt;
    // CREATE_NO_WINDOW: the GUI build must not flash a console.
    let output = std::process::Command::new(program)
        .args(args)
        .creation_flags(0x0800_0000)
        .output()
        .map_err(|e| format!("{program}: {e}"))?;
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}
#[cfg(not(windows))]
fn run_hidden(program: &str, args: &[&str]) -> Result<String, String> {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .map_err(|e| format!("{program}: {e}"))?;
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// A command to run and the parser of its output.
type Attempt<'a> = (&'a str, Vec<&'a str>, fn(&str) -> Vec<LocalNet>);

/// The local IPv4 networks, from the operating system. `Err` when no source could be read or
/// none gave an address.
pub fn detect() -> Result<Vec<LocalNet>, String> {
    let mut errors = vec![];
    let attempts: Vec<Attempt> = if cfg!(windows) {
        vec![
            (
                "powershell.exe",
                vec![
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "Get-NetIPAddress -AddressFamily IPv4 | ForEach-Object { '{0}|{1}|{2}' -f $_.InterfaceAlias, $_.IPAddress, $_.PrefixLength }",
                ],
                parse_pipe_lines,
            ),
            ("route", vec!["print", "-4"], parse_route_print),
        ]
    } else if cfg!(target_os = "linux") {
        vec![
            ("ip", vec!["-4", "-o", "addr", "show"], parse_ip_addr),
            ("ifconfig", vec![], parse_ifconfig),
        ]
    } else {
        vec![
            ("/sbin/ifconfig", vec!["-a"], parse_ifconfig),
            ("ifconfig", vec!["-a"], parse_ifconfig),
        ]
    };
    for (program, args, parse) in attempts {
        match run_hidden(program, &args) {
            Ok(text) => {
                let nets = parse(&text);
                if !nets.is_empty() {
                    return Ok(nets);
                }
                errors.push(format!("{program}: no IPv4 addresses in its output"));
            }
            Err(e) => errors.push(e),
        }
    }
    Err(format!(
        "The local networks could not be read ({})",
        errors.join("; ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(interface: &str, ip: &str, prefix: u8) -> LocalNet {
        LocalNet {
            interface: interface.into(),
            ip: ip.parse().unwrap(),
            prefix,
        }
    }
    fn decision(interface: &str, ip: &str, prefix: u8) -> Decision {
        classify(&[net(interface, ip, prefix)]).remove(0).decision
    }

    #[test]
    fn network_cidr_and_size() {
        let n = net("eth0", "192.168.1.77", 24);
        assert_eq!(n.network(), "192.168.1.0".parse::<Ipv4Addr>().unwrap());
        assert_eq!(n.cidr(), "192.168.1.0/24");
        assert_eq!(n.size(), 256);
        assert_eq!(net("x", "10.1.130.5", 17).cidr(), "10.1.128.0/17");
        assert_eq!(net("x", "10.0.0.1", 8).size(), 1 << 24);
    }

    #[test]
    fn private_lan_networks_are_scanned() {
        assert_eq!(decision("eth0", "192.168.1.5", 24), Decision::Scan);
        assert_eq!(decision("Ethernet", "10.20.0.31", 24), Decision::Scan);
        assert_eq!(
            decision("en0", "172.16.4.9", 22),
            Decision::Scan,
            "a /22 is the limit"
        );
        assert_eq!(decision("Wi-Fi", "172.31.0.2", 23), Decision::Scan);
    }

    #[test]
    fn large_private_networks_need_confirmation() {
        for (ip, prefix, size) in [
            ("10.0.0.5", 16, "65536"),
            ("172.16.1.1", 21, "2048"),
            ("10.9.0.1", 8, "16777216"),
        ] {
            match decision("eth0", ip, prefix) {
                Decision::Confirm(why) => assert!(why.contains(size), "{why}"),
                other => panic!("{ip}/{prefix}: {other:?}"),
            }
        }
    }

    #[test]
    fn loopback_link_local_vpn_single_and_public_are_skipped() {
        for (name, ip, prefix) in [
            ("lo", "127.0.0.1", 8),
            ("Loopback Pseudo-Interface 1", "127.0.0.1", 8),
            ("eth0", "169.254.12.3", 16),
            ("tun0", "10.8.0.6", 32),
            ("eth0", "10.8.0.6", 32),
            ("eth0", "10.8.0.6", 31),
            ("eth0", "203.0.113.9", 24),
            ("eth0", "100.64.3.3", 24),
            ("eth0", "8.8.8.8", 24),
            ("eth0", "224.0.0.1", 24),
            ("eth0", "172.32.0.5", 24),
            ("eth0", "172.15.0.5", 24),
        ] {
            assert!(
                matches!(decision(name, ip, prefix), Decision::Skip(_)),
                "{name} {ip}/{prefix}"
            );
        }
    }

    #[test]
    fn virtual_adapters_are_recognised_by_name_and_real_ones_are_not() {
        for v in [
            "docker0",
            "veth3a1b",
            "virbr0",
            "br-4f2a",
            "tun0",
            "tap1",
            "wg0",
            "utun3",
            "vmnet8",
            "VMware Network Adapter VMnet1",
            "vEthernet (WSL (Hyper-V firewall))",
            "VirtualBox Host-Only Network",
            "OpenVPN TAP-Windows Adapter",
            "Tailscale",
            "Loopback Pseudo-Interface 1",
        ] {
            assert!(virtual_name(v), "{v}");
        }
        for real in [
            "eth0",
            "enp3s0",
            "en0",
            "Ethernet",
            "Ethernet 2",
            "Wi-Fi",
            "wlan0",
            "WLAN",
            "Local Area Connection",
            "LAN-Verbindung",
            "Laptop-Ethernet",
        ] {
            assert!(!virtual_name(real), "{real}");
        }
        assert!(matches!(
            decision("docker0", "172.17.0.1", 16),
            Decision::Skip(why) if why.contains("virtual")
        ));
    }

    #[test]
    fn the_same_network_on_two_interfaces_is_listed_once_and_a_usable_one_wins() {
        let c = classify(&[
            net("tun0", "192.168.1.9", 24),
            net("eth0", "192.168.1.5", 24),
            net("wlan0", "192.168.1.6", 24),
            net("eth1", "10.0.0.2", 24),
        ]);
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].net.cidr(), "10.0.0.0/24", "sorted by network");
        assert_eq!(c[1].decision, Decision::Scan);
        assert_eq!(c[1].net.interface, "eth0");
    }

    #[test]
    fn selected_follows_the_decisions_and_the_confirmation() {
        let c = classify(&[
            net("eth0", "192.168.1.5", 24),
            net("eth1", "10.0.0.5", 16),
            net("lo", "127.0.0.1", 8),
            net("tun0", "10.8.0.2", 32),
        ]);
        assert_eq!(selected(&c, false), ["192.168.1.0/24"]);
        assert_eq!(selected(&c, true), ["10.0.0.0/16", "192.168.1.0/24"]);
        assert!(selected(&classify(&[]), true).is_empty());
    }

    #[test]
    fn linux_ip_addr_output_is_parsed() {
        let text = "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever\n\
                    2: eth0    inet 192.168.1.5/24 brd 192.168.1.255 scope global dynamic eth0\\       valid_lft 86000sec\n\
                    3: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0\\       valid_lft forever\n\
                    4: tun0    inet 10.8.0.6 peer 10.8.0.5/32 scope global tun0\\       valid_lft forever\n";
        let nets = parse_ip_addr(text);
        assert_eq!(nets.len(), 3, "{nets:?}");
        assert_eq!(nets[1], net("eth0", "192.168.1.5", 24));
        let c = classify(&nets);
        assert_eq!(selected(&c, true), ["192.168.1.0/24"]);
        assert!(parse_ip_addr("garbage\n\n").is_empty());
    }

    #[test]
    fn macos_and_net_tools_ifconfig_output_is_parsed() {
        let mac = "lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384\n\
                   \tinet 127.0.0.1 netmask 0xff000000\n\
                   en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\
                   \tether aa:bb:cc:dd:ee:ff\n\
                   \tinet6 fe80::1%en0 prefixlen 64 scopeid 0x4\n\
                   \tinet 192.168.178.20 netmask 0xffffff00 broadcast 192.168.178.255\n\
                   utun2: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380\n\
                   \tinet 10.9.0.4 --> 10.9.0.4 netmask 0xffffffff\n";
        let nets = parse_ifconfig(mac);
        assert_eq!(nets.len(), 3, "{nets:?}");
        assert_eq!(nets[1], net("en0", "192.168.178.20", 24));
        assert_eq!(selected(&classify(&nets), true), ["192.168.178.0/24"]);
        let linux = "eth0      Link encap:Ethernet  HWaddr 00:11:22:33:44:55\n\
                     \x20         inet addr:10.1.2.3  Bcast:10.1.2.255  Mask:255.255.255.0\n\
                     wlan0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n\
                     \x20       inet 192.168.0.8  netmask 255.255.255.0  broadcast 192.168.0.255\n";
        let nets = parse_ifconfig(linux);
        assert_eq!(
            nets,
            [net("eth0", "10.1.2.3", 24), net("wlan0", "192.168.0.8", 24)]
        );
        // A non-contiguous mask is not a network.
        assert!(parse_ifconfig("en0: x\n\tinet 10.0.0.1 netmask 0xff00ff00\n").is_empty());
    }

    #[test]
    fn powershell_lines_are_parsed() {
        let text = "Ethernet|192.168.1.50|24\nvEthernet (WSL)|172.28.16.1|20\nLoopback Pseudo-Interface 1|127.0.0.1|8\nbad line\n|10.0.0.1|x\n";
        let nets = parse_pipe_lines(text);
        assert_eq!(nets.len(), 3, "{nets:?}");
        assert_eq!(nets[1].interface, "vEthernet (WSL)");
        assert_eq!(selected(&classify(&nets), true), ["192.168.1.0/24"]);
    }

    #[test]
    fn windows_route_print_is_parsed_in_any_language() {
        let text = "IPv4-Routentabelle\n\
            ===========================================================================\n\
            Aktive Routen:\n\
            Netzwerkziel    Netzwerkmaske    Gateway    Schnittstelle    Metrik\n\
                      0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.50     25\n\
                    127.0.0.0        255.0.0.0   Auf Verbindung         127.0.0.1    331\n\
                  192.168.1.0    255.255.255.0   Auf Verbindung      192.168.1.50    281\n\
                 192.168.1.50  255.255.255.255   Auf Verbindung      192.168.1.50    281\n\
                192.168.1.255  255.255.255.255   Auf Verbindung      192.168.1.50    281\n\
                    224.0.0.0        240.0.0.0   Auf Verbindung      192.168.1.50    281\n\
              255.255.255.255  255.255.255.255   Auf Verbindung      192.168.1.50    281\n\
                   10.8.0.0    255.255.255.0       On-link        10.8.0.6      291\n";
        let nets = parse_route_print(text);
        assert_eq!(
            nets.iter().map(LocalNet::cidr).collect::<Vec<_>>(),
            ["192.168.1.0/24", "10.8.0.0/24"]
        );
        assert!(parse_route_print("nothing here").is_empty());
    }

    #[test]
    fn broadcast_comes_from_the_most_specific_network() {
        let nets = [net("eth0", "10.0.0.5", 16), net("eth1", "10.0.5.9", 24)];
        let ip = |s: &str| s.parse::<Ipv4Addr>().unwrap();
        assert_eq!(
            broadcast_for(&nets, ip("10.0.5.17")),
            Some(ip("10.0.5.255"))
        );
        assert_eq!(
            broadcast_for(&nets, ip("10.0.9.1")),
            Some(ip("10.0.255.255"))
        );
        assert_eq!(broadcast_for(&nets, ip("10.1.0.1")), None);
    }

    /// The real command runs on every platform the tests run on (it only reads addresses). A CI
    /// container without `ip` and `ifconfig` is allowed to fail; a machine that answers must
    /// answer with plausible networks.
    #[test]
    fn detect_returns_plausible_networks_when_the_system_answers() {
        if let Ok(nets) = detect() {
            assert!(!nets.is_empty());
            assert!(nets.iter().all(|n| n.prefix <= 32));
        }
    }
}
