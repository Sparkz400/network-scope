//! Wake-on-LAN: one "magic packet" to a MAC address on the broadcast address.
//!
//! This is a send, so it follows the rules of every sender: it takes a token from the rate
//! [`Gate`] with the packet kind [`PacketKind::WakeOnLan`] (which also records it in the sent
//! log), the plan lists it ([`crate::plan::wol`], shown by `wol --dry-run`) and the entry points
//! call the scope guard first. It is never part of a scan and never sent automatically: only an
//! explicit action (the `wol` command, or the button in the desktop app) sends it.
//!
//! The packet is the usual one: six bytes `FF`, then the target MAC sixteen times (102 bytes), as
//! a UDP datagram to port 9. The destination must be the limited broadcast address or a private
//! (non-public) address, so a magic packet can never be aimed at the Internet.
use crate::{core::Gate, scope, sendlog::PacketKind};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    time::Duration,
};

/// The UDP port magic packets go to (the "discard" port, the conventional choice).
pub const PORT: u16 = 9;
/// Length of a magic packet: 6 + 16 * 6.
pub const PACKET_LEN: usize = 102;
/// The detail recorded in the sent log and shown in the plan.
pub const DETAIL: &str = "magic packet (6 x FF, then the MAC 16 times)";

/// A MAC address in `00:11:22:33:44:55`, `00-11-22-33-44-55`, `0011.2233.4455` or
/// `001122334455` notation. The all-zero and all-ones addresses are refused.
pub fn parse_mac(text: &str) -> Result<[u8; 6], String> {
    let t = text.trim();
    let bad = || format!("{t}: not a MAC address (use 00:11:22:33:44:55)");
    let hex: String = t
        .chars()
        .filter(|c| !matches!(c, ':' | '-' | '.'))
        .collect();
    let separators_ok = t
        .chars()
        .all(|c| c.is_ascii_hexdigit() || matches!(c, ':' | '-' | '.'));
    if hex.len() != 12 || !separators_ok || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(bad());
    }
    let mut mac = [0u8; 6];
    for (i, byte) in mac.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).map_err(|_| bad())?;
    }
    if mac == [0; 6] || mac == [0xFF; 6] {
        return Err(format!("{t}: not a device MAC address"));
    }
    Ok(mac)
}

/// The magic packet for `mac`.
pub fn magic_packet(mac: [u8; 6]) -> [u8; PACKET_LEN] {
    let mut packet = [0xFFu8; PACKET_LEN];
    for chunk in packet[6..].as_chunks_mut::<6>().0 {
        *chunk = mac;
    }
    packet
}

/// The directed broadcast address of `ip` in a network with `prefix` bits (`10.0.5.17/24` gives
/// `10.0.5.255`). `None` for a prefix that has no broadcast address (31, 32) or is out of range.
pub fn directed_broadcast(ip: Ipv4Addr, prefix: u8) -> Option<Ipv4Addr> {
    if !(1..=30).contains(&prefix) {
        return None;
    }
    let host_bits = u32::MAX >> prefix;
    Some(Ipv4Addr::from(u32::from(ip) | host_bits))
}

/// The addresses the scope guard must look at for a magic packet to `destination`: none for the
/// limited broadcast (it never leaves the local network segment), else the address itself.
pub fn guard_addresses(destination: Ipv4Addr) -> Vec<IpAddr> {
    if destination == Ipv4Addr::BROADCAST {
        vec![]
    } else {
        vec![IpAddr::V4(destination)]
    }
}

/// `Err` unless `destination` is the limited broadcast or a non-public address.
pub fn check_destination(destination: Ipv4Addr) -> Result<(), String> {
    if destination == Ipv4Addr::BROADCAST || !scope::is_public(IpAddr::V4(destination)) {
        Ok(())
    } else {
        Err(format!(
            "{destination} is a public address; a magic packet goes to the local broadcast address only"
        ))
    }
}

/// Sends one magic packet for `mac` to `destination` (port 9). It waits for a token of `gate`,
/// which records the packet in the gate's sent log. Nothing is read back: a device that is
/// already on gives no reply, and one that wakes does so on its own.
pub fn send(mac: [u8; 6], destination: Ipv4Addr, gate: &Gate) -> Result<(), String> {
    check_destination(destination)?;
    let socket = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0))).map_err(|e| e.to_string())?;
    socket.set_broadcast(true).map_err(|e| e.to_string())?;
    // One token, taken without an async runtime (the callers are plain threads).
    let mut waited = Duration::ZERO;
    while let Err(wait) = gate.try_take_for(PacketKind::WakeOnLan, DETAIL) {
        std::thread::sleep(wait.min(Duration::from_millis(250)));
        waited += wait;
        if waited > Duration::from_secs(30) {
            return Err("The rate limit did not release a packet in 30 seconds".into());
        }
    }
    socket
        .send_to(&magic_packet(mac), (destination, PORT))
        .map_err(|e| format!("The magic packet could not be sent: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_magic_packet_is_six_ff_and_the_mac_sixteen_times() {
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let p = magic_packet(mac);
        assert_eq!(p.len(), 102);
        assert_eq!(&p[..6], &[0xFF; 6]);
        for i in 0..16 {
            assert_eq!(&p[6 + 6 * i..12 + 6 * i], &mac, "repetition {i}");
        }
        assert_eq!(p.iter().filter(|b| **b == 0xFF).count(), 6);
    }

    #[test]
    fn mac_notations_are_accepted_and_garbage_is_refused() {
        let want = [0x00, 0x1B, 0x1B, 0x4A, 0x10, 0x01];
        for ok in [
            "00:1B:1B:4A:10:01",
            "00-1b-1b-4a-10-01",
            "001b.1b4a.1001",
            "001B1B4A1001",
            "  00:1b:1b:4a:10:01 ",
        ] {
            assert_eq!(parse_mac(ok).unwrap(), want, "{ok}");
        }
        for bad in [
            "",
            "00:1B:1B:4A:10",
            "00:1B:1B:4A:10:01:02",
            "00:1B:1B:4A:10:0G",
            "00:1B:1B:4A:10:0",
            "00 1B 1B 4A 10 01",
            "00:00:00:00:00:00",
            "FF:FF:FF:FF:FF:FF",
            "not a mac",
            "0x001B1B4A1001",
        ] {
            assert!(parse_mac(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn directed_broadcast_follows_the_prefix() {
        let ip = |s: &str| s.parse::<Ipv4Addr>().unwrap();
        assert_eq!(
            directed_broadcast(ip("10.0.5.17"), 24),
            Some(ip("10.0.5.255"))
        );
        assert_eq!(
            directed_broadcast(ip("192.168.1.130"), 25),
            Some(ip("192.168.1.255"))
        );
        assert_eq!(
            directed_broadcast(ip("172.16.4.9"), 16),
            Some(ip("172.16.255.255"))
        );
        assert_eq!(directed_broadcast(ip("10.0.0.1"), 32), None);
        assert_eq!(directed_broadcast(ip("10.0.0.1"), 31), None);
        assert_eq!(directed_broadcast(ip("10.0.0.1"), 0), None);
    }

    #[test]
    fn only_local_destinations_are_allowed() {
        for ok in [
            "255.255.255.255",
            "10.0.5.255",
            "192.168.1.255",
            "172.16.255.255",
        ] {
            check_destination(ok.parse().unwrap()).unwrap_or_else(|e| panic!("{ok}: {e}"));
        }
        for public in ["8.8.8.8", "93.184.216.34", "1.1.1.255"] {
            let e = check_destination(public.parse().unwrap()).unwrap_err();
            assert!(e.contains("public"), "{e}");
        }
        // The limited broadcast needs no scope check; a directed one does.
        assert!(guard_addresses(Ipv4Addr::BROADCAST).is_empty());
        assert_eq!(guard_addresses("10.0.5.255".parse().unwrap()).len(), 1);
    }

    #[test]
    fn the_packet_goes_out_through_the_gate_and_is_logged() {
        // Loopback stands in for the broadcast address; the datagram must arrive intact.
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let log = std::sync::Arc::new(crate::sendlog::SentLog::new());
        let gate = Gate::new(1000).with_log(log.clone());
        let mac = [0x02, 0x4E, 0x53, 0x01, 0x02, 0x03];
        // Port 9 is fixed, so the real send is only checked for its refusals and its log;
        // the datagram itself is built by `magic_packet` (tested above).
        let e = send(mac, "8.8.8.8".parse().unwrap(), &gate).unwrap_err();
        assert!(e.contains("public"));
        assert!(log.is_empty(), "a refused send records nothing");
        send(mac, Ipv4Addr::LOCALHOST, &gate).unwrap();
        let snapshot = log.snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].kind, PacketKind::WakeOnLan);
        assert_eq!(snapshot[0].detail, DETAIL);
        assert_eq!(snapshot[0].count, 1);
        drop(receiver);
    }
}
