use super::*;
use crate::pcapfile::Reader;

fn peer(text: &str) -> SocketAddr {
    text.parse().unwrap()
}

fn modbus_read() -> Vec<u8> {
    vec![0, 1, 0, 0, 0, 6, 1, 3, 0, 0, 0, 2]
}

/// The frames of a pcapng file (time stamp in seconds, bytes).
fn read_back(bytes: &[u8]) -> Vec<(i64, Vec<u8>)> {
    let mut reader = Reader::new(bytes).unwrap();
    let mut out = vec![];
    while let Some(frame) = reader.next_frame().unwrap() {
        out.push(frame);
    }
    out
}

fn sums_to_zero(parts: &[&[u8]]) -> bool {
    checksum(parts) == 0
}

#[test]
fn chunks_are_kept_in_order_and_bounded() {
    let r = Recorder::new();
    r.add(
        peer("10.0.0.5:502"),
        false,
        true,
        &modbus_read(),
        "Modbus/TCP read",
    );
    r.add(
        peer("10.0.0.5:502"),
        false,
        false,
        &[0, 1, 0, 0, 0, 3, 1, 3, 0],
        "reply",
    );
    r.add(peer("10.0.0.5:502"), false, true, &[], "nothing: ignored");
    let all = r.records();
    assert_eq!(all.len(), 2);
    assert!(all[0].outbound && !all[1].outbound);
    assert!(all[0].micros <= all[1].micros);
    assert_eq!(r.counts(), (2, 0));
    // a long payload is cut and says so
    r.add(
        peer("10.0.0.5:80"),
        false,
        false,
        &vec![7u8; MAX_PAYLOAD + 100],
        "big",
    );
    let big = r.records().pop().unwrap();
    assert_eq!((big.data.len(), big.truncated), (MAX_PAYLOAD, true));
    // the bounds drop and count
    let small = Recorder::with_limits(2, 10);
    for i in 0..4u8 {
        small.add(peer("10.0.0.5:80"), false, true, &[i; 4], "x");
    }
    assert_eq!(small.counts(), (2, 2), "two chunks, then the byte limit");
}

#[test]
fn the_file_reads_back_as_frames_with_valid_checksums() {
    let r = Recorder::new();
    r.add(
        peer("10.0.0.5:502"),
        false,
        true,
        &modbus_read(),
        "Modbus/TCP: read",
    );
    r.add(
        peer("10.0.0.5:502"),
        false,
        false,
        &[0, 1, 0, 0, 0, 5, 1, 3, 2, 0, 9],
        "reply",
    );
    r.add(
        peer("[fd00::5]:47808"),
        true,
        true,
        &[0x81, 0x0b, 0, 4],
        "BACnet Who-Is",
    );
    r.add(peer("10.0.0.6:161"), true, false, &[1, 2, 3], "answer");
    let (bytes, frames) = pcapng(&r.records());
    assert_eq!(frames, 4);
    let back = read_back(&bytes);
    assert_eq!(back.len(), 4);
    // frame 0: Ethernet, IPv4, TCP, the Modbus request as payload
    let f = &back[0].1;
    assert_eq!(&f[12..14], &[8, 0]);
    let (ip, tcp) = (&f[14..34], &f[34..]);
    assert_eq!((ip[0], ip[9]), (0x45, 6));
    assert!(sums_to_zero(&[ip]), "IPv4 header checksum");
    let pseudo: Vec<u8> = [&ip[12..20], &[0, 6], &(tcp.len() as u16).to_be_bytes()[..]].concat();
    assert!(sums_to_zero(&[&pseudo, tcp]), "TCP checksum");
    assert_eq!(&tcp[20..], &modbus_read()[..]);
    assert_eq!(
        u16::from_be_bytes([tcp[2], tcp[3]]),
        502,
        "to the peer's port"
    );
    // frame 1 is the reply: the ports are swapped and the acknowledgement is the request's end
    let reply = &back[1].1[34..];
    assert_eq!(u16::from_be_bytes([reply[0], reply[1]]), 502);
    let request_end =
        u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]) + modbus_read().len() as u32;
    assert_eq!(
        u32::from_be_bytes([reply[8], reply[9], reply[10], reply[11]]),
        request_end
    );
    // frame 2: IPv6 and UDP
    let f = &back[2].1;
    assert_eq!(&f[12..14], &[0x86, 0xdd]);
    let (ip6, udp) = (&f[14..54], &f[54..]);
    assert_eq!(ip6[6], 17);
    let pseudo: Vec<u8> = [
        &ip6[8..40],
        &(udp.len() as u32).to_be_bytes()[..],
        &[0, 0, 0, 17],
    ]
    .concat();
    assert!(sums_to_zero(&[&pseudo, udp]), "UDP over IPv6 checksum");
    assert_eq!(&udp[8..], &[0x81, 0x0b, 0, 4]);
    // frame 3: UDP over IPv4, from the peer
    let f = &back[3].1;
    assert_eq!(&f[26..30], &[10, 0, 0, 6]);
    assert!(sums_to_zero(&[&f[14..34]]));
}

#[test]
fn the_header_and_every_packet_say_what_this_is() {
    let r = Recorder::new();
    r.add(
        peer("10.0.0.5:502"),
        false,
        true,
        &modbus_read(),
        "Modbus/TCP: read",
    );
    r.add(peer("10.0.0.5:502"), false, false, &[1, 2], "reply");
    r.add(
        peer("10.0.0.5:80"),
        false,
        false,
        &vec![1u8; MAX_PAYLOAD + 1],
        "HTTP reply",
    );
    let (bytes, _) = pcapng(&r.records());
    let text = String::from_utf8_lossy(&bytes);
    assert!(text.contains("APPLICATION-LEVEL RECORD, NOT A WIRE CAPTURE"));
    assert!(text.contains(&format!("network-scope {}", env!("CARGO_PKG_VERSION"))));
    assert!(text.contains("sent: Modbus/TCP: read"));
    assert!(text.contains("received: reply"));
    assert!(text.contains("received: HTTP reply (payload cut)"));
}

#[test]
fn a_long_chunk_is_several_frames_and_the_sequence_numbers_follow() {
    let r = Recorder::new();
    r.add(
        peer("10.0.0.5:80"),
        false,
        true,
        &vec![5u8; 3000],
        "request",
    );
    let (bytes, frames) = pcapng(&r.records());
    assert_eq!(frames, 3, "1400 + 1400 + 200");
    let back = read_back(&bytes);
    let seq = |f: &[u8]| u32::from_be_bytes([f[38], f[39], f[40], f[41]]);
    let payload = |f: &[u8]| f.len() - 54;
    assert_eq!(
        back.iter().map(|(_, f)| payload(f)).collect::<Vec<_>>(),
        [1400, 1400, 200]
    );
    assert_eq!(seq(&back[1].1) - seq(&back[0].1), 1400);
    assert_eq!(seq(&back[2].1) - seq(&back[1].1), 1400);
}

/// The record of a scan is something the program's own passive decoders understand: the Modbus
/// request of the recording is decoded as a request to a Modbus device.
#[test]
fn the_passive_decoders_read_what_was_recorded() {
    let r = Recorder::new();
    r.add(
        peer("10.0.0.5:502"),
        false,
        true,
        &modbus_read(),
        "Modbus/TCP: read",
    );
    r.add(
        peer("10.0.0.5:502"),
        false,
        false,
        &[0, 1, 0, 0, 0, 5, 1, 3, 2, 0, 9],
        "reply",
    );
    let dir = std::env::temp_dir().join(format!("ns-record-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("scan.pcapng");
    let written = r.write_pcapng(&file).unwrap();
    assert_eq!(
        written,
        Written {
            records: 2,
            frames: 2,
            dropped: 0
        }
    );
    let mut tracker = crate::otpassive::Tracker::new();
    crate::otpassive::read_pcap_file(file.to_str().unwrap(), &mut tracker).unwrap();
    let servers: Vec<String> = tracker
        .observations()
        .into_iter()
        .filter(|o| o.protocol == "Modbus/TCP server (observed)")
        .map(|o| format!("{} {}", o.ip.unwrap(), o.fields["functions"]))
        .collect();
    assert_eq!(servers, ["10.0.0.5 Read Holding Registers x1"]);
    // an unwritable path is an error, not a panic
    assert!(
        r.write_pcapng(&dir.join("missing").join("x.pcapng"))
            .is_err()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_empty_record_is_still_a_valid_file() {
    let (bytes, frames) = pcapng(&[]);
    assert_eq!(frames, 0);
    assert!(read_back(&bytes).is_empty());
}

/// The blocks of a pcapng file: (type, body).
fn blocks(bytes: &[u8]) -> Vec<(u32, Vec<u8>)> {
    let mut out = vec![];
    let mut at = 0;
    while at < bytes.len() {
        let kind = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let total = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as usize;
        assert_eq!(
            total,
            u32::from_le_bytes(bytes[at + total - 4..at + total].try_into().unwrap()) as usize,
            "the length is repeated at the end of the block"
        );
        out.push((kind, bytes[at + 8..at + total - 4].to_vec()));
        at += total;
    }
    out
}

#[test]
fn a_wire_file_carries_the_frames_unchanged_and_says_it_is_a_wire_capture() {
    let eth = |last: u8, len: usize| -> Vec<u8> {
        let mut f = vec![
            0, 1, 2, 3, 4, last, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x08, 0x00,
        ];
        f.resize(len, last);
        f
    };
    let frames = vec![
        WireFrame {
            micros: 1_700_000_000_123_456,
            data: eth(1, 60),
        },
        WireFrame {
            micros: 1_700_000_000_123_999,
            data: eth(2, 61), // odd length: padded in the file, not in the frame
        },
    ];
    let bytes = wire_pcapng(1, "eth0", "host 10.0.0.5", &frames);
    let all = blocks(&bytes);
    assert_eq!(
        all.iter().map(|(k, _)| *k).collect::<Vec<_>>(),
        [0x0a0d_0d0a, 1, 6, 6]
    );
    // read back with the program's own reader: the frames and the seconds
    let back = read_back(&bytes);
    assert_eq!(back.len(), 2);
    assert_eq!(back[0], (1_700_000_000, frames[0].data.clone()));
    assert_eq!(back[1], (1_700_000_000, frames[1].data.clone()));
    // the enhanced packet block holds the exact microseconds and the captured length
    let epb = &all[3].1;
    let micros = (u64::from(u32::from_le_bytes(epb[4..8].try_into().unwrap())) << 32)
        | u64::from(u32::from_le_bytes(epb[8..12].try_into().unwrap()));
    assert_eq!(micros, frames[1].micros);
    assert_eq!(u32::from_le_bytes(epb[12..16].try_into().unwrap()), 61);
    // the labels: a wire capture, with interface and filter, and not the application-level text
    let text = String::from_utf8_lossy(&bytes);
    assert!(
        text.contains("WIRE CAPTURE") && text.contains("eth0") && text.contains("host 10.0.0.5")
    );
    assert!(!text.contains("APPLICATION-LEVEL RECORD"));
    assert!(!text.contains("synthetic"), "nothing here is made up");
    // the loopback link type goes into the interface block as it is
    let loopback = blocks(&wire_pcapng(0, "lo", "host 127.0.0.1", &frames));
    assert_eq!(
        u16::from_le_bytes(loopback[1].1[0..2].try_into().unwrap()),
        0
    );
    assert_eq!(u16::from_le_bytes(all[1].1[0..2].try_into().unwrap()), 1);
    // no frames is still a valid file
    assert_eq!(
        blocks(&wire_pcapng(1, "eth0", "host 10.0.0.5", &[])).len(),
        2
    );
}

#[test]
fn the_application_level_file_still_says_what_it_is() {
    let (bytes, _) = pcapng(&[]);
    let text = String::from_utf8_lossy(&bytes);
    assert!(text.contains("APPLICATION-LEVEL RECORD, NOT A WIRE CAPTURE"));
    assert!(!text.contains("WIRE CAPTURE of a Network Scope scan"));
}
