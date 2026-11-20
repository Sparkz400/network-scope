//! The OT decoders on real captures: public pcaps from ITI/ICS-Security-Tools under
//! `tests/fixtures/ics/` (see `PROVENANCE.md` there), read through `read_pcap_file`, the same
//! function `ot-listen --pcap` uses. Expected values were read from the decoded output of the
//! captures first; they are what the decoders really find, not what a spec says should be there.
use super::packet::parse_ip;
use super::testutil::obs;
use super::{Asset, Tracker, assets, control_findings, read_pcap_file};
use crate::{ot, passive::Observation, risk::Severity};
use std::{collections::BTreeMap, net::IpAddr};

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/fixtures/ics");

fn path(name: &str) -> String {
    format!("{DIR}/{name}")
}

fn track(name: &str) -> Tracker {
    let mut t = Tracker::new();
    read_pcap_file(&path(name), &mut t).unwrap_or_else(|e| panic!("{name}: {e}"));
    t
}

fn one(t: &Tracker, protocol: &str) -> Observation {
    let mut found = obs(t, protocol);
    assert_eq!(found.len(), 1, "{protocol}: {found:?}");
    found.remove(0)
}

fn ip(o: &Observation) -> String {
    o.ip.expect("an endpoint has an IP").to_string()
}

fn field<'a>(o: &'a Observation, key: &str) -> &'a str {
    o.fields.get(key).map_or("", String::as_str)
}

/// (severity, device, text) of every control-traffic finding.
fn findings(t: &Tracker) -> Vec<(Severity, String, String)> {
    control_findings(&t.observations())
        .into_iter()
        .map(|(s, ip, text)| (s, ip.to_string(), text))
        .collect()
}

fn asset_of(all: &[Asset], address: &str) -> Asset {
    let address: IpAddr = address.parse().unwrap();
    all.iter()
        .find(|a| a.ips.contains(&address))
        .unwrap_or_else(|| panic!("no asset for {address}: {all:?}"))
        .clone()
}

/// Every server (device) endpoint observed, by protocol label and IP.
fn servers(t: &Tracker) -> Vec<String> {
    t.observations()
        .into_iter()
        .filter(|o| o.protocol.ends_with("server (observed)"))
        .map(|o| format!("{} {}", o.protocol, ip(&o)))
        .collect()
}

#[test]
fn every_fixture_reads_to_the_end_with_the_expected_frame_count() {
    let frames = [
        ("bacnet_test.pcap", 26),
        ("dnp3_read_and_response.pcap", 12),
        ("dnp3_select_operate.pcap", 12),
        ("dnp3_write_binary_output.pcap", 1),
        ("enip_cip_stop_plc.pcap", 1),
        ("enip_test.pcap", 11),
        ("fox_info.pcap", 10),
        ("iec104_diverse.pcap", 173),
        ("iec104_test_dissect.pcap", 147),
        ("melsec_melsoft_udp.pcap", 432),
        ("mms_read_request.pcap", 16),
        ("mms_stop_request.pcap", 24),
        ("modbus_test_data_part1.pcap", 118),
        ("modbus_test_data_part2.pcap", 350),
        ("omron_test.pcap", 18),
        ("opcua_method_call.pcap", 90),
        ("profinet_dcp_change_ip.pcap", 6),
        ("profinet_test.pcap", 2),
        ("s7_1200_hmi.pcap", 79),
        ("s7comm_downloading_block_db1.pcap", 93),
        ("s7comm_reading_plc_status.pcap", 240),
        ("snap7_s300_stop.pcapng", 2),
    ];
    let on_disk = std::fs::read_dir(DIR)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.ends_with(".pcap") || n.ends_with(".pcapng"))
        .count();
    assert_eq!(on_disk, frames.len(), "a fixture is missing from this list");
    for (name, count) in frames {
        for reassembly in [true, false] {
            let mut t = Tracker::new();
            t.set_reassembly(reassembly);
            read_pcap_file(&path(name), &mut t).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(t.frames, count, "{name}");
            // whatever was found renders as an inventory and as findings
            let all = t.observations();
            super::assets_csv(&assets(&all));
            control_findings(&all);
        }
    }
}

#[test]
fn provenance_lists_every_fixture() {
    let provenance = std::fs::read_to_string(path("PROVENANCE.md")).unwrap();
    for entry in std::fs::read_dir(DIR).unwrap() {
        let name = entry.unwrap().file_name().into_string().unwrap();
        if name.ends_with(".pcap") || name.ends_with(".pcapng") {
            assert!(
                provenance.contains(&format!("`{name}`")),
                "{name} has no entry in PROVENANCE.md"
            );
        }
    }
}

#[test]
fn modbus_reads_diagnostics_and_writes() {
    // Part 1: two clients talk to two devices; one client sends writes, the other sends
    // diagnostics (Force Listen Only, Restart Communications).
    let t = track("modbus_test_data_part1.pcap");
    assert_eq!(
        servers(&t),
        [
            "Modbus/TCP server (observed) 10.0.0.3",
            "Modbus/TCP server (observed) 10.0.0.8"
        ]
    );
    let all = t.observations();
    let device = all
        .iter()
        .find(|o| o.protocol == "Modbus/TCP server (observed)" && ip(o) == "10.0.0.3")
        .unwrap();
    assert_eq!(field(device, "clients"), "10.0.0.9, 10.0.0.57");
    assert_eq!(field(device, "unit_ids"), "10");
    assert_eq!(
        field(device, "control_traffic"),
        "Diagnostics: Force Listen Only Mode x3, Diagnostics: Restart Communications x3, \
         Write Single Coil x2, Write Single Register x1"
    );
    for read in [
        "Read Coils x2",
        "Read Holding Registers x1",
        "Report Server ID x2",
    ] {
        assert!(field(device, "functions").contains(read), "{read}");
    }
    let reader = all
        .iter()
        .find(|o| o.protocol == "Modbus/TCP server (observed)" && ip(o) == "10.0.0.8")
        .unwrap();
    assert_eq!(field(reader, "unit_ids"), "5, 10");
    assert_eq!(
        field(reader, "functions"),
        "Read Device Identification x2, Read Exception Status x2"
    );
    assert_eq!(field(reader, "control_traffic"), "");
    // who does what
    let client = |address: &str| {
        all.iter()
            .find(|o| o.protocol == "Modbus/TCP client (observed)" && ip(o) == address)
            .unwrap()
            .clone()
    };
    assert_eq!(
        field(&client("10.0.0.9"), "control_traffic"),
        "Write Single Coil x2, Write Single Register x1"
    );
    assert_eq!(
        field(&client("10.0.0.57"), "control_traffic"),
        "Diagnostics: Force Listen Only Mode x3, Diagnostics: Restart Communications x3"
    );
    assert_eq!(field(&client("10.0.0.57"), "servers"), "10.0.0.3, 10.0.0.8");
    // Restart Communications is High; the read-only device has no finding.
    let f = findings(&t);
    assert_eq!(f.len(), 1, "{f:?}");
    assert_eq!((f[0].0, f[0].1.as_str()), (Severity::High, "10.0.0.3"));
    assert!(f[0].2.contains("from 10.0.0.9, 10.0.0.57"), "{}", f[0].2);
    // The device at 10.0.0.8 ends two of its Read Device Identification replies with three
    // bytes beyond the length in the MBAP header. The reply itself decodes; the surplus is held
    // as the start of a next message and given up on (once when the next reply arrives, once
    // at the end of the capture). Nothing is lost, but the counter shows it.
    assert_eq!(t.reassembly_stats(), (0, 2));

    // Part 2: one master walks the function code space against one device.
    let t = track("modbus_test_data_part2.pcap");
    let device = one(&t, "Modbus/TCP server (observed)");
    assert_eq!(ip(&device), "166.161.16.230");
    assert_eq!(field(&device, "clients"), "192.168.66.235");
    assert_eq!(field(&device, "unit_ids"), "1");
    assert_eq!(
        field(&device, "control_traffic"),
        "Mask Write Register x1, Read/Write Multiple Registers x1, Write File Record x1, \
         Write Multiple Coils x1, Write Multiple Registers x1, Write Single Coil x1, \
         Write Single Register x1"
    );
    for read in [
        "Read Coils x14",
        "Read Discrete Inputs x1",
        "Read Input Registers x1",
        "Read File Record x1",
        "Read Device Identification x1",
    ] {
        assert!(field(&device, "functions").contains(read), "{read}");
    }
    // codes outside the standard are listed by number, not mistaken for writes
    assert!(field(&device, "functions").contains("function 63 x1"));
    let f = findings(&t);
    assert_eq!(f.len(), 1, "{f:?}");
    assert_eq!(
        (f[0].0, f[0].1.as_str()),
        (Severity::Medium, "166.161.16.230")
    );
    let a = asset_of(&assets(&t.observations()), "166.161.16.230");
    assert_eq!(a.roles, ["server"]);
    assert_eq!(a.control_traffic.len(), 7);
    assert_eq!(a.packets, 281);
}

#[test]
fn s7_block_download_is_flagged() {
    // The capture also holds the PLC's own Download Block (x3) and Download Ended (x1) jobs.
    // They travel from port 102 and are counted as presence only; the download is flagged by
    // the client's Request Download and PLC Control.
    let t = track("s7comm_downloading_block_db1.pcap");
    let server = one(&t, "S7comm server (observed)");
    assert_eq!(
        (ip(&server).as_str(), field(&server, "clients")),
        ("192.168.1.40", "192.168.1.10")
    );
    assert_eq!(
        field(&server, "control_traffic"),
        "PLC Control x1, Request Download x1"
    );
    assert_eq!(
        field(&server, "functions"),
        "PLC Control x1, Request Download x1, Setup Communication x3"
    );
    let client = one(&t, "S7comm client (observed)");
    assert_eq!(ip(&client), "192.168.1.10");
    assert_eq!(field(&client, "servers"), "192.168.1.40");
    let f = findings(&t);
    assert_eq!(f.len(), 1, "{f:?}");
    assert_eq!((f[0].0, f[0].1.as_str()), (Severity::High, "192.168.1.40"));
    assert!(f[0].2.contains("Request Download"), "{}", f[0].2);
    let all = assets(&t.observations());
    assert_eq!(asset_of(&all, "192.168.1.40").roles, ["server"]);
    assert_eq!(asset_of(&all, "192.168.1.10").roles, ["client"]);
    assert_eq!(
        asset_of(&all, "192.168.1.10").control_traffic,
        ["S7comm: PLC Control x1", "S7comm: Request Download x1"]
    );
}

#[test]
fn s7_stop_from_a_pcapng_capture_is_flagged() {
    let t = track("snap7_s300_stop.pcapng");
    let server = one(&t, "S7comm server (observed)");
    assert_eq!(
        (ip(&server).as_str(), field(&server, "clients")),
        ("134.249.61.163", "134.249.62.206")
    );
    assert_eq!(field(&server, "control_traffic"), "PLC Stop x1");
    let f = findings(&t);
    assert_eq!(f.len(), 1, "{f:?}");
    assert_eq!(
        (f[0].0, f[0].1.as_str()),
        (Severity::High, "134.249.61.163")
    );
    assert!(f[0].2.contains("PLC Stop"), "{}", f[0].2);
}

#[test]
fn s7_status_reading_is_not_control_traffic_and_its_szl_decodes() {
    // A programming device reads the CPU's status (SZL userdata requests): no control traffic.
    let t = track("s7comm_reading_plc_status.pcap");
    let server = one(&t, "S7comm server (observed)");
    let client = one(&t, "S7comm client (observed)");
    assert_eq!(
        (ip(&server).as_str(), field(&server, "clients")),
        ("192.168.1.40", "192.168.1.10")
    );
    assert_eq!(ip(&client), "192.168.1.10");
    assert_eq!(field(&server, "functions"), "Setup Communication x1");
    assert_eq!(field(&server, "control_traffic"), "");
    assert!(findings(&t).is_empty());
    // MACs come from the ARP exchange, vendors from the OUI table
    let all = assets(&t.observations());
    let plc = asset_of(&all, "192.168.1.40");
    assert_eq!(plc.mac, "00:1B:1B:23:EB:3B");
    assert!(plc.vendor.starts_with("Siemens"), "{}", plc.vendor);
    assert_eq!(plc.roles, ["server"]);
    let pg = asset_of(&all, "192.168.1.10");
    assert_eq!(pg.mac, "90:E6:BA:84:5E:41");
    assert_eq!(pg.roles, ["client"]);

    // The PLC's own replies hold SZL data. The active S7 probe's SZL parser reads them.
    // Only the request reference differs: the real programming device used its own, the
    // parser matches it against the request our probe sends (PDU reference 0, 2), so the
    // real reference is rewritten to that.
    let mut szl = BTreeMap::new();
    let mut segmented = vec![];
    let mut reader = crate::pcapfile::Reader::new(
        std::fs::File::open(path("s7comm_reading_plc_status.pcap")).unwrap(),
    )
    .unwrap();
    while let Some((_, frame)) = reader.next_frame().unwrap() {
        let Some(p) = parse_ip(&frame) else { continue };
        if !p.tcp || p.sport != 102 || p.payload.len() < 20 || p.payload[7..9] != [0x32, 7] {
            continue;
        }
        let mut reply = p.payload.to_vec();
        reply[11..13].copy_from_slice(&[0, 2]);
        // the SZL id the reply carries (after the 12-byte parameter block and the data header)
        let params = usize::from(u16::from_be_bytes([reply[13], reply[14]]));
        let carried = reply
            .get(17 + params + 4..17 + params + 6)
            .map(|b| u16::from_be_bytes([b[0], b[1]]));
        for id in [0x11, 0x1c] {
            if let Err(e) = ot::parse_szl(&reply, 2, id, &mut szl)
                && e.contains("segmented")
            {
                segmented.extend(carried);
            }
        }
    }
    // SZL 0x11 (module identification): order number and firmware of an ET 200S IM151-8 CPU
    assert_eq!(szl["order_code"], "6ES7 151-8AB01-0AB0");
    assert_eq!(szl["firmware"], "3.2.6");
    // SZL 0x1c (component identification) came back in several fragments, which the probe does
    // not join: it says so instead of returning half a record. (The reply to the SZL 0x00 list
    // request is fragmented as well and is rejected the same way, for either id tried.)
    segmented.sort_unstable();
    segmented.dedup();
    assert_eq!(segmented, [0x0000, 0x001c]);
    assert!(!szl.contains_key("serial"), "{szl:?}");
}

#[test]
fn s7_1200_hmi_traffic_is_presence_only() {
    // An S7-1200 and an HMI speak S7CommPlus: the endpoints are found, but no function can be
    // named and nothing is flagged.
    let t = track("s7_1200_hmi.pcap");
    let server = one(&t, "S7comm server (observed)");
    let client = one(&t, "S7comm client (observed)");
    assert_eq!(
        (ip(&server).as_str(), field(&server, "clients")),
        ("192.168.25.131", "192.168.25.177")
    );
    assert_eq!(
        (ip(&client).as_str(), field(&client, "servers")),
        ("192.168.25.177", "192.168.25.131")
    );
    assert_eq!(
        (field(&server, "packets"), field(&client, "packets")),
        ("63", "50")
    );
    assert!(!server.fields.contains_key("functions"));
    assert!(findings(&t).is_empty());
}

#[test]
fn ethernet_ip_list_identity_decodes() {
    let t = track("enip_test.pcap");
    let device = one(&t, "EtherNet/IP server (observed)");
    assert_eq!(ip(&device), "10.1.1.164");
    assert_eq!(field(&device, "vendor_id"), "1");
    assert_eq!(
        field(&device, "vendor"),
        "Rockwell Automation/Allen-Bradley"
    );
    assert_eq!(field(&device, "name"), "1756-ENBT/A");
    assert_eq!(field(&device, "firmware"), "4.3");
    assert_eq!(field(&device, "serial"), "5393806");
    assert_eq!(field(&device, "device_type"), "12");
    assert_eq!(field(&device, "product_code"), "58");
    assert_eq!(field(&device, "functions"), "List Identity x1");
    assert_eq!(field(&device, "clients"), "10.1.1.167");
    let client = one(&t, "EtherNet/IP client (observed)");
    assert_eq!(
        (ip(&client).as_str(), field(&client, "servers")),
        ("10.1.1.167", "10.1.1.164")
    );
    let all = assets(&t.observations());
    let a = asset_of(&all, "10.1.1.164");
    assert_eq!(a.vendor, "Rockwell Automation/Allen-Bradley");
    assert_eq!(a.product, "1756-ENBT/A");
    assert_eq!((a.firmware.as_str(), a.serial.as_str()), ("4.3", "5393806"));
    assert_eq!(a.protocols, ["EtherNet/IP"]);
    assert!(findings(&t).is_empty());
}

#[test]
fn cip_stop_is_flagged() {
    // One connected CIP message: service 0x07 (Stop) to class 0x8e instance 1
    let t = track("enip_cip_stop_plc.pcap");
    let server = one(&t, "EtherNet/IP server (observed)");
    assert_eq!(
        (ip(&server).as_str(), field(&server, "clients")),
        ("192.168.1.30", "192.168.1.69")
    );
    assert_eq!(field(&server, "functions"), "Stop x1");
    assert_eq!(field(&server, "control_traffic"), "Stop x1");
    let f = findings(&t);
    assert_eq!(f.len(), 1, "{f:?}");
    assert_eq!((f[0].0, f[0].1.as_str()), (Severity::High, "192.168.1.30"));
    let client = one(&t, "EtherNet/IP client (observed)");
    assert_eq!(field(&client, "control_traffic"), "Stop x1");
}

#[test]
fn dnp3_reads_are_quiet_and_writes_and_operates_are_flagged() {
    let t = track("dnp3_read_and_response.pcap");
    let server = one(&t, "DNP3 server (observed)");
    assert_eq!(
        (ip(&server).as_str(), field(&server, "clients")),
        ("192.168.60.130", "192.168.60.1")
    );
    assert_eq!(field(&server, "functions"), "Read x1");
    assert_eq!(field(&server, "control_traffic"), "");
    assert_eq!(
        field(&server, "packets"),
        "3",
        "the outstation's replies count as presence"
    );
    assert!(findings(&t).is_empty());

    let t = track("dnp3_select_operate.pcap");
    let server = one(&t, "DNP3 server (observed)");
    assert_eq!(
        (ip(&server).as_str(), field(&server, "clients")),
        ("192.168.60.130", "192.168.60.1")
    );
    assert_eq!(field(&server, "control_traffic"), "Operate x1, Select x1");
    assert_eq!(
        field(&one(&t, "DNP3 client (observed)"), "control_traffic"),
        "Operate x1, Select x1"
    );
    let f = findings(&t);
    assert_eq!(f.len(), 1, "{f:?}");
    assert_eq!(
        (f[0].0, f[0].1.as_str()),
        (Severity::Medium, "192.168.60.130")
    );

    // A single write of a binary output
    let t = track("dnp3_write_binary_output.pcap");
    let server = one(&t, "DNP3 server (observed)");
    assert_eq!(
        (ip(&server).as_str(), field(&server, "clients")),
        ("192.168.81.1", "192.168.247.131")
    );
    assert_eq!(field(&server, "control_traffic"), "Write x1");
    let f = findings(&t);
    assert_eq!(f.len(), 1, "{f:?}");
    assert_eq!(
        (f[0].0, f[0].1.as_str()),
        (Severity::Medium, "192.168.81.1")
    );
    assert!(f[0].2.contains("from 192.168.247.131"), "{}", f[0].2);
}

#[test]
fn iec104_commands_are_flagged_and_interrogation_is_not() {
    // a master and an outstation on separate hosts
    let t = track("iec104_test_dissect.pcap");
    let server = one(&t, "IEC 104 server (observed)");
    assert_eq!(
        (ip(&server).as_str(), field(&server, "clients")),
        ("172.27.248.79", "172.27.248.109")
    );
    assert_eq!(
        field(&server, "control_traffic"),
        "C_CS clock synchronisation x1, C_DC double command x1, C_SC single command x4"
    );
    assert!(field(&server, "functions").contains("C_IC interrogation x1"));
    assert!(!field(&server, "control_traffic").contains("interrogation"));
    let client = one(&t, "IEC 104 client (observed)");
    assert_eq!(
        (ip(&client).as_str(), field(&client, "servers")),
        ("172.27.248.109", "172.27.248.79")
    );
    let f = findings(&t);
    assert_eq!(f.len(), 1, "{f:?}");
    assert_eq!(
        (f[0].0, f[0].1.as_str()),
        (Severity::Medium, "172.27.248.79")
    );

    // a loopback capture: both ends are 10.0.0.10; setpoint and time-tagged commands
    let t = track("iec104_diverse.pcap");
    let server = one(&t, "IEC 104 server (observed)");
    assert_eq!(ip(&server), "10.0.0.10");
    assert_eq!(
        field(&server, "control_traffic"),
        "C_DC double command x2, C_SC single command x2, C_SE setpoint command (type 50) x4, \
         time-tagged command (type 58) x2, time-tagged command (type 59) x4, \
         time-tagged command (type 61) x2, time-tagged command (type 63) x2"
    );
    let a = asset_of(&assets(&t.observations()), "10.0.0.10");
    assert_eq!(a.roles, ["client", "server"]);
    assert_eq!(a.protocols, ["IEC 104"]);
    assert_eq!(a.control_traffic.len(), 7);
    assert_eq!(findings(&t).len(), 1);
}

#[test]
fn bacnet_read_property_traffic() {
    let t = track("bacnet_test.pcap");
    let server = one(&t, "BACnet/IP server (observed)");
    assert_eq!(
        (ip(&server).as_str(), field(&server, "clients")),
        ("10.1.1.165", "10.1.1.167")
    );
    assert_eq!(field(&server, "functions"), "ReadProperty x9");
    assert_eq!(field(&server, "control_traffic"), "");
    let client = one(&t, "BACnet/IP client (observed)");
    assert_eq!(
        (ip(&client).as_str(), field(&client, "servers")),
        ("10.1.1.167", "10.1.1.165")
    );
    assert!(findings(&t).is_empty());
    let all = assets(&t.observations());
    assert_eq!(asset_of(&all, "10.1.1.165").protocols, ["BACnet/IP"]);
    assert_eq!(asset_of(&all, "10.1.1.165").roles, ["server"]);
}

#[test]
fn profinet_dcp_identify_response_names_the_device() {
    let t = track("profinet_dcp_change_ip.pcap");
    let dcp = one(&t, "Profinet DCP");
    assert_eq!(ip(&dcp), "192.168.0.6");
    assert_eq!(field(&dcp, "name"), "X208-BORD");
    assert_eq!(field(&dcp, "vendor"), "INC");
    assert_eq!(
        (field(&dcp, "vendor_id"), field(&dcp, "device_id")),
        ("42", "2561")
    );
    assert_eq!(
        (field(&dcp, "subnet"), field(&dcp, "gateway")),
        ("255.255.255.0", "192.168.0.1")
    );
    // the device role and option list are decoded too (the capture has no instance or OEM block)
    assert_eq!(field(&dcp, "role"), "IO-Device");
    let options = field(&dcp, "options");
    for pair in ["1/2", "2/1", "2/2", "2/3", "2/4", "2/5", "3/61"] {
        assert!(
            options.split(", ").any(|p| p == pair),
            "{pair} in {options}"
        );
    }
    assert!(!dcp.fields.contains_key("instance") && !dcp.fields.contains_key("oem_vendor_id"));
    // The DCP "Set IP" request that follows is not decoded, but the device then answers ARP
    // from its new address: the inventory merges both addresses under its MAC.
    let all = assets(&t.observations());
    let a = asset_of(&all, "192.168.0.6");
    assert_eq!(a.mac, "08:00:06:93:CF:32");
    assert_eq!(a.vendor, "SIEMENS AG");
    assert_eq!(a.name, "X208-BORD");
    assert_eq!(a.protocols, ["Profinet DCP"]);
    assert_eq!(
        a.ips,
        [
            "192.168.0.6".parse::<IpAddr>().unwrap(),
            "192.168.0.10".parse().unwrap()
        ]
    );
    // PN-CBA over UDP is not Profinet RT/DCP: nothing is invented from it
    let t = track("profinet_test.pcap");
    assert!(t.observations().is_empty());
}

#[test]
fn opcua_chunks_are_reassembled_and_the_server_answers_decode() {
    // The server listens on 12001, not 4840, so the port-based detection ignores it.
    let t = track("opcua_method_call.pcap");
    assert!(t.observations().is_empty(), "{:?}", t.observations());

    // On the standard port the same traffic is an OPC UA conversation whose multi-kilobyte
    // chunks span several TCP segments (5 messages joined, none given up).
    let mut t = Tracker::new();
    let mut reader =
        crate::pcapfile::Reader::new(std::fs::File::open(path("opcua_method_call.pcap")).unwrap())
            .unwrap();
    while let Some((ts, mut frame)) = reader.next_frame().unwrap() {
        let tcp = 14 + usize::from(frame[14] & 15) * 4;
        for at in [tcp, tcp + 2] {
            if frame[at..at + 2] == 12001u16.to_be_bytes() {
                frame[at..at + 2].copy_from_slice(&4840u16.to_be_bytes());
            }
        }
        t.feed(&frame, ts);
    }
    t.flush();
    assert_eq!(t.reassembly_stats(), (5, 0));
    let server = one(&t, "OPC UA server (observed)");
    assert_eq!(
        (ip(&server).as_str(), field(&server, "clients")),
        ("192.168.41.212", "192.168.41.176")
    );
    assert_eq!(field(&server, "packets"), "24");
    assert_eq!(ip(&one(&t, "OPC UA client (observed)")), "192.168.41.176");
    assert!(findings(&t).is_empty());

    // The server's replies on the first connection, through the parsers of the OPC UA probe.
    let mut reader =
        crate::pcapfile::Reader::new(std::fs::File::open(path("opcua_method_call.pcap")).unwrap())
            .unwrap();
    let mut stream = vec![];
    while let Some((_, frame)) = reader.next_frame().unwrap() {
        if let Some(p) = parse_ip(&frame)
            && p.tcp
            && (p.sport, p.dport) == (12001, 58674)
        {
            stream.extend_from_slice(p.payload);
        }
    }
    let mut chunks = vec![];
    let mut at = 0;
    while let Some(head) = stream.get(at..at + 8) {
        let n = u32::from_le_bytes(head[4..].try_into().unwrap()) as usize;
        chunks.push((
            head[..4].to_vec(),
            stream[at + 8..(at + n).min(stream.len())].to_vec(),
        ));
        at += n;
    }
    let kinds: Vec<_> = chunks
        .iter()
        .map(|(k, _)| String::from_utf8_lossy(k).into_owned())
        .collect();
    assert_eq!(kinds, ["ACKF", "OPNF", "MSGF", "MSGF", "MSGF", "ERRF"]);
    // OpenSecureChannel response: secure channel 6495, token 1
    assert_eq!(ot::opcua::parse_open(&chunks[1].1).unwrap(), (6495, 1));
    // GetEndpoints response (chunk body: channel, token, sequence, request ID, then the
    // service response). The probe checks the response's request handle against its own
    // GetEndpoints request (handle 2); this client used another one, so it is rewritten.
    let mut body = chunks[2].1[16..].to_vec();
    body[12..16].copy_from_slice(&2u32.to_le_bytes());
    let endpoints = ot::opcua::parse_endpoints(&body).unwrap();
    assert_eq!(endpoints["endpoint_count"], "5");
    let url = "opc.tcp://vm-xp-steven:12001/StackTestServer/AnsiC/2048";
    let policy = "http://opcfoundation.org/UA/SecurityPolicy#";
    let expected = [
        ("None", "1"),
        ("Basic128Rsa15", "3"),
        ("Basic128Rsa15", "2"),
        ("Basic256", "3"),
        ("Basic256", "2"),
    ];
    for (i, (name, mode)) in expected.into_iter().enumerate() {
        assert_eq!(endpoints[&format!("endpoint_{i}.url")], url);
        assert_eq!(
            endpoints[&format!("endpoint_{i}.name")],
            "UA StackTest Server (AnsiC/2048)"
        );
        assert_eq!(
            endpoints[&format!("endpoint_{i}.application_uri")],
            "http://vm-xp-steven/UA StackTest Server (AnsiC/2048)"
        );
        assert_eq!(
            endpoints[&format!("endpoint_{i}.security_policy")],
            format!("{policy}{name}")
        );
        assert_eq!(endpoints[&format!("endpoint_{i}.security_mode")], mode);
    }
    // the transport error the server ends the connection with
    assert_eq!(
        ot::opcua::transport_error(&chunks[5].1).unwrap(),
        "UA transport error 0x80020000: "
    );
}

/// The payloads of one capture file for which `keep(&packet)` holds, in order.
fn payloads(name: &str, keep: impl Fn(&super::packet::Packet<'_>) -> bool) -> Vec<Vec<u8>> {
    let mut reader =
        crate::pcapfile::Reader::new(std::fs::File::open(path(name)).unwrap()).unwrap();
    let mut out = vec![];
    while let Some((_, frame)) = reader.next_frame().unwrap() {
        if let Some(p) = parse_ip(&frame)
            && !p.payload.is_empty()
            && keep(&p)
        {
            out.push(p.payload.to_vec());
        }
    }
    out
}

#[test]
fn omron_fins_controller_data_read_names_the_cp1l() {
    // FINS/TCP (node address handshake, then a frame) and FINS/UDP: both ask Controller Data
    // Read (0x0501) and the CP1L-EL answers with its model and versions.
    let t = track("omron_test.pcap");
    let server = one(&t, "Omron FINS server (observed)");
    assert_eq!(
        (ip(&server).as_str(), field(&server, "clients")),
        ("10.1.1.164", "10.1.1.173")
    );
    assert_eq!(field(&server, "model"), "CP1L-EL20DR-D");
    assert_eq!(field(&server, "firmware"), "01.00");
    assert_eq!(field(&server, "versions"), "01.00, 01.06");
    assert_eq!(field(&server, "node"), "200");
    assert_eq!(field(&server, "functions"), "Controller Data Read x2");
    assert_eq!(field(&server, "control_traffic"), "");
    assert_eq!(field(&server, "packets"), "6");
    assert!(findings(&t).is_empty());
    let all = assets(&t.observations());
    let a = asset_of(&all, "10.1.1.164");
    assert_eq!(
        (a.protocols.as_slice(), a.roles.as_slice()),
        (&["Omron FINS".to_string()][..], &["server".to_string()][..])
    );
    assert_eq!(a.product, "CP1L-EL20DR-D");
    assert_eq!(a.firmware, "01.00");
    assert_eq!(asset_of(&all, "10.1.1.173").roles, ["client"]);

    // The active request is the frame the captured client sent over UDP, byte for byte (the node
    // number is the capture's 0x63).
    use crate::ot_readonly::{FinsCommand, FinsRequest, ReadOnlyRequest};
    let sent = payloads("omron_test.pcap", |p| !p.tcp && p.dport == 9600);
    assert_eq!(sent.len(), 1);
    assert_eq!(
        FinsRequest::new(0x63, FinsCommand::ControllerDataRead).encode(),
        sent[0]
    );
    assert_eq!(
        FinsCommand::of_frame(&sent[0]),
        Some(FinsCommand::ControllerDataRead)
    );
    // and the active parser reads the captured UDP reply the same way
    let reply = payloads("omron_test.pcap", |p| !p.tcp && p.sport == 9600);
    assert_eq!(
        ot::extra::parse_fins_controller_data(&reply[0]).unwrap()["model"],
        "CP1L-EL20DR-D"
    );
}

#[test]
fn niagara_fox_hello_exchange_names_the_station_and_the_workbench() {
    let t = track("fox_info.pcap");
    let server = one(&t, "Niagara Fox server (observed)");
    assert_eq!(
        (ip(&server).as_str(), field(&server, "clients")),
        ("106.68.88.119", "10.1.3.4")
    );
    for (key, want) in [
        ("app_name", "Station"),
        ("app_version", "3.5.41.1"),
        ("os_name", "QNX"),
        ("os_version", "6.3.2"),
        ("vm_name", "J9"),
        ("station_name", "Legion_HQ_V4"),
        ("host_name", "192.168.2.15"),
        ("host_id", "Qnx-NPM6-0000-1490-C30C"),
        ("brand_id", "vykon"),
    ] {
        assert_eq!(field(&server, key), want, "{key}");
    }
    assert_eq!(field(&server, "functions"), "fox hello x1");
    assert_eq!(field(&server, "control_traffic"), "");
    let client = one(&t, "Niagara Fox client (observed)");
    assert_eq!(
        (
            field(&client, "app_name"),
            field(&client, "os_name"),
            field(&client, "host_name")
        ),
        ("Workbench", "Windows XP", "xpvm-0omdc01xmy")
    );
    assert!(findings(&t).is_empty());

    // The active hello has the layout of the captured client hello: same first line, same keys
    // in the same order, same terminator.
    use crate::ot_readonly::{FoxMessage, FoxRequest, ReadOnlyRequest};
    let captured = payloads("fox_info.pcap", |p| p.tcp && p.dport == 1911);
    let hello = String::from_utf8(captured[0].clone()).unwrap();
    assert_eq!(
        FoxMessage::of_frame(hello.as_bytes()),
        Some(FoxMessage::Hello)
    );
    let ours = String::from_utf8(FoxRequest::new(FoxMessage::Hello).encode()).unwrap();
    let layout = |text: &str| -> Vec<String> {
        text.lines()
            .map(|l| match l.split_once('=') {
                Some((k, v)) => format!("{k}={}", &v[..2]),
                None => l.to_string(),
            })
            .collect()
    };
    assert_eq!(layout(&ours), layout(&hello));
    // the station's captured hello parses with the active parser
    let reply = payloads("fox_info.pcap", |p| p.tcp && p.sport == 1911);
    let fields = ot::extra::parse_fox_hello(&reply[0]).unwrap();
    assert_eq!(fields["station_name"], "Legion_HQ_V4");
}

#[test]
fn melsoft_udp_capture_names_the_iq_f_cpu() {
    // GX Works talking to an FX5U over the MELSOFT direct connection (UDP 5560); the request
    // frames go to the broadcast address, the PLC answers to it as well.
    let t = track("melsec_melsoft_udp.pcap");
    let server = one(&t, "MELSEC server (observed)");
    assert_eq!(ip(&server), "192.168.3.250");
    assert_eq!(field(&server, "model"), "FX5U-32MT/ES");
    assert_eq!(field(&server, "protocol"), "MELSOFT direct connection");
    assert_eq!(field(&server, "packets"), "216");
    assert_eq!(
        field(&server, "clients"),
        "",
        "a reply to a broadcast address names no client"
    );
    let client = one(&t, "MELSEC client (observed)");
    assert_eq!(ip(&client), "192.168.3.101");
    // nothing is invented about what the frames do
    assert!(!server.fields.contains_key("functions"));
    assert!(findings(&t).is_empty());
    let a = asset_of(&assets(&t.observations()), "192.168.3.250");
    assert_eq!(a.product, "FX5U-32MT/ES");
    assert_eq!(a.protocols, ["MELSEC"]);
}

#[test]
fn iec61850_mms_is_told_from_s7comm_and_a_stop_is_flagged() {
    // MMS shares TCP port 102 with S7comm. These two captures (bare MMS PDUs in TPKT/COTP) are
    // MMS, not S7comm.
    let t = track("mms_read_request.pcap");
    assert!(obs(&t, "S7comm server (observed)").is_empty());
    let server = one(&t, "IEC 61850 MMS server (observed)");
    assert_eq!(
        (ip(&server).as_str(), field(&server, "clients")),
        ("127.0.0.1", "127.0.0.1")
    );
    assert_eq!(field(&server, "functions"), "Initiate x1, Read x1");
    assert_eq!(field(&server, "control_traffic"), "");
    // the connection request and confirm that came before the first data are counted too
    assert_eq!(field(&server, "packets"), "6");
    assert!(findings(&t).is_empty());

    let t = track("mms_stop_request.pcap");
    assert!(obs(&t, "S7comm server (observed)").is_empty());
    let server = one(&t, "IEC 61850 MMS server (observed)");
    assert_eq!(
        field(&server, "control_traffic"),
        "Start Program Invocation x1, Stop Program Invocation x1"
    );
    assert_eq!(
        field(&server, "functions"),
        "Conclude x1, Initiate x1, Start Program Invocation x1, Stop Program Invocation x1"
    );
    assert_eq!(
        field(
            &one(&t, "IEC 61850 MMS client (observed)"),
            "control_traffic"
        ),
        "Start Program Invocation x1, Stop Program Invocation x1"
    );
    let f = findings(&t);
    assert_eq!(f.len(), 1, "{f:?}");
    assert_eq!((f[0].0, f[0].1.as_str()), (Severity::High, "127.0.0.1"));
    assert!(
        f[0].2
            .starts_with("IEC 61850 MMS server: control traffic observed"),
        "{}",
        f[0].2
    );
    let a = asset_of(&assets(&t.observations()), "127.0.0.1");
    assert_eq!(a.protocols, ["IEC 61850 MMS"]);
    assert_eq!(a.control_traffic.len(), 2);
    // the S7 captures on the same port stay S7, including S7CommPlus and a PLC stop
    for name in [
        "s7_1200_hmi.pcap",
        "s7comm_reading_plc_status.pcap",
        "s7comm_downloading_block_db1.pcap",
        "snap7_s300_stop.pcapng",
    ] {
        let t = track(name);
        assert!(
            obs(&t, "IEC 61850 MMS server (observed)").is_empty(),
            "{name}"
        );
        assert_eq!(obs(&t, "S7comm server (observed)").len(), 1, "{name}");
    }
}

#[test]
fn dnp3_link_addresses_come_from_the_data_link_header() {
    let t = track("dnp3_read_and_response.pcap");
    let server = one(&t, "DNP3 server (observed)");
    assert_eq!(field(&server, "link_address"), "10");
    assert_eq!(
        field(&one(&t, "DNP3 client (observed)"), "link_address"),
        "1"
    );
    // the outstation's reply carries internal indications; none of the interesting ones is set
    assert_eq!(field(&server, "iin"), "");
    let t = track("dnp3_write_binary_output.pcap");
    assert_eq!(
        field(&one(&t, "DNP3 server (observed)"), "link_address"),
        "3"
    );
    assert_eq!(
        field(&one(&t, "DNP3 client (observed)"), "link_address"),
        "4"
    );
}

#[test]
fn no_fixture_is_reported_by_a_decoder_that_is_port_only() {
    // CODESYS is recognised by port only and no capture of it is among the fixtures: none of
    // them may be reported as CODESYS.
    for entry in std::fs::read_dir(DIR).unwrap() {
        let name = entry.unwrap().file_name().into_string().unwrap();
        if name.ends_with(".pcap") || name.ends_with(".pcapng") {
            let t = track(&name);
            assert!(obs(&t, "CODESYS server (observed)").is_empty(), "{name}");
        }
    }
}
