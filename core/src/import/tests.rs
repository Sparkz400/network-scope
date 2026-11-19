//! Tests of the import parsers and of merging an import into the inventory.
use super::*;
use crate::{
    baseline::{self, Criticality},
    monitor::{self, Context, Policy},
    scan::{Host, Settings},
    store::{self, Snapshot},
};
use std::path::PathBuf;

const ISC: &str = r#"# The format of this file is documented in the dhcpd.leases(5) manual page.
authoring-byte-order little-endian;
server-duid "\000\001\000\001#\002\003\004\000\014)\001\002\003";

lease 192.168.1.50 {
  starts 3 2026/11/18 10:00:00;
  ends 3 2026/11/18 22:00:00;
  cltt 3 2026/11/18 10:00:00;
  binding state active;
  next binding state free;
  rewind binding state free;
  hardware ethernet aa:bb:cc:dd:ee:01;
  uid "\001\252\273\314\335\356\001";
  client-hostname "Laptop-Ada";
  set vendor-class-identifier = "MSFT 5.0";
}
lease 192.168.1.51 {
  starts 3 2026/11/18 09:00:00;
  ends 3 2026/11/18 09:30:00;
  binding state free;
  hardware ethernet aa:bb:cc:dd:ee:02;
  client-hostname "gone-host";
}
lease 192.168.1.52 {
  binding state active;
  hardware ethernet aa:bb:cc:dd:ee:03;
}
lease 192.168.1.53 {
  binding state active;
  client-hostname "no-mac";
}
failover peer "dhcp-failover" state {
  my state normal at 3 2026/11/18 10:00:00;
}
lease 192.168.1.52 {
  binding state active;
  hardware ethernet aa:bb:cc:dd:ee:03;
  client-hostname "printer-3";
  on expiry {
    set x = "y";
  }
}
"#;

const DNSMASQ: &str = "duid 00:01:00:01:2b:1c:2d:3e:aa:bb:cc:dd:ee:ff\n\
1763500000 aa:bb:cc:dd:ee:10 192.168.1.60 phone *\n\
0 aa:bb:cc:dd:ee:11 192.168.1.61 * 01:aa:bb:cc:dd:ee:11\n\
1763500000 12345 fd00::5 laptop00:01:00:01\n\
this is not a lease\n";

const WIN_CSV: &str = "#TYPE Microsoft.Management.Infrastructure.CimInstance#ROOT/Microsoft/Windows/DHCP/DhcpServerv4Lease\r\n\
\"IPAddress\",\"ScopeId\",\"AddressState\",\"ClientId\",\"HostName\",\"LeaseExpiryTime\"\r\n\
\"10.1.0.20\",\"10.1.0.0\",\"Active\",\"aa-bb-cc-00-00-01\",\"pc-01.corp.local\",\"11/19/2026 8:00:00 AM\"\r\n\
\"10.1.0.21\",\"10.1.0.0\",\"ActiveReservation\",\"aa-bb-cc-00-00-02\",\"printer.corp.local\",\"\"\r\n\
\"10.1.0.22\",\"10.1.0.0\",\"Expired\",\"aa-bb-cc-00-00-03\",\"old.corp.local\",\"\"\r\n";

const WIN_XML: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<DHCPServer><IPv4><Scopes><Scope><ScopeId>10.1.0.0</ScopeId>
<Leases>
 <Lease><IPAddress>10.1.0.20</IPAddress><ClientId>aa-bb-cc-00-00-01</ClientId><HostName>pc-01.corp.local</HostName><AddressState>Active</AddressState></Lease>
 <Lease><IPAddress>10.1.0.23</IPAddress><ClientId>aa-bb-cc-00-00-04</ClientId><AddressState>Expired</AddressState></Lease>
</Leases>
<Reservations><Reservation><IPAddress>10.1.0.30</IPAddress><ClientId>aa-bb-cc-00-00-05</ClientId><Name>cam-1</Name></Reservation></Reservations>
</Scope></Scopes></IPv4></DHCPServer>"#;

const AD_CSV: &str = "\"Name\",\"DNSHostName\",\"SamAccountName\",\"Enabled\",\"IPv4Address\",\"OperatingSystem\",\"ManagedBy\",\"Description\"\r\n\
\"PC-01\",\"PC-01.corp.local\",\"PC-01$\",\"True\",\"10.1.0.20\",\"Windows 11 Enterprise\",\"CN=Ada Lovelace,OU=Staff,DC=corp,DC=local\",\"Ada's PC\"\r\n\
\"SRV-DB\",\"srv-db.corp.local\",\"SRV-DB$\",\"True\",\"\",\"Windows Server 2022 Standard\",\"\",\"\"\r\n\
\"OLD-PC\",\"\",\"OLD-PC$\",\"False\",\"\",\"Windows 7\",\"\",\"\"\r\n";

const LDIF: &str = "version: 1\n\
# an AD export\n\
dn: CN=PC-01,OU=Workstations,DC=corp,DC=local\n\
objectClass: top\n\
objectClass: computer\n\
cn: PC-01\n\
dNSHostName: pc-01.corp.local\n\
sAMAccountName: PC-01$\n\
operatingSystem: Windows 11\n\x20Enterprise\n\
userAccountControl: 4096\n\
managedBy:: Q049QWRhIExvdmVsYWNlLE9VPVN0YWZmLERDPWNvcnA=\n\
\n\
dn: CN=Ada,OU=Staff,DC=corp,DC=local\n\
objectClass: user\n\
cn: Ada\n\
\n\
dn: CN=OLD-PC,OU=Workstations,DC=corp,DC=local\n\
objectClass: computer\n\
cn: OLD-PC\n\
userAccountControl: 4098\n\
photo:< file:///etc/passwd\n\
\n";

const NETBOX_DEVICES: &str = r#"{"count":3,"next":null,"previous":null,"results":[
 {"id":1,"name":"core-sw-1","device_type":{"model":"C9300"},"role":{"name":"Core Switch","slug":"core-switch"},
  "tenant":{"name":"NetOps"},"site":{"name":"HQ"},"status":{"value":"active","label":"Active"},
  "primary_ip4":{"address":"10.1.0.1/24"},"tags":[{"name":"critical-infra"},{"name":"rack-1"}]},
 {"id":2,"name":"spare-ap","device_type":{"model":"AP-1"},"role":{"name":"AP"},"status":{"value":"planned"},"primary_ip":null,"tags":[]},
 {"id":3,"name":"plc-7","device_type":{"model":"S7-1500"},"role":{"name":"PLC"},"status":{"value":"offline"},"tags":[]}
]}"#;
const NETBOX_IPS: &str = r#"{"count":3,"results":[
 {"id":10,"address":"10.1.0.2/24","status":{"value":"active"},"dns_name":"core-sw-1.corp.local",
  "assigned_object_type":"dcim.interface","assigned_object":{"name":"vlan10","device":{"name":"core-sw-1"}}},
 {"id":11,"address":"10.1.0.99/24","status":{"value":"active"},"dns_name":"printer-9.corp.local"},
 {"id":12,"address":"10.1.0.98/24","status":{"value":"reserved"}}
]}"#;

fn parse_ok(kind: Kind, text: &str) -> Import {
    parse(kind, text.as_bytes()).unwrap_or_else(|e| panic!("{kind:?}: {e}"))
}
fn temp_db(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "netscope-import-{tag}-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}
fn remove_db(path: &Path) {
    for suffix in ["", "-wal", "-shm"] {
        let mut p = path.as_os_str().to_owned();
        p.push(suffix);
        let _ = std::fs::remove_file(PathBuf::from(p));
    }
}
fn host(ip: &str, mac: &str, name: &str) -> Host {
    Host {
        ip: ip.parse().unwrap(),
        responding: true,
        ping: None,
        ttl: Some(64),
        hostname: name.into(),
        mac: mac.into(),
        open: vec![22],
        closed: 0,
        unanswered: 0,
        errors: vec![],
        ports_checked: true,
        identity: Default::default(),
        udp_open: vec![],
        trace: vec![],
    }
}
fn snapshot(hosts: Vec<Host>) -> Snapshot {
    Snapshot {
        targets: "10.1.0.0/24".into(),
        complete: true,
        settings: Settings::default(),
        hosts,
        observations: vec![],
        notes: Default::default(),
    }
}

#[test]
fn values_are_normalised_or_refused() {
    for (text, want) in [
        ("aa:bb:cc:dd:ee:ff", Some("AA:BB:CC:DD:EE:FF")),
        ("AA-BB-CC-DD-EE-FF", Some("AA:BB:CC:DD:EE:FF")),
        ("aabb.ccdd.eeff", Some("AA:BB:CC:DD:EE:FF")),
        (" aabbccddeeff ", Some("AA:BB:CC:DD:EE:FF")),
        ("00:00:00:00:00:00", None),
        ("ff:ff:ff:ff:ff:ff", None),
        ("aa:bb:cc:dd:ee", None),
        ("01:aa:bb:cc:dd:ee:ff", None),
        ("junk aabbccddeeff", None),
        ("", None),
    ] {
        assert_eq!(norm_mac(text).as_deref(), want, "{text:?}");
    }
    assert_eq!(norm_ip("10.0.0.5/24"), Some("10.0.0.5".parse().unwrap()));
    assert_eq!(norm_ip("[fd00::1]"), Some("fd00::1".parse().unwrap()));
    assert_eq!(norm_ip("fe80::1%eth0"), Some("fe80::1".parse().unwrap()));
    for bad in [
        "0.0.0.0",
        "127.0.0.1",
        "224.0.0.1",
        "255.255.255.255",
        "x",
        "",
    ] {
        assert_eq!(norm_ip(bad), None, "{bad:?}");
    }
    assert_eq!(norm_name("PC-01$").as_deref(), Some("pc-01"));
    assert_eq!(
        norm_name(" Host.Corp.Local. ").as_deref(),
        Some("host.corp.local")
    );
    for bad in ["", "*", "localhost", "10.0.0.1", "a b", "a..b", "-x", "a/b"] {
        assert_eq!(norm_name(bad), None, "{bad:?}");
    }
    assert_eq!(norm_name(&"a".repeat(300)), None);
    assert_eq!(cn_of("CN=Ada Lovelace,OU=Staff,DC=corp"), "Ada Lovelace");
    assert_eq!(cn_of("CN=Doe\\, Jane,OU=Staff"), "Doe, Jane");
    assert_eq!(cn_of("plain text"), "plain text");
}

#[test]
fn text_is_decoded_from_the_encodings_powershell_writes() {
    assert_eq!(decode(b"ip,mac\n").unwrap(), "ip,mac\n");
    assert_eq!(decode(b"\xEF\xBB\xBFip").unwrap(), "ip");
    let le: Vec<u8> = [0xFF, 0xFE]
        .into_iter()
        .chain("ip,mac\r\n1".encode_utf16().flat_map(u16::to_le_bytes))
        .collect();
    assert_eq!(decode(&le).unwrap(), "ip,mac\r\n1");
    let be: Vec<u8> = [0xFE, 0xFF]
        .into_iter()
        .chain("ip,mac".encode_utf16().flat_map(u16::to_be_bytes))
        .collect();
    assert_eq!(decode(&be).unwrap(), "ip,mac");
    let no_bom: Vec<u8> = "ip,mac,hostname\r\n"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    assert_eq!(decode(&no_bom).unwrap(), "ip,mac,hostname\r\n");
    assert_eq!(decode(b"a\0b\xFFc").unwrap(), "ab\u{fffd}c");
    assert!(
        decode(&vec![b'a'; MAX_FILE_BYTES + 1])
            .unwrap_err()
            .contains("too large")
    );
    // A UTF-16 CSV imports like any other.
    let bytes: Vec<u8> = [0xFF, 0xFE]
        .into_iter()
        .chain(
            "mac,hostname\r\naa:bb:cc:dd:ee:01,pc-1\r\n"
                .encode_utf16()
                .flat_map(u16::to_le_bytes),
        )
        .collect();
    let i = parse(Kind::Csv, &bytes).unwrap();
    assert_eq!(i.devices[0].names, ["pc-1"]);
}

#[test]
fn csv_columns_are_found_by_name_in_any_order_and_delimiter() {
    let i = parse_ok(
        Kind::Csv,
        "Hostname;MAC Address;IP;Owner;Tags;Criticality;Expected;Extra\n\
         plc-1;aa-bb-cc-00-00-01;10.0.0.5;\"Plant, Line 1\";ot;critical;yes;x\n\
         cam-2;;10.0.0.6/24;;\"cctv|lobby\";HIGH;no;y\n\
         ;;;;;;;\n\
         ;;;Orphan;;;;\n\
         bad;zz;nope;;;urgent;maybe;\n",
    );
    assert_eq!(i.kind, "csv");
    assert!(i.declared_names);
    assert_eq!(
        i.devices.len(),
        3,
        "the empty row is dropped, `bad` has a name"
    );
    let plc = &i.devices[0];
    assert_eq!(plc.macs, ["AA:BB:CC:00:00:01"]);
    assert_eq!(plc.ips, ["10.0.0.5".parse::<IpAddr>().unwrap()]);
    assert_eq!(plc.names, ["plc-1"]);
    assert_eq!(plc.owner, "Plant, Line 1");
    assert_eq!(plc.tags, ["ot"]);
    assert_eq!(plc.criticality, Some(Criticality::Critical));
    assert_eq!(plc.expected, Some(true));
    let cam = &i.devices[1];
    assert_eq!(cam.tags, ["cctv", "lobby"]);
    assert_eq!(cam.criticality, Some(Criticality::High));
    assert_eq!(cam.expected, Some(false));
    let bad = &i.devices[2];
    assert!(bad.macs.is_empty() && bad.ips.is_empty());
    assert_eq!(bad.names, ["bad"]);
    assert!(bad.criticality.is_none() && bad.expected.is_none());
    assert!(
        i.notes.iter().any(|n| n.contains("urgent")),
        "{:?}",
        i.notes
    );
    assert!(i.notes.iter().any(|n| n.contains("maybe")), "{:?}", i.notes);
    assert!(i.skipped >= 1, "the row without identity is counted");
}

#[test]
fn csv_reader_handles_quotes_line_breaks_bom_type_line_and_sep() {
    let rows = csv::rows("\u{feff}#TYPE Something\r\nsep=;\r\n\"a;b\";\"say \"\"hi\"\"\"\r\n\"multi\nline\";x\r\n\r\n").unwrap();
    assert_eq!(
        rows,
        vec![
            vec!["a;b".to_string(), "say \"hi\"".to_string()],
            vec!["multi\nline".to_string(), "x".to_string()]
        ]
    );
    // The delimiter comes from the header line.
    assert_eq!(csv::rows("a\tb\n1\t2").unwrap()[1], ["1", "2"]);
    assert_eq!(csv::rows("a|b\n1|2").unwrap()[1], ["1", "2"]);
    assert!(csv::rows("").unwrap().is_empty());
    assert!(csv::rows("#TYPE x").unwrap().is_empty());
    // An unterminated quote swallows the rest of the file but does not fail or hang.
    assert_eq!(csv::rows("a,b\n\"1,2\n3,4").unwrap().len(), 2);
    // A CSV without a usable header is refused with a hint.
    assert!(
        parse(Kind::Csv, b"foo,bar\n1,2\n")
            .unwrap_err()
            .contains("at least one of: ip, mac, hostname")
    );
    assert!(parse(Kind::Csv, b"").unwrap_err().contains("empty"));
}

#[test]
fn csv_is_bounded_in_rows_columns_and_cell_length() {
    // A cell is cut at the limit, extra columns are ignored.
    let long = "x".repeat(MAX_VALUE * 3);
    let cols: Vec<String> = (0..200).map(|i| format!("c{i}")).collect();
    let text = format!("hostname,{}\n{long},{}\n", cols.join(","), cols.join(","));
    let rows = csv::rows(&text).unwrap();
    assert!(rows[1][0].chars().count() <= MAX_VALUE);
    assert!(rows[0].len() <= 64);
    // Too many rows are refused.
    let mut big = String::from("ip\n");
    for i in 0..=MAX_DEVICES {
        big.push_str(&format!(
            "10.{}.{}.{}\n",
            (i >> 16) & 255,
            (i >> 8) & 255,
            i & 255
        ));
    }
    assert!(
        parse(Kind::Csv, big.as_bytes())
            .unwrap_err()
            .contains("More than")
    );
}

#[test]
fn isc_leases_are_a_journal_and_only_active_leases_are_devices() {
    let i = parse_ok(Kind::IscDhcp, ISC);
    assert!(!i.declared_names, "client host names are not declarations");
    let ips: Vec<String> = i.devices.iter().map(|d| d.ips[0].to_string()).collect();
    assert_eq!(ips, ["192.168.1.50", "192.168.1.52"], "{i:?}");
    assert_eq!(i.devices[0].macs, ["AA:BB:CC:DD:EE:01"]);
    assert_eq!(i.devices[0].names, ["laptop-ada"]);
    // The later block for .52 (with a name) wins over the earlier one.
    assert_eq!(i.devices[1].names, ["printer-3"]);
    assert_eq!(i.devices[1].tags, ["dhcp"]);
    // free lease and the lease without a hardware address are skipped and counted.
    assert_eq!(i.skipped, 2, "{:?}", i.notes);
    // Not a lease file, truncated file, empty file.
    assert!(
        parse(Kind::IscDhcp, b"hello world\n")
            .unwrap_err()
            .contains("Not a dhcpd.leases")
    );
    assert!(
        parse(Kind::IscDhcp, b"# only a comment\n")
            .unwrap()
            .devices
            .is_empty()
    );
    let cut = &ISC[..ISC.find("client-hostname \"Laptop").unwrap()];
    assert!(
        parse(Kind::IscDhcp, cut.as_bytes())
            .unwrap()
            .devices
            .is_empty()
    );
    let deep = format!("lease 10.0.0.1 {{\n{}", "a {\n".repeat(20));
    assert!(
        parse(Kind::IscDhcp, deep.as_bytes())
            .unwrap_err()
            .contains("nested")
    );
    // Two leases for one MAC are one device.
    let two = "lease 10.0.0.1 {\n binding state active;\n hardware ethernet aa:bb:cc:00:00:01;\n}\nlease 10.0.0.2 {\n binding state active;\n hardware ethernet aa:bb:cc:00:00:01;\n}\n";
    let i = parse_ok(Kind::IscDhcp, two);
    assert_eq!(i.devices.len(), 1);
    assert_eq!(i.devices[0].ips.len(), 2);
}

#[test]
fn dnsmasq_leases_ipv4_ipv6_and_placeholders() {
    let i = parse_ok(Kind::Dnsmasq, DNSMASQ);
    assert_eq!(i.devices.len(), 3);
    assert_eq!(i.devices[0].macs, ["AA:BB:CC:DD:EE:10"]);
    assert_eq!(i.devices[0].names, ["phone"]);
    assert!(i.devices[1].names.is_empty(), "`*` is no name");
    assert_eq!(i.devices[2].ips, ["fd00::5".parse::<IpAddr>().unwrap()]);
    assert!(i.devices[2].macs.is_empty(), "an IAID is not a MAC");
    assert_eq!(i.skipped, 1);
    assert!(
        parse(Kind::Dnsmasq, b"hello\nworld\n")
            .unwrap_err()
            .contains("Not a dnsmasq")
    );
}

#[test]
fn windows_dhcp_csv_and_xml() {
    let csv = parse_ok(Kind::WindowsDhcp, WIN_CSV);
    let macs: Vec<&str> = csv.devices.iter().map(|d| d.macs[0].as_str()).collect();
    assert_eq!(
        macs,
        ["AA:BB:CC:00:00:01", "AA:BB:CC:00:00:02"],
        "expired skipped"
    );
    assert_eq!(csv.devices[0].ips, ["10.1.0.20".parse::<IpAddr>().unwrap()]);
    assert_eq!(csv.devices[0].names, ["pc-01.corp.local"]);
    assert_eq!(csv.skipped, 1);
    assert!(!csv.declared_names);
    let xml = parse_ok(Kind::WindowsDhcp, WIN_XML);
    let macs: Vec<&str> = xml.devices.iter().map(|d| d.macs[0].as_str()).collect();
    assert_eq!(macs, ["AA:BB:CC:00:00:01", "AA:BB:CC:00:00:05"]);
    assert_eq!(xml.devices[1].names, ["cam-1"]);
    assert_eq!(xml.skipped, 1);
    // Refusals: XML without leases, malformed XML, a DTD, a CSV that is not a lease export.
    assert!(
        parse(Kind::WindowsDhcp, b"<a><b/></a>")
            .unwrap_err()
            .contains("Export-DhcpServer")
    );
    assert!(
        parse(Kind::WindowsDhcp, b"<a><Lease>")
            .unwrap_err()
            .contains("Not valid XML")
    );
    let dtd = "<!DOCTYPE x [<!ENTITY e \"boom\">]><DHCPServer><Lease><IPAddress>10.0.0.1</IPAddress></Lease></DHCPServer>";
    assert!(parse(Kind::WindowsDhcp, dtd.as_bytes()).is_err());
    assert!(
        parse(Kind::WindowsDhcp, b"a,b\n1,2\n")
            .unwrap_err()
            .contains("DHCP lease export")
    );
}

#[test]
fn active_directory_csv_and_ldif() {
    let csv = parse_ok(Kind::AdCsv, AD_CSV);
    assert!(csv.declared_names);
    assert_eq!(csv.devices.len(), 2, "the disabled account is skipped");
    assert_eq!(csv.skipped, 1);
    let pc = &csv.devices[0];
    assert_eq!(pc.names, ["pc-01", "pc-01.corp.local"], "in column order");
    assert_eq!(pc.ips, ["10.1.0.20".parse::<IpAddr>().unwrap()]);
    assert_eq!(pc.owner, "Ada Lovelace");
    assert_eq!(pc.tags, ["ad", "os:Windows 11 Enterprise"]);
    assert!(
        parse(Kind::AdCsv, b"foo,bar\n1,2\n")
            .unwrap_err()
            .contains("Get-ADComputer")
    );

    let ldif = parse_ok(Kind::AdLdif, LDIF);
    assert_eq!(ldif.devices.len(), 1, "{ldif:?}");
    let pc = &ldif.devices[0];
    assert_eq!(pc.names, ["pc-01.corp.local", "pc-01"]);
    assert_eq!(pc.owner, "Ada Lovelace", "managedBy was base64");
    assert_eq!(
        pc.tags,
        ["ad", "os:Windows 11Enterprise"],
        "continuation joins without the space"
    );
    // The user entry is ignored, the disabled computer skipped.
    assert_eq!(ldif.skipped, 2, "{:?}", ldif.notes);
    assert!(
        parse(Kind::AdLdif, b"hello\nworld\n")
            .unwrap_err()
            .contains("Not an LDIF")
    );
    // `attr:<` is never fetched, a bad base64 value is dropped, a huge one too.
    let tricky = format!(
        "dn: CN=X\nobjectClass: computer\ncn: x1\nmanagedBy:: !!!\ndescription:: {}\n",
        "QUFB".repeat(5000)
    );
    let i = parse_ok(Kind::AdLdif, &tricky);
    assert_eq!(i.devices[0].owner, "");
    assert_eq!(ldif::base64("SGVsbG8=").as_deref(), Some("Hello"));
    assert_eq!(ldif::base64("SGVsbG8").as_deref(), Some("Hello"));
    assert_eq!(ldif::base64("SGV$bG8"), None);
}

#[test]
fn netbox_devices_and_addresses_join_by_name() {
    let both = parse_files(
        Kind::Netbox,
        &[
            NETBOX_DEVICES.as_bytes().to_vec(),
            NETBOX_IPS.as_bytes().to_vec(),
        ],
    )
    .unwrap();
    let by_name = |n: &str| {
        both.devices
            .iter()
            .find(|d| d.names.iter().any(|x| x == n))
            .unwrap()
    };
    let sw = by_name("core-sw-1");
    // The device's primary address and the address assigned to it are one device.
    assert_eq!(sw.ips.len(), 2, "{sw:?}");
    assert_eq!(sw.owner, "NetOps");
    assert_eq!(sw.expected, Some(true));
    for t in [
        "role:Core Switch",
        "site:HQ",
        "type:C9300",
        "critical-infra",
        "rack-1",
    ] {
        assert!(sw.tags.contains(&t.to_string()), "{t}: {:?}", sw.tags);
    }
    // planned: described, not expected; offline: expected.
    assert_eq!(by_name("spare-ap").expected, Some(false));
    assert!(
        by_name("spare-ap")
            .tags
            .contains(&"status:planned".to_string())
    );
    assert_eq!(by_name("plc-7").expected, Some(true));
    // An address without a device is named by its DNS name; a reserved one is skipped.
    assert_eq!(by_name("printer-9.corp.local").ips.len(), 1);
    assert_eq!(both.skipped, 1);
    assert_eq!(both.devices.len(), 4);
    // Alone, the address file stands for itself; a plain array and one object work too.
    assert_eq!(parse_ok(Kind::Netbox, NETBOX_IPS).devices.len(), 2);
    assert_eq!(
        parse_ok(Kind::Netbox, r#"[{"name":"x1","device_type":{}}]"#)
            .devices
            .len(),
        1
    );
    assert_eq!(
        parse_ok(Kind::Netbox, r#"{"name":"x1","role":{"name":"r"}}"#)
            .devices
            .len(),
        1
    );
    for (bad, want) in [
        ("{not json", "Not valid JSON"),
        ("42", "Not a NetBox"),
        (r#"{"results": 3}"#, "not a list"),
        (r#"[1,2,3]"#, "no device or IP"),
        (r#"{"results":[{"foo":1}]}"#, "no device or IP"),
    ] {
        let e = parse(Kind::Netbox, bad.as_bytes()).unwrap_err();
        assert!(e.contains(want), "{bad}: {e}");
    }
    // Deep nesting is refused by the JSON parser, not by a stack overflow.
    let deep = format!("{}1{}", "[".repeat(5000), "]".repeat(5000));
    assert!(parse(Kind::Netbox, deep.as_bytes()).is_err());
}

#[test]
fn entries_for_one_device_are_joined_but_clients_that_share_a_name_are_not() {
    // Declared names join; leases join by MAC only.
    let named = Imported {
        names: vec!["srv".into()],
        ips: vec!["10.0.0.5".parse().unwrap()],
        ..Default::default()
    };
    let named2 = Imported {
        names: vec!["srv".into()],
        tags: vec!["db".into()],
        ..Default::default()
    };
    assert_eq!(coalesce(vec![named.clone(), named2.clone()], true).len(), 1);
    assert_eq!(coalesce(vec![named, named2], false).len(), 2);
    let a = Imported {
        macs: vec!["AA:BB:CC:00:00:01".into()],
        names: vec!["android".into()],
        ..Default::default()
    };
    let b = Imported {
        macs: vec!["AA:BB:CC:00:00:02".into()],
        names: vec!["android".into()],
        ..Default::default()
    };
    assert_eq!(coalesce(vec![a, b], false).len(), 2);
}

#[test]
fn every_parser_survives_truncated_and_hostile_input() {
    let samples: [(&str, Kind); 11] = [
        (ISC, Kind::IscDhcp),
        (DNSMASQ, Kind::Dnsmasq),
        (WIN_CSV, Kind::WindowsDhcp),
        (WIN_XML, Kind::WindowsDhcp),
        (AD_CSV, Kind::AdCsv),
        (LDIF, Kind::AdLdif),
        (NETBOX_DEVICES, Kind::Netbox),
        (NETBOX_IPS, Kind::Netbox),
        ("ip,mac,hostname\n10.0.0.5,aa:bb:cc:dd:ee:ff,x\n", Kind::Csv),
        (AD_CSV, Kind::Csv),
        (LDIF, Kind::Netbox),
    ];
    for (text, kind) in samples {
        for end in (0..text.len()).filter(|e| text.is_char_boundary(*e)) {
            let _ = parse(kind, &text.as_bytes()[..end]);
        }
        // Every kind on every sample, and on garbage and oversized lines.
        for k in Kind::ALL {
            let _ = parse(k, text.as_bytes());
        }
    }
    for k in Kind::ALL {
        for junk in [
            &b"\xff\xfe\x00\x00"[..],
            &[0u8; 1000][..],
            b"\"\"\"\"\"\"",
            b"{{{{{{{{",
            b"dn:\n\n\n",
            b"lease {\n}\n}\n}\n",
            b"lease 1.2.3.4 {\n",
        ] {
            let _ = parse(k, junk);
        }
        let long = "a".repeat(200_000);
        let _ = parse(k, long.as_bytes());
        let _ = parse(
            k,
            format!("lease 10.0.0.1 {{\n client-hostname \"{long}\";\n}}\n").as_bytes(),
        );
        let _ = parse(
            k,
            format!("dn: x\nobjectClass: computer\ncn: {long}\n").as_bytes(),
        );
    }
}

#[test]
fn an_import_makes_devices_known_and_expected_without_saving_a_scan() {
    let db = temp_db("merge");
    let leases = parse_ok(Kind::WindowsDhcp, WIN_CSV);
    let m = merge(&db, &leases, 1000).unwrap();
    assert_eq!((m.devices, m.new, m.known, m.skipped), (2, 2, 0, 0));
    // Not a scan result: the inventory has no scan, no host, no finding.
    assert!(store::list(&db).unwrap().is_empty());
    let known = store::known_devices(&db).unwrap();
    assert!(known.contains_key("AA:BB:CC:00:00:01") && known.contains_key("AA:BB:CC:00:00:02"));
    let b = baseline::load(&db).unwrap();
    assert_eq!(b.entries.len(), 2);
    assert!(
        b.entries
            .iter()
            .all(|e| e.expected && e.source == "import:windows-dhcp")
    );
    assert!(
        b.entry("AA:BB:CC:00:00:01")
            .unwrap()
            .tags
            .contains(&"dhcp".to_string())
    );
    assert!(!b.exists(), "importing does not start the baseline");
    // Importing the same file again changes nothing; a richer CSV adds owner and tags.
    let again = merge(&db, &leases, 2000).unwrap();
    assert_eq!((again.new, again.known), (0, 2));
    assert_eq!(baseline::load(&db).unwrap().entries.len(), 2);
    let csv = parse_ok(
        Kind::Csv,
        "mac,owner,tags,criticality\naa:bb:cc:00:00:01,Ada,lab,high\n",
    );
    let m = merge(&db, &csv, 3000).unwrap();
    assert_eq!((m.new, m.known), (0, 1), "known by MAC");
    let b = baseline::load(&db).unwrap();
    let e = b.entry("AA:BB:CC:00:00:01").unwrap();
    assert_eq!(
        (e.owner.as_str(), e.criticality),
        ("Ada", Some(Criticality::High))
    );
    assert!(e.tags.contains(&"dhcp".to_string()) && e.tags.contains(&"lab".to_string()));
    assert_eq!(e.source, "import:windows-dhcp", "the first source stays");
    remove_db(&db);
}

#[test]
fn imported_names_recognise_scanned_devices_but_client_reported_names_do_not() {
    let db = temp_db("names");
    // An Active Directory list: names only.
    let ad = parse_ok(Kind::AdCsv, AD_CSV);
    merge(&db, &ad, 1000).unwrap();
    let entries = baseline::load(&db).unwrap();
    assert!(
        entries.entry("ip:10.1.0.20").is_some(),
        "{:?}",
        entries.entries
    );
    assert!(
        entries.entry("name:srv-db").is_some(),
        "no address: by name"
    );
    // A scan finds PC-01 by its NetBIOS name under a MAC the list never heard of.
    let found = crate::devices::merge(
        &[
            host("10.1.0.20", "02:11:22:33:44:55", "PC-01"),
            host("10.1.0.77", "02:99:99:99:99:99", "intruder"),
        ],
        &[],
    );
    let matches = store::resolve_devices(&db, &found).unwrap();
    assert_eq!(matches[0].key, "ip:10.1.0.20", "{matches:?}");
    assert!(!matches[0].new);
    assert!(matches[1].new);
    // With a baseline, PC-01 is expected and the intruder is not.
    baseline::enable(&db, 1500).unwrap();
    let b = baseline::load(&db).unwrap();
    let keys: Vec<String> = matches.iter().map(|m| m.key.clone()).collect();
    assert_eq!(b.expects(&found, &keys), [true, false]);
    // A name that a DHCP client reported is not a declaration: it matches nothing by itself.
    let db2 = temp_db("names2");
    let leases = parse_ok(Kind::Dnsmasq, "0 aa:bb:cc:dd:ee:10 192.168.1.60 phone *\n");
    merge(&db2, &leases, 1000).unwrap();
    let spoof = crate::devices::merge(&[host("192.168.1.99", "02:aa:aa:aa:aa:aa", "phone")], &[]);
    assert!(store::resolve_devices(&db2, &spoof).unwrap()[0].new);
    remove_db(&db);
    remove_db(&db2);
}

#[test]
fn an_imported_list_drives_unknown_device_alerts_once_enabled() {
    let db = temp_db("alerts");
    let list = parse_ok(
        Kind::Csv,
        "mac,hostname\naa:bb:cc:00:00:01,plc-1\naa:bb:cc:00:00:02,plc-2\n",
    );
    merge(&db, &list, 1000).unwrap();
    assert!(
        baseline::enable(&temp_db("nothing"), 1)
            .unwrap_err()
            .contains("No device is expected"),
        "an empty database has nothing to expect"
    );
    assert_eq!(baseline::enable(&db, 1500).unwrap(), 2);
    let cur = snapshot(vec![
        host("10.1.0.5", "AA:BB:CC:00:00:01", "plc-1"),
        host("10.1.0.6", "AA:BB:CC:00:00:02", "plc-2"),
        host("10.1.0.9", "AA:BB:CC:00:00:09", "newcomer"),
    ]);
    let devices = crate::devices::merge(&cur.hosts, &cur.observations);
    let matches = store::resolve_devices(&db, &devices).unwrap();
    let ctx = Context {
        keys: crate::identity::key_map(&devices, &matches),
        baseline: Some(baseline::load(&db).unwrap()),
    };
    let known = store::known_devices(&db).unwrap();
    let alerts = monitor::evaluate_with(None, &cur, &known, &Policy::default(), &ctx, 2000);
    let unknown: Vec<_> = alerts
        .iter()
        .filter(|a| a.kind == "unknown-device")
        .collect();
    assert_eq!(unknown.len(), 1, "{alerts:?}");
    assert_eq!(unknown[0].subject, "AA:BB:CC:00:00:09");
    remove_db(&db);
}

#[test]
fn the_fuzz_seeds_are_real_files_that_parse() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../fuzz/corpus/import_inventory");
    let mut n = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        let kind = Kind::ALL[usize::from(bytes[0]) % Kind::ALL.len()];
        let i = parse(kind, &bytes[1..]).unwrap();
        assert!(!i.devices.is_empty(), "{kind:?}");
        n += 1;
    }
    assert_eq!(n, 8, "one seed per kind plus the XML form");
}
