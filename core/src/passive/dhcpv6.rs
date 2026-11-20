//! DHCPv6 client messages (RFC 8415, UDP 546 to 547): the DUID (option 1), the option request
//! list (option 6), the vendor class (option 16, RFC 8415 21.16) and the client FQDN (option 39,
//! RFC 4704). Server and relay messages are ignored: their sender is not the client. Passive
//! decoding only; nothing here transmits.
use super::{MAX_CLIENT_ID, MAX_PARAMETER_LIST, Observation, be16, hints, mac, text};

/// Client message types (RFC 8415 7.3) by name.
fn client_message(kind: u8) -> Option<&'static str> {
    Some(match kind {
        1 => "solicit",
        3 => "request",
        4 => "confirm",
        5 => "renew",
        6 => "rebind",
        8 => "release",
        9 => "decline",
        11 => "information_request",
        _ => return None,
    })
}

/// Decodes the UDP payload of a message to port 547.
pub(super) fn decode(b: &[u8], o: &mut Observation) -> Option<()> {
    let kind = client_message(*b.first()?)?;
    if b.len() < 4 {
        return None;
    }
    o.protocol = "DHCPv6".into();
    o.fields.insert("message_type".into(), kind.into());
    let mut i = 4;
    // A truncated tail ends the loop but keeps what was read so far.
    while let (Some(code), Some(len)) = (be16(b, i), be16(b, i + 2)) {
        let Some(v) = b.get(i + 4..i + 4 + usize::from(len)) else {
            break;
        };
        i += 4 + usize::from(len);
        match code {
            1 if v.len() >= 2 => duid(v, o),
            6 => {
                let list: Vec<String> = v
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .take(MAX_PARAMETER_LIST)
                    .map(|c| u16::from_be_bytes(*c).to_string())
                    .collect();
                o.fields.insert("oro".into(), list.join(","));
            }
            16 if v.len() >= 4 => {
                o.fields.insert(
                    "vendor_enterprise".into(),
                    u32::from_be_bytes(v[..4].try_into().ok()?).to_string(),
                );
                // vendor-class-data: strings, each with a 2-byte length.
                let mut parts = vec![];
                let mut j = 4;
                while let Some(n) = be16(v, j).map(usize::from)
                    && let Some(s) = v.get(j + 2..j + 2 + n)
                    && parts.len() < 8
                {
                    parts.push(text(s));
                    j += 2 + n;
                }
                if !parts.is_empty() {
                    o.fields.insert("vendor_class".into(), parts.join(" "));
                }
            }
            39 if v.len() >= 2 => {
                let fqdn = fqdn(&v[1..]);
                if let Some(host) = fqdn.split('.').next().filter(|h| !h.is_empty()) {
                    o.fields.insert("hostname".into(), host.into());
                    o.fields.insert("fqdn".into(), fqdn.clone());
                }
            }
            _ => {}
        }
    }
    let hints = hints::dhcp(
        &[],
        o.fields.get("vendor_class").map_or("", String::as_str),
        o.fields.get("hostname").map_or("", String::as_str),
    );
    if let Some(os) = hints::dhcp_os(&hints) {
        o.fields.insert("os_hint".into(), os.into());
    }
    hints::attach(&mut o.fields, hints);
    Some(())
}

/// The DUID: kept whole as `client_id` (device identity uses it), with its type and the
/// link-layer address of a DUID-LLT or DUID-LL. That address may belong to another interface of
/// the host, so it is a field, never the observation's MAC.
fn duid(v: &[u8], o: &mut Observation) {
    o.fields.insert(
        "client_id".into(),
        v.iter()
            .take(MAX_CLIENT_ID)
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
    );
    let (kind, address) = match be16(v, 0) {
        Some(1) => ("LLT", v.get(8..).filter(|_| be16(v, 2) == Some(1))),
        Some(2) => {
            if let Some(n) = v.get(2..6) {
                o.fields.insert(
                    "duid_enterprise".into(),
                    u32::from_be_bytes([n[0], n[1], n[2], n[3]]).to_string(),
                );
            }
            ("EN", None)
        }
        Some(3) => ("LL", v.get(4..).filter(|_| be16(v, 2) == Some(1))),
        Some(4) => ("UUID", None),
        _ => return,
    };
    o.fields.insert("duid_type".into(), kind.into());
    if let Some(a) = address.filter(|a| a.len() == 6) {
        o.fields.insert("duid_mac".into(), mac(a));
    }
}

/// A domain name in uncompressed wire format that may lack the final zero (a partial name).
fn fqdn(b: &[u8]) -> String {
    let mut labels = vec![];
    let mut i = 0;
    while let Some(&n) = b.get(i)
        && n != 0
        && n <= 63
        && labels.len() < 16
    {
        let Some(label) = b.get(i + 1..i + 1 + usize::from(n)) else {
            break;
        };
        labels.push(text(label));
        i += 1 + usize::from(n);
    }
    labels.join(".")
}
