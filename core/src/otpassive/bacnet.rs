//! BACnet/IP: BVLC/NPDU/APDU parsing, I-Am and service names.
use super::{Proto, Tracker};
use std::net::IpAddr;

fn bacnet_service(s: u8) -> (String, bool) {
    let (n, c) = match s {
        12 => ("ReadProperty", false),
        14 => ("ReadPropertyMultiple", false),
        15 => ("WriteProperty", true),
        16 => ("WritePropertyMultiple", true),
        17 => ("DeviceCommunicationControl", true),
        20 => ("ReinitializeDevice", true),
        7 => ("AtomicWriteFile", true),
        _ => return (format!("confirmed service {s}"), false),
    };
    (n.to_string(), c)
}

/// (APDU type, service choice, bytes after the service choice) of a BACnet/IP datagram.
fn bacnet_apdu(b: &[u8]) -> Option<(u8, u8, &[u8])> {
    if b.first() != Some(&0x81) || !matches!(b.get(1)?, 0x0a | 0x0b | 0x04) {
        return None;
    }
    let mut i = if b[1] == 0x04 { 10 } else { 4 };
    if *b.get(i)? != 1 {
        return None;
    }
    let control = *b.get(i + 1)?;
    i += 2;
    if control & 0x20 != 0 {
        i += 3 + usize::from(*b.get(i + 2)?);
    }
    if control & 0x08 != 0 {
        i += 3 + usize::from(*b.get(i + 2)?);
    }
    if control & 0x20 != 0 {
        i += 1;
    }
    if control & 0x80 != 0 {
        return None;
    }
    let apdu = b.get(i..)?;
    let kind = apdu.first()? >> 4;
    match kind {
        0 => {
            let skip = if apdu[0] & 0x08 != 0 { 5 } else { 3 };
            Some((0, *apdu.get(skip)?, apdu.get(skip + 1..)?))
        }
        1 => Some((1, *apdu.get(1)?, apdu.get(2..)?)),
        _ => None,
    }
}
fn bacnet_iam(b: &[u8]) -> Option<(u32, u32)> {
    let mut i = 0;
    let mut value = |tag: u8| -> Option<u32> {
        let t = *b.get(i)?;
        i += 1;
        let n = usize::from(t & 7);
        if t >> 4 != tag || t & 8 != 0 || !(1..=4).contains(&n) {
            return None;
        }
        let v = b
            .get(i..i + n)?
            .iter()
            .fold(0u32, |a, v| (a << 8) | u32::from(*v));
        i += n;
        Some(v)
    };
    let object = value(12)?;
    if object >> 22 != 8 {
        return None;
    }
    value(2)?;
    value(9)?;
    Some((object & 0x3f_ffff, value(2)?))
}

impl Tracker {
    pub(super) fn bacnet(&mut self, src: IpAddr, dst: IpAddr, pl: &[u8], ts: i64) {
        let Some((kind, service, rest)) = bacnet_apdu(pl) else {
            return;
        };
        match kind {
            1 if service == 0 => {
                // I-Am: the sender is a BACnet device.
                if let Some(s) = self.server(Proto::Bacnet, src) {
                    s.touch(ts, None);
                    if let Some((device, vendor)) = bacnet_iam(rest) {
                        s.fields.insert("device_id".into(), device.to_string());
                        s.fields.insert("vendor_id".into(), vendor.to_string());
                    }
                }
            }
            1 => {
                let name = match service {
                    8 => "Who-Is",
                    7 => "Who-Has",
                    other => {
                        return self.bacnet_client(
                            src,
                            ts,
                            format!("unconfirmed service {other}"),
                            false,
                        );
                    }
                };
                self.bacnet_client(src, ts, name.to_string(), false);
            }
            0 => {
                // A broadcast destination only records the client (see `request`).
                self.request(
                    Proto::Bacnet,
                    src,
                    dst,
                    ts,
                    Some(bacnet_service(service)),
                    None,
                );
            }
            _ => {}
        }
    }
    fn bacnet_client(&mut self, ip: IpAddr, ts: i64, name: String, control: bool) {
        if let Some(c) = self.client(Proto::Bacnet, ip) {
            c.touch(ts, None);
            c.function(&name, control);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::otpassive::Tracker;
    use crate::otpassive::testutil::{HMI, PLC, bvlc, frame, obs};

    #[test]
    fn bacnet_iam_with_global_broadcast_destination_and_writes() {
        let mut t = Tracker::new();
        // I-Am broadcast: NPDU destination = global broadcast (dnet 0xffff, dlen 0) plus hop count.
        let iam = [
            0x10, 0x00, 0xc4, 0x02, 0x00, 0x03, 0xe8, 0x22, 0x05, 0xc4, 0x91, 0x00, 0x21, 0x0f,
        ];
        t.feed(
            &frame(
                PLC,
                [10, 0, 0, 255],
                false,
                47808,
                47808,
                &bvlc(0x20, &[0xff, 0xff, 0, 255], &iam, 0x0b),
            ),
            20,
        );
        let s = &obs(&t, "BACnet/IP server (observed)")[0];
        assert_eq!(s.fields["device_id"], "1000");
        assert_eq!(s.fields["vendor_id"], "15");
        // WriteProperty (confirmed request, service 15) sent unicast to the device.
        let write = [0x00, 0x05, 0x01, 0x0f, 0x0c, 0x00, 0x00, 0x00, 0x01];
        t.feed(
            &frame(HMI, PLC, false, 47808, 47808, &bvlc(0, &[], &write, 0x0a)),
            21,
        );
        let s = &obs(&t, "BACnet/IP server (observed)")[0];
        assert_eq!(s.fields["control_traffic"], "WriteProperty x1");
        // Who-Is makes the sender a client, not a server.
        t.feed(
            &frame(
                HMI,
                [10, 0, 0, 255],
                false,
                47808,
                47808,
                &bvlc(0x20, &[0xff, 0xff, 0, 255], &[0x10, 0x08], 0x0b),
            ),
            22,
        );
        assert!(
            obs(&t, "BACnet/IP client (observed)")
                .iter()
                .any(|c| c.fields["functions"].contains("Who-Is"))
        );
        assert_eq!(obs(&t, "BACnet/IP server (observed)").len(), 1);
    }
}
