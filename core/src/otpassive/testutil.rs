//! Frame builders shared by the tests of the decoders.
use super::Tracker;
use crate::passive::Observation;

pub(super) fn frame(
    src: [u8; 4],
    dst: [u8; 4],
    tcp: bool,
    sport: u16,
    dport: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut f = vec![0u8; 12];
    f.extend([8, 0]);
    let l4_len = if tcp { 20 } else { 8 } + payload.len();
    let mut ip = vec![
        0x45,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        64,
        if tcp { 6 } else { 17 },
        0,
        0,
    ];
    ip.extend(src);
    ip.extend(dst);
    let total = (20 + l4_len) as u16;
    ip[2..4].copy_from_slice(&total.to_be_bytes());
    f.extend(ip);
    f.extend(sport.to_be_bytes());
    f.extend(dport.to_be_bytes());
    if tcp {
        f.extend([0; 8]);
        f.extend([0x50, 0x18, 0, 0, 0, 0, 0, 0]);
    } else {
        f.extend((l4_len as u16).to_be_bytes());
        f.extend([0, 0]);
    }
    f.extend(payload);
    f
}
pub(super) const HMI: [u8; 4] = [10, 0, 0, 50];
pub(super) const PLC: [u8; 4] = [10, 0, 0, 10];
pub(super) fn obs(t: &Tracker, protocol: &str) -> Vec<Observation> {
    t.observations()
        .into_iter()
        .filter(|o| o.protocol == protocol)
        .collect()
}
pub(super) fn s7(function: u8, rosctr: u8) -> Vec<u8> {
    let mut p = vec![3, 0, 0, 0, 2, 0xf0, 0x80];
    p.extend([0x32, rosctr, 0, 0, 0, 1, 0, 2, 0, 0, function, 1]);
    let n = p.len() as u16;
    p[2..4].copy_from_slice(&n.to_be_bytes());
    p
}
pub(super) fn cip_identity() -> Vec<u8> {
    let mut v = vec![1, 0];
    v.extend([0u8; 16]);
    v.extend(1u16.to_le_bytes()); // vendor 1: Rockwell
    v.extend(14u16.to_le_bytes());
    v.extend(166u16.to_le_bytes());
    v.extend([20, 11]);
    v.extend([0, 0]);
    v.extend(0xDEADBEEFu32.to_le_bytes());
    v.push(10);
    v.extend(b"1756-L81E ");
    v.push(3);
    let mut data = vec![1, 0, 0x0c, 0];
    data.extend((v.len() as u16).to_le_bytes());
    data.extend(v);
    let mut p = vec![
        0x63, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, b'N', b'E', b'T', b'S', b'C', b'O', b'P', b'E', 0,
        0, 0, 0,
    ];
    p[2..4].copy_from_slice(&(data.len() as u16).to_le_bytes());
    p.extend(data);
    p
}
pub(super) fn cip_send_rr(service: u8) -> Vec<u8> {
    let mut p = vec![
        0x6f, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    p.extend([
        0, 0, 0, 0, 5, 0, 2, 0, 0, 0, 0, 0, 0xb2, 0, 4, 0, service, 1, 0x20, 0x06,
    ]);
    p
}
pub(super) fn bvlc(npdu_control: u8, extra: &[u8], apdu: &[u8], function: u8) -> Vec<u8> {
    let mut p = vec![0x81, function, 0, 0, 1, npdu_control];
    p.extend(extra);
    p.extend(apdu);
    let n = p.len() as u16;
    p[2..4].copy_from_slice(&n.to_be_bytes());
    p
}
/// A TCP frame with sequence number and flags (0x18 PSH/ACK, 0x11 FIN/ACK, 0x04 RST).
pub(super) fn seg(
    src: [u8; 4],
    dst: [u8; 4],
    dport: u16,
    seq: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut f = frame(src, dst, true, 50000, dport, payload);
    let tcp = 14 + 20;
    f[tcp + 4..tcp + 8].copy_from_slice(&seq.to_be_bytes());
    f[tcp + 13] = flags;
    f
}
pub(super) fn modbus_write() -> Vec<u8> {
    // Write Multiple Registers (16), unit 7: MBAP length 11
    vec![0, 9, 0, 0, 0, 11, 7, 16, 0, 1, 0, 2, 4, 0, 1, 0, 2]
}
pub(super) fn control(t: &Tracker, protocol: &str) -> Option<String> {
    obs(t, protocol)
        .first()
        .and_then(|o| o.fields.get("control_traffic").cloned())
}
