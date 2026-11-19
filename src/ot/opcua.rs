//! Sessionless UA Binary discovery using SecurityPolicy None; no authentication or writes.
use super::{AsyncReadExt, AsyncWriteExt, Fields, TcpStream};
use crate::core::Gate;
use std::net::IpAddr;
const POLICY: &str = "http://opcfoundation.org/UA/SecurityPolicy#None";
fn u32le(b: &mut Vec<u8>, v: u32) {
    b.extend_from_slice(&v.to_le_bytes());
}
fn string(b: &mut Vec<u8>, v: &str) {
    u32le(b, v.len() as u32);
    b.extend_from_slice(v.as_bytes());
}
fn node(b: &mut Vec<u8>, id: u16) {
    b.extend_from_slice(&[1, 0]);
    b.extend_from_slice(&id.to_le_bytes());
}
fn request(id: u16, handle: u32) -> Vec<u8> {
    let mut b = vec![];
    node(&mut b, id);
    b.extend_from_slice(&[0, 0]);
    let ticks = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        / 100
        + 116444736000000000) as u64;
    b.extend_from_slice(&ticks.to_le_bytes());
    u32le(&mut b, handle);
    u32le(&mut b, 0);
    u32le(&mut b, u32::MAX);
    u32le(&mut b, 5000);
    b.extend_from_slice(&[0, 0, 0]);
    b
}
struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}
impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, i: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.i.checked_add(n).ok_or("UA length overflow")?;
        let b = self.b.get(self.i..end).ok_or("Truncated UA response")?;
        self.i = end;
        Ok(b)
    }
    fn byte(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    fn word(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn count(&mut self) -> Result<usize, String> {
        let n = self.word()?;
        if n == u32::MAX {
            return Ok(0);
        }
        if n > 4096 {
            return Err("UA array exceeds limit".into());
        }
        Ok(n as usize)
    }
    fn bytes(&mut self) -> Result<&'a [u8], String> {
        let n = self.word()?;
        if n == u32::MAX {
            return Ok(&[]);
        }
        if n > 1_048_576 {
            return Err("UA string exceeds limit".into());
        }
        self.take(n as usize)
    }
    fn string(&mut self) -> Result<String, String> {
        Ok(String::from_utf8_lossy(self.bytes()?).into_owned())
    }
    fn node(&mut self) -> Result<u32, String> {
        match self.byte()? {
            0 => Ok(self.byte()? as u32),
            1 => {
                let ns = self.byte()?;
                let id = u16::from_le_bytes(self.take(2)?.try_into().unwrap());
                if ns != 0 {
                    return Err("Nonstandard UA namespace".into());
                }
                Ok(id as u32)
            }
            2 => {
                self.take(2)?;
                self.word()
            }
            _ => Err("Unsupported UA NodeId encoding".into()),
        }
    }
    fn extension(&mut self) -> Result<(), String> {
        self.node()?;
        let enc = self.byte()?;
        if enc != 0 {
            self.bytes()?;
        }
        Ok(())
    }
    fn localized(&mut self) -> Result<String, String> {
        let m = self.byte()?;
        if m & 1 != 0 {
            self.string()?;
        }
        if m & 2 != 0 {
            self.string()
        } else {
            Ok(String::new())
        }
    }
    fn diagnostic(&mut self, depth: usize) -> Result<(), String> {
        if depth > 16 {
            return Err("UA diagnostic nesting limit".into());
        }
        let m = self.byte()?;
        for bit in [1, 2, 4, 8] {
            if m & bit != 0 {
                self.word()?;
            }
        }
        if m & 16 != 0 {
            self.string()?;
        }
        if m & 32 != 0 {
            self.word()?;
        }
        if m & 64 != 0 {
            self.diagnostic(depth + 1)?;
        }
        Ok(())
    }
    fn response(&mut self, expected: u32, handle: u32) -> Result<(), String> {
        let ty = self.node()?;
        self.take(8)?;
        let actual = self.word()?;
        let status = self.word()?;
        if actual != handle {
            return Err("UA request handle mismatch".into());
        }
        if status & 0x80000000 != 0 {
            return Err(format!("UA service returned 0x{status:08x}"));
        }
        if ty != expected {
            return Err(format!("Unexpected UA response type {ty}"));
        }
        self.diagnostic(0)?;
        for _ in 0..self.count()? {
            self.string()?;
        }
        self.extension()
    }
    fn application(&mut self) -> Result<Fields, String> {
        let uri = self.string()?;
        let product = self.string()?;
        let name = self.localized()?;
        let kind = self.word()?;
        self.string()?;
        self.string()?;
        let mut urls = vec![];
        for _ in 0..self.count()? {
            urls.push(self.string()?);
        }
        Ok(Fields::from([
            ("name".into(), name),
            ("application_uri".into(), uri),
            ("product_uri".into(), product),
            ("application_type".into(), kind.to_string()),
            ("discovery_urls".into(), urls.join(", ")),
        ]))
    }
}
/// Body of an ERR message: the status code and reason, as the error text.
pub(crate) fn transport_error(b: &[u8]) -> Result<String, String> {
    let mut r = Reader::new(b);
    let status = r.word()?;
    Ok(format!(
        "UA transport error 0x{status:08x}: {}",
        r.string()?
    ))
}
/// OpenSecureChannel response body: (channel ID, token ID).
pub(crate) fn parse_open(b: &[u8]) -> Result<(u32, u32), String> {
    let mut r = Reader::new(b);
    let channel = r.word()?;
    if r.string()? != POLICY {
        return Err("Server did not permit an unsecured discovery channel".into());
    }
    r.bytes()?;
    r.bytes()?;
    r.word()?;
    if r.word()? != 1 {
        return Err("UA open request mismatch".into());
    }
    r.response(449, 1)?;
    r.word()?;
    if r.word()? != channel {
        return Err("UA channel ID mismatch".into());
    }
    let token = r.word()?;
    r.take(12)?;
    r.bytes()?;
    Ok((channel, token))
}
/// GetEndpoints response (request ID 2).
pub(crate) fn parse_endpoints(b: &[u8]) -> Result<Fields, String> {
    let mut r = Reader::new(b);
    r.response(431, 2)?;
    let mut fields = Fields::new();
    let n = r.count()?;
    fields.insert("endpoint_count".into(), n.to_string());
    for index in 0..n {
        let prefix = format!("endpoint_{index}");
        fields.insert(format!("{prefix}.url"), r.string()?);
        for (k, v) in r.application()? {
            fields.insert(format!("{prefix}.{k}"), v);
        }
        let cert = r.bytes()?;
        if !cert.is_empty() {
            fields.insert(
                format!("{prefix}.certificate_der_hex"),
                cert.iter().map(|b| format!("{b:02x}")).collect(),
            );
        }
        fields.insert(format!("{prefix}.security_mode"), r.word()?.to_string());
        fields.insert(format!("{prefix}.security_policy"), r.string()?);
        for _ in 0..r.count()? {
            r.string()?;
            r.word()?;
            r.string()?;
            r.string()?;
            r.string()?;
        }
        fields.insert(format!("{prefix}.transport"), r.string()?);
        fields.insert(format!("{prefix}.security_level"), r.byte()?.to_string());
    }
    Ok(fields)
}
/// FindServers response (request ID 3).
pub(crate) fn parse_servers(b: &[u8]) -> Result<Fields, String> {
    let mut r = Reader::new(b);
    r.response(425, 3)?;
    let mut f = Fields::new();
    for i in 0..r.count()? {
        for (k, v) in r.application()? {
            f.insert(format!("server_{i}.{k}"), v);
        }
    }
    Ok(f)
}
async fn send(s: &mut TcpStream, kind: &[u8; 4], body: &[u8]) -> Result<(), String> {
    let mut b = kind.to_vec();
    u32le(&mut b, (body.len() + 8) as u32);
    b.extend_from_slice(body);
    s.write_all(&b).await.map_err(|e| e.to_string())
}
async fn receive(s: &mut TcpStream) -> Result<([u8; 4], Vec<u8>), String> {
    let mut h = [0; 8];
    s.read_exact(&mut h).await.map_err(|e| e.to_string())?;
    let n = u32::from_le_bytes(h[4..].try_into().unwrap()) as usize;
    if !(8..=65536).contains(&n) {
        return Err("UA chunk size exceeds negotiated limit".into());
    }
    let mut b = vec![0; n - 8];
    s.read_exact(&mut b).await.map_err(|e| e.to_string())?;
    if &h[..3] == b"ERR" {
        return Err(transport_error(&b)?);
    }
    Ok((h[..4].try_into().unwrap(), b))
}
async fn service(
    s: &mut TcpStream,
    channel: u32,
    token: u32,
    sequence: u32,
    body: &[u8],
) -> Result<Vec<u8>, String> {
    let mut b = vec![];
    for v in [channel, token, sequence, sequence] {
        u32le(&mut b, v);
    }
    b.extend_from_slice(body);
    send(s, b"MSGF", &b).await?;
    let mut result = vec![];
    for _ in 0..32 {
        let (kind, b) = receive(s).await?;
        if &kind[..3] != b"MSG" || !b"CF".contains(&kind[3]) {
            return Err("Unexpected or aborted UA chunk".into());
        }
        let mut r = Reader::new(&b);
        if r.word()? != channel || r.word()? != token {
            return Err("UA channel mismatch".into());
        }
        r.word()?;
        if r.word()? != sequence {
            return Err("UA request ID mismatch".into());
        }
        result.extend_from_slice(&b[r.i..]);
        if result.len() > 1_048_576 {
            return Err("UA message exceeds limit".into());
        }
        if kind[3] == b'F' {
            return Ok(result);
        }
    }
    Err("Too many UA chunks".into())
}
pub async fn discover(ip: IpAddr, gate: &Gate) -> Result<Fields, String> {
    let url = format!(
        "opc.tcp://{}:4840",
        if ip.is_ipv6() {
            format!("[{ip}]")
        } else {
            ip.to_string()
        }
    );
    let s = TcpStream::connect((ip, 4840))
        .await
        .map_err(|e| e.to_string())?;
    discover_stream(s, &url, gate).await
}
async fn discover_stream(mut s: TcpStream, url: &str, gate: &Gate) -> Result<Fields, String> {
    let mut hello = vec![];
    for v in [0, 65536, 65536, 1_048_576, 32] {
        u32le(&mut hello, v);
    }
    string(&mut hello, url);
    send(&mut s, b"HELF", &hello).await?;
    let (kind, _) = receive(&mut s).await?;
    if &kind != b"ACKF" {
        return Err("UA hello rejected".into());
    }
    gate.wait().await;
    let mut open = vec![];
    u32le(&mut open, 0);
    string(&mut open, POLICY);
    u32le(&mut open, u32::MAX);
    u32le(&mut open, u32::MAX);
    u32le(&mut open, 1);
    u32le(&mut open, 1);
    open.extend_from_slice(&request(446, 1));
    for v in [0, 0, 1, u32::MAX, 60000] {
        u32le(&mut open, v);
    }
    send(&mut s, b"OPNF", &open).await?;
    let (kind, b) = receive(&mut s).await?;
    if &kind != b"OPNF" {
        return Err("UA discovery channel rejected".into());
    }
    let (channel, token) = parse_open(&b)?;
    gate.wait().await;
    let mut req = request(428, 2);
    string(&mut req, url);
    u32le(&mut req, 0);
    u32le(&mut req, 0);
    let b = service(&mut s, channel, token, 2, &req).await?;
    let mut fields = parse_endpoints(&b)?;
    gate.wait().await;
    let mut req = request(422, 3);
    string(&mut req, url);
    u32le(&mut req, 0);
    u32le(&mut req, 0);
    match service(&mut s, channel, token, 3, &req).await {
        Ok(b) => match parse_servers(&b) {
            Ok(f) => fields.extend(f),
            Err(e) => {
                fields.insert("find_servers_error".into(), e);
            }
        },
        Err(e) => {
            fields.insert("find_servers_error".into(), e);
        }
    }
    // CloseSecureChannel has no response.
    let mut close = vec![];
    for v in [channel, token, 4, 4] {
        u32le(&mut close, v);
    }
    close.extend_from_slice(&request(452, 4));
    let _ = send(&mut s, b"CLOF", &close).await;
    Ok(fields)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn response(id: u16, handle: u32) -> Vec<u8> {
        let mut b = vec![];
        node(&mut b, id);
        b.extend_from_slice(&[0; 8]);
        u32le(&mut b, handle);
        u32le(&mut b, 0);
        b.push(0);
        u32le(&mut b, 0);
        b.extend_from_slice(&[0, 0, 0]);
        b
    }
    fn app(b: &mut Vec<u8>) {
        string(b, "urn:fixture:plc");
        string(b, "urn:vendor:product");
        b.push(2);
        string(b, "Fixture PLC");
        u32le(b, 0);
        string(b, "");
        string(b, "");
        u32le(b, 1);
        string(b, "opc.tcp://localhost:4840");
    }
    #[tokio::test]
    async fn real_discovery_transport_and_chunked_endpoints() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let (kind, _) = receive(&mut s).await.unwrap();
            assert_eq!(&kind, b"HELF");
            send(&mut s, b"ACKF", &[0; 20]).await.unwrap();
            let (kind, b) = receive(&mut s).await.unwrap();
            assert_eq!(&kind, b"OPNF");
            let mut r = Reader::new(&b);
            assert_eq!(r.word().unwrap(), 0);
            assert_eq!(r.string().unwrap(), POLICY);
            r.bytes().unwrap();
            r.bytes().unwrap();
            r.take(8).unwrap();
            assert_eq!(r.node().unwrap(), 446);
            let mut b = vec![];
            u32le(&mut b, 42);
            string(&mut b, POLICY);
            u32le(&mut b, u32::MAX);
            u32le(&mut b, u32::MAX);
            u32le(&mut b, 1);
            u32le(&mut b, 1);
            b.extend(response(449, 1));
            for v in [0, 42, 77, 0, 0, 60000, u32::MAX] {
                u32le(&mut b, v);
            }
            send(&mut s, b"OPNF", &b).await.unwrap();
            let (kind, b) = receive(&mut s).await.unwrap();
            assert_eq!(&kind, b"MSGF");
            assert_eq!(Reader::new(&b[16..]).node().unwrap(), 428);
            let mut body = response(431, 2);
            u32le(&mut body, 1);
            string(&mut body, "opc.tcp://localhost:4840");
            app(&mut body);
            u32le(&mut body, 3);
            body.extend_from_slice(&[1, 2, 3]);
            u32le(&mut body, 1);
            string(&mut body, POLICY);
            u32le(&mut body, 0);
            string(&mut body, "ua-tcp");
            body.push(0);
            let half = body.len() / 2;
            for (part, kind) in [(&body[..half], b"MSGC"), (&body[half..], b"MSGF")] {
                let mut chunk = vec![];
                for v in [42, 77, 2, 2] {
                    u32le(&mut chunk, v);
                }
                chunk.extend_from_slice(part);
                send(&mut s, kind, &chunk).await.unwrap();
            }
            let (_, b) = receive(&mut s).await.unwrap();
            assert_eq!(Reader::new(&b[16..]).node().unwrap(), 422);
            let mut b = vec![];
            for v in [42, 77, 4, 3] {
                u32le(&mut b, v);
            }
            b.extend(response(425, 3));
            u32le(&mut b, 1);
            app(&mut b);
            send(&mut s, b"MSGF", &b).await.unwrap();
            assert_eq!(&receive(&mut s).await.unwrap().0, b"CLOF");
        });
        let socket = TcpStream::connect(address).await.unwrap();
        let fields = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            discover_stream(socket, "opc.tcp://localhost:4840", &Gate::new(0)),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(fields["endpoint_0.name"], "Fixture PLC");
        assert_eq!(fields["endpoint_0.certificate_der_hex"], "010203");
        assert_eq!(fields["server_0.name"], "Fixture PLC");
        server.await.unwrap();
    }
    #[test]
    fn rejects_unbounded_lengths_and_truncation() {
        assert!(Reader::new(&[0xff, 0xff, 0xff, 0x7f]).bytes().is_err());
        assert!(Reader::new(&[1, 0, 0, 0]).string().is_err());
        assert!(Reader::new(&[1]).node().is_err());
    }
}
