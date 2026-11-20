//! Niagara Fox (TCP 1911): the text messages `fox a <id> -1 <service> <command>` with a
//! `{ key=type:value ... };;` body. A hello from a station names the device (host name,
//! application, VM and OS versions, station name); a hello from a client names the tool. Fox
//! carries no command this decoder can call a write, so nothing is flagged as control traffic.
use super::{Proto, Tracker};
use crate::ot::extra::parse_fox_hello;
use std::net::IpAddr;

/// The service and command of the first line: `fox hello` of `fox a 1 -1 fox hello`.
fn command(first: &str) -> Option<String> {
    let mut parts = first.splitn(5, ' ');
    let (magic, _kind, _id, _channel) =
        (parts.next()?, parts.next()?, parts.next()?, parts.next()?);
    let rest = parts.next()?;
    if magic != "fox" {
        return None;
    }
    let rest: String = rest
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(40)
        .collect();
    (!rest.is_empty()).then_some(rest)
}

impl Tracker {
    pub(super) fn fox(
        &mut self,
        client: IpAddr,
        server: IpAddr,
        pl: &[u8],
        ts: i64,
        to_server: bool,
    ) {
        let first = pl
            .split(|b| *b == b'\n')
            .next()
            .and_then(|l| std::str::from_utf8(l.get(..l.len().min(200))?).ok());
        // Anything that does not open with a Fox message line is not decoded.
        if !first.is_some_and(|l| l.starts_with("fox ")) {
            return;
        }
        let name = first.and_then(command);
        let hello = name.as_deref() == Some("fox hello");
        let fields = if hello {
            parse_fox_hello(pl).ok()
        } else {
            None
        };
        if to_server {
            let functions = name.map(|n| (n, false));
            self.request(Proto::Fox, client, server, ts, functions, None);
            if let Some(f) = fields
                && let Some(c) = self.client(Proto::Fox, client)
            {
                c.fields.extend(f);
            }
        } else if name.is_some() {
            self.response(Proto::Fox, server, client, ts);
            if let Some(f) = fields
                && let Some(s) = self.server(Proto::Fox, server)
            {
                s.fields.extend(f);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::otpassive::Tracker;
    use crate::otpassive::testutil::{HMI, PLC, frame, obs};

    #[test]
    fn hello_and_challenge_are_decoded_and_nothing_is_control() {
        let station = b"fox a 0 -1 fox hello\n{\nfox.version=s:1.0\nid=i:2\nhostName=s:jace\napp.name=s:Station\napp.version=s:4.8\nos.name=s:QNX\nstation.name=s:Plant1\nbrandId=s:acme\n};;\n";
        let client = b"fox a 1 -1 fox hello\n{\nfox.version=s:1.0\nid=i:1\nhostName=s:eng-pc\napp.name=s:Workbench\napp.version=s:4.8\n};;\n";
        let mut t = Tracker::new();
        t.feed(&frame(HMI, PLC, true, 40000, 1911, client), 1);
        t.feed(&frame(PLC, HMI, true, 1911, 40000, station), 2);
        t.feed(
            &frame(
                PLC,
                HMI,
                true,
                1911,
                40000,
                b"fox a 1 -1 fox challenge\n{\n};;\n",
            ),
            3,
        );
        let s = &obs(&t, "Niagara Fox server (observed)")[0];
        assert_eq!(s.fields["app_name"], "Station");
        assert_eq!(s.fields["station_name"], "Plant1");
        assert_eq!(s.fields["os_name"], "QNX");
        assert_eq!(s.fields["functions"], "fox hello x1");
        assert_eq!(s.fields["packets"], "3");
        let c = &obs(&t, "Niagara Fox client (observed)")[0];
        assert_eq!(c.fields["app_name"], "Workbench");
        assert!(!s.fields.contains_key("control_traffic"));
        // text that is not Fox is not a Fox message
        let mut t = Tracker::new();
        t.feed(
            &frame(HMI, PLC, true, 40000, 1911, b"GET / HTTP/1.1\r\n\r\n"),
            1,
        );
        t.feed(&frame(HMI, PLC, true, 40000, 1911, &[0xff; 20]), 2);
        assert!(t.observations().is_empty());
    }
}
