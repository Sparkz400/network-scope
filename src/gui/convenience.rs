//! Everyday conveniences (ROADMAP F38): the host context menu with openers (browser, SSH, remote
//! desktop, ping in a terminal), favorites (stars) and Wake-on-LAN.
//!
//! **Openers launch programs the user asked for, never through a shell.** A command line is built
//! as a program name plus a list of arguments ([`Command`]) and started with
//! `std::process::Command`, so no quoting is interpreted. The host that goes into it is checked
//! first ([`valid_host`]): an IP address or a plain host name made of letters, digits, `-`, `_`
//! and dots, never starting with `-` (which a program could read as an option) and never
//! containing anything else. URLs are built from a checked host and a port number.
//!
//! **Favorites** are kept in the preferences file (`preferences.json`, the field `starred`), not
//! in the inventory database: they are a view setting of this computer, not scan data, so they
//! need no database migration. A device is keyed by its MAC address when it has one (so a star
//! follows it across address changes), else by its IP address.
//!
//! **Wake-on-LAN** is a send: only the explicit "Send" in its dialog sends one magic packet
//! ([`crate::wol`]), through the rate gate with the packet kind `wake-on-lan`, after the scope
//! guard looked at the destination.
use super::{i18n::tr, *};
use crate::{localnets, wol};
use std::net::Ipv4Addr;

/// The operating system, as far as openers differ.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Os {
    Windows,
    Apple,
    Linux,
}
impl Os {
    pub fn current() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else if cfg!(target_os = "macos") {
            Self::Apple
        } else {
            Self::Linux
        }
    }
}

/// A program and its arguments, started without a shell.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Command {
    pub program: String,
    pub args: Vec<String>,
    /// Windows: give the program its own console window (for `ping`).
    pub new_console: bool,
}
impl Command {
    fn new(program: &str, args: &[&str]) -> Self {
        Self {
            program: program.into(),
            args: args.iter().map(ToString::to_string).collect(),
            new_console: false,
        }
    }
}

/// The host unchanged when it is an IP address or a valid host name; `None` otherwise.
pub(super) fn valid_host(host: &str) -> Option<String> {
    if host.parse::<IpAddr>().is_ok() {
        return Some(host.to_string());
    }
    if host.is_empty() || host.len() > 253 {
        return None;
    }
    let label_ok = |l: &str| {
        (1..=63).contains(&l.len())
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    };
    host.split('.').all(label_ok).then(|| host.to_string())
}

/// `http://host:port/` or `https://host:port/` for a valid host; the port is left out when it is
/// the scheme's default. IPv6 addresses are put in brackets.
pub(super) fn web_url(https: bool, host: &str, port: u16) -> Option<String> {
    let host = valid_host(host)?;
    if port == 0 {
        return None;
    }
    let shown = if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host
    };
    let default = if https { 443 } else { 80 };
    Some(format!(
        "{}://{shown}{}/",
        if https { "https" } else { "http" },
        if port == default {
            String::new()
        } else {
            format!(":{port}")
        }
    ))
}

/// `ssh://host` (the operating system opens its registered SSH handler).
pub(super) fn ssh_url(host: &str) -> Option<String> {
    let host = valid_host(host)?;
    Some(if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("ssh://[{host}]")
    } else {
        format!("ssh://{host}")
    })
}

/// The command that opens a remote desktop connection: `mstsc` on Windows, the `rdp://` handler
/// elsewhere. `None` for an invalid host (and for an IPv6 address on Windows, which `mstsc /v:`
/// does not take in a form that can be checked here).
pub(super) fn rdp_command(os: Os, host: &str) -> Option<Command> {
    let host = valid_host(host)?;
    let v6 = host.parse::<std::net::Ipv6Addr>().is_ok();
    match os {
        Os::Windows if v6 => None,
        Os::Windows => Some(Command::new("mstsc.exe", &[&format!("/v:{host}")])),
        Os::Apple => Some(Command::new(
            "open",
            &[&format!("rdp://{}", bracket(&host, v6))],
        )),
        Os::Linux => Some(Command::new(
            "xdg-open",
            &[&format!("rdp://{}", bracket(&host, v6))],
        )),
    }
}
fn bracket(host: &str, v6: bool) -> String {
    if v6 {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

/// Commands that run `ping` in a terminal window, best first; the caller starts the first one
/// that can be launched. Empty for an invalid host.
pub(super) fn ping_commands(os: Os, host: &str) -> Vec<Command> {
    let Some(host) = valid_host(host) else {
        return vec![];
    };
    match os {
        Os::Windows => vec![Command {
            program: "ping.exe".into(),
            args: vec!["-t".into(), host],
            new_console: true,
        }],
        Os::Apple => vec![Command::new(
            "osascript",
            &[
                "-e",
                &format!("tell application \"Terminal\" to do script \"ping {host}\""),
                "-e",
                "tell application \"Terminal\" to activate",
            ],
        )],
        Os::Linux => vec![
            Command::new("x-terminal-emulator", &["-e", "ping", &host]),
            Command::new("gnome-terminal", &["--", "ping", &host]),
            Command::new("konsole", &["-e", "ping", &host]),
            Command::new("xterm", &["-e", "ping", &host]),
        ],
    }
}

/// Starts the first command that launches. The standard streams are closed so the child cannot
/// write into this program's console.
pub(super) fn launch(commands: &[Command]) -> Result<(), String> {
    let mut last = "nothing to start".to_string();
    for c in commands {
        let mut cmd = std::process::Command::new(&c.program);
        cmd.args(&c.args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        #[cfg(windows)]
        if c.new_console {
            use std::os::windows::process::CommandExt;
            // CREATE_NEW_CONSOLE
            cmd.creation_flags(0x0000_0010);
        }
        match cmd.spawn() {
            Ok(_) => return Ok(()),
            Err(e) => last = format!("{}: {e}", c.program),
        }
    }
    Err(last)
}

/// TCP ports of a host that a browser can open: `(https, port)`, at most `limit`.
pub(super) fn web_ports(host: &scan::Host, limit: usize) -> Vec<(bool, u16)> {
    let mut out: Vec<(bool, u16)> = vec![];
    for &p in &host.open {
        let service = host
            .identity
            .get(&format!("svc.{p}"))
            .map(|s| s.to_lowercase())
            .unwrap_or_default();
        let https = matches!(p, 443 | 8443 | 4443 | 9443)
            || service.contains("https")
            || service.contains("tls");
        let http = matches!(p, 80 | 8000 | 8008 | 8080 | 8888) || service.starts_with("http");
        if (https || http) && !out.iter().any(|(_, q)| *q == p) {
            out.push((https, p));
        }
    }
    out.truncate(limit);
    out
}

/// The URL schemes the app hands to the operating system.
const URL_SCHEMES: [&str; 4] = ["https", "http", "ssh", "rdp"];

/// Whether `url` may be opened: one of [`URL_SCHEMES`], no spaces, control characters, quotes or
/// other characters a command line could misread, at most 2,048 bytes, no user name or password,
/// and a valid host (see [`valid_host`]) with an optional port.
pub(super) fn valid_url(url: &str) -> bool {
    if url.is_empty() || url.len() > 2048 {
        return false;
    }
    if url
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || "\"'`<>|^\\{}".contains(c))
    {
        return false;
    }
    let Some((scheme, rest)) = url.split_once("://") else {
        return false;
    };
    if !URL_SCHEMES.contains(&scheme) {
        return false;
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        return false;
    }
    let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
        let Some((addr, after)) = inner.split_once(']') else {
            return false;
        };
        if addr.parse::<std::net::Ipv6Addr>().is_err() {
            return false;
        }
        (addr, after.strip_prefix(':'))
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        }
    };
    let port_ok =
        port.is_none_or(|p| !p.is_empty() && p.len() <= 5 && p.chars().all(|c| c.is_ascii_digit()));
    port_ok && valid_host(host).is_some()
}

/// The command that opens `url` in the program registered for it (the default browser for
/// `http` and `https`): `rundll32 url.dll,FileProtocolHandler URL` on Windows, `open URL` on
/// macOS, `xdg-open URL` elsewhere. The URL is the last argument and has been checked by
/// [`valid_url`], so it cannot be read as an option or split into several arguments. `None` for
/// a URL that is not valid.
pub(super) fn open_command(os: Os, url: &str) -> Option<Command> {
    if !valid_url(url) {
        return None;
    }
    Some(match os {
        Os::Windows => Command::new("rundll32.exe", &["url.dll,FileProtocolHandler", url]),
        Os::Apple => Command::new("open", &[url]),
        Os::Linux => Command::new("xdg-open", &[url]),
    })
}

thread_local! {
    /// The reason the last link could not be opened; the window shows it on the next frame.
    static LINK_ERROR: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}
/// Takes the error of a link that could not be opened.
pub(super) fn take_link_error() -> Option<String> {
    LINK_ERROR.with(|e| e.borrow_mut().take())
}

/// Opens `url` in the default program (the browser for web links). eframe is built without its
/// `links` feature (it would add the `webbrowser` crate), so `ctx.open_url` would do nothing:
/// this is the opener the whole app uses.
pub(super) fn open_url(url: &str) -> Result<(), String> {
    let command =
        open_command(Os::current(), url).ok_or_else(|| tr!("The link is not valid: {}", url))?;
    launch(&[command])
}

/// A link that opens in the default browser when clicked; the address is the tooltip. A failure
/// is reported in the error line of the window.
pub(super) fn link_to(
    ui: &mut egui::Ui,
    text: impl Into<egui::WidgetText>,
    url: &str,
) -> egui::Response {
    let response = ui.link(text).on_hover_text(url);
    if response.clicked()
        && let Err(e) = open_url(url)
    {
        LINK_ERROR.with(|slot| *slot.borrow_mut() = Some(e));
    }
    response
}

/// The key a device is starred under: its MAC address (upper case) when it has one, else its IP.
pub(super) fn favorite_key(host: &scan::Host) -> String {
    let mac = host.mac.trim();
    if mac.is_empty() {
        host.ip.to_string()
    } else {
        mac.to_ascii_uppercase()
    }
}

/// Adds or removes a star; returns whether the device is starred now.
pub(super) fn toggle_favorite(
    starred: &mut std::collections::BTreeSet<String>,
    key: String,
) -> bool {
    if starred.remove(&key) {
        false
    } else {
        starred.insert(key);
        true
    }
}

/// A Wake-on-LAN request waiting for the user's "Send".
pub(super) struct WakeRequest {
    pub label: String,
    pub mac: String,
    /// The destination, editable in the dialog.
    pub destination: String,
}

/// What the context menu asked for.
#[derive(Default)]
pub(super) struct MenuAction {
    pub url: Option<String>,
    pub commands: Option<Vec<Command>>,
    pub copy: Option<String>,
    pub star: bool,
    pub wake: bool,
}

/// The context menu of a host (right click on its row, or the "Actions" menu in its details).
pub(super) fn host_menu(ui: &mut egui::Ui, host: &scan::Host, starred: bool) -> MenuAction {
    let mut act = MenuAction::default();
    let ip = host.ip.to_string();
    if ui
        .button(if starred {
            tr!("Remove from favorites ★")
        } else {
            tr!("Add to favorites ☆")
        })
        .clicked()
    {
        act.star = true;
        ui.close();
    }
    ui.separator();
    let web = web_ports(host, 4);
    if web.is_empty() {
        ui.add_enabled(false, egui::Button::new(tr!("Open in browser")))
            .on_disabled_hover_text(tr!(
                "No web port (80, 443, 8080, ...) was found open on this host."
            ));
    }
    for (https, port) in web {
        if let Some(url) = web_url(https, &ip, port)
            && ui.button(tr!("Open {}", url)).clicked()
        {
            act.url = Some(url);
            ui.close();
        }
    }
    let open = |p: u16| host.open.contains(&p);
    if let Some(url) = ssh_url(&ip) {
        let button = ui.add_enabled(open(22), egui::Button::new(tr!("Open SSH (ssh://)")));
        if button
            .on_disabled_hover_text(tr!("Port 22 was not found open on this host."))
            .clicked()
        {
            act.url = Some(url);
            ui.close();
        }
    }
    if let Some(cmd) = rdp_command(Os::current(), &ip) {
        let button = ui.add_enabled(
            open(3389),
            egui::Button::new(tr!("Open remote desktop (RDP)")),
        );
        if button
            .on_disabled_hover_text(tr!("Port 3389 was not found open on this host."))
            .clicked()
        {
            act.commands = Some(vec![cmd]);
            ui.close();
        }
    }
    if ui.button(tr!("Ping in a terminal")).clicked() {
        act.commands = Some(ping_commands(Os::current(), &ip));
        ui.close();
    }
    ui.separator();
    if ui
        .add_enabled(!host.mac.is_empty(), egui::Button::new(tr!("Wake-on-LAN…")))
        .on_hover_text(tr!(
            "Sends one magic packet to the broadcast address after you confirm."
        ))
        .on_disabled_hover_text(tr!("The MAC address of this host is not known."))
        .clicked()
    {
        act.wake = true;
        ui.close();
    }
    if ui.button(tr!("Copy IP address")).clicked() {
        act.copy = Some(ip);
        ui.close();
    }
    if !host.mac.is_empty() && ui.button(tr!("Copy MAC address")).clicked() {
        act.copy = Some(host.mac.clone());
        ui.close();
    }
    act
}

impl Scanner {
    /// Carries out what a context menu chose for `host`.
    pub(super) fn do_menu_action(
        &mut self,
        ctx: &egui::Context,
        host: &scan::Host,
        act: MenuAction,
    ) {
        if act.star {
            let on = toggle_favorite(&mut self.saved.starred, favorite_key(host));
            self.generation_view();
            self.status = if on {
                tr!("{} added to the favorites", host.ip)
            } else {
                tr!("{} removed from the favorites", host.ip)
            };
        }
        if let Some(url) = act.url
            && let Err(e) = open_url(&url)
        {
            self.error = e;
        }
        if let Some(commands) = act.commands {
            if commands.is_empty() {
                self.error = tr!("The address is not valid for this action.").into();
            } else if let Err(e) = launch(&commands) {
                self.error = tr!("The program could not be started: {}", e);
            }
        }
        if let Some(text) = act.copy {
            ctx.copy_text(text);
        }
        if act.wake {
            let label = if host.hostname.is_empty() {
                host.ip.to_string()
            } else {
                format!("{} ({})", host.hostname, host.ip)
            };
            // The broadcast address of the host's own network when it is known.
            let destination = match host.ip {
                IpAddr::V4(v4) => localnets::broadcast_for(&self.local_nets, v4),
                IpAddr::V6(_) => None,
            }
            .unwrap_or(Ipv4Addr::BROADCAST);
            self.wake = Some(WakeRequest {
                label,
                mac: host.mac.clone(),
                destination: destination.to_string(),
            });
        }
    }

    /// Filter and sort depend on the stars: recompute the visible rows.
    fn generation_view(&mut self) {
        self.notes_generation += 1;
    }

    /// The confirmation of a Wake-on-LAN. Sending is the only thing that sends.
    pub(super) fn wake_dialog(&mut self, ctx: &egui::Context) {
        let Some(request) = &mut self.wake else {
            return;
        };
        let mut choice = None;
        egui::Window::new(tr!("Wake-on-LAN"))
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.set_max_width(460.0);
                ui.label(tr!("Send one magic packet for {} ({}) as a UDP broadcast?", request.mac, request.label));
                ui.label(tr!(
                    "Nothing else is sent. It only wakes a device that is set up for Wake-on-LAN, and it answers nothing back."
                ));
                ui.horizontal(|ui| {
                    ui.label(tr!("Send to"));
                    ui.add(egui::TextEdit::singleline(&mut request.destination).desired_width(140.0));
                });
                ui.horizontal(|ui| {
                    if ui.button(tr!("Send")).clicked() {
                        choice = Some(true);
                    }
                    if ui.button(tr!("Cancel")).clicked() {
                        choice = Some(false);
                    }
                });
            });
        match choice {
            Some(true) => {
                if let Some(request) = self.wake.take() {
                    self.send_wake(request);
                }
            }
            Some(false) => self.wake = None,
            None => {}
        }
    }

    /// Sends the magic packet: the scope guard first, then one token from the rate gate.
    fn send_wake(&mut self, request: WakeRequest) {
        let mac = match wol::parse_mac(&request.mac) {
            Ok(mac) => mac,
            Err(e) => {
                self.error = e;
                return;
            }
        };
        let Ok(destination) = request.destination.trim().parse::<Ipv4Addr>() else {
            self.error = tr!("{} is not an IPv4 address.", request.destination);
            return;
        };
        if let Err(e) = wol::check_destination(destination) {
            self.error = e;
            return;
        }
        // The same scope check as every other sender; a limited broadcast has nothing to check.
        let addresses = wol::guard_addresses(destination);
        if !addresses.is_empty()
            && let Some(text) = self.scope_check(&addresses, crate::scope::Consent::default())
        {
            self.error = tr!("Wake-on-LAN was not sent. {}", text);
            return;
        }
        let log = std::sync::Arc::new(crate::sendlog::SentLog::new());
        let gate = crate::core::Gate::new(1000).with_log(log.clone());
        match wol::send(mac, destination, &gate) {
            Ok(()) => {
                self.error.clear();
                self.status = tr!(
                    "Sent a Wake-on-LAN magic packet for {} to {} (1 packet)",
                    request.mac,
                    destination
                );
            }
            Err(e) => self.error = e,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_must_be_addresses_or_plain_names() {
        for ok in [
            "10.0.0.5",
            "::1",
            "fe80::1",
            "2001:db8::7",
            "plc-1",
            "plc-1.lab.example.com",
            "HMI_Packaging",
            "a",
            "1host",
        ] {
            assert_eq!(valid_host(ok).as_deref(), Some(ok), "{ok}");
        }
        for bad in [
            "",
            "-oProxyCommand=calc",
            "--help",
            "-x",
            "host name",
            "host;rm -rf /",
            "host&calc",
            "host|calc",
            "host$(id)",
            "host`id`",
            "host\"quote",
            "host'quote",
            "ho\nst",
            "host\r",
            "evil.com/path",
            "user@host",
            "host:22",
            "[::1]",
            "fe80::1%eth0",
            "a..b",
            ".leading",
            "trailing-.example",
            "-lead.example",
            "ünïcode.example",
            "host%20name",
            "host,other",
            "10.0.0.5 --flag",
            &"a".repeat(64),
            &format!("{}.com", "a.".repeat(130)),
        ] {
            assert_eq!(valid_host(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn web_urls_use_the_scheme_port_and_brackets() {
        assert_eq!(
            web_url(false, "10.0.0.5", 80).as_deref(),
            Some("http://10.0.0.5/")
        );
        assert_eq!(
            web_url(true, "10.0.0.5", 443).as_deref(),
            Some("https://10.0.0.5/")
        );
        assert_eq!(
            web_url(false, "10.0.0.5", 8080).as_deref(),
            Some("http://10.0.0.5:8080/")
        );
        assert_eq!(
            web_url(true, "plc.lab", 8443).as_deref(),
            Some("https://plc.lab:8443/")
        );
        assert_eq!(
            web_url(true, "fe80::1", 443).as_deref(),
            Some("https://[fe80::1]/")
        );
        assert_eq!(web_url(false, "10.0.0.5", 0), None);
        assert_eq!(web_url(false, "10.0.0.5/evil", 80), None);
        assert_eq!(web_url(false, "x@10.0.0.5", 80), None);
        assert_eq!(ssh_url("10.0.0.5").as_deref(), Some("ssh://10.0.0.5"));
        assert_eq!(ssh_url("::1").as_deref(), Some("ssh://[::1]"));
        assert_eq!(ssh_url("-oProxyCommand=x"), None);
        assert_eq!(ssh_url("a b"), None);
    }

    #[test]
    fn only_plain_links_with_a_valid_host_are_opened() {
        for ok in [
            "https://sparkz400.github.io/network-scope/findings/telnet-open.html",
            "https://github.com/Sparkz400/network-scope/releases",
            "https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3",
            "http://10.0.0.5/",
            "http://10.0.0.5:8080/",
            "https://[fe80::1]/",
            "https://[fe80::1]:8443/x?y=1#z",
            "ssh://10.0.0.5",
            "rdp://hmi.lab",
            "https://example.com/a_b-c.d~e%20f?q=1&r=2#frag",
        ] {
            assert!(valid_url(ok), "{ok}");
        }
        for bad in [
            "",
            "example.com",
            "javascript:alert(1)",
            "file:///C:/Windows/System32/calc.exe",
            "C:\\Windows\\System32\\calc.exe",
            "ftp://example.com/",
            "https://",
            "https:///path",
            "https://user:pass@example.com/",
            "https://example.com/ with space",
            "https://example.com/\"quote",
            "https://example.com/'x'",
            "https://example.com/`id`",
            "https://example.com/a|b",
            "https://example.com/a^b",
            "https://example.com/<x>",
            "https://example.com/\nnewline",
            "https://exa mple.com/",
            "https://-evil.com/",
            "https://example.com:port/",
            "https://example.com:123456x/",
            "https://[not-an-address]/",
            "https://[::1/",
            "--help",
            "-oProxyCommand=x",
            "https://evil.com\\@example.com/",
            &format!("https://example.com/{}", "a".repeat(2100)),
        ] {
            assert!(!valid_url(bad), "{bad:?}");
        }
    }

    #[test]
    fn the_opener_command_has_the_url_as_its_last_argument_and_no_shell() {
        let url = "https://example.com/a?b=1&c=2";
        for (os, program, args) in [
            (Os::Windows, "rundll32.exe", 2),
            (Os::Apple, "open", 1),
            (Os::Linux, "xdg-open", 1),
        ] {
            let c = open_command(os, url).unwrap();
            assert_eq!(c.program, program);
            assert_eq!(c.args.len(), args);
            assert_eq!(c.args.last().map(String::as_str), Some(url));
            assert!(
                !["cmd", "cmd.exe", "sh", "bash", "powershell.exe"].contains(&c.program.as_str())
            );
        }
        // An invalid URL builds nothing, on every system.
        for os in [Os::Windows, Os::Apple, Os::Linux] {
            assert_eq!(open_command(os, "https://example.com/x y"), None);
            assert_eq!(open_command(os, "-flag"), None);
        }
        assert!(open_url("not a link").unwrap_err().contains("not valid"));
    }

    #[test]
    fn rdp_and_ping_commands_have_no_shell_and_checked_arguments() {
        let win = rdp_command(Os::Windows, "10.0.0.12").unwrap();
        assert_eq!(
            (win.program.as_str(), win.args.as_slice()),
            ("mstsc.exe", &["/v:10.0.0.12".to_string()][..])
        );
        assert_eq!(rdp_command(Os::Windows, "::1"), None);
        let linux = rdp_command(Os::Linux, "10.0.0.12").unwrap();
        assert_eq!(
            (linux.program.as_str(), linux.args[0].as_str()),
            ("xdg-open", "rdp://10.0.0.12")
        );
        let mac = rdp_command(Os::Apple, "hmi.lab").unwrap();
        assert_eq!(
            (mac.program.as_str(), mac.args[0].as_str()),
            ("open", "rdp://hmi.lab")
        );
        assert_eq!(rdp_command(Os::Linux, "x y"), None);
        assert_eq!(rdp_command(Os::Windows, "/v:evil /admin"), None);

        let ping = ping_commands(Os::Windows, "10.0.0.5");
        assert_eq!(ping.len(), 1);
        assert_eq!(
            (ping[0].program.as_str(), ping[0].args.as_slice()),
            ("ping.exe", &["-t".to_string(), "10.0.0.5".to_string()][..])
        );
        assert!(ping[0].new_console);
        let linux = ping_commands(Os::Linux, "10.0.0.5");
        assert!(linux.len() >= 3);
        for c in &linux {
            assert_eq!(c.args.last().map(String::as_str), Some("10.0.0.5"), "{c:?}");
            assert!(
                !c.program.contains(' ') && !["sh", "bash", "cmd"].contains(&c.program.as_str())
            );
        }
        let mac = ping_commands(Os::Apple, "10.0.0.5");
        assert_eq!(mac[0].program, "osascript");
        assert!(mac[0].args[1].contains("ping 10.0.0.5\""));
        // An invalid host gives nothing to launch, on every system.
        for os in [Os::Windows, Os::Apple, Os::Linux] {
            for bad in [
                "",
                "-c1",
                "a;b",
                "a\"b",
                "a b",
                "$(id)",
                "10.0.0.5\" & calc & \"",
            ] {
                assert!(ping_commands(os, bad).is_empty(), "{os:?} {bad:?}");
            }
        }
    }

    #[test]
    fn no_argument_can_smuggle_a_second_command_into_the_terminal_script() {
        // The macOS ping goes through an AppleScript string: a quote would end it.
        for os in [Os::Apple] {
            for hostile in ["x\" & (do shell script \"id\") & \"", "a'b", "a\\b"] {
                assert!(ping_commands(os, hostile).is_empty(), "{hostile}");
            }
        }
    }

    #[test]
    fn web_ports_come_from_the_open_ports_and_the_service_names() {
        let mut h = demo::demo_host(
            "10.0.0.5",
            &[22, 80, 443, 8080, 9999, 8443],
            &[("svc.9999", "http-alt nginx")],
        );
        let ports = web_ports(&h, 10);
        assert_eq!(
            ports,
            [
                (false, 80),
                (true, 443),
                (false, 8080),
                (false, 9999),
                (true, 8443)
            ]
        );
        assert_eq!(web_ports(&h, 2).len(), 2, "capped");
        h.open = vec![22, 3389];
        assert!(web_ports(&h, 4).is_empty());
        h.open = vec![8081];
        h.identity.insert("svc.8081".into(), "https tls".into());
        assert_eq!(web_ports(&h, 4), [(true, 8081)]);
    }

    #[test]
    fn favorites_follow_the_mac_and_toggle() {
        let mut h = demo::demo_host("10.0.0.5", &[], &[]);
        assert_eq!(favorite_key(&h), "10.0.0.5");
        h.mac = "aa:bb:cc:00:11:22".into();
        assert_eq!(favorite_key(&h), "AA:BB:CC:00:11:22");
        let mut set = std::collections::BTreeSet::new();
        assert!(toggle_favorite(&mut set, favorite_key(&h)));
        // The same device at another address is still starred.
        h.ip = "10.0.0.99".parse().unwrap();
        assert!(set.contains(&favorite_key(&h)));
        assert!(!toggle_favorite(&mut set, favorite_key(&h)));
        assert!(set.is_empty());
    }

    #[test]
    fn stars_are_saved_with_the_preferences_and_absent_in_old_files() {
        let mut saved = Saved::default();
        saved.starred.insert("AA:BB:CC:00:11:22".into());
        let disk: Saved = serde_json::from_slice(&saved.to_disk()).unwrap();
        assert!(disk.starred.contains("AA:BB:CC:00:11:22"));
        let old: Saved = serde_json::from_str(r#"{"favorites":["10.0.0.1"]}"#).unwrap();
        assert!(old.starred.is_empty());
    }

    #[test]
    fn launching_something_that_does_not_exist_reports_it() {
        let e = launch(&[Command::new("definitely-not-a-program-xyz", &["a"])]).unwrap_err();
        assert!(e.contains("definitely-not-a-program-xyz"), "{e}");
        assert!(launch(&[]).is_err());
    }

    /// Run by hand to see the opener work: `cargo test --lib live_link_opener -- --ignored
    /// --nocapture`. Refused links start nothing; the documentation page goes to the default
    /// browser.
    #[test]
    #[ignore = "opens a page in the default browser"]
    fn live_link_opener_hands_a_docs_page_to_the_default_browser() {
        for bad in [
            "file:///C:/Windows/win.ini",
            "javascript:alert(1)",
            "https://exa mple.com/",
            "calc.exe",
        ] {
            assert!(open_url(bad).is_err(), "{bad}");
        }
        let url = super::super::docs_url("telnet-open");
        open_url(&url).unwrap();
        eprintln!("handed to the system: {url}");
    }
}
