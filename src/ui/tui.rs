// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! The live terminal view of `scan --tui`: host list, detail view, sort, pause and stop keys.
use super::commands::scan::{Collected, accept, collect};
use crate::{evidence::Evidence, risk, scan};
use std::{collections::HashMap, net::IpAddr, sync::atomic::Ordering, time::Duration};

fn stop_key(code: crossterm::event::KeyCode) -> bool {
    use crossterm::event::KeyCode;
    matches!(code, KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc)
}
static TUI_THREAD: std::sync::Mutex<Option<std::thread::ThreadId>> = std::sync::Mutex::new(None);
fn restore_terminal() {
    let _ = crossterm::terminal::disable_raw_mode();
    let _ = crossterm::execute!(
        std::io::stdout(),
        crossterm::terminal::LeaveAlternateScreen,
        crossterm::cursor::Show
    );
}
/// Panic messages from other threads while the live view is on; printed once it is closed.
static TUI_PANICS: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
/// A panic printed inside the alternate screen would be lost. On the TUI thread the terminal is
/// restored first; panics of worker threads (the TUI keeps running) are also kept and printed
/// after the terminal is restored. Then the previous (default) hook runs. Installed once; inert
/// outside the TUI.
fn install_panic_hook() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let tui = TUI_THREAD.lock().map(|t| *t).unwrap_or(None);
            if let Some(id) = tui {
                if id == std::thread::current().id() {
                    restore_terminal();
                } else {
                    if let Ok(mut panics) = TUI_PANICS.lock()
                        && panics.len() < 16
                    {
                        let thread = std::thread::current();
                        panics.push(format!(
                            "thread '{}' {info}",
                            thread.name().unwrap_or("<unnamed>")
                        ));
                    }
                }
            }
            previous(info);
        }));
    });
}
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
enum TuiSort {
    #[default]
    Newest,
    Address,
    OpenPorts,
}
impl TuiSort {
    fn next(self) -> Self {
        match self {
            Self::Newest => Self::Address,
            Self::Address => Self::OpenPorts,
            Self::OpenPorts => Self::Newest,
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Newest => "newest",
            Self::Address => "address",
            Self::OpenPorts => "open ports",
        }
    }
}
#[derive(PartialEq, Eq, Debug)]
enum TuiAction {
    None,
    Stop,
    Pause,
}
/// Live view state: sort order, selection (kept by address across re-sorts) and detail view.
#[derive(Default)]
struct TuiView {
    sort: TuiSort,
    selected: Option<IpAddr>,
    detail: bool,
    /// First line shown in the detail view.
    scroll: u16,
    /// Indexes into the host list in display order.
    order: Vec<usize>,
    key: Option<(usize, TuiSort, u64)>,
    /// Hosts still being scanned, with the index of their provisional row (`scan::Event::Partial`).
    pending: HashMap<IpAddr, usize>,
    /// Counts changes to a row that keep the list length (a provisional row updated).
    version: u64,
}
impl TuiView {
    /// Re-sorts only when hosts arrived or the sort mode changed.
    fn refresh(&mut self, hosts: &[scan::Host]) {
        let key = (hosts.len(), self.sort, self.version);
        if self.key == Some(key) {
            return;
        }
        self.key = Some(key);
        let mut order: Vec<usize> = (0..hosts.len()).collect();
        match self.sort {
            TuiSort::Newest => order.reverse(),
            TuiSort::Address => order.sort_by_key(|&i| hosts[i].ip),
            TuiSort::OpenPorts => order.sort_by(|&a, &b| {
                let n = |h: &scan::Host| h.open.len() + h.udp_open.len();
                n(&hosts[b])
                    .cmp(&n(&hosts[a]))
                    .then(hosts[a].ip.cmp(&hosts[b].ip))
            }),
        }
        self.order = order;
    }
    fn position(&self, hosts: &[scan::Host]) -> Option<usize> {
        let ip = self.selected?;
        self.order.iter().position(|&i| hosts[i].ip == ip)
    }
    /// Visible slice of `order` for a list of `height` rows, keeping the selection in view.
    fn window(&self, hosts: &[scan::Host], height: usize) -> (usize, usize) {
        let start = match self.position(hosts) {
            Some(p) if height > 0 && p >= height => p + 1 - height,
            _ => 0,
        };
        (start, (start + height).min(self.order.len()))
    }
    fn detail_host<'a>(&self, hosts: &'a [scan::Host]) -> Option<&'a scan::Host> {
        if !self.detail {
            return None;
        }
        let ip = self.selected?;
        hosts.iter().find(|h| h.ip == ip)
    }
    fn key(&mut self, code: crossterm::event::KeyCode, hosts: &[scan::Host]) -> TuiAction {
        use crossterm::event::KeyCode;
        if stop_key(code) {
            return TuiAction::Stop;
        }
        self.refresh(hosts);
        let len = self.order.len();
        let current = self.position(hosts);
        let target = match code {
            KeyCode::Char(' ') => return TuiAction::Pause,
            KeyCode::Char('s') | KeyCode::Char('S') => {
                self.sort = self.sort.next();
                self.refresh(hosts);
                return TuiAction::None;
            }
            KeyCode::Enter => {
                self.scroll = 0;
                if self.detail {
                    self.detail = false;
                } else if current.is_some() {
                    self.detail = true;
                } else if let Some(&first) = self.order.first() {
                    self.selected = Some(hosts[first].ip);
                    self.detail = true;
                }
                return TuiAction::None;
            }
            KeyCode::Backspace | KeyCode::Left => {
                self.detail = false;
                return TuiAction::None;
            }
            KeyCode::Down | KeyCode::PageDown if self.detail => {
                let step = if code == KeyCode::Down { 1 } else { 10 };
                self.scroll = self.scroll.saturating_add(step).min(500);
                return TuiAction::None;
            }
            KeyCode::Up | KeyCode::PageUp if self.detail => {
                let step = if code == KeyCode::Up { 1 } else { 10 };
                self.scroll = self.scroll.saturating_sub(step);
                return TuiAction::None;
            }
            _ if self.detail || len == 0 => return TuiAction::None,
            KeyCode::Down => current.map_or(0, |p| (p + 1).min(len - 1)),
            KeyCode::Up => current.map_or(0, |p| p.saturating_sub(1)),
            KeyCode::PageDown => current.map_or(0, |p| (p + 10).min(len - 1)),
            KeyCode::PageUp => current.map_or(0, |p| p.saturating_sub(10)),
            KeyCode::Home => 0,
            KeyCode::End => len - 1,
            _ => return TuiAction::None,
        };
        self.selected = Some(hosts[self.order[target]].ip);
        TuiAction::None
    }
}
/// Detail view text: ports with their identified services, identity and findings.
fn detail_lines(h: &scan::Host) -> Vec<String> {
    let mut lines = vec![
        format!(
            "Status: {}{}",
            if h.responding {
                "responding"
            } else {
                "no reply"
            },
            h.ping.map_or(String::new(), |p| format!(" · ping {p} ms"))
        ),
        format!(
            "Hostname: {}",
            if h.hostname.is_empty() {
                "-"
            } else {
                &h.hostname
            }
        ),
        format!("MAC: {}", if h.mac.is_empty() { "-" } else { &h.mac }),
    ];
    // Conclusions with their reasons and confidence ("Printer / MFP (75 %) because ...").
    for (label, key, prefix) in [("OS", "os.guess", "os"), ("Type", "device.type", "device")] {
        if let Some(value) = h.identity.get(key) {
            lines.push(format!(
                "{label}: {}",
                Evidence::from_identity(&h.identity, prefix)
                    .map_or_else(|| value.clone(), |e| e.line(value))
            ));
        }
    }
    lines.push(String::new());
    lines.push(format!("Open TCP ports ({})", h.open.len()));
    for p in &h.open {
        let service = h.identity.get(&format!("svc.{p}"));
        lines.push(format!(
            "  {p:>5}/tcp  {}",
            service.map_or("", String::as_str)
        ));
    }
    if !h.udp_open.is_empty() {
        lines.push(format!("Open UDP ports ({})", h.udp_open.len()));
        for p in &h.udp_open {
            let service = h.identity.get(&format!("udp.{p}"));
            lines.push(format!(
                "  {p:>5}/udp  {}",
                service.map_or("", String::as_str)
            ));
        }
    }
    let findings = risk::analyze_host(h);
    lines.push(String::new());
    lines.push(format!("Findings ({})", findings.len()));
    for f in &findings {
        lines.push(format!(
            "  [{}] {}{}: {}{}",
            f.severity.name(),
            f.title,
            f.port.map_or(String::new(), |p| format!(" (port {p})")),
            f.evidence,
            if f.confidence > 0 {
                format!(" [confidence {} %]", f.confidence)
            } else {
                String::new()
            }
        ));
    }
    let identity: Vec<String> = h
        .identity
        .iter()
        .filter(|(k, _)| {
            !k.starts_with("svc.") && !k.starts_with("udp.") && !k.starts_with("finding.")
        })
        .map(|(k, v)| format!("  {k}: {v}"))
        .collect();
    if !identity.is_empty() {
        lines.push(String::new());
        lines.push("Identity".into());
        lines.extend(identity);
    }
    for e in &h.errors {
        lines.push(format!("Error: {e}"));
    }
    lines
}
/// Applies one scan event to the live view. A `Partial` host becomes (or updates) a provisional
/// row; the final `Host` event replaces it. Returns true on `Done`. Provisional rows are not
/// results: see [`drop_provisional`].
fn apply_event(
    event: scan::Event,
    hosts: &mut Vec<scan::Host>,
    view: &mut TuiView,
    sparse: bool,
    errors: &mut Vec<String>,
) -> bool {
    match event {
        scan::Event::Partial(h) => {
            view.version += 1;
            match view.pending.get(&h.ip).copied() {
                Some(i) if hosts.get(i).is_some_and(|r| r.ip == h.ip) => hosts[i] = h,
                _ => {
                    view.pending.insert(h.ip, hosts.len());
                    hosts.push(h);
                }
            }
            false
        }
        scan::Event::Host(h) => match view.pending.remove(&h.ip) {
            Some(i) if hosts.get(i).is_some_and(|r| r.ip == h.ip) => {
                view.version += 1;
                hosts[i] = h;
                false
            }
            _ => accept(scan::Event::Host(h), hosts, sparse, errors),
        },
        other => accept(other, hosts, sparse, errors),
    }
}
/// Removes the provisional rows that never became final (the scan was stopped): half-known hosts
/// are shown while the scan runs but are not saved as if they were complete results.
fn drop_provisional(hosts: &mut Vec<scan::Host>, view: &TuiView) {
    let pending: std::collections::HashSet<usize> = view.pending.values().copied().collect();
    let mut index = 0usize;
    hosts.retain(|_| {
        let keep = !pending.contains(&index);
        index += 1;
        keep
    });
}
/// One frame of the live view: the host list, or the detail view of the selected host.
fn draw_tui(f: &mut ratatui::Frame, view: &TuiView, hosts: &[scan::Host], progress: &str) {
    use ratatui::{
        layout::Constraint,
        style::{Modifier, Style},
        text::Line,
        widgets::{Block, Borders, Paragraph, Row, Table, Wrap},
    };
    let area = f.area();
    if let Some(host) = view.detail_host(hosts) {
        let lines: Vec<Line> = detail_lines(host).into_iter().map(Line::from).collect();
        f.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: false })
                .scroll((view.scroll, 0))
                .block(Block::default().borders(Borders::ALL).title(format!(
                    " {} · {progress} · ↑↓ scroll · Enter/Backspace back · Space pause / Q stop ",
                    host.ip
                ))),
            area,
        );
        return;
    }
    let height = area.height.saturating_sub(3) as usize;
    let (start, end) = view.window(hosts, height);
    let rows = view.order[start..end].iter().map(|&i| {
        let h: &scan::Host = &hosts[i];
        let row = Row::new(vec![
            h.ip.to_string(),
            if view.pending.contains_key(&h.ip) {
                "Scanning..."
            } else if h.responding {
                "Responding"
            } else {
                "No reply"
            }
            .into(),
            h.open
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(","),
            h.identity
                .keys()
                .filter(|k| k.ends_with("name") || k.ends_with("firmware"))
                .map(|k| format!("{k}: {}", h.identity[k]))
                .collect::<Vec<_>>()
                .join("; "),
        ]);
        if view.selected == Some(h.ip) {
            row.style(Style::default().add_modifier(Modifier::REVERSED))
        } else {
            row
        }
    });
    f.render_widget(
        Table::new(
            rows,
            [
                Constraint::Length(18),
                Constraint::Length(13),
                Constraint::Length(22),
                Constraint::Min(10),
            ],
        )
        .header(Row::new(["IP", "Status", "Ports", "Identity"]))
        .block(Block::default().borders(Borders::ALL).title(format!(
            " Network Scope · {progress} · sort: {} (S) · ↑↓ Enter details · Space pause / Q stop ",
            view.sort.name()
        ))),
        area,
    );
}
pub(super) fn tui(run: &scan::Running) -> Collected {
    use crossterm::{
        event::{self, Event, KeyEventKind},
        execute,
        terminal::{EnterAlternateScreen, enable_raw_mode},
    };
    use ratatui::{Terminal, backend::CrosstermBackend};
    /// Undoes only what was set up, then prints panics of other threads seen meanwhile.
    struct Restore {
        raw: bool,
        screen: bool,
    }
    impl Drop for Restore {
        fn drop(&mut self) {
            if let Ok(mut t) = TUI_THREAD.lock() {
                *t = None;
            }
            if self.raw {
                let _ = crossterm::terminal::disable_raw_mode();
            }
            if self.screen {
                let _ = crossterm::execute!(
                    std::io::stdout(),
                    crossterm::terminal::LeaveAlternateScreen,
                    crossterm::cursor::Show
                );
            }
            if let Ok(mut panics) = TUI_PANICS.lock() {
                for p in panics.drain(..) {
                    eprintln!("{p}");
                }
            }
        }
    }
    install_panic_hook();
    if let Ok(mut t) = TUI_THREAD.lock() {
        *t = Some(std::thread::current().id());
    }
    let mut restore = Restore {
        raw: false,
        screen: false,
    };
    let setup = enable_raw_mode()
        .and_then(|()| {
            restore.raw = true;
            execute!(std::io::stdout(), EnterAlternateScreen)
        })
        .and_then(|()| {
            restore.screen = true;
            Terminal::new(CrosstermBackend::new(std::io::stdout()))
        });
    let mut terminal = match setup {
        Ok(t) => t,
        Err(e) => {
            // No usable terminal: keep the scan and collect it without the live view.
            drop(restore);
            eprintln!("Live view unavailable ({e}); collecting without it.");
            return collect(run, false);
        }
    };
    let mut hosts = vec![];
    let mut errors = vec![];
    let mut seen = 0usize;
    let mut view = TuiView::default();
    let sparse = run.total > scan::MAX_HOSTS;
    let mut done = false;
    while !done {
        loop {
            match run.receiver.try_recv() {
                Ok(event) => {
                    if matches!(event, scan::Event::Host(_)) {
                        seen += 1;
                    }
                    if apply_event(event, &mut hosts, &mut view, sparse, &mut errors) {
                        done = true;
                        break;
                    }
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(_) => {
                    errors.push("Scan worker disconnected".into());
                    done = true;
                    break;
                }
            }
        }
        if done {
            break;
        }
        view.refresh(&hosts);
        let paused = run.pause.load(Ordering::Relaxed);
        let progress = format!(
            "{seen}/{} · {}",
            run.total,
            if paused { "paused" } else { "scanning" }
        );
        let drawn = terminal.draw(|f| draw_tui(f, &view, &hosts, &progress));
        let input = drawn.and_then(|_| {
            if event::poll(Duration::from_millis(60))?
                && let Event::Key(k) = event::read()?
                && k.kind == KeyEventKind::Press
            {
                // In raw mode Ctrl+C arrives as a key: it stops (and saves) like Q.
                let ctrl_c = k.code == event::KeyCode::Char('c')
                    && k.modifiers.contains(event::KeyModifiers::CONTROL);
                let action = match ctrl_c {
                    true => TuiAction::Stop,
                    false => view.key(k.code, &hosts),
                };
                match action {
                    TuiAction::Stop => run.cancel.store(true, Ordering::Relaxed),
                    TuiAction::Pause => {
                        run.pause.fetch_xor(true, Ordering::Relaxed);
                    }
                    TuiAction::None => {}
                }
            }
            Ok(())
        });
        if let Err(e) = input {
            // Terminal failure: stop the scan but keep what was found.
            errors.push(format!("Terminal: {e}"));
            run.cancel.store(true, Ordering::Relaxed);
            break;
        }
    }
    drop(restore);
    drop_provisional(&mut hosts, &view);
    let complete = done && errors.is_empty() && !run.cancel.load(Ordering::Relaxed);
    (hosts, complete, errors)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::testutil::tui_host;

    #[test]
    fn upper_and_lower_case_q_stop_the_tui() {
        use crossterm::event::KeyCode;
        assert!(stop_key(KeyCode::Char('q')));
        assert!(stop_key(KeyCode::Char('Q')));
        assert!(stop_key(KeyCode::Esc));
        assert!(!stop_key(KeyCode::Char(' ')));
    }

    #[test]
    fn partial_hosts_show_up_at_once_and_are_replaced_by_the_final_row() {
        let (mut hosts, mut view, mut errors) = (vec![], TuiView::default(), vec![]);
        let mut step = |e, hosts: &mut Vec<scan::Host>, view: &mut TuiView| {
            apply_event(e, hosts, view, false, &mut errors)
        };
        let ip: IpAddr = "10.0.0.7".parse().unwrap();
        // First sign of life: a provisional row, listed and sortable.
        assert!(!step(
            scan::Event::Partial(tui_host("10.0.0.7", vec![])),
            &mut hosts,
            &mut view
        ));
        assert_eq!(hosts.len(), 1);
        assert!(view.pending.contains_key(&ip));
        view.refresh(&hosts);
        assert_eq!(view.order, [0]);
        // A port found open updates the same row (same length, the list is still re-sorted).
        step(
            scan::Event::Partial(tui_host("10.0.0.7", vec![80])),
            &mut hosts,
            &mut view,
        );
        assert_eq!((hosts.len(), hosts[0].open.clone()), (1, vec![80]));
        let before = view.key;
        view.refresh(&hosts);
        assert_ne!(view.key, before, "an update of a row is noticed");
        // A second host, then the final record of the first replaces its provisional row.
        step(
            scan::Event::Partial(tui_host("10.0.0.8", vec![])),
            &mut hosts,
            &mut view,
        );
        step(
            scan::Event::Host(tui_host("10.0.0.7", vec![80, 443])),
            &mut hosts,
            &mut view,
        );
        assert_eq!(hosts.len(), 2, "no duplicate row");
        assert_eq!(hosts[0].open, [80, 443]);
        assert!(!view.pending.contains_key(&ip));
        // The scan is stopped: 10.0.0.8 never finished, so it is not kept as a result.
        assert_eq!(view.pending.len(), 1);
        drop_provisional(&mut hosts, &view);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].ip, ip);
        // Events without a provisional row behave as before.
        assert!(step(scan::Event::Done, &mut hosts, &mut view));
        step(
            scan::Event::Host(tui_host("10.0.0.9", vec![])),
            &mut hosts,
            &mut view,
        );
        assert_eq!(hosts.len(), 2);
    }

    #[test]
    fn a_provisional_row_is_labelled_scanning() {
        use ratatui::{Terminal, backend::TestBackend};
        let mut hosts = vec![];
        let (mut view, mut errors) = (TuiView::default(), vec![]);
        apply_event(
            scan::Event::Partial(tui_host("10.0.0.7", vec![80])),
            &mut hosts,
            &mut view,
            false,
            &mut errors,
        );
        view.refresh(&hosts);
        let mut t = Terminal::new(TestBackend::new(100, 10)).unwrap();
        let screen = |t: &Terminal<TestBackend>| {
            t.backend()
                .buffer()
                .content()
                .iter()
                .map(|c| c.symbol())
                .collect::<String>()
        };
        t.draw(|f| draw_tui(f, &view, &hosts, "0/1 · scanning"))
            .unwrap();
        let text = screen(&t);
        assert!(
            text.contains("Scanning...") && text.contains("80"),
            "{text}"
        );
        apply_event(
            scan::Event::Host(tui_host("10.0.0.7", vec![80])),
            &mut hosts,
            &mut view,
            false,
            &mut errors,
        );
        view.refresh(&hosts);
        t.draw(|f| draw_tui(f, &view, &hosts, "1/1 · scanning"))
            .unwrap();
        assert!(screen(&t).contains("Responding"));
    }

    #[test]
    fn tui_selection_detail_and_sort_keys() {
        use crossterm::event::KeyCode;
        let hosts = vec![
            tui_host("10.0.0.3", vec![80]),
            tui_host("10.0.0.1", vec![]),
            tui_host("10.0.0.2", vec![22, 23, 80]),
        ];
        let mut v = TuiView::default();
        v.refresh(&hosts);
        assert_eq!(v.order, [2, 1, 0], "newest first");
        // Enter without a selection opens the first row.
        assert_eq!(v.key(KeyCode::Enter, &hosts), TuiAction::None);
        assert!(v.detail);
        assert_eq!(v.detail_host(&hosts).unwrap().ip, hosts[2].ip);
        // Arrows do nothing in the detail view; Esc and Q still stop, Space still pauses.
        v.key(KeyCode::Down, &hosts);
        assert_eq!(v.selected, Some(hosts[2].ip));
        assert_eq!(v.key(KeyCode::Esc, &hosts), TuiAction::Stop);
        assert_eq!(v.key(KeyCode::Char('Q'), &hosts), TuiAction::Stop);
        assert_eq!(v.key(KeyCode::Char(' '), &hosts), TuiAction::Pause);
        v.key(KeyCode::Backspace, &hosts);
        assert!(!v.detail && v.detail_host(&hosts).is_none());
        v.key(KeyCode::Down, &hosts);
        assert_eq!(v.selected, Some(hosts[1].ip));
        // Sorting keeps the selected host.
        v.key(KeyCode::Char('s'), &hosts);
        assert_eq!(v.sort, TuiSort::Address);
        assert_eq!(v.order, [1, 2, 0]);
        assert_eq!(v.position(&hosts), Some(0));
        v.key(KeyCode::Char('S'), &hosts);
        assert_eq!(v.order, [2, 0, 1], "most open ports first");
        v.key(KeyCode::End, &hosts);
        assert_eq!(v.selected, Some(hosts[1].ip));
        v.key(KeyCode::Up, &hosts);
        assert_eq!(v.selected, Some(hosts[0].ip));
        v.key(KeyCode::Char('s'), &hosts);
        assert_eq!(v.sort, TuiSort::Newest);
        // The window follows the selection.
        let many: Vec<scan::Host> = (1..=50)
            .map(|i| tui_host(&format!("10.0.1.{i}"), vec![]))
            .collect();
        let mut v = TuiView::default();
        v.key(KeyCode::End, &many);
        assert_eq!(v.window(&many, 10), (40, 50));
        v.key(KeyCode::Home, &many);
        assert_eq!(v.window(&many, 10), (0, 10));
        assert_eq!(TuiView::default().window(&[], 10), (0, 0));
    }

    #[test]
    fn tui_renders_list_and_detail_views_at_any_size() {
        use crossterm::event::KeyCode;
        use ratatui::{Terminal, backend::TestBackend};
        let hosts: Vec<scan::Host> = (1..=30)
            .map(|i| tui_host(&format!("10.0.0.{i}"), vec![23]))
            .collect();
        let text = |t: &Terminal<TestBackend>| {
            let b = t.backend().buffer();
            b.content().iter().map(|c| c.symbol()).collect::<String>()
        };
        for (w, h) in [(100, 24), (12, 3), (1, 1)] {
            let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
            let mut v = TuiView::default();
            v.refresh(&hosts);
            v.key(KeyCode::End, &hosts);
            t.draw(|f| draw_tui(f, &v, &hosts, "30/30 · scanning"))
                .unwrap();
            if w == 100 {
                let screen = text(&t);
                assert!(screen.contains("10.0.0.1 "), "{screen}");
                assert!(screen.contains("sort: newest"), "{screen}");
            }
            v.key(KeyCode::Enter, &hosts);
            v.key(KeyCode::PageDown, &hosts);
            t.draw(|f| draw_tui(f, &v, &hosts, "30/30 · scanning"))
                .unwrap();
            if w == 100 {
                assert_eq!(v.scroll, 10);
                v.key(KeyCode::Up, &hosts);
                v.key(KeyCode::PageUp, &hosts);
                assert_eq!(v.scroll, 0);
                t.draw(|f| draw_tui(f, &v, &hosts, "30/30 · scanning"))
                    .unwrap();
                let screen = text(&t);
                assert!(screen.contains("23/tcp  telnet"), "{screen}");
                assert!(screen.contains("Findings ("), "{screen}");
            }
        }
    }

    #[test]
    fn tui_details_show_conclusions_with_reasons_and_confidence() {
        let mut h = tui_host("10.0.0.2", vec![23]);
        let text = detail_lines(&h).join("\n");
        assert!(!text.contains("OS:") && !text.contains("Type:"), "{text}");
        assert!(text.contains("[confidence 90 %]"), "{text}");
        h.identity.insert("os.guess".into(), "Linux".into());
        h.identity.insert("os.confidence".into(), "70%".into());
        h.identity.insert(
            "os.evidence".into(),
            "initial TTL 64; TCP options M,S,T,N,W".into(),
        );
        h.identity
            .insert("device.type".into(), "Printer / MFP".into());
        let lines = detail_lines(&h);
        assert!(
            lines.contains(
                &"OS: Linux (70 %) because initial TTL 64; TCP options M,S,T,N,W".to_string()
            ),
            "{lines:?}"
        );
        // A conclusion without stored reasons is shown plainly.
        assert!(
            lines.contains(&"Type: Printer / MFP".to_string()),
            "{lines:?}"
        );
    }

    #[test]
    fn tui_details_show_ports_services_and_findings() {
        let h = tui_host("10.0.0.2", vec![23]);
        let text = detail_lines(&h).join("\n");
        assert!(text.contains("23/tcp  telnet"), "{text}");
        assert!(text.contains("Findings ("), "{text}");
        let findings = risk::analyze_host(&h);
        for f in &findings {
            assert!(text.contains(&f.title), "{text}");
        }
    }
}
