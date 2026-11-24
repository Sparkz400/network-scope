//! The interactive network map (ROADMAP F37): the path map of `topology::build` (traceroute data;
//! later also LLDP and SNMP links, which appear here without changes because only the node and
//! edge lists are read) drawn as a graph you can pan (drag) and zoom (scroll or pinch). Nodes are
//! coloured by device type and carry a badge for their worst finding; a click opens the host's
//! details. The positions come from `netmap::layout` (a ring layout relaxed by a force pass, plain
//! Rust). With hundreds of nodes only a limited number of labels is drawn; hover shows the rest,
//! and a list below the map offers the same hosts to keyboard and screen reader users.
use super::{i18n::tr, *};
use crate::netmap;

/// Labels drawn at most; the others show on hover.
const MAX_LABELS: usize = 60;

/// What a node stands for, by device type; decides its colour.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Class {
    Scanner,
    /// A router on the path (a hop that is not a scanned host).
    Hop,
    /// A hop that did not answer.
    Silent,
    Controller,
    Network,
    Server,
    Workstation,
    Printer,
    Camera,
    Other,
}

impl Class {
    pub const LEGEND: [Self; 8] = [
        Self::Scanner,
        Self::Controller,
        Self::Network,
        Self::Server,
        Self::Workstation,
        Self::Printer,
        Self::Camera,
        Self::Other,
    ];
    pub fn name(self) -> &'static str {
        match self {
            Self::Scanner => tr!("This scanner"),
            Self::Hop => tr!("Router on the path"),
            Self::Silent => tr!("Hop without a reply"),
            Self::Controller => tr!("Controller / HMI"),
            Self::Network => tr!("Network device"),
            Self::Server => tr!("Server / storage"),
            Self::Workstation => tr!("Workstation"),
            Self::Printer => tr!("Printer"),
            Self::Camera => tr!("Camera"),
            Self::Other => tr!("Other device"),
        }
    }
    pub fn color(self, dark: bool) -> Color32 {
        let (l, d) = match self {
            Self::Scanner => ((43, 108, 176), (110, 170, 240)),
            Self::Hop => ((113, 128, 150), (160, 175, 195)),
            Self::Silent => ((160, 160, 160), (120, 120, 120)),
            Self::Controller => ((200, 90, 20), (245, 150, 80)),
            Self::Network => ((70, 90, 140), (140, 160, 220)),
            Self::Server => ((30, 120, 140), (90, 200, 220)),
            Self::Workstation => ((47, 133, 90), (110, 205, 150)),
            Self::Printer => ((130, 70, 160), (200, 150, 230)),
            Self::Camera => ((170, 60, 100), (235, 140, 175)),
            Self::Other => ((100, 100, 100), (170, 170, 170)),
        };
        let (r, g, b) = if dark { d } else { l };
        Color32::from_rgb(r, g, b)
    }
}

/// The class of a node: from its kind in the graph, then its device type, then its open ports.
pub(super) fn classify(kind: topology::Kind, device_type: &str, open: &[u16]) -> Class {
    match kind {
        topology::Kind::Source => return Class::Scanner,
        topology::Kind::Router => return Class::Hop,
        topology::Kind::Unknown => return Class::Silent,
        _ => {}
    }
    let t = device_type.to_lowercase();
    let has = |words: &[&str]| words.iter().any(|w| t.contains(w));
    if has(&[
        "plc",
        "controller",
        "hmi",
        "i/o",
        "rtu",
        "drive",
        "scada",
        "building",
    ]) {
        Class::Controller
    } else if has(&[
        "switch",
        "router",
        "gateway",
        "firewall",
        "access point",
        "wlan",
        "network",
    ]) {
        Class::Network
    } else if has(&["printer", "mfp"]) {
        Class::Printer
    } else if has(&["camera", "nvr", "dvr"]) {
        Class::Camera
    } else if has(&["server", "nas", "storage", "historian", "database"]) {
        Class::Server
    } else if has(&["workstation", "laptop", "desktop", "pc", "computer"]) {
        Class::Workstation
    } else if !t.is_empty() {
        Class::Other
    } else if open
        .iter()
        .any(|p| [102, 502, 4840, 44818, 47808, 20000].contains(p))
    {
        Class::Controller
    } else if open.iter().any(|p| [515, 631, 9100].contains(p)) {
        Class::Printer
    } else if open.contains(&554) {
        Class::Camera
    } else if open.iter().any(|p| [135, 445, 3389].contains(p)) {
        Class::Workstation
    } else {
        Class::Other
    }
}

/// What the drawing needs to know about one node besides the graph.
#[derive(Clone, Debug)]
pub(super) struct NodeInfo {
    pub class: Class,
    pub risk: Option<risk::Severity>,
    pub ip: Option<IpAddr>,
}

/// The part of the map in view: the map point at the middle of the canvas and the zoom (screen
/// pixels per map unit). Panning and zooming change it; the drawing keeps nodes and text at a
/// fixed pixel size, so a zoomed-out map of hundreds of nodes stays readable.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct View {
    pub center: [f32; 2],
    pub zoom: f32,
}
/// The zoom limits.
const ZOOM_RANGE: (f32, f32) = (0.02, 8.0);
impl View {
    /// The view that shows all of `bounds` (`[min_x, min_y, max_x, max_y]`) in a canvas of
    /// `size` pixels.
    pub fn fit(bounds: [f32; 4], size: [f32; 2]) -> Self {
        let (w, h) = (
            (bounds[2] - bounds[0]).max(1.0),
            (bounds[3] - bounds[1]).max(1.0),
        );
        let zoom = (size[0].max(1.0) / w).min(size[1].max(1.0) / h);
        Self {
            center: [(bounds[0] + bounds[2]) / 2.0, (bounds[1] + bounds[3]) / 2.0],
            zoom: zoom.clamp(ZOOM_RANGE.0, ZOOM_RANGE.1),
        }
    }
    /// Where a map point is on screen, for a canvas whose middle is at `middle`.
    pub fn to_screen(self, p: [f32; 2], middle: [f32; 2]) -> [f32; 2] {
        [
            middle[0] + (p[0] - self.center[0]) * self.zoom,
            middle[1] + (p[1] - self.center[1]) * self.zoom,
        ]
    }
    /// The map point at a screen position.
    pub fn to_map(self, s: [f32; 2], middle: [f32; 2]) -> [f32; 2] {
        [
            self.center[0] + (s[0] - middle[0]) / self.zoom,
            self.center[1] + (s[1] - middle[1]) / self.zoom,
        ]
    }
    /// Moves the map by a drag of `delta` pixels.
    pub fn pan(&mut self, delta: [f32; 2]) {
        self.center[0] -= delta[0] / self.zoom;
        self.center[1] -= delta[1] / self.zoom;
    }
    /// Zooms by `factor` keeping the map point under the screen position `at` where it is.
    pub fn zoom_at(&mut self, factor: f32, at: [f32; 2], middle: [f32; 2]) {
        let before = self.to_map(at, middle);
        self.zoom = (self.zoom * factor).clamp(ZOOM_RANGE.0, ZOOM_RANGE.1);
        self.center = [
            before[0] - (at[0] - middle[0]) / self.zoom,
            before[1] - (at[1] - middle[1]) / self.zoom,
        ];
    }
}

pub(super) struct MapState {
    /// The part of the map in view (changed by panning and zooming).
    pub view: View,
    /// The data generations the layout was computed for.
    pub key: Option<(u64, u64)>,
    pub positions: Vec<[f32; 2]>,
    pub info: Vec<NodeInfo>,
    /// Show the whole map on the next frame.
    pub fit: bool,
    pub selected: Option<usize>,
}
impl Default for MapState {
    fn default() -> Self {
        Self {
            view: View {
                center: [0.0, 0.0],
                zoom: 1.0,
            },
            key: None,
            positions: vec![],
            info: vec![],
            fit: true,
            selected: None,
        }
    }
}

/// The node nearest to `at` (a screen position) within `radius` pixels, among `screen` positions.
pub(super) fn nearest(screen: &[(usize, [f32; 2])], at: [f32; 2], radius: f32) -> Option<usize> {
    screen
        .iter()
        .map(|&(i, p)| (i, (p[0] - at[0]).powi(2) + (p[1] - at[1]).powi(2)))
        .filter(|&(_, d2)| d2 <= radius * radius)
        .min_by(|a, b| a.1.total_cmp(&b.1).then(a.0.cmp(&b.0)))
        .map(|(i, _)| i)
}

/// Whether a label rectangle `[min_x, min_y, max_x, max_y]` is clear of those already placed.
pub(super) fn fits(placed: &[[f32; 4]], r: [f32; 4]) -> bool {
    placed
        .iter()
        .all(|p| r[2] < p[0] || r[0] > p[2] || r[3] < p[1] || r[1] > p[3])
}

/// The nodes to label: the selected one first, then the scanner, routers and nodes with a bad
/// finding, then the rest in order, at most `limit` of the `visible` ones.
pub(super) fn label_order(
    visible: &[usize],
    info: &[NodeInfo],
    selected: Option<usize>,
    limit: usize,
) -> Vec<usize> {
    let rank = |i: usize| -> u8 {
        if Some(i) == selected {
            0
        } else if matches!(info[i].class, Class::Scanner) {
            1
        } else if info[i].risk.is_some_and(|r| r >= risk::Severity::High) {
            2
        } else if matches!(info[i].class, Class::Hop) {
            3
        } else {
            4
        }
    };
    let mut order: Vec<usize> = visible.to_vec();
    order.sort_by_key(|&i| (rank(i), i));
    order.truncate(limit);
    order
}

impl Scanner {
    fn map_data(&mut self) {
        if self.topology.stale(self.generation, self.live()) {
            let graph = topology::build(&self.results);
            let layers = topology::layers(&graph);
            self.topology.set(self.generation, (graph, layers));
        }
        self.ensure_findings();
        let key = (
            self.topology.generation.unwrap_or(0),
            self.findings.generation.unwrap_or(0),
        );
        if self.map.key == Some(key) {
            return;
        }
        let graph = &self.topology.value.0;
        let by_ip: HashMap<IpAddr, &scan::Host> = self.results.iter().map(|h| (h.ip, h)).collect();
        let worst = tables::risk_by_ip(&self.findings.value);
        self.map.positions = netmap::layout(graph);
        self.map.info = graph
            .nodes
            .iter()
            .map(|node| {
                let ip = node.id.parse::<IpAddr>().ok();
                let host = ip.and_then(|ip| by_ip.get(&ip).copied());
                let device_type = host
                    .and_then(|h| h.identity.get("device.type"))
                    .map_or("", String::as_str);
                NodeInfo {
                    class: classify(node.kind, device_type, host.map_or(&[][..], |h| &h.open)),
                    risk: ip.and_then(|ip| worst.get(&ip).copied()),
                    ip,
                }
            })
            .collect();
        if self.map.key.is_none() {
            self.map.fit = true;
        }
        self.map.selected = self.map.selected.filter(|&i| i < graph.nodes.len());
        self.map.key = Some(key);
    }

    /// The Network map page.
    pub(super) fn map_view(&mut self, ui: &mut egui::Ui) {
        self.map_data();
        let mut focus: Option<IpAddr> = None;
        let mut selected = self.map.selected;
        let mut view = self.map.view;
        let mut fit = self.map.fit;
        let mut ask_fit = false;
        let graph = &self.topology.value.0;
        let (positions, info) = (&self.map.positions, &self.map.info);
        super::windows::page(ui, tr!("Network map"), |ui| {
            let dark = ui.visuals().dark_mode;
            let hosts = graph
                .nodes
                .iter()
                .filter(|n| n.kind == topology::Kind::Host)
                .count();
            ui.horizontal_wrapped(|ui| {
                    ui.label(tr!(
                        "{} nodes ({} hosts), {} links. Drag to move, scroll to zoom, click a host for its details.",
                        graph.nodes.len(),
                        hosts,
                        graph.edges.len()
                    ));
                    if ui.button(tr!("Fit to window")).clicked() {
                        ask_fit = true;
                    }
                });
            ui.horizontal_wrapped(|ui| {
                for class in Class::LEGEND {
                    let (rect, _) =
                        ui.allocate_exact_size(egui::vec2(12.0, 12.0), egui::Sense::hover());
                    ui.painter()
                        .circle_filled(rect.center(), 5.0, class.color(dark));
                    ui.label(class.name());
                }
                ui.label(tr!("A dot in the corner is the worst finding of the host."));
            });
            if graph.nodes.len() <= 1 {
                ui.weak(tr!("No devices to draw yet. Scan, and enable \"Record router path\" in Settings to see the path to each device."));
            }
            // The page is the map: leave room only for the list header and the selected node.
            let height = (ui.available_height() - 70.0).max(220.0);
            egui::Frame::canvas(ui.style()).show(ui, |ui| {
                let size = egui::vec2(ui.available_width(), height);
                let (rect, response) = ui.allocate_exact_size(size, egui::Sense::click_and_drag());
                if fit || ask_fit {
                    view = View::fit(
                        netmap::bounds(positions, 40.0),
                        [rect.width(), rect.height()],
                    );
                    fit = false;
                }
                draw_graph(
                    ui,
                    rect,
                    &response,
                    graph,
                    positions,
                    info,
                    &mut view,
                    &mut selected,
                    &mut focus,
                    dark,
                );
            });
            ui.collapsing(tr!("Show the devices as a list"), |ui| {
                let row = ui.text_style_height(&egui::TextStyle::Body) + 4.0;
                egui::ScrollArea::vertical()
                    .id_salt("map_list")
                    .max_height(150.0)
                    .show_rows(ui, row, graph.nodes.len(), |ui, range| {
                        for i in range {
                            let node = &graph.nodes[i];
                            let worst = info[i].risk.map_or(String::new(), |r| {
                                format!(" · {}", home::severity_name(r))
                            });
                            let text = format!("{} · {}{worst}", node.label, info[i].class.name());
                            if ui.selectable_label(selected == Some(i), text).clicked() {
                                selected = Some(i);
                                focus = info[i].ip;
                            }
                        }
                    });
            });
            if let Some(i) = selected.filter(|&i| i < graph.nodes.len()) {
                let node = &graph.nodes[i];
                ui.label(format!(
                    "{} · {}{}",
                    node.label,
                    info[i].class.name(),
                    if node.detail.is_empty() {
                        String::new()
                    } else {
                        format!(" · {}", node.detail)
                    }
                ));
            }
        });
        self.map.selected = selected;
        self.map.view = view;
        self.map.fit = fit;
        if let Some(ip) = focus {
            self.focus_host(&[ip]);
        }
    }
}

/// Draws the links, nodes and labels on the canvas `rect` and handles panning, zooming, hover and
/// clicks. Nodes and text keep a fixed pixel size; only the positions follow the zoom. At most
/// [`MAX_LABELS`] labels are drawn, and none that would overlap one already drawn.
#[allow(clippy::too_many_arguments)]
fn draw_graph(
    ui: &mut egui::Ui,
    rect: egui::Rect,
    response: &egui::Response,
    graph: &topology::Graph,
    positions: &[[f32; 2]],
    info: &[NodeInfo],
    view: &mut View,
    selected: &mut Option<usize>,
    focus: &mut Option<IpAddr>,
    dark: bool,
) {
    let middle = [rect.center().x, rect.center().y];
    if response.dragged() {
        let d = response.drag_delta();
        view.pan([d.x, d.y]);
    }
    if response.hovered() {
        let (scroll, pinch) = ui.input(|i| (i.smooth_scroll_delta.y, i.zoom_delta()));
        let factor = pinch * (scroll * 0.0025).exp();
        if (factor - 1.0).abs() > 1e-4
            && let Some(p) = response.hover_pos()
        {
            view.zoom_at(factor, [p.x, p.y], middle);
        }
    }
    let painter = ui.painter_at(rect);
    let screen_of = |i: usize| view.to_screen(positions[i], middle);
    let on_screen = rect.expand(30.0);
    let at = |i: usize| {
        let p = screen_of(i);
        egui::pos2(p[0], p[1])
    };
    let edge_color = if dark {
        Color32::from_gray(110)
    } else {
        Color32::from_gray(170)
    };
    for &(a, b) in &graph.edges {
        if a < positions.len() && b < positions.len() {
            let (pa, pb) = (at(a), at(b));
            if on_screen.intersects(egui::Rect::from_two_pos(pa, pb)) {
                painter.line_segment([pa, pb], egui::Stroke::new(1.0, edge_color));
            }
        }
    }
    let visible: Vec<usize> = (0..graph.nodes.len())
        .filter(|&i| on_screen.contains(at(i)))
        .collect();
    let screen: Vec<(usize, [f32; 2])> = visible.iter().map(|&i| (i, screen_of(i))).collect();
    let hovered = response
        .hover_pos()
        .and_then(|p| nearest(&screen, [p.x, p.y], 10.0));
    if response.clicked()
        && let Some(i) = response
            .interact_pointer_pos()
            .and_then(|p| nearest(&screen, [p.x, p.y], 10.0))
    {
        *selected = Some(i);
        *focus = info[i].ip;
    }
    for &i in &visible {
        let class = info[i].class;
        let radius = match class {
            Class::Scanner => 8.0,
            Class::Hop | Class::Silent => 5.0,
            _ => 6.0,
        };
        let (center, color) = (at(i), class.color(dark));
        match class {
            Class::Hop | Class::Silent => {
                painter.rect_filled(
                    egui::Rect::from_center_size(center, egui::Vec2::splat(radius * 1.7)),
                    2.0,
                    color,
                );
            }
            _ => {
                painter.circle_filled(center, radius, color);
            }
        }
        if *selected == Some(i) || hovered == Some(i) {
            painter.circle_stroke(
                center,
                radius + 3.0,
                egui::Stroke::new(2.0, ui.visuals().strong_text_color()),
            );
        }
        if let Some(sev) = info[i].risk {
            let badge = center + egui::vec2(radius * 0.9, -radius * 0.9);
            painter.circle_filled(badge, 4.0, home::severity_color(sev, dark));
            painter.circle_stroke(
                badge,
                4.0,
                egui::Stroke::new(1.0, ui.visuals().extreme_bg_color),
            );
        }
    }
    let font = egui::FontId::proportional(11.0);
    let text_color = ui.visuals().text_color();
    let back = ui.visuals().extreme_bg_color.gamma_multiply(0.8);
    let mut order = label_order(&visible, info, *selected, MAX_LABELS);
    if let Some(h) = hovered {
        order.retain(|&i| i != h);
        order.insert(0, h);
    }
    let mut placed: Vec<[f32; 4]> = vec![];
    for i in order {
        let label: String = graph.nodes[i].label.chars().take(30).collect();
        let galley = painter.layout_no_wrap(label, font.clone(), text_color);
        let top_left = at(i) + egui::vec2(10.0, -galley.size().y / 2.0);
        let r = egui::Rect::from_min_size(top_left, galley.size()).expand2(egui::vec2(2.0, 1.0));
        let key = [r.min.x, r.min.y, r.max.x, r.max.y];
        // The hovered and the selected node are always labelled.
        if hovered == Some(i) || *selected == Some(i) || fits(&placed, key) {
            painter.rect_filled(r, 2.0, back);
            painter.galley(top_left, galley, text_color);
            placed.push(key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(class: Class, risk: Option<risk::Severity>) -> NodeInfo {
        NodeInfo {
            class,
            risk,
            ip: None,
        }
    }

    #[test]
    fn device_types_choose_the_class() {
        use topology::Kind::*;
        for (kind, device, ports, class) in [
            (Source, "", &[][..], Class::Scanner),
            (Router, "", &[], Class::Hop),
            (Unknown, "", &[], Class::Silent),
            (Host, "PLC", &[], Class::Controller),
            (Host, "Remote I/O", &[], Class::Controller),
            (Host, "Building controller", &[], Class::Controller),
            (Host, "HMI", &[], Class::Controller),
            (Host, "Switch", &[], Class::Network),
            (Host, "Printer", &[], Class::Printer),
            (Host, "IP camera", &[], Class::Camera),
            (Host, "Workstation", &[], Class::Workstation),
            (Host, "NAS", &[], Class::Server),
            (Host, "Toaster", &[], Class::Other),
            // Without a device type the open ports decide.
            (Host, "", &[502][..], Class::Controller),
            (Host, "", &[9100][..], Class::Printer),
            (Host, "", &[554][..], Class::Camera),
            (Host, "", &[3389][..], Class::Workstation),
            (Host, "", &[22][..], Class::Other),
            (Host, "", &[][..], Class::Other),
        ] {
            assert_eq!(
                classify(kind, device, ports),
                class,
                "{kind:?} {device:?} {ports:?}"
            );
        }
    }

    #[test]
    fn every_class_has_a_name_and_two_distinct_theme_colours() {
        let all = [
            Class::Scanner,
            Class::Hop,
            Class::Silent,
            Class::Controller,
            Class::Network,
            Class::Server,
            Class::Workstation,
            Class::Printer,
            Class::Camera,
            Class::Other,
        ];
        let names: std::collections::BTreeSet<_> = all.iter().map(|c| c.name()).collect();
        assert_eq!(names.len(), all.len());
        for c in all {
            assert_ne!(c.color(false), c.color(true), "{c:?}");
        }
        assert!(Class::LEGEND.iter().all(|c| all.contains(c)));
    }

    #[test]
    fn labels_are_capped_and_prefer_the_important_nodes() {
        let n = 300;
        let mut infos: Vec<NodeInfo> = (0..n).map(|_| info(Class::Other, None)).collect();
        infos[0] = info(Class::Scanner, None);
        infos[250] = info(Class::Workstation, Some(risk::Severity::Critical));
        infos[100] = info(Class::Hop, None);
        infos[7] = info(Class::Other, Some(risk::Severity::Low));
        let visible: Vec<usize> = (0..n).collect();
        let order = label_order(&visible, &infos, Some(42), MAX_LABELS);
        assert_eq!(order.len(), MAX_LABELS);
        assert_eq!(
            &order[..4],
            &[42, 0, 250, 100],
            "selected, scanner, risky, router first"
        );
        // No duplicates, and a small graph labels everything.
        let unique: std::collections::BTreeSet<_> = order.iter().collect();
        assert_eq!(unique.len(), order.len());
        assert_eq!(label_order(&[3, 1, 2], &infos, None, MAX_LABELS).len(), 3);
        assert!(label_order(&[], &infos, None, MAX_LABELS).is_empty());
    }

    #[test]
    fn the_view_fits_the_whole_map_even_when_it_is_empty() {
        let v = View::fit(netmap::bounds(&[], 40.0), [800.0, 400.0]);
        assert!(v.zoom.is_finite() && v.zoom > 0.0);
        let bounds = netmap::bounds(&[[-100.0, 0.0], [300.0, 200.0]], 10.0);
        let v = View::fit(bounds, [800.0, 400.0]);
        // Both corners land inside the canvas.
        let middle = [400.0, 200.0];
        for corner in [[-100.0, 0.0], [300.0, 200.0]] {
            let s = v.to_screen(corner, middle);
            assert!(
                (0.0..=800.0).contains(&s[0]) && (0.0..=400.0).contains(&s[1]),
                "{s:?}"
            );
        }
        assert!(
            View::fit([0.0, 0.0, 0.0, 0.0], [0.0, 0.0]).zoom.is_finite(),
            "degenerate input"
        );
    }

    #[test]
    fn panning_and_zooming_keep_the_point_under_the_pointer() {
        let middle = [400.0, 200.0];
        let mut v = View {
            center: [10.0, 20.0],
            zoom: 2.0,
        };
        let there = [250.0, 120.0];
        let map_point = v.to_map(there, middle);
        v.zoom_at(1.5, there, middle);
        let after = v.to_map(there, middle);
        assert!((after[0] - map_point[0]).abs() < 1e-3 && (after[1] - map_point[1]).abs() < 1e-3);
        assert!((v.zoom - 3.0).abs() < 1e-5);
        // To the screen and back.
        let p = [33.0, -7.0];
        let back = v.to_map(v.to_screen(p, middle), middle);
        assert!((back[0] - p[0]).abs() < 1e-3 && (back[1] - p[1]).abs() < 1e-3);
        // A drag moves the map with the pointer.
        let mut v = View {
            center: [0.0, 0.0],
            zoom: 2.0,
        };
        let before = v.to_screen([5.0, 5.0], middle);
        v.pan([20.0, -10.0]);
        let after = v.to_screen([5.0, 5.0], middle);
        assert_eq!([after[0] - before[0], after[1] - before[1]], [20.0, -10.0]);
        // The zoom stays within its limits.
        let mut v = View {
            center: [0.0, 0.0],
            zoom: 1.0,
        };
        v.zoom_at(1e9, middle, middle);
        assert_eq!(v.zoom, ZOOM_RANGE.1);
        v.zoom_at(1e-9, middle, middle);
        assert_eq!(v.zoom, ZOOM_RANGE.0);
    }

    #[test]
    fn the_nearest_node_within_the_radius_is_picked() {
        let screen = [
            (0, [100.0, 100.0]),
            (1, [108.0, 100.0]),
            (2, [300.0, 300.0]),
        ];
        assert_eq!(nearest(&screen, [107.0, 100.0], 10.0), Some(1));
        assert_eq!(nearest(&screen, [101.0, 100.0], 10.0), Some(0));
        assert_eq!(nearest(&screen, [200.0, 200.0], 10.0), None);
        assert_eq!(nearest(&[], [0.0, 0.0], 10.0), None);
        // On an exact tie the lower index wins, so the pick is stable.
        assert_eq!(
            nearest(&[(3, [0.0, 5.0]), (2, [0.0, -5.0])], [0.0, 0.0], 10.0),
            Some(2)
        );
    }

    #[test]
    fn labels_that_would_overlap_are_left_out() {
        let first = [0.0, 0.0, 50.0, 12.0];
        assert!(fits(&[], first));
        assert!(!fits(&[first], [40.0, 5.0, 90.0, 17.0]), "overlaps");
        assert!(fits(&[first], [60.0, 0.0, 110.0, 12.0]), "beside");
        assert!(fits(&[first], [0.0, 20.0, 50.0, 32.0]), "below");
        assert!(!fits(&[first], [10.0, 2.0, 20.0, 8.0]), "inside");
    }
}
