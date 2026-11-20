//! The unknown-device workbench window (ROADMAP L73), the desktop counterpart of
//! `fingerprints groups|compare|draft`: it lists the groups of similar banners that no rule
//! identified, shows one group's variants (or two groups side by side), and turns a group into a
//! draft probe file with the pull request checklist.
//!
//! It calls the functions of `service::workbench` (the same ones the CLI calls) on the inventory
//! worker: reading the saved scans and grouping, drafting and writing the files never run on the
//! UI thread. It reads the local inventory only and sends nothing, and the file it writes holds
//! the banner texts (host data replaced), which the user reads and redacts before sharing them.
use super::*;
use crate::service::workbench::{self, Draft, Group};
use std::path::Path;

/// What the worker found in the saved scans.
pub(super) struct GroupsData {
    pub groups: Vec<Group>,
    /// How many saved scans were read.
    pub scans: usize,
}

/// A draft with the Markdown checklist that is written beside the probe file.
pub(super) struct DraftView {
    pub draft: Draft,
    pub checklist_md: String,
}

/// The window's state.
#[derive(Default)]
pub(super) struct WorkbenchState {
    pub open: bool,
    /// Matches the answer of the worker to the latest request for the groups.
    pub token: u64,
    /// `None` while the worker reads the saved scans.
    pub data: Option<Result<Box<GroupsData>, String>>,
    /// The id of the group on view.
    pub selected: Option<String>,
    /// The id of the group it is compared with.
    pub other: Option<String>,
    /// Matches the answer of the worker to the latest request for a draft.
    pub draft_token: u64,
    /// The draft of the selected group (its id first), or why the workbench refused to make one.
    pub draft: Option<(String, Result<Box<DraftView>, String>)>,
    /// A draft is being made.
    pub drafting: bool,
    /// What the last file write did: the probe file and checklist paths, or the error.
    pub written: Option<Result<(String, String), String>>,
    /// Screenshot runs: show the end of the detail area (the draft and its checklist).
    pub show_end: bool,
}

impl WorkbenchState {
    /// Starts a new read of the saved scans; returns the token the answer must carry.
    pub fn request(&mut self) -> u64 {
        self.token += 1;
        self.data = None;
        self.draft = None;
        self.drafting = false;
        self.written = None;
        self.token
    }

    /// An answer of the worker. One for an older request is dropped (returns false). The
    /// selections that no longer exist (the scans changed) are cleared.
    pub fn loaded(&mut self, token: u64, result: Result<Box<GroupsData>, String>) -> bool {
        if token != self.token {
            return false;
        }
        if let Ok(data) = &result {
            let has = |id: &Option<String>| {
                id.as_ref()
                    .is_some_and(|id| data.groups.iter().any(|g| &g.id == id))
            };
            if !has(&self.selected) {
                self.selected = None;
                self.other = None;
                self.draft = None;
            }
            if !has(&self.other) {
                self.other = None;
            }
        }
        self.data = Some(result);
        true
    }

    pub fn groups(&self) -> &[Group] {
        match &self.data {
            Some(Ok(data)) => &data.groups,
            _ => &[],
        }
    }

    fn group(&self, id: &Option<String>) -> Option<&Group> {
        let id = id.as_ref()?;
        self.groups().iter().find(|g| &g.id == id)
    }
    pub fn selected_group(&self) -> Option<&Group> {
        self.group(&self.selected)
    }
    pub fn other_group(&self) -> Option<&Group> {
        self.group(&self.other)
    }

    /// Shows another group: its draft and the last file notice belong to the old one.
    pub fn select(&mut self, id: &str) {
        if self.selected.as_deref() == Some(id) {
            return;
        }
        self.selected = Some(id.to_string());
        if self.other.as_deref() == Some(id) {
            self.other = None;
        }
        self.draft_token += 1;
        self.draft = None;
        self.drafting = false;
        self.written = None;
    }

    /// Compares the group on view with another one (`None` ends the comparison). The group on
    /// view cannot be compared with itself.
    pub fn compare_with(&mut self, id: Option<&str>) {
        self.other = id
            .filter(|id| self.selected.as_deref() != Some(*id))
            .map(str::to_string);
    }

    /// The request for a draft of the group on view: the token the answer must carry and the
    /// group the worker drafts. `None` when nothing is selected.
    pub fn ask_draft(&mut self) -> Option<(u64, Box<Group>)> {
        let group = self.selected_group()?.clone();
        self.draft_token += 1;
        self.draft = None;
        self.written = None;
        self.drafting = true;
        Some((self.draft_token, Box::new(group)))
    }

    /// An answer of the worker for a draft; one for an older request or another group is dropped.
    pub fn drafted(
        &mut self,
        token: u64,
        group: String,
        result: Result<Box<DraftView>, String>,
    ) -> bool {
        if token != self.draft_token || self.selected.as_deref() != Some(group.as_str()) {
            return false;
        }
        self.drafting = false;
        self.draft = Some((group, result));
        true
    }

    /// The draft of the group on view, if one was made.
    pub fn current_draft(&self) -> Option<&Result<Box<DraftView>, String>> {
        let (id, result) = self.draft.as_ref()?;
        (self.selected.as_deref() == Some(id.as_str())).then_some(result)
    }
}

/// Reads every saved scan and groups the unidentified banners: what `fingerprints groups` does
/// without a scan id. Runs on the inventory worker.
pub(super) fn load_groups(db: &Path) -> Result<Box<GroupsData>, String> {
    let snapshots = store::list(db)?
        .into_iter()
        .map(|e| store::load(db, e.id))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Box::new(GroupsData {
        groups: workbench::groups(&snapshots),
        scans: snapshots.len(),
    }))
}

/// The draft of a group and its checklist file: `fingerprints draft`. Runs on the worker.
pub(super) fn make_draft(group: &Group) -> Result<Box<DraftView>, String> {
    let draft = workbench::draft(group)?;
    let checklist_md = workbench::checklist_markdown(&draft, group);
    Ok(Box::new(DraftView {
        draft,
        checklist_md,
    }))
}

/// The path of the checklist that belongs to a probe file: `FILE.checklist.md`.
pub(super) fn checklist_path(file: &Path) -> std::path::PathBuf {
    let mut name = file.as_os_str().to_owned();
    name.push(".checklist.md");
    name.into()
}

/// Writes the probe file and the checklist exactly as `fingerprints draft --output FILE` does:
/// FILE holds the probe file and a newline, FILE.checklist.md the checklist. Returns both paths.
/// Runs on the worker.
pub(super) fn write_draft(file: &Path, view: &DraftView) -> Result<(String, String), String> {
    let checklist = checklist_path(file);
    std::fs::write(file, format!("{}\n", view.draft.probe_file))
        .map_err(|e| format!("{}: {e}", file.display()))?;
    std::fs::write(&checklist, &view.checklist_md)
        .map_err(|e| format!("{}: {e}", checklist.display()))?;
    Ok((file.display().to_string(), checklist.display().to_string()))
}

fn ports_text(ports: &[u16]) -> String {
    ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// One line of the list of groups.
pub(super) fn group_line(g: &Group) -> String {
    let mut line = tr!(
        "{} · {} hosts · {} banners · port {} · {}",
        g.id,
        g.hosts,
        g.banners,
        ports_text(&g.ports),
        g.template
    );
    if let Some(hint) = &g.port_hint {
        line.push_str(&format!(" ({})", tr!("port suggests {}", hint)));
    }
    line
}

/// The line that says how alike two groups are, from the commonest banner of each.
pub(super) fn similarity_line(a: &Group, b: &Group) -> String {
    let (Some(x), Some(y)) = (a.variants.first(), b.variants.first()) else {
        return String::new();
    };
    let score = workbench::similarity(&x.banner, &y.banner);
    let verdict = if score >= workbench::THRESHOLD {
        tr!("they would be one group")
    } else {
        tr!("different products or protocols")
    };
    tr!(
        "Similarity of the commonest banners: {} (a group needs at least {}): {}",
        format!("{score:.2}"),
        format!("{:.2}", workbench::THRESHOLD),
        verdict
    )
}

/// The rows of the side-by-side comparison: what, group A, group B.
pub(super) fn compare_rows(a: &Group, b: &Group) -> Vec<(String, String, String)> {
    let vendors = |g: &Group| {
        if g.vendors.is_empty() {
            "—".to_string()
        } else {
            g.vendors.join(", ")
        }
    };
    let varying = |g: &Group| {
        if g.varying.is_empty() {
            "—".to_string()
        } else {
            g.varying.join("; ")
        }
    };
    let hint = |g: &Group| g.port_hint.clone().unwrap_or_else(|| "—".into());
    vec![
        (tr!("Group").to_string(), a.id.clone(), b.id.clone()),
        (
            tr!("Template").to_string(),
            a.template.clone(),
            b.template.clone(),
        ),
        (
            tr!("Ports").to_string(),
            ports_text(&a.ports),
            ports_text(&b.ports),
        ),
        (
            tr!("The port number suggests").to_string(),
            hint(a),
            hint(b),
        ),
        (
            tr!("Hosts").to_string(),
            a.hosts.to_string(),
            b.hosts.to_string(),
        ),
        (
            tr!("Distinct banners").to_string(),
            a.banners.to_string(),
            b.banners.to_string(),
        ),
        (tr!("MAC vendors").to_string(), vendors(a), vendors(b)),
        (tr!("Differs").to_string(), varying(a), varying(b)),
    ]
}

/// The versions of a variant, or a dash.
fn versions_text(versions: &[String]) -> String {
    if versions.is_empty() {
        "—".into()
    } else {
        versions.join(" / ")
    }
}

impl Scanner {
    /// Opens the window and reads the saved scans (screenshot runs show their sample data).
    pub(super) fn open_workbench(&mut self) {
        self.workbench.open = true;
        if self.workbench.data.is_none() || self.screenshot.is_none() {
            self.refresh_workbench();
        }
    }

    pub(super) fn refresh_workbench(&mut self) {
        let token = self.workbench.request();
        if self.screenshot.is_none() {
            self.submit(Job::Groups(token));
        }
    }

    /// The answers of the worker.
    pub(super) fn groups_loaded(&mut self, token: u64, result: Result<Box<GroupsData>, String>) {
        self.busy.workbench = false;
        self.workbench.loaded(token, result);
    }
    pub(super) fn draft_made(
        &mut self,
        token: u64,
        group: String,
        result: Result<Box<DraftView>, String>,
    ) {
        self.busy.drafting = false;
        self.workbench.drafted(token, group, result);
    }
    pub(super) fn draft_written(&mut self, result: Result<(String, String), String>) {
        self.busy.writing_draft = false;
        if let Ok((file, _)) = &result {
            self.status = tr!("Saved {}", file);
        }
        self.workbench.written = Some(result);
    }

    /// Asks for a file name and has the worker write the probe file and its checklist.
    fn save_draft(&mut self, group: &str, view: &DraftView) {
        let Some(path) = rfd::FileDialog::new()
            .set_file_name(format!("probes-{group}.json"))
            .add_filter(tr!("Probe file"), &["json"])
            .save_file()
        else {
            return;
        };
        let copy = DraftView {
            draft: view.draft.clone(),
            checklist_md: view.checklist_md.clone(),
        };
        self.submit(Job::WriteDraft(Box::new(copy), path));
    }

    pub(super) fn workbench_window(&mut self, ctx: &egui::Context) {
        if !self.workbench.open {
            return;
        }
        let mut open = true;
        let mut refresh = false;
        let mut pick: Option<String> = None;
        let mut other: Option<Option<String>> = None;
        let mut draft = false;
        let mut save: Option<(String, DraftView)> = None;
        let busy = self.workbench.data.is_none();
        let st = &self.workbench;
        egui::Window::new(tr!("Unknown devices: banner workbench"))
            .open(&mut open)
            .default_size(win_size([700.0, 470.0]))
            .default_pos(self.window_origin)
            .max_width((ctx.content_rect().width() - 24.0).max(320.0))
            .show(ctx, |ui| {
                ui.label(
                    RichText::new(tr!(
                        "Banners of services that no rule identified, grouped by how alike they are. This reads the saved scans only and sends nothing."
                    ))
                    .small()
                    .color(ui.visuals().weak_text_color()),
                );
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(!busy, egui::Button::new(tr!("Refresh")))
                        .clicked()
                    {
                        refresh = true;
                    }
                    match &st.data {
                        None => {
                            ui.spinner();
                            ui.label(tr!("Reading the saved scans…"));
                        }
                        Some(Ok(d)) => {
                            ui.label(tr!("{} groups from {} saved scans", d.groups.len(), d.scans));
                        }
                        Some(Err(_)) => {}
                    }
                });
                if let Some(Err(e)) = &st.data {
                    ui.colored_label(Color32::from_rgb(205, 70, 70), e);
                    return;
                }
                if let Some(Ok(d)) = &st.data
                    && d.groups.is_empty()
                {
                    ui.label(tr!("No unidentified banners in the stored scans."));
                    return;
                }
                ui.separator();
                egui::ScrollArea::vertical()
                    .id_salt("workbench_groups")
                    .max_height(130.0)
                    .auto_shrink([false, true])
                    .show(ui, |ui| {
                        for g in st.groups() {
                            let on = st.selected.as_deref() == Some(g.id.as_str());
                            if ui.selectable_label(on, group_line(g)).clicked() {
                                pick = Some(g.id.clone());
                            }
                        }
                    });
                let Some(group) = st.selected_group() else {
                    ui.label(tr!("Choose a group to see its variants."));
                    return;
                };
                ui.separator();
                egui::ScrollArea::vertical()
                    .id_salt("workbench_detail")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        // Compare with another group.
                        ui.horizontal(|ui| {
                            ui.label(tr!("Compare with"));
                            let shown = st
                                .other_group()
                                .map_or_else(|| tr!("(none)").to_string(), |g| g.id.clone());
                            let combo = egui::ComboBox::from_id_salt("workbench_other")
                                .selected_text(shown)
                                .show_ui(ui, |ui| {
                                    if ui.selectable_label(st.other.is_none(), tr!("(none)")).clicked() {
                                        other = Some(None);
                                    }
                                    for g in st.groups().iter().filter(|g| g.id != group.id) {
                                        let on = st.other.as_deref() == Some(g.id.as_str());
                                        if ui.selectable_label(on, group_line(g)).clicked() {
                                            other = Some(Some(g.id.clone()));
                                        }
                                    }
                                });
                            super::a11y::named(combo.response, tr!("Compare with"));
                        });
                        match st.other_group() {
                            Some(b) => {
                                egui::Grid::new("workbench_compare")
                                    .num_columns(3)
                                    .striped(true)
                                    .show(ui, |ui| {
                                        for (what, x, y) in compare_rows(group, b) {
                                            ui.strong(what);
                                            ui.label(x);
                                            ui.label(y);
                                            ui.end_row();
                                        }
                                    });
                                ui.label(similarity_line(group, b));
                            }
                            None => variants_view(ui, group),
                        }
                        ui.separator();
                        ui.horizontal(|ui| {
                            if ui
                                .add_enabled(!st.drafting, egui::Button::new(tr!("Draft a probe rule")))
                                .on_hover_text(tr!(
                                    "Builds a rule for data/probes.json from the banners of the group on view. It only listens: the rule adds no probe that sends anything."
                                ))
                                .clicked()
                            {
                                draft = true;
                            }
                            if st.drafting {
                                ui.spinner();
                            }
                        });
                        match st.current_draft() {
                            Some(Err(e)) => {
                                ui.colored_label(Color32::from_rgb(205, 70, 70), e);
                            }
                            Some(Ok(view)) => {
                                draft_view(ui, view);
                                if ui.button(tr!("Save probe file…")).clicked() {
                                    save = Some((
                                        group.id.clone(),
                                        DraftView {
                                            draft: view.draft.clone(),
                                            checklist_md: view.checklist_md.clone(),
                                        },
                                    ));
                                }
                            }
                            None => {}
                        }
                        match &st.written {
                            Some(Ok((file, checklist))) => {
                                ui.label(tr!(
                                    "Wrote {} (check it with `probes validate`) and {}. Read both and remove anything that identifies a person, host or site; nothing was sent.",
                                    file,
                                    checklist
                                ));
                            }
                            Some(Err(e)) => {
                                ui.colored_label(Color32::from_rgb(205, 70, 70), e);
                            }
                            None => {}
                        }
                        if st.show_end {
                            ui.scroll_to_cursor(Some(egui::Align::BOTTOM));
                        }
                    });
            });
        if refresh {
            self.refresh_workbench();
        }
        if let Some(id) = pick {
            self.workbench.select(&id);
        }
        if let Some(id) = other {
            self.workbench.compare_with(id.as_deref());
        }
        if draft && let Some((token, group)) = self.workbench.ask_draft() {
            if self.screenshot.is_none() {
                self.submit(Job::Draft(token, group));
            } else {
                // A screenshot run submits no job: the draft is made here, as the worker would.
                let id = group.id.clone();
                let result = make_draft(&group);
                self.draft_made(token, id, result);
            }
        }
        if let Some((group, view)) = save {
            self.save_draft(&group, &view);
        }
        if !open {
            self.workbench.open = false;
        }
    }
}

/// The variants of a group, as `fingerprints compare` lists them.
fn variants_view(ui: &mut egui::Ui, g: &Group) {
    ui.label(tr!(
        "Group {}: {} ({} hosts, {} distinct banners, ports {})",
        g.id,
        g.template,
        g.hosts,
        g.banners,
        ports_text(&g.ports)
    ));
    if let Some(h) = &g.port_hint {
        ui.label(tr!("The port number suggests: {}", h));
    }
    if !g.vendors.is_empty() {
        ui.label(tr!("MAC vendors of the hosts: {}", g.vendors.join(", ")));
    }
    if g.varying.is_empty() {
        ui.label(tr!(
            "The banners are identical apart from nothing the workbench can see."
        ));
    }
    for v in &g.varying {
        ui.label(tr!("Differs: {}", v));
    }
    egui::Grid::new("workbench_variants")
        .num_columns(3)
        .striped(true)
        .show(ui, |ui| {
            ui.strong(tr!("Hosts"));
            ui.strong(tr!("Banner"));
            ui.strong(tr!("Versions"));
            ui.end_row();
            for v in &g.variants {
                ui.label(v.hosts.to_string());
                ui.label(RichText::new(&v.banner).monospace());
                ui.label(versions_text(&v.versions));
                ui.end_row();
            }
        });
    if g.banners > g.variants.len() {
        ui.label(tr!("… and {} more banners", g.banners - g.variants.len()));
    }
}

/// The draft: the probe file, what to check, and the pull request checklist (engine text,
/// English by design, like finding titles).
fn draft_view(ui: &mut egui::Ui, view: &DraftView) {
    let mut text = view.draft.probe_file.clone();
    ui.add(
        egui::TextEdit::multiline(&mut text)
            .font(egui::TextStyle::Monospace)
            .desired_rows(6)
            .desired_width(f32::INFINITY)
            .interactive(false),
    );
    for n in &view.draft.notes {
        ui.label(tr!("Note: {}", n));
    }
    ui.strong(tr!("Pull request checklist:"));
    for item in &view.draft.checklist {
        ui.label(format!("[ ] {item}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::workbench::Variant;

    fn variant(banner: &str, versions: &[&str], hosts: usize) -> Variant {
        Variant {
            banner: banner.into(),
            versions: versions.iter().map(ToString::to_string).collect(),
            ports: vec![9999],
            hosts,
            vendors: vec![],
        }
    }

    /// A group of one product in two firmware versions, built the way the core builds it.
    fn acme() -> Group {
        let host = |ip: &str, banner: &str| {
            let mut h = demo::demo_host(ip, &[9999], &[]);
            h.identity.insert("banner.9999".into(), banner.into());
            h.identity.insert("svc.9999".into(), "unidentified".into());
            h
        };
        let snapshot = store::Snapshot {
            sent: vec![],
            targets: "10.0.0.0/24".into(),
            complete: true,
            settings: Default::default(),
            hosts: vec![
                host("10.0.0.1", "ACME-GW 2.1 ready"),
                host("10.0.0.2", "ACME-GW 2.1 ready"),
                host("10.0.0.3", "ACME-GW 3.0.4 ready"),
            ],
            observations: vec![],
            notes: Default::default(),
        };
        let groups = workbench::groups(&[snapshot]);
        assert_eq!(groups.len(), 1, "{groups:?}");
        groups.into_iter().next().unwrap()
    }

    /// A group that nothing can be drafted from: the banners differ from the start.
    fn too_different() -> Group {
        let mut g = acme();
        g.id = "deadbeef".into();
        g.variants = vec![variant("ab 1", &["1"], 1), variant("zq 2", &["2"], 1)];
        g.banners = 2;
        g
    }

    fn data(groups: Vec<Group>) -> Result<Box<GroupsData>, String> {
        Ok(Box::new(GroupsData { scans: 3, groups }))
    }

    fn temp(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "ns-gui-workbench-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn an_answer_for_an_older_request_is_dropped() {
        let mut st = WorkbenchState::default();
        let first = st.request();
        let second = st.request();
        assert!(!st.loaded(first, data(vec![acme()])), "stale");
        assert!(st.data.is_none(), "still waiting for the second answer");
        assert!(st.loaded(second, data(vec![acme()])));
        assert_eq!(st.groups().len(), 1);
        // An error is kept as the answer.
        let third = st.request();
        assert!(st.loaded(third, Err("no database".into())));
        assert!(matches!(&st.data, Some(Err(e)) if e == "no database"));
        assert!(st.groups().is_empty());
    }

    #[test]
    fn a_selection_that_no_longer_exists_is_cleared_after_a_refresh() {
        let mut st = WorkbenchState::default();
        let t = st.request();
        let g = acme();
        let id = g.id.clone();
        st.loaded(t, data(vec![g.clone(), too_different()]));
        st.select(&id);
        st.compare_with(Some("deadbeef"));
        assert_eq!(
            st.selected_group().map(|g| g.id.as_str()),
            Some(id.as_str())
        );
        assert_eq!(st.other_group().map(|g| g.id.as_str()), Some("deadbeef"));
        // Refreshed, and the compared group is gone: the selection stays, the comparison ends.
        let t = st.request();
        st.loaded(t, data(vec![g]));
        assert!(st.selected_group().is_some());
        assert!(st.other_group().is_none() && st.other.is_none());
        // Everything is gone.
        let t = st.request();
        st.loaded(t, data(vec![]));
        assert!(st.selected_group().is_none() && st.selected.is_none());
    }

    #[test]
    fn a_group_is_not_compared_with_itself_and_choosing_another_drops_the_draft() {
        let mut st = WorkbenchState::default();
        let t = st.request();
        let g = acme();
        let id = g.id.clone();
        st.loaded(t, data(vec![g, too_different()]));
        st.select(&id);
        st.compare_with(Some(&id));
        assert!(st.other.is_none(), "not with itself");
        st.compare_with(Some("deadbeef"));
        assert!(st.other.is_some());
        st.compare_with(None);
        assert!(st.other.is_none());
        // A draft and a file notice belong to the group they were made for.
        let (token, group) = st.ask_draft().unwrap();
        assert!(st.drafting);
        assert!(st.drafted(token, group.id.clone(), make_draft(&group)));
        assert!(matches!(st.current_draft(), Some(Ok(_))));
        st.written = Some(Ok(("a".into(), "b".into())));
        st.select("deadbeef");
        assert!(st.current_draft().is_none());
        assert!(st.written.is_none());
        // Choosing the group on view again keeps what was made for it.
        let (token, group) = st.ask_draft().unwrap();
        st.drafted(token, group.id.clone(), make_draft(&group));
        st.select("deadbeef");
        assert!(st.draft.is_some());
        // Comparing with the group that becomes the one on view ends the comparison.
        st.compare_with(Some(&id));
        st.select(&id);
        assert!(st.other.is_none());
    }

    #[test]
    fn a_draft_for_another_request_or_group_is_dropped() {
        let mut st = WorkbenchState::default();
        let t = st.request();
        let g = acme();
        let id = g.id.clone();
        st.loaded(t, data(vec![g, too_different()]));
        assert!(st.ask_draft().is_none(), "nothing selected");
        st.select(&id);
        let (old, group) = st.ask_draft().unwrap();
        let (new, _) = st.ask_draft().unwrap();
        assert!(
            !st.drafted(old, id.clone(), make_draft(&group)),
            "an older request"
        );
        assert!(st.drafting, "still waiting for the newer one");
        assert!(
            !st.drafted(new, "deadbeef".into(), make_draft(&group)),
            "another group"
        );
        assert!(st.drafted(new, id, make_draft(&group)));
        assert!(!st.drafting);
    }

    #[test]
    fn the_workbench_refuses_a_draft_it_cannot_stand_behind() {
        let refused = make_draft(&too_different());
        let Err(e) = refused else {
            panic!("a draft of banners that differ from the start");
        };
        assert!(e.contains("differ too early"), "{e}");
        // The refusal is what the window shows.
        let mut st = WorkbenchState::default();
        let t = st.request();
        st.loaded(t, data(vec![too_different()]));
        st.select("deadbeef");
        let (token, group) = st.ask_draft().unwrap();
        st.drafted(token, group.id.clone(), make_draft(&group));
        assert!(matches!(st.current_draft(), Some(Err(e)) if e.contains("differ too early")));
        assert!(!st.drafting);
    }

    #[test]
    fn the_rows_are_the_cli_output_of_the_core_functions() {
        let g = acme();
        assert_eq!(g.hosts, 3);
        assert_eq!(g.banners, 2);
        let line = group_line(&g);
        assert!(line.starts_with(&format!("{} · 3 hosts · 2 banners · port 9999", g.id)));
        assert!(line.contains("ACME-GW"), "{line}");
        // The same facts as `fingerprints compare`.
        let text = workbench::compare_text(&g);
        assert!(text.contains(&g.template));
        let other = too_different();
        let rows = compare_rows(&g, &other);
        assert_eq!(rows[0], ("Group".into(), g.id.clone(), "deadbeef".into()));
        assert_eq!(rows[1].1, g.template);
        assert_eq!(rows[2].1, "9999");
        assert_eq!(rows[4], ("Hosts".into(), "3".into(), "3".into()));
        assert_eq!(rows[5], ("Distinct banners".into(), "2".into(), "2".into()));
        assert!(rows[7].1.contains("number 1 varies"), "{rows:?}");
        let similar = similarity_line(&g, &g);
        assert!(
            similar.contains("1.00") && similar.contains("one group"),
            "{similar}"
        );
        let apart = similarity_line(&g, &other);
        assert!(apart.contains("different products"), "{apart}");
        assert_eq!(
            similarity_line(
                &g,
                &Group {
                    variants: vec![],
                    ..g.clone()
                }
            ),
            ""
        );
        assert_eq!(versions_text(&[]), "—");
        assert_eq!(versions_text(&["2.1".into(), "3.0".into()]), "2.1 / 3.0");
    }

    #[test]
    fn the_files_are_the_ones_the_cli_writes() {
        let g = acme();
        let view = make_draft(&g).unwrap();
        // The same draft the CLI function makes.
        let cli = workbench::draft(&g).unwrap();
        assert_eq!(view.draft, cli);
        assert_eq!(view.checklist_md, workbench::checklist_markdown(&cli, &g));
        let file = temp("probes");
        let file = file.with_extension("json");
        let (probe, checklist) = write_draft(&file, &view).unwrap();
        assert_eq!(probe, file.display().to_string());
        assert_eq!(
            checklist,
            format!("{}.checklist.md", file.display()),
            "FILE.checklist.md like --output"
        );
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            format!("{}\n", cli.probe_file)
        );
        let md = std::fs::read_to_string(&checklist).unwrap();
        assert!(md.contains("## Checklist") && md.contains("- [ ]"), "{md}");
        // `probes validate` accepts the file.
        crate::service::lint_probes(&std::fs::read_to_string(&file).unwrap()).unwrap();
        // The draft holds no host data, only the banners.
        assert!(!md.contains("10.0.0."), "{md}");
        assert!(!view.draft.probe_file.contains("10.0.0."));
        let _ = std::fs::remove_file(&file);
        let _ = std::fs::remove_file(&checklist);
        // A folder that does not exist is an error, not a panic.
        let bad = std::env::temp_dir()
            .join("ns-gui-no-such-folder")
            .join("x.json");
        let e = write_draft(&bad, &view).unwrap_err();
        assert!(e.contains("x.json"), "{e}");
    }

    #[test]
    fn the_worker_function_groups_the_saved_scans_like_the_cli() {
        let db = temp("db").with_extension("sqlite");
        // Nothing saved yet: an empty answer, not an error.
        let empty = load_groups(&db).unwrap();
        assert!(empty.groups.is_empty());
        assert_eq!(empty.scans, 0);
        let g = acme();
        let mut hosts = vec![];
        for (ip, banner) in [
            ("10.0.0.1", "ACME-GW 2.1 ready"),
            ("10.0.0.2", "ACME-GW 2.1 ready"),
            ("10.0.0.3", "ACME-GW 3.0.4 ready"),
        ] {
            let mut h = demo::demo_host(ip, &[9999], &[]);
            h.identity.insert("banner.9999".into(), banner.into());
            h.identity.insert("svc.9999".into(), "unidentified".into());
            hosts.push(h);
        }
        let scan = |hosts: Vec<scan::Host>| store::Snapshot {
            sent: vec![],
            targets: "10.0.0.0/24".into(),
            complete: true,
            settings: Default::default(),
            hosts,
            observations: vec![],
            notes: Default::default(),
        };
        store::save(&db, &scan(hosts.clone())).unwrap();
        store::save(&db, &scan(hosts)).unwrap();
        let loaded = load_groups(&db).unwrap();
        assert_eq!(loaded.scans, 2);
        // What `fingerprints groups` prints for the same scans.
        let snapshots: Vec<_> = store::list(&db)
            .unwrap()
            .into_iter()
            .map(|e| store::load(&db, e.id).unwrap())
            .collect();
        assert_eq!(loaded.groups, workbench::groups(&snapshots));
        assert_eq!(loaded.groups.len(), 1);
        assert_eq!(loaded.groups[0].id, g.id);
        assert_eq!(
            loaded.groups[0].hosts, 3,
            "hosts counted once over both scans"
        );
        for suffix in ["", "-wal", "-shm"] {
            let mut p = db.as_os_str().to_owned();
            p.push(suffix);
            let _ = std::fs::remove_file(PathBuf::from(p));
        }
    }

    #[test]
    fn the_window_texts_are_in_the_catalog() {
        super::i18n::set(super::i18n::Lang::German);
        let g = acme();
        let line = group_line(&g);
        assert!(line.contains("3 Hosts · 2 Banner · Port 9999"), "{line}");
        assert!(similarity_line(&g, &g).contains("eine Gruppe"));
        assert_eq!(compare_rows(&g, &g)[1].0, "Vorlage");
        super::i18n::set(super::i18n::Lang::English);
    }
}
