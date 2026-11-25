//! Names for screen readers. egui publishes the widget tree through AccessKit (UI Automation on
//! Windows). A widget is named by its own text (buttons, checkboxes), by `labelled_by` a visible
//! label, or by this module. Two things are not names in egui: the hint text of a text box (it is
//! the "placeholder", which many screen readers do not speak) and the suffix of a number field
//! (`" ms"` ends up as the name). Fields that have no visible label of their own are named here.
use super::*;

/// Gives `response` the accessible name `name` and returns it. Use it for a widget that has no
/// visible label next to it; with a label use `labelled_by(label.id)` instead.
pub(super) fn named(response: egui::Response, name: &str) -> egui::Response {
    response.ctx.accesskit_node_builder(response.id, |node| {
        node.set_label(name);
    });
    response
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    /// One node of a frame's accessibility tree: its role and name.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Node {
        pub role: String,
        pub name: String,
    }

    /// Runs `add_contents` for one frame with accessibility on and returns what a screen reader
    /// would see: every node with its role and name (the label, else what labels it).
    pub fn tree(mut add_contents: impl FnMut(&mut egui::Ui)) -> Vec<Node> {
        let ctx = egui::Context::default();
        ctx.enable_accesskit();
        let mut output = ctx.run_ui(egui::RawInput::default(), |ui| {
            egui::CentralPanel::default().show(ui, |ui| add_contents(ui));
        });
        // Nothing renders these textures.
        output.textures_delta.clear();
        let update = output
            .platform_output
            .accesskit_update
            .expect("accessibility is on");
        let labels: std::collections::HashMap<_, _> = update
            .nodes
            .iter()
            .map(|(id, node)| {
                (
                    *id,
                    node.value()
                        .map(str::to_string)
                        .or_else(|| node.label().map(str::to_string))
                        .unwrap_or_default(),
                )
            })
            .collect();
        update
            .nodes
            .iter()
            .map(|(_, node)| {
                let name = node.label().map(str::to_string).unwrap_or_else(|| {
                    node.labelled_by()
                        .iter()
                        .filter_map(|id| labels.get(id))
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(" ")
                });
                Node {
                    role: format!("{:?}", node.role()),
                    name,
                }
            })
            .collect()
    }

    /// The names of the nodes with one of the given roles.
    pub fn names(nodes: &[Node], roles: &[&str]) -> Vec<String> {
        nodes
            .iter()
            .filter(|n| roles.contains(&n.role.as_str()))
            .map(|n| n.name.clone())
            .collect()
    }

    #[test]
    fn a_text_box_with_only_a_hint_has_no_name_until_it_is_named() {
        let mut text = String::new();
        let bare = tree(|ui| {
            ui.add(egui::TextEdit::singleline(&mut text).hint_text("Search"));
        });
        assert_eq!(
            names(&bare, &["TextInput"]),
            [""],
            "egui names it by nothing"
        );
        let named_box = tree(|ui| {
            named(
                ui.add(egui::TextEdit::singleline(&mut text).hint_text("Search")),
                "Search",
            );
        });
        assert_eq!(names(&named_box, &["TextInput"]), ["Search"]);
    }

    #[test]
    fn a_number_field_is_named_by_its_label_not_by_its_suffix() {
        let mut n = 60u64;
        let by_suffix = tree(|ui| {
            ui.horizontal(|ui| {
                ui.label("Every");
                ui.add(egui::DragValue::new(&mut n).suffix(" min"));
            });
        });
        let spinner = names(&by_suffix, &["SpinButton"]);
        assert_ne!(spinner, ["Every"], "the label alone does not name it");
        let labelled = tree(|ui| {
            ui.horizontal(|ui| {
                let label = ui.label("Every");
                ui.add(egui::DragValue::new(&mut n).suffix(" min"))
                    .labelled_by(label.id);
            });
        });
        assert_eq!(names(&labelled, &["SpinButton"]), ["Every"]);
    }

    /// Roles that a person can operate, with the names a screen reader announces. None may be
    /// empty: a field announced as just "edit" or "combo box" cannot be used.
    const OPERABLE: [&str; 6] = [
        "TextInput",
        "MultilineTextInput",
        "ComboBox",
        "SpinButton",
        "Slider",
        "CheckBox",
    ];

    fn assert_all_named(nodes: &[Node], what: &str) {
        let unnamed: Vec<&Node> = nodes
            .iter()
            .filter(|n| OPERABLE.contains(&n.role.as_str()) && n.name.trim().is_empty())
            .collect();
        assert!(unnamed.is_empty(), "{what}: unnamed controls {unnamed:?}");
    }

    #[test]
    fn the_table_filters_and_the_schedule_section_have_named_controls() {
        let mut view = super::super::tables::View::default();
        let nodes =
            tree(|ui| view.controls_with(ui, "findings_severity", "Any risk", true, |_| {}));
        assert_all_named(&nodes, "table filters");
        let names = names(&nodes, &["TextInput", "ComboBox"]);
        assert!(names.contains(&"Filter…".to_string()), "{names:?}");
        assert!(names.contains(&"Minimum severity".to_string()), "{names:?}");
        assert!(names.contains(&"Minimum EPSS".to_string()), "{names:?}");

        let mut saved = super::super::Saved::default();
        let mut error = String::new();
        let nodes = tree(|ui| {
            super::super::scheduler::schedule_section(ui, &mut saved, "10.0.0.0/24", "", &mut error)
        });
        assert_all_named(&nodes, "schedule section");
        assert_eq!(names_of(&nodes, "SpinButton"), ["Every"]);
        assert_eq!(names_of(&nodes, "TextInput"), ["Targets"]);
    }

    fn names_of(nodes: &[Node], role: &str) -> Vec<String> {
        names(nodes, &[role])
    }
}
