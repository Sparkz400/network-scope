// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! Small line icons for the sidebar pages, painted as shapes in the text colour (no icon font,
//! so they are sharp at every scale, follow the theme and never become part of a widget's
//! accessible name), the app logo as a texture, and the sidebar's page button.
use eframe::egui::{
    self, Color32, Pos2, Rect, Response, Sense, Shape, Stroke, StrokeKind, TextureHandle, Ui,
    WidgetInfo, WidgetText, pos2, vec2,
};

use super::MainView;

/// The app icon in its small-size design (assets/icon/icon-small.svg rendered at 48 px).
pub(super) const LOGO_PNG: &[u8] = include_bytes!("../../assets/icon/icon-48.png");

/// The logo as a texture, decoded once per window.
pub(super) fn logo(ctx: &egui::Context) -> TextureHandle {
    // Temp data is keyed by id and type: no other value of this type is stored.
    let id = egui::Id::NULL;
    if let Some(texture) = ctx.data(|d| d.get_temp::<TextureHandle>(id)) {
        return texture;
    }
    let image = image::load_from_memory_with_format(LOGO_PNG, image::ImageFormat::Png)
        .expect("the bundled icon is a valid PNG")
        .into_rgba8();
    let size = [image.width() as usize, image.height() as usize];
    let pixels = egui::ColorImage::from_rgba_unmultiplied(size, image.as_raw());
    let texture = ctx.load_texture("logo", pixels, egui::TextureOptions::LINEAR);
    ctx.data_mut(|d| d.insert_temp(id, texture.clone()));
    texture
}

/// Paints the icon of a page into `rect` (a square of about 16 points).
pub(super) fn paint(painter: &egui::Painter, rect: Rect, view: MainView, color: Color32) {
    let s = rect.width() / 16.0;
    // A point of the 16 x 16 design grid.
    let p = |x: f32, y: f32| pos2(rect.left() + x * s, rect.top() + y * s);
    let stroke = Stroke::new(1.4 * s.max(1.0), color);
    match view {
        // Four tiles: the overview's dashboard.
        MainView::Home => {
            for (x, y) in [(2.0, 2.0), (9.0, 2.0), (2.0, 9.0), (9.0, 9.0)] {
                let tile = Rect::from_min_max(p(x, y), p(x + 5.0, y + 5.0));
                painter.rect_stroke(tile, 1.5 * s, stroke, StrokeKind::Middle);
            }
        }
        // A list: a dot and a line per row.
        MainView::Hosts => {
            for y in [3.5, 8.0, 12.5] {
                painter.circle_filled(p(2.8, y), 1.2 * s, color);
                painter.line_segment([p(6.0, y), p(14.5, y)], stroke);
            }
        }
        // A screen on a stand.
        MainView::Devices => {
            let screen = Rect::from_min_max(p(1.5, 2.5), p(14.5, 11.0));
            painter.rect_stroke(screen, 1.5 * s, stroke, StrokeKind::Middle);
            painter.line_segment([p(8.0, 11.0), p(8.0, 13.5)], stroke);
            painter.line_segment([p(5.0, 13.5), p(11.0, 13.5)], stroke);
        }
        // A shield with an exclamation mark.
        MainView::Findings => {
            let outline = vec![
                p(8.0, 1.5),
                p(14.0, 3.5),
                p(13.5, 8.5),
                p(11.5, 12.0),
                p(8.0, 14.5),
                p(4.5, 12.0),
                p(2.5, 8.5),
                p(2.0, 3.5),
            ];
            painter.add(Shape::closed_line(outline, stroke));
            painter.line_segment([p(8.0, 5.0), p(8.0, 8.8)], stroke);
            painter.circle_filled(p(8.0, 11.2), 0.9 * s, color);
        }
        // Three connected nodes.
        MainView::Map => {
            let (a, b, c) = (p(3.5, 4.0), p(12.5, 4.5), p(7.5, 12.5));
            painter.line_segment([a, b], stroke);
            painter.line_segment([a, c], stroke);
            painter.line_segment([b, c], stroke);
            for node in [a, b, c] {
                painter.circle_filled(node, 2.1 * s, color);
            }
        }
        // A point that listens: radio waves on both sides.
        MainView::Passive => {
            let center = p(8.0, 8.0);
            painter.circle_filled(center, 1.6 * s, color);
            for radius in [3.8, 6.4] {
                for side in [0.0, std::f32::consts::PI] {
                    painter.add(Shape::line(arc(center, radius * s, side, 0.75), stroke));
                }
            }
        }
        // An archive box: a lid, the box and a handle.
        MainView::Inventory => {
            let lid = Rect::from_min_max(p(1.5, 2.5), p(14.5, 6.0));
            let body = Rect::from_min_max(p(2.5, 6.0), p(13.5, 14.0));
            painter.rect_stroke(lid, 1.0 * s, stroke, StrokeKind::Middle);
            painter.rect_stroke(body, 1.0 * s, stroke, StrokeKind::Middle);
            painter.line_segment([p(6.0, 9.0), p(10.0, 9.0)], stroke);
        }
    }
}

/// Points along an arc around `center`, from `mid - half` to `mid + half` (radians; 0 points
/// right, PI left).
fn arc(center: Pos2, radius: f32, mid: f32, half: f32) -> Vec<Pos2> {
    const STEPS: usize = 10;
    (0..=STEPS)
        .map(|i| {
            let angle = mid - half + 2.0 * half * i as f32 / STEPS as f32;
            center + radius * vec2(angle.cos(), angle.sin())
        })
        .collect()
}

/// A sidebar entry: the page's icon, its name and, optionally, a count in a pill (in `color`
/// when given, for the worst finding). Screen readers get "name count", like a button with the
/// count as its right text.
pub(super) fn page_button(
    ui: &mut Ui,
    view: MainView,
    selected: bool,
    label: &str,
    badge: Option<&(String, Option<Color32>)>,
) -> Response {
    let height = 30.0;
    let (rect, response) =
        ui.allocate_exact_size(vec2(ui.available_width(), height), Sense::click());
    let name = match badge {
        Some((count, _)) => format!("{label} {count}"),
        None => label.to_owned(),
    };
    let enabled = ui.is_enabled();
    response.widget_info(|| WidgetInfo::selected(egui::Role::Button, enabled, selected, &name));
    if !ui.is_rect_visible(rect) {
        return response;
    }
    let visuals = ui.style().interact_selectable(&response, selected);
    let painter = ui.painter();
    if selected || response.hovered() || response.has_focus() {
        painter.rect(
            rect,
            visuals.corner_radius,
            visuals.weak_bg_fill,
            visuals.bg_stroke,
            StrokeKind::Inside,
        );
    }
    let text_color = visuals.text_color();
    let icon = Rect::from_center_size(pos2(rect.left() + 18.0, rect.center().y), vec2(16.0, 16.0));
    paint(painter, icon, view, text_color);

    // The count first: the name gets the room that is left.
    let mut right = rect.right() - 8.0;
    if let Some((count, color)) = badge {
        let galley = WidgetText::from(count.as_str()).into_galley(
            ui,
            Some(egui::TextWrapMode::Extend),
            f32::INFINITY,
            egui::TextStyle::Small,
        );
        let pill = Rect::from_min_size(
            pos2(right - galley.size().x - 12.0, rect.center().y - 9.0),
            vec2(galley.size().x + 12.0, 18.0),
        );
        let (fill, ink) = match color {
            Some(c) => (*c, readable_on(*c)),
            None => (
                ui.visuals().widgets.inactive.weak_bg_fill,
                ui.visuals().text_color(),
            ),
        };
        painter.rect_filled(pill, 9.0, fill);
        painter.galley(pill.center() - galley.size() / 2.0, galley, ink);
        right = pill.left() - 6.0;
    }
    let left = icon.right() + 10.0;
    let galley = WidgetText::from(label).into_galley(
        ui,
        Some(egui::TextWrapMode::Truncate),
        (right - left).max(0.0),
        egui::TextStyle::Button,
    );
    let pos = pos2(left, rect.center().y - galley.size().y / 2.0);
    painter.galley(pos, galley, text_color);
    response
}

/// Black or white, whichever reads better on `background`.
fn readable_on(background: Color32) -> Color32 {
    let [r, g, b, _] = background.to_array();
    // Relative luminance with the sRGB weights; the threshold suits the severity colours of
    // both themes.
    let luma = 0.2126 * f32::from(r) + 0.7152 * f32::from(g) + 0.0722 * f32::from(b);
    if luma > 150.0 {
        Color32::BLACK
    } else {
        Color32::WHITE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn badge_text_is_readable_on_severity_colours() {
        for dark in [false, true] {
            use crate::risk::Severity::*;
            for severity in [Info, Low, Medium, High, Critical] {
                let fill = super::super::home::severity_color(severity, dark);
                let ink = readable_on(fill);
                assert!(contrast(fill, ink) >= 3.0, "{severity:?} dark={dark}");
            }
        }
    }

    /// The WCAG contrast ratio of two colours.
    fn contrast(a: Color32, b: Color32) -> f32 {
        fn lum(c: Color32) -> f32 {
            let ch = |v: u8| {
                let v = f32::from(v) / 255.0;
                if v <= 0.03928 {
                    v / 12.92
                } else {
                    ((v + 0.055) / 1.055).powf(2.4)
                }
            };
            0.2126 * ch(c.r()) + 0.7152 * ch(c.g()) + 0.0722 * ch(c.b())
        }
        let (x, y) = (lum(a), lum(b));
        (x.max(y) + 0.05) / (x.min(y) + 0.05)
    }
}
