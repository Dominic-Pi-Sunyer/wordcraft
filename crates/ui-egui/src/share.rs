//! Share Mode in the window: a Share button in the title bar (a status pill while a session is on)
//! that opens the share controls, and the per-frame hook that takes in other people's edits. The
//! engine is [`wordcraft_collab::Collab`]; this file only draws and forwards.

use egui::{Sense, Ui, pos2, vec2};
use wordcraft_collab::Role;

use crate::WordApp;
use crate::theme::{Tokens, TypeRung, medium, paint_text, text_width};

/// What the share popup remembers between frames.
#[derive(Default)]
pub struct ShareUi {
    /// The `ssync://` link being typed or pasted.
    pub join_input: String,
}

/// Once per frame, before layout: finish starting and stopping, load a joined document, apply
/// what others did, and show what went wrong.
pub fn poll(app: &mut WordApp, ctx: &egui::Context) {
    let polled = app.collab.poll(&mut app.session);
    if polled.loaded {
        app.autosave_path = None;
        app.status(tl!("Joined the shared document").to_string());
    }
    for n in app.collab.take_notices() {
        app.status(n);
    }
    if polled.changed {
        ctx.request_repaint();
    }
    // Others' edits and peers arrive on their own: look again soon while a session is on.
    if app.collab.live() || app.collab.busy() {
        ctx.request_repaint_after(std::time::Duration::from_millis(100));
    }
}

/// The pill text for the current role.
pub fn pill(app: &WordApp) -> Option<String> {
    match app.collab.role() {
        Role::Offline => None,
        Role::JoinedViewOnly => Some(tl!("View Only").to_string()),
        Role::Hosting | Role::JoinedCanEdit => {
            let n = app.collab.peers();
            Some(crate::i18n::fmt(if n == 1 { tl!("Live ({n} Peer)") } else { tl!("Live ({n} Peers)") }, &[("n", &n.to_string())]))
        }
    }
}

/// The title bar's Share control (right-to-left layout: call it before the controls to its left).
pub fn title_control(ui: &mut Ui, app: &mut WordApp, control_h: f32) {
    if !app.collab.available() {
        return;
    }
    let t = Tokens::get(ui.ctx());
    let label = pill(app).unwrap_or_else(|| tl!("Co-edit").to_string());
    let font = medium(11.5);
    let w = text_width(ui.painter(), &label, &font, TypeRung::Control.tracking(), t.text) + 34.0;
    let (r, _) = ui.allocate_exact_size(vec2(w, control_h - 4.0), Sense::hover());
    let resp = ui.interact(r, ui.id().with("share_button"), Sense::click());
    let live = app.collab.live();
    let fill = if resp.hovered() {
        t.hover
    } else if live {
        t.checked
    } else {
        t.ribbon
    };
    ui.painter().rect(r, 6.0, fill, egui::Stroke::new(1.0, t.border), egui::StrokeKind::Inside);
    let dot = match app.collab.role() {
        Role::Offline => t.text_dim,
        Role::JoinedViewOnly => egui::Color32::from_rgb(214, 150, 40),
        _ => egui::Color32::from_rgb(52, 178, 90),
    };
    ui.painter().circle_filled(pos2(r.min.x + 13.0, r.center().y), 4.0, dot);
    paint_text(
        ui.painter(),
        pos2(r.min.x + 24.0, r.center().y - TypeRung::Control.line_height() / 2.0),
        egui::Align2::LEFT_TOP,
        &label,
        &font,
        TypeRung::Control.tracking(),
        t.text,
    );
    resp.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, true, &label));
    let resp = resp.on_hover_text(tl!("Edit this document together, live"));
    egui::Popup::menu(&resp).show(|ui| {
        ui.set_min_width(300.0);
        controls(ui, app);
    });
}

/// The share controls, by role.
fn controls(ui: &mut Ui, app: &mut WordApp) {
    let t = Tokens::get(ui.ctx());
    if app.collab.busy() {
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label(tl!("Working…"));
        });
        return;
    }
    match app.collab.role() {
        Role::Offline => {
            if ui.button(tl!("Share Document")).clicked()
                && let Err(e) = app.collab.start_share(&app.session)
            {
                app.status(e);
            }
            ui.separator();
            ui.label(tl!("Join via Link"));
            ui.add(egui::TextEdit::singleline(&mut app.share_ui.join_input).hint_text("ssync://…").desired_width(f32::INFINITY));
            let ready = !app.share_ui.join_input.trim().is_empty();
            if ui.add_enabled(ready, egui::Button::new(tl!("Join via Link"))).clicked() {
                let link = std::mem::take(&mut app.share_ui.join_input);
                if let Err(e) = app.collab.join(&link) {
                    app.status(e);
                }
            }
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(tl!("Anyone with a link can read the whole document and keep a copy. Undo and redo are off while sharing."))
                    .small()
                    .color(t.text_dim),
            );
        }
        Role::Hosting => {
            ui.label(pill(app).unwrap_or_default());
            let (edit, view) = app.collab.links().map(|l| (l.edit.clone(), l.view.clone())).unzip();
            if ui
                .add_enabled(edit.is_some(), egui::Button::new(tl!("Copy Edit Link")))
                .on_hover_text(tl!("Whoever has this link can read and change the document"))
                .clicked()
            {
                ui.ctx().copy_text(edit.unwrap_or_default());
                app.status(tl!("Edit link copied").to_string());
            }
            if ui
                .add_enabled(view.is_some(), egui::Button::new(tl!("Copy View-Only Link")))
                .on_hover_text(tl!("Whoever has this link can read the document but not change it"))
                .clicked()
            {
                ui.ctx().copy_text(view.unwrap_or_default());
                app.status(tl!("View-only link copied").to_string());
            }
            stop_button(ui, app, tl!("Stop Sharing"));
        }
        Role::JoinedCanEdit => {
            ui.label(pill(app).unwrap_or_default());
            stop_button(ui, app, tl!("Leave"));
        }
        Role::JoinedViewOnly => {
            ui.label(tl!("View Only"));
            stop_button(ui, app, tl!("Leave"));
        }
    }
}

fn stop_button(ui: &mut Ui, app: &mut WordApp, label: &str) {
    let b = egui::Button::new(egui::RichText::new(label).color(egui::Color32::WHITE)).fill(egui::Color32::from_rgb(200, 40, 40));
    if ui.add(b).clicked() {
        if let Err(e) = app.collab.stop() {
            app.status(e);
        }
        ui.close();
    }
}
