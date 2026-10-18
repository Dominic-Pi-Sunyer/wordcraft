//! WordCraft Share Mode: live, end-to-end encrypted peer-to-peer editing of one document, with no
//! server. The transport is `simple-sync` (native builds only; the web build compiles a stub).
//!
//! The front end calls three things around every command it runs for the user:
//! [`Collab::gate`] before (refuse what must not happen now), [`Collab::before`] and
//! [`Collab::after`] around [`Session::run`] (send the edit), and [`Collab::poll`] once a frame
//! (apply what arrived). Edits that arrive are applied with [`Session::run`] directly and never
//! sent back, so there is no echo.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::unimplemented, clippy::todo, clippy::unreachable)]

pub mod merge;

#[cfg(not(target_arch = "wasm32"))]
#[path = "link_native.rs"]
mod link;
#[cfg(target_arch = "wasm32")]
#[path = "link_stub.rs"]
mod link;

use bincode::Options;
use serde_json::Value;
use wordcraft_engine::Session;

pub use merge::{Op, Replica, Snapshot, Verdict};

/// Largest edit message accepted from a peer.
const MAX_MESSAGE: u64 = 2 * 1024 * 1024;

/// What this window is doing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Offline,
    Hosting,
    JoinedCanEdit,
    JoinedViewOnly,
}

/// The two links a host hands out. They are secrets: anyone holding one can read the document.
#[derive(Clone)]
pub struct Links {
    /// Anyone with this can read and edit.
    pub edit: String,
    /// Anyone with this can read.
    pub view: String,
}

impl std::fmt::Debug for Links {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Links { <redacted> }")
    }
}

pub(crate) enum LinkEvent {
    Base { filename: String, bytes: Vec<u8> },
    Remote(Vec<u8>),
    Peers,
    Error(String),
}

pub(crate) enum LinkNotice {
    Shared(Links),
    Joined,
    Stopped,
    Failed(String),
}

/// What [`Collab::poll`] did, so the front end can refresh.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Polled {
    /// A document arrived and replaced the session's (joining).
    pub loaded: bool,
    /// The document, the role or the peer count changed.
    pub changed: bool,
}

pub struct Collab {
    link: link::Link,
    replica: Replica,
    links: Option<Links>,
    notices: Vec<String>,
}

impl Default for Collab {
    fn default() -> Self {
        Self::new()
    }
}

impl Collab {
    pub fn new() -> Self {
        Self::with_link(link::Link::new(false))
    }

    /// No relay or discovery servers: peers on this machine or network only. For tests.
    #[doc(hidden)]
    pub fn local_only() -> Self {
        Self::with_link(link::Link::new(true))
    }

    fn with_link(link: link::Link) -> Self {
        Collab { link, replica: Replica::new(""), links: None, notices: Vec::new() }
    }

    /// False in builds that cannot share (the web build).
    pub fn available(&self) -> bool {
        self.link.available()
    }
    pub fn role(&self) -> Role {
        self.link.role()
    }
    /// Starting, joining or stopping: local edits are refused until it settles.
    pub fn busy(&self) -> bool {
        self.link.busy()
    }
    pub fn peers(&self) -> usize {
        self.link.peers()
    }
    /// The links of the session this window hosts; they are only known on the host.
    pub fn links(&self) -> Option<&Links> {
        self.links.as_ref()
    }
    /// Sharing or joined (not merely starting).
    pub fn live(&self) -> bool {
        self.role() != Role::Offline
    }
    /// Messages for the status line (errors, edits that stay on this machine).
    pub fn take_notices(&mut self) -> Vec<String> {
        std::mem::take(&mut self.notices)
    }

    /// Share this window's document. Returns at once; the links appear in [`Collab::links`].
    pub fn start_share(&mut self, session: &Session) -> Result<(), String> {
        if self.live() {
            return Err("This document is already shared; stop sharing first".into());
        }
        let name = session.file_name.clone().or_else(|| session.path.as_ref().and_then(|p| p.file_name()).map(|n| n.to_string_lossy().into_owned()));
        let name = match name {
            Some(n) if n.to_lowercase().ends_with(".docx") => n,
            Some(n) => format!("{n}.docx"),
            None => "Shared document.docx".to_string(),
        };
        // The current text, including edits not saved to disk.
        let bytes = wordcraft_engine::io::save_bytes(&name, &session.doc)?;
        self.link.begin_share(name, bytes)
    }

    /// Join from an `ssync://` link. The document arrives later (see [`Polled::loaded`]).
    pub fn join(&mut self, uri: &str) -> Result<(), String> {
        if self.live() {
            return Err("Leave the current session first".into());
        }
        self.link.begin_join(uri.trim().to_string())
    }

    /// Stop sharing (host) or leave (joiner). Old links stop working.
    pub fn stop(&mut self) -> Result<(), String> {
        self.links = None;
        self.link.begin_stop()
    }

    /// Refuse commands that must not run now. `Ok` means go ahead.
    pub fn gate(&self, session: &Session, id: &str, params: &Value) -> Result<(), String> {
        let _ = params;
        let editing =
            session.registry.get(id).is_some_and(|s| s.mutates) && !id.starts_with("file.") && !id.starts_with("ui.") && !id.starts_with("view.");
        if self.busy() && (editing || matches!(id, "file.new" | "file.open" | "file.close")) {
            return Err("Share Mode is starting or stopping; try again in a moment".into());
        }
        match self.role() {
            Role::Offline => Ok(()),
            _ if matches!(id, "edit.undo" | "edit.redo" | "edit.undoTo" | "edit.repeat") => {
                Err("Undo and redo are off while sharing: they would also undo other people's edits".into())
            }
            Role::JoinedViewOnly if editing => Err("You have view-only access to this shared document".into()),
            _ if matches!(id, "file.new" | "file.open" | "file.close" | "file.recover" | "file.openRecent") => {
                Err("Stop sharing (or leave) before opening or closing documents".into())
            }
            _ => Ok(()),
        }
    }

    /// Call just before running a command for the user; hand the result to [`Collab::after`].
    pub fn before(&self, session: &Session) -> Option<Snapshot> {
        self.live().then(|| Snapshot::take(session))
    }

    /// Call after a command the user ran succeeded: sends it to the others.
    pub fn after(&mut self, session: &Session, snap: Option<Snapshot>, id: &str, params: &Value) {
        let Some(snap) = snap else { return };
        match merge::verdict(session, id, params) {
            Verdict::Quiet => {}
            Verdict::Unshared(why) => {
                let label = session.registry.get(id).map_or(id, |s| s.label);
                self.notices.push(format!("{label} is not shared with the others: {why}."));
            }
            Verdict::Share => {
                let (wid, wparams) = merge::wire_command(id, params);
                let op = self.replica.local(&wid, &wparams, &snap, session);
                if let Err(e) = self.link.broadcast(&op) {
                    self.notices.push(format!("This edit could not be shared: {e}"));
                }
            }
        }
    }

    /// Once per frame: finish starting/stopping, load the shared document, apply others' edits.
    pub fn poll(&mut self, session: &mut Session) -> Polled {
        let mut out = Polled::default();
        while let Some(n) = self.link.poll_done() {
            out.changed = true;
            match n {
                LinkNotice::Shared(l) => {
                    self.replica = Replica::new(&self.link.local_id());
                    self.links = Some(l);
                }
                LinkNotice::Joined => self.replica = Replica::new(&self.link.local_id()),
                LinkNotice::Stopped => {
                    self.links = None;
                    self.replica = Replica::new("");
                }
                LinkNotice::Failed(m) => self.notices.push(m),
            }
        }
        while let Some(ev) = self.link.poll_event() {
            out.changed = true;
            match ev {
                LinkEvent::Base { filename, bytes } => match wordcraft_engine::io::open_bytes(&filename, &bytes) {
                    Ok(doc) => {
                        session.set_document(doc);
                        out.loaded = true;
                    }
                    Err(e) => self.notices.push(format!("The shared document couldn't be opened: {e}")),
                },
                LinkEvent::Remote(bytes) => {
                    let decoded = bincode::DefaultOptions::new()
                        .with_fixint_encoding()
                        .allow_trailing_bytes()
                        .with_limit(MAX_MESSAGE)
                        .deserialize::<Op>(&bytes);
                    match decoded {
                        Ok(op) => {
                            for op in self.replica.accept(op) {
                                if let Err(e) = self.apply_remote(session, &op) {
                                    self.notices.push(e);
                                }
                            }
                        }
                        Err(e) => self.notices.push(format!("An edit from another person couldn't be read: {e}")),
                    }
                }
                LinkEvent::Peers => {}
                LinkEvent::Error(m) => self.notices.push(m),
            }
        }
        out
    }

    /// Apply another person's edit without sending it on.
    fn apply_remote(&mut self, session: &mut Session, op: &Op) -> Result<(), String> {
        let params: Value = serde_json::from_str(&op.params).map_err(|e| format!("An edit from another person had unreadable parameters: {e}"))?;
        if merge::verdict(session, &op.id, &params) != Verdict::Share {
            return Err(format!("Ignored an edit from another person that isn't allowed in Share Mode ({})", op.id));
        }
        let mut local = session.sel.clone();
        session.sel = self.replica.rebase(op);
        session.clamp_selection();
        let snap = Snapshot::take(session);
        let result = session.run(&op.id, &params);
        let effect = if result.is_ok() { snap.effect_in(session) } else { None };
        self.replica.applied_remote(op, effect, &mut local);
        session.sel = local;
        session.clamp_selection();
        result.map(|_| ()).map_err(|e| format!("An edit from another person couldn't be applied: {e}"))
    }
}
