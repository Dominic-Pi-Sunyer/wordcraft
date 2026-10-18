//! Merging concurrent edits.
//!
//! WordCraft's edits are commands (`id` + JSON params) that act on a selection. Share Mode sends
//! each command together with the selection it ran on and a version vector (`seen`): how many
//! edits of every site the author had applied. A receiver then knows which of its own applied
//! edits the author could not see (the *concurrent* ones) and shifts the author's positions past
//! the text those edits inserted or removed, so two people typing in the same paragraph both land
//! where they meant to. This is the two-writer transform of Jupiter; with three or more writers
//! editing the same spot at the same moment it can still diverge (see `docs/collab.md`).
//!
//! Only edits inside one paragraph are transformed. An edit that splits, merges or deletes
//! paragraphs is applied as sent and does not shift concurrent edits' paragraph numbers.

use std::collections::{BTreeMap, VecDeque};

use serde::{Deserialize, Serialize};
use wordcraft_doc::Pos;
use wordcraft_engine::{Selection, Session};

/// Applied edits remembered for transforming late-arriving concurrent ones.
const LOG_CAP: usize = 4096;
/// Edits held back until the ones they depend on arrive.
const PENDING_CAP: usize = 4096;

/// One shared edit, as broadcast.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Op {
    /// The author's session id.
    pub site: String,
    /// 1, 2, 3… per site.
    pub seq: u64,
    /// The edits (site → highest seq) the author had applied before this one.
    pub seen: BTreeMap<String, u64>,
    /// Command id.
    pub id: String,
    /// Command params as JSON text (bincode cannot carry `serde_json::Value`).
    pub params: String,
    /// The selection the command ran on, in the author's document.
    pub sel: Selection,
}

/// What an applied edit did to one paragraph's text: `removed` bytes at `at` became `inserted`.
#[derive(Clone, Debug, PartialEq)]
pub struct Effect {
    pub site: String,
    pub seq: u64,
    pub story: wordcraft_doc::StoryRef,
    pub path: wordcraft_doc::Path,
    pub at: usize,
    pub removed: usize,
    pub inserted: usize,
}

impl Effect {
    /// Where a position in the same paragraph ends up. `p_site` breaks the tie when text was
    /// inserted exactly at the position: the lower site id's text goes first, on every peer.
    pub fn shift(&self, off: usize, p_site: &str) -> usize {
        let end = self.at.saturating_add(self.removed);
        if off < self.at {
            off
        } else if off == self.at {
            if self.site.as_str() < p_site { off.saturating_add(self.inserted) } else { off }
        } else if off >= end {
            off.saturating_sub(self.removed).saturating_add(self.inserted)
        } else {
            // Inside removed text: after whatever replaced it.
            self.at.saturating_add(self.inserted)
        }
    }

    fn applies_to(&self, p: &Pos) -> bool {
        p.story == self.story && p.path == self.path
    }

    pub fn shift_pos(&self, p: &mut Pos, p_site: &str) {
        if self.applies_to(p) {
            p.off = self.shift(p.off, p_site);
        }
    }

    pub fn shift_sel(&self, s: &mut Selection, p_site: &str) {
        self.shift_pos(&mut s.anchor, p_site);
        self.shift_pos(&mut s.focus, p_site);
    }
}

/// The state of the shared paragraph before a command, to find out what the command did.
pub struct Snapshot {
    pub sel: Selection,
    text: Option<String>,
    blocks: usize,
    single: bool,
}

impl Snapshot {
    pub fn take(s: &Session) -> Snapshot {
        let single = s.sel.anchor.story == s.sel.focus.story && s.sel.anchor.path == s.sel.focus.path;
        Snapshot {
            sel: s.sel.clone(),
            text: if single { s.doc.para_at(&s.sel.focus).map(|p| p.text.clone()) } else { None },
            blocks: s.doc.body.len(),
            single,
        }
    }

    /// The text change inside the selection's paragraph, if the command made one and did not
    /// change the paragraph structure.
    pub fn effect_in(&self, s: &Session) -> Option<Effect> {
        if !self.single || s.doc.body.len() != self.blocks {
            return None;
        }
        let old = self.text.as_deref()?;
        let new = s.doc.para_at(&self.sel.focus)?.text.as_str();
        if old == new {
            return None;
        }
        let prefix = old.chars().zip(new.chars()).take_while(|(a, b)| a == b).map(|(a, _)| a.len_utf8()).sum::<usize>();
        let (old_t, new_t) = (old.get(prefix..)?, new.get(prefix..)?);
        let suffix = old_t.chars().rev().zip(new_t.chars().rev()).take_while(|(a, b)| a == b).map(|(a, _)| a.len_utf8()).sum::<usize>();
        let removed = old_t.len().saturating_sub(suffix);
        let inserted = new_t.len().saturating_sub(suffix);
        Some(Effect { site: String::new(), seq: 0, story: self.sel.focus.story, path: self.sel.focus.path.clone(), at: prefix, removed, inserted })
    }
}

/// One peer's view of the shared edit history.
#[derive(Debug, Default)]
pub struct Replica {
    site: String,
    next_seq: u64,
    seen: BTreeMap<String, u64>,
    log: VecDeque<Effect>,
    pending: Vec<Op>,
}

impl Replica {
    pub fn new(site: &str) -> Self {
        Replica { site: site.to_string(), next_seq: 1, ..Default::default() }
    }

    pub fn site(&self) -> &str {
        &self.site
    }

    fn push_effect(&mut self, e: Effect) {
        self.log.push_back(e);
        while self.log.len() > LOG_CAP {
            self.log.pop_front();
        }
    }

    /// Record an edit this peer just made (already applied to its document).
    pub fn local(&mut self, id: &str, params: &serde_json::Value, snap: &Snapshot, after: &Session) -> Op {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        let seen = self.seen.clone();
        self.seen.insert(self.site.clone(), seq);
        if let Some(mut e) = snap.effect_in(after) {
            e.site = self.site.clone();
            e.seq = seq;
            self.push_effect(e);
        }
        Op { site: self.site.clone(), seq, seen, id: id.to_string(), params: params.to_string(), sel: snap.sel.clone() }
    }

    fn ready(&self, op: &Op) -> bool {
        op.seq == self.seen.get(&op.site).copied().unwrap_or(0).saturating_add(1)
            && op.seen.iter().all(|(s, n)| s == &op.site || self.seen.get(s).copied().unwrap_or(0) >= *n)
    }

    /// Take in a received edit; returns the edits now ready to apply, in order. Duplicates and
    /// our own edits come back as nothing; edits whose predecessors haven't arrived wait.
    pub fn accept(&mut self, op: Op) -> Vec<Op> {
        if op.site == self.site || op.seq <= self.seen.get(&op.site).copied().unwrap_or(0) {
            return Vec::new();
        }
        if self.pending.len() >= PENDING_CAP {
            self.pending.remove(0);
        }
        if !self.pending.iter().any(|p| p.site == op.site && p.seq == op.seq) {
            self.pending.push(op);
        }
        let mut out = Vec::new();
        while let Some(i) = self.pending.iter().position(|p| self.ready(p)) {
            let op = self.pending.remove(i);
            self.seen.insert(op.site.clone(), op.seq);
            out.push(op);
        }
        out
    }

    /// The author's selection moved past every applied edit they had not seen.
    pub fn rebase(&self, op: &Op) -> Selection {
        let mut sel = op.sel.clone();
        for e in &self.log {
            if e.site != op.site && op.seen.get(&e.site).copied().unwrap_or(0) < e.seq {
                e.shift_sel(&mut sel, &op.site);
            }
        }
        sel
    }

    /// Record a remote edit that has just been applied (`effect` from [`Snapshot::effect_in`]),
    /// and return the local selection moved past it.
    pub fn applied_remote(&mut self, op: &Op, effect: Option<Effect>, local: &mut Selection) {
        if let Some(mut e) = effect {
            e.site = op.site.clone();
            e.seq = op.seq;
            e.shift_sel(local, &self.site);
            self.push_effect(e);
        }
    }
}

/// How a command takes part in Share Mode.
#[derive(Debug, PartialEq)]
pub enum Verdict {
    /// Send it to the other people.
    Share,
    /// Nothing to send (a caret move, saving, a view setting).
    Quiet,
    /// It changes the document but stays on this machine; the reason is shown to the user.
    Unshared(&'static str),
}

/// Parameters that mean "a file or secret on this machine".
const LOCAL_KEYS: &[&str] = &["path", "paths", "password", "file", "url", "folder", "dir"];

/// Decide how `id` is shared. The same check guards incoming edits: a peer can't make us save,
/// open or run anything.
pub fn verdict(session: &Session, id: &str, params: &serde_json::Value) -> Verdict {
    let Some(spec) = session.registry.get(id) else { return Verdict::Quiet };
    if !spec.mutates || id.starts_with("file.") || id.starts_with("ui.") || id.starts_with("view.") {
        return Verdict::Quiet;
    }
    match id {
        "edit.undo" | "edit.redo" | "edit.undoTo" | "edit.repeat" => {
            return Verdict::Unshared("undo and redo would also undo other people's edits");
        }
        "edit.paste" | "edit.pasteSpecial" if params.get("text").is_none() => {
            return Verdict::Unshared("paste uses your own clipboard");
        }
        _ => {}
    }
    if id.starts_with("tools.") || id.starts_with("mailings.") || id.starts_with("font.") || id.starts_with("zotero.") {
        return Verdict::Unshared("it depends on settings or files on this machine");
    }
    if let Some(o) = params.as_object()
        && LOCAL_KEYS.iter().any(|k| o.contains_key(*k))
    {
        return Verdict::Unshared("it refers to a file or password on this machine");
    }
    Verdict::Share
}

/// Cut is shared as the deletion it amounts to (the other side has no use for your clipboard).
pub fn wire_command(id: &str, params: &serde_json::Value) -> (String, serde_json::Value) {
    if id == "edit.cut" {
        return ("text.delete".into(), serde_json::json!({}));
    }
    (id.to_string(), params.clone())
}
