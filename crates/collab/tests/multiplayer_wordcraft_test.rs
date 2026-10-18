//! Two or three WordCraft sessions share one document over simple-sync (local network only, no
//! relay) and converge. Every edit goes through the same gate/before/run/after sequence the
//! window uses.

use std::time::{Duration, Instant};

use serde_json::{Value, json};
use wordcraft_collab::{Collab, Role};
use wordcraft_doc::{Document, StoryRef};
use wordcraft_engine::Session;

struct App {
    session: Session,
    collab: Collab,
}

impl App {
    fn new() -> App {
        App { session: Session::new(Document::new()), collab: Collab::local_only() }
    }

    /// What the window does for a command the user runs.
    fn user(&mut self, id: &str, params: Value) -> Result<Value, String> {
        self.collab.gate(&self.session, id, &params)?;
        let snap = self.collab.before(&self.session);
        let r = self.session.run(id, &params).map_err(|e| e.to_string())?;
        self.collab.after(&self.session, snap, id, &params);
        Ok(r)
    }

    fn text(&self) -> String {
        self.session.doc.plain_text(StoryRef::Body)
    }

    fn pump(&mut self) -> wordcraft_collab::Polled {
        self.collab.poll(&mut self.session)
    }
}

/// Poll every app until `done` holds.
fn settle(apps: &mut [&mut App], what: &str, done: impl Fn(&[&mut App]) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        for a in apps.iter_mut() {
            a.pump();
        }
        if done(apps) {
            return;
        }
        let notices: Vec<_> = apps.iter_mut().flat_map(|a| a.collab.take_notices()).collect();
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {what}; texts {:?}; notices {notices:?}",
            apps.iter().map(|a| a.text()).collect::<Vec<_>>()
        );
        std::thread::sleep(Duration::from_millis(15));
    }
}

fn join(app: &mut App, link: &str, host: &mut App) {
    app.collab.join(link).unwrap();
    let mut loaded = false;
    let deadline = Instant::now() + Duration::from_secs(45);
    while !loaded {
        host.pump();
        loaded = app.pump().loaded;
        assert!(Instant::now() < deadline, "joiner never received the document: {:?}", app.collab.take_notices());
        std::thread::sleep(Duration::from_millis(15));
    }
}

fn start(host: &mut App) -> wordcraft_collab::Links {
    host.collab.start_share(&host.session).unwrap();
    settle(&mut [host], "share to start", |a| !a[0].collab.busy() && a[0].collab.links().is_some());
    host.collab.links().cloned().unwrap()
}

#[test]
fn concurrent_typing_converges_and_view_only_cannot_edit() {
    let mut host = App::new();
    host.user("text.insert", json!({"text": "Hello world"})).unwrap();
    let links = start(&mut host);
    assert_eq!(host.collab.role(), Role::Hosting);

    let mut joiner = App::new();
    join(&mut joiner, &links.edit, &mut host);
    assert_eq!(joiner.collab.role(), Role::JoinedCanEdit);
    assert_eq!(joiner.text(), "Hello world", "the joiner receives the existing document");

    // Both type before either has heard from the other: host at the start, joiner at the end.
    host.user("caret.docStart", json!({})).unwrap();
    host.user("text.insert", json!({"text": "Say: "})).unwrap();
    joiner.user("caret.docEnd", json!({})).unwrap();
    joiner.user("text.insert", json!({"text": "!"})).unwrap();
    settle(&mut [&mut host, &mut joiner], "convergence", |a| a[0].text() == "Say: Hello world!" && a[1].text() == "Say: Hello world!");

    // Both type at exactly the same spot at once: the order is the same on both sides.
    host.user("caret.docStart", json!({})).unwrap();
    joiner.user("caret.docStart", json!({})).unwrap();
    host.user("text.insert", json!({"text": "H"})).unwrap();
    joiner.user("text.insert", json!({"text": "J"})).unwrap();
    settle(&mut [&mut host, &mut joiner], "same-spot convergence", |a| a[0].text().len() == 19 && a[0].text() == a[1].text());
    assert!(host.text() == "HJSay: Hello world!" || host.text() == "JHSay: Hello world!", "{}", host.text());

    // Formatting concurrent with typing: bold "world" on the host while the joiner types before it.
    let before = host.text();
    host.user("select.text", json!({"text": "world"})).unwrap();
    joiner.user("caret.docStart", json!({})).unwrap();
    joiner.user("text.insert", json!({"text": "++"})).unwrap();
    host.user("format.bold", json!({})).unwrap();
    host.user("caret.docEnd", json!({})).unwrap();
    host.user("text.insert", json!({"text": " end"})).unwrap();
    settle(&mut [&mut host, &mut joiner], "second convergence", |a| {
        a[0].text() == a[1].text()
            && a[0].text().len() == before.len() + 6
            && a[0].session.doc.body[0].as_para().is_some_and(|p| p.runs.iter().any(|r| r.props.bold == Some(true)))
            && a[1].session.doc.body[0].as_para().is_some_and(|p| p.runs.iter().any(|r| r.props.bold == Some(true)))
    });
    // Both peers bolded the exact same shifted byte range ("world").
    assert_eq!(host.session.doc.body[0].as_para().unwrap().runs, joiner.session.doc.body[0].as_para().unwrap().runs);

    // A view-only link shows the document and refuses edits.
    let mut viewer = App::new();
    join(&mut viewer, &links.view, &mut host);
    assert_eq!(viewer.collab.role(), Role::JoinedViewOnly);
    assert_eq!(viewer.text(), host.text(), "a late joiner receives the earlier edits too");
    let before_view = viewer.text();
    assert!(viewer.user("text.insert", json!({"text": "nope"})).is_err());
    assert_eq!(viewer.text(), before_view);
    host.user("text.insert", json!({"text": "?"})).unwrap();
    settle(&mut [&mut host, &mut joiner, &mut viewer], "view-only receives updates", |a| a[2].text() == a[0].text() && a[1].text() == a[0].text());
    assert!(viewer.user("format.bold", json!({})).is_err(), "formatting is an edit too");

    // Kill switch.
    host.collab.stop().unwrap();
    settle(&mut [&mut host], "stop", |a| !a[0].collab.busy());
    assert_eq!(host.collab.role(), Role::Offline);
    assert!(host.collab.links().is_none());
}

#[test]
fn unshared_commands_say_so_and_are_refused_when_unsafe() {
    let mut host = App::new();
    host.user("text.insert", json!({"text": "abc"})).unwrap();
    start(&mut host);
    host.user("select.all", json!({})).unwrap();
    host.user("edit.copy", json!({})).unwrap();
    host.user("edit.paste", json!({})).unwrap();
    let notices = host.collab.take_notices();
    assert!(notices.iter().any(|n| n.contains("not shared")), "{notices:?}");
    // Undo would also remove other people's edits: refused while sharing.
    assert!(host.user("edit.undo", json!({})).is_err());
    assert!(host.user("file.new", json!({})).is_err(), "can't swap the shared document away");
}

#[test]
fn incoming_edits_cannot_reach_files_or_settings() {
    let s = Session::new(Document::new());
    for (id, params) in [
        ("file.save", json!({"path": "/tmp/x"})),
        ("file.open", json!({"path": "/tmp/x"})),
        ("tools.macros", json!({})),
        ("insert.picture", json!({"path": "/etc/passwd"})),
        ("file.encrypt", json!({"password": "x"})),
        ("edit.paste", json!({})),
    ] {
        assert_ne!(wordcraft_collab::merge::verdict(&s, id, &params), wordcraft_collab::Verdict::Share, "{id}");
    }
    assert_eq!(wordcraft_collab::merge::verdict(&s, "text.insert", &json!({"text": "a"})), wordcraft_collab::Verdict::Share);
}

#[test]
fn shared_commands_survive_wire_round_trip() {
    use bincode::Options;
    let mut s = Session::new(Document::new());
    s.run("text.insert", &json!({"text": "Hello world"})).unwrap();
    let mut r = wordcraft_collab::Replica::new("peer-a");
    let params = json!({"text": "!", "align": "center", "name": "Heading 1"});
    let mut count = 0usize;
    for spec in s.registry.all() {
        if wordcraft_collab::merge::verdict(&s, spec.id, &params) != wordcraft_collab::Verdict::Share {
            continue;
        }
        count += 1;
        let snap = wordcraft_collab::Snapshot::take(&s);
        let (wid, wparams) = wordcraft_collab::merge::wire_command(spec.id, &params);
        let op = r.local(&wid, &wparams, &snap, &s);
        let bytes = bincode::serialize(&op).unwrap();
        let decoded: wordcraft_collab::Op = bincode::DefaultOptions::new().with_fixint_encoding().allow_trailing_bytes().deserialize(&bytes).unwrap();
        assert_eq!(decoded, op, "{} round-trip", spec.id);
    }
    assert!(count > 50, "expected many shared commands, got {count}");
}
