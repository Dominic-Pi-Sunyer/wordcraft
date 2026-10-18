//! The network side: `simple_sync::SyncEngine` moved onto a worker thread for every call that
//! blocks (share, join, stop), so the window never freezes.

use std::sync::mpsc::{Receiver, channel};

use simple_sync::{ShareRole, SyncConfig, SyncEngine, SyncEvent};

use super::{LinkEvent, LinkNotice, Links, Role};

enum Done {
    Shared(SyncEngine, Result<Links, String>),
    Joined(SyncEngine, Result<ShareRole, String>),
    Stopped(SyncEngine, Result<(), String>),
}

pub struct Link {
    engine: Option<SyncEngine>,
    busy: Option<Receiver<Done>>,
    /// Role the engine will have when the pending call finishes, for `role()`.
    cfg_local: bool,
}

fn engine(local_only: bool) -> Option<SyncEngine> {
    let cfg = if local_only { SyncConfig::local_only() } else { SyncConfig::default() };
    SyncEngine::with_config("wordcraft", cfg).ok()
}

impl Link {
    pub fn new(local_only: bool) -> Self {
        // The engine (a thread and a runtime) is made on first use, not for every window.
        Link { engine: None, busy: None, cfg_local: local_only }
    }

    pub fn available(&self) -> bool {
        true
    }

    pub fn busy(&self) -> bool {
        self.busy.is_some()
    }

    pub fn role(&self) -> Role {
        match self.engine.as_ref().map(SyncEngine::role) {
            Some(ShareRole::Hosting) => Role::Hosting,
            Some(ShareRole::JoinedCanEdit) => Role::JoinedCanEdit,
            Some(ShareRole::JoinedViewOnly) => Role::JoinedViewOnly,
            _ => Role::Offline,
        }
    }

    pub fn peers(&self) -> usize {
        self.engine.as_ref().map_or(0, SyncEngine::connected_peers_count)
    }

    pub fn local_id(&self) -> String {
        self.engine.as_ref().map(SyncEngine::local_peer_id).unwrap_or_default()
    }

    fn take_engine(&mut self) -> Result<SyncEngine, String> {
        if self.busy.is_some() {
            return Err("Share Mode is busy; try again in a moment".into());
        }
        match self.engine.take() {
            Some(e) => Ok(e),
            None => engine(self.cfg_local).ok_or_else(|| "Share Mode couldn't start its network thread".to_string()),
        }
    }

    pub fn begin_share(&mut self, filename: String, bytes: Vec<u8>) -> Result<(), String> {
        let mut e = self.take_engine()?;
        let (tx, rx) = channel();
        self.busy = Some(rx);
        std::thread::spawn(move || {
            let r = e.enable_share_mode(&filename, bytes).map(|l| Links { edit: l.edit_uri, view: l.view_only_uri }).map_err(|e| e.to_string());
            let _ = tx.send(Done::Shared(e, r));
        });
        Ok(())
    }

    pub fn begin_join(&mut self, uri: String) -> Result<(), String> {
        let mut e = self.take_engine()?;
        let (tx, rx) = channel();
        self.busy = Some(rx);
        std::thread::spawn(move || {
            let r = e.join_via_ticket(&uri).map_err(|e| e.to_string());
            let _ = tx.send(Done::Joined(e, r));
        });
        Ok(())
    }

    pub fn begin_stop(&mut self) -> Result<(), String> {
        let mut e = self.take_engine()?;
        let (tx, rx) = channel();
        self.busy = Some(rx);
        std::thread::spawn(move || {
            let r = e.disable_share_mode().map_err(|e| e.to_string());
            let _ = tx.send(Done::Stopped(e, r));
        });
        Ok(())
    }

    /// Outcome of a finished share/join/stop, if any.
    pub fn poll_done(&mut self) -> Option<LinkNotice> {
        let rx = self.busy.as_ref()?;
        let done = match rx.try_recv() {
            Ok(d) => d,
            Err(std::sync::mpsc::TryRecvError::Empty) => return None,
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                self.busy = None;
                return Some(LinkNotice::Failed("Share Mode's worker stopped unexpectedly".into()));
            }
        };
        self.busy = None;
        Some(match done {
            Done::Shared(e, r) => {
                self.engine = Some(e);
                r.map_or_else(LinkNotice::Failed, LinkNotice::Shared)
            }
            Done::Joined(e, r) => {
                self.engine = Some(e);
                r.map_or_else(LinkNotice::Failed, |_| LinkNotice::Joined)
            }
            Done::Stopped(e, r) => {
                self.engine = Some(e);
                r.map_or_else(LinkNotice::Failed, |()| LinkNotice::Stopped)
            }
        })
    }

    pub fn poll_event(&mut self) -> Option<LinkEvent> {
        let e = self.engine.as_mut()?;
        Some(match e.poll()? {
            SyncEvent::BaseDocumentReady { filename, bytes } => LinkEvent::Base { filename, bytes },
            SyncEvent::RemoteMutation { mutation_bytes, .. } => LinkEvent::Remote(mutation_bytes),
            SyncEvent::PeerJoined { .. } | SyncEvent::PeerLeft { .. } => LinkEvent::Peers,
            SyncEvent::Error(m) => LinkEvent::Error(m),
            SyncEvent::CrdtUpdated { .. } => LinkEvent::Peers,
        })
    }

    pub fn broadcast<T: serde::Serialize>(&self, m: &T) -> Result<(), String> {
        match &self.engine {
            Some(e) => e.broadcast_mutation(m).map_err(|e| e.to_string()),
            None => Err("Share Mode is busy".into()),
        }
    }
}
