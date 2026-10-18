//! simple-sync: zero-server, end-to-end encrypted P2P sync with capability
//! "Share Mode" tickets (edit / view-only) and a kill switch.
//!
//! The host app stays fully synchronous: [`SyncEngine`] runs its own Tokio
//! runtime on a background thread and exchanges messages with the app through
//! channels. Call [`SyncEngine::poll`] once per frame.

pub mod crypto;
pub mod replay;
pub mod state;
pub mod ticket;
mod worker;

use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

pub use ticket::{SessionTicket, SharePermission};
pub use worker::SyncConfig;
use worker::{Shared, Worker, WorkerCommand};

/// Events polled by the host application once per frame.
#[derive(Debug, Clone)]
pub enum SyncEvent {
    /// Fired on the joiner's machine once the base file (e.g. raw PDF bytes) is
    /// downloaded and verified against the ticket's BLAKE3 hash.
    BaseDocumentReady {
        filename: String,
        bytes: Vec<u8>,
    },
    /// A remote writer broadcast a mutation. `mutation_bytes` is the `bincode`
    /// encoding of what they passed to [`SyncEngine::broadcast_mutation`].
    RemoteMutation {
        author_peer_id: String,
        mutation_bytes: Vec<u8>,
    },
    /// A *remote* Loro CRDT delta/snapshot was merged.
    CrdtUpdated {
        json_state: String,
    },
    PeerJoined {
        peer_id: String,
    },
    PeerLeft {
        peer_id: String,
    },
    Error(String),
}

/// The two capability links produced when Share Mode is enabled.
#[derive(Clone)]
pub struct ShareLinks {
    /// "Anyone with this link can edit."
    pub edit_uri: String,
    /// "Anyone with this link can view."
    pub view_only_uri: String,
}

// Links are secrets; keep them out of logs.
impl std::fmt::Debug for ShareLinks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ShareLinks { <redacted> }")
    }
}

/// What the top-bar status pill should show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareRole {
    Offline,
    Hosting,
    JoinedCanEdit,
    JoinedViewOnly,
}

/// Lock a mutex, recovering the data if another thread panicked while holding it: a poisoned
/// lock must not take the host app's UI thread down with it.
pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Plaintext message inside an encrypted frame. Public only so tests can forge frames.
#[doc(hidden)]
#[derive(Serialize, Deserialize)]
pub enum Wire {
    Mutation(Vec<u8>),
    Crdt(Vec<u8>),
}

/// The single struct added to the target app's main State/Workbench struct.
pub struct SyncEngine {
    cmd_tx: UnboundedSender<WorkerCommand>,
    event_rx: UnboundedReceiver<SyncEvent>,
    shared: Arc<Shared>,
    role: ShareRole,
}

const REPLY_TIMEOUT: Duration = Duration::from_secs(60);

/// Largest gossip frame, set on every peer's gossip instance. iroh-gossip's own default is 4 KiB,
/// which an ink stroke, a long text or an attachment exceeds; all peers of a session must agree.
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;

/// Largest mutation `broadcast_mutation` accepts: the frame limit less the nonce, tag, signature
/// and framing overhead.
pub const MAX_MUTATION_BYTES: usize = MAX_FRAME_BYTES - 1024;

impl SyncEngine {
    /// Initialize the background runtime. Only a thread is spawned; no socket is
    /// bound until a session is started or joined.
    pub fn new(app_namespace: &str) -> Result<Self> {
        Self::with_config(app_namespace, SyncConfig::default())
    }

    /// Like [`SyncEngine::new`] with explicit network configuration
    /// (e.g. [`SyncConfig::local_only`] for tests).
    pub fn with_config(app_namespace: &str, cfg: SyncConfig) -> Result<Self> {
        let (cmd_tx, cmd_rx) = unbounded_channel();
        let (evt_tx, event_rx) = unbounded_channel();
        let shared = Arc::new(Shared::default());
        let worker = Worker::new(cfg, evt_tx, shared.clone());
        std::thread::Builder::new()
            .name(format!("simple-sync:{app_namespace}"))
            .spawn(move || {
                let Ok(rt) = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                else {
                    return;
                };
                rt.block_on(worker.run(cmd_rx));
            })?;
        Ok(Self {
            cmd_tx,
            event_rx,
            shared,
            role: ShareRole::Offline,
        })
    }

    fn request<T>(&self, make: impl FnOnce(mpsc::Sender<Result<T>>) -> WorkerCommand) -> Result<T> {
        let (reply, rx) = mpsc::channel();
        self.cmd_tx
            .send(make(reply))
            .map_err(|_| anyhow!("sync worker stopped"))?;
        rx.recv_timeout(REPLY_TIMEOUT)
            .map_err(|_| anyhow!("sync worker did not respond"))?
    }

    // ---- Share Mode lifecycle -------------------------------------------------

    /// Turn Share Mode ON. Generates a fresh topic, read key and write keypair,
    /// serves `base_bytes` over iroh-blobs and returns both capability links.
    ///
    /// Waits briefly for the socket to bind; call it from a button handler.
    pub fn enable_share_mode(&mut self, filename: &str, base_bytes: Vec<u8>) -> Result<ShareLinks> {
        if self.role != ShareRole::Offline {
            bail!("already sharing or joined; stop first");
        }
        let links = self.request(|reply| WorkerCommand::Enable {
            filename: filename.to_string(),
            bytes: base_bytes,
            reply,
        })?;
        self.role = ShareRole::Hosting;
        Ok(links)
    }

    /// The Kill Switch. Drops the gossip subscription, wipes the session keys,
    /// releases the served blob and returns to [`ShareRole::Offline`]. Also the
    /// way for a joiner to leave. Re-enabling generates entirely new keys/topic,
    /// so old links can never reconnect.
    pub fn disable_share_mode(&mut self) -> Result<()> {
        if self.role == ShareRole::Offline {
            return Ok(());
        }
        self.request(|reply| WorkerCommand::Disable { reply })?;
        self.role = ShareRole::Offline;
        Ok(())
    }

    /// Join a session from an `ssync://` link. The role follows the ticket's
    /// capability. The base document arrives later as
    /// [`SyncEvent::BaseDocumentReady`]; remote events are held back until then.
    pub fn join_via_ticket(&mut self, ticket_uri: &str) -> Result<ShareRole> {
        if self.role != ShareRole::Offline {
            bail!("already sharing or joined; stop first");
        }
        let ticket = SessionTicket::from_uri(ticket_uri)?;
        let role = match ticket.permission() {
            SharePermission::ReadWrite => ShareRole::JoinedCanEdit,
            SharePermission::ReadOnly => ShareRole::JoinedViewOnly,
        };
        self.request(|reply| WorkerCommand::Join { ticket, reply })?;
        self.role = role;
        Ok(role)
    }

    /// Alias of [`SyncEngine::enable_share_mode`].
    pub fn start_share_mode(&mut self, filename: &str, base_bytes: Vec<u8>) -> Result<ShareLinks> {
        self.enable_share_mode(filename, base_bytes)
    }

    /// Alias of [`SyncEngine::disable_share_mode`].
    pub fn stop_share_mode(&mut self) -> Result<()> {
        self.disable_share_mode()
    }

    /// Alias of [`SyncEngine::join_via_ticket`].
    pub fn join_session(&mut self, ticket_uri: &str) -> Result<ShareRole> {
        self.join_via_ticket(ticket_uri)
    }

    // ---- Getters (lock-free enough for a 60fps UI) -------------------------------

    pub fn role(&self) -> ShareRole {
        self.role
    }

    /// Currently connected gossip neighbors.
    pub fn connected_peers_count(&self) -> usize {
        self.shared.peers.load(Ordering::Relaxed)
    }

    /// This session's ephemeral peer id (hex); empty while offline. It is the
    /// `author_peer_id` other peers see on your mutations.
    pub fn local_peer_id(&self) -> String {
        lock(&self.shared.peer_id).clone()
    }

    // ---- Data plane ------------------------------------------------------------------

    /// Broadcast a structured mutation (`bincode`-serialized, signed with the
    /// session write key, encrypted with the read key). Non-blocking.
    ///
    /// Fails with `Session is View-Only` for view-only joiners, before anything
    /// touches the network.
    pub fn broadcast_mutation<T: Serialize>(&self, mutation: &T) -> Result<()> {
        self.ensure_can_write()?;
        let bytes = bincode::serialize(mutation)?;
        if bytes.len() > MAX_MUTATION_BYTES {
            bail!(
                "this edit is too large to share live ({} bytes; the limit is {MAX_MUTATION_BYTES})",
                bytes.len()
            );
        }
        self.cmd_tx
            .send(WorkerCommand::Mutation(bytes))
            .map_err(|_| anyhow!("sync worker stopped"))
    }

    /// Set a key in the shared Loro CRDT map and broadcast the delta (writers only).
    pub fn set_shared(&self, key: &str, value: &str) -> Result<()> {
        self.ensure_can_write()?;
        self.cmd_tx
            .send(WorkerCommand::CrdtSet {
                key: key.to_string(),
                value: value.to_string(),
            })
            .map_err(|_| anyhow!("sync worker stopped"))
    }

    fn ensure_can_write(&self) -> Result<()> {
        match self.role {
            ShareRole::Offline => bail!("No active session"),
            ShareRole::JoinedViewOnly => bail!("Session is View-Only"),
            ShareRole::Hosting | ShareRole::JoinedCanEdit => Ok(()),
        }
    }

    /// Non-blocking poll called inside the host app's main update/render loop.
    pub fn poll(&mut self) -> Option<SyncEvent> {
        self.event_rx.try_recv().ok()
    }

    /// Test hook: publish raw bytes on the session's gossip topic, bypassing the
    /// role check and crypto. Used to prove receivers reject forged frames.
    #[doc(hidden)]
    pub fn __inject_raw_frame(&self, frame: Vec<u8>) {
        let _ = self.cmd_tx.send(WorkerCommand::RawFrame(frame));
    }
}
