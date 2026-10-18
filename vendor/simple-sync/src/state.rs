//! Loro CRDT document wrapper for conflict-free delta merging.
//!
//! Gives apps a tiny shared key/value map (`"shared"`) whose concurrent edits
//! merge deterministically on every peer, independent of delivery order.

use anyhow::{anyhow, Result};
use loro::{ExportMode, LoroDoc, VersionVector};

const ROOT: &str = "shared";

pub struct CrdtState {
    doc: LoroDoc,
}

impl Default for CrdtState {
    fn default() -> Self {
        Self::new()
    }
}

impl CrdtState {
    pub fn new() -> Self {
        Self {
            doc: LoroDoc::new(),
        }
    }

    /// Set `key = value` in the shared map; returns the delta to broadcast.
    pub fn set(&self, key: &str, value: &str) -> Result<Vec<u8>> {
        let before: VersionVector = self.doc.oplog_vv();
        self.doc
            .get_map(ROOT)
            .insert(key, value)
            .map_err(|e| anyhow!("crdt insert: {e}"))?;
        self.doc.commit();
        self.doc
            .export(ExportMode::updates(&before))
            .map_err(|e| anyhow!("crdt export: {e}"))
    }

    /// Merge a remote delta or snapshot. Idempotent and order-independent.
    pub fn apply(&self, bytes: &[u8]) -> Result<()> {
        self.doc
            .import(bytes)
            .map(|_| ())
            .map_err(|e| anyhow!("crdt import: {e}"))
    }

    /// All known operations, for bringing a late joiner up to date.
    pub fn snapshot(&self) -> Result<Vec<u8>> {
        self.doc
            .export(ExportMode::all_updates())
            .map_err(|e| anyhow!("crdt export: {e}"))
    }

    pub fn is_empty(&self) -> bool {
        self.doc.oplog_vv().is_empty()
    }

    /// Whole document as JSON, e.g. `{"shared":{"title":"Hi"}}`.
    pub fn json(&self) -> String {
        serde_json::to_string(&self.doc.get_deep_value()).unwrap_or_else(|_| "{}".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deltas_converge_in_any_order() {
        let a = CrdtState::new();
        let b = CrdtState::new();
        let d1 = a.set("title", "A").unwrap();
        let d2 = b.set("author", "B").unwrap();
        a.apply(&d2).unwrap();
        b.apply(&d1).unwrap();
        b.apply(&d1).unwrap(); // idempotent
        assert_eq!(a.json(), b.json());
        assert!(a.json().contains("title") && a.json().contains("author"));
    }

    #[test]
    fn concurrent_writes_to_same_key_converge() {
        let a = CrdtState::new();
        let b = CrdtState::new();
        let d1 = a.set("k", "from-a").unwrap();
        let d2 = b.set("k", "from-b").unwrap();
        a.apply(&d2).unwrap();
        b.apply(&d1).unwrap();
        assert_eq!(a.json(), b.json());
    }

    #[test]
    fn snapshot_catches_up_late_joiner() {
        let a = CrdtState::new();
        a.set("x", "1").unwrap();
        a.set("y", "2").unwrap();
        let late = CrdtState::new();
        assert!(late.is_empty());
        late.apply(&a.snapshot().unwrap()).unwrap();
        assert_eq!(a.json(), late.json());
    }
}
