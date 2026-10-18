//! Duplicate-frame suppression.
//!
//! Every frame carries a per-sender `seq` inside its signed bytes. A peer that holds the read key
//! (a View-Only peer included) can capture a valid frame and publish it again; the signature
//! still verifies, so only remembering what was already applied stops it from being applied twice.
//!
//! Per author this keeps the highest `seq` seen and the set of `seq`s seen within a sliding
//! window below it. A `seq` older than the window is refused rather than remembered forever, so
//! memory stays bounded; the number of distinct authors is capped for the same reason.

use std::collections::{HashMap, HashSet};

/// How far below the newest `seq` an author's frames are still tracked individually.
pub const WINDOW: u64 = 65_536;
/// Distinct authors remembered; frames from further authors are refused.
pub const MAX_AUTHORS: usize = 256;

#[derive(Default)]
struct AuthorWindow {
    max: u64,
    seen: HashSet<u64>,
}

#[derive(Default)]
pub struct ReplayGuard {
    authors: HashMap<[u8; 32], AuthorWindow>,
}

impl ReplayGuard {
    pub fn new() -> Self {
        Self::default()
    }

    /// `true` the first time `(author, seq)` is offered and it is within the window.
    pub fn accept(&mut self, author: [u8; 32], seq: u64) -> bool {
        if !self.authors.contains_key(&author) && self.authors.len() >= MAX_AUTHORS {
            return false;
        }
        let w = self.authors.entry(author).or_default();
        if w.max.saturating_sub(seq) >= WINDOW {
            return false;
        }
        if !w.seen.insert(seq) {
            return false;
        }
        if seq > w.max {
            w.max = seq;
            if w.seen.len() as u64 > WINDOW * 2 {
                let floor = w.max.saturating_sub(WINDOW);
                w.seen.retain(|s| *s > floor);
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_repeated_frame_is_refused() {
        let mut g = ReplayGuard::new();
        assert!(g.accept([1; 32], 5));
        assert!(!g.accept([1; 32], 5), "a replay of the same frame");
        assert!(
            g.accept([2; 32], 5),
            "another author's frame with the same seq"
        );
    }

    #[test]
    fn reordered_frames_are_each_accepted_once() {
        let mut g = ReplayGuard::new();
        for seq in [3, 1, 2] {
            assert!(g.accept([1; 32], seq));
        }
        for seq in [1, 2, 3] {
            assert!(!g.accept([1; 32], seq));
        }
    }

    #[test]
    fn frames_older_than_the_window_are_refused() {
        let mut g = ReplayGuard::new();
        assert!(g.accept([1; 32], WINDOW + 10));
        assert!(!g.accept([1; 32], 10));
        assert!(g.accept([1; 32], 11));
    }

    #[test]
    fn memory_and_authors_stay_bounded() {
        let mut g = ReplayGuard::new();
        for seq in 0..(WINDOW * 4) {
            g.accept([1; 32], seq);
        }
        assert!(g.authors[&[1; 32]].seen.len() as u64 <= WINDOW * 2 + 1);
        for a in 0..=255u8 {
            g.accept([a.wrapping_add(10); 32], 1);
        }
        let mut extra = [0u8; 32];
        extra[0] = 200;
        extra[1] = 200;
        assert!(!g.accept(extra, 1), "authors beyond the cap are refused");
        assert!(
            g.accept([1; 32], u64::MAX - 1),
            "known authors keep working"
        );
    }
}
