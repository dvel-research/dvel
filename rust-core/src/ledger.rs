// Linkage-aware ledger (single-parent, fork-legal).
// Separates validity from linkage: this module only enforces parent existence + duplicate rules and derives tips.

use crate::event::{Event, Hash};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::collections::{HashMap, HashSet};

/// Genesis marker: prev_hash = all-zeroes means no parent.
pub const ZERO_HASH: Hash = [0u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedgerLinkError {
    Duplicate,
    MissingParent,
}

#[derive(Debug)]
pub struct Ledger {
    events: HashMap<Hash, Event>,
    tips: HashSet<Hash>,
}

impl Ledger {
    pub fn new() -> Self {
        Ledger {
            events: HashMap::new(),
            tips: HashSet::new(),
        }
    }

    pub fn hash_event(event: &Event) -> Hash {
        let bytes = event.hash_material();
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        hasher.finalize().into()
    }

    /// Unchecked add: insert and update tips without linkage tests (legacy path).
    pub fn add_event(&mut self, event: Event) -> Hash {
        let hash = Self::hash_event(&event);
        self.events.insert(hash, event.clone());

        // Update tips (legacy): remove parent tip (even if ZERO_HASH) and insert new tip.
        if event.prev_hash != ZERO_HASH {
            self.tips.remove(&event.prev_hash);
        }
        self.tips.insert(hash);

        hash
    }

    /// Linkage-aware add:
    /// - Reject duplicate hash
    /// - Reject missing parent unless genesis (prev_hash == ZERO_HASH)
    /// - Update tips deterministically on success
    pub fn try_add_event(&mut self, event: Event) -> Result<Hash, LedgerLinkError> {
        let hash = Self::hash_event(&event);

        if self.events.contains_key(&hash) {
            return Err(LedgerLinkError::Duplicate);
        }

        if event.prev_hash != ZERO_HASH && !self.events.contains_key(&event.prev_hash) {
            return Err(LedgerLinkError::MissingParent);
        }

        self.events.insert(hash, event.clone());

        if event.prev_hash != ZERO_HASH {
            self.tips.remove(&event.prev_hash);
        }
        self.tips.insert(hash);

        Ok(hash)
    }

    pub fn get_event(&self, hash: &Hash) -> Option<&Event> {
        self.events.get(hash)
    }

    /// Snapshot of all event hashes.
    pub fn hashes_set(&self) -> HashSet<Hash> {
        self.events.keys().cloned().collect()
    }

    /// Snapshot copy of current tips (small set; OK for sim).
    pub fn get_tips(&self) -> HashSet<Hash> {
        self.tips.clone()
    }

    /// Deterministic Merkle root over all event hashes (lexicographically sorted leaves).
    /// None iff ledger is empty.
    pub fn merkle_root(&self) -> Option<Hash> {
        if self.events.is_empty() {
            return None;
        }
        let mut level: Vec<Hash> = BTreeSet::from_iter(self.events.keys().cloned())
            .into_iter()
            .collect();

        while level.len() > 1 {
            let mut next: Vec<Hash> = Vec::with_capacity(level.len().div_ceil(2));
            let mut i = 0;
            while i < level.len() {
                let a = level[i];
                let b = if i + 1 < level.len() {
                    level[i + 1]
                } else {
                    level[i]
                };
                let mut hasher = Sha256::new();
                hasher.update(a);
                hasher.update(b);
                let h: Hash = hasher.finalize().into();
                next.push(h);
                i += 2;
            }
            level = next;
        }

        level.first().copied()
    }
}

impl Default for Ledger {
    fn default() -> Self {
        Self::new()
    }
}
