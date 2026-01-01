// Local scoring / preference (non-consensus)
// Deterministic, in-memory; treat this as an argmax over chain scores.

use crate::event::{Event, Hash, PublicKey, Signature};
use crate::ledger::Ledger;
use std::collections::{HashMap, HashSet};

/// Non-consensus weighting policy.
/// Constraints: never touches validity; purely local function of the event.
pub trait WeightPolicy {
    fn weight_event(&self, event: &Event) -> u64;
}

/// Baseline policy: weight(e) = 1 for all e.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnitWeight;

impl WeightPolicy for UnitWeight {
    fn weight_event(&self, _event: &Event) -> u64 {
        1
    }
}

/// Optional policy hook: maturity-style weighting (stub).
#[derive(Clone, Copy, Debug)]
pub struct MaturityStubWeight {
    pub new_author_weight: u64,
    pub mature_author_weight: u64,
    pub mature_author: PublicKey,
}

impl WeightPolicy for MaturityStubWeight {
    fn weight_event(&self, event: &Event) -> u64 {
        if event.author == self.mature_author {
            self.mature_author_weight
        } else {
            self.new_author_weight
        }
    }
}

#[derive(Debug, Clone)]
pub struct Chain {
    /// Ordered genesis->tip if possible (best effort).
    pub hashes: Vec<Hash>,
    pub score: u64,
}

/// Build a best-effort chain by walking prev_hash backwards from a tip.
/// Stop if parent is unknown or max_steps is hit (safety guard).
pub fn build_chain_from_tip(ledger: &Ledger, tip: &Hash, max_steps: usize) -> Chain {
    let mut rev: Vec<Hash> = Vec::new();
    let mut cur = *tip;

    for _ in 0..max_steps {
        if ledger.get_event(&cur).is_none() {
            break;
        }
        rev.push(cur);
        let e = ledger.get_event(&cur).expect("checked exists");
        cur = e.prev_hash;
    }

    rev.reverse();
    Chain {
        hashes: rev,
        score: 0,
    }
}

/// Compute chain score with a local WeightPolicy (simple additive).
pub fn score_chain(ledger: &Ledger, chain: &mut Chain, policy: &dyn WeightPolicy) {
    let mut s: u64 = 0;
    for h in &chain.hashes {
        if let Some(e) = ledger.get_event(h) {
            s = s.saturating_add(policy.weight_event(e));
        }
    }
    chain.score = s;
}

/// Sybil policy: Latest-per-author unit weighting.
/// Only the most recent event per author contributes 1 (scan tip->genesis; first hit wins).
pub fn score_chain_latest_per_author_unit(ledger: &Ledger, chain: &mut Chain) {
    let mut seen: HashSet<PublicKey> = HashSet::new();
    let mut s: u64 = 0;

    // chain.hashes stored genesis->tip; iterate tip->genesis
    for h in chain.hashes.iter().rev() {
        if let Some(e) = ledger.get_event(h) && seen.insert(e.author) {
            s = s.saturating_add(1);
        }
    }

    chain.score = s;
}

/// Select the preferred tip from the ledger tips set.
/// Tie-breaker: lexicographically smallest tip hash on equal scores.
pub fn select_preferred_tip(
    ledger: &Ledger,
    policy: &dyn WeightPolicy,
    max_steps: usize,
) -> Option<(Hash, Chain)> {
    let tips = ledger.get_tips();
    if tips.is_empty() {
        return None;
    }

    let mut best_tip: Option<Hash> = None;
    let mut best_chain: Option<Chain> = None;

    for tip in tips.iter() {
        let mut c = build_chain_from_tip(ledger, tip, max_steps);
        score_chain(ledger, &mut c, policy);

        match (&best_tip, &best_chain) {
            (None, None) => {
                best_tip = Some(*tip);
                best_chain = Some(c);
            }
            (Some(bt), Some(bc)) => {
                if c.score > bc.score || (c.score == bc.score && tip < bt) {
                    best_tip = Some(*tip);
                    best_chain = Some(c);
                }
            }
            _ => unreachable!("best_tip and best_chain must move together"),
        }
    }

    Some((best_tip.unwrap(), best_chain.unwrap()))
}

/// Select preferred tip with a policy kind.
/// Returns (tip, score). This is the FFI-facing entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalPolicyKind {
    Unit,
    LatestPerAuthorUnit,
    /// Sybil overlay requires state + tick; omitted from the stateless FFI call.
    #[allow(unused)]
    LatestPerAuthorSybil,
}

pub fn select_preferred_tip_score(
    ledger: &Ledger,
    policy: LocalPolicyKind,
    max_steps: usize,
) -> Option<(Hash, u64)> {
    let tips = ledger.get_tips();
    if tips.is_empty() {
        return None;
    }

    let mut best_tip: Option<Hash> = None;
    let mut best_score: u64 = 0;

    for tip in tips.iter() {
        let mut c = build_chain_from_tip(ledger, tip, max_steps);

        match policy {
            LocalPolicyKind::Unit => score_chain(ledger, &mut c, &UnitWeight),
            LocalPolicyKind::LatestPerAuthorUnit => {
                score_chain_latest_per_author_unit(ledger, &mut c)
            }
            LocalPolicyKind::LatestPerAuthorSybil => {
                // Stateless call lacks overlay state; use select_preferred_tip_score_sybil instead.
                c.score = 0;
            }
        }

        match best_tip {
            None => {
                best_tip = Some(*tip);
                best_score = c.score;
            }
            Some(bt) => {
                if c.score > best_score || (c.score == best_score && tip < &bt) {
                    best_tip = Some(*tip);
                    best_score = c.score;
                }
            }
        }
    }

    best_tip.map(|t| (t, best_score))
}

// ------------------------
// Sybil overlay: warm-up + equivocation quarantine + economic penalties
// ------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EquivocationPolicy {
    Quarantine,
    Slash,
}

#[derive(Clone, Debug)]
pub struct SybilConfig {
    pub warmup_ticks: u64,
    pub quarantine_ticks: u64,
    pub policy: EquivocationPolicy,
    pub fixed_point_scale: u64,
    pub max_link_walk: usize,
    pub slash_percent: u64, // Percentage of weight to slash for equivocation (0-100)
}

impl Default for SybilConfig {
    fn default() -> Self {
        Self {
            warmup_ticks: 8,
            quarantine_ticks: 16,
            policy: EquivocationPolicy::Quarantine,
            fixed_point_scale: 1000,
            max_link_walk: 4096,
            slash_percent: 5, // 5% economic penalty
        }
    }
}

#[derive(Clone, Debug)]
struct AuthorState {
    first_seen_tick: u64,
    seen_by: HashSet<u32>,
    last_tip: Option<Hash>,
    quarantined_until: u64,
    slashed_weight: u64, // Cumulative slashed amount (fixed-point)
}

#[derive(Clone, Debug)]
pub struct TraceRow {
    pub prev_hash: Hash,
    pub author: PublicKey,
    pub timestamp: u64,
    pub payload_hash: Hash,
    pub signature: Signature,
    pub parent_present: bool,
    pub ancestor_check: bool,
    pub quarantined_until_before: u64,
    pub quarantined_until_after: u64,
    pub merkle_root: Option<Hash>,
    pub preferred_tip: Option<Hash>,
    pub author_weight_fp: u64,
}

#[derive(Clone, Debug, Default)]
pub struct TraceRecorder {
    rows: Vec<TraceRow>,
}

impl TraceRecorder {
    pub fn new() -> Self {
        Self { rows: Vec::new() }
    }

    pub fn push(&mut self, row: TraceRow) {
        self.rows.push(row);
    }

    pub fn clear(&mut self) {
        self.rows.clear();
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    pub fn rows(&self) -> &[TraceRow] {
        &self.rows
    }
}

impl AuthorState {
    fn new(first_seen_tick: u64) -> Self {
        Self {
            first_seen_tick,
            seen_by: HashSet::new(),
            last_tip: None,
            quarantined_until: 0,
            slashed_weight: 0,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SybilOverlay {
    pub(crate) cfg: SybilConfig,
    authors: HashMap<PublicKey, AuthorState>,
    trace_recorder: Option<*mut TraceRecorder>,
}

impl SybilOverlay {
    pub fn new(cfg: SybilConfig) -> Self {
        Self {
            cfg,
            authors: HashMap::new(),
            trace_recorder: None,
        }
    }

    pub fn attach_trace_recorder(&mut self, recorder: Option<*mut TraceRecorder>) {
        self.trace_recorder = recorder;
    }

    pub fn config(&self) -> &SybilConfig {
        &self.cfg
    }

    pub fn observe_event(
        &mut self,
        ledger: &Ledger,
        tick: u64,
        observer_node: u32,
        ev: &Event,
        event_hash: Hash,
    ) {
        let author = ev.author;
        let tip = event_hash;

        let quarantine_ticks = self.cfg.quarantine_ticks;

        let st = self
            .authors
            .entry(author)
            .or_insert_with(|| AuthorState::new(tick));

        let quarantine_before = st.quarantined_until;
        st.seen_by.insert(observer_node);

        let mut ancestor_linked = true;
        if let Some(prev) = st.last_tip && prev != tip {
            let linked = is_ancestor_by_walk(ledger, prev, tip, self.cfg.max_link_walk)
                || is_ancestor_by_walk(ledger, tip, prev, self.cfg.max_link_walk);
            ancestor_linked = linked;

            if !linked {
                // Fork sibling detected (divergent children of the same author): trigger quarantine + slashing.
                Self::apply_quarantine_and_slash(st, tick, quarantine_ticks, &self.cfg);
            }
        }

        st.last_tip = Some(tip);
        let quarantine_after = st.quarantined_until;

        // Optional trace recording for proof systems (deterministic; does not mutate state).
        if let Some(ptr) = self.trace_recorder {
            let parent_present = ev.prev_hash == crate::event::ZERO_HASH
                || ledger.get_event(&ev.prev_hash).is_some();
            let author_weight_fp = self.author_weight_fp(tick, author);
            // Borrow of self is gone here; safe to call preference.
            let pref = select_preferred_tip_score_sybil(ledger, self, tick, self.cfg.max_link_walk);
            unsafe {
                let merkle_root = ledger.merkle_root();
                let rec = &mut *ptr;
                rec.push(TraceRow {
                    prev_hash: ev.prev_hash,
                    author,
                    timestamp: ev.timestamp,
                    payload_hash: ev.payload_hash,
                    signature: ev.signature,
                    parent_present,
                    ancestor_check: ancestor_linked,
                    quarantined_until_before: quarantine_before,
                    quarantined_until_after: quarantine_after,
                    merkle_root,
                    preferred_tip: pref.map(|p| p.0),
                    author_weight_fp,
                });
            }
        }
    }

    pub fn author_weight(&self, tick: u64, author: PublicKey) -> f64 {
        let Some(st) = self.authors.get(&author) else {
            return 0.0;
        };

        if tick < st.quarantined_until {
            return 0.0;
        }

        let warm = self.author_warmup(tick, st);
        let base_weight = warm.clamp(0.0, 1.0);
        
        // Apply economic penalty from slashing
        let slashed_fp = st.slashed_weight as f64;
        let scale = self.cfg.fixed_point_scale as f64;
        let penalty = (slashed_fp / scale).clamp(0.0, 1.0);
        
        // Reduce weight by slashed amount
        (base_weight * (1.0 - penalty)).clamp(0.0, 1.0)
    }

    pub fn author_weight_fp(&self, tick: u64, author: PublicKey) -> u64 {
        let w = self.author_weight(tick, author);
        ((w * self.cfg.fixed_point_scale as f64).round() as i64)
            .clamp(0, self.cfg.fixed_point_scale as i64) as u64
    }

    #[allow(dead_code)]
    fn apply_quarantine(st: &mut AuthorState, tick: u64, quarantine_ticks: u64) {
        let until = tick.saturating_add(quarantine_ticks);
        st.quarantined_until = st.quarantined_until.max(until);
    }

    fn apply_quarantine_and_slash(st: &mut AuthorState, tick: u64, quarantine_ticks: u64, cfg: &SybilConfig) {
        // Apply quarantine
        let until = tick.saturating_add(quarantine_ticks);
        st.quarantined_until = st.quarantined_until.max(until);
        
        // Apply economic slash if configured
        if cfg.policy == EquivocationPolicy::Slash {
            let slash_amount = (cfg.fixed_point_scale * cfg.slash_percent) / 100;
            st.slashed_weight = st.slashed_weight.saturating_add(slash_amount);
            // Cap at fixed_point_scale to prevent overflow and ensure penalty stays at 100%
            st.slashed_weight = st.slashed_weight.min(cfg.fixed_point_scale);
        }
    }

    fn author_warmup(&self, tick: u64, st: &AuthorState) -> f64 {
        let age = tick.saturating_sub(st.first_seen_tick);
        let t = self.cfg.warmup_ticks.max(1) as f64;

        let age_term = (age as f64 / t).clamp(0.0, 1.0);

        let seen = st.seen_by.len() as f64;
        let seen_term = if seen <= 0.0 {
            0.0
        } else {
            (seen.ln_1p() / (8.0_f64).ln_1p()).clamp(0.0, 1.0)
        };

        (0.65 * age_term + 0.35 * seen_term).clamp(0.0, 1.0)
    }
}

fn is_ancestor_by_walk(
    ledger: &Ledger,
    ancestor: Hash,
    mut descendant: Hash,
    max_steps: usize,
) -> bool {
    if ancestor == descendant {
        return true;
    }
    for _ in 0..max_steps {
        let Some(e) = ledger.get_event(&descendant) else {
            return false;
        };
        if e.prev_hash == ancestor {
            return true;
        }
        if e.prev_hash == descendant {
            return false;
        }
        descendant = e.prev_hash;
        if descendant == ancestor {
            return true;
        }
    }
    false
}

pub fn score_chain_latest_per_author_sybil_fp(
    ledger: &Ledger,
    chain: &mut Chain,
    overlay: &SybilOverlay,
    tick: u64,
) {
    let mut seen: HashSet<PublicKey> = HashSet::new();
    let mut s_fp: u64 = 0;

    for h in chain.hashes.iter().rev() {
        if let Some(e) = ledger.get_event(h) && seen.insert(e.author) {
            s_fp = s_fp.saturating_add(overlay.author_weight_fp(tick, e.author));
        }
    }

    chain.score = s_fp;
}

pub fn select_preferred_tip_score_sybil(
    ledger: &Ledger,
    overlay: &SybilOverlay,
    tick: u64,
    max_steps: usize,
) -> Option<(Hash, u64)> {
    let tips = ledger.get_tips();
    if tips.is_empty() {
        return None;
    }

    let mut best_tip: Option<Hash> = None;
    let mut best_score: u64 = 0;

    for tip in tips.iter() {
        let mut c = build_chain_from_tip(ledger, tip, max_steps);
        score_chain_latest_per_author_sybil_fp(ledger, &mut c, overlay, tick);

        match best_tip {
            None => {
                best_tip = Some(*tip);
                best_score = c.score;
            }
            Some(bt) => {
                if c.score > best_score || (c.score == best_score && tip < &bt) {
                    best_tip = Some(*tip);
                    best_score = c.score;
                }
            }
        }
    }

    best_tip.map(|t| (t, best_score))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Event;
    use crate::event::ZERO_HASH;
    use crate::ledger::Ledger;
    use crate::validation::{ValidationContext, validate_event};

    #[test]
    fn latest_per_author_unit_basic() {
        // Smoke: ensure the enum exists; heavy integration lives in sims.
        let _ = LocalPolicyKind::LatestPerAuthorUnit;
    }

    #[test]
    fn sybil_overlay_detects_equivocation_and_zeroes_weight() {
        let mut ledger = Ledger::new();
        let mut overlay = SybilOverlay::new(SybilConfig::default());
        let secret: [u8; 32] = [0x42; 32];
        let secret_key = ed25519_dalek::SecretKey::from_bytes(&secret).unwrap();
        let public_key: ed25519_dalek::PublicKey = (&secret_key).into();
        let author: PublicKey = public_key.to_bytes();

        let mut vctx = ValidationContext::new();

        let ev1 = {
            let mut e = Event::new(ZERO_HASH, author, 1, [0x01; 32], [0u8; 64]);
            e.signature = crate::validation::compute_signature_with_secret(&e, &secret);
            e
        };
        validate_event(&ev1, &mut vctx).expect("ev1 valid");
        let h1 = ledger.try_add_event(ev1.clone()).expect("add ev1");
        overlay.observe_event(&ledger, 10, 0, &ev1, h1);

        let ev2 = {
            let mut e = Event::new(ZERO_HASH, author, 2, [0x02; 32], [0u8; 64]);
            e.signature = crate::validation::compute_signature_with_secret(&e, &secret);
            e
        };
        validate_event(&ev2, &mut vctx).expect("ev2 valid");
        let h2 = ledger.try_add_event(ev2.clone()).expect("add ev2");
        overlay.observe_event(&ledger, 10, 0, &ev2, h2);

        assert_ne!(h1, h2, "distinct forks must hash differently");
        assert_eq!(
            overlay.author_weight_fp(11, author),
            0,
            "equivocating author should be quarantined"
        );

        let pref = select_preferred_tip_score_sybil(&ledger, &overlay, 11, 8).expect("tip exists");
        assert_eq!(pref.1, 0, "quarantined tips should have zero weight");
        assert!(
            pref.0 == h1 || pref.0 == h2,
            "preferred tip should be one of the equivocator forks"
        );
    }
}
