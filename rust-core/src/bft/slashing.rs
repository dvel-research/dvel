use crate::bft::config::SlashingConfig;
use crate::bft::types::{NodeId, SignedVote, SlashingEvidence, SlashingRecord, VoteType};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Tracks validator stakes and slashing history
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlashingState {
    /// Current stake per validator (after slashing)
    pub stakes: HashMap<NodeId, u64>,
    /// Original stake (immutable)
    pub original_stakes: HashMap<NodeId, u64>,
    /// Slashing records
    pub slashed: Vec<SlashingRecord>,
    /// Validators in jail (node_id -> release_height)
    pub jailed: HashMap<NodeId, u64>,
    /// Vote tracking for double-sign detection: (height, round, vote_type) -> (node_id -> vote)
    votes_by_validator: HashMap<(u64, u64, VoteType), HashMap<NodeId, SignedVote>>,
}

impl SlashingState {
    pub fn new(initial_stakes: HashMap<NodeId, u64>) -> Self {
        Self {
            stakes: initial_stakes.clone(),
            original_stakes: initial_stakes,
            slashed: Vec::new(),
            jailed: HashMap::new(),
            votes_by_validator: HashMap::new(),
        }
    }

    /// Check if validator is jailed at given height
    pub fn is_jailed(&self, validator_id: &NodeId, current_height: u64) -> bool {
        if let Some(&jail_until) = self.jailed.get(validator_id) {
            current_height < jail_until
        } else {
            false
        }
    }

    /// Get effective stake (returns 0 if jailed)
    pub fn effective_stake(&self, validator_id: &NodeId, current_height: u64) -> u64 {
        if self.is_jailed(validator_id, current_height) {
            return 0;
        }
        self.stakes.get(validator_id).copied().unwrap_or(0)
    }

    /// Record a vote and detect double-signing
    pub fn record_vote(
        &mut self,
        vote: &SignedVote,
        config: &SlashingConfig,
        _current_height: u64,
    ) -> Option<SlashingEvidence> {
        if !config.enabled {
            return None;
        }

        let v = &vote.vote;
        let key = (v.height, v.round, v.vote_type);
        
        let votes = self.votes_by_validator.entry(key).or_insert_with(HashMap::new);

        // Check for double-signing: same height/round/type but different block hash
        if let Some(existing) = votes.get(&v.validator_id) {
            if existing.vote.block_hash != v.block_hash {
                // Double-sign detected! Clone evidence data before mutating
                let evidence = Some(SlashingEvidence::DoubleSign {
                    validator_id: v.validator_id,
                    height: v.height,
                    round: v.round,
                    vote1: existing.clone(),
                    vote2: vote.clone(),
                });
                // Store the second vote to prevent re-detection
                votes.insert(v.validator_id, vote.clone());
                return evidence;
            }
            // Same vote as existing - ignore duplicate
        } else {
            votes.insert(v.validator_id, vote.clone());
        }

        // Clean up old votes (keep last 100 heights)
        if v.height > 100 {
            let old_height = v.height - 100;
            self.votes_by_validator.retain(|(h, _, _), _| *h > old_height);
        }

        None
    }

    /// Apply slashing for evidence
    pub fn slash(
        &mut self,
        evidence: SlashingEvidence,
        config: &SlashingConfig,
        current_height: u64,
    ) -> Result<SlashingRecord, String> {
        if !config.enabled {
            return Err("slashing disabled".into());
        }

        let (validator_id, slash_percent) = match &evidence {
            SlashingEvidence::DoubleSign { validator_id, .. } => {
                (*validator_id, config.double_sign_percent)
            }
            SlashingEvidence::InvalidProposal { validator_id, .. } => {
                (*validator_id, config.invalid_proposal_percent)
            }
        };

        let current_stake = self.stakes.get(&validator_id).copied().unwrap_or(0);
        if current_stake == 0 {
            return Err("validator already has zero stake".into());
        }

        // Calculate slashing amount (percentage of current stake)
        let slash_amount = current_stake.saturating_mul(slash_percent) / 100;
        let new_stake = current_stake.saturating_sub(slash_amount);

        // Update stake
        self.stakes.insert(validator_id, new_stake);

        // Jail validator
        let jail_until = current_height.saturating_add(config.jail_duration_blocks);
        self.jailed.insert(validator_id, jail_until);

        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let record = SlashingRecord {
            evidence,
            slashed_amount: slash_amount,
            jail_until_height: jail_until,
            timestamp_ms,
        };

        self.slashed.push(record.clone());

        Ok(record)
    }

    /// Get total slashed amount for a validator
    pub fn total_slashed(&self, validator_id: &NodeId) -> u64 {
        let original = self.original_stakes.get(validator_id).copied().unwrap_or(0);
        let current = self.stakes.get(validator_id).copied().unwrap_or(0);
        original.saturating_sub(current)
    }

    /// Get all slashing records for a validator
    pub fn slashing_history(&self, validator_id: &NodeId) -> Vec<&SlashingRecord> {
        self.slashed
            .iter()
            .filter(|r| match &r.evidence {
                SlashingEvidence::DoubleSign { validator_id: vid, .. } => vid == validator_id,
                SlashingEvidence::InvalidProposal { validator_id: vid, .. } => vid == validator_id,
            })
            .collect()
    }

    /// Unjail a validator (manual governance action or after jail period)
    pub fn unjail(&mut self, validator_id: &NodeId, current_height: u64) -> Result<(), String> {
        match self.jailed.get(validator_id) {
            Some(&jail_until) if current_height >= jail_until => {
                self.jailed.remove(validator_id);
                Ok(())
            }
            Some(&jail_until) => {
                Err(format!("validator still jailed until height {}", jail_until))
            }
            None => Err("validator not jailed".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bft::types::Vote;
    use crate::event::Hash;

    fn test_config() -> SlashingConfig {
        SlashingConfig {
            enabled: true,
            double_sign_percent: 5,
            invalid_proposal_percent: 1,
            jail_duration_blocks: 100,
        }
    }

    fn make_vote(validator_id: NodeId, height: u64, round: u64, block_hash: Hash) -> SignedVote {
        SignedVote {
            vote: Vote {
                height,
                round,
                vote_type: VoteType::Prevote,
                block_hash,
                validator_id,
            },
            signature: "test".to_string(),
        }
    }

    #[test]
    fn detect_double_sign() {
        let validator_id = [1u8; 32];
        let mut stakes = HashMap::new();
        stakes.insert(validator_id, 1_000_000);

        let mut state = SlashingState::new(stakes);
        let config = test_config();

        let vote1 = make_vote(validator_id, 10, 0, [0xAA; 32]);
        let vote2 = make_vote(validator_id, 10, 0, [0xBB; 32]); // Different block!

        // First vote - no evidence
        assert!(state.record_vote(&vote1, &config, 10).is_none());

        // Second vote with different hash - double sign!
        let evidence = state.record_vote(&vote2, &config, 10);
        assert!(evidence.is_some());
    }

    #[test]
    fn slash_reduces_stake() {
        let validator_id = [1u8; 32];
        let mut stakes = HashMap::new();
        stakes.insert(validator_id, 1_000_000);

        let mut state = SlashingState::new(stakes);
        let config = test_config();

        let evidence = SlashingEvidence::DoubleSign {
            validator_id,
            height: 10,
            round: 0,
            vote1: make_vote(validator_id, 10, 0, [0xAA; 32]),
            vote2: make_vote(validator_id, 10, 0, [0xBB; 32]),
        };

        let record = state.slash(evidence, &config, 10).unwrap();
        
        // 5% slashed from 1_000_000 = 50_000
        assert_eq!(record.slashed_amount, 50_000);
        assert_eq!(state.stakes.get(&validator_id), Some(&950_000));
        assert!(state.is_jailed(&validator_id, 10));
        assert!(!state.is_jailed(&validator_id, 111)); // After jail period
    }

    #[test]
    fn effective_stake_zero_when_jailed() {
        let validator_id = [1u8; 32];
        let mut stakes = HashMap::new();
        stakes.insert(validator_id, 1_000_000);

        let mut state = SlashingState::new(stakes);
        let config = test_config();

        let evidence = SlashingEvidence::DoubleSign {
            validator_id,
            height: 10,
            round: 0,
            vote1: make_vote(validator_id, 10, 0, [0xAA; 32]),
            vote2: make_vote(validator_id, 10, 0, [0xBB; 32]),
        };

        state.slash(evidence, &config, 10).unwrap();

        // Jailed - effective stake is 0
        assert_eq!(state.effective_stake(&validator_id, 10), 0);
        
        // After jail - effective stake restored
        assert_eq!(state.effective_stake(&validator_id, 111), 950_000);
    }
}
