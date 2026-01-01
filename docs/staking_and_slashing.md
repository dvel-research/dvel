# Slashing Implementation

## Design

Validator stake tracked per node. Double-sign detection automatic via vote history. Slashing applied immediately on evidence.

## Slashing conditions

### Double-sign
Same validator signs two votes at identical (height, round, type) with different block hashes.
Default penalty: 5% of current stake.

### Invalid proposal
Proposal fails validation (reserved; not yet enforced).
Default penalty: 1%.

## Stake mechanics

```
effective_stake = is_jailed ? 0 : current_stake
current_stake = original_stake - sum(slashed_amounts)
```

Jailed validators: zero effective stake until `current_height >= jail_until_height`.

## Genesis format

```json
{
  "chain_id": "dvel-secure",
  "validators": [
    {
      "pubkey_hex": "a1b2c3...",
      "address": "127.0.0.1:9001",
      "power": 1,
      "stake": 10000000
    }
  ],
  "consensus": {
    "slashing": {
      "enabled": true,
      "double_sign_percent": 5,
      "invalid_proposal_percent": 1,
      "jail_duration_blocks": 1000
    }
  }
}
```

## Implementation

### SlashingState

Core state tracker:
```rust
pub struct SlashingState {
    stakes: HashMap<NodeId, u64>,
    original_stakes: HashMap<NodeId, u64>,
    slashed: Vec<SlashingRecord>,
    jailed: HashMap<NodeId, u64>,
    votes_by_validator: HashMap<(u64, u64, VoteType), HashMap<NodeId, SignedVote>>,
}
```

### Vote recording

```rust
pub fn record_vote(
    &mut self,
    vote: &SignedVote,
    config: &SlashingConfig,
    _current_height: u64,
) -> Option<SlashingEvidence>
```

Returns `Some(SlashingEvidence::DoubleSign)` if conflicting vote detected. Vote history pruned to last 100 heights.

### Slashing execution

```rust
pub fn slash(
    &mut self,
    evidence: SlashingEvidence,
    config: &SlashingConfig,
    current_height: u64,
) -> Result<SlashingRecord, String>
```

1. Calculate `slash_amount = (current_stake * slash_percent) / 100`
2. Update `current_stake -= slash_amount`
3. Set `jail_until = current_height + jail_duration_blocks`
4. Append `SlashingRecord` to history

## BFT integration

In `Node::handle_vote`:
```rust
if let Some(evidence) = self.slashing_state.record_vote(&signed, &config, height) {
    let record = self.slashing_state.slash(evidence, &config, height)?;
    // Log: "Validator slashed: {} removed, jailed until {}"
    // Update snapshot with slashing_state
}
```

## SybilOverlay integration

Non-BFT overlay supports economic penalties via `SybilConfig::slash_percent`. When `policy = EquivocationPolicy::Slash`, equivocation triggers weight reduction:

```rust
st.slashed_weight += (cfg.fixed_point_scale * cfg.slash_percent) / 100;
```

Weight calculation includes penalty:
```rust
let penalty = (st.slashed_weight as f64) / (cfg.fixed_point_scale as f64);
base_weight * (1.0 - penalty)
```

## Defaults

```rust
SlashingConfig::default() {
    enabled: true,
    double_sign_percent: 5,
    invalid_proposal_percent: 1,
    jail_duration_blocks: 1000,
}

ValidatorConfig::default_stake() {
    1_000_000
}
```

## Testing

```bash
cargo test --features bft slashing
```

Tests: double-sign detection, stake reduction, jail enforcement, effective stake calculation.
