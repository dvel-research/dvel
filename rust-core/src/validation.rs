// Validation: deterministic, in-memory; enforces version, ed25519 signature, and bounded timestamp skew.
// Crypto here is reference-grade only (not hardened).
use crate::event::{Event, Signature};
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature as DalekSignature, Signer, Verifier};
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, PartialEq)]
pub enum ValidationError {
    InvalidVersion,
    InvalidSignature,
    TimestampNonMonotonic,
}

#[derive(Clone)]
pub struct ValidationContext {
    pub last_timestamp: u64,
}

// Runtime-configurable backward skew bound (default 4).
static MAX_BACKWARD_SKEW: AtomicU64 = AtomicU64::new(4);

pub fn set_max_backward_skew(skew: u64) {
    // Clamp to >=1 to avoid rejecting equal timestamps.
    let s = skew.max(1);
    MAX_BACKWARD_SKEW.store(s, Ordering::Relaxed);
}

pub fn compute_signature_with_secret(event: &Event, secret: &[u8; 32]) -> Signature {
    let secret = SecretKey::from_bytes(secret).expect("secret key must be 32 bytes");
    let public: PublicKey = (&secret).into();
    let kp = Keypair { secret, public };
    let sig = kp.sign(&event.canonical_bytes());
    sig.to_bytes()
}

impl ValidationContext {
    pub fn new() -> Self {
        ValidationContext { last_timestamp: 0 }
    }
}

impl Default for ValidationContext {
    fn default() -> Self {
        Self::new()
    }
}

fn to_verifying_key(pk: &[u8; 32]) -> Option<PublicKey> {
    PublicKey::from_bytes(pk).ok()
}

fn to_signature(sig: &[u8; 64]) -> Option<DalekSignature> {
    DalekSignature::from_bytes(sig).ok()
}

/// Stateful validator:
/// - updates ctx.last_timestamp
/// - caller must present events in ledger order
pub fn validate_event(event: &Event, ctx: &mut ValidationContext) -> Result<(), ValidationError> {
    // --- Version check (hard rule) ---
    if event.version != crate::PROTOCOL_VERSION {
        return Err(ValidationError::InvalidVersion);
    }

    // --- Signature check (ed25519) ---
    let vk = to_verifying_key(&event.author).ok_or(ValidationError::InvalidSignature)?;
    let sig = to_signature(&event.signature).ok_or(ValidationError::InvalidSignature)?;
    vk.verify(&event.canonical_bytes(), &sig)
        .map_err(|_| ValidationError::InvalidSignature)?;

    // --- Timestamp monotonicity with bounded skew ---
    // Permit small backward steps; reject large rewinds.
    let skew = MAX_BACKWARD_SKEW.load(Ordering::Relaxed);
    if event.timestamp.saturating_add(skew) < ctx.last_timestamp {
        return Err(ValidationError::TimestampNonMonotonic);
    }
    // Keep monotone max for forward progress
    if event.timestamp > ctx.last_timestamp {
        ctx.last_timestamp = event.timestamp;
    }

    Ok(())
}
