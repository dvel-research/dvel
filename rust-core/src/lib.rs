// Reference skeleton: deterministic, in-memory, audit-first.

pub mod event;
pub mod ffi;
pub mod ledger;
pub mod scoring;
pub mod storage;
#[cfg(feature = "trace_check")]
pub mod trace_check;
#[cfg(feature = "bft")]
pub mod bft;
pub mod validation;

// Global constants for determinism
pub const PROTOCOL_VERSION: u8 = 1;

// No randomness or wall clock access; time is injected explicitly.

/*
Intentionally avoids:
- async
- threads
- global mutable state
- external IO
*/
