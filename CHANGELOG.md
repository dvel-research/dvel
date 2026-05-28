# DVEL Protocol Changelog

All notable changes to the Deterministic Event Ledger (DVEL) protocol suite are documented in this file.

---

## [v0.1.4] — Secure Archiving, MMR Verification & Hardware Hardening
### Added
*   **Secure Archival Anchoring & MMR Proof Audits**: Implemented a comprehensive file archival script (`dvel_archive.py`) featuring binary file chunking, Ed25519 signed manifest generation, and logarithmic **Merkle Mountain Range (MMR)** dynamic inclusion proof verification.
*   **Documentation Consolidation**: Consolidated all fragmented documentation files under `docs/` and `docs/paper/` into a single, comprehensive, academic-grade **[DVEL Technical Paper](docs/dvel_technical_paper.md)**.
*   **ESP32 Firmware Resiliency Upgrades**:
    *   *Server Reset Recovery*: Automatically aligns historical block height if the BFT server resets (`current_height < last_height`), preventing observer desynchronization.
    *   *Merkle Root Overwrite Protection*: Replaced standard string checks with an 8-character `strncmp` filter to prevent BFT empty-block 64-zero hashes from overwriting valid manifest Merkle Roots on the LCD screen.
*   **Consensus Deadlock Resolution**: Documented operations to wipe BFT snapshot database states and re-initialize the ledger from Genesis Height 0, solving infinite prevoting loops caused by mismatched locked block hashes.

---

## [v0.1.3] — Attack Resistance & Security Hardening
### Added
*   **Attack Scenario Suite**: Implemented 4 experimental C++ attack simulation executables under `cpp-sim/executables/attacks/` for deep protocol vulnerability research:
    *   `sim_attack_eclipse`: Eclipse attack analysis. Honey nodes maintain isolation recovery.
    *   `sim_attack_51percent`: 51% Byzantine safety boundaries audit.
    *   `sim_attack_sybil_flood`: Sybil resistance limits mapping.
    *   `sim_attack_partition`: Minority isolation and adaptive healing validation.
*   **Adaptive Partition Recovery**: Suppresses isolated minority splits until majority consensus achieves dynamic healing thresholds (set to 90% of majority network size).
*   **Stake-Weighted Consensus Rules**: Embedded `preferred_tip()` inside all simulator scenarios to transition voting weight rules from raw node counts to active validator stakes.

### Security & Hardening
*   Validated cryptographic signature constraints inside BFT pipelines.
*   Enforced event timestamp monotonicity per-author context.
*   Hardened equivocation quarantine overlay heuristics.

---

## [v0.1.2] — Parallel Verification & Hybrid Threading
### Added
*   **Parallel Signature Verification**: Introduced parallel cryptographic validation using Rayon (`parallel` feature flag), doubling validation speed.
*   **Hybrid Threading Model**: Computes intense cryptographic signature verifications concurrently across multiple CPU cores while keeping state application single-threaded to preserve 100% execution determinism.
*   **Performance Benchmark Suite**: Validated throughput speedups:
    *   *Single-threaded baseline*: ~12.9k events/second.
    *   *Parallel (Rayon) enabled*: ~25.9k events/second (a **2.01x speedup** on 4-core architectures).

---

## [v0.1.1] — Staking, Slashing, & Government Ledger
### Added
*   **Validator Staking**: Introduced stake tracking in `genesis.json` with a standard validator weight of 1,000,000 units.
*   **Automated Slashing & Jailing**: Implemented active double-signing detection inside BFT consensus, penalizing rogue validators with a **5% stake deduction** and **1000-block jail sentence**.
*   **Staking Integration**: Integrated slashing states directly into consensus logic with automated persistence across state transition snapshots (`bft_snapshot.json`).
*   **Government Ledger Simulator (`gov_ledger`)**: A production-ready benchmark model simulating distributed governance transparency across 38 nodes (Indonesia's provinces), confirming 100% consensus availability.

---

## [v0.1.0] — Reference Prototype (Deterministic C-FFI Core)
### Added
*   **Core Ledger**: Developed linkage-aware insertion algorithms, tip-tracking systems, and deterministic Merkle commitments.
*   **Validation Core**: Implemented Ed25519 signature checks, protocol version gates, and monotonic timestamp skew boundaries.
*   **Sybil Quarantine Overlay**: Developed divergent sibling quarantine penalties.
*   **Storage FFI Engine**: Created file slicing (chunking), Ed25519 manifest signing/verification, and logarithmic MMR inclusion proof endpoints.
*   **C ABI (`dvel_ffi.h`)**: Exposed all Rust ledger, validation, overlay, and secure storage capabilities via a standard C FFI C-ABI interface for C++ integrations.

