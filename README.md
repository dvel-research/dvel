# DVEL Reference (v0.1.3)

Deterministic, in-memory event ledger with staking, slashing, and hybrid threading. Exposed over C ABI for C++ simulations. Audit-first design (traceable hashes/Merkle roots).

## v0.1.3 changes
- **Attack resistance**: Comprehensive security validation suite (4 attack scenarios)
  - Eclipse, 51% Byzantine, Sybil flood, Network partition - ALL RESISTED
- **Adaptive recovery**: Dynamic thresholds for partition healing (90% of majority size)
- **Stake-weighted consensus**: All simulations use `preferred_tip()` for proper tip selection
- **Security hardening**: Validated cryptographic signatures, timestamp monotonicity, equivocation quarantine

## v0.1.2 changes
- Hybrid threading model: parallel signature verification with deterministic state application
- Performance: 2-4x throughput improvement on multi-core systems (compile with `--features parallel`)
- Maintains determinism: validation parallelized, ledger application single-threaded

## v0.1.1 changes
- Validator staking (configurable per-validator)
- Automatic double-sign detection and slashing (5% penalty default)
- Jail mechanism (1000 blocks default)
- Economic penalties in SybilOverlay

See `docs/staking_and_slashing.md` for slashing implementation.

## What it does
- **Events**: single-parent DAG with hash identity `H = SHA256(C(event) || signature)`, where `C` omits the signature slot.
- **Ledger**: linkage-aware insert (rejects duplicates/missing parents), tips tracking, Merkle root over all event hashes.
- **Validation**: protocol version, ed25519 signature, bounded timestamp skew (monotonic within a per-author context).
- **Sybil overlay**: latest-per-author weights plus quarantine + economic slashing on equivocation.
- **BFT Consensus**: Tendermint-style with staking, automatic slashing, and jail mechanism.
- **Storage helper**: chunk/sign/verify files, compute manifest hash and chunk Merkle root for anchoring/audit.

## Build & run
```bash
# Rust core tests (includes FFI/storage integration)
cargo test --release -p rust_core

# With parallel verification (hybrid threading)
cargo test --release -p rust_core --features parallel

# BFT node with parallel validation
cargo build --release --features bft,parallel

# Benchmark (C++ calling FFI)
cmake -S benchmarks -B benchmarks/build
cmake --build benchmarks/build
./benchmarks/build/benchmark

# BFT throughput benchmark (Rust, tests parallel validation)
cd rust-core
cargo bench --bench bft_throughput --features bft              # single-threaded: ~12.9k events/sec
cargo bench --bench bft_throughput --features bft,parallel     # parallel: ~25.9k events/sec (2x speedup)

# Simulator executables (C++ calling FFI)
cmake -S cpp-sim -B cpp-sim/build
cmake --build cpp-sim/build
./cpp-sim/build/sim_baseline   # see also sim_scenario, sim_scheduler, sim_metrics, sim_sybil

# Government ledger (production, configurable nodes)
./cpp-sim/build/gov_ledger --nodes 38 --ticks 100 --audit

# Attack scenarios (experimental/research)
./cpp-sim/build/sim_attack_eclipse        # Test eclipse attack resistance
./cpp-sim/build/sim_attack_51percent      # Test BFT threshold (30% Byzantine)
./cpp-sim/build/sim_attack_sybil_flood --honest 5 --sybil 10  # Test sybil resistance
./cpp-sim/build/sim_attack_partition      # Test partition recovery (WARNING: finds vulnerability)

# Full smoke (cargo tests + all C++ binaries)
./scripts/smoke.sh

# Minimal FFI example (C++)
cmake -S examples -B examples/build
cmake --build examples/build
./examples/build/ffi_minimal

# Permissioned BFT node (experimental)
cargo run --release --features bft --bin dvel-bft-node \
  --genesis /path/to/genesis.json \
  --key-hex <32-byte-secret-hex> \
  --listen 127.0.0.1:9001 \
  --client 127.0.0.1:7001 \
  --data-dir /path/to/node-data \
  --tls-cert /path/to/node.crt \
  --tls-key /path/to/node.key
```
If `transport.tls_enabled` is true in `genesis.json`, each validator must include
`tls_cert_hex` (DER hex); the cert must include the listen host in SAN (IP or DNS) and
should be self-signed CA or chain to a private CA used as a trust anchor.
You can generate a self-signed cert with `openssl`:
`./scripts/gen_tls_selfsigned.sh /path/to/out 127.0.0.1 node1`
If `--data-dir` is omitted, the node stores snapshots under `data/<node_id_hex>`.
Snapshots are stored as `bft_snapshot.json` inside the data directory.

## FFI surface
Header: `include/dvel_ffi.h` (see `docs/ffi_reference.md` for details).
- Ledger: `dvel_ledger_link_event`, `dvel_ledger_get_event`, `dvel_ledger_get_tips`, `dvel_ledger_merkle_root`, `dvel_hash_event_struct`.
- Validation/keys: `dvel_validate_event`, `dvel_sign_event`, `dvel_derive_pubkey_from_secret`, `dvel_set_max_backward_skew`.
- Sybil/trace: `dvel_sybil_overlay_*`, `dvel_select_preferred_tip_sybil`, `dvel_trace_recorder_*`.
- Storage: `dvel_storage_chunk_file`, `dvel_storage_download`, `dvel_storage_manifest_hash`, `dvel_storage_chunk_merkle_root`, `dvel_storage_last_error`.

## CI checklist (recommended)
- `cargo fmt` and `cargo clippy --release -- -D warnings`
- `cargo test --release -p rust_core`
- `./scripts/smoke.sh`

## BFT design notes
See `docs/bft_design.md` for protocol parameters, genesis format, and API usage.

## Design sketch (why it’s deterministic)
- No wall-clock reads: time is injected (`timestamp`/`tick`).
- No randomness: hashes/signatures deterministic; sha256 + ed25519.
- No shared mutable globals: ledger/overlay are caller-owned handles.
- Merkle root over sorted event hashes gives a stable commitment for audit.

## Government transparency deployment
**gov_ledger**: production-ready configurable system for distributed government ledger.

Usage:
```bash
./cpp-sim/build/gov_ledger --nodes 38 --ticks 100    # baseline (Indonesia provinces)
./cpp-sim/build/gov_ledger --nodes 40 --ticks 100    # scales with province changes
./cpp-sim/build/gov_ledger --audit                   # full transparency mode
```

Anti-corruption guarantees:
- Full mesh topology: every node validates every transaction (no single point of failure)
- Immutable ledger: distributed across all nodes, cannot hide/modify transactions
- Consensus requirement: 90%+ agreement needed (33%+ nodes required to attack)
- Public verification: audit trail accessible for transparency

Results (38 nodes): 100% consensus, high availability confirmed.

Performance (BFT block processing):
- Single-threaded: 12.9k events/sec
- Parallel (rayon): 25.9k events/sec
- Speedup: 2.01x (verified on 4-core system)
- Test: `cd rust-core && cargo bench --bench bft_throughput --features bft,parallel`

Test files (`sim_*.cpp`) for protocol validation; `gov_ledger.cpp` for production deployment.
