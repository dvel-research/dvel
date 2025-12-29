# DVEL Reference (v0.1.0)

Deterministic, in-memory event ledger with a sybil-aware overlay, exposed over a C ABI for C++ simulations and tooling. This repo is a reference prototype: small surface area, no wall-clock dependencies, and an audit-first design (traceable hashes/Merkle roots).

## What it does
- **Events**: single-parent DAG with hash identity `H = SHA256(C(event) || signature)`, where `C` omits the signature slot.
- **Ledger**: linkage-aware insert (rejects duplicates/missing parents), tips tracking, Merkle root over all event hashes.
- **Validation**: protocol version, ed25519 signature, bounded timestamp skew (monotonic within a per-author context).
- **Sybil overlay**: latest-per-author weights plus quarantine on equivocation; preferred-tip selection that respects author weights.
- **Storage helper**: chunk/sign/verify files, compute manifest hash and chunk Merkle root for anchoring/audit.

## Build & run
```bash
# Rust core tests (includes FFI/storage integration)
cargo test --release -p rust_core

# Benchmark (C++ calling FFI)
cmake -S benchmarks -B benchmarks/build
cmake --build benchmarks/build
./benchmarks/build/benchmark

# Simulator executables (C++ calling FFI)
cmake -S cpp-sim -B cpp-sim/build
cmake --build cpp-sim/build
./cpp-sim/build/sim_baseline   # see also sim_scenario, sim_scheduler, sim_metrics, sim_sybil

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

## Versioning
Current version: **v0.1.0** (reference prototype; not hardened for production security).
