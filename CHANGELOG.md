# Changelog

## Unreleased
- BFT: permissioned Tendermint-style prototype with HTTP client API and round-based finality checks.
- BFT security: optional mTLS transport with pinned validator certs in genesis and CLI wiring for cert/key files.
- BFT persistence: snapshot storage for blocks/tx index with replay on restart; `--data-dir` CLI flag and default `data/<node_id_hex>`.
- Tooling: multi-node BFT integration test and TLS helper scripts for self-signed certs and cert hex.
- Docs: expanded BFT design notes, TLS requirements, and persistence behavior.

## v0.1.0 — Reference prototype (deterministic, FFI-first)
- Ledger: linkage-aware insert, tips tracking, Merkle root over event hashes; `Default` impl added.
- Validation: ed25519 signature, protocol version, bounded timestamp skew; `Default` impl for `ValidationContext`.
- Sybil overlay: latest-per-author weighting with quarantine; trace recorder exports deterministic rows.
- Storage: chunk/sign/verify helpers, manifest/chunk Merkle roots, error reporting via `dvel_storage_last_error`.
- FFI: C ABI (`include/dvel_ffi.h`) covering ledger, validation, sybil overlay, trace, storage; error buffer helper.
- C++ integrations: benchmark + simulator binaries linked to the Rust core via shared CMake helper; minimal FFI example (`examples/ffi_minimal.cpp`).
- Tooling: smoke script runs cargo tests + C++ binaries; CI workflow runs fmt, clippy, tests, smoke.
- Docs: architecture notes, trace pipeline, FFI reference, build guide, README.
