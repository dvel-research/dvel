# DVEL: Byzantine Fault-Tolerant Deterministic Event Ledger (v0.1.4)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Consensus: BFT](https://img.shields.io/badge/Consensus-mTLS%20BFT-blue.svg)]()
[![Hardware: ESP32](https://img.shields.io/badge/Observer-ESP32%20FreeRTOS-green.svg)]()

DVEL is an academic-grade, high-performance **hybrid distributed ledger technology (DLT)**. It features a Directed Acyclic Graph (DAG) for real-time, asynchronous event logging and secures it via a linear, permissioned **Byzantine Fault-Tolerant (BFT) Consensus Blockchain** utilizing mutual TLS (mTLS) transport. 

This repository implements the Rust core ledger, C-ABI FFI wrapper, C++ simulator/benchmarks suite, Python secure archiving scripts, and the dual-core ESP32 TFT observer firmware.

---

## System Documentation

All architectural specifications, cryptographic parameters, authority reputation rules, and hardware configurations are consolidated in the technical paper:
> **[DVEL Technical Specification & Architecture Whitepaper](docs/dvel_technical_paper.md)**
> Read this for detailed mathematical formulas of the Merkle Mountain Range (MMR) validation, mTLS handshake specifications, and authority weight penalization and jailing conditions.

---

## Core Features

*   **Hybrid Topology**: DAG Event ingestion for zero-latency hardware logging, anchored dynamically into a Tendermint-style linear BFT blockchain.
*   **mTLS Network Transport**: Strict SubjectAltName DER validator certificate checks inside peering loops to resist Man-in-the-Middle and Eclipse attacks.
*   **Consortium Security (Authority Weight & Jailing)**: Automatic double-signing detection via vote history database, initiating an immediate 5% validator authority weight penalty and a 1000-block jail sentence.
*   **Secure Archival & Gossip replication (Chunk Sync)**: 
    *   Slices files into equal chunks and creates signed Ed25519 manifests.
    *   **Gossip Storage Engine**: Uploaded chunks are replicated across all validator nodes in the BFT cluster using the existing secure mTLS peering network.
    *   **Automatic Fallback Recovery**: If the primary validator node is offline or fails, the client dynamically queries surviving BFT validators, downloads the missing chunks, verifies SHA256 integrity, and reassembles the file seamlessly.
*   **Hardware Telemetry Observer**: Standalone ESP32 firmware utilizing dual-core FreeRTOS to poll BFT nodes over Wi-Fi and render interactive DAG graphs at 40+ FPS on TFT LCD screens.

---

## Build & Run Commands

### 1. Compile & Test Rust Core
```bash
# Run standard ledger tests (includes FFI and storage integration)
cargo test --release -p rust_core

# Run tests with parallel signature verification (hybrid threading mode)
cargo test --release -p rust_core --features parallel

# Run the BFT throughput benchmarks (Rust Rayon validation)
cd rust-core
cargo bench --bench bft_throughput --features bft              # Single-threaded
cargo bench --bench bft_throughput --features bft,parallel     # Parallel Rayon
```

### 2. Compile C++ Simulations & Benchmarks (FFI-Connected)
```bash
# Build & Run C++ baseline performance benchmarks
cmake -S benchmarks -B benchmarks/build
cmake --build benchmarks/build
./benchmarks/build/benchmark

# Build & Run C++ Multi-peer simulations (sim_baseline, sim_scheduler, sim_sybil, etc.)
cmake -S cpp-sim -B cpp-sim/build
cmake --build cpp-sim/build
./cpp-sim/build/sim_baseline
```

### 3. Launch Permissioned mTLS BFT Validator Node
```bash
cargo run --release --features bft --bin dvel-bft-node \
  --genesis /path/to/genesis.json \
  --key-hex <32-byte-secret-key-hex> \
  --listen 127.0.0.1:9001 \
  --client 127.0.0.1:7001 \
  --data-dir /path/to/node-data \
  --tls-cert /path/to/node.crt \
  --tls-key /path/to/node.key
```
> [!NOTE]
> If `transport.tls_enabled` is active in `genesis.json`, validators must present DER certificates allowlisted in genesis, with SAN matching their listen IP.

### 4. Government Ledger Transparency Simulation
The `gov_ledger` binary showcases anti-corruption, Byzantine-fault-tolerant ledger distribution at scale:
```bash
# Execute simulation with 38 Indonesian provinces
./cpp-sim/build/gov_ledger --nodes 38 --ticks 100

# Execute in full transparency audit mode
./cpp-sim/build/gov_ledger --audit
```

---

## Attack Scenarios & Research
Validate the network's resilience under adverse environments using C++ simulation executables:
```bash
# Eclipse Attack: honest node isolation resistance
./cpp-sim/build/sim_attack_eclipse

# 51% Byzantine Attack: safety limits check (30% Byzantine threshold)
./cpp-sim/build/sim_attack_51percent

# Sybil Flood Attack: proof of authority-weight-weighted resistance
./cpp-sim/build/sim_attack_sybil_flood --honest 5 --sybil 10

# Network Partition Attack: adaptive minority healing thresholds
./cpp-sim/build/sim_attack_partition
```

---

## FFI API Interface
DVEL exposes all capabilities over a standard C-ABI wrapper header at `include/dvel_ffi.h`:
*   **Ledger Interface**: `dvel_ledger_link_event()`, `dvel_ledger_merkle_root()`, `dvel_ledger_get_tips()`.
*   **Authority & Overlay**: `dvel_sybil_overlay_init()`, `dvel_select_preferred_tip_sybil()`.
*   **Storage Core FFI**: `dvel_storage_chunk_file()`, `dvel_storage_download()`, `dvel_storage_manifest_hash()`.

---

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
