# Contributing to DVEL

Thank you for your interest in contributing to DVEL! As an open-source project, we welcome contributions of all kinds, including bug reports, documentation improvements, feature requests, and code contributions.

Please review the following guidelines before you start contributing.

---

## Getting Started

### 1. Prerequisite Installations
Ensure you have the following system dependencies installed:
* **Rust compiler**: Installation via `rustup` is recommended. DVEL is tested with both `stable` and `nightly` channels.
* **CMake & C++ compiler**: Standard C++17 compiler (GCC, Clang, or MSVC) and CMake 3.15+ are required for FFI benchmarks and simulation targets.
* **Python 3.8+**: Used for running cluster orchestration and secure storage utility tools.

### 2. Set Up a Local Test Network
To spin up a local 4-node mTLS BFT cluster to test your changes:
```bash
# Clean database state and logs
python scripts/run_local_cluster.py clean

# Spawn 4 local BFT validator nodes in the background
python scripts/run_local_cluster.py start

# Verify cluster height and consensus state
python scripts/run_local_cluster.py status
```

---

## Code Guidelines

### Rust Core (`rust-core`)
* Run `cargo fmt` to automatically format your changes before submitting.
* Ensure all code compiles cleanly with no clippy warnings:
  ```bash
  cargo clippy --features bft,parallel --all-targets -- -D warnings
  ```
* Write unit/integration tests for any new features or protocol variants. All tests should pass:
  ```bash
  cargo test --features bft,parallel
  ```

### Python Utilities (`scripts`)
* Follow standard PEP 8 naming conventions.
* Avoid adding heavy third-party dependencies to keep scripts portable and easy to run in diverse environments.

### FFI & C++ Simulations (`cpp-sim`, `include`)
* Maintain deterministic event processing rules inside DAG linking logic.
* Ensure FFI declarations in `include/dvel_ffi.h` match the ABI layout precisely.

---

## Submitting Changes

1. **Fork the Repository**: Create your own fork and clone it to your local environment.
2. **Create a Topic Branch**: Use a descriptive branch name (e.g. `feature/snapshot-pruning` or `bugfix/signature-validation`).
3. **Commit Your Work**: Make precise, atomic commits with clear descriptions.
4. **Push & Open a Pull Request (PR)**:
   * Keep your PR focused on solving a single issue or introducing one cohesive feature.
   * Provide a clear summary of what you implemented and how you verified/tested it.

---

## Contribution Ideas
If you are looking for somewhere to start, here are some high-value roadmap tasks:
* **State Snapshot Pruning**: Implement automated database pruning in `rust-core/src/bft/storage.rs` to limit disk space utilization.
* **Web UI Block Explorer**: Build a lightweight web-based dashboard utilizing the BFT HTTP API to render DAG paths and validator telemetry.
* **Firmware Wi-Fi Telemetry**: Enhance the ESP32 TFT firmware in `dvel_observer/` to perform direct WebSocket/HTTP connection pooling to BFT nodes.
