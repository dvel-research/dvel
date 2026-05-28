# DVEL: A High-Throughput Hybrid Event Ledger with mTLS BFT Consensus and Secure Storage Anchoring

## Technical Specification & Architecture Whitepaper (v0.1.4)

---

### Abstract
Deterministic Event Ledger (DVEL) is a high-performance, hybrid distributed ledger technology (DLT) designed to secure real-time hardware telemetry and decentralized data archives. DVEL resolves the trade-off between the latency demands of real-time physical logging and the cryptographic finality of blockchain architectures. It achieves this by implementing a **hybrid topology**: a Directed Acyclic Graph (DAG) for asynchronous telemetry events, anchored dynamically into a linear, authenticated **BFT Consensus Blockchain** utilizing mutual TLS (mTLS) P2P transport. Additionally, DVEL integrates a cryptographic secure storage engine featuring **Logarithmic Merkle Mountain Range (MMR)** proofs for zero-sidecar integrity audits, actively verified via local Wi-Fi by resource-constrained hardware observers.

---

## 1. System Architecture: Hybrid DAG-Blockchain Topology

To meet the high-throughput requirements of hardware systems while ensuring Byzantine fault tolerance, DVEL separates the **ingestion state** (asynchronous DAG) from the **finality layer** (linear BFT blockchain).

```
 +-----------------------------------------------------------------------------------+
 |                             INGESTION STATE (DAG)                                 |
 |                                                                                   |
 |  [Peer 0 Event] -> [Peer 0 Event] ---\                                            |
 |                                       \---> [Dynamic Parent Selection]            |
 |  [Peer 1 Event] -> [Peer 1 Event] ----/     (Sybil & Quarantine Filters)          |
 |                                                                                   |
 +-----------------------------------------------------------------------------------+
                                           |
                                           v
 +-----------------------------------------------------------------------------------+
 |                            FINALITY LAYER (BFT BLOCKCHAIN)                        |
 |                                                                                   |
 |  [Block H=10] <==== [BFT Consensus Round] <==== [Proposed Block H=11]             |
 |  - Linearized Events  (Propose -> Prevote -> Precommit)                           |
 |  - Merkle Commitments                                                             |
 |                                                                                   |
 +-----------------------------------------------------------------------------------+
```

### 1.1 The Directed Acyclic Graph (DAG) Event Ledger
The basic transactional unit in DVEL is an **Event** ($E$). Events represent telemetry state changes, log entries, or archival metadata. Unlike traditional blockchains where transactions must immediately wait for a block proposer, DVEL events are structured as an active graph:

$$E = (\text{Version}, \text{Previous Hash}, \text{Author}, \text{Timestamp}, \text{Payload Hash}, \text{Signature})$$

*   `version`: 8-bit protocol version identifier.
*   `prev_hash`: 32-byte cryptographic pointer to the author's previous event, forming a sequential, non-equivocating chain per author.
*   `author`: 32-byte Ed25519 public key of the event's generator.
*   `timestamp`: 64-bit Unix timestamp (stored in little-endian format) representing event issuance.
*   `payload_hash`: 32-byte SHA256 commitment of the arbitrary data payload.
*   `signature`: 64-byte Ed25519 signature computed over the canonical representation of the event ($C(E)$) which excludes the signature slot.

The unique identity hash of an event is computed as:

$$\text{Identity Hash } (H) = \text{SHA256}(C(E) \parallel \text{signature})$$

This event structure creates an asynchronous, parallel DAG of dependencies across different authors. Event ordering is finalized when they are bundled into blocks.

### 1.2 The Linear BFT Consensus Blockchain
While events flow continuously across the network, they are anchored into a single canonical history through a linear BFT blockchain.
*   **Finalization blocks**: Bundles of finalized events, capped at a maximum of **1 MB** in size or **5,000 events** (whichever limit is hit first).
*   **Validator-Driven Ordering**: A static validator set defined at genesis processes transactions linearly. The proposer for any given round is chosen using a deterministic round-robin index:
    $$\text{Proposer Index} = (\text{Height} + \text{Round}) \pmod N$$
    where $N$ is the total number of validators in the active genesis set.

---

## 2. Permissioned BFT Consensus & mTLS Transport

DVEL consensus is built upon a high-performance, single-round-trip Tendermint-style BFT machine featuring fast finality.

```
       +------------------+
       |     PROPOSE      |  (Proposer sends proposed block)
       +------------------+
                |
                v
       +------------------+
       |     PREVOTE      |  (Validators vote if proposal is valid)
       +------------------+
                |
                v
       +------------------+
       |    PRECOMMIT     |  (Validators confirm they saw prevote quorum)
       +------------------+
                |
                v
  (2f + 1 Quorum Met? -> COMMIT!)
```

### 2.1 Consensus Voting Steps
Consensus progresses through three distinct, timed steps per height ($H$) and round ($R$):
1.  **Propose**: The designated proposer constructs a candidate block from its mempool and broadcasts it.
2.  **Prevote**: Validators verify the block structure, signature validity, and timestamp skew. If valid, they broadcast a signed `Prevote` vote containing the block hash. Otherwise, they broadcast a `Prevote` for a `ZERO_HASH`.
3.  **Precommit**: Once a validator collects $2f + 1$ prevotes for a block hash, it broadcasts a signed `Precommit` vote. If a validator collects $2f + 1$ prevotes for `ZERO_HASH` (or hits a timeout), it broadcasts a `Precommit` for `ZERO_HASH`.

A block is permanently committed to the ledger once any node gathers $2f + 1$ valid precommits out of the $3f + 1$ total voting power (where $f$ represents the maximum tolerated Byzantine nodes). 

### 2.2 Consensus Timeouts
To maintain liveness under network partitions, consensus steps employ a dynamic backoff strategy:
*   `propose_timeout`: Base **500 ms**
*   `prevote_timeout`: Base **400 ms**
*   `precommit_timeout`: Base **400 ms**
*   `timeout_backoff`: Backs off exponentially at $\times 1.5$ per round (capped at **30 seconds**).
*   `target_block_ms`: Default **2000 ms** interval.

### 2.3 Mutual TLS (mTLS) P2P Transport Layer
In production mode, validators communicate exclusively over a cryptographically secure **mutual TLS (mTLS)** overlay:
*   **Validator Anchors**: All active validators must have their X.509 certificates (DER-encoded hex representation) compiled directly into the `genesis.json` allowlist.
*   **Subject Alternative Name (SAN) Checks**: Connection handshakes validate that the certificate presented by a peer matches the IP address or DNS host bound to the validator's address in `genesis.json`.
*   **Self-Signed Trust Anchors**: Nodes use 2048-bit RSA keys for mTLS encryption and Ed25519 keys for consensus voting. Peering connections are immediately dropped if a node fails the mutual certificate handshake, protecting the consensus layer against external man-in-the-middle or spoofing attacks.

---

## 3. Consortium Governance: Authority & Reputation-Based Jailing

Consortium trust and ledger integrity in DVEL are enforced through cryptographically pinned validator identities and automated reputation jailing mechanisms designed to isolate Byzantine behavior.

### 3.1 Authority Violations
The consensus engine actively audits peer behavior and applies immediate reputation penalties and voting restrictions for the following protocol violations:
*   **Double-Signing**: If an authorized validator signs two conflicting votes (different block hashes) at the same height, round, and vote type. This is detected automatically by tracking the local vote history database.
*   **Invalid Proposals**: Proposing a block with mutated hashes, invalid transaction formats, or timestamp skews exceeding the tolerated boundaries.

### 3.2 Authority Penalties & Jailing
Upon receiving valid cryptographic evidence of a double-signing violation:
1.  **Authority Weight Slashing**: The current voting weight of the offending validator is immediately penalized by **5%**:

$$\text{New Weight} = \text{Old Weight} \times 0.95$$

2.  **Jailing**: The validator is marked as `jailed` in the ledger state. While jailed, their **effective voting power** is driven to zero:

$$\text{Effective Weight} = 0$$

3.  **Jail Duration**: The jailed validator's voting power remains deactivated until the network advances past the jailing penalty duration:

$$\text{Jail Until Height} = \text{Current Height} + 1000 \text{ blocks}$$
4.  **State Persistence**: Slashing records and updated authority weights are stored in the state database and propagated deterministically in BFT state transition snapshots.

---

## 4. Secure Storage FFI Engine & MMR Inclusion Audits

DVEL features a native Rust C-ABI Storage engine accessible to external hosts. This engine enables slicing raw files, generating cryptographic manifests, and auditing file records via the blockchain without storing the actual file contents on-chain.

```
 +-----------------------------------------------------------------------------------+
 |                            SECURE STORAGE PIPELINE                                |
 |                                                                                   |
 |   [Raw File]                                                                      |
 |       |                                                                           |
 |       v (dvel_storage_chunk_file)                                                 |
 |   [64-Byte Chunk 0] [64-Byte Chunk 1] ... [64-Byte Chunk N]                       |
 |       \                /                                                          |
 |        \              /                                                           |
 |         v            v                                                            |
 |        [Manifest File] ---> Canonical Hash -> Broadcast to BFT Blockchain         |
 |                                                                                   |
 +-----------------------------------------------------------------------------------+
```

### 4.1 Chunking and Manifest Design
The FFI interface (`dvel_ffi.h`) provides deterministic slicing:
*   **File Chunking**: A raw input file is sliced into equal-sized binary pieces (e.g., 64-byte chunks).
*   **Manifest Creation**: A text manifest is written containing a sorted index of chunk hashes alongside the publisher's cryptographic Ed25519 signature.
*   **Canonical Manifest Hashing**: To produce a deterministic blockchain anchor, the manifest is parsed into a canonical (unsigned) state. The canonical manifest is then hashed:
    $$\text{Canonical Manifest Hash} = \text{SHA256}(C(\text{Manifest}))$$
    This 32-byte hash acts as the payload representing the entire archive in DVEL consensus.

### 4.2 Merkle Mountain Range (MMR) & Inclusion Proofs
To allow zero-sidecar verification, the ledger folds canonical manifest commitments into a dynamic **Merkle Mountain Range (MMR)** tree. An MMR is a binary Merkle tree variant that allows logarithmic append operations and proof generation:
*   **Logarithmic Proof Extraction**: When a client requests verification for a manifest hash, the node returns an inclusion proof containing the **MMR Root**, **Leaf Index**, **Leaf Count**, **Peaks**, and **Siblings** list.
*   **Cryptographic Climb & Verification**:
    The client hashes the target manifest:

$$\text{curr} = \text{SHA256}(\text{Manifest Hash})$$

    The client then climbs the tree by folding `curr` with sibling hashes provided in the proof:

$$\text{curr} = \begin{cases} 
  \text{SHA256}(\text{curr} \parallel \text{sibling}) & \text{if sibling is right} \\
  \text{SHA256}(\text{sibling} \parallel \text{curr}) & \text{if sibling is left}
\end{cases}$$

    The resulting peak must match one of the active MMR peaks. The Peaks are then folded from right to left:

$$\text{Folded Root} = \text{SHA256}(\text{Peak A} \parallel \text{Peak B})$$

    If `folded_root` matches the consensus MMR root, the file's historical existence is verified.

---

## 5. Hardware Observer: Dual-Core ESP32 Standalone Telemetry

Telemetry visualization and real-time ledger auditing are delegated to standalone hardware observers (ESP32 controllers with 2.8" ILI9341 TFT displays).

```
 +-----------------------------------------------------------------------------------+
 |                              ESP32 DUAL-CORE ENGINE                               |
 |                                                                                   |
 |   CORE 0: NETWORK POLLING                                                         |
 |   - Polling /tip and /block/<height> directly over Wi-Fi.                         |
 |   - Performs local HTTP Health Checks of validators.                              |
 |   - Semaphore Mutex locks shared ledger state.                                    |
 |                                                                                   |
 |   CORE 1: REAL-TIME RENDERING                                                     |
 |   - Capped at ~40 FPS.                                                            |
 |   - Double-buffered TFT_eSprite zero-flicker graphics pipeline.                   |
 |   - Renders DAG graph, active consensus tips, and system alerts.                  |
 |                                                                                   |
 +-----------------------------------------------------------------------------------+
```

### 5.1 Dual-Core FreeRTOS Tasking Architecture
To prevent network latency from choking graphical rendering, the ESP32 firmware splits operations across its two hardware cores using FreeRTOS:
1.  **Core 0 (Network Polling Task)**: Executes the `networkTask` loop. Connects to local Wi-Fi and polls HTTP endpoints (`/tip` and `/block/<height>`) from Node 0. It sequentially pulls blocks and updates ledger metadata.
2.  **Core 1 (Main Rendering & UI)**: Executes the standard Arduino `loop()` at approximately **40 FPS**. It renders the sliding graphical DAG nodes, displays live tick metrics, preferred tips, and peer weights.

Thread-safety between the two cores is guaranteed using a FreeRTOS semaphore mutex (`xMutex`):
```cpp
if (xSemaphoreTake(xMutex, portMAX_DELAY) == pdTRUE) {
    // Read or write shared variables (currentTick, merkleRoot, nodeWeights)
    xSemaphoreGive(xMutex);
}
```

### 5.2 Dynamic Peer Weights & Sybil Quarantine Alarms
Core 0 polls the health of three active validators (`17001`, `17002`, `17003`) every 3 seconds:
*   **Local Health Check**: Sends an HTTP request to `http://<ip>:<port>/tip` with a 1000 ms timeout.
*   **Weight Penalty**: If the HTTP request succeeds, the peer weight is set to **1000**. If it fails (timeouts/offline), the weight drops to **0**.
*   **Sybil / Isolation Alarm**: If the weight of Node 2 is marked as `0` (`w == 0`), the observer triggers an orange/red flashing screen alert, logs `"SYBIL ATTACK DETECTED: NODE 2 QUARANTINED!"` to the terminal, and sets `sybilAttackActive = true`. Once Node 2 passes its health check, the observer transitions back to normal green state.

### 5.3 Server Reset Synchronization Handling
To gracefully handle BFT ledger resets (e.g. database wipes), the firmware compares the server's current height (`current_height`) with the observer's historical height (`last_height`). If:
$$\text{Current Height} < \text{Last Height}$$
The observer detects the server reset, automatically resets `last_height` to `current_height`, logs `"SERVER RESET. SYNCING..."` to the screen, and restarts smooth block tracking from the new block height without stalling.

---

## 6. Implementation Specifications & Performance Parameters

| Parameter / Metric | Local Development Value | Purpose / Constraint |
| :--- | :--- | :--- |
| **BFT Consensus Engine** | Tendermint-Style Protocol | 2f+1 Quorum Fast Finality |
| **Max Block Size** | 1,048,576 bytes (1 MB) | Throughput boundary |
| **Max Events per Block** | 5,000 | Ingestion rate limit |
| **Base Block Interval** | 2000 ms | Target block generation speed |
| **P2P Transport Security** | mTLS RSA-2048 with DER | Authenticated validator mesh |
| **Consensus Key Scheme** | Ed25519 | Faster signing & signature validation |
| **Double-Sign Slashing** | 5% Authority Weight Penalty + 1000 Blocks Jail | Severe Byzantine mitigation |
| **FFI Storage Core** | Rust static library C-ABI | Unified storage orchestrator |
| **Hardware Observer LCD** | 2.8" ILI9341 (320x240) SPI | Zero-flicker double-buffered rendering |
| **Hardware Tasking** | Dual-core ESP32 (FreeRTOS) | Parallel network and render loops |

---

## 7. Operational Roadmap & Limitations

### 7.1 Current System Boundaries
While DVEL provides robust local consistency and high performance, the current release operates with the following boundary constraints:
1.  **Static Validator Configuration**: Peer endpoints and mTLS certificates are fixed inside `genesis.json`. Adding or removing a validator requires regenerating genesis configurations.
2.  **Local Network Dependency**: Nodes expect a transparent IPv4/IPv6 networking environment. Validator deployments across the public internet are susceptible to NAT constraints.

### 7.2 Future Architecture Goals
To transition the protocol for national-scale production:
*   **Dynamic Peer Discovery (Gossip DHT)**: Implementing a Kademlia-based Distributed Hash Table (DHT) to allow nodes to locate validator peers dynamically without static configuration.
*   **NAT Traversal overlay**: Implementing hole-punching (STUN/TURN) and UPnP inside the Rust transport layer to allow public-internet peering across heterogeneous ISP networks.
