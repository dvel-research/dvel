# Permissioned BFT (v0.1.0)

This repository includes a **Tendermint‑style** BFT prototype for permissioned validators.
It provides fast finality (commit after 2f+1 precommits out of 3f+1 validators) and
assumes a static validator set defined in `genesis.json`.

## Protocol summary
- **Proposer**: `(height + round) % N` over the validator list.
- **Rounds**: propose → prevote → precommit.
- **Commit**: block is final after **2f+1** precommits for the same block hash.
- **Blocks**: bundle up to **1 MB** or **5,000** events (whichever comes first).
- **Tx encoding**: `version | prev_hash | author | timestamp_le | payload_hash | signature`.
- **Tx root**: Merkle root over `SHA256(tx)` in block order.

## Timeouts
```
propose_timeout  = 800ms
prevote_timeout  = 600ms
precommit_timeout= 600ms
backoff          = ×1.5 per round (cap 10s)
target block     = 2s
```

## Security model (v0.1.0)
- **Permissioned validators only**: peers must appear in the genesis allowlist.
- **Authenticated transport**: peers sign a hello message using ed25519 keys.
- **mTLS (optional)**: when enabled, connections require a pinned cert from `genesis.json`.
  The certificate must include the validator's listen host in SubjectAltName (IP or DNS),
  and should be self-signed CA or chain to a private CA used as a trust anchor.

## Example genesis.json
```json
{
  "chain_id": "dvel-bft-test",
  "validators": [
    {
      "pubkey_hex": "…32-byte-hex…",
      "address": "127.0.0.1:9001",
      "tls_cert_hex": "…der-hex…"
    },
    {
      "pubkey_hex": "…32-byte-hex…",
      "address": "127.0.0.1:9002",
      "tls_cert_hex": "…der-hex…"
    },
    {
      "pubkey_hex": "…32-byte-hex…",
      "address": "127.0.0.1:9003",
      "tls_cert_hex": "…der-hex…"
    },
    {
      "pubkey_hex": "…32-byte-hex…",
      "address": "127.0.0.1:9004",
      "tls_cert_hex": "…der-hex…"
    }
  ],
  "consensus": {
    "max_block_bytes": 1048576,
    "max_events": 5000,
    "target_block_ms": 2000,
    "propose_timeout_ms": 800,
    "prevote_timeout_ms": 600,
    "precommit_timeout_ms": 600,
    "timeout_backoff_num": 3,
    "timeout_backoff_den": 2,
    "timeout_cap_ms": 10000
  },
  "client": {
    "listen_addr": "127.0.0.1:7000"
  },
  "transport": {
    "tls_enabled": true
  }
}
```
`tls_cert_hex` is the DER-encoded X.509 cert in hex (omit when `tls_enabled` is false).
The node expects PEM files for `--tls-cert` and `--tls-key` (PKCS#8 private key).
Helper to generate `tls_cert_hex` from a PEM cert:
```
python3 scripts/cert_hex.py /path/to/node.crt
```
Self-signed cert helper (requires `openssl`):
```
./scripts/gen_tls_selfsigned.sh /path/to/out 127.0.0.1 node1
```
If `--data-dir` is omitted, the node stores snapshots under `data/<node_id_hex>`.

## Running a node
```
cargo run --release --features bft --bin dvel-bft-node \
  --genesis /path/to/genesis.json \
  --key-hex <32-byte-secret-hex> \
  --listen 127.0.0.1:9001 \
  --client 127.0.0.1:7001 \
  --data-dir /path/to/node-data \
  --tls-cert /path/to/node.crt \
  --tls-key /path/to/node.key
```

## Client API (HTTP/JSON)
- `POST /tx` with `{ "tx_hex": "<hex>" }` → `{ "tx_hash": "<hex>" }`
- `GET /tip` → `{ "height": <u64>, "hash": "<hex>" }`
- `GET /block/<height>` → header + tx hashes
- `GET /tx/<hash>` → `{ "status": "committed", "height": <u64>, "block_hash": "<hex>" }`

## Persistence
- Blocks and the tx index are persisted to `bft_snapshot.json` under `--data-dir`.
- On restart, the node replays stored blocks to rebuild the ledger and indices.
