// DVEL Reference Implementation FFI (C ABI)

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C"
{
#endif

    // ---------------- FIXED-size core types ----------------
    typedef struct
    {
        uint8_t bytes[32];
    } dvel_hash_t;
    typedef struct
    {
        uint8_t bytes[32];
    } dvel_pubkey_t;
    typedef struct
    {
        uint8_t bytes[64];
    } dvel_sig_t;

    // Mirrors the Rust Event layout (field-by-field).
    // NOTE: Signature is currently dummy in Rust Validation.
    typedef struct
    {
        uint8_t version;
        dvel_hash_t prev_hash;
        dvel_pubkey_t author;
        uint64_t timestamp;
        dvel_hash_t payload_hash;
        dvel_sig_t signature;
    } dvel_event_t;

    // Opaque handles (owned by Rust). Called MUST free.
    typedef void dvel_ledger_t;

    dvel_ledger_t *dvel_ledger_new(void);
    void dvel_ledger_free(dvel_ledger_t *ledger);

    // Adds an event to the ledger.
    // Returns the computed event hash (deterministic, non-crypto placeholder).
    // NOTE: This funciton does NOT validate event linkage or signature.
    // Validation is explicit: call dvel_validate_event first.
    dvel_hash_t dvel_ledger_add_event(dvel_ledger_t *ledger, const dvel_event_t *event);

    // ---------------- Linkage-aware add ----------------
    typedef enum
    {
        DVEL_LINK_OK = 0,
        DVEL_LINK_ERR_DUPLICATE = 1,
        DVEL_LINK_ERR_MISSING_PARENT = 2,
    } dvel_link_result_t;

    // Linkage-aware add:
    // - checks duplicate
    // - checks parent existence unless genesis
    // - updates tips on success
    // - writes computed hash to out_hash on success
    // NOTE: validation (version/signature/timestamp) remains separate.
    dvel_link_result_t dvel_ledger_link_event(
        dvel_ledger_t *ledger,
        const dvel_event_t *event,
        dvel_hash_t *out_hash);

    // Look up an event by hash
    // Returns true and writes to out_event if found.
    bool dvel_ledger_get_event(const dvel_ledger_t *ledger, const dvel_hash_t *hash, dvel_event_t *out_event);

    // Tips enumeration
    // Writes up to out_capacity tips into out_tips.
    // Return total number of tips currently in the ledger (may exceed out_capacity).
    size_t dvel_ledger_get_tips(const dvel_ledger_t *ledger, dvel_hash_t *out_tips, size_t out_capacity);

    // ---------------- Validation ----------------
    typedef enum
    {
        DVEL_OK = 0,
        DVEL_ERR_INVALID_VERSION = 1,
        DVEL_ERR_INVALID_SIGNATURE = 2,
        DVEL_ERR_TIMESTAMP_NON_MONOTONIC = 3,
    } dvel_validation_result_t;

    // Minimal validation context.
    // The simulator owns and updates this.
    typedef struct
    {
        uint64_t last_timestamp;
    } dvel_validation_ctx_t;

    // Initializes the validation context deterministically.
    void dvel_validation_ctx_init(dvel_validation_ctx_t *ctx);

    // Sets maximum allowed backward skew (in ticks) for timestamp validation (min 1).
    void dvel_set_max_backward_skew(uint64_t skew);

    // Sets signing key (32 bytes). Sim-only deterministic signing.
    void dvel_set_signing_key(const dvel_hash_t *key);

    // Validates an event against a context.
    // DOES NOT check prev_hash existence (ledger linkage) - that is separate.
    dvel_validation_result_t dvel_validate_event(const dvel_event_t *event, dvel_validation_ctx_t *ctx);

    // ---------------- Scoring / Preference (no-consensus) ----------------
    typedef enum
    {
        DVEL_WEIGHT_UNIT = 0,
        DVEL_WEIGHT_LATEST_PER_AUTHOR_UNIT = 1,
    } dvel_weight_policy_t;

    typedef struct
    {
        dvel_hash_t tip;
        uint64_t score;
        bool has_value;
    } dvel_preferred_tip_t;

    typedef struct
    {
        dvel_hash_t root;
        bool has_value;
    } dvel_merkle_root_t;

    // Compute event hash (canonical) from struct fields.
    dvel_hash_t dvel_hash_event_struct(const dvel_event_t *ev);

    // Select preferred tip using a local weight policy.
    // max_steps bounds prev_hash walk for safety.
    dvel_preferred_tip_t dvel_select_preferred_tip(
        const dvel_ledger_t *ledger,
        dvel_weight_policy_t policy,
        size_t max_steps);

    // ---------------- Sybil overlay (stateful quarantine, latest-per-author) ----------------
    typedef void dvel_sybil_overlay_t;
    typedef void dvel_trace_recorder_t;

    typedef struct
    {
        uint64_t warmup_ticks;
        uint64_t quarantine_ticks;
        uint64_t fixed_point_scale;
        size_t max_link_walk;
    } dvel_sybil_config_t;

    typedef struct
    {
        dvel_hash_t prev_hash;
        dvel_pubkey_t author;
        uint64_t timestamp;
        dvel_hash_t payload_hash;
        dvel_sig_t signature;
        bool parent_present;
        bool ancestor_check;
        uint64_t quarantined_until_before;
        uint64_t quarantined_until_after;
        dvel_hash_t merkle_root;
        bool merkle_root_has;
        dvel_hash_t preferred_tip;
        bool preferred_tip_has;
        uint64_t author_weight_fp;
    } dvel_trace_row_t;

    // Derive ed25519 public key from 32-byte secret key. Returns true on success.
    bool dvel_derive_pubkey_from_secret(const dvel_hash_t *secret_key, dvel_pubkey_t *out_pub);

    // Default-config overlay handle (owned by caller).
    dvel_sybil_overlay_t *dvel_sybil_overlay_new(void);
    void dvel_sybil_overlay_free(dvel_sybil_overlay_t *ptr);

    // Override overlay config in-place.
    void dvel_sybil_overlay_set_config(dvel_sybil_overlay_t *overlay, const dvel_sybil_config_t *cfg);

    // Trace recorder (optional, proof tooling). Ownership belongs to caller.
    dvel_trace_recorder_t *dvel_trace_recorder_new(void);
    void dvel_trace_recorder_free(dvel_trace_recorder_t *ptr);
    void dvel_trace_recorder_clear(dvel_trace_recorder_t *ptr);
    size_t dvel_trace_recorder_len(const dvel_trace_recorder_t *ptr);
    bool dvel_trace_recorder_get(const dvel_trace_recorder_t *ptr, size_t idx, dvel_trace_row_t *out_row);

    // Attach/detach a trace recorder to an overlay (overlay does not free it).
    void dvel_sybil_overlay_attach_trace_recorder(dvel_sybil_overlay_t *overlay, dvel_trace_recorder_t *recorder);

    // Observe an event that was ACCEPTED by the ledger.
    // Uses the canonical ledger-stored event (hash must match ledger entry).
    void dvel_sybil_overlay_observe_event(
        dvel_sybil_overlay_t *overlay,
        const dvel_ledger_t *ledger,
        uint64_t tick,
        uint32_t observer_node,
        const dvel_hash_t *event_hash);

    // Returns fixed-point author weight (scaled by overlay config; default 1000).
    uint64_t dvel_sybil_overlay_author_weight_fp(
        const dvel_sybil_overlay_t *overlay,
        uint64_t tick,
        dvel_pubkey_t author);

    // Select preferred tip using sybil-aware weighting (latest-per-author + quarantine).
    dvel_preferred_tip_t dvel_select_preferred_tip_sybil(
        const dvel_ledger_t *ledger,
        const dvel_sybil_overlay_t *overlay,
        uint64_t tick,
        size_t max_steps);

    // Compute Merkle root over all event hashes in the ledger.
    // Returns false if ledger is empty.
    bool dvel_ledger_merkle_root(const dvel_ledger_t *ledger, dvel_merkle_root_t *out_root);

    // Signing helper (ed25519). Signs canonical event bytes with the provided 32-byte secret key.
    // Writes the signature into out_sig.
    void dvel_sign_event(const dvel_event_t *event, const dvel_hash_t *secret_key, dvel_sig_t *out_sig);

    // ---------------- MMR (Merkle Mountain Range) Proofs ----------------
    typedef struct
    {
        uint64_t leaf_index;
        uint64_t leaf_count;
        dvel_hash_t siblings[64];
        uint32_t siblings_count;
        bool sibling_is_right[64];
        dvel_hash_t peaks[64];
        uint32_t peaks_count;
    } dvel_mmr_proof_t;

    // Verify an MMR inclusion proof against a trusted MMR root hash.
    bool dvel_mmr_verify_proof(
        const dvel_hash_t *trusted_root,
        const dvel_hash_t *leaf_hash,
        const dvel_mmr_proof_t *proof);

    // ---------------- Storage (chunk/manifest/sign/verify) ----------------
    // Copies last error string into buf (NUL-terminated if space). Returns full length of the message.
    size_t dvel_storage_last_error(uint8_t *buf, size_t buf_len);

    // Chunk a file into out_dir and write manifest (.manifest). If sign=true, secret_key32 must be non-null.
    bool dvel_storage_chunk_file(
        const char *input_path,
        const char *out_dir,
        size_t chunk_size_bytes,
        const uint8_t *secret_key32,
        bool sign);

    // Verify manifest/chunks and reassemble to output_path. If expect_signer is non-null, it must match manifest signer.
    bool dvel_storage_download(
        const char *manifest_path,
        const char *chunk_dir,
        const char *output_path,
        const uint8_t *expect_signer32);

    // Compute hashes from manifest (for anchoring into ledger events or audit).
    // Returns false on error; use dvel_storage_last_error to inspect.
    bool dvel_storage_manifest_hash(const char *manifest_path, dvel_hash_t *out_hash);
    bool dvel_storage_chunk_merkle_root(const char *manifest_path, dvel_hash_t *out_hash);

#ifdef __cplusplus
} // extern "C"
#endif
