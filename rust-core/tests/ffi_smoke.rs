use dvel_core::PROTOCOL_VERSION;
use dvel_core::ffi::*;
use std::ffi::CString;
use std::ptr;
use tempfile::tempdir;

fn zero_hash() -> dvel_hash_t {
    dvel_hash_t { bytes: [0u8; 32] }
}

fn make_payload(tag: u8) -> dvel_hash_t {
    let mut h = [0u8; 32];
    for (i, b) in h.iter_mut().enumerate() {
        *b = tag.wrapping_add(i as u8);
    }
    dvel_hash_t { bytes: h }
}

fn make_secret(tag: u8) -> dvel_hash_t {
    let mut h = [0u8; 32];
    for (i, b) in h.iter_mut().enumerate() {
        *b = tag.wrapping_add(i as u8);
    }
    dvel_hash_t { bytes: h }
}

struct LedgerHandle(*mut dvel_core::ledger::Ledger);
impl LedgerHandle {
    fn new() -> Self {
        LedgerHandle(dvel_ledger_new())
    }
}
impl Drop for LedgerHandle {
    fn drop(&mut self) {
        dvel_ledger_free(self.0);
    }
}

#[test]
fn ffi_validate_link_and_fetch() {
    // Setup keys
    let secret = make_secret(7);
    let mut author = dvel_pubkey_t { bytes: [0u8; 32] };
    assert!(dvel_derive_pubkey_from_secret(&secret, &mut author));

    // Build event
    let mut ev = dvel_event_t {
        version: PROTOCOL_VERSION,
        prev_hash: zero_hash(),
        author,
        timestamp: 10,
        payload_hash: make_payload(0xAB),
        signature: dvel_sig_t { bytes: [0u8; 64] },
    };

    dvel_sign_event(&ev, &secret, &mut ev.signature);

    // Validate with context
    let mut ctx = dvel_validation_ctx_t { last_timestamp: 0 };
    dvel_validation_ctx_init(&mut ctx);
    let vr = dvel_validate_event(&ev, &mut ctx);
    assert!(matches!(vr, dvel_validation_result_t::DVEL_OK));

    // Link into ledger
    let ledger = LedgerHandle::new();
    let mut out_hash = zero_hash();
    let lr = dvel_ledger_link_event(ledger.0, &ev, &mut out_hash);
    assert!(matches!(lr, dvel_link_result_t::DVEL_LINK_OK));

    // Fetch and compare
    let mut fetched: dvel_event_t = unsafe { std::mem::zeroed() };
    let found = dvel_ledger_get_event(ledger.0, &out_hash, &mut fetched);
    assert!(found);
    assert_eq!(fetched.timestamp, ev.timestamp);
    assert_eq!(fetched.author.bytes, ev.author.bytes);

    // Tips and Merkle root should be non-empty
    let mut tips = [zero_hash(); 4];
    let tip_count = dvel_ledger_get_tips(ledger.0, tips.as_mut_ptr(), tips.len());
    assert_eq!(tip_count, 1);
    assert_eq!(tips[0].bytes, out_hash.bytes);

    let mut merkle = dvel_merkle_root_t {
        root: zero_hash(),
        has_value: false,
    };
    let ok = dvel_ledger_merkle_root(ledger.0, &mut merkle);
    assert!(ok);
    assert!(merkle.has_value);
    assert_eq!(merkle.root.bytes, out_hash.bytes);

    // Duplicate should be rejected
    let mut dup_hash = zero_hash();
    let lr_dup = dvel_ledger_link_event(ledger.0, &ev, &mut dup_hash);
    assert!(matches!(
        lr_dup,
        dvel_link_result_t::DVEL_LINK_ERR_DUPLICATE
    ));
}

#[test]
fn ffi_link_rejects_missing_parent() {
    let secret = make_secret(9);
    let mut author = dvel_pubkey_t { bytes: [0u8; 32] };
    assert!(dvel_derive_pubkey_from_secret(&secret, &mut author));

    let mut ev = dvel_event_t {
        version: PROTOCOL_VERSION,
        prev_hash: make_payload(0x01), // nonexistent parent
        author,
        timestamp: 1,
        payload_hash: make_payload(0xCD),
        signature: dvel_sig_t { bytes: [0u8; 64] },
    };
    dvel_sign_event(&ev, &secret, &mut ev.signature);

    let ledger = LedgerHandle::new();
    let mut ctx = dvel_validation_ctx_t { last_timestamp: 0 };
    dvel_validation_ctx_init(&mut ctx);
    let vr = dvel_validate_event(&ev, &mut ctx);
    assert!(matches!(vr, dvel_validation_result_t::DVEL_OK));

    let mut out_hash = zero_hash();
    let lr = dvel_ledger_link_event(ledger.0, &ev, &mut out_hash);
    assert!(matches!(
        lr,
        dvel_link_result_t::DVEL_LINK_ERR_MISSING_PARENT
    ));
}

#[test]
fn ffi_storage_round_trip() {
    let dir = tempdir().unwrap();
    let input_path = dir.path().join("input.bin");
    std::fs::write(&input_path, b"ffi storage round trip").unwrap();

    let out_dir = dir.path().join("chunks");
    let c_input = CString::new(input_path.to_str().unwrap()).unwrap();
    let c_out = CString::new(out_dir.to_str().unwrap()).unwrap();

    let ok = dvel_storage_chunk_file(c_input.as_ptr(), c_out.as_ptr(), 8, ptr::null(), false);
    assert!(ok, "chunk_file failed");

    let manifest_path = out_dir.join("input.bin.manifest");
    let rebuilt_path = dir.path().join("rebuilt.bin");

    let c_manifest = CString::new(manifest_path.to_str().unwrap()).unwrap();
    let c_chunk_dir = CString::new(out_dir.to_str().unwrap()).unwrap();
    let c_rebuilt = CString::new(rebuilt_path.to_str().unwrap()).unwrap();

    let ok = dvel_storage_download(
        c_manifest.as_ptr(),
        c_chunk_dir.as_ptr(),
        c_rebuilt.as_ptr(),
        ptr::null(),
    );
    assert!(ok, "storage_download failed");

    let original = std::fs::read(&input_path).unwrap();
    let rebuilt = std::fs::read(&rebuilt_path).unwrap();
    assert_eq!(rebuilt, original);

    // Hash helpers should return non-zero values.
    let mut manifest_hash = zero_hash();
    let mut chunk_root = zero_hash();
    assert!(dvel_storage_manifest_hash(
        c_manifest.as_ptr(),
        &mut manifest_hash
    ));
    assert!(dvel_storage_chunk_merkle_root(
        c_manifest.as_ptr(),
        &mut chunk_root
    ));
    assert!(manifest_hash.bytes.iter().any(|b| *b != 0));
    assert!(chunk_root.bytes.iter().any(|b| *b != 0));
}

#[test]
fn ffi_mmr_verification() {
    let mut mmr = dvel_core::mmr::Mmr::new();
    let mut leaves = Vec::new();
    for i in 0..10 {
        let mut leaf = [0u8; 32];
        leaf[0] = i as u8;
        mmr.append(leaf);
        leaves.push(leaf);
    }

    let root = mmr.get_root().unwrap();
    let proof = mmr.gen_proof(4).unwrap();

    let c_root = dvel_hash_t { bytes: root };
    let c_leaf = dvel_hash_t { bytes: leaves[4] };

    let mut c_siblings = [dvel_hash_t { bytes: [0u8; 32] }; 64];
    let mut c_sibling_is_right = [false; 64];
    for (idx, &(sh, is_right)) in proof.siblings.iter().enumerate() {
        c_siblings[idx] = dvel_hash_t { bytes: sh };
        c_sibling_is_right[idx] = is_right;
    }

    let mut c_peaks = [dvel_hash_t { bytes: [0u8; 32] }; 64];
    for (idx, &ph) in proof.peaks.iter().enumerate() {
        c_peaks[idx] = dvel_hash_t { bytes: ph };
    }

    let c_proof = dvel_mmr_proof_t {
        leaf_index: proof.leaf_index,
        leaf_count: proof.leaf_count,
        siblings: c_siblings,
        siblings_count: proof.siblings.len() as u32,
        sibling_is_right: c_sibling_is_right,
        peaks: c_peaks,
        peaks_count: proof.peaks.len() as u32,
    };

    assert!(dvel_mmr_verify_proof(&c_root, &c_leaf, &c_proof));

    let bad_leaf = dvel_hash_t { bytes: [0xFF; 32] };
    assert!(!dvel_mmr_verify_proof(&c_root, &bad_leaf, &c_proof));
}
