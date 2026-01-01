#![allow(clippy::not_unsafe_ptr_arg_deref)]

use crate::event::{Event, Hash};
use crate::ledger::{Ledger, LedgerLinkError};
use crate::scoring::{
    EquivocationPolicy, LocalPolicyKind, SybilConfig, SybilOverlay, TraceRecorder, TraceRow,
    select_preferred_tip_score, select_preferred_tip_score_sybil,
};
use crate::storage;
use crate::validation::{
    ValidationContext, ValidationError, compute_signature_with_secret, set_max_backward_skew,
    validate_event,
};
use std::cell::RefCell;
use std::ffi::CStr;
use std::os::raw::c_char;

#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Clone, Copy)]
pub struct dvel_hash_t {
    pub bytes: [u8; 32],
}

#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Clone, Copy)]
pub struct dvel_pubkey_t {
    pub bytes: [u8; 32],
}

#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Clone, Copy)]
pub struct dvel_sig_t {
    pub bytes: [u8; 64],
}

#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Clone, Copy)]
pub struct dvel_event_t {
    pub version: u8,
    pub prev_hash: dvel_hash_t,
    pub author: dvel_pubkey_t,
    pub timestamp: u64,
    pub payload_hash: dvel_hash_t,
    pub signature: dvel_sig_t,
}

#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Clone, Copy)]
pub struct dvel_validation_ctx_t {
    pub last_timestamp: u64,
}

#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum dvel_validation_result_t {
    DVEL_OK = 0,
    DVEL_ERR_INVALID_VERSION = 1,
    DVEL_ERR_INVALID_SIGNATURE = 2,
    DVEL_ERR_TIMESTAMP_NON_MONOTONIC = 3,
}

#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum dvel_link_result_t {
    DVEL_LINK_OK = 0,
    DVEL_LINK_ERR_DUPLICATE = 1,
    DVEL_LINK_ERR_MISSING_PARENT = 2,
}

#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum dvel_weight_policy_t {
    DVEL_WEIGHT_UNIT = 0,
    DVEL_WEIGHT_LATEST_PER_AUTHOR_UNIT = 1,
}

#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Clone, Copy)]
pub struct dvel_preferred_tip_t {
    pub tip: dvel_hash_t,
    pub score: u64,
    pub has_value: bool,
}

#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Clone, Copy)]
pub struct dvel_merkle_root_t {
    pub root: dvel_hash_t,
    pub has_value: bool,
}

#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Clone, Copy)]
pub struct dvel_sybil_config_t {
    pub warmup_ticks: u64,
    pub quarantine_ticks: u64,
    pub fixed_point_scale: u64,
    pub max_link_walk: usize,
}

#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Clone, Copy)]
pub struct dvel_trace_row_t {
    pub prev_hash: dvel_hash_t,
    pub author: dvel_pubkey_t,
    pub timestamp: u64,
    pub payload_hash: dvel_hash_t,
    pub signature: dvel_sig_t,
    pub parent_present: bool,
    pub ancestor_check: bool,
    pub quarantined_until_before: u64,
    pub quarantined_until_after: u64,
    pub merkle_root: dvel_hash_t,
    pub merkle_root_has: bool,
    pub preferred_tip: dvel_hash_t,
    pub preferred_tip_has: bool,
    pub author_weight_fp: u64,
}

thread_local! {
    static LAST_ERROR: RefCell<String> = const { RefCell::new(String::new()) };
}

fn set_last_error(msg: impl Into<String>) {
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = msg.into();
    });
}

#[unsafe(no_mangle)]
pub extern "C" fn dvel_storage_last_error(buf: *mut u8, buf_len: usize) -> usize {
    let msg = LAST_ERROR.with(|e| e.borrow().clone());
    let bytes = msg.as_bytes();
    let copy_len = bytes.len().min(buf_len.saturating_sub(1));
    if !buf.is_null() && buf_len > 0 {
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, copy_len);
            *buf.add(copy_len) = 0;
        }
    }
    bytes.len()
}

#[unsafe(no_mangle)]
pub extern "C" fn dvel_hash_event_struct(ev: *const dvel_event_t) -> dvel_hash_t {
    if ev.is_null() {
        return dvel_hash_t { bytes: [0u8; 32] };
    }
    let e = unsafe { to_event(&*ev) };
    let h = Ledger::hash_event(&e);
    from_hash(&h)
}

#[unsafe(no_mangle)]
pub extern "C" fn dvel_derive_pubkey_from_secret(
    secret_key: *const dvel_hash_t,
    out_pub: *mut dvel_pubkey_t,
) -> bool {
    if secret_key.is_null() || out_pub.is_null() {
        return false;
    }
    unsafe {
        let sk = &*secret_key;
        let secret = ed25519_dalek::SecretKey::from_bytes(&sk.bytes);
        if let Ok(sec) = secret {
            let public: ed25519_dalek::PublicKey = (&sec).into();
            (*out_pub).bytes = public.to_bytes();
            true
        } else {
            false
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn dvel_storage_chunk_file(
    input_path: *const c_char,
    out_dir: *const c_char,
    chunk_size: usize,
    secret_key: *const u8,
    sign: bool,
) -> bool {
    set_last_error("");
    let input = match cstr_to_str(input_path) {
        Ok(s) => std::path::Path::new(s),
        Err(e) => {
            set_last_error(format!("input_path: {}", e));
            return false;
        }
    };
    let out_dir = match cstr_to_str(out_dir) {
        Ok(s) => std::path::Path::new(s),
        Err(e) => {
            set_last_error(format!("out_dir: {}", e));
            return false;
        }
    };

    let mut manifest = match storage::chunk_file_to_dir(input, out_dir, chunk_size) {
        Ok(m) => m,
        Err(e) => {
            set_last_error(format!("{}", e));
            return false;
        }
    };

    if sign {
        if secret_key.is_null() {
            set_last_error("secret_key is null");
            return false;
        }
        let sk = unsafe { std::slice::from_raw_parts(secret_key, 32) };
        let mut sk_array = [0u8; 32];
        sk_array.copy_from_slice(sk);
        if let Err(e) = storage::sign_manifest_inplace(&mut manifest, &sk_array) {
            set_last_error(format!("{}", e));
            return false;
        }
    }

    let mpath = storage::manifest_path(out_dir, &manifest.file_name);
    if let Err(e) = storage::write_manifest(&manifest, &mpath) {
        set_last_error(format!("{}", e));
        return false;
    }

    true
}

#[unsafe(no_mangle)]
pub extern "C" fn dvel_storage_download(
    manifest_path: *const c_char,
    chunk_dir: *const c_char,
    output_path: *const c_char,
    expect_signer: *const u8,
) -> bool {
    set_last_error("");

    let mpath = match cstr_to_str(manifest_path) {
        Ok(s) => std::path::Path::new(s),
        Err(e) => {
            set_last_error(format!("manifest_path: {}", e));
            return false;
        }
    };
    let cdir = match cstr_to_str(chunk_dir) {
        Ok(s) => std::path::Path::new(s),
        Err(e) => {
            set_last_error(format!("chunk_dir: {}", e));
            return false;
        }
    };
    let out = match cstr_to_str(output_path) {
        Ok(s) => std::path::Path::new(s),
        Err(e) => {
            set_last_error(format!("output_path: {}", e));
            return false;
        }
    };

    let manifest = match storage::read_manifest(mpath) {
        Ok(m) => m,
        Err(e) => {
            set_last_error(format!("{}", e));
            return false;
        }
    };

    if !expect_signer.is_null() {
        let expected = unsafe { std::slice::from_raw_parts(expect_signer, 32) };
        if manifest.signer.as_ref().map(|s| &s[..]) != Some(expected) {
            set_last_error("signer mismatch");
            return false;
        }
    }

    if manifest.signature.is_some()
        && let Err(e) = storage::verify_manifest_signature(&manifest)
    {
        set_last_error(format!("{}", e));
        return false;
    }

    if let Err(e) = storage::verify_chunks(&manifest, cdir) {
        set_last_error(format!("{}", e));
        return false;
    }

    if let Err(e) = storage::reassemble(&manifest, cdir, out) {
        set_last_error(format!("{}", e));
        return false;
    }

    true
}

#[unsafe(no_mangle)]
pub extern "C" fn dvel_storage_manifest_hash(
    manifest_path: *const c_char,
    out_hash: *mut dvel_hash_t,
) -> bool {
    set_last_error("");
    if out_hash.is_null() {
        set_last_error("out_hash is null");
        return false;
    }
    let mpath = match cstr_to_str(manifest_path) {
        Ok(s) => std::path::Path::new(s),
        Err(e) => {
            set_last_error(format!("manifest_path: {}", e));
            return false;
        }
    };
    match storage::manifest_hash_from_file(mpath) {
        Ok(h) => {
            unsafe { *out_hash = from_hash(&h) };
            true
        }
        Err(e) => {
            set_last_error(format!("{}", e));
            false
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn dvel_storage_chunk_merkle_root(
    manifest_path: *const c_char,
    out_hash: *mut dvel_hash_t,
) -> bool {
    set_last_error("");
    if out_hash.is_null() {
        set_last_error("out_hash is null");
        return false;
    }
    let mpath = match cstr_to_str(manifest_path) {
        Ok(s) => std::path::Path::new(s),
        Err(e) => {
            set_last_error(format!("manifest_path: {}", e));
            return false;
        }
    };
    match storage::chunk_merkle_root_from_file(mpath) {
        Ok(Some(h)) => {
            unsafe { *out_hash = from_hash(&h) };
            true
        }
        Ok(None) => {
            set_last_error("no chunks");
            false
        }
        Err(e) => {
            set_last_error(format!("{}", e));
            false
        }
    }
}

#[inline]
fn to_hash(h: &dvel_hash_t) -> Hash {
    h.bytes
}

#[inline]
fn from_hash(h: &Hash) -> dvel_hash_t {
    dvel_hash_t { bytes: *h }
}

#[inline]
fn to_event(e: &dvel_event_t) -> Event {
    Event {
        version: e.version,
        prev_hash: e.prev_hash.bytes,
        author: e.author.bytes,
        timestamp: e.timestamp,
        payload_hash: e.payload_hash.bytes,
        signature: e.signature.bytes,
    }
}

#[inline]
fn from_event(e: &Event) -> dvel_event_t {
    dvel_event_t {
        version: e.version,
        prev_hash: dvel_hash_t { bytes: e.prev_hash },
        author: dvel_pubkey_t { bytes: e.author },
        timestamp: e.timestamp,
        payload_hash: dvel_hash_t {
            bytes: e.payload_hash,
        },
        signature: dvel_sig_t { bytes: e.signature },
    }
}

fn cstr_to_str<'a>(ptr: *const c_char) -> Result<&'a str, &'static str> {
    if ptr.is_null() {
        return Err("null pointer");
    }
    unsafe { CStr::from_ptr(ptr).to_str().map_err(|_| "invalid utf-8") }
}

fn map_validation_error(err: ValidationError) -> dvel_validation_result_t {
    match err {
        ValidationError::InvalidVersion => dvel_validation_result_t::DVEL_ERR_INVALID_VERSION,
        ValidationError::InvalidSignature => dvel_validation_result_t::DVEL_ERR_INVALID_SIGNATURE,
        ValidationError::TimestampNonMonotonic => {
            dvel_validation_result_t::DVEL_ERR_TIMESTAMP_NON_MONOTONIC
        }
    }
}

fn map_link_error(err: LedgerLinkError) -> dvel_link_result_t {
    match err {
        LedgerLinkError::Duplicate => dvel_link_result_t::DVEL_LINK_ERR_DUPLICATE,
        LedgerLinkError::MissingParent => dvel_link_result_t::DVEL_LINK_ERR_MISSING_PARENT,
    }
}

fn from_trace_row(row: &TraceRow) -> dvel_trace_row_t {
    dvel_trace_row_t {
        prev_hash: from_hash(&row.prev_hash),
        author: dvel_pubkey_t { bytes: row.author },
        timestamp: row.timestamp,
        payload_hash: from_hash(&row.payload_hash),
        signature: dvel_sig_t {
            bytes: row.signature,
        },
        parent_present: row.parent_present,
        ancestor_check: row.ancestor_check,
        quarantined_until_before: row.quarantined_until_before,
        quarantined_until_after: row.quarantined_until_after,
        merkle_root: row
            .merkle_root
            .map(|h| from_hash(&h))
            .unwrap_or(dvel_hash_t { bytes: [0u8; 32] }),
        merkle_root_has: row.merkle_root.is_some(),
        preferred_tip: row
            .preferred_tip
            .map(|h| from_hash(&h))
            .unwrap_or(dvel_hash_t { bytes: [0u8; 32] }),
        preferred_tip_has: row.preferred_tip.is_some(),
        author_weight_fp: row.author_weight_fp,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn dvel_ledger_new() -> *mut Ledger {
    Box::into_raw(Box::new(Ledger::new()))
}

#[unsafe(no_mangle)]
pub extern "C" fn dvel_ledger_free(ledger: *mut Ledger) {
    if !ledger.is_null() {
        unsafe {
            drop(Box::from_raw(ledger));
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn dvel_ledger_add_event(
    ledger: *mut Ledger,
    event: *const dvel_event_t,
) -> dvel_hash_t {
    if ledger.is_null() || event.is_null() {
        return dvel_hash_t { bytes: [0u8; 32] };
    }
    let h = unsafe {
        let l = &mut *ledger;
        let e = to_event(&*event);
        l.add_event(e)
    };
    from_hash(&h)
}

#[unsafe(no_mangle)]
pub extern "C" fn dvel_ledger_link_event(
    ledger: *mut Ledger,
    event: *const dvel_event_t,
    out_hash: *mut dvel_hash_t,
) -> dvel_link_result_t {
    if ledger.is_null() || event.is_null() {
        return dvel_link_result_t::DVEL_LINK_ERR_MISSING_PARENT;
    }

    let (res, maybe_hash) = unsafe {
        let l = &mut *ledger;
        let e = to_event(&*event);
        match l.try_add_event(e) {
            Ok(hash) => (dvel_link_result_t::DVEL_LINK_OK, Some(hash)),
            Err(err) => (map_link_error(err), None),
        }
    };

    if let Some(hash) = maybe_hash && !out_hash.is_null() {
        unsafe {
            *out_hash = from_hash(&hash);
        }
    }

    res
}

#[unsafe(no_mangle)]
pub extern "C" fn dvel_ledger_get_event(
    ledger: *const Ledger,
    hash: *const dvel_hash_t,
    out_event: *mut dvel_event_t,
) -> bool {
    if ledger.is_null() || hash.is_null() || out_event.is_null() {
        return false;
    }

    unsafe {
        let l = &*ledger;
        let h = to_hash(&*hash);

        if let Some(ev) = l.get_event(&h) {
            *out_event = from_event(ev);
            true
        } else {
            false
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn dvel_validation_ctx_init(ctx: *mut dvel_validation_ctx_t) {
    if ctx.is_null() {
        return;
    }
    unsafe {
        (*ctx).last_timestamp = 0;
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn dvel_set_max_backward_skew(skew: u64) {
    set_max_backward_skew(skew);
}

#[unsafe(no_mangle)]
pub extern "C" fn dvel_validate_event(
    event: *const dvel_event_t,
    ctx: *mut dvel_validation_ctx_t,
) -> dvel_validation_result_t {
    if event.is_null() || ctx.is_null() {
        return dvel_validation_result_t::DVEL_ERR_INVALID_VERSION;
    }

    let (mut vctx, c_ptr) = unsafe {
        (
            ValidationContext {
                last_timestamp: (*ctx).last_timestamp,
            },
            ctx,
        )
    };

    match validate_event(&unsafe { to_event(&*event) }, &mut vctx) {
        Ok(()) => {
            unsafe {
                (*c_ptr).last_timestamp = vctx.last_timestamp;
            }
            dvel_validation_result_t::DVEL_OK
        }
        Err(err) => map_validation_error(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn dvel_select_preferred_tip(
    ledger: *const Ledger,
    policy: dvel_weight_policy_t,
    max_steps: usize,
) -> dvel_preferred_tip_t {
    if ledger.is_null() {
        return dvel_preferred_tip_t {
            tip: dvel_hash_t { bytes: [0u8; 32] },
            score: 0,
            has_value: false,
        };
    }

    let l = unsafe { &*ledger };

    let kind = match policy {
        dvel_weight_policy_t::DVEL_WEIGHT_UNIT => LocalPolicyKind::Unit,
        dvel_weight_policy_t::DVEL_WEIGHT_LATEST_PER_AUTHOR_UNIT => {
            LocalPolicyKind::LatestPerAuthorUnit
        }
    };

    match select_preferred_tip_score(l, kind, max_steps) {
        Some((tip, score)) => dvel_preferred_tip_t {
            tip: from_hash(&tip),
            score,
            has_value: true,
        },
        None => dvel_preferred_tip_t {
            tip: dvel_hash_t { bytes: [0u8; 32] },
            score: 0,
            has_value: false,
        },
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn dvel_ledger_get_tips(
    ledger: *const Ledger,
    out: *mut dvel_hash_t,
    max: usize,
) -> usize {
    if ledger.is_null() || out.is_null() || max == 0 {
        return 0;
    }

    unsafe {
        let l = &*ledger;
        let tips = l.get_tips();

        let mut n = 0usize;
        for h in tips.iter() {
            if n >= max {
                break;
            }
            *out.add(n) = dvel_hash_t { bytes: *h };
            n += 1;
        }

        n
    }
}

// ----------------
// Sybil overlay FFI (latest-per-author + quarantine)
// ----------------

#[unsafe(no_mangle)]
pub extern "C" fn dvel_sybil_overlay_new() -> *mut SybilOverlay {
    Box::into_raw(Box::new(SybilOverlay::new(SybilConfig::default())))
}

#[unsafe(no_mangle)]
pub extern "C" fn dvel_sybil_overlay_free(ptr: *mut SybilOverlay) {
    if !ptr.is_null() {
        unsafe {
            drop(Box::from_raw(ptr));
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn dvel_sybil_overlay_set_config(
    overlay: *mut SybilOverlay,
    cfg: *const dvel_sybil_config_t,
) {
    if overlay.is_null() || cfg.is_null() {
        return;
    }
    unsafe {
        let o = &mut *overlay;
        let c = &*cfg;
        o.cfg = SybilConfig {
            warmup_ticks: c.warmup_ticks,
            quarantine_ticks: c.quarantine_ticks,
            policy: EquivocationPolicy::Quarantine,
            fixed_point_scale: c.fixed_point_scale,
            max_link_walk: c.max_link_walk,
            slash_percent: 5, // Default 5% economic penalty
        };
    }
}

// Trace recorder (for external proof systems)
#[unsafe(no_mangle)]
pub extern "C" fn dvel_trace_recorder_new() -> *mut TraceRecorder {
    Box::into_raw(Box::new(TraceRecorder::new()))
}

#[unsafe(no_mangle)]
pub extern "C" fn dvel_trace_recorder_free(ptr: *mut TraceRecorder) {
    if !ptr.is_null() {
        unsafe {
            drop(Box::from_raw(ptr));
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn dvel_trace_recorder_clear(ptr: *mut TraceRecorder) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        (&mut *ptr).clear();
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn dvel_trace_recorder_len(ptr: *const TraceRecorder) -> usize {
    if ptr.is_null() {
        return 0;
    }
    unsafe { (&*ptr).len() }
}

#[unsafe(no_mangle)]
pub extern "C" fn dvel_trace_recorder_get(
    ptr: *const TraceRecorder,
    idx: usize,
    out_row: *mut dvel_trace_row_t,
) -> bool {
    if ptr.is_null() || out_row.is_null() {
        return false;
    }
    unsafe {
        let rec = &*ptr;
        if idx >= rec.len() {
            return false;
        }
        let row = from_trace_row(&rec.rows()[idx]);
        *out_row = row;
    }
    true
}

#[unsafe(no_mangle)]
pub extern "C" fn dvel_sybil_overlay_attach_trace_recorder(
    overlay: *mut SybilOverlay,
    recorder: *mut TraceRecorder,
) {
    if overlay.is_null() {
        return;
    }
    unsafe {
        let o = &mut *overlay;
        if recorder.is_null() {
            o.attach_trace_recorder(None);
        } else {
            o.attach_trace_recorder(Some(recorder));
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn dvel_sign_event(
    event: *const dvel_event_t,
    secret_key: *const dvel_hash_t,
    out_sig: *mut dvel_sig_t,
) {
    if event.is_null() || secret_key.is_null() || out_sig.is_null() {
        return;
    }
    unsafe {
        let ev = to_event(&*event);
        let sk = &*secret_key;
        let sig = compute_signature_with_secret(&ev, &sk.bytes);
        (*out_sig).bytes = sig;
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn dvel_sybil_overlay_observe_event(
    overlay: *mut SybilOverlay,
    ledger: *const Ledger,
    tick: u64,
    observer_node: u32,
    event_hash: *const dvel_hash_t,
) {
    if overlay.is_null() || ledger.is_null() || event_hash.is_null() {
        return;
    }

    unsafe {
        let l = &*ledger;
        let h = to_hash(&*event_hash);

        if let Some(ev) = l.get_event(&h) {
            let o = &mut *overlay;
            o.observe_event(l, tick, observer_node, ev, h);
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn dvel_sybil_overlay_author_weight_fp(
    overlay: *const SybilOverlay,
    tick: u64,
    author: dvel_pubkey_t,
) -> u64 {
    if overlay.is_null() {
        return 0;
    }

    unsafe {
        let o = &*overlay;
        o.author_weight_fp(tick, author.bytes)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn dvel_select_preferred_tip_sybil(
    ledger: *const Ledger,
    overlay: *const SybilOverlay,
    tick: u64,
    max_steps: usize,
) -> dvel_preferred_tip_t {
    if ledger.is_null() || overlay.is_null() {
        return dvel_preferred_tip_t {
            tip: dvel_hash_t { bytes: [0u8; 32] },
            score: 0,
            has_value: false,
        };
    }

    unsafe {
        let l = &*ledger;
        let o = &*overlay;

        match select_preferred_tip_score_sybil(l, o, tick, max_steps) {
            Some((tip, score)) => dvel_preferred_tip_t {
                tip: from_hash(&tip),
                score,
                has_value: true,
            },
            None => dvel_preferred_tip_t {
                tip: dvel_hash_t { bytes: [0u8; 32] },
                score: 0,
                has_value: false,
            },
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn dvel_ledger_merkle_root(
    ledger: *const Ledger,
    out_root: *mut dvel_merkle_root_t,
) -> bool {
    if ledger.is_null() || out_root.is_null() {
        return false;
    }
    unsafe {
        let l = &*ledger;
        let res = l.merkle_root();
        match res {
            Some(root) => {
                (*out_root).root = from_hash(&root);
                (*out_root).has_value = true;
                true
            }
            None => {
                (*out_root).root = dvel_hash_t { bytes: [0u8; 32] };
                (*out_root).has_value = false;
                false
            }
        }
    }
}
