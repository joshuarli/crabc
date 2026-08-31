//! Immutable x86 static-startup secure-execution fact.
//!
//! This private companion to super::static_startup caches only musl's
//! secure-execution decision from the already validated initial auxiliary
//! vector before callbacks. It neither retains nor exposes the vector: the
//! separate super::auxv_observation leaf remains the sole owner of raw
//! __getauxval/weak-getauxval observation.
//!
//! Translation provenance is musl 1.2.6 release commit
//! 9fa28ece75d8a2191de7c5bb53bed224c5947417, under musl's MIT license:
//! src/env/__libc_start_main.c makes libc.secure true when the last
//! AT_SECURE value is nonzero or the final AT_UID/AT_EUID or
//! AT_GID/AT_EGID values differ. The cache exists solely for
//! super::secure_environment::secure_getenv, not privilege management,
//! descriptor hygiene, credential mutation, loader policy, or process
//! lifecycle.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("x86 startup security requires little-endian Linux/x86-64");

use core::sync::atomic::{AtomicBool, Ordering};

const AT_NULL: usize = 0;
const AT_UID: usize = 11;
const AT_EUID: usize = 12;
const AT_GID: usize = 13;
const AT_EGID: usize = 14;
const AT_SECURE: usize = 23;
const MAX_AUXV_ENTRIES: usize = 4_096;

static INITIAL_SECURE: AtomicBool = AtomicBool::new(false);
static INITIAL_SECURE_READY: AtomicBool = AtomicBool::new(false);

/// Derive musl's cached secure-execution fact from a validated auxv.
///
/// Each repeated relevant tag overwrites its prior value, exactly as musl's
/// startup array does, so the last matching auxiliary-vector value supplies
/// the decision.
unsafe fn secure_from_auxv(auxv: *const usize) -> bool {
    let mut uid = 0usize;
    let mut euid = 0usize;
    let mut gid = 0usize;
    let mut egid = 0usize;
    let mut at_secure = 0usize;

    for index in 0..MAX_AUXV_ENTRIES {
        let offset = index * 2;
        // SAFETY: static startup validated pairs through AT_NULL before this
        // one-time private cache handoff.
        let kind = unsafe { core::ptr::read(auxv.add(offset)) };
        if kind == AT_NULL {
            break;
        }
        // SAFETY: every non-terminating auxv record has its paired value.
        let value = unsafe { core::ptr::read(auxv.add(offset + 1)) };
        match kind {
            AT_UID => uid = value,
            AT_EUID => euid = value,
            AT_GID => gid = value,
            AT_EGID => egid = value,
            AT_SECURE => at_secure = value,
            _ => {}
        }
    }

    at_secure != 0 || uid != euid || gid != egid
}

/// Cache validated initial secure-execution state before callbacks.
///
/// # Safety
///
/// auxv must be the immutable initial Linux auxiliary-vector sequence with
/// an AT_NULL within MAX_AUXV_ENTRIES records. Static startup calls this once
/// before application callbacks; it is not a public reinitialization API.
pub(super) unsafe fn install_initial(auxv: *const usize) {
    debug_assert!(!auxv.is_null());
    let secure = unsafe { secure_from_auxv(auxv) };
    INITIAL_SECURE.store(secure, Ordering::Relaxed);
    INITIAL_SECURE_READY.store(true, Ordering::Release);
}

/// Return musl's cached initial secure-execution decision.
#[inline]
pub(super) fn is_secure() -> bool {
    INITIAL_SECURE_READY.load(Ordering::Acquire) && INITIAL_SECURE.load(Ordering::Acquire)
}
