//! Selected static Linux/x86-64 `sync` C ABI leaf.
//!
//! This leaf owns exactly `void sync(void)`. It preserves pinned musl 1.2.6's
//! direct `src/unistd/sync.c` mapping: issue `__syscall(SYS_sync)` and discard
//! Linux's raw result because the public C spelling is void. Linux 5.10's
//! `sync=162` request has no pointer, descriptor, errno, cancellation, TLS,
//! allocation, locale, pathname, or process-policy parameter. A normal return
//! establishes only that the system-wide kernel/filesystem writeback request
//! was issued; it does not promise a writeback schedule, storage-cache flush,
//! power-loss durability, `syncfs`, `fsync`, `fdatasync`, or any broader
//! filesystem policy.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//! `src/unistd/sync.c::sync` is exactly `__syscall(SYS_sync);`. Unlike musl's
//! cancellation-point descriptor synchronization entries, this source itself
//! has no `syscall_cp` or runtime-state dependency, so the selected static
//! archive retains the direct raw syscall boundary without an errno bridge.

use super::raw_syscall;

/// Request Linux system-wide filesystem writeback.
///
/// This C ABI has no status result. The kernel owns all writeback timing and
/// persistence semantics; callers must not infer media-cache or power-loss
/// durability from the return to this void function.
#[no_mangle]
pub extern "C" fn sync() {
    // SAFETY: Linux/x86-64 `sync=162` takes no arguments. Musl deliberately
    // discards its raw result because `sync` has a void public C ABI.
    let _ = unsafe { raw_syscall::syscall0(raw_syscall::SYS_SYNC) };
}
