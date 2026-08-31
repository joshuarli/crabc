//! Selected static Linux/x86-64 C `mq_setattr(3)` boundary.
//!
//! This leaf owns only the direct three-word POSIX message-queue attribute
//! update entry point. It forwards one queue descriptor plus optional input
//! and output LP64 `struct mq_attr` pointers to Linux
//! `mq_getsetattr=245` in `rdi`/`rsi`/`rdx`, then maps the raw status through
//! the selected initial-TLS C `errno` boundary. It does not select queue
//! opening, closing, unlinking, send/receive, notification, timed operations,
//! descriptor policy, general IPC, libc.so, CRT, loader, sysroot, or public
//! x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/mq/mq_setattr.c` maps to [`mq_setattr`] and its direct Linux
//!   `mq_getsetattr=245` request.
//!
//! Musl's selected source has no cancellation-point, queue-name translation,
//! allocation, or fallback path. This direct x86 leaf preserves only that
//! source-closed syscall boundary.

use core::ffi::{c_int, c_long, c_void};
use core::mem::{align_of, offset_of, size_of};

use super::{c_status, raw_syscall};

/// Layout-only Linux/x86-64 LP64 `struct mq_attr` view.
///
/// The wrapper does not read either pointer. Keeping this private record pins
/// the selected C header's 64-byte input/output layout without selecting the
/// other POSIX message-queue functions or a Rust queue abstraction.
#[repr(C)]
struct MqAttr {
    flags: c_long,
    maximum_messages: c_long,
    message_size: c_long,
    current_messages: c_long,
    reserved: [c_long; 4],
}

const _: () = {
    assert!(size_of::<MqAttr>() == 64);
    assert!(align_of::<MqAttr>() == 8);
    assert!(offset_of!(MqAttr, flags) == 0);
    assert!(offset_of!(MqAttr, maximum_messages) == 8);
    assert!(offset_of!(MqAttr, message_size) == 16);
    assert!(offset_of!(MqAttr, current_messages) == 24);
    assert!(offset_of!(MqAttr, reserved) == 32);
};

/// Replace one queue's status flags and optionally report its prior attributes.
///
/// # Safety
///
/// `new_attributes` must point to a readable x86 LP64 `struct mq_attr` for the
/// syscall duration. `old_attributes` must be null or point to writable
/// storage for that same 64-byte record. The queue descriptor must remain open
/// for the call; queue naming, creation, close/unlink, message transfer,
/// notification, synchronization, and ownership policy remain with the C
/// caller. Null or inaccessible pointers intentionally reach Linux unchanged
/// and use its ordinary direct error result.
#[no_mangle]
pub unsafe extern "C" fn mq_setattr(
    queue_descriptor: c_int,
    new_attributes: *const c_void,
    old_attributes: *mut c_void,
) -> c_int {
    // SAFETY: the caller owns both record-pointer and descriptor-lifetime
    // contracts. Linux/x86-64 receives the exact three C ABI words in
    // rdi/rsi/rdx and validates their current values.
    c_status(unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_MQ_GETSETATTR,
            i64::from(queue_descriptor),
            new_attributes as usize as i64,
            old_attributes as usize as i64,
        )
    })
}
