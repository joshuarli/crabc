//! Static Linux/x86-64 POSIX `_exit` forwarding boundary.
//!
//! This leaf owns exactly POSIX [`_exit`]. It is a no-return forwarding C ABI
//! boundary to the separately selected C11 [`super::immediate_termination::_Exit`]
//! leaf; it has no raw syscall, no errno, TLS, callback, allocator, lock, or
//! mutable lifecycle state of its own. It does not establish ordinary `exit`,
//! `abort`, `atexit`, `at_quick_exit`, `quick_exit`, stdio flushing,
//! fini/destructor processing, fork coordination, pthread lifecycle, a dynamic
//! libc, CRT, loader, sysroot, allocator, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//! `src/unistd/_exit.c` is the complete C source for this boundary. It
//! includes `<unistd.h>` and `<stdlib.h>`, then forwards `_exit(status)`
//! directly to `_Exit(status)`. The sibling C11 leaf retains musl's Linux
//! `exit_group` then defensive `exit` syscall behavior; this leaf deliberately
//! adds no process-control or lifecycle mechanism around that direct call.

use core::ffi::c_int;

use super::immediate_termination;

/// Immediately terminate the process through the selected C11 sibling.
///
/// Musl's complete POSIX source is this direct no-return forwarding call. Keep
/// it separately visible so the POSIX `<unistd.h>` declaration and static
/// archive relation have their own bounded evidence without widening C11
/// immediate termination or ordinary-exit ownership.
#[no_mangle]
#[inline(never)]
pub extern "C" fn _exit(status: c_int) -> ! {
    immediate_termination::_Exit(status)
}
