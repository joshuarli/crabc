//! Selected static Linux/x86-64 realtime signal minimum C ABI boundary.
//!
//! This is the exact, standalone adaptation of pinned musl 1.2.6 revision
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417` under musl's MIT license.
//! Its complete source mapping is `src/signal/sigrtmin.c`:
//! `int __libc_current_sigrtmin() { return 35; }`. Musl reserves Linux
//! signals 32 through 34, so the fixed x86 application realtime minimum is
//! 35.
//!
//! This one-symbol direct bridge has no storage, syscall, signal delivery,
//! action, mask, wait, descriptor, timer, pthread, or runtime-policy path.
//! It deliberately does not establish a general realtime-signal family or
//! promote any x86 runtime capability.

use core::ffi::c_int;

const X86_SIGRTMIN: c_int = 35;
const _: [(); 35] = [(); X86_SIGRTMIN as usize];

/// Return musl's fixed x86 application realtime signal minimum.
#[no_mangle]
pub extern "C" fn __libc_current_sigrtmin() -> c_int {
    X86_SIGRTMIN
}
