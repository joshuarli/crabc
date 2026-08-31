//! Selected static Linux/x86-64 realtime signal maximum C ABI boundary.
//!
//! This is the exact, standalone adaptation of pinned musl 1.2.6 revision
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417` under musl's MIT license.
//! Its complete source mapping is `src/signal/sigrtmax.c`:
//! `int __libc_current_sigrtmax() { return _NSIG-1; }`. Musl's x86-64
//! `arch/x86_64/bits/signal.h` fixes `_NSIG` at 65, so this C ABI returns 64.
//!
//! This one-symbol macro bridge has no storage, syscall, signal delivery,
//! action, mask, wait, descriptor, timer, pthread, or runtime-policy path.
//! It deliberately does not establish a general realtime-signal family or
//! promote any x86 runtime capability.

use core::ffi::c_int;

const X86_NSIG: c_int = 65;
const X86_SIGRTMAX: c_int = X86_NSIG - 1;
const _: [(); 64] = [(); X86_SIGRTMAX as usize];

/// Return musl's fixed x86 realtime signal maximum.
#[no_mangle]
pub extern "C" fn __libc_current_sigrtmax() -> c_int {
    X86_SIGRTMAX
}
