//! Bounded Linux/x86-64 static pthread/C11 thread-identity leaf.
//!
//! Provenance is fixed to musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license
//! recorded in its `COPYRIGHT` file. The exact mappings are:
//!
//! - `arch/x86_64/pthread_arch.h::__get_tp()` supplies the `%fs:0` read.
//! - `src/internal/pthread_impl.h::__pthread_self()` maps directly to that
//!   thread pointer on x86-64: this target has neither `TLS_ABOVE_TP` nor a
//!   nonzero `TP_OFFSET` adjustment.
//! - `src/thread/pthread_self.c` supplies the weak same-address
//!   `pthread_self`/`thrd_current` aliases.
//! - `src/thread/pthread_equal.c` supplies the weak same-address
//!   `pthread_equal`/`thrd_equal` aliases and their exact 0-or-1 equality
//!   result.
//!
//! Static Initial TLS v1 owns only the `%fs:0` self word, not musl's full
//! `struct pthread` TCB. That is sufficient for this selected opaque-handle
//! boundary because the installed x86 C header deliberately leaves the C
//! `struct __pthread` incomplete. The sibling bounded create/join leaf
//! returns the same TP value as its selected worker's `pthread_t`, so C's
//! `pthread_equal` macro remains correct as ordinary pointer equality.
//!
//! This leaf is deliberately static-only. It selects no dereferenceable TCB
//! layout, thread list, detached lifecycle, cancellation, TSD, lock, dynamic
//! TLS/DTV, loader handoff, or general C11 thread implementation. In
//! particular, a future loader-owned dynamic-TLS transition must preserve this
//! identity before it can reuse this static evidence.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 pthread identity leaf requires little-endian Linux/x86-64");

use core::arch::asm;

/// Read the current x86-64 Variant-II thread pointer from its `%fs:0` self
/// word.
///
/// The selected static startup and bounded child lifecycle establish this word
/// before any selected C entry runs. It is deliberately private so callers
/// obtain an opaque identity only through the C ABI below.
#[inline]
pub(super) fn current_thread_pointer() -> *mut u8 {
    let thread_pointer: usize;
    // SAFETY: the selected static runtime establishes a readable `%fs:0`
    // self word before this leaf runs. The instruction reads that word only;
    // it does not dereference the returned opaque handle or alter TLS state.
    unsafe {
        asm!(
            "mov {thread_pointer}, fs:[0]",
            thread_pointer = out(reg) thread_pointer,
            options(readonly, nostack, preserves_flags),
        );
    }
    thread_pointer as *mut u8
}

// Musl emits all four public symbols as weak, same-address pairs.  Defining
// them here in assembler rather than through Rust's ordinary strong exports
// preserves that archive-level override and address contract.  The function
// bodies are intentionally the exact two operations this leaf admits: the
// Variant-II `%fs:0` identity load and canonical pointer equality.  C++
// callers, and C callers that undefine the equality macros, consequently see
// the same ABI surface without pulling in C11 creation, TSD, or
// synchronization machinery.
core::arch::global_asm!(
    r#"
    .text
    .weak pthread_self
    .type pthread_self,@function
pthread_self:
    mov rax, qword ptr fs:[0]
    ret
    .size pthread_self, .-pthread_self

    .weak thrd_current
    .set thrd_current, pthread_self

    .weak pthread_equal
    .type pthread_equal,@function
pthread_equal:
    xor eax, eax
    cmp rdi, rsi
    sete al
    ret
    .size pthread_equal, .-pthread_equal

    .weak thrd_equal
    .set thrd_equal, pthread_equal

    .section .note.GNU-stack,"",@progbits
"#,
);
