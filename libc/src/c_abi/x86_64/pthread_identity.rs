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
//! Static Initial TLS v1 owns the `%fs:0` self word and reserves `%fs:32` for
//! exactly one opaque `SelectedWorkerCancellation *`. The cache lets the
//! selected cancellation signal path read current state without a registry
//! lock, dynamic TLS lookup, allocation, or interposition. It names no full
//! musl `struct pthread` and exposes no field to C: create/join publishes only
//! a live selected state before a callback can receive SIGCANCEL, and clears
//! it before that state can be retired. The dynamic TLS owner reserves the
//! same word and never dereferences it. The installed x86 C header deliberately
//! leaves the C `struct __pthread` incomplete. The sibling bounded create/join
//! leaf returns the same TP value as its selected worker's `pthread_t`, so C's
//! `pthread_equal` macro remains correct as ordinary pointer equality.
//!
//! This leaf is deliberately static-only. It selects no dereferenceable TCB
//! layout, thread list, detached lifecycle, cancellation state machine, TSD,
//! lock, dynamic TLS/DTV, loader handoff, or general C11 thread
//! implementation. In particular, a future loader-owned dynamic-TLS
//! transition must preserve this identity and the opaque `%fs:32` cache before
//! it can reuse this static evidence.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 pthread identity leaf requires little-endian Linux/x86-64");

use core::arch::asm;
use core::sync::atomic::{AtomicUsize, Ordering};

use super::pthread_cancel::SelectedWorkerCancellation;

const CANCELLATION_STATE_POINTER_OFFSET: usize = 32;

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

/// Publish the current selected cancellation state in the reserved `%fs:32`
/// word.
///
/// This is the only libc writer of that concrete TCB word. The caller must
/// run on a selected x86 task whose TLS owner materialized the documented
/// aligned zero word. It must publish the fully initialized state before
/// callback entry or SIGCANCEL unmask, and clear it only after cancellation is
/// disabled and any current-thread cleanup owner has finished using it.
///
/// # Safety
///
/// `state` must be either null or point to a live
/// [`SelectedWorkerCancellation`] whose storage remains mapped until a later
/// release store clears this task's cache. Concurrent readers use only atomic
/// loads through [`current_selected_cancellation_state`].
#[inline(always)]
pub(super) unsafe fn publish_current_selected_cancellation_state(
    state: *const SelectedWorkerCancellation,
) {
    let thread_pointer = current_thread_pointer();
    debug_assert!(!thread_pointer.is_null());
    // SAFETY: the static and dynamic x86 TLS owners reserve this exact aligned
    // word for an atomic opaque pointer. This caller establishes the lifetime
    // and publish/clear ordering documented above.
    unsafe {
        AtomicUsize::from_ptr(
            thread_pointer
                .add(CANCELLATION_STATE_POINTER_OFFSET)
                .cast::<usize>(),
        )
    }
    .store(state as usize, Ordering::Release);
}

/// Clear this task's selected cancellation-state cache before task retirement.
///
/// The caller must first disable current-task cancellation and complete any
/// state owner that still needs the cache (such as orphaned FILE-lock repair).
/// It must not use this for an ordinary final-process exit, whose callbacks
/// and stream flush may still observe current cancellation state.
#[inline(always)]
pub(super) unsafe fn clear_current_selected_cancellation_state() {
    // SAFETY: this is the documented null publication after the current task
    // has finished every selected cancellation-state user.
    unsafe { publish_current_selected_cancellation_state(core::ptr::null()) }
}

/// Load an owned task's opaque selected cancellation-state cache without a
/// lock.
///
/// The SIGCANCEL handler and syscall-cancellation leaf may use this immediate
/// acquire load only after they have established that the current task uses an
/// owned static or materialized-dynamic x86 TCB. A foreign `%fs` base need not
/// reserve this word or leave it zero, so its value is not an identity or
/// provenance test. Within an owned TCB, null means the task has not reached
/// selected callback entry or has committed its selected state to retirement.
#[inline(always)]
pub(super) fn current_selected_cancellation_state() -> *const SelectedWorkerCancellation {
    let thread_pointer = current_thread_pointer();
    if thread_pointer.is_null() {
        return core::ptr::null();
    }
    // SAFETY: both selected TLS owners reserve this aligned word for the
    // atomic cache. An acquire load pairs with create/join's release
    // publication and performs no registry, TLS-GD, allocator, or libc work.
    unsafe {
        AtomicUsize::from_ptr(
            thread_pointer
                .add(CANCELLATION_STATE_POINTER_OFFSET)
                .cast::<usize>(),
        )
    }
    .load(Ordering::Acquire) as *const SelectedWorkerCancellation
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
