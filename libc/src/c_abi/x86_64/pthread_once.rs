//! Bounded Linux/x86-64 static `pthread_once`/C11 `call_once` artifact.
//!
//! This leaf preserves the selected normal and canceled-initializer paths from pinned musl 1.2.6 release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license recorded in `COPYRIGHT`:
//!
//! - `src/thread/pthread_once.c::{__pthread_once,__pthread_once_full}` maps
//!   the `0 -> 1 -> 2` initializer state and its contended `3` waiter state.
//! - `src/thread/call_once.c` maps C11 `call_once` directly to that same
//!   pthread once state machine.
//! - `src/thread/__wait.c::__wait` and
//!   `src/internal/pthread_impl.h::__wake` supply the private futex wait and
//!   wake shape used when another selected worker owns initialization.
//!
//! A four-byte aligned `pthread_once_t`/C11 `once_flag` initialized to zero
//! may run one non-null initializer. A first caller changes zero to `1`;
//! contending callers mark `1` as `3` and wait with `FUTEX_WAIT_PRIVATE`.
//! Normal completion exchanges `2` and wakes all waiters only if the prior
//! value was `3`. A cleanup handler resets the state to zero if cancellation
//! or exit of a selected pthread worker interrupts the initializer, waking
//! waiters so one can retry. This artifact does not promise cleanup for
//! unselected threads.
//! The acquire fast path makes completed initializer effects visible without C
//! `errno` publication.
//!
//! Recursive same-control entry, fork/atfork interaction, dynamic/loader TLS,
//! TSS, general pthread/C11 synchronization, family promotion, and public x86
//! support remain outside this private artifact. Musl's weak `pthread_once`
//! ELF-alias binding is retained as the provider boundary below; it does not
//! widen this behavior.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 pthread/C11 once leaf requires little-endian Linux/x86-64");

use core::ffi::c_int;

use super::{atomic, pthread_cancel, raw_syscall};

// This is musl's `weak_alias(__pthread_once,pthread_once)` source form. The
// Rust item retains its direct internal spelling while ELF callers receive a
// weak public alias of the hidden provider.
core::arch::global_asm!(
    ".hidden __pthread_once",
);

const ONCE_INITIAL: c_int = 0;
const ONCE_INITIALIZING: c_int = 1;
const ONCE_COMPLETE: c_int = 2;
const ONCE_WAITERS: c_int = 3;

const FUTEX_WAIT: i64 = 0;
const FUTEX_WAKE: i64 = 1;
const FUTEX_PRIVATE_FLAG: i64 = 128;
const FUTEX_WAIT_PRIVATE: i64 = FUTEX_WAIT | FUTEX_PRIVATE_FLAG;
const FUTEX_WAKE_PRIVATE: i64 = FUTEX_WAKE | FUTEX_PRIVATE_FLAG;

type OnceRoutine = unsafe extern "C" fn();

/// Wait until a selected control leaves the contended state.
///
/// The raw result is deliberately ignored. `EAGAIN`, `EINTR`, and a normal
/// wake all retry the selected `3` state. This retains musl's bounded
/// pause-spin and private-futex recheck shape before returning to the outer
/// compare/exchange loop.
///
/// # Safety
///
/// `control` must designate one live, four-byte-aligned selected once word.
/// Every concurrent access to that word must use this state machine or an
/// atomic operation compatible with it.
#[inline(always)]
unsafe fn wait_selected_once(control: *mut c_int) {
    // Retain musl's small no-syscall window before the kernel wait. The
    // acquire recheck avoids sleeping after an initializer has already
    // published completion.
    let mut spins = 100;
    while spins > 0 {
        if unsafe { atomic::x86_64_load_acquire_i32(control) } != ONCE_WAITERS {
            return;
        }
        core::hint::spin_loop();
        spins -= 1;
    }

    // Linux may report EAGAIN, EINTR, or a spurious wake. As in musl's
    // `__wait`, none is a C API result: retry only while the precise state
    // remains contended.
    while unsafe { atomic::x86_64_load_acquire_i32(control) } == ONCE_WAITERS {
        // SAFETY: Linux x86-64 futex=202 receives uaddr, private wait op,
        // expected state 3, and a null timeout in r10. The caller owns the
        // control-word lifetime while the kernel may observe it.
        let _ = unsafe {
            raw_syscall::syscall4(
                raw_syscall::SYS_FUTEX,
                control as usize as i64,
                FUTEX_WAIT_PRIVATE,
                ONCE_WAITERS as i64,
                0,
            )
        };
    }
}

/// Wake all selected once waiters after completion.
///
/// # Safety
///
/// `control` must designate one live, four-byte-aligned selected once word
/// whose state was just released from this state machine.
#[inline(always)]
unsafe fn wake_selected_once_waiters(control: *mut c_int) {
    // SAFETY: musl's `__wake(control, -1, 1)` normalizes its all-waiters
    // sentinel to INT_MAX before the raw futex request. Linux x86-64
    // futex=202 therefore receives uaddr, private wake op, and 0x7fffffff.
    // The selected object stays live through the state publication and wake
    // handoff.
    let _ = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_FUTEX,
            control as usize as i64,
            FUTEX_WAKE_PRIVATE,
            c_int::MAX as i64,
        )
    };
}

/// Reset an interrupted initializer and release every waiter for a retry.
///
/// # Safety
/// `argument` must be the live, aligned once control whose initializer owns
/// state 1 or 3. The cleanup chain invokes this before the selected worker
/// stack or control argument can be retired.
unsafe extern "C" fn undo_selected_once(argument: *mut core::ffi::c_void) {
    let control = argument.cast::<c_int>();
    // Musl's cleanup undo exchanges the control to zero. When the previous
    // state was 3, the waiter bit would otherwise be lost before wake-all.
    if unsafe { atomic::x86_64_swap_acqrel_i32(control, ONCE_INITIAL) } == ONCE_WAITERS {
        // SAFETY: undo runs while the once control remains live and a previous
        // state of 3 proves at least one selected waiter can be asleep on it.
        unsafe { wake_selected_once_waiters(control) };
    }
}

/// Execute the shared selected pthread/C11 once state machine.
///
/// # Safety
///
/// `control` must designate a live, four-byte-aligned zero-initialized once
/// control for its entire concurrent lifetime. `init_routine` must be a
/// non-null C function that returns normally exactly when called; it must not
/// cancel or terminate its thread, re-enter this control, or destroy/reuse
/// the control while any selected caller can observe it. Every concurrent
/// caller must use this same selected once protocol.
#[inline(always)]
unsafe fn run_selected_once(control: *mut c_int, init_routine: OnceRoutine) -> c_int {
    // Musl's volatile completed fast path has an acquire barrier. The x86
    // atomic helper makes that edge explicit while preserving no-syscall
    // completion after a prior initializer has published state 2.
    if unsafe { atomic::x86_64_load_acquire_i32(control) } == ONCE_COMPLETE {
        return 0;
    }

    loop {
        // SAFETY: the caller owns a live aligned control word and requires
        // every concurrent access to share this atomic state machine.
        let observed = unsafe {
            atomic::x86_64_compare_exchange_acqrel_i32(
                control,
                ONCE_INITIAL,
                ONCE_INITIALIZING,
            )
        };
        match observed {
            ONCE_INITIAL => {
                // The cleanup chain returns this control to its initial state
                // if pthread cancellation or thread exit abandons the callback.
                let mut cleanup = core::mem::MaybeUninit::<pthread_cancel::CleanupNode>::uninit();
                // SAFETY: the node lives on this call's stack until either a
                // normal pop below or selected worker cleanup during exit.
                unsafe {
                    pthread_cancel::_pthread_cleanup_push(
                        cleanup.as_mut_ptr(),
                        Some(undo_selected_once),
                        control.cast(),
                    )
                };
                // SAFETY: caller supplies a non-null initializer. The once
                // cleanup remains registered across cancellation/exit.
                unsafe { init_routine() };
                // SAFETY: callback returned normally, so this caller still
                // owns state 1/3 and removes its cleanup node before publish.
                unsafe { pthread_cancel::_pthread_cleanup_pop(cleanup.as_mut_ptr(), 0) };
                // SAFETY: this initializer owns state 1 and publishes state 2
                // with the release half of the locked x86 exchange.
                if unsafe { atomic::x86_64_swap_acqrel_i32(control, ONCE_COMPLETE) }
                    == ONCE_WAITERS
                {
                    // SAFETY: the control remains live under the caller's
                    // once-object lifetime while wake observes it.
                    unsafe { wake_selected_once_waiters(control) };
                }
                return 0;
            }
            ONCE_INITIALIZING => {
                // The transition can race completion. In that case the
                // following futex wait receives EAGAIN and the loop observes
                // state 2, exactly as musl's `a_cas(1, 3); __wait(..., 3)`.
                // SAFETY: the selected caller lifetime keeps the aligned
                // control word live for the compare/exchange.
                let _ = unsafe {
                    atomic::x86_64_compare_exchange_acqrel_i32(
                        control,
                        ONCE_INITIALIZING,
                        ONCE_WAITERS,
                    )
                };
                // SAFETY: the control lifetime is retained across this
                // private futex observation.
                unsafe { wait_selected_once(control) };
            }
            ONCE_WAITERS => {
                // SAFETY: the control lifetime is retained across this
                // private futex observation.
                unsafe { wait_selected_once(control) };
            }
            ONCE_COMPLETE => return 0,
            // Invalid values are outside the selected object contract. Musl
            // simply retries its outer loop rather than manufacturing an
            // errno result, so retain that closed normal-path behavior.
            _ => core::hint::spin_loop(),
        }
    }
}

// Musl's `src/thread/pthread_once.c` object.
static_archive_member! { pthread_once_source {
    // Musl defines this alias beside its target, in the same object.
    core::arch::global_asm!(
        ".weak pthread_once",
        ".set pthread_once, __pthread_once",
    );

    /// Run a selected POSIX pthread once initializer.
    ///
    /// # Safety
    ///
    /// `control` must designate a live, four-byte-aligned `pthread_once_t` with
    /// the selected zero initializer and must outlive every concurrent call.
    /// `init_routine` must be non-null and must not recursively enter the same
    /// control or cross fork/atfork transitions. Cancellation or exit of a
    /// selected pthread worker during initialization resets this control and
    /// allows a waiting selected caller to retry. This artifact does not promise
    /// cleanup for unselected threads. The control must not be destroyed or
    /// reused while active. The routine and all callers must follow the selected
    /// private once protocol.
    #[export_name = "__pthread_once"]
    pub unsafe extern "C" fn pthread_once(
        control: *mut c_int,
        init_routine: Option<OnceRoutine>,
    ) -> c_int {
        // SAFETY: a null function pointer violates the concrete C caller
        // obligations above, just as it lies outside the selected musl route.
        let init_routine = unsafe { init_routine.unwrap_unchecked() };
        // SAFETY: the public C obligations above exactly establish the selected
        // shared once state-machine and callback lifetime.
        unsafe { run_selected_once(control, init_routine) }
    }
}}

// Musl's `src/thread/call_once.c` object.
static_archive_member! { call_once_source {
    /// Run a selected C11 once initializer through the private shared state
    /// machine rather than an interposable pthread C symbol.
    ///
    /// # Safety
    ///
    /// `flag` must designate a live, four-byte-aligned `once_flag` with
    /// `ONCE_FLAG_INIT` representation and must outlive every concurrent call.
    /// `function` must be non-null and must not recursively enter the same flag or
    /// cross fork/atfork transitions. Cancellation or exit of a selected pthread
    /// worker during initialization resets the flag and allows a waiting selected
    /// caller to retry. This artifact does not promise cleanup for unselected
    /// threads. The flag must not be destroyed or reused while active. The
    /// routine and all callers must follow the selected private once protocol.
    #[no_mangle]
    pub unsafe extern "C" fn call_once(flag: *mut c_int, function: Option<OnceRoutine>) {
        // SAFETY: a null function pointer violates the concrete C caller
        // obligations above, just as it lies outside the selected musl route.
        let function = unsafe { function.unwrap_unchecked() };
        // SAFETY: the public C obligations above establish the selected shared
        // state-machine and callback lifetime without crossing a pthread C ABI.
        let _ = unsafe { run_selected_once(flag, function) };
    }
}}
