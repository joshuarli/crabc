//! Selected static Linux/x86-64 POSIX spawn-attribute signal-field C ABI.
//!
//! Pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license,
//! maps five independent source leaves to this one bounded provider block:
//! `src/process/posix_spawnattr_setflags.c::posix_spawnattr_setflags`,
//! `src/process/posix_spawnattr_setsigmask.c::posix_spawnattr_setsigmask`,
//! `src/process/posix_spawnattr_getsigmask.c::posix_spawnattr_getsigmask`,
//! `src/process/posix_spawnattr_setsigdefault.c::posix_spawnattr_setsigdefault`,
//! and `src/process/posix_spawnattr_getsigdefault.c::posix_spawnattr_getsigdefault`.
//! The flags leaf accepts only musl's bits one through 128 and returns
//! `EINVAL=22` before writing for every other bit. The other four source
//! bodies directly assign the complete 16-word `sigset_t` `__def` or `__mask`
//! fields and return zero.
//!
//! On x86-64 the public 336-byte, eight-byte-aligned `posix_spawnattr_t`
//! places `__flags` at byte zero, `__def` at byte eight, and `__mask` at byte
//! 136. The System V AMD64 ABI passes the first two pointers in `rdi`/`rsi`
//! and a `short` flags value in `esi`, returning the signed `int` status in
//! `eax`. The local assembly copies exactly 128 caller-owned bytes without
//! selecting an allocator or general memory primitive. It preserves musl's
//! `restrict` non-overlap precondition for the four signal-set assignments.
//!
//! This private artifact selects record-field mutation/readback only. It has
//! no errno or TLS mutation, allocation, syscall, signal delivery, spawn or
//! file-action execution, fork, exec, child lifecycle, scheduler behavior,
//! libc.so, CRT, loader, sysroot, family-completion, promotion, or public x86
//! support claim. The generic AArch64 exports and behavior remain unchanged.

use core::ffi::{c_int, c_short, c_ulong, c_void};

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_endian = "little"
)))]
compile_error!("the x86 POSIX spawn-attribute signal-field block requires little-endian Linux/x86-64");

const EINVAL: c_int = 22;
const POSIX_SPAWNATTR_VALID_FLAGS: c_int = 1 | 2 | 4 | 8 | 16 | 32 | 64 | 128;
const POSIX_SPAWNATTR_SIGDEFAULT_OFFSET: usize = 8;
const POSIX_SPAWNATTR_SIGMASK_OFFSET: usize = 136;
const POSIX_SPAWNATTR_SIGSET_WORDS: usize = 16;
const _: [(); 8] = [(); POSIX_SPAWNATTR_SIGDEFAULT_OFFSET];
const _: [(); 136] = [(); POSIX_SPAWNATTR_SIGMASK_OFFSET];
const _: [(); 16] = [(); POSIX_SPAWNATTR_SIGSET_WORDS];

/// Copy musl's complete x86 `sigset_t` storage under the declared restrict
/// contract, without importing a general memory helper into this artifact.
#[inline(always)]
unsafe fn copy_sigset_words(destination: *mut c_ulong, source: *const c_ulong) {
    // SAFETY: each public sigset_t has sixteen aligned c_ulong words. Callers
    // of the C declarations supply distinct, valid objects because both musl
    // source declarations use restrict-qualified pointers.
    unsafe {
        core::arch::asm!(
            "mov rax, [rsi + 0]", "mov [rdi + 0], rax",
            "mov rax, [rsi + 8]", "mov [rdi + 8], rax",
            "mov rax, [rsi + 16]", "mov [rdi + 16], rax",
            "mov rax, [rsi + 24]", "mov [rdi + 24], rax",
            "mov rax, [rsi + 32]", "mov [rdi + 32], rax",
            "mov rax, [rsi + 40]", "mov [rdi + 40], rax",
            "mov rax, [rsi + 48]", "mov [rdi + 48], rax",
            "mov rax, [rsi + 56]", "mov [rdi + 56], rax",
            "mov rax, [rsi + 64]", "mov [rdi + 64], rax",
            "mov rax, [rsi + 72]", "mov [rdi + 72], rax",
            "mov rax, [rsi + 80]", "mov [rdi + 80], rax",
            "mov rax, [rsi + 88]", "mov [rdi + 88], rax",
            "mov rax, [rsi + 96]", "mov [rdi + 96], rax",
            "mov rax, [rsi + 104]", "mov [rdi + 104], rax",
            "mov rax, [rsi + 112]", "mov [rdi + 112], rax",
            "mov rax, [rsi + 120]", "mov [rdi + 120], rax",
            in("rdi") destination,
            in("rsi") source,
            out("rax") _,
            options(nostack, preserves_flags),
        );
    }
}

/// Store musl's validated POSIX spawn flags in a caller-owned attribute record.
///
/// # Safety
///
/// For a valid flag value, `attributes` must name a writable, aligned complete
/// x86-64 `posix_spawnattr_t`. Invalid flags are rejected before musl reaches
/// the pointer, so a null pointer is observable only in that invalid branch.
#[no_mangle]
pub unsafe extern "C" fn posix_spawnattr_setflags(
    attributes: *mut c_void,
    flags: c_short,
) -> c_int {
    if (flags as c_int & !POSIX_SPAWNATTR_VALID_FLAGS) != 0 {
        return EINVAL;
    }
    // SAFETY: the valid-flags C contract supplies the complete aligned record.
    unsafe { core::ptr::write(attributes.cast::<c_int>(), flags as c_int) };
    0
}

/// Copy a caller-supplied complete signal mask into an attribute record.
///
/// # Safety
/// `attributes` and `mask` must name distinct valid aligned complete C objects.
#[no_mangle]
pub unsafe extern "C" fn posix_spawnattr_setsigmask(
    attributes: *mut c_void,
    mask: *const c_void,
) -> c_int {
    // SAFETY: this is musl's direct restrict-qualified field assignment.
    unsafe {
        copy_sigset_words(
            attributes.cast::<u8>().add(POSIX_SPAWNATTR_SIGMASK_OFFSET).cast(),
            mask.cast(),
        );
    }
    0
}

/// Copy an attribute record's complete signal mask into caller-owned storage.
///
/// # Safety
/// `attributes` and `mask` must name distinct valid aligned complete C objects.
#[no_mangle]
pub unsafe extern "C" fn posix_spawnattr_getsigmask(
    attributes: *const c_void,
    mask: *mut c_void,
) -> c_int {
    // SAFETY: this is musl's direct restrict-qualified field assignment.
    unsafe {
        copy_sigset_words(
            mask.cast(),
            attributes.cast::<u8>().add(POSIX_SPAWNATTR_SIGMASK_OFFSET).cast(),
        );
    }
    0
}

/// Copy a caller-supplied complete default-signal set into an attribute record.
///
/// # Safety
/// `attributes` and `default_signals` must name distinct valid aligned C objects.
#[no_mangle]
pub unsafe extern "C" fn posix_spawnattr_setsigdefault(
    attributes: *mut c_void,
    default_signals: *const c_void,
) -> c_int {
    // SAFETY: this is musl's direct restrict-qualified field assignment.
    unsafe {
        copy_sigset_words(
            attributes.cast::<u8>().add(POSIX_SPAWNATTR_SIGDEFAULT_OFFSET).cast(),
            default_signals.cast(),
        );
    }
    0
}

/// Copy an attribute record's complete default-signal set into caller storage.
///
/// # Safety
/// `attributes` and `default_signals` must name distinct valid aligned C objects.
#[no_mangle]
pub unsafe extern "C" fn posix_spawnattr_getsigdefault(
    attributes: *const c_void,
    default_signals: *mut c_void,
) -> c_int {
    // SAFETY: this is musl's direct restrict-qualified field assignment.
    unsafe {
        copy_sigset_words(
            default_signals.cast(),
            attributes.cast::<u8>().add(POSIX_SPAWNATTR_SIGDEFAULT_OFFSET).cast(),
        );
    }
    0
}
