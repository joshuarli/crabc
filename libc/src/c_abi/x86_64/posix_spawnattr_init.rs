//! Selected static Linux/x86-64 POSIX spawn-attribute initialization C ABI.
//!
//! Pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license,
//! maps `src/process/posix_spawnattr_init.c::posix_spawnattr_init` directly
//! to [`posix_spawnattr_init`]. Its complete body assigns a zero-initialized
//! `posix_spawnattr_t` to the caller's record and returns zero.
//!
//! The x86-64 public header fixes that record at 336 bytes with eight-byte
//! alignment. Keeping the local representation makes this target-private
//! composition boundary explicit while preserving the generic AArch64 export
//! and behavior exactly: a valid writable full record becomes all zero bytes
//! and success leaves errno untouched. The exported pointer uses `c_void` so
//! the System V AMD64 pointer ABI remains exact without leaking this private
//! Rust layout into a Rust-facing API.
//!
//! This private static artifact selects only caller-owned attribute-record
//! initialization. It has no allocation, errno, TLS, syscall, spawn, fork,
//! exec, child lifecycle, file-action, signal, scheduler-policy, libc.so,
//! CRT, loader, sysroot, family-completion, promotion, or public x86 support
//! claim.

use core::{
    ffi::{c_int, c_ulong, c_void},
    mem::{align_of, size_of},
};

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_endian = "little"
)))]
compile_error!("the x86 POSIX spawn-attribute initializer requires little-endian Linux/x86-64");

// This is the installed `<spawn.h>` `posix_spawnattr_t` layout. It stays
// private because the selected C boundary owns only zero initialization.
#[repr(C)]
struct PosixSpawnAttr {
    flags: c_int,
    process_group: c_int,
    default_signals: [c_ulong; 16],
    signal_mask: [c_ulong; 16],
    priority: c_int,
    policy: c_int,
    implementation: *mut c_void,
    padding: [u8; 64 - size_of::<*mut c_void>()],
}

const _: [(); 336] = [(); size_of::<PosixSpawnAttr>()];
const _: [(); 8] = [(); align_of::<PosixSpawnAttr>()];
const POSIX_SPAWNATTR_INIT_WORDS: usize = size_of::<PosixSpawnAttr>() / size_of::<u64>();
const _: [(); 0] = [(); size_of::<PosixSpawnAttr>() % size_of::<u64>()];

/// Initialize a caller-owned POSIX spawn-attribute record to musl's zero state.
///
/// # Safety
///
/// `attributes` must designate one writable, properly aligned complete x86-64
/// `posix_spawnattr_t` record. A null, dangling, misaligned, aliased, or
/// concurrently accessed pointer is outside the C declaration's contract.
#[no_mangle]
pub unsafe extern "C" fn posix_spawnattr_init(attributes: *mut c_void) -> c_int {
    // Keep this static artifact self-contained: at the selected optimization
    // profile `write_bytes` becomes an external `memset` reference and the
    // volatile intrinsic pulls in Rust's debug precondition machinery. The
    // public record is eight-byte aligned and has an exact whole-word size, so
    // this fixed direct-store loop reproduces musl's complete all-zero
    // assignment without selecting a general memory utility.
    //
    // SAFETY: the entry contract supplies all 42 aligned u64 words. The inline
    // assembly modifies only those words and declares its scratch registers.
    unsafe {
        core::arch::asm!(
            "xor eax, eax",
            "mov ecx, {word_count}",
            "2:",
            "mov qword ptr [{attributes} + rcx * 8 - 8], rax",
            "loop 2b",
            attributes = in(reg) attributes,
            word_count = const POSIX_SPAWNATTR_INIT_WORDS,
            out("rax") _,
            out("rcx") _,
            options(nostack),
        );
    }
    0
}
