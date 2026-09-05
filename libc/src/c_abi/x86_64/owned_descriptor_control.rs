//! Installed Linux/x86-64 `fcntl` command and variadic ABI owner.
//!
//! Source: musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417` (MIT, musl `COPYRIGHT`),
//! `src/fcntl/fcntl.c::fcntl`, with Linux 5.10 as the kernel baseline.
//! The frozen private whitelist remains in `descriptor_control.rs`.
//!
//! The assembly entry classifies no-argument, promoted-int, unsigned-long,
//! and pointer commands before entering Rust. In particular legal two-argument
//! queries never acquire an absent third Rust argument. Unrecognized commands
//! use a zero syscall word, preserving kernel descriptor/command errors without
//! reading an unspecified C register. This is the Linux-5.10 command contract,
//! not an ABI for hypothetical future pointer commands.
//!
//! Only POSIX `F_SETLKW` uses `record_locks`' cancellation path. OFD's blocking
//! extension is an ordinary syscall, matching musl. `F_GETOWN` queries
//! `F_GETOWN_EX` and returns a negative process-group ID without errno decoding.
//! Linux 5.10 provides GETOWN_EX and atomic DUPFD_CLOEXEC, so musl's
//! older-kernel owner and duplication fallbacks/workaround are omitted.

use core::ffi::{c_int, c_void};
use super::{c_status, raw_syscall, record_locks};

const F_SETFL: c_int = 4;
const F_GETOWN: c_int = 9;
const F_GETOWN_EX: c_int = 16;
const F_OWNER_PGRP: c_int = 2;
const O_LARGEFILE: c_int = 0x8_000;

// C fcntl has two fixed words. Tail branches preserve the variadic word only
// for a command that defines one; the no-argument helper supplies syscall rdx=0.
// Keep this public entry in its own section for archive garbage collection.
core::arch::global_asm!(
    r#"
    .section .text.fcntl,"ax",@progbits
    .p2align 4
    .global fcntl
    .type fcntl,@function
fcntl:
    cmp esi, 1
    je {no_argument}
    cmp esi, 3
    je {no_argument}
    cmp esi, 9
    je {no_argument}
    cmp esi, 11
    je {no_argument}
    cmp esi, 1025
    je {no_argument}
    cmp esi, 1032
    je {no_argument}
    cmp esi, 1034
    je {no_argument}
    cmp esi, 0
    je {integer}
    cmp esi, 2
    je {integer}
    cmp esi, 4
    je {integer}
    cmp esi, 8
    je {integer}
    cmp esi, 10
    je {integer}
    cmp esi, 1024
    je {integer}
    cmp esi, 1030
    je {integer}
    cmp esi, 1031
    je {integer}
    cmp esi, 1033
    je {integer}
    cmp esi, 5
    je {record_lock}
    cmp esi, 6
    je {record_lock}
    cmp esi, 7
    je {record_lock}
    cmp esi, 15
    je {pointer}
    cmp esi, 16
    je {pointer}
    cmp esi, 17
    je {pointer}
    cmp esi, 36
    je {pointer}
    cmp esi, 37
    je {pointer}
    cmp esi, 38
    je {pointer}
    cmp esi, 1029
    je {pointer}
    cmp esi, 1035
    je {pointer}
    cmp esi, 1036
    je {pointer}
    cmp esi, 1037
    je {pointer}
    cmp esi, 1038
    je {pointer}
    cmp esi, 1026
    je {word}
    jmp {no_argument}
    .size fcntl, .-fcntl
    .section .note.GNU-stack,"",@progbits
"#,
    no_argument = sym fcntl_no_argument,
    integer = sym fcntl_integer,
    pointer = sym fcntl_pointer,
    word = sym fcntl_word,
    record_lock = sym record_locks::fcntl_record_lock,
);

/// A Linux f_owner_ex has two adjacent signed int words on x86-64.
#[repr(C)]
struct Owner {
    kind: c_int,
    id: c_int,
}

const _: () = {
    assert!(core::mem::size_of::<Owner>() == 8);
    assert!(core::mem::align_of::<Owner>() == 4);
};

#[inline(never)]
unsafe extern "C" fn fcntl_no_argument(descriptor: c_int, command: c_int) -> c_int {
    if command == F_GETOWN {
        let mut owner = Owner { kind: 0, id: 0 };
        // SAFETY: the local record is writable for exactly the kernel's two
        // words. No user pointer or optional vararg is read on this route.
        let result = unsafe { raw_syscall::syscall3(
            raw_syscall::SYS_FCNTL, descriptor as i64, F_GETOWN_EX as i64,
            core::ptr::addr_of_mut!(owner) as i64,
        ) };
        if result != 0 { return c_status(result); }
        // A negative process-group ID is data, including -1; errno stays as
        // the caller left it. Linux owner IDs are nonnegative signed pid_t.
        return if owner.kind == F_OWNER_PGRP { -owner.id } else { owner.id };
    }
    c_status(unsafe { raw_syscall::syscall3(
        raw_syscall::SYS_FCNTL, descriptor as i64, command as i64, 0,
    ) })
}

#[inline(never)]
unsafe extern "C" fn fcntl_integer(descriptor: c_int, command: c_int, argument: c_int) -> c_int {
    let argument = if command == F_SETFL { argument | O_LARGEFILE } else { argument };
    // SAFETY: assembly reaches this route only for a promoted-int C vararg;
    // Linux validates the descriptor and the scalar command's argument.
    c_status(unsafe { raw_syscall::syscall3(
        raw_syscall::SYS_FCNTL, descriptor as i64, command as i64, argument as i64,
    ) })
}

#[inline(never)]
unsafe extern "C" fn fcntl_word(descriptor: c_int, command: c_int, argument: usize) -> c_int {
    // SAFETY: F_NOTIFY supplies an unsigned-long event mask, not a pointer.
    c_status(unsafe { raw_syscall::syscall3(
        raw_syscall::SYS_FCNTL, descriptor as i64, command as i64, argument as i64,
    ) })
}

#[inline(never)]
unsafe extern "C" fn fcntl_pointer(descriptor: c_int, command: c_int, argument: *mut c_void) -> c_int {
    // SAFETY: assembly established a pointer-bearing command and its C vararg.
    // Linux copies the command-specific flock/owner/uids/u64 record; Rust
    // neither dereferences nor retains the pointer. The C caller keeps any
    // pointed-to object alive for syscall duration, including OFD_SETLKW waits.
    // Invalid addresses remain kernel EFAULT, without a Rust memory access.
    c_status(unsafe { raw_syscall::syscall3(
        raw_syscall::SYS_FCNTL, descriptor as i64, command as i64, argument as usize as i64,
    ) })
}
