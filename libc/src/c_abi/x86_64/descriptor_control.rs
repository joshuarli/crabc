//! Selected static Linux/x86-64 C descriptor-control boundary.
//!
//! This leaf owns exactly the status and descriptor-flag forms of public C
//! `fcntl`: `F_GETFD`, `F_SETFD`, `F_GETFL`, and `F_SETFL`. It composes the
//! raw Linux syscall register boundary with the selected initial-TLS C
//! `errno` publisher. It is not generic C `fcntl`, duplication, record/OFD
//! locks, ownership/signalling control, leases, seals, `lockf`, descriptor
//! pathname policy, vector I/O, a filesystem capability, stdio, a general
//! C/POSIX runtime, libc.so, CRT, thread lifecycle, dynamic TLS, loader,
//! sysroot, allocator, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/fcntl/fcntl.c` maps to the selected command dispatch below.
//!
//! Musl passes a raw third word to Linux `fcntl=72`, ORs `O_LARGEFILE` into a
//! `F_SETFL` request, and uses a cancellation-point route only for
//! `F_SETLKW`. The selected direct Linux-5.10 leaf retains the status-control
//! route and `O_LARGEFILE` rule. It deliberately does not select the blocking
//! lock/cancellation path, musl's `F_GETOWN` translation, or its historical
//! `F_DUPFD_CLOEXEC` fallback.
//!
//! C `fcntl` is variadic: legal `F_GETFD` and `F_GETFL` calls have only its
//! two fixed C words, so an ordinary three-argument Rust entry would have an
//! invalid ABI for them. The public assembly shim therefore routes these two
//! commands to a two-word helper that explicitly supplies Linux rdx=0,
//! routes `F_SETFD`/`F_SETFL` to a three-word scalar helper, and rejects every
//! other command before touching rdx. SysV AMD64 places fd/cmd/the first
//! scalar vararg in rdi/rsi/rdx, which is also Linux `fcntl`'s three-word
//! register order.

use core::ffi::c_int;

use super::{c_status, errno, raw_syscall};

const EINVAL: c_int = 22;
const F_GETFD: c_int = 1;
const F_SETFD: c_int = 2;
const F_GETFL: c_int = 3;
const F_SETFL: c_int = 4;
const O_LARGEFILE: c_int = 0x8_000;

/*
 * Keep the public entry in assembly. A C fcntl(fd, F_GETFD) call has no rdx
 * vararg word, while a Rust function with a fixed third parameter would
 * require one. The tail branches preserve the C caller's return address and
 * every argument register needed by the destination helper.
 */
core::arch::global_asm!(
    r#"
    .text
    .p2align 4
    .global fcntl
    .type fcntl,@function
fcntl:
    cmp esi, 1
    je {no_argument}
    cmp esi, 3
    je {no_argument}
    cmp esi, 2
    je {scalar}
    cmp esi, 4
    je {scalar}
    jmp {unsupported}
    .size fcntl, .-fcntl

    .section .note.GNU-stack,"",@progbits
"#,
    no_argument = sym fcntl_no_argument,
    scalar = sym fcntl_scalar,
    unsupported = sym fcntl_unsupported,
);

#[inline(never)]
unsafe extern "C" fn fcntl_no_argument(
    descriptor: c_int,
    command: c_int,
) -> c_int {
    if command != F_GETFD && command != F_GETFL {
        return fcntl_unsupported(descriptor, command);
    }
    // SAFETY: the assembly dispatcher admits only no-vararg commands here;
    // Linux ignores the explicit zero third word for both selected commands.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_FCNTL,
            i64::from(descriptor),
            i64::from(command),
            0,
        )
    };
    c_status(result)
}

#[inline(never)]
unsafe extern "C" fn fcntl_scalar(
    descriptor: c_int,
    command: c_int,
    argument: c_int,
) -> c_int {
    if command != F_SETFD && command != F_SETFL {
        return fcntl_unsupported(descriptor, command);
    }
    let argument = if command == F_SETFL {
        argument | O_LARGEFILE
    } else {
        argument
    };
    // SAFETY: the assembly dispatcher reaches this helper only after C has
    // supplied the scalar vararg in rdx; each selected command takes an int
    // immediate, and Linux validates descriptor, command, and flag bits.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_FCNTL,
            i64::from(descriptor),
            i64::from(command),
            i64::from(argument),
        )
    };
    c_status(result)
}

#[inline(never)]
unsafe extern "C" fn fcntl_unsupported(_descriptor: c_int, _command: c_int) -> c_int {
    // SAFETY: this selected-static profile owns the calling initial-TLS errno
    // slot. Unselected commands must not read an absent vararg, issue a raw
    // syscall, or mutate descriptor state.
    unsafe { errno::set_errno(EINVAL) };
    -1
}
