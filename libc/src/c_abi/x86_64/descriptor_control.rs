//! Selected static Linux/x86-64 C descriptor-control boundary.
//!
//! This module owns the shared public `fcntl` assembly dispatch for two
//! separate selected static artifacts: descriptor/status flags (`F_GETFD`,
//! `F_SETFD`, `F_GETFL`, and `F_SETFL`) and the sibling nonblocking
//! record-lock forms (`F_GETLK` and `F_SETLK`). The owned runtime additionally
//! admits the pointer-bearing blocking `F_SETLKW` cancellation point.
//! It composes the Linux syscall register boundary with the selected C `errno`
//! publisher. It is not generic C `fcntl`, duplication, OFD locks,
//! ownership/signalling control, leases, seals,
//! `lockf`, descriptor pathname policy, vector I/O, a filesystem capability,
//! stdio, a general C/POSIX runtime, libc.so, CRT, thread lifecycle, dynamic
//! TLS, loader, sysroot, allocator, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/fcntl/fcntl.c` maps to the selected command dispatch below.
//!
//! Musl passes a raw third word to Linux `fcntl=72`, ORs `O_LARGEFILE` into a
//! `F_SETFL` request, and uses a cancellation-point route only for
//! `F_SETLKW`. The selected direct Linux-5.10 leaves retain the status-control
//! route, `O_LARGEFILE` rule, and the sibling direct nonblocking record-lock
//! pointer forms. Only the owned-runtime composition admits the blocking
//! lock/cancellation path. Neither selects musl's `F_GETOWN` translation or
//! its historical `F_DUPFD_CLOEXEC` fallback.
//!
//! C `fcntl` is variadic: legal `F_GETFD` and `F_GETFL` calls have only its
//! two fixed C words, so an ordinary three-argument Rust entry would have an
//! invalid ABI for them. The public assembly shim therefore routes these two
//! commands to a two-word helper that explicitly supplies Linux rdx=0,
//! routes `F_SETFD`/`F_SETFL` to a three-word scalar helper, routes the two
//! standalone record commands (plus owned-runtime `F_SETLKW`) to their
//! pointer helper, and rejects every other command before touching rdx. SysV AMD64 places fd/cmd/the first variadic
//! word in rdi/rsi/rdx, which is also Linux `fcntl`'s three-word register
//! order.

use core::ffi::c_int;

use super::{c_status, errno, raw_syscall, record_locks};

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
 * every argument register needed by the destination helper. Give this shim
 * its own executable section so selecting fcntl does not retain unrelated
 * global-assembly entries from the same archive object.
 */
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
    cmp esi, 2
    je {scalar}
    cmp esi, 4
    je {scalar}
    cmp esi, 5
    je {record_lock}
    cmp esi, 6
    je {record_lock}
    .if {owned_blocking_lock}
    cmp esi, 7
    je {record_lock}
    .endif
    jmp {unsupported}
    .size fcntl, .-fcntl

    .section .note.GNU-stack,"",@progbits
"#,
    owned_blocking_lock = const cfg!(feature = "x86-owned-static-runtime") as u8,
    no_argument = sym fcntl_no_argument,
    scalar = sym fcntl_scalar,
    record_lock = sym record_locks::fcntl_record_lock,
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
