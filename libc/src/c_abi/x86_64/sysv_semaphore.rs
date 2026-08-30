//! Selected static Linux/x86-64 SysV semaphore C boundary.
//!
//! This leaf owns one complete, deliberately bounded SysV semaphore family:
//! `semget`, `semop`, `semtimedop`, and variadic `semctl`. It composes only
//! the raw Linux/x86-64 syscall register boundary and the selected initial-TLS
//! C `errno` writer. It is not SysV message queues or shared memory, POSIX
//! semaphores, a process-exit `SEM_UNDO` lifecycle policy, pthread
//! cancellation, a general C/POSIX runtime, libc.so, CRT, dynamic TLS,
//! loader, sysroot, allocator, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/ipc/semget.c` maps to [`semget`], including musl's unsigned-short
//!   semaphore-count guard.
//! - `src/ipc/semop.c` maps to [`semop`].
//! - `src/ipc/semtimedop.c` maps to [`semtimedop`].
//! - `src/ipc/semctl.c` maps to the public assembly `semctl` entry plus its
//!   two fixed-arity helpers below.
//!
//! Musl routes blocking semaphore operations through cancellation-point
//! machinery. The selected static archive deliberately issues the direct
//! Linux calls instead because the general pthread cancellation lifecycle is
//! not yet selected. Linux 5.10 supplies every syscall used here, so this
//! target-specific leaf carries no legacy compatibility fallback.

use core::ffi::{c_int, c_void};

use super::{c_status, errno, raw_syscall};

const EINVAL: c_int = 22;
const SEM_COUNT_MAX: c_int = 65_535;

// Musl consumes `union semun` only for SETVAL, GETALL, SETALL, IPC_SET,
// IPC_INFO, SEM_INFO, IPC_STAT, SEM_STAT, and SEM_STAT_ANY. Every selected
// caller of those forms supplies one explicit union machine word in the SysV
// AMD64 fourth C argument register (`rcx`). The known no-vararg forms are
// IPC_RMID, GETPID, GETVAL, GETNCNT, and GETZCNT; all other commands use
// musl's zero-initialized union fallback. These values are the x86 LP64
// definitions from the installed `sys/ipc.h` and `sys/sem.h`.
const IPC_SET: c_int = 1;
const IPC_STAT: c_int = 2;
const IPC_INFO: c_int = 3;
const GETALL: c_int = 13;
const SETVAL: c_int = 16;
const SETALL: c_int = 17;
const SEM_STAT: c_int = 18;
const SEM_INFO: c_int = 19;
const SEM_STAT_ANY: c_int = 20;

// Musl's src/ipc/ipc.h applies IPC_CMD(cmd) to every direct semctl syscall.
// Its x86-64 syscall_arch.h target override makes IPC_64 zero (the generic
// 0x100 definition is for older IPC ABIs), and x86's IPC_TIME64 is likewise
// zero because public IPC_STAT carries no 0x100 bit. Keep both names visible
// so this exact target mapping cannot silently inherit a 32-bit IPC encoding.
const IPC_64: c_int = 0;
const IPC_TIME64: c_int = 0;

#[inline]
const fn ipc_command(command: c_int) -> c_int {
    (command & !IPC_TIME64) | IPC_64
}

// Match musl's C `union semun` calling representation rather than treating
// the public variadic argument as an `int` or pointer. The target headers
// intentionally leave that union application-defined (`_SEM_SEMUN_UNDEFINED`),
// so these private arms model only its Linux/x86-64 ABI: every real arm is one
// INTEGER-class eightbyte in the fourth SysV C argument position. `raw` is
// private conversion storage; it is never exposed through a Rust or C header.
#[repr(C)]
union Semun {
    value: c_int,
    buffer: *mut c_void,
    array: *mut u16,
    raw: usize,
}

// Rust has no stable C-variadic implementation surface. Keep the public
// source ABI in this assembly entry instead: after the three fixed `int`
// arguments in rdi/rsi/rdx, a supplied union semun word is already in rcx.
// Only musl's nine union-consuming command forms may preserve that word. Every
// other command, including the five standard no-vararg forms and unknown
// commands, installs an explicit zero before passing through the fixed helper.
// This exactly retains musl's zero-initialized `union semun` fallback rather
// than reading an unspecified fourth register.
core::arch::global_asm!(
    r#"
    .text
    .p2align 4
    .global semctl
    .type semctl,@function
semctl:
    cmp edx, {setval}
    je {word}
    cmp edx, {getall}
    je {word}
    cmp edx, {setall}
    je {word}
    cmp edx, {ipc_set}
    je {word}
    cmp edx, {ipc_info}
    je {word}
    cmp edx, {sem_info}
    je {word}
    cmp edx, {ipc_stat}
    je {word}
    cmp edx, {sem_stat}
    je {word}
    cmp edx, {sem_stat_any}
    je {word}
    jmp {no_argument}
    .size semctl, .-semctl

    .section .note.GNU-stack,"",@progbits
"#,
    setval = const SETVAL,
    getall = const GETALL,
    setall = const SETALL,
    ipc_set = const IPC_SET,
    ipc_info = const IPC_INFO,
    sem_info = const SEM_INFO,
    ipc_stat = const IPC_STAT,
    sem_stat = const SEM_STAT,
    sem_stat_any = const SEM_STAT_ANY,
    no_argument = sym semctl_no_argument,
    word = sym semctl_word,
);

/// Create one System V semaphore set through Linux `semget(2)`.
///
/// `key`, `semaphore_count`, and `flags` are passed to Linux unchanged after
/// musl's `unsigned short` count bound. The caller owns IPC key, permissions,
/// creation/race policy, and eventual `IPC_RMID` lifecycle.
#[no_mangle]
pub extern "C" fn semget(key: c_int, semaphore_count: c_int, flags: c_int) -> c_int {
    if semaphore_count > SEM_COUNT_MAX {
        // SAFETY: this C ABI leaf owns publication to the calling initial-TLS
        // errno slot for its locally rejected musl-compatible argument.
        unsafe { errno::set_errno(EINVAL) };
        return -1;
    }

    // SAFETY: the three C scalar words map directly to Linux x86-64
    // semget=64; Linux owns all remaining key/count/permission validation.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_SEMGET,
            i64::from(key),
            i64::from(semaphore_count),
            i64::from(flags),
        )
    };
    c_status(result)
}

/// Apply one or more semaphore operations through Linux `semop(2)`.
///
/// # Safety
///
/// `operations` must designate `operation_count` writable x86
/// `struct sembuf` records for the kernel's duration. The caller owns the
/// semaphore-set lifetime, blocking and signal policy, and any `SEM_UNDO`
/// process-exit semantics. This direct static leaf intentionally has no musl
/// pthread cancellation point.
#[no_mangle]
pub unsafe extern "C" fn semop(
    semaphore_id: c_int,
    operations: *mut c_void,
    operation_count: usize,
) -> c_int {
    // SAFETY: the caller supplies the complete Linux semaphore-operation
    // buffer contract; x86 arguments occupy rdi/rsi/rdx.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_SEMOP,
            i64::from(semaphore_id),
            operations as usize as i64,
            operation_count as i64,
        )
    };
    c_status(result)
}

/// Apply timed semaphore operations through Linux `semtimedop(2)`.
///
/// # Safety
///
/// `operations` has the same requirements as [`semop`]. `timeout` must be
/// null or point to a readable x86 16-byte, align-eight `struct timespec` for
/// the syscall's duration. The timeout is relative; caller-owned storage and
/// Linux's timeout/error policy are forwarded directly. This leaf omits
/// musl's pthread cancellation point.
#[no_mangle]
pub unsafe extern "C" fn semtimedop(
    semaphore_id: c_int,
    operations: *mut c_void,
    operation_count: usize,
    timeout: *const c_void,
) -> c_int {
    // SAFETY: the caller supplies both kernel-visible records; x86 syscall
    // argument four is explicitly moved to r10 by this raw helper.
    let result = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_SEMTIMEDOP,
            i64::from(semaphore_id),
            operations as usize as i64,
            operation_count as i64,
            timeout as usize as i64,
        )
    };
    c_status(result)
}

/// Forward one no-vararg SysV `semctl` command with an explicit zero union.
///
/// The public assembly entry sends every command other than musl's nine
/// union-consuming forms here. That includes `IPC_RMID`, `GETPID`, `GETVAL`,
/// `GETNCNT`, `GETZCNT`, and unknown commands. Linux ignores the fourth
/// syscall word for the known no-vararg forms; establishing it also preserves
/// musl's zero-initialized union for unknown commands without treating an
/// absent C vararg register as input.
#[inline(never)]
unsafe extern "C" fn semctl_no_argument(
    semaphore_id: c_int,
    semaphore_number: c_int,
    command: c_int,
) -> c_int {
    // SAFETY: the assembly dispatcher admits only command values for which
    // musl does not consume a union semun C argument.
    unsafe {
        semctl_word(
            semaphore_id,
            semaphore_number,
            command,
            Semun { raw: 0 },
        )
    }
}

/// Forward one explicit `union semun` word through Linux `semctl=66`.
///
/// The public assembly entry preserves SysV AMD64's supplied fourth C
/// argument in `rcx`; this fixed helper then moves it to Linux's `r10` slot.
/// Pointers, `SETVAL` integer values, command selection, and all pointed-to
/// storage remain caller-owned according to the selected `sys/sem.h` ABI.
#[inline(never)]
unsafe extern "C" fn semctl_word(
    semaphore_id: c_int,
    semaphore_number: c_int,
    command: c_int,
    argument: Semun,
) -> c_int {
    // SAFETY: every Semun arm is one x86-64 INTEGER-class word. The assembly
    // entry passes a supplied C union unchanged, while the no-argument helper
    // constructs the explicit all-zero representation above.
    let argument = unsafe { argument.raw };
    let command = ipc_command(command);
    // SAFETY: the caller/assembly boundary provides the exact musl-normalized
    // Linux command and union word. x86's fourth syscall argument is r10.
    let result = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_SEMCTL,
            i64::from(semaphore_id),
            i64::from(semaphore_number),
            i64::from(command),
            argument as i64,
        )
    };
    c_status(result)
}
