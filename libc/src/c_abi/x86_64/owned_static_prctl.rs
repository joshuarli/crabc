//! Public Linux/x86-64 `prctl(int, ...)` support for the owned static runtime.
//!
//! Pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417` is the source oracle, under
//! musl's MIT license.  Its `src/linux/prctl.c` reads four unsigned-long
//! variadic words and forwards `SYS_prctl`, the operation, and those words
//! through `syscall`.
//!
//! This x86 owner deliberately uses the SysV AMD64 register form rather than
//! Rust `va_arg`: `option` arrives in `rdi`, and the four variadic words are
//! in `rsi`, `rdx`, `rcx`, and `r8`.  Linux syscall argument four is `r10`,
//! so the shim moves only that word before `syscall=157`.  It leaves no Rust
//! variadic read that could claim absent trailing C arguments exist.  The
//! common Linux error interval publishes through the existing initial-TLS
//! `errno` owner, preserving musl's `__syscall_ret` result contract.
//!
//! It owns only this public C ABI forwarding boundary.  Option policy,
//! cancellation, signal/allocator/loader state, and a portable `prctl`
//! abstraction are outside the owned-static runtime.

#[cfg(not(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64"), target_endian = "little")))]
compile_error!("owned static prctl support requires little-endian Linux/x86-64");

// The fifth prctl word is already in r8; r9 is not consumed by Linux's
// five-argument prctl syscall, so clear it rather than forwarding unrelated
// caller state.  The error path is intentionally duplicated with `syscall`:
// keeping this owner independently extractable avoids a hidden dependency on
// an extra support symbol while retaining the same `__syscall_ret` semantics.
#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    r#"
    .text
    .global prctl
    .type prctl,@function
prctl:
    mov r10, rcx
    mov rax, 157
    xor r9d, r9d
    syscall
    cmp rax, -4095
    jae .Lcrabc_owned_static_prctl_error
    ret
.Lcrabc_owned_static_prctl_error:
    neg rax
    push rax
    call __errno_location
    pop rcx
    mov dword ptr [rax], ecx
    mov rax, -1
    ret
    .size prctl, .-prctl
    .section .note.GNU-stack,"",@progbits
"#,
);

#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(include_str!("owned_prctl_aarch64.S"));

#[cfg(target_arch = "aarch64")]
#[no_mangle]
unsafe extern "C" fn __crabc_aarch64_prctl(option: i32, a: i64, b: i64, c: i64, d: i64) -> i32 {
    // SAFETY: the assembly entry forwards the C caller's register words and Linux validates the option's arguments.
    let result = unsafe { super::raw_syscall::syscall5(super::raw_syscall::SYS_PRCTL, i64::from(option), a, b, c, d) };
    super::c_status(result)
}
