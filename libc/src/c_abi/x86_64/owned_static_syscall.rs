//! Public Linux/x86-64 `syscall(long, ...)` support for the owned static runtime.
//!
//! This owner translates pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/misc/syscall.c` supplies the public six-word variadic wrapper and
//!   its `__syscall_ret` error convention.
//! - `arch/x86_64/syscall_arch.h` supplies the Linux register order: syscall
//!   number in `rax`, then `rdi`, `rsi`, `rdx`, `r10`, `r8`, and `r9`.
//! - `src/internal/syscall_ret.c` supplies the `-4095..=-1` errno boundary.
//!
//! Rust cannot soundly use `va_arg` to manufacture trailing C arguments that
//! a caller did not provide.  The SysV AMD64 machine ABI can, however, move
//! the variadic register/stack slots exactly as musl's C wrapper ultimately
//! passes them to the kernel.  The assembly below therefore consumes the six
//! machine-word slots directly: the sixth is the first stack word after the
//! return address.  Linux ignores unused words for each named syscall, just
//! as it does for musl's always-six-word forwarding call.
//!
//! This is an owned-static support owner only.  It has no cancellation-point,
//! restart, syscall-number policy, pointer-validation, loader, or portability
//! contract beyond the Linux/x86-64 C ABI.  Raw typed syscalls remain owned by
//! [`super::raw_syscall`]; the error path writes the existing initial-TLS
//! `errno` object through `__errno_location`.

#[cfg(not(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64"), target_endian = "little")))]
compile_error!("owned static syscall support requires little-endian Linux/x86-64");

// The entry C ABI is `syscall(long number, ...)`:
//
//   rdi = number; rsi, rdx, rcx, r8, r9 = words 1..5; [rsp+8] = word 6.
//
// After remapping, `syscall` clobbers rcx/r11 as required by Linux.  On an
// errno-encoded result, preserve the positive errno across the ABI-correct
// call to the existing TLS accessor, then publish `-1` exactly as musl's
// `__syscall_ret` does.  The push aligns the stack before the nested call:
// entry `%rsp % 16 == 8`, and `push` makes it zero before `call`.
#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    r#"
    .text
    .global syscall
    .type syscall,@function
syscall:
    mov rax, rdi
    mov rdi, rsi
    mov rsi, rdx
    mov rdx, rcx
    mov r10, r8
    mov r8, r9
    mov r9, qword ptr [rsp + 8]
    syscall
    cmp rax, -4095
    jae .Lcrabc_owned_static_syscall_error
    ret
.Lcrabc_owned_static_syscall_error:
    neg rax
    push rax
    call __errno_location
    pop rcx
    mov dword ptr [rax], ecx
    mov rax, -1
    ret
    .size syscall, .-syscall
    .section .note.GNU-stack,"",@progbits
"#,
);

#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(include_str!("owned_syscall_aarch64.S"));

#[cfg(target_arch = "aarch64")]
#[no_mangle]
unsafe extern "C" fn __crabc_aarch64_syscall(number: i64, a: i64, b: i64, c: i64, d: i64, e: i64, f: i64) -> i64 {
    // SAFETY: the assembly entry forwards the C caller's register words unchanged; Linux validates them for the selected syscall.
    let result = unsafe { super::raw_syscall::syscall6(number, a, b, c, d, e, f) };
    super::c_result(result)
}
