//! Private Linux/x86-64 raw clone machine boundary.
//!
//! This is the fixed-argument shape used by musl 1.2.6
//! `src/thread/x86_64/clone.s`, intentionally exposed under a crabc-private
//! name. Its assembly is a lexical private-symbol rename of that source:
//! it preserves the seven-argument SysV entry layout, the Linux five-word
//! `clone(2)` register shuffle, the aligned child stack, and the child
//! callback/exit tail. It is source-only evidence: no public
//! `clone`/`__clone` ABI, pthread state, or TLS setup is provided here.
//! Callers must use process-clone flags only; in particular `CLONE_THREAD`,
//! `CLONE_VM`, and `CLONE_SETTLS` are outside this leaf.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 raw clone leaf requires little-endian Linux/x86-64");

use core::ffi::c_void;

// Fixed musl-shaped raw clone entry, with a private symbol to prevent C ABI
// or libc selection claims. `stack` points to writable stack storage whose
// lifetime extends through the child callback.
extern "C" {
    fn __crabc_x86_clone_raw(
        func: unsafe extern "C" fn(*mut c_void) -> i32,
        stack: *mut u8,
        flags: i32,
        arg: *mut c_void,
        ptid: *mut i32,
        tls: *mut c_void,
        ctid: *mut i32,
    ) -> i64;
}

core::arch::global_asm!(
    r#"
    .text
    .global __crabc_x86_clone_raw
    .hidden __crabc_x86_clone_raw
    .type __crabc_x86_clone_raw,@function
__crabc_x86_clone_raw:
    // Fixed musl 1.2.6 x86_64 clone.s algorithm, under a private symbol.
    xor eax, eax
    mov al, 56
    mov r11, rdi
    // clone(flags, stack, ptid, tls, ctid): rdx,rsi,r8,r10,r9.
    mov rdi, rdx
    mov rdx, r8
    mov r8, r9
    mov r10, qword ptr [rsp + 8]
    mov r9, r11
    and rsi, -16
    sub rsi, 8
    mov qword ptr [rsi], rcx
    syscall
    test eax, eax
    jne 1f
    xor ebp, ebp
    pop rdi
    call r9
    mov edi, eax
    xor eax, eax
    mov al, 60
    syscall
    hlt
1:
    ret
    .size __crabc_x86_clone_raw, .-__crabc_x86_clone_raw
    .section .note.GNU-stack,"",@progbits
"#
);

/// Invoke the private raw process-clone boundary.
///
/// # Safety
///
/// `func` must be valid for the child, `stack` must designate writable
/// storage owned until child exit, and all pointer arguments must satisfy the
/// Linux `clone` contract.  This leaf is intended only for process-clone
/// flags and does not establish TLS or pthread invariants.
pub(crate) unsafe fn clone_raw(
    func: unsafe extern "C" fn(*mut c_void) -> i32,
    stack: *mut u8,
    flags: i32,
    arg: *mut c_void,
) -> i64 {
    unsafe { __crabc_x86_clone_raw(func, stack, flags, arg, core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut()) }
}
