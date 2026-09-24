#![no_std]

//! Conventional Linux/x86-64 non-PIE application entry.
//!
//! One `crt1.o` serves ordinary static `ET_EXEC` and dynamic non-PIE
//! executables, as pinned musl's does and as the frozen AArch64
//! `crt/src/normal_entry.rs` did, so a combined sysroot installs it once for
//! both products. Facts fixed before `_start` runs select the startup owner:
//!
//! - Kernel entry of a static executable: Linux clears `%rdx`, and there is
//!   no owned loader handoff record. libc installs the static initial TLS and
//!   this CRT runs the main image's preinit, init and fini arrays
//!   (`x86_64_startup.rs`).
//! - Entry from the owned interpreter: the loader resolved the handoff record
//!   and passes its process finalizer in `%rdx`. The dynamic path
//!   authenticates that pair, attaches RuntimeV1 TLS, and leaves main
//!   construction and finalization to the loader (`x86_64_dynamic_startup.rs`).
//!
//! Any other combination is rejected before libc or application code runs.
//!
//! The static product forbids unresolved symbols in its executables, and a
//! dynamic link has no libc.a. This object therefore carries a failing weak
//! default for each mode-specific boundary; the strong definition in the
//! matching link overrides it:
//!
//! - `__crabc_x86_static_tls_bootstrap`: libc.a's hidden static TLS
//!   bootstrap, from the member that also defines `__libc_start_main`.
//! - `__crabc_x86_64_attached_owned_crt_handoff`: the reader of the weak
//!   `__crabc_x86_64_owned_crt_handoff` GOT slot that the owned interpreter
//!   relocates. crabc-dynamic-attach.o, linked only into dynamic executables,
//!   carries it (`x86_64_owned_crt_handoff_attachment.rs`), so a static
//!   executable never imports the loader symbol. The default reports no
//!   handoff.
//! - `__crabc_x86_loader_tls_runtime_v1_attach`: crabc-dynamic-attach.o's
//!   RuntimeV1 attachment.
//!
//! A default is reached only if the matching definition is missing, and then
//! the path rejects.
//!
//! `crt/build_x86_64.py` builds this combined entry
//! (`crabc_x86_64_combined_exec_entry` with the owned-dynamic cfgs) for every
//! product. Compiled without that cfg, as private static-only runners do, it
//! is the legacy static entry alone.

mod x86_64_array_boundaries;
#[cfg(crabc_x86_64_combined_exec_entry)]
mod x86_64_dynamic_startup;
mod x86_64_startup;

#[cfg(crabc_x86_64_combined_exec_entry)]
pub use x86_64_dynamic_startup::__crabc_x86_64_dynamic_start;
pub use x86_64_startup::__crabc_x86_64_static_pie_start;

#[cfg(crabc_x86_64_combined_exec_entry)]
type LifecycleHook = unsafe extern "C" fn();

// Failing weak defaults for the mode-specific boundaries described above,
// each in its own section like compiler-emitted functions.
#[cfg(crabc_x86_64_combined_exec_entry)]
core::arch::global_asm!(
    ".section .text.__crabc_x86_static_tls_bootstrap,\"ax\",@progbits",
    ".weak __crabc_x86_static_tls_bootstrap",
    ".hidden __crabc_x86_static_tls_bootstrap",
    ".type __crabc_x86_static_tls_bootstrap,@function",
    "__crabc_x86_static_tls_bootstrap:",
    "mov eax, 1",
    "ret",
    ".size __crabc_x86_static_tls_bootstrap, .-__crabc_x86_static_tls_bootstrap",
    ".section .text.__crabc_x86_64_attached_owned_crt_handoff,\"ax\",@progbits",
    ".weak __crabc_x86_64_attached_owned_crt_handoff",
    ".hidden __crabc_x86_64_attached_owned_crt_handoff",
    ".type __crabc_x86_64_attached_owned_crt_handoff,@function",
    "__crabc_x86_64_attached_owned_crt_handoff:",
    "xor eax, eax",
    "ret",
    ".size __crabc_x86_64_attached_owned_crt_handoff, .-__crabc_x86_64_attached_owned_crt_handoff",
    ".section .text.__crabc_x86_loader_tls_runtime_v1_attach,\"ax\",@progbits",
    ".weak __crabc_x86_loader_tls_runtime_v1_attach",
    ".type __crabc_x86_loader_tls_runtime_v1_attach,@function",
    "__crabc_x86_loader_tls_runtime_v1_attach:",
    "mov eax, 1",
    "ret",
    ".size __crabc_x86_loader_tls_runtime_v1_attach, .-__crabc_x86_loader_tls_runtime_v1_attach",
);

// The owned interpreter admits a dynamic main image's owned entry only by
// this private revision-one marker. A static executable carries it inertly.
#[cfg(crabc_x86_64_combined_exec_entry)]
core::arch::global_asm!(
    r#"
    .section .note.crabc.owned-crt,"a",@note
    .balign 4
    .long 6
    .long 4
    .long 0x43525401
    .asciz "CRABC"
    .balign 4
    .long 1
    .balign 4
"#,
);

#[cfg(crabc_x86_64_combined_exec_entry)]
core::arch::global_asm!(
    r#"
    .intel_syntax noprefix
    .section .text._start,"ax",@progbits
    .global _start
    .type _start,@function
_start:
    // Preserve the untouched initial stack and the entry `%rdx` (zero from
    // the kernel, the process finalizer from the owned interpreter) before
    // any call. Do not read the GOT or TLS before a startup owner is chosen.
    mov r15, rsp
    mov rsi, rdx
    xor ebp, ebp
    and rsp, -16
    mov rdi, r15
    call {startup}
    ud2
    .size _start, .-_start

    .att_syntax prefix
    .section .note.GNU-stack,"",@progbits
"#,
    startup = sym __crabc_x86_64_exec_start,
);

#[cfg(not(crabc_x86_64_combined_exec_entry))]
core::arch::global_asm!(
    r#"
    .intel_syntax noprefix
    .section .text._start,"ax",@progbits
    .global _start
    .type _start,@function
_start:
    // Preserve the kernel-owned initial stack outside Rust allocation
    // provenance, establish the required SysV call alignment, and enter the
    // ordinary static startup path. Do not read the GOT or TLS before libc
    // has validated and installed the executable's initial TLS image.
    mov r15, rsp
    xor ebp, ebp
    and rsp, -16
    mov rdi, r15
    call {startup}
    ud2
    .size _start, .-_start

    .att_syntax prefix
    .section .note.GNU-stack,"",@progbits
"#,
    startup = sym __crabc_x86_64_static_pie_start,
);

/// Choose the static or owned-dynamic startup owner for this process.
///
/// # Safety
///
/// Only `_start` may call this, with the untouched Linux/x86-64 initial stack
/// and the entry `%rdx` value.
#[cfg(crabc_x86_64_combined_exec_entry)]
#[no_mangle]
pub unsafe extern "C" fn __crabc_x86_64_exec_start(
    initial_stack: *const usize,
    loader_finalizer: Option<LifecycleHook>,
) -> ! {
    // A static link has no attachment, so the default reports no handoff.
    let handoff_present = unsafe { x86_64_dynamic_startup::owned_crt_handoff_present() };
    if loader_finalizer.is_none() && !handoff_present {
        unsafe { __crabc_x86_64_static_pie_start(initial_stack) }
    }
    // The dynamic path rejects a handoff without the matching register, or
    // a register without a handoff, before any libc or application code.
    unsafe { __crabc_x86_64_dynamic_start(initial_stack, loader_finalizer) }
}
