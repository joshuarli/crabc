//! Private static Linux/x86-64 stack-check failure compiler-support seam.
//!
//! This is the terminal-function fragment of musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`,
//! `src/env/__stack_chk_fail.c::__stack_chk_fail`, under musl's MIT license.
//! On x86-64 that function's `a_crash()` macro is the one-instruction `hlt`
//! definition in `arch/x86_64/atomic_arch.h`; Linux turns its user-mode
//! privileged-instruction fault into the observed SIGSEGV boundary. Musl
//! declares the private companion with `hidden void __stack_chk_fail_local()`
//! and emits `weak_alias(__stack_chk_fail, __stack_chk_fail_local)`, so the
//! assembly keeps one strong default-visible primary symbol and one hidden
//! weak same-address function alias.
//!
//! The source file also owns `__stack_chk_guard` storage and the strong
//! `__init_ssp` canary initializer. They are deliberately not selected here:
//! this static archive leaf handles an already-detected failed check only. It
//! neither creates guard storage nor consumes entropy, initializes a canary,
//! or selects a public x86 C API. The separate static TLS bootstrap owns the
//! x86 FS+40 guard and its worker copies; static startup retains the inert weak
//! `__init_ssp` compatibility spelling without reseeding a running thread.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("x86 stack-check failure requires little-endian Linux/x86-64");

core::arch::global_asm!(
    ".text",
    ".global __stack_chk_fail",
    ".type __stack_chk_fail,@function",
    "__stack_chk_fail:",
    "hlt",
    ".size __stack_chk_fail, .-__stack_chk_fail",
    ".weak __stack_chk_fail_local",
    ".hidden __stack_chk_fail_local",
    ".type __stack_chk_fail_local,@function",
    ".set __stack_chk_fail_local, __stack_chk_fail",
    ".section .note.GNU-stack,\"\",@progbits",
);
