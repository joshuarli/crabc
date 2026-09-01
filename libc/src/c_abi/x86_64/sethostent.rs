//! Linux/x86-64 opt-in static C `sethostent`/`setnetent` ABI boundary.
//!
//! Pinned musl 1.2.6 provenance is fixed to release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417` under musl's MIT license
//! recorded in `COPYRIGHT`. The direct mapping is
//! `src/network/ent.c::sethostent`: musl accepts but ignores the `int`
//! `stayopen` argument, returns immediately, and then declares
//! `weak_alias(sethostent, setnetent)`.
//!
//! The default x86 static root owns the source file's distinct
//! `endhostent`/`endnetent` no-argument terminator pair in `endhostent.rs`.
//! This separate opt-in owner adds only the setter pair; it does not open or
//! close a database, retain an enumeration cursor, consult `/etc/hosts` or
//! `/etc/networks`, or select resolver, NSS, filesystem, errno/TLS,
//! allocation, syscall, locale, or runtime state.
//!
//! The System V AMD64 ABI passes the signed `int` in `edi`; ignoring it is
//! musl's complete behavior. The weak alias is emitted in assembler rather
//! than as a Rust forwarding function, preserving same-address identity and
//! ordinary strong caller override semantics. This is a private C ABI
//! artifact, not netdb/resolver completion, libc.so, CRT, loader, sysroot,
//! promotion, or public x86 support.

use core::ffi::c_int;

// Musl's weak_alias(sethostent, setnetent) is one same-address weak ELF alias.
// A forwarding body would alter pointer identity and make a caller's strong
// `setnetent` definition coexist rather than supersede this weak binding.
core::arch::global_asm!(
    ".weak setnetent",
    ".set setnetent, sethostent",
);

/// Set musl's stateless legacy host-database enumeration boundary.
///
/// The `stayopen` argument is intentionally ignored, exactly as in musl's
/// empty source body. It neither creates nor changes legacy netdb state.
#[no_mangle]
pub extern "C" fn sethostent(_stayopen: c_int) {}
