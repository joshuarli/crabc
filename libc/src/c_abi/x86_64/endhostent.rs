//! Selected static Linux/x86-64 legacy netdb terminator C ABI boundary.
//!
//! This private leaf owns musl's strong `void endhostent(void)` spelling and
//! its weak same-address `endnetent` alias. Pinned musl 1.2.6
//! `src/network/ent.c` makes `endhostent` an exact no-op, then uses
//! `weak_alias(endhostent, endnetent)`. The source's separate null-returning
//! host/network enumeration entries and its no-op sethostent/setnetent
//! spellings remain unselected: this leaf neither opens nor closes a legacy
//! database, owns no enumeration cursor, and makes no resolver, NSS,
//! `/etc/hosts`, `/etc/networks`, filesystem, process, or network-policy
//! claim.
//!
//! The System V AMD64 ABI gives both no-argument `void` entries no incoming
//! C argument words. The alias is emitted in assembler rather than through a
//! Rust forwarding wrapper so it preserves musl's same-address weak override
//! contract. This leaf has no mutable state, errno, TLS, allocation, syscall,
//! libc.so, CRT, loader, sysroot, family-completion, promotion, or public x86
//! support boundary.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license.

// Musl's weak_alias(endhostent, endnetent) is a same-address weak ELF alias.
// A Rust forwarding function would change both pointer identity and a strong
// caller override's ordinary ELF resolution behavior.
core::arch::global_asm!(
    ".weak endnetent",
    ".set endnetent, endhostent",
);

/// End musl's stateless legacy host-database enumeration boundary.
#[no_mangle]
pub extern "C" fn endhostent() {}
