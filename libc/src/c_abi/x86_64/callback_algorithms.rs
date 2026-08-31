//! Selected static Linux/x86-64 C context-sorting callback boundary.
//!
//! This leaf owns exactly musl's private `__qsort_r` helper and its public weak
//! same-address GNU/BSD `qsort_r` alias. It delegates the stateless,
//! allocation-free smoothsort worker to the separate qsort.rs leaf so qsort's
//! standalone static candidate cannot extract this context-bearing ABI. It is
//! not public `qsort`, `bsearch`, lfind/lsearch, `search.h` trees or hashes,
//! locale-aware ordering, callback registration, C++ exception or C longjmp
//! transport across Rust, libc.so, a CRT, a loader, a sysroot, or public x86
//! support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! 9fa28ece75d8a2191de7c5bb53bed224c5947417, under musl's MIT license:
//! `src/stdlib/qsort.c::__qsort_r` maps to this context ABI wrapper and the
//! qsort.rs worker; its `weak_alias(__qsort_r, qsort_r)` maps to the exact
//! same-address x86 global-assembly alias below. `src/stdlib/qsort_nr.c` and
//! the two-argument `qsort` adapter remain separately owned by qsort.rs.
//!
//! The fixed smoothsort algorithm retains musl's unstable equal-key ordering.
//! The qsort.rs worker's defensive nel-times-width overflow return is
//! intentional and occurs only outside the valid caller-owned C array domain.
//! No public entry reads or writes TLS, errno, allocation, locks, locale,
//! callback registries, or process state.

use core::ffi::{c_void};

use super::qsort::{qsort_with_context, QsortContextCmp};

// Musl weak_alias(__qsort_r, qsort_r) makes both ELF names identify the same
// implementation. A Rust weak wrapper would have a different address and
// would silently widen the translated source contract.
core::arch::global_asm!(
    ".weak qsort_r",
    ".set qsort_r, __qsort_r",
);

/// Sort caller-owned byte records with a context-bearing C callback.
///
/// # Safety
///
/// For a nonzero nel-times-width product, base must address that many writable
/// bytes as valid records. The multiplication must not overflow. cmp must be
/// a non-null C-ABI callback that returns normally and imposes a consistent
/// ordering. C++ exceptions and C longjmp may not cross this Rust code.
#[no_mangle]
pub unsafe extern "C" fn __qsort_r(
    base: *mut c_void,
    nel: usize,
    width: usize,
    cmp: QsortContextCmp,
    argument: *mut c_void,
) {
    unsafe { qsort_with_context(base, nel, width, cmp, argument) };
}
