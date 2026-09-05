//! Pinned-musl TRE records for the owned static Linux/x86-64 regex provider.
//!
//! This is a source-shaped port scaffold, not a second regex implementation.
//! It starts with the exact compiled-TNFA records from musl 1.2.6's
//! `src/regex/tre.h:91-229` (`e734e68decc33b5ee983db12cabcbdd2589c2d16088677228087b0e5dc365cf3`)
//! and the active dynamic compiler/matcher arena from
//! `src/regex/tre-mem.c:53-151` (`4721979ce365a395fd7644335c847a8a97913e87f14348641f7f199b57b93e28`).
//! The compiler is assembled in the same source order as pinned
//! `src/regex/regcomp.c:70-2953`
//! (`56b0a765e084a5cd3ed7113a893b50d259265ba76b6bea98889c45d7aec302a0`):
//! its AST/parser, tag insertion, bounded-repetition expansion, nullable /
//! first-position / last-position pass, TNFA materialization, `regcomp`, and
//! `regfree` form the compiled graph consumed by the executor. Pinned
//! `src/regex/regexec.c:169-1028`
//! (`072e8a1092c98830b48e784fb74ce486f7c39e27207f79f1dd161e2c5d86ba77`)
//! retains its separate parallel leftmost-longest and backreference
//! backtracking routes. The C-locale error-table route is pinned
//! `src/regex/regerror.c:7-37`
//! (`72b3ab9c63c88c43aa37c4a4d4a89d07f892f42cbbf8801806b7b40135466bb9`).
//!
//! `tre.h` and `tre-mem.c` originated in TRE and carry Ville Laurikari's
//! two-clause BSD license, reproduced in
//! [`LICENSE-TRE-2-CLAUSE-BSD.txt`](LICENSE-TRE-2-CLAUSE-BSD.txt); musl records
//! that they were substantially modified by Rich Felker.  The later
//! `regcomp.c` and `regexec.c` retain this same source and license provenance.
//! `regerror.c` is musl MIT; its fixed C-locale table is in `error.rs`. This
//! private module is not selected from `static_c_abi.rs` yet; routing and
//! public support qualification remain outside this checkpoint.

use core::ffi::c_void;

// The TRE compiler and matcher allocate every compiled record and temporary
// queue through the C ABI. These opaque tails deliberately keep LLVM from
// resolving an `extern` call to this crate's known mimalloc wrapper before the
// ELF lookup boundary. They follow the interposition-preserving allocation
// thunks in `owned_static_stdio.rs` and `directory_streams.rs`: an executable
// may replace malloc/calloc/realloc/free, and allocation plus release must
// select precisely that same provider.
core::arch::global_asm!(
    r#"
    .text
    .p2align 4
    .globl __crabc_x86_regex_cabi_malloc
    .hidden __crabc_x86_regex_cabi_malloc
    .type __crabc_x86_regex_cabi_malloc,@function
__crabc_x86_regex_cabi_malloc:
    jmp malloc
    .size __crabc_x86_regex_cabi_malloc, .-__crabc_x86_regex_cabi_malloc

    .p2align 4
    .globl __crabc_x86_regex_cabi_calloc
    .hidden __crabc_x86_regex_cabi_calloc
    .type __crabc_x86_regex_cabi_calloc,@function
__crabc_x86_regex_cabi_calloc:
    jmp calloc
    .size __crabc_x86_regex_cabi_calloc, .-__crabc_x86_regex_cabi_calloc

    .p2align 4
    .globl __crabc_x86_regex_cabi_realloc
    .hidden __crabc_x86_regex_cabi_realloc
    .type __crabc_x86_regex_cabi_realloc,@function
__crabc_x86_regex_cabi_realloc:
    jmp realloc
    .size __crabc_x86_regex_cabi_realloc, .-__crabc_x86_regex_cabi_realloc

    .p2align 4
    .globl __crabc_x86_regex_cabi_free
    .hidden __crabc_x86_regex_cabi_free
    .type __crabc_x86_regex_cabi_free,@function
__crabc_x86_regex_cabi_free:
    jmp free
    .size __crabc_x86_regex_cabi_free, .-__crabc_x86_regex_cabi_free
"#
);

unsafe extern "C" {
    #[link_name = "__crabc_x86_regex_cabi_malloc"]
    fn regex_cabi_malloc(size: usize) -> *mut c_void;
    #[link_name = "__crabc_x86_regex_cabi_calloc"]
    fn regex_cabi_calloc(count: usize, size: usize) -> *mut c_void;
    #[link_name = "__crabc_x86_regex_cabi_realloc"]
    fn regex_cabi_realloc(pointer: *mut c_void, size: usize) -> *mut c_void;
    #[link_name = "__crabc_x86_regex_cabi_free"]
    fn regex_cabi_free(pointer: *mut c_void);
}

#[inline]
pub(crate) unsafe fn cabi_malloc(size: usize) -> *mut c_void {
    // SAFETY: the source caller forwards malloc's ordinary size contract.
    unsafe { regex_cabi_malloc(size) }
}

#[inline]
pub(crate) unsafe fn cabi_calloc(count: usize, size: usize) -> *mut c_void {
    // SAFETY: the source caller forwards calloc's ordinary product contract.
    unsafe { regex_cabi_calloc(count, size) }
}

#[inline]
pub(crate) unsafe fn cabi_realloc(pointer: *mut c_void, size: usize) -> *mut c_void {
    // SAFETY: the source caller forwards realloc's ownership contract.
    unsafe { regex_cabi_realloc(pointer, size) }
}

#[inline]
pub(crate) unsafe fn cabi_free(pointer: *mut c_void) {
    // SAFETY: the source caller forwards one allocation from this ABI provider.
    unsafe { regex_cabi_free(pointer) };
}

mod memory;
mod types;
mod compile;
mod execute;
mod error;
