//! Literal Rust data definitions for musl 1.2.6 `src/regex/tre.h`.
//!
//! The source's compiled representation is a tagged nondeterministic finite
//! automaton.  Its transition, tag, submatch, and allocator layouts are kept
//! separate from future parser and executor code so that those stages must
//! operate on the same records as `regcomp.c` and `regexec.c`; no AST matcher
//! or fixed-capacity substitute is permitted here.

#![allow(non_camel_case_types)]

use core::ffi::{c_char, c_int, c_long, c_void};

// `include/bits/alltypes.h` fixes these installed x86-64 representations.
pub(crate) type regoff_t = c_long;
pub(crate) type tre_char_t = c_int;
pub(crate) type tre_cint_t = u32;
pub(crate) type tre_ctype_t = usize;

#[repr(C)]
pub(crate) struct regex_t {
    pub(crate) re_nsub: usize,
    pub(crate) __opaque: *mut c_void,
    pub(crate) __padding: [*mut c_void; 4],
    pub(crate) __nsub2: usize,
    pub(crate) __padding2: c_char,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct regmatch_t {
    pub(crate) rm_so: regoff_t,
    pub(crate) rm_eo: regoff_t,
}

#[repr(C)]
pub(crate) union TreAssertionParameter {
    pub(crate) class: tre_ctype_t,
    pub(crate) backref: c_int,
}

/// `struct tnfa_transition` in `tre.h`.
///
/// An array is terminated by a transition whose `state` is null.  The fields
/// are intentionally pointers and C scalar arrays rather than Rust ownership:
/// `regcomp.c` creates the records and `regfree` later releases every source
/// allocation in its TNFA ownership order.
#[repr(C)]
pub(crate) struct TreTnfaTransition {
    pub(crate) code_min: tre_cint_t,
    pub(crate) code_max: tre_cint_t,
    pub(crate) state: *mut TreTnfaTransition,
    pub(crate) state_id: c_int,
    pub(crate) tags: *mut c_int,
    pub(crate) assertions: c_int,
    pub(crate) assertion_parameter: TreAssertionParameter,
    pub(crate) neg_classes: *mut tre_ctype_t,
}

pub(crate) const ASSERT_AT_BOL: c_int = 1;
pub(crate) const ASSERT_AT_EOL: c_int = 2;
pub(crate) const ASSERT_CHAR_CLASS: c_int = 4;
pub(crate) const ASSERT_CHAR_CLASS_NEG: c_int = 8;
pub(crate) const ASSERT_AT_BOW: c_int = 16;
pub(crate) const ASSERT_AT_EOW: c_int = 32;
pub(crate) const ASSERT_AT_WB: c_int = 64;
pub(crate) const ASSERT_AT_WB_NEG: c_int = 128;
pub(crate) const ASSERT_BACKREF: c_int = 256;
pub(crate) const ASSERT_LAST: c_int = ASSERT_BACKREF;

/// `tre_tag_direction_t` in `tre.h`.
///
/// The source initializes the allocated direction array bytewise to `-1`
/// before assigning its `TRE_TAG_MINIMIZE`/`TRE_TAG_MAXIMIZE` members.  Keep
/// the C integer representation rather than a Rust enum so that temporary
/// source state never becomes an invalid Rust discriminant.
pub(crate) type TreTagDirection = c_int;
pub(crate) const TRE_TAG_MINIMIZE: TreTagDirection = 0;
pub(crate) const TRE_TAG_MAXIMIZE: TreTagDirection = 1;

/// `struct tre_submatch_data` in `tre.h`.
#[repr(C)]
pub(crate) struct TreSubmatchData {
    pub(crate) so_tag: c_int,
    pub(crate) eo_tag: c_int,
    pub(crate) parents: *mut c_int,
}

/// `struct tnfa` in `tre.h`.
///
/// `regex_t.__opaque` receives one heap-allocated instance after source
/// compilation succeeds.  The complete allocation graph is intentionally
/// explicit because the source's `regfree` distinguishes transition tags,
/// negative class arrays, tag directions, minimal tags, submatch parents,
/// and the TNFA record itself.
#[repr(C)]
pub(crate) struct TreTnfa {
    pub(crate) transitions: *mut TreTnfaTransition,
    pub(crate) num_transitions: u32,
    pub(crate) initial: *mut TreTnfaTransition,
    pub(crate) final_state: *mut TreTnfaTransition,
    pub(crate) submatch_data: *mut TreSubmatchData,
    pub(crate) firstpos_chars: *mut c_char,
    pub(crate) first_char: c_int,
    pub(crate) num_submatches: u32,
    pub(crate) tag_directions: *mut TreTagDirection,
    pub(crate) minimal_tags: *mut c_int,
    pub(crate) num_tags: c_int,
    pub(crate) num_minimals: c_int,
    pub(crate) end_tag: c_int,
    pub(crate) num_states: c_int,
    pub(crate) cflags: c_int,
    pub(crate) have_backrefs: c_int,
    pub(crate) have_approx: c_int,
}

/// `struct tre_list` in the `tre-mem.h` portion of `tre.h`.
#[repr(C)]
pub(crate) struct TreList {
    pub(crate) data: *mut c_void,
    pub(crate) next: *mut TreList,
}

/// `struct tre_mem_struct` in the `tre-mem.h` portion of `tre.h`.
#[repr(C)]
pub(crate) struct TreMem {
    pub(crate) blocks: *mut TreList,
    pub(crate) current: *mut TreList,
    pub(crate) ptr: *mut c_char,
    pub(crate) n: usize,
    pub(crate) failed: c_int,
    pub(crate) provided: *mut *mut c_void,
}

pub(crate) const TRE_MEM_BLOCK_SIZE: usize = 1024;

pub(crate) const REG_EXTENDED: c_int = 1;
pub(crate) const REG_ICASE: c_int = 2;
pub(crate) const REG_NEWLINE: c_int = 4;
pub(crate) const REG_NOSUB: c_int = 8;
pub(crate) const REG_NOTBOL: c_int = 1;
pub(crate) const REG_NOTEOL: c_int = 2;

pub(crate) const REG_OK: c_int = 0;
pub(crate) const REG_NOMATCH: c_int = 1;
pub(crate) const REG_BADPAT: c_int = 2;
pub(crate) const REG_ECOLLATE: c_int = 3;
pub(crate) const REG_ECTYPE: c_int = 4;
pub(crate) const REG_EESCAPE: c_int = 5;
pub(crate) const REG_ESUBREG: c_int = 6;
pub(crate) const REG_EBRACK: c_int = 7;
pub(crate) const REG_EPAREN: c_int = 8;
pub(crate) const REG_EBRACE: c_int = 9;
pub(crate) const REG_BADBR: c_int = 10;
pub(crate) const REG_ERANGE: c_int = 11;
pub(crate) const REG_ESPACE: c_int = 12;
pub(crate) const REG_BADRPT: c_int = 13;

const _: () = assert!(core::mem::size_of::<regex_t>() == 64);
const _: () = assert!(core::mem::align_of::<regex_t>() == 8);
const _: () = assert!(core::mem::size_of::<regmatch_t>() == 16);
const _: () = assert!(core::mem::size_of::<TreTnfaTransition>() == 56);
const _: () = assert!(core::mem::size_of::<TreSubmatchData>() == 16);
const _: () = assert!(core::mem::size_of::<TreTnfa>() == 104);
const _: () = assert!(core::mem::size_of::<TreList>() == 16);
const _: () = assert!(core::mem::size_of::<TreMem>() == 48);
