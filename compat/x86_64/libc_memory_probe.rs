#![no_std]

// This source-only probe selects only the pinned-musl-derived x86 C memory
// leaf. It does not build the selected static archive or claim that a
// complete x86 C runtime exists.
include!("../../libc/src/c_abi/x86_64/static_archive_member.rs");

#[path = "../../libc/src/c_abi/x86_64/memory.rs"]
mod memory;
