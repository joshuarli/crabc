#![no_std]

// This source-only probe selects the exact x86 control-transfer assembly
// without building the separately selected `crabc-libc` static archive.
include!("../../libc/src/c_abi/x86_64/static_archive_member.rs");

#[path = "../../libc/src/c_abi/x86_64/setjmp.rs"]
mod setjmp;
