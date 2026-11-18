//! Raw linker-array boundary bridges for the Linux/x86-64 static-PIE slice.
//!
//! The linker may resolve an empty array's start and end symbols to the same
//! address. These RIP-relative address bridges keep that raw ELF fact outside
//! Rust's distinct-static assumptions.

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    r#"
    .text
    .global __crabc_preinit_array_start_address
    .hidden __crabc_preinit_array_start_address
    .type __crabc_preinit_array_start_address,@function
__crabc_preinit_array_start_address:
    lea rax, [rip + __preinit_array_start]
    ret

    .global __crabc_preinit_array_end_address
    .hidden __crabc_preinit_array_end_address
    .type __crabc_preinit_array_end_address,@function
__crabc_preinit_array_end_address:
    lea rax, [rip + __preinit_array_end]
    ret

    .global __crabc_init_array_start_address
    .hidden __crabc_init_array_start_address
    .type __crabc_init_array_start_address,@function
__crabc_init_array_start_address:
    lea rax, [rip + __init_array_start]
    ret

    .global __crabc_init_array_end_address
    .hidden __crabc_init_array_end_address
    .type __crabc_init_array_end_address,@function
__crabc_init_array_end_address:
    lea rax, [rip + __init_array_end]
    ret

    .global __crabc_fini_array_start_address
    .hidden __crabc_fini_array_start_address
    .type __crabc_fini_array_start_address,@function
__crabc_fini_array_start_address:
    lea rax, [rip + __fini_array_start]
    ret

    .global __crabc_fini_array_end_address
    .hidden __crabc_fini_array_end_address
    .type __crabc_fini_array_end_address,@function
__crabc_fini_array_end_address:
    lea rax, [rip + __fini_array_end]
    ret

    .section .note.GNU-stack,"",@progbits
"#,
);

#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    r#"
    .text
    .global __crabc_preinit_array_start_address
    .hidden __crabc_preinit_array_start_address
    .type __crabc_preinit_array_start_address,%function
__crabc_preinit_array_start_address:
    adrp x0, __preinit_array_start
    add x0, x0, :lo12:__preinit_array_start
    ret

    .global __crabc_preinit_array_end_address
    .hidden __crabc_preinit_array_end_address
    .type __crabc_preinit_array_end_address,%function
__crabc_preinit_array_end_address:
    adrp x0, __preinit_array_end
    add x0, x0, :lo12:__preinit_array_end
    ret

    .global __crabc_init_array_start_address
    .hidden __crabc_init_array_start_address
    .type __crabc_init_array_start_address,%function
__crabc_init_array_start_address:
    adrp x0, __init_array_start
    add x0, x0, :lo12:__init_array_start
    ret

    .global __crabc_init_array_end_address
    .hidden __crabc_init_array_end_address
    .type __crabc_init_array_end_address,%function
__crabc_init_array_end_address:
    adrp x0, __init_array_end
    add x0, x0, :lo12:__init_array_end
    ret

    .global __crabc_fini_array_start_address
    .hidden __crabc_fini_array_start_address
    .type __crabc_fini_array_start_address,%function
__crabc_fini_array_start_address:
    adrp x0, __fini_array_start
    add x0, x0, :lo12:__fini_array_start
    ret

    .global __crabc_fini_array_end_address
    .hidden __crabc_fini_array_end_address
    .type __crabc_fini_array_end_address,%function
__crabc_fini_array_end_address:
    adrp x0, __fini_array_end
    add x0, x0, :lo12:__fini_array_end
    ret

    .section .note.GNU-stack,"",%progbits
"#,
);
