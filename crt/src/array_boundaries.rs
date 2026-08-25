//! Raw linker-array boundary address bridges.
//!
//! Empty linker arrays are permitted to give their start and end symbols the
//! same address. Rust declarations of two distinct `static`s may be optimized
//! under the opposite identity assumption, so this small AArch64 assembly
//! bridge returns the linker-computed addresses as opaque raw values instead.

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

    .section .note.GNU-stack,"",@progbits
"#,
);
