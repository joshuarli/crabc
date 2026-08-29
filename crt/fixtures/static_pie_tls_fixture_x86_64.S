/*
 * Native x86-64 local-exec TLS companion for the static-PIE CRT fixture.
 *
 * The fixed initialized/TBSS words and 4096-byte image alignment force one
 * observable PT_TLS contract.  Every accessor uses an already-resolved
 * `@tpoff` displacement, so the fixture cannot succeed through a dynamic TLS
 * resolver or an ambient libc thread pointer.
 */

    .intel_syntax noprefix

    .section .tdata,"awT",@progbits
    .p2align 12
    .global crabc_x86_64_static_tls_initialized
    .hidden crabc_x86_64_static_tls_initialized
    .type crabc_x86_64_static_tls_initialized,@object
    .size crabc_x86_64_static_tls_initialized,8
crabc_x86_64_static_tls_initialized:
    .quad 0x746c735f696e6974

    .section .tbss,"awT",@nobits
    .p2align 3
    .global crabc_x86_64_static_tls_zero
    .hidden crabc_x86_64_static_tls_zero
    .type crabc_x86_64_static_tls_zero,@object
    .size crabc_x86_64_static_tls_zero,8
crabc_x86_64_static_tls_zero:
    .zero 8

    .text
    .global crabc_x86_64_static_tls_read_initialized
    .hidden crabc_x86_64_static_tls_read_initialized
    .type crabc_x86_64_static_tls_read_initialized,@function
crabc_x86_64_static_tls_read_initialized:
    mov rax, QWORD PTR fs:crabc_x86_64_static_tls_initialized@tpoff
    ret
    .size crabc_x86_64_static_tls_read_initialized,.-crabc_x86_64_static_tls_read_initialized

    .global crabc_x86_64_static_tls_write_initialized
    .hidden crabc_x86_64_static_tls_write_initialized
    .type crabc_x86_64_static_tls_write_initialized,@function
crabc_x86_64_static_tls_write_initialized:
    mov QWORD PTR fs:crabc_x86_64_static_tls_initialized@tpoff, rdi
    ret
    .size crabc_x86_64_static_tls_write_initialized,.-crabc_x86_64_static_tls_write_initialized

    .global crabc_x86_64_static_tls_read_zero
    .hidden crabc_x86_64_static_tls_read_zero
    .type crabc_x86_64_static_tls_read_zero,@function
crabc_x86_64_static_tls_read_zero:
    mov rax, QWORD PTR fs:crabc_x86_64_static_tls_zero@tpoff
    ret
    .size crabc_x86_64_static_tls_read_zero,.-crabc_x86_64_static_tls_read_zero

    .global crabc_x86_64_static_tls_write_zero
    .hidden crabc_x86_64_static_tls_write_zero
    .type crabc_x86_64_static_tls_write_zero,@function
crabc_x86_64_static_tls_write_zero:
    mov QWORD PTR fs:crabc_x86_64_static_tls_zero@tpoff, rdi
    ret
    .size crabc_x86_64_static_tls_write_zero,.-crabc_x86_64_static_tls_write_zero

    .global crabc_x86_64_static_tls_thread_pointer
    .hidden crabc_x86_64_static_tls_thread_pointer
    .type crabc_x86_64_static_tls_thread_pointer,@function
crabc_x86_64_static_tls_thread_pointer:
    mov rax, QWORD PTR fs:0
    ret
    .size crabc_x86_64_static_tls_thread_pointer,.-crabc_x86_64_static_tls_thread_pointer

    .section .note.GNU-stack,"",@progbits
