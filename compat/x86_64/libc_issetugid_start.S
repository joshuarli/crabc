/* Test-only static x86-64 entry for the bounded issetugid observation.
 *
 * The normal fixture preserves the Linux entry stack for static TLS and the
 * selected startup cache. Synthetic modes preserve that stack only for TLS,
 * then pass a bounded fake argv/envp/auxv sequence to prove AT_SECURE and
 * UID/EUID-mismatch values. They do not select a public auxv or credential API.
 */

/* AT_UID=11, AT_EUID=12, AT_GID=13, AT_EGID=14, AT_SECURE=23. */

#ifdef CRABC_ISSETUGID_SYNTHETIC
    .section .rodata
    .balign 8
crabc_x86_64_issetugid_argv0:
    .asciz "issetugid-synthetic"
    .balign 8
crabc_x86_64_issetugid_vectors:
    .quad crabc_x86_64_issetugid_argv0
    .quad 0
    .quad 0
    .quad 11
    .quad 777
    .quad 11
    .quad 1000
    .quad 12
#ifdef CRABC_ISSETUGID_SYNTHETIC_UID_MISMATCH
    .quad 1001
#else
    .quad 1000
#endif
    .quad 13
    .quad 1000
    .quad 14
    .quad 1000
    .quad 23
    .quad 0
#ifdef CRABC_ISSETUGID_SYNTHETIC_AT_SECURE
    .quad 23
    .quad 1
#endif
    .quad 0
    .quad 0
#endif

    .text
    .globl _start
    .type _start,@function
_start:
    mov %rsp, %r12
    xor %ebp, %ebp
    and $-16, %rsp

    mov %r12, %rdi
    call __crabc_x86_static_tls_bootstrap
    test %eax, %eax
    jne .Lstartup_failure

    lea main(%rip), %rdi
#ifdef CRABC_ISSETUGID_SYNTHETIC
    mov $1, %esi
    lea crabc_x86_64_issetugid_vectors(%rip), %rdx
#else
    mov (%r12), %esi
    lea 8(%r12), %rdx
#endif
    xor %ecx, %ecx
    xor %r8d, %r8d
    xor %r9d, %r9d
    call __libc_start_main
    ud2

.Lstartup_failure:
    mov $127, %edi
    mov $231, %eax
    syscall
    ud2
    .size _start, .-_start

    .section .note.GNU-stack,"",@progbits
