/* Test-only static x86-64 entry shim for libc_environment_probe.c.
 *
 * The shim preserves the untouched Linux entry stack, invokes the archive's
 * selected Static Initial TLS v1 bootstrap, then calls its musl-shaped
 * __libc_start_main.  This proves the environment owner sees the original
 * envp before main without claiming a Rust-produced CRT object, general
 * process startup, pthread/TLS lifecycle, dynamic TLS, or a loader.
 */

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
    mov (%r12), %esi
    lea 8(%r12), %rdx
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
