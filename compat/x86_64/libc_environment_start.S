/* Legacy test-only static x86-64 entry shim for libc_environment_probe.c.
 *
 * No current runner links this shim. `run_libc_environment.sh` instead links
 * real crabc `crt1`/`crti`/`crtn` objects, which is the only environment
 * evidence path allowed to prove constructor-before-main publication. This
 * retained shim passes a null init callback and therefore cannot make that
 * constructor claim; it remains solely as an older isolated startup harness.
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
