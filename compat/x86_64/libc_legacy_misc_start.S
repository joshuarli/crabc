/* Test-only static x86-64 entry for the frozen legacy.misc fixture.
 *
 * fmtmsg reads the inherited process environment for MSGVERB, while the
 * retained issetugid leaf observes static-startup security state.  This uses
 * the already-selected static Initial TLS and bounded __libc_start_main handoff
 * solely to publish those two prerequisites before main.  It is not a CRT,
 * dynamic libc, loader, sysroot, or general legacy-runtime claim.
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
