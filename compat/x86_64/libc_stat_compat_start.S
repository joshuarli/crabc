/* Test-only static x86-64 entry shim for libc_stat_compat_probe.c.
 *
 * `ERRNO` is the selected archive's sole TLS datum. The static test executable
 * has no crabc CRT or loader yet, so the shim supplies one zero-initialized
 * initial-TLS scratch block plus the one-word x86 Variant-II thread-pointer
 * record. It installs that record before the C probe calls __errno_location.
 * This is deliberately
 * fixture-local: it does not initialize a general TLS image, support threads,
 * or provide application startup outside this one archive proof.
 */

    .section .bss
    .balign 64
crabc_x86_64_stat_compat_initial_tls:
    .zero 4096
crabc_x86_64_stat_compat_thread_pointer:
    .zero 64

    .text
    .globl _start
    .type _start,@function
_start:
    xor %ebp, %ebp

    /* arch_prctl(ARCH_SET_FS, thread_pointer) = syscall 158. */
    lea crabc_x86_64_stat_compat_thread_pointer(%rip), %rsi
    mov $0x1002, %edi
    mov $158, %eax
    syscall
    test %rax, %rax
    js .Ltls_failure

    /* x86 initial-exec code reads the thread pointer from %fs:0. */
    mov %rsi, %fs:0

    and $-16, %rsp
    call crabc_x86_64_stat_compat_probe
    mov %eax, %edi
    mov $60, %eax
    syscall

.Ltls_failure:
    mov $127, %edi
    mov $60, %eax
    syscall
    .size _start, .-_start

    .section .note.GNU-stack,"",@progbits
