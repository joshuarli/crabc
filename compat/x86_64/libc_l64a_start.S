/* Test-only static x86-64 entry shim for the selected l64a fixture.
 *
 * The selected l64a leaf owns one ordinary BSS scratch buffer, no errno, and
 * no TLS. This aligns the initial stack, runs the C probe, and exits; it is
 * not CRT, pthread/TLS lifecycle, or application-startup code.
 */

    .text
#ifdef CRABC_L64A_FREESTANDING
    .globl _start
    .type _start,@function
_start:
    xor %ebp, %ebp
    and $-16, %rsp
    call crabc_x86_64_l64a_probe
    mov %eax, %edi
    mov $60, %eax
    syscall
    .size _start, .-_start
#endif

/* Clone one task into the caller's address space without selecting a C thread
 * runtime. The worker only touches the shared l64a buffer and atomic probe
 * state; it uses this private stack and exits via the kernel syscall.
 */
    .globl crabc_l64a_spawn_shared_worker
    .type crabc_l64a_spawn_shared_worker,@function
crabc_l64a_spawn_shared_worker:
    mov %rdi, %rsi
    and $-16, %rsi
    mov $0x10f00, %edi
    mov $56, %eax
    syscall
    test %eax, %eax
    jnz 1f
    call crabc_l64a_shared_worker
    xor %edi, %edi
    mov $60, %eax
    syscall
1:
    ret
    .size crabc_l64a_spawn_shared_worker, .-crabc_l64a_spawn_shared_worker

    .section .note.GNU-stack,"",@progbits
