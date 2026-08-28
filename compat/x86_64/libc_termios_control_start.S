/* Test-only static x86-64 entry shim for selected termios-control evidence.
 *
 * The selected archive retains one initial-TLS errno datum. x86 CRT and
 * loader lifecycle remain unselected, so this fixture-local entry creates
 * just enough %fs initial-TLS state to run one static C program.
 */

    .section .bss
    .balign 64
crabc_x86_64_termios_control_initial_tls:
    .zero 4096
crabc_x86_64_termios_control_thread_pointer:
    .zero 64

    .text
    .globl _start
    .type _start,@function
_start:
    xor %ebp, %ebp

    /* arch_prctl(ARCH_SET_FS, thread_pointer) = syscall 158. */
    lea crabc_x86_64_termios_control_thread_pointer(%rip), %rsi
    mov $0x1002, %edi
    mov $158, %eax
    syscall
    test %rax, %rax
    js .Ltls_failure

    /* x86 initial-exec errno code reads its thread pointer from %fs:0. */
    mov %rsi, %fs:0

    and $-16, %rsp
    call crabc_x86_64_termios_control_probe
    mov %eax, %edi
    mov $60, %eax
    syscall

.Ltls_failure:
    mov $127, %edi
    mov $60, %eax
    syscall
    .size _start, .-_start

    .section .note.GNU-stack,"",@progbits
