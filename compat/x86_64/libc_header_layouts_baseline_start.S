/* Test-only static x86-64 entry shim for the header/layout baseline fixture.
 *
 * The selected archive has only initial-TLS errno data.  This fixture creates
 * a bounded Variant-II %fs scratch block before calling its C entry.  It is
 * neither a CRT nor a C++ constructor/exception startup, pthread, dynamic
 * TLS, loader, auxv, or application-startup implementation.
 */

    .section .bss
    .balign 64
crabc_x86_64_header_layouts_baseline_initial_tls:
    .zero 4096
crabc_x86_64_header_layouts_baseline_thread_pointer:
    .zero 64

    .text
    .globl _start
    .type _start,@function
_start:
    xor %ebp, %ebp

    /* arch_prctl(ARCH_SET_FS, thread_pointer) = syscall 158. */
    lea crabc_x86_64_header_layouts_baseline_thread_pointer(%rip), %rsi
    mov $0x1002, %edi
    mov $158, %eax
    syscall
    test %rax, %rax
    js .Ltls_failure

    mov %rsi, %fs:0
    and $-16, %rsp
    call crabc_x86_64_header_layouts_baseline_probe
    mov %eax, %edi
    mov $60, %eax
    syscall

.Ltls_failure:
    mov $127, %edi
    mov $60, %eax
    syscall
    .size _start, .-_start

    .section .note.GNU-stack,"",@progbits
