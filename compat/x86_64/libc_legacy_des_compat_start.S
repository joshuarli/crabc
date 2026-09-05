/* Test-only static Linux/x86-64 entry for the inert-DES feature probe.
 *
 * It publishes selected static initial TLS so errno can be tested without
 * importing a CRT, dynamic runtime, or a general process-start contract.
 */
    .text
    .globl _start
    .type _start,@function
_start:
    mov %rsp, %rdi
    call __crabc_x86_static_tls_bootstrap
    test %eax, %eax
    jne .Lstartup_failure

    call crabc_x86_legacy_des_compat_probe
    mov %eax, %edi
    mov $231, %eax
    syscall
    ud2

.Lstartup_failure:
    mov $127, %edi
    mov $231, %eax
    syscall
    ud2
    .size _start, .-_start

    .section .note.GNU-stack,"",@progbits
