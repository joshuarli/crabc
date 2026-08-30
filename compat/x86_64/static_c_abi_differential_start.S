/* Test-only entry for static_c_abi_differential_memfd_probe.c.
 *
 * The selected archive, not this shim, owns Static Initial TLS v1 setup. This
 * retains the Linux entry stack for its hidden bootstrap and exits directly.
 * It is not a CRT, dynamic-TLS, or application-startup implementation.
 */
	.text
	.globl _start
	.type _start,@function
_start:
	xor %ebp, %ebp
	mov %rsp, %rdi
	and $-16, %rsp
	call __crabc_x86_static_tls_bootstrap
	test %eax, %eax
	jne .Ltls_failure
	call crabc_x86_64_static_c_abi_differential_probe
	mov %eax, %edi
	mov $60, %eax
	syscall

.Ltls_failure:
	mov $127, %edi
	mov $60, %eax
	syscall
	.size _start, .-_start
	.section .note.GNU-stack,"",@progbits
