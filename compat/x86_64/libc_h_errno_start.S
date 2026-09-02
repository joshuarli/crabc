/* Freestanding entry for libc_h_errno_probe.c.
 *
 * h_errno's selected main/worker contract requires Static Initial TLS v1
 * before its C accessor or selected pthread worker runs. This fixture-only
 * entry establishes that existing private prerequisite; it is not a CRT.
 */
	.text
#ifdef CRABC_H_ERRNO_FREESTANDING
	.global _start
	.type _start,@function
_start:
	mov %rsp, %r12
	mov %rsp, %rdi
	call __crabc_x86_static_tls_bootstrap
	test %eax, %eax
	jne 1f
	call crabc_x86_64_h_errno_probe
	mov %eax, %edi
	mov $231, %eax
	syscall
1:
	mov $127, %edi
	mov $231, %eax
	syscall
	.size _start, .-_start
#endif
	.section .note.GNU-stack,"",@progbits
