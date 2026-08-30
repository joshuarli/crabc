/* Freestanding static entry for libc_extended_attributes_probe.c.
 *
 * The selected archive owns errno's initial TLS storage. Delegate first-thread
 * setup to its private bootstrap before entering the project-header fixture.
 */
	.text
#ifdef CRABC_EXTENDED_ATTRIBUTES_FREESTANDING
	.global _start
	.type _start,@function
_start:
	mov %rsp, %rdi
	call __crabc_x86_static_tls_bootstrap
	test %eax, %eax
	jne 1f
	call crabc_x86_64_extended_attributes_probe
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
