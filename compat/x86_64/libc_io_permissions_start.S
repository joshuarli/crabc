/* Freestanding static entry for the selected iopl/ioperm fixture.
 *
 * The archive owns the only initial-TLS errno bootstrap needed for invalid
 * syscall results. This shim does not request I/O permissions or execute any
 * port-I/O instruction.
 */
	.text
#ifdef CRABC_IO_PERMISSIONS_FREESTANDING
	.global _start
	.type _start,@function
_start:
	mov %rsp, %rdi
	call __crabc_x86_static_tls_bootstrap
	test %eax, %eax
	jne 1f
	call crabc_x86_64_io_permissions_probe
	mov %eax, %edi
	/* exit_group closes unexpected fixture failure paths. */
	mov $231, %eax
	syscall
1:
	mov $127, %edi
	mov $231, %eax
	syscall
	.size _start, .-_start
#endif
	.section .note.GNU-stack,"",@progbits
