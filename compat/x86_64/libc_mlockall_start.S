/* Freestanding static entry for the selected mlockall fixture.
 *
 * The archive owns first-thread initial-TLS setup for C errno. Process-wide
 * lock effects are contained in this disposable fixture process, and cleanup
 * remains a raw syscall inside the C body rather than a candidate export.
 */
	.text
#ifdef CRABC_MLOCKALL_FREESTANDING
	.global _start
	.type _start,@function
_start:
	mov %rsp, %rdi
	call __crabc_x86_static_tls_bootstrap
	test %eax, %eax
	jne 1f
	call crabc_x86_64_mlockall_probe
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
