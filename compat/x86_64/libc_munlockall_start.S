/* Freestanding static entry for the selected munlockall fixture.
 *
 * The archive owns first-thread initial-TLS setup for C errno. The release
 * request runs only inside this disposable fixture process and does not claim
 * process lock-policy ownership or a general C runtime.
 */
	.text
#ifdef CRABC_MUNLOCKALL_FREESTANDING
	.global _start
	.type _start,@function
_start:
	mov %rsp, %rdi
	call __crabc_x86_static_tls_bootstrap
	test %eax, %eax
	jne 1f
	call crabc_x86_64_munlockall_probe
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
