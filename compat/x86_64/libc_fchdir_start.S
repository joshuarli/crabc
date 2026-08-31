/* Freestanding static entry for libc_fchdir_probe.c.
 *
 * The selected archive owns the direct initial-TLS errno slot that this
 * boundary observes. This evidence-only shim invokes its private bootstrap;
 * it is neither a general CRT nor a general TLS runtime.
 */
	.text
#ifdef CRABC_FCHDIR_FREESTANDING
	.global _start
	.type _start,@function
_start:
	mov %rsp, %rdi
	call __crabc_x86_static_tls_bootstrap
	test %eax, %eax
	jne 1f
	call crabc_x86_64_fchdir_probe
	mov %eax, %edi
	/* exit_group ends the isolated CWD-mutating fixture process. */
	mov $231, %eax
	syscall
1:
	mov $127, %edi
	mov $231, %eax
	syscall
	.size _start, .-_start
#endif
	.section .note.GNU-stack,"",@progbits
