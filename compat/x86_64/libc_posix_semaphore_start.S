/* Freestanding static entry for libc_posix_semaphore_probe.c.
 *
 * The selected archive owns the initial-TLS errno datum.  The candidate uses
 * its private bootstrap before the project-header C body, while raw fork and
 * shared mapping plumbing stay in the fixture.  This is neither a CRT nor a
 * pthread or named-semaphore runtime.
 */
	.text
	.globl _start
	.type _start,@function
_start:
	mov %rsp, %rdi
	call __crabc_x86_static_tls_bootstrap
	test %eax, %eax
	jne 1f
	call crabc_x86_64_posix_semaphore_probe
	mov %eax, %edi
	/* exit_group closes an unexpected candidate failure in both parent and
	 * any still-running fixture child process. */
	mov $231, %eax
	syscall
1:
	mov $127, %edi
	mov $231, %eax
	syscall
	.size _start, .-_start
	.section .note.GNU-stack,"",@progbits
