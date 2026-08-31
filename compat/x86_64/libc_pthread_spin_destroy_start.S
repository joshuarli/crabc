/* Freestanding static entry for libc_pthread_spin_destroy_probe.c.
 *
 * This intentionally owns no CRT, TLS, errno, thread, or spin-lock runtime
 * setup. The selected destroy leaf neither observes nor changes caller storage;
 * this shim merely returns its fixture status through Linux x86-64 exit(60).
 */
	.text
	.globl _start
	.type _start,@function
_start:
	call crabc_x86_64_pthread_spin_destroy_probe
	mov %eax, %edi
	mov $60, %eax
	syscall
	.size _start, .-_start

	.section .note.GNU-stack,"",@progbits
