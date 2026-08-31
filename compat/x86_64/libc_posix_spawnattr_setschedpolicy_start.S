/* Freestanding static entry for libc_posix_spawnattr_setschedpolicy_probe.c.
 *
 * This evidence shim is neither a CRT nor a process-spawn runtime owner.
 */

	.text
#ifdef CRABC_POSIX_SPAWNATTR_SETSCHEDPOLICY_FREESTANDING
	.global _start
	.type _start,@function
_start:
	call crabc_x86_64_posix_spawnattr_setschedpolicy_probe
	mov %eax, %edi
	/* exit ends only this evidence fixture. */
	mov $60, %eax
	syscall
	.size _start, .-_start
#endif
	.section .note.GNU-stack,"",@progbits
