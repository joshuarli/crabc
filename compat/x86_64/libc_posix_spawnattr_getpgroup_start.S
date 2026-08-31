/* Freestanding static entry for libc_posix_spawnattr_getpgroup_probe.c.
 *
 * This evidence shim is neither a CRT nor a process-spawn runtime owner.
 */
	.text
	.global _start
	.type _start,@function
_start:
	call crabc_x86_64_posix_spawnattr_getpgroup_probe
	mov %eax, %edi
	/* exit ends only this evidence fixture. */
	mov $60, %eax
	syscall
	.size _start, .-_start

	.section .note.GNU-stack,"",@progbits
