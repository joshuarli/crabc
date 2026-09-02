/* Freestanding static entry for libc_protocol_database_probe.c.
 *
 * This no-state evidence shim is neither a CRT nor a resolver or filesystem
 * runtime owner.
 */

	.text
#ifdef CRABC_PROTOCOL_DATABASE_FREESTANDING
	.global _start
	.type _start,@function
_start:
	xor %ebp, %ebp
	and $-16, %rsp
	call crabc_x86_64_protocol_database_probe
	mov %eax, %edi
	/* exit ends only this evidence fixture. */
	mov $60, %eax
	syscall
	.size _start, .-_start
#endif
	.section .note.GNU-stack,"",@progbits
