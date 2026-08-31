/* Freestanding static entry for libc_endservent_probe.c.
 *
 * This no-state evidence shim is neither a CRT nor a service-database or
 * resolver-runtime owner.
 */
	.text
#ifdef CRABC_ENDSERVENT_FREESTANDING
	.global _start
	.type _start,@function
_start:
	xor %ebp, %ebp
	and $-16, %rsp
	call crabc_x86_64_endservent_probe
	mov %eax, %edi
	/* exit ends only this evidence fixture. */
	mov $60, %eax
	syscall
	.size _start, .-_start
#endif
	.section .note.GNU-stack,"",@progbits
