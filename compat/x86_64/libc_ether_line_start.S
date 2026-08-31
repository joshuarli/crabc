/* Freestanding static entry for libc_ether_line_probe.c.
 *
 * This no-state evidence shim is neither a CRT nor an Ethernet runtime owner.
 */
	.text
#ifdef CRABC_ETHER_LINE_FREESTANDING
	.global _start
	.type _start,@function
_start:
	call crabc_x86_64_ether_line_probe
	mov %eax, %edi
	/* exit ends only this evidence fixture. */
	mov $60, %eax
	syscall
	.size _start, .-_start
#endif
	.section .note.GNU-stack,"",@progbits
