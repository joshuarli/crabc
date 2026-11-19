/* Freestanding static entry for libc_sethostent_probe.c.
 *
 * This no-state evidence shim is neither a CRT nor a netdb/runtime owner.
 */

	.text
#ifdef CRABC_SETHOSTENT_FREESTANDING
	.global _start
	.type _start,@function
_start:
#if defined(__aarch64__)
    bl crabc_x86_64_sethostent_probe
    mov x8, #93
    svc #0
#else
	call crabc_x86_64_sethostent_probe
	mov %eax, %edi
	/* exit ends only this evidence fixture. */
	mov $60, %eax
	syscall
#endif
	.size _start, .-_start
#endif
	.section .note.GNU-stack,"",@progbits
