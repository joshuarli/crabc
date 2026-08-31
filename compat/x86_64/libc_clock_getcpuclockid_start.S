/* Freestanding static entry for the selected clock_getcpuclockid fixture.
 *
 * The selected boundary returns direct positive status values and needs no C
 * errno/TLS/CRT bootstrap. This shim adds only exit_group on completion.
 */
	.text
#ifdef CRABC_CLOCK_GETCPUCLOCKID_FREESTANDING
	.global _start
	.type _start,@function
_start:
	xor %ebp, %ebp
	and $-16, %rsp
	call crabc_x86_64_clock_getcpuclockid_probe
	mov %eax, %edi
	/* exit_group closes unexpected fixture failure paths. */
	mov $231, %eax
	syscall
	.size _start, .-_start
#endif
	.section .note.GNU-stack,"",@progbits
