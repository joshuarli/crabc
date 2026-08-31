/* Freestanding static entry for libc_sync_file_range_probe.c.
 *
 * The selected archive owns the initial-TLS errno datum. This test-only shim
 * initializes that private state before the fixture uses errno; it is neither
 * a general CRT nor a filesystem/descriptor runtime.
 */
	.text
#ifdef CRABC_SYNC_FILE_RANGE_FREESTANDING
	.global _start
	.type _start,@function
_start:
	mov %rsp, %rdi
	call __crabc_x86_static_tls_bootstrap
	test %eax, %eax
	jne 1f
	call crabc_x86_64_sync_file_range_probe
	mov %eax, %edi
	/* exit_group closes fixture descriptors without selecting C exit. */
	mov $231, %eax
	syscall
1:
	mov $127, %edi
	mov $231, %eax
	syscall
	.size _start, .-_start
#endif
	.section .note.GNU-stack,"",@progbits
