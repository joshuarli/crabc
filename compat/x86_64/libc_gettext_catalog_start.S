/* Freestanding static entry for libc_gettext_catalog_probe.c.
 *
 * The selected archive owns initial-exec errno storage. Its private Static
 * Initial TLS v1 bootstrap supplies the test process's first thread before the
 * no-catalog fixture runs; it is not a CRT, loader, or general TLS runtime.
 */
	.text
#ifdef CRABC_GETTEXT_CATALOG_FREESTANDING
	.global _start
	.type _start,@function
_start:
	mov %rsp, %rdi
	call __crabc_x86_static_tls_bootstrap
	test %eax, %eax
	jne 1f
	call crabc_x86_64_gettext_catalog_probe
	mov %eax, %edi
	mov $231, %eax
	syscall
1:
	mov $127, %edi
	mov $231, %eax
	syscall
	.size _start, .-_start
#endif
	.section .note.GNU-stack,"",@progbits
