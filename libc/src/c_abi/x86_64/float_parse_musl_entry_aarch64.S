/* AArch64 translation of pinned native musl; see float_parse.rs for provenance and license. */
/* musl-1.2.6/src/stdlib/strtod.c */
	.arch armv8-a
	.text
	.section	.text.strtox,"ax",@progbits
	.align	2
	.type	strtox, %function
strtox:
	stp	x30, x19, [sp, -288]!
	mov	x19, x0
	str	x0, [sp, 56]
	str	x0, [sp, 136]
	mov	x0, -1
	stp	x20, x21, [sp, 16]
	mov	w21, w2
	mov	x20, x1
	mov	x1, 0
	str	x0, [sp, 64]
	add	x0, sp, 48
	str	x0, [sp, 40]
	bl	crabc_x86_float_parse_shlim
	ldr	x0, [sp, 40]
	mov	w1, w21
	mov	w2, 1
	bl	crabc_x86_float_parse_floatscan
	cbz	x20, .Lcrabc_float_parse_musl_entry_0_1
	ldr	x0, [sp, 56]
	ldr	x1, [sp, 136]
	sub	x0, x0, x1
	ldr	x1, [sp, 248]
	add	x0, x0, x1
	add	x19, x19, x0
	str	x19, [x20]
.Lcrabc_float_parse_musl_entry_0_1:
	ldp	x20, x21, [sp, 16]
	ldp	x30, x19, [sp], 288
	ret
	.size	strtox, .-strtox
	.section	.text.strtof,"ax",@progbits
	.align	2
	.global	strtof
	.type	strtof, %function
strtof:
	mov	w2, 0
	str	x30, [sp, -16]!
	bl	strtox
	bl	__trunctfsf2
	ldr	x30, [sp], 16
	ret
	.size	strtof, .-strtof
	.section	.text.strtod,"ax",@progbits
	.align	2
	.global	strtod
	.type	strtod, %function
strtod:
	mov	w2, 1
	str	x30, [sp, -16]!
	bl	strtox
	bl	__trunctfdf2
	ldr	x30, [sp], 16
	ret
	.size	strtod, .-strtod
	.section	.text.strtold,"ax",@progbits
	.align	2
	.global	strtold
	.type	strtold, %function
strtold:
	mov	w2, 2
	b	strtox
	.size	strtold, .-strtold
	.hidden	crabc_x86_float_parse_floatscan
	.hidden	crabc_x86_float_parse_shlim
	.global	__trunctfdf2
	.global	__trunctfsf2
	.section	.note.GNU-stack,"",@progbits

/* musl-1.2.6/src/stdlib/atof.c */
	.arch armv8-a
	.text
	.section	.text.atof,"ax",@progbits
	.align	2
	.global	atof
	.type	atof, %function
atof:
	mov	x1, 0
	b	strtod
	.size	atof, .-atof
	.section	.note.GNU-stack,"",@progbits
