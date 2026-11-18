/* AArch64 translation of pinned native musl; see float_parse.rs for provenance and license. */
/* musl-1.2.6/src/stdlib/wcstod.c */
	.arch armv8-a
	.text
	.section	.rodata.do_read.str4.8,"aMS",@progbits,4
	.align	3
.Lcrabc_float_parse_locale_musl_0_C0:
	.string	"@"
	.base64	"AAAAAAAA"
	.section	.text.do_read,"ax",@progbits
	.align	2
	.type	do_read, %function
do_read:
	mov	x6, x0
	adrp	x5, .Lcrabc_float_parse_locale_musl_0_C0
	ldr	x0, [x0, 152]
	add	x5, x5, :lo12:.Lcrabc_float_parse_locale_musl_0_C0
	mov	x4, 0
	mov	w7, 64
	ldr	w3, [x0]
	cmp	w3, 0
	csel	x5, x5, x0, eq
	b	.Lcrabc_float_parse_locale_musl_0_3
.Lcrabc_float_parse_locale_musl_0_6:
	ldr	x0, [x6, 88]
	cmp	w3, 128
	csel	w3, w3, w7, cc
	add	x5, x5, 4
	strb	w3, [x0, x4]
	add	x4, x4, 1
.Lcrabc_float_parse_locale_musl_0_3:
	ldr	x0, [x6, 96]
	cmp	x0, x4
	bls	.Lcrabc_float_parse_locale_musl_0_5
	ldr	w3, [x5]
	cbnz	w3, .Lcrabc_float_parse_locale_musl_0_6
.Lcrabc_float_parse_locale_musl_0_5:
	ldr	x3, [x6, 88]
	str	x5, [x6, 152]
	cmp	x4, 0
	add	x0, x3, x4
	stp	x3, x0, [x6, 8]
	ccmp	x2, 0, 4, ne
	mov	x0, 0
	bne	.Lcrabc_float_parse_locale_musl_0_12
.Lcrabc_float_parse_locale_musl_0_1:
	ret
.Lcrabc_float_parse_locale_musl_0_12:
	add	x0, x3, 1
	str	x0, [x6, 8]
	ldrb	w0, [x3]
	strb	w0, [x1]
	mov	x0, 1
	b	.Lcrabc_float_parse_locale_musl_0_1
	.size	do_read, .-do_read
	.section	.text.wcstox,"ax",@progbits
	.align	2
	.type	wcstox, %function
wcstox:
	movi	v31.4s, 0
	stp	x30, x19, [sp, -352]!
	stp	x20, x21, [sp, 16]
	add	x20, sp, 112
	mov	x21, x1
	stp	x22, x23, [sp, 32]
	mov	x22, x0
	add	x0, sp, 52
	stp	q31, q31, [x20]
	mov	w23, w2
	mov	x19, x22
	stp	q31, q31, [x20, 32]
	stp	q31, q31, [x20, 64]
	stp	q31, q31, [x20, 96]
	stp	q31, q31, [x20, 128]
	stp	q31, q31, [x20, 160]
	stp	q31, q31, [x20, 192]
	str	xzr, [x20, 224]
	stp	x0, x0, [sp, 120]
	str	x0, [sp, 200]
	mov	x0, 60
	str	x0, [sp, 208]
	mov	w0, -1
	str	w0, [sp, 252]
	adrp	x0, do_read
	add	x0, x0, :lo12:do_read
	str	x0, [sp, 176]
	b	.Lcrabc_float_parse_locale_musl_0_14
.Lcrabc_float_parse_locale_musl_0_15:
	add	x19, x19, 4
.Lcrabc_float_parse_locale_musl_0_14:
	ldr	w0, [x19]
	bl	iswspace
	cbnz	w0, .Lcrabc_float_parse_locale_musl_0_15
	mov	x0, x20
	mov	x1, 0
	str	x19, [sp, 264]
	bl	crabc_x86_float_parse_shlim
	mov	w1, w23
	mov	x0, x20
	mov	w2, 1
	bl	crabc_x86_float_parse_floatscan
	cbz	x21, .Lcrabc_float_parse_locale_musl_0_13
	ldr	x0, [sp, 120]
	ldr	x1, [sp, 200]
	sub	x0, x0, x1
	ldr	x1, [sp, 312]
	adds	x0, x0, x1
	add	x19, x19, x0, lsl 2
	csel	x19, x19, x22, ne
	str	x19, [x21]
.Lcrabc_float_parse_locale_musl_0_13:
	ldp	x20, x21, [sp, 16]
	ldp	x22, x23, [sp, 32]
	ldp	x30, x19, [sp], 352
	ret
	.size	wcstox, .-wcstox
	.section	.text.wcstof,"ax",@progbits
	.align	2
	.global	wcstof
	.type	wcstof, %function
wcstof:
	mov	w2, 0
	str	x30, [sp, -16]!
	bl	wcstox
	bl	__trunctfsf2
	ldr	x30, [sp], 16
	ret
	.size	wcstof, .-wcstof
	.section	.text.wcstod,"ax",@progbits
	.align	2
	.global	wcstod
	.type	wcstod, %function
wcstod:
	mov	w2, 1
	str	x30, [sp, -16]!
	bl	wcstox
	bl	__trunctfdf2
	ldr	x30, [sp], 16
	ret
	.size	wcstod, .-wcstod
	.section	.text.wcstold,"ax",@progbits
	.align	2
	.global	wcstold
	.type	wcstold, %function
wcstold:
	mov	w2, 2
	b	wcstox
	.size	wcstold, .-wcstold
	.hidden	crabc_x86_float_parse_floatscan
	.hidden	crabc_x86_float_parse_shlim
	.global	__trunctfdf2
	.global	__trunctfsf2
	.section	.note.GNU-stack,"",@progbits
