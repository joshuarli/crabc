/* AArch64 translation of pinned native musl; see float_parse.rs for provenance and license. */
/* musl-1.2.6/src/internal/shgetc.c */
	.arch armv8-a
	.text
	.section	.text.crabc_x86_float_parse_shlim,"ax",@progbits
	.align	2
	.local	crabc_x86_float_parse_shlim
	.hidden	crabc_x86_float_parse_shlim
	.type	crabc_x86_float_parse_shlim, %function
crabc_x86_float_parse_shlim:
	ldp	x2, x4, [x0, 8]
	ldr	x3, [x0, 88]
	sub	x3, x3, x2
	stp	x1, x3, [x0, 192]
	cbz	x1, .Lcrabc_float_parse_musl_support_0_2
	sub	x3, x4, x2
	add	x2, x2, x1
	cmp	x3, x1
	csel	x4, x2, x4, gt
.Lcrabc_float_parse_musl_support_0_2:
	str	x4, [x0, 184]
	ret
	.size	crabc_x86_float_parse_shlim, .-crabc_x86_float_parse_shlim
	.section	.text.crabc_x86_float_parse_shgetc,"ax",@progbits
	.align	2
	.local	crabc_x86_float_parse_shgetc
	.hidden	crabc_x86_float_parse_shgetc
	.type	crabc_x86_float_parse_shgetc, %function
crabc_x86_float_parse_shgetc:
	stp	x30, x19, [sp, -32]!
	mov	x19, x0
	ldr	x1, [x0, 8]
	ldr	x2, [x0, 88]
	str	x20, [sp, 16]
	ldp	x3, x4, [x0, 192]
	sub	x20, x1, x2
	add	x20, x20, x4
	cmp	x3, 0
	ccmp	x3, x20, 0, ne
	ble	.Lcrabc_float_parse_musl_support_0_8
	bl	__uflow
	ldr	x1, [x19, 8]
	ldr	x2, [x19, 88]
	tbnz	w0, #31, .Lcrabc_float_parse_musl_support_0_8
	ldr	x3, [x19, 192]
	add	x20, x20, 1
	ldr	x4, [x19, 16]
	cbz	x3, .Lcrabc_float_parse_musl_support_0_11
	sub	x3, x3, x20
	sub	x6, x4, x1
	add	x5, x1, x3
	cmp	x6, x3
	csel	x4, x5, x4, gt
.Lcrabc_float_parse_musl_support_0_11:
	sub	x3, x2, x1
	str	x4, [x19, 184]
	add	x3, x3, x20
	str	x3, [x19, 200]
	cmp	x1, x2
	bhi	.Lcrabc_float_parse_musl_support_0_7
	strb	w0, [x1, -1]
.Lcrabc_float_parse_musl_support_0_7:
	ldr	x20, [sp, 16]
	ldp	x30, x19, [sp], 32
	ret
.Lcrabc_float_parse_musl_support_0_8:
	sub	x0, x2, x1
	add	x0, x0, x20
	str	x0, [x19, 200]
	mov	x0, -1
	stp	x1, x0, [x19, 184]
	b	.Lcrabc_float_parse_musl_support_0_7
	.size	crabc_x86_float_parse_shgetc, .-crabc_x86_float_parse_shgetc
	.protected	__uflow
	.section	.note.GNU-stack,"",@progbits

/* musl-1.2.6/src/math/scalbn.c */
	.arch armv8-a
	.text
	.section	.text.crabc_x86_float_parse_scalbn,"ax",@progbits
	.align	2
	.local	crabc_x86_float_parse_scalbn
	.type	crabc_x86_float_parse_scalbn, %function
crabc_x86_float_parse_scalbn:
	cmp	w0, 1023
	ble	.Lcrabc_float_parse_musl_support_1_2
	mov	x1, 9214364837600034816
	fmov	d31, x1
	fmul	d0, d0, d31
	cmp	w0, 2046
	ble	.Lcrabc_float_parse_musl_support_1_3
	sub	w0, w0, #2046
	mov	w1, 1023
	cmp	w0, 1023
	fmul	d0, d0, d31
	csel	w0, w0, w1, le
	add	w0, w0, w1
.Lcrabc_float_parse_musl_support_1_3:
	fmov	d31, x0
	shl	d31, d31, 52
	fmul	d0, d0, d31
	ret
.Lcrabc_float_parse_musl_support_1_2:
	cmn	w0, #1022
	blt	.Lcrabc_float_parse_musl_support_1_4
	add	w0, w0, 1023
	b	.Lcrabc_float_parse_musl_support_1_3
.Lcrabc_float_parse_musl_support_1_4:
	mov	x1, 243194379878006784
	fmov	d31, x1
	fmul	d0, d0, d31
	cmn	w0, #1991
	blt	.Lcrabc_float_parse_musl_support_1_5
	add	w0, w0, 1992
	b	.Lcrabc_float_parse_musl_support_1_3
.Lcrabc_float_parse_musl_support_1_5:
	add	w0, w0, 1938
	fmul	d0, d0, d31
	adds	w0, w0, #1023
	csinc	w0, w0, wzr, gt
	b	.Lcrabc_float_parse_musl_support_1_3
	.size	crabc_x86_float_parse_scalbn, .-crabc_x86_float_parse_scalbn
	.section	.note.GNU-stack,"",@progbits

/* musl-1.2.6/src/math/scalbnl.c */
	.arch armv8-a
	.text
	.section	.text.crabc_x86_float_parse_scalbnl,"ax",@progbits
	.align	2
	.local	crabc_x86_float_parse_scalbnl
	.type	crabc_x86_float_parse_scalbnl, %function
crabc_x86_float_parse_scalbnl:
	stp	x30, x19, [sp, -32]!
	mov	w19, 16383
	cmp	w0, w19
	ble	.Lcrabc_float_parse_musl_support_2_2
	str	w0, [sp, 24]
	adrp	x0, .Lcrabc_float_parse_musl_support_2_C1
	add	x0, x0, :lo12:.Lcrabc_float_parse_musl_support_2_C1
	ldr	q1, [x0]
	bl	__multf3
	mov	v30.16b, v0.16b
	ldr	w0, [sp, 24]
	sub	w1, w0, w19
	cmp	w1, w19
	ble	.Lcrabc_float_parse_musl_support_2_3
	adrp	x1, .Lcrabc_float_parse_musl_support_2_C1
	add	x1, x1, :lo12:.Lcrabc_float_parse_musl_support_2_C1
	str	w0, [sp, 24]
	ldr	q1, [x1]
	bl	__multf3
	mov	v30.16b, v0.16b
	ldr	w0, [sp, 24]
	mov	w3, -32766
	add	w1, w0, w3
	cmp	w1, w19
	csel	w1, w1, w19, le
.Lcrabc_float_parse_musl_support_2_3:
	mov	w0, 16383
	add	w1, w1, w0
	mov	x2, 0
	mov	x3, 4611404543450677248
	fmov	d1, x2
	bfi	x3, x1, 48, 16
	mov	v0.16b, v30.16b
	fmov	v1.d[1], x3
	bl	__multf3
	ldp	x30, x19, [sp], 32
	ret
.Lcrabc_float_parse_musl_support_2_2:
	mov	v30.16b, v0.16b
	mov	w1, w0
	mov	w19, -16382
	cmp	w0, w19
	bge	.Lcrabc_float_parse_musl_support_2_3
	adrp	x1, .Lcrabc_float_parse_musl_support_2_C2
	add	x1, x1, :lo12:.Lcrabc_float_parse_musl_support_2_C2
	stp	w0, w0, [sp, 24]
	ldr	q1, [x1]
	bl	__multf3
	mov	v30.16b, v0.16b
	ldr	w1, [sp, 24]
	mov	w2, 16269
	add	w1, w1, w2
	cmp	w1, w19
	bge	.Lcrabc_float_parse_musl_support_2_3
	adrp	x0, .Lcrabc_float_parse_musl_support_2_C2
	add	x0, x0, :lo12:.Lcrabc_float_parse_musl_support_2_C2
	ldr	q1, [x0]
	bl	__multf3
	mov	v30.16b, v0.16b
	ldr	w0, [sp, 28]
	mov	w1, 32538
	add	w1, w0, w1
	cmp	w1, w19
	csel	w1, w1, w19, ge
	b	.Lcrabc_float_parse_musl_support_2_3
	.size	crabc_x86_float_parse_scalbnl, .-crabc_x86_float_parse_scalbnl
	.section	.rodata.cst16,"aM",@progbits,16
	.align	4
.Lcrabc_float_parse_musl_support_2_C1:
	.word	0
	.word	0
	.word	0
	.word	2147352576
	.align	4
.Lcrabc_float_parse_musl_support_2_C2:
	.word	0
	.word	0
	.word	0
	.word	7471104
	.global	__multf3
	.section	.note.GNU-stack,"",@progbits

/* musl-1.2.6/src/math/copysignl.c */
	.arch armv8-a
	.text
	.section	.text.crabc_x86_float_parse_copysignl,"ax",@progbits
	.align	2
	.local	crabc_x86_float_parse_copysignl
	.type	crabc_x86_float_parse_copysignl, %function
crabc_x86_float_parse_copysignl:
	sub	sp, sp, #32
	stp	q0, q1, [sp]
	ldp	x2, x3, [sp]
	ldr	x1, [sp, 24]
	ldr	x0, [sp, 8]
	add	sp, sp, 32
	lsr	x1, x1, 48
	fmov	d0, x2
	and	w1, w1, -32768
	ubfx	x0, x0, 48, 15
	orr	w0, w0, w1
	bfi	x3, x0, 48, 16
	fmov	v0.d[1], x3
	ret
	.size	crabc_x86_float_parse_copysignl, .-crabc_x86_float_parse_copysignl
	.section	.note.GNU-stack,"",@progbits

/* musl-1.2.6/src/math/fabsl.c */
	.arch armv8-a
	.text
	.section	.text.crabc_x86_float_parse_fabsl,"ax",@progbits
	.align	2
	.local	crabc_x86_float_parse_fabsl
	.type	crabc_x86_float_parse_fabsl, %function
crabc_x86_float_parse_fabsl:
	sub	sp, sp, #16
	str	q0, [sp]
	ldp	x0, x1, [sp]
	ldr	x2, [sp, 8]
	add	sp, sp, 16
	ubfx	x2, x2, 48, 15
	fmov	d0, x0
	bfi	x1, x2, 48, 16
	fmov	v0.d[1], x1
	ret
	.size	crabc_x86_float_parse_fabsl, .-crabc_x86_float_parse_fabsl
	.section	.note.GNU-stack,"",@progbits

/* musl-1.2.6/src/math/fmodl.c */
	.arch armv8-a
	.text
	.section	.text.crabc_x86_float_parse_fmodl,"ax",@progbits
	.align	2
	.local	crabc_x86_float_parse_fmodl
	.type	crabc_x86_float_parse_fmodl, %function
crabc_x86_float_parse_fmodl:
	stp	x30, x19, [sp, -128]!
	stp	q1, q0, [sp, 64]
	ldr	q0, [sp, 64]
	movi	v1.2d, #0
	stp	x20, x21, [sp, 16]
	ldp	x20, x21, [sp, 64]
	stp	x22, x23, [sp, 32]
	ldp	x22, x23, [sp, 80]
	bl	__eqtf2
	cbnz	w0, .Lcrabc_float_parse_musl_support_5_40
.Lcrabc_float_parse_musl_support_5_5:
	ldp	q1, q0, [sp, 64]
	bl	__multf3
	mov	v1.16b, v0.16b
	bl	__divtf3
.Lcrabc_float_parse_musl_support_5_4:
	ldp	x20, x21, [sp, 16]
	ldp	x22, x23, [sp, 32]
	ldp	x30, x19, [sp], 128
	ret
.Lcrabc_float_parse_musl_support_5_44:
	ldr	x24, [sp, 48]
	b	.Lcrabc_float_parse_musl_support_5_5
.Lcrabc_float_parse_musl_support_5_40:
	ldr	x0, [sp, 88]
	str	x24, [sp, 48]
	ldr	q0, [sp, 64]
	ubfx	x19, x0, 48, 15
	lsr	x24, x0, 48
	bl	__fpclassifyl
	cmp	w0, 0
	mov	w0, 32767
	ccmp	w19, w0, 4, ne
	beq	.Lcrabc_float_parse_musl_support_5_44
	ldr	x5, [sp, 72]
	fmov	d0, x22
	fmov	d31, x20
	bfi	x23, x19, 48, 16
	fmov	v0.d[1], x23
	ubfx	x5, x5, 48, 15
	str	w5, [sp, 124]
	str	q0, [sp, 96]
	bfi	x21, x5, 48, 16
	fmov	v31.d[1], x21
	mov	v1.16b, v31.16b
	str	q31, [sp, 64]
	bl	__letf2
	cmp	w0, 0
	ldr	q0, [sp, 96]
	ldr	w5, [sp, 124]
	bgt	.Lcrabc_float_parse_musl_support_5_41
	ldr	q1, [sp, 64]
	bl	__eqtf2
	cbnz	w0, .Lcrabc_float_parse_musl_support_5_42
.Lcrabc_float_parse_musl_support_5_16:
	movi	v1.2d, #0
	ldr	q0, [sp, 80]
	bl	__multf3
	ldr	x24, [sp, 48]
	b	.Lcrabc_float_parse_musl_support_5_4
.Lcrabc_float_parse_musl_support_5_41:
	cbnz	w19, .Lcrabc_float_parse_musl_support_5_10
	adrp	x0, .Lcrabc_float_parse_musl_support_5_C0
	add	x0, x0, :lo12:.Lcrabc_float_parse_musl_support_5_C0
	str	w5, [sp, 124]
	ldr	q1, [x0]
	bl	__multf3
	str	q0, [sp, 96]
	ldr	x0, [sp, 104]
	ldp	x22, x23, [sp, 96]
	lsr	x0, x0, 48
	ldr	w5, [sp, 124]
	sub	w19, w0, #120
.Lcrabc_float_parse_musl_support_5_10:
	cbnz	w5, .Lcrabc_float_parse_musl_support_5_12
	adrp	x0, .Lcrabc_float_parse_musl_support_5_C0
	add	x0, x0, :lo12:.Lcrabc_float_parse_musl_support_5_C0
	ldr	q0, [sp, 64]
	ldr	q1, [x0]
	bl	__multf3
	str	q0, [sp, 64]
	ldr	x5, [sp, 72]
	ldp	x20, x21, [sp, 64]
	lsr	x5, x5, 48
	sub	w5, w5, #120
.Lcrabc_float_parse_musl_support_5_12:
	mov	x3, x23
	mov	x6, x21
	mov	x2, x22
	movk	x3, #0x1, lsl 48
	movk	x6, #0x1, lsl 48
	b	.Lcrabc_float_parse_musl_support_5_13
.Lcrabc_float_parse_musl_support_5_47:
	lsl	x2, x4, 1
	extr	x3, x1, x4, 63
.Lcrabc_float_parse_musl_support_5_17:
	sub	w19, w19, #1
.Lcrabc_float_parse_musl_support_5_13:
	subs	x4, x2, x20
	sbc	x1, x3, x6
	cmp	w19, w5
	ble	.Lcrabc_float_parse_musl_support_5_46
	tbnz	x1, #63, .Lcrabc_float_parse_musl_support_5_15
	orr	x2, x1, x4
	cbnz	x2, .Lcrabc_float_parse_musl_support_5_47
	b	.Lcrabc_float_parse_musl_support_5_16
.Lcrabc_float_parse_musl_support_5_15:
	extr	x3, x3, x2, 63
	lsl	x2, x2, 1
	b	.Lcrabc_float_parse_musl_support_5_17
.Lcrabc_float_parse_musl_support_5_46:
	tbnz	x1, #63, .Lcrabc_float_parse_musl_support_5_22
	orr	x2, x1, x4
	cbz	x2, .Lcrabc_float_parse_musl_support_5_16
	mov	x2, x4
	mov	x3, x1
.Lcrabc_float_parse_musl_support_5_22:
	and	w1, w24, 32768
.Lcrabc_float_parse_musl_support_5_21:
	cmp	xzr, x3, lsr 48
	bne	.Lcrabc_float_parse_musl_support_5_48
	sub	w19, w19, #1
	extr	x3, x3, x2, 63
	lsl	x2, x2, 1
	b	.Lcrabc_float_parse_musl_support_5_21
.Lcrabc_float_parse_musl_support_5_48:
	mov	x22, x2
	mov	x23, x3
	and	w2, w19, 65535
	cmp	w19, 0
	ble	.Lcrabc_float_parse_musl_support_5_49
	orr	w1, w1, w2
	fmov	d0, x22
	ldr	x24, [sp, 48]
	bfi	x23, x1, 48, 16
	fmov	v0.d[1], x23
	b	.Lcrabc_float_parse_musl_support_5_4
.Lcrabc_float_parse_musl_support_5_49:
	adrp	x0, .Lcrabc_float_parse_musl_support_5_C1
	add	x0, x0, :lo12:.Lcrabc_float_parse_musl_support_5_C1
	add	w2, w2, 120
	fmov	d0, x22
	orr	w1, w1, w2
	ldr	q1, [x0]
	bfi	x23, x1, 48, 16
	fmov	v0.d[1], x23
	bl	__multf3
	ldr	x24, [sp, 48]
	b	.Lcrabc_float_parse_musl_support_5_4
.Lcrabc_float_parse_musl_support_5_42:
	ldr	x24, [sp, 48]
	ldr	q0, [sp, 80]
	b	.Lcrabc_float_parse_musl_support_5_4
	.size	crabc_x86_float_parse_fmodl, .-crabc_x86_float_parse_fmodl
	.section	.rodata.cst16,"aM",@progbits,16
	.align	4
.Lcrabc_float_parse_musl_support_5_C0:
	.word	0
	.word	0
	.word	0
	.word	1081540608
	.align	4
.Lcrabc_float_parse_musl_support_5_C1:
	.word	0
	.word	0
	.word	0
	.word	1065811968
	.global	__letf2
	.global	__divtf3
	.global	__multf3
	.global	__eqtf2
	.section	.note.GNU-stack,"",@progbits
