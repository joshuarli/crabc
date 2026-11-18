/*
 * Pinned native musl aarch64 src/internal/floatscan.c assembly translation.
 * See float_parse.rs for source mapping and license.
 */
	.arch armv8-a
	.text
	.section	.text.crabc_x86_float_parse_scanexp,"ax",@progbits
	.align	2
	.type	crabc_x86_float_parse_scanexp, %function
crabc_x86_float_parse_scanexp:
	stp	x30, x19, [sp, -64]!
	stp	x20, x21, [sp, 16]
	mov	x21, x0
	ldr	x2, [x0, 8]
	ldr	x3, [x0, 184]
	cmp	x2, x3
	beq	.Lcrabc_x86_float_parse_scan_2
	add	x0, x2, 1
	str	x0, [x21, 8]
	ldrb	w2, [x2]
.Lcrabc_x86_float_parse_scan_3:
	sub	w0, w2, #43
	tst	w0, -3
	bne	.Lcrabc_x86_float_parse_scan_4
	ldr	x0, [x21, 8]
	ldr	x3, [x21, 184]
	cmp	x0, x3
	beq	.Lcrabc_x86_float_parse_scan_5
	add	x3, x0, 1
	str	x3, [x21, 8]
	ldrb	w3, [x0]
.Lcrabc_x86_float_parse_scan_6:
	sub	w0, w3, #48
	cmp	w0, 9
	bhi	.Lcrabc_x86_float_parse_scan_7
	cmp	w2, 45
	mov	w2, w3
	cset	w20, eq
	str	x22, [sp, 32]
	b	.Lcrabc_x86_float_parse_scan_8
.Lcrabc_x86_float_parse_scan_2:
	str	w1, [sp, 56]
	bl	crabc_x86_float_parse_shgetc
	ldr	w1, [sp, 56]
	mov	w2, w0
	b	.Lcrabc_x86_float_parse_scan_3
.Lcrabc_x86_float_parse_scan_5:
	mov	x0, x21
	stp	w2, w1, [sp, 56]
	bl	crabc_x86_float_parse_shgetc
	mov	w3, w0
	ldp	w2, w1, [sp, 56]
	b	.Lcrabc_x86_float_parse_scan_6
.Lcrabc_x86_float_parse_scan_7:
	cbz	w1, .Lcrabc_x86_float_parse_scan_9
	ldr	x0, [x21, 192]
	tbnz	x0, #63, .Lcrabc_x86_float_parse_scan_11
	ldr	x0, [x21, 8]
	sub	x0, x0, #1
.Lcrabc_x86_float_parse_scan_12:
	sub	x0, x0, #1
	str	x0, [x21, 8]
.Lcrabc_x86_float_parse_scan_11:
	mov	x19, -9223372036854775808
	b	.Lcrabc_x86_float_parse_scan_1
.Lcrabc_x86_float_parse_scan_4:
	sub	w0, w2, #48
	cmp	w0, 9
	bhi	.Lcrabc_x86_float_parse_scan_9
	mov	w20, 0
	str	x22, [sp, 32]
.Lcrabc_x86_float_parse_scan_8:
	mov	w22, 52427
	mov	w19, 0
	movk	w22, 0xccc, lsl 16
	b	.Lcrabc_x86_float_parse_scan_13
.Lcrabc_x86_float_parse_scan_9:
	ldr	x0, [x21, 192]
	tbnz	x0, #63, .Lcrabc_x86_float_parse_scan_11
	ldr	x0, [x21, 8]
	b	.Lcrabc_x86_float_parse_scan_12
.Lcrabc_x86_float_parse_scan_16:
	mov	x0, x21
	bl	crabc_x86_float_parse_shgetc
	mov	w2, w0
.Lcrabc_x86_float_parse_scan_17:
	sub	w0, w2, #48
.Lcrabc_x86_float_parse_scan_13:
	cmp	w0, 9
	ccmp	w19, w22, 0, ls
	bgt	.Lcrabc_x86_float_parse_scan_35
	ldr	x0, [x21, 8]
	add	w19, w19, w19, lsl 2
	ldr	x1, [x21, 184]
	add	w19, w2, w19, lsl 1
	sub	w19, w19, #48
	cmp	x0, x1
	beq	.Lcrabc_x86_float_parse_scan_16
	add	x1, x0, 1
	str	x1, [x21, 8]
	ldrb	w2, [x0]
	b	.Lcrabc_x86_float_parse_scan_17
.Lcrabc_x86_float_parse_scan_35:
	mov	x22, 18349
	sxtw	x19, w19
	movk	x22, 0x7ae1, lsl 16
	movk	x22, 0xae14, lsl 32
	movk	x22, 0x147, lsl 48
	b	.Lcrabc_x86_float_parse_scan_19
.Lcrabc_x86_float_parse_scan_20:
	mov	x0, x21
	bl	crabc_x86_float_parse_shgetc
	mov	w2, w0
.Lcrabc_x86_float_parse_scan_21:
	sub	w0, w2, #48
.Lcrabc_x86_float_parse_scan_19:
	cmp	w0, 9
	ccmp	x19, x22, 0, ls
	bgt	.Lcrabc_x86_float_parse_scan_23
	add	x19, x19, x19, lsl 2
	sxtw	x0, w2
	ldr	x1, [x21, 184]
	add	x19, x0, x19, lsl 1
	ldr	x0, [x21, 8]
	sub	x19, x19, #48
	cmp	x0, x1
	beq	.Lcrabc_x86_float_parse_scan_20
	add	x1, x0, 1
	str	x1, [x21, 8]
	ldrb	w2, [x0]
	b	.Lcrabc_x86_float_parse_scan_21
.Lcrabc_x86_float_parse_scan_24:
	mov	x0, x21
	bl	crabc_x86_float_parse_shgetc
	mov	w2, w0
.Lcrabc_x86_float_parse_scan_25:
	sub	w0, w2, #48
.Lcrabc_x86_float_parse_scan_23:
	cmp	w0, 9
	bhi	.Lcrabc_x86_float_parse_scan_36
	ldr	x0, [x21, 8]
	ldr	x1, [x21, 184]
	cmp	x0, x1
	beq	.Lcrabc_x86_float_parse_scan_24
	add	x1, x0, 1
	str	x1, [x21, 8]
	ldrb	w2, [x0]
	b	.Lcrabc_x86_float_parse_scan_25
.Lcrabc_x86_float_parse_scan_36:
	ldr	x0, [x21, 192]
	tbnz	x0, #63, .Lcrabc_x86_float_parse_scan_27
	ldr	x0, [x21, 8]
	sub	x0, x0, #1
	str	x0, [x21, 8]
.Lcrabc_x86_float_parse_scan_27:
	ldr	x22, [sp, 32]
	cmp	w20, 0
	csneg	x19, x19, x19, eq
.Lcrabc_x86_float_parse_scan_1:
	ldp	x20, x21, [sp, 16]
	mov	x0, x19
	ldp	x30, x19, [sp], 64
	ret
	.size	crabc_x86_float_parse_scanexp, .-crabc_x86_float_parse_scanexp
	.section	.text.crabc_x86_float_parse_decfloat,"ax",@progbits
	.align	2
	.type	crabc_x86_float_parse_decfloat, %function
crabc_x86_float_parse_decfloat:
	mov	x12, 8368
	sub	sp, sp, x12
	stp	x30, x19, [sp]
	mov	w19, w3
	stp	x20, x21, [sp, 16]
	mov	x20, x0
	mov	w0, w1
	stp	x22, x23, [sp, 32]
	stp	x24, x25, [sp, 48]
	mov	w25, 0
	stp	x26, x27, [sp, 64]
	str	x28, [sp, 80]
	str	w4, [sp, 96]
	str	w5, [sp, 112]
	str	w2, [sp, 168]
	b	.Lcrabc_x86_float_parse_scan_38
.Lcrabc_x86_float_parse_scan_39:
	mov	x0, x20
	bl	crabc_x86_float_parse_shgetc
.Lcrabc_x86_float_parse_scan_40:
	mov	w25, 1
.Lcrabc_x86_float_parse_scan_38:
	cmp	w0, 48
	bne	.Lcrabc_x86_float_parse_scan_190
	ldr	x0, [x20, 8]
	ldr	x1, [x20, 184]
	cmp	x0, x1
	beq	.Lcrabc_x86_float_parse_scan_39
	add	x1, x0, 1
	str	x1, [x20, 8]
	ldrb	w0, [x0]
	b	.Lcrabc_x86_float_parse_scan_40
.Lcrabc_x86_float_parse_scan_190:
	mov	w28, 0
	mov	x26, 0
	cmp	w0, 46
	beq	.Lcrabc_x86_float_parse_scan_191
.Lcrabc_x86_float_parse_scan_42:
	add	x21, sp, 176
	mov	w27, 0
	mov	x22, 0
	mov	w24, 0
	mov	w23, 0
	str	wzr, [sp, 176]
	b	.Lcrabc_x86_float_parse_scan_49
.Lcrabc_x86_float_parse_scan_191:
	ldr	x0, [x20, 8]
	ldr	x1, [x20, 184]
	cmp	x0, x1
	beq	.Lcrabc_x86_float_parse_scan_43
	add	x1, x0, 1
	str	x1, [x20, 8]
	ldrb	w0, [x0]
.Lcrabc_x86_float_parse_scan_44:
	mov	x26, 0
	b	.Lcrabc_x86_float_parse_scan_45
.Lcrabc_x86_float_parse_scan_43:
	mov	x0, x20
	bl	crabc_x86_float_parse_shgetc
	b	.Lcrabc_x86_float_parse_scan_44
.Lcrabc_x86_float_parse_scan_46:
	mov	x0, x20
	bl	crabc_x86_float_parse_shgetc
.Lcrabc_x86_float_parse_scan_47:
	mov	w25, 1
.Lcrabc_x86_float_parse_scan_45:
	cmp	w0, 48
	bne	.Lcrabc_x86_float_parse_scan_192
	ldr	x0, [x20, 8]
	sub	x26, x26, #1
	ldr	x1, [x20, 184]
	cmp	x0, x1
	beq	.Lcrabc_x86_float_parse_scan_46
	add	x1, x0, 1
	str	x1, [x20, 8]
	ldrb	w0, [x0]
	b	.Lcrabc_x86_float_parse_scan_47
.Lcrabc_x86_float_parse_scan_192:
	mov	w28, 1
	b	.Lcrabc_x86_float_parse_scan_42
.Lcrabc_x86_float_parse_scan_194:
	cbnz	w28, .Lcrabc_x86_float_parse_scan_51
	mov	x26, x22
	mov	w28, 1
.Lcrabc_x86_float_parse_scan_52:
	ldr	x0, [x20, 8]
	ldr	x1, [x20, 184]
	cmp	x0, x1
	beq	.Lcrabc_x86_float_parse_scan_57
	add	x1, x0, 1
	str	x1, [x20, 8]
	ldrb	w0, [x0]
.Lcrabc_x86_float_parse_scan_49:
	sub	w1, w0, #48
	cmp	w0, 46
	ccmp	w1, 9, 0, ne
	bhi	.Lcrabc_x86_float_parse_scan_193
	cmp	w0, 46
	beq	.Lcrabc_x86_float_parse_scan_194
	add	x22, x22, 1
	cmp	w24, 2044
	bgt	.Lcrabc_x86_float_parse_scan_53
	cmp	w0, 48
	csel	w27, w27, w22, eq
	cbz	w23, .Lcrabc_x86_float_parse_scan_55
	sbfiz	x3, x24, 2, 32
	add	w23, w23, 1
	mov	w25, 1
	ldr	w0, [x21, x3]
	add	w0, w0, w0, lsl 2
	add	w0, w1, w0, lsl 1
	str	w0, [x21, x3]
	cmp	w23, 9
	bne	.Lcrabc_x86_float_parse_scan_52
	add	w24, w24, 1
	mov	w25, 1
	mov	w23, 0
	b	.Lcrabc_x86_float_parse_scan_52
.Lcrabc_x86_float_parse_scan_55:
	mov	w23, 1
	mov	w25, w23
	str	w1, [x21, w24, sxtw 2]
	b	.Lcrabc_x86_float_parse_scan_52
.Lcrabc_x86_float_parse_scan_53:
	cmp	w0, 48
	beq	.Lcrabc_x86_float_parse_scan_52
	ldr	w0, [sp, 8352]
	mov	w27, 18396
	orr	w0, w0, 1
	str	w0, [sp, 8352]
	b	.Lcrabc_x86_float_parse_scan_52
.Lcrabc_x86_float_parse_scan_57:
	mov	x0, x20
	bl	crabc_x86_float_parse_shgetc
	b	.Lcrabc_x86_float_parse_scan_49
.Lcrabc_x86_float_parse_scan_193:
	cmp	w28, 0
	csel	x26, x26, x22, ne
	cbz	w25, .Lcrabc_x86_float_parse_scan_61
	orr	w1, w0, 32
	cmp	w1, 101
	beq	.Lcrabc_x86_float_parse_scan_195
	tbnz	w0, #31, .Lcrabc_x86_float_parse_scan_68
.Lcrabc_x86_float_parse_scan_161:
	ldr	x0, [x20, 192]
	tbnz	x0, #63, .Lcrabc_x86_float_parse_scan_68
	ldr	x0, [x20, 8]
	sub	x0, x0, #1
	str	x0, [x20, 8]
.Lcrabc_x86_float_parse_scan_68:
	ldr	w20, [sp, 176]
	cbz	w20, .Lcrabc_x86_float_parse_scan_196
	cmp	x22, x26
	ccmp	x22, 9, 0, eq
	bgt	.Lcrabc_x86_float_parse_scan_75
	ldr	w0, [sp, 168]
	cmp	w0, 30
	bgt	.Lcrabc_x86_float_parse_scan_76
	lsr	w0, w20, w0
	cbz	w0, .Lcrabc_x86_float_parse_scan_76
.Lcrabc_x86_float_parse_scan_75:
	add	w0, w19, w19, lsr 31
	neg	w0, w0, asr 1
	cmp	x26, w0, sxtw
	bgt	.Lcrabc_x86_float_parse_scan_197
	sub	w0, w19, #226
	cmp	x26, w0, sxtw
	blt	.Lcrabc_x86_float_parse_scan_198
	cbz	w23, .Lcrabc_x86_float_parse_scan_80
	sbfiz	x1, x24, 2, 32
	add	x2, sp, 176
	b	.Lcrabc_x86_float_parse_scan_79
.Lcrabc_x86_float_parse_scan_195:
	ldr	w1, [sp, 112]
	mov	x0, x20
	bl	crabc_x86_float_parse_scanexp
	mov	x1, -9223372036854775808
	cmp	x0, x1
	beq	.Lcrabc_x86_float_parse_scan_199
	add	x26, x26, x0
	b	.Lcrabc_x86_float_parse_scan_68
.Lcrabc_x86_float_parse_scan_199:
	ldr	w0, [sp, 112]
	cbnz	w0, .Lcrabc_x86_float_parse_scan_161
	b	.Lcrabc_x86_float_parse_scan_186
.Lcrabc_x86_float_parse_scan_61:
	tbz	w0, #31, .Lcrabc_x86_float_parse_scan_135
.Lcrabc_x86_float_parse_scan_71:
	bl	__errno_location
	mov	w1, 22
	str	w1, [x0]
.Lcrabc_x86_float_parse_scan_186:
	mov	x0, x20
	mov	x1, 0
	bl	crabc_x86_float_parse_shlim
	movi	v0.2d, #0
	b	.Lcrabc_x86_float_parse_scan_37
.Lcrabc_x86_float_parse_scan_196:
	ldr	w0, [sp, 96]
	movi	d31, #0
	scvtf	d0, w0
	fmul	d0, d0, d31
	bl	__extenddftf2
.Lcrabc_x86_float_parse_scan_37:
	ldr	x28, [sp, 80]
	mov	x12, 8368
	ldp	x30, x19, [sp]
	ldp	x20, x21, [sp, 16]
	ldp	x22, x23, [sp, 32]
	ldp	x24, x25, [sp, 48]
	ldp	x26, x27, [sp, 64]
	add	sp, sp, x12
	ret
.Lcrabc_x86_float_parse_scan_76:
	ldr	w0, [sp, 96]
	bl	__floatsitf
	str	q0, [sp, 96]
	mov	w0, w20
	bl	__floatunsitf
	mov	v1.16b, v0.16b
	ldr	q0, [sp, 96]
	bl	__multf3
	b	.Lcrabc_x86_float_parse_scan_37
.Lcrabc_x86_float_parse_scan_197:
	bl	__errno_location
	mov	w1, 34
	str	w1, [x0]
	ldr	w0, [sp, 96]
	bl	__floatsitf
	adrp	x0, .Lcrabc_x86_float_parse_scan_C0
	add	x0, x0, :lo12:.Lcrabc_x86_float_parse_scan_C0
	ldr	q1, [x0]
	bl	__multf3
	adrp	x0, .Lcrabc_x86_float_parse_scan_C0
	add	x0, x0, :lo12:.Lcrabc_x86_float_parse_scan_C0
	ldr	q1, [x0]
	bl	__multf3
	b	.Lcrabc_x86_float_parse_scan_37
.Lcrabc_x86_float_parse_scan_198:
	bl	__errno_location
	mov	w1, 34
	str	w1, [x0]
	ldr	w0, [sp, 96]
	bl	__floatsitf
	adrp	x0, .Lcrabc_x86_float_parse_scan_C1
	add	x0, x0, :lo12:.Lcrabc_x86_float_parse_scan_C1
	ldr	q1, [x0]
	bl	__multf3
	adrp	x0, .Lcrabc_x86_float_parse_scan_C1
	add	x0, x0, :lo12:.Lcrabc_x86_float_parse_scan_C1
	ldr	q1, [x0]
	bl	__multf3
	b	.Lcrabc_x86_float_parse_scan_37
.Lcrabc_x86_float_parse_scan_81:
	ldr	w0, [x2, x1]
	add	w23, w23, 1
	add	w0, w0, w0, lsl 2
	lsl	w0, w0, 1
	str	w0, [x2, x1]
.Lcrabc_x86_float_parse_scan_79:
	cmp	w23, 8
	ble	.Lcrabc_x86_float_parse_scan_81
	add	w24, w24, 1
.Lcrabc_x86_float_parse_scan_80:
	mov	w20, 8
	cmp	w26, w20
	csel	w0, w26, w20, le
	mov	w23, w26
	cmp	w27, w0
	ccmp	w26, 17, 0, le
	ble	.Lcrabc_x86_float_parse_scan_200
.Lcrabc_x86_float_parse_scan_82:
	ldr	w0, [sp, 168]
	neg	w20, w19
	add	x22, sp, 176
	sub	w20, w20, w0
	sub	w0, w24, #1
	mov	x5, x22
	add	x1, x22, w0, sxtw 2
.Lcrabc_x86_float_parse_scan_86:
	ldr	w2, [x1], -4
	mov	w28, w24
	mov	w24, w0
	cbnz	w2, .Lcrabc_x86_float_parse_scan_183
	sub	w0, w0, #1
	b	.Lcrabc_x86_float_parse_scan_86
.Lcrabc_x86_float_parse_scan_200:
	ldr	w21, [sp, 176]
	cmp	w26, 9
	beq	.Lcrabc_x86_float_parse_scan_201
	cmp	w26, 8
	ble	.Lcrabc_x86_float_parse_scan_202
	sub	w26, w26, #9
	ldr	w0, [sp, 168]
	sub	w26, w26, w26, lsl 2
	add	w0, w26, w0
	cmp	w0, 30
	bgt	.Lcrabc_x86_float_parse_scan_85
	lsr	w0, w21, w0
	cbnz	w0, .Lcrabc_x86_float_parse_scan_82
.Lcrabc_x86_float_parse_scan_85:
	ldr	w0, [sp, 96]
	sub	w23, w23, #10
	bl	__floatsitf
	str	q0, [sp, 96]
	mov	w0, w21
	bl	__floatunsitf
	mov	v1.16b, v0.16b
	ldr	q0, [sp, 96]
	bl	__multf3
	str	q0, [sp, 96]
	adrp	x0, crabc_x86_float_parse_p10s_1
	add	x0, x0, :lo12:crabc_x86_float_parse_p10s_1
	ldr	w0, [x0, w23, sxtw 2]
	bl	__floatsitf
	mov	v1.16b, v0.16b
	ldr	q0, [sp, 96]
	bl	__multf3
	b	.Lcrabc_x86_float_parse_scan_37
.Lcrabc_x86_float_parse_scan_201:
	ldr	w0, [sp, 96]
	bl	__floatsitf
	str	q0, [sp, 96]
	mov	w0, w21
	bl	__floatunsitf
	mov	v1.16b, v0.16b
	ldr	q0, [sp, 96]
	bl	__multf3
	b	.Lcrabc_x86_float_parse_scan_37
.Lcrabc_x86_float_parse_scan_202:
	ldr	w0, [sp, 96]
	sub	w20, w20, w26
	bl	__floatsitf
	str	q0, [sp, 96]
	mov	w0, w21
	bl	__floatunsitf
	mov	v1.16b, v0.16b
	ldr	q0, [sp, 96]
	bl	__multf3
	str	q0, [sp, 96]
	adrp	x0, crabc_x86_float_parse_p10s_1
	add	x0, x0, :lo12:crabc_x86_float_parse_p10s_1
	ldr	w0, [x0, w20, sxtw 2]
	bl	__floatsitf
	mov	v1.16b, v0.16b
	ldr	q0, [sp, 96]
	bl	__divtf3
	b	.Lcrabc_x86_float_parse_scan_37
.Lcrabc_x86_float_parse_scan_183:
	mov	w21, 9
	sdiv	w21, w23, w21
	add	w21, w21, w21, lsl 3
	subs	w21, w23, w21
	beq	.Lcrabc_x86_float_parse_scan_87
	add	w0, w21, 9
	cmp	w23, 0
	csel	w21, w0, w21, lt
	mov	w1, 8
	adrp	x0, crabc_x86_float_parse_p10s_1
	sub	w1, w1, w21
	add	x0, x0, :lo12:crabc_x86_float_parse_p10s_1
	mov	w9, 51712
	mov	w2, 0
	mov	w3, 0
	movk	w9, 0x3b9a, lsl 16
	ldr	w6, [x0, w1, sxtw 2]
	mov	w0, 0
	b	.Lcrabc_x86_float_parse_scan_89
.Lcrabc_x86_float_parse_scan_91:
	ldr	w8, [x5]
	udiv	w1, w8, w6
	adds	w7, w1, w0
	msub	w1, w1, w6, w8
	sdiv	w0, w9, w6
	ccmp	w3, w2, 0, eq
	str	w7, [x5], 4
	cset	w7, eq
	cmp	w7, 0
	add	w3, w3, 1
	mul	w0, w0, w1
	add	w1, w2, 1
	and	w1, w1, 2047
	csel	w2, w1, w2, ne
	sub	w1, w23, #9
	csel	w23, w1, w23, ne
.Lcrabc_x86_float_parse_scan_89:
	cmp	w3, w28
	bne	.Lcrabc_x86_float_parse_scan_91
	cbz	w0, .Lcrabc_x86_float_parse_scan_92
	str	w0, [x22, w28, sxtw 2]
	add	w28, w28, 1
.Lcrabc_x86_float_parse_scan_92:
	sub	w23, w23, w21
	mov	w21, w2
	add	w23, w23, 9
.Lcrabc_x86_float_parse_scan_87:
	mov	x8, 23123
	mov	w9, 29904
	movk	x8, 0xa09b, lsl 16
	mov	x6, 51712
	movk	x8, 0xb82f, lsl 32
	mov	w24, 0
	movk	w9, 0x9e, lsl 16
	movk	x6, 0x3b9a, lsl 16
	movk	x8, 0x44, lsl 48
	b	.Lcrabc_x86_float_parse_scan_93
.Lcrabc_x86_float_parse_scan_94:
	and	w3, w7, 2047
	str	w1, [x22, x5, lsl 2]
	cmp	w3, w0
	beq	.Lcrabc_x86_float_parse_scan_203
	cmp	w0, w21
	beq	.Lcrabc_x86_float_parse_scan_96
	sub	w0, w0, #1
	and	w0, w0, 2047
.Lcrabc_x86_float_parse_scan_98:
	ubfiz	x1, x0, 2, 11
	sxtw	x5, w0
	ldr	w1, [x22, x1]
	add	x1, x2, x1, lsl 29
	mov	x2, 0
	cmp	x1, x6
	bls	.Lcrabc_x86_float_parse_scan_94
	lsr	x3, x1, 9
	umulh	x3, x3, x8
	lsr	x3, x3, 11
	uxtw	x2, w3
	msub	x1, x3, x6, x1
	b	.Lcrabc_x86_float_parse_scan_94
.Lcrabc_x86_float_parse_scan_203:
	cmp	w0, w21
	beq	.Lcrabc_x86_float_parse_scan_96
	sub	w5, w0, #1
	cbnz	x1, .Lcrabc_x86_float_parse_scan_139
	mov	w28, w0
	sub	w7, w3, #1
	and	w0, w5, 2047
	b	.Lcrabc_x86_float_parse_scan_98
.Lcrabc_x86_float_parse_scan_139:
	and	w0, w5, 2047
	b	.Lcrabc_x86_float_parse_scan_98
.Lcrabc_x86_float_parse_scan_96:
	cbnz	w2, .Lcrabc_x86_float_parse_scan_99
	cmp	w23, 35
	ble	.Lcrabc_x86_float_parse_scan_100
.Lcrabc_x86_float_parse_scan_101:
	ldr	w0, [x22, w21, sxtw 2]
	cmp	w0, w9
	bhi	.Lcrabc_x86_float_parse_scan_104
.Lcrabc_x86_float_parse_scan_103:
	sub	w7, w28, #1
.Lcrabc_x86_float_parse_scan_100:
	sub	w24, w24, #29
	and	w0, w7, 2047
	mov	x2, 0
	b	.Lcrabc_x86_float_parse_scan_98
.Lcrabc_x86_float_parse_scan_99:
	sub	w21, w21, #1
	add	w23, w23, 9
	and	w21, w21, 2047
	cmp	w28, w21
	beq	.Lcrabc_x86_float_parse_scan_204
.Lcrabc_x86_float_parse_scan_102:
	str	w2, [x22, w21, sxtw 2]
.Lcrabc_x86_float_parse_scan_93:
	cmp	w23, 35
	ble	.Lcrabc_x86_float_parse_scan_103
	cmp	w23, 36
	beq	.Lcrabc_x86_float_parse_scan_101
.Lcrabc_x86_float_parse_scan_104:
	mov	w10, 51712
	adrp	x7, crabc_x86_float_parse_th_0
	mov	w8, 1
	add	x7, x7, :lo12:crabc_x86_float_parse_th_0
	mov	w9, 9
	movk	w10, 0x3b9a, lsl 16
	b	.Lcrabc_x86_float_parse_scan_105
.Lcrabc_x86_float_parse_scan_204:
	sub	w0, w3, #1
	ubfiz	x4, x3, 2, 11
	mov	w28, w3
	ubfiz	x0, x0, 2, 11
	ldr	w4, [x22, x4]
	ldr	w1, [x22, x0]
	orr	w1, w1, w4
	str	w1, [x22, x0]
	b	.Lcrabc_x86_float_parse_scan_102
.Lcrabc_x86_float_parse_scan_141:
	mov	w0, 1
.Lcrabc_x86_float_parse_scan_107:
	cmp	w23, 36
	ccmp	w0, 0, 4, eq
	bne	.Lcrabc_x86_float_parse_scan_205
	cmp	w23, 45
	mov	w0, w21
	csinc	w6, w9, wzr, gt
	mov	w5, 0
	add	w24, w24, w6
	lsl	w11, w8, w6
	sub	w11, w11, #1
	asr	w12, w10, w6
	b	.Lcrabc_x86_float_parse_scan_112
.Lcrabc_x86_float_parse_scan_205:
	movi	v30.2d, #0
	mov	w26, w21
	add	w23, w21, 4
	b	.Lcrabc_x86_float_parse_scan_110
.Lcrabc_x86_float_parse_scan_114:
	sbfiz	x3, x0, 2, 32
	ldr	w2, [x22, x3]
	lsr	w1, w2, w6
	and	w2, w11, w2
	adds	w1, w1, w5
	str	w1, [x22, x3]
	ccmp	w0, w21, 0, eq
	add	w1, w21, 1
	mul	w5, w2, w12
	cset	w2, eq
	and	w1, w1, 2047
	cmp	w2, 0
	csel	w21, w1, w21, ne
	add	w0, w0, 1
	sub	w1, w23, #9
	and	w0, w0, 2047
	csel	w23, w1, w23, ne
.Lcrabc_x86_float_parse_scan_112:
	cmp	w0, w28
	bne	.Lcrabc_x86_float_parse_scan_114
	cbz	w5, .Lcrabc_x86_float_parse_scan_105
	add	w0, w28, 1
	and	w0, w0, 2047
	cmp	w0, w21
	beq	.Lcrabc_x86_float_parse_scan_116
	str	w5, [x22, w28, sxtw 2]
	mov	w28, w0
.Lcrabc_x86_float_parse_scan_105:
	mov	x1, 0
.Lcrabc_x86_float_parse_scan_106:
	cmp	x1, 4
	beq	.Lcrabc_x86_float_parse_scan_141
	add	w0, w21, w1
	and	w0, w0, 2047
	cmp	w28, w0
	beq	.Lcrabc_x86_float_parse_scan_141
	ubfiz	x0, x0, 2, 11
	ldr	w2, [x22, x0]
	ldr	w0, [x7, x1, lsl 2]
	cmp	w2, w0
	bcc	.Lcrabc_x86_float_parse_scan_141
	add	x1, x1, 1
	bls	.Lcrabc_x86_float_parse_scan_106
	mov	w0, 0
	b	.Lcrabc_x86_float_parse_scan_107
.Lcrabc_x86_float_parse_scan_116:
	sub	w0, w28, #1
	ubfiz	x0, x0, 2, 11
	ldr	w1, [x22, x0]
	orr	w1, w1, 1
	str	w1, [x22, x0]
	b	.Lcrabc_x86_float_parse_scan_105
.Lcrabc_x86_float_parse_scan_118:
	adrp	x0, .Lcrabc_x86_float_parse_scan_C2
	add	x0, x0, :lo12:.Lcrabc_x86_float_parse_scan_C2
	ubfiz	x25, x25, 2, 11
	mov	v0.16b, v30.16b
	add	w26, w26, 1
	ldr	q1, [x0]
	bl	__multf3
	str	q0, [sp, 112]
	ldr	w0, [x22, x25]
	bl	__floatunsitf
	ldr	q1, [sp, 112]
	bl	__addtf3
	mov	v30.16b, v0.16b
	cmp	w26, w23
	beq	.Lcrabc_x86_float_parse_scan_206
.Lcrabc_x86_float_parse_scan_110:
	and	w25, w26, 2047
	cmp	w25, w28
	bne	.Lcrabc_x86_float_parse_scan_118
	add	w4, w28, 1
	str	wzr, [x22, w28, sxtw 2]
	and	w28, w4, 2047
	b	.Lcrabc_x86_float_parse_scan_118
.Lcrabc_x86_float_parse_scan_206:
	ldr	w0, [sp, 96]
	add	w27, w24, 113
	str	q0, [sp, 112]
	sub	w25, w27, w19
	bl	__floatsitf
	ldr	q1, [sp, 112]
	bl	__multf3
	str	q0, [sp, 112]
	ldr	w0, [sp, 168]
	cmp	w25, w0
	bge	.Lcrabc_x86_float_parse_scan_144
	tbnz	w25, #31, .Lcrabc_x86_float_parse_scan_145
	mov	w0, 1
	str	w0, [sp, 172]
	b	.Lcrabc_x86_float_parse_scan_119
.Lcrabc_x86_float_parse_scan_144:
	ldr	w25, [sp, 168]
	str	wzr, [sp, 172]
.Lcrabc_x86_float_parse_scan_119:
	cmp	w25, 112
	bgt	.Lcrabc_x86_float_parse_scan_146
	mov	w0, 225
	mov	w1, 113
	sub	w0, w0, w25
	sub	w26, w1, w25
.Lcrabc_x86_float_parse_scan_120:
	fmov	d0, 1.0e+0
	bl	crabc_x86_float_parse_scalbn
	bl	__extenddftf2
	ldr	q1, [sp, 112]
	bl	crabc_x86_float_parse_copysignl
	str	q0, [sp, 144]
	mov	w0, w26
	fmov	d0, 1.0e+0
	bl	crabc_x86_float_parse_scalbn
	bl	__extenddftf2
	mov	v1.16b, v0.16b
	ldr	q0, [sp, 112]
	bl	crabc_x86_float_parse_fmodl
	mov	v1.16b, v0.16b
	str	q0, [sp, 128]
	ldr	q0, [sp, 112]
	bl	__subtf3
	mov	v1.16b, v0.16b
	ldr	q0, [sp, 144]
	bl	__addtf3
	str	q0, [sp, 112]
.Lcrabc_x86_float_parse_scan_121:
	and	w23, w23, 2047
	cmp	w23, w28
	beq	.Lcrabc_x86_float_parse_scan_122
	ubfiz	x23, x23, 2, 11
	mov	w0, 25855
	movk	w0, 0x1dcd, lsl 16
	ldr	w1, [x22, x23]
	cmp	w1, w0
	bhi	.Lcrabc_x86_float_parse_scan_123
	cbnz	w1, .Lcrabc_x86_float_parse_scan_124
	add	w0, w21, 5
	and	w0, w0, 2047
	cmp	w0, w28
	beq	.Lcrabc_x86_float_parse_scan_125
.Lcrabc_x86_float_parse_scan_124:
	ldr	w0, [sp, 96]
	scvtf	d0, w0, #2
.Lcrabc_x86_float_parse_scan_187:
	bl	__extenddftf2
	mov	v1.16b, v0.16b
	ldr	q0, [sp, 128]
	bl	__addtf3
	str	q0, [sp, 128]
.Lcrabc_x86_float_parse_scan_125:
	cmp	w25, 111
	ble	.Lcrabc_x86_float_parse_scan_207
.Lcrabc_x86_float_parse_scan_122:
	ldp	q0, q1, [sp, 112]
	bl	__addtf3
	ldr	q1, [sp, 144]
	bl	__subtf3
	mov	v30.16b, v0.16b
	sub	w0, w20, #1
	and	w1, w27, 2147483647
	cmp	w0, w1
	ble	.Lcrabc_x86_float_parse_scan_208
.Lcrabc_x86_float_parse_scan_129:
	ldp	x30, x19, [sp]
	mov	w0, w24
	ldp	x20, x21, [sp, 16]
	mov	x12, 8368
	ldp	x22, x23, [sp, 32]
	mov	v0.16b, v30.16b
	ldp	x24, x25, [sp, 48]
	ldp	x26, x27, [sp, 64]
	ldr	x28, [sp, 80]
	add	sp, sp, x12
	b	crabc_x86_float_parse_scalbnl
.Lcrabc_x86_float_parse_scan_145:
	mov	w1, 1
	mov	w26, 113
	mov	w0, 225
	mov	w25, 0
	str	w1, [sp, 172]
	b	.Lcrabc_x86_float_parse_scan_120
.Lcrabc_x86_float_parse_scan_146:
	movi	v31.2d, #0
	stp	q31, q31, [sp, 128]
	b	.Lcrabc_x86_float_parse_scan_121
.Lcrabc_x86_float_parse_scan_123:
	ldr	w2, [sp, 96]
	add	w0, w0, 1
	scvtf	d31, w2
	cmp	w1, w0
	bne	.Lcrabc_x86_float_parse_scan_126
	add	w0, w21, 5
	fmov	d0, 5.0e-1
	and	w0, w0, 2047
	cmp	w0, w28
	beq	.Lcrabc_x86_float_parse_scan_188
.Lcrabc_x86_float_parse_scan_126:
	fmov	d0, 7.5e-1
.Lcrabc_x86_float_parse_scan_188:
	fmul	d0, d31, d0
	b	.Lcrabc_x86_float_parse_scan_187
.Lcrabc_x86_float_parse_scan_207:
	adrp	x0, .Lcrabc_x86_float_parse_scan_C3
	add	x0, x0, :lo12:.Lcrabc_x86_float_parse_scan_C3
	ldr	q0, [sp, 128]
	ldr	q1, [x0]
	bl	crabc_x86_float_parse_fmodl
	movi	v1.2d, #0
	bl	__eqtf2
	cbnz	w0, .Lcrabc_x86_float_parse_scan_122
	adrp	x0, .Lcrabc_x86_float_parse_scan_C3
	add	x0, x0, :lo12:.Lcrabc_x86_float_parse_scan_C3
	ldr	q0, [sp, 128]
	ldr	q1, [x0]
	bl	__addtf3
	str	q0, [sp, 128]
	b	.Lcrabc_x86_float_parse_scan_122
.Lcrabc_x86_float_parse_scan_208:
	str	q0, [sp, 96]
	bl	crabc_x86_float_parse_fabsl
	adrp	x0, .Lcrabc_x86_float_parse_scan_C4
	add	x0, x0, :lo12:.Lcrabc_x86_float_parse_scan_C4
	add	w20, w20, 3
	ldr	q1, [x0]
	bl	__getf2
	ldr	q30, [sp, 96]
	tbnz	w0, #31, .Lcrabc_x86_float_parse_scan_184
	adrp	x0, .Lcrabc_x86_float_parse_scan_C5
	add	x0, x0, :lo12:.Lcrabc_x86_float_parse_scan_C5
	mov	v0.16b, v30.16b
	ldr	q1, [x0]
	bl	__multf3
	mov	v30.16b, v0.16b
	ldr	w1, [sp, 168]
	add	w0, w24, 1
	add	w24, w24, 114
	add	w1, w19, w1
	cmp	w24, w1
	mov	w24, w0
	blt	.Lcrabc_x86_float_parse_scan_132
	cmp	w27, w20
	bge	.Lcrabc_x86_float_parse_scan_133
	b	.Lcrabc_x86_float_parse_scan_129
.Lcrabc_x86_float_parse_scan_184:
	add	w27, w24, 112
.Lcrabc_x86_float_parse_scan_132:
	cmp	w20, w27
	ble	.Lcrabc_x86_float_parse_scan_133
	movi	v1.2d, #0
	ldr	q0, [sp, 128]
	str	q30, [sp, 96]
	bl	__netf2
	cmp	w0, 0
	ldr	w1, [sp, 172]
	cset	w0, ne
	ldr	q30, [sp, 96]
	tst	w1, w0
	beq	.Lcrabc_x86_float_parse_scan_129
.Lcrabc_x86_float_parse_scan_133:
	str	q30, [sp, 96]
	bl	__errno_location
	ldr	q30, [sp, 96]
	mov	w1, 34
	str	w1, [x0]
	b	.Lcrabc_x86_float_parse_scan_129
.Lcrabc_x86_float_parse_scan_51:
	cbnz	w25, .Lcrabc_x86_float_parse_scan_161
.Lcrabc_x86_float_parse_scan_135:
	ldr	x0, [x20, 192]
	tbnz	x0, #63, .Lcrabc_x86_float_parse_scan_71
	ldr	x0, [x20, 8]
	sub	x0, x0, #1
	str	x0, [x20, 8]
	b	.Lcrabc_x86_float_parse_scan_71
	.size	crabc_x86_float_parse_decfloat, .-crabc_x86_float_parse_decfloat
	.section	.rodata.crabc_x86_float_parse_floatscan.str1.8,"aMS",@progbits,1
	.align	3
.Lcrabc_x86_float_parse_scan_C6:
	.string	"infinity"
	.align	3
.Lcrabc_x86_float_parse_scan_C7:
	.string	"nan"
	.section	.text.crabc_x86_float_parse_floatscan,"ax",@progbits
	.align	2
	.type	crabc_x86_float_parse_floatscan, %function
crabc_x86_float_parse_floatscan:
	cmp	w1, 2
	bhi	.Lcrabc_x86_float_parse_scan_379
	stp	x30, x19, [sp, -144]!
	mov	x19, x0
	adrp	x0, crabc_x86_float_parse_CSW16
	add	x0, x0, :lo12:crabc_x86_float_parse_CSW16
	stp	x20, x21, [sp, 16]
	mov	w20, w2
	stp	x22, x23, [sp, 32]
	ldr	w0, [x0, w1, uxtw 2]
	mov	w21, w0
	adrp	x0, crabc_x86_float_parse_CSW17
	add	x0, x0, :lo12:crabc_x86_float_parse_CSW17
	ldr	w0, [x0, w1, uxtw 2]
	mov	w22, w0
	b	.Lcrabc_x86_float_parse_scan_213
.Lcrabc_x86_float_parse_scan_211:
	mov	x0, x19
	bl	crabc_x86_float_parse_shgetc
	mov	w1, w0
.Lcrabc_x86_float_parse_scan_212:
	sub	w0, w1, #9
	cmp	w1, 32
	ccmp	w0, 4, 0, ne
	bhi	.Lcrabc_x86_float_parse_scan_389
.Lcrabc_x86_float_parse_scan_213:
	ldr	x0, [x19, 8]
	ldr	x1, [x19, 184]
	cmp	x0, x1
	beq	.Lcrabc_x86_float_parse_scan_211
	add	x1, x0, 1
	str	x1, [x19, 8]
	ldrb	w1, [x0]
	b	.Lcrabc_x86_float_parse_scan_212
.Lcrabc_x86_float_parse_scan_389:
	sub	w0, w1, #43
	mov	w4, 1
	tst	w0, -3
	bne	.Lcrabc_x86_float_parse_scan_214
	cmp	w1, 45
	cset	w0, eq
	ldr	x1, [x19, 184]
	sub	w4, w4, w0, lsl 1
	ldr	x0, [x19, 8]
	cmp	x0, x1
	beq	.Lcrabc_x86_float_parse_scan_215
	add	x1, x0, 1
	str	x1, [x19, 8]
	ldrb	w1, [x0]
.Lcrabc_x86_float_parse_scan_214:
	adrp	x3, .Lcrabc_x86_float_parse_scan_C6
	add	x3, x3, :lo12:.Lcrabc_x86_float_parse_scan_C6
	mov	x5, 0
.Lcrabc_x86_float_parse_scan_216:
	ldrb	w2, [x3, x5]
	orr	w0, w1, 32
	cmp	w0, w2
	bne	.Lcrabc_x86_float_parse_scan_390
	cmp	x5, 7
	beq	.Lcrabc_x86_float_parse_scan_217
	ldr	x0, [x19, 8]
	ldr	x1, [x19, 184]
	cmp	x0, x1
	beq	.Lcrabc_x86_float_parse_scan_218
	add	x1, x0, 1
	str	x1, [x19, 8]
	add	x5, x5, 1
	ldrb	w1, [x0]
	b	.Lcrabc_x86_float_parse_scan_216
.Lcrabc_x86_float_parse_scan_215:
	mov	x0, x19
	str	w4, [sp, 80]
	bl	crabc_x86_float_parse_shgetc
	mov	w1, w0
	ldr	w4, [sp, 80]
	b	.Lcrabc_x86_float_parse_scan_214
.Lcrabc_x86_float_parse_scan_218:
	mov	x0, x19
	str	x5, [sp, 80]
	str	w4, [sp, 96]
	str	x3, [sp, 112]
	bl	crabc_x86_float_parse_shgetc
	ldr	x5, [sp, 80]
	mov	w1, w0
	ldr	x3, [sp, 112]
	add	x5, x5, 1
	ldr	w4, [sp, 96]
	b	.Lcrabc_x86_float_parse_scan_216
.Lcrabc_x86_float_parse_scan_390:
	mov	x2, 264
	lsr	x2, x2, x5
	tbnz	x2, 0, .Lcrabc_x86_float_parse_scan_221
	cmp	w20, 0
	ccmp	x5, 3, 0, ne
	bhi	.Lcrabc_x86_float_parse_scan_391
	adrp	x3, .Lcrabc_x86_float_parse_scan_C7
	add	x3, x3, :lo12:.Lcrabc_x86_float_parse_scan_C7
	cbz	x5, .Lcrabc_x86_float_parse_scan_232
.Lcrabc_x86_float_parse_scan_261:
	ldr	x0, [x19, 192]
	tbnz	x0, #63, .Lcrabc_x86_float_parse_scan_384
	ldr	x0, [x19, 8]
	sub	x0, x0, #1
	str	x0, [x19, 8]
.Lcrabc_x86_float_parse_scan_384:
	bl	__errno_location
	mov	w1, 22
	str	w1, [x0]
	mov	x0, x19
	mov	x1, 0
	bl	crabc_x86_float_parse_shlim
.Lcrabc_x86_float_parse_scan_210:
	movi	v0.2d, #0
	b	.Lcrabc_x86_float_parse_scan_209
.Lcrabc_x86_float_parse_scan_391:
	ldr	x0, [x19, 192]
	tbnz	x0, #63, .Lcrabc_x86_float_parse_scan_224
	ldr	x1, [x19, 8]
	sub	x1, x1, #1
	str	x1, [x19, 8]
.Lcrabc_x86_float_parse_scan_224:
	cmp	x5, 3
	beq	.Lcrabc_x86_float_parse_scan_217
	tbnz	x0, #63, .Lcrabc_x86_float_parse_scan_231
.Lcrabc_x86_float_parse_scan_228:
	ldr	x0, [x19, 8]
	cmp	x5, 4
	beq	.Lcrabc_x86_float_parse_scan_392
	sub	x0, x0, #2
	sub	x5, x5, #2
	str	x0, [x19, 8]
	cmp	x5, 3
	bne	.Lcrabc_x86_float_parse_scan_228
	b	.Lcrabc_x86_float_parse_scan_217
.Lcrabc_x86_float_parse_scan_221:
	ldr	x0, [x19, 192]
	tbnz	x0, #63, .Lcrabc_x86_float_parse_scan_227
	ldr	x1, [x19, 8]
	sub	x1, x1, #1
	str	x1, [x19, 8]
.Lcrabc_x86_float_parse_scan_227:
	cbnz	w20, .Lcrabc_x86_float_parse_scan_224
.Lcrabc_x86_float_parse_scan_217:
	scvtf	s0, w4
	mov	w0, 2139095040
	fmov	s31, w0
	fmul	s0, s0, s31
	bl	__extendsftf2
.Lcrabc_x86_float_parse_scan_209:
	ldp	x20, x21, [sp, 16]
	ldp	x22, x23, [sp, 32]
	ldp	x30, x19, [sp], 144
	ret
.Lcrabc_x86_float_parse_scan_231:
	cmp	x5, 4
	beq	.Lcrabc_x86_float_parse_scan_217
	sub	x5, x5, #2
	cmp	x5, 3
	bne	.Lcrabc_x86_float_parse_scan_231
	b	.Lcrabc_x86_float_parse_scan_217
.Lcrabc_x86_float_parse_scan_392:
	sub	x0, x0, #1
	str	x0, [x19, 8]
	b	.Lcrabc_x86_float_parse_scan_217
.Lcrabc_x86_float_parse_scan_236:
	mov	x0, x19
	str	x5, [sp, 80]
	str	w4, [sp, 96]
	str	x3, [sp, 112]
	bl	crabc_x86_float_parse_shgetc
	ldr	x5, [sp, 80]
	mov	w1, w0
	ldr	x3, [sp, 112]
	add	x5, x5, 1
	ldr	w4, [sp, 96]
.Lcrabc_x86_float_parse_scan_237:
	orr	w0, w1, 32
.Lcrabc_x86_float_parse_scan_232:
	ldrb	w2, [x3, x5]
	cmp	w0, w2
	bne	.Lcrabc_x86_float_parse_scan_393
	ldr	x0, [x19, 8]
	ldr	x1, [x19, 184]
	cmp	x5, 2
	beq	.Lcrabc_x86_float_parse_scan_235
	cmp	x0, x1
	beq	.Lcrabc_x86_float_parse_scan_236
	add	x1, x0, 1
	str	x1, [x19, 8]
	add	x5, x5, 1
	ldrb	w1, [x0]
	b	.Lcrabc_x86_float_parse_scan_237
.Lcrabc_x86_float_parse_scan_235:
	cmp	x0, x1
	beq	.Lcrabc_x86_float_parse_scan_394
	add	x1, x0, 1
	str	x1, [x19, 8]
	ldrb	w0, [x0]
	cmp	w0, 40
	cset	w0, ne
.Lcrabc_x86_float_parse_scan_242:
	mov	x1, 1
	cbnz	w0, .Lcrabc_x86_float_parse_scan_395
.Lcrabc_x86_float_parse_scan_252:
	ldr	x0, [x19, 8]
	ldr	x2, [x19, 184]
	cmp	x0, x2
	beq	.Lcrabc_x86_float_parse_scan_245
	add	x2, x0, 1
	str	x2, [x19, 8]
	ldrb	w0, [x0]
.Lcrabc_x86_float_parse_scan_246:
	cmp	w0, 57
	ble	.Lcrabc_x86_float_parse_scan_396
	sub	w0, w0, #65
	cmp	w0, 57
	bhi	.Lcrabc_x86_float_parse_scan_250
	mov	x2, -3154116609
	movk	x2, 0x3ff, lsl 48
	lsr	x0, x2, x0
	tbz	x0, 0, .Lcrabc_x86_float_parse_scan_250
.Lcrabc_x86_float_parse_scan_248:
	add	x1, x1, 1
	b	.Lcrabc_x86_float_parse_scan_252
.Lcrabc_x86_float_parse_scan_394:
	mov	x0, x19
	bl	crabc_x86_float_parse_shgetc
	cmp	w0, 40
	cset	w0, ne
	b	.Lcrabc_x86_float_parse_scan_242
.Lcrabc_x86_float_parse_scan_395:
	ldr	x0, [x19, 192]
	tbnz	x0, #63, .Lcrabc_x86_float_parse_scan_244
	ldr	x0, [x19, 8]
	sub	x0, x0, #1
	str	x0, [x19, 8]
.Lcrabc_x86_float_parse_scan_244:
	adrp	x0, .Lcrabc_x86_float_parse_scan_C8
	add	x0, x0, :lo12:.Lcrabc_x86_float_parse_scan_C8
	ldr	q0, [x0]
	b	.Lcrabc_x86_float_parse_scan_209
.Lcrabc_x86_float_parse_scan_245:
	mov	x0, x19
	str	x1, [sp, 80]
	bl	crabc_x86_float_parse_shgetc
	ldr	x1, [sp, 80]
	b	.Lcrabc_x86_float_parse_scan_246
.Lcrabc_x86_float_parse_scan_396:
	cmp	w0, 47
	bgt	.Lcrabc_x86_float_parse_scan_248
	cmp	w0, 41
	beq	.Lcrabc_x86_float_parse_scan_244
.Lcrabc_x86_float_parse_scan_250:
	ldr	x2, [x19, 192]
	tbnz	x2, #63, .Lcrabc_x86_float_parse_scan_254
	ldr	x0, [x19, 8]
	sub	x0, x0, #1
	str	x0, [x19, 8]
.Lcrabc_x86_float_parse_scan_254:
	cbz	w20, .Lcrabc_x86_float_parse_scan_384
	cbz	x1, .Lcrabc_x86_float_parse_scan_244
	sub	x0, x1, #1
	tbnz	x2, #63, .Lcrabc_x86_float_parse_scan_259
.Lcrabc_x86_float_parse_scan_256:
	ldr	x1, [x19, 8]
	cbz	x0, .Lcrabc_x86_float_parse_scan_397
	sub	x1, x1, #2
	str	x1, [x19, 8]
	cmp	x0, 1
	beq	.Lcrabc_x86_float_parse_scan_244
	sub	x0, x0, #2
	b	.Lcrabc_x86_float_parse_scan_256
.Lcrabc_x86_float_parse_scan_259:
	cbz	x0, .Lcrabc_x86_float_parse_scan_244
	cmp	x0, 1
	beq	.Lcrabc_x86_float_parse_scan_244
	sub	x0, x0, #2
	b	.Lcrabc_x86_float_parse_scan_259
.Lcrabc_x86_float_parse_scan_397:
	sub	x1, x1, #1
	str	x1, [x19, 8]
	b	.Lcrabc_x86_float_parse_scan_244
.Lcrabc_x86_float_parse_scan_393:
	cbnz	x5, .Lcrabc_x86_float_parse_scan_261
	cmp	w1, 48
	bne	.Lcrabc_x86_float_parse_scan_264
	ldr	x0, [x19, 8]
	ldr	x2, [x19, 184]
	cmp	x0, x2
	beq	.Lcrabc_x86_float_parse_scan_265
	add	x2, x0, 1
	str	x2, [x19, 8]
	ldrb	w0, [x0]
.Lcrabc_x86_float_parse_scan_266:
	orr	w0, w0, 32
	cmp	w0, 120
	beq	.Lcrabc_x86_float_parse_scan_398
	ldr	x0, [x19, 192]
	tbnz	x0, #63, .Lcrabc_x86_float_parse_scan_264
	ldr	x0, [x19, 8]
	sub	x0, x0, #1
	str	x0, [x19, 8]
.Lcrabc_x86_float_parse_scan_264:
	mov	w5, w20
	mov	w3, w22
	mov	w2, w21
	mov	x0, x19
	ldp	x20, x21, [sp, 16]
	ldp	x22, x23, [sp, 32]
	ldp	x30, x19, [sp], 144
	b	crabc_x86_float_parse_decfloat
.Lcrabc_x86_float_parse_scan_265:
	mov	x0, x19
	str	w4, [sp, 80]
	str	w1, [sp, 96]
	bl	crabc_x86_float_parse_shgetc
	ldr	w4, [sp, 80]
	ldr	w1, [sp, 96]
	b	.Lcrabc_x86_float_parse_scan_266
.Lcrabc_x86_float_parse_scan_398:
	stp	x24, x25, [sp, 48]
	ldr	x0, [x19, 8]
	ldr	x1, [x19, 184]
	cmp	x0, x1
	beq	.Lcrabc_x86_float_parse_scan_268
	add	x1, x0, 1
	str	x1, [x19, 8]
	ldrb	w1, [x0]
.Lcrabc_x86_float_parse_scan_269:
	mov	w6, 0
	b	.Lcrabc_x86_float_parse_scan_272
.Lcrabc_x86_float_parse_scan_268:
	mov	x0, x19
	str	w4, [sp, 80]
	bl	crabc_x86_float_parse_shgetc
	mov	w1, w0
	ldr	w4, [sp, 80]
	b	.Lcrabc_x86_float_parse_scan_269
.Lcrabc_x86_float_parse_scan_270:
	mov	x0, x19
	str	w4, [sp, 80]
	bl	crabc_x86_float_parse_shgetc
	mov	w1, w0
	ldr	w4, [sp, 80]
.Lcrabc_x86_float_parse_scan_271:
	mov	w6, 1
.Lcrabc_x86_float_parse_scan_272:
	cmp	w1, 48
	bne	.Lcrabc_x86_float_parse_scan_399
	ldr	x0, [x19, 8]
	ldr	x1, [x19, 184]
	cmp	x0, x1
	beq	.Lcrabc_x86_float_parse_scan_270
	add	x1, x0, 1
	str	x1, [x19, 8]
	ldrb	w1, [x0]
	b	.Lcrabc_x86_float_parse_scan_271
.Lcrabc_x86_float_parse_scan_399:
	mov	x24, 0
	mov	w23, 0
	cmp	w1, 46
	beq	.Lcrabc_x86_float_parse_scan_400
.Lcrabc_x86_float_parse_scan_274:
	adrp	x0, .Lcrabc_x86_float_parse_scan_C3
	add	x0, x0, :lo12:.Lcrabc_x86_float_parse_scan_C3
	mov	x2, 0
	mov	w25, 0
	mov	w5, 0
	stp	xzr, xzr, [sp, 80]
	ldr	q31, [x0]
	str	q31, [sp, 96]
	b	.Lcrabc_x86_float_parse_scan_290
.Lcrabc_x86_float_parse_scan_400:
	ldr	x0, [x19, 8]
	ldr	x1, [x19, 184]
	cmp	x0, x1
	beq	.Lcrabc_x86_float_parse_scan_275
	add	x1, x0, 1
	str	x1, [x19, 8]
	ldrb	w1, [x0]
.Lcrabc_x86_float_parse_scan_276:
	mov	x24, 0
	b	.Lcrabc_x86_float_parse_scan_279
.Lcrabc_x86_float_parse_scan_275:
	mov	x0, x19
	str	w4, [sp, 80]
	str	w6, [sp, 96]
	bl	crabc_x86_float_parse_shgetc
	ldr	w4, [sp, 80]
	mov	w1, w0
	ldr	w6, [sp, 96]
	b	.Lcrabc_x86_float_parse_scan_276
.Lcrabc_x86_float_parse_scan_277:
	mov	x0, x19
	str	w4, [sp, 80]
	bl	crabc_x86_float_parse_shgetc
	mov	w1, w0
	ldr	w4, [sp, 80]
.Lcrabc_x86_float_parse_scan_278:
	sub	x24, x24, #1
	mov	w6, 1
.Lcrabc_x86_float_parse_scan_279:
	cmp	w1, 48
	bne	.Lcrabc_x86_float_parse_scan_401
	ldr	x0, [x19, 8]
	ldr	x1, [x19, 184]
	cmp	x0, x1
	beq	.Lcrabc_x86_float_parse_scan_277
	add	x1, x0, 1
	str	x1, [x19, 8]
	ldrb	w1, [x0]
	b	.Lcrabc_x86_float_parse_scan_278
.Lcrabc_x86_float_parse_scan_401:
	mov	w23, 1
	b	.Lcrabc_x86_float_parse_scan_274
.Lcrabc_x86_float_parse_scan_291:
	cmp	w1, 46
	beq	.Lcrabc_x86_float_parse_scan_292
	sub	w3, w3, #87
	cmp	w1, 57
	csel	w0, w3, w0, gt
.Lcrabc_x86_float_parse_scan_284:
	cmp	x2, 7
	bgt	.Lcrabc_x86_float_parse_scan_285
	add	w5, w0, w5, lsl 4
.Lcrabc_x86_float_parse_scan_286:
	add	x2, x2, 1
	mov	w6, 1
.Lcrabc_x86_float_parse_scan_283:
	ldr	x0, [x19, 8]
	ldr	x1, [x19, 184]
	cmp	x0, x1
	beq	.Lcrabc_x86_float_parse_scan_288
	add	x1, x0, 1
	str	x1, [x19, 8]
	ldrb	w1, [x0]
.Lcrabc_x86_float_parse_scan_290:
	sub	w0, w1, #48
	cmp	w0, 9
	bls	.Lcrabc_x86_float_parse_scan_284
	orr	w3, w1, 32
	sub	w7, w3, #97
	cmp	w7, 5
	bls	.Lcrabc_x86_float_parse_scan_291
	cmp	w1, 46
	bne	.Lcrabc_x86_float_parse_scan_402
.Lcrabc_x86_float_parse_scan_292:
	cbnz	w23, .Lcrabc_x86_float_parse_scan_282
	mov	x24, x2
	mov	w23, 1
	b	.Lcrabc_x86_float_parse_scan_283
.Lcrabc_x86_float_parse_scan_285:
	cmp	x2, 29
	bgt	.Lcrabc_x86_float_parse_scan_287
	stp	w5, w0, [sp, 136]
	adrp	x0, .Lcrabc_x86_float_parse_scan_C9
	add	x0, x0, :lo12:.Lcrabc_x86_float_parse_scan_C9
	ldr	q0, [sp, 96]
	str	w4, [sp, 112]
	str	x2, [sp, 128]
	ldr	q1, [x0]
	bl	__multf3
	str	q0, [sp, 96]
	ldr	w0, [sp, 140]
	bl	__floatsitf
	ldr	q1, [sp, 96]
	bl	__multf3
	mov	v1.16b, v0.16b
	ldr	q0, [sp, 80]
	bl	__addtf3
	str	q0, [sp, 80]
	ldr	x2, [sp, 128]
	ldr	w4, [sp, 112]
	ldr	w5, [sp, 136]
	b	.Lcrabc_x86_float_parse_scan_286
.Lcrabc_x86_float_parse_scan_287:
	cmp	w0, 0
	eor	w0, w25, 1
	cset	w1, ne
	tst	w1, w0
	beq	.Lcrabc_x86_float_parse_scan_286
	adrp	x0, .Lcrabc_x86_float_parse_scan_C5
	add	x0, x0, :lo12:.Lcrabc_x86_float_parse_scan_C5
	ldr	q0, [sp, 96]
	mov	w25, 1
	str	w4, [sp, 112]
	ldr	q1, [x0]
	str	x2, [sp, 128]
	str	w5, [sp, 136]
	bl	__multf3
	mov	v1.16b, v0.16b
	ldr	q0, [sp, 80]
	bl	__addtf3
	str	q0, [sp, 80]
	ldr	x2, [sp, 128]
	ldr	w4, [sp, 112]
	ldr	w5, [sp, 136]
	b	.Lcrabc_x86_float_parse_scan_286
.Lcrabc_x86_float_parse_scan_288:
	mov	x0, x19
	str	w4, [sp, 112]
	str	x2, [sp, 128]
	stp	w5, w6, [sp, 136]
	bl	crabc_x86_float_parse_shgetc
	ldr	x2, [sp, 128]
	mov	w1, w0
	ldr	w4, [sp, 112]
	ldp	w5, w6, [sp, 136]
	b	.Lcrabc_x86_float_parse_scan_290
.Lcrabc_x86_float_parse_scan_402:
	cmp	w23, 0
	csel	x24, x24, x2, ne
	cbnz	w6, .Lcrabc_x86_float_parse_scan_303
	ldr	x0, [x19, 192]
	tbnz	x0, #63, .Lcrabc_x86_float_parse_scan_294
	ldr	x0, [x19, 8]
	cbz	w20, .Lcrabc_x86_float_parse_scan_296
	cbnz	w23, .Lcrabc_x86_float_parse_scan_299
	sub	x0, x0, #2
	str	x0, [x19, 8]
	b	.Lcrabc_x86_float_parse_scan_386
.Lcrabc_x86_float_parse_scan_294:
	cbnz	w20, .Lcrabc_x86_float_parse_scan_386
	b	.Lcrabc_x86_float_parse_scan_297
.Lcrabc_x86_float_parse_scan_296:
	sub	x0, x0, #1
	str	x0, [x19, 8]
.Lcrabc_x86_float_parse_scan_297:
	mov	x0, x19
	mov	x1, 0
	str	w4, [sp, 80]
	bl	crabc_x86_float_parse_shlim
	ldr	w4, [sp, 80]
.Lcrabc_x86_float_parse_scan_386:
	scvtf	d0, w4
	movi	d31, #0
	fmul	d0, d0, d31
	bl	__extenddftf2
	ldp	x24, x25, [sp, 48]
	b	.Lcrabc_x86_float_parse_scan_209
.Lcrabc_x86_float_parse_scan_304:
	lsl	w5, w5, 4
	add	x2, x2, 1
.Lcrabc_x86_float_parse_scan_303:
	cmp	x2, 7
	ble	.Lcrabc_x86_float_parse_scan_304
	cmp	w3, 112
	beq	.Lcrabc_x86_float_parse_scan_403
.Lcrabc_x86_float_parse_scan_388:
	ldr	x0, [x19, 192]
	tbnz	x0, #63, .Lcrabc_x86_float_parse_scan_309
	ldr	x0, [x19, 8]
	sub	x0, x0, #1
	str	x0, [x19, 8]
.Lcrabc_x86_float_parse_scan_309:
	mov	x0, 0
.Lcrabc_x86_float_parse_scan_306:
	cbz	w5, .Lcrabc_x86_float_parse_scan_386
	sub	x19, x24, #8
	add	x19, x0, x19, lsl 2
	neg	w0, w22
	cmp	x19, w0, sxtw
	bgt	.Lcrabc_x86_float_parse_scan_404
	sub	w0, w22, #226
	cmp	x19, w0, sxtw
	bge	.Lcrabc_x86_float_parse_scan_313
	str	w4, [sp, 80]
	bl	__errno_location
	mov	w1, 34
	str	w1, [x0]
	ldr	w0, [sp, 80]
	bl	__floatsitf
	adrp	x0, .Lcrabc_x86_float_parse_scan_C1
	add	x0, x0, :lo12:.Lcrabc_x86_float_parse_scan_C1
	ldr	q1, [x0]
	bl	__multf3
	adrp	x0, .Lcrabc_x86_float_parse_scan_C1
	add	x0, x0, :lo12:.Lcrabc_x86_float_parse_scan_C1
	ldr	q1, [x0]
	bl	__multf3
	ldp	x24, x25, [sp, 48]
	b	.Lcrabc_x86_float_parse_scan_209
.Lcrabc_x86_float_parse_scan_403:
	mov	w1, w20
	mov	x0, x19
	str	w4, [sp, 96]
	str	w5, [sp, 112]
	bl	crabc_x86_float_parse_scanexp
	mov	x1, -9223372036854775808
	ldr	w4, [sp, 96]
	ldr	w5, [sp, 112]
	cmp	x0, x1
	bne	.Lcrabc_x86_float_parse_scan_306
	cbnz	w20, .Lcrabc_x86_float_parse_scan_388
	mov	x0, x19
	mov	x1, 0
	bl	crabc_x86_float_parse_shlim
	ldp	x24, x25, [sp, 48]
	b	.Lcrabc_x86_float_parse_scan_210
.Lcrabc_x86_float_parse_scan_404:
	str	w4, [sp, 80]
	bl	__errno_location
	mov	w1, 34
	str	w1, [x0]
	ldr	w0, [sp, 80]
	bl	__floatsitf
	adrp	x0, .Lcrabc_x86_float_parse_scan_C0
	add	x0, x0, :lo12:.Lcrabc_x86_float_parse_scan_C0
	ldr	q1, [x0]
	bl	__multf3
	adrp	x0, .Lcrabc_x86_float_parse_scan_C0
	add	x0, x0, :lo12:.Lcrabc_x86_float_parse_scan_C0
	ldr	q1, [x0]
	bl	__multf3
	ldp	x24, x25, [sp, 48]
	b	.Lcrabc_x86_float_parse_scan_209
.Lcrabc_x86_float_parse_scan_377:
	ldr	q1, [sp, 80]
	str	w4, [sp, 96]
	str	w5, [sp, 112]
	mov	v0.16b, v1.16b
	bl	__addtf3
	ldr	w4, [sp, 96]
	ldr	w5, [sp, 112]
	str	q0, [sp, 80]
.Lcrabc_x86_float_parse_scan_316:
	sub	x19, x19, #1
.Lcrabc_x86_float_parse_scan_313:
	tbnz	w5, #31, .Lcrabc_x86_float_parse_scan_405
	adrp	x0, .Lcrabc_x86_float_parse_scan_C5
	add	x0, x0, :lo12:.Lcrabc_x86_float_parse_scan_C5
	ldr	q0, [sp, 80]
	lsl	w5, w5, 1
	str	w5, [sp, 96]
	ldr	q1, [x0]
	str	w4, [sp, 112]
	bl	__getf2
	ldr	w5, [sp, 96]
	ldr	w4, [sp, 112]
	tbnz	w0, #31, .Lcrabc_x86_float_parse_scan_377
	adrp	x0, .Lcrabc_x86_float_parse_scan_C3
	add	x0, x0, :lo12:.Lcrabc_x86_float_parse_scan_C3
	ldr	q0, [sp, 80]
	add	w5, w5, 1
	str	w5, [sp, 96]
	ldr	q1, [x0]
	str	w4, [sp, 112]
	bl	__subtf3
	mov	v1.16b, v0.16b
	ldr	q0, [sp, 80]
	bl	__addtf3
	str	q0, [sp, 80]
	ldr	w5, [sp, 96]
	ldr	w4, [sp, 112]
	b	.Lcrabc_x86_float_parse_scan_316
.Lcrabc_x86_float_parse_scan_405:
	add	x0, x19, 32
	sub	x0, x0, w22, sxtw
	cmp	x0, w21, sxtw
	bge	.Lcrabc_x86_float_parse_scan_318
	sub	w0, w19, w22
	adds	w0, w0, 32
	mov	w21, w0
	bmi	.Lcrabc_x86_float_parse_scan_329
.Lcrabc_x86_float_parse_scan_318:
	cmp	w21, 112
	bgt	.Lcrabc_x86_float_parse_scan_330
	str	d15, [sp, 64]
.Lcrabc_x86_float_parse_scan_319:
	fmov	d0, 1.0e+0
	mov	w0, 144
	sub	w0, w0, w21
	str	w4, [sp, 96]
	str	w5, [sp, 136]
	bl	crabc_x86_float_parse_scalbn
	ldr	w4, [sp, 96]
	fmov	d15, d0
	str	w4, [sp, 128]
	mov	w0, w4
	bl	__floatsitf
	str	q0, [sp, 96]
	fmov	d0, d15
	bl	__extenddftf2
	ldr	q1, [sp, 96]
	bl	crabc_x86_float_parse_copysignl
	str	q0, [sp, 96]
	cmp	w21, 31
	ldr	q0, [sp, 80]
	movi	v1.2d, #0
	cset	w1, le
	str	w1, [sp, 112]
	bl	__netf2
	cmp	w0, 0
	ldr	w1, [sp, 112]
	cset	w0, ne
	ldr	w4, [sp, 128]
	ldr	w5, [sp, 136]
	tst	w1, w0
	beq	.Lcrabc_x86_float_parse_scan_383
	tbnz	x5, 0, .Lcrabc_x86_float_parse_scan_383
	ldr	d15, [sp, 64]
	add	w5, w5, 1
	stp	xzr, xzr, [sp, 80]
	b	.Lcrabc_x86_float_parse_scan_320
.Lcrabc_x86_float_parse_scan_329:
	mov	w21, 0
	str	d15, [sp, 64]
	b	.Lcrabc_x86_float_parse_scan_319
.Lcrabc_x86_float_parse_scan_330:
	stp	xzr, xzr, [sp, 96]
.Lcrabc_x86_float_parse_scan_320:
	mov	w0, w4
	str	w5, [sp, 128]
	bl	__floatsitf
	ldr	q1, [sp, 80]
	str	q0, [sp, 112]
	bl	__multf3
	str	q0, [sp, 80]
	ldr	w0, [sp, 128]
	bl	__floatunsitf
	ldr	q1, [sp, 112]
	bl	__multf3
	ldr	q1, [sp, 96]
	bl	__addtf3
	ldr	q1, [sp, 80]
	bl	__addtf3
	ldr	q1, [sp, 96]
	bl	__subtf3
	str	q0, [sp, 80]
	movi	v1.2d, #0
	bl	__eqtf2
	cbnz	w0, .Lcrabc_x86_float_parse_scan_322
	bl	__errno_location
	mov	w1, 34
	str	w1, [x0]
.Lcrabc_x86_float_parse_scan_322:
	ldr	q0, [sp, 80]
	mov	w0, w19
	ldp	x24, x25, [sp, 48]
	ldp	x20, x21, [sp, 16]
	ldp	x22, x23, [sp, 32]
	ldp	x30, x19, [sp], 144
	b	crabc_x86_float_parse_scalbnl
.Lcrabc_x86_float_parse_scan_383:
	ldr	d15, [sp, 64]
	b	.Lcrabc_x86_float_parse_scan_320
.Lcrabc_x86_float_parse_scan_282:
	mov	w3, 46
	cbnz	w6, .Lcrabc_x86_float_parse_scan_303
	ldr	x0, [x19, 192]
	tbnz	x0, #63, .Lcrabc_x86_float_parse_scan_294
	ldr	x0, [x19, 8]
	cbz	w20, .Lcrabc_x86_float_parse_scan_296
.Lcrabc_x86_float_parse_scan_299:
	sub	x0, x0, #3
	str	x0, [x19, 8]
	b	.Lcrabc_x86_float_parse_scan_386
.Lcrabc_x86_float_parse_scan_379:
	movi	v0.2d, #0
	ret
	.size	crabc_x86_float_parse_floatscan, .-crabc_x86_float_parse_floatscan
	.section	.rodata.crabc_x86_float_parse_CSW17,"a"
	.align	3
	.type	crabc_x86_float_parse_CSW17, %object
	.size	crabc_x86_float_parse_CSW17, 12
crabc_x86_float_parse_CSW17:
	.word	-149
	.word	-1074
	.word	-16494
	.section	.rodata.crabc_x86_float_parse_CSW16,"a"
	.align	3
	.type	crabc_x86_float_parse_CSW16, %object
	.size	crabc_x86_float_parse_CSW16, 12
crabc_x86_float_parse_CSW16:
	.word	24
	.word	53
	.word	113
	.section	.rodata.crabc_x86_float_parse_th_0,"a"
	.align	4
	.type	crabc_x86_float_parse_th_0, %object
	.size	crabc_x86_float_parse_th_0, 16
crabc_x86_float_parse_th_0:
	.word	10384593
	.word	717069655
	.word	257060992
	.word	658440191
	.section	.rodata.crabc_x86_float_parse_p10s_1,"a"
	.align	4
	.type	crabc_x86_float_parse_p10s_1, %object
	.size	crabc_x86_float_parse_p10s_1, 32
crabc_x86_float_parse_p10s_1:
	.word	10
	.word	100
	.word	1000
	.word	10000
	.word	100000
	.word	1000000
	.word	10000000
	.word	100000000
	.section	.rodata.cst16,"aM",@progbits,16
	.align	4
.Lcrabc_x86_float_parse_scan_C0:
	.word	-1
	.word	-1
	.word	-1
	.word	2147418111
	.align	4
.Lcrabc_x86_float_parse_scan_C1:
	.word	0
	.word	0
	.word	0
	.word	65536
	.align	4
.Lcrabc_x86_float_parse_scan_C2:
	.word	0
	.word	0
	.word	1342177280
	.word	1075633366
	.align	4
.Lcrabc_x86_float_parse_scan_C3:
	.word	0
	.word	0
	.word	0
	.word	1073676288
	.align	4
.Lcrabc_x86_float_parse_scan_C4:
	.word	0
	.word	0
	.word	0
	.word	1081081856
	.align	4
.Lcrabc_x86_float_parse_scan_C5:
	.word	0
	.word	0
	.word	0
	.word	1073610752
	.align	4
.Lcrabc_x86_float_parse_scan_C8:
	.word	0
	.word	0
	.word	0
	.word	2147450880
	.align	4
.Lcrabc_x86_float_parse_scan_C9:
	.word	0
	.word	0
	.word	0
	.word	1073414144
	.global	__extendsftf2
	.global	__netf2
	.global	__getf2
	.global	__eqtf2
	.global	__subtf3
	.global	__addtf3
	.global	__divtf3
	.global	__multf3
	.global	__floatunsitf
	.global	__floatsitf
	.global	__extenddftf2
	.section	.note.GNU-stack,"",@progbits
