.text
/* musl 1.2.6 src/string/aarch64/memset.S; Copyright (c) 2012-2020 Arm Limited; SPDX-License-Identifier: MIT */
.global memset
.type memset,%function
memset:
 dup v0.16B, w1
 add x4, x0, x2
 cmp x2, 96
 b.hi .Lset_long
 cmp x2, 16
 b.hs .Lset_medium
 mov x1, v0.D[0]
 tbz x2, 3, 1f
 str x1, [x0]
 str x1, [x4, -8]
 ret
 nop
1: tbz x2, 2, 2f
 str w1, [x0]
 str w1, [x4, -4]
 ret
2: cbz x2, 3f
 strb w1, [x0]
 tbz x2, 1, 3f
 strh w1, [x4, -2]
3: ret
.Lset_medium:
 str q0, [x0]
 tbnz x2, 6, .Lset96
 str q0, [x4, -16]
 tbz x2, 5, 1f
 str q0, [x0, 16]
 str q0, [x4, -32]
1: ret
 .p2align 4
.Lset96:
 str q0, [x0, 16]
 stp q0, q0, [x0, 32]
 stp q0, q0, [x4, -32]
 ret
 .p2align 4
.Lset_long:
 and w1, w1, 255
 bic x3, x0, 15
 str q0, [x0]
 cmp x2, 160
 ccmp w1, 0, 0, hs
 b.ne .Lno_zva
 mrs x5, dczid_el0
 and x5, x5, 31
 cmp x5, 4
 b.ne .Lno_zva
 str q0, [x3, 16]
 stp q0, q0, [x3, 32]
 bic x3, x3, 63
 sub x2, x4, x3
 sub x2, x2, 128
 .p2align 4
.Lzva_loop:
 add x3, x3, 64
 dc zva, x3
 subs x2, x2, 64
 b.hi .Lzva_loop
 stp q0, q0, [x4, -64]
 stp q0, q0, [x4, -32]
 ret
.Lno_zva:
 sub x2, x4, x3
 sub x3, x3, 16
 sub x2, x2, 64 + 16
.Lno_zva_loop:
 stp q0, q0, [x3, 32]
 stp q0, q0, [x3, 64]!
 subs x2, x2, 64
 b.hi .Lno_zva_loop
 stp q0, q0, [x4, -64]
 stp q0, q0, [x4, -32]
 ret
.size memset,.-memset

.section .note.GNU-stack,"",%progbits
