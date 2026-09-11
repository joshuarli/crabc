"""Explicit native-x86 conformance deltas to pinned musl 1.2.6 sources.

The generators validate the unmodified complete upstream source tree first.
These bounded changes preserve its numerical algorithms and source notices;
see math-scalar-corrections.md for their proof and independent oracle results.
"""


def replace_once(source: str, old: str, new: str) -> str:
    if source.count(old) != 1:
        raise ValueError("pinned math correction source anchor drifted")
    return source.replace(old, new)


def corrected_source(relative: str, source: str) -> str:
    if relative == "src/math/fmaf.c":
        return replace_once(source,
            '\t/* Common case: The double precision result is fine. */\n'
            '\tif ((u.i & 0x1fffffff) != 0x10000000 || /* not a halfway case */',
            '''	/* crabc x86 conformance correction: normal binary32 spacing loses
	 * 29 binary64 significand bits. Subnormal spacing is fixed at 2^-149:
	 * for exponent E in [-150,-127], it loses n=-97-E bits (30..53).
	 * Include the implicit bit for the zero/min-subnormal midpoint n=53.
	 * Smaller magnitudes cannot be binary32 midpoints. The established
	 * residual-directed one-bit repair below remains unchanged. */
	int halfway = (u.i & 0x1fffffff) == 0x10000000;
	if (e < 0x3ff-126) {
		halfway = 0;
		if (e >= 0x3ff-150) {
			int n = 0x3ff-97-e;
			uint64_t significand = (u.i & 0xfffffffffffff) | 0x10000000000000;
			halfway = (significand & ((UINT64_C(1) << n)-1)) == (UINT64_C(1) << (n-1));
		}
	}
	/* Common case: The double precision result is fine. */
	if (!halfway || /* not a halfway case */''')
    if relative == "src/math/fmal.c":
        source = replace_once(source,
            'bits_lost = -u.i.se - scale + 1;',
            '/* The sign bit is not part of the magnitude exponent. */\n\t\tbits_lost = -(u.i.se & 0x7fff) - scale + 1;')
        source = replace_once(source,
            '\tsum = dd_add(a, b);\n\n\t/*\n\t * If we are losing',
            '\tsum = dd_add(a, b);\n'
            '\t/* Save the precision-rounded unbounded exponent before tie repair. */\n'
            '\tu.f = sum.hi;\n'
            '\tint tiny = (int)(u.i.se & 0x7fff) + scale <= 0;\n\n\t/*\n\t * If we are losing')
        return replace_once(source,
            '\treturn scalbnl(sum.hi, scale);\n',
            '''	long double ret = scalbnl(sum.hi, scale);
	/* crabc x86 conformance correction: a nonzero exact dd residual
	 * certifies inexactness. The tie/sticky repair above can make scalbnl
	 * exact, hiding underflow. Intel tininess uses destination precision
	 * with an unbounded exponent (the original sum.hi), not the stored ret:
	 * ret can round to LDBL_MIN and still require underflow. Scaling itself
	 * handles exact dd sums, including the exact half-ULP boundary. */
#if defined(FE_INEXACT) && defined(FE_UNDERFLOW)
	if (sum.lo != 0 && tiny)
		feraiseexcept(FE_UNDERFLOW | FE_INEXACT);
#endif
	return ret;
''')
    if relative == "src/math/nextafterl.c":
        return replace_once(source,
            '\t\t\tif (ux.i.se)\n',
            '\t\t\t/* Negative min-normal also enters the subnormal binade. */\n'
            '\t\t\tif (ux.i.se & 0x7fff)\n')
    if relative == "src/math/powf.c":
        return replace_once(source,
            '\tix = asuint(x);\n\tiy = asuint(y);\n',
            '''	ix = asuint(x);
	iy = asuint(y);
	/* crabc x86 conformance correction: the exact finite identity needs
	 * no logarithm/exponential approximation or flags in any rounding mode.
	 * Raw classification preserves signed zero and leaves signalling NaNs
	 * and infinities to the existing exceptional-value path. */
	if (iy == 0x3f800000 && (ix & 0x7fffffff) < 0x7f800000)
		return x;
''')
    return source
