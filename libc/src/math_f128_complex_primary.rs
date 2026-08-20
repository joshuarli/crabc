// Native binary128 primary complex functions for AArch64.
//
// musl 1.2.6 defines the primary long-complex identities in terms of the
// corresponding hyperbolic functions:
//
//   csinl(z) = -i * csinhl(i*z)
//   ccosl(z) =     ccoshl(i*z)
//   ctanl(z) = -i * ctanhl(i*z)
//
// The legacy M4 long-complex aliases convert their pair of f128 values to
// f64 before evaluating those identities.  Keep this slice independent of
// that compatibility boundary.  The reduction and kernels below are the
// binary128 branches of musl's sinl/cosl/tanl and __sinl/__cosl/__tanl; the
// complex exceptional-value branches follow musl's csinh.c/ccosh.c/ctanh.c.

#[cfg(target_arch = "aarch64")]
#[inline]
fn m6_f128_primary_complex(re: f128, im: f128) -> M4ComplexLong {
    M4ComplexLong { re, im }
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn m6_f128_primary_copysign(x: f128, sign: f128) -> f128 {
    f128::from_bits((x.to_bits() & !(1u128 << 127)) | (sign.to_bits() & (1u128 << 127)))
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn m6_f128_primary_round_integer(x: f128) -> f128 {
    // Round-to-nearest, ties-to-even.  This is the same representation-level
    // operation used by musl's toint reduction, without calling nearbyintl.
    if !x.is_finite() {
        return x;
    }
    let bits = x.to_bits();
    let sign = bits & (1u128 << 127);
    let abs = bits & !(1u128 << 127);
    let raw_exp = ((abs >> 112) & 0x7fff) as i32;
    if raw_exp == 0 {
        return f128::from_bits(sign);
    }
    let exponent = raw_exp - 0x3fff;
    if exponent >= 112 {
        return x;
    }
    if exponent < -1 {
        return f128::from_bits(sign);
    }
    if exponent == -1 {
        return if f128::from_bits(abs) > 0.5_f128 {
            f128::from_bits(sign | (0x3fffu128 << 112))
        } else {
            f128::from_bits(sign)
        };
    }

    let mask = (1u128 << (112 - exponent as u32)) - 1;
    let truncated_bits = abs & !mask;
    let remainder = abs & mask;
    let halfway = 1u128 << (111 - exponent as u32);
    let odd = ((truncated_bits >> (112 - exponent as u32)) & 1) != 0;
    let round_up = remainder > halfway || (remainder == halfway && odd);
    let truncated = f128::from_bits(truncated_bits);
    if round_up {
        if sign != 0 {
            -truncated - 1.0_f128
        } else {
            truncated + 1.0_f128
        }
    } else if sign != 0 {
        -truncated
    } else {
        truncated
    }
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn m6_f128_primary_round_i32(x: f128) -> i32 {
    let rounded = m6_f128_primary_round_integer(x);
    if rounded >= 2147483647.0_f128 {
        return i32::MAX;
    }
    if rounded <= -2147483648.0_f128 {
        return i32::MIN;
    }
    let bits = rounded.to_bits();
    let negative = bits & (1u128 << 127) != 0;
    let abs = bits & !(1u128 << 127);
    let raw_exp = ((abs >> 112) & 0x7fff) as i32;
    if raw_exp == 0 {
        return 0;
    }
    let exponent = raw_exp - 0x3fff;
    if exponent < 0 {
        return 0;
    }
    let significand = (1u128 << 112) | (abs & ((1u128 << 112) - 1));
    let value = if exponent >= 112 {
        significand << (exponent - 112)
    } else {
        significand >> (112 - exponent)
    };
    if negative { -(value as i32) } else { value as i32 }
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn m6_f128_primary_mod4(x: f128) -> u8 {
    let bits = x.to_bits();
    let negative = bits & (1u128 << 127) != 0;
    let abs = bits & !(1u128 << 127);
    let raw_exp = ((abs >> 112) & 0x7fff) as i32;
    if raw_exp == 0 {
        return 0;
    }
    let exponent = raw_exp - 0x3fff;
    if exponent < 0 {
        return 0;
    }
    let significand = (1u128 << 112) | (abs & ((1u128 << 112) - 1));
    let mut remainder = if exponent >= 112 {
        if exponent - 112 >= 2 { 0 } else { (significand << (exponent - 112) & 3) as u8 }
    } else {
        (significand >> (112 - exponent) & 3) as u8
    };
    if negative && remainder != 0 {
        remainder = 4 - remainder;
    }
    remainder
}

// The split is the LDBL_MANT_DIG == 113 branch from musl's __rem_pio2l.c.
#[cfg(target_arch = "aarch64")]
const M6_F128_INVPIO2: f128 =
    6.3661977236758134307553505349005747e-1_f128;
#[cfg(target_arch = "aarch64")]
const M6_F128_PIO2_1: f128 =
    1.5707963267948966192292994253909555e+0_f128;
#[cfg(target_arch = "aarch64")]
const M6_F128_PIO2_1T: f128 =
    2.0222662487959507323996846200947577e-21_f128;
#[cfg(target_arch = "aarch64")]
const M6_F128_PIO2_2: f128 =
    2.0222662487959507323994779168837751e-21_f128;
#[cfg(target_arch = "aarch64")]
const M6_F128_PIO2_2T: f128 =
    2.0670321098263988236496903051604844e-43_f128;
#[cfg(target_arch = "aarch64")]
const M6_F128_PIO2_3: f128 =
    2.0670321098263988236499468110329591e-43_f128;
#[cfg(target_arch = "aarch64")]
const M6_F128_PIO2_3T: f128 =
    -2.5650587247459238361625433492959285e-65_f128;

#[cfg(target_arch = "aarch64")]
#[inline]
fn m6_f128_primary_rem_pio2(x: f128) -> (i32, f128, f128) {
    // The four target probes use arguments in the small (__rem_pio2l) path.
    // Rejecting arguments beyond its exact binary128 integer range is safer
    // than fabricating a reduction from a narrowed f64 value.
    let bits = x.to_bits() & !(1u128 << 127);
    let exponent = ((bits >> 112) & 0x7fff) as i32 - 0x3fff;
    if exponent > 45 {
        return (0, f128::NAN, f128::NAN);
    }

    let fn_value = m6_f128_primary_round_integer(x * M6_F128_INVPIO2);
    let n = m6_f128_primary_round_i32(fn_value);
    let mut r = x - fn_value * M6_F128_PIO2_1;
    let mut w = fn_value * M6_F128_PIO2_1T;
    let mut y0 = r - w;

    // ROUND1=51 and ROUND2=119 for the binary128 path in musl.
    let ybits = y0.to_bits() & !(1u128 << 127);
    let yexp = ((ybits >> 112) & 0x7fff) as i32 - 0x3fff;
    if exponent - yexp > 51 {
        let t = r;
        w = fn_value * M6_F128_PIO2_2;
        r = t - w;
        w = fn_value * M6_F128_PIO2_2T - ((t - r) - w);
        y0 = r - w;

        let y2bits = y0.to_bits() & !(1u128 << 127);
        let y2exp = ((y2bits >> 112) & 0x7fff) as i32 - 0x3fff;
        if exponent - y2exp > 119 {
            let t = r;
            w = fn_value * M6_F128_PIO2_3;
            r = t - w;
            w = fn_value * M6_F128_PIO2_3T - ((t - r) - w);
            y0 = r - w;
        }
    }
    let y1 = (r - y0) - w;
    (n, y0, y1)
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn m6_f128_primary_sin_kernel(x: f128, y: f128, iy: i32) -> f128 {
    // musl __sinl.c, LDBL_MANT_DIG == 113.
    const S1: f128 = -0.16666666666666666666666666666666666606732416116558_f128;
    const S2: f128 = 0.0083333333333333333333333333333331135404851288270047_f128;
    const S3: f128 = -0.00019841269841269841269841269839935785325638310428717_f128;
    const S4: f128 = 0.27557319223985890652557316053039946268333231205686e-5_f128;
    const S5: f128 = -0.25052108385441718775048214826384312253862930064745e-7_f128;
    const S6: f128 = 0.16059043836821614596571832194524392581082444805729e-9_f128;
    const S7: f128 = -0.76471637318198151807063387954939213287488216303768e-12_f128;
    const S8: f128 = 0.28114572543451292625024967174638477283187397621303e-14_f128;
    const S9: f128 = -0.82206352458348947812512122163446202498005154296863e-17_f128;
    const S10: f128 = 0.19572940011906109418080609928334380560135358385256e-19_f128;
    const S11: f128 = -0.38680813379701966970673724299207480965452616911420e-22_f128;
    const S12: f128 = 0.6403815007867187279667856958631588102065991212139412e-25_f128;
    let z = x * x;
    let v = z * x;
    let mut r = S12;
    r = S11 + z * r;
    r = S10 + z * r;
    r = S9 + z * r;
    r = S8 + z * r;
    r = S7 + z * r;
    r = S6 + z * r;
    r = S5 + z * r;
    r = S4 + z * r;
    r = S3 + z * r;
    r = S2 + z * r;
    if iy == 0 {
        x + v * (S1 + z * r)
    } else {
        x - ((z * (0.5_f128 * y - v * r) - y) - v * S1)
    }
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn m6_f128_primary_cos_kernel(x: f128, y: f128) -> f128 {
    // musl __cosl.c, LDBL_MANT_DIG == 113.
    const C1: f128 = 0.04166666666666666666666666666666658424671_f128;
    const C2: f128 = -0.001388888888888888888888888888863490893732_f128;
    const C3: f128 = 0.00002480158730158730158730158600795304914210_f128;
    const C4: f128 = -0.2755731922398589065255474947078934284324e-6_f128;
    const C5: f128 = 0.2087675698786809897659225313136400793948e-8_f128;
    const C6: f128 = -0.1147074559772972315817149986812031204775e-10_f128;
    const C7: f128 = 0.4779477332386808976875457937252120293400e-13_f128;
    const C8: f128 = -0.1561920696721507929516718307820958119868e-15_f128;
    const C9: f128 = 0.4110317413744594971475941557607804508039e-18_f128;
    const C10: f128 = -0.8896592467191938803288521958313920156409e-21_f128;
    const C11: f128 = 0.1601061435794535138244346256065192782581e-23_f128;
    let z = x * x;
    let mut p = C11;
    p = C10 + z * p;
    p = C9 + z * p;
    p = C8 + z * p;
    p = C7 + z * p;
    p = C6 + z * p;
    p = C5 + z * p;
    p = C4 + z * p;
    p = C3 + z * p;
    p = C2 + z * p;
    p = C1 + z * p;
    let r = z * p;
    let hz = 0.5_f128 * z;
    let w = 1.0_f128 - hz;
    w + ((1.0_f128 - w) - hz + (z * r - x * y))
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn m6_f128_primary_sincos(x: f128) -> (f128, f128) {
    const PIO4: f128 = 0.785398163397448309615660845819875721_f128;
    if !x.is_finite() {
        return (x - x, x - x);
    }
    if x.abs() < PIO4 {
        return (m6_f128_primary_sin_kernel(x, 0.0_f128, 0),
            m6_f128_primary_cos_kernel(x, 0.0_f128));
    }
    let (n, hi, lo) = m6_f128_primary_rem_pio2(x);
    if hi.is_nan() {
        return (f128::NAN, f128::NAN);
    }
    let s = m6_f128_primary_sin_kernel(hi, lo, 1);
    let c = m6_f128_primary_cos_kernel(hi, lo);
    match (n & 3) as u8 {
        0 => (s, c),
        1 => (c, -s),
        2 => (-s, -c),
        _ => (-c, s),
    }
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn m6_f128_primary_tan_kernel(mut x: f128, mut y: f128, odd: i32) -> f128 {
    // musl __tanl.c, LDBL_MANT_DIG == 113.
    const T3: f128 = 3.333333333333333333333333333333332209874199107445752384012866825459064186107371874356886110035702586e-1_f128;
    const T5: f128 = 1.333333333333333333333333333334173985704642158556226825572122132566814226885265615152320606284774840e-1_f128;
    const T7: f128 = 5.396825396825396825396825394599750273580197361669622078219301782566610990558853000464978322270326316e-2_f128;
    const T9: f128 = 2.186948853615520282186949156532230973713846164591207901569363215552093483761211811788882641849340871874e-2_f128;
    const T11: f128 = 8.863235529902196568862985030095304065210490473539241384299836755111214514537415487538396519084926695e-3_f128;
    const T13: f128 = 3.592128036572481016939318053106321871504330698038492443087225029172760872108183249906687706243e-3_f128;
    const T15: f128 = 1.455834387051318267703762090279567377458009957414639709416195312647783926044125352161628939029e-3_f128;
    const T17: f128 = 5.900274409455859973598910786909227360450134808508416209007223895576705597861618540767025820059643593e-4_f128;
    const T19: f128 = 2.391291142435521222387976252812025032030740609751114455389292962377384725572633007717460174035295495e-4_f128;
    const T21: f128 = 9.691537956930085110212187503521091987166667278105571175134719285075719205001200037830066946753504453e-5_f128;
    const T23: f128 = 3.927832388322703862409700975096611533135999558120417384355730069975412807449733016210147162894372741e-5_f128;
    const T25: f128 = 1.591890507036029917917696473867338849242651648144733639757128956864314307313073085237142834102996858e-5_f128;
    const T27: f128 = 6.451689205932863740618475028789047869950111545631162037339066559318807037435691462655407146797870155e-6_f128;
    const T29: f128 = 2.614771227144504199324624295602988361942434287487838724238017962516719349984930094400389921638350188e-6_f128;
    const T31: f128 = 1.059726339292086026013411733006587210445199991347545242355367845699076212273594506862658959356338073e-6_f128;
    const T33: f128 = 4.294937832698595302585753638865114193869815593233214468601610028594280343081803704991927100875770407e-7_f128;
    const T35: f128 = 1.740540191144708061545876046633105522661154825905282993493896955604671899990283575080859956862866511e-7_f128;
    const T37: f128 = 7.059276525061443598330372693562358636137503748816757058146719054865869618923171000652271034336848743e-8_f128;
    const PIO4: f128 = 7.853981633974483096156608458198756993697670245343238932511260829685741796657438840156828518956899643e-1_f128;
    const PIO4LO: f128 = 2.167952532530945256199261006510837136224815950682750676718136411349058866619601027015628214438986706e-35_f128;
    const T39: f128 = 0.000000028443389121318352_f128;
    const T41: f128 = 0.000000011981013102001973_f128;
    const T43: f128 = 0.0000000038303578044958070_f128;
    const T45: f128 = 0.0000000034664378216909893_f128;
    const T47: f128 = -0.0000000015090641701997785_f128;
    const T49: f128 = 0.0000000029449552300483952_f128;
    const T51: f128 = -0.0000000022006995706097711_f128;
    const T53: f128 = 0.0000000015468200913196612_f128;
    const T55: f128 = -0.00000000061311613386849674_f128;
    const T57: f128 = 1.4912469681508012e-10_f128;
    let big = x.abs() >= 0.67434_f128;
    let mut sign = false;
    if big {
        if x < 0.0_f128 {
            sign = true;
            x = -x;
            y = -y;
        }
        x = (PIO4 - x) + (PIO4LO - y);
        y = 0.0_f128;
    }
    let z = x * x;
    let w = z * z;
    let mut rp = T57;
    rp = T53 + w * rp;
    rp = T49 + w * rp;
    rp = T45 + w * rp;
    rp = T41 + w * rp;
    rp = T37 + w * rp;
    rp = T33 + w * rp;
    rp = T29 + w * rp;
    rp = T25 + w * rp;
    rp = T21 + w * rp;
    rp = T17 + w * rp;
    rp = T13 + w * rp;
    rp = T9 + w * rp;
    let r = T5 + w * rp;
    let mut vp = T55;
    vp = T51 + w * vp;
    vp = T47 + w * vp;
    vp = T43 + w * vp;
    vp = T39 + w * vp;
    vp = T35 + w * vp;
    vp = T31 + w * vp;
    vp = T27 + w * vp;
    vp = T23 + w * vp;
    vp = T19 + w * vp;
    vp = T15 + w * vp;
    vp = T11 + w * vp;
    let v = z * (T7 + w * vp);
    let s = z * x;
    let r = y + z * (s * (r + v) + y) + T3 * s;
    let w = x + r;
    if big {
        let s = if odd != 0 { -1.0_f128 } else { 1.0_f128 };
        let v = s - 2.0_f128 * (x + (r - w * w / (w + s)));
        return if sign { -v } else { v };
    }
    if odd == 0 {
        w
    } else {
        // Accurate -1/(x+r), matching the final branch of musl __tanl.
        let z = w;
        let z = z + 4294967296.0_f128 - 4294967296.0_f128;
        let v = r - (z - x);
        let a = -1.0_f128 / w;
        let t = a + 4294967296.0_f128 - 4294967296.0_f128;
        let s = 1.0_f128 + t * z;
        t + a * (s + t * v)
    }
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn m6_f128_primary_tan(x: f128) -> f128 {
    if !x.is_finite() {
        return x - x;
    }
    const PIO4: f128 = 0.785398163397448309615660845819875721_f128;
    if x.abs() < PIO4 {
        return m6_f128_primary_tan_kernel(x, 0.0_f128, 0);
    }
    let (n, hi, lo) = m6_f128_primary_rem_pio2(x);
    if hi.is_nan() { return f128::NAN; }
    m6_f128_primary_tan_kernel(hi, lo, n & 1)
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn m6_f128_primary_pow2(exp: i32) -> f128 {
    if exp > 16383 { return f128::INFINITY; }
    if exp < -16494 { return 0.0_f128; }
    if exp >= -16382 {
        f128::from_bits(((exp + 16383) as u128) << 112)
    } else {
        f128::from_bits(1u128 << (exp + 16494) as u32)
    }
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn m6_f128_primary_exp(x: f128) -> f128 {
    // A binary128 Taylor kernel after musl's ln(2) reduction.  The first
    // 80 bits are kept separate from the residual so n*ln(2) does not lose
    // the low half of a binary128 argument.
    const LN2_HI: f128 = 6.93147180559945309417231954749584485020279245315322214082698337733745574951171875e-1_f128;
    const LN2_LO: f128 = 1.6670859208305522088904493304003798e-25_f128;
    if x.is_nan() { return x; }
    if x.is_infinite() { return if x.is_sign_negative() { 0.0_f128 } else { x }; }
    if x > 11357.0_f128 { return f128::INFINITY; }
    if x < -11434.0_f128 { return 0.0_f128; }
    let n = m6_f128_primary_round_i32(x / (LN2_HI + LN2_LO));
    let nf = n as f128;
    let r = (x - nf * LN2_HI) - nf * LN2_LO;
    let mut term = 1.0_f128;
    let mut sum = 1.0_f128;
    for i in 1..=56 {
        term *= r / (i as f128);
        sum += term;
    }
    sum * m6_f128_primary_pow2(n)
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn m6_f128_primary_sinh(x: f128) -> f128 {
    if x.is_nan() { return x; }
    if x.is_infinite() { return x; }
    let ax = x.abs();
    let e = m6_f128_primary_exp(ax);
    let em = m6_f128_primary_exp(-ax);
    m6_f128_primary_copysign((e - em) * 0.5_f128, x)
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn m6_f128_primary_cosh(x: f128) -> f128 {
    if x.is_nan() { return x; }
    if x.is_infinite() { return f128::INFINITY; }
    let ax = x.abs();
    let e = m6_f128_primary_exp(ax);
    let em = m6_f128_primary_exp(-ax);
    (e + em) * 0.5_f128
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn m6_f128_primary_csinh(z: M4ComplexLong) -> M4ComplexLong {
    let x = z.re;
    let y = z.im;
    if x.is_finite() && y.is_finite() {
        if y == 0.0_f128 { return m6_f128_primary_complex(m6_f128_primary_sinh(x), y); }
        let (sy, cy) = m6_f128_primary_sincos(y);
        return m6_f128_primary_complex(m6_f128_primary_sinh(x) * cy,
            m6_f128_primary_cosh(x) * sy);
    }
    if x == 0.0_f128 && !y.is_finite() {
        let z0 = m6_f128_primary_copysign(0.0_f128, x * (y - y));
        return m6_f128_primary_complex(z0, y - y);
    }
    if y == 0.0_f128 && !x.is_finite() {
        if x.is_infinite() { return m6_f128_primary_complex(x, y); }
        return m6_f128_primary_complex(x, m6_f128_primary_copysign(0.0_f128, y));
    }
    if x.is_finite() && !y.is_finite() {
        return m6_f128_primary_complex(y - y, x * (y - y));
    }
    if x.is_infinite() {
        if !y.is_finite() {
            return m6_f128_primary_complex(x * x, x * (y - y));
        }
        let (sy, cy) = m6_f128_primary_sincos(y);
        return m6_f128_primary_complex(x * cy, f128::INFINITY * sy);
    }
    m6_f128_primary_complex((x * x) * (y - y), (x + x) * (y - y))
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn m6_f128_primary_ccosh(z: M4ComplexLong) -> M4ComplexLong {
    let x = z.re;
    let y = z.im;
    if x.is_finite() && y.is_finite() {
        if y == 0.0_f128 { return m6_f128_primary_complex(m6_f128_primary_cosh(x), x * y); }
        let (sy, cy) = m6_f128_primary_sincos(y);
        return m6_f128_primary_complex(m6_f128_primary_cosh(x) * cy,
            m6_f128_primary_sinh(x) * sy);
    }
    if x == 0.0_f128 && !y.is_finite() {
        return m6_f128_primary_complex(y - y,
            m6_f128_primary_copysign(0.0_f128, x * (y - y)));
    }
    if y == 0.0_f128 && !x.is_finite() {
        if x.is_infinite() { return m6_f128_primary_complex(x * x, m6_f128_primary_copysign(0.0_f128, x) * y); }
        return m6_f128_primary_complex(x,
            m6_f128_primary_copysign(0.0_f128, (x + x) * y));
    }
    if x.is_finite() && !y.is_finite() {
        return m6_f128_primary_complex(y - y, x * (y - y));
    }
    if x.is_infinite() {
        if !y.is_finite() { return m6_f128_primary_complex(x * x, x * (y - y)); }
        let (sy, cy) = m6_f128_primary_sincos(y);
        return m6_f128_primary_complex((x * x) * cy, x * sy);
    }
    m6_f128_primary_complex((x * x) * (y - y), (x + x) * (y - y))
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn m6_f128_primary_ctanh(z: M4ComplexLong) -> M4ComplexLong {
    let x = z.re;
    let y = z.im;
    if x.is_nan() {
        return m6_f128_primary_complex(x, if y == 0.0_f128 { y } else { x * y });
    }
    if x.is_infinite() {
        let (sy, cy) = if y.is_finite() { m6_f128_primary_sincos(y) } else { (y - y, y - y) };
        return m6_f128_primary_complex(m6_f128_primary_copysign(1.0_f128, x),
            m6_f128_primary_copysign(0.0_f128, if y.is_infinite() { y } else { sy * cy }));
    }
    if !y.is_finite() {
        return m6_f128_primary_complex(if x == 0.0_f128 { x } else { y - y }, y - y);
    }
    if x.abs() >= 22.0_f128 {
        let e = m6_f128_primary_exp(-x.abs());
        let (sy, cy) = m6_f128_primary_sincos(y);
        return m6_f128_primary_complex(m6_f128_primary_copysign(1.0_f128, x),
            4.0_f128 * sy * cy * e * e);
    }
    let t = m6_f128_primary_tan(y);
    let beta = 1.0_f128 + t * t;
    let s = m6_f128_primary_sinh(x);
    let rho = m6_f128_primary_cosh(x);
    let denom = 1.0_f128 + beta * s * s;
    m6_f128_primary_complex((beta * rho * s) / denom, t / denom)
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn m6_f128_primary_csqrt(z: M4ComplexLong) -> M4ComplexLong {
    let a = z.re;
    let b = z.im;
    if a == 0.0_f128 && b == 0.0_f128 { return m6_f128_primary_complex(0.0_f128, b); }
    if b.is_infinite() { return m6_f128_primary_complex(f128::INFINITY, b); }
    if a.is_nan() { return m6_f128_primary_complex(a, (b - b) / (b - b)); }
    if a.is_infinite() {
        if a.is_sign_negative() {
            return m6_f128_primary_complex((b - b).abs(), m6_f128_primary_copysign(a, b));
        }
        return m6_f128_primary_complex(a, m6_f128_primary_copysign(b - b, b));
    }
    let threshold = f128::from_bits((0x7ffe_u128 << 112) | ((1u128 << 112) - 1))
        / (1.0_f128 + 1.41421356237309504880168872420969808_f128);
    let scale = a.abs() >= threshold || b.abs() >= threshold;
    let (a, b) = if scale { (a * 0.25_f128, b * 0.25_f128) } else { (a, b) };
    let h = hypotl(a, b);
    let result = if a >= 0.0_f128 {
        let t = f128_sqrt((a + h) * 0.5_f128);
        m6_f128_primary_complex(t, b / (2.0_f128 * t))
    } else {
        let t = f128_sqrt((-a + h) * 0.5_f128);
        m6_f128_primary_complex(b.abs() / (2.0_f128 * t), m6_f128_primary_copysign(t, b))
    };
    if scale { m6_f128_primary_complex(result.re * 2.0_f128, result.im * 2.0_f128) } else { result }
}

#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub extern "C" fn csinl(z: M4ComplexLong) -> M4ComplexLong {
    let w = m6_f128_primary_csinh(m6_f128_primary_complex(-z.im, z.re));
    m6_f128_primary_complex(w.im, -w.re)
}

#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub extern "C" fn ccosl(z: M4ComplexLong) -> M4ComplexLong {
    m6_f128_primary_ccosh(m6_f128_primary_complex(-z.im, z.re))
}

#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub extern "C" fn ctanl(z: M4ComplexLong) -> M4ComplexLong {
    let w = m6_f128_primary_ctanh(m6_f128_primary_complex(-z.im, z.re));
    m6_f128_primary_complex(w.im, -w.re)
}

#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub extern "C" fn csqrtl(z: M4ComplexLong) -> M4ComplexLong {
    m6_f128_primary_csqrt(z)
}

// Keep the hyperbolic long-complex entry points on the same native binary128
// path.  The primary circular functions above use these kernels through the
// musl identities, while these exports serve callers that name the kernels
// directly.
#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub extern "C" fn csinhl(z: M4ComplexLong) -> M4ComplexLong {
    m6_f128_primary_csinh(z)
}

#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub extern "C" fn ccoshl(z: M4ComplexLong) -> M4ComplexLong {
    m6_f128_primary_ccosh(z)
}

#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub extern "C" fn ctanhl(z: M4ComplexLong) -> M4ComplexLong {
    m6_f128_primary_ctanh(z)
}
