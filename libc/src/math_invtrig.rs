// Translated from musl: asin.c, acos.c, atan.c, atan2.c,
// asinf.c, acosf.c, atanf.c, atan2f.c

// ============================================================
// Double-precision: shared constants for asin/acos
// ============================================================

const INVTRIG_PIO2_HI: f64 = asdouble(0x3FF921FB54442D18);
const INVTRIG_PIO2_LO: f64 = asdouble(0x3C91A62633145C07);

const INVTRIG_PS0: f64 = asdouble(0x3FC5555555555555);
const INVTRIG_PS1: f64 = asdouble(0xBFD4D61203EB6F7D);
const INVTRIG_PS2: f64 = asdouble(0x3FC9C1550E884455);
const INVTRIG_PS3: f64 = asdouble(0xBFA48228B5688F3B);
const INVTRIG_PS4: f64 = asdouble(0x3F49EFE07501B288);
const INVTRIG_PS5: f64 = asdouble(0x3F023DE10DFDF709);
const INVTRIG_QS1: f64 = asdouble(0xC0033A271C8A2D4B);
const INVTRIG_QS2: f64 = asdouble(0x40002AE59C598AC8);
const INVTRIG_QS3: f64 = asdouble(0xBFE6066C1B8D0159);
const INVTRIG_QS4: f64 = asdouble(0x3FB3B8C5B12E9282);

// Rational approximation R(z) shared by asin and acos.
#[inline]
fn invtrig_r(z: f64) -> f64 {
    let p = z * (INVTRIG_PS0 + z * (INVTRIG_PS1 + z * (INVTRIG_PS2
        + z * (INVTRIG_PS3 + z * (INVTRIG_PS4 + z * INVTRIG_PS5)))));
    let q = 1.0 + z * (INVTRIG_QS1 + z * (INVTRIG_QS2 + z * (INVTRIG_QS3 + z * INVTRIG_QS4)));
    p / q
}

// ============================================================
// asin (double)
// ============================================================

#[no_mangle]
pub unsafe extern "C" fn asin(x: f64) -> f64 {
    let hx = get_high_word(x);
    let ix = hx & 0x7fffffff;
    // |x| >= 1 or nan
    if ix >= 0x3ff00000 {
        let lx = get_low_word(x);
        if (ix.wrapping_sub(0x3ff00000) | lx) == 0 {
            // asin(1) = +-pi/2 with inexact
            return x * INVTRIG_PIO2_HI + asdouble(0x3870000000000000); // 0x1p-120f
        }
        return 0.0 / (x - x);
    }
    // |x| < 0.5
    if ix < 0x3fe00000 {
        // if 0x1p-1022 <= |x| < 0x1p-26, avoid raising underflow
        if ix < 0x3e500000 && ix >= 0x00100000 {
            return x;
        }
        return x + x * invtrig_r(x * x);
    }
    // 1 > |x| >= 0.5
    let z = (1.0 - fabs(x)) * 0.5;
    let s = sqrt(z);
    let r = invtrig_r(z);
    let result;
    if ix >= 0x3fef3333 {
        // |x| > 0.975
        result = INVTRIG_PIO2_HI - (2.0 * (s + s * r) - INVTRIG_PIO2_LO);
    } else {
        // f+c = sqrt(z)
        let mut f = s;
        set_low_word(&mut f, 0);
        let c = (z - f * f) / (s + f);
        result = 0.5 * INVTRIG_PIO2_HI
            - (2.0 * s * r - (INVTRIG_PIO2_LO - 2.0 * c) - (0.5 * INVTRIG_PIO2_HI - 2.0 * f));
    }
    if (hx >> 31) != 0 {
        return -result;
    }
    result
}

// ============================================================
// acos (double)
// ============================================================

#[no_mangle]
pub unsafe extern "C" fn acos(x: f64) -> f64 {
    let hx = get_high_word(x);
    let ix = hx & 0x7fffffff;
    // |x| >= 1 or nan
    if ix >= 0x3ff00000 {
        let lx = get_low_word(x);
        if (ix.wrapping_sub(0x3ff00000) | lx) == 0 {
            // acos(1)=0, acos(-1)=pi
            if (hx >> 31) != 0 {
                return 2.0 * INVTRIG_PIO2_HI + asdouble(0x3870000000000000); // 0x1p-120f
            }
            return 0.0;
        }
        return 0.0 / (x - x);
    }
    // |x| < 0.5
    if ix < 0x3fe00000 {
        if ix <= 0x3c600000 {
            // |x| < 2**-57
            return INVTRIG_PIO2_HI + asdouble(0x3870000000000000); // 0x1p-120f
        }
        return INVTRIG_PIO2_HI - (x - (INVTRIG_PIO2_LO - x * invtrig_r(x * x)));
    }
    // x < -0.5
    if (hx >> 31) != 0 {
        let z = (1.0 + x) * 0.5;
        let s = sqrt(z);
        let w = invtrig_r(z) * s - INVTRIG_PIO2_LO;
        return 2.0 * (INVTRIG_PIO2_HI - (s + w));
    }
    // x > 0.5
    let z = (1.0 - x) * 0.5;
    let s = sqrt(z);
    let mut df = s;
    set_low_word(&mut df, 0);
    let c = (z - df * df) / (s + df);
    let w = invtrig_r(z) * s + c;
    2.0 * (df + w)
}

// ============================================================
// atan (double)
// ============================================================

const INVTRIG_ATANHI: [f64; 4] = [
    asdouble(0x3FDDAC670561BB4F), // atan(0.5)hi
    asdouble(0x3FE921FB54442D18), // atan(1.0)hi
    asdouble(0x3FEF730BD281F69B), // atan(1.5)hi
    asdouble(0x3FF921FB54442D18), // atan(inf)hi
];

const INVTRIG_ATANLO: [f64; 4] = [
    asdouble(0x3C7A2B7F222F65E2), // atan(0.5)lo
    asdouble(0x3C81A62633145C07), // atan(1.0)lo
    asdouble(0x3C7007887AF0CBBD), // atan(1.5)lo
    asdouble(0x3C91A62633145C07), // atan(inf)lo
];

const INVTRIG_AT: [f64; 11] = [
    asdouble(0x3FD555555555550D),
    asdouble(0xBFC999999998EBC4),
    asdouble(0x3FC24924920083FF),
    asdouble(0xBFBC71C6FE231671),
    asdouble(0x3FB745CDC54C206E),
    asdouble(0xBFB3B0F2AF749A6D),
    asdouble(0x3FB10D66A0D03D51),
    asdouble(0xBFADDE2D52DEFD9A),
    asdouble(0x3FA97B4B24760DEB),
    asdouble(0xBFA2B4442C6A6C2F),
    asdouble(0x3F90AD3AE322DA11),
];

#[no_mangle]
pub unsafe extern "C" fn atan(x: f64) -> f64 {
    let ix_raw = get_high_word(x);
    let sign = ix_raw >> 31;
    let mut ix = ix_raw & 0x7fffffff;
    let mut x = x;

    if ix >= 0x44100000 {
        // |x| >= 2^66
        if is_nan(x) {
            return x;
        }
        let z = INVTRIG_ATANHI[3] + asdouble(0x3870000000000000); // 0x1p-120f
        return if sign != 0 { -z } else { z };
    }

    let id;
    if ix < 0x3fdc0000 {
        // |x| < 0.4375
        if ix < 0x3e400000 {
            // |x| < 2^-27
            if ix < 0x00100000 {
                // raise underflow for subnormal x
                force_eval(x as f32);
            }
            return x;
        }
        id = -1i32;
    } else {
        x = fabs(x);
        ix = get_high_word(x) & 0x7fffffff;
        if ix < 0x3ff30000 {
            // |x| < 1.1875
            if ix < 0x3fe60000 {
                // 7/16 <= |x| < 11/16
                id = 0;
                x = (2.0 * x - 1.0) / (2.0 + x);
            } else {
                // 11/16 <= |x| < 19/16
                id = 1;
                x = (x - 1.0) / (x + 1.0);
            }
        } else {
            if ix < 0x40038000 {
                // |x| < 2.4375
                id = 2;
                x = (x - 1.5) / (1.0 + 1.5 * x);
            } else {
                // 2.4375 <= |x| < 2^66
                id = 3;
                x = -1.0 / x;
            }
        }
    }

    // end of argument reduction
    let z = x * x;
    let w = z * z;
    // break sum from i=0 to 10 aT[i]z**(i+1) into odd and even poly
    let s1 = z * (INVTRIG_AT[0] + w * (INVTRIG_AT[2] + w * (INVTRIG_AT[4]
        + w * (INVTRIG_AT[6] + w * (INVTRIG_AT[8] + w * INVTRIG_AT[10])))));
    let s2 = w * (INVTRIG_AT[1] + w * (INVTRIG_AT[3] + w * (INVTRIG_AT[5]
        + w * (INVTRIG_AT[7] + w * INVTRIG_AT[9]))));
    if id < 0 {
        return x - x * (s1 + s2);
    }
    let z = INVTRIG_ATANHI[id as usize] - (x * (s1 + s2) - INVTRIG_ATANLO[id as usize] - x);
    if sign != 0 { -z } else { z }
}

// ============================================================
// atan2 (double)
// ============================================================

const INVTRIG_PI: f64 = asdouble(0x400921FB54442D18);
const INVTRIG_PI_LO: f64 = asdouble(0x3CA1A62633145C07);

#[no_mangle]
pub unsafe extern "C" fn atan2(y: f64, x: f64) -> f64 {
    // GCC lowers the C99 `carg` builtin directly to atan2 on AArch64,
    // bypassing the complex wrapper.  Keep the native binary128
    // intermediates until the public binary64 rounding boundary so the
    // generated complex source checks do not inherit the f64 polynomial
    // boundary error from musl's double implementation.
    let result = atan2l(y as f128, x as f128) as f64;
    // AArch64's f128-to-f64 conversion does not raise the underflow and
    // inexact flags that musl's f64 division raises for a tiny finite result.
    // Restore that observable part of the f64 contract after narrowing.
    if x.is_finite() && y.is_finite() && y != 0.0 {
        let bits = asuint64(result) & 0x7fff_ffff_ffff_ffff;
        if bits == 0 || bits < 0x0010_0000_0000_0000 {
            unsafe { feraiseexcept(FE_INEXACT | FE_UNDERFLOW); }
        }
    }
    result
}



// ============================================================
// Single-precision: shared constants for asinf/acosf
// ============================================================

const INVTRIG_PS0_F: f32 = 1.6666586697e-01;
const INVTRIG_PS1_F: f32 = -4.2743422091e-02;
const INVTRIG_PS2_F: f32 = -8.6563630030e-03;
const INVTRIG_QS1_F: f32 = -7.0662963390e-01;

// Rational approximation R(z) for single-precision asinf/acosf.
#[inline]
fn invtrig_rf(z: f32) -> f32 {
    let p = z * (INVTRIG_PS0_F + z * (INVTRIG_PS1_F + z * INVTRIG_PS2_F));
    let q = 1.0f32 + z * INVTRIG_QS1_F;
    p / q
}

// ============================================================
// asinf (float)
// ============================================================

const INVTRIG_PIO2_F: f64 = asdouble(0x3FF921FB54442D18);

#[no_mangle]
pub unsafe extern "C" fn asinf(x: f32) -> f32 {
    let hx = get_float_word(x);
    let ix = hx & 0x7fffffff;
    // |x| >= 1
    if ix >= 0x3f800000 {
        if ix == 0x3f800000 {
            // |x| == 1
            return (x as f64 * INVTRIG_PIO2_F + asdouble(0x3870000000000000)) as f32; // 0x1p-120f
        }
        return 0.0f32 / (x - x); // asin(|x|>1) is NaN
    }
    // |x| < 0.5
    if ix < 0x3f000000 {
        // if 0x1p-126 <= |x| < 0x1p-12, avoid raising underflow
        if ix < 0x39800000 && ix >= 0x00800000 {
            return x;
        }
        return x + x * invtrig_rf(x * x);
    }
    // 1 > |x| >= 0.5
    let z = (1.0f32 - fabsf(x)) * 0.5f32;
    let s = sqrt(z as f64);
    let result = INVTRIG_PIO2_F - 2.0 * (s + s * invtrig_rf(z) as f64);
    let result = result as f32;
    if (hx >> 31) != 0 {
        return -result;
    }
    result
}

// ============================================================
// acosf (float)
// ============================================================

const INVTRIG_PIO2_HI_F: f32 = asfloat(0x3fc90fda);
const INVTRIG_PIO2_LO_F: f32 = asfloat(0x33a22168);

#[no_mangle]
pub unsafe extern "C" fn acosf(x: f32) -> f32 {
    let hx = get_float_word(x);
    let ix = hx & 0x7fffffff;
    // |x| >= 1 or nan
    if ix >= 0x3f800000 {
        if ix == 0x3f800000 {
            if (hx >> 31) != 0 {
                return 2.0 * INVTRIG_PIO2_HI_F + asfloat(0x03800000); // 0x1p-120f
            }
            return 0.0;
        }
        return 0.0f32 / (x - x);
    }
    // |x| < 0.5
    if ix < 0x3f000000 {
        if ix <= 0x32800000 {
            // |x| < 2**-26
            return INVTRIG_PIO2_HI_F + asfloat(0x03800000); // 0x1p-120f
        }
        return INVTRIG_PIO2_HI_F - (x - (INVTRIG_PIO2_LO_F - x * invtrig_rf(x * x)));
    }
    // x < -0.5
    if (hx >> 31) != 0 {
        let z = (1.0f32 + x) * 0.5f32;
        let s = sqrtf(z);
        let w = invtrig_rf(z) * s - INVTRIG_PIO2_LO_F;
        return 2.0 * (INVTRIG_PIO2_HI_F - (s + w));
    }
    // x > 0.5
    let z = (1.0f32 - x) * 0.5f32;
    let s = sqrtf(z);
    let hz = get_float_word(s);
    let df = asfloat(hz & 0xfffff000);
    let c = (z - df * df) / (s + df);
    let w = invtrig_rf(z) * s + c;
    2.0 * (df + w)
}

// ============================================================
// atanf (float)
// ============================================================

const INVTRIG_ATANHI_F: [f32; 4] = [
    asfloat(0x3eed6338), // atan(0.5)hi
    asfloat(0x3f490fda), // atan(1.0)hi
    asfloat(0x3f7b985e), // atan(1.5)hi
    asfloat(0x3fc90fda), // atan(inf)hi
];

const INVTRIG_ATANLO_F: [f32; 4] = [
    asfloat(0x31ac3769), // atan(0.5)lo
    asfloat(0x33222168), // atan(1.0)lo
    asfloat(0x33140fb4), // atan(1.5)lo
    asfloat(0x33a22168), // atan(inf)lo
];

const INVTRIG_AT_F: [f32; 5] = [
    3.3333328366e-01,
    -1.9999158382e-01,
    1.4253635705e-01,
    -1.0648017377e-01,
    6.1687607318e-02,
];

#[no_mangle]
pub unsafe extern "C" fn atanf(x: f32) -> f32 {
    let ix_raw = get_float_word(x);
    let sign = ix_raw >> 31;
    let mut ix = ix_raw & 0x7fffffff;
    let mut x = x;

    if ix >= 0x4c800000 {
        // |x| >= 2**26
        if is_nanf(x) {
            return x;
        }
        let z = INVTRIG_ATANHI_F[3] + asfloat(0x03800000); // 0x1p-120f
        return if sign != 0 { -z } else { z };
    }

    let id;
    if ix < 0x3ee00000 {
        // |x| < 0.4375
        if ix < 0x39800000 {
            // |x| < 2**-12
            if ix < 0x00800000 {
                // raise underflow for subnormal x
                force_eval(x * x);
            }
            return x;
        }
        id = -1i32;
    } else {
        x = fabsf(x);
        ix = get_float_word(x) & 0x7fffffff;
        if ix < 0x3f980000 {
            // |x| < 1.1875
            if ix < 0x3f300000 {
                // 7/16 <= |x| < 11/16
                id = 0;
                x = (2.0f32 * x - 1.0f32) / (2.0f32 + x);
            } else {
                // 11/16 <= |x| < 19/16
                id = 1;
                x = (x - 1.0f32) / (x + 1.0f32);
            }
        } else {
            if ix < 0x401c0000 {
                // |x| < 2.4375
                id = 2;
                x = (x - 1.5f32) / (1.0f32 + 1.5f32 * x);
            } else {
                // 2.4375 <= |x| < 2**26
                id = 3;
                x = -1.0f32 / x;
            }
        }
    }

    // end of argument reduction
    let z = x * x;
    let w = z * z;
    let s1 = z * (INVTRIG_AT_F[0] + w * (INVTRIG_AT_F[2] + w * INVTRIG_AT_F[4]));
    let s2 = w * (INVTRIG_AT_F[1] + w * INVTRIG_AT_F[3]);
    if id < 0 {
        return x - x * (s1 + s2);
    }
    let z = INVTRIG_ATANHI_F[id as usize] - ((x * (s1 + s2) - INVTRIG_ATANLO_F[id as usize]) - x);
    if sign != 0 { -z } else { z }
}

// ============================================================
// atan2f (float)
// ============================================================

const INVTRIG_PI_F: f32 = asfloat(0x40490fdb);
const INVTRIG_PI_LO_F: f32 = asfloat(0xb3bbbd2e);

#[no_mangle]
pub unsafe extern "C" fn atan2f(y: f32, x: f32) -> f32 {
    let result = atan2l(y as f128, x as f128) as f32;
    if x.is_finite() && y.is_finite() && y != 0.0 {
        let bits = asuint(result) & 0x7fff_ffff;
        if bits == 0 || bits < 0x0080_0000 {
            unsafe { feraiseexcept(FE_INEXACT | FE_UNDERFLOW); }
        }
    }
    result
}
