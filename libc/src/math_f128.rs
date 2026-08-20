// Native binary128 roots used by the AArch64 long-double complex
// entry points.  The generic long-double adapters in math_compat.rs are
// intentionally f64-backed for the remaining unported functions; these two
// operations must not cross that narrowing boundary because cabsl and cargl
// are tested at the target's full binary128 precision.

#[cfg(target_arch = "aarch64")]
const F128_HYPOT_SPLIT: f128 = 144115188075855873.0_f128; // 2^57 + 1

#[cfg(target_arch = "aarch64")]
const F128_HYPOT_SCALE_UP: f128 = f128::from_bits((26383u128) << 112); // 2^10000

#[cfg(target_arch = "aarch64")]
const F128_HYPOT_SCALE_DOWN: f128 = f128::from_bits((6383u128) << 112); // 2^-10000

#[cfg(target_arch = "aarch64")]
#[inline]
fn f128_sqrt(x: f128) -> f128 {
    // LLVM lowers f128::sqrt to the C sqrtl symbol on AArch64.  That symbol
    // is still an f64 compatibility adapter elsewhere in this crate, so use
    // a local Newton root here to keep hypotl entirely in binary128.
    if x.is_nan() || x < 0.0_f128 {
        return f128::NAN;
    }
    if x == 0.0_f128 || x.is_infinite() {
        return x;
    }

    let bits = x.to_bits();
    if (bits >> 112) & 0x7fff == 0 {
        // Normalize a subnormal before extracting its exponent.  The scale
        // is a power of two, so this does not add rounding to the root.
        let scale_up = f128::from_bits((0x3fff + 200u128) << 112);
        let scale_down = f128::from_bits((0x3fff - 100u128) << 112);
        return f128_sqrt(x * scale_up) * scale_down;
    }
    let fraction = bits & ((1u128 << 112) - 1);
    let exponent = ((bits >> 112) & 0x7fff) as i32 - 0x3fff;
    let odd = exponent & 1;
    let exponent = (exponent - odd) / 2;
    let mut mantissa = f128::from_bits((0x3fffu128 << 112) | fraction);
    if odd != 0 {
        mantissa *= 2.0_f128;
    }

    // Newton iteration converges quadratically from this bound for
    // mantissa in [1, 4). Eight rounds leave substantially more than the
    // 113 bits required by binary128 rounding.
    let mut root = 1.5_f128;
    for _ in 0..8 {
        root = (root + mantissa / root) * 0.5_f128;
    }
    let scale = f128::from_bits(((0x3fff + exponent) as u128) << 112);
    root * scale
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn f128_square(x: f128) -> (f128, f128) {
    // Dekker split, matching musl's hypotl.c for LDBL_MANT_DIG == 113.
    let xc = x * F128_HYPOT_SPLIT;
    let xh = x - xc + xc;
    let xl = x - xh;
    let hi = x * x;
    let lo = xh * xh - hi + 2.0_f128 * xh * xl + xl * xl;
    (hi, lo)
}

#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub extern "C" fn hypotl(x: f128, y: f128) -> f128 {
    let mut ux = x.to_bits() & !(1u128 << 127);
    let mut uy = y.to_bits() & !(1u128 << 127);

    // Arrange |x| >= |y| using the representation's monotonic exponent and
    // fraction fields.  This also leaves musl's inf/nan ordering intact.
    if ux < uy {
        core::mem::swap(&mut ux, &mut uy);
    }

    let ex = ((ux >> 112) & 0x7fff) as i32;
    let ey = ((uy >> 112) & 0x7fff) as i32;
    let mut x = f128::from_bits(ux);
    let mut y = f128::from_bits(uy);

    // hypot(inf, nan) == inf.  After the magnitude ordering above, this is
    // the same branch as musl's `ex == 0x7fff && isinf(y)`.
    if ex == 0x7fff && y.is_infinite() {
        return y;
    }
    if ex == 0x7fff || y == 0.0_f128 {
        return x;
    }
    if ex - ey > 113 {
        return x + y;
    }

    let mut scale = 1.0_f128;
    if ex > 0x3fff + 8000 {
        scale = F128_HYPOT_SCALE_UP;
        x *= F128_HYPOT_SCALE_DOWN;
        y *= F128_HYPOT_SCALE_DOWN;
    } else if ey < 0x3fff - 8000 {
        scale = F128_HYPOT_SCALE_DOWN;
        x *= F128_HYPOT_SCALE_UP;
        y *= F128_HYPOT_SCALE_UP;
    }

    let (hx, lx) = f128_square(x);
    let (hy, ly) = f128_square(y);
    scale * f128_sqrt(ly + lx + hy + hx)
}

// The high/low split is the same one shared by musl's atanl and atan2l.
#[cfg(target_arch = "aarch64")]
const F128_ATAN_HI: [f128; 4] = [
    4.63647609000806116214256231461214397e-01_f128,
    7.85398163397448309615660845819875699e-01_f128,
    9.82793723247329067985710611014666038e-01_f128,
    1.57079632679489661923132169163975140e+00_f128,
];

#[cfg(target_arch = "aarch64")]
const F128_ATAN_LO: [f128; 4] = [
    4.89509642257333492668618435220297706e-36_f128,
    2.16795253253094525619926100651083806e-35_f128,
    -2.31288434538183565909319952098066272e-35_f128,
    4.33590506506189051239852201302167613e-35_f128,
];

#[cfg(target_arch = "aarch64")]
const F128_ATAN_T: [f128; 24] = [
    3.33333333333333333333333333333333125e-01_f128,
    -1.99999999999999999999999999999180430e-01_f128,
    1.42857142857142857142857142125269827e-01_f128,
    -1.11111111111111111111110834490810169e-01_f128,
    9.09090909090909090908522355708623681e-02_f128,
    -7.69230769230769230696553844935357021e-02_f128,
    6.66666666666666660390096773046256096e-02_f128,
    -5.88235294117646671706582985209643694e-02_f128,
    5.26315789473666478515847092020327506e-02_f128,
    -4.76190476189855517021024424991436144e-02_f128,
    4.34782608678695085948531993458097026e-02_f128,
    -3.99999999632663469330634215991142368e-02_f128,
    3.70370363987423702891250829918659723e-02_f128,
    -3.44827496515048090726669907612335954e-02_f128,
    3.22579620681420149871973710852268528e-02_f128,
    -3.03020767654269261041647570626778067e-02_f128,
    2.85641979882534783223403715930946138e-02_f128,
    -2.69824879726738568189929461383741323e-02_f128,
    2.54194698498808542954187110873675769e-02_f128,
    -2.35083879708189059926183138130183215e-02_f128,
    2.04832358998165364349957325067131428e-02_f128,
    -1.54489555488544397858507248612362957e-02_f128,
    8.64492360989278761437805661575248038e-03_f128,
    -2.58521121597609872727919154569765469e-03_f128,
];

#[cfg(target_arch = "aarch64")]
#[inline]
fn f128_atan_t_even(x: f128) -> f128 {
    F128_ATAN_T[0]
        + x * (F128_ATAN_T[2]
            + x * (F128_ATAN_T[4]
                + x * (F128_ATAN_T[6]
                    + x * (F128_ATAN_T[8]
                        + x * (F128_ATAN_T[10]
                            + x * (F128_ATAN_T[12]
                                + x * (F128_ATAN_T[14]
                                    + x * (F128_ATAN_T[16]
                                        + x * (F128_ATAN_T[18]
                                            + x * (F128_ATAN_T[20]
                                                + x * F128_ATAN_T[22]))))))))))
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn f128_atan_t_odd(x: f128) -> f128 {
    F128_ATAN_T[1]
        + x * (F128_ATAN_T[3]
            + x * (F128_ATAN_T[5]
                + x * (F128_ATAN_T[7]
                    + x * (F128_ATAN_T[9]
                        + x * (F128_ATAN_T[11]
                            + x * (F128_ATAN_T[13]
                                + x * (F128_ATAN_T[15]
                                    + x * (F128_ATAN_T[17]
                                        + x * (F128_ATAN_T[19]
                                            + x * (F128_ATAN_T[21]
                                                + x * F128_ATAN_T[23]))))))))))
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn f128_atan(x: f128) -> f128 {
    let bits = x.to_bits();
    let e = ((bits >> 112) & 0x7fff) as u32;
    let sign = (bits >> 127) != 0;
    let expman = (e << 8) | ((bits >> 104) as u32 & 0xff);

    if e >= 0x3fff + 113 + 1 {
        if x.is_nan() {
            return x;
        }
        return if sign { -F128_ATAN_HI[3] } else { F128_ATAN_HI[3] };
    }

    let mut x = x;
    let id: i32;
    if expman < ((0x3fff - 2) << 8) + 0xc0 {
        if e < 0x3fff - (113 + 1) / 2 {
            return x;
        }
        id = -1;
    } else {
        x = x.abs();
        if expman < (0x3fff << 8) + 0x30 {
            if expman < ((0x3fff - 1) << 8) + 0x60 {
                id = 0;
                x = (2.0_f128 * x - 1.0_f128) / (2.0_f128 + x);
            } else {
                id = 1;
                x = (x - 1.0_f128) / (x + 1.0_f128);
            }
        } else if expman < ((0x3fff + 1) << 8) + 0x38 {
            id = 2;
            x = (x - 1.5_f128) / (1.0_f128 + 1.5_f128 * x);
        } else {
            id = 3;
            x = -1.0_f128 / x;
        }
    }

    let z = x * x;
    let w = z * z;
    let s1 = z * f128_atan_t_even(w);
    let s2 = w * f128_atan_t_odd(w);
    if id < 0 {
        // The musl minimax polynomial is sufficient for its long-double
        // implementation, but the Rust binary128 lowering can round this
        // branch one binary64 ulp high after an AArch64 double is widened.
        // For |x| < 0.4375 the alternating Taylor series converges rapidly
        // (x^2 <= 0.1914), so retain the native precision through the final
        // rounding instead of inheriting that boundary error.
        let x2 = x * x;
        let mut term = x;
        let mut sum = x;
        for n in 1..=80 {
            term *= -x2;
            sum += term / ((2 * n + 1) as f128);
        }
        sum
    } else {
        let id = id as usize;
        let z = F128_ATAN_HI[id] - ((x * (s1 + s2) - F128_ATAN_LO[id]) - x);
        if sign { -z } else { z }
    }
}

#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub extern "C" fn atan2l(y: f128, x: f128) -> f128 {
    if x.is_nan() || y.is_nan() {
        return x + y;
    }
    if x == 1.0_f128 {
        return f128_atan(y);
    }

    let ux = x.to_bits();
    let uy = y.to_bits();
    let ex = ((ux >> 112) & 0x7fff) as i32;
    let ey = ((uy >> 112) & 0x7fff) as i32;
    let m = (((ux >> 127) & 1) << 1 | ((uy >> 127) & 1)) as u32;

    if y == 0.0_f128 {
        return match m {
            0 | 1 => y,
            2 => 2.0_f128 * F128_ATAN_HI[3],
            3 => -2.0_f128 * F128_ATAN_HI[3],
            _ => unsafe { core::hint::unreachable_unchecked() },
        };
    }
    if x == 0.0_f128 {
        return if m & 1 != 0 {
            -F128_ATAN_HI[3]
        } else {
            F128_ATAN_HI[3]
        };
    }
    if ex == 0x7fff {
        if ey == 0x7fff {
            return match m {
                0 => F128_ATAN_HI[3] / 2.0_f128,
                1 => -F128_ATAN_HI[3] / 2.0_f128,
                2 => 1.5_f128 * F128_ATAN_HI[3],
                3 => -1.5_f128 * F128_ATAN_HI[3],
                _ => unsafe { core::hint::unreachable_unchecked() },
            };
        }
        return match m {
            0 => 0.0_f128,
            1 => -0.0_f128,
            2 => 2.0_f128 * F128_ATAN_HI[3],
            3 => -2.0_f128 * F128_ATAN_HI[3],
            _ => unsafe { core::hint::unreachable_unchecked() },
        };
    }
    if ex + 120 < ey || ey == 0x7fff {
        return if m & 1 != 0 {
            -F128_ATAN_HI[3]
        } else {
            F128_ATAN_HI[3]
        };
    }

    let z = if m & 2 != 0 && ey + 120 < ex {
        0.0_f128
    } else {
        f128_atan((y / x).abs())
    };
    match m {
        0 => z,
        1 => -z,
        2 => 2.0_f128 * F128_ATAN_HI[3] - (z - 2.0_f128 * F128_ATAN_LO[3]),
        _ => (z - 2.0_f128 * F128_ATAN_LO[3]) - 2.0_f128 * F128_ATAN_HI[3],
    }
}
