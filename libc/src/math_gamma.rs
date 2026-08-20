// Gamma functions from musl 1.2.6.
//
// The double and float implementations are the FreeBSD/Sun lgamma_r
// approximation used by musl.  tgamma uses musl's Lanczos approximation.

const GAMMA_PI: f64 = 3.14159265358979311600e+00;

const A0: f64 = 7.72156649015328655494e-02;
const A1: f64 = 3.22467033424113591611e-01;
const A2: f64 = 6.73523010531292681824e-02;
const A3: f64 = 2.05808084325167332806e-02;
const A4: f64 = 7.38555086081402883957e-03;
const A5: f64 = 2.89051383673415629091e-03;
const A6: f64 = 1.19270763183362067845e-03;
const A7: f64 = 5.10069792153511336608e-04;
const A8: f64 = 2.20862790713908385557e-04;
const A9: f64 = 1.08011567247583939954e-04;
const A10: f64 = 2.52144565451257326939e-05;
const A11: f64 = 4.48640949618915160150e-05;
const TC: f64 = 1.46163214496836224576e+00;
const TF: f64 = -1.21486290535849611461e-01;
const TT: f64 = -3.63867699703950536541e-18;
const T0: f64 = 4.83836122723810047042e-01;
const T1: f64 = -1.47587722994593911752e-01;
const T2: f64 = 6.46249402391333854778e-02;
const T3: f64 = -3.27885410759859649565e-02;
const T4: f64 = 1.79706750811820387126e-02;
const T5: f64 = -1.03142241298341437450e-02;
const T6: f64 = 6.10053870246291332635e-03;
const T7: f64 = -3.68452016781138256760e-03;
const T8: f64 = 2.25964780900612472250e-03;
const T9: f64 = -1.40346469989232843813e-03;
const T10: f64 = 8.81081882437654011382e-04;
const T11: f64 = -5.38595305356740546715e-04;
const T12: f64 = 3.15632070903625950361e-04;
const T13: f64 = -3.12754168375120860518e-04;
const T14: f64 = 3.35529192635519073543e-04;
const U0: f64 = -7.72156649015328655494e-02;
const U1: f64 = 6.32827064025093366517e-01;
const U2: f64 = 1.45492250137234768737e+00;
const U3: f64 = 9.77717527963372745603e-01;
const U4: f64 = 2.28963728064692451092e-01;
const U5: f64 = 1.33810918536787660377e-02;
const V1: f64 = 2.45597793713041134822e+00;
const V2: f64 = 2.12848976379893395361e+00;
const V3: f64 = 7.69285150456672783825e-01;
const V4: f64 = 1.04222645593369134254e-01;
const V5: f64 = 3.21709242282423911810e-03;
const S0: f64 = -7.72156649015328655494e-02;
const S1: f64 = 2.14982415960608852501e-01;
const S2: f64 = 3.25778796408930981787e-01;
const S3: f64 = 1.46350472652464452805e-01;
const S4: f64 = 2.66422703033638609560e-02;
const S5: f64 = 1.84028451407337715652e-03;
const S6: f64 = 3.19475326584100867617e-05;
const R1: f64 = 1.39200533467621045958e+00;
const R2: f64 = 7.21935547567138069525e-01;
const R3: f64 = 1.71933865632803078993e-01;
const R4: f64 = 1.86459191715652901344e-02;
const R5: f64 = 7.77942496381893596434e-04;
const R6: f64 = 7.32668430744625636189e-06;
const W0: f64 = 4.18938533204672725052e-01;
const W1: f64 = 8.33333333333329678849e-02;
const W2: f64 = -2.77777777728775536470e-03;
const W3: f64 = 7.93650558643019558500e-04;
const W4: f64 = -5.95187557450339963135e-04;
const W5: f64 = 8.36339918996282139126e-04;
const W6: f64 = -1.63092934096575273989e-03;

fn gamma_sin_pi(mut x: f64) -> f64 {
    x = 2.0 * (x * 0.5 - floor(x * 0.5));
    let mut n = (x * 4.0) as i32;
    n = (n + 1) / 2;
    x -= n as f64 * 0.5;
    x *= GAMMA_PI;
    match n {
        0 => __sin(x, 0.0, 0),
        1 => __cos(x, 0.0),
        2 => __sin(-x, 0.0, 0),
        3 => -__cos(x, 0.0),
        _ => __sin(x, 0.0, 0),
    }
}

unsafe fn lgamma_r_impl(x: f64, signgamp: *mut c_int) -> f64 {
    let bits = x.to_bits();
    let sign = bits >> 63 != 0;
    let ix = ((bits >> 32) & 0x7fffffff) as u32;
    let mut x = x;
    let mut nadj = 0.0;
    let mut r;

    if !signgamp.is_null() { *signgamp = 1; }
    if ix >= 0x7ff00000 {
        return x * x;
    }
    if ix < ((0x3ff - 70) << 20) {
        if sign {
            x = -x;
            if !signgamp.is_null() { *signgamp = -1; }
        }
        return -log(x);
    }
    if sign {
        x = -x;
        let mut t = gamma_sin_pi(x);
        if t == 0.0 {
            return 1.0 / (x - x);
        }
        if t > 0.0 {
            if !signgamp.is_null() { *signgamp = -1; }
        } else {
            t = -t;
        }
        nadj = log(GAMMA_PI / (t * x));
    }

    if (ix == 0x3ff00000 || ix == 0x40000000) && (bits as u32) == 0 {
        r = 0.0;
    } else if ix < 0x40000000 {
        let (y, i, base) = if ix <= 0x3feccccc {
            let y;
            let i;
            if ix >= 0x3FE76944 {
                y = 1.0 - x;
                i = 0;
            } else if ix >= 0x3FCDA661 {
                y = x - (TC - 1.0);
                i = 1;
            } else {
                y = x;
                i = 2;
            }
            (y, i, -log(x))
        } else {
            let y;
            let i;
            if ix >= 0x3FFBB4C3 {
                y = 2.0 - x;
                i = 0;
            } else if ix >= 0x3FF3B4C4 {
                y = x - TC;
                i = 1;
            } else {
                y = x - 1.0;
                i = 2;
            }
            (y, i, 0.0)
        };
        r = base;
        match i {
            0 => {
                let z = y * y;
                let p1 = A0 + z * (A2 + z * (A4 + z * (A6 + z * (A8 + z * A10))));
                let p2 = z * (A1 + z * (A3 + z * (A5 + z * (A7 + z * (A9 + z * A11)))));
                let p = y * p1 + p2;
                r += p - 0.5 * y;
            }
            1 => {
                let z = y * y;
                let w = z * y;
                let p1 = T0 + w * (T3 + w * (T6 + w * (T9 + w * T12)));
                let p2 = T1 + w * (T4 + w * (T7 + w * (T10 + w * T13)));
                let p3 = T2 + w * (T5 + w * (T8 + w * (T11 + w * T14)));
                let p = z * p1 - (TT - w * (p2 + y * p3));
                r += TF + p;
            }
            _ => {
                let p1 = y * (U0 + y * (U1 + y * (U2 + y * (U3 + y * (U4 + y * U5)))));
                let p2 = 1.0 + y * (V1 + y * (V2 + y * (V3 + y * (V4 + y * V5))));
                r += -0.5 * y + p1 / p2;
            }
        }
    } else if ix < 0x40200000 {
        let i = x as i32;
        let y = x - i as f64;
        let p = y * (S0 + y * (S1 + y * (S2 + y * (S3 + y * (S4 + y * (S5 + y * S6))))));
        let q = 1.0 + y * (R1 + y * (R2 + y * (R3 + y * (R4 + y * (R5 + y * R6)))));
        r = 0.5 * y + p / q;
        let mut z = 1.0;
        match i {
            7 => { z *= y + 6.0; z *= y + 5.0; z *= y + 4.0; z *= y + 3.0; z *= y + 2.0; r += log(z); }
            6 => { z *= y + 5.0; z *= y + 4.0; z *= y + 3.0; z *= y + 2.0; r += log(z); }
            5 => { z *= y + 4.0; z *= y + 3.0; z *= y + 2.0; r += log(z); }
            4 => { z *= y + 3.0; z *= y + 2.0; r += log(z); }
            3 => { z *= y + 2.0; r += log(z); }
            _ => {}
        }
    } else if ix < 0x43900000 {
        let t = log(x);
        let z = 1.0 / x;
        let y = z * z;
        let w = W0 + z * (W1 + y * (W2 + y * (W3 + y * (W4 + y * (W5 + y * W6)))));
        r = (x - 0.5) * (t - 1.0) + w;
    } else {
        r = x * (log(x) - 1.0);
    }
    if sign { r = nadj - r; }
    r
}

const AF0: f32 = 7.7215664089e-02;
const AF1: f32 = 3.2246702909e-01;
const AF2: f32 = 6.7352302372e-02;
const AF3: f32 = 2.0580807701e-02;
const AF4: f32 = 7.3855509982e-03;
const AF5: f32 = 2.8905137442e-03;
const AF6: f32 = 1.1927076848e-03;
const AF7: f32 = 5.1006977446e-04;
const AF8: f32 = 2.2086278477e-04;
const AF9: f32 = 1.0801156895e-04;
const AF10: f32 = 2.5214456400e-05;
const AF11: f32 = 4.4864096708e-05;
const ATC: f32 = 1.4616321325e+00;
const ATF: f32 = -1.2148628384e-01;
const ATT: f32 = 6.6971006518e-09;
const AT0: f32 = 4.8383611441e-01;
const AT1: f32 = -1.4758771658e-01;
const AT2: f32 = 6.4624942839e-02;
const AT3: f32 = -3.2788541168e-02;
const AT4: f32 = 1.7970675603e-02;
const AT5: f32 = -1.0314224288e-02;
const AT6: f32 = 6.1005386524e-03;
const AT7: f32 = -3.6845202558e-03;
const AT8: f32 = 2.2596477065e-03;
const AT9: f32 = -1.4034647029e-03;
const AT10: f32 = 8.8108185446e-04;
const AT11: f32 = -5.3859531181e-04;
const AT12: f32 = 3.1563205994e-04;
const AT13: f32 = -3.1275415677e-04;
const AT14: f32 = 3.3552919264e-04;
const AU0: f32 = -7.7215664089e-02;
const AU1: f32 = 6.3282704353e-01;
const AU2: f32 = 1.4549225569e+00;
const AU3: f32 = 9.7771751881e-01;
const AU4: f32 = 2.2896373272e-01;
const AU5: f32 = 1.3381091878e-02;
const AV1: f32 = 2.4559779167e+00;
const AV2: f32 = 2.1284897327e+00;
const AV3: f32 = 7.6928514242e-01;
const AV4: f32 = 1.0422264785e-01;
const AV5: f32 = 3.2170924824e-03;
const AS0: f32 = -7.7215664089e-02;
const AS1: f32 = 2.1498242021e-01;
const AS2: f32 = 3.2577878237e-01;
const AS3: f32 = 1.4635047317e-01;
const AS4: f32 = 2.6642270386e-02;
const AS5: f32 = 1.8402845599e-03;
const AS6: f32 = 3.1947532989e-05;
const AR1: f32 = 1.3920053244e+00;
const AR2: f32 = 7.2193557024e-01;
const AR3: f32 = 1.7193385959e-01;
const AR4: f32 = 1.8645919859e-02;
const AR5: f32 = 7.7794247773e-04;
const AR6: f32 = 7.3266842264e-06;
const AW0: f32 = 4.1893854737e-01;
const AW1: f32 = 8.3333335817e-02;
const AW2: f32 = -2.7777778450e-03;
const AW3: f32 = 7.9365057172e-04;
const AW4: f32 = -5.9518753551e-04;
const AW5: f32 = 8.3633989561e-04;
const AW6: f32 = -1.6309292987e-03;

fn gamma_sin_pif(mut x: f32) -> f32 {
    x = 2.0 * (x * 0.5 - floorf(x * 0.5));
    let mut n = (x * 4.0) as i32;
    n = (n + 1) / 2;
    let y = (x - n as f32 * 0.5) as f64 * 3.14159265358979323846;
    match n {
        0 => __sindf(y),
        1 => __cosdf(y),
        2 => __sindf(-y),
        3 => -__cosdf(y),
        _ => __sindf(y),
    }
}

unsafe fn lgammaf_r_impl(x: f32, signgamp: *mut c_int) -> f32 {
    let bits = x.to_bits();
    let sign = bits >> 31 != 0;
    let ix = bits & 0x7fffffff;
    let mut x = x;
    let mut nadj = 0.0f32;
    let mut r;
    if !signgamp.is_null() { *signgamp = 1; }
    if ix >= 0x7f800000 { return x * x; }
    if ix < 0x35000000 {
        if sign {
            x = -x;
            if !signgamp.is_null() { *signgamp = -1; }
        }
        return -logf(x);
    }
    if sign {
        x = -x;
        let mut t = gamma_sin_pif(x);
        if t == 0.0 { return 1.0 / (x - x); }
        if t > 0.0 {
            if !signgamp.is_null() { *signgamp = -1; }
        } else { t = -t; }
        nadj = logf(3.1415927410 / (t * x));
    }
    if ix == 0x3f800000 || ix == 0x40000000 {
        r = 0.0;
    } else if ix < 0x40000000 {
        let (y, i, base) = if ix <= 0x3f666666 {
            if ix >= 0x3f3b4a20 { (1.0 - x, 0, -logf(x)) }
            else if ix >= 0x3e6d3308 { (x - (ATC - 1.0), 1, -logf(x)) }
            else { (x, 2, -logf(x)) }
        } else if ix >= 0x3fdda618 {
            (2.0 - x, 0, 0.0)
        } else if ix >= 0x3f9da620 {
            (x - ATC, 1, 0.0)
        } else { (x - 1.0, 2, 0.0) };
        r = base;
        match i {
            0 => {
                let z = y * y;
                let p1 = AF0 + z * (AF2 + z * (AF4 + z * (AF6 + z * (AF8 + z * AF10))));
                let p2 = z * (AF1 + z * (AF3 + z * (AF5 + z * (AF7 + z * (AF9 + z * AF11)))));
                r += y * p1 + p2 - 0.5 * y;
            }
            1 => {
                let z = y * y;
                let w = z * y;
                let p1 = AT0 + w * (AT3 + w * (AT6 + w * (AT9 + w * AT12)));
                let p2 = AT1 + w * (AT4 + w * (AT7 + w * (AT10 + w * AT13)));
                let p3 = AT2 + w * (AT5 + w * (AT8 + w * (AT11 + w * AT14)));
                let p = z * p1 - (ATT - w * (p2 + y * p3));
                r += ATF + p;
            }
            _ => {
                let p1 = y * (AU0 + y * (AU1 + y * (AU2 + y * (AU3 + y * (AU4 + y * AU5)))));
                let p2 = 1.0 + y * (AV1 + y * (AV2 + y * (AV3 + y * (AV4 + y * AV5))));
                r += -0.5 * y + p1 / p2;
            }
        }
    } else if ix < 0x41000000 {
        let i = x as i32;
        let y = x - i as f32;
        let p = y * (AS0 + y * (AS1 + y * (AS2 + y * (AS3 + y * (AS4 + y * (AS5 + y * AS6))))));
        let q = 1.0 + y * (AR1 + y * (AR2 + y * (AR3 + y * (AR4 + y * (AR5 + y * AR6)))));
        r = 0.5 * y + p / q;
        let mut z = 1.0f32;
        match i {
            7 => { z *= y + 6.0; z *= y + 5.0; z *= y + 4.0; z *= y + 3.0; z *= y + 2.0; r += logf(z); }
            6 => { z *= y + 5.0; z *= y + 4.0; z *= y + 3.0; z *= y + 2.0; r += logf(z); }
            5 => { z *= y + 4.0; z *= y + 3.0; z *= y + 2.0; r += logf(z); }
            4 => { z *= y + 3.0; z *= y + 2.0; r += logf(z); }
            3 => { z *= y + 2.0; r += logf(z); }
            _ => {}
        }
    } else if ix < 0x5c800000 {
        let t = logf(x);
        let z = 1.0 / x;
        let y = z * z;
        let w = AW0 + z * (AW1 + y * (AW2 + y * (AW3 + y * (AW4 + y * (AW5 + y * AW6)))));
        r = (x - 0.5) * (t - 1.0) + w;
    } else {
        r = x * (logf(x) - 1.0);
    }
    if sign { r = nadj - r; }
    r
}

#[no_mangle]
pub unsafe extern "C" fn lgamma(x: f64) -> f64 {
    let result = lgamma_r_impl(x, core::ptr::addr_of_mut!(__signgam));
    signgam = __signgam;
    result
}

#[no_mangle]
pub unsafe extern "C" fn lgammaf(x: f32) -> f32 {
    let result = lgammaf_r_impl(x, core::ptr::addr_of_mut!(__signgam));
    signgam = __signgam;
    result
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn lgamma_r(x: f64, sign: *mut c_int) -> f64 {
    lgamma_r_impl(x, sign)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn lgammaf_r(x: f32, sign: *mut c_int) -> f32 {
    lgammaf_r_impl(x, sign)
}

const TGAMMA_PI: f64 = 3.141592653589793238462643383279502884;
const TGAMMA_GMHALF: f64 = 5.524680040776729583740234375;
const TGAMMA_SNUM: [f64; 13] = [
    23531376880.410759688572007674451636754734846804940,
    42919803642.649098768957899047001988850926355848959,
    35711959237.355668049440185451547166705960488635843,
    17921034426.037209699919755754458931112671403265390,
    6039542586.3520280050642916443072979210699388420708,
    1439720407.3117216736632230727949123939715485786772,
    248874557.86205415651146038641322942321632125127801,
    31426415.585400194380614231628318205362874684987640,
    2876370.6289353724412254090516208496135991145378768,
    186056.26539522349504029471604569928220784236328,
    8071.6720023658162106380029022722506138218516325024,
    210.82427775157934587250973392071336271166969580291,
    2.5066282746310002701649081771338373386264310793408,
];
const TGAMMA_SDEN: [f64; 13] = [0.0, 39916800.0, 120543840.0, 150917976.0, 105258076.0, 45995730.0, 13339535.0, 2637558.0, 357423.0, 32670.0, 1925.0, 66.0, 1.0];
const TGAMMA_FACT: [f64; 23] = [
    1.0, 1.0, 2.0, 6.0, 24.0, 120.0, 720.0, 5040.0, 40320.0, 362880.0,
    3628800.0, 39916800.0, 479001600.0, 6227020800.0, 87178291200.0,
    1307674368000.0, 20922789888000.0, 355687428096000.0,
    6402373705728000.0, 121645100408832000.0, 2432902008176640000.0,
    51090942171709440000.0, 1124000727777607680000.0,
];

fn tgamma_s(x: f64) -> f64 {
    let mut num = 0.0;
    let mut den = 0.0;
    if x < 8.0 {
        for i in (0..=12).rev() {
            num = num * x + TGAMMA_SNUM[i];
            den = den * x + TGAMMA_SDEN[i];
        }
    } else {
        for i in 0..=12 {
            num = num / x + TGAMMA_SNUM[i];
            den = den / x + TGAMMA_SDEN[i];
        }
    }
    num / den
}

fn tgamma_sinpi(mut x: f64) -> f64 {
    x *= 0.5;
    x = 2.0 * (x - floor(x));
    let mut n = (4.0 * x) as i32;
    n = (n + 1) / 2;
    x -= n as f64 * 0.5;
    x *= TGAMMA_PI;
    match n {
        0 => __sin(x, 0.0, 0),
        1 => __cos(x, 0.0),
        2 => __sin(-x, 0.0, 0),
        3 => -__cos(x, 0.0),
        _ => __sin(x, 0.0, 0),
    }
}

#[no_mangle]
pub extern "C" fn tgamma(x: f64) -> f64 {
    let bits = x.to_bits();
    let ix = ((bits >> 32) & 0x7fffffff) as u32;
    let sign = bits >> 63 != 0;
    if ix >= 0x7ff00000 { return x + f64::INFINITY; }
    if ix < ((0x3ff - 54) << 20) { return 1.0 / x; }
    if x == floor(x) {
        if sign { return __math_invalid(x); }
        if x <= TGAMMA_FACT.len() as f64 {
            return TGAMMA_FACT[x as usize - 1];
        }
    }
    if ix >= 0x40670000 {
        if sign {
            let x1p_126 = f64::from_bits(0x3810000000000000);
            fp_force_evalf((x1p_126 / x) as f32);
            if floor(x) * 0.5 == floor(x * 0.5) { return 0.0; }
            return -0.0;
        }
        return x * f64::from_bits(0x7fe0000000000000);
    }

    let absx = if sign { -x } else { x };
    let y = absx + TGAMMA_GMHALF;
    let dy = if absx > TGAMMA_GMHALF {
        let mut dy = y - absx;
        dy -= TGAMMA_GMHALF;
        dy
    } else {
        let mut dy = y - TGAMMA_GMHALF;
        dy -= absx;
        dy
    };
    let z = absx - 0.5;
    let mut r = tgamma_s(absx) * exp(-y);
    let (dy, z) = if sign {
        (-dy, -z)
    } else {
        (dy, z)
    };
    if sign { r = -TGAMMA_PI / (tgamma_sinpi(absx) * absx * r); }
    r += dy * (TGAMMA_GMHALF + 0.5) * r / y;
    let zpow = pow(y, 0.5 * z);
    r * zpow * zpow
}
