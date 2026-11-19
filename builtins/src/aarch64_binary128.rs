use core::arch::asm;

const SIGN: u128 = 1_u128 << 127;
const INF: u128 = 0x7fff_u128 << 112;
const QUIET: u128 = 1_u128 << 111;

fn raise_invalid() {
    let mut fpsr: u64;
    // SAFETY: FPSR is thread-local architectural state; preserve all existing flags.
    unsafe {
        asm!("mrs {0}, fpsr", out(reg) fpsr, options(nomem, nostack));
        fpsr |= 1;
        asm!("msr fpsr, {0}", in(reg) fpsr, options(nomem, nostack));
    }
}

fn compare(a: f128, b: f128, unordered: i32, signaling: bool, equality: bool) -> i32 {
    let a = a.to_bits();
    let b = b.to_bits();
    let aa = a & !SIGN;
    let bb = b & !SIGN;
    let an = aa > INF;
    let bn = bb > INF;
    if an || bn {
        if signaling || (an && aa & QUIET == 0) || (bn && bb & QUIET == 0) {
            raise_invalid();
        }
        return unordered;
    }
    if a == b || (aa == 0 && bb == 0) { return 0; }
    if equality { return 1; }
    if a & SIGN != b & SIGN { return if a & SIGN != 0 { -1 } else { 1 }; }
    let lt = if a & SIGN != 0 { aa > bb } else { aa < bb };
    if lt { -1 } else { 1 }
}

#[no_mangle]
pub extern "C" fn __eqtf2(a: f128, b: f128) -> i32 { compare(a, b, 1, false, true) }
#[no_mangle]
pub extern "C" fn __netf2(a: f128, b: f128) -> i32 { compare(a, b, 1, false, true) }
#[no_mangle]
pub extern "C" fn __letf2(a: f128, b: f128) -> i32 { compare(a, b, 2, true, false) }
#[no_mangle]
pub extern "C" fn __lttf2(a: f128, b: f128) -> i32 { compare(a, b, 2, true, false) }
#[no_mangle]
pub extern "C" fn __getf2(a: f128, b: f128) -> i32 { compare(a, b, -2, true, false) }
#[no_mangle]
pub extern "C" fn __gttf2(a: f128, b: f128) -> i32 { compare(a, b, -2, true, false) }
#[no_mangle]
pub extern "C" fn __unordtf2(a: f128, b: f128) -> i32 {
    let aa = a.to_bits() & !SIGN;
    let bb = b.to_bits() & !SIGN;
    let an = aa > INF;
    let bn = bb > INF;
    if (an && aa & QUIET == 0) || (bn && bb & QUIET == 0) { raise_invalid(); }
    (an || bn) as i32
}

const FRAC: u128 = (1_u128 << 112) - 1;
const ONE: u128 = 1_u128 << 112;

fn round_mode() -> u64 {
    let fpcr: u64;
    // SAFETY: Reading FPCR does not alter architectural state.
    unsafe { asm!("mrs {0}, fpcr", out(reg) fpcr, options(nomem, nostack)); }
    (fpcr >> 22) & 3
}

fn raise(flags: u64) {
    let mut fpsr: u64;
    // SAFETY: FPSR is thread-local architectural state; preserve all existing flags.
    unsafe {
        asm!("mrs {0}, fpsr", out(reg) fpsr, options(nomem, nostack));
        fpsr |= flags;
        asm!("msr fpsr, {0}", in(reg) fpsr, options(nomem, nostack));
    }
}

fn jam(x: u128, shift: u32) -> u128 {
    if shift == 0 { x } else if shift < 128 { (x >> shift) | ((x << (128 - shift) != 0) as u128) } else { (x != 0) as u128 }
}

fn pack(sign: u128, mut exp: i32, mut sig: u128) -> u128 {
    if exp < 1 {
        sig = jam(sig, (1 - exp) as u32);
        exp = 1;
    }
    let mode = round_mode();
    let discarded = sig & 7;
    let tiny = exp == 1 && sig < ONE << 3;
    let mut mag = sig >> 3;
    let increment = match mode {
        0 => discarded > 4 || (discarded == 4 && mag & 1 != 0),
        1 => sign == 0 && discarded != 0,
        2 => sign != 0 && discarded != 0,
        _ => false,
    };
    if increment { mag += 1; }
    if mag >= ONE << 1 { mag >>= 1; exp += 1; }
    if exp >= 0x7fff {
        raise(0x14);
        let infinity = mode == 0 || (mode == 1 && sign == 0) || (mode == 2 && sign != 0);
        return sign | if infinity { INF } else { INF - 1 };
    }
    let encoded = if exp == 1 && mag < ONE { 0 } else { exp as u128 };
    if discarded != 0 { raise(0x10 | if tiny { 8 } else { 0 }); }
    sign | (encoded << 112) | (mag & FRAC)
}

fn nan(a: u128, b: u128) -> Option<u128> {
    let aa = a & !SIGN;
    let bb = b & !SIGN;
    let an = aa > INF;
    let bn = bb > INF;
    if !an && !bn { return None; }
    let asig = an && aa & QUIET == 0;
    let bsig = bn && bb & QUIET == 0;
    if asig || bsig { raise(1); }
    let selected = if asig { a } else if bsig { b } else if an { a } else { b };
    Some(selected | QUIET)
}

fn add_bits(a: u128, b: u128, subtract: bool) -> u128 {
    if let Some(n) = nan(a, b) { return n; }
    let b = b ^ if subtract { SIGN } else { 0 };
    let aa = a & !SIGN;
    let bb = b & !SIGN;
    if aa == INF || bb == INF {
        if aa == INF && bb == INF && (a ^ b) & SIGN != 0 { raise(1); return INF | FRAC; }
        return if aa == INF { a } else { b };
    }
    if aa == 0 && bb == 0 {
        return if a & SIGN == b & SIGN { a } else if round_mode() == 2 { SIGN } else { 0 };
    }
    if aa == 0 { return b; }
    if bb == 0 { return a; }
    let (a,b) = if aa < bb { (b,a) } else { (a,b) };
    let mut exp = ((a >> 112) & 0x7fff) as i32;
    let bexp = ((b >> 112) & 0x7fff) as i32;
    let mut asig = (a & FRAC) | if exp != 0 { ONE } else { 0 };
    let bsig = (b & FRAC) | if bexp != 0 { ONE } else { 0 };
    exp = exp.max(1);
    let bsig = jam(bsig << 3, (exp - bexp.max(1)) as u32);
    asig <<= 3;
    if (a ^ b) & SIGN == 0 {
        asig += bsig;
        if asig & (ONE << 4) != 0 { asig = jam(asig, 1); exp += 1; }
    } else {
        asig -= bsig;
        if asig == 0 { return if round_mode() == 2 { SIGN } else { 0 }; }
        while asig < ONE << 3 && exp > 1 { asig <<= 1; exp -= 1; }
    }
    pack(a & SIGN, exp, asig)
}

#[no_mangle]
pub extern "C" fn __addtf3(a: f128, b: f128) -> f128 { f128::from_bits(add_bits(a.to_bits(), b.to_bits(), false)) }
#[no_mangle]
pub extern "C" fn __subtf3(a: f128, b: f128) -> f128 { f128::from_bits(add_bits(a.to_bits(), b.to_bits(), true)) }

fn normalized(bits: u128) -> (i32, u128) {
    let exponent = ((bits >> 112) & 0x7fff) as i32;
    let mut fraction = bits & FRAC;
    if exponent != 0 { return (exponent, fraction | ONE); }
    let shift = fraction.leading_zeros() - ONE.leading_zeros();
    fraction <<= shift;
    (1 - shift as i32, fraction)
}

fn product(a: u128, b: u128) -> (u128, u128) {
    let mask = u64::MAX as u128;
    let a0 = a & mask;
    let a1 = a >> 64;
    let b0 = b & mask;
    let b1 = b >> 64;
    let p0 = a0 * b0;
    let p1 = a0 * b1;
    let p2 = a1 * b0;
    let (lo, c1) = p0.overflowing_add(p1 << 64);
    let (lo, c2) = lo.overflowing_add(p2 << 64);
    let hi = a1 * b1 + (p1 >> 64) + (p2 >> 64) + c1 as u128 + c2 as u128;
    (hi, lo)
}

fn mul_bits(a: u128, b: u128) -> u128 {
    if let Some(n) = nan(a, b) { return n; }
    let aa = a & !SIGN;
    let bb = b & !SIGN;
    let sign = (a ^ b) & SIGN;
    if aa == INF || bb == INF {
        if aa == 0 || bb == 0 { raise(1); return INF | FRAC; }
        return sign | INF;
    }
    if aa == 0 || bb == 0 { return sign; }
    let (ae, av) = normalized(a);
    let (be, bv) = normalized(b);
    let (hi, lo) = product(av, bv);
    let high = hi & (1_u128 << (225 - 128)) != 0;
    let shift = if high { 110 } else { 109 };
    let sig = (hi << (128 - shift)) | (lo >> shift) | ((lo << (128 - shift) != 0) as u128);
    pack(sign, ae + be - 16383 + high as i32, sig)
}

fn div_bits(a: u128, b: u128) -> u128 {
    if let Some(n) = nan(a, b) { return n; }
    let aa = a & !SIGN;
    let bb = b & !SIGN;
    let sign = (a ^ b) & SIGN;
    if (aa == INF && bb == INF) || (aa == 0 && bb == 0) { raise(1); return INF | FRAC; }
    if aa == INF { return sign | INF; }
    if bb == INF { return sign; }
    if bb == 0 { raise(2); return sign | INF; }
    if aa == 0 { return sign; }
    let (ae, mut av) = normalized(a);
    let (be, bv) = normalized(b);
    let mut exp = ae - be + 16383;
    if av < bv { av <<= 1; exp -= 1; }
    let mut rem = av - bv;
    let mut quotient = 1_u128;
    for _ in 0..115 {
        rem <<= 1;
        quotient <<= 1;
        if rem >= bv { rem -= bv; quotient |= 1; }
    }
    quotient |= (rem != 0) as u128;
    pack(sign, exp, quotient)
}

#[no_mangle]
pub extern "C" fn __multf3(a: f128, b: f128) -> f128 { f128::from_bits(mul_bits(a.to_bits(), b.to_bits())) }
#[no_mangle]
pub extern "C" fn __divtf3(a: f128, b: f128) -> f128 { f128::from_bits(div_bits(a.to_bits(), b.to_bits())) }

fn int_quad(value: u128, sign: u128) -> f128 {
    if value == 0 { return f128::from_bits(sign); }
    let top = 127 - value.leading_zeros();
    let sig = if top <= 115 { value << (115 - top) } else { jam(value, top - 115) };
    f128::from_bits(pack(sign, 16383 + top as i32, sig))
}

#[no_mangle]
pub extern "C" fn __floatsitf(x: i32) -> f128 { int_quad(x.unsigned_abs() as u128, if x < 0 { SIGN } else { 0 }) }
#[no_mangle]
pub extern "C" fn __floatunsitf(x: u32) -> f128 { int_quad(x as u128, 0) }
#[no_mangle]
pub extern "C" fn __floatditf(x: i64) -> f128 { int_quad(x.unsigned_abs() as u128, if x < 0 { SIGN } else { 0 }) }
#[no_mangle]
pub extern "C" fn __floatunditf(x: u64) -> f128 { int_quad(x as u128, 0) }
#[no_mangle]
pub extern "C" fn __floattitf(x: i128) -> f128 { int_quad(x.unsigned_abs(), if x < 0 { SIGN } else { 0 }) }
#[no_mangle]
pub extern "C" fn __floatuntitf(x: u128) -> f128 { int_quad(x, 0) }

fn extend(bits: u64, frac_bits: u32, exp_bits: u32) -> f128 {
    let sign = ((bits >> (frac_bits + exp_bits)) as u128) << 127;
    let exp_mask = (1_u64 << exp_bits) - 1;
    let exp = (bits >> frac_bits) & exp_mask;
    let frac = bits & ((1_u64 << frac_bits) - 1);
    if exp == exp_mask {
        if frac == 0 { return f128::from_bits(sign | INF); }
        if frac & (1_u64 << (frac_bits - 1)) == 0 { raise(1); }
        return f128::from_bits(sign | INF | QUIET | ((frac as u128) << (112 - frac_bits)));
    }
    if exp == 0 && frac == 0 { return f128::from_bits(sign); }
    let bias = (1_i32 << (exp_bits - 1)) - 1;
    let (exp, frac) = if exp == 0 {
        let top = 63 - frac.leading_zeros();
        (1 - bias - (frac_bits - top) as i32, (frac as u128) << (112 - top))
    } else { (exp as i32 - bias, (frac as u128) << (112 - frac_bits)) };
    f128::from_bits(sign | (((exp + 16383) as u128) << 112) | (frac & FRAC))
}

#[no_mangle]
pub extern "C" fn __extendsftf2(x: f32) -> f128 { extend(x.to_bits() as u64, 23, 8) }
#[no_mangle]
pub extern "C" fn __extenddftf2(x: f64) -> f128 { extend(x.to_bits(), 52, 11) }

fn truncate(bits: u128, frac_bits: u32, exp_bits: u32) -> u64 {
    let sign = ((bits >> 127) as u64) << (frac_bits + exp_bits);
    let exp = ((bits >> 112) & 0x7fff) as i32;
    let frac = bits & FRAC;
    let max_exp = (1_u64 << exp_bits) - 1;
    if exp == 0x7fff {
        if frac == 0 { return sign | (max_exp << frac_bits); }
        if frac & QUIET == 0 { raise(1); }
        return sign | (max_exp << frac_bits) | ((frac >> (112-frac_bits)) as u64) | (1_u64 << (frac_bits-1));
    }
    if exp == 0 && frac == 0 { return sign; }
    let (src_exp, src_sig) = normalized(bits);
    let mut target_exp = src_exp - 16383 + ((1_i32 << (exp_bits - 1)) - 1);
    let mut sig = jam(src_sig << 3, 112-frac_bits);
    if target_exp < 1 { sig = jam(sig, (1-target_exp) as u32); target_exp = 1; }
    let lost = sig & 7;
    let tiny = target_exp == 1 && sig < 1_u128 << (frac_bits + 3);
    let mut mag = (sig >> 3) as u64;
    let mode = round_mode();
    let inc = match mode { 0 => lost > 4 || (lost == 4 && mag & 1 != 0), 1 => sign == 0 && lost != 0, 2 => sign != 0 && lost != 0, _ => false };
    if inc { mag += 1; }
    if mag >= 1_u64 << (frac_bits+1) { mag >>= 1; target_exp += 1; }
    if target_exp >= max_exp as i32 {
        raise(0x14);
        let infinity = mode == 0 || (mode == 1 && sign == 0) || (mode == 2 && sign != 0);
        return sign | if infinity { max_exp << frac_bits } else { (max_exp << frac_bits) - 1 };
    }
    let encoded = if target_exp == 1 && mag < 1_u64 << frac_bits { 0 } else { target_exp as u64 };
    if lost != 0 { raise(0x10 | if tiny { 8 } else { 0 }); }
    sign | (encoded << frac_bits) | (mag & ((1_u64 << frac_bits)-1))
}
#[no_mangle]
pub extern "C" fn __trunctfsf2(x: f128) -> f32 { f32::from_bits(truncate(x.to_bits(), 23, 8) as u32) }
#[no_mangle]
pub extern "C" fn __trunctfdf2(x: f128) -> f64 { f64::from_bits(truncate(x.to_bits(), 52, 11)) }

fn fix(bits: u128, width: u32, signed: bool) -> u128 {
    let sign = bits & SIGN != 0;
    let abs = bits & !SIGN;
    let negative = sign;
    let limit = if signed { 1_u128 << (width - 1) } else if width == 128 { u128::MAX } else { (1_u128 << width) - 1 };
    let invalid_value = if negative { if signed { limit } else { 0 } } else if signed { limit - 1 } else { limit };
    let exp = ((abs >> 112) & 0x7fff) as i32 - 16383;
    if abs >= INF || exp >= 128 { raise(1); return if negative && signed { invalid_value.wrapping_neg() } else { invalid_value }; }
    if abs == 0 { return 0; }
    if exp < 0 { raise(0x10); return 0; }
    let sig = (abs & FRAC) | ONE;
    let (magnitude, lost) = if exp >= 112 {
        (sig << (exp - 112), false)
    } else {
        let shift = (112 - exp) as u32;
        (sig >> shift, (sig << (128 - shift)) != 0)
    };
    let invalid = if signed { if negative { magnitude > limit } else { magnitude >= limit } } else { (negative && magnitude != 0) || magnitude > limit };
    if invalid { raise(1); return if negative && signed { invalid_value.wrapping_neg() } else { invalid_value }; }
    if lost { raise(0x10); }
    if negative { magnitude.wrapping_neg() } else { magnitude }
}
#[no_mangle]
pub extern "C" fn __fixtfsi(x: f128) -> i32 { fix(x.to_bits(), 32, true) as i32 }
#[no_mangle]
pub extern "C" fn __fixunstfsi(x: f128) -> u32 { fix(x.to_bits(), 32, false) as u32 }
#[no_mangle]
pub extern "C" fn __fixtfdi(x: f128) -> i64 { fix(x.to_bits(), 64, true) as i64 }
#[no_mangle]
pub extern "C" fn __fixunstfdi(x: f128) -> u64 { fix(x.to_bits(), 64, false) as u64 }
#[no_mangle]
pub extern "C" fn __fixtfti(x: f128) -> i128 { fix(x.to_bits(), 128, true) as i128 }
#[no_mangle]
pub extern "C" fn __fixunstfti(x: f128) -> u128 { fix(x.to_bits(), 128, false) }
