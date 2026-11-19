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
    if discarded != 0 { raise(0x10 | if encoded == 0 { 8 } else { 0 }); }
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
