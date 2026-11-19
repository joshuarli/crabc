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
