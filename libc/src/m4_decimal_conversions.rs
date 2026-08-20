// M4 legacy decimal-conversion interfaces.
//
// musl implements these entry points in terms of its printf decimal
// formatter. Keep the same bounds and the same single static result buffer:
// callers of ecvt/fcvt are allowed to retain the pointer only until the next
// conversion call.

static mut M4_ECVT_RESULT: [c_char; 17] = [0; 17];

unsafe fn m4_ecvt_result_ptr() -> *mut c_char {
    core::ptr::addr_of_mut!(M4_ECVT_RESULT).cast::<c_char>()
}

unsafe fn m4_ecvt_special(x: f64, decpt: *mut c_int, sign: *mut c_int) -> *mut c_char {
    let word = if x.is_nan() { b"nan\0" } else { b"inf\0" };
    let result = m4_ecvt_result_ptr();
    for (i, c) in word.iter().enumerate() {
        *result.add(i) = *c as c_char;
    }
    *decpt = 0;
    *sign = x.is_sign_negative() as c_int;
    result
}

#[no_mangle]
pub unsafe extern "C" fn ecvt(
    x: f64,
    n: c_int,
    decpt: *mut c_int,
    sign: *mut c_int,
) -> *mut c_char {
    // This is musl's `if (n-1U > 15) n = 15`, including its treatment of
    // zero and negative values after the signed-to-unsigned conversion.
    let mut digits = n;
    if (digits as c_uint).wrapping_sub(1) > 15 {
        digits = 15;
    }

    // The source-level musl implementation obtains these strings through
    // sprintf, but an exponent is absent for inf/nan. Handle those values
    // before scanning for the exponent so the ABI remains deterministic.
    if !x.is_finite() {
        return m4_ecvt_special(x, decpt, sign);
    }

    let mut tmp = [0 as c_char; 32];
    sprintf(
        tmp.as_mut_ptr(),
        b"%.*e\0".as_ptr() as *const c_char,
        digits - 1,
        x,
    );

    let result = m4_ecvt_result_ptr();
    *sign = (tmp[0] == b'-' as c_char) as c_int;
    let mut i = *sign as usize;
    let mut j = 0usize;
    while tmp[i] != b'e' as c_char {
        if tmp[i] != b'.' as c_char {
            *result.add(j) = tmp[i];
            j += 1;
        }
        i += 1;
    }
    *result.add(j) = 0;
    *decpt = atoi(tmp.as_ptr().add(i + 1)) + 1;
    result
}

#[no_mangle]
pub unsafe extern "C" fn fcvt(
    x: f64,
    n: c_int,
    decpt: *mut c_int,
    sign: *mut c_int,
) -> *mut c_char {
    // Match musl's unsigned comparison: negative ndigit values are treated
    // as out of range and therefore use the 1400-digit cap.
    let mut digits = n;
    if (digits as c_uint) > 1400 {
        digits = 1400;
    }

    if !x.is_finite() {
        return m4_ecvt_special(x, decpt, sign);
    }

    // fcvt only needs this temporary to discover the decimal-point position.
    // The existing formatter's internal fractional work area is bounded, so
    // format the significant prefix safely and append the exact trailing
    // zeros that a binary64 value has beyond that precision.
    let format_digits = digits.min(1098);
    let mut tmp = [0 as c_char; 2048];
    sprintf(
        tmp.as_mut_ptr(),
        b"%.*f\0".as_ptr() as *const c_char,
        format_digits,
        x,
    );
    if format_digits < digits {
        let mut end = 0usize;
        while tmp[end] != 0 {
            end += 1;
        }
        for _ in format_digits..digits {
            *tmp.as_mut_ptr().add(end) = b'0' as c_char;
            end += 1;
        }
        *tmp.as_mut_ptr().add(end) = 0;
    }

    let i = (tmp[0] == b'-' as c_char) as c_int;
    let lz = if tmp[i as usize] == b'0' as c_char {
        strspn(
            tmp.as_ptr().add(i as usize + 2) as *const u8,
            b"0\0".as_ptr(),
        ) as c_int
    } else {
        -(strcspn(
            tmp.as_ptr().add(i as usize) as *const u8,
            b".\0".as_ptr(),
        ) as c_int)
    };

    if digits <= lz {
        *sign = i;
        *decpt = 1;
        let mut zero_digits = digits;
        if zero_digits > 14 {
            zero_digits = 14;
        }
        return b"000000000000000\0".as_ptr().add((14 - zero_digits) as usize)
            as *mut c_char;
    }

    ecvt(x, digits - lz, decpt, sign)
}

unsafe fn m4_gcvt_large(x: f64, n: c_int, buf: *mut c_char) -> *mut c_char {
    // The shared printf formatter has a compact fixed work area for its
    // scientific path. For larger gcvt precisions, obtain the same rounded
    // decimal digits through its bounded fixed-point path and then lay them
    // out as %g. Binary64 has at most 1074 meaningful decimal places, so the
    // 1200-digit internal bound is sufficient after trailing-zero removal.
    let precision = n as usize;
    let precision = precision.min(1200);
    let negative = x.is_sign_negative();
    let value = if negative { -x } else { x };
    let exponent = compute_exp10(value);
    let wanted_fraction = precision as i32 - exponent - 1;
    let fixed_precision = if wanted_fraction > 0 {
        (wanted_fraction as usize).min(1098)
    } else {
        0
    };

    let mut tmp = [0 as c_char; 2048];
    sprintf(
        tmp.as_mut_ptr(),
        b"%.*f\0".as_ptr() as *const c_char,
        fixed_precision as c_int,
        x,
    );
    if wanted_fraction > fixed_precision as i32 {
        let mut end = 0usize;
        while tmp[end] != 0 {
            end += 1;
        }
        for _ in fixed_precision..wanted_fraction as usize {
            *tmp.as_mut_ptr().add(end) = b'0' as c_char;
            end += 1;
        }
        *tmp.as_mut_ptr().add(end) = 0;
    }

    let mut digits = [0u8; 2048];
    let mut ndigits = 0usize;
    let mut integer_digits = 0usize;
    let mut after_point = false;
    let mut i = if tmp[0] == b'-' as c_char { 1 } else { 0 };
    while tmp[i] != 0 {
        let c = tmp[i];
        if c == b'.' as c_char {
            after_point = true;
        } else {
            digits[ndigits] = (c - b'0' as c_char) as u8;
            ndigits += 1;
            if !after_point {
                integer_digits += 1;
            }
        }
        i += 1;
    }

    let mut first = 0usize;
    while first < ndigits && digits[first] == 0 {
        first += 1;
    }
    let use_fixed = exponent >= -4 && exponent < precision as i32;
    let mut out = 0usize;
    if negative {
        *buf.add(out) = b'-' as c_char;
        out += 1;
    }

    if use_fixed {
        let mut end = ndigits;
        while end > integer_digits && digits[end - 1] == 0 {
            end -= 1;
        }
        for j in 0..end {
            if j == integer_digits && end > integer_digits {
                *buf.add(out) = b'.' as c_char;
                out += 1;
            }
            *buf.add(out) = (b'0' + digits[j]) as c_char;
            out += 1;
        }
    } else {
        let mut exp = exponent;
        let mut keep = precision.min(ndigits.saturating_sub(first));
        if keep == 0 {
            keep = 1;
        }

        // When the requested significant digits lie entirely left of the
        // radix, %f with precision zero retained the complete integer. Round
        // that integer to the requested significant count before emitting %e.
        if wanted_fraction <= 0 && first + keep < ndigits {
            let next = digits[first + keep];
            let mut rest = false;
            for j in first + keep + 1..ndigits {
                if digits[j] != 0 {
                    rest = true;
                    break;
                }
            }
            let last = digits[first + keep - 1];
            if next > 5 || (next == 5 && (rest || last & 1 != 0)) {
                let mut j = first + keep;
                let mut carry = true;
                while j > first {
                    j -= 1;
                    if digits[j] < 9 {
                        digits[j] += 1;
                        carry = false;
                        break;
                    }
                    digits[j] = 0;
                }
                if carry {
                    digits[first] = 1;
                    for j in first + 1..first + keep {
                        digits[j] = 0;
                    }
                    exp += 1;
                }
            }
        }

        let mut end = first + keep;
        while end > first + 1 && digits[end - 1] == 0 {
            end -= 1;
        }
        *buf.add(out) = (b'0' + digits[first]) as c_char;
        out += 1;
        if end > first + 1 {
            *buf.add(out) = b'.' as c_char;
            out += 1;
            for j in first + 1..end {
                *buf.add(out) = (b'0' + digits[j]) as c_char;
                out += 1;
            }
        }
        *buf.add(out) = b'e' as c_char;
        out += 1;
        *buf.add(out) = (if exp < 0 { b'-' } else { b'+' }) as c_char;
        out += 1;
        let mut magnitude = if exp < 0 { (-exp) as u32 } else { exp as u32 };
        let mut exponent_digits = [0u8; 10];
        let mut exponent_len = 0usize;
        loop {
            exponent_digits[exponent_len] = (magnitude % 10) as u8;
            exponent_len += 1;
            magnitude /= 10;
            if magnitude == 0 {
                break;
            }
        }
        if exponent_len < 2 {
            *buf.add(out) = b'0' as c_char;
            out += 1;
        }
        while exponent_len > 0 {
            exponent_len -= 1;
            *buf.add(out) = (b'0' + exponent_digits[exponent_len]) as c_char;
            out += 1;
        }
    }
    *buf.add(out) = 0;
    buf
}

#[no_mangle]
pub unsafe extern "C" fn gcvt(x: f64, n: c_int, buf: *mut c_char) -> *mut c_char {
    if !x.is_finite() {
        let negative = x.is_sign_negative();
        let word = if x.is_nan() { b"nan\0" } else { b"inf\0" };
        let mut i = 0usize;
        if negative {
            *buf = b'-' as c_char;
            i = 1;
        }
        for c in word.iter() {
            *buf.add(i) = *c as c_char;
            i += 1;
        }
        return buf;
    }

    // Keep musl's negative/zero precision behavior in sprintf, and use the
    // direct source-level wrapper for the formatter's normal precision range.
    if n <= 18 {
        sprintf(
            buf,
            b"%.*g\0".as_ptr() as *const c_char,
            n,
            x,
        );
        return buf;
    }
    if x == 0.0 {
        if x.is_sign_negative() {
            *buf = b'-' as c_char;
            *buf.add(1) = b'0' as c_char;
            *buf.add(2) = 0;
        } else {
            *buf = b'0' as c_char;
            *buf.add(1) = 0;
        }
        return buf;
    }
    m4_gcvt_large(x, n, buf)
}
