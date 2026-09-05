// Shared hardened `WRDE_NOCMD` scanner.
//
// The AArch64 wordexp implementation originally owned this parser beside its
// raw child protocol.  The x86 owned-static adapter uses a different child
// and FILE lifecycle, but must preserve these established quote, parameter,
// arithmetic, comment, and adversarial-substitution decisions.  Keep this
// lexical boundary shared while each target retains its own process/runtime
// integration.  Inclusion sites provide `c_char`, `c_int`, and the WRDE
// result constants.

unsafe fn wordexp_nocmd_check(s: *const c_char) -> c_int {
    let mut i = 0usize;
    let mut sq = false;
    let mut dq = false;
    let mut aq = false;
    let mut np = 0usize;
    let mut nb = 0usize;
    let mut param_dq = false;
    let mut param_np = 0usize;
    let mut saw_arithmetic = false;

    while *s.add(i) != 0 {
        match *s.add(i) as u8 {
            b'#' if !sq && !dq && !aq && nb == 0 && (i == 0 || (*s.add(i - 1) as u8).is_ascii_whitespace()) => {
                while *s.add(i) != 0 && *s.add(i) != b'\n' as c_char { i += 1; }
                continue;
            }
            b'\\' => {
                if !sq || aq {
                    i += 1;
                    if *s.add(i) == 0 { return WRDE_SYNTAX; }
                }
            }
            b'\'' => {
                if !dq || nb > 1 {
                    if aq { aq = false; }
                    else { sq = !sq; }
                }
            }
            b'"' => {
                if !sq && !aq { dq = !dq; }
            }
            b'(' => {
                if nb == 0 {
                    if np != 0 { np += 1; }
                    else if !sq && !dq && !aq { return WRDE_BADCHAR; }
                }
            }
            b')' => {
                if nb != 0 {
                    if param_np != 0 {
                        np -= 1;
                        param_np -= 1;
                    }
                } else {
                    if np != 0 {
                        np -= 1;
                        if np == 0 && saw_arithmetic && i != 0 &&
                            (*s.add(i - 1) as u8).is_ascii_whitespace()
                        {
                            return WRDE_CMDSUB;
                        }
                    }
                    else if !sq && !dq && !aq {
                        if saw_arithmetic { return WRDE_SYNTAX; }
                        return WRDE_BADCHAR;
                    }
                }
            }
            b'{' => {
                if np == 0 && !sq && !dq && !aq && nb == 0 { return WRDE_BADCHAR; }
            }
            b'}' => {
                if !sq && !aq {
                    if nb != 0 {
                        nb -= 1;
                        if nb == 0 { param_dq = false; }
                    } else if np == 0 && !dq { return WRDE_BADCHAR; }
                }
            }
            b'\n' | b'|' | b'&' | b';' | b'<' | b'>' => {
                if !sq && !dq && !aq && np == 0 {
                    if saw_arithmetic { return WRDE_SYNTAX; }
                    return WRDE_BADCHAR;
                }
            }
            b'$' if !sq && !aq => {
                if *s.add(i + 1) == b'\'' as c_char {
                    if np == 0 {
                        if nb != 0 {
                            if dq && param_dq { return WRDE_SYNTAX; }
                            if dq { i += 1; }
                            else { return WRDE_SYNTAX; }
                        } else if dq { i += 1; }
                        else { aq = true; i += 1; }
                    }
                } else if *s.add(i + 1) == b'{' as c_char {
                    if nb == 0 { param_dq = dq; }
                    nb += 1;
                    i += 1;
                } else if *s.add(i + 1) == b'(' as c_char && *s.add(i + 2) == b'(' as c_char {
                    // Shell syntax that looks arithmetic can contain a
                    // command substitution (for example `case ...`).
                    // Let the caller reject the entire construct rather
                    // than accepting it as a safe arithmetic expression.
                    let mut j = i + 3;
                    while *s.add(j) != 0 {
                        if *s.add(j) == b';' as c_char ||
                            (*s.add(j) == b'c' as c_char &&
                                *s.add(j + 1) == b'a' as c_char &&
                                *s.add(j + 2) == b's' as c_char &&
                                *s.add(j + 3) == b'e' as c_char)
                        {
                            return WRDE_CMDSUB;
                        }
                        if *s.add(j) == b'<' as c_char &&
                            *s.add(j + 1) == b'<' as c_char
                        {
                            return WRDE_CMDSUB;
                        }
                        if *s.add(j) == b')' as c_char { break; }
                        j += 1;
                    }
                    i += 2;
                    np += 2;
                    if nb != 0 { param_np += 2; }
                    saw_arithmetic = true;
                } else if *s.add(i + 1) == b'(' as c_char {
                    if nb != 0 && dq && param_dq { return WRDE_SYNTAX; }
                    return WRDE_CMDSUB;
                }
            }
            b'`' if !sq && !aq => return WRDE_CMDSUB,
            _ => {}
        }
        i += 1;
    }
    if sq || dq || aq || np != 0 || nb != 0 { return WRDE_SYNTAX; }
    0
}
