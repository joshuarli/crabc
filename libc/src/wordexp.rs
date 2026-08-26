// wordexp.h: shell-style word expansion.
//
// musl deliberately delegates the expansion grammar to /bin/sh. The child
// prints NUL-delimited words so whitespace and newlines in an expanded word
// remain distinguishable. The bounded WRDE_NOCMD scanner rejects command
// substitutions before starting a child while tracking the nested quoting and
// parameter/arithmetic grammar needed to distinguish literal `$(` text.

const WRDE_DOOFFS: c_int = 1;
const WRDE_APPEND: c_int = 2;
const WRDE_NOCMD: c_int = 4;
const WRDE_REUSE: c_int = 8;
const WRDE_SHOWERR: c_int = 16;
const WRDE_UNDEF: c_int = 32;

const WRDE_NOSPACE: c_int = 1;
const WRDE_BADCHAR: c_int = 2;
const WRDE_BADVAL: c_int = 3;
const WRDE_CMDSUB: c_int = 4;
const WRDE_SYNTAX: c_int = 5;

#[repr(C)]
pub struct wordexp_t {
    pub we_wordc: usize,
    pub we_wordv: *mut *mut c_char,
    pub we_offs: usize,
}

// The shell receives the input as $1. Save it and clear the shell's
// positional parameters before `eval`: otherwise an input such as `$1`
// expands to the argument used to carry the input, rather than the empty
// positional parameter required by wordexp. The first output word is a
// sentinel, allowing an empty expansion to be distinguished from a syntax
// error (which produces no output).
const WORDEXP_SCRIPT: &[u8] = b"input=$1; shift; eval \"set -- $input\" || exit $?; printf %s\\\\0 x \"$@\"\0";
const WORDEXP_UNDEF_SCRIPT: &[u8] = b"set -u; input=$1; shift; /bin/sh -n -c \"set -- $input\" || exit 125; eval \"set -- $input\" || exit $?; printf %s\\\\0 x \"$@\"\0";
const SH: &[u8] = b"/bin/sh\0";
const SH_ARG0: &[u8] = b"sh\0";
const SH_C: &[u8] = b"-c\0";
const WORDEXP_DEV_NULL: &[u8] = b"/dev/null\0";
const WORDEXP_SYNTAX_EXIT: c_int = 125;

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

unsafe fn wordexp_reap(pid: c_int) -> c_int {
    let mut status = 0;
    loop {
        let r = sys_wait4(pid, &mut status, 0, core::ptr::null_mut());
        if r >= 0 { return status; }
        if r != -(EINTR as i64) { return -1; }
    }
}

unsafe fn wordexp_free_words(wv: *mut *mut c_char, wc: usize, offs: usize) {
    if wv.is_null() { return; }
    for i in 0..wc {
        let word = *wv.add(offs + i);
        if !word.is_null() { free(word as *mut c_void); }
    }
    free(wv as *mut c_void);
}

unsafe fn wordexp_do(s: *const c_char, we: *mut wordexp_t, flags: c_int) -> c_int {
    if s.is_null() || we.is_null() { return WRDE_BADCHAR; }

    if flags & WRDE_REUSE != 0 { wordfree(we); }
    if flags & WRDE_NOCMD != 0 {
        let check = wordexp_nocmd_check(s);
        if check != 0 { return check; }
    }

    let mut wc = 0usize;
    let mut wv: *mut *mut c_char = core::ptr::null_mut();
    if flags & WRDE_APPEND != 0 {
        wc = (*we).we_wordc;
        wv = (*we).we_wordv;
    }
    let offs = if flags & WRDE_DOOFFS != 0 {
        (*we).we_offs
    } else {
        (*we).we_offs = 0;
        0
    };
    let mut index = match wc.checked_add(offs) {
        Some(value) => value,
        None => return WRDE_NOSPACE,
    };

    let mut fds = [0 as c_int; 2];
    let pipe_result = sys_pipe2(fds.as_mut_ptr(), O_CLOEXEC);
    if pipe_result < 0 {
        if flags & WRDE_APPEND == 0 {
            (*we).we_wordc = 0;
            (*we).we_wordv = core::ptr::null_mut();
        }
        ERRNO = (-pipe_result) as c_int;
        return WRDE_NOSPACE;
    }

    let pid = sys_fork(false);
    if pid < 0 {
        sys_close(fds[0] as i64);
        sys_close(fds[1] as i64);
        if flags & WRDE_APPEND == 0 {
            (*we).we_wordc = 0;
            (*we).we_wordv = core::ptr::null_mut();
        }
        ERRNO = (-pid) as c_int;
        return WRDE_NOSPACE;
    }
    if pid == 0 {
        if fds[1] != 1 {
            sys_dup2(fds[1], 1);
            sys_close(fds[1] as i64);
        }
        sys_close(fds[0] as i64);
        if flags & WRDE_SHOWERR == 0 {
            let null_fd = sys_open(WORDEXP_DEV_NULL.as_ptr(), O_WRONLY as i64, 0);
            if null_fd >= 0 && null_fd != 2 {
                sys_dup2(null_fd as c_int, 2);
                sys_close(null_fd);
            }
        }
        let script = if flags & WRDE_UNDEF != 0 {
            WORDEXP_UNDEF_SCRIPT
        } else {
            WORDEXP_SCRIPT
        };
        let argv = [
            SH_ARG0.as_ptr() as *const c_char,
            SH_C.as_ptr() as *const c_char,
            script.as_ptr() as *const c_char,
            SH_ARG0.as_ptr() as *const c_char,
            s,
            core::ptr::null(),
        ];
        sys_execve(SH.as_ptr() as *const c_char, argv.as_ptr(), __environ as *const *const c_char);
        _exit(1);
    }

    sys_close(fds[1] as i64);
    // Read one byte at a time: wordexp output is NUL-delimited and words may
    // contain arbitrary whitespace. The functional workload is small, while
    // this keeps the parser bounded and independent of stdio buffering.
    let mut cap = if wv.is_null() { 0 } else { index.saturating_add(1) };
    let mut first_word = true;
    let mut word: *mut c_char = core::ptr::null_mut();
    let mut word_len = 0usize;
    let mut word_cap = 0usize;
    let mut read_error = false;
    let mut byte = 0u8;

    loop {
        let n = sys_read(fds[0] as i64, &mut byte, 1);
        if n == 0 { break; }
        if n < 0 { read_error = true; break; }
        if byte == 0 {
            if first_word {
                if !word.is_null() { free(word as *mut c_void); }
                word = core::ptr::null_mut();
                word_len = 0;
                word_cap = 0;
                first_word = false;
                continue;
            }
            if word.is_null() {
                word = malloc(1) as *mut c_char;
                if word.is_null() { read_error = true; break; }
                *word = 0;
            } else {
                *word.add(word_len) = 0;
            }
            if index.checked_add(1).is_none() { read_error = true; break; }
            if wv.is_null() || index + 1 >= cap {
                let new_cap = match cap.checked_add(cap / 2 + 10) {
                    Some(value) => value.max(index + 2),
                    None => { read_error = true; break; }
                };
                let new_wv = realloc(wv as *mut c_void, new_cap * core::mem::size_of::<*mut c_char>()) as *mut *mut c_char;
                if new_wv.is_null() { read_error = true; break; }
                wv = new_wv;
                cap = new_cap;
            }
            *wv.add(index) = word;
            index += 1;
            *wv.add(index) = core::ptr::null_mut();
            word = core::ptr::null_mut();
            word_len = 0;
            word_cap = 0;
        } else {
            if word_len.checked_add(2).is_none() { read_error = true; break; }
            if word.is_null() || word_len + 1 >= word_cap {
                let new_cap = if word_cap == 0 { 64 } else { word_cap.saturating_mul(2) };
                let new_word = realloc(word as *mut c_void, new_cap) as *mut c_char;
                if new_word.is_null() { read_error = true; break; }
                word = new_word;
                word_cap = new_cap;
            }
            *word.add(word_len) = byte as c_char;
            word_len += 1;
        }
    }
    sys_close(fds[0] as i64);
    if !word.is_null() { free(word as *mut c_void); }
    let child_status = wordexp_reap(pid as c_int);

    if first_word {
        if !wv.is_null() && flags & WRDE_APPEND == 0 {
            wordexp_free_words(wv, wc, offs);
        }
        if flags & WRDE_APPEND == 0 {
            (*we).we_wordc = 0;
            (*we).we_wordv = core::ptr::null_mut();
        }
        if read_error { return WRDE_NOSPACE; }
        // `set -u` rejects an otherwise valid expansion before the sentinel
        // is emitted. The syntax-only shell pass uses a private exit status
        // so parse failures remain WRDE_SYNTAX instead of being mistaken for
        // WRDE_BADVAL.
        if flags & WRDE_UNDEF != 0 &&
            ((child_status >> 8) & 0xff) != WORDEXP_SYNTAX_EXIT
        {
            return WRDE_BADVAL;
        }
        return WRDE_SYNTAX;
    }
    if read_error {
        if flags & WRDE_APPEND == 0 {
            wordexp_free_words(wv, wc, offs);
            (*we).we_wordc = 0;
            (*we).we_wordv = core::ptr::null_mut();
        }
        return WRDE_NOSPACE;
    }

    if wv.is_null() {
        wv = calloc(1, core::mem::size_of::<*mut c_char>()) as *mut *mut c_char;
        if wv.is_null() {
            if flags & WRDE_APPEND == 0 {
                (*we).we_wordc = 0;
                (*we).we_wordv = core::ptr::null_mut();
            }
            return WRDE_NOSPACE;
        }
    }
    if flags & WRDE_DOOFFS != 0 {
        for i in (1..=offs).rev() {
            if i <= index { *wv.add(i - 1) = core::ptr::null_mut(); }
        }
    }
    (*we).we_wordv = wv;
    (*we).we_wordc = index - offs;
    0
}

#[no_mangle]
pub unsafe extern "C" fn wordexp(s: *const c_char, we: *mut wordexp_t, flags: c_int) -> c_int {
    wordexp_do(s, we, flags)
}

#[no_mangle]
pub unsafe extern "C" fn wordfree(we: *mut wordexp_t) {
    if we.is_null() || (*we).we_wordv.is_null() { return; }
    wordexp_free_words((*we).we_wordv, (*we).we_wordc, (*we).we_offs);
    (*we).we_wordv = core::ptr::null_mut();
    (*we).we_wordc = 0;
}
