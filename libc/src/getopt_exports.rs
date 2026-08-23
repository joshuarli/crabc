// getopt state and program-name exports.
//
// These globals are an ABI contract as well as parser state: applications
// commonly reset `optind` between independent parses and GNU-facing code uses
// the program-invocation spellings in diagnostics.  `getopt` observes both
// reset spellings, so code written against either musl declaration resets the
// parser state.

#[no_mangle]
pub static mut optarg: *mut c_char = core::ptr::null_mut();
#[no_mangle]
pub static mut optind: c_int = 1;
#[no_mangle]
pub static mut opterr: c_int = 1;
#[no_mangle]
pub static mut optopt: c_int = 0;
#[no_mangle]
pub static mut __optpos: c_int = 0;
#[no_mangle]
pub static mut __optreset: c_int = 0;
#[no_mangle]
#[linkage = "weak"]
pub static mut optreset: c_int = 0;

#[no_mangle]
pub static mut __progname: *mut c_char = core::ptr::null_mut();
#[no_mangle]
pub static mut __progname_full: *mut c_char = core::ptr::null_mut();
#[no_mangle]
#[linkage = "weak"]
pub static mut program_invocation_name: *mut c_char = core::ptr::null_mut();
#[no_mangle]
#[linkage = "weak"]
pub static mut program_invocation_short_name: *mut c_char = core::ptr::null_mut();

unsafe fn cabi_getopt_message(argv0: *const c_char, prefix: *const u8, option: *const c_char, len: usize) {
    if argv0.is_null() || stderr.is_null() {
        return;
    }
    let _ = fputs(argv0, stderr);
    let _ = fputs(prefix as *const c_char, stderr);
    let _ = fwrite(option as *const c_void, 1, len, stderr);
    let _ = fputc(b'\n' as c_int, stderr);
}

#[inline]
unsafe fn cabi_getopt_codepoint(argument: *const c_char, position: c_int) -> (c_int, c_int) {
    let mut codepoint = 0;
    let mut width = mbtowc(&mut codepoint, argument.add(position as usize), 4);
    if width < 0 {
        // Musl advances over one ill-formed byte and reports U+FFFD, rather
        // than becoming stuck on an invalid command-line argument.
        width = 1;
        codepoint = 0xfffd;
    }
    (codepoint, width)
}

#[no_mangle]
pub unsafe extern "C" fn getopt(
    argc: c_int,
    argv: *const *mut c_char,
    optstring: *const c_char,
) -> c_int {
    if argv.is_null() || optstring.is_null() {
        ERRNO = EINVAL;
        return -1;
    }

    if optind == 0 || __optreset != 0 || optreset != 0 {
        __optreset = 0;
        optreset = 0;
        __optpos = 0;
        optind = 1;
    }
    if optind >= argc || (*argv.add(optind as usize)).is_null() {
        return -1;
    }

    let current = *argv.add(optind as usize);
    if *current as u8 != b'-' {
        if *optstring as u8 == b'-' {
            optarg = current;
            optind += 1;
            return 1;
        }
        return -1;
    }
    if *current.add(1) == 0 {
        return -1;
    }
    if *current.add(1) as u8 == b'-' && *current.add(2) == 0 {
        optind += 1;
        return -1;
    }

    if __optpos == 0 {
        __optpos = 1;
    }
    let option_ptr = current.add(__optpos as usize);
    let (option, width) = cabi_getopt_codepoint(current, __optpos);
    __optpos += width;
    if *current.add(__optpos as usize) == 0 {
        optind += 1;
        __optpos = 0;
    }

    let mut options = optstring;
    if *options as u8 == b'-' || *options as u8 == b'+' {
        options = options.add(1);
    }

    let mut offset = 0usize;
    let mut matched = false;
    loop {
        let mut candidate = 0;
        let bytes = mbtowc(&mut candidate, options.add(offset), 4);
        if bytes <= 0 {
            break;
        }
        offset += bytes as usize;
        if candidate == option {
            matched = candidate != b':' as c_int;
            break;
        }
    }

    if !matched {
        optopt = option;
        if *optstring as u8 != b':' && opterr != 0 {
            cabi_getopt_message(
                *argv,
                b": unrecognized option: \0".as_ptr(),
                option_ptr,
                width as usize,
            );
        }
        return b'?' as c_int;
    }

    if *options.add(offset) as u8 == b':' {
        optarg = core::ptr::null_mut();
        if *options.add(offset + 1) as u8 != b':' || __optpos != 0 {
            // Consume the argument slot in both forms. For a clustered
            // argument this is the current argv element; for a separate
            // argument it is the next element after the option word.
            optarg = *argv.add(optind as usize);
            optind += 1;
            if __optpos != 0 {
                optarg = current.add(__optpos as usize);
            }
            __optpos = 0;
        }
        if optind > argc {
            optopt = option;
            if *optstring as u8 == b':' {
                return b':' as c_int;
            }
            if opterr != 0 {
                cabi_getopt_message(
                    *argv,
                    b": option requires an argument: \0".as_ptr(),
                    option_ptr,
                    width as usize,
                );
            }
            return b'?' as c_int;
        }
    }
    option
}

// `getopt_long` shares the parser state above, including GNU's permutation of
// non-options. Keep this ABI layout in lockstep with include/getopt.h: the
// pointers are native C pointers and the struct is passed by reference only.
#[repr(C)]
pub struct CabiGetoptOption {
    pub name: *const c_char,
    pub has_arg: c_int,
    pub flag: *mut c_int,
    pub val: c_int,
}

const CABI_GETOPT_NO_ARGUMENT: c_int = 0;
const CABI_GETOPT_REQUIRED_ARGUMENT: c_int = 1;

#[inline]
unsafe fn cabi_getopt_long_colon(optstring: *const c_char) -> bool {
    let first = *optstring as u8;
    let options = if first == b'+' || first == b'-' {
        optstring.add(1)
    } else {
        optstring
    };
    *options as u8 == b':'
}

unsafe fn cabi_getopt_long_permute(
    argv: *const *mut c_char,
    dest: c_int,
    src: c_int,
) {
    // The C API promises a mutable argv array even though the parameter is
    // conventionally written as `char *const *`.
    let av = argv as *mut *mut c_char;
    let tmp = *av.add(src as usize);
    let mut i = src;
    while i > dest {
        *av.add(i as usize) = *av.add((i - 1) as usize);
        i -= 1;
    }
    *av.add(dest as usize) = tmp;
}

unsafe fn cabi_getopt_long_core(
    argc: c_int,
    argv: *const *mut c_char,
    optstring: *const c_char,
    longopts: *const CabiGetoptOption,
    idx: *mut c_int,
    longonly: bool,
) -> c_int {
    // Unlike short-option parsing, a long option parse always starts with a
    // clear optarg. This is observable for optional arguments without `=`.
    optarg = core::ptr::null_mut();

    let current = *argv.add(optind as usize);
    if !current.is_null()
        && !longopts.is_null()
        && *current as u8 == b'-'
        && ((longonly && *current.add(1) != 0 && *current.add(1) as u8 != b'-')
            || (*current.add(1) as u8 == b'-' && *current.add(2) != 0))
    {
        let colon = cabi_getopt_long_colon(optstring);
        let mut count = 0;
        let mut match_index = 0;
        let mut match_arg = current.add(1);
        let start = current.add(1);
        let mut i = 0;

        while !(*longopts.add(i as usize)).name.is_null() {
            let name = (*longopts.add(i as usize)).name;
            let mut option = start;
            if *option as u8 == b'-' {
                option = option.add(1);
            }
            let mut name_cursor = name;
            while *option != 0
                && *option as u8 != b'='
                && *option == *name_cursor
            {
                option = option.add(1);
                name_cursor = name_cursor.add(1);
            }
            if *option != 0 && *option as u8 != b'=' {
                i += 1;
                continue;
            }
            match_arg = option;
            match_index = i;
            if *name_cursor == 0 {
                count = 1;
                break;
            }
            count += 1;
            i += 1;
        }

        // In long-only mode, a one-character long-name match must yield to a
        // short option with the same spelling. This is the subtle distinction
        // between `-v` and `-verbose` in GNU/musl parsing.
        if count == 1 && longonly {
            let prefix_len = match_arg.offset_from(start);
            let first_width = mblen(start, 4);
            if first_width >= 0 && prefix_len == first_width as isize {
                let mut short_index = 0usize;
                while *optstring.add(short_index) != 0 {
                    let mut j = 0;
                    while j < prefix_len
                        && *start.add(j as usize)
                            == *optstring.add(short_index + j as usize)
                    {
                        j += 1;
                    }
                    if j == prefix_len {
                        count += 1;
                        break;
                    }
                    short_index += 1;
                }
            }
        }

        if count == 1 {
            let option = &*longopts.add(match_index as usize);
            let argument = match_arg;
            optind += 1;

            if *argument as u8 == b'=' {
                if option.has_arg == CABI_GETOPT_NO_ARGUMENT {
                    optopt = option.val;
                    if colon || opterr == 0 {
                        return b'?' as c_int;
                    }
                    cabi_getopt_message(
                        *argv,
                        b": option does not take an argument: \0".as_ptr(),
                        option.name,
                        strlen(option.name),
                    );
                    return b'?' as c_int;
                }
                optarg = argument.add(1) as *mut c_char;
            } else if option.has_arg == CABI_GETOPT_REQUIRED_ARGUMENT {
                let next = if optind < argc {
                    *argv.add(optind as usize)
                } else {
                    core::ptr::null_mut()
                };
                if next.is_null() {
                    optopt = option.val;
                    if colon {
                        return b':' as c_int;
                    }
                    if opterr == 0 {
                        return b'?' as c_int;
                    }
                    cabi_getopt_message(
                        *argv,
                        b": option requires an argument: \0".as_ptr(),
                        option.name,
                        strlen(option.name),
                    );
                    return b'?' as c_int;
                }
                optarg = next;
                optind += 1;
            }

            if !idx.is_null() {
                *idx = match_index;
            }
            if !option.flag.is_null() {
                *option.flag = option.val;
                return 0;
            }
            return option.val;
        }

        // A double-dash word was intended as a long option. Do not fall back
        // to short parsing: musl reports either ambiguity or an unknown long
        // option and advances past that argv element.
        if *current.add(1) as u8 == b'-' {
            optopt = 0;
            if !colon && opterr != 0 {
                let prefix = if count != 0 {
                    b": option is ambiguous: \0".as_ptr()
                } else {
                    b": unrecognized option: \0".as_ptr()
                };
                let option_name = current.add(2);
                cabi_getopt_message(*argv, prefix, option_name, strlen(option_name));
            }
            optind += 1;
            return b'?' as c_int;
        }
    }

    getopt(argc, argv, optstring)
}

unsafe fn cabi_getopt_long_impl(
    argc: c_int,
    argv: *const *mut c_char,
    optstring: *const c_char,
    longopts: *const CabiGetoptOption,
    idx: *mut c_int,
    longonly: bool,
) -> c_int {
    if argv.is_null() || optstring.is_null() {
        ERRNO = EINVAL;
        return -1;
    }
    if optind == 0 || __optreset != 0 || optreset != 0 {
        __optreset = 0;
        optreset = 0;
        __optpos = 0;
        optind = 1;
    }
    if optind >= argc || (*argv.add(optind as usize)).is_null() {
        return -1;
    }

    let skipped = optind;
    if *optstring as u8 != b'+' && *optstring as u8 != b'-' {
        let mut i = optind;
        loop {
            if i >= argc || (*argv.add(i as usize)).is_null() {
                return -1;
            }
            let argument = *argv.add(i as usize);
            if *argument as u8 == b'-' && *argument.add(1) != 0 {
                optind = i;
                break;
            }
            i += 1;
        }
    }
    let resumed = optind;
    let result = cabi_getopt_long_core(argc, argv, optstring, longopts, idx, longonly);
    if resumed > skipped {
        let count = optind - resumed;
        let mut i = 0;
        while i < count {
            cabi_getopt_long_permute(argv, skipped, optind - 1);
            i += 1;
        }
        optind = skipped + count;
    }
    result
}

#[no_mangle]
pub unsafe extern "C" fn getopt_long(
    argc: c_int,
    argv: *const *mut c_char,
    optstring: *const c_char,
    longopts: *const CabiGetoptOption,
    idx: *mut c_int,
) -> c_int {
    cabi_getopt_long_impl(argc, argv, optstring, longopts, idx, false)
}

#[no_mangle]
pub unsafe extern "C" fn getopt_long_only(
    argc: c_int,
    argv: *const *mut c_char,
    optstring: *const c_char,
    longopts: *const CabiGetoptOption,
    idx: *mut c_int,
) -> c_int {
    cabi_getopt_long_impl(argc, argv, optstring, longopts, idx, true)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn __posix_getopt(
    argc: c_int,
    argv: *const *mut c_char,
    optstring: *const c_char,
) -> c_int {
    getopt(argc, argv, optstring)
}

pub unsafe fn cabi_set_program_names(argv0: *const c_char) {
    if argv0.is_null() {
        return;
    }
    let mut short = argv0;
    let mut cursor = argv0;
    while *cursor != 0 {
        if *cursor as u8 == b'/' {
            short = cursor.add(1);
        }
        cursor = cursor.add(1);
    }
    __progname_full = argv0 as *mut c_char;
    __progname = short as *mut c_char;
    program_invocation_name = argv0 as *mut c_char;
    program_invocation_short_name = short as *mut c_char;
}
