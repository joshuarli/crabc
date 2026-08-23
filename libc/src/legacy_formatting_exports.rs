// legacy formatting interfaces.
//
// fmtmsg follows musl's POSIX/XSI implementation, including MSGVERB's
// component selection and the separate console and fd 2 output routes.
// strfmon follows musl's 1.2.6 formatter literally.  The parser accepts the
// monetary conversion flags, but the current libc only has C/POSIX monetary
// data, so those flags do not add a currency symbol, grouping, or signs.

const CABI_MM_PRINT: c_int = 256;
const CABI_MM_CONSOLE: c_int = 512;
const CABI_MM_NOTOK: c_int = -1;
const CABI_MM_NOMSG: c_int = 1;
const CABI_MM_NOCON: c_int = 4;

const CABI_MM_HALT: c_int = 1;
const CABI_MM_ERROR: c_int = 2;
const CABI_MM_WARNING: c_int = 3;
const CABI_MM_INFO: c_int = 4;

unsafe fn cabi_fmtmsg_component_mismatch(
    wanted: *const u8,
    actual: *const u8,
) -> bool {
    let mut i = 0usize;
    while *wanted.add(i) != 0 && *actual.add(i) != 0 && *actual.add(i) == *wanted.add(i) {
        i += 1;
    }
    *wanted.add(i) != 0 || (*actual.add(i) != 0 && *actual.add(i) != b':')
}

unsafe fn cabi_fmtmsg_verb_mask() -> c_int {
    static COMPONENTS: [&[u8]; 5] = [
        b"label\0",
        b"severity\0",
        b"text\0",
        b"action\0",
        b"tag\0",
    ];

    let mut verb = 0;
    let mut current = getenv(b"MSGVERB\0".as_ptr() as *const c_char);
    while !current.is_null() && *current != 0 {
        let mut component = 0usize;
        while component < COMPONENTS.len()
            && cabi_fmtmsg_component_mismatch(
                COMPONENTS[component].as_ptr(),
                current as *const u8,
            )
        {
            component += 1;
        }
        if component == COMPONENTS.len() {
            // musl treats an unrecognized component as a request for all
            // components, rather than discarding the complete message.
            return 0xff;
        }
        verb |= 1 << component;
        let colon = strchr(current as *const u8, b':' as c_int);
        current = if colon.is_null() {
            null_mut()
        } else {
            colon.add(1) as *mut c_char
        };
    }
    if verb == 0 { 0xff } else { verb }
}

// Keep fmtmsg's failure result meaningful even though the existing dprintf
// implementation is intentionally a count-only formatter.  POSIX requires
// MM_NOMSG/MM_NOCON to reflect a failed write, so this small piece writer
// retries short writes and reports the first write error to the caller.
unsafe fn cabi_fmtmsg_write(
    fd: c_int,
    pieces: [*const c_char; 9],
) -> c_int {
    for piece in pieces {
        let length = strlen(piece);
        let mut offset = 0usize;
        while offset < length {
            let written = write(
                fd,
                piece.add(offset) as *const c_void,
                length - offset,
            );
            if written <= 0 {
                return -1;
            }
            offset += written as usize;
        }
    }
    1
}

#[no_mangle]
pub unsafe extern "C" fn fmtmsg(
    classification: c_long,
    label: *const c_char,
    severity: c_int,
    text: *const c_char,
    action: *const c_char,
    tag: *const c_char,
) -> c_int {
    let mut result = 0;
    let severity_text = match severity {
        CABI_MM_HALT => b"HALT: \0".as_ptr() as *const c_char,
        CABI_MM_ERROR => b"ERROR: \0".as_ptr() as *const c_char,
        CABI_MM_WARNING => b"WARNING: \0".as_ptr() as *const c_char,
        CABI_MM_INFO => b"INFO: \0".as_ptr() as *const c_char,
        _ => b"\0".as_ptr() as *const c_char,
    } as *const c_char;

    if classification & CABI_MM_CONSOLE as c_long != 0 {
        let console_fd = open(b"/dev/console\0".as_ptr() as *const c_char, O_WRONLY, 0);
        if console_fd < 0 {
            result = CABI_MM_NOCON;
        } else {
            let written = cabi_fmtmsg_write(
                console_fd,
                [
                    if label.is_null() { b"\0".as_ptr() as *const c_char } else { label },
                    if label.is_null() { b"\0".as_ptr() as *const c_char } else { b": \0".as_ptr() as *const c_char },
                    if severity != 0 { severity_text } else { b"\0".as_ptr() as *const c_char },
                    if text.is_null() { b"\0".as_ptr() as *const c_char } else { text },
                    if action.is_null() { b"\0".as_ptr() as *const c_char } else { b"\nTO FIX: \0".as_ptr() as *const c_char },
                    if action.is_null() { b"\0".as_ptr() as *const c_char } else { action },
                    if action.is_null() { b"\0".as_ptr() as *const c_char } else { b" \0".as_ptr() as *const c_char },
                    if tag.is_null() { b"\0".as_ptr() as *const c_char } else { tag },
                    b"\n\0".as_ptr() as *const c_char,
                ],
            );
            if written < 1 {
                result = CABI_MM_NOCON;
            }
            let _ = close(console_fd);
        }
    }

    if classification & CABI_MM_PRINT as c_long != 0 {
        let verb = cabi_fmtmsg_verb_mask();
        let written = cabi_fmtmsg_write(
            2,
            [
                if verb & 1 != 0 && !label.is_null() { label } else { b"\0".as_ptr() as *const c_char },
                if verb & 1 != 0 && !label.is_null() { b": \0".as_ptr() as *const c_char } else { b"\0".as_ptr() as *const c_char },
                if verb & 2 != 0 && severity != 0 { severity_text } else { b"\0".as_ptr() as *const c_char },
                if verb & 4 != 0 && !text.is_null() { text } else { b"\0".as_ptr() as *const c_char },
                if verb & 8 != 0 && !action.is_null() { b"\nTO FIX: \0".as_ptr() as *const c_char } else { b"\0".as_ptr() as *const c_char },
                if verb & 8 != 0 && !action.is_null() { action } else { b"\0".as_ptr() as *const c_char },
                if verb & 8 != 0 && !action.is_null() { b" \0".as_ptr() as *const c_char } else { b"\0".as_ptr() as *const c_char },
                if verb & 16 != 0 && !tag.is_null() { tag } else { b"\0".as_ptr() as *const c_char },
                b"\n\0".as_ptr() as *const c_char,
            ],
        );
        if written < 1 {
            result |= CABI_MM_NOMSG;
        }
    }

    if result == (CABI_MM_NOCON | CABI_MM_NOMSG) {
        CABI_MM_NOTOK
    } else {
        result
    }
}

#[inline]
fn cabi_strfmon_digit(value: u8) -> bool {
    value >= b'0' && value <= b'9'
}

unsafe fn cabi_vstrfmon_l(
    output: *mut c_char,
    mut remaining: usize,
    format: *const c_char,
    mut args: VaList,
) -> SSizeT {
    let start = output;
    let mut cursor = format as *const u8;
    let mut destination = output as *mut u8;

    while remaining != 0 && *cursor != 0 {
        if *cursor != b'%' {
            *destination = *cursor;
            destination = destination.add(1);
            cursor = cursor.add(1);
            remaining -= 1;
            continue;
        }
        cursor = cursor.add(1);
        if *cursor == b'%' {
            *destination = b'%';
            destination = destination.add(1);
            cursor = cursor.add(1);
            remaining -= 1;
            continue;
        }

        // These fields are part of the POSIX grammar.  They are intentionally
        // parsed even though C/POSIX locale data leaves their output inert,
        // matching musl's 1.2.6 implementation.
        let mut fill = b' ';
        let mut no_grouping = false;
        let mut negative_parentheses = false;
        let mut no_symbol = false;
        let mut left = false;
        loop {
            match *cursor {
                b'=' => {
                    cursor = cursor.add(1);
                    fill = *cursor;
                    cursor = cursor.add(1);
                }
                b'^' => {
                    no_grouping = true;
                    cursor = cursor.add(1);
                }
                b'(' => {
                    negative_parentheses = true;
                    cursor = cursor.add(1);
                }
                b'+' => {
                    cursor = cursor.add(1);
                }
                b'!' => {
                    no_symbol = true;
                    cursor = cursor.add(1);
                }
                b'-' => {
                    left = true;
                    cursor = cursor.add(1);
                }
                _ => break,
            }
        }

        let mut field_width: c_int = 0;
        while cabi_strfmon_digit(*cursor) {
            field_width = field_width
                .wrapping_mul(10)
                .wrapping_add((*cursor - b'0') as c_int);
            cursor = cursor.add(1);
        }
        let mut left_places: c_int = 0;
        let mut right_places: c_int = 2;
        if *cursor == b'#' {
            cursor = cursor.add(1);
            left_places = 0;
            while cabi_strfmon_digit(*cursor) {
                left_places = left_places
                    .wrapping_mul(10)
                    .wrapping_add((*cursor - b'0') as c_int);
                cursor = cursor.add(1);
            }
        }
        if *cursor == b'.' {
            cursor = cursor.add(1);
            right_places = 0;
            while cabi_strfmon_digit(*cursor) {
                right_places = right_places
                    .wrapping_mul(10)
                    .wrapping_add((*cursor - b'0') as c_int);
                cursor = cursor.add(1);
            }
        }
        let _international = *cursor == b'i';
        cursor = cursor.add(1);

        let mut width = left_places
            .wrapping_add(1)
            .wrapping_add(right_places);
        if !left && field_width > width {
            width = field_width;
        }

        // Keep the parsed-but-inert fields live for the same reason they are
        // present in musl's C implementation: they document the locale
        // boundary and prevent an accidental future formatter from dropping
        // grammar coverage silently.
        let _ = (fill, no_grouping, negative_parentheses, no_symbol);
        let value = args.next_arg::<f64>();
        let required = snprintf(
            destination as *mut c_char,
            remaining,
            b"%*.*f\0".as_ptr() as *const c_char,
            width,
            right_places,
            value,
        );
        if required < 0 || required as usize >= remaining {
            *__errno_location() = E2BIG;
            return -1;
        }
        destination = destination.add(required as usize);
        remaining -= required as usize;
    }

    destination as usize as SSizeT - start as usize as SSizeT
}

#[no_mangle]
pub unsafe extern "C" fn strfmon_l(
    output: *mut c_char,
    remaining: usize,
    _locale: locale_t,
    format: *const c_char,
    args: ...,
) -> SSizeT {
    cabi_vstrfmon_l(output, remaining, format, args)
}

#[no_mangle]
pub unsafe extern "C" fn strfmon(
    output: *mut c_char,
    remaining: usize,
    format: *const c_char,
    args: ...,
) -> SSizeT {
    // The active locale is C/POSIX-only in this libc; retaining the locale
    // argument in the `_l` entry point preserves the ABI without fabricating
    // non-C monetary data.
    cabi_vstrfmon_l(output, remaining, format, args)
}
