// M4 Ethernet address conversion and legacy /etc/ethers mappings.
//
// The conversion entry points follow musl's wire/text ABI: ether_aton uses a
// process-static result, ether_ntoa uses a process-static 18-byte result, and
// their _r variants write only through caller-owned storage.  The host mapping
// entry points deliberately consult the real /etc/ethers file; an absent file
// or missing entry is an error rather than a fabricated address or hostname.

#[repr(C)]
pub struct M4EtherAddr {
    pub ether_addr_octet: [u8; 6],
}

const M4_ETHER_TEXT_LEN: usize = 18;
const M4_ETHER_LINE_LEN: usize = 4096;
const M4_ETHER_ENOENT: c_int = 2;

static mut M4_ETHER_ATON_RESULT: M4EtherAddr = M4EtherAddr {
    ether_addr_octet: [0; 6],
};
static mut M4_ETHER_NTOA_RESULT: [c_char; M4_ETHER_TEXT_LEN] = [0; M4_ETHER_TEXT_LEN];

#[inline]
unsafe fn m4_ether_hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[inline]
unsafe fn m4_ether_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\r' | b'\x0b' | b'\x0c')
}

#[inline]
unsafe fn m4_ether_ascii_lower(c: u8) -> u8 {
    if c >= b'A' && c <= b'Z' {
        c + (b'a' - b'A')
    } else {
        c
    }
}

// This intentionally retains musl's strtoul-based parser, including its
// accepted hexadecimal spellings and its destination-unchanged-on-failure
// behavior.  The local result prevents malformed input from partially
// modifying the caller's struct.
#[no_mangle]
pub unsafe extern "C" fn ether_aton_r(
    asc: *const c_char,
    addr: *mut M4EtherAddr,
) -> *mut M4EtherAddr {
    if asc.is_null() || addr.is_null() {
        return core::ptr::null_mut();
    }

    let mut parsed = M4EtherAddr {
        ether_addr_octet: [0; 6],
    };
    let mut cursor = asc;
    for index in 0..6 {
        if index != 0 {
            if *cursor as u8 != b':' {
                return core::ptr::null_mut();
            }
            cursor = cursor.add(1);
        }

        let mut end = core::ptr::null_mut();
        let value = strtoul(cursor, &mut end, 16);
        if end == cursor as *mut c_char {
            return core::ptr::null_mut();
        }
        cursor = end as *const c_char;
        if value > 0xff {
            return core::ptr::null_mut();
        }
        parsed.ether_addr_octet[index] = value as u8;
    }

    if *cursor as u8 != 0 {
        return core::ptr::null_mut();
    }
    core::ptr::write(addr, parsed);
    addr
}

#[no_mangle]
pub unsafe extern "C" fn ether_aton(asc: *const c_char) -> *mut M4EtherAddr {
    ether_aton_r(asc, core::ptr::addr_of_mut!(M4_ETHER_ATON_RESULT))
}

#[no_mangle]
pub unsafe extern "C" fn ether_ntoa_r(
    addr: *const M4EtherAddr,
    buffer: *mut c_char,
) -> *mut c_char {
    if addr.is_null() || buffer.is_null() {
        return core::ptr::null_mut();
    }

    let digits = b"0123456789ABCDEF";
    let output = buffer as *mut u8;
    for index in 0..6 {
        if index != 0 {
            *output.add(index * 3 - 1) = b':';
        }
        let value = (*addr).ether_addr_octet[index] as usize;
        *output.add(index * 3) = digits[value >> 4];
        *output.add(index * 3 + 1) = digits[value & 0xf];
    }
    *output.add(17) = 0;
    buffer
}

#[no_mangle]
pub unsafe extern "C" fn ether_ntoa(addr: *const M4EtherAddr) -> *mut c_char {
    ether_ntoa_r(addr, core::ptr::addr_of_mut!(M4_ETHER_NTOA_RESULT).cast())
}

// Parse the /etc/ethers line grammar.  Each octet is one or two hexadecimal
// digits followed by ':' (except the last); a hostname is a single non-space
// token and '#' starts a comment after the token.  No output is published
// until both the address and hostname have been validated.
#[no_mangle]
pub unsafe extern "C" fn ether_line(
    line: *const c_char,
    addr: *mut M4EtherAddr,
    hostname: *mut c_char,
) -> c_int {
    if line.is_null() || addr.is_null() || hostname.is_null() {
        return -1;
    }

    let mut cursor = line as *const u8;
    let mut parsed = M4EtherAddr {
        ether_addr_octet: [0; 6],
    };

    for index in 0..6 {
        let first = match m4_ether_hex(*cursor) {
            Some(value) => value,
            None => return -1,
        };
        cursor = cursor.add(1);
        let mut value = first;
        let next = *cursor;
        if index < 5 {
            if next != b':' {
                let second = match m4_ether_hex(next) {
                    Some(value) => value,
                    None => return -1,
                };
                value = (first << 4) | second;
                cursor = cursor.add(1);
                if *cursor != b':' {
                    return -1;
                }
            }
            cursor = cursor.add(1);
        } else if next != 0 && !m4_ether_space(next) {
            let second = match m4_ether_hex(next) {
                Some(value) => value,
                None => return -1,
            };
            value = (first << 4) | second;
            cursor = cursor.add(1);
        }
        parsed.ether_addr_octet[index] = value;
    }

    // The address and hostname are whitespace-separated in /etc/ethers.
    // Without this check a two-digit final octet followed immediately by a
    // hostname would be accepted as one field.
    if *cursor != 0 && !m4_ether_space(*cursor) {
        return -1;
    }
    while m4_ether_space(*cursor) {
        cursor = cursor.add(1);
    }
    if *cursor == 0 || *cursor == b'#' {
        return -1;
    }

    let mut host_cursor = hostname as *mut u8;
    while *cursor != 0 && *cursor != b'#' && !m4_ether_space(*cursor) {
        *host_cursor = *cursor;
        host_cursor = host_cursor.add(1);
        cursor = cursor.add(1);
    }
    *host_cursor = 0;

    core::ptr::write(addr, parsed);
    0
}

#[inline]
unsafe fn m4_ether_name_equal(left: *const c_char, right: *const c_char) -> bool {
    let mut index = 0usize;
    loop {
        let left_byte = m4_ether_ascii_lower(*left.add(index) as u8);
        let right_byte = m4_ether_ascii_lower(*right.add(index) as u8);
        if left_byte != right_byte {
            return false;
        }
        if left_byte == 0 {
            return true;
        }
        index += 1;
    }
}

unsafe fn m4_ether_lookup(
    wanted_name: *const c_char,
    wanted_addr: *const M4EtherAddr,
    output_name: *mut c_char,
    output_addr: *mut M4EtherAddr,
) -> c_int {
    if (wanted_name.is_null() && wanted_addr.is_null())
        || (wanted_name.is_null() && output_addr.is_null())
        || (wanted_addr.is_null() && output_name.is_null())
    {
        ERRNO = EINVAL;
        return -1;
    }

    let path = b"/etc/ethers\0";
    let fd = sys_open(path.as_ptr(), (O_RDONLY | O_CLOEXEC) as i64, 0);
    if fd < 0 {
        ERRNO = (-fd) as c_int;
        return -1;
    }

    let mut line = [0u8; M4_ETHER_LINE_LEN];
    let mut line_len = 0usize;
    let mut overlong = false;
    let mut chunk = [0u8; 512];

    loop {
        let read_len = sys_read(fd, chunk.as_mut_ptr(), chunk.len());
        if read_len < 0 {
            ERRNO = (-read_len) as c_int;
            let _ = sys_close(fd);
            return -1;
        }
        if read_len == 0 {
            break;
        }

        for index in 0..read_len as usize {
            let byte = chunk[index];
            if overlong {
                if byte == b'\n' {
                    overlong = false;
                    line_len = 0;
                }
                continue;
            }
            if byte == b'\n' {
                line[line_len] = 0;
                if m4_ether_lookup_line(
                    line.as_ptr() as *const c_char,
                    wanted_name,
                    wanted_addr,
                    output_name,
                    output_addr,
                ) {
                    let _ = sys_close(fd);
                    return 0;
                }
                line_len = 0;
            } else if line_len + 1 < line.len() {
                line[line_len] = byte;
                line_len += 1;
            } else {
                overlong = true;
                line_len = 0;
            }
        }
    }

    if !overlong && line_len != 0 {
        line[line_len] = 0;
        if m4_ether_lookup_line(
            line.as_ptr() as *const c_char,
            wanted_name,
            wanted_addr,
            output_name,
            output_addr,
        ) {
            let _ = sys_close(fd);
            return 0;
        }
    }

    let _ = sys_close(fd);
    ERRNO = M4_ETHER_ENOENT;
    -1
}

unsafe fn m4_ether_lookup_line(
    line: *const c_char,
    wanted_name: *const c_char,
    wanted_addr: *const M4EtherAddr,
    output_name: *mut c_char,
    output_addr: *mut M4EtherAddr,
) -> bool {
    let mut parsed_addr = M4EtherAddr {
        ether_addr_octet: [0; 6],
    };
    let mut parsed_name = [0 as c_char; M4_ETHER_LINE_LEN];
    if ether_line(
        line,
        &mut parsed_addr,
        parsed_name.as_mut_ptr(),
    ) != 0
    {
        return false;
    }

    let matches = if !wanted_name.is_null() {
        m4_ether_name_equal(wanted_name, parsed_name.as_ptr())
    } else {
        core::ptr::read(wanted_addr)
            .ether_addr_octet
            == parsed_addr.ether_addr_octet
    };
    if !matches {
        return false;
    }

    if !output_addr.is_null() {
        core::ptr::write(output_addr, parsed_addr);
    }
    if !output_name.is_null() {
        let mut index = 0usize;
        loop {
            let byte = *parsed_name.as_ptr().add(index);
            *output_name.add(index) = byte;
            if byte == 0 {
                break;
            }
            index += 1;
        }
    }
    true
}

#[no_mangle]
pub unsafe extern "C" fn ether_hostton(
    hostname: *const c_char,
    addr: *mut M4EtherAddr,
) -> c_int {
    m4_ether_lookup(hostname, core::ptr::null(), core::ptr::null_mut(), addr)
}

#[no_mangle]
pub unsafe extern "C" fn ether_ntohost(
    hostname: *mut c_char,
    addr: *const M4EtherAddr,
) -> c_int {
    m4_ether_lookup(core::ptr::null(), addr, hostname, core::ptr::null_mut())
}
