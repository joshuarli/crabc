#[no_mangle]
pub extern "C" fn toascii(c: c_int) -> c_int {
    c & 0x7f
}

#[no_mangle]
#[linkage = "weak"]
pub extern "C" fn isalnum_l(c: c_int, _loc: locale_t) -> c_int {
    isalnum(c)
}

#[no_mangle]
#[linkage = "weak"]
pub extern "C" fn isalpha_l(c: c_int, _loc: locale_t) -> c_int {
    isalpha(c)
}

#[no_mangle]
#[linkage = "weak"]
pub extern "C" fn isblank_l(c: c_int, _loc: locale_t) -> c_int {
    isblank(c)
}

#[no_mangle]
#[linkage = "weak"]
pub extern "C" fn iscntrl_l(c: c_int, _loc: locale_t) -> c_int {
    iscntrl(c)
}

#[no_mangle]
#[linkage = "weak"]
pub extern "C" fn isdigit_l(c: c_int, _loc: locale_t) -> c_int {
    isdigit(c)
}

#[no_mangle]
#[linkage = "weak"]
pub extern "C" fn isgraph_l(c: c_int, _loc: locale_t) -> c_int {
    isgraph(c)
}

#[no_mangle]
#[linkage = "weak"]
pub extern "C" fn islower_l(c: c_int, _loc: locale_t) -> c_int {
    islower(c)
}

#[no_mangle]
#[linkage = "weak"]
pub extern "C" fn isprint_l(c: c_int, _loc: locale_t) -> c_int {
    isprint(c)
}

#[no_mangle]
#[linkage = "weak"]
pub extern "C" fn ispunct_l(c: c_int, _loc: locale_t) -> c_int {
    ispunct(c)
}

#[no_mangle]
#[linkage = "weak"]
pub extern "C" fn isspace_l(c: c_int, _loc: locale_t) -> c_int {
    isspace(c)
}

#[no_mangle]
#[linkage = "weak"]
pub extern "C" fn isupper_l(c: c_int, _loc: locale_t) -> c_int {
    isupper(c)
}

#[no_mangle]
#[linkage = "weak"]
pub extern "C" fn isxdigit_l(c: c_int, _loc: locale_t) -> c_int {
    isxdigit(c)
}

#[no_mangle]
#[linkage = "weak"]
pub extern "C" fn tolower_l(c: c_int, _loc: locale_t) -> c_int {
    tolower(c)
}

#[no_mangle]
#[linkage = "weak"]
pub extern "C" fn toupper_l(c: c_int, _loc: locale_t) -> c_int {
    toupper(c)
}

// musl's glibc-compatibility ctype locators expose tables covering the
// signed-char range through 255.  The returned table pointer is biased by
// 128, so callers may index it directly with any value in [-128, 255].
// Keep the table encoding (including the endian-dependent byte swap) exactly
// as musl does: the 16-bit class bits are part of this ABI, not an internal
// representation of the is* functions above.

#[inline]
const fn m4_ctype_b_x(value: u16) -> u16 {
    #[cfg(target_endian = "little")]
    { value.rotate_left(8) }
    #[cfg(target_endian = "big")]
    { value }
}

const fn m4_ctype_b_value(c: i32) -> u16 {
    if c < 0 || c > 127 {
        return 0;
    }
    let raw = if c == b'\t' as i32 {
        0x0320
    } else if c == b'\n' as i32 || c == b'\x0b' as i32
        || c == b'\x0c' as i32 || c == b'\r' as i32
    {
        0x0220
    } else if c < 0x20 || c == 0x7f {
        0x0200
    } else if c == b' ' as i32 {
        0x0160
    } else if (c >= b'!' as i32 && c <= b'/' as i32)
        || (c >= b':' as i32 && c <= b'@' as i32)
        || (c >= b'[' as i32 && c <= b'`' as i32)
        || (c >= b'{' as i32 && c <= b'~' as i32)
    {
        0x04c0
    } else if c >= b'0' as i32 && c <= b'9' as i32 {
        0x08d8
    } else if c >= b'A' as i32 && c <= b'F' as i32 {
        0x08d5
    } else if c >= b'G' as i32 && c <= b'Z' as i32 {
        0x08c5
    } else if c >= b'a' as i32 && c <= b'f' as i32 {
        0x08d6
    } else if c >= b'g' as i32 && c <= b'z' as i32 {
        0x08c6
    } else {
        0
    };
    m4_ctype_b_x(raw)
}

const fn m4_ctype_b_table() -> [u16; 384] {
    let mut table = [0u16; 384];
    let mut i = 0usize;
    while i < table.len() {
        table[i] = m4_ctype_b_value(i as i32 - 128);
        i += 1;
    }
    table
}

const fn m4_ctype_tolower_value(c: i32) -> i32 {
    if c >= b'A' as i32 && c <= b'Z' as i32 { c + 32 }
    else if c >= 0 && c <= 127 { c }
    else { 0 }
}

const fn m4_ctype_toupper_value(c: i32) -> i32 {
    if c >= b'a' as i32 && c <= b'z' as i32 { c - 32 }
    else if c >= 0 && c <= 127 { c }
    else { 0 }
}

const fn m4_ctype_tolower_table() -> [i32; 384] {
    let mut table = [0i32; 384];
    let mut i = 0usize;
    while i < table.len() {
        table[i] = m4_ctype_tolower_value(i as i32 - 128);
        i += 1;
    }
    table
}

const fn m4_ctype_toupper_table() -> [i32; 384] {
    let mut table = [0i32; 384];
    let mut i = 0usize;
    while i < table.len() {
        table[i] = m4_ctype_toupper_value(i as i32 - 128);
        i += 1;
    }
    table
}

static M4_CTYPE_B_TABLE: [u16; 384] = m4_ctype_b_table();
static M4_CTYPE_TOLOWER_TABLE: [i32; 384] = m4_ctype_tolower_table();
static M4_CTYPE_TOUPPER_TABLE: [i32; 384] = m4_ctype_toupper_table();

// These are intentionally pointer objects, as in musl's `ptable` symbols:
// __ctype_*_loc returns the address of the table pointer, not the table
// itself.  A mutable static is used only to avoid requiring raw pointers to
// implement Sync; callers still receive a const pointer and never modify it.
static mut M4_CTYPE_B_PTR: *const u16 =
    core::ptr::addr_of!(M4_CTYPE_B_TABLE).cast::<u16>().wrapping_add(128);
static mut M4_CTYPE_TOLOWER_PTR: *const i32 =
    core::ptr::addr_of!(M4_CTYPE_TOLOWER_TABLE).cast::<i32>().wrapping_add(128);
static mut M4_CTYPE_TOUPPER_PTR: *const i32 =
    core::ptr::addr_of!(M4_CTYPE_TOUPPER_TABLE).cast::<i32>().wrapping_add(128);

#[no_mangle]
pub unsafe extern "C" fn __ctype_b_loc() -> *const *const u16 {
    core::ptr::addr_of!(M4_CTYPE_B_PTR)
}

#[no_mangle]
pub unsafe extern "C" fn __ctype_tolower_loc() -> *const *const i32 {
    core::ptr::addr_of!(M4_CTYPE_TOLOWER_PTR)
}

#[no_mangle]
pub unsafe extern "C" fn __ctype_toupper_loc() -> *const *const i32 {
    core::ptr::addr_of!(M4_CTYPE_TOUPPER_PTR)
}
