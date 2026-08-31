//! Fixed-C-locale glibc-compatibility ctype table locators for Linux/x86-64.
//!
//! This leaf owns exactly the internal ABI locator trio `__ctype_b_loc`,
//! `__ctype_tolower_loc`, and `__ctype_toupper_loc`.  Each returns the
//! address of one immutable pointer object, whose target is a 384-entry table
//! biased by 128.  That shape lets C callers index the returned table with
//! every signed-char value through every unsigned byte value (`-128..=255`),
//! just as musl's glibc-compatibility ABI does.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/ctype/__ctype_b_loc.c` maps to `CABI_CTYPE_B_TABLE` and
//!   `__ctype_b_loc` below, including musl's network-byte-order 16-bit class
//!   encoding on little-endian x86-64.
//! - `src/ctype/__ctype_tolower_loc.c` and `src/ctype/__ctype_toupper_loc.c`
//!   map to the paired signed 32-bit ASCII conversion tables and locators.
//!
//! These compatibility locators are deliberately not public `<ctype.h>`
//! declarations.  They are a stable C-link ABI detail for consumers that
//! declare them themselves, not a new project C API or a replacement for the
//! ordinary selected ctype entries.  The tables are immutable fixed-C-locale
//! data, so `C`, `POSIX`, and `C.UTF-8` observe the same bytes.  There is no
//! locale selection, locale database, environment lookup, UTF-8
//! classification, TLS, errno, allocation, syscall, cancellation, mutable
//! runtime state, loader, CRT, sysroot, or public x86 support here.

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_endian = "little"
)))]
compile_error!("the x86 ctype locator leaf requires little-endian Linux/x86-64");

/// An immutable raw table pointer stored in a process-lifetime static object.
///
/// The inner pointer targets a separate immutable static table and the tuple
/// is private, so sharing the locator's pointer object cannot permit Rust or
/// C to mutate either datum.  This mirrors musl's `static const T *const
/// ptable` while allowing the raw pointer to occupy a Rust static.
#[repr(transparent)]
struct CtypeTablePointer<T>(*const T);

unsafe impl<T> Sync for CtypeTablePointer<T> {}

#[inline]
const fn musl_ctype_class_word(value: u16) -> u16 {
    // musl's X(x) writes the class bits in network byte order even when the
    // host is little-endian.  This target is little-endian by construction.
    value.rotate_left(8)
}

const fn ctype_class_value(character: i32) -> u16 {
    if character < 0 || character > 0x7f {
        return 0;
    }

    let class_bits = if character == b'\t' as i32 {
        0x0320
    } else if character == b'\n' as i32
        || character == b'\x0b' as i32
        || character == b'\x0c' as i32
        || character == b'\r' as i32
    {
        0x0220
    } else if character < 0x20 || character == 0x7f {
        0x0200
    } else if character == b' ' as i32 {
        0x0160
    } else if (character >= b'!' as i32 && character <= b'/' as i32)
        || (character >= b':' as i32 && character <= b'@' as i32)
        || (character >= b'[' as i32 && character <= b'`' as i32)
        || (character >= b'{' as i32 && character <= b'~' as i32)
    {
        0x04c0
    } else if character >= b'0' as i32 && character <= b'9' as i32 {
        0x08d8
    } else if character >= b'A' as i32 && character <= b'F' as i32 {
        0x08d5
    } else if character >= b'G' as i32 && character <= b'Z' as i32 {
        0x08c5
    } else if character >= b'a' as i32 && character <= b'f' as i32 {
        0x08d6
    } else if character >= b'g' as i32 && character <= b'z' as i32 {
        0x08c6
    } else {
        0
    };

    musl_ctype_class_word(class_bits)
}

const fn ctype_class_table() -> [u16; 384] {
    let mut table = [0u16; 384];
    let mut index = 0usize;
    while index < table.len() {
        table[index] = ctype_class_value(index as i32 - 128);
        index += 1;
    }
    table
}

const fn ctype_tolower_value(character: i32) -> i32 {
    if character >= b'A' as i32 && character <= b'Z' as i32 {
        character + (b'a' - b'A') as i32
    } else if character >= 0 && character <= 0x7f {
        character
    } else {
        0
    }
}

const fn ctype_toupper_value(character: i32) -> i32 {
    if character >= b'a' as i32 && character <= b'z' as i32 {
        character - (b'a' - b'A') as i32
    } else if character >= 0 && character <= 0x7f {
        character
    } else {
        0
    }
}

const fn ctype_tolower_table() -> [i32; 384] {
    let mut table = [0i32; 384];
    let mut index = 0usize;
    while index < table.len() {
        table[index] = ctype_tolower_value(index as i32 - 128);
        index += 1;
    }
    table
}

const fn ctype_toupper_table() -> [i32; 384] {
    let mut table = [0i32; 384];
    let mut index = 0usize;
    while index < table.len() {
        table[index] = ctype_toupper_value(index as i32 - 128);
        index += 1;
    }
    table
}

static CABI_CTYPE_B_TABLE: [u16; 384] = ctype_class_table();
static CABI_CTYPE_TOLOWER_TABLE: [i32; 384] = ctype_tolower_table();
static CABI_CTYPE_TOUPPER_TABLE: [i32; 384] = ctype_toupper_table();

// As in musl, each locator returns the address of a pointer object rather
// than the table itself.  The pointer is biased by 128 for the signed-char
// extension range and cannot be changed after static initialization.
static CABI_CTYPE_B_POINTER: CtypeTablePointer<u16> = CtypeTablePointer(
    core::ptr::addr_of!(CABI_CTYPE_B_TABLE)
        .cast::<u16>()
        .wrapping_add(128),
);
static CABI_CTYPE_TOLOWER_POINTER: CtypeTablePointer<i32> = CtypeTablePointer(
    core::ptr::addr_of!(CABI_CTYPE_TOLOWER_TABLE)
        .cast::<i32>()
        .wrapping_add(128),
);
static CABI_CTYPE_TOUPPER_POINTER: CtypeTablePointer<i32> = CtypeTablePointer(
    core::ptr::addr_of!(CABI_CTYPE_TOUPPER_TABLE)
        .cast::<i32>()
        .wrapping_add(128),
);

/// Return musl's fixed-C-locale ctype-class table locator.
#[no_mangle]
pub extern "C" fn __ctype_b_loc() -> *const *const u16 {
    core::ptr::addr_of!(CABI_CTYPE_B_POINTER.0)
}

/// Return musl's fixed-C-locale ASCII-lowercase table locator.
#[no_mangle]
pub extern "C" fn __ctype_tolower_loc() -> *const *const i32 {
    core::ptr::addr_of!(CABI_CTYPE_TOLOWER_POINTER.0)
}

/// Return musl's fixed-C-locale ASCII-uppercase table locator.
#[no_mangle]
pub extern "C" fn __ctype_toupper_loc() -> *const *const i32 {
    core::ptr::addr_of!(CABI_CTYPE_TOUPPER_POINTER.0)
}
