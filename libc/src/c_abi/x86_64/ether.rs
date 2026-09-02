//! Selected static Linux/x86-64 legacy Ethernet conversion C ABI.
//!
//! This module maps the six non-`ether_line` public entries of pinned musl
//! 1.2.6 `src/network/ether.c`: `ether_aton_r`, `ether_aton`, `ether_ntoa_r`,
//! `ether_ntoa`, `ether_ntohost`, and `ether_hostton`. The source's remaining
//! exact `return -1` `ether_line` body remains in the neighboring
//! `ether_line.rs` archive boundary so its existing demand-extraction evidence
//! keeps proving that the new provider block is not pulled in by that leaf.
//!
//! The parser deliberately calls the selected musl-shaped `strtoul` C ABI
//! entry with base 16, preserving its leading-space/sign/prefix/end-pointer
//! and `errno` behavior. The source formats six bounded octets through
//! `sprintf`; this translation writes the equivalent fixed uppercase 17-byte
//! text plus terminator directly, so it neither selects stdio nor changes the
//! fixed 18-byte caller/static-buffer contract. The source-shaped host stubs
//! do not dereference their pointers and return `-1` without `/etc/ethers`,
//! resolver, socket, interface, file, or network-policy behavior.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license.

use core::ffi::{c_char, c_int};

use super::{ether_line::CabiEtherAddr, integer_parse};

const ETHER_TEXT_LENGTH: usize = 18;
const HEX: &[u8; 16] = b"0123456789ABCDEF";

// Musl owns process-static rather than thread-local storage for these two
// non-reentrant compatibility entry points. A later successful call replaces
// the earlier result, exactly as the C source's local statics do.
static mut ETHER_ATON_RESULT: CabiEtherAddr = CabiEtherAddr { octets: [0; 6] };
static mut ETHER_NTOA_RESULT: [c_char; ETHER_TEXT_LENGTH] = [0; ETHER_TEXT_LENGTH];

/// Parse one six-octet Ethernet address with musl's `strtoul` grammar.
///
/// # Safety
///
/// `input` must be a readable NUL-terminated C string and `address` must be
/// writable for one `struct ether_addr`. Those direct-pointer requirements are
/// inherited from musl; the destination is only overwritten after the complete
/// six-field parse succeeds.
#[no_mangle]
pub unsafe extern "C" fn ether_aton_r(
    input: *const c_char,
    address: *mut CabiEtherAddr,
) -> *mut CabiEtherAddr {
    let mut parsed = CabiEtherAddr { octets: [0; 6] };
    let mut cursor = input;

    for index in 0..parsed.octets.len() {
        if index != 0 {
            // SAFETY: the C-string precondition covers this delimiter byte.
            if unsafe { cursor.read() } != b':' as c_char {
                return core::ptr::null_mut();
            }
            // SAFETY: advancing after the inspected delimiter remains within
            // the caller's NUL-terminated input sequence.
            cursor = unsafe { cursor.add(1) };
        }

        let mut end = core::ptr::null_mut();
        // SAFETY: this preserves musl ether.c's direct base-16 strtoul call;
        // both pointer contracts are the caller obligations documented above.
        let value = unsafe { integer_parse::strtoul(cursor, &mut end, 16) };
        cursor = end;
        if value > 0xff {
            return core::ptr::null_mut();
        }
        parsed.octets[index] = value as u8;
    }

    // SAFETY: the C-string precondition covers the trailing-format byte.
    if unsafe { cursor.read() } != 0 {
        return core::ptr::null_mut();
    }
    // SAFETY: only a complete parse reaches this source-equivalent write.
    unsafe { address.write(parsed) };
    address
}

/// Parse an Ethernet address into musl's process-static result storage.
///
/// # Safety
///
/// `input` must be a readable NUL-terminated C string. The returned pointer is
/// process-static, non-reentrant storage that later successful calls overwrite.
#[no_mangle]
pub unsafe extern "C" fn ether_aton(input: *const c_char) -> *mut CabiEtherAddr {
    // SAFETY: the static is one valid destination; `input` retains the public
    // function's documented C-string obligation.
    unsafe { ether_aton_r(input, core::ptr::addr_of_mut!(ETHER_ATON_RESULT)) }
}

/// Render an Ethernet address into exactly eighteen caller-owned bytes.
///
/// # Safety
///
/// `address` must point to six readable octets and `output` must point to at
/// least eighteen writable bytes. Musl performs no null or bounds checks.
#[no_mangle]
pub unsafe extern "C" fn ether_ntoa_r(
    address: *const CabiEtherAddr,
    output: *mut c_char,
) -> *mut c_char {
    let original = output;
    let mut cursor = output.cast::<u8>();
    let address_bytes = address.cast::<u8>();

    for index in 0..6 {
        if index != 0 {
            // SAFETY: the caller supplies all eighteen output bytes.
            unsafe { cursor.write(b':') };
            // SAFETY: this follows one byte just written to caller storage.
            cursor = unsafe { cursor.add(1) };
        }
        // SAFETY: the caller supplies a six-octet readable address record.
        // A byte-level raw read preserves the C API's invalid-pointer domain
        // without introducing Rust debug null-dereference machinery.
        let value = unsafe { address_bytes.add(index).read() } as usize;
        // SAFETY: each octet consumes exactly two of the documented output
        // bytes, using source-equivalent uppercase `%.2X` digits.
        unsafe { cursor.write(HEX[value >> 4]) };
        // SAFETY: this follows the first digit in caller-owned storage.
        cursor = unsafe { cursor.add(1) };
        // SAFETY: `value & 15` is a valid hexadecimal table index.
        unsafe { cursor.write(HEX[value & 15]) };
        // SAFETY: this follows the second digit in caller-owned storage.
        cursor = unsafe { cursor.add(1) };
    }
    // SAFETY: six two-digit fields plus five colons use seventeen bytes.
    unsafe { cursor.write(0) };
    original
}

/// Render an Ethernet address into musl's process-static text buffer.
///
/// # Safety
///
/// `address` must point to six readable octets. The returned pointer aliases
/// process-static non-reentrant storage that later calls overwrite.
#[no_mangle]
pub unsafe extern "C" fn ether_ntoa(address: *const CabiEtherAddr) -> *mut c_char {
    // SAFETY: the static result has exactly the eighteen writable bytes
    // documented by `ether_ntoa_r`; `address` retains this function's precondition.
    unsafe { ether_ntoa_r(address, core::ptr::addr_of_mut!(ETHER_NTOA_RESULT).cast()) }
}

/// Return musl's fixed unsupported Ethernet-address-to-host result.
#[no_mangle]
pub extern "C" fn ether_ntohost(
    _hostname: *mut c_char,
    _address: *const CabiEtherAddr,
) -> c_int {
    -1
}

/// Return musl's fixed unsupported host-to-Ethernet-address result.
#[no_mangle]
pub extern "C" fn ether_hostton(
    _hostname: *const c_char,
    _address: *mut CabiEtherAddr,
) -> c_int {
    -1
}
