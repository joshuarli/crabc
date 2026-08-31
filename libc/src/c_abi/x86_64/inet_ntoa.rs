//! Isolated Linux/x86-64 C `inet_ntoa` presentation buffer.
//!
//! Pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417` maps
//! `src/network/inet_ntoa.c` to one process-global 16-byte `char` buffer and
//! `snprintf(buf, sizeof buf, "%d.%d.%d.%d", ...)` over the four in-memory
//! network-order bytes of `struct in_addr`. This target-local leaf preserves
//! that one shared non-reentrant scratch-buffer contract, while deliberately
//! keeping it separate from `inet_ntop`, `h_errno`, numeric `netdb.h`,
//! resolver configuration, DNS, `/etc/hosts`, `/etc/resolv.conf`, conventional
//! network databases, interfaces, sockets, and public support.
//!
//! The source's `snprintf` call is intentionally inlined only for four
//! unsigned IPv4 octets. The maximum dotted-decimal result is fifteen bytes
//! plus NUL, so the fixed sixteen-byte destination cannot truncate or fail;
//! direct decimal writes retain musl's observable text and shared-buffer
//! behavior without selecting stdio or a formatting runtime.

use core::ffi::{c_char, c_uint};

// Musl intentionally owns one shared static buffer rather than thread-local
// or caller-owned storage. Every call returns this same address and overwrites
// the prior NUL-terminated text.
static mut INET_NTOA_BUFFER: [c_char; 16] = [0; 16];

/// Write one decimal IPv4 octet into the fixed `inet_ntoa` buffer.
///
/// # Safety
///
/// `output` must designate enough writable bytes for the at-most-three-byte
/// rendering of `value`.
#[inline]
unsafe fn write_decimal_octet(mut output: *mut c_char, value: u8) -> *mut c_char {
    if value >= 100 {
        // SAFETY: `value / 100` is at most two, so this is an ASCII digit.
        unsafe { output.write(b'0'.wrapping_add(value / 100) as c_char) };
        // SAFETY: this follows one byte written inside the fixed buffer.
        output = unsafe { output.add(1) };
        // SAFETY: `(value / 10) % 10` is an ASCII decimal digit.
        unsafe { output.write(b'0'.wrapping_add((value / 10) % 10) as c_char) };
        // SAFETY: this follows one byte written inside the fixed buffer.
        output = unsafe { output.add(1) };
    } else if value >= 10 {
        // SAFETY: `value / 10` is an ASCII decimal digit.
        unsafe { output.write(b'0'.wrapping_add(value / 10) as c_char) };
        // SAFETY: this follows one byte written inside the fixed buffer.
        output = unsafe { output.add(1) };
    }
    // SAFETY: `value % 10` is an ASCII decimal digit.
    unsafe { output.write(b'0'.wrapping_add(value % 10) as c_char) };
    // SAFETY: this follows one byte written inside the fixed buffer.
    unsafe { output.add(1) }
}

/// Return musl's shared dotted-decimal presentation buffer for one IPv4 value.
///
/// The x86-64 C ABI passes `struct in_addr` as its single 32-bit `in_addr_t`
/// word in `edi`. `to_ne_bytes` recovers the four in-memory network-order
/// bytes held by that C record on this little-endian target. The return is the
/// process-global scratch address and the next call overwrites it.
///
/// # Safety
///
/// Concurrent callers must externally synchronize access to the one shared
/// C presentation buffer. This is musl's non-reentrant C contract; the leaf
/// does not add locking, TLS, or a caller-owned alternative.
#[no_mangle]
pub unsafe extern "C" fn inet_ntoa(address: c_uint) -> *mut c_char {
    let bytes = address.to_ne_bytes();
    let input = bytes.as_ptr();
    let buffer = core::ptr::addr_of_mut!(INET_NTOA_BUFFER).cast::<c_char>();
    let mut output = buffer;
    let mut index = 0usize;

    while index < 4 {
        if index != 0 {
            // SAFETY: a dotted IPv4 rendering has exactly three separators.
            unsafe { output.write(b'.' as c_char) };
            // SAFETY: this follows one byte written inside the fixed buffer.
            output = unsafe { output.add(1) };
        }
        // SAFETY: `index` stays in the four-byte local input array.
        let octet = unsafe { input.add(index).read() };
        // SAFETY: the maximum dotted IPv4 rendering consumes fifteen bytes.
        output = unsafe { write_decimal_octet(output, octet) };
        index += 1;
    }

    // SAFETY: the maximum fifteen-byte rendering leaves the terminator slot.
    unsafe { output.write(0) };
    buffer
}
