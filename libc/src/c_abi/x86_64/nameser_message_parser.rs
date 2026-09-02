//! Linux/x86-64 caller-owned nameserver message-parser C ABI block.
//!
//! Pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417` maps exactly
//! `src/network/ns_parse.c::{ns_initparse, ns_parserr, ns_name_uncompress}`
//! to this target-local provider block.  It initializes and advances only
//! caller-owned `ns_msg`/`ns_rr` records over a caller-owned DNS wire range.
//! The parser retains musl's state transitions and error publication while
//! delegating wire reads, RR skipping, and name expansion to the separately
//! selected `ns_get16`, `ns_get32`, `ns_skiprr`, and `dn_expand` C ABI leaves.
//!
//! This is deliberately not resolver state, resolver configuration,
//! `/etc/resolv.conf`, `/etc/hosts`, DNS transport, sockets, netdb databases,
//! allocation, or a general DNS framework.  It owns no input, output, or
//! mutable global state beyond the selected calling thread's `errno` slot.

use core::ffi::{c_char, c_int, c_uint, c_ulong};

const NS_S_QD: c_int = 0;
const NS_S_MAX: c_int = 4;
const NS_HEADER_BYTES: c_int = (2 + NS_S_MAX) * 2;
const NS_INT16SZ: usize = 2;
const NS_INT32SZ: usize = 4;
const NS_MAXDNAME: usize = 1025;
const EMSGSIZE: c_int = 90;
const ENODEV: c_int = 19;

/// Rust's private layout mirror for `<arpa/nameser.h>` `ns_msg`.
///
/// The public record is owned by the C header.  Keeping the mirror private
/// makes this module an ABI implementation rather than a second public type
/// surface.
#[repr(C)]
pub(super) struct NsMsg {
    message: *const u8,
    end_of_message: *const u8,
    id: u16,
    flags: u16,
    counts: [u16; NS_S_MAX as usize],
    sections: [*const u8; NS_S_MAX as usize],
    section: c_int,
    record_number: c_int,
    message_cursor: *const u8,
}

/// Rust's private layout mirror for `<arpa/nameser.h>` `ns_rr`.
#[repr(C)]
pub(super) struct NsRr {
    name: [c_char; NS_MAXDNAME],
    record_type: u16,
    record_class: u16,
    ttl: u32,
    rdata_length: u16,
    rdata: *const u8,
}

// Preserve musl's source-level helper boundaries rather than copying their
// byte-order, RR-span, or compressed-name behavior into this parser block.
unsafe extern "C" {
    #[link_name = "dn_expand"]
    fn selected_dn_expand(
        message: *const u8,
        end_of_message: *const u8,
        source: *const u8,
        destination: *mut c_char,
        space: c_int,
    ) -> c_int;

    #[link_name = "ns_get16"]
    fn selected_ns_get16(bytes: *const u8) -> c_uint;

    #[link_name = "ns_get32"]
    fn selected_ns_get32(bytes: *const u8) -> c_ulong;

    #[link_name = "ns_skiprr"]
    fn selected_ns_skiprr(
        cursor: *const u8,
        end_of_message: *const u8,
        section: c_int,
        count: c_int,
    ) -> c_int;
}

#[inline]
unsafe fn read16(cursor: &mut *const u8) -> u16 {
    let value = unsafe { selected_ns_get16(*cursor) } as u16;
    *cursor = unsafe { (*cursor).add(NS_INT16SZ) };
    value
}

#[inline]
unsafe fn read32(cursor: &mut *const u8) -> u32 {
    let value = unsafe { selected_ns_get32(*cursor) } as u32;
    *cursor = unsafe { (*cursor).add(NS_INT32SZ) };
    value
}

#[inline]
fn remaining_bytes(cursor: *const u8, end_of_message: *const u8) -> usize {
    (end_of_message as usize).wrapping_sub(cursor as usize)
}

#[inline]
unsafe fn malformed() -> c_int {
    unsafe { super::errno::set_errno(EMSGSIZE) };
    -1
}

#[inline]
unsafe fn missing_record() -> c_int {
    unsafe { super::errno::set_errno(ENODEV) };
    -1
}

/// Initialize one caller-owned `ns_msg` from a bounded DNS message.
///
/// # Safety
///
/// `message` must point to `message_length` readable bytes in one ordered
/// allocation when `message_length` is nonnegative. `handle` must point to a
/// writable, properly aligned `<arpa/nameser.h>` `ns_msg` that does not
/// overlap the message range. The function retains message pointers in that
/// caller-owned handle but performs no allocation or I/O. Negative lengths do
/// not form a valid C packet range and return `EMSGSIZE` without dereferencing
/// the input.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn ns_initparse(
    message: *const u8,
    message_length: c_int,
    handle: *mut NsMsg,
) -> c_int {
    unsafe {
        core::ptr::write(core::ptr::addr_of_mut!((*handle).message), message);
    }

    // Musl computes `message + message_length` before testing the fixed DNS
    // header. Negative lengths are outside C's valid pointer-range contract;
    // avoid manufacturing that invalid Rust pointer while preserving musl's
    // EMSGSIZE outcome for the API boundary.
    if message_length < 0 {
        unsafe {
            core::ptr::write(
                core::ptr::addr_of_mut!((*handle).end_of_message),
                message,
            );
        }
        return unsafe { malformed() };
    }

    let end_of_message = unsafe { message.add(message_length as usize) };
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!((*handle).end_of_message),
            end_of_message,
        );
    }
    if message_length < NS_HEADER_BYTES {
        return unsafe { malformed() };
    }

    let mut cursor = message;
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!((*handle).id),
            read16(&mut cursor),
        );
        core::ptr::write(
            core::ptr::addr_of_mut!((*handle).flags),
            read16(&mut cursor),
        );
    }
    for index in 0..NS_S_MAX as usize {
        let count = unsafe { read16(&mut cursor) };
        unsafe {
            core::ptr::write(core::ptr::addr_of_mut!((*handle).counts[index]), count);
        }
    }

    for index in 0..NS_S_MAX as usize {
        let count = unsafe { core::ptr::read(core::ptr::addr_of!((*handle).counts[index])) };
        if count != 0 {
            unsafe {
                core::ptr::write(
                    core::ptr::addr_of_mut!((*handle).sections[index]),
                    cursor,
                );
            }
            let end_of_message = unsafe {
                core::ptr::read(core::ptr::addr_of!((*handle).end_of_message))
            };
            let skipped = unsafe {
                selected_ns_skiprr(
                    cursor,
                    end_of_message,
                    index as c_int,
                    count as c_int,
                )
            };
            if skipped < 0 {
                // ns_skiprr owns the selected malformed-range errno result.
                return -1;
            }
            cursor = unsafe { cursor.add(skipped as usize) };
        } else {
            unsafe {
                core::ptr::write(
                    core::ptr::addr_of_mut!((*handle).sections[index]),
                    core::ptr::null(),
                );
            }
        }
    }

    let stored_end_of_message = unsafe {
        core::ptr::read(core::ptr::addr_of!((*handle).end_of_message))
    };
    if cursor != stored_end_of_message {
        return unsafe { malformed() };
    }
    unsafe {
        core::ptr::write(core::ptr::addr_of_mut!((*handle).section), NS_S_MAX);
        core::ptr::write(core::ptr::addr_of_mut!((*handle).record_number), -1);
        core::ptr::write(
            core::ptr::addr_of_mut!((*handle).message_cursor),
            core::ptr::null(),
        );
    }
    0
}

/// Parse one caller-selected resource record from an initialized `ns_msg`.
///
/// # Safety
///
/// `handle` must be an `ns_msg` successfully initialized by
/// [`ns_initparse`] for a still-live message range. `record` must point to a
/// writable, properly aligned `<arpa/nameser.h>` `ns_rr` that does not overlap
/// the message or handle. The function updates only those caller-owned
/// records; it retains no new ownership and performs no resolver I/O.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn ns_parserr(
    handle: *mut NsMsg,
    section: c_int,
    mut record_number: c_int,
    record: *mut NsRr,
) -> c_int {
    if !(0..NS_S_MAX).contains(&section) {
        return unsafe { missing_record() };
    }

    let section_index = section as usize;

    let active_section = unsafe { core::ptr::read(core::ptr::addr_of!((*handle).section)) };
    if section != active_section {
        let section_start = unsafe {
            core::ptr::read(core::ptr::addr_of!((*handle).sections[section_index]))
        };
        unsafe {
            core::ptr::write(core::ptr::addr_of_mut!((*handle).section), section);
            core::ptr::write(core::ptr::addr_of_mut!((*handle).record_number), 0);
            core::ptr::write(
                core::ptr::addr_of_mut!((*handle).message_cursor),
                section_start,
            );
        }
    }
    if record_number == -1 {
        record_number = unsafe {
            core::ptr::read(core::ptr::addr_of!((*handle).record_number))
        };
    }
    let count = unsafe { core::ptr::read(core::ptr::addr_of!((*handle).counts[section_index])) };
    if record_number < 0 || record_number >= count as c_int {
        return unsafe { missing_record() };
    }
    let mut current_record_number = unsafe {
        core::ptr::read(core::ptr::addr_of!((*handle).record_number))
    };
    if record_number < current_record_number {
        let section_start = unsafe {
            core::ptr::read(core::ptr::addr_of!((*handle).sections[section_index]))
        };
        unsafe {
            core::ptr::write(core::ptr::addr_of_mut!((*handle).record_number), 0);
            core::ptr::write(
                core::ptr::addr_of_mut!((*handle).message_cursor),
                section_start,
            );
        }
        current_record_number = 0;
    }
    if record_number > current_record_number {
        let message_cursor = unsafe {
            core::ptr::read(core::ptr::addr_of!((*handle).message_cursor))
        };
        let end_of_message = unsafe {
            core::ptr::read(core::ptr::addr_of!((*handle).end_of_message))
        };
        let skipped = unsafe {
            selected_ns_skiprr(
                message_cursor,
                end_of_message,
                section,
                record_number.wrapping_sub(current_record_number),
            )
        };
        if skipped < 0 {
            return -1;
        }
        unsafe {
            core::ptr::write(
                core::ptr::addr_of_mut!((*handle).message_cursor),
                message_cursor.add(skipped as usize),
            );
            core::ptr::write(
                core::ptr::addr_of_mut!((*handle).record_number),
                record_number,
            );
        }
    }

    let message = unsafe { core::ptr::read(core::ptr::addr_of!((*handle).message)) };
    let end_of_message = unsafe {
        core::ptr::read(core::ptr::addr_of!((*handle).end_of_message))
    };
    let message_cursor = unsafe {
        core::ptr::read(core::ptr::addr_of!((*handle).message_cursor))
    };
    let name_bytes = unsafe {
        ns_name_uncompress(
            message,
            end_of_message,
            message_cursor,
            core::ptr::addr_of_mut!((*record).name).cast::<c_char>(),
            NS_MAXDNAME,
        )
    };
    if name_bytes < 0 {
        return -1;
    }
    let mut cursor = unsafe { message_cursor.add(name_bytes as usize) };
    unsafe {
        core::ptr::write(core::ptr::addr_of_mut!((*handle).message_cursor), cursor);
    }

    if 2 * NS_INT16SZ > remaining_bytes(cursor, end_of_message) {
        return unsafe { malformed() };
    }
    let record_type = unsafe { read16(&mut cursor) };
    let record_class = unsafe { read16(&mut cursor) };
    unsafe {
        core::ptr::write(core::ptr::addr_of_mut!((*record).record_type), record_type);
        core::ptr::write(core::ptr::addr_of_mut!((*record).record_class), record_class);
        core::ptr::write(core::ptr::addr_of_mut!((*handle).message_cursor), cursor);
    }

    if section != NS_S_QD {
        if NS_INT32SZ + NS_INT16SZ > remaining_bytes(cursor, end_of_message) {
            return unsafe { malformed() };
        }
        let ttl = unsafe { read32(&mut cursor) };
        let rdata_length = unsafe { read16(&mut cursor) };
        unsafe {
            core::ptr::write(core::ptr::addr_of_mut!((*record).ttl), ttl);
            core::ptr::write(
                core::ptr::addr_of_mut!((*record).rdata_length),
                rdata_length,
            );
            core::ptr::write(core::ptr::addr_of_mut!((*handle).message_cursor), cursor);
        }
        if rdata_length as usize > remaining_bytes(cursor, end_of_message) {
            return unsafe { malformed() };
        }
        unsafe {
            core::ptr::write(core::ptr::addr_of_mut!((*record).rdata), cursor);
            cursor = cursor.add(rdata_length as usize);
            core::ptr::write(core::ptr::addr_of_mut!((*handle).message_cursor), cursor);
        }
    } else {
        unsafe {
            core::ptr::write(core::ptr::addr_of_mut!((*record).ttl), 0);
            core::ptr::write(core::ptr::addr_of_mut!((*record).rdata_length), 0);
            core::ptr::write(
                core::ptr::addr_of_mut!((*record).rdata),
                core::ptr::null(),
            );
        }
    }

    let next_record_number = unsafe {
        core::ptr::read(core::ptr::addr_of!((*handle).record_number)).wrapping_add(1)
    };
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!((*handle).record_number),
            next_record_number,
        );
    }
    if next_record_number > count as c_int {
        let next_section = section.wrapping_add(1);
        unsafe {
            core::ptr::write(core::ptr::addr_of_mut!((*handle).section), next_section);
        }
        if next_section == NS_S_MAX {
            unsafe {
                core::ptr::write(core::ptr::addr_of_mut!((*handle).record_number), -1);
                core::ptr::write(
                    core::ptr::addr_of_mut!((*handle).message_cursor),
                    core::ptr::null(),
                );
            }
        } else {
            unsafe {
                core::ptr::write(core::ptr::addr_of_mut!((*handle).record_number), 0);
            }
        }
    }
    0
}

/// Expand one caller-owned DNS name and normalize failure to `EMSGSIZE`.
///
/// # Safety
///
/// `message..end_of_message` must delimit one ordered readable DNS message
/// allocation, `source` must be inside that range or equal to its end, and
/// `destination` must have `destination_size` writable bytes when that size is
/// nonzero. The pointers may not be retained after the call. This function
/// delegates the bounded compression-pointer behavior to the selected
/// [`dn_expand`] provider and changes only the calling thread's `errno` on
/// failure.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn ns_name_uncompress(
    message: *const u8,
    end_of_message: *const u8,
    source: *const u8,
    destination: *mut c_char,
    destination_size: usize,
) -> c_int {
    // musl passes size_t directly to dn_expand's historical int parameter.
    // The explicit cast retains the target C conversion at this ABI boundary.
    let result = unsafe {
        selected_dn_expand(
            message,
            end_of_message,
            source,
            destination,
            destination_size as c_int,
        )
    };
    if result < 0 {
        unsafe { malformed() }
    } else {
        result
    }
}
