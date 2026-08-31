//! Selected static Linux/x86-64 `hasmntopt` C ABI leaf.
//!
//! This leaf owns exactly `hasmntopt(const struct mntent *, const char *)`.
//! It preserves pinned musl 1.2.6's direct caller-owned `mnt_opts` scan from
//! `src/misc/mntent.c`: an option matches only when its bytes begin at a list
//! element and are followed by NUL, `,`, or `=`.  The returned pointer borrows
//! that matching element within the caller's mutable option string; neither
//! the string nor the `struct mntent` is changed.
//!
//! The selected static artifact deliberately implements musl's `strlen`,
//! `strncmp`, and `strchr` composition as local byte loops, preserving the
//! exact mapping without selecting those helper exports or a general string
//! runtime closure. It has no syscall, errno, TLS, allocation, FILE/stdio,
//! mount-table, environment, locale-object, catalog, or parser state. It is
//! not `setmntent`, `endmntent`, `getmntent`, `getmntent_r`, `addmntent`, a
//! mount database, a pathname-policy family, libc.so, CRT, loader, sysroot,
//! Rust facade, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//! `src/misc/mntent.c::hasmntopt` computes `l = strlen(opt)`, tests
//! `!strncmp(p, opt, l) && (!p[l] || p[l]==',' || p[l]=='=')`, then advances
//! with `strchr(p, ',')`. This private leaf retains exactly that scan over the
//! caller's valid NUL-terminated bytes.

use core::ffi::{c_char, c_int};
use core::ptr;

/// The private x86 view of the public `<mntent.h>` record.
///
/// The entry remains caller-owned. Keeping it private prevents this bounded
/// lookup leaf from claiming a general mntent object or mount-table API.
#[repr(C)]
pub struct MntEnt {
    mnt_fsname: *mut c_char,
    mnt_dir: *mut c_char,
    mnt_type: *mut c_char,
    mnt_opts: *mut c_char,
    mnt_freq: c_int,
    mnt_passno: c_int,
}

const _: () = {
    assert!(core::mem::size_of::<MntEnt>() == 40);
    assert!(core::mem::align_of::<MntEnt>() == 8);
    assert!(core::mem::offset_of!(MntEnt, mnt_fsname) == 0);
    assert!(core::mem::offset_of!(MntEnt, mnt_dir) == 8);
    assert!(core::mem::offset_of!(MntEnt, mnt_type) == 16);
    assert!(core::mem::offset_of!(MntEnt, mnt_opts) == 24);
    assert!(core::mem::offset_of!(MntEnt, mnt_freq) == 32);
    assert!(core::mem::offset_of!(MntEnt, mnt_passno) == 36);
};

#[inline(always)]
unsafe fn byte_at(bytes: *const c_char, offset: usize) -> u8 {
    // SAFETY: the exported function retains musl's requirement that callers
    // provide readable NUL-terminated strings for every examined byte. A
    // volatile byte read keeps this selected object from being recognized as
    // a compiler `strlen`/`strncmp` replacement and acquiring their exports.
    unsafe { core::ptr::read_volatile(bytes.wrapping_add(offset)) as u8 }
}

unsafe fn byte_length(bytes: *const c_char) -> usize {
    let mut length = 0;
    while unsafe { byte_at(bytes, length) } != 0 {
        length = length.wrapping_add(1);
    }
    length
}

unsafe fn prefix_matches(option_list: *const c_char, option: *const c_char, length: usize) -> bool {
    let mut offset = 0;
    while offset < length {
        let list_byte = unsafe { byte_at(option_list, offset) };
        let option_byte = unsafe { byte_at(option, offset) };
        if list_byte != option_byte {
            return false;
        }
        // Match strncmp's stop-at-NUL behavior: a shorter list element must
        // reject a longer requested option without examining bytes after its
        // NUL terminator.
        if list_byte == 0 {
            return true;
        }
        offset = offset.wrapping_add(1);
    }
    true
}

/// Find one whole option in a caller-owned comma-separated mount option list.
///
/// # Safety
///
/// `mount_entry` must point to a readable x86 `<mntent.h>`-layout record whose
/// `mnt_opts` field points to readable NUL-terminated bytes. `option` must
/// likewise point to readable NUL-terminated bytes. The returned pointer, if
/// non-null, borrows `mnt_opts`; callers retain the record and byte storage for
/// its use. Invalid pointers retain musl's undefined behavior.
#[no_mangle]
pub unsafe extern "C" fn hasmntopt(
    mount_entry: *const MntEnt,
    option: *const c_char,
) -> *mut c_char {
    let option_length = unsafe { byte_length(option) };
    // SAFETY: the caller supplies the public `struct mntent` representation.
    // Read the fixed pointer slot directly rather than forming a Rust place
    // from an untrusted C pointer: that keeps musl's caller-validity contract
    // and prevents a freestanding panic-runtime dependency for null or
    // misaligned invalid inputs, which remain undefined exactly as in musl.
    let options_slot = mount_entry
        .cast::<u8>()
        .wrapping_add(core::mem::offset_of!(MntEnt, mnt_opts))
        .cast::<*mut c_char>();
    let mut cursor = unsafe { core::ptr::read_unaligned(options_slot) };

    loop {
        if unsafe { prefix_matches(cursor, option, option_length) } {
            let boundary = unsafe { byte_at(cursor, option_length) };
            if boundary == 0 || boundary == b',' || boundary == b'=' {
                return cursor;
            }
        }

        loop {
            let current = unsafe { byte_at(cursor, 0) };
            if current == 0 {
                return ptr::null_mut();
            }
            // SAFETY: `current != 0`, so the caller's NUL-terminated list has
            // at least this next byte. The outer loop performs musl's `p++`
            // only after a comma.
            cursor = cursor.wrapping_add(1);
            if current == b',' {
                break;
            }
        }
    }
}
