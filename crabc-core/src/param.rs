//! Direct Linux/AArch64 process auxiliary-vector reads.
//!
//! Linux does not provide an auxv syscall. This module reads the kernel's
//! fixed-width records from `/proc/self/auxv` through the existing direct
//! `openat`/`read`/`close` seams. It deliberately does not call libc's
//! `getauxval`, which would add a libc-global dependency to the native Rust
//! facade.

const AT_NULL: usize = 0;
const PROC_SELF_AUXV: &[u8] = b"/proc/self/auxv\0";
const AUXV_RECORD_BYTES: usize = 16;

/// `AT_PAGESZ`: the process page size.
pub const AT_PAGESZ: usize = 6;
/// `AT_CLKTCK`: the process clock tick rate.
pub const AT_CLKTCK: usize = 17;
/// `AT_HWCAP`: the architecture hardware-capability bitset.
pub const AT_HWCAP: usize = 16;
/// `AT_HWCAP2`: the secondary hardware-capability bitset.
pub const AT_HWCAP2: usize = 26;
/// `AT_EXECFN`: pointer to the executable pathname string.
pub const AT_EXECFN: usize = 31;
/// `AT_SYSINFO_EHDR`: base address of the kernel-provided vDSO ELF image.
pub const AT_SYSINFO_EHDR: usize = 33;
/// `AT_MINSIGSTKSZ`: the kernel minimum signal-stack size.
pub const AT_MINSIGSTKSZ: usize = 51;

/// Reads one Linux auxv value without libc or TLS `errno`.
///
/// `None` means `/proc/self/auxv` could not be read, the record stream was
/// malformed or truncated, or the requested tag was not present. The caller
/// owns the policy for converting absence into a default value.
#[inline]
pub fn auxv_value(tag: usize) -> Option<usize> {
    // SAFETY: `PROC_SELF_AUXV` is a static, NUL-terminated path and the
    // direct open seam does not retain the pointer after returning.
    let fd = unsafe {
        super::fs::openat_raw(
            super::AT_FDCWD,
            PROC_SELF_AUXV.as_ptr(),
            0,
            0,
        )
    }
    .ok()?;

    let value = read_auxv_value(fd, tag);
    // The descriptor is private to this query. Linux releases it even when
    // the read failed, so no retry is attempted for EINTR here.
    let _ = super::io::close(fd);
    value
}

#[inline]
fn read_auxv_value(fd: super::RawFd, requested_tag: usize) -> Option<usize> {
    let mut record = [0u8; AUXV_RECORD_BYTES];
    let mut filled = 0usize;

    loop {
        let count = super::io::read(fd, &mut record[filled..]).ok()?;
        if count == 0 {
            return None;
        }
        filled += count;
        if filled != AUXV_RECORD_BYTES {
            continue;
        }

        let tag = u64::from_ne_bytes([
            record[0], record[1], record[2], record[3],
            record[4], record[5], record[6], record[7],
        ]) as usize;
        let value = u64::from_ne_bytes([
            record[8], record[9], record[10], record[11],
            record[12], record[13], record[14], record[15],
        ]) as usize;
        if tag == requested_tag {
            return Some(value);
        }
        if tag == AT_NULL {
            return None;
        }
        filled = 0;
    }
}
