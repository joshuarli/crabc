//! Direct Linux 64-bit process auxiliary-vector reads.
//!
//! Linux does not provide an auxv syscall. This module reads the kernel's
//! fixed-width records from `/proc/self/auxv` through the existing direct
//! `openat`/`read`/`close` seams. It deliberately does not call libc's
//! `getauxval`, which would add a libc-global dependency to the native Rust
//! facade.

const AT_NULL: usize = 0;
const PROC_SELF_AUXV: &[u8] = b"/proc/self/auxv\0";
const AUXV_RECORD_BYTES: usize = 16;

#[cfg(target_arch = "x86_64")]
use core::sync::atomic::{AtomicUsize, Ordering};

// Zero means no startup owner has supplied the kernel vDSO base. One means
// the validated initial vector had no usable base. A kernel vDSO address is
// page aligned, so neither state can be confused with a valid base.
#[cfg(target_arch = "x86_64")]
static INITIAL_SYSINFO_EHDR_FOR_VDSO: AtomicUsize = AtomicUsize::new(0);

/// `AT_PAGESZ`: the process page size.
pub const AT_PAGESZ: usize = 6;
/// `AT_CLKTCK`: the process clock tick rate.
pub const AT_CLKTCK: usize = 17;
/// `AT_HWCAP`: the architecture hardware-capability bitset.
pub const AT_HWCAP: usize = 16;
/// `AT_HWCAP2`: the secondary hardware-capability bitset.
pub const AT_HWCAP2: usize = 26;
/// `AT_RANDOM`: pointer-valued tag for the kernel-provided random bytes.
///
/// This module exposes the tag only. [`auxv_value`] may return its raw word,
/// but does not dereference it; startup owners decide whether and when the
/// pointed-to material is valid to read.
pub const AT_RANDOM: usize = 25;
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
    let fd = open_auxv()?;

    let value = read_auxv_value(fd, tag);
    // The descriptor is private to this query. Linux releases it even when
    // the read failed, so no retry is attempted for EINTR here.
    let _ = crate::io::close(fd);
    value
}

/// Supply the process's initial vDSO base to this copy of the core clock
/// dispatcher. The first handoff wins; a later call returns `false` without
/// replacing it. An absent or zero base is retained so clock lookup does not
/// retry `/proc/self/auxv`. Copies without a handoff still read procfs.
///
/// # Safety
///
/// `base` must be absent or the `AT_SYSINFO_EHDR` word from this process's
/// validated, immutable kernel initial auxiliary vector. The startup owner
/// must publish it before other threads can use this core clock dispatcher.
#[cfg(target_arch = "x86_64")]
pub unsafe fn install_initial_sysinfo_ehdr_for_vdso(base: Option<usize>) -> bool {
    install_initial_sysinfo_ehdr_into(&INITIAL_SYSINFO_EHDR_FOR_VDSO, base)
}

#[cfg(target_arch = "x86_64")]
fn install_initial_sysinfo_ehdr_into(state: &AtomicUsize, base: Option<usize>) -> bool {
    let selected = base.filter(|base| *base > 1).unwrap_or(1);
    state.compare_exchange(0, selected, Ordering::Release, Ordering::Relaxed)
        .is_ok()
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn vdso_sysinfo_ehdr() -> Option<usize> {
    let published = INITIAL_SYSINFO_EHDR_FOR_VDSO.load(Ordering::Acquire);
    vdso_sysinfo_ehdr_from_state(published, || auxv_value(AT_SYSINFO_EHDR))
}

#[cfg(target_arch = "x86_64")]
fn vdso_sysinfo_ehdr_from_state(
    state: usize,
    read_proc: impl FnOnce() -> Option<usize>,
) -> Option<usize> {
    match state {
        0 => read_proc(),
        1 => None,
        base => Some(base),
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use super::{install_initial_sysinfo_ehdr_into, vdso_sysinfo_ehdr_from_state};
    use core::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn vdso_handoff_keeps_first_base_and_avoids_procfs() {
        let state = AtomicUsize::new(0);
        assert_eq!(
            vdso_sysinfo_ehdr_from_state(state.load(Ordering::Acquire), || Some(0x4000)),
            Some(0x4000)
        );
        assert!(install_initial_sysinfo_ehdr_into(&state, Some(0x5000)));
        assert!(!install_initial_sysinfo_ehdr_into(&state, None));
        assert_eq!(
            vdso_sysinfo_ehdr_from_state(state.load(Ordering::Acquire), || panic!("reopened procfs")),
            Some(0x5000)
        );
    }

    #[test]
    fn vdso_handoff_keeps_absent_and_zero_base_without_procfs() {
        for base in [None, Some(0)] {
            let state = AtomicUsize::new(0);
            assert!(install_initial_sysinfo_ehdr_into(&state, base));
            assert!(!install_initial_sysinfo_ehdr_into(&state, Some(0x5000)));
            assert_eq!(
                vdso_sysinfo_ehdr_from_state(state.load(Ordering::Acquire), || panic!("reopened procfs")),
                None
            );
        }
    }
}

#[inline]
fn open_auxv() -> Option<crate::RawFd> {
    loop {
        // SAFETY: `PROC_SELF_AUXV` is a static, NUL-terminated path and the
        // direct open seam does not retain the pointer after returning. This
        // query never intentionally transfers its private descriptor across
        // exec, including between this call and the later close.
        match unsafe {
            crate::fs::openat_raw(
                crate::AT_FDCWD,
                PROC_SELF_AUXV.as_ptr(),
                crate::io::O_CLOEXEC as i32,
                0,
            )
        } {
            Ok(fd) => return Some(fd),
            Err(crate::Errno::INTR) => continue,
            Err(_) => return None,
        }
    }
}

#[inline]
fn read_auxv_value(fd: crate::RawFd, requested_tag: usize) -> Option<usize> {
    let mut record = [0u8; AUXV_RECORD_BYTES];
    let mut filled = 0usize;

    loop {
        let count = loop {
            match crate::io::read(fd, &mut record[filled..]) {
                Ok(count) => break count,
                Err(crate::Errno::INTR) => continue,
                Err(_) => return None,
            }
        };
        if count == 0 {
            return None;
        }
        filled += count;
        if filled != AUXV_RECORD_BYTES {
            continue;
        }

        let tag = u64::from_ne_bytes([
            record[0], record[1], record[2], record[3], record[4], record[5], record[6], record[7],
        ]) as usize;
        let value = u64::from_ne_bytes([
            record[8], record[9], record[10], record[11], record[12], record[13], record[14],
            record[15],
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
