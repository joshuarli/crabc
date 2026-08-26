//! Bounded Linux vDSO discovery for hot clock reads on supported 64-bit targets.
//!
//! The kernel owns the `AT_SYSINFO_EHDR` mapping for the lifetime of a
//! process. This module reads that immutable ELF image once, validates the
//! metadata needed for `clock_gettime`, and caches only the resolved function
//! address. A failed lookup is cached as well: malformed or unavailable vDSO
//! metadata must leave every caller on the ordinary direct-syscall path rather
//! than repeatedly reading `/proc/self/auxv`.
//!
//! `crabc-core` can be linked into both `libc.so` and a direct `crabc-rs`
//! application. Each copy may therefore hold a cache entry, but every entry
//! denotes the same kernel-owned, process-lifetime mapping; no mutable libc or
//! loader state is shared or inferred here.

use core::mem;
use core::sync::atomic::{AtomicUsize, Ordering};

const ELF_HEADER_BYTES: usize = 64;
const ELF_PROGRAM_HEADER_BYTES: usize = 56;
const ELF_SYMBOL_BYTES: usize = 24;
const ELF_DYNAMIC_BYTES: usize = 16;
const MAX_PROGRAM_HEADERS: usize = 128;
const MAX_IMAGE_BYTES: usize = 1 << 20;

const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ELF_ET_DYN: u16 = 3;
const ELF_EM_X86_64: u16 = 62;
const ELF_EM_AARCH64: u16 = 183;
#[cfg(target_arch = "aarch64")]
const SUPPORTED_ELF_MACHINE: u16 = ELF_EM_AARCH64;
#[cfg(target_arch = "x86_64")]
const SUPPORTED_ELF_MACHINE: u16 = ELF_EM_X86_64;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const STT_FUNC: u8 = 2;

const DT_NULL: u64 = 0;
const DT_HASH: u64 = 4;
const DT_STRTAB: u64 = 5;
const DT_SYMTAB: u64 = 6;
const DT_STRSZ: u64 = 10;
const DT_SYMENT: u64 = 11;

const UNRESOLVED: usize = 0;

type ClockGettime = unsafe extern "C" fn(i32, *mut u8) -> i32;
type Gettimeofday = unsafe extern "C" fn(*mut u8, *mut u8) -> i32;

static CLOCK_GETTIME: AtomicUsize = AtomicUsize::new(UNRESOLVED);
static GETTIMEOFDAY: AtomicUsize = AtomicUsize::new(UNRESOLVED);

#[derive(Copy, Clone)]
struct ProgramHeaderTable {
    offset: usize,
    entry_size: usize,
    count: usize,
}

/// Calls the resolved vDSO entry point or the direct-syscall fallback.
///
/// The returned value is the Linux kernel convention: zero on success or a
/// negative errno. Absent or malformed metadata is cached as the typed direct
/// syscall function, so the hot path has one pointer load and one indirect
/// call. The target vDSO owns any direct-syscall fallback for a clock ID it
/// cannot serve from its data page, so this route may invoke the validated
/// target entry for every public Linux clock ID without a duplicate user-space
/// eligibility screen.
///
/// # Safety
///
/// `timespec` must be writable for one target Linux `struct timespec`.
#[inline(always)]
pub(crate) unsafe fn clock_gettime_status(clock_id: i32, timespec: *mut u8) -> i32 {
    // The cache is a single immutable function address. It protects no
    // associated mutable data, so a relaxed load is sufficient and avoids
    // putting an acquire barrier in every clock read.
    let cached = CLOCK_GETTIME.load(Ordering::Relaxed);
    if cached == UNRESOLVED {
        // SAFETY: The cold path publishes a validated kernel-vDSO function or
        // this module's direct syscall fallback before invoking it.
        return unsafe { resolve_and_call_clock_gettime(clock_id, timespec) };
    }

    // SAFETY: Every nonzero cache value was published by
    // `resolve_and_publish_clock_gettime`.
    let function = unsafe { published_clock_gettime_function(cached) };
    // SAFETY: The caller owns the Linux timespec output contract.
    unsafe { dispatch_clock_gettime(function, clock_id, timespec) }
}

/// Calls the target Linux `__vdso_gettimeofday` or `__kernel_gettimeofday`
/// vDSO entry when its bounded ELF metadata validates, otherwise uses the
/// direct syscall. The vDSO ABI is the kernel's two-pointer
/// `timeval`/timezone form and returns zero or a negative errno.
///
/// # Safety
///
/// `timeval` must be null or writable for one target Linux `struct timeval`;
/// `timezone` is passed through under the kernel ABI.
#[inline(always)]
pub(crate) unsafe fn gettimeofday_status(timeval: *mut u8, timezone: *mut u8) -> i32 {
    let cached = GETTIMEOFDAY.load(Ordering::Relaxed);
    let address = if cached == UNRESOLVED {
        let selected = select_gettimeofday(crate::param::auxv_value(crate::param::AT_SYSINFO_EHDR));
        let selected = selected as *const () as usize;
        match GETTIMEOFDAY.compare_exchange(
            UNRESOLVED,
            selected,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => selected,
            Err(existing) => existing,
        }
    } else {
        cached
    };
    // SAFETY: `GETTIMEOFDAY` accepts only values that have already passed
    // `validated_gettimeofday_function` or `direct_gettimeofday`.
    let function = unsafe { published_gettimeofday_function(address) };
    // SAFETY: the caller owns the kernel two-pointer output contract.
    unsafe { function(timeval, timezone) }
}

#[inline(always)]
unsafe fn dispatch_clock_gettime(function: ClockGettime, clock_id: i32, timespec: *mut u8) -> i32 {
    // SAFETY: The typed function address comes from the validated vDSO and
    // the caller owns the Linux timespec output contract.
    unsafe { function(clock_id, timespec) }
}

#[cold]
#[inline(never)]
unsafe fn resolve_and_call_clock_gettime(clock_id: i32, timespec: *mut u8) -> i32 {
    let function = resolve_and_publish_clock_gettime();
    // SAFETY: The caller owns the Linux timespec output contract.
    unsafe { dispatch_clock_gettime(function, clock_id, timespec) }
}

#[cold]
#[inline(never)]
fn resolve_and_publish_clock_gettime() -> ClockGettime {
    let resolved = select_clock_gettime(crate::param::auxv_value(crate::param::AT_SYSINFO_EHDR));
    let resolved = resolved as *const () as usize;
    let published = match CLOCK_GETTIME.compare_exchange(
        UNRESOLVED,
        resolved,
        Ordering::Relaxed,
        Ordering::Relaxed,
    ) {
        Ok(_) => resolved,
        Err(existing) => existing,
    };

    // SAFETY: See the corresponding cached branch above. The cache contains
    // only validated vDSO code addresses or `direct_clock_gettime`.
    unsafe { published_clock_gettime_function(published) }
}

#[inline]
unsafe fn validated_clock_gettime_function(address: usize) -> Option<ClockGettime> {
    if address == UNRESOLVED || address & 3 != 0 {
        return None;
    }
    // SAFETY: This conversion is used only for a function address validated
    // from the target kernel vDSO symbol table.
    Some(unsafe { mem::transmute::<usize, ClockGettime>(address) })
}

#[inline]
unsafe fn validated_gettimeofday_function(address: usize) -> Option<Gettimeofday> {
    if address == UNRESOLVED || address & 3 != 0 {
        return None;
    }
    // SAFETY: This conversion is used only for a function address validated
    // from the target kernel vDSO symbol table.
    Some(unsafe { mem::transmute::<usize, Gettimeofday>(address) })
}

#[inline(always)]
unsafe fn published_clock_gettime_function(address: usize) -> ClockGettime {
    debug_assert_ne!(address, UNRESOLVED);
    // SAFETY: `CLOCK_GETTIME` accepts only values that have already passed
    // `validated_clock_gettime_function` or `direct_clock_gettime`.
    unsafe { mem::transmute::<usize, ClockGettime>(address) }
}

#[inline(always)]
unsafe fn published_gettimeofday_function(address: usize) -> Gettimeofday {
    debug_assert_ne!(address, UNRESOLVED);
    // SAFETY: `GETTIMEOFDAY` accepts only values that have already passed
    // `validated_gettimeofday_function` or `direct_gettimeofday`.
    unsafe { mem::transmute::<usize, Gettimeofday>(address) }
}

unsafe extern "C" fn direct_clock_gettime(clock_id: i32, timespec: *mut u8) -> i32 {
    // SAFETY: The caller owns the writable Linux timespec output contract.
    (unsafe {
        crate::syscall::syscall2(
            crate::syscall::SYS_CLOCK_GETTIME,
            clock_id as usize,
            timespec as usize,
        )
    }) as i32
}

unsafe extern "C" fn direct_gettimeofday(timeval: *mut u8, timezone: *mut u8) -> i32 {
    // SAFETY: the caller owns the kernel two-pointer output contract.
    (unsafe {
        crate::syscall::syscall2(
            crate::syscall::SYS_GETTIMEOFDAY,
            timeval as usize,
            timezone as usize,
        )
    })
        as i32
}

#[inline]
fn select_clock_gettime(base: Option<usize>) -> ClockGettime {
    base.and_then(|base| unsafe { resolve_kernel_clock_gettime(base) })
        .and_then(|address| unsafe { validated_clock_gettime_function(address) })
        .unwrap_or(direct_clock_gettime)
}

#[inline]
fn select_gettimeofday(base: Option<usize>) -> Gettimeofday {
    base.and_then(|base| unsafe { resolve_kernel_gettimeofday(base) })
        .and_then(|address| unsafe { validated_gettimeofday_function(address) })
        .unwrap_or(direct_gettimeofday)
}

/// Resolves the live kernel vDSO without assigning arbitrary caller memory a
/// `'static` lifetime. The kernel supplies this base through auxv and keeps
/// the mapping live until process exit.
unsafe fn resolve_kernel_clock_gettime(base: usize) -> Option<usize> {
    // SAFETY: `base` originates from the kernel aux vector in the caller.
    unsafe { resolve_kernel_vdso_function(base, clock_gettime_symbol_offset) }
}

unsafe fn resolve_kernel_gettimeofday(base: usize) -> Option<usize> {
    // SAFETY: `base` originates from the kernel aux vector in the caller.
    unsafe { resolve_kernel_vdso_function(base, gettimeofday_symbol_offset) }
}

unsafe fn resolve_kernel_vdso_function(
    base: usize,
    symbol_offset: fn(&[u8]) -> Option<usize>,
) -> Option<usize> {
    if base == 0 || base & 3 != 0 {
        return None;
    }
    // SAFETY: `AT_SYSINFO_EHDR` is a kernel-owned pointer to at least the ELF
    // header. We bound all subsequent reads before interpreting metadata.
    let header = unsafe { core::slice::from_raw_parts(base as *const u8, ELF_HEADER_BYTES) };
    let table = program_header_table(header)?;
    let table_bytes = table.entry_size.checked_mul(table.count)?;
    let table_end = table.offset.checked_add(table_bytes)?;
    if table_end > MAX_IMAGE_BYTES {
        return None;
    }

    // SAFETY: The kernel vDSO's program-header table is part of the same
    // mapping. `table_end` is capped before the read and later metadata is
    // bounded against the image length derived from PT_LOAD records.
    let headers = unsafe { core::slice::from_raw_parts(base as *const u8, table_end) };
    let image_length = image_length(headers, table)?;
    // SAFETY: `image_length` is derived from the kernel vDSO's PT_LOAD file
    // ranges and capped at one MiB before creating this slice.
    let image = unsafe { core::slice::from_raw_parts(base as *const u8, image_length) };
    let offset = symbol_offset(image)?;
    let address = base.checked_add(offset)?;
    (address != UNRESOLVED && address & 3 == 0).then_some(address)
}

fn clock_gettime_symbol_offset(image: &[u8]) -> Option<usize> {
    vdso_symbol_offset(image, &[b"__vdso_clock_gettime", b"__kernel_clock_gettime"])
}

fn gettimeofday_symbol_offset(image: &[u8]) -> Option<usize> {
    vdso_symbol_offset(
        image,
        &[b"__vdso_gettimeofday", b"__kernel_gettimeofday"],
    )
}

/// Resolve one of `names` from the bounded kernel vDSO image.
///
/// Every candidate must be a function inside an executable `PT_LOAD` range;
/// callers separately validate the resulting address against their ABI.
fn vdso_symbol_offset(image: &[u8], names: &[&[u8]]) -> Option<usize> {
    let table = program_header_table(image)?;
    let table_bytes = table.entry_size.checked_mul(table.count)?;
    range_within(image.len(), table.offset, table_bytes)?;

    let (dynamic_address, dynamic_size) = dynamic_segment(image, table)?;
    let dynamic_offset = virtual_range_to_file(image, table, dynamic_address, dynamic_size)?;
    let dynamic = image.get(dynamic_offset..dynamic_offset.checked_add(dynamic_size)?)?;

    let mut string_address = None;
    let mut string_size = None;
    let mut symbol_address = None;
    let mut symbol_size = None;
    let mut hash_address = None;
    let mut terminated = false;

    for entry in dynamic.chunks_exact(ELF_DYNAMIC_BYTES) {
        let tag = read_u64(entry, 0)?;
        let value = read_u64(entry, 8)? as usize;
        match tag {
            DT_NULL => {
                terminated = true;
                break;
            }
            DT_STRTAB => string_address = Some(value),
            DT_STRSZ => string_size = Some(value),
            DT_SYMTAB => symbol_address = Some(value),
            DT_SYMENT => symbol_size = Some(value),
            DT_HASH => hash_address = Some(value),
            _ => {}
        }
    }
    if !terminated || symbol_size != Some(ELF_SYMBOL_BYTES) {
        return None;
    }

    let strings = file_range_at_virtual(image, table, string_address?, string_size?)?;
    let hash_offset = virtual_range_to_file(image, table, hash_address?, 8)?;
    let bucket_count = read_u32(image, hash_offset)? as usize;
    let symbol_count = read_u32(image, hash_offset.checked_add(4)?)? as usize;
    if bucket_count == 0 || symbol_count == 0 {
        return None;
    }

    let bucket_bytes = bucket_count.checked_mul(4)?;
    let chain_bytes = symbol_count.checked_mul(4)?;
    let hash_bytes = 8usize.checked_add(bucket_bytes)?.checked_add(chain_bytes)?;
    let hash = file_range_at_virtual(image, table, hash_address?, hash_bytes)?;
    let symbol_bytes = symbol_count.checked_mul(ELF_SYMBOL_BYTES)?;
    let symbols = file_range_at_virtual(image, table, symbol_address?, symbol_bytes)?;

    let symbol = names.iter().find_map(|name| {
        lookup_sysv_symbol(hash, symbols, strings, name, bucket_count, symbol_count)
    })?;
    executable_virtual_range_to_file(image, table, symbol, 4).map(|_| symbol)
}

fn program_header_table(image: &[u8]) -> Option<ProgramHeaderTable> {
    if image.len() < ELF_HEADER_BYTES
        || image.get(0..4)? != b"\x7fELF"
        || image[4] != ELFCLASS64
        || image[5] != ELFDATA2LSB
        || image[6] != 1
        || read_u16(image, 16)? != ELF_ET_DYN
        || read_u16(image, 18)? != SUPPORTED_ELF_MACHINE
        || read_u32(image, 20)? != 1
        || read_u16(image, 52)? as usize != ELF_HEADER_BYTES
        || read_u16(image, 54)? as usize != ELF_PROGRAM_HEADER_BYTES
    {
        return None;
    }

    let offset = read_u64(image, 32)? as usize;
    let count = read_u16(image, 56)? as usize;
    if count == 0 || count > MAX_PROGRAM_HEADERS {
        return None;
    }
    let bytes = ELF_PROGRAM_HEADER_BYTES.checked_mul(count)?;
    let end = offset.checked_add(bytes)?;
    if end > MAX_IMAGE_BYTES {
        return None;
    }
    Some(ProgramHeaderTable {
        offset,
        entry_size: ELF_PROGRAM_HEADER_BYTES,
        count,
    })
}

fn image_length(image: &[u8], table: ProgramHeaderTable) -> Option<usize> {
    let mut length = table
        .offset
        .checked_add(table.entry_size.checked_mul(table.count)?)?;
    for index in 0..table.count {
        let header = program_header(image, table, index)?;
        if read_u32(header, 0)? != PT_LOAD {
            continue;
        }
        let offset = read_u64(header, 8)? as usize;
        let size = read_u64(header, 32)? as usize;
        length = length.max(offset.checked_add(size)?);
    }
    if length < ELF_HEADER_BYTES || length > MAX_IMAGE_BYTES {
        return None;
    }
    Some(length)
}

fn dynamic_segment(image: &[u8], table: ProgramHeaderTable) -> Option<(usize, usize)> {
    for index in 0..table.count {
        let header = program_header(image, table, index)?;
        if read_u32(header, 0)? != PT_DYNAMIC {
            continue;
        }
        let address = read_u64(header, 16)? as usize;
        let size = read_u64(header, 32)? as usize;
        if size == 0 || size % ELF_DYNAMIC_BYTES != 0 {
            return None;
        }
        return Some((address, size));
    }
    None
}

fn program_header<'a>(
    image: &'a [u8],
    table: ProgramHeaderTable,
    index: usize,
) -> Option<&'a [u8]> {
    if index >= table.count {
        return None;
    }
    let offset = table
        .offset
        .checked_add(table.entry_size.checked_mul(index)?)?;
    image.get(offset..offset.checked_add(table.entry_size)?)
}

fn file_range_at_virtual<'a>(
    image: &'a [u8],
    table: ProgramHeaderTable,
    address: usize,
    length: usize,
) -> Option<&'a [u8]> {
    let offset = virtual_range_to_file(image, table, address, length)?;
    image.get(offset..offset.checked_add(length)?)
}

fn virtual_range_to_file(
    image: &[u8],
    table: ProgramHeaderTable,
    address: usize,
    length: usize,
) -> Option<usize> {
    virtual_range_to_file_with_permissions(image, table, address, length, false)
}

fn executable_virtual_range_to_file(
    image: &[u8],
    table: ProgramHeaderTable,
    address: usize,
    length: usize,
) -> Option<usize> {
    virtual_range_to_file_with_permissions(image, table, address, length, true)
}

fn virtual_range_to_file_with_permissions(
    image: &[u8],
    table: ProgramHeaderTable,
    address: usize,
    length: usize,
    executable: bool,
) -> Option<usize> {
    for index in 0..table.count {
        let header = program_header(image, table, index)?;
        if read_u32(header, 0)? != PT_LOAD {
            continue;
        }
        if executable && read_u32(header, 4)? & 1 == 0 {
            continue;
        }
        let virtual_start = read_u64(header, 16)? as usize;
        let file_offset = read_u64(header, 8)? as usize;
        let file_size = read_u64(header, 32)? as usize;
        let delta = match address.checked_sub(virtual_start) {
            Some(delta) => delta,
            None => continue,
        };
        if delta > file_size || length > file_size - delta {
            continue;
        }
        let offset = file_offset.checked_add(delta)?;
        range_within(image.len(), offset, length)?;
        return Some(offset);
    }
    None
}

fn lookup_sysv_symbol(
    hash: &[u8],
    symbols: &[u8],
    strings: &[u8],
    requested: &[u8],
    bucket_count: usize,
    symbol_count: usize,
) -> Option<usize> {
    let hash_value = elf_hash(requested);
    let bucket_offset = 8usize.checked_add((hash_value as usize % bucket_count).checked_mul(4)?)?;
    let mut index = read_u32(hash, bucket_offset)? as usize;
    let chain_start = 8usize.checked_add(bucket_count.checked_mul(4)?)?;

    for _ in 0..symbol_count {
        if index == 0 {
            return None;
        }
        if index >= symbol_count {
            return None;
        }
        let symbol_offset = index.checked_mul(ELF_SYMBOL_BYTES)?;
        let symbol = symbols.get(symbol_offset..symbol_offset.checked_add(ELF_SYMBOL_BYTES)?)?;
        let name_offset = read_u32(symbol, 0)? as usize;
        let symbol_type = symbol[4] & 0x0f;
        let section_index = read_u16(symbol, 6)?;
        let value = read_u64(symbol, 8)? as usize;
        if symbol_type == STT_FUNC
            && section_index != 0
            && value != 0
            && string_equals(strings, name_offset, requested)
        {
            return Some(value);
        }
        let chain_offset = chain_start.checked_add(index.checked_mul(4)?)?;
        index = read_u32(hash, chain_offset)? as usize;
    }
    None
}

#[inline]
fn string_equals(strings: &[u8], offset: usize, expected: &[u8]) -> bool {
    let Some(value) = strings.get(offset..) else {
        return false;
    };
    let Some(end) = value.iter().position(|byte| *byte == 0) else {
        return false;
    };
    value.get(..end) == Some(expected)
}

#[inline]
fn elf_hash(name: &[u8]) -> u32 {
    let mut hash = 0u32;
    for byte in name {
        hash = hash.wrapping_shl(4).wrapping_add(*byte as u32);
        let high = hash & 0xf000_0000;
        if high != 0 {
            hash ^= high >> 24;
        }
        hash &= !high;
    }
    hash
}

#[inline]
fn range_within(total: usize, offset: usize, length: usize) -> Option<()> {
    (offset.checked_add(length)? <= total).then_some(())
}

#[inline]
fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let bytes = bytes.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

#[inline]
fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let bytes = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

#[inline]
fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let bytes = bytes.get(offset..offset.checked_add(8)?)?;
    Some(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

#[cfg(test)]
mod tests {
    use super::{
        clock_gettime_symbol_offset, direct_gettimeofday, dispatch_clock_gettime,
        gettimeofday_symbol_offset, resolve_kernel_clock_gettime, resolve_kernel_gettimeofday,
        select_clock_gettime, select_gettimeofday, ClockGettime, Gettimeofday,
    };
    use crate::param;

    #[repr(C)]
    struct Timespec {
        seconds: i64,
        nanoseconds: i64,
    }

    #[repr(C)]
    struct Timeval {
        seconds: i64,
        microseconds: i64,
    }

    #[test]
    fn resolves_a_bounded_sysv_clock_symbol() {
        let image = synthetic_vdso();
        assert_eq!(clock_gettime_symbol_offset(&image), Some(448));
    }

    #[test]
    fn resolves_a_bounded_sysv_gettimeofday_symbol() {
        let image = synthetic_vdso_for_symbol(b"__kernel_gettimeofday");
        assert_eq!(gettimeofday_symbol_offset(&image), Some(448));

        let image = synthetic_vdso_for_symbol(b"__vdso_gettimeofday");
        assert_eq!(gettimeofday_symbol_offset(&image), Some(448));

        let mut image = synthetic_vdso_for_symbol(b"__kernel_gettimeofday");
        put_u64(&mut image, 384 + 24 + 8, 512);
        assert_eq!(gettimeofday_symbol_offset(&image), None);
    }

    #[test]
    fn rejects_a_foreign_elf_machine() {
        let mut image = synthetic_vdso();
        let foreign_machine = if super::SUPPORTED_ELF_MACHINE == super::ELF_EM_AARCH64 {
            super::ELF_EM_X86_64
        } else {
            super::ELF_EM_AARCH64
        };
        put_u16(&mut image, 18, foreign_machine);

        assert_eq!(clock_gettime_symbol_offset(&image), None);
    }

    #[test]
    fn rejects_malformed_or_unterminated_vdso_metadata() {
        let mut image = synthetic_vdso();
        image[5] = 2;
        assert_eq!(clock_gettime_symbol_offset(&image), None);

        let mut image = synthetic_vdso();
        put_u64(&mut image, 176 + 8, 960);
        assert_eq!(clock_gettime_symbol_offset(&image), None);

        let mut image = synthetic_vdso();
        put_u64(&mut image, 176 + 5 * 16, 5);
        assert_eq!(clock_gettime_symbol_offset(&image), None);

        let mut image = synthetic_vdso();
        put_u64(&mut image, 384 + 24 + 8, 512);
        assert_eq!(clock_gettime_symbol_offset(&image), None);
    }

    #[test]
    fn missing_vdso_metadata_selects_the_direct_syscall_fallback() {
        let mut output = Timespec {
            seconds: 0,
            nanoseconds: 0,
        };
        let fallback = select_clock_gettime(None);
        assert_eq!(
            unsafe { dispatch_clock_gettime(fallback, 1, (&mut output as *mut Timespec).cast()) },
            0,
        );
        assert!(output.seconds >= 0);
        assert!((0..1_000_000_000).contains(&output.nanoseconds));
    }

    #[test]
    fn missing_gettimeofday_metadata_selects_the_direct_syscall_fallback() {
        let fallback = select_gettimeofday(None);
        assert_eq!(fallback as usize, direct_gettimeofday as *const () as usize);

        let mut output = Timeval {
            seconds: 0,
            microseconds: 0,
        };
        assert_eq!(
            unsafe { fallback((&mut output as *mut Timeval).cast(), core::ptr::null_mut()) },
            0,
        );
        assert!(output.seconds >= 0);
        assert!((0..1_000_000).contains(&output.microseconds));
    }

    #[test]
    fn accepted_vdso_result_and_errno_keep_kernel_semantics() {
        let mut output = Timespec {
            seconds: 0,
            nanoseconds: 0,
        };
        assert_eq!(
            unsafe {
                dispatch_clock_gettime(vdso_success, 1, (&mut output as *mut Timespec).cast())
            },
            0,
        );
        assert_eq!((output.seconds, output.nanoseconds), (7, 9));
        assert_eq!(
            unsafe {
                dispatch_clock_gettime(vdso_einval, 1, (&mut output as *mut Timespec).cast())
            },
            -22,
        );
    }

    #[test]
    fn live_kernel_vdso_resolves_and_accepts_monotonic_time() {
        let base = param::auxv_value(param::AT_SYSINFO_EHDR)
            .expect("Linux supplies AT_SYSINFO_EHDR for the vDSO");
        let address = unsafe {
            resolve_kernel_clock_gettime(base).expect("vDSO exports a bounded clock_gettime entry")
        };
        let function: ClockGettime = unsafe { core::mem::transmute(address) };
        let mut output = Timespec {
            seconds: 0,
            nanoseconds: 0,
        };
        let result = unsafe { function(1, (&mut output as *mut Timespec).cast()) };
        assert_eq!(result, 0);
        assert!(output.seconds >= 0);
        assert!((0..1_000_000_000).contains(&output.nanoseconds));
    }

    #[test]
    fn live_kernel_vdso_resolves_and_accepts_realtime() {
        let base = param::auxv_value(param::AT_SYSINFO_EHDR)
            .expect("Linux supplies AT_SYSINFO_EHDR for the vDSO");
        let address = unsafe {
            resolve_kernel_gettimeofday(base).expect("vDSO exports a bounded gettimeofday entry")
        };
        let function: Gettimeofday = unsafe { core::mem::transmute(address) };
        let mut output = Timeval {
            seconds: 0,
            microseconds: 0,
        };
        let result =
            unsafe { function((&mut output as *mut Timeval).cast(), core::ptr::null_mut()) };
        assert_eq!(result, 0);
        assert!(output.seconds > 0);
        assert!((0..1_000_000).contains(&output.microseconds));
    }

    unsafe extern "C" fn vdso_success(_clock: i32, output: *mut u8) -> i32 {
        unsafe {
            output.cast::<Timespec>().write(Timespec {
                seconds: 7,
                nanoseconds: 9,
            });
        }
        0
    }

    unsafe extern "C" fn vdso_einval(_clock: i32, _output: *mut u8) -> i32 {
        -22
    }

    fn synthetic_vdso() -> [u8; 512] {
        synthetic_vdso_for_symbol(b"__vdso_clock_gettime")
    }

    fn synthetic_vdso_for_symbol(name: &[u8]) -> [u8; 512] {
        assert!(
            name.len() <= 22,
            "synthetic string table is intentionally bounded"
        );
        let mut image = [0u8; 512];
        image[..4].copy_from_slice(b"\x7fELF");
        image[4] = 2;
        image[5] = 1;
        image[6] = 1;
        put_u16(&mut image, 16, 3);
        put_u16(&mut image, 18, super::SUPPORTED_ELF_MACHINE);
        put_u32(&mut image, 20, 1);
        put_u64(&mut image, 32, 64);
        put_u16(&mut image, 52, 64);
        put_u16(&mut image, 54, 56);
        put_u16(&mut image, 56, 2);

        // PT_LOAD covers the complete synthetic image.
        put_u32(&mut image, 64, 1);
        put_u32(&mut image, 64 + 4, 5);
        put_u64(&mut image, 64 + 8, 0);
        put_u64(&mut image, 64 + 16, 0);
        put_u64(&mut image, 64 + 32, 512);

        // PT_DYNAMIC points at six exact Elf64_Dyn entries.
        put_u32(&mut image, 120, 2);
        put_u64(&mut image, 120 + 8, 176);
        put_u64(&mut image, 120 + 16, 176);
        put_u64(&mut image, 120 + 32, 6 * 16);

        put_dynamic(&mut image, 176, 5, 320); // DT_STRTAB
        put_dynamic(&mut image, 192, 10, (name.len() + 2) as u64); // DT_STRSZ
        put_dynamic(&mut image, 208, 6, 384); // DT_SYMTAB
        put_dynamic(&mut image, 224, 11, 24); // DT_SYMENT
        put_dynamic(&mut image, 240, 4, 280); // DT_HASH
        put_dynamic(&mut image, 256, 0, 0); // DT_NULL

        // SysV hash: one bucket, two symbols, with symbol one in bucket zero.
        put_u32(&mut image, 280, 1);
        put_u32(&mut image, 284, 2);
        put_u32(&mut image, 288, 1);
        put_u32(&mut image, 292, 0);
        put_u32(&mut image, 296, 0);

        image[321..321 + name.len()].copy_from_slice(name);
        put_u32(&mut image, 384 + 24, 1);
        image[384 + 24 + 4] = 2;
        put_u16(&mut image, 384 + 24 + 6, 1);
        put_u64(&mut image, 384 + 24 + 8, 448);
        image
    }

    fn put_dynamic(image: &mut [u8], offset: usize, tag: u64, value: u64) {
        put_u64(image, offset, tag);
        put_u64(image, offset + 8, value);
    }

    fn put_u16(image: &mut [u8], offset: usize, value: u16) {
        image[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(image: &mut [u8], offset: usize, value: u32) {
        image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(image: &mut [u8], offset: usize, value: u64) {
        image[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
}
