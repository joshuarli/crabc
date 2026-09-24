//! Miri-only model of the Linux kernel boundary.
//!
//! Miri cannot execute the `syscall` instruction or read `%fs:0`. Under
//! `cfg(miri)` the raw syscall functions dispatch to [`syscall`] instead, and
//! the few typed seams that return a pointer or write through a caller pointer
//! call the matching typed functions here so no pointer is ever reconstructed
//! from an integer. Every allocation-bearing effect is therefore ordinary
//! Miri-tracked memory with real provenance.
//!
//! This is a verification instrument, not a host backend. It models private
//! anonymous mappings (backed by Miri heap allocations with per-page mapped
//! state and `MADV_DONTNEED` zeroing), deterministic clocks, identities, and
//! entropy, and returns `ENOSYS` for every other call. It does not model page
//! protection faults, file systems, RSS, NUMA placement, signals, or process
//! lifetime; evidence must not infer any of those from it. The entropy stream
//! is a fixed test sequence and must never feed a security decision.
//!
//! Nothing here is compiled without `cfg(miri)`.

extern crate alloc;

use alloc::alloc::{alloc_zeroed, dealloc, Layout};
use core::cell::{Cell, UnsafeCell};
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};

use crate::{Errno, Result};

const PAGE: usize = 4096;
const MAX_MAPPINGS: usize = 256;

const ENOENT: isize = 2;
const EBADF: isize = 9;
const EAGAIN: isize = 11;
const ENOMEM: isize = 12;
const EINVAL: isize = 22;
const ENOSYS: isize = 38;

const MAP_FIXED: u32 = 0x10;
const MAP_ANONYMOUS: u32 = 0x20;
const MAP_FIXED_NOREPLACE: u32 = 0x10_0000;
const MADV_DONTNEED: usize = 4;

/// One live model mapping. `base` keeps the allocation's provenance; every
/// model write into mapped memory is derived from it.
#[derive(Clone, Copy)]
struct Mapping {
    base: *mut u8,
    pages: usize,
    /// One bit per page: set when the page has been unmapped.
    unmapped: *mut u8,
    unmapped_count: usize,
}

impl Mapping {
    fn start(&self) -> usize {
        self.base.addr()
    }

    fn end(&self) -> usize {
        self.start() + self.pages * PAGE
    }

    fn page_unmapped(&self, page: usize) -> bool {
        // SAFETY: `unmapped` holds `pages.div_ceil(8)` bytes and `page` is in range.
        unsafe { *self.unmapped.add(page / 8) & (1 << (page % 8)) != 0 }
    }

    fn set_page(&mut self, page: usize, unmapped: bool) {
        // SAFETY: as in `page_unmapped`.
        let byte = unsafe { &mut *self.unmapped.add(page / 8) };
        let bit = 1u8 << (page % 8);
        let was = *byte & bit != 0;
        if unmapped && !was {
            *byte |= bit;
            self.unmapped_count += 1;
        } else if !unmapped && was {
            *byte &= !bit;
            self.unmapped_count -= 1;
        }
    }
}

struct Table {
    busy: AtomicBool,
    entries: UnsafeCell<[Option<Mapping>; MAX_MAPPINGS]>,
}

// SAFETY: `entries` is only accessed while `busy` is held by `with_table`.
unsafe impl Sync for Table {}

static TABLE: Table = Table {
    busy: AtomicBool::new(false),
    entries: UnsafeCell::new([None; MAX_MAPPINGS]),
};

fn with_table<R>(operation: impl FnOnce(&mut [Option<Mapping>; MAX_MAPPINGS]) -> R) -> R {
    while TABLE
        .busy
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    // SAFETY: the spin lock above grants exclusive access until release.
    let result = operation(unsafe { &mut *TABLE.entries.get() });
    TABLE.busy.store(false, Ordering::Release);
    result
}

/// Returns the mapping and first page index for `[address, address + length)`
/// when that range lies inside one mapping.
fn containing(
    entries: &mut [Option<Mapping>; MAX_MAPPINGS],
    address: usize,
    length: usize,
) -> Option<(&mut Mapping, usize, usize)> {
    let end = address.checked_add(length)?;
    entries.iter_mut().flatten().find_map(|mapping| {
        (mapping.start() <= address && end <= mapping.end()).then(|| {
            let first = (address - mapping.start()) / PAGE;
            let count = length.div_ceil(PAGE);
            (mapping, first, count)
        })
    })
}

/// Models `mmap` for private anonymous memory.
///
/// # Safety
///
/// Same contract as the Linux call. A fixed mapping must lie inside an
/// existing model mapping; the model cannot place memory at a chosen address.
pub(crate) unsafe fn mmap(
    address: *mut u8,
    length: usize,
    _protection: u32,
    flags: u32,
    fd: crate::RawFd,
    offset: u64,
) -> Result<*mut u8> {
    if length == 0 || fd != -1 || offset != 0 || flags & MAP_ANONYMOUS == 0 {
        return Err(Errno::from_raw_os_error(EINVAL as i32));
    }
    let length = length.div_ceil(PAGE) * PAGE;
    if flags & (MAP_FIXED | MAP_FIXED_NOREPLACE) != 0 {
        return with_table(|entries| {
            let Some((mapping, first, count)) = containing(entries, address.addr(), length) else {
                return Err(Errno::from_raw_os_error(ENOMEM as i32));
            };
            // A fresh anonymous replacement reads as zero.
            let offset = address.addr() - mapping.start();
            // SAFETY: the range lies inside this live model allocation.
            unsafe { core::ptr::write_bytes(mapping.base.wrapping_add(offset), 0, length) };
            for page in first..first + count {
                mapping.set_page(page, false);
            }
            Ok(mapping.base.wrapping_add(offset))
        });
    }
    let pages = length / PAGE;
    let Ok(layout) = Layout::from_size_align(length, PAGE) else {
        return Err(Errno::from_raw_os_error(ENOMEM as i32));
    };
    let Ok(bitmap_layout) = Layout::from_size_align(pages.div_ceil(8), 1) else {
        return Err(Errno::from_raw_os_error(ENOMEM as i32));
    };
    // SAFETY: both layouts are nonzero.
    let base = unsafe { alloc_zeroed(layout) };
    let unmapped = unsafe { alloc_zeroed(bitmap_layout) };
    if base.is_null() || unmapped.is_null() {
        // SAFETY: each non-null block was allocated just above with its layout.
        unsafe {
            if !base.is_null() {
                dealloc(base, layout);
            }
            if !unmapped.is_null() {
                dealloc(unmapped, bitmap_layout);
            }
        }
        return Err(Errno::from_raw_os_error(ENOMEM as i32));
    }
    let inserted = with_table(|entries| {
        let slot = entries.iter_mut().find(|entry| entry.is_none())?;
        *slot = Some(Mapping { base, pages, unmapped, unmapped_count: 0 });
        Some(())
    });
    if inserted.is_none() {
        // SAFETY: both blocks were allocated above and never published.
        unsafe {
            dealloc(base, layout);
            dealloc(unmapped, bitmap_layout);
        }
        return Err(Errno::from_raw_os_error(ENOMEM as i32));
    }
    Ok(base)
}

fn munmap(address: usize, length: usize) -> isize {
    if address % PAGE != 0 || length == 0 {
        return -EINVAL;
    }
    let end = address.saturating_add(length.div_ceil(PAGE) * PAGE);
    with_table(|entries| {
        for entry in entries.iter_mut() {
            let Some(mapping) = entry.as_mut() else { continue };
            let start = mapping.start().max(address);
            let stop = mapping.end().min(end);
            if start >= stop {
                continue;
            }
            for page in (start - mapping.start()) / PAGE..(stop - mapping.start()) / PAGE {
                mapping.set_page(page, true);
            }
            if mapping.unmapped_count == mapping.pages {
                let mapping = entry.take().unwrap();
                // SAFETY: these are the exact layouts used by `mmap`, and no
                // page of the allocation remains mapped.
                unsafe {
                    dealloc(mapping.base, Layout::from_size_align_unchecked(mapping.pages * PAGE, PAGE));
                    dealloc(mapping.unmapped, Layout::from_size_align_unchecked(mapping.pages.div_ceil(8), 1));
                }
            }
        }
        0
    })
}

fn require_mapped(address: usize, length: usize, zero: bool) -> isize {
    if address % PAGE != 0 {
        return -EINVAL;
    }
    if length == 0 {
        return 0;
    }
    with_table(|entries| {
        let Some((mapping, first, count)) = containing(entries, address, length) else {
            return -ENOMEM;
        };
        if (first..first + count).any(|page| mapping.page_unmapped(page)) {
            return -ENOMEM;
        }
        if zero {
            let offset = address - mapping.start();
            // SAFETY: the whole range is mapped inside this live allocation.
            unsafe { core::ptr::write_bytes(mapping.base.wrapping_add(offset), 0, count * PAGE) };
        }
        0
    })
}

/// Models `mincore`: every mapped page is resident.
///
/// # Safety
///
/// `vector` must be writable for `ceil(length / 4096)` bytes.
pub(crate) unsafe fn mincore(address: *mut u8, length: usize, vector: *mut u8) -> Result<()> {
    let status = require_mapped(address.addr(), length, false);
    if status != 0 {
        return Err(Errno::from_raw_os_error((-status) as i32));
    }
    // SAFETY: forwarded output-vector contract.
    unsafe { core::ptr::write_bytes(vector, 1, length.div_ceil(PAGE)) };
    Ok(())
}

static CLOCK_NANOSECONDS: AtomicU64 = AtomicU64::new(1_000_000_000);

/// Models `clock_gettime` with one deterministic clock that advances one
/// millisecond per observation, so bounded waits always make progress.
///
/// # Safety
///
/// `timespec` must be writable for one 16-byte Linux `struct timespec`.
pub(crate) unsafe fn clock_gettime(_clock_id: i32, timespec: *mut u8) -> Result<()> {
    let now = CLOCK_NANOSECONDS.fetch_add(1_000_000, Ordering::Relaxed);
    let seconds = (now / 1_000_000_000) as i64;
    let nanoseconds = (now % 1_000_000_000) as i64;
    // SAFETY: forwarded output contract; Linux `timespec` is two i64 words.
    unsafe {
        timespec.cast::<i64>().write_unaligned(seconds);
        timespec.cast::<i64>().add(1).write_unaligned(nanoseconds);
    }
    Ok(())
}

static ENTROPY_STATE: AtomicU64 = AtomicU64::new(0x4d49_5249_4d4f_4445); // "MIRIMODE"

/// Models `getrandom` with a fixed SplitMix64 test stream.
///
/// # Safety
///
/// `buffer` must be writable for `length` bytes.
pub(crate) unsafe fn getrandom(buffer: *mut u8, length: usize, _flags: u32) -> Result<usize> {
    let mut written = 0;
    while written < length {
        let mut value = ENTROPY_STATE.fetch_add(0x9e37_79b9_7f4a_7c15, Ordering::Relaxed);
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^= value >> 31;
        for byte in value.to_le_bytes() {
            if written == length {
                break;
            }
            // SAFETY: `written < length` within the caller's writable buffer.
            unsafe { buffer.add(written).write(byte) };
            written += 1;
        }
    }
    Ok(length)
}

#[thread_local]
static THREAD_MARKER: u8 = 0;
#[thread_local]
static THREAD_ID: Cell<i32> = Cell::new(0);
static NEXT_THREAD_ID: AtomicI32 = AtomicI32::new(1001);
const PROCESS_ID: isize = 1000;

/// A stable per-thread address standing in for `%fs:0`.
pub(crate) fn thread_pointer_identity() -> usize {
    core::ptr::addr_of!(THREAD_MARKER).addr()
}

fn thread_id() -> isize {
    if THREAD_ID.get() == 0 {
        THREAD_ID.set(NEXT_THREAD_ID.fetch_add(1, Ordering::Relaxed));
    }
    THREAD_ID.get() as isize
}

/// The integer-level dispatcher for calls that neither return nor write
/// through a caller pointer.
pub(crate) fn syscall(number: usize, arguments: [usize; 6]) -> isize {
    use crate::syscall::*;
    match number {
        SYS_MUNMAP => munmap(arguments[0], arguments[1]),
        SYS_MPROTECT => require_mapped(arguments[0], arguments[1], false),
        SYS_MADVISE => require_mapped(arguments[0], arguments[1], arguments[2] == MADV_DONTNEED),
        SYS_SCHED_YIELD => 0,
        SYS_GETTID => thread_id(),
        SYS_GETPID => PROCESS_ID,
        SYS_PRCTL => -EINVAL,
        SYS_FUTEX => match arguments[1] & 0x7f {
            // FUTEX_WAIT / FUTEX_WAIT_BITSET: never block; the caller rechecks.
            0 | 9 => -EAGAIN,
            // FUTEX_WAKE / FUTEX_WAKE_BITSET: no modeled sleeper.
            1 | 10 => 0,
            _ => -ENOSYS,
        },
        SYS_CLOSE => 0,
        SYS_OPENAT | SYS_FACCESSAT => -ENOENT,
        SYS_READ => -EBADF,
        SYS_WRITE if arguments[0] == 1 || arguments[0] == 2 => arguments[2] as isize,
        SYS_WRITE => -EBADF,
        SYS_EXIT_GROUP => panic!("the Miri kernel model cannot exit the process"),
        _ => -ENOSYS,
    }
}
