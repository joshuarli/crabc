#![cfg(target_arch = "x86_64")]

use core::ffi::{c_void, CStr};

use crabc_rs::{io, mm, OwnedFd};

const PAGE_SIZE: usize = 4096;
const SPARSE_OFFSET: u64 = 4 * 1024 * 1024 * 1024;

struct Mapping {
    pointer: *mut c_void,
    length: usize,
}

fn mlock_was_admitted(result: crabc_rs::Result<()>, operation: &str) -> bool {
    match result {
        Ok(()) => true,
        Err(error)
            if matches!(
                error,
                crabc_rs::Errno::PERM | crabc_rs::Errno::AGAIN | crabc_rs::Errno::NOMEM
            ) => false,
        Err(error) => panic!("{operation} returned unexpected error: {error:?}"),
    }
}

impl Mapping {
    fn anonymous() -> Self {
        let pointer = unsafe {
            mm::mmap_anonymous(
                core::ptr::null_mut(),
                PAGE_SIZE,
                mm::ProtFlags::READ | mm::ProtFlags::WRITE,
                mm::MapFlags::PRIVATE,
            )
        }
        .expect("create an x86-64 anonymous mapping");

        Self {
            pointer,
            length: PAGE_SIZE,
        }
    }

    fn resize(&mut self, new_length: usize, flags: mm::MremapFlags) {
        let successor = unsafe { mm::mremap(self.pointer, self.length, new_length, flags) }
            .expect("resize x86-64 mapping");
        // Linux consumes the old mapping on success, even when the numeric
        // address is unchanged. Publish only the returned successor.
        self.pointer = successor;
        self.length = new_length;
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        if !self.pointer.is_null() {
            // SAFETY: This owner consumes the one mapping created above,
            // after the test has stopped using pointers into it.
            let _ = unsafe { mm::munmap(self.pointer, self.length) };
        }
    }
}

fn anonymous_file() -> OwnedFd {
    let name = CStr::from_bytes_with_nul(b"crabc-rs-x86-64-mm\0")
        .expect("the fixed memfd name is NUL-terminated");
    let raw = crabc_core::fs::memfd_create(name, 0).expect("create anonymous mapping file");
    crabc_core::fs::ftruncate(raw, (SPARSE_OFFSET + PAGE_SIZE as u64) as i64)
        .expect("size sparse anonymous mapping file");

    // SAFETY: `memfd_create` returned one newly-open descriptor whose unique
    // ownership transfers to this RAII value.
    unsafe { OwnedFd::from_raw_fd(raw) }
}

#[test]
fn x86_64_mapping_flags_match_the_linux_abi() {
    assert_eq!(mm::ProtFlags::empty().bits(), 0x0);
    assert_eq!(mm::ProtFlags::READ.bits(), 0x1);
    assert_eq!(mm::ProtFlags::WRITE.bits(), 0x2);
    assert_eq!(mm::ProtFlags::EXEC.bits(), 0x4);
    assert_eq!(mm::MprotectFlags::empty().bits(), 0x0);
    assert_eq!(mm::MapFlags::SHARED.bits(), 0x1);
    assert_eq!(mm::MapFlags::PRIVATE.bits(), 0x2);
    assert_eq!(mm::MremapFlags::empty().bits(), 0x0);
    assert_eq!(mm::MremapFlags::MAYMOVE.bits(), 0x1);
    assert_eq!(mm::MlockFlags::empty().bits(), 0x0);
    assert_eq!(mm::MlockFlags::ONFAULT.bits(), 0x1);
    assert_eq!(mm::MsyncFlags::ASYNC.bits(), 0x1);
    assert_eq!(mm::MsyncFlags::INVALIDATE.bits(), 0x2);
    assert_eq!(mm::MsyncFlags::SYNC.bits(), 0x4);
    assert_eq!(mm::Advice::Normal as u32, 0);
    assert_eq!(mm::Advice::Random as u32, 1);
    assert_eq!(mm::Advice::Sequential as u32, 2);
    assert_eq!(mm::Advice::WillNeed as u32, 3);
    assert_eq!(mm::Advice::LinuxDontNeed as u32, 4);
    assert_eq!(mm::PosixAdvice::Normal as u32, 0);
    assert_eq!(mm::PosixAdvice::Random as u32, 1);
    assert_eq!(mm::PosixAdvice::Sequential as u32, 2);
    assert_eq!(mm::PosixAdvice::WillNeed as u32, 3);
    assert_eq!(mm::PosixAdvice::DontNeed as u32, 4);
    assert_eq!(mm::MINCORE_PAGE_SIZE, PAGE_SIZE);
}

#[test]
fn x86_64_msync_accepts_linux_sync_modes_for_anonymous_mapping() {
    let mapping = Mapping::anonymous();
    // SAFETY: The mapping owns a writable page until Drop unmaps it.
    unsafe { mapping.pointer.cast::<u8>().write(0x5a) };

    // SAFETY: The mapping is page-aligned, mapped, and remains owned for the
    // duration of each direct synchronization syscall.
    unsafe { mm::msync(mapping.pointer, mapping.length, mm::MsyncFlags::SYNC) }
        .expect("synchronize anonymous page through direct x86-64 msync");
    // SAFETY: The same mapped range remains valid for the asynchronous call.
    unsafe { mm::msync(mapping.pointer, mapping.length, mm::MsyncFlags::ASYNC) }
        .expect("schedule anonymous page synchronization through direct x86-64 msync");
    assert_eq!(unsafe { mapping.pointer.cast::<u8>().read() }, 0x5a);
}

#[test]
fn x86_64_msync_and_madvise_accept_zero_length_as_linux_noops() {
    let mapping = Mapping::anonymous();

    // SAFETY: Linux accepts zero-length operations without accessing the
    // otherwise valid, page-aligned mapping address.
    unsafe { mm::msync(mapping.pointer, 0, mm::MsyncFlags::empty()) }
        .expect("zero-length x86-64 msync is a no-op");
    // SAFETY: Linux accepts zero-length normal advice without accessing the
    // otherwise valid mapped range.
    unsafe { mm::madvise(mapping.pointer, 0, mm::Advice::Normal) }
        .expect("zero-length x86-64 madvise is a no-op");
}

#[test]
fn x86_64_madvise_linux_dontneed_discards_anonymous_page_contents() {
    let mapping = Mapping::anonymous();
    // SAFETY: The mapping owns a writable page until Drop unmaps it.
    unsafe { mapping.pointer.cast::<u8>().write(0x5a) };

    // Linux's private-anonymous MADV_DONTNEED policy discards the page; the
    // next read faults in a fresh zero-filled page.
    // SAFETY: The mapped range remains valid, and no typed contents are used
    // across the potentially destructive advice operation.
    unsafe { mm::madvise(mapping.pointer, mapping.length, mm::Advice::LinuxDontNeed) }
        .expect("discard anonymous page through direct x86-64 madvise");
    assert_eq!(unsafe { mapping.pointer.cast::<u8>().read() }, 0);
}

#[test]
fn x86_64_posix_madvise_dontneed_preserves_anonymous_page_contents() {
    let mapping = Mapping::anonymous();
    // SAFETY: The mapping owns a writable page until Drop unmaps it.
    unsafe { mapping.pointer.cast::<u8>().write(0x5a) };

    // POSIX_MADV_DONTNEED is an advisory no-op on Linux in musl's contract;
    // it must not inherit Linux MADV_DONTNEED's page-discard behavior.
    // POSIX DONTNEED does not forward to Linux madvise. The deliberately
    // unaligned, one-byte-shifted range would otherwise be rejected by Linux.
    // SAFETY: The pointer originates in the owned mapping; this no-op advisory
    // does not access or validate the shifted range.
    unsafe {
        mm::posix_madvise(
            mapping.pointer.cast::<u8>().wrapping_add(1).cast(),
            mapping.length,
            mm::PosixAdvice::DontNeed,
        )
    }
        .expect("apply POSIX x86-64 DONTNEED advisory");
    assert_eq!(unsafe { mapping.pointer.cast::<u8>().read() }, 0x5a);
}

#[test]
fn x86_64_mincore_reports_residency_and_preserves_extra_output() {
    let mapping = {
        let pointer = unsafe {
            mm::mmap_anonymous(
                core::ptr::null_mut(),
                PAGE_SIZE * 2,
                mm::ProtFlags::READ | mm::ProtFlags::WRITE,
                mm::MapFlags::PRIVATE,
            )
        }
        .expect("create a two-page x86-64 anonymous mapping");
        Mapping {
            pointer,
            length: PAGE_SIZE * 2,
        }
    };

    // Discard both pages, then fault only the first one before querying.
    // SAFETY: The complete two-page mapping remains owned throughout.
    unsafe { mm::madvise(mapping.pointer, mapping.length, mm::Advice::LinuxDontNeed) }
        .expect("discard pages before x86-64 residency query");
    // SAFETY: The first page is mapped writable and remains so until Drop.
    unsafe { mapping.pointer.cast::<u8>().write(0x5a) };

    let mut residency = [0xa5_u8; 3];
    // SAFETY: The mapping is aligned and the output is separate caller-owned
    // storage with one byte per queried page plus an untouched sentinel.
    unsafe { mm::mincore(mapping.pointer, mapping.length, &mut residency) }
        .expect("query x86-64 page residency through direct mincore");
    assert_eq!(residency[0] & 1, 1, "the written page must be resident");
    assert_eq!(residency[2], 0xa5, "extra output remains untouched");
}

#[test]
fn x86_64_mincore_rejects_short_or_overflowing_output_before_syscall() {
    let mapping = Mapping::anonymous();
    let mut short = [];
    let mut overflow = [0_u8; 1];

    // SAFETY: The mapping remains valid; the short output is intentionally
    // rejected before any kernel write.
    assert_eq!(
        unsafe { mm::mincore(mapping.pointer, PAGE_SIZE, &mut short) },
        Err(crabc_rs::Errno::INVAL),
    );
    // SAFETY: This invalid length is used only to exercise checked arithmetic;
    // no raw syscall should receive it.
    assert_eq!(
        unsafe { mm::mincore(mapping.pointer, usize::MAX, &mut overflow) },
        Err(crabc_rs::Errno::INVAL),
    );
}

#[test]
fn x86_64_mlock_and_munlock_balance_a_mapped_page() {
    let mapping = Mapping::anonymous();
    let byte = mapping.pointer.cast::<u8>();

    // SAFETY: The mapping owns one writable page until its Drop unmap.
    unsafe { byte.write(0x5a) };
    // SAFETY: The mapping remains valid and readable for the lock call.
    let admitted = mlock_was_admitted(
        unsafe { mm::mlock(mapping.pointer, mapping.length) },
        "mlock",
    );
    if !admitted {
        return;
    }
    // SAFETY: Locking does not change mapping permissions or contents.
    assert_eq!(unsafe { byte.read() }, 0x5a);
    // SAFETY: The mapping remains valid for the unlock call.
    unsafe { mm::munlock(mapping.pointer, mapping.length) }
        .expect("unlock x86-64 mapped page through direct munlock");
}

#[test]
fn x86_64_mlock2_onfault_and_munlock_balance_a_mapped_page() {
    let mapping = Mapping::anonymous();
    let byte = mapping.pointer.cast::<u8>();

    // SAFETY: The mapping remains valid and readable for the lock call.
    let admitted = mlock_was_admitted(
        unsafe { mm::mlock_with(mapping.pointer, mapping.length, mm::MlockFlags::ONFAULT) },
        "mlock2",
    );
    if !admitted {
        return;
    }
    // SAFETY: The on-fault lock leaves the mapping writable.
    unsafe { byte.write(0xa5) };
    assert_eq!(unsafe { byte.read() }, 0xa5);
    // SAFETY: The mapping remains valid for the unlock call.
    unsafe { mm::munlock(mapping.pointer, mapping.length) }
        .expect("unlock x86-64 on-fault page");
}

#[test]
fn x86_64_mlock2_rejects_unknown_flags() {
    let mapping = Mapping::anonymous();

    // SAFETY: The mapping remains valid for the direct syscall. The retained
    // unknown bit is deliberately passed through for Linux validation.
    let error = unsafe {
        mm::mlock_with(
            mapping.pointer,
            mapping.length,
            mm::MlockFlags::from_bits_retain(2),
        )
    }
    .expect_err("Linux must reject unsupported x86-64 mlock2 flags");

    assert_eq!(error, crabc_rs::Errno::INVAL);
}

#[test]
fn x86_64_mlock_and_munlock_report_overflow_without_errno_translation() {
    // Linux rejects a range whose address plus length wraps with EINVAL. The
    // pointer is used only as an invalid raw syscall fixture here.
    let overflowing = (usize::MAX - PAGE_SIZE + 1) as *mut c_void;

    let error = unsafe { mm::mlock(overflowing, PAGE_SIZE) }
        .expect_err("mlock must preserve Linux's overflow validation");
    assert_eq!(error, crabc_rs::Errno::INVAL);
    let error = unsafe { mm::munlock(overflowing, PAGE_SIZE) }
        .expect_err("munlock must preserve Linux's overflow validation");
    assert_eq!(error, crabc_rs::Errno::INVAL);
}

#[test]
fn x86_64_mremap_maymove_preserves_contents_and_expands_the_owned_range() {
    let mut mapping = Mapping::anonymous();
    // SAFETY: The mapping owns one writable page until the successful remap.
    unsafe { mapping.pointer.cast::<u8>().write(0x5a) };

    mapping.resize(PAGE_SIZE * 2, mm::MremapFlags::MAYMOVE);

    // SAFETY: The returned mapping owns the expanded writable range.
    assert_eq!(unsafe { mapping.pointer.cast::<u8>().read() }, 0x5a);
    // SAFETY: The second page is part of the newly expanded mapping.
    unsafe { mapping.pointer.cast::<u8>().add(PAGE_SIZE).write(0xa5) };
    // SAFETY: The second page remains mapped and writable.
    assert_eq!(unsafe { mapping.pointer.cast::<u8>().add(PAGE_SIZE).read() }, 0xa5);
}

#[test]
fn x86_64_mremap_without_maymove_can_shrink_in_place() {
    let mut mapping = Mapping::anonymous();
    mapping.resize(PAGE_SIZE * 2, mm::MremapFlags::MAYMOVE);
    let original = mapping.pointer;
    // SAFETY: The mapping owns two writable pages before the shrink.
    unsafe {
        mapping.pointer.cast::<u8>().write(0x11);
        mapping.pointer.cast::<u8>().add(PAGE_SIZE).write(0x22);
    }

    mapping.resize(PAGE_SIZE, mm::MremapFlags::empty());

    assert_eq!(mapping.pointer, original, "a shrink without MAYMOVE stays in place");
    // SAFETY: The first page remains mapped and writable after the shrink.
    assert_eq!(unsafe { mapping.pointer.cast::<u8>().read() }, 0x11);
}

#[test]
fn x86_64_mremap_fixed_replaces_destination_and_invalidates_both_inputs() {
    let mut source = Mapping::anonymous();
    let mut destination = Mapping::anonymous();
    // SAFETY: Each owner holds one writable page until the fixed remap.
    unsafe {
        source.pointer.cast::<u8>().write(0x5a);
        destination.pointer.cast::<u8>().write(0xa5);
    }
    let source_pointer = source.pointer;
    let destination_pointer = destination.pointer;

    let successor = unsafe {
        mm::mremap_fixed(
            source_pointer,
            source.length,
            PAGE_SIZE,
            mm::MremapFlags::MAYMOVE,
            destination_pointer,
        )
    }
    .expect("move x86-64 mapping to a fixed destination");

    // Both input mappings are consumed by successful fixed mremap. Keep only
    // the returned destination armed for Drop, avoiding a second unmap.
    source.pointer = core::ptr::null_mut();
    destination.pointer = successor;
    destination.length = PAGE_SIZE;

    assert_eq!(successor, destination_pointer);
    // SAFETY: The returned destination owns the source's former contents.
    assert_eq!(unsafe { successor.cast::<u8>().read() }, 0x5a);
}

#[test]
fn x86_64_mremap_rejects_flags_outside_the_closed_facade_contract() {
    let mapping = Mapping::anonymous();
    let error = unsafe {
        mm::mremap(
            mapping.pointer,
            mapping.length,
            mapping.length,
            mm::MremapFlags::from_bits_retain(0x2),
        )
    }
    .expect_err("ordinary mremap must reject MREMAP_FIXED as a facade flag");

    assert_eq!(error, crabc_rs::Errno::INVAL);
}

#[test]
fn x86_64_anonymous_mapping_preserves_permissions_and_lifetime() {
    let mapping = Mapping::anonymous();
    let byte = mapping.pointer.cast::<u8>();

    // SAFETY: `mapping` owns a writable page and no references outlive its
    // drop-based unmap.
    unsafe { byte.write(0x5a) };
    // SAFETY: no Rust reference is used while this page is `PROT_NONE`.
    unsafe { mm::mprotect(mapping.pointer, mapping.length, mm::MprotectFlags::empty()) }
        .expect("make x86-64 mapping inaccessible");
    // SAFETY: `mapping` owns the complete valid page and no Rust reference is
    // used across the `PROT_NONE` transition.
    unsafe { mm::mprotect(mapping.pointer, mapping.length, mm::MprotectFlags::READ) }
        .expect("make x86-64 mapping read-only");
    // SAFETY: the mapping remains readable after the protection transition.
    assert_eq!(unsafe { byte.read() }, 0x5a);
    // SAFETY: `mapping` still owns the complete page and no reference is
    // retained across this second transition.
    unsafe {
        mm::mprotect(
            mapping.pointer,
            mapping.length,
            mm::MprotectFlags::READ | mm::MprotectFlags::WRITE,
        )
    }
    .expect("restore x86-64 mapping write permission");
    // SAFETY: the mapping is writable again and remains owned until drop.
    unsafe { byte.write(0xa5) };
    // SAFETY: the mapping remains readable until its owner drops.
    assert_eq!(unsafe { byte.read() }, 0xa5);
}

#[test]
fn x86_64_file_mapping_uses_the_borrowed_descriptor_boundary() {
    let file = anonymous_file();
    let pointer = unsafe {
        mm::mmap(
            core::ptr::null_mut(),
            PAGE_SIZE,
            mm::ProtFlags::READ | mm::ProtFlags::WRITE,
            mm::MapFlags::SHARED,
            &file,
            SPARSE_OFFSET,
        )
    }
    .expect("map a page through the borrowed descriptor");
    let mapping = Mapping {
        pointer,
        length: PAGE_SIZE,
    };

    // SAFETY: `mapping` owns a writable shared page and the file remains open
    // for the mapping's lifetime.
    unsafe { mapping.pointer.cast::<u8>().write(0x3c) };
    let mut observed = [0_u8; 1];
    assert_eq!(
        io::pread(&file, &mut observed, SPARSE_OFFSET)
            .expect("read shared sparse mapping backing file"),
        1
    );
    assert_eq!(observed, [0x3c]);
}

#[test]
fn x86_64_mapping_rejects_unadmitted_flag_bits_before_the_kernel_boundary() {
    assert_eq!(
        unsafe {
            mm::mmap_anonymous(
                core::ptr::null_mut(),
                PAGE_SIZE,
                mm::ProtFlags::READ,
                mm::MapFlags::from_bits_retain(0x40),
            )
        },
        Err(crabc_rs::Errno::INVAL),
        "MAP_32BIT is x86-specific but intentionally unadmitted",
    );
    assert_eq!(
        unsafe {
            mm::mmap_anonymous(
                core::ptr::null_mut(),
                PAGE_SIZE,
                mm::ProtFlags::READ,
                mm::MapFlags::from_bits_retain(0x10),
            )
        },
        Err(crabc_rs::Errno::INVAL),
        "MAP_FIXED is intentionally unadmitted",
    );
    assert_eq!(
        unsafe {
            mm::mmap_anonymous(
                core::ptr::null_mut(),
                PAGE_SIZE,
                mm::ProtFlags::READ,
                mm::MapFlags::from_bits_retain(0x0010_0000),
            )
        },
        Err(crabc_rs::Errno::INVAL),
        "MAP_FIXED_NOREPLACE is intentionally unadmitted",
    );

    let mapping = Mapping::anonymous();
    assert_eq!(
        unsafe {
            mm::mprotect(
                mapping.pointer,
                mapping.length,
                mm::MprotectFlags::from_bits_retain(0x10),
            )
        },
        Err(crabc_rs::Errno::INVAL),
        "unadmitted protection bits must not reach the raw syscall seam",
    );
    assert_eq!(
        unsafe {
            mm::mmap_anonymous(
                core::ptr::null_mut(),
                PAGE_SIZE,
                mm::ProtFlags::READ,
                mm::MapFlags::SHARED | mm::MapFlags::PRIVATE,
            )
        },
        Err(crabc_rs::Errno::INVAL),
        "exactly one mapping sharing mode is required",
    );
}
