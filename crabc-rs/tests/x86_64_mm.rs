#![cfg(target_arch = "x86_64")]

use core::ffi::{c_void, CStr};

use crabc_rs::{io, mm, OwnedFd};

const PAGE_SIZE: usize = 4096;
const SPARSE_OFFSET: u64 = 4 * 1024 * 1024 * 1024;

struct Mapping {
    pointer: *mut c_void,
    length: usize,
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
