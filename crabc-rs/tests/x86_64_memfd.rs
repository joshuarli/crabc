#![cfg(target_arch = "x86_64")]

use core::ffi::{c_void, CStr};

use crabc_rs::{fs, io, mm, pipe, Errno, OwnedFd};

const PAGE_SIZE: usize = 4096;

struct WritableSharedMapping {
    pointer: *mut c_void,
}

impl WritableSharedMapping {
    fn new(file: &OwnedFd) -> Self {
        // SAFETY: the test keeps `file` open and sized to `PAGE_SIZE` for the
        // mapping lifetime, and this owner unmaps its one successful mapping.
        let pointer = unsafe {
            mm::mmap(
                core::ptr::null_mut(),
                PAGE_SIZE,
                mm::ProtFlags::READ | mm::ProtFlags::WRITE,
                mm::MapFlags::SHARED,
                file,
                0,
            )
        }
        .expect("create a writable shared memfd mapping");
        Self { pointer }
    }

    fn write_first_byte(&self, byte: u8) {
        // SAFETY: this owner keeps the one-page writable shared mapping live.
        unsafe { self.pointer.cast::<u8>().write(byte) };
    }

    fn unmap(mut self) {
        // SAFETY: this owner consumes exactly the one-page mapping it created.
        unsafe { mm::munmap(self.pointer, PAGE_SIZE) }
            .expect("unmap the writable shared memfd mapping");
        self.pointer = core::ptr::null_mut();
    }
}

impl Drop for WritableSharedMapping {
    fn drop(&mut self) {
        if !self.pointer.is_null() {
            // SAFETY: this fallback consumes the mapping only if `unmap` did
            // not already consume it.
            let _ = unsafe { mm::munmap(self.pointer, PAGE_SIZE) };
        }
    }
}

#[test]
fn x86_64_memfd_owns_a_cloexec_descriptor_and_preserves_content() {
    let file = fs::memfd_create(
        "crabc-x86-64-memfd-content",
        fs::MemfdFlags::CLOEXEC | fs::MemfdFlags::ALLOW_SEALING,
    )
    .expect("create a sealing-capable anonymous memory file");

    assert!(
        io::fcntl_getfd(&file)
            .expect("read memfd descriptor flags")
            .contains(io::FdFlags::CLOEXEC),
        "MFD_CLOEXEC must become FD_CLOEXEC on the owned descriptor",
    );

    let payload = b"memfd_buf";
    assert_eq!(io::write(&file, payload).expect("write memfd content"), 9);
    let mut content = [0_u8; 9];
    assert_eq!(
        io::pread(&file, &mut content, 0).expect("read memfd content"),
        9,
    );
    assert_eq!(&content, payload);
}

#[test]
fn x86_64_memfd_keeps_the_closed_name_and_flag_boundary() {
    assert_eq!(fs::MemfdFlags::CLOEXEC.bits(), 0x0001);
    assert_eq!(fs::MemfdFlags::ALLOW_SEALING.bits(), 0x0002);
    assert_eq!(fs::MemfdFlags::HUGETLB.bits(), 0x0004);
    assert_eq!(fs::SealFlags::SEAL.bits(), 0x0001);
    assert_eq!(fs::SealFlags::SHRINK.bits(), 0x0002);
    assert_eq!(fs::SealFlags::GROW.bits(), 0x0004);
    assert_eq!(fs::SealFlags::WRITE.bits(), 0x0008);
    assert_eq!(fs::SealFlags::FUTURE_WRITE.bits(), 0x0010);
    assert_eq!(fs::SealFlags::EXEC.bits(), 0x0020);

    assert!(
        fs::MemfdFlags::from_bits(0x0008).is_none(),
        "unknown MFD bits must not be silently forwarded",
    );
    assert_eq!(
        fs::memfd_create(&b"bad\0name"[..], fs::MemfdFlags::empty()).unwrap_err(),
        Errno::INVAL,
        "PathArg rejects an interior NUL before crossing the syscall boundary",
    );
    assert_eq!(
        fs::memfd_create(
            "crabc-x86-64-memfd-unknown-flags",
            fs::MemfdFlags::from_bits_retain(0x0008),
        )
        .unwrap_err(),
        Errno::INVAL,
        "retained unknown MFD bits must be rejected before the syscall boundary",
    );

    // The no-allocation PathArg conversion still reaches Linux for names
    // shorter than its fixed 256-byte stack buffer. That distinguishes the
    // Linux memfd label limit from the facade's separate conversion limit.
    let accepted_by_linux = [b'a'; 249];
    let _file = fs::memfd_create(&accepted_by_linux[..], fs::MemfdFlags::empty())
        .expect("Linux accepts a 249-byte memfd label");

    let rejected_by_linux = [b'b'; 250];
    assert_eq!(
        fs::memfd_create(&rejected_by_linux[..], fs::MemfdFlags::empty()).unwrap_err(),
        Errno::INVAL,
        "the 250-byte memfd label reaches Linux and is rejected there",
    );

    let mut borrowed_kernel_rejected = [b'c'; 251];
    borrowed_kernel_rejected[250] = 0;
    let borrowed_kernel_rejected =
        CStr::from_bytes_with_nul(&borrowed_kernel_rejected).expect("a 250-byte C string");
    assert_eq!(
        fs::memfd_create(borrowed_kernel_rejected, fs::MemfdFlags::empty()).unwrap_err(),
        Errno::INVAL,
        "a borrowed C string bypasses the stack conversion but keeps Linux's label limit",
    );

    let rejected_by_facade = [b'd'; fs::SMALL_PATH_BUFFER_SIZE];
    assert_eq!(
        fs::memfd_create(&rejected_by_facade[..], fs::MemfdFlags::empty()).unwrap_err(),
        Errno::NAMETOOLONG,
        "the fixed-stack conversion rejects 256 bytes before the syscall",
    );
}

#[test]
fn x86_64_memfd_seals_are_observable_and_final_seal_is_immutable() {
    let file = fs::memfd_create(
        "crabc-x86-64-memfd-seals",
        fs::MemfdFlags::CLOEXEC | fs::MemfdFlags::ALLOW_SEALING,
    )
    .expect("create a memfd that permits sealing");
    assert_eq!(
        fs::fcntl_get_seals(&file).expect("read initial memfd seals"),
        fs::SealFlags::empty(),
    );

    let seals = fs::SealFlags::GROW | fs::SealFlags::SHRINK;
    fs::fcntl_add_seals(&file, seals).expect("add memfd seals");
    assert_eq!(
        fs::fcntl_get_seals(&file).expect("read added memfd seals"),
        seals,
    );
    fs::fcntl_add_seals(&file, fs::SealFlags::SEAL).expect("add final seal");
    assert_eq!(
        fs::fcntl_add_seals(&file, fs::SealFlags::WRITE),
        Err(Errno::PERM),
    );

    let unsealable = fs::memfd_create("crabc-x86-64-memfd-unsealable", fs::MemfdFlags::CLOEXEC)
        .expect("create a memfd without sealing permission");
    assert_eq!(
        fs::fcntl_get_seals(&unsealable).expect("read initial unsealable memfd seals"),
        fs::SealFlags::SEAL,
    );
    assert_eq!(
        fs::fcntl_add_seals(&unsealable, fs::SealFlags::GROW),
        Err(Errno::PERM),
    );

    let invalid_seal = fs::SealFlags::from_bits_retain(0x4000_0000);
    let unknown_seal_file = fs::memfd_create(
        "crabc-x86-64-memfd-unknown-seal",
        fs::MemfdFlags::CLOEXEC | fs::MemfdFlags::ALLOW_SEALING,
    )
    .expect("create an unsealed memfd for an unknown seal");
    assert_eq!(
        fs::fcntl_add_seals(&unknown_seal_file, invalid_seal),
        Err(Errno::INVAL),
        "an unknown seal bit must reach Linux unchanged",
    );
    assert_eq!(
        fs::fcntl_get_seals(&unknown_seal_file),
        Ok(fs::SealFlags::empty()),
        "a rejected unknown seal must not mutate the observed seal set",
    );

    let (reader, writer) = pipe::pipe().expect("create a pipe");
    assert_eq!(fs::fcntl_get_seals(&reader), Err(Errno::INVAL));
    assert_eq!(
        fs::fcntl_add_seals(&reader, fs::SealFlags::GROW),
        Err(Errno::PERM),
        "the read-only pipe end fails its writable-descriptor check first",
    );
    assert_eq!(
        fs::fcntl_add_seals(&writer, fs::SealFlags::GROW),
        Err(Errno::INVAL),
        "the writable pipe end reaches the unsupported-sealing check",
    );
}

#[test]
fn x86_64_memfd_seals_enforce_size_and_write_mutation() {
    let size_sealed = fs::memfd_create(
        "crabc-x86-64-memfd-size-seals",
        fs::MemfdFlags::CLOEXEC | fs::MemfdFlags::ALLOW_SEALING,
    )
    .expect("create a memfd for size-seal enforcement");
    fs::ftruncate(&size_sealed, 4).expect("size the memfd before sealing");
    let size_seals = fs::SealFlags::GROW | fs::SealFlags::SHRINK;
    fs::fcntl_add_seals(&size_sealed, size_seals).expect("add size seals");
    assert_eq!(
        fs::ftruncate(&size_sealed, 5),
        Err(Errno::PERM),
        "F_SEAL_GROW must reject a larger file length",
    );
    assert_eq!(
        fs::ftruncate(&size_sealed, 3),
        Err(Errno::PERM),
        "F_SEAL_SHRINK must reject a smaller file length",
    );
    assert_eq!(
        fs::fcntl_get_seals(&size_sealed).expect("observe size seals"),
        size_seals,
    );

    let write_sealed = fs::memfd_create(
        "crabc-x86-64-memfd-write-seal",
        fs::MemfdFlags::CLOEXEC | fs::MemfdFlags::ALLOW_SEALING,
    )
    .expect("create a memfd for write-seal enforcement");
    fs::ftruncate(&write_sealed, PAGE_SIZE as u64).expect("size the write-seal memfd");
    let write_mapping = WritableSharedMapping::new(&write_sealed);
    assert_eq!(
        fs::fcntl_add_seals(&write_sealed, fs::SealFlags::WRITE),
        Err(Errno::BUSY),
        "F_SEAL_WRITE must reject a live writable shared mapping",
    );
    assert_eq!(
        fs::fcntl_get_seals(&write_sealed),
        Ok(fs::SealFlags::empty()),
        "the rejected F_SEAL_WRITE request must not mutate seals",
    );
    write_mapping.unmap();
    fs::fcntl_add_seals(&write_sealed, fs::SealFlags::WRITE).expect("add write seal");
    assert_eq!(
        io::pwrite(&write_sealed, b"x", 0),
        Err(Errno::PERM),
        "F_SEAL_WRITE must reject in-place writes",
    );

    let future_write_sealed = fs::memfd_create(
        "crabc-x86-64-memfd-future-write-seal",
        fs::MemfdFlags::CLOEXEC | fs::MemfdFlags::ALLOW_SEALING,
    )
    .expect("create a memfd for the future-write mapping boundary");
    fs::ftruncate(&future_write_sealed, PAGE_SIZE as u64)
        .expect("size the future-write-seal memfd");
    let existing_mapping = WritableSharedMapping::new(&future_write_sealed);
    fs::fcntl_add_seals(&future_write_sealed, fs::SealFlags::FUTURE_WRITE)
        .expect("add future-write seal");
    existing_mapping.write_first_byte(b'm');
    let mut observed = [0_u8; 1];
    assert_eq!(
        io::pread(&future_write_sealed, &mut observed, 0),
        Ok(1),
        "the preexisting shared mapping must remain observable through the file",
    );
    assert_eq!(observed, [b'm']);
    assert_eq!(
        io::pwrite(&future_write_sealed, b"x", 0),
        Err(Errno::PERM),
        "F_SEAL_FUTURE_WRITE must reject later direct descriptor writes",
    );
    // SAFETY: the file remains open and page-sized; the expected failure does
    // not create a mapping for this test to own.
    assert_eq!(
        unsafe {
            mm::mmap(
                core::ptr::null_mut(),
                PAGE_SIZE,
                mm::ProtFlags::READ | mm::ProtFlags::WRITE,
                mm::MapFlags::SHARED,
                &future_write_sealed,
                0,
            )
        },
        Err(Errno::PERM),
        "F_SEAL_FUTURE_WRITE must reject a new writable shared mapping",
    );
}
