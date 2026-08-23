//! Behavioral evidence for the native process-break and VM-policy seam.

use crabc_rs::{mm, process, Errno};

const PAGE_SIZE: usize = 4096;

fn mapped_page() -> *mut crabc_rs::ffi::c_void {
    unsafe {
        mm::mmap_anonymous(
            core::ptr::null_mut(),
            PAGE_SIZE,
            mm::ProtFlags::READ | mm::ProtFlags::WRITE,
            mm::MapFlags::PRIVATE,
        )
    }
    .expect("map one anonymous page through the direct VM seam")
}

#[test]
fn native_kernel_brk_query_can_be_replayed_without_allocator_bookkeeping() {
    let current = unsafe { process::kernel_brk(core::ptr::null_mut()) }
        .expect("Linux brk query is a direct pointer result");
    assert!(
        !current.is_null(),
        "the process has a non-null current break"
    );

    let replayed = unsafe { process::kernel_brk(current) }
        .expect("replaying the current break must remain a no-op");
    assert_eq!(replayed, current);
}

#[test]
fn native_mlockall_and_munlockall_preserve_process_scope() {
    let locked = mm::mlockall(mm::MlockAllFlags::CURRENT);
    match locked {
        Ok(()) => {
            mm::munlockall().expect("undo successful process-wide lock");
        }
        Err(error) => assert!(
            matches!(
                error,
                Errno::PERM | Errno::AGAIN | Errno::NOMEM | Errno::INVAL
            ),
            "unexpected mlockall error: {error:?}"
        ),
    }
}

#[test]
fn native_posix_madvise_uses_the_non_discarding_policy_vocabulary() {
    let mapping = mapped_page();
    let byte = mapping.cast::<u8>();
    unsafe { byte.write(0x5a) };

    unsafe { mm::posix_madvise(mapping, PAGE_SIZE, mm::PosixAdvice::Normal) }
        .expect("POSIX normal advisory should succeed on an anonymous mapping");
    assert_eq!(unsafe { byte.read() }, 0x5a);

    // musl's Linux POSIX_MADV_DONTNEED implementation is deliberately a
    // no-op. It must not inherit Linux MADV_DONTNEED's page-discarding
    // behavior, which would turn this read into zero.
    unsafe { mm::posix_madvise(mapping, PAGE_SIZE, mm::PosixAdvice::DontNeed) }
        .expect("POSIX DONTNEED is an advisory no-op on Linux");
    assert_eq!(unsafe { byte.read() }, 0x5a);

    unsafe { mm::munmap(mapping, PAGE_SIZE) }.expect("unmap advised mapping");
}

#[test]
fn native_remap_file_pages_keeps_legacy_kernel_errors_typed() {
    let mapping = mapped_page();
    let error = unsafe { mm::remap_file_pages(mapping, PAGE_SIZE, 0) }
        .expect_err("an anonymous mapping is not a remappable file mapping");
    assert_eq!(error, Errno::INVAL);

    unsafe { mm::munmap(mapping, PAGE_SIZE) }.expect("unmap rejected remap mapping");
}
