use crabc_rs::{mm, Errno};

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
    .expect("map one page through the direct kernel seam")
}

#[test]
fn native_mlock_and_munlock_balance_a_mapped_page() {
    let mapping = mapped_page();
    let byte = mapping.cast::<u8>();
    unsafe { byte.write(0x5a) };

    unsafe { mm::mlock(mapping, PAGE_SIZE) }.expect("lock mapped page through direct mlock");
    assert_eq!(unsafe { byte.read() }, 0x5a);
    unsafe { mm::munlock(mapping, PAGE_SIZE) }.expect("unlock mapped page through direct munlock");
    unsafe { mm::munmap(mapping, PAGE_SIZE) }.expect("unmap unlocked page");
}

#[test]
fn native_mlock_with_onfault_and_munlock_balance_a_mapped_page() {
    let mapping = mapped_page();
    let byte = mapping.cast::<u8>();

    unsafe { mm::mlock_with(mapping, PAGE_SIZE, mm::MlockFlags::ONFAULT) }
        .expect("lock mapped page on fault through direct mlock2");
    unsafe { byte.write(0xa5) };
    assert_eq!(unsafe { byte.read() }, 0xa5);
    unsafe { mm::munlock(mapping, PAGE_SIZE) }.expect("unlock on-fault page");
    unsafe { mm::munmap(mapping, PAGE_SIZE) }.expect("unmap unlocked on-fault page");
}

#[test]
fn native_mlock_syscall_reports_overflow_without_errno_translation() {
    // Linux specifies EINVAL when adding `len` to `addr` wraps. This address
    // is deliberately outside the userspace range and is used only as an
    // invalid raw syscall fixture inside an unsafe call.
    let overflowing = (usize::MAX - PAGE_SIZE + 1) as *mut crabc_rs::ffi::c_void;

    let error = unsafe { mm::mlock(overflowing, PAGE_SIZE) }
        .expect_err("a range whose end wraps must be rejected by Linux");
    assert_eq!(error, Errno::INVAL);
    let error = unsafe { mm::munlock(overflowing, PAGE_SIZE) }
        .expect_err("munlock must preserve Linux's overflow validation");
    assert_eq!(error, Errno::INVAL);
}

#[test]
fn native_mlock2_syscall_reports_unknown_flags() {
    let mapping = mapped_page();

    let error = unsafe { mm::mlock_with(mapping, PAGE_SIZE, mm::MlockFlags::from_bits_retain(2)) }
        .expect_err("Linux must reject unsupported mlock2 flags");
    assert_eq!(error, Errno::INVAL);

    unsafe { mm::munmap(mapping, PAGE_SIZE) }.expect("unmap invalid-flag page");
}
