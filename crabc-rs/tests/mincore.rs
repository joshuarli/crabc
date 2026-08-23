use crabc_rs::{mm, Errno};

#[test]
fn native_mincore_reports_faulted_pages_and_preserves_extra_output() {
    const PAGE_SIZE: usize = mm::MINCORE_PAGE_SIZE;
    const MAPPING_LEN: usize = PAGE_SIZE * 2;

    let mapping = unsafe {
        mm::mmap_anonymous(
            core::ptr::null_mut(),
            MAPPING_LEN,
            mm::ProtFlags::READ | mm::ProtFlags::WRITE,
            mm::MapFlags::PRIVATE,
        )
    }
    .expect("map two anonymous pages through the direct kernel seam");

    // Remove any residency established by the mapping setup, then fault only
    // the first page. The second page is intentionally never read or written.
    unsafe { mm::madvise(mapping, MAPPING_LEN, mm::Advice::LinuxDontNeed) }
        .expect("discard anonymous pages before the residency query");
    unsafe { mapping.cast::<u8>().write(0x5a) };

    let mut residency = [0xa5_u8; 3];
    unsafe { mm::mincore(mapping, MAPPING_LEN, &mut residency) }
        .expect("query residency through the direct mincore syscall");

    assert_eq!(residency[0] & 1, 1, "the written page must be resident");
    assert_eq!(
        residency[2], 0xa5,
        "bytes beyond the required vector stay untouched"
    );

    unsafe { mm::munmap(mapping, MAPPING_LEN) }.expect("unmap queried pages");
}

#[test]
fn native_mincore_rejects_short_output_before_entering_the_kernel() {
    const PAGE_SIZE: usize = mm::MINCORE_PAGE_SIZE;

    let mapping = unsafe {
        mm::mmap_anonymous(
            core::ptr::null_mut(),
            PAGE_SIZE,
            mm::ProtFlags::READ | mm::ProtFlags::WRITE,
            mm::MapFlags::PRIVATE,
        )
    }
    .expect("map an anonymous page for output validation");

    let mut output = [];
    let mut overflow_output = [0_u8; 1];
    assert_eq!(
        unsafe { mm::mincore(mapping, PAGE_SIZE, &mut output) },
        Err(Errno::INVAL),
        "a one-page query needs one caller-owned output byte",
    );
    assert_eq!(
        unsafe { mm::mincore(mapping, usize::MAX, &mut overflow_output) },
        Err(Errno::INVAL),
        "an unrepresentable page count is rejected before the raw syscall",
    );

    unsafe { mm::munmap(mapping, PAGE_SIZE) }.expect("unmap validation page");
}

#[test]
fn native_mincore_rounds_a_partial_final_page_to_one_output_byte() {
    const PAGE_SIZE: usize = mm::MINCORE_PAGE_SIZE;
    const MAPPING_LEN: usize = PAGE_SIZE * 2;

    let mapping = unsafe {
        mm::mmap_anonymous(
            core::ptr::null_mut(),
            MAPPING_LEN,
            mm::ProtFlags::READ | mm::ProtFlags::WRITE,
            mm::MapFlags::PRIVATE,
        )
    }
    .expect("map two pages for partial-range validation");

    unsafe { mapping.cast::<u8>().add(PAGE_SIZE).write(0x7b) };
    let mut residency = [0_u8; 2];
    unsafe { mm::mincore(mapping, PAGE_SIZE + 1, &mut residency) }
        .expect("query the page containing a one-byte partial tail");
    assert_eq!(
        residency[1] & 1,
        1,
        "the partial final page must be reported"
    );

    unsafe { mm::munmap(mapping, MAPPING_LEN) }.expect("unmap partial-range fixture");
}
