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
    #[cfg(target_os = "linux")]
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

#[cfg(target_os = "macos")]
#[test]
fn native_mincore_reports_an_untouched_darwin_page_as_not_resident() {
    const PAGE_SIZE: usize = mm::MINCORE_PAGE_SIZE;

    assert_eq!(PAGE_SIZE, 16384, "Apple Silicon processes use 16 KiB pages");
    // SAFETY: a null hint asks for a fresh mapping this test owns.
    let mapping = unsafe {
        mm::mmap_anonymous(
            core::ptr::null_mut(),
            PAGE_SIZE * 2,
            mm::ProtFlags::READ | mm::ProtFlags::WRITE,
            mm::MapFlags::PRIVATE,
        )
    }
    .expect("map two fresh anonymous pages");

    // SAFETY: the first page is mapped writable and owned by this test.
    unsafe { mapping.cast::<u8>().write(0x5a) };
    let mut residency = [0xa5_u8; 2];
    // SAFETY: both pages stay mapped, and the output is separate storage
    // with one byte per page.
    unsafe { mm::mincore(mapping, PAGE_SIZE * 2, &mut residency) }
        .expect("query fresh anonymous residency");
    assert_eq!(residency[0] & 1, 1, "the written page must be resident");
    assert_eq!(residency[1] & 1, 0, "a never-touched anonymous page has no frame");

    // SAFETY: no pointer into the mapping is used after this unmap.
    unsafe { mm::munmap(mapping, PAGE_SIZE * 2) }.expect("unmap queried pages");
}

#[cfg(target_os = "macos")]
#[test]
fn native_mincore_sizes_darwin_output_by_the_page_span_of_an_unaligned_range() {
    const PAGE_SIZE: usize = mm::MINCORE_PAGE_SIZE;

    // SAFETY: a null hint asks for a fresh mapping this test owns.
    let mapping = unsafe {
        mm::mmap_anonymous(
            core::ptr::null_mut(),
            PAGE_SIZE * 2,
            mm::ProtFlags::READ | mm::ProtFlags::WRITE,
            mm::MapFlags::PRIVATE,
        )
    }
    .expect("map two pages for unaligned-range validation");
    let last_byte = mapping.cast::<u8>().wrapping_add(PAGE_SIZE - 1);
    // SAFETY: the byte after `last_byte` starts the second mapped page.
    unsafe { last_byte.add(1).write(0x7b) };

    // Two bytes straddling the page boundary touch two pages, so a one-byte
    // output is refused before XNU could write past it.
    let mut short = [0xa5_u8; 1];
    // SAFETY: both pages of the span stay mapped; the short output is
    // refused before the call.
    assert_eq!(
        unsafe { mm::mincore(last_byte.cast(), 2, &mut short) },
        Err(Errno::INVAL),
    );
    assert_eq!(short, [0xa5]);
    let mut residency = [0xa5_u8; 3];
    // SAFETY: both pages of the span stay mapped, and the output is separate
    // storage with room for both.
    unsafe { mm::mincore(last_byte.cast(), 2, &mut residency) }
        .expect("query a range straddling two pages");
    assert_eq!(residency[1] & 1, 1, "the written second page must be resident");
    assert_eq!(residency[2], 0xa5, "bytes beyond the page span stay untouched");

    // SAFETY: no pointer into the mapping is used after this unmap.
    unsafe { mm::munmap(mapping, PAGE_SIZE * 2) }.expect("unmap unaligned-range fixture");
}
