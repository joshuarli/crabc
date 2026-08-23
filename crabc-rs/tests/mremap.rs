use crabc_rs::{mm, Errno};

const PAGE_SIZE: usize = mm::MINCORE_PAGE_SIZE;

/// Owns a raw mapping for the duration of a test, including when an assertion
/// panics. A successful mremap transfers ownership to the returned pointer;
/// the old pointer is cleared before any post-move observation.
struct Mapping {
    ptr: *mut crabc_rs::ffi::c_void,
    len: usize,
}

impl Mapping {
    fn anonymous(len: usize) -> Self {
        let ptr = unsafe {
            mm::mmap_anonymous(
                core::ptr::null_mut(),
                len,
                mm::ProtFlags::READ | mm::ProtFlags::WRITE,
                mm::MapFlags::PRIVATE,
            )
        }
        .expect("map anonymous mremap fixture");
        Self { ptr, len }
    }

    fn resize(&mut self, new_len: usize, flags: mm::MremapFlags) {
        let old_ptr = self.ptr;
        let new_ptr = unsafe { mm::mremap(old_ptr, self.len, new_len, flags) }
            .expect("resize mremap fixture");
        // The old pointer is invalid after success, even when Linux returns
        // the same numeric address. Publish only the returned successor.
        self.ptr = new_ptr;
        self.len = new_len;
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            let _ = unsafe { mm::munmap(self.ptr, self.len) };
        }
    }
}

#[test]
fn native_mremap_maymove_preserves_contents_and_expands_the_owned_range() {
    let mut mapping = Mapping::anonymous(PAGE_SIZE);
    unsafe { mapping.ptr.cast::<u8>().write(0x5a) };

    mapping.resize(PAGE_SIZE * 2, mm::MremapFlags::MAYMOVE);

    assert_eq!(unsafe { mapping.ptr.cast::<u8>().read() }, 0x5a);
    unsafe { mapping.ptr.cast::<u8>().add(PAGE_SIZE).write(0xa5) };
    assert_eq!(
        unsafe { mapping.ptr.cast::<u8>().add(PAGE_SIZE).read() },
        0xa5
    );
}

#[test]
fn native_mremap_without_maymove_can_shrink_in_place() {
    let mut mapping = Mapping::anonymous(PAGE_SIZE * 2);
    let original = mapping.ptr;
    unsafe {
        mapping.ptr.cast::<u8>().write(0x11);
        mapping.ptr.cast::<u8>().add(PAGE_SIZE).write(0x22);
    }

    mapping.resize(PAGE_SIZE, mm::MremapFlags::empty());

    assert_eq!(
        mapping.ptr, original,
        "a shrink without MAYMOVE stays in place"
    );
    assert_eq!(unsafe { mapping.ptr.cast::<u8>().read() }, 0x11);
}

#[test]
fn native_mremap_fixed_replaces_destination_and_invalidates_both_inputs() {
    let mut source = Mapping::anonymous(PAGE_SIZE);
    let mut destination = Mapping::anonymous(PAGE_SIZE);
    unsafe {
        source.ptr.cast::<u8>().write(0x5a);
        destination.ptr.cast::<u8>().write(0xa5);
    }
    let source_ptr = source.ptr;
    let destination_ptr = destination.ptr;

    let successor = unsafe {
        mm::mremap_fixed(
            source_ptr,
            source.len,
            PAGE_SIZE,
            mm::MremapFlags::MAYMOVE,
            destination_ptr,
        )
    }
    .expect("move mremap fixture to a fixed destination");

    // The source and the destination's former mapping are both consumed by
    // the successful fixed operation. Keep only the returned successor armed
    // for Drop so cleanup cannot issue a second unmap for either range.
    source.ptr = core::ptr::null_mut();
    destination.ptr = successor;
    destination.len = PAGE_SIZE;

    assert_eq!(successor, destination_ptr);
    assert_eq!(unsafe { successor.cast::<u8>().read() }, 0x5a);
}

#[test]
fn native_mremap_rejects_flags_outside_the_closed_facade_contract() {
    let mapping = Mapping::anonymous(PAGE_SIZE);
    let error = unsafe {
        mm::mremap(
            mapping.ptr,
            mapping.len,
            mapping.len,
            mm::MremapFlags::from_bits_retain(0x2),
        )
    }
    .expect_err("the ordinary operation must reject MREMAP_FIXED as a facade flag");

    assert_eq!(error, Errno::INVAL);
}
