//! Common Rustix/crabc-rs source fixture for the shared VM-policy subset.
//!
//! Legacy `brk`/`sbrk` and `remap_file_pages` are intentionally absent from
//! Rustix's public API, so this fixture compares the overlapping typed
//! `madvise` and process-wide lock operations only.

use api::mm::{self, Advice, MapFlags, MlockAllFlags, ProtFlags};

const PAGE_SIZE: usize = 4096;

fn main() {
    let mapping = unsafe {
        mm::mmap_anonymous(
            core::ptr::null_mut(),
            PAGE_SIZE,
            ProtFlags::READ | ProtFlags::WRITE,
            MapFlags::PRIVATE,
        )
    }
    .expect("map one anonymous page");

    unsafe { mm::madvise(mapping, PAGE_SIZE, Advice::Normal) }
        .expect("ordinary advisory should succeed");

    // Locking is subject to the process memlock limit.  Both backends expose
    // the same direct result; only undo the process-wide policy when the
    // request succeeded.
    if mm::mlockall(MlockAllFlags::CURRENT).is_ok() {
        mm::munlockall().expect("undo successful process-wide lock");
    }

    unsafe { mm::munmap(mapping, PAGE_SIZE) }.expect("unmap advised mapping");
    println!("m10-memory-vm ok");
}
