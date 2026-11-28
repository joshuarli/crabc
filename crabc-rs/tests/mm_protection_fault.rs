use std::os::unix::process::ExitStatusExt;
use std::process::Command;

use crabc_rs::{mm, signal::Signal};

const FAULT_CHILD: &str = "CRABC_RS_MM_PROTECTION_FAULT_CHILD";

#[cfg(target_os = "linux")]
const PAGE_SIZE: usize = 4096;
#[cfg(target_os = "macos")]
const PAGE_SIZE: usize = 16384;

#[cfg(target_os = "linux")]
const PROTECTION_FAULT: Signal = Signal::SEGV;
// XNU reports an access that the page protection forbids as SIGBUS.
#[cfg(target_os = "macos")]
const PROTECTION_FAULT: Signal = Signal::BUS;

/// Maps one page, stores a byte, then applies `protection` and touches the
/// page in the way that protection forbids. Returning means no fault arrived.
fn fault_after(protection: mm::MprotectFlags, write: bool) {
    // SAFETY: a null hint asks for a fresh mapping that this child owns.
    let page = unsafe {
        mm::mmap_anonymous(
            core::ptr::null_mut(),
            PAGE_SIZE,
            mm::ProtFlags::READ | mm::ProtFlags::WRITE,
            mm::MapFlags::PRIVATE,
        )
    }
    .expect("map one page")
    .cast::<u8>();
    // SAFETY: the page is mapped writable.
    unsafe { page.write_volatile(0x5a) };
    // SAFETY: no reference into the page exists across the change.
    unsafe { mm::mprotect(page.cast(), PAGE_SIZE, protection) }.expect("change protection");
    if write {
        // SAFETY: the page stays mapped; the forbidden store is the fault
        // under test and ends this child process.
        unsafe { page.write_volatile(0xa5) };
    } else {
        // SAFETY: as above, for a forbidden load.
        let _ = unsafe { page.read_volatile() };
    }
}

fn run_child(test: &str, mode: &str) -> std::process::ExitStatus {
    Command::new(std::env::current_exe().expect("locate test binary"))
        .args(["--exact", test, "--nocapture", "--test-threads=1"])
        .env(FAULT_CHILD, mode)
        .output()
        .expect("run protection-fault child")
        .status
}

#[test]
fn protection_changes_take_effect_in_a_child_and_spare_the_parent() {
    let test = "protection_changes_take_effect_in_a_child_and_spare_the_parent";
    match std::env::var(FAULT_CHILD).as_deref() {
        Ok("read-only-store") => {
            fault_after(mm::MprotectFlags::READ, true);
            return;
        }
        Ok("inaccessible-load") => {
            fault_after(mm::MprotectFlags::empty(), false);
            return;
        }
        Ok("readable-load") => {
            fault_after(mm::MprotectFlags::READ, false);
            return;
        }
        _ => {}
    }

    for mode in ["read-only-store", "inaccessible-load"] {
        let status = run_child(test, mode);
        assert_eq!(
            status.signal(),
            Some(PROTECTION_FAULT.as_raw()),
            "{mode} child must die from a protection fault: {status:?}",
        );
    }
    let status = run_child(test, "readable-load");
    assert!(status.success(), "a load from a read-only page is allowed: {status:?}");

    // SAFETY: a null hint asks for a fresh mapping this test owns.
    let page = unsafe {
        mm::mmap_anonymous(
            core::ptr::null_mut(),
            PAGE_SIZE,
            mm::ProtFlags::READ | mm::ProtFlags::WRITE,
            mm::MapFlags::PRIVATE,
        )
    }
    .expect("map one parent page")
    .cast::<u8>();
    // SAFETY: the page is mapped writable.
    unsafe { page.write_volatile(0x11) };
    // SAFETY: no reference into the page exists across the change.
    unsafe { mm::mprotect(page.cast(), PAGE_SIZE, mm::MprotectFlags::READ) }
        .expect("make the parent page read-only");
    // SAFETY: the page is readable.
    assert_eq!(unsafe { page.read_volatile() }, 0x11);
    // SAFETY: no reference into the page exists across the change.
    unsafe { mm::mprotect(page.cast(), PAGE_SIZE, mm::MprotectFlags::READ | mm::MprotectFlags::WRITE) }
        .expect("restore parent write access");
    // SAFETY: the page is writable again.
    unsafe { page.write_volatile(0x22) };
    // SAFETY: the page is readable.
    assert_eq!(unsafe { page.read_volatile() }, 0x22);
    // SAFETY: no pointer into the page is used after this unmap.
    unsafe { mm::munmap(page.cast(), PAGE_SIZE) }.expect("unmap parent page");
}
