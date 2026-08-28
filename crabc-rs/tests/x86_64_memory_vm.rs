//! Linux/x86-64 evidence for the deliberately narrow VM-policy seam.

#![cfg(target_arch = "x86_64")]

use std::process::Command;

use crabc_rs::{mm, process, Errno};

const PAGE_SIZE: usize = 4096;
const KERNEL_BRK_CHILD: &str = "CRABC_RS_X86_64_KERNEL_BRK_CHILD";
const VM_POLICY_CHILD: &str = "CRABC_RS_X86_64_MEMORY_VM_CHILD";

#[test]
fn x86_64_kernel_brk_queries_and_replays_without_allocator_mutation() {
    if std::env::var_os(KERNEL_BRK_CHILD).is_some() {
        let current = unsafe { process::kernel_brk(core::ptr::null_mut()) }
            .expect("Linux brk query is a direct pointer result");
        assert!(
            !current.is_null(),
            "the process has a non-null current break"
        );

        let replayed = unsafe { process::kernel_brk(current) }
            .expect("replaying the current break must remain a no-op");
        assert_eq!(replayed, current);
        return;
    }

    let output = Command::new(std::env::current_exe().expect("locate test binary"))
        .args([
            "--exact",
            "x86_64_kernel_brk_queries_and_replays_without_allocator_mutation",
            "--nocapture",
        ])
        .env(KERNEL_BRK_CHILD, "1")
        .output()
        .expect("run isolated kernel-break child");
    assert!(
        output.status.success(),
        "isolated kernel-break child failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn x86_64_mlockall_flags_are_the_closed_linux_vocabulary() {
    assert_eq!(mm::MlockAllFlags::CURRENT.bits(), 0x1);
    assert_eq!(mm::MlockAllFlags::FUTURE.bits(), 0x2);
    assert_eq!(mm::MlockAllFlags::ONFAULT.bits(), 0x4);
    assert_eq!(mm::MlockAllFlags::all().bits(), 0x7);
    assert_eq!(mm::MlockAllFlags::from_bits(0x8), None);
}

#[test]
fn x86_64_mlockall_is_child_contained_and_unlocked_after_success() {
    if std::env::var_os(VM_POLICY_CHILD).is_some() {
        match mm::mlockall(mm::MlockAllFlags::CURRENT) {
            Ok(()) => mm::munlockall().expect("undo successful process-wide lock"),
            Err(error) => assert!(
                matches!(
                    error,
                    Errno::PERM | Errno::AGAIN | Errno::NOMEM
                ),
                "unexpected mlockall error: {error:?}"
            ),
        }
        return;
    }

    let output = Command::new(std::env::current_exe().expect("locate test binary"))
        .args([
            "--exact",
            "x86_64_mlockall_is_child_contained_and_unlocked_after_success",
            "--nocapture",
        ])
        .env(VM_POLICY_CHILD, "1")
        .output()
        .expect("run isolated VM-policy child");
    assert!(
        output.status.success(),
        "isolated VM-policy child failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn x86_64_remap_file_pages_keeps_legacy_anonymous_error_typed() {
    let mapping = unsafe {
        mm::mmap_anonymous(
            core::ptr::null_mut(),
            PAGE_SIZE,
            mm::ProtFlags::READ | mm::ProtFlags::WRITE,
            mm::MapFlags::PRIVATE,
        )
    }
    .expect("map an anonymous page through the direct VM seam");

    let remap = unsafe { mm::remap_file_pages(mapping, PAGE_SIZE, 0) };
    unsafe { mm::munmap(mapping, PAGE_SIZE) }.expect("unmap rejected legacy-remap mapping");

    assert_eq!(
        remap,
        Err(Errno::INVAL),
        "an anonymous mapping is not a remappable file mapping"
    );
}
