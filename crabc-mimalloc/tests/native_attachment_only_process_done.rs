#![cfg(feature = "native-runtime-test-audit")]

#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;

use crabc_mimalloc::__crabc_runtime::{
    SelectedProcessDoneResult, ThreadAttachResult, attach_current_thread,
    finish_selected_default_release_process_after_user_atexit,
    native_runtime_current_thread_attachment_test_audit, prepare_native_later_thread_arena,
};

const CHILD: &str = "CRABC_NATIVE_ATTACHMENT_ONLY_PROCESS_DONE_CHILD";

/// An adopted worker can become the final process task without ever asking
/// for an application page. Pinned init.c::mi_process_done_once retains that
/// valid TLD/Theap just as it retains an owner with allocated pages. A direct
/// kernel exit follows process done, so this final task never loses its TLS
/// owner to ordinary thread teardown after deleting automatic thread cleanup.
#[test]
fn attachment_only_worker_may_run_source_process_done() {
    if std::env::var_os(CHILD).is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--nocapture")
            .arg("--exact")
            .arg("attachment_only_worker_may_run_source_process_done")
            .env(CHILD, "1")
            .status()
            .expect("the isolated final-task process starts");
        assert_eq!(status.code(), Some(0), "a page-empty worker is a valid final process owner");
        return;
    }

    let page_size = crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ).unwrap();
    assert!(native_runtime_test_support::initialize(page_size));
    assert!(prepare_native_later_thread_arena());
    std::thread::spawn(|| {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        let attached = native_runtime_current_thread_attachment_test_audit();
        assert_eq!(attached.persistent_owner_installed, 1);
        assert_eq!(attached.page_engine_active, 0);
        let done = finish_selected_default_release_process_after_user_atexit();
        if done != SelectedProcessDoneResult::Completed {
            eprintln!("attachment-only process done returned {done:?}");
            crabc_core::process::exit_immediately(101);
        }
        crabc_core::process::exit_immediately(0);
    }).join().expect("the final task exits the process without returning");
    panic!("the final task must not return after source process done");
}
