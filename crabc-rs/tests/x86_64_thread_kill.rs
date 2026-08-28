#![cfg(target_arch = "x86_64")]

use core::sync::atomic::{AtomicBool, AtomicI32, Ordering};

use crabc_rs::{signal, thread, Errno};

const THREAD_KILL_CHILD: &str = "CRABC_RS_X86_64_THREAD_KILL_CHILD";
const SIG_SETMASK: i32 = 2;
const SIGUSR1_MASK: u64 = 1 << (signal::Signal::USR1.as_raw() - 1);

// `tgkill` must select this worker rather than merely enqueueing a
// process-directed signal. The handler records its own TID using the direct,
// reentrant `gettid` syscall and performs no allocation or locking.
static HANDLER_TID: AtomicI32 = AtomicI32::new(0);

unsafe extern "C" fn record_delivery_thread(_: signal::Signal) {
    HANDLER_TID.store(crabc_core::thread::gettid(), Ordering::SeqCst);
}

struct RestoreSignalMask(u64);

impl Drop for RestoreSignalMask {
    fn drop(&mut self) {
        // SAFETY: This child-local guard restores exactly the calling thread's
        // one-word kernel mask saved before the test temporarily unblocked
        // SIGUSR1. The worker has already exited before normal drop.
        let _ = unsafe {
            crabc_core::signal::rt_sigprocmask_raw(
                SIG_SETMASK,
                &self.0,
                core::ptr::null_mut(),
            )
        };
    }
}

fn unmask_usr1_for_worker_inheritance() -> RestoreSignalMask {
    let mut saved = 0_u64;
    // SAFETY: A null input queries the calling thread's one-word kernel mask.
    unsafe {
        crabc_core::signal::rt_sigprocmask_raw(
            SIG_SETMASK,
            core::ptr::null(),
            &mut saved,
        )
        .expect("query child SIGUSR1 mask");
    }
    let unblocked = saved & !SIGUSR1_MASK;
    // SAFETY: The initialized replacement differs only by unblocking SIGUSR1
    // before the worker inherits this test-controlled mask.
    unsafe {
        crabc_core::signal::rt_sigprocmask_raw(
            SIG_SETMASK,
            &unblocked,
            core::ptr::null_mut(),
        )
        .expect("unblock child SIGUSR1 before starting worker");
    }
    RestoreSignalMask(saved)
}

/// Proves the staged facade selects an exact live thread in the calling
/// process, and keeps its process-wide signal disposition inside a disposable
/// test child.
#[test]
fn x86_64_kill_thread_targets_the_selected_live_worker_and_preserves_errors() {
    if std::env::var_os(THREAD_KILL_CHILD).is_some() {
        thread_kill_child();
        return;
    }

    let output = std::process::Command::new(std::env::current_exe().expect("locate test binary"))
        .args([
            "--exact",
            "x86_64_kill_thread_targets_the_selected_live_worker_and_preserves_errors",
            "--nocapture",
        ])
        .env(THREAD_KILL_CHILD, "1")
        .output()
        .expect("run isolated thread-kill child");
    assert!(
        output.status.success(),
        "isolated thread-kill child failed with {:?}, stdout: {}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn thread_kill_child() {
    let selected = signal::Signal::USR1;
    let old_action = unsafe { signal::sigaction(selected, None) }
        .expect("query SIGUSR1 action before direct thread delivery");
    let action = signal::SigAction::new(
        signal::SigHandler::Simple(record_delivery_thread),
        signal::SigActionFlags::empty(),
    );
    // SAFETY: The static handler remains installed through the worker join;
    // it only records its own TID with direct, signal-safe primitives.
    unsafe { signal::sigaction(selected, Some(&action)) }
        .expect("install disposable SIGUSR1 delivery handler");
    let _restore_mask = unmask_usr1_for_worker_inheritance();

    HANDLER_TID.store(0, Ordering::SeqCst);
    let release_worker = std::sync::Arc::new(AtomicBool::new(false));
    let worker_release = std::sync::Arc::clone(&release_worker);
    let (tid_sender, tid_receiver) = std::sync::mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        let tid = thread::gettid();
        tid_sender.send(tid).expect("publish live worker TID");
        while !worker_release.load(Ordering::Acquire) {
            core::hint::spin_loop();
        }
    });
    let worker_tid = tid_receiver
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("receive live worker TID");

    signal::kill_thread(worker_tid, selected).expect("deliver SIGUSR1 to the selected worker");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
    while HANDLER_TID.load(Ordering::Acquire) == 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "selected worker did not run the direct SIGUSR1 handler"
        );
        std::thread::yield_now();
    }
    assert_eq!(
        HANDLER_TID.load(Ordering::Acquire),
        worker_tid.as_raw_pid(),
        "tgkill must run the handler on the selected worker, not merely in this process",
    );

    // `i32::MAX` cannot be a Linux task ID, so the kernel must preserve
    // `tgkill`'s direct missing-thread error for the calling process's TGID.
    let impossible_tid = signal::Pid::from_raw(i32::MAX).expect("positive typed impossible TID");
    assert_eq!(
        signal::kill_thread(impossible_tid, selected),
        Err(Errno::SRCH),
    );
    // SAFETY: 65 is non-zero but outside Linux's signal range; this isolated
    // direct call must return the kernel error without delivering a signal.
    let invalid_signal = unsafe { signal::Signal::from_raw_unchecked(65) };
    assert_eq!(signal::kill_thread(worker_tid, invalid_signal), Err(Errno::INVAL));

    release_worker.store(true, Ordering::Release);
    worker.join().expect("join selected worker after delivery");
    // SAFETY: No worker remains and the temporary handler has completed, so
    // the action obtained before this child-local replacement can be restored.
    unsafe { signal::sigaction(selected, Some(&old_action)) }
        .expect("restore child SIGUSR1 action");
}
