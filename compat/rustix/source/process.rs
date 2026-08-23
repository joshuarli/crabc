//! Common Rustix/crabc-rs process-wait source fixture.
//!
//! The fixture deliberately has no child process to reap. Linux reports
//! `ECHILD` for both wait interfaces in this isolated process, so the
//! comparison exercises the shared public API shape and direct error
//! semantics without depending on mutable process state between backends.

use api::process::{self, WaitId, WaitIdOptions, WaitOptions};

fn main() {
    let wait = process::wait(WaitOptions::NOHANG);
    assert_eq!(wait.expect_err("wait without children must fail"), api::io::Errno::CHILD);

    let waitid = process::waitid(
        WaitId::All,
        WaitIdOptions::NOHANG | WaitIdOptions::EXITED,
    );
    assert_eq!(
        waitid.expect_err("waitid without children must fail"),
        api::io::Errno::CHILD
    );

    println!("signal-process-process-wait ok");
}
