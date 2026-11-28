use crabc_rs::process::{self, Mode};

struct RestoreUmask(Mode);

impl Drop for RestoreUmask {
    fn drop(&mut self) {
        let _ = process::umask(self.0);
    }
}

#[test]
fn x86_64_umask_returns_the_previous_typed_mask_and_restores_process_state() {
    // The native facade runner uses one test thread. Keep the process-global
    // transition restore-safe even when an assertion below unwinds.
    let original = process::umask(Mode::empty());
    let _restore = RestoreUmask(original);

    let requested = Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::ROTH;
    assert_eq!(process::umask(requested), Mode::empty());
    assert_eq!(process::umask(Mode::empty()), requested);
}
