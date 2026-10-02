#![cfg(all(target_arch = "x86_64", feature = "alloc"))]

use std::ffi::{CStr, CString};
use std::os::unix::ffi::OsStrExt;
use crabc_rs::{process, signal, Errno};

fn cstr(bytes: &'static [u8]) -> &'static CStr {
    CStr::from_bytes_with_nul(bytes).unwrap()
}

#[test]
fn x86_64_child_options_exec_observer() {
    let Some(mode) = std::env::var_os("CRABC_CHILD_OPTIONS_OBSERVER") else { return };
    let pid = process::getpid();
    if mode == "session" {
        assert_eq!(process::getsid(None).unwrap(), pid);
        assert_eq!(process::getpgrp(), pid);
    } else {
        assert_eq!(process::getpgrp(), pid);
    }
    let mask = signal::current_mask().unwrap();
    assert!(mask.contains(signal::Signal::USR1));
    assert!(!mask.contains(signal::Signal::USR2));
}

#[test]
fn x86_64_prepared_child_options_survive_exec_without_changing_parent() {
    let executable = CString::new(std::env::current_exe().unwrap().as_os_str().as_bytes()).unwrap();
    let argv = [executable.as_c_str(), cstr(b"--exact\0"),
        cstr(b"x86_64_child_options_exec_observer\0")];
    let mut parent_mask = signal::current_mask().unwrap();
    parent_mask.insert(signal::Signal::USR2);
    parent_mask.remove(signal::Signal::USR1);
    let old_mask = signal::set_mask(&parent_mask).unwrap();
    let parent_group = process::getpgrp();
    let parent_session = process::getsid(None).unwrap();
    let mut child_mask = signal::SignalSet::EMPTY;
    child_mask.insert(signal::Signal::USR1);
    for (mode, options) in [
        (cstr(b"CRABC_CHILD_OPTIONS_OBSERVER=group\0"), process::SpawnOptions::new().process_group(None)),
        (cstr(b"CRABC_CHILD_OPTIONS_OBSERVER=session\0"), process::SpawnOptions::new().new_session(true)),
    ] {
        let prepared = process::PreparedExec::new(executable.as_c_str(), &argv, &[mode]).unwrap()
            .with_options(options.signal_mask(&child_mask));
        assert_eq!(prepared.spawn().unwrap().wait(process::WaitOptions::empty())
            .unwrap().unwrap().exit_status(), Some(0));
    }
    let invalid = process::PreparedExec::new(executable.as_c_str(), &argv, &[]).unwrap()
        .with_options(process::SpawnOptions::new().new_session(true).process_group(None));
    // A new session leader cannot also change its process group; report the
    // child setup error through the private pipe rather than executing.
    assert_eq!(invalid.spawn().unwrap_err(), Errno::PERM);
    let observed_mask = signal::current_mask().unwrap();
    signal::set_mask(&old_mask).unwrap();
    assert_eq!(observed_mask, parent_mask);
    assert_eq!(process::getpgrp(), parent_group);
    assert_eq!(process::getsid(None).unwrap(), parent_session);
}
