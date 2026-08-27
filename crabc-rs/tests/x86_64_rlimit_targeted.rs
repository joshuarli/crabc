#![cfg(target_arch = "x86_64")]

use crabc_rs::process::{self, Resource};
use crabc_rs::Errno;

// This remains private record-owning evidence. The direct x86 slice admits
// only `process::getrlimit`, which always uses PID zero.
#[test]
fn x86_64_getrlimit_for_explicit_current_pid_matches_zero() {
    let implicit = process::getrlimit_for(None, Resource::Nofile)
        .expect("read current open-file limit through implicit PID");
    let direct = process::getrlimit(Resource::Nofile).expect("read current open-file limit");
    assert_eq!(implicit, direct);

    let explicit = process::getrlimit_for(Some(process::getpid()), Resource::Nofile)
        .expect("read current open-file limit through explicit PID");
    assert_eq!(explicit, direct);
}

#[test]
fn x86_64_getrlimit_for_missing_pid_preserves_esrch() {
    let missing = process::Pid::from_raw(i32::MAX).expect("i32::MAX is non-zero");
    assert_eq!(
        process::getrlimit_for(Some(missing), Resource::Nofile),
        Err(Errno::SRCH),
    );
}
