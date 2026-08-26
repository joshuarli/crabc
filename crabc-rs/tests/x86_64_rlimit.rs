#![cfg(target_arch = "x86_64")]

use crabc_rs::process::{self, Resource, Rlimit};
use crabc_rs::Errno;

const RESOURCES: &[Resource] = &[
    Resource::Cpu,
    Resource::Fsize,
    Resource::Data,
    Resource::Stack,
    Resource::Core,
    Resource::Rss,
    Resource::Nproc,
    Resource::Nofile,
    Resource::Memlock,
    Resource::As,
    Resource::Locks,
    Resource::Sigpending,
    Resource::Msgqueue,
    Resource::Nice,
    Resource::Rtprio,
    Resource::Rttime,
];

fn assert_limit_invariant(resource: Resource, limit: Rlimit) {
    match (limit.current, limit.maximum) {
        (Some(current), Some(maximum)) => assert!(
            current <= maximum,
            "{resource:?} returned a soft limit above its hard limit",
        ),
        (None, Some(_)) => {
            panic!("{resource:?} cannot have an unlimited soft limit below a finite hard limit")
        }
        (Some(_), None) | (None, None) => {}
    }
}

#[test]
fn x86_64_getrlimit_reads_all_pinned_resources_with_valid_ordering() {
    for (raw, &resource) in RESOURCES.iter().enumerate() {
        assert_eq!(resource.as_raw(), raw as u32);
        let limit = process::getrlimit(resource).expect("read Linux resource limit");
        assert_limit_invariant(resource, limit);
    }
}

#[test]
fn x86_64_getrlimit_is_read_only_and_explicit_current_pid_matches_zero() {
    let first = process::getrlimit(Resource::Nofile).expect("read open-file limit");
    let second = process::getrlimit(Resource::Nofile).expect("read open-file limit again");
    assert_eq!(first, second);
    assert_limit_invariant(Resource::Nofile, first);

    let implicit = process::getrlimit_for(None, Resource::Nofile)
        .expect("read current open-file limit through implicit PID");
    assert_eq!(implicit, first);

    let explicit = process::getrlimit_for(Some(process::getpid()), Resource::Nofile)
        .expect("read current open-file limit through explicit PID");
    assert_eq!(explicit, first);
}

#[test]
fn x86_64_getrlimit_for_missing_pid_preserves_esrch() {
    let missing = process::Pid::from_raw(i32::MAX).expect("i32::MAX is non-zero");
    assert_eq!(
        process::getrlimit_for(Some(missing), Resource::Nofile),
        Err(Errno::SRCH),
    );
}
