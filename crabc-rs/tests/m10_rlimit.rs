use crabc_rs::process::{self, Resource, Rlimit};
use crabc_rs::process::Mode;
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
        (None, Some(_)) => panic!("{resource:?} cannot have an unlimited soft limit below a finite hard limit"),
        (Some(_), None) | (None, None) => {}
    }
}

#[test]
fn getrlimit_reads_every_pinned_linux_resource_with_valid_ordering() {
    for &resource in RESOURCES {
        let limit = process::getrlimit(resource).expect("read Linux resource limit");
        assert_limit_invariant(resource, limit);
    }
}

#[test]
fn getrlimit_is_read_only_and_does_not_change_the_observed_limit() {
    let first = process::getrlimit(Resource::Nofile).expect("read open-file limit");
    let second = process::getrlimit(Resource::Nofile).expect("read open-file limit again");

    assert_eq!(first, second);
    assert_limit_invariant(Resource::Nofile, first);
}

#[test]
fn getrlimit_for_explicit_current_pid_matches_pid_zero_query() {
    let current = process::getrlimit(Resource::Nofile).expect("read current open-file limit");
    let explicit = process::getrlimit_for(Some(process::getpid()), Resource::Nofile)
        .expect("read current open-file limit through explicit PID");

    assert_eq!(explicit, current);
    assert_limit_invariant(Resource::Nofile, explicit);
}

#[test]
fn getrlimit_for_missing_pid_preserves_esrch() {
    let missing = process::Pid::from_raw(i32::MAX).expect("i32::MAX is a non-zero typed PID");
    assert_eq!(
        process::getrlimit_for(Some(missing), Resource::Nofile),
        Err(Errno::SRCH),
    );
}

#[test]
fn umask_returns_previous_mask_and_restores_process_state() {
    let original = process::umask(Mode::empty());
    struct RestoreUmask(Mode);
    impl Drop for RestoreUmask {
        fn drop(&mut self) {
            let _ = process::umask(self.0);
        }
    }
    let _restore = RestoreUmask(original);

    let requested = Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::ROTH;
    assert_eq!(process::umask(requested), Mode::empty());
    assert_eq!(process::umask(Mode::empty()), requested);
}

#[test]
fn setrlimit_changes_a_safe_process_limit_and_restores_it() {
    let resource = Resource::Core;
    let original = process::getrlimit(resource).expect("read core limit before mutation");
    let changed_current = match (original.current, original.maximum) {
        (Some(current), Some(maximum)) if current < maximum => Some(current + 1),
        (Some(current), _) if current > 0 => Some(current - 1),
        (None, None) => Some(1),
        _ => None,
    };

    if let Some(current) = changed_current {
        let changed = Rlimit {
            current: Some(current),
            maximum: original.maximum,
        };
        process::setrlimit(resource, changed).expect("change core limit through prlimit64");
        assert_eq!(process::getrlimit(resource).expect("read changed core limit"), changed);
    }

    process::setrlimit(resource, original).expect("restore core limit through prlimit64");
    assert_eq!(process::getrlimit(resource).expect("read restored core limit"), original);
}

#[test]
fn setrlimit_rejects_an_inverted_limit_before_crossing_the_facade() {
    assert_eq!(
        process::setrlimit(
            Resource::Core,
            Rlimit {
                current: Some(1),
                maximum: Some(0),
            },
        ),
        Err(Errno::INVAL),
    );
}
