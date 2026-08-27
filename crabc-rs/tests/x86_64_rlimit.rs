#![cfg(target_arch = "x86_64")]

use crabc_rs::process::{self, Resource, Rlimit};

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
fn x86_64_getrlimit_is_read_only_and_stable() {
    let first = process::getrlimit(Resource::Nofile).expect("read open-file limit");
    let second = process::getrlimit(Resource::Nofile).expect("read open-file limit again");
    assert_eq!(first, second);
    assert_limit_invariant(Resource::Nofile, first);
}
