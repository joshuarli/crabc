#![cfg(target_arch = "x86_64")]

use crabc_rs::process::{self, SchedulerPolicy};

#[test]
fn x86_64_scheduler_priority_bounds_match_linux_policy_values() {
    let policies = [
        (SchedulerPolicy::Other, (0, 0)),
        (SchedulerPolicy::Fifo, (1, 99)),
        (SchedulerPolicy::RoundRobin, (1, 99)),
    ];

    for (policy, expected) in policies {
        let bounds = process::scheduler_priority_bounds(policy)
            .expect("Linux must expose bounds for each admitted scheduler policy");
        assert_eq!((bounds.minimum(), bounds.maximum()), expected);
        assert!(bounds.minimum() <= bounds.maximum());
    }
}

#[test]
fn x86_64_scheduler_priority_bounds_are_stable_read_only_observations() {
    for policy in [
        SchedulerPolicy::Other,
        SchedulerPolicy::Fifo,
        SchedulerPolicy::RoundRobin,
    ] {
        let first = process::scheduler_priority_bounds(policy)
            .expect("first scheduler-priority observation");
        let second = process::scheduler_priority_bounds(policy)
            .expect("second scheduler-priority observation");
        assert_eq!(first, second);
    }
}
