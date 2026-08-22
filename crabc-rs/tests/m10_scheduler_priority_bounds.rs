use crabc_rs::process::{self, SchedulerPolicy};

#[test]
fn scheduler_priority_bounds_match_the_three_pinned_linux_policies() {
    let policies = [
        (SchedulerPolicy::Other, (0, 0)),
        (SchedulerPolicy::Fifo, (1, 99)),
        (SchedulerPolicy::RoundRobin, (1, 99)),
    ];

    for (policy, expected) in policies {
        let bounds = process::scheduler_priority_bounds(policy)
            .expect("Linux must expose bounds for the three closed policies");
        assert_eq!((bounds.minimum(), bounds.maximum()), expected);
        assert!(bounds.minimum() <= bounds.maximum());
    }
}

#[test]
fn scheduler_priority_bounds_are_stable_and_read_only() {
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
