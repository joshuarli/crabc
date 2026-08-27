#![cfg(target_arch = "x86_64")]

use std::process::Command;

use crabc_rs::{
    process::{self, Resource, Rlimit},
    Errno,
};

struct RestoreRlimit {
    original: Rlimit,
    active: bool,
}

impl Drop for RestoreRlimit {
    fn drop(&mut self) {
        if self.active {
            let _ = process::setrlimit(Resource::Core, self.original);
        }
    }
}

fn reversible_core_limit(original: Rlimit) -> Rlimit {
    let current = match (original.current, original.maximum) {
        // `maximum` is finite here, so incrementing `current` cannot produce
        // the `u64::MAX` infinity sentinel.
        (Some(current), Some(maximum)) if current < maximum => Some(current + 1),
        // With an unlimited hard limit, lowering a nonzero soft limit is
        // always reversible without requiring a privilege change.
        (Some(current), _) if current > 0 => Some(current - 1),
        // The two unlimited/soft-zero cases can safely raise the soft limit
        // without changing the hard limit.
        (Some(0), None) | (None, None) => Some(1),
        // A zero hard limit is already the only valid closed state. Still
        // exercise the setter with that exact valid record.
        _ => original.current,
    };
    Rlimit {
        current,
        maximum: original.maximum,
    }
}

#[test]
fn x86_64_setrlimit_is_child_contained_and_validates_before_the_syscall() {
    let output = Command::new(std::env::current_exe().expect("locate test binary"))
        .args([
            "--exact",
            "x86_64_setrlimit_child_mutates_and_restores",
            "--ignored",
            "--nocapture",
        ])
        .output()
        .expect("run isolated resource-limit child");
    assert!(
        output.status.success(),
        "isolated resource-limit child failed with {:?}, stdout: {}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
#[ignore = "the parent regression invokes this test only in a subprocess"]
fn x86_64_setrlimit_child_mutates_and_restores() {
    assert_eq!(
        process::setrlimit(
            Resource::Core,
            Rlimit {
                current: None,
                maximum: Some(0),
            },
        ),
        Err(Errno::INVAL),
        "an inverted rlimit must be rejected before it can change state",
    );

    let original = process::getrlimit(Resource::Core)
        .expect("read the inherited core limit in the isolated child");
    let changed = reversible_core_limit(original);
    let mut restore = RestoreRlimit {
        original,
        active: true,
    };

    process::setrlimit(Resource::Core, changed)
        .expect("set a valid calling-process core limit through prlimit64");
    assert_eq!(
        process::getrlimit(Resource::Core).expect("read changed core limit"),
        changed,
    );

    process::setrlimit(Resource::Core, original)
        .expect("restore the inherited core limit before child exit");
    restore.active = false;
    assert_eq!(
        process::getrlimit(Resource::Core).expect("read restored core limit"),
        original,
    );
}
