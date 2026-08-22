use api::thread;

fn main() {
    let mut local = thread::CpuSet::new();
    assert_eq!(local.count(), 0);
    assert_eq!(local, thread::CpuSet::default());
    local.set(0);
    local.set(thread::CpuSet::MAX_CPU - 1);
    assert!(local.is_set(0));
    assert!(local.is_set(thread::CpuSet::MAX_CPU - 1));
    assert_eq!(local.count(), 2);
    local.unset(0);
    assert!(!local.is_set(0));
    local.clear();
    assert_eq!(local.count(), 0);

    let first = thread::sched_getaffinity(None).expect("read current CPU affinity");
    thread::sched_setaffinity(None, &first)
        .expect("reapply the calling task's observed CPU-affinity mask");
    let second = thread::sched_getaffinity(None).expect("read current CPU affinity again");

    assert!(first.count() > 0);
    assert!(first.count() <= thread::CpuSet::MAX_CPU as u32);
    assert!(second.count() > 0);
    assert!(second.count() <= thread::CpuSet::MAX_CPU as u32);
    for cpu in 0..thread::CpuSet::MAX_CPU {
        assert!(
            !second.is_set(cpu) || first.is_set(cpu),
            "the kernel must not add a CPU outside the requested mask",
        );
    }

    let mut found = false;
    for cpu in 0..thread::CpuSet::MAX_CPU {
        if first.is_set(cpu) {
            found = true;
            break;
        }
    }
    assert!(found);
    println!("m10-sched-getaffinity ok");
}
