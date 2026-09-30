#![cfg(target_arch = "x86_64")]

use crabc_rs::{signal, Errno};

#[test]
fn x86_64_signal_mask_query_preserves_the_calling_thread() {
    let before = signal::current_mask().unwrap();
    for how in [signal::SigmaskHow::Block, signal::SigmaskHow::Unblock,
                signal::SigmaskHow::SetMask] {
        assert_eq!(signal::sigprocmask(how, None).unwrap(), before);
        assert_eq!(signal::current_mask().unwrap(), before);
    }
    assert_eq!(signal::block(&signal::SignalSet::EMPTY).unwrap(), before);
    assert_eq!(signal::unblock(&signal::SignalSet::EMPTY).unwrap(), before);
    assert_eq!(signal::current_mask().unwrap(), before);
}

#[test]
fn x86_64_signal_mask_full_set_matches_one_kernel_word() {
    let previous = signal::set_mask(&signal::SignalSet::full()).unwrap();
    let observed = signal::current_mask().unwrap();
    let mut raw = 0_u64;
    // SAFETY: The null input queries one writable kernel-sized output word.
    unsafe {
        crabc_core::signal::rt_sigprocmask_raw(2, core::ptr::null(), &mut raw).unwrap();
    }
    let replaced = signal::set_mask(&previous).unwrap();
    assert_eq!(replaced, observed);
    assert_eq!(signal::current_mask().unwrap(), previous);
    let reserved = (1_u64 << 31) | (1_u64 << 32) | (1_u64 << 33);
    let unmaskable = (1_u64 << 8) | (1_u64 << 18);
    assert_eq!(raw, u64::MAX & !reserved & !unmaskable);
    assert!(!observed.contains(signal::Signal::KILL));
    assert!(!observed.contains(signal::Signal::STOP));
    assert!(observed.contains(signal::Signal::RTMIN));
    assert!(observed.contains(signal::Signal::RTMAX));
    for number in 32..=34 {
        // SAFETY: These are valid Linux numbers used only to inspect the set;
        // no libc-reserved signal is installed, delivered, or added to a mask.
        let reserved_signal = unsafe { signal::Signal::from_raw_unchecked(number) };
        assert!(!observed.contains(reserved_signal));
    }
}

#[test]
fn x86_64_signal_mask_pending_inheritance_and_signalfd_drain() {
    const CHILD: &str = "CRABC_SIGNAL_MASK_TEST_CHILD";
    let mut selected = signal::SignalSet::EMPTY;
    selected.insert(signal::Signal::USR1);
    selected.insert(signal::Signal::USR2);
    selected.insert(signal::Signal::RTMAX);
    let previous = signal::block(&selected).unwrap();
    if std::env::var_os(CHILD).is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("x86_64_signal_mask_pending_inheritance_and_signalfd_drain")
            .arg("--test-threads=1").env(CHILD, "1").status().unwrap();
        signal::set_mask(&previous).unwrap();
        assert!(status.success(), "isolated inherited signal-mask child: {status}");
        return;
    }
    let inherited = signal::current_mask().unwrap();
    for member in [signal::Signal::USR1, signal::Signal::USR2, signal::Signal::RTMAX] {
        assert!(inherited.contains(member));
    }
    assert!(signal::pending().unwrap().is_empty());
    let worker = std::thread::spawn(move || {
        assert_eq!(signal::current_mask().unwrap(), inherited);
        assert!(signal::pending().unwrap().is_empty());
        let mut only_usr1 = signal::SignalSet::EMPTY;
        only_usr1.insert(signal::Signal::USR1);
        let fd = signal::signalfd(&only_usr1, signal::SignalFdFlags::NONBLOCK).unwrap();
        signal::raise(signal::Signal::USR1).unwrap();
        assert!(signal::pending().unwrap().contains(signal::Signal::USR1));
        assert_eq!(signal::read_signalfd(&fd).unwrap().signal(), Some(signal::Signal::USR1));
        assert!(signal::pending().unwrap().is_empty());
        assert_eq!(signal::unblock(&only_usr1).unwrap(), inherited);
        assert!(!signal::current_mask().unwrap().contains(signal::Signal::USR1));
        signal::set_mask(&inherited).unwrap();
    });
    worker.join().unwrap();
    assert_eq!(signal::current_mask().unwrap(), inherited);
    assert!(signal::pending().unwrap().is_empty());
    for member in [signal::Signal::USR1, signal::Signal::USR2, signal::Signal::RTMAX] {
        signal::raise(member).unwrap();
    }
    assert_eq!(signal::pending().unwrap(), selected);
    let mut only_usr1 = signal::SignalSet::EMPTY;
    only_usr1.insert(signal::Signal::USR1);
    let fd = signal::signalfd(&only_usr1, signal::SignalFdFlags::NONBLOCK).unwrap();
    signal::read_signalfd(&fd).unwrap();
    let mut remaining = selected;
    remaining.remove(signal::Signal::USR1);
    assert_eq!(signal::pending().unwrap(), remaining);
    assert_eq!(signal::read_signalfd(&fd).unwrap_err(), Errno::AGAIN);
    signal::signalfd_update(&fd, &remaining).unwrap();
    assert_eq!(signal::read_signalfd(&fd).unwrap().signal(), Some(signal::Signal::USR2));
    assert_eq!(signal::read_signalfd(&fd).unwrap().signal(), Some(signal::Signal::RTMAX));
    assert!(signal::pending().unwrap().is_empty());
    assert_eq!(signal::current_mask().unwrap(), inherited);
    assert_eq!(signal::unblock(&only_usr1).unwrap(), inherited);
    let mut unblocked = inherited;
    unblocked.remove(signal::Signal::USR1);
    assert_eq!(signal::current_mask().unwrap(), unblocked);
    assert_eq!(signal::set_mask(&previous).unwrap(), unblocked);
    assert_eq!(signal::current_mask().unwrap(), previous);
}
