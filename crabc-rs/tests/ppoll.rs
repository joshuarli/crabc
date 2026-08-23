use crabc_rs::{event, io, pipe, process, signal, time};

unsafe extern "C" fn ppoll_signal_handler(_: process::Signal) {}

fn child_ppoll_case(reader: &crabc_rs::OwnedFd, result: &crabc_rs::OwnedFd) -> ! {
    let mut selected = signal::SignalSet::EMPTY;
    selected.insert(process::Signal::USR1);

    let action = signal::SigAction::new(
        signal::SigHandler::Simple(ppoll_signal_handler),
        signal::SignalSet::EMPTY,
        signal::SigActionFlags::empty(),
    );
    let old_action = match unsafe { signal::sigaction(process::Signal::USR1, Some(&action)) } {
        Ok(action) => action,
        Err(_) => child_report(result, 1),
    };
    let old_mask = match signal::block(&selected) {
        Ok(mask) => mask,
        Err(_) => child_report(result, 2),
    };
    if signal::raise(process::Signal::USR1).is_err() {
        child_report(result, 3);
    }

    let timeout = time::Timespec::default();
    let mut fds = [event::PollFd::new(reader, event::PollFlags::IN)];
    if event::ppoll(&mut fds, Some(&timeout), Some(&selected)) != Ok(0) {
        child_report(result, 4);
    }
    if !signal::pending().map(|pending| pending.contains(process::Signal::USR1)).unwrap_or(false) {
        child_report(result, 5);
    }

    let empty = signal::SignalSet::EMPTY;
    let timeout = time::Timespec { tv_sec: 1, tv_nsec: 0 };
    let interrupted = event::ppoll(&mut fds, Some(&timeout), Some(&empty));
    if interrupted != Err(crabc_rs::Errno::INTR) {
        child_report(result, 6);
    }
    if !signal::current_mask()
        .map(|mask| mask.contains(process::Signal::USR1))
        .unwrap_or(false)
    {
        child_report(result, 7);
    }

    if signal::set_mask(&old_mask).is_err() {
        child_report(result, 8);
    }
    if unsafe { signal::sigaction(process::Signal::USR1, Some(&old_action)) }.is_err() {
        child_report(result, 9);
    }
    child_report(result, 0)
}

fn child_report(result: &crabc_rs::OwnedFd, status: u8) -> ! {
    let _ = io::write(result, &[status]);
    process::exit_immediately(0)
}

#[test]
fn ppoll_temporarily_installs_signal_mask_and_preserves_legacy_poll() {
    let (reader, writer) = pipe::pipe().expect("create poll fixture pipe");
    let (result_reader, result_writer) = pipe::pipe().expect("create result pipe");

    let child = match unsafe { process::fork_raw() }.expect("fork isolated ppoll case") {
        process::ForkResult::Parent { child } => child,
        process::ForkResult::Child => child_ppoll_case(&reader, &result_writer),
    };
    drop(writer);
    drop(result_writer);

    let mut status = [0_u8; 1];
    assert_eq!(io::read(&result_reader, &mut status).expect("read ppoll child result"), 1);
    assert_eq!(status[0], 0, "isolated ppoll case failed at step {}", status[0]);
    let (_, wait_status) = process::waitpid(Some(child), process::WaitOptions::empty())
        .expect("wait for isolated ppoll child")
        .expect("isolated ppoll child changed state");
    assert_eq!(wait_status.exit_status(), Some(0));
}

#[test]
fn poll_without_mask_keeps_existing_unmasked_contract() {
    let (reader, writer) = pipe::pipe().expect("create legacy poll fixture pipe");
    let timeout = time::Timespec::default();
    let mut fds = [event::PollFd::new(&reader, event::PollFlags::IN)];
    assert_eq!(event::poll(&mut fds, Some(&timeout)).expect("legacy poll"), 0);
    assert!(fds[0].revents().is_empty());
    drop(writer);
}
