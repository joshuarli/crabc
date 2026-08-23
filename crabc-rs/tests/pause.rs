use core::sync::atomic::{AtomicBool, Ordering};

use crabc_rs::{event, io, pipe, process, signal, time, Errno};

static ALARM_SEEN: AtomicBool = AtomicBool::new(false);

unsafe extern "C" fn alarm_handler(_: process::Signal) {
    ALARM_SEEN.store(true, Ordering::Relaxed);
}

fn child_pause_case(result: &crabc_rs::OwnedFd) -> ! {
    ALARM_SEEN.store(false, Ordering::Relaxed);

    let action = signal::SigAction::new(
        signal::SigHandler::Simple(alarm_handler),
        signal::SignalSet::EMPTY,
        signal::SigActionFlags::empty(),
    );
    let old_action = match unsafe { signal::sigaction(process::Signal::ALARM, Some(&action)) } {
        Ok(action) => action,
        Err(_) => child_report(result, 1),
    };
    // Make the mask known before arming the timer and entering pause. The
    // child exits after the check, so this state cannot leak into the test.
    let old_mask = match signal::set_mask(&signal::SignalSet::EMPTY) {
        Ok(mask) => mask,
        Err(_) => child_report(result, 2),
    };
    if time::alarm(1).is_err() {
        child_report(result, 3);
    }
    if io::write(result, &[0xA5]).is_err() {
        child_report(result, 4);
    }

    event::pause();
    if !ALARM_SEEN.load(Ordering::Relaxed) {
        child_report(result, 5);
    }

    let cleanup_ok = time::alarm(0).is_ok()
        && signal::set_mask(&old_mask).is_ok()
        // SAFETY: `old_action` was returned by the successful installation
        // above and remains valid in this isolated child.
        && unsafe { signal::sigaction(process::Signal::ALARM, Some(&old_action)).is_ok() };
    if !cleanup_ok {
        child_report(result, 6);
    }
    child_report(result, 0)
}

fn child_report(result: &crabc_rs::OwnedFd, status: u8) -> ! {
    let _ = io::write(result, &[status]);
    process::exit_immediately(0)
}

fn read_phase(reader: &crabc_rs::OwnedFd) -> u8 {
    for _ in 0..400 {
        let mut phase = [0_u8; 1];
        match io::read(reader, &mut phase) {
            Ok(1) => return phase[0],
            Ok(0) => panic!("pause child closed its result pipe before reporting"),
            Ok(_) => unreachable!("one-byte phase read cannot be longer"),
            Err(Errno::AGAIN) => std::thread::sleep(std::time::Duration::from_millis(5)),
            Err(error) => panic!("read pause child result: {error:?}"),
        }
    }
    panic!("pause child did not report setup within the deadline")
}

#[test]
fn pause_blocks_in_an_isolated_child_until_handler_delivery_and_cleans_up() {
    let (result_reader, result_writer) =
        pipe::pipe_with(pipe::PipeFlags::NONBLOCK | pipe::PipeFlags::CLOEXEC)
            .expect("create pause result pipe");
    let child = match unsafe { process::fork_raw() }.expect("fork isolated pause case") {
        process::ForkResult::Parent { child } => child,
        process::ForkResult::Child => child_pause_case(&result_writer),
    };
    drop(result_writer);

    assert_eq!(read_phase(&result_reader), 0xA5, "pause child setup failed");

    let status = (0..500)
        .find_map(|_| {
            match process::waitpid(Some(child), process::WaitOptions::NOHANG)
                .expect("poll pause child status")
            {
                Some((_, status)) => Some(status),
                None => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                    None
                }
            }
        })
        .unwrap_or_else(|| {
            let _ = process::kill_process(child, process::Signal::KILL);
            process::waitpid(Some(child), process::WaitOptions::empty())
                .expect("reap timed-out pause child")
                .expect("timed-out pause child status")
                .1
        });
    assert_eq!(status.exit_status(), Some(0), "pause child status: {status:?}");

    let mut completion = [0_u8; 1];
    assert_eq!(
        io::read(&result_reader, &mut completion).expect("read pause completion"),
        1,
    );
    assert_eq!(completion[0], 0, "pause child failed cleanup");
}
