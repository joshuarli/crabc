use crabc_rs::{fs, mount, param, process, pty, shm, system, termios, thread, Errno};

#[test]
fn process_thread_and_system_identity_use_direct_kernel_state() {
    let pid = process::getpid();
    assert!(pid.as_raw_pid() > 0);
    assert!(process::getppid().map_or(true, |parent| parent.as_raw_pid() > 0));
    process::test_kill_process(pid).expect("the current process accepts a signal-zero probe");
    assert_eq!(process::getpgid(None).expect("get current process group"), process::getpgrp());
    assert!(thread::gettid().as_raw_pid() > 0);
    thread::sched_yield();

    assert_eq!(param::clock_ticks_per_second(), 100);
    let uname = system::uname();
    assert!(!uname.sysname().to_bytes().is_empty());
    assert!(!uname.machine().to_bytes().is_empty());
    let info = system::sysinfo();
    assert!(info.mem_unit == 0 || info.mem_unit.is_power_of_two());
}

#[test]
fn terminal_and_pty_operations_have_typed_linux_contracts() {
    let master = pty::openpt(pty::OpenptFlags::RDWR | pty::OpenptFlags::CLOEXEC)
        .expect("open a close-on-exec PTY master");
    pty::grantpt(&master).expect("validate devpts grant");
    pty::unlockpt(&master).expect("unlock PTY slave");
    let name = pty::ptsname(&master, Vec::new()).expect("derive slave device name");
    assert!(name.as_bytes().starts_with(b"/dev/pts/"));

    let slave = pty::ioctl_tiocgptpeer(&master, pty::OpenptFlags::RDWR | pty::OpenptFlags::CLOEXEC)
        .expect("open unlocked PTY slave through the direct ioctl");
    assert!(termios::isatty(&slave));
    let mut attributes = termios::tcgetattr(&slave).expect("read slave terminal attributes");
    attributes.make_raw();
    attributes.set_speed(9_600).expect("set a portable numeric baud rate");
    assert_eq!((attributes.input_speed(), attributes.output_speed()), (9_600, 9_600));
    assert_eq!(attributes.set_speed(123_456).unwrap_err(), Errno::INVAL);
    assert_eq!((attributes.input_speed(), attributes.output_speed()), (9_600, 9_600));
    termios::tcsetattr(&slave, termios::OptionalActions::Now, &attributes)
        .expect("apply raw terminal attributes");
    let size = termios::tcgetwinsize(&slave).expect("read slave terminal size");
    termios::tcsetwinsize(&slave, size).expect("restore terminal size");

    let not_a_tty = fs::open("/dev/null", fs::OFlags::RDONLY, fs::Mode::empty())
        .expect("open deterministic non-terminal");
    assert!(!termios::isatty(&not_a_tty));
}

#[test]
fn shm_namespace_and_mount_errors_remain_direct_and_state_free() {
    let name = format!("/crabc-rs-m4-{}", process::getpid().as_raw_pid());
    match shm::unlink(&name) {
        Ok(()) | Err(Errno::NOENT) => {}
        Err(error) => panic!("remove stale shared-memory name: {error}"),
    }
    let descriptor = shm::open(
        &name,
        fs::OFlags::CREATE | fs::OFlags::EXCL | fs::OFlags::RDWR,
        fs::Mode::RUSR | fs::Mode::WUSR,
    )
    .expect("create a close-on-exec shared-memory object");
    drop(descriptor);
    shm::unlink(&name).expect("unlink shared-memory object");
    assert_eq!(shm::open("/", fs::OFlags::RDWR, fs::Mode::empty()).unwrap_err(), Errno::INVAL);

    let result = mount::unmount("/crabc-rs-m4-definitely-not-mounted", mount::UnmountFlags::empty());
    assert!(result.is_err(), "a nonexistent mount point must not report success");
}
