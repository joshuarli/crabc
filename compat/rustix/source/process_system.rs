use api::{mount, param, process, pty, shm, system, termios, thread};

fn main() {
    let pid = process::getpid();
    assert!(process::getppid().map_or(true, |parent| parent.as_raw_pid() > 0));
    process::test_kill_process(pid).expect("signal-zero self probe");
    assert_eq!(process::getpgid(None).unwrap(), process::getpgrp());
    assert!(thread::gettid().as_raw_pid() > 0);
    thread::sched_yield();

    assert_eq!(param::clock_ticks_per_second(), 100);
    assert!(!system::uname().sysname().to_bytes().is_empty());
    assert!(system::sysinfo().uptime >= 0);

    let master = pty::openpt(pty::OpenptFlags::RDWR | pty::OpenptFlags::CLOEXEC).unwrap();
    pty::grantpt(&master).unwrap();
    pty::unlockpt(&master).unwrap();
    let slave = pty::ioctl_tiocgptpeer(&master, pty::OpenptFlags::RDWR | pty::OpenptFlags::CLOEXEC).unwrap();
    assert!(termios::isatty(&slave));
    let mut attributes = termios::tcgetattr(&slave).unwrap();
    attributes.make_raw();
    attributes.set_speed(9_600).unwrap();
    assert_eq!((attributes.input_speed(), attributes.output_speed()), (9_600, 9_600));
    termios::tcsetattr(&slave, termios::OptionalActions::Now, &attributes).unwrap();
    let size = termios::tcgetwinsize(&slave).unwrap();
    termios::tcsetwinsize(&slave, size).unwrap();

    let name = format!("/crabc-rs-c-abi-source-{}", pid.as_raw_pid());
    let _ = shm::unlink(&name);
    let object = shm::open(
        &name,
        shm::OFlags::CREATE | shm::OFlags::EXCL | shm::OFlags::RDWR,
        shm::Mode::RUSR | shm::Mode::WUSR,
    )
    .unwrap();
    drop(object);
    shm::unlink(&name).unwrap();

    assert!(mount::unmount("/crabc-rs-c-abi-source-not-mounted", mount::UnmountFlags::empty()).is_err());
    println!("c-abi-process-system ok");
}
