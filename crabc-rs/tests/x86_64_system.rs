#![cfg(target_arch = "x86_64")]

use crabc_rs::system;

#[test]
fn x86_64_uname_returns_linux_fixed_record_fields() {
    let value = system::uname();
    assert_eq!(value.sysname().to_bytes(), b"Linux");
    assert!(!value.nodename().to_bytes().is_empty());
    assert!(!value.release().to_bytes().is_empty());
    assert!(!value.version().to_bytes().is_empty());
    assert!(!value.machine().to_bytes().is_empty());
    let _ = value.domainname().to_bytes();
}

#[test]
fn x86_64_sysinfo_and_load_average_are_native_observations() {
    let before = system::sysinfo();
    let after = system::sysinfo();
    assert!(before.uptime >= 0);
    assert!(after.uptime >= before.uptime);
    assert!(before.procs > 0);

    let load = system::load_average();
    assert!(load.one_minute.is_finite());
    assert!(load.five_minutes.is_finite());
    assert!(load.fifteen_minutes.is_finite());
    assert!(load.one_minute >= 0.0);
    assert!(load.five_minutes >= 0.0);
    assert!(load.fifteen_minutes >= 0.0);
}
