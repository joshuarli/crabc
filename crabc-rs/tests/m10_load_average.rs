use crabc_rs::system;

#[test]
fn typed_load_average_matches_linux_sysinfo_fixed_point_values() {
    let info = system::sysinfo();
    let loads = system::load_average();

    assert_eq!(loads.one_minute, info.loads[0] as f64 / 65_536.0);
    assert_eq!(loads.five_minutes, info.loads[1] as f64 / 65_536.0);
    assert_eq!(loads.fifteen_minutes, info.loads[2] as f64 / 65_536.0);
    assert!(loads.one_minute.is_finite() && loads.one_minute >= 0.0);
    assert!(loads.five_minutes.is_finite() && loads.five_minutes >= 0.0);
    assert!(loads.fifteen_minutes.is_finite() && loads.fifteen_minutes >= 0.0);
}
