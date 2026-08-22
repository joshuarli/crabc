use crabc_rs::param;

#[test]
fn auxv_values_are_present_and_stable() {
    let page_size = param::page_size();
    assert!(page_size != 0 && page_size.is_power_of_two());
    assert_eq!(page_size, param::page_size());

    let (hwcap, hwcap2) = param::linux_hwcap();
    assert_ne!(hwcap, 0);
    assert_eq!((hwcap, hwcap2), param::linux_hwcap());

    let minimum_signal_stack = param::linux_minsigstksz();
    assert_ne!(minimum_signal_stack, 0);
    assert_eq!(minimum_signal_stack, param::linux_minsigstksz());

    assert!(!param::linux_execfn().to_bytes().is_empty());
}
