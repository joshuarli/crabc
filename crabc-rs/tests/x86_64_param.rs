#![cfg(target_arch = "x86_64")]

use crabc_rs::param;

#[test]
fn x86_64_auxv_scalar_values_are_stable_without_exposing_execfn() {
    let page_size = param::page_size();
    assert!(page_size != 0, "Linux supplies AT_PAGESZ");
    assert!(page_size.is_power_of_two(), "Linux page size is a power of two");
    assert_eq!(page_size, param::page_size());

    assert_eq!(param::clock_ticks_per_second(), 100);

    let hwcap = param::linux_hwcap();
    assert_eq!(hwcap, param::linux_hwcap());

    let minimum_signal_stack = param::linux_minsigstksz();
    assert_eq!(minimum_signal_stack, param::linux_minsigstksz());
}
