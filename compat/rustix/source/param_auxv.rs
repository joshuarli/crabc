use api::param;

fn main() {
    let page_size = param::page_size();
    assert!(page_size != 0 && page_size.is_power_of_two());
    assert_eq!(page_size, param::page_size());

    let (hwcap, hwcap2) = param::linux_hwcap();
    assert_ne!(hwcap, 0);
    assert_eq!((hwcap, hwcap2), param::linux_hwcap());
    assert_ne!(param::linux_minsigstksz(), 0);
    assert!(!param::linux_execfn().to_bytes().is_empty());
    println!("native-param-auxv ok");
}
