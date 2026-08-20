use std::process::Command;

#[test]
fn strtold_preserves_long_double_precision() {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let fixtures = manifest_dir.join("tests/fixtures");
    let include = manifest_dir.join("include");
    let target = manifest_dir.join("target/debug");
    let ldso_path = target.join("libldso.so");
    let libc_path = target.join("libc.so");
    assert!(ldso_path.exists(), "libldso.so not found");
    assert!(libc_path.exists(), "libc.so not found");

    let src = fixtures.join("strtold_test.c");
    let bin = fixtures.join("strtold_test");
    let mut args = vec![
        "-fPIE".to_string(),
        "-pie".to_string(),
        "-fno-builtin".to_string(),
    ];
    if cfg!(target_arch = "x86_64") {
        args.push("-mlong-double-64".to_string());
    }
    args.extend([
        "-I".to_string(),
        include.to_str().unwrap().to_string(),
        "-Wl,--dynamic-linker".to_string(),
        ldso_path.to_str().unwrap().to_string(),
        "-L".to_string(),
        target.to_str().unwrap().to_string(),
        src.to_str().unwrap().to_string(),
        "-Wl,--allow-shlib-undefined".to_string(),
        "-lc".to_string(),
        "-o".to_string(),
        bin.to_str().unwrap().to_string(),
    ]);
    let status = Command::new("musl-gcc")
        .args(&args)
        .status()
        .expect("failed to run musl-gcc for strtold_test");
    assert!(status.success(), "musl-gcc strtold_test compilation failed");

    let output = Command::new(&bin)
        .env("LD_LIBRARY_PATH", target.to_str().unwrap())
        .output()
        .expect("failed to run strtold_test");
    assert!(
        output.status.success(),
        "strtold_test exited with {:?}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "strtold ok\n");
}
