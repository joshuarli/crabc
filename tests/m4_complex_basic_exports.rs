#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

#[test]
fn complex_basic_exports_under_libc_so() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let target = root.join("target/debug");
    let source = root.join("tests/fixtures/m4_complex_basic_exports_test.c");
    let binary = test_support::TempArtifact::new("crabc-m4-complex-basic");

    let mut args = vec![
        "-fPIE".to_string(),
        "-pie".to_string(),
        "-fno-builtin".to_string(),
        "-I".to_string(),
        root.join("include").to_str().unwrap().to_string(),
        "-Wl,--dynamic-linker".to_string(),
        target.join("libldso.so").to_str().unwrap().to_string(),
        "-L".to_string(),
        target.to_str().unwrap().to_string(),
        source.to_str().unwrap().to_string(),
        "-Wl,--allow-shlib-undefined".to_string(),
        "-lc".to_string(),
        "-o".to_string(),
        binary.to_str().unwrap().to_string(),
    ];
    // crabc follows musl's 64-bit long-double ABI for x86_64; AArch64 and
    // riscv64 use the native IEEE binary128 long-double ABI.
    if cfg!(target_arch = "x86_64") {
        args.insert(3, "-mlong-double-64".to_string());
    }

    let status = Command::new("musl-gcc")
        .args(&args)
        .status()
        .expect("failed to compile M4 complex-basic fixture");
    assert!(status.success(), "M4 complex-basic fixture compilation failed");

    let output = Command::new(&binary)
        .env("LD_LIBRARY_PATH", &target)
        .output()
        .expect("failed to run M4 complex-basic fixture");
    let _ = std::fs::remove_file(&binary);
    assert!(
        output.status.success(),
        "M4 complex-basic fixture exited with {:?}, stdout: {}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "m4 complex basic exports ok\n"
    );
}
