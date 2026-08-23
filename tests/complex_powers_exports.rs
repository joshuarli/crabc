#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

#[test]
fn complex_power_exports_under_libc_so() {
    let root = std::path::Path::new(test_support::REPOSITORY_ROOT);
    let target = root.join("target/debug");
    let source = root.join("tests/fixtures/complex_powers_exports_test.c");
    let binary = test_support::TempArtifact::new("crabc-c-abi-complex-powers");

    let args = vec![
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
    let status = Command::new("musl-gcc")
        .args(&args)
        .status()
        .expect("failed to compile complex-powers fixture");
    assert!(
        status.success(),
        "complex-powers fixture compilation failed"
    );

    let output = Command::new(&binary)
        .env("LD_LIBRARY_PATH", &target)
        .output()
        .expect("failed to run complex-powers fixture");
    assert!(
        output.status.success(),
        "complex-powers fixture exited with {:?}, stdout: {}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "c-abi complex powers exports ok\n"
    );
}
