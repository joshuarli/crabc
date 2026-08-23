#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

#[test]
fn ctype_assert_exports_under_libc_so() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let target = root.join("target/debug");
    let source = root.join("tests/fixtures/ctype_assert_exports_test.c");
    let binary = test_support::TempArtifact::new("crabc-c-abi-ctype-assert");

    let mut args = vec![
        "-fPIE".to_string(),
        "-pie".to_string(),
        "-fno-builtin".to_string(),
        "-D_GNU_SOURCE".to_string(),
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
    // crabc's x86_64 libc uses the binary64 long-double ABI.  AArch64 and
    // riscv64 use IEEE binary128, which is the ABI represented by f128 above.
    if cfg!(target_arch = "x86_64") {
        args.insert(3, "-mlong-double-64".to_string());
    }

    let status = Command::new("musl-gcc")
        .args(&args)
        .status()
        .expect("failed to compile ctype_assert_exports_test");
    assert!(
        status.success(),
        "ctype_assert_exports_test compilation failed"
    );

    let output = Command::new(&binary)
        .env("LD_LIBRARY_PATH", &target)
        .output()
        .expect("failed to run ctype_assert_exports_test");
    let _ = std::fs::remove_file(&binary);
    assert!(
        output.status.success(),
        "ctype_assert_exports_test exited with {:?}, stdout: {}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "c-abi ctype assert exports ok\n"
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "Assertion failed: value != 0 (ctype_assert_exports_test.c: main: 77)\n"
    );
}
