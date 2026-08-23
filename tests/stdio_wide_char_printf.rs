#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

#[test]
fn stdio_printf_wide_character_conversion_under_libc_so() {
    let root = std::path::Path::new(test_support::REPOSITORY_ROOT);
    let binary = test_support::TempArtifact::new("stdio_wide_char_printf_test");
    let status = Command::new("musl-gcc")
        .args([
            "-fPIE",
            "-pie",
            "-I",
            root.join("include").to_str().unwrap(),
            "-Wl,--dynamic-linker",
            root.join("target/debug/libldso.so").to_str().unwrap(),
            "-L",
            root.join("target/debug").to_str().unwrap(),
            root.join("tests/fixtures/stdio_wide_char_printf_test.c")
                .to_str()
                .unwrap(),
            "-Wl,--allow-shlib-undefined",
            "-lc",
            "-o",
            binary.to_str().unwrap(),
        ])
        .status()
        .expect("failed to compile stdio wide-character printf fixture");
    assert!(
        status.success(),
        "stdio wide-character printf fixture compilation failed"
    );

    let output = Command::new(&binary)
        .env("LD_LIBRARY_PATH", root.join("target/debug"))
        .output()
        .expect("failed to run stdio wide-character printf fixture");
    assert!(
        output.status.success(),
        "stdio wide-character printf fixture exited with {:?}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "/etc/alpine-release: ASCII text\n"
    );
}
