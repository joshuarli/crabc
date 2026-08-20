#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

#[test]
fn legacy_formatting_exports_under_libc_so() {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let fixtures = manifest_dir.join("tests/fixtures");
    let include = manifest_dir.join("include");
    let target = manifest_dir.join("target/debug");
    let ldso_path = target.join("libldso.so");
    let libc_path = target.join("libc.so");
    assert!(ldso_path.exists(), "libldso.so not found");
    assert!(libc_path.exists(), "libc.so not found");

    let src = fixtures.join("m4_legacy_formatting_test.c");
    let bin = test_support::TempArtifact::new("m4_legacy_formatting_test");
    let status = Command::new("musl-gcc")
        .args([
            "-fPIE",
            "-pie",
            "-fno-builtin",
            "-D_GNU_SOURCE",
            "-I",
            include.to_str().unwrap(),
            "-Wl,--dynamic-linker",
            ldso_path.to_str().unwrap(),
            "-L",
            target.to_str().unwrap(),
            src.to_str().unwrap(),
            "-Wl,--allow-shlib-undefined",
            "-lc",
            "-o",
            bin.to_str().unwrap(),
        ])
        .status()
        .expect("failed to run musl-gcc for m4_legacy_formatting_test");
    assert!(
        status.success(),
        "musl-gcc m4_legacy_formatting_test compilation failed"
    );

    let output = Command::new(&bin)
        .env("LD_LIBRARY_PATH", &target)
        .output()
        .expect("failed to run m4_legacy_formatting_test");
    assert!(
        output.status.success(),
        "m4_legacy_formatting_test exited with {:?}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "m4 legacy formatting ok\n"
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "LBL: ERROR: TEXT\nTO FIX: FIX TAG\nLBL: TEXT\n"
    );
}
