#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

#[test]
fn credential_mutation_profile_limitation_preserves_ids() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let target = root.join("target/debug");
    let source = root.join("tests/fixtures/credentials_profile_test.c");
    let binary = test_support::TempArtifact::new("crabc-c-abi-credentials-profile");

    let status = Command::new("musl-gcc")
        .args([
            "-std=c11",
            "-fPIE",
            "-pie",
            "-fno-builtin",
            "-D_GNU_SOURCE",
            "-I",
            root.join("include").to_str().unwrap(),
            "-Wl,--dynamic-linker",
            target.join("libldso.so").to_str().unwrap(),
            "-L",
            target.to_str().unwrap(),
            source.to_str().unwrap(),
            "-Wl,--allow-shlib-undefined",
            "-lc",
            "-o",
            binary.to_str().unwrap(),
        ])
        .status()
        .expect("failed to compile credentials_profile_test");
    assert!(
        status.success(),
        "musl-gcc credentials_profile_test compilation failed"
    );

    let output = Command::new(&binary)
        .env("LD_LIBRARY_PATH", &target)
        .output()
        .expect("failed to run credentials_profile_test");
    let _ = std::fs::remove_file(&binary);

    assert!(
        output.status.success(),
        "credentials_profile_test exited with {:?}, stdout: {}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "c-abi credentials profile ok\n"
    );
}
