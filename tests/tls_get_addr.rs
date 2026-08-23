#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

#[test]
fn public_tls_get_addr_resolves_a_dso_tls_image() {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let fixtures = manifest_dir.join("tests/fixtures");
    let include = manifest_dir.join("include");
    let target = manifest_dir.join("target/debug");
    let ldso = target.join("libldso.so");
    let dso = test_support::TempArtifact::new("libtls_get_addr.so");
    let temp_dir = dso.parent();
    let binary = test_support::TempArtifact::new("tls_get_addr_test");

    let status = Command::new("musl-gcc")
        .args([
            "-shared",
            "-fPIC",
            fixtures.join("libtls_get_addr.c").to_str().unwrap(),
            "-o",
            dso.to_str().unwrap(),
        ])
        .status()
        .expect("failed to build TLS DSO");
    assert!(status.success(), "TLS DSO compilation failed");

    let status = Command::new("musl-gcc")
        .args([
            "-fPIE",
            "-pie",
            "-I",
            include.to_str().unwrap(),
            fixtures.join("tls_get_addr_test.c").to_str().unwrap(),
            "-Wl,--dynamic-linker",
            ldso.to_str().unwrap(),
            "-L",
            target.to_str().unwrap(),
            "-Wl,--allow-shlib-undefined",
            "-ldl",
            "-lc",
            "-o",
            binary.to_str().unwrap(),
        ])
        .status()
        .expect("failed to build TLS ABI test");
    assert!(status.success(), "TLS ABI test compilation failed");

    let output = Command::new(&binary)
        .env(
            "LD_LIBRARY_PATH",
            format!("{}:{}", temp_dir.display(), target.display()),
        )
        .output()
        .expect("failed to run TLS ABI test");
    assert!(
        output.status.success(),
        "TLS ABI test exited with {:?}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "tls get addr ok\n");
}
