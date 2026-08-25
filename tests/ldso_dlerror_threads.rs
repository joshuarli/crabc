#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

#[test]
fn ldso_dlerror_is_thread_local() {
    let manifest_dir = std::path::Path::new(test_support::REPOSITORY_ROOT);
    let fixture = manifest_dir.join("tests/fixtures/ldso_dlerror_threads_test.c");
    let target = manifest_dir.join("target/debug");
    let binary = test_support::TempArtifact::new("ldso_dlerror_threads_test");

    let status = Command::new(test_support::crabc_cc())
        .args([
            "-fPIE",
            "-pie",
            "-D_GNU_SOURCE",
            "-I",
            manifest_dir.join("include").to_str().unwrap(),
            "-L",
            target.to_str().unwrap(),
            fixture.to_str().unwrap(),
            "-Wl,--allow-shlib-undefined",
            "-ldl",
            "-lpthread",
            "-lc",
            "-o",
            binary.to_str().unwrap(),
        ])
        .status()
        .expect("failed to run crabc-cc for dlerror thread fixture");
    assert!(
        status.success(),
        "dlerror thread fixture compilation failed"
    );

    let output = Command::new(&binary)
        .env("LD_LIBRARY_PATH", &target)
        .output()
        .expect("failed to run dlerror thread fixture");
    assert!(
        output.status.success(),
        "dlerror thread fixture exited with {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "dlerror threads ok\n"
    );
}
