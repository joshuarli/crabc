#[path = "common/mod.rs"]
mod test_support;

use std::process::{Command, Output};

fn compile_fixture(binary: &std::path::Path) {
    let root = std::path::Path::new(test_support::REPOSITORY_ROOT);
    let fixture = root.join("tests/fixtures/native_mimalloc_owner_exit_realloc_test.c");
    let mut command = Command::new(test_support::crabc_cc());
    command.args(["-fPIE", "-pie", "-fno-builtin"]);
    command.args([
        "-I",
        root.join("include").to_str().unwrap(),
        "-L",
        root.join("target/debug").to_str().unwrap(),
        "-Wl,--allow-shlib-undefined",
    ]);
    command.arg(&fixture).args(["-lc", "-o"]).arg(binary);
    let status = command
        .status()
        .expect("failed to compile the native mimalloc post-exit realloc fixture");
    assert!(
        status.success(),
        "native mimalloc post-exit realloc fixture compilation failed"
    );
}

fn run(binary: &std::path::Path) -> Output {
    let root = std::path::Path::new(test_support::REPOSITORY_ROOT);
    Command::new(binary)
        .env("LD_LIBRARY_PATH", root.join("target/debug"))
        .output()
        .expect("failed to run the native mimalloc post-exit realloc fixture")
}

#[test]
fn native_mimalloc_owner_exit_realloc_freezes_b_client_through_pthread_exit_and_cancellation() {
    let candidate = test_support::TempArtifact::new("native-mimalloc-owner-exit-realloc-candidate");
    compile_fixture(&candidate);

    let output = run(&candidate);
    assert!(
        output.status.success(),
        "the selected native shadow rejected its post-exit realloc contract with {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(
        output.stdout,
        b"native mimalloc owner exit realloc ok\n"
    );
    assert_eq!(output.stderr, b"");
}
