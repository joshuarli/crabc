#[path = "common/mod.rs"]
mod test_support;

use std::process::{Command, Output};

fn assert_candidate_free_uses_native_shadow() {
    let root = std::path::Path::new(test_support::REPOSITORY_ROOT);
    let libc = root.join("target/debug/libc.so");
    let output = Command::new("objdump")
        .args(["-d", "--demangle", "--disassemble=free"])
        .arg(&libc)
        .output()
        .expect("failed to disassemble the selected candidate libc");
    assert!(
        output.status.success(),
        "could not disassemble selected candidate libc {}: {}",
        libc.display(),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("crabc_mimalloc::runtime_lifecycle::native_free"),
        "candidate libc free does not resolve to the Rust native shadow route"
    );
}

fn compile_fixture(binary: &std::path::Path, candidate: bool) {
    let root = std::path::Path::new(test_support::REPOSITORY_ROOT);
    let fixture = root.join("tests/fixtures/native_mimalloc_initial_post_exit_free_test.c");
    let mut command = if candidate {
        Command::new(test_support::crabc_cc())
    } else {
        Command::new("musl-gcc")
    };
    command.args(["-fPIE", "-pie", "-fno-builtin"]);
    if candidate {
        command.args([
            "-I",
            root.join("include").to_str().unwrap(),
            "-L",
            root.join("target/debug").to_str().unwrap(),
            "-Wl,--allow-shlib-undefined",
        ]);
    }
    command.arg(&fixture).args(["-lc", "-o"]).arg(binary);
    let status = command
        .status()
        .expect("failed to compile the native mimalloc initial-post-exit-free fixture");
    assert!(
        status.success(),
        "native mimalloc initial-post-exit-free fixture compilation failed"
    );
}

fn run(binary: &std::path::Path, candidate: bool) -> Output {
    let root = std::path::Path::new(test_support::REPOSITORY_ROOT);
    let mut command = Command::new(binary);
    if candidate {
        command.env("LD_LIBRARY_PATH", root.join("target/debug"));
    }
    command
        .output()
        .expect("failed to run the native mimalloc initial-post-exit-free fixture")
}

#[test]
fn native_mimalloc_initial_post_exit_free_matches_pinned_musl() {
    let reference =
        test_support::TempArtifact::new("native-mimalloc-initial-post-exit-free-reference");
    let candidate =
        test_support::TempArtifact::new("native-mimalloc-initial-post-exit-free-candidate");
    compile_fixture(&reference, false);
    compile_fixture(&candidate, true);

    assert_candidate_free_uses_native_shadow();

    let reference_output = run(&reference, false);
    let candidate_output = run(&candidate, true);
    assert!(
        reference_output.status.success(),
        "pinned musl fixture failed with {:?}: {}",
        reference_output.status.code(),
        String::from_utf8_lossy(&reference_output.stderr),
    );
    assert_eq!(reference_output.stdout, b"ok\n");
    assert_eq!(
        candidate_output.status,
        reference_output.status,
        "crabc exit status differs; stderr: {}",
        String::from_utf8_lossy(&candidate_output.stderr),
    );
    assert_eq!(candidate_output.stdout, reference_output.stdout);
    assert_eq!(candidate_output.stderr, reference_output.stderr);
}
