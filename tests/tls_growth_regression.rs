#[path = "common/mod.rs"]
mod test_support;

use std::process::{Command, Output};

const MODULES: u32 = 8;

fn compile_tls_dsos(directory: &std::path::Path) {
    let root = std::path::Path::new(test_support::REPOSITORY_ROOT);
    let source = root.join("compat/perf/fixtures/tls_growth_dso.c");
    for index in 0..MODULES {
        let binary = directory.join(format!("libbench_tls_growth_{index}.so"));
        let status = Command::new(test_support::crabc_cc())
            .args([
                // Optimized AArch64 TLSDESC callers preserve their thread
                // pointer in x1 across the resolver call. Keep this aligned
                // with the performance fixture so the direct differential
                // catches a resolver that follows only the ordinary C ABI.
                "-O3",
                "-fPIC",
                "-shared",
                "-fno-builtin",
                &format!("-DTLS_GROWTH_INDEX={index}"),
            ])
            .arg(&source)
            .args(["-o"])
            .arg(binary)
            .status()
            .expect("failed to compile a dynamic TLS growth DSO");
        assert!(
            status.success(),
            "dynamic TLS growth DSO compilation failed"
        );
    }
}

fn compile_fixture(binary: &std::path::Path, candidate: bool) {
    let root = std::path::Path::new(test_support::REPOSITORY_ROOT);
    let target = root.join("target/debug");
    let fixture = root.join("tests/fixtures/tls_growth_regression_test.c");
    let mut command = if candidate {
        Command::new(test_support::crabc_cc())
    } else {
        Command::new("musl-gcc")
    };
    command.args(["-O3", "-fPIE", "-pie", "-fno-builtin"]);
    if candidate {
        command.args([
            "-I",
            root.join("include").to_str().unwrap(),
            "-L",
            target.to_str().unwrap(),
            "-Wl,--allow-shlib-undefined",
        ]);
    }
    command
        .arg(&fixture)
        .args(["-ldl", "-lpthread", "-lc", "-o"])
        .arg(binary);
    let status = command
        .status()
        .expect("failed to compile the dynamic TLS growth regression fixture");
    assert!(
        status.success(),
        "dynamic TLS growth regression fixture compilation failed"
    );
}

fn run(binary: &std::path::Path, directory: &std::path::Path, candidate: bool) -> Output {
    let root = std::path::Path::new(test_support::REPOSITORY_ROOT);
    let mut command = Command::new(binary);
    command.arg(directory).env("LD_LIBRARY_PATH", directory);
    if candidate {
        command.env(
            "LD_LIBRARY_PATH",
            format!(
                "{}:{}",
                directory.display(),
                root.join("target/debug").display()
            ),
        );
    }
    command
        .output()
        .expect("failed to run the dynamic TLS growth regression fixture")
}

#[test]
fn dynamic_tls_growth_matches_pinned_musl() {
    let reference = test_support::TempArtifact::new("tls-growth-reference");
    let candidate = test_support::TempArtifact::new("tls-growth-candidate");
    let dso_anchor = test_support::TempArtifact::new("libbench_tls_growth_0.so");
    let dso_directory = dso_anchor.parent();
    compile_tls_dsos(dso_directory);
    compile_fixture(&reference, false);
    compile_fixture(&candidate, true);

    let reference_output = run(&reference, dso_directory, false);
    let candidate_output = run(&candidate, dso_directory, true);
    assert!(
        reference_output.status.success(),
        "pinned musl fixture failed with {:?}: {}",
        reference_output.status.code(),
        String::from_utf8_lossy(&reference_output.stderr),
    );
    assert_eq!(reference_output.stdout, b"dynamic TLS growth contract ok\n");
    assert_eq!(
        candidate_output.status,
        reference_output.status,
        "crabc exit status differs; stderr: {}",
        String::from_utf8_lossy(&candidate_output.stderr),
    );
    assert_eq!(candidate_output.stdout, reference_output.stdout);
    assert_eq!(candidate_output.stderr, reference_output.stderr);

    for index in 1..MODULES {
        std::fs::remove_file(dso_directory.join(format!("libbench_tls_growth_{index}.so")))
            .expect("failed to remove a dynamic TLS growth DSO");
    }
}
