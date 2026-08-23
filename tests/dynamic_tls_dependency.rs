#[path = "common/mod.rs"]
mod test_support;

use std::process::{Command, Output};

fn compile_shared(source: &std::path::Path, output: &std::path::Path) {
    let status = Command::new("musl-gcc")
        .args(["-O3", "-fPIC", "-shared", "-fno-builtin"])
        .arg(source)
        .args(["-o"])
        .arg(output)
        .status()
        .expect("failed to compile dynamic TLS dependency DSO");
    assert!(
        status.success(),
        "dynamic TLS dependency DSO compilation failed"
    );
}

fn compile_parent(source: &std::path::Path, directory: &std::path::Path, output: &std::path::Path) {
    let status = Command::new("musl-gcc")
        .args([
            "-O3",
            "-fPIC",
            "-shared",
            "-fno-builtin",
            "-Wl,-rpath,$ORIGIN",
            "-ltls_dependency_child",
        ])
        .arg(source)
        .args(["-L"])
        .arg(directory)
        .args(["-o"])
        .arg(output)
        .status()
        .expect("failed to compile parent dynamic TLS dependency DSO");
    assert!(
        status.success(),
        "parent dynamic TLS dependency DSO compilation failed"
    );
}

fn compile_fixture(binary: &std::path::Path, candidate: bool) {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let target = root.join("target/debug");
    let fixture = root.join("tests/fixtures/dynamic_tls_dependency_test.c");
    let mut command = Command::new("musl-gcc");
    command.args(["-O3", "-fPIE", "-pie", "-fno-builtin"]);
    if candidate {
        command.args([
            "-I",
            root.join("include").to_str().unwrap(),
            "-Wl,--dynamic-linker",
            target.join("libldso.so").to_str().unwrap(),
            "-L",
            target.to_str().unwrap(),
            "-Wl,--allow-shlib-undefined",
        ]);
    }
    command
        .arg(fixture)
        .args(["-ldl", "-lpthread", "-lc", "-o"])
        .arg(binary);
    let status = command
        .status()
        .expect("failed to compile dynamic TLS dependency fixture");
    assert!(
        status.success(),
        "dynamic TLS dependency fixture compilation failed"
    );
}

fn run(
    binary: &std::path::Path,
    parent: &std::path::Path,
    directory: &std::path::Path,
    candidate: bool,
) -> Output {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut command = Command::new(binary);
    command.arg(parent).env("LD_LIBRARY_PATH", directory);
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
        .expect("failed to run dynamic TLS dependency fixture")
}

#[test]
fn dynamic_tls_dependency_graph_matches_pinned_musl() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let fixtures = root.join("tests/fixtures");
    let reference = test_support::TempArtifact::new("dynamic-tls-dependency-reference");
    let candidate = test_support::TempArtifact::new("dynamic-tls-dependency-candidate");
    let parent = test_support::TempArtifact::new("libtls_dependency_parent.so");
    let directory = parent.parent();
    let child = directory.join("libtls_dependency_child.so");

    compile_shared(&fixtures.join("dynamic_tls_dependency_child_dso.c"), &child);
    compile_parent(
        &fixtures.join("dynamic_tls_dependency_parent_dso.c"),
        directory,
        &parent,
    );
    let dependencies = Command::new("readelf")
        .args(["-d"])
        .arg(&parent)
        .output()
        .expect("failed to inspect parent dynamic TLS dependency DSO");
    assert!(
        dependencies.status.success(),
        "readelf failed for parent dynamic TLS DSO"
    );
    assert!(
        String::from_utf8_lossy(&dependencies.stdout)
            .contains("Shared library: [libtls_dependency_child.so]"),
        "parent DSO lacks the child DT_NEEDED edge",
    );
    compile_fixture(&reference, false);
    compile_fixture(&candidate, true);

    let reference_output = run(&reference, &parent, directory, false);
    let candidate_output = run(&candidate, &parent, directory, true);
    assert!(
        reference_output.status.success(),
        "pinned musl fixture failed with {:?}: {}",
        reference_output.status.code(),
        String::from_utf8_lossy(&reference_output.stderr),
    );
    assert_eq!(
        reference_output.stdout,
        b"dynamic TLS dependency graph ok\n"
    );
    assert_eq!(candidate_output.status, reference_output.status);
    assert_eq!(candidate_output.stdout, reference_output.stdout);
    assert_eq!(candidate_output.stderr, reference_output.stderr);

    std::fs::remove_file(child).expect("failed to remove dynamic TLS child DSO");
}
