#[path = "common/mod.rs"]
mod test_support;

use std::path::Path;
use std::process::{Command, Output};

const INTERPOSITION_DSO: &str = "libnative_mimalloc_shadow_interposition.so";

fn compile_malloc_fixture(source: &Path, binary: &Path, candidate: bool) {
    let root = Path::new(test_support::REPOSITORY_ROOT);
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
    command.arg(source).args(["-lc", "-o"]).arg(binary);
    let status = command
        .status()
        .expect("failed to compile native mimalloc shadow ABI fixture");
    assert!(
        status.success(),
        "native mimalloc shadow ABI fixture compilation failed: {source:?}"
    );
}

fn run_malloc_fixture(binary: &Path, candidate: bool) -> Output {
    let root = Path::new(test_support::REPOSITORY_ROOT);
    let mut command = Command::new(binary);
    if candidate {
        command.env("LD_LIBRARY_PATH", root.join("target/debug"));
    }
    command
        .output()
        .expect("failed to run native mimalloc shadow ABI fixture")
}

fn assert_musl_differential(source_name: &str, expected_stdout: &[u8]) {
    let root = Path::new(test_support::REPOSITORY_ROOT);
    let source = root.join("tests/fixtures").join(source_name);
    let reference = test_support::TempArtifact::new(&format!("{source_name}-reference"));
    let candidate = test_support::TempArtifact::new(&format!("{source_name}-candidate"));

    compile_malloc_fixture(&source, &reference, false);
    compile_malloc_fixture(&source, &candidate, true);
    let reference_output = run_malloc_fixture(&reference, false);
    let candidate_output = run_malloc_fixture(&candidate, true);

    assert!(
        reference_output.status.success(),
        "pinned musl fixture {source_name} failed with {:?}: {}",
        reference_output.status.code(),
        String::from_utf8_lossy(&reference_output.stderr),
    );
    assert_eq!(reference_output.stdout, expected_stdout);
    assert_eq!(reference_output.stderr, b"");
    assert_eq!(
        candidate_output.status,
        reference_output.status,
        "selected native shadow differs for {source_name}; stderr: {}",
        String::from_utf8_lossy(&candidate_output.stderr),
    );
    assert_eq!(candidate_output.stdout, reference_output.stdout);
    assert_eq!(candidate_output.stderr, reference_output.stderr);
}

fn defined_symbol(output: &str, symbol: &str) -> Vec<(String, String)> {
    output
        .lines()
        .filter_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() < 8
                || fields[3] != "FUNC"
                || fields[6] == "UND"
                || fields[7].split('@').next() != Some(symbol)
            {
                return None;
            }
            Some((fields[4].to_owned(), fields[5].to_owned()))
        })
        .collect()
}

fn readelf_symbols(path: &Path, dynamic: bool) -> String {
    let mut command = Command::new("readelf");
    if dynamic {
        command.args(["--dyn-syms", "--wide"]);
    } else {
        command.args(["--syms", "--wide"]);
    }
    let output = command
        .arg(path)
        .output()
        .expect("failed to inspect selected native shadow symbols");
    assert!(
        output.status.success(),
        "readelf failed for {}: {}",
        path.display(),
        String::from_utf8_lossy(&output.stderr),
    );
    String::from_utf8(output.stdout).expect("readelf output is UTF-8")
}

#[test]
fn native_mimalloc_shadow_completes_missing_local_abi_contracts() {
    assert_musl_differential(
        "native_mimalloc_shadow_abi_test.c",
        b"native mimalloc shadow abi ok\n",
    );
}

#[test]
fn native_mimalloc_shadow_matches_pinned_musl_for_one_live_foreign_reallocation() {
    assert_musl_differential(
        "native_mimalloc_shadow_foreign_realloc_test.c",
        b"native mimalloc shadow foreign realloc ok\n",
    );
}

#[test]
fn native_mimalloc_shadow_symbols_preserve_static_and_dynamic_linkage_contracts() {
    let root = Path::new(test_support::REPOSITORY_ROOT);
    let dynamic = readelf_symbols(&root.join("target/debug/libc.so"), true);
    let archive = readelf_symbols(&root.join("target/debug/libc.a"), false);

    // The selected debug archive is not the installed static sysroot runtime:
    // that archive remains the default C backend until promotion. Inspect the
    // selected archive's binding here without mislabeling a default-static
    // executable as native-shadow execution evidence.
    assert_eq!(
        defined_symbol(&dynamic, "malloc"),
        vec![("WEAK".to_owned(), "DEFAULT".to_owned())],
        "selected dynamic libc must retain musl's weak/default-visible malloc"
    );
    let strong_symbols = [
        "free",
        "calloc",
        "realloc",
        "aligned_alloc",
        "posix_memalign",
        "malloc_usable_size",
    ];
    for symbol in strong_symbols {
        let definitions = defined_symbol(&dynamic, symbol);
        assert_eq!(
            definitions.len(),
            1,
            "selected dynamic libc has wrong {symbol} definition count"
        );
        assert_eq!(
            definitions[0].0, "GLOBAL",
            "selected dynamic {symbol} binding drifted"
        );
        assert_eq!(
            definitions[0].1, "DEFAULT",
            "selected dynamic {symbol} visibility drifted"
        );
    }
    assert_eq!(
        defined_symbol(&archive, "malloc"),
        vec![("WEAK".to_owned(), "DEFAULT".to_owned())],
        "selected static libc must retain musl's weak/default-visible malloc"
    );
    for symbol in strong_symbols {
        assert_eq!(
            defined_symbol(&archive, symbol),
            vec![("GLOBAL".to_owned(), "DEFAULT".to_owned())],
            "selected static {symbol} binding or visibility drifted"
        );
    }
}

#[test]
fn native_mimalloc_shadow_allows_executable_interposition_across_a_dso() {
    let root = Path::new(test_support::REPOSITORY_ROOT);
    let fixtures = root.join("tests/fixtures");
    let target = root.join("target/debug");
    let dso = test_support::TempArtifact::new(INTERPOSITION_DSO);
    let executable = test_support::TempArtifact::new("native-mimalloc-shadow-interposition");

    let dso_status = Command::new(test_support::crabc_cc())
        .args(["-shared", "-fPIC", "-fno-builtin"])
        .arg(fixtures.join("native_mimalloc_shadow_interposition_dso.c"))
        .args([
            "-L",
            target.to_str().unwrap(),
            "-Wl,--allow-shlib-undefined",
            "-lc",
            "-o",
        ])
        .arg(&dso)
        .status()
        .expect("failed to compile native mimalloc shadow interposition DSO");
    assert!(dso_status.success(), "interposition DSO compilation failed");

    let executable_status = Command::new(test_support::crabc_cc())
        .args(["-fPIE", "-pie", "-fno-builtin"])
        .arg(fixtures.join("native_mimalloc_shadow_interposition_test.c"))
        .args(["-L", dso.parent().to_str().unwrap()])
        .arg(format!("-l:{INTERPOSITION_DSO}"))
        .args([
            "-L",
            target.to_str().unwrap(),
            "-Wl,--allow-shlib-undefined",
            "-lc",
            "-o",
        ])
        .arg(&executable)
        .status()
        .expect("failed to compile native mimalloc shadow interposition executable");
    assert!(
        executable_status.success(),
        "interposition executable compilation failed"
    );

    let dso_relocations = Command::new("readelf")
        .args(["--relocs", "--wide"])
        .arg(&dso)
        .output()
        .expect("failed to inspect interposition DSO relocations");
    assert!(dso_relocations.status.success());
    let dso_relocations = String::from_utf8_lossy(&dso_relocations.stdout);
    for symbol in [
        "malloc",
        "free",
        "calloc",
        "realloc",
        "aligned_alloc",
        "posix_memalign",
        "malloc_usable_size",
    ] {
        assert!(
            dso_relocations.lines().any(|line| {
                line.contains("R_AARCH64_JUMP_SLOT")
                    && line.split_whitespace().any(|field| field == symbol)
            }),
            "interposition DSO does not call {symbol} through a JUMP_SLOT"
        );
    }

    let library_path = std::env::join_paths([dso.parent(), target.as_path()])
        .expect("interposition library path is valid");
    let output = Command::new(&executable)
        .env("LD_LIBRARY_PATH", library_path)
        .output()
        .expect("failed to run native mimalloc shadow interposition fixture");
    assert!(
        output.status.success(),
        "interposition fixture failed with {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(
        output.stdout,
        b"native mimalloc shadow interposition ok\n"
    );
    assert_eq!(output.stderr, b"");
}
