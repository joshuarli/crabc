//! Helpers for integration tests that compile and run crabc-linked artifacts.
//!
//! The workspace integration suite deliberately separates its two runtime
//! roles. C fixtures link through the sealed installed `crabc-cc` driver, so
//! their startup objects and compiler helpers cannot come from musl or GCC.
//! They may still execute against `target/debug` libraries when a regression
//! is specifically exercising the current debug loader/libc image; the test
//! dispatcher stages that owned loader at crabc's canonical interpreter path.
//!
//! Fixtures are inputs and must remain untouched.  Every artifact produced by
//! a test gets a process-unique path in `temp_dir()` and is removed when the
//! guard goes out of scope.

#![allow(dead_code)]

use std::ffi::OsStr;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

/// The repository root remains the authority for C fixtures and installed
/// headers even though `crabc-libc` owns these integration-test targets.
pub const REPOSITORY_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/..");

/// The only interpreter used by new crabc-linked test executables.
pub const CANONICAL_INTERPRETER: &str = "/lib/ld-crabc-aarch64.so.1";

static NEXT_ARTIFACT: AtomicU64 = AtomicU64::new(0);

/// Return the installed owned sysroot prepared by `scripts/dev.sh test`.
///
/// A direct `cargo test` remains usable after `scripts/dev.sh sysroot`: the
/// default is the canonical development output. The dispatcher supplies the
/// environment value so a test never infers a target runtime from `PATH` or a
/// musl compiler wrapper.
pub fn owned_sysroot() -> PathBuf {
    let sysroot = std::env::var_os("CRABC_TEST_SYSROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(REPOSITORY_ROOT).join("target/crabc-sysroot"));
    assert!(
        sysroot.join("share/crabc/manifest.json").is_file(),
        "owned crabc sysroot is unavailable at {}; run ./scripts/dev.sh sysroot",
        sysroot.display()
    );
    sysroot
}

/// Return the sealed compiler driver used for every crabc C-runtime fixture.
///
/// The wrapper, rather than the host `musl-gcc` convenience driver, owns the
/// target headers, CRT selection, libc aliases, compiler helpers, and dynamic
/// interpreter. Tests that intentionally exercise a naked no-libc loader
/// image use their separately documented raw-clang boundary instead.
pub fn crabc_cc() -> PathBuf {
    let compiler = owned_sysroot().join("bin/crabc-cc");
    assert!(
        compiler.is_file(),
        "owned crabc compiler is unavailable at {}",
        compiler.display()
    );
    compiler
}

/// Construct the deliberately bare compiler boundary used by three loader
/// probes with their own `_start` and `-nostdlib` contract.
///
/// These are not libc/CRT candidate links: they inspect early loader behavior
/// before a C runtime is present. Keeping the raw Clang invocation explicit
/// makes that distinction auditable while preventing musl's convenience
/// driver from contributing headers, startup files, or helper archives.
pub fn naked_aarch64_command() -> Command {
    let mut command = Command::new("clang");
    command.args([
        "--target=aarch64-unknown-linux-musl",
        "-fuse-ld=lld",
        "-nostdinc",
    ]);
    command
}

/// A generated test artifact in its own unique temporary directory.
///
/// Keeping the basename unchanged is important for shared-library fixtures:
/// `-lfoo` searches for `libfoo.so`, and a fixture may call `dlopen` with a
/// literal library name.  The directory provides isolation and uniqueness
/// without changing those loader-visible names.
pub struct TempArtifact {
    dir: PathBuf,
    path: PathBuf,
}

impl TempArtifact {
    pub fn new(stem: &str) -> Self {
        let serial = NEXT_ARTIFACT.fetch_add(1, Ordering::Relaxed);
        let stem = stem.replace(['/', '\\'], "-");
        let dir =
            std::env::temp_dir().join(format!("crabc-artifact-{}-{serial}", std::process::id()));
        std::fs::create_dir(&dir).expect("failed to create temporary artifact directory");
        let path = dir.join(stem);
        Self { dir, path }
    }

    /// Returns the unique temporary directory containing this artifact.
    pub fn parent(&self) -> &Path {
        &self.dir
    }
}

impl Deref for TempArtifact {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        &self.path
    }
}

impl AsRef<Path> for TempArtifact {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

impl AsRef<OsStr> for TempArtifact {
    fn as_ref(&self) -> &OsStr {
        self.path.as_os_str()
    }
}

impl Drop for TempArtifact {
    fn drop(&mut self) {
        // Tests may create a sibling DSO directory or other link inputs next
        // to the primary artifact. Remove the whole process-unique directory
        // so a failing assertion cannot turn that ordinary fixture shape into
        // a persistent host-side dependency for a later test run.
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
