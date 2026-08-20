//! Helpers for integration tests that compile and run musl-linked artifacts.
//!
//! Fixtures are inputs and must remain untouched.  Every artifact produced by
//! a test gets a process-unique path in `temp_dir()` and is removed when the
//! guard goes out of scope.

#![allow(dead_code)]

use std::ffi::OsStr;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_ARTIFACT: AtomicU64 = AtomicU64::new(0);

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
        let stem = stem.replace('/', "-").replace('\\', "-");
        let dir = std::env::temp_dir().join(format!(
            "crabc-artifact-{}-{serial}",
            std::process::id()
        ));
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
        let _ = std::fs::remove_file(&self.path);
        let _ = std::fs::remove_dir(&self.dir);
    }
}
