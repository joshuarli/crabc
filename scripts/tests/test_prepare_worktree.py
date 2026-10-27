"""Keep generated Lua seeds inside the dispatcher’s physical work boundary."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
LUA_ARCHIVE = b"pinned Lua source archive fixture\n"


class PrepareWorktreeTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary_root = ROOT / ".work" / "tmp"
        temporary_root.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(prefix="prepare-worktree-", dir=temporary_root)
        self.addCleanup(temporary.cleanup)
        self.scratch = Path(temporary.name)
        self.primary = self.scratch / "primary"
        self.primary.mkdir()
        self.lane = self.scratch / "lane"
        self._create_fixture()

    def _git(self, cwd: Path, *arguments: str) -> str:
        return subprocess.check_output(["git", *arguments], cwd=cwd, text=True).strip()

    def _create_oracle(self, path: Path) -> str:
        path.mkdir(parents=True)
        self._git(path, "init", "-q")
        (path / "fixture.txt").write_text("pinned oracle\n", encoding="utf-8")
        self._git(path, "add", ".")
        subprocess.run(
            ["git", "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid",
             "-c", "core.hooksPath=/dev/null", "commit", "-qm", "fixture"],
            cwd=path, check=True,
        )
        return self._git(path, "rev-parse", "HEAD")

    def _create_fixture(self) -> None:
        primary = self.primary
        self._git(primary, "init", "-q")
        (primary / ".gitignore").write_text(
            ".work/\ncompat/lua/.cache/\ncompat/corpus/.cache/\n", encoding="utf-8")

        for directory in ("scripts/lanes", "compat/lua", "compat/corpus", "compat/x86_64"):
            (primary / directory).mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / "scripts/lanes/prepare-worktree.sh", primary / "scripts/lanes/prepare-worktree.sh")
        rust_check = primary / "scripts/lanes/rust-check.sh"
        rust_check.write_text(
            "#!/bin/sh\n"
            "set -eu\n"
            "if [ \"$1\" = cargo ] && [ \"$2\" = fetch ]; then\n"
            "    mkdir -p .work/x86_64/cargo/native-static-source-runtime-vendor\n"
            "    registry=.work/x86_64/cargo/registry/src/index.crates.io-fixture/base64ct-1.6.0\n"
            "    mkdir -p \"$registry\"\n"
            "    printf 'locked base64ct fixture\\n' > \"$registry/Cargo.toml\"\n"
            "    exit 0\n"
            "fi\n"
            "printf 'unexpected rust-check command: %s\\n' \"$*\" >&2\n"
            "exit 99\n",
            encoding="utf-8",
        )
        rust_check.chmod(0o755)
        shutil.copy2(ROOT / "scripts/dev-x86_64.sh", primary / "scripts/dev-x86_64.sh")
        shutil.copy2(ROOT / "compat/x86_64/qualification_candidate.py",
                     primary / "compat/x86_64/qualification_candidate.py")
        fetch = primary / "compat/corpus/fetch_x86.py"
        fetch.write_text(
            "from pathlib import Path\n"
            "Path('.work/x86_64/owned-package-corpus-input/apks').mkdir(parents=True, exist_ok=True)\n",
            encoding="utf-8",
        )

        lua_cache = primary / "compat/lua/.cache"
        lua_cache.mkdir(parents=True)
        (lua_cache / "lua-5.4.8.tar.gz").write_bytes(LUA_ARCHIVE)
        lua_manifest = primary / "compat/lua/manifest.toml"
        lua_manifest.write_text(
            "[lua]\n"
            'version = "5.4.8"\n'
            'source_url = "https://invalid.example/lua-5.4.8.tar.gz"\n'
            f'sha256 = "{hashlib.sha256(LUA_ARCHIVE).hexdigest()}"\n',
            encoding="utf-8",
        )

        oracle_repositories = []
        for section, directory in (("os_test", "os-test"), ("libc_test", "libc-test")):
            repository = self.scratch / directory
            oracle_repositories.append((section, self._create_oracle(repository), repository))
        (primary / "compat/upstreams.toml").write_text(
            "\n".join(
                f'[{section}]\nrevision = "{revision}"\nrepository = {json.dumps(str(repository))}'
                for section, revision, repository in oracle_repositories
            ) + "\n",
            encoding="utf-8",
        )

        for directory in ("provider-vendor", "dependency-vendor"):
            (primary / ".work/x86_64/rust-std-lto" / directory).mkdir(parents=True)
        self._git(primary, "add", ".")
        subprocess.run(
            ["git", "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid",
             "-c", "core.hooksPath=/dev/null", "commit", "-qm", "fixture"],
            cwd=primary, check=True,
        )
        subprocess.run(["git", "worktree", "add", "--quiet", "-b", "prepare-worktree-test",
                        str(self.lane), "HEAD"], cwd=primary, check=True)

    def _run_launcher(self, archive_seed: str) -> subprocess.CompletedProcess[str]:
        work = self.lane / ".work/x86_64/launcher-fixture"
        for name in ("installed", "rebuilt", "extracted"):
            (work / name).mkdir(parents=True, exist_ok=True)
        preparation = work / "static-preparation.json"
        preparation.write_text("{}\n", encoding="utf-8")
        return subprocess.run(
            ["bash", str(self.lane / "scripts/dev-x86_64.sh"), "lua-static-source-build",
             "--cohort-checkout", str(self.lane),
             "--static-preparation", str(preparation),
             "--installed-sysroot", str(work / "installed"),
             "--rebuilt-sysroot", str(work / "rebuilt"),
             "--extracted-sysroot", str(work / "extracted"),
             "--archive-seed", archive_seed,
             "--work-root", str(work / "fresh-output"),
             "--invalid-test-flag", "value"],
            cwd=self.lane, capture_output=True, text=True, check=False,
        )

    def test_generated_lua_seed_passes_the_real_dispatcher_path_boundary(self) -> None:
        prepared = subprocess.run(
            ["sh", str(self.lane / "scripts/lanes/prepare-worktree.sh")],
            cwd=self.lane, capture_output=True, text=True, check=False,
        )
        self.assertEqual(prepared.returncode, 0, prepared.stderr)

        inputs = json.loads((self.lane / ".work/x86_64/inputs.json").read_text(encoding="utf-8"))
        archive_seed = inputs["lua_source_build"]["archive_seed"]
        cached_archive = self.lane / "compat/lua/.cache/lua-5.4.8.tar.gz"
        staged_archive = self.lane / archive_seed
        self.assertEqual(archive_seed, ".work/x86_64/lua-source-build-seed/lua-5.4.8.tar.gz")
        self.assertEqual(cached_archive.read_bytes(), LUA_ARCHIVE)
        self.assertEqual(staged_archive.read_bytes(), cached_archive.read_bytes())
        self.assertEqual(hashlib.sha256(staged_archive.read_bytes()).hexdigest(),
                         hashlib.sha256(LUA_ARCHIVE).hexdigest())

        repeated = subprocess.run(
            ["sh", str(self.lane / "scripts/lanes/prepare-worktree.sh")],
            cwd=self.lane, capture_output=True, text=True, check=False,
        )
        self.assertEqual(repeated.returncode, 0, repeated.stderr)
        self.assertEqual(staged_archive.read_bytes(), LUA_ARCHIVE)

        cache_result = self._run_launcher("compat/lua/.cache/lua-5.4.8.tar.gz")
        self.assertEqual(cache_result.returncode, 2)
        self.assertIn("path must be below the physical checkout .work directory", cache_result.stderr)

        seed_result = self._run_launcher(archive_seed)
        self.assertEqual(seed_result.returncode, 2)
        self.assertIn("takes only explicit cohort flags", seed_result.stderr)
        self.assertNotIn("supplied POSIX product", seed_result.stderr)

    def test_allocator_cargo_home_receives_the_fetched_registry(self) -> None:
        prepared = subprocess.run(
            ["sh", str(self.lane / "scripts/lanes/prepare-worktree.sh")],
            cwd=self.lane, capture_output=True, text=True, check=False,
        )
        self.assertEqual(prepared.returncode, 0, prepared.stderr)

        allocator_manifest = (
            self.lane / ".work/allocator-x86_64/cargo/registry/src/index.crates.io-fixture"
            "/base64ct-1.6.0/Cargo.toml"
        )
        self.assertTrue(allocator_manifest.is_file(),
                        "fetched core registry was not copied into allocator Cargo home")
        self.assertEqual(allocator_manifest.read_text(encoding="utf-8"), "locked base64ct fixture\n")

    def test_clones_verified_primary_oracle_with_different_owner(self) -> None:
        repository = self.scratch / "libc-test"
        revision = self._git(repository, "rev-parse", "HEAD")
        primary_oracle = self.primary / f".work/x86_64/source-oracles/laputa-libc-test-{revision}"
        shutil.copytree(repository, primary_oracle)
        environment = os.environ.copy()
        environment.update({
            "GIT_TEST_ASSUME_DIFFERENT_OWNER": "1",
            "GIT_CONFIG_COUNT": "4",
            "GIT_CONFIG_KEY_0": "safe.directory",
            "GIT_CONFIG_VALUE_0": str(self.primary),
            "GIT_CONFIG_KEY_1": "safe.directory",
            "GIT_CONFIG_VALUE_1": str(self.lane),
            "GIT_CONFIG_KEY_2": "safe.directory",
            "GIT_CONFIG_VALUE_2": f"{self.lane}/*",
            "GIT_CONFIG_KEY_3": "safe.directory",
            "GIT_CONFIG_VALUE_3": str(self.scratch / "os-test" / ".git"),
        })
        prepared = subprocess.run(
            ["sh", str(self.lane / "scripts/lanes/prepare-worktree.sh")],
            cwd=self.lane, env=environment, capture_output=True, text=True, check=False,
        )
        self.assertEqual(prepared.returncode, 0, prepared.stderr)
        cloned = self.lane / f".work/x86_64/source-oracles/laputa-libc-test-{revision}"
        self.assertEqual(self._git(cloned, "rev-parse", "HEAD"), revision)

    def test_allocator_cargo_home_symlink_is_rejected_without_writing_through_it(self) -> None:
        allocator_home = self.lane / ".work/allocator-x86_64"
        allocator_home.mkdir(parents=True)
        outside_cargo_home = self.scratch / "outside-cargo-home"
        outside_cargo_home.mkdir()
        (allocator_home / "cargo").symlink_to(outside_cargo_home, target_is_directory=True)

        prepared = subprocess.run(
            ["sh", str(self.lane / "scripts/lanes/prepare-worktree.sh")],
            cwd=self.lane, capture_output=True, text=True, check=False,
        )
        self.assertEqual(prepared.returncode, 1)
        self.assertIn("allocator Cargo home is a symlink", prepared.stderr)
        self.assertFalse((outside_cargo_home / "registry").exists())

    def test_lua_seed_symlink_is_rejected_without_touching_its_target(self) -> None:
        seed_directory = self.lane / ".work/x86_64/lua-source-build-seed"
        seed_directory.mkdir(parents=True)
        outside_seed = self.scratch / "outside-seed"
        outside_seed.write_bytes(b"leave this file alone\n")
        (seed_directory / "lua-5.4.8.tar.gz").symlink_to(outside_seed)

        prepared = subprocess.run(
            ["sh", str(self.lane / "scripts/lanes/prepare-worktree.sh")],
            cwd=self.lane, capture_output=True, text=True, check=False,
        )
        self.assertEqual(prepared.returncode, 1)
        self.assertIn("worktree Lua source seed is not a regular file", prepared.stderr)
        self.assertEqual(outside_seed.read_bytes(), b"leave this file alone\n")


if __name__ == "__main__":
    unittest.main()
