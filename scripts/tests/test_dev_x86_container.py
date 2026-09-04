#!/usr/bin/env python3
"""Behavioral tests for x86 Docker work-root containment."""
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DISPATCHER = ROOT / "scripts/dev-x86_64.sh"

class X86ContainerTests(unittest.TestCase):
    def tempdir(self):
        base = ROOT / ".work/tmp"; base.mkdir(parents=True, exist_ok=True)
        return tempfile.TemporaryDirectory(dir=base)

    def fake_docker(self, root):
        bindir = root / "bin"; bindir.mkdir(); capture = root / "args"
        docker = bindir / "docker"
        docker.write_text('''#!/usr/bin/env bash
set -euo pipefail
printf "%s\\n" "$*" >> "$FAKE_DOCKER_ARGS.calls"
if [[ "$1" == image && "$2" == inspect ]]; then [[ "${3:-}" == --format ]] && printf "linux/amd64\\n"; exit 0; fi
if [[ "$1" == run ]]; then printf "%s\\0" "$@" > "$FAKE_DOCKER_ARGS"; exit 0; fi
exit 64
''')
        docker.chmod(docker.stat().st_mode | stat.S_IXUSR)
        return bindir, capture

    def invoke(self, bindir, capture, command="musl-oracle", **overrides):
        env = os.environ.copy()
        for key in ("CRABC_X86_64_WORK_DIR", "CRABC_X86_64_CORE_TARGET_VOLUME", "CRABC_X86_64_CORE_CARGO_VOLUME"):
            env.pop(key, None)
        env.update(overrides, PATH=f"{bindir}:{env['PATH']}", FAKE_DOCKER_ARGS=str(capture))
        return subprocess.run(["bash", str(DISPATCHER), command], cwd=ROOT, env=env,
                              text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def test_default_mounts_are_local_and_legacy_tmp_is_bound(self):
        with self.tempdir() as td:
            bindir, capture = self.fake_docker(Path(td))
            for command in ("musl-oracle", "interface-device-reference", "root-change-reference", "libc-uts-identity"):
                result = self.invoke(bindir, capture, command)
                self.assertEqual(result.returncode, 0, result.stderr)
                args = capture.read_bytes().split(b"\0")
                for source, target in (
                    ("tmp", "/tmp"),
                    ("target", "/workspace/target"),
                    ("cargo", "/workspace/.work/x86_64/cargo"),
                ):
                    self.assertIn(f"{ROOT}/.work/x86_64/{source}:{target}".encode(), args)
                self.assertIn(b"CARGO_HOME=/workspace/.work/x86_64/cargo", args)
                self.assertIn(b"TMPDIR=/workspace/.work/x86_64/tmp", args)

    def test_accepts_descendant_work_override(self):
        with self.tempdir() as td:
            root = Path(td); bindir, capture = self.fake_docker(root)
            work_root = ROOT / ".work/x86_64"
            work_root.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(dir=work_root) as work:
                result = self.invoke(bindir, capture, CRABC_X86_64_WORK_DIR=work)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f"{work}:/workspace/.work/x86_64".encode(), capture.read_bytes().split(b"\0"))

    def test_rejects_external_named_and_traversal_overrides_before_docker(self):
        cases = ({"CRABC_X86_64_WORK_DIR": "/tmp/outside"},
                 {"CRABC_X86_64_WORK_DIR": "../escape"},
                 {"CRABC_X86_64_CORE_TARGET_VOLUME": "named"},
                 {"CRABC_X86_64_CORE_TARGET_VOLUME": "/tmp/outside"},
                 {"CRABC_X86_64_CORE_CARGO_VOLUME": "/tmp/outside"})
        with self.tempdir() as td:
            bindir, capture = self.fake_docker(Path(td))
            for case in cases:
                result = self.invoke(bindir, capture, **case)
                self.assertNotEqual(result.returncode, 0, case)
                self.assertFalse(capture.exists(), case)
                self.assertFalse(capture.with_suffix(".calls").exists(), case)

    def test_rejects_symlink_work_override(self):
        with self.tempdir() as td:
            root = Path(td); bindir, capture = self.fake_docker(root)
            work_root = ROOT / ".work/x86_64"
            work_root.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(dir=work_root) as work:
                link = Path(work) / "escape"
                link.symlink_to(root, target_is_directory=True)
                for option in ("CRABC_X86_64_WORK_DIR", "CRABC_X86_64_CORE_TARGET_VOLUME", "CRABC_X86_64_CORE_CARGO_VOLUME"):
                    result = self.invoke(bindir, capture, **{option: str(link)})
                    self.assertNotEqual(result.returncode, 0, option)
                    self.assertFalse(capture.exists())
                    self.assertFalse(capture.with_suffix(".calls").exists())

if __name__ == "__main__":
    unittest.main()
