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

    def invoke(self, bindir, capture, command="musl-oracle", arguments=(), **overrides):
        env = os.environ.copy()
        for key in ("CRABC_X86_64_WORK_DIR", "CRABC_X86_64_CORE_TARGET_VOLUME", "CRABC_X86_64_CORE_CARGO_VOLUME"):
            env.pop(key, None)
        env.update(overrides, PATH=f"{bindir}:{env['PATH']}", FAKE_DOCKER_ARGS=str(capture))
        return subprocess.run(["bash", str(DISPATCHER), command, *arguments], cwd=ROOT, env=env,
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

    def test_unwinder_owned_cleanup_isolates_supplied_inputs_from_writable_evidence(self):
        with self.tempdir() as td, tempfile.TemporaryDirectory(dir=ROOT / ".work/x86_64") as work:
            bindir, capture = self.fake_docker(Path(td))
            work_root = Path(work)
            input_root = work_root / "inputs"; input_root.mkdir()
            provider = input_root / "provider-vendor"; provider.mkdir()
            static = input_root / "static-product"; static.mkdir()
            dynamic = input_root / "dynamic-product"; dynamic.mkdir()
            result = self.invoke(
                bindir, capture, "unwinder-owned-cleanup",
                ("--provider-vendor", str(provider), "--static-sysroot", str(static), "--dynamic-sysroot", str(dynamic)),
                CRABC_X86_64_WORK_DIR=str(work_root),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            arguments = [argument.decode() for argument in capture.read_bytes().split(b"\0") if argument]
            mounts = [arguments[index + 1] for index, argument in enumerate(arguments[:-1]) if argument == "--volume"]
            evidence_root = work_root / "owned-rust-std-cleanup"
            self.assertIn(f"{ROOT}:/workspace:ro", mounts)
            self.assertIn(f"{evidence_root}:/workspace/.work/x86_64/owned-rust-std-cleanup", mounts)
            self.assertIn(f"{evidence_root / 'tmp'}:/tmp", mounts)
            self.assertNotIn(f"{work_root}:/workspace/.work/x86_64", mounts)
            self.assertNotIn(f"{work_root / 'target'}:/workspace/target", mounts)
            self.assertNotIn(f"{work_root / 'cargo'}:/workspace/.work/x86_64/cargo", mounts)
            self.assertIn("CARGO_HOME=/workspace/.work/x86_64/owned-rust-std-cleanup/cargo", arguments)
            self.assertIn("CRABC_WORK_DIR=/workspace/.work/x86_64/owned-rust-std-cleanup", arguments)
            self.assertIn("TMPDIR=/workspace/.work/x86_64/owned-rust-std-cleanup/tmp", arguments)
            for source, target in (
                (provider, "/workspace/.work/x86_64/inputs/provider-vendor"),
                (static, "/workspace/.work/x86_64/inputs/static-product"),
                (dynamic, "/workspace/.work/x86_64/inputs/dynamic-product"),
            ):
                self.assertIn(f"{source}:{target}:ro", mounts)
            self.assertEqual(arguments[arguments.index("--network") + 1], "none")
            self.assertIn(f"{os.getuid()}:{os.getgid()}", arguments)
            command = arguments[arguments.index("python3"):]
            self.assertEqual(command, [
                "python3", "-B", "/workspace/unwinder/owned_cleanup.py",
                "--provider-vendor", "/workspace/.work/x86_64/inputs/provider-vendor",
                "--static-sysroot", "/workspace/.work/x86_64/inputs/static-product",
                "--dynamic-sysroot", "/workspace/.work/x86_64/inputs/dynamic-product",
            ])

    def test_unwinder_owned_cleanup_rejects_an_input_inside_writable_evidence(self):
        with self.tempdir() as td, tempfile.TemporaryDirectory(dir=ROOT / ".work/x86_64") as work:
            bindir, capture = self.fake_docker(Path(td))
            work_root = Path(work)
            evidence_root = work_root / "owned-rust-std-cleanup"; evidence_root.mkdir()
            provider = evidence_root / "provider-vendor"; provider.mkdir()
            static = work_root / "static-product"; static.mkdir()
            dynamic = work_root / "dynamic-product"; dynamic.mkdir()
            result = self.invoke(
                bindir, capture, "unwinder-owned-cleanup",
                ("--provider-vendor", str(provider), "--static-sysroot", str(static), "--dynamic-sysroot", str(dynamic)),
                CRABC_X86_64_WORK_DIR=str(work_root),
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("must be outside its writable evidence root", result.stderr)
            self.assertFalse(capture.exists())

    def test_unwinder_owned_cleanup_rejects_a_missing_provider_vendor_before_docker(self):
        with self.tempdir() as td:
            bindir, capture = self.fake_docker(Path(td))
            result = self.invoke(
                bindir, capture, "unwinder-owned-cleanup",
                ("--static-sysroot", ".work/x86_64/static", "--dynamic-sysroot", ".work/x86_64/dynamic"),
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("--provider-vendor", result.stderr)
            self.assertFalse(capture.exists())

    def test_unwinder_owned_cleanup_forwards_the_compile_diagnostic_mode(self):
        with self.tempdir() as td, tempfile.TemporaryDirectory(dir=ROOT / ".work/x86_64") as inputs:
            bindir, capture = self.fake_docker(Path(td))
            input_root = Path(inputs)
            provider = input_root / "provider-vendor"; provider.mkdir()
            static = input_root / "static-product"; static.mkdir()
            dynamic = input_root / "dynamic-product"; dynamic.mkdir()
            result = self.invoke(
                bindir, capture, "unwinder-owned-cleanup",
                ("--provider-vendor", str(provider), "--static-sysroot", str(static), "--dynamic-sysroot", str(dynamic),
                 "--mixed-source-generated-compile-diagnostics-only"),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            arguments = [argument.decode() for argument in capture.read_bytes().split(b"\0") if argument]
            self.assertEqual(arguments[-1], "--mixed-source-generated-compile-diagnostics-only")

if __name__ == "__main__":
    unittest.main()
