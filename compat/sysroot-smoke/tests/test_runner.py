"""Pure archive and manifest checks for the extracted-sysroot smoke runner."""

from __future__ import annotations

import importlib.util
import io
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("crabc_sysroot_smoke_test_runner", ROOT / "compat/sysroot-smoke/run.py")
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


def member(name: str, kind: str = "file", linkname: str = "") -> tarfile.TarInfo:
    value = tarfile.TarInfo(name)
    if kind == "directory":
        value.type = tarfile.DIRTYPE
        value.mode = 0o755
    elif kind == "symlink":
        value.type = tarfile.SYMTYPE
        value.linkname = linkname
        value.mode = 0o777
    else:
        value.type = tarfile.REGTYPE
        value.mode = 0o644
    return value


class ArchiveValidationTests(unittest.TestCase):
    def test_one_root_and_internal_symlink_are_accepted(self) -> None:
        members = [member("root", "directory"), member("root/usr", "directory"), member("root/usr/libc.so"), member("root/usr/libc-alias.so", "symlink", "libc.so")]
        self.assertEqual(RUNNER.validate_archive_members(members), "root")

    def test_absolute_and_traversing_members_are_rejected(self) -> None:
        for name in ("/outside", "root/../outside"):
            with self.subTest(name=name):
                with self.assertRaises(RUNNER.SmokeError):
                    RUNNER.validate_archive_members([member("root", "directory"), member(name)])

    def test_escaping_and_ancestor_symlinks_are_rejected(self) -> None:
        with self.assertRaises(RUNNER.SmokeError):
            RUNNER.validate_archive_members([member("root", "directory"), member("root/lib", "symlink", "../../outside")])
        with self.assertRaises(RUNNER.SmokeError):
            RUNNER.validate_archive_members([member("root", "directory"), member("root/lib", "symlink", "target"), member("root/lib/file")])

    def test_special_and_hard_link_members_are_rejected(self) -> None:
        for kind in ("hard", "fifo", "device"):
            value = member("root/item")
            if kind == "hard":
                value.type = tarfile.LNKTYPE
                value.linkname = "root/other"
            elif kind == "fifo":
                value.type = tarfile.FIFOTYPE
            else:
                value.type = tarfile.CHRTYPE
            with self.subTest(kind=kind):
                with self.assertRaises(RUNNER.SmokeError):
                    RUNNER.validate_archive_members([member("root", "directory"), value])

    def test_safe_extract_preserves_internal_symlink_without_following_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            archive = base / "sysroot.tar.xz"
            with tarfile.open(archive, "w:xz") as stream:
                directory = member("root", "directory")
                stream.addfile(directory)
                data = b"owned\n"
                file_info = member("root/libc.so")
                file_info.size = len(data)
                stream.addfile(file_info, io.BytesIO(data))
                stream.addfile(member("root/libc-alias.so", "symlink", "libc.so"))
            extracted = RUNNER.safe_extract_archive(archive, base / "out")
            self.assertEqual((extracted / "libc.so").read_bytes(), b"owned\n")
            self.assertTrue((extracted / "libc-alias.so").is_symlink())
            self.assertEqual((extracted / "libc-alias.so").readlink().as_posix(), "libc.so")


class ElfValidationTests(unittest.TestCase):
    def test_dynamic_non_pie_requires_et_exec(self) -> None:
        def parsed(elf_type: int) -> dict[str, object]:
            return {
                "machine": RUNNER.SYSROOT.EM_AARCH64,
                "elf_type": elf_type,
                "interpreter": RUNNER.SYSROOT.CANONICAL_INTERPRETER,
                "dynamic_needed": [],
            }

        with mock.patch.object(RUNNER, "raw_elf_tools", return_value={}), mock.patch.object(
            RUNNER.SYSROOT, "inspect_elf", return_value=parsed(2)
        ):
            result = RUNNER.elf_record(
                Path("/synthetic/dynamic-non-pie"),
                1.0,
                kind="dynamic-executable",
                interpreter=RUNNER.SYSROOT.CANONICAL_INTERPRETER,
            )
        self.assertTrue(result["passed"])

        with mock.patch.object(RUNNER, "raw_elf_tools", return_value={}), mock.patch.object(
            RUNNER.SYSROOT, "inspect_elf", return_value=parsed(3)
        ):
            with self.assertRaises(RUNNER.SmokeError):
                RUNNER.elf_record(
                    Path("/synthetic/wrong-dynamic-non-pie"),
                    1.0,
                    kind="dynamic-executable",
                    interpreter=RUNNER.SYSROOT.CANONICAL_INTERPRETER,
                )


class LinkModeDeclarationTests(unittest.TestCase):
    def test_requires_all_release_link_modes(self) -> None:
        required = list(RUNNER.REQUIRED_RELEASE_LINK_MODE_REPORT_KEYS)
        declared = RUNNER.require_release_link_modes({"supported_link_modes": required})

        self.assertEqual(declared, set(required))

    def test_rejects_a_missing_or_uncovered_declared_link_mode(self) -> None:
        with self.assertRaises(RUNNER.SmokeError):
            RUNNER.require_release_link_modes({"supported_link_modes": ["dynamic-pie"]})
        with self.assertRaises(RUNNER.SmokeError):
            RUNNER.require_release_link_modes(
                {
                    "supported_link_modes": [
                        *RUNNER.REQUIRED_RELEASE_LINK_MODE_REPORT_KEYS,
                        "future-unverified-mode",
                    ]
                }
            )

    def test_attestation_requires_a_passing_detailed_probe(self) -> None:
        self.assertEqual(
            RUNNER.link_mode_attestation("dynamic", {"passed": True}),
            {"passed": True, "probe": "dynamic"},
        )
        with self.assertRaises(RUNNER.SmokeError):
            RUNNER.link_mode_attestation("dynamic", {"passed": False})


class LinkModeProbeTests(unittest.TestCase):
    def test_complete_link_probe_accepts_a_successful_link_artifact_phase(self) -> None:
        """A verified link must carry the phase verdict consumed by the aggregator."""

        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            output = work / "dynamic"
            output.write_bytes(b"ELF")
            (work / "dynamic.map").write_text("link map\n", encoding="utf-8")
            with mock.patch.object(RUNNER, "link_plan", return_value={}), mock.patch.object(
                RUNNER,
                "command_record",
                return_value={"status": 0, "stdout": {"hex": ""}, "stderr": {"hex": ""}},
            ), mock.patch.object(RUNNER.SYSROOT, "audit_linker_trace", return_value={"status": "passed"}):
                probe = RUNNER.link_artifact(
                    work,
                    work / "crabc-cc",
                    ("input.c", "-o", str(output)),
                    output,
                    work,
                    1.0,
                    (),
                )

        probe["elf"] = {"passed": True}
        probe["runtime"] = {"passed": True}
        self.assertTrue(probe["link"]["passed"])
        self.assertTrue(RUNNER.complete_link_probe("dynamic PIE", probe)["passed"])


if __name__ == "__main__":
    unittest.main()
