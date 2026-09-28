#!/usr/bin/env python3
"""Canonical package/extraction tests for the owned dynamic product."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
X86 = ROOT / "compat" / "x86_64"
if str(X86) not in sys.path:
    sys.path.insert(0, str(X86))
import owned_posix_product_evidence as product_evidence
import owned_dynamic_qualification as qualification

SCRIPT = X86 / "owned_dynamic_package.py"
SPEC = importlib.util.spec_from_file_location("owned_dynamic_package_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
package = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = package
SPEC.loader.exec_module(package)


class OwnedDynamicPackageTests(unittest.TestCase):
    """Exercise archive metadata without building or executing a native product."""

    def test_rehashed_archive_payload_must_match_materialization_state(self) -> None:
        temporary_root = ROOT / ".work/x86_64/tmp"
        temporary_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="owned-dynamic-package-state.", dir=temporary_root) as temporary:
            workspace = Path(temporary)
            source = workspace / "source"
            files = {}
            for relative in sorted(package.driver.REQUIRED | {"bin/crabc-cc-dynamic"}):
                path = source / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(relative.encode())
                path.chmod(0o755 if relative in package.EXECUTABLE_PAYLOADS else 0o644)
                files[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
            state_path = source / "share/crabc/dynamic-product-state.json"
            state = {
                "schema": "crabc.x86_64-owned-dynamic-materialization/v1",
                "status": "materialized-unqualified", "source_sha256": "a" * 64,
                "contracts": {"contract": "b" * 64}, "payload_files": dict(files),
                "allocator_backend": "accepted-c", "allocator_lifecycle_test_audit": False,
                "allocator_promoted": False, "runtime_v1_published": False,
                "campaign_complete": False, "public_support": False,
                "modes": ["dynamic-pie", "dynamic-non-pie", "dynamic-shared-object"],
                "runtime_profile": qualification.MATERIALIZATION_PROFILE,
                "qualification": qualification.MATERIALIZATION_QUALIFICATION,
            }
            state_path.write_text(json.dumps(state), encoding="utf-8")
            files["share/crabc/dynamic-product-state.json"] = hashlib.sha256(state_path.read_bytes()).hexdigest()
            manifest_path = source / "share/crabc/manifest.json"
            manifest = {"schema": 1, "format": package.driver.FORMAT,
                        "target": package.driver.shared.TARGET,
                        "symlinks": package.driver.ALIASES, "files": files}
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            for relative, target in package.driver.ALIASES.items():
                (source / relative).symlink_to(target)
            entries = sorted({*files, "share/crabc/manifest.json", *package.driver.ALIASES})
            baseline = workspace / "baseline.tar"
            package.write_archive(source, baseline, manifest, entries)
            with mock.patch.object(qualification, "source_digest", return_value="a" * 64), \
                 mock.patch.object(qualification, "contract_digests", return_value={"contract": "b" * 64}):
                package.package(source, workspace / "created-baseline.tar")
                package.extract(baseline, workspace / "baseline")
                libc = source / "usr/lib/libc.so"
                libc.write_bytes(b"different selected libc bytes")
                manifest["files"]["usr/lib/libc.so"] = hashlib.sha256(libc.read_bytes()).hexdigest()
                manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                forged = workspace / "forged.tar"
                package.write_archive(source, forged, manifest, entries)
                with self.assertRaisesRegex(qualification.QualificationError, "payload binding"):
                    package.package(source, workspace / "created-forged.tar")
                with self.assertRaisesRegex(qualification.QualificationError, "payload binding"):
                    package.extract(forged, workspace / "forged")
                self.assertFalse((workspace / "forged").exists())

    def test_archive_and_extraction_preserve_canonical_dynamic_member_metadata(self) -> None:
        """Every archive member uses the writer's fixed mode and owner metadata."""

        modes = {
            "bin/crabc-cc-dynamic": 0o755,
            "lib/ld-crabc-x86_64.so.1": 0o755,
            "usr/lib/libc.so": 0o755,
            "usr/lib/crt1.o": 0o644,
            "usr/lib/Scrt1.o": 0o644,
            "usr/lib/crti.o": 0o644,
            "usr/lib/crtn.o": 0o644,
            "usr/lib/crabc-dynamic-attach.o": 0o644,
            "usr/lib/libcrabc-builtins.a": 0o644,
            "share/crabc/crabc_cc_static.py": 0o644,
            "share/crabc/owned_dynamic_receipt.py": 0o644,
            "share/crabc/owned_dynamic_elf.py": 0o644,
        }
        self.assertTrue(package.driver.REQUIRED <= modes.keys())
        self.assertEqual(
            {relative: modes[relative] for relative in product_evidence.DYNAMIC_LINK_INPUT_MODES},
            product_evidence.DYNAMIC_LINK_INPUT_MODES,
        )
        self.assertEqual(
            {relative for relative, mode in modes.items() if mode == 0o755},
            {"bin/crabc-cc-dynamic", "lib/ld-crabc-x86_64.so.1", "usr/lib/libc.so"},
        )
        temporary_root = ROOT / ".work" / "x86_64" / "tmp"
        temporary_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="owned-dynamic-package.", dir=temporary_root) as temporary:
            workspace = Path(temporary)
            source = workspace / "source"
            files: dict[str, str] = {}
            for relative, mode in modes.items():
                path = source / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                payload = (relative + "\n").encode("utf-8")
                path.write_bytes(payload)
                path.chmod(mode)
                files[relative] = hashlib.sha256(payload).hexdigest()
            manifest = {
                "schema": 1,
                "format": package.driver.FORMAT,
                "target": package.driver.shared.TARGET,
                "symlinks": package.driver.ALIASES,
                "files": files,
            }
            manifest_path = source / "share/crabc/manifest.json"
            manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
            record = {"files": files, "symlinks": package.driver.ALIASES}
            archive = workspace / "runtime.tar"
            entries = sorted({*files, "share/crabc/manifest.json", *package.driver.ALIASES})
            package.write_archive(source, archive, record, entries)

            with tarfile.open(archive, "r:") as opened:
                archived_members = opened.getmembers()
                archived_modes = {
                    member.name: member.mode & 0o777
                    for member in archived_members
                    if member.isfile() and member.name != "share/crabc/manifest.json"
                }
                self.assertTrue(all(
                    (member.mtime, member.uid, member.gid, member.uname, member.gname) == (1, 0, 0, "", "")
                    for member in archived_members
                ))
            self.assertEqual(archived_modes, modes)

            extracted = workspace / "extracted"
            with mock.patch.object(package.driver, "validate", return_value=record), \
                 mock.patch.object(package.qualification, "product_identity"):
                package.extract(archive, extracted)
            self.assertEqual(
                {
                    relative: (extracted / relative).stat().st_mode & 0o777
                    for relative in modes
                },
                modes,
            )

            for relative, changed_mode in (("usr/lib/libc.so", 0o644),
                                           ("usr/lib/crt1.o", 0o755),
                                           ("share/crabc/manifest.json", 0o755)):
                with self.subTest(relative=relative):
                    forged = workspace / (relative.replace("/", "-") + ".tar")
                    with tarfile.open(archive, "r:") as original, \
                         tarfile.open(forged, "w", format=tarfile.USTAR_FORMAT) as rewritten:
                        for member in original.getmembers():
                            projected = copy.copy(member)
                            if projected.name == relative:
                                projected.mode = changed_mode
                            payload = original.extractfile(member) if member.isfile() else None
                            rewritten.addfile(projected, payload)
                    output = workspace / ("rejected-" + relative.replace("/", "-"))
                    with mock.patch.object(package.driver, "validate", return_value=record), \
                         mock.patch.object(package.qualification, "product_identity"):
                        with self.assertRaisesRegex(package.driver.shared.DriverError, "package member mode"):
                            package.extract(forged, output)
                    self.assertFalse(output.exists())

            for relative, field, changed in (("usr/lib/libc.so", "mtime", 2),
                                             ("usr/lib/libc.so", "uid", 1000),
                                             ("usr/lib/libc.so", "gid", 1000),
                                             ("usr/lib/libc.so", "uname", "forged"),
                                             ("usr/lib/libc.so", "gname", "forged"),
                                             (next(iter(sorted(package.driver.ALIASES))), "mtime", 2)):
                with self.subTest(relative=relative, field=field):
                    forged = workspace / (relative.replace("/", "-") + "-" + field + ".tar")
                    with tarfile.open(archive, "r:") as original, \
                         tarfile.open(forged, "w", format=tarfile.USTAR_FORMAT) as rewritten:
                        for member in original.getmembers():
                            projected = copy.copy(member)
                            if projected.name == relative:
                                setattr(projected, field, changed)
                            payload = original.extractfile(member) if member.isfile() else None
                            rewritten.addfile(projected, payload)
                    output = workspace / ("rejected-" + relative.replace("/", "-") + "-" + field)
                    with mock.patch.object(package.driver, "validate", return_value=record), \
                         mock.patch.object(package.qualification, "product_identity"):
                        with self.assertRaisesRegex(package.driver.shared.DriverError, "package member metadata"):
                            package.extract(forged, output)
                    self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
