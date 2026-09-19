#!/usr/bin/env python3
"""Mode-preserving package/extraction tests for the owned dynamic product."""

from __future__ import annotations

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

SCRIPT = X86 / "owned_dynamic_package.py"
SPEC = importlib.util.spec_from_file_location("owned_dynamic_package_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
package = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = package
SPEC.loader.exec_module(package)


class OwnedDynamicPackageTests(unittest.TestCase):
    """Exercise archive modes without building or executing a native product."""

    def test_archive_and_extraction_preserve_the_canonical_dynamic_mode_roster(self) -> None:
        """The package cannot demote the executable shared-libc link input."""

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
                archived_modes = {
                    member.name: member.mode & 0o777
                    for member in opened.getmembers()
                    if member.isfile() and member.name != "share/crabc/manifest.json"
                }
            self.assertEqual(archived_modes, modes)

            extracted = workspace / "extracted"
            with mock.patch.object(package.driver, "validate", return_value=record):
                package.extract(archive, extracted)
            self.assertEqual(
                {
                    relative: (extracted / relative).stat().st_mode & 0o777
                    for relative in modes
                },
                modes,
            )


if __name__ == "__main__":
    unittest.main()
