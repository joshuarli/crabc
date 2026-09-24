#!/usr/bin/env python3
"""The combined sysroot is an exact composition of the static and dynamic products."""
from __future__ import annotations

import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import build_x86_64_owned_combined_sysroot as combined

HEADER = b"/* owned header */\n"


class CombinedSysrootCompositionTests(unittest.TestCase):
    def setUp(self):
        temporary_root = ROOT / ".work/x86_64/tmp"
        temporary_root.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=temporary_root)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.static = self.product("static", {
            "bin/crabc-cc": (b"static driver", 0o755),
            "usr/lib/crt1.o": (b"shared ET_EXEC entry", 0o644),
            "usr/lib/Scrt1.o": (b"static default Scrt1", 0o644),
            "usr/lib/rcrt1.o": (b"static-pie entry", 0o644),
            "usr/lib/libc.a": (b"static libc", 0o644),
            "share/crabc/crt.provenance.json": (b"static crt producer", 0o644),
            "share/crabc/headers.provenance.json": (b"static headers", 0o644),
        })
        self.dynamic = self.product("dynamic", {
            "bin/crabc-cc-dynamic": (b"dynamic driver", 0o755),
            "lib/ld-crabc-x86_64.so.1": (b"loader", 0o755),
            "usr/lib/libc.so": (b"shared libc", 0o755),
            "usr/lib/crt1.o": (b"shared ET_EXEC entry", 0o644),
            "usr/lib/Scrt1.o": (b"owned dynamic Scrt1", 0o644),
            "usr/lib/crabc-dynamic-attach.o": (b"attach", 0o644),
            "share/crabc/crabc_cc_static.py": (b"static driver module", 0o644),
            "share/crabc/crt.provenance.json": (b"dynamic crt producer", 0o644),
            "share/crabc/dynamic-product-state.json": (b"state", 0o644),
        }, symlinks={"lib/ld-musl-x86_64.so.1": "ld-crabc-x86_64.so.1"})

    def product(self, name: str, files: dict[str, tuple[bytes, int]], symlinks=None) -> Path:
        root = self.root / name
        shared = {"usr/include/stdio.h": (HEADER, 0o644), "usr/lib/crti.o": (b"crti", 0o644),
                  "usr/lib/crtn.o": (b"crtn", 0o644), "usr/lib/libcrabc-builtins.a": (b"helpers", 0o644)}
        for relative, (payload, mode) in {**shared, **files}.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            path.chmod(mode)
        for relative, target in (symlinks or {}).items():
            (root / relative).symlink_to(target)
        manifest = {"schema": 1, "format": combined.PRODUCT_FORMATS[name], "target": combined.TARGET,
                    "toolchain": "nightly-pinned", "files": {}}
        (root / combined.MANIFEST).write_text(json.dumps(manifest))
        return root

    def compose(self, name: str = "combined") -> Path:
        output = self.root / name
        combined.compose({"static": self.static, "dynamic": self.dynamic}, output)
        return output

    def test_one_tree_owns_every_mode_input_once(self):
        output = self.compose()
        record = combined.validate(output)
        self.assertEqual(record["modes"], list(combined.MODES))
        for relative in ("bin/crabc-cc", "bin/crabc-cc-dynamic", "usr/lib/libc.a", "usr/lib/libc.so",
                         "usr/lib/rcrt1.o", "usr/lib/crt1.o", "usr/lib/crti.o", "usr/include/stdio.h"):
            self.assertIn(relative, record["files"])
        self.assertEqual((output / "usr/lib/Scrt1.o").read_bytes(), b"owned dynamic Scrt1")
        self.assertIsNone(record["products"]["static"]["placements"]["usr/lib/Scrt1.o"])
        self.assertEqual(record["products"]["dynamic"]["placements"]["usr/lib/Scrt1.o"], "usr/lib/Scrt1.o")
        self.assertEqual(os.readlink(output / "lib/ld-musl-x86_64.so.1"), "ld-crabc-x86_64.so.1")
        self.assertEqual(record["executables"], ["bin/crabc-cc", "bin/crabc-cc-dynamic",
                                                 "lib/ld-crabc-x86_64.so.1", "usr/lib/libc.so"])
        # Disagreeing metadata moves under both products; agreeing metadata stays.
        self.assertFalse((output / "share/crabc/crt.provenance.json").exists())
        self.assertEqual((output / "share/crabc/static/crt.provenance.json").read_bytes(), b"static crt producer")
        self.assertEqual((output / "share/crabc/dynamic/crt.provenance.json").read_bytes(), b"dynamic crt producer")
        self.assertTrue((output / "share/crabc/headers.provenance.json").is_file())
        for name in combined.PRODUCTS:
            original = json.loads((output / f"share/crabc/{name}/manifest.json").read_text())
            self.assertEqual(original["format"], combined.PRODUCT_FORMATS[name])

    def test_one_crt1_must_serve_static_exec_and_dynamic_non_pie(self):
        (self.dynamic / "usr/lib/crt1.o").write_bytes(b"dynamic-only non-PIE entry")
        with self.assertRaisesRegex(combined.CompositionError, r"shared runtime paths: usr/lib/crt1\.o"):
            self.compose()
        self.assertFalse((self.root / "combined").exists())

    def test_other_runtime_disagreements_fail_closed_without_a_preferred_product(self):
        for relative, payload in (("usr/lib/crti.o", b"other crti"), ("usr/include/stdio.h", b"other"),
                                  ("usr/lib/libcrabc-builtins.a", b"other helpers"),
                                  ("share/crabc/crabc_cc_static.py", b"other module")):
            with self.subTest(relative=relative):
                path = self.static / relative
                original = path.read_bytes() if path.exists() else None
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(payload)
                with self.assertRaisesRegex(combined.CompositionError, relative.replace(".", r"\.")):
                    combined.plan({"static": self.static, "dynamic": self.dynamic})
                if original is None:
                    path.unlink()
                else:
                    path.write_bytes(original)
        (self.static / "usr/lib/crti.o").chmod(0o755)
        with self.assertRaisesRegex(combined.CompositionError, r"usr/lib/crti\.o"):
            combined.plan({"static": self.static, "dynamic": self.dynamic})

    def test_toolchains_symlinks_and_claimed_paths_must_agree(self):
        manifest = json.loads((self.static / combined.MANIFEST).read_text())
        (self.static / combined.MANIFEST).write_text(json.dumps({**manifest, "toolchain": "other"}))
        with self.assertRaisesRegex(combined.CompositionError, "toolchains"):
            combined.plan({"static": self.static, "dynamic": self.dynamic})
        (self.static / combined.MANIFEST).write_text(json.dumps(manifest))
        (self.static / "lib").mkdir()
        (self.static / "lib/ld-musl-x86_64.so.1").symlink_to("/lib/ld-musl-x86_64.so.1")
        with self.assertRaisesRegex(combined.CompositionError, "symlink"):
            combined.plan({"static": self.static, "dynamic": self.dynamic})
        (self.static / "lib/ld-musl-x86_64.so.1").unlink()
        (self.static / "share/crabc/dynamic").mkdir()
        (self.static / "share/crabc/dynamic/crt.provenance.json").write_bytes(b"squatter")
        with self.assertRaisesRegex(combined.CompositionError, "claim installed path"):
            combined.plan({"static": self.static, "dynamic": self.dynamic})

    def test_validation_rejects_changed_extra_mode_and_link_drift(self):
        def retarget(root: Path) -> None:
            (root / "lib/ld-musl-x86_64.so.1").unlink()
            (root / "lib/ld-musl-x86_64.so.1").symlink_to("/lib/ld-musl-x86_64.so.1")

        cases = (
            lambda root: (root / "usr/lib/libc.a").write_bytes(b"foreign"),
            lambda root: (root / "usr/lib/libforeign.a").write_bytes(b"foreign"),
            lambda root: (root / "usr/lib/crti.o").chmod(0o755),
            retarget,
        )
        for index, mutate in enumerate(cases):
            with self.subTest(index=index):
                candidate = self.compose(f"candidate-{index}")
                combined.validate(candidate)
                mutate(candidate)
                with self.assertRaises(combined.CompositionError):
                    combined.validate(candidate)

    def test_package_is_deterministic_and_extraction_reproduces_the_tree(self):
        first, second = self.compose("first"), self.compose("second")
        combined.compare(first, second)
        archives = [self.root / "first.tar", self.root / "second.tar"]
        combined.package(first, archives[0])
        combined.package(second, archives[1])
        self.assertEqual(archives[0].read_bytes(), archives[1].read_bytes())
        extracted = self.root / "extracted"
        combined.extract(archives[0], extracted)
        combined.compare(first, extracted)
        self.assertTrue(os.access(extracted / "bin/crabc-cc-dynamic", os.X_OK))
        self.assertFalse(os.access(extracted / "usr/lib/libc.a", os.X_OK))
        (second / "usr/lib/libc.a").write_bytes(b"drift")
        with self.assertRaises(combined.CompositionError):
            combined.compare(first, second)

    def test_extraction_rejects_roster_hash_and_link_forgery_before_writing(self):
        source = self.compose()
        archive_path = self.root / "good.tar"
        combined.package(source, archive_path)
        with tarfile.open(archive_path) as archive:
            members = [(member, archive.extractfile(member).read() if member.isfile() else None)
                       for member in archive.getmembers()]

        def forge(name: str, edit) -> Path:
            path = self.root / f"{name}.tar"
            with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as archive:
                for member, payload in edit(list(members)):
                    archive.addfile(member, None if payload is None else io.BytesIO(payload))
            return path

        def replace_payload(entries):
            result = []
            for member, payload in entries:
                if member.name == "usr/lib/libc.a":
                    payload = b"forged"
                    member.size = len(payload)
                result.append((member, payload))
            return result

        def retarget_alias(entries):
            for member, _ in entries:
                if member.issym():
                    member.linkname = "/lib/ld-musl-x86_64.so.1"
            return entries

        def extra_member(entries):
            extra = tarfile.TarInfo("usr/lib/libforeign.a")
            extra.size = 3
            return entries + [(extra, b"foo")]

        def traversal(entries):
            evil = tarfile.TarInfo("../escape")
            evil.size = 1
            return entries + [(evil, b"x")]

        def no_manifest(entries):
            return [(member, payload) for member, payload in entries if member.name != combined.MANIFEST]

        for name, edit in (("payload", replace_payload), ("alias", retarget_alias),
                           ("extra", extra_member), ("traversal", traversal), ("manifest", no_manifest)):
            with self.subTest(name=name):
                output = self.root / f"extract-{name}"
                with self.assertRaises(combined.CompositionError):
                    combined.extract(forge(name, edit), output)
                self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
