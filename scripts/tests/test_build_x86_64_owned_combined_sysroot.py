#!/usr/bin/env python3
"""The combined sysroot is an exact composition of the static and dynamic products."""
from __future__ import annotations

import copy
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
        self.source_sha256 = "a" * 64
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
            "share/crabc/dynamic-product-state.json": (
                json.dumps({"schema": "crabc.x86_64-owned-dynamic-materialization/v1",
                            "source_sha256": self.source_sha256}).encode(), 0o644),
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
        files = {relative: digest for relative, (digest, _) in combined.tree(root)[0].items()}
        manifest = {"schema": 1, "format": combined.PRODUCT_FORMATS[name], "target": combined.TARGET,
                    "toolchain": "nightly-pinned"}
        if name == "static":
            manifest["installed"] = {"files": files}
            manifest["source_sha256"] = self.source_sha256
        else:
            manifest["files"] = files
            manifest["symlinks"] = symlinks or {}
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

    def test_products_with_different_allocator_configuration_cannot_compose(self):
        manifest = json.loads((self.static / combined.MANIFEST).read_text())
        for field, value in (("allocator_backend", "native-shadow"),
                             ("allocator_lifecycle_test_audit", True), ("build_profile", "debug")):
            with self.subTest(field=field):
                (self.static / combined.MANIFEST).write_text(json.dumps({**manifest, field: value}))
                with self.assertRaisesRegex(combined.CompositionError, "product configuration differs"):
                    self.compose(field)
                self.assertFalse((self.root / field).exists())
        (self.static / combined.MANIFEST).write_text(json.dumps(manifest))

    def test_debug_products_compose_with_manifest_source_seals_and_unqualified_state(self):
        configuration = {"build_profile": "debug", "allocator_backend": "native-shadow",
                         "allocator_lifecycle_test_audit": False}
        state_path = self.dynamic / combined.DYNAMIC_STATE
        state_path.write_text(json.dumps({**configuration, "status": "materialized-unqualified"}))
        for product in (self.static, self.dynamic):
            path = product / combined.MANIFEST
            manifest = json.loads(path.read_text())
            if product == self.static:
                manifest.update(configuration)
            else:
                manifest["build_profile"] = "debug"
            manifest["source_sha256"] = self.source_sha256
            if product == self.dynamic:
                manifest["files"][combined.DYNAMIC_STATE] = combined.sha256_bytes(state_path.read_bytes())
            path.write_text(json.dumps(manifest))
        output = self.compose()
        combined.validate(output)
        archive = self.root / "debug.tar.gz"
        combined.package(output, archive)
        extracted = self.root / "debug-extracted"
        combined.extract(archive, extracted)
        combined.compare(output, extracted)
        manifest = json.loads((self.dynamic / combined.MANIFEST).read_text())
        manifest["source_sha256"] = "b" * 64
        (self.dynamic / combined.MANIFEST).write_text(json.dumps(manifest))
        with self.assertRaisesRegex(combined.CompositionError, "source seals differ"):
            self.compose("different-debug-source")

    def test_debug_state_requires_actual_producer_shape_types_and_matching_configuration(self):
        configuration = {"build_profile": "debug", "allocator_backend": "accepted-c",
                         "allocator_lifecycle_test_audit": False}
        state = {**configuration, "status": "materialized-unqualified"}
        static = {**configuration, "source_sha256": self.source_sha256}
        dynamic = {"build_profile": "debug", "source_sha256": self.source_sha256}
        combined.require_matching_source_seals(static, dynamic, json.dumps(state).encode())
        malformed = (
            ("missing-audit", {key: value for key, value in state.items()
                               if key != "allocator_lifecycle_test_audit"}, static),
            ("extra-field", {**state, "source_sha256": self.source_sha256}, static),
            ("unknown-backend", {**state, "allocator_backend": "other"},
             {**static, "allocator_backend": "other"}),
            ("non-string-backend", {**state, "allocator_backend": ["accepted-c"]},
             {**static, "allocator_backend": ["accepted-c"]}),
            ("integer-audit", {**state, "allocator_lifecycle_test_audit": 0},
             {**static, "allocator_lifecycle_test_audit": 0}),
            ("string-audit", {**state, "allocator_lifecycle_test_audit": "false"},
             {**static, "allocator_lifecycle_test_audit": "false"}),
            ("native-audit", {**state, "allocator_backend": "native", "allocator_lifecycle_test_audit": True},
             {**static, "allocator_backend": "native", "allocator_lifecycle_test_audit": True}),
            ("missing-static-audit", state, {key: value for key, value in static.items()
                                           if key != "allocator_lifecycle_test_audit"}),
        )
        for label, candidate, manifest in malformed:
            with self.subTest(label=label):
                with self.assertRaisesRegex(combined.CompositionError, "debug product.*differs"):
                    combined.require_matching_source_seals(manifest, dynamic, json.dumps(candidate).encode())
        for backend, audit in (("native-shadow", False), ("accepted-c", True), ("native", False)):
            selected = {**static, "allocator_backend": backend, "allocator_lifecycle_test_audit": audit}
            selected_state = {**state, "allocator_backend": backend, "allocator_lifecycle_test_audit": audit}
            combined.require_matching_source_seals(selected, dynamic, json.dumps(selected_state).encode())
            with self.assertRaisesRegex(combined.CompositionError, "product configuration differs"):
                combined.require_matching_source_seals(static, dynamic, json.dumps(selected_state).encode())

    def test_source_seals_must_match_before_composition(self):
        manifest_path = self.static / combined.MANIFEST
        manifest = json.loads(manifest_path.read_text())
        manifest["source_sha256"] = "b" * 64
        manifest_path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(combined.CompositionError, "source seals differ"):
            self.compose()
        self.assertFalse((self.root / "combined").exists())
        del manifest["source_sha256"]
        manifest_path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(combined.CompositionError, "static product source seal is missing"):
            self.compose()
        self.assertFalse((self.root / "combined").exists())

    def test_rehashed_package_cannot_substitute_dynamic_source_seal(self):
        product = self.compose()
        archive_path = self.root / "good.tar"
        combined.package(product, archive_path)
        state_path = "share/crabc/dynamic-product-state.json"
        dynamic_manifest_path = "share/crabc/dynamic/manifest.json"
        with tarfile.open(archive_path) as archive:
            members = [(copy.copy(member), archive.extractfile(member).read() if member.isfile() else None)
                       for member in archive.getmembers()]
        for index, (member, payload) in enumerate(members):
            if member.name == state_path:
                state = json.loads(payload)
                state["source_sha256"] = "b" * 64
                payload = json.dumps(state).encode()
                member.size = len(payload)
                members[index] = (member, payload)
                state_digest = combined.sha256_bytes(payload)
        for index, (member, payload) in enumerate(members):
            if member.name == dynamic_manifest_path:
                manifest = json.loads(payload)
                manifest["files"][state_path] = state_digest
                payload = json.dumps(manifest).encode()
                member.size = len(payload)
                members[index] = (member, payload)
                manifest_digest = combined.sha256_bytes(payload)
        for index, (member, payload) in enumerate(members):
            if member.name == combined.MANIFEST:
                manifest = json.loads(payload)
                manifest["files"][state_path] = state_digest
                manifest["files"][dynamic_manifest_path] = manifest_digest
                payload = json.dumps(manifest).encode()
                member.size = len(payload)
                members[index] = (member, payload)
        forged = self.root / "mixed-source.tar"
        with tarfile.open(forged, "w", format=tarfile.USTAR_FORMAT) as archive:
            for member, payload in members:
                archive.addfile(member, None if payload is None else io.BytesIO(payload))
        output = self.root / "extracted-mixed-source"
        with self.assertRaisesRegex(combined.CompositionError, "source seals differ"):
            combined.extract(forged, output)
        self.assertFalse(output.exists())

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
        record, payloads = combined.read_validated_package(archives[0])
        self.assertEqual(record, combined.validate(first))
        self.assertEqual(payloads[combined.MANIFEST], (first / combined.MANIFEST).read_bytes())
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
                for member, payload in edit([(copy.copy(member), payload) for member, payload in members]):
                    archive.addfile(member, None if payload is None else io.BytesIO(payload))
            return path

        def executable_mode_drift(entries):
            for member, _ in entries:
                if member.name == "lib/ld-crabc-x86_64.so.1":
                    member.mode = 0o644
            return entries

        def manifest_mode_drift(entries):
            for member, _ in entries:
                if member.name == combined.MANIFEST:
                    member.mode = 0o755
            return entries

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

        def rehashed_unsafe_alias(entries):
            alias = "lib/ld-musl-x86_64.so.1"
            embedded_path = "share/crabc/dynamic/manifest.json"
            for index, (member, payload) in enumerate(entries):
                if member.name == embedded_path:
                    embedded = json.loads(payload)
                    embedded["symlinks"][alias] = "../escape"
                    payload = json.dumps(embedded).encode()
                    member.size = len(payload)
                    entries[index] = (member, payload)
                    embedded_digest = combined.sha256_bytes(payload)
            for index, (member, payload) in enumerate(entries):
                if member.name == combined.MANIFEST:
                    record = json.loads(payload)
                    record["files"][embedded_path] = embedded_digest
                    record["symlinks"][alias] = "../escape"
                    payload = json.dumps(record).encode()
                    member.size = len(payload)
                    entries[index] = (member, payload)
                elif member.name == alias:
                    member.linkname = "../escape"
            return entries

        def extra_member(entries):
            extra = tarfile.TarInfo("usr/lib/libforeign.a")
            extra.size = 3
            return entries + [(extra, b"foo")]

        def rehashed_unclaimed_member(entries):
            extra = tarfile.TarInfo("usr/lib/libforeign.a")
            extra.size, extra.mode = 3, 0o644
            for index, (member, payload) in enumerate(entries):
                if member.name == combined.MANIFEST:
                    record = json.loads(payload)
                    record["files"][extra.name] = combined.sha256_bytes(b"foo")
                    payload = json.dumps(record).encode()
                    member.size = len(payload)
                    entries[index] = (member, payload)
            return entries + [(extra, b"foo")]

        def duplicate_member(entries):
            member, payload = entries[0]
            return entries + [(copy.copy(member), payload)]

        def parent_path(entries):
            evil = tarfile.TarInfo("../escape")
            evil.size = 1
            return entries + [(evil, b"x")]

        def absolute_path(entries):
            evil = tarfile.TarInfo("/escape")
            evil.size = 1
            return entries + [(evil, b"x")]

        def no_manifest(entries):
            return [(member, payload) for member, payload in entries if member.name != combined.MANIFEST]

        cases = (
            ("mode", executable_mode_drift, "package member mode differs"),
            ("manifest-mode", manifest_mode_drift, "package member mode differs"),
            ("payload", replace_payload, "combined package payload differs"),
            ("alias", retarget_alias, "combined package alias differs"),
            ("extra", extra_member, "combined package roster differs"),
            ("rehashed-extra", rehashed_unclaimed_member, "unclaimed package payload"),
            ("duplicate", duplicate_member, "duplicate package member"),
            ("parent", parent_path, "unsafe package member path"),
            ("absolute", absolute_path, "unsafe package member path"),
            ("manifest", no_manifest, "combined package has no manifest"),
        )
        for name, edit, error in cases:
            with self.subTest(name=name):
                output = self.root / f"extract-{name}"
                with self.assertRaisesRegex(combined.CompositionError, error):
                    combined.extract(forge(name, edit), output)
                self.assertFalse(output.exists())

        forged_alias = forge("rehashed-alias", rehashed_unsafe_alias)
        with self.assertRaisesRegex(combined.CompositionError, "unsafe package alias target"):
            combined.read_validated_package(forged_alias)
        output = self.root / "extract-rehashed-alias"
        with self.assertRaisesRegex(combined.CompositionError, "unsafe package alias target"):
            combined.extract(forged_alias, output)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
