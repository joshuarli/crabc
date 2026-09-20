#!/usr/bin/env python3
"""Semantic regressions for the installed calendar component public reader."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
MODULE = ROOT / "compat/x86_64/owned_calendar_component_receipt.py"


def load_module():
    if not MODULE.is_file():
        raise AssertionError("installed calendar component receipt reader is missing")
    spec = importlib.util.spec_from_file_location("owned_calendar_component_receipt_test", MODULE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    return module


class OwnedCalendarComponentReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_module()

    def setUp(self) -> None:
        (ROOT / ".work/x86_64/tmp").mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="owned-calendar-reader.", dir=ROOT / ".work/x86_64/tmp")
        self.root = Path(self.temporary.name)
        self.work = self.root / ".work/x86_64/owned-calendar-products.fixture"
        self.work.mkdir(parents=True)
        self.static = self.mkdir(".work/x86_64/static")
        self.dynamic = self.mkdir(".work/x86_64/dynamic")
        self.mkdir(".work/x86_64/dynamic/runtime")
        self.write(".work/x86_64/dynamic/runtime/mode-bound", b"dynamic payload\n", mode=0o755)
        self.copy_sources()
        self.sources = {name: {**self.identity(self.root / path), "mode": stat.S_IMODE((self.root / path).stat().st_mode)}
                        for name, path in self.module.SOURCE_PATHS.items()}
        self.seal = {"sources": self.sources,
                     "static": {"path": self.relative(self.static), "manifest": self.identity(self.write(".work/x86_64/static/manifest", b"static\n")),
                                "tree": self.module.family.snapshot(self.static)},
                     "dynamic": {"path": self.relative(self.dynamic), "manifest": self.identity(self.write(".work/x86_64/dynamic/manifest", b"dynamic\n")),
                                 "tree": self.module.family.snapshot(self.dynamic)}}
        self.tools = {name: {"path": f"/tool/{name}", "sha256": "0" * 64, "size": 1}
                      for name in ("oracle", "static_driver", "dynamic_driver", "compiler", "linker")}
        self.tools["shell"] = {"path": "/bin/sh", "resolved_path": "/bin/busybox", "sha256": "0" * 64, "size": 1}
        self.tools["chroot"] = {"path": "/usr/sbin/chroot", "resolved_path": "/bin/coreutils", "sha256": "0" * 64, "size": 1}
        self.report = self.make_report()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def mkdir(self, relative: str) -> Path:
        path = self.root / relative
        path.mkdir(parents=True, exist_ok=True)
        return path

    def write(self, relative: str, contents: bytes, *, mode: int = 0o644) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(contents)
        path.chmod(mode)
        return path

    def copy_sources(self) -> None:
        for relative in dict.fromkeys(self.module.SOURCE_PATHS.values()):
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, destination)

    def write_elf(self, relative: str, etype: int = 1) -> Path:
        header = bytearray(64)
        header[:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
        header[16:18] = etype.to_bytes(2, "little")
        header[18:20] = (62).to_bytes(2, "little")
        return self.write(relative, bytes(header), mode=0o755)

    def relative(self, path: Path) -> str:
        return path.relative_to(self.root).as_posix()

    def identity(self, path: Path) -> dict[str, object]:
        data = path.read_bytes()
        return {"path": self.relative(path), "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}

    def raw(self, label: str, argv: list[str], *, cwd: str | None = None, stdout: bytes = b"", stderr: bytes = b"", status: int = 0) -> dict[str, dict[str, object]]:
        values = {"argv": json.dumps(argv, separators=(",", ":")).encode() + b"\n",
                  "cwd": json.dumps(self.module.SOURCE_MOUNT if cwd is None else cwd, separators=(",", ":")).encode() + b"\n", "stdout": stdout,
                  "stderr": stderr, "status": f"{status}\n".encode()}
        return {name: self.identity(self.write(f".work/x86_64/owned-calendar-products.fixture/{label}.{name}{'.json' if name in {'argv', 'cwd'} else ''}", value))
                for name, value in values.items()}

    def raw_at(self, directory: Path, label: str, argv: list[str], *, stdout: bytes = b"", stderr: bytes = b"",
               status: int = 0) -> dict[str, dict[str, object]]:
        values = {"argv": json.dumps(argv, separators=(",", ":")).encode() + b"\n",
                  "cwd": json.dumps(self.module.SOURCE_MOUNT, separators=(",", ":")).encode() + b"\n", "stdout": stdout,
                  "stderr": stderr, "status": f"{status}\n".encode()}
        return {name: self.identity(self.write_at(directory / f"{label}.{name}{'.json' if name in {'argv', 'cwd'} else ''}", value))
                for name, value in values.items()}

    def fake_link(self, product: Path, linkage: str) -> dict[str, object]:
        return {"linkage": linkage, "product": self.module.mounted(self.root, product), "fixture": True}

    def reconstructed_link(self, _root: Path, _mount: str, product: Path, _object: Path, _executable: Path,
                           _receipt: Path, linkage: str, _linker: object) -> dict[str, object]:
        value = self.fake_link(product, linkage)
        value["product"] = str(product)
        return value

    def stage_fixtures(self) -> dict[str, object]:
        input_root = self.mkdir(".work/x86_64/calendar-tzif-input.fixture")
        archive_pins = {}
        archives = {}
        for name, expected in self.module.TZDATA_ARCHIVES.items():
            archive_name = f"{name}2025b.tar.gz"
            archive = self.write(f".work/x86_64/calendar-tzif-input.fixture/archives/{archive_name}",
                                 f"{name}-archive\n".encode())
            signature = self.write(f".work/x86_64/calendar-tzif-input.fixture/archives/{archive_name}.asc",
                                   f"{name}-signature\n".encode())
            archive_pins[name] = {**expected, "sha256": self.identity(archive)["sha256"]}
            archives[name] = {
                "url": expected["url"], "sha256": archive_pins[name]["sha256"],
                "signature_url": expected["signature_url"], "signature_verification": "retained-unverified",
                "archive": self.identity(archive), "signature": self.identity(signature),
            }
        zic = self.write(".work/x86_64/calendar-tzif-input.fixture/build/tzdb/zic", b"fixture-zic\n", mode=0o755)
        inputs = {}
        for name, _destination in self.module.TZIF_FIXTURES:
            payload = b"new-york\n" if name == "localtime" else name.encode() + b"\n"
            inputs[name] = self.write(f".work/x86_64/calendar-tzif-input.fixture/{self.module.TZIF_INPUT_PATHS[name]}", payload)
        # The explicit /etc/localtime input is an ordinary physical New_York copy.
        inputs["localtime"].write_bytes(inputs["America/New_York"].read_bytes())
        fixtures = {name: self.identity(path) for name, path in inputs.items()}
        commands = {
            "build-zic": self.raw_at(
                input_root, "build-zic",
                ["/tool/make", "-C", self.module.mounted(self.root, input_root / "build/tzdb"),
                 "CC=/tool/compiler", "zic"],
            ),
            "derive-zoneinfo": self.raw_at(
                input_root, "derive-zoneinfo",
                [self.module.mounted(self.root, zic), "-d", self.module.mounted(self.root, input_root / "build/zoneinfo"),
                 self.module.mounted(self.root, input_root / "build/tzdb/northamerica"),
                 self.module.mounted(self.root, input_root / "build/tzdb/europe"),
                 self.module.mounted(self.root, input_root / "build/tzdb/australasia")],
            ),
        }
        manifest = {
            "schema": self.module.TZIF_INPUT_SCHEMA, "image_id": self.module.PINNED_IMAGE_ID,
            "version": self.module.TZDATA_VERSION, "archives": archives,
            "tools": {"compiler": {"path": "/tool/compiler", "sha256": "0" * 64, "size": 1},
                      "make": {"path": "/tool/make", "sha256": "0" * 64, "size": 1},
                      "zic": self.identity(zic)},
            "recipe": {"make_target": "zic", "zic_sources": ["northamerica", "europe", "australasia"],
                       "localtime_source": "America/New_York"},
            "commands": commands,
            "fixtures": fixtures,
        }
        manifest_path = self.write_json(input_root / "manifest.json", manifest)
        staged = {}
        for name, _destination in self.module.TZIF_FIXTURES:
            target = self.work / "zoneinfo-source" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(inputs[name], target)
            target.chmod(0o644)
            staged[name] = {"input": fixtures[name], "staged": self.identity(target)}
        self.tzif_archive_pins = archive_pins
        self.tzif_fixture_pins = {
            name: {"sha256": self.identity(path)["sha256"], "size": path.stat().st_size}
            for name, path in inputs.items()
        }
        return {"input_root": self.relative(input_root), "input_manifest": self.identity(manifest_path), "staged": staged}

    def copy_root(self, root: Path, executable: Path, role: str, action: str, dynamic: bool) -> dict[str, object]:
        root.parent.mkdir(parents=True, exist_ok=True)
        if dynamic:
            shutil.copytree(self.dynamic, root)
        else:
            root.mkdir()
        copied_product = None
        audit = self.work / "root-audits" / f"{root.parent.name}-{root.name}"
        audit.mkdir(parents=True, exist_ok=True)
        if dynamic:
            copied_product = self.write_json(audit / "product-copy.json", self.module.family.snapshot(root))
        shutil.copy2(executable, root / f"consumer-{role}")
        missing_lord_howe = action == "calendar-real-zones-missing-lord-howe"
        for name, destination in self.module.TZIF_FIXTURES:
            if missing_lord_howe and name == "Australia/Lord_Howe":
                continue
            target = root / destination.lstrip("/")
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(self.work / "zoneinfo-source" / name, target)
        if action in {"calendar", "calendar-malformed"}:
            self.write_at(root / "fixture/calendar-private.tzif", b"")
        elif action.startswith("tzif"):
            self.write_at(root / "fixture/tzif-private.tzif", b"")
        elif action == "getdate":
            self.write_at(root / "templates/mask", b"")
        before = self.write_json(audit / "before.json", self.module.family.snapshot(root))
        for leaf in ("fixture/calendar-private.tzif", "fixture/tzif-private.tzif", "templates/mask"):
            (root / leaf).unlink(missing_ok=True)
        after = self.write_json(audit / "after.json", self.module.family.snapshot(root))
        record: dict[str, object] = {"before": self.identity(before), "after": self.identity(after),
                                     "product-copy": self.identity(copied_product) if copied_product else None,
                                     "capability": None}
        return record

    def write_at(self, path: Path, value: bytes) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)
        path.chmod(0o644)
        return path

    def write_json(self, path: Path, value: object) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        return path

    def make_report(self) -> Path:
        module = self.module
        fixtures = self.stage_fixtures()
        objects = {}
        for role, spec in module.role_map().items():
            object_path = self.write_elf(f".work/x86_64/owned-calendar-products.fixture/objects/{role}.o")
            objects[role] = {"source": spec["source"], "defines": list(spec["defines"]), "object": self.identity(object_path)}
        plan = module.command_plan(self.root, self.work, self.static, self.dynamic, self.tools)
        commands = {}
        links = {}
        mode_linkage = {"static": "static", "static-pie": "static-pie", "dynamic-pie": "pie", "dynamic-non-pie": "non-pie"}
        actions = {name: (role, kind) for name, role, _arguments, kind in module.action_specs()}
        for label, argv in plan.items():
            stdout = b""
            stderr = b""
            status = 0
            if label.startswith("header-"):
                stdout = b"preprocessed\n"
                stderr = (module.mounted(self.root, self.dynamic / "usr/include/time.h") + "\n").encode()
            elif "-validate-" in label:
                mode = label.split("-validate-", 1)[0]
                role = label.split("-validate-", 1)[1]
                product = self.static if mode.startswith("static") else self.dynamic
                stdout = module.canonical(self.fake_link(product, mode_linkage[mode]))
            elif label.startswith("oracle-") and not label.startswith("oracle-link-"):
                action = label.removeprefix("oracle-")
                role, kind = actions[action]
                if kind == "musl-defect":
                    stdout = module.TZIF_MUSL_DEFECT_STDOUT
                elif kind == "musl-fault-correction":
                    status = 139
                elif kind == "fixture-required":
                    status = 1
                    stderr = module.REAL_ZONE_MISSING_LORD_HOWE_STDERR
                elif action == "calendar-real-zones":
                    stdout = module.REAL_ZONE_SUCCESS_STDOUT
                else:
                    stdout = f"oracle:{action}\n".encode()
            elif label.startswith("candidate-"):
                cell_action = label.removeprefix("candidate-").split("-", 1)
                # Recover the action from the known suffix rather than parsing cell dashes.
                action = next(name for name in actions if label.endswith("-" + name))
                _role, kind = actions[action]
                if kind == "tzif-specification":
                    stdout = module.TZIF_SPECIFICATION_STDOUT
                elif kind == "musl-fault-correction":
                    stdout = b""
                elif kind == "musl-delimiter-correction":
                    stdout = module.STRPTIME_DELIMITERS_STDOUT
                elif kind == "fixture-required":
                    status = 1
                    stderr = module.REAL_ZONE_MISSING_LORD_HOWE_STDERR
                elif action == "calendar-real-zones":
                    stdout = module.REAL_ZONE_SUCCESS_STDOUT
                elif kind == "candidate-only":
                    stdout = b"oracle:calendar\n"
                else:
                    stdout = f"oracle:{action}\n".encode()
            commands[label] = self.raw(label, argv, cwd=module.command_cwd(self.root, self.work, label),
                                       stdout=stdout, stderr=stderr, status=status)
        for mode, linkage in mode_linkage.items():
            product = self.static if mode.startswith("static") else self.dynamic
            for role in module.role_map():
                link = self.write_json(self.work / "links" / f"{mode}-{role}.json", self.fake_link(product, linkage))
                links[f"{mode}/{role}"] = self.identity(link)
                executable = self.write_elf(f".work/x86_64/owned-calendar-products.fixture/executables/{mode}/{role}",
                                            etype=3 if mode.endswith("pie") else 2)
                self.write_at(executable.with_name(executable.name + ".crabc-link.json"), b"receipt\n")
        roots = {}
        for label, root in module.execution_roots(self.work).items():
            cell, action = label.split("/", 1)
            role, kind = actions[action]
            mode = "static" if cell == "static-et-exec" else "static-pie" if cell == "static-pie" else "dynamic-pie" if cell.startswith("dynamic-pie") else "dynamic-non-pie"
            record = self.copy_root(root, self.work / "executables" / mode / role, role, action, cell.startswith("dynamic"))
            if kind == "differential-capability-absent":
                proof = self.write_at(
                    self.work / "capability" / f"{cell}-{action}.status",
                    b"CapInh:\t0000000000000000\nCapPrm:\t00000000a80425fb\nCapEff:\t00000000a80425fb\n"
                    b"CapBnd:\t00000000a80425fb\nCapAmb:\t0000000000000000\n",
                )
                record["capability"] = self.identity(proof)
            roots[label] = record
        for name, value in (("source-product-before", self.seal), ("source-product-after", self.seal),
                            ("tools-before", self.tools), ("tools-after", self.tools)):
            self.write_json(self.work / f"{name}.json", value)
        record = {"schema": module.SCHEMA, "source_mount": module.SOURCE_MOUNT, "image_id": module.PINNED_IMAGE_ID,
                  "execution_mode": module.FULL_MODE, "scope": list(module.SCOPE), "rows": [list(row) for row in module.ROWS],
                  "sources": self.sources, "objects": objects,
                  "products": {"static": self.relative(self.static), "dynamic": self.relative(self.dynamic)},
                  "seals": {name: self.identity(self.work / f"{name}.json") for name in
                            ("source-product-before", "source-product-after", "tools-before", "tools-after")},
                  "fixtures": fixtures, "commands": commands, "links": links, "execution_roots": roots,
                  "family_completion": False, "promotion_ready": False, "public_support": False}
        report = self.work / "owned-calendar-products.json"
        self.write_json(report, record)
        return report

    def validate(self) -> dict[str, object]:
        with mock.patch.object(self.module, "source_product_seal", return_value=self.seal), \
             mock.patch.object(self.module, "tool_roster", return_value=self.tools), \
             mock.patch.object(self.module, "TZDATA_ARCHIVES", self.tzif_archive_pins), \
             mock.patch.object(self.module, "TZIF_EXPECTED_FIXTURES", self.tzif_fixture_pins), \
             mock.patch.object(self.module.products, "validate_retained_link", side_effect=self.reconstructed_link):
            return self.module.validate_report(self.root, self.report, require_static=True)

    def report_value(self) -> dict[str, object]:
        return json.loads(self.report.read_text(encoding="utf-8"))

    def rewrite_identity(self, value: dict[str, object]) -> None:
        path = self.root / str(value["path"])
        value.update(self.identity(path))

    def rewrite_report(self, value: dict[str, object]) -> None:
        self.write_json(self.report, value)

    def test_full_six_control_reconstructs(self) -> None:
        result = self.validate()
        self.assertEqual(result["execution_mode"], "full-six-mode")
        self.assertEqual(result["scope"], ["time.clock-calendar"])

    def test_family_adapter_consumes_the_reconstructed_calendar_report(self) -> None:
        import owned_text_math_locale_stdio_family as coordinator

        source = {"revision": "a" * 40, "content_sha256": "b" * 64}
        request = coordinator.ComponentRequest(reports={pair: self.report for pair in coordinator.PAIRS})
        # Reuse the physical calendar fixture and its real public reader;
        # this adapter test does not claim three independent product builds.
        public = SimpleNamespace(validate_report=lambda root, path, require_static: self.validate())
        with mock.patch.object(coordinator.importlib, "import_module", return_value=public), \
                mock.patch.object(coordinator, "_source_after_reader", return_value=source):
            observed = coordinator._calendar_adapter(self.root, request, None)
        for evidence in observed.values():
            self.assertEqual(evidence.products, {"static": self.static, "dynamic": self.dynamic})
            self.assertEqual(evidence.modes, coordinator.PAIR_MODES)
            self.assertEqual(evidence.scope, self.module.SCOPE)
            self.assertEqual(tuple(evidence.rows), coordinator.CALENDAR_ROWS)

    def test_exact_rows_keep_candidate_only_malformed_object_outside_capabilities(self) -> None:
        self.assertEqual(self.module.ROWS, (
            ("calendar-posix-tz-format", "calendar-differential"),
            ("calendar-tzif-specification", "tzif-specification"),
            ("calendar-strptime", "strptime"),
            ("calendar-getdate-global", "getdate"),
            ("calendar-clock-adjustment-safe", "legacy-clock-control"),
        ))
        roles = self.module.role_map()
        self.assertEqual(roles["calendar-malformed-tzif"]["defines"], ("-DCRABC_OWNED_CALENDAR",))
        self.assertNotIn("calendar-malformed-tzif", {role for _row, role in self.module.ROWS})
        self.assertEqual(self.module.EXECUTION_CELLS, (
            "static-et-exec", "static-pie", "dynamic-pie-kernel", "dynamic-pie-direct",
            "dynamic-non-pie-kernel", "dynamic-non-pie-direct"))

    def test_real_zone_role_requires_known_transitions_and_a_missing_fixture_failure(self) -> None:
        roles = self.module.role_map()
        self.assertEqual(
            roles["calendar-real-zones"],
            {"source": "compat/x86_64/owned_calendar_real_zone_probe.c", "defines": (),
             "comparison": "real-zone-transitions"},
        )
        actions = {name: (role, arguments, kind) for name, role, arguments, kind in self.module.action_specs()}
        self.assertEqual(actions["calendar-real-zones"], ("calendar-real-zones", (), "differential"))
        self.assertEqual(
            actions["calendar-real-zones-missing-lord-howe"],
            ("calendar-real-zones", ("--missing-lord-howe",), "fixture-required"),
        )
        self.assertEqual(
            self.module.REAL_ZONE_SUCCESS_STDOUT,
            b"owned-calendar-real-zones: New_York Berlin Lord_Howe localtime\n",
        )
        self.assertEqual(
            self.module.REAL_ZONE_MISSING_LORD_HOWE_STDERR,
            b"owned-calendar-real-zones: fixture assertion failed: Lord_Howe-January\n",
        )

    def test_static_driver_receipt_is_checkout_relative(self) -> None:
        plan = self.module.command_plan(self.root, self.work, self.static, self.dynamic, self.tools)
        argv = plan["static-link-calendar-differential"]
        receipt = argv[argv.index("--link-receipt") + 1]
        self.assertEqual(receipt, "calendar-differential.crabc-link.json")
        self.assertEqual(self.module.command_cwd(self.root, self.work, "static-link-calendar-differential"),
                         self.module.mounted(self.root, self.work / "executables/static"))

    def test_dynamic_link_retains_the_actual_sidecar_directory(self) -> None:
        self.assertEqual(
            self.module.command_cwd(self.root, self.work, "dynamic-pie-link-calendar-differential"),
            self.module.mounted(self.root, self.work / "executables/dynamic-pie"),
        )

    def test_root_owned_runtime_product_copy_preserves_payload_and_modes(self) -> None:
        record = self.report_value()
        value = record["execution_roots"]["dynamic-pie-kernel/calendar"]["product-copy"]
        assert isinstance(value, dict)
        path = self.root / str(value["path"])
        copied = json.loads(path.read_text(encoding="utf-8"))
        for entry in copied.values():
            assert isinstance(entry, dict)
            entry["uid"] = 0
            entry["gid"] = 0
        self.write_json(path, copied)
        self.rewrite_identity(value)
        self.rewrite_report(record)
        self.validate()

    def test_rehashed_runtime_product_copy_cannot_change_a_supplied_mode(self) -> None:
        record = self.report_value()
        value = record["execution_roots"]["dynamic-pie-kernel/calendar"]["product-copy"]
        assert isinstance(value, dict)
        path = self.root / str(value["path"])
        copied = json.loads(path.read_text(encoding="utf-8"))
        leaf = next(iter(copied))
        copied[leaf]["mode"] = 0o777
        self.write_json(path, copied)
        self.rewrite_identity(value)
        self.rewrite_report(record)
        with self.assertRaisesRegex(self.module.CalendarReceiptError, "product copy differs from supplied product"):
            self.validate()

    def test_tzif_specification_check_never_runs_the_known_defect_oracle(self) -> None:
        plan = self.module.command_plan(self.root, self.work, self.static, self.dynamic, self.tools)
        self.assertNotIn("oracle-tzif-check", plan)
        self.assertIn("oracle-tzif-observe", plan)

    def test_guard_plan_proves_all_capability_sets_without_busybox_setpriv(self) -> None:
        plan = self.module.command_plan(self.root, self.work, self.static, self.dynamic, self.tools)
        command = plan["candidate-static-et-exec-adjustment-guards"]
        proof = self.module.mounted(self.root, self.work / "capability/static-et-exec-adjustment-guards.status")
        self.assertEqual(
            command[:4],
            ["/bin/sh", "-c",
             f"grep -E '^Cap(Eff|Prm|Inh|Amb|Bnd):' /proc/self/status > {proof}; exec \"$@\"",
             "calendar-capability-absent"],
        )
        self.assertEqual(command[4], "/usr/sbin/chroot")
        self.assertNotIn("setpriv", command)

    def test_rehashed_tzif_defect_stream_does_not_admit_musl_result_as_candidate(self) -> None:
        record = self.report_value()
        value = record["commands"]["candidate-static-et-exec-tzif-check"]["stdout"]
        path = self.root / value["path"]
        path.write_bytes(self.module.TZIF_MUSL_DEFECT_STDOUT)
        self.rewrite_identity(value)
        self.rewrite_report(record)
        with self.assertRaisesRegex(self.module.CalendarReceiptError, "matches pinned-musl defect"):
            self.validate()

    def test_rehashed_product_link_cannot_replace_reconstructed_validation(self) -> None:
        record = self.report_value()
        link = record["links"]["dynamic-pie/calendar-differential"]
        path = self.root / link["path"]
        path.write_bytes(self.module.canonical({"linkage": "pie", "product": "/workspace/forged"}))
        self.rewrite_identity(link)
        validate = record["commands"]["dynamic-pie-validate-calendar-differential"]["stdout"]
        validate_path = self.root / validate["path"]
        validate_path.write_bytes(path.read_bytes())
        self.rewrite_identity(validate)
        self.rewrite_report(record)
        with self.assertRaisesRegex(self.module.CalendarReceiptError, "product-link differs"):
            self.validate()

    def test_rehashed_zone_fixture_copy_cannot_drift_from_staged_image_input(self) -> None:
        record = self.report_value()
        target = self.work / "roots/static-et-exec/calendar/usr/share/zoneinfo/America/New_York"
        target.write_bytes(b"forged-zone\n")
        audit = self.work / "root-audits/static-et-exec-calendar"
        after = self.write_json(audit / "after.json", self.module.family.snapshot(self.work / "roots/static-et-exec/calendar"))
        record["execution_roots"]["static-et-exec/calendar"]["after"] = self.identity(after)
        self.rewrite_report(record)
        with self.assertRaisesRegex(self.module.CalendarReceiptError, "sealed TZif fixture differs"):
            self.validate()

    def test_rehashed_derived_tzif_cannot_drift_from_tracked_iana_derivation(self) -> None:
        record = self.report_value()
        manifest_identity = record["fixtures"]["input_manifest"]
        manifest_path = self.root / manifest_identity["path"]
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        fixture = self.root / manifest["fixtures"]["Europe/Berlin"]["path"]
        fixture.write_bytes(b"forged-zone\n")
        manifest["fixtures"]["Europe/Berlin"] = self.identity(fixture)
        self.write_json(manifest_path, manifest)
        manifest_identity.update(self.identity(manifest_path))
        self.rewrite_report(record)
        with self.assertRaisesRegex(self.module.CalendarReceiptError, "fixture bytes differ from the tracked derivation"):
            self.validate()

    def test_rehashed_real_zone_outputs_cannot_admit_a_shared_utc_fallback(self) -> None:
        record = self.report_value()
        for label, command in record["commands"].items():
            if label == "oracle-calendar-real-zones" or (
                    label.startswith("candidate-") and label.endswith("-calendar-real-zones")):
                stdout = command["stdout"]
                path = self.root / stdout["path"]
                path.write_bytes(b"UTC fallback\n")
                self.rewrite_identity(stdout)
        self.rewrite_report(record)
        with self.assertRaisesRegex(self.module.CalendarReceiptError, "did not prove known named-zone transitions"):
            self.validate()

    def test_rehashed_capability_proof_cannot_admit_sys_time(self) -> None:
        record = self.report_value()
        value = record["execution_roots"]["static-et-exec/adjustment-guards"]["capability"]
        assert isinstance(value, dict)
        path = self.root / str(value["path"])
        path.write_bytes(
            b"CapInh:\t0000000000000000\nCapPrm:\t00000000a80425fb\nCapEff:\t00000000a80425fb\n"
            b"CapBnd:\t0000000002000000\nCapAmb:\t0000000000000000\n"
        )
        self.rewrite_identity(value)
        self.rewrite_report(record)
        with self.assertRaisesRegex(self.module.CalendarReceiptError, "retains CAP_SYS_TIME in CapBnd"):
            self.validate()

    def test_rehashed_argv_cannot_change_execution_root_or_entry(self) -> None:
        record = self.report_value()
        value = record["commands"]["candidate-dynamic-pie-direct-calendar"]["argv"]
        path = self.root / value["path"]
        path.write_bytes(b'["garbage"]\n')
        self.rewrite_identity(value)
        self.rewrite_report(record)
        with self.assertRaisesRegex(self.module.CalendarReceiptError, "retained argv differs"):
            self.validate()


if __name__ == "__main__":
    unittest.main()
