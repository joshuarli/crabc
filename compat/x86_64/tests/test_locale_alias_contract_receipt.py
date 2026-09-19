#!/usr/bin/env python3
"""Process-free controls for retained locale/time alias receipts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import locale_alias_contract_receipt as receipt


class LocaleAliasContractReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        scratch = ROOT / ".work/x86_64/locale-alias-contract-receipt-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix="receipt-", dir=scratch))
        self.addCleanup(shutil.rmtree, self.root)

    @staticmethod
    def digest(value: bytes) -> str:
        return hashlib.sha256(value).hexdigest()

    def write(self, relative: str, value: bytes) -> dict[str, object]:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)
        return {
            "path": relative,
            "bytes": len(value),
            "sha256": self.digest(value),
            "mode": 0o644,
        }

    def fixed_command(self) -> dict[str, object]:
        return {
            "schema": receipt.COMMAND_SCHEMA,
            "role": "compile",
            "cwd": "/workspace",
            "argv": ["/workspace/inputs/dynamic/bin/crabc-cc-dynamic", "--dynamic-pie", "-c"],
            "status": 0,
            "environment": {"LC_ALL": "C", "PATH": receipt.COMMAND_PATH},
            "stdin": "/dev/null",
            "launcher": ["/usr/bin/env", "-i", "LC_ALL=C", f"PATH={receipt.COMMAND_PATH}", "/usr/bin/timeout", "20"],
            "stdout": self.write("raw/compile.stdout", b""),
            "stderr": self.write("raw/compile.stderr", b""),
            "status_stream": self.write("raw/compile.status", b"0\n"),
            "cwd_stream": self.write("raw/compile.cwd", b"/workspace\n"),
            "environment_stream": self.write("raw/compile.environment.json", b'{"LC_ALL":"C","PATH":"/opt/cargo/bin:/opt/musl-1.2.6/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}\n'),
            "stdin_stream": self.write("raw/compile.stdin", b"/dev/null\n"),
            "launcher_stream": self.write("raw/compile.launcher.json", b'["/usr/bin/env","-i","LC_ALL=C","PATH=/opt/cargo/bin:/opt/musl-1.2.6/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","/usr/bin/timeout","20"]\n'),
        }

    def public_entry_fixture(self, *, tracked_unselected: bool = False) -> tuple[Path, Path, dict[str, object]]:
        """Build a copied receipt whose source admission remains real on replay."""

        trusted = self.root / "trusted"
        for relative in receipt.SELECTED_SOURCES:
            source = ROOT / relative
            destination = trusted / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
        if tracked_unselected:
            (trusted / "unselected-tracked.txt").write_text("tracked original\n", encoding="utf-8")
        for command in (("git", "init", "-q"), ("git", "add", "."),
                        ("git", "-c", "user.email=receipt@example.invalid", "-c", "user.name=Receipt", "commit", "-qm", "receipt")):
            subprocess.run(command, cwd=trusted, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        revision = subprocess.check_output(("git", "rev-parse", "HEAD"), cwd=trusted, text=True).strip()
        tree = subprocess.check_output(("git", "rev-parse", "HEAD^{tree}"), cwd=trusted, text=True).strip()
        report_root = trusted / ".work/x86_64/entry-report"
        report_root.mkdir(parents=True)
        sys.path.insert(0, str(ROOT / "compat/x86_64"))
        import owned_syscall_alias_authority as authority

        authority.capture_git_objects(trusted, report_root, [revision])
        authenticated, _files = authority.source_tree(report_root, revision)
        for directory in ("inputs/source", "source-after/inputs/source"):
            for relative in receipt.SELECTED_SOURCES:
                destination = report_root / directory / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(trusted / relative, destination)
        source = {"revision": revision, "tree": tree, "content_sha256": authenticated["content_sha256"],
                  "clean": True, "paths": receipt.source_records(report_root / "inputs/source", receipt.SELECTED_SOURCES)}
        source_contract = receipt.validate_source_contract(report_root / "inputs/source")
        report = {
            "schema": receipt.SCHEMA, "status": receipt.STATUS, "mode_policy": receipt.MODE_POLICY,
            "image_inputs": {"image": "deferred"}, "source_before": source, "source_after": source,
            "source_contract": source_contract, "products": {"products": "deferred"},
            "collector_commands": [{"collector": "deferred"}], "runner_commands": [{"runner": "deferred"}],
            "snapshots": {"before": {"records": ["same"]}, "after": {"records": ["same"]}},
            "artifacts": {"artifacts": "deferred"}, "runtime": {"runtime": "deferred"},
            "symbols": {"symbols": "deferred"}, "nonclaims": list(receipt.NONCLAIMS),
        }
        report_path = report_root / "report.json"
        report_path.write_text(json.dumps(report), encoding="utf-8")
        return trusted, report_path, report

    def admit_public_entry(self, trusted: Path, report_path: Path, *, runtime_side_effect: object | None = None) -> dict[str, object]:
        """Keep source admission real while deferring the expensive native product leaves."""

        runtime = {"runtime": "deferred"}
        with mock.patch.object(receipt, "ROOT", trusted), \
             mock.patch("subprocess.Popen", side_effect=AssertionError("validate-report started a process")), \
             mock.patch.object(receipt, "_validate_image_inputs", return_value={"image": "deferred"}), \
             mock.patch.object(receipt, "_validate_products", return_value={"products": "deferred"}), \
             mock.patch.object(receipt, "_validate_collector_commands", return_value=[{"collector": "deferred"}]), \
             mock.patch.object(receipt, "_runner_records", return_value=[{"runner": "deferred"}]), \
             mock.patch.object(receipt, "_validate_execution_tools"), \
             mock.patch.object(receipt, "_validate_artifacts", return_value={"artifacts": "deferred"}), \
             mock.patch.object(receipt, "_validate_dynamic_executable_link_sidecars", return_value={"links": "deferred"}), \
             mock.patch.object(receipt, "_validate_snapshot", side_effect=lambda _root, _output_relative, value, _name: value), \
             mock.patch.object(receipt, "_validate_runtime_and_headers", side_effect=runtime_side_effect or (lambda _root: runtime)), \
             mock.patch.object(receipt, "_validate_symbol_observation", return_value={"symbols": "deferred"}):
            return receipt.validate_report(trusted, report_path)

    def test_retained_command_requires_exact_argv_and_all_raw_streams(self) -> None:
        record = self.fixed_command()
        receipt.validate_command_record(
            self.root,
            record,
            role="compile",
            cwd="/workspace",
            argv=["/workspace/inputs/dynamic/bin/crabc-cc-dynamic", "--dynamic-pie", "-c"],
            environment=receipt.COMMAND_ENVIRONMENT,
            launcher=receipt.RUNNER_LAUNCHER,
        )

        (self.root / "raw/compile.stdout").unlink()
        with self.assertRaisesRegex(receipt.LocaleAliasReceiptError, "stdout"):
            receipt.validate_command_record(
                self.root,
                record,
                role="compile",
                cwd="/workspace",
                argv=["/workspace/inputs/dynamic/bin/crabc-cc-dynamic", "--dynamic-pie", "-c"],
                environment=receipt.COMMAND_ENVIRONMENT,
                launcher=receipt.RUNNER_LAUNCHER,
            )

        self.write("raw/compile.stdout", b"")
        forged = json.loads(json.dumps(record))
        forged["argv"][-1] = "--forged"
        with self.assertRaisesRegex(receipt.LocaleAliasReceiptError, "argv"):
            receipt.validate_command_record(
                self.root,
                forged,
                role="compile",
                cwd="/workspace",
                argv=["/workspace/inputs/dynamic/bin/crabc-cc-dynamic", "--dynamic-pie", "-c"],
                environment=receipt.COMMAND_ENVIRONMENT,
                launcher=receipt.RUNNER_LAUNCHER,
            )

        forged = json.loads(json.dumps(record))
        forged["environment"]["PATH"] = "/forged"
        with self.assertRaisesRegex(receipt.LocaleAliasReceiptError, "environment"):
            receipt.validate_command_record(
                self.root,
                forged,
                role="compile",
                cwd="/workspace",
                argv=["/workspace/inputs/dynamic/bin/crabc-cc-dynamic", "--dynamic-pie", "-c"],
                environment=receipt.COMMAND_ENVIRONMENT,
                launcher=receipt.RUNNER_LAUNCHER,
            )

    def test_source_records_bind_current_bytes_not_only_claimed_hashes(self) -> None:
        source = self.root / "source/owned_calendar.rs"
        source.parent.mkdir(parents=True)
        source.write_bytes(b"#[export_name = \"__asctime_r\"]\n")
        records = receipt.source_records(self.root, ("source/owned_calendar.rs",))
        receipt.validate_source_records(self.root, records)

        source.write_bytes(b"#[export_name = \"__forged___\"]\n")
        with self.assertRaisesRegex(receipt.LocaleAliasReceiptError, "source bytes"):
            receipt.validate_source_records(self.root, records)

    def test_source_contract_keeps_the_full_roster_and_hidden_time_boundary(self) -> None:
        for relative in (receipt.CONTRACT_PATH, "docker/x86_64-musl-oracle-gcc", *receipt.IMPLEMENTATION_SOURCES):
            source = ROOT / relative
            copied = self.root / relative
            copied.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, copied)
        observed = receipt.validate_source_contract(self.root)
        self.assertEqual((observed["visible_pairs"], observed["hidden_pairs"]), (43, 4))
        self.assertFalse(observed["wcsftime_l_in_contract"])

        timezone = self.root / "libc/src/c_abi/x86_64/owned_timezone.rs"
        timezone.write_text(timezone.read_text(encoding="utf-8").replace('fn refresh_tzset()', 'fn forged_refresh()'), encoding="utf-8")
        with self.assertRaisesRegex(receipt.LocaleAliasReceiptError, "tzset boundary"):
            receipt.validate_source_contract(self.root)

    def test_runner_plan_is_the_closed_35_command_normal_consumer_matrix(self) -> None:
        plan = receipt._runner_plan(".work/x86_64/locale-alias-contract-receipt")
        self.assertEqual([role for role, _argv in plan], list(receipt.RUNNER_STEMS))
        self.assertEqual(len(plan), 35)
        self.assertEqual(plan[0][1][-2:], ["-o", "/workspace/.work/x86_64/locale-alias-contract-receipt/tmp/runner/probe.o"])
        self.assertNotIn("wcsftime_l", "\n".join(argument for _role, argv in plan for argument in argv))

    def test_runner_snapshot_keeps_producer_paths_and_receipt_relative_identities(self) -> None:
        """The runner hashes supplied products at their mounted producer paths."""

        output_relative = ".work/x86_64/locale-alias-contract-receipt"
        receipt_root = self.root / output_relative
        raw = receipt_root / receipt.RUNNER_DIRECTORY
        raw.mkdir(parents=True)
        source_paths = (receipt.PROBE_PATH, receipt.CONTRACT_PATH, receipt.SYMBOL_READER_PATH)
        product_paths = (
            receipt.STATIC_PRODUCT_DIRECTORY + "/usr/lib/libc.a",
            receipt.DYNAMIC_PRODUCT_DIRECTORY + "/usr/lib/libc.so",
        )
        runner_paths = [
            *(receipt._mount(path) for path in source_paths),
            *(receipt._mount(f"{output_relative}/{path}") for path in product_paths),
        ]
        snapshot = "".join(f"{'a' * 64}  {path}\n" for path in runner_paths)
        (raw / "before.sha256").write_text(snapshot, encoding="ascii")

        observed = receipt._snapshot(receipt_root, output_relative, "before")

        self.assertEqual(
            observed["records"],
            [{"path": path, "sha256": "a" * 64} for path in (*source_paths, *product_paths)],
        )

        wrong_paths = [*runner_paths[:3], *(receipt._mount(path) for path in product_paths)]
        (raw / "before.sha256").write_text(
            "".join(f"{'a' * 64}  {path}\n" for path in wrong_paths), encoding="ascii"
        )
        with self.assertRaisesRegex(receipt.LocaleAliasReceiptError, "snapshot path changed"):
            receipt._snapshot(receipt_root, output_relative, "before")

    def test_static_preparation_safe_directory_is_inside_its_closed_environment(self) -> None:
        output = self.root / ".work/x86_64/collector"
        relative = ".work/x86_64/collector"
        environment = {
            **receipt.COMMAND_ENVIRONMENT,
            "TMPDIR": str(output / "tmp"),
            "TZ": "UTC",
            "PYTHONDONTWRITEBYTECODE": "1",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "safe.directory",
            "GIT_CONFIG_VALUE_0": "/workspace",
        }
        observed: list[dict[str, object]] = []

        def run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
            observed.append({"argv": argv, "env": kwargs["env"]})
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        expected = receipt._collector_environment(relative)
        with mock.patch("subprocess.run", side_effect=run):
            for role, argv in receipt._expected_collector_commands(relative):
                receipt._run(self.root, output, role, argv, env=environment)

        reconstructed = receipt._raw_collector_commands(output, relative)
        self.assertEqual([record["environment"] for record in reconstructed], [expected] * 3)
        self.assertEqual([record["launcher"] for record in reconstructed], [receipt._collector_launcher(relative)] * 3)
        self.assertEqual([record["env"] for record in observed], [environment] * 3)
        self.assertEqual(
            [record["argv"] for record in observed],
            [[*receipt._collector_launcher(relative), *argv]
             for _role, argv in receipt._expected_collector_commands(relative)],
        )
        self.assertIn("GIT_CONFIG_KEY_0=safe.directory", receipt._collector_launcher(relative))
        self.assertIn("GIT_CONFIG_VALUE_0=/workspace", receipt._collector_launcher(relative))

    def test_execution_tools_joins_source_tool_by_logical_source_path(self) -> None:
        """A mounted source tool and its retained copy have distinct root paths."""

        source_copy = self.write(f"inputs/source/{receipt.RUNNER_PATH}", b"runner source\n")
        source = {"paths": [{**source_copy, "path": receipt.RUNNER_PATH}]}
        image_files: dict[str, object] = {}
        for index, program in enumerate(("/bin/bash", "/bin/sh", "/usr/bin/gcc", "/usr/bin/env", "/usr/bin/timeout")):
            retained = self.write(f"inputs/image/{index}", program.encode())
            image_files[program] = {
                "image": {"path": program, "sha256": self.digest(program.encode()), "size": len(program), "mode": 0o644},
                "retained": retained,
            }
        command = {"argv": [receipt._mount(receipt.RUNNER_PATH)], "launcher": receipt.RUNNER_LAUNCHER}

        receipt._validate_execution_tools(self.root, ".work/x86_64/receipt", source, {"files": image_files}, {}, [command], [])

        forged = {"paths": [{**source["paths"][0], "sha256": "0" * 64}]}
        with self.assertRaisesRegex(receipt.LocaleAliasReceiptError, "source tool differs"):
            receipt._validate_execution_tools(self.root, ".work/x86_64/receipt", forged, {"files": image_files}, {}, [command], [])

    def test_collector_uses_the_established_static_preparation_primary(self) -> None:
        output = ".work/x86_64/locale-alias-contract-receipt"
        commands = receipt._expected_collector_commands(output)
        self.assertEqual(
            commands[0],
            ("prepare-static", [
                "/usr/bin/python3", "-B", "/workspace/compat/x86_64/owned_posix_static_products.py",
                "prepare", "/workspace/.work/x86_64/locale-alias-contract-receipt/static-preparation",
            ]),
        )
        self.assertEqual(
            commands[-1][1][-3:],
            ["--static-sysroot", "/workspace/.work/x86_64/locale-alias-contract-receipt/static-preparation/products/primary",
             "/workspace/.work/x86_64/locale-alias-contract-receipt/products/dynamic"],
        )
        self.assertNotIn("build_x86_64_owned_sysroot.py", "\n".join(" ".join(argv) for _role, argv in commands))

    def test_runner_raw_roster_admits_the_two_dynamic_link_receipts(self) -> None:
        output_relative = ".work/x86_64/runner-roster"
        receipt_root = self.root / output_relative
        raw = receipt_root / receipt.RUNNER_DIRECTORY
        raw.mkdir(parents=True)
        for stem, argv in receipt._runner_plan(output_relative):
            (raw / f"{stem}.argv.json").write_text(json.dumps(argv), encoding="utf-8")
            (raw / f"{stem}.cwd").write_text("/workspace\n", encoding="utf-8")
            (raw / f"{stem}.environment.json").write_text(json.dumps(receipt.COMMAND_ENVIRONMENT), encoding="utf-8")
            (raw / f"{stem}.stdin").write_text("/dev/null\n", encoding="utf-8")
            (raw / f"{stem}.launcher.json").write_text(json.dumps(receipt.RUNNER_LAUNCHER), encoding="utf-8")
            (raw / f"{stem}.stdout").write_bytes(b"")
            (raw / f"{stem}.stderr").write_bytes(b"")
            (raw / f"{stem}.status").write_text("0\n", encoding="utf-8")
        for name in ("before.sha256", "after.sha256", "alias-observation.json", *receipt.RUNNER_ARTIFACTS):
            (raw / name).write_bytes(b"{}\n")
        for name in ("oracle-dynamic-root", "candidate-dynamic-root"):
            (raw / name).mkdir()

        records = receipt._raw_runner_records(receipt_root, output_relative)
        self.assertEqual([record["role"] for record in records], list(receipt.RUNNER_STEMS))
        artifacts = receipt._artifacts(receipt_root)
        self.assertEqual(set(artifacts), set(receipt.RUNNER_ARTIFACTS))
        for _executable, sidecar, _linkage in receipt.DYNAMIC_EXECUTABLE_LINK_SIDECARS:
            self.assertEqual(artifacts[sidecar], {
                "path": f"{receipt.RUNNER_DIRECTORY}/{sidecar}", "bytes": 3,
                "sha256": self.digest(b"{}\n"), "mode": 0o644,
            })
        sidecar = receipt.DYNAMIC_EXECUTABLE_LINK_SIDECARS[0][1]
        (raw / sidecar).write_bytes(b"forged sidecar\n")
        with self.assertRaisesRegex(receipt.LocaleAliasReceiptError, "linked executable bytes changed"):
            receipt._validate_artifacts(receipt_root, artifacts)
        (raw / sidecar).write_bytes(b"{}\n")

        (raw / "forged-extra").write_bytes(b"forged\n")
        with self.assertRaisesRegex(receipt.LocaleAliasReceiptError, "raw file roster"):
            receipt._raw_runner_records(receipt_root, output_relative)

    def test_dynamic_link_sidecars_use_the_sealed_product_reader(self) -> None:
        receipt_root = self.root / ".work/x86_64/retained-receipt"
        raw = receipt_root / receipt.RUNNER_DIRECTORY
        raw.mkdir(parents=True)
        dynamic = receipt_root / receipt.DYNAMIC_PRODUCT_DIRECTORY
        dynamic.mkdir(parents=True)
        image = {"files": {
            receipt.DYNAMIC_LINKER_PATH: {"image": {
                "path": receipt.DYNAMIC_LINKER_PATH, "sha256": "a" * 64, "size": 1, "mode": 0o755,
            }},
        }}
        result = {
            "linkage": "pie", "product": str(dynamic), "product_format": "dynamic", "product_manifest_sha256": "b" * 64,
            "workload_sha256": "c" * 64, "executable_sha256": "d" * 64, "receipt_sha256": "e" * 64,
        }
        with mock.patch("owned_posix_product_evidence.validate_retained_link", return_value=result) as validate:
            observed = receipt._validate_dynamic_executable_link_sidecars(self.root, receipt_root, image)

        self.assertEqual(set(observed), {"candidate-dynamic-pie", "candidate-dynamic-non-pie"})
        self.assertEqual(validate.call_count, 2)
        for call, (executable, sidecar, linkage) in zip(validate.call_args_list, receipt.DYNAMIC_EXECUTABLE_LINK_SIDECARS):
            args, kwargs = call
            self.assertEqual(args, (
                self.root, "/workspace", dynamic, raw / "probe.o", raw / executable, raw / sidecar, linkage,
                {"path": receipt.DYNAMIC_LINKER_PATH, "sha256": "a" * 64},
            ))
            self.assertEqual(kwargs, {"export_dynamic": True})

    def test_both_product_producer_tool_records_must_match_pinned_image_inputs(self) -> None:
        base = "/opt/rustup/toolchains/nightly-2026-07-24-x86_64-unknown-linux-musl/lib/rustlib/x86_64-unknown-linux-musl/bin/"
        tools = {
            "schema": 1,
            "target": "x86_64-unknown-linux-musl",
            "toolchain": "nightly-2026-07-24",
            "selection": {}, "rustup": {}, "rustc": {},
            "llvm_target_tools": {
                name: {"path": base + name, "resolved_path": base + name, "sha256": self.digest(name.encode())}
                for name in ("llvm-ar", "llvm-nm", "llvm-objdump")
            },
        }
        image = {"files": {
            base + name: {"image": {"path": base + name, "sha256": self.digest(name.encode())}}
            for name in ("llvm-ar", "llvm-nm", "llvm-objdump")
        }}
        static = self.root / "products/static/share/crabc"
        dynamic = self.root / "products/dynamic/share/crabc"
        static.mkdir(parents=True)
        dynamic.mkdir(parents=True)
        (static / "manifest.json").write_text(json.dumps({"producer_tools": tools}), encoding="utf-8")
        (dynamic / "producer-tools.json").write_text(json.dumps(tools), encoding="utf-8")
        self.assertEqual(
            set(receipt._validate_producer_tools(self.root, static.parents[1], "static", image)["llvm_target_tools"]),
            {"llvm-ar", "llvm-nm", "llvm-objdump"},
        )
        self.assertEqual(
            set(receipt._validate_producer_tools(self.root, dynamic.parents[1], "dynamic", image)["llvm_target_tools"]),
            {"llvm-ar", "llvm-nm", "llvm-objdump"},
        )
        forged = json.loads(json.dumps(tools))
        forged["llvm_target_tools"]["llvm-ar"]["sha256"] = "0" * 64
        (static / "manifest.json").write_text(json.dumps({"producer_tools": forged}), encoding="utf-8")
        with self.assertRaisesRegex(receipt.LocaleAliasReceiptError, "llvm-ar producer tool differs"):
            receipt._validate_producer_tools(self.root, static.parents[1], "static", image)
        forged = json.loads(json.dumps(tools))
        forged["llvm_target_tools"]["llvm-nm"]["sha256"] = "0" * 64
        (dynamic / "producer-tools.json").write_text(json.dumps(forged), encoding="utf-8")
        with self.assertRaisesRegex(receipt.LocaleAliasReceiptError, "llvm-nm producer tool differs"):
            receipt._validate_producer_tools(self.root, dynamic.parents[1], "dynamic", image)

    def test_trusted_image_manifest_requires_the_pinned_oracle_and_actual_launch_tools(self) -> None:
        manifest = json.loads((ROOT / receipt.IMAGE_MANIFEST_PATH).read_text(encoding="utf-8"))
        self.assertIn("/opt/musl-1.2.6/lib/libc.a", manifest["files"])
        self.assertIn("/usr/bin/timeout", manifest["files"])
        self.assertEqual(
            {path.rsplit("/", 1)[-1] for path in receipt.PRODUCER_TOOL_PATHS.values()},
            {"llvm-ar", "llvm-nm", "llvm-objdump"},
        )
        for path in receipt.PRODUCER_TOOL_PATHS.values():
            self.assertIn(path, manifest["files"])

        forged_root = self.root / "forged-root"
        manifest_path = forged_root / receipt.IMAGE_MANIFEST_PATH
        manifest_path.parent.mkdir(parents=True)
        manifest["files"].pop("/usr/bin/timeout")
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        with mock.patch.object(receipt, "ROOT", forged_root):
            with self.assertRaisesRegex(receipt.LocaleAliasReceiptError, "unexpected oracle or tool roster"):
                receipt._trusted_image_manifest()
        manifest = json.loads((ROOT / receipt.IMAGE_MANIFEST_PATH).read_text(encoding="utf-8"))
        manifest["files"]["/forged-tool"] = manifest["files"]["/usr/bin/timeout"]
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        with mock.patch.object(receipt, "ROOT", forged_root):
            with self.assertRaisesRegex(receipt.LocaleAliasReceiptError, "unexpected oracle or tool roster"):
                receipt._trusted_image_manifest()

    def test_product_tree_retains_directory_file_and_symlink_modes(self) -> None:
        product = self.root / "products/static"
        nested = product / "bin"
        nested.mkdir(parents=True)
        nested.chmod(0o751)
        tool = nested / "crabc-cc"
        tool.write_bytes(b"driver\n")
        tool.chmod(0o755)
        (product / "driver-link").symlink_to("bin/crabc-cc")
        records = receipt._tree_records(self.root, "products/static")
        self.assertIn({"path": "products/static/bin", "kind": "directory", "mode": 0o751}, records)
        self.assertIn({"path": "products/static/bin/crabc-cc", "kind": "file", "bytes": 7,
                       "sha256": self.digest(b"driver\n"), "mode": 0o755}, records)
        self.assertIn({"path": "products/static/driver-link", "kind": "symlink", "target": "bin/crabc-cc", "mode": 0o777}, records)

    def test_product_root_mode_is_explicit_and_rejects_legacy_or_forged_records(self) -> None:
        """The descendant roster cannot silently stand in for a setgid root."""
        static = self.root / receipt.STATIC_PRODUCT_DIRECTORY
        dynamic = self.root / receipt.DYNAMIC_PRODUCT_DIRECTORY
        for product, name in ((static, "static"), (dynamic, "dynamic")):
            metadata = product / "share/crabc/manifest.json"
            metadata.parent.mkdir(parents=True, exist_ok=True)
            metadata.write_text("{}\n", encoding="utf-8")
            (product / "usr/lib").mkdir(parents=True, exist_ok=True)
            (product / "usr/lib" / f"lib{name}.a").write_bytes(name.encode())
        static.chmod(0o2755)
        dynamic.chmod(0o2755)
        state = dynamic / "share/crabc/dynamic-product-state.json"
        state.write_text('{"source_sha256":"' + "c" * 64 + '"}\n', encoding="utf-8")
        source = {
            "revision": "a" * 40, "tree": "b" * 40, "content_sha256": "c" * 64, "clean": True,
            "paths": [{"path": "compat/x86_64/locale_alias_contract.json", "bytes": 2071,
                       "sha256": "d" * 64, "mode": 0o644}],
        }
        products = {
            "static": {
                "root_mode": 0o2755, "tree": receipt._tree_records(self.root, receipt.STATIC_PRODUCT_DIRECTORY),
                "manifest": receipt._identity(self.root, static / "share/crabc/manifest.json"), "preparation": {},
            },
            "dynamic": {
                "root_mode": 0o2755, "tree": receipt._tree_records(self.root, receipt.DYNAMIC_PRODUCT_DIRECTORY),
                "manifest": receipt._identity(self.root, dynamic / "share/crabc/manifest.json"),
                "source_before": source, "source_after": source,
                "state": receipt._identity(self.root, state),
            },
        }
        with mock.patch.object(receipt, "_validate_static_preparation", return_value={}), \
             mock.patch("owned_posix_product_evidence._validate_static_product", return_value=(static / "share/crabc/manifest.json", {})), \
             mock.patch("owned_posix_product_evidence._validate_dynamic_product", return_value=(dynamic / "share/crabc/manifest.json", {})), \
             mock.patch.object(receipt, "_validate_producer_tools"):
            observed = receipt._validate_products(self.root, self.root, products, source, {"files": {}})
            self.assertEqual(observed["static"]["root_mode"], 0o2755)
            self.assertEqual(observed["dynamic"]["root_mode"], 0o2755)
            forged = json.loads(json.dumps(products))
            forged["dynamic"]["root_mode"] = 0o755
            with self.assertRaisesRegex(receipt.LocaleAliasReceiptError, "dynamic retained product root mode changed"):
                receipt._validate_products(self.root, self.root, forged, source, {"files": {}})
            forged = json.loads(json.dumps(products))
            forged["dynamic"]["root_mode"] = float(0o2755)
            with self.assertRaisesRegex(receipt.LocaleAliasReceiptError, "dynamic retained product root mode is invalid"):
                receipt._validate_products(self.root, self.root, forged, source, {"files": {}})
            forged = json.loads(json.dumps(products))
            forged["dynamic"].pop("root_mode")
            with self.assertRaisesRegex(receipt.LocaleAliasReceiptError, "dynamic retained product fields changed"):
                receipt._validate_products(self.root, self.root, forged, source, {"files": {}})
            forged = json.loads(json.dumps(products))
            forged["dynamic"]["source_before"]["paths"][0]["sha256"] = "0" * 64
            with self.assertRaisesRegex(receipt.LocaleAliasReceiptError, "dynamic product source transaction changed"):
                receipt._validate_products(self.root, self.root, forged, source, {"files": {}})

    def test_retained_image_input_binds_manifest_bytes_and_mode(self) -> None:
        tool_bytes = b"pinned tool\n"
        image_entry = {"path": "/tool", "sha256": self.digest(tool_bytes), "size": len(tool_bytes), "mode": 0o644}
        trusted = {"schema": "test", "image": "test", "path": "test", "files": {"/tool": image_entry}}
        manifest_record = self.write(f"inputs/source/{receipt.IMAGE_MANIFEST_PATH}", json.dumps(trusted).encode() + b"\n")
        tool_record = self.write("inputs/image/tool", tool_bytes)
        report = {"id": receipt.PINNED_IMAGE, "manifest": manifest_record,
                  "files": {"/tool": {"image": image_entry, "retained": tool_record}}}
        with mock.patch.object(receipt, "_trusted_image_manifest", return_value=trusted):
            self.assertEqual(receipt._validate_image_inputs(self.root, report), report)
            (self.root / "inputs/image/tool").write_bytes(b"forged tool\n")
            with self.assertRaisesRegex(receipt.LocaleAliasReceiptError, "bytes changed"):
                receipt._validate_image_inputs(self.root, report)

    def test_final_transaction_recheck_rejects_a_post_report_source_change(self) -> None:
        source = {"revision": "a" * 40, "tree": "b" * 40, "content_sha256": "c" * 64, "clean": True,
                  "paths": []}
        with mock.patch.object(receipt, "_live_source_state", return_value={**source, "content_sha256": "d" * 64}), \
             mock.patch.object(receipt, "_validate_image_inputs"), \
             mock.patch.object(receipt, "_validate_products"), \
             mock.patch.object(receipt, "_raw_collector_commands"), \
             mock.patch.object(receipt, "_raw_runner_records"), \
             mock.patch.object(receipt, "_validate_dynamic_executable_link_sidecars"):
            with self.assertRaisesRegex(receipt.LocaleAliasReceiptError, "source changed after"):
                receipt._final_transaction_recheck(self.root, self.root, source, {}, {}, [], [], ".work/x86_64/test")

    def test_final_transaction_recheck_rejects_a_changed_raw_command_stream(self) -> None:
        source = {"revision": "a" * 40, "tree": "b" * 40, "content_sha256": "c" * 64, "clean": True,
                  "paths": []}
        with mock.patch.object(receipt, "_live_source_state", return_value=receipt._source_state(source)), \
             mock.patch.object(receipt, "_validate_image_inputs", return_value={}), \
             mock.patch.object(receipt, "_validate_products", return_value={}), \
             mock.patch.object(receipt, "_raw_collector_commands", return_value=[{"changed": True}]), \
             mock.patch.object(receipt, "_raw_runner_records", return_value=[]), \
             mock.patch.object(receipt, "_validate_dynamic_executable_link_sidecars"):
            with self.assertRaisesRegex(receipt.LocaleAliasReceiptError, "collector raw streams changed"):
                receipt._final_transaction_recheck(self.root, self.root, source, {}, {}, [], [], ".work/x86_64/test")

    def test_live_source_state_rejects_an_untracked_input(self) -> None:
        source = self.root / "clean-source"
        source.mkdir()
        (source / "tracked.txt").write_text("tracked\n", encoding="utf-8")
        for command in (("git", "init", "-q"), ("git", "add", "tracked.txt"),
                        ("git", "-c", "user.email=receipt@example.invalid", "-c", "user.name=Receipt", "commit", "-qm", "source")):
            subprocess.run(command, cwd=source, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        state = receipt._live_source_state(source)
        self.assertTrue(state["clean"])
        (source / "untracked.txt").write_text("untracked\n", encoding="utf-8")
        with self.assertRaisesRegex(receipt.LocaleAliasReceiptError, "clean Git source state"):
            receipt._live_source_state(source)

    def test_validate_report_public_entry_runs_real_source_authority_before_admission(self) -> None:
        report_root = Path(tempfile.mkdtemp(prefix="real-entry-", dir=ROOT / ".work/x86_64"))
        self.addCleanup(shutil.rmtree, report_root)
        report = {
            "schema": receipt.SCHEMA,
            "status": receipt.STATUS,
            "mode_policy": receipt.MODE_POLICY,
            "image_inputs": {"id": receipt.PINNED_IMAGE, "manifest": {}, "files": {}},
            "source_before": {"revision": "0" * 40, "tree": "0" * 40, "content_sha256": "0" * 64,
                              "clean": True, "paths": []},
            "source_after": {"revision": "0" * 40, "tree": "0" * 40, "content_sha256": "0" * 64,
                             "clean": True, "paths": []},
            "source_contract": {}, "products": {}, "collector_commands": [], "runner_commands": [],
            "snapshots": {}, "artifacts": {}, "runtime": {}, "symbols": {}, "nonclaims": list(receipt.NONCLAIMS),
        }
        report_path = report_root / "report.json"
        report_path.write_text(json.dumps(report), encoding="utf-8")
        with self.assertRaisesRegex(receipt.LocaleAliasReceiptError, "complete Git source authority"):
            receipt.validate_report(ROOT, report_path)

    def test_validate_report_entry_uses_real_source_and_contract_validators(self) -> None:
        """The public entry reaches source admission without mocking it away."""

        trusted, report_path, report = self.public_entry_fixture()
        admitted = self.admit_public_entry(trusted, report_path)
        self.assertEqual(admitted["source"], report["source_before"])

    def test_validate_report_rejects_a_forged_selected_source_path_identity(self) -> None:
        """The source seal includes its path records, not only its Git digest."""

        trusted, report_path, report = self.public_entry_fixture()
        for name in ("source_before", "source_after"):
            report[name]["paths"][0]["sha256"] = "0" * 64
        report_path.write_text(json.dumps(report), encoding="utf-8")
        with self.assertRaisesRegex(receipt.LocaleAliasReceiptError, "retained source bytes changed"):
            self.admit_public_entry(trusted, report_path)

    def test_validate_report_rejects_the_v2_product_root_omission_schema(self) -> None:
        trusted, report_path, report = self.public_entry_fixture()
        report["schema"] = "crabc.x86_64-locale-alias-contract-receipt/v2"
        report_path.write_text(json.dumps(report), encoding="utf-8")
        with self.assertRaisesRegex(receipt.LocaleAliasReceiptError, "status changed"):
            self.admit_public_entry(trusted, report_path)

    def test_validate_report_public_exit_rejects_a_report_changed_after_initial_reconstruction(self) -> None:
        trusted, report_path, report = self.public_entry_fixture()

        def mutate_report(_root: Path) -> dict[str, object]:
            changed = dict(report)
            changed["runtime"] = {"runtime": "changed-after-initial-read"}
            report_path.write_text(json.dumps(changed), encoding="utf-8")
            return {"runtime": "deferred"}

        with self.assertRaisesRegex(receipt.LocaleAliasReceiptError, "report changed during process-free replay"):
            self.admit_public_entry(trusted, report_path, runtime_side_effect=mutate_report)

    def test_validate_report_public_exit_rechecks_retained_source_after_initial_reconstruction(self) -> None:
        trusted, report_path, _report = self.public_entry_fixture()
        changed = trusted / ".work/x86_64/entry-report/inputs/source" / receipt.CONTRACT_PATH

        def mutate_retained_source(_root: Path) -> dict[str, object]:
            changed.write_bytes(changed.read_bytes() + b"\n")
            return {"runtime": "deferred"}

        with self.assertRaisesRegex(receipt.LocaleAliasReceiptError, "retained source bytes changed"):
            self.admit_public_entry(trusted, report_path, runtime_side_effect=mutate_retained_source)

    def test_validate_report_rejects_an_unselected_tracked_source_change_without_spawning(self) -> None:
        trusted, report_path, _report = self.public_entry_fixture(tracked_unselected=True)
        (trusted / "unselected-tracked.txt").write_text("changed after receipt\n", encoding="utf-8")
        with self.assertRaisesRegex(receipt.LocaleAliasReceiptError, "current tracked source differs"):
            self.admit_public_entry(trusted, report_path)

    def test_validate_report_entry_joins_every_required_retained_relation(self) -> None:
        report_root = Path(tempfile.mkdtemp(prefix="report-", dir=ROOT / ".work/x86_64"))
        self.addCleanup(shutil.rmtree, report_root)
        report = {
            "schema": receipt.SCHEMA,
            "status": receipt.STATUS,
            "mode_policy": receipt.MODE_POLICY,
            "image_inputs": {"image": "ok"},
            "source_before": {"source": "same"},
            "source_after": {"source": "same"},
            "source_contract": {"contract": "ok"},
            "products": {"products": "ok"},
            "collector_commands": [{"collector": "ok"}],
            "runner_commands": [{"runner": "ok"}],
            "snapshots": {"before": {"records": ["same"]}, "after": {"records": ["same"]}},
            "artifacts": {"object": "ok"},
            "runtime": {"runtime": "ok"},
            "symbols": {"symbols": "ok"},
            "nonclaims": list(receipt.NONCLAIMS),
        }
        report_path = report_root / "report.json"
        report_path.write_text(json.dumps(report), encoding="utf-8")
        source_value = {"source": "same", "paths": []}
        with mock.patch.object(receipt, "_validate_source_seal", return_value=source_value) as source_seal, \
             mock.patch.object(receipt, "validate_source_contract", return_value={"contract": "ok"}) as source_contract, \
             mock.patch.object(receipt, "_validate_image_inputs", return_value={"image": "ok"}) as image, \
             mock.patch.object(receipt, "_validate_products", return_value={"products": "ok"}) as products, \
             mock.patch.object(receipt, "_validate_collector_commands", return_value=[{"collector": "ok"}]) as collector, \
             mock.patch.object(receipt, "_runner_records", return_value=[{"runner": "ok"}]) as runner, \
             mock.patch.object(receipt, "_validate_execution_tools") as tools, \
             mock.patch.object(receipt, "_validate_artifacts", return_value={"object": "ok"}) as artifacts, \
             mock.patch.object(receipt, "_validate_dynamic_executable_link_sidecars", return_value={"links": "ok"}) as dynamic_links, \
             mock.patch.object(receipt, "_validate_snapshot", side_effect=lambda _root, _output_relative, value, _name: value) as snapshots, \
             mock.patch.object(receipt, "_validate_runtime_and_headers", return_value={"runtime": "ok"}) as runtime, \
             mock.patch.object(receipt, "_validate_symbol_observation", return_value={"symbols": "ok"}) as symbols:
            admitted = receipt.validate_report(ROOT, report_path)

        self.assertEqual(admitted["status"], receipt.STATUS)
        for boundary in (source_seal, source_contract, image, products, collector, runner, tools, artifacts, dynamic_links, snapshots, runtime, symbols):
            self.assertGreaterEqual(boundary.call_count, 1)

        malformed = dict(report)
        malformed.pop("artifacts")
        report_path.write_text(json.dumps(malformed), encoding="utf-8")
        with self.assertRaisesRegex(receipt.LocaleAliasReceiptError, "fields changed"):
            receipt.validate_report(ROOT, report_path)


class LocaleAliasRunnerRetentionTests(unittest.TestCase):
    def test_runner_accepts_a_fresh_explicit_receipt_directory_and_records_cwd(self) -> None:
        runner = (ROOT / "compat/x86_64/run_locale_alias_contract.sh").read_text(encoding="utf-8")
        self.assertIn("--receipt-dir", runner)
        self.assertIn('"$work/$stem.cwd"', runner)
        self.assertIn('"$work/$stem.environment.json"', runner)
        self.assertIn('"$work/$stem.launcher.json"', runner)
        self.assertIn('< /dev/null', runner)
        self.assertIn('umask 022', runner)
        self.assertIn("receipt directory must be below checkout-local TMPDIR", runner)


if __name__ == "__main__":
    unittest.main()
