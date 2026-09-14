#!/usr/bin/env python3
"""Focused contracts for the finite loader structural-owner receipt."""
from __future__ import annotations

import sys
import json
import hashlib
import tempfile
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat" / "x86_64"))

import loader_structural_owner_contract_reader as reader  # noqa: E402


class LoaderStructuralOwnerProjectionTests(unittest.TestCase):
    def test_projection_is_exactly_the_eight_structural_identities(self) -> None:
        self.assertEqual(reader.component_projection(), {
            "identities": [
                "__dls2b", "__dls3", "_dlstart", "__ldso_register_dlopen",
                "__ldso_register_dlsym", "__ldso_register_dlclose",
                "__ldso_register_dlerror", "__ldso_register_mark_multithreaded",
            ],
            "component_complete": True,
            "family_completion": False,
            "runtime_qualification": False,
            "promotion_ready": False,
            "public_support": False,
        })


class LoaderStructuralOwnerSourceTests(unittest.TestCase):
    def test_current_source_has_the_selected_function_and_feature_routes(self) -> None:
        source = reader.validate_source_algorithms(ROOT)
        self.assertEqual(source["ldso_feature"], "x86_64-owned-dynamic-runtime")
        self.assertEqual(source["libc_feature"], "x86-owned-dynamic-runtime")
        self.assertEqual(source["selected_graph"],
                         "ldso/src/x86_64_general_initial_graph.rs::run_with_initial_tls")

    def test_reordered_graph_transition_rejects_within_the_selected_function(self) -> None:
        graph = (ROOT / "ldso/src/x86_64_general_initial_graph.rs").read_text(encoding="utf-8")
        body = reader.rust_function_body(graph, "unsafe fn run_with_initial_tls")
        selected_commit = "let conventional_startup = unsafe { state.commit_runtime_v1(installed) };"
        changed = body.replace("state.materialize_initial_tls()", "__temporary_materialize__", 1)
        changed = changed.replace(selected_commit, "state.materialize_initial_tls()", 1)
        changed = changed.replace("__temporary_materialize__", selected_commit, 1)
        with self.assertRaisesRegex(reader.LoaderStructuralOwnerError, "selected graph order"):
            reader.validate_selected_graph_body(changed)

    def test_duplicate_selected_graph_transition_rejects(self) -> None:
        graph = (ROOT / "ldso/src/x86_64_general_initial_graph.rs").read_text(encoding="utf-8")
        body = reader.rust_function_body(graph, "unsafe fn run_with_initial_tls")
        changed = body.replace("state.materialize_initial_tls()", "state.materialize_initial_tls();\n        state.materialize_initial_tls()", 1)
        with self.assertRaisesRegex(reader.LoaderStructuralOwnerError, "selected graph duplicates"):
            reader.validate_selected_graph_body(changed)

    def test_commented_or_false_branch_graph_transition_rejects(self) -> None:
        graph = (ROOT / "ldso/src/x86_64_general_initial_graph.rs").read_text(encoding="utf-8")
        body = reader.rust_function_body(graph, "unsafe fn run_with_initial_tls")
        with self.assertRaisesRegex(reader.LoaderStructuralOwnerError, "selected graph omits"):
            reader.validate_selected_graph_body(body.replace(
                "state.plan_initial_tls()", "// state.plan_initial_tls()", 1))
        with self.assertRaisesRegex(reader.LoaderStructuralOwnerError, "unselected false branch"):
            reader.validate_selected_graph_body(body.replace(
                "state.plan_initial_tls()", "if false { state.plan_initial_tls() }", 1))

    def test_ldso_and_libc_feature_spelling_cannot_cross_crates(self) -> None:
        ldso = (ROOT / "ldso/Cargo.toml").read_text(encoding="utf-8")
        libc = (ROOT / "libc/Cargo.toml").read_text(encoding="utf-8")
        with self.assertRaisesRegex(reader.LoaderStructuralOwnerError, "ldso feature route"):
            reader.validate_feature_routes(ldso.replace(
                "x86_64-owned-dynamic-runtime", "x86-owned-dynamic-runtime", 1), libc,
                (ROOT / "ldso/src/x86_64_general_initial_graph.rs").read_text(encoding="utf-8"),
                (ROOT / "libc/src/c_abi/x86_64/static_c_abi.rs").read_text(encoding="utf-8"))

    def test_reviewed_selected_body_preserves_cfg_feature_literals(self) -> None:
        graph = (ROOT / "ldso/src/x86_64_general_initial_graph.rs").read_text(encoding="utf-8")
        body = reader.rust_function_body(graph, "unsafe fn run_with_initial_tls")
        changed = body.replace("x86_64-owned-dynamic-runtime", "x86_64-owned-dynamic-runtimf", 1)
        self.assertEqual(len(changed), len(body))
        with self.assertRaisesRegex(reader.LoaderStructuralOwnerError, "reviewed selected source body differs"):
            reader._reviewed_body("graph_selected", changed)

    def test_build_tls_bridge_and_public_dlfcn_route_mutations_reject(self) -> None:
        build = (ROOT / "ldso/build.rs").read_text(encoding="utf-8")
        before, after = build.rsplit('cargo::rustc-cfg=crabc_dynamic_main_thread_runtime_v1', 1)
        changed_build = before + 'cargo::rustc-cfg=crabc_dynamic_main_thread_runtime_v1_wrong' + after
        with self.assertRaisesRegex(reader.LoaderStructuralOwnerError, "dynamic main interpreter build cfg"):
            reader.validate_build_feature_routes(changed_build)
        dynamic_tls = (ROOT / "libc/src/c_abi/x86_64/dynamic_tls.rs").read_text(encoding="utf-8")
        body = reader.rust_function_body(dynamic_tls, "pub(super) unsafe fn allocate_thread")
        with self.assertRaisesRegex(reader.LoaderStructuralOwnerError, "dynamic TLS allocation bridge"):
            reader.validate_dynamic_tls_bridge(body.replace(
                "__crabc_x86_64_initial_tls_allocate", "__crabc_x86_64_initial_tls_release", 1))
        dlfcn = (ROOT / "libc/src/c_abi/x86_64/general_dlfcn.rs").read_text(encoding="utf-8")
        registry = (ROOT / "ldso/src/x86_64_runtime_registry.rs").read_text(encoding="utf-8")
        with self.assertRaisesRegex(reader.LoaderStructuralOwnerError, "selected dlfcn runtime route"):
            reader.validate_dlfcn_routes(dlfcn.replace(
                "let result = unsafe { __crabc_x86_64_runtime_close(handle) };",
                "let result = unsafe { __crabc_x86_64_runtime_open(handle.cast(), 0, ptr::null_mut()) };", 1), registry)

    def test_lock_bypass_and_changed_registry_target_reject(self) -> None:
        lock = (ROOT / "ldso/src/x86_64_runtime_lock.rs").read_text(encoding="utf-8")
        with self.assertRaisesRegex(reader.LoaderStructuralOwnerError, "RuntimeGuard acquire bypasses"):
            reader.validate_runtime_lock_source(lock.replace("acquire(&LOCK);", "acquire(&CALLBACK_LOCK);", 1))
        registry = (ROOT / "ldso/src/x86_64_runtime_registry.rs").read_text(encoding="utf-8")
        body = reader.rust_function_body(registry, "pub(super) fn runtime_function")
        changed = body.replace("Some(runtime_open as *const ()", "Some(runtime_close as *const ()", 1)
        with self.assertRaisesRegex(reader.LoaderStructuralOwnerError, "registry resolver target"):
            reader.validate_registry_body(changed)


class LoaderStructuralOwnerFactsTests(unittest.TestCase):
    def test_reference_startup_rows_are_finite_without_reclassifying_other_rows(self) -> None:
        rows = []
        for name in ("__dls2b", "__dls3", "_dlstart"):
            for table in (".dynsym", ".symtab"):
                rows.append({"artifact_key": "reference-shared", "table": table, "role": "definition",
                             "row": {"name": name, "type": "FUNC", "binding": "GLOBAL", "visibility": "DEFAULT"}})
        rows.append({"artifact_key": "candidate-shared", "table": ".symtab", "role": "definition",
                     "row": {"name": "unrelated", "type": "FUNC", "binding": "GLOBAL", "visibility": "DEFAULT"}})
        result = reader.project_structural_facts(rows)
        self.assertEqual(result["full_occurrence_count"], 7)
        self.assertEqual(result["unnamed_occurrence_count"], 0)
        self.assertEqual(result["reference_startup_rows"], 6)
        self.assertEqual(result["candidate_rows"], [])
        self.assertEqual(result["named_identity_filter"], list(reader.IDENTITIES))

    def test_actual_raw_fact_report_keeps_the_complete_named_filter_counts(self) -> None:
        report = (ROOT.parent / "runtimev1_descriptor_requirement_order/.work/x86_64/native-abi-elf-facts/"
                  "clean-6b5e146b/report.json")
        if not report.is_file():
            self.skipTest("requires the retained complete 6b5 ELF fact report")
        facts = json.loads(report.read_text(encoding="utf-8"))
        rows = reader._flatten_fact_rows(facts)
        projection = reader.project_structural_facts(rows)
        self.assertEqual(projection["full_occurrence_count"], 30667)
        self.assertEqual(projection["unnamed_occurrence_count"], 1365)
        self.assertEqual(projection["reference_startup_rows"], 6)

    def test_candidate_row_for_a_legacy_registration_name_rejects(self) -> None:
        rows = []
        for name in ("__dls2b", "__dls3", "_dlstart"):
            for table in (".dynsym", ".symtab"):
                rows.append({"artifact_key": "reference-shared", "table": table, "role": "definition",
                             "row": {"name": name, "type": "FUNC", "binding": "GLOBAL", "visibility": "DEFAULT"}})
        rows.append({"artifact_key": "candidate-shared", "table": ".symtab", "role": "definition",
                     "row": {"name": "__ldso_register_dlopen", "type": "FUNC", "binding": "GLOBAL", "visibility": "DEFAULT"}})
        with self.assertRaisesRegex(reader.LoaderStructuralOwnerError, "invented candidate occurrence"):
            reader.project_structural_facts(rows)

    def test_archive_members_are_flattened_without_losing_unnamed_rows(self) -> None:
        facts = {"facts": {
            "candidate-static": [{
                "member": "first.o", "member_index": 0, "member_occurrence": 0,
                "symbol_tables": [{"name": ".symtab", "rows": [
                    {"name": None, "section_index": "UND"},
                    {"name": "ordinary", "section_index": "1"},
                ]}],
            }],
        }}
        rows = reader._flatten_fact_rows(facts)
        self.assertEqual(rows[0]["archive_member"], {
            "member": "first.o", "member_index": 0, "member_occurrence": 0,
        })
        self.assertEqual(sum(row["row"]["name"] is None for row in rows), 1)


class LoaderStructuralOwnerLifecycleTests(unittest.TestCase):
    def test_begin_record_requires_every_preexecution_cohort_join(self) -> None:
        source = {"revision": "r", "tree": "t", "source_sha256": "s"}
        contract = {"schema": "contract", "id": "owner"}
        begin = {"schema": "crabc.x86_64-loader-structural-owner-begin/v1", "image": reader.PINNED_IMAGE,
                 "output": "/workspace/.work/out", "selected_source": source, "collector": source,
                 "contract": contract, "inputs": {"input": 1}, "source_contract": {"source": 2},
                 "source_algorithm": {"algorithm": 3}, "upstream": {"upstream": 4}}
        reader._validate_begin_record(begin, source=source, contract=contract, collector_output=begin["output"],
                                      inputs=begin["inputs"], source_contract=begin["source_contract"],
                                      source_algorithm=begin["source_algorithm"], upstream=begin["upstream"])
        for field in ("selected_source", "collector", "inputs", "source_contract", "source_algorithm", "upstream"):
            changed = dict(begin)
            changed[field] = {"changed": True}
            with self.subTest(field=field), self.assertRaisesRegex(reader.LoaderStructuralOwnerError, "begin admission"):
                reader._validate_begin_record(changed, source=source, contract=contract, collector_output=begin["output"],
                                              inputs=begin["inputs"], source_contract=begin["source_contract"],
                                              source_algorithm=begin["source_algorithm"], upstream=begin["upstream"])


class LoaderStructuralOwnerCommandTests(unittest.TestCase):
    @staticmethod
    def _command_inputs() -> dict[str, dict[str, object]]:
        return {role: {"path": f"/{role}", "sha256": "0", "size": 0, "mode": 0o644,
                       "retained": f"retained/inputs/{role}"}
                for role in reader.INPUT_NAMES}

    def test_selected_link_input_modes_use_role_to_installed_path_mapping(self) -> None:
        inputs = {name: {"mode": 0o644} for name in reader.INPUT_NAMES}
        inputs["static_driver"]["mode"] = 0o755
        inputs["dynamic_driver"]["mode"] = 0o755
        inputs["dynamic_loader"]["mode"] = 0o755
        inputs["dynamic_libc"]["mode"] = 0o755
        reader._validate_input_modes(inputs)
        inputs["dynamic_attach"]["mode"] = 0o600
        with self.assertRaisesRegex(reader.LoaderStructuralOwnerError, "dynamic link-input mode"):
            reader._validate_input_modes(inputs)

    def test_command_record_requires_the_actual_component_output_cwd(self) -> None:
        scratch = ROOT / ".work" / "x86_64" / "tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            output = Path(temporary)
            commands = output / "commands"
            commands.mkdir()
            name = "compile-plugin"
            collector_output = "/workspace/.work/loader-structural-owner/control"
            inputs = self._command_inputs()
            argv = reader._expected_command_argv(name, collector_output, inputs)
            (commands / f"{name}.argv.json").write_text(json.dumps({
                "argv": argv, "cwd": collector_output, "environment": reader.COMMAND_ENVIRONMENT,
                "stdin": "/dev/null",
            }) + "\n", encoding="utf-8")
            (commands / f"{name}.stdout").write_bytes(b"")
            (commands / f"{name}.stderr").write_bytes(b"")
            (commands / f"{name}.status").write_bytes(b"0\n")
            self.assertEqual(reader._read_command(output, name, collector_output=collector_output, inputs=inputs)["argv"]["cwd"], collector_output)
            record = json.loads((commands / f"{name}.argv.json").read_text(encoding="utf-8"))
            record["cwd"] = collector_output + "/different"
            (commands / f"{name}.argv.json").write_text(json.dumps(record) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(reader.LoaderStructuralOwnerError, "command compile-plugin invocation differs"):
                reader._read_command(output, name, collector_output=collector_output, inputs=inputs)

    def test_runtime_command_binds_exact_argv_and_public_transcript(self) -> None:
        scratch = ROOT / ".work" / "x86_64" / "tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            output = Path(temporary)
            commands = output / "commands"
            commands.mkdir()
            name = "startup-entry-public-dlfcn-candidate-dynamic-pie-direct-run"
            collector_output = "/workspace/.work/loader-structural-owner/control"
            inputs = self._command_inputs()
            (commands / f"{name}.argv.json").write_text(json.dumps({
                "argv": reader._expected_command_argv(name, collector_output, inputs),
                "cwd": collector_output, "environment": reader.COMMAND_ENVIRONMENT, "stdin": "/dev/null",
            }) + "\n", encoding="utf-8")
            stdout, stderr = reader._expected_command_streams(name)
            (commands / f"{name}.stdout").write_bytes(stdout)
            (commands / f"{name}.stderr").write_bytes(stderr)
            (commands / f"{name}.status").write_bytes(b"0\n")
            reader._read_command(output, name, collector_output=collector_output, inputs=inputs)
            (commands / f"{name}.stdout").write_bytes(stdout + b"forged\n")
            with self.assertRaisesRegex(reader.LoaderStructuralOwnerError, "command transcript differs"):
                reader._read_command(output, name, collector_output=collector_output, inputs=inputs)

    def test_host_input_replay_uses_retained_image_tools_and_current_checkout_bytes(self) -> None:
        scratch = ROOT / ".work" / "x86_64" / "tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            root, output = Path(temporary) / "checkout", Path(temporary) / "receipt"
            root.mkdir()
            (output / "retained/inputs").mkdir(parents=True)
            paths: dict[str, Path] = {}
            inputs: dict[str, dict[str, object]] = {}
            image_manifest = {"files": {}}
            for name in reader.INPUT_NAMES:
                if name in reader.IMAGE_INPUT_PATHS:
                    source = Path(reader.IMAGE_INPUT_PATHS[name])
                    path = str(source)
                    image_manifest["files"][str(source)] = {
                        "path": f"/physical/{name}", "sha256": hashlib.sha256(name.encode("ascii")).hexdigest(),
                        "size": len(name), "mode": 0o644,
                    }
                elif name == "image_manifest":
                    source = root / reader.IMAGE_MANIFEST_SOURCE
                    source.parent.mkdir(parents=True, exist_ok=True)
                    source.write_text("{}\n", encoding="utf-8")
                    path = str(Path("/workspace") / source.relative_to(root))
                else:
                    source = root / "fixture" / name
                    source.parent.mkdir(parents=True, exist_ok=True)
                    source.write_bytes(name.encode("ascii"))
                    path = str(Path("/workspace") / source.relative_to(root))
                retained = output / "retained/inputs" / name
                retained.write_bytes(name.encode("ascii") if name in reader.IMAGE_INPUT_PATHS else source.read_bytes())
                retained.chmod(0o644)
                inputs[name] = {"path": path, "sha256": reader._sha256(retained), "size": retained.stat().st_size,
                                "mode": 0o644, "retained": f"retained/inputs/{name}"}
                paths[name] = source
            with mock.patch.object(reader, "_trusted_image_manifest", return_value=image_manifest):
                self.assertEqual(reader._validate_inputs(root, output, inputs, **paths), inputs)
                paths["reader"].write_bytes(b"changed")
                with self.assertRaisesRegex(reader.LoaderStructuralOwnerError, "current component input differs: reader"):
                    reader._validate_inputs(root, output, inputs, **paths)

    def test_pinned_runtime_root_binds_musl_retained_identity(self) -> None:
        executable = {"mode": 0o755, "size": 11, "sha256": "exe"}
        plugin = {"mode": 0o644, "size": 12, "sha256": "plugin"}
        musl = {"path": reader.IMAGE_INPUT_PATHS["musl_shared"], "mode": 0o644, "size": 13,
                "sha256": "musl", "retained": "retained/inputs/musl_shared"}
        tree = reader._expected_pinned_tree(executable, plugin, musl)
        self.assertEqual(tree["lib/ld-musl-x86_64.so.1"],
                         {"kind": "regular", "mode": 0o755, "size": 13, "sha256": "musl"})

    def test_image_manifest_alias_uses_its_one_physical_target(self) -> None:
        scratch = ROOT / ".work" / "x86_64" / "tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            directory = Path(temporary)
            target, logical, wrong = directory / "coreutils", directory / "timeout", directory / "other"
            target.write_bytes(b"pinned tool")
            target.chmod(0o755)
            logical.symlink_to(target.name)
            wrong.write_bytes(b"wrong tool")
            wrong.chmod(0o755)
            invocation = str(logical)
            manifest = {"files": {invocation: {
                "path": str(target), "sha256": reader._sha256(target), "size": target.stat().st_size, "mode": 0o755,
            }}}
            with mock.patch.object(reader, "IMAGE_INPUT_PATHS", {"timeout": invocation}):
                physical, expected = reader._image_input_physical(logical, "timeout", manifest)
                self.assertEqual(physical, target)
                self.assertEqual(expected["path"], str(target))
                with self.assertRaisesRegex(reader.LoaderStructuralOwnerError, "invocation target"):
                    reader._image_input_physical(wrong, "timeout", manifest)


if __name__ == "__main__":
    unittest.main()
