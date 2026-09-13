"""Focused contracts for the nine private loader-runtime protocol imports."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "compat/x86_64/loader_runtime_registry_evidence.py"
SPEC = importlib.util.spec_from_file_location("loader_runtime_registry_evidence_test", MODULE_PATH)
assert SPEC and SPEC.loader
EVIDENCE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = EVIDENCE
SPEC.loader.exec_module(EVIDENCE)


class LoaderRuntimeRegistryEvidenceTests(unittest.TestCase):
    def test_replay_dlfcn_link_binds_the_retained_linker_and_exact_command(self):
        scratch = ROOT / '.work/x86_64/loader-runtime-registry-tests'; scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            root = Path(temporary)
            output, work, product = root / '.work/report', root / '.work/report/work', root / '.work/product'
            work.mkdir(parents=True); (product / 'usr/lib').mkdir(parents=True)
            manifest = product / 'share/crabc/manifest.json'; manifest.parent.mkdir(parents=True); manifest.write_text('{}\n', encoding='utf-8')
            runtime = product / 'usr/lib'
            for name in ('Scrt1.o', 'crabc-dynamic-attach.o', 'crti.o', 'libc.so', 'libcrabc-builtins.a', 'crtn.o'):
                (runtime / name).write_bytes(name.encode())
            executable = work / 'consumer'; executable.write_bytes(b'linked executable')
            object_path = work / 'crabc-dynamic-link.fixture/source-0.o'; object_path.parent.mkdir(); object_path.write_bytes(b'object')
            tools = {}
            for role, native in EVIDENCE.fork_evidence.REPLAY_TOOL_PATHS.items():
                source = root / (role + '-source'); source.write_bytes(role.encode()); source.chmod(0o755)
                tools[role] = EVIDENCE.inventory._snapshot_regular(output, source, 'inputs/tools/' + role, native)
            replay = EVIDENCE.fork_evidence.RetainedRuntimeInputs(root, output, tools)
            digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
            inputs = [runtime / name for name in ('crti.o', 'libc.so', 'crtn.o', 'Scrt1.o', 'crabc-dynamic-attach.o')]
            inputs += [object_path, runtime / 'libcrabc-builtins.a']
            command = [str(replay.tool_path('linker')), '-pie', '--hash-style=sysv', '-z', 'relro', '-z', 'now',
                       '-z', 'noexecstack', '-z', 'text', '--no-undefined', '--allow-shlib-undefined', '--enable-new-dtags',
                       '-rpath', '/usr/lib', '--dynamic-linker', EVIDENCE.fork_evidence.INTERPRETER,
                       replay.recorded(runtime / 'Scrt1.o'), replay.recorded(runtime / 'crabc-dynamic-attach.o'),
                       replay.recorded(runtime / 'crti.o'), replay.recorded(object_path), replay.recorded(runtime / 'libc.so'),
                       replay.recorded(runtime / 'libcrabc-builtins.a'), replay.recorded(runtime / 'crtn.o'), '-o', replay.recorded(executable)]
            expected_command = list(command)
            receipt = {
                'schema': 2, 'format': EVIDENCE.product_evidence.DYNAMIC_PRODUCT_FORMAT, 'mode': 'pie', 'binding': 'now',
                'runtime_imports': [], 'application_runpath': '/usr/lib', 'application_rpath': None,
                'application_search_kind': 'runpath', 'application_hash_style': 'sysv', 'output_path': replay.recorded(executable),
                'output_sha256': digest(executable), 'manifest_sha256': digest(manifest), 'application_dsos': {},
                'owned_runtime_inputs': sorted(path.relative_to(product).as_posix() for path in [*inputs[:5], inputs[-1]]),
                'input_receipts': [{'path': replay.recorded(path), 'sha256': digest(path)} for path in inputs],
                'resolved_linker': {key: tools['linker']['original'][key] for key in ('path', 'sha256')},
                'link_command': command,
                'link_trace': [replay.recorded(path) for path in (runtime / 'Scrt1.o', runtime / 'crabc-dynamic-attach.o',
                                                                    runtime / 'crti.o', object_path, runtime / 'libc.so', runtime / 'crtn.o')],
                'campaign_complete': False,
            }
            receipt_path = work / 'consumer.crabc-link.json'; receipt_path.write_text(json.dumps(receipt), encoding='utf-8')
            facts = {'type': 3, 'machine': 62, 'interpreters': [EVIDENCE.fork_evidence.INTERPRETER], 'dynamic': True, 'needed': ['libc.so'],
                     'runpaths': ['/usr/lib'], 'rpaths': [], 'sonames': [], 'textrel': False}
            with mock.patch.object(EVIDENCE.product_evidence, 'retained_elf_facts', return_value=facts):
                observed = EVIDENCE._link_record(product, work, output, 'consumer', 'pie', replay=replay)
            self.assertEqual(observed['mode'], 'pie')
            with mock.patch.object(EVIDENCE.product_evidence, 'retained_elf_facts', return_value={**facts, 'textrel': True}):
                with self.assertRaisesRegex(EVIDENCE.RuntimeRegistryEvidenceError, 'ELF shape'):
                    EVIDENCE._link_record(product, work, output, 'consumer', 'pie', replay=replay)
            receipt['link_command'][-1] = '/workspace/changed-output'
            receipt_path.write_text(json.dumps(receipt), encoding='utf-8')
            with mock.patch.object(EVIDENCE.product_evidence, 'retained_elf_facts', return_value=facts):
                with self.assertRaisesRegex(EVIDENCE.RuntimeRegistryEvidenceError, 'link command'):
                    EVIDENCE._link_record(product, work, output, 'consumer', 'pie', replay=replay)
            receipt['link_command'] = expected_command
            receipt['resolved_linker'] = {'path': '/foreign/ld.lld', 'sha256': tools['linker']['original']['sha256']}
            receipt_path.write_text(json.dumps(receipt), encoding='utf-8')
            with mock.patch.object(EVIDENCE.product_evidence, 'retained_elf_facts', return_value=facts):
                with self.assertRaisesRegex(EVIDENCE.fork_evidence.EvidenceError, 'retained tool identity'):
                    EVIDENCE._link_record(product, work, output, 'consumer', 'pie', replay=replay)

    def test_supplied_identity_projects_only_the_exact_physical_checkout_mount(self):
        scratch=ROOT/'.work/x86_64/loader-runtime-registry-tests';scratch.mkdir(parents=True,exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            parent=Path(temporary);root=parent/'checkout';root.mkdir()
            path=root/'.work/facts.json';path.parent.mkdir();path.write_bytes(b'facts')
            physical=EVIDENCE.identity(path)
            retained=EVIDENCE.checkout_identity(root,path)
            self.assertEqual(retained,{**physical,'path':'/workspace/.work/facts.json'})
            outside=parent/'outside';outside.write_bytes(b'facts')
            link=root/'alias';link.symlink_to(path)
            for bad in (outside,link,root/'../outside'):
                with self.assertRaises(EVIDENCE.RuntimeRegistryEvidenceError):
                    EVIDENCE.retained_checkout_path(root,bad)

    def test_runner_contract_preserves_native_argv_and_tmpdir_during_host_replay(self):
        scratch=ROOT/'.work/x86_64/loader-runtime-registry-tests';scratch.mkdir(parents=True,exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            root=Path(temporary);script=root/'compat/x86_64/run_general_dynamic_dlopen.sh'
            script.parent.mkdir(parents=True);script.write_bytes(b'fixture')
            product=root/'.work/product';output=root/'.work/receipt'
            product.mkdir(parents=True);output.mkdir()
            with mock.patch.object(EVIDENCE,'ROOT',root):
                command,environment=EVIDENCE.runner_contract(output,product,'dlfcn-pie')
            self.assertEqual(command,['bash','/workspace/compat/x86_64/run_general_dynamic_dlopen.sh','/workspace/.work/product'])
            self.assertEqual(environment,{**EVIDENCE.WORKLOAD_ENVIRONMENT,'TMPDIR':'/workspace/.work/receipt',
                'CRABC_GENERAL_DYNAMIC_ENTRY_MODE':'--dynamic-pie',EVIDENCE.DLFCN_SKIP_SEARCH_ENV:'1'})

    def test_replay_files_retain_every_fork_and_timer_preprocessing_input(self):
        scratch = ROOT / '.work/x86_64/loader-runtime-registry-tests'; scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            root = Path(temporary)
            output = root / 'report'
            output.mkdir()
            fork, timer = output / 'fork', output / 'timer'
            for directory in (fork / 'dependencies', fork / 'preprocessed', timer):
                directory.mkdir(parents=True, exist_ok=True)
            identifiers = [name for name, *_ in EVIDENCE.fork_evidence.DSO_TOPOLOGY]
            identifiers += [role for role, *_ in EVIDENCE.fork_evidence.CONSUMER_ROLES]
            for identifier in identifiers:
                (fork / 'dependencies' / f'{identifier}.d').write_text('target: input\n', encoding='utf-8')
                (fork / 'preprocessed' / f'{identifier}.i').write_text(identifier + '\n', encoding='utf-8')
            for stem in ('probe.compile-audit', 'tls.compile-audit'):
                (timer / f'{stem}.dependencies').write_text('target: input\n', encoding='utf-8')
                (timer / f'{stem}.headers').write_text('', encoding='utf-8')
                (timer / f'{stem}.exit-status').write_bytes(b'0\n')
            records = EVIDENCE.replay_files(output, fork, timer)
            self.assertEqual(len(records), 16)
            self.assertEqual(records['fork/preprocessed/initial.i']['path'], 'fork/preprocessed/initial.i')
            self.assertEqual(records['timer/probe.compile-audit.exit-status']['path'],
                             'timer/probe.compile-audit.exit-status')
            (timer / 'tls.compile-audit.exit-status').write_bytes(b'1\n')
            with self.assertRaisesRegex(EVIDENCE.RuntimeRegistryEvidenceError, 'preprocessing status'):
                EVIDENCE.replay_files(output, fork, timer)
            outside = root / 'outside-replay-work'; outside.mkdir()
            with self.assertRaisesRegex(EVIDENCE.RuntimeRegistryEvidenceError, 'escapes report root'):
                EVIDENCE.replay_files(output, outside, timer)

    def contract(self):
        return copy.deepcopy(EVIDENCE.load_contract(ROOT))

    def facts(self):
        rows = []
        for index, name in enumerate(EVIDENCE.RESOLVERS, start=1):
            row = {"name": name, "raw_name": name, "row_index": index,
                   "type": "NOTYPE", "binding": "GLOBAL", "visibility": "DEFAULT",
                   "section_index": "UND", "version": None, "version_default": False,
                   "size_bytes": 0, "value": "0000000000000000"}
            rows.append(row)
        return {
            "artifacts": {"candidate-shared": {}, "candidate-loader": {}},
            "facts": {
                "candidate-shared": {"symbol_tables": [
                    {"name": ".dynsym", "rows": copy.deepcopy(rows)},
                    {"name": ".symtab", "rows": copy.deepcopy(rows)},
                ]},
                "candidate-loader": {"symbol_tables": [{"name": ".dynsym", "rows": []}]},
            },
        }

    def test_contract_and_live_source_are_an_exact_closed_resolver(self):
        contract = self.contract()
        self.assertEqual({row["name"]: row["resolver"] for row in contract["operation"]}, EVIDENCE.RESOLVERS)
        resolution = EVIDENCE.source_resolution(ROOT)
        self.assertEqual(resolution["resolvers"], dict(sorted(EVIDENCE.RESOLVERS.items())))
        self.assertEqual(resolution["feature"], EVIDENCE.FEATURE)

    def test_non_pie_workload_label_requires_the_owned_driver_exec_receipt(self):
        self.assertEqual(EVIDENCE.DLOPEN_DRIVER_MODES, {"pie": "pie", "non-pie": "exec"})
        self.assertEqual(EVIDENCE.single_driver_mode({"exec"}), "exec")
        with self.assertRaisesRegex(EVIDENCE.RuntimeRegistryEvidenceError, "mode roster"):
            EVIDENCE.single_driver_mode({"pie", "exec"})

    def test_workload_environment_retains_the_existing_chroot_and_rust_paths(self):
        self.assertIn("/usr/sbin", EVIDENCE.WORKLOAD_ENVIRONMENT["PATH"].split(":"))
        self.assertIn("/opt/cargo/bin", EVIDENCE.WORKLOAD_ENVIRONMENT["PATH"].split(":"))
        self.assertEqual(EVIDENCE.WORKLOAD_ENVIRONMENT["RUSTUP_HOME"], "/opt/rustup")

    def test_bounded_dlfcn_capture_explicitly_excludes_the_separate_proc_mount_search_leaf(self):
        self.assertEqual(EVIDENCE.DLFCN_SKIP_SEARCH_ENV, "CRABC_GENERAL_DYNAMIC_DLOPEN_SKIP_SEARCH")
        runner = (ROOT / "compat/x86_64/run_general_dynamic_dlopen.sh").read_text(encoding="utf-8")
        self.assertIn(EVIDENCE.DLFCN_SKIP_SEARCH_ENV, runner)

    def test_growth_projection_requires_the_41_module_line_and_exact_oracle_stream(self):
        stream = EVIDENCE.EXPECTED_GROWTH + b"runtime fini 40\n"
        EVIDENCE.validate_growth_output(stream, stream)
        with self.assertRaisesRegex(EVIDENCE.RuntimeRegistryEvidenceError, "41-module"):
            EVIDENCE.validate_growth_output(b"different\n", b"different\n")
        with self.assertRaisesRegex(EVIDENCE.RuntimeRegistryEvidenceError, "differential"):
            EVIDENCE.validate_growth_output(stream, EVIDENCE.EXPECTED_GROWTH)

    def test_contract_rejects_ambiguous_unknown_and_promoting_operation(self):
        contract = self.contract()
        contract["operation"].append({"name": "__crabc_x86_64_runtime_unknown", "resolver": "unknown",
                                      "consumer": "general_dlfcn", "scenario": "runtime-tls-41-modules"})
        with self.assertRaisesRegex(EVIDENCE.RuntimeRegistryEvidenceError, "operation roster"):
            EVIDENCE.validate_contract(contract)
        contract = self.contract()
        contract["operation"][0]["scenario"] = "inferred-from-runner"
        with self.assertRaisesRegex(EVIDENCE.RuntimeRegistryEvidenceError, "scenario"):
            EVIDENCE.validate_contract(contract)
        contract = self.contract()
        contract["limits"]["public_provider"] = True
        with self.assertRaisesRegex(EVIDENCE.RuntimeRegistryEvidenceError, "nonpromotion"):
            EVIDENCE.validate_contract(contract)

    def test_import_placement_requires_one_undefined_row_in_each_named_shared_table(self):
        placement = EVIDENCE.import_placement(self.facts())
        self.assertEqual(set(placement), set(EVIDENCE.RESOLVERS))
        self.assertTrue(all(set(row) == set(EVIDENCE.SYMBOL_TABLES) for row in placement.values()))
        self.assertTrue(all(row[".dynsym"]["section_index"] == "UND" for row in placement.values()))
        malformed = self.facts()
        malformed["facts"]["candidate-shared"]["symbol_tables"][0]["rows"][0]["visibility"] = "HIDDEN"
        with self.assertRaisesRegex(EVIDENCE.RuntimeRegistryEvidenceError, "metadata"):
            EVIDENCE.import_placement(malformed)
        malformed = self.facts()
        dynsym, symtab = malformed["facts"]["candidate-shared"]["symbol_tables"]
        dynsym["rows"].extend(copy.deepcopy(symtab["rows"]))
        symtab["rows"].clear()
        with self.assertRaisesRegex(EVIDENCE.RuntimeRegistryEvidenceError, "each named symbol table"):
            EVIDENCE.import_placement(malformed)
        malformed = self.facts()
        malformed["facts"]["candidate-loader"]["symbol_tables"][0]["rows"].append(
            copy.deepcopy(malformed["facts"]["candidate-shared"]["symbol_tables"][0]["rows"][0])
        )
        with self.assertRaisesRegex(EVIDENCE.RuntimeRegistryEvidenceError, "candidate loader"):
            EVIDENCE.import_placement(malformed)

    def test_dlfcn_stream_projection_reopens_all_runner_oracle_pairs(self):
        scratch = ROOT / ".work/x86_64/loader-runtime-registry-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            output = Path(temporary)
            work = output / "work"
            work.mkdir()
            streams = {
                "consumer.stdout": EVIDENCE.EXPECTED_DLOPEN,
                "tbss-candidate.stdout": EVIDENCE.EXPECTED_TBSS,
                "tbss-oracle.stdout": EVIDENCE.EXPECTED_TBSS,
                "growth.stdout": EVIDENCE.EXPECTED_GROWTH,
                "oracle.stdout": EVIDENCE.EXPECTED_GROWTH,
                "scope.stdout": b"scope=first\n",
                "oracle-scope.stdout": b"scope=first\n",
                "failure-ie.stdout": b"failure=ie\n",
                "oracle-failure-ie.stdout": b"failure=ie\n",
                "failure-unresolved.stdout": b"failure=unresolved\n",
                "oracle-failure-unresolved.stdout": b"failure=unresolved\n",
                "failure-array-half.stdout": b"failure=array-half\n",
                "failure-tls-filesz.stdout": b"failure=tls-filesz\n",
                "failure-relocation-kind.stdout": b"failure=relocation-kind\n",
            }
            for name, contents in streams.items():
                (work / name).write_bytes(contents)
            observed = EVIDENCE._dlfcn_streams(work, output)
            self.assertEqual(set(observed), set(streams))
            for name, altered, message in (
                ("tbss-oracle.stdout", b"wrong\n", "TBSS differential"),
                ("oracle-scope.stdout", b"wrong\n", "scope differential"),
                ("oracle-failure-ie.stdout", b"wrong\n", "failure ie differential"),
            ):
                (work / name).write_bytes(altered)
                with self.assertRaisesRegex(EVIDENCE.RuntimeRegistryEvidenceError, message):
                    EVIDENCE._dlfcn_streams(work, output)
                (work / name).write_bytes(streams[name])
            (work / "oracle-failure-unresolved.stdout").unlink()
            with self.assertRaisesRegex(EVIDENCE.RuntimeRegistryEvidenceError, "oracle-failure-unresolved"):
                EVIDENCE._dlfcn_streams(work, output)

    def test_timer_source_test_roster_and_oracle_capture_are_reopened(self):
        scratch = ROOT / ".work/x86_64/loader-runtime-registry-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            output = Path(temporary)
            work = output / "work"
            work.mkdir()
            executable = work / "tls-reset-tests"
            executable.write_bytes(b"source-test")
            executable.chmod(0o755)
            for stem in ("tls-reset-build.stdout", "tls-reset-tests.stdout", "tls-import-tests.stdout"):
                (work / stem).write_bytes(b"ok\n")
                (work / f"{stem}.stderr").write_bytes(b"")
                (work / f"{stem}.status").write_bytes(b"0\n")
            source_tests = EVIDENCE.timer_source_test_observations(work, output)
            self.assertEqual(set(source_tests), {"executable", "build", "timer_reset", "import_shape"})
            (work / "tls-import-tests.stdout.stderr").unlink()
            with self.assertRaisesRegex(EVIDENCE.RuntimeRegistryEvidenceError, "import_shape stderr"):
                EVIDENCE.timer_source_test_observations(work, output)
            with self.assertRaisesRegex(EVIDENCE.RuntimeRegistryEvidenceError, "kernel execution differs"):
                EVIDENCE.validate_timer_oracle_capture((b"same\n", b"", b"0\n"), (b"same\n", b"different\n", b"0\n"), "kernel")

    def test_source_and_relocation_contract_reject_python_bool_lookalikes(self):
        source = {"revision": "a" * 40, "content_sha256": "b" * 64, "clean": True}
        with mock.patch.object(EVIDENCE.inventory, "collector_source_seal", return_value=copy.deepcopy(source)):
            EVIDENCE.validate_current_source(source)
            source["clean"] = 1
            with self.assertRaisesRegex(EVIDENCE.RuntimeRegistryEvidenceError, "collector source"):
                EVIDENCE.validate_current_source(source)
        contract = self.contract()
        contract["relocation"]["addend"] = False
        with self.assertRaisesRegex(EVIDENCE.RuntimeRegistryEvidenceError, "relocation contract"):
            EVIDENCE.validate_contract(contract)

    def test_collect_rejects_a_fresh_output_inside_a_supplied_product_before_reading_inputs(self):
        scratch = ROOT / ".work/x86_64/loader-runtime-registry-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            root = Path(temporary)
            dynamic = root / "dynamic-product"
            static = root / "static-product"
            cohort = root / "static-preparation"
            for directory in (dynamic, static, cohort):
                directory.mkdir()
            preparation = cohort / "preparation.json"
            preparation.write_text("{}\n", encoding="utf-8")
            output = dynamic / "must-not-exist"
            with mock.patch.object(EVIDENCE, "validate_supplied_products", side_effect=AssertionError("input reader ran")):
                with self.assertRaisesRegex(EVIDENCE.RuntimeRegistryEvidenceError, "overlaps supplied dynamic product"):
                    EVIDENCE.collect(base_inventory=root / "inventory.json", elf_report=root / "facts.json",
                                     static_preparation=preparation, static_product=static, dynamic_product=dynamic,
                                     output=output)
            self.assertFalse(output.exists())

    def test_raw_command_replay_requires_its_authoritative_streams_and_terminal_zero(self):
        scratch = ROOT / ".work/x86_64/loader-runtime-registry-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            output = Path(temporary)
            raw = output / "raw"
            raw.mkdir()
            for suffix, contents in (("stdout", b"ok\n"), ("stderr", b""), ("status", b"0\n")):
                (raw / f"dlfcn-pie.{suffix}").write_bytes(contents)
            command = ["bash", "/fixture/run_general_dynamic_dlopen.sh", "/fixture/product"]
            environment = {"PATH": "/fixture/bin"}
            record = {"argv": command, "environment": environment,
                      **{suffix: EVIDENCE.identity(raw / f"dlfcn-pie.{suffix}", logical_path=f"raw/dlfcn-pie.{suffix}")
                         for suffix in ("stdout", "stderr", "status")}}
            EVIDENCE._validate_command(output, record, "dlfcn-pie", command, environment)
            changed = copy.deepcopy(record)
            changed["environment"] = {"PATH": "/usr/bin:/bin"}
            with self.assertRaisesRegex(EVIDENCE.RuntimeRegistryEvidenceError, "environment drifted"):
                EVIDENCE._validate_command(output, changed, "dlfcn-pie", command, environment)
            changed = copy.deepcopy(record)
            changed["stdout"]["path"] = "raw/unrelated.stdout"
            with self.assertRaisesRegex(EVIDENCE.RuntimeRegistryEvidenceError, "path drifted"):
                EVIDENCE._validate_command(output, changed, "dlfcn-pie", command, environment)
            (raw / "dlfcn-pie.status").write_bytes(b"1\n")
            changed["stdout"] = EVIDENCE.identity(raw / "dlfcn-pie.stdout", logical_path="raw/dlfcn-pie.stdout")
            changed["status"] = EVIDENCE.identity(raw / "dlfcn-pie.status", logical_path="raw/dlfcn-pie.status")
            with self.assertRaisesRegex(EVIDENCE.RuntimeRegistryEvidenceError, "did not succeed"):
                EVIDENCE._validate_command(output, changed, "dlfcn-pie", command, environment)

    def test_fork_reader_extension_is_a_replay_command_not_a_second_runner(self):
        source = (ROOT / "compat/x86_64/owned_dynamic_fork_evidence.py").read_text(encoding="utf-8")
        self.assertIn("def validate_observations(product: Path, work: Path, *, replay: RetainedRuntimeInputs | None = None)", source)
        self.assertIn("replay is None else preprocessed_path.read_bytes()", source)
        self.assertIn("record = receipt_record(Path(str(output) + \".crabc-link.json\"))", source)
        self.assertIn("fork observation receipt does not reconstruct", source)
        self.assertIn('"validate-observations"', source)

    def test_cli_rejects_abbreviation_and_requires_both_runtime_product_inputs(self):
        with self.assertRaises(SystemExit):
            EVIDENCE.main(["collect", "--dynamic-prod", "x"])
        with self.assertRaises(SystemExit):
            EVIDENCE.main(["validate-report"])


if __name__ == "__main__":
    unittest.main()
