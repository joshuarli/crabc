#!/usr/bin/env python3
"""Fail-closed admission policy of the RuntimeV1 native-facade runner."""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "compat/x86_64/runtime_private_facades.py"
SPEC = importlib.util.spec_from_file_location("runtime_private_facades", RUNNER)
assert SPEC is not None and SPEC.loader is not None
facades = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = facades
SPEC.loader.exec_module(facades)


def probe(example: str):
    return next(item for item in facades.PROBES if item.example == example)


def retained(root: Path, relative: str, payload: bytes) -> dict[str, object]:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return facades.artifact_identity(path, root)


class ProbeAdmissionTests(unittest.TestCase):
    def test_roster_keeps_each_frozen_probe_unchanged_and_every_facade_differential(self) -> None:
        frozen = {item.example for item in facades.PROBES if item.same_source_aarch64}
        self.assertEqual(frozen, {"loader_runtime_probe", "runtime_thread_probe", "cfile_direct_probe"})
        for item in facades.PROBES:
            self.assertTrue(item.fixture.is_file(), item.fixture)
            self.assertTrue((ROOT / "crabc-rs/examples" / f"{item.example}.rs").is_file())
            self.assertTrue(set(item.features) <= set(facades.FEATURES) | {"runtime-thread"})
        differentials = {item.features for item in facades.PROBES if not item.same_source_aarch64}
        self.assertEqual(differentials, {("runtime-loader",), ("runtime-thread-alloc",), ("runtime-stdio",)})

    def test_admits_only_the_private_getter_memory_primitives_and_declared_callbacks(self) -> None:
        thread = probe("x86_64_thread_facade_probe")
        facades.admit_probe_symbols(
            thread,
            ["__crabc_runtime_v1", "crabc_x86_64_thread_facade_c_self", "memcpy"],
            sorted(thread.entries | {"crabc_rs_signal_restorer"}),
        )

    def test_rejects_a_missing_private_getter(self) -> None:
        loader = probe("x86_64_loader_facade_probe")
        with self.assertRaisesRegex(facades.EvidenceError, "private runtime getter"):
            facades.admit_probe_symbols(loader, ["memcpy"], sorted(loader.entries))

    def test_rejects_public_c_abi_errno_and_allocator_imports_even_when_declared(self) -> None:
        loader = probe("x86_64_loader_facade_probe")
        declared = facades.Probe(
            loader.example, loader.features, loader.entries, loader.fixture,
            loader.expected_stdout, False, fixture_imports=frozenset({"dlopen"}),
        )
        for name in ("dlopen", "dlerror", "pthread_create", "fmemopen", "__errno_location", "malloc"):
            with self.subTest(name=name), self.assertRaisesRegex(facades.EvidenceError, "public C ABI"):
                facades.admit_probe_symbols(declared, ["__crabc_runtime_v1", name], sorted(loader.entries))

    def test_rejects_undeclared_imports_and_uninternalized_facade_definitions(self) -> None:
        cfile = probe("x86_64_cfile_facade_probe")
        with self.assertRaisesRegex(facades.EvidenceError, "undeclared imports"):
            facades.admit_probe_symbols(cfile, ["__crabc_runtime_v1", "__udivti3"], sorted(cfile.entries))
        with self.assertRaisesRegex(facades.EvidenceError, "internalize"):
            facades.admit_probe_symbols(
                cfile, ["__crabc_runtime_v1"],
                sorted(cfile.entries | {"_ZN8crabc_rs5cfile5CFile11from_memory17h0123456789abcdefE"}),
            )
        with self.assertRaisesRegex(facades.EvidenceError, "lacks probe entries"):
            facades.admit_probe_symbols(cfile, ["__crabc_runtime_v1"], ["crabc_rs_x86_64_cfile_facade_run"])

    def test_selects_exactly_the_fat_lto_member_and_never_builtins(self) -> None:
        members = [
            "x86_64_cfile_facade_probe-0123abcd.x86_64_cfile_facade_probe.4567ef-cgu.0.rcgu.o",
            "compiler_builtins-89ab.compiler_builtins.cdef-cgu.000.rcgu.o",
            "b2f3eb2f094cea5b-absvdi2.o",
        ]
        self.assertEqual(facades.select_lto_member(members, "x86_64_cfile_facade_probe"), members[0])
        with self.assertRaisesRegex(facades.EvidenceError, "exactly one"):
            facades.select_lto_member(members[1:], "x86_64_cfile_facade_probe")
        with self.assertRaisesRegex(facades.EvidenceError, "exactly one"):
            facades.select_lto_member(
                [members[0], members[0].replace("0123abcd", "0123abce")],
                "x86_64_cfile_facade_probe",
            )


class ReceiptBindingTests(unittest.TestCase):
    def test_rejects_the_unsealed_v1_report(self) -> None:
        scratch = ROOT / ".work/runtime-private-facades-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            report = Path(temporary) / "report.json"
            report.write_text(json.dumps({"schema": "crabc.x86_64-runtime-private-facades/v1"}), encoding="utf-8")
            with self.assertRaisesRegex(facades.EvidenceError, "report fields differ"):
                facades.validate_report(report, expected_source={}, dynamic_product=Path(temporary),
                                        dynamic_libc_sha256="0" * 64)

    def test_accepts_exact_current_probe_product_and_execution_rosters(self) -> None:
        source = {'revision': 'a' * 40, 'content_sha256': 'b' * 64, 'clean': True}
        product = {
            'root': '.work/current/dynamic',
            'manifest': {'path': 'share/crabc/manifest.json', 'sha256': 'c' * 64,
                         'size': 1, 'mode': 0o644},
            'libc': {'path': 'usr/lib/libc.so', 'sha256': 'd' * 64,
                     'size': 1, 'mode': 0o755},
        }
        scratch = ROOT / ".work/runtime-private-facades-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            work = Path(temporary)
            probes = {}
            for item in facades.PROBES:
                probes[item.example] = {
                    'features': list(item.features),
                    'object': retained(work, f'objects/{item.example}.o', b'object'),
                    'undefined': [facades.PRIVATE_RUNTIME],
                    'global_definitions': sorted(item.entries),
                    'same_source_aarch64': item.same_source_aarch64,
                }
            dsos = {}
            for item in facades.DSOS:
                dsos[item.name] = {
                    'artifact': retained(work, f'products/{item.name}', item.name.encode()),
                    'object': retained(work, f'objects/{item.name}.o', b'dso object'),
                    'receipt': retained(work, f'products/{item.name}.crabc-link.json', b'dso receipt'),
                }
            executables = {}
            for item in facades.PROBES:
                for mode in ('pie', 'non-pie'):
                    name = f'{item.example}-{mode}'
                    executables[name] = {
                        'artifact': retained(work, f'products/{name}', b'executable'),
                        'objects': [
                            probes[item.example]['object'],
                            retained(work, f'objects/{name}-fixture.o', b'fixture object'),
                        ],
                        'receipt': retained(work, f'products/{name}.crabc-link.json', b'executable receipt'),
                    }
            executions = []
            for item in facades.PROBES:
                for mode in ('pie', 'non-pie'):
                    for entry in ('kernel', 'direct'):
                        label = f'{item.example}-{mode}-{entry}'
                        executions.append({
                            'probe': item.example, 'mode': mode, 'entry': entry, 'status': 0, 'passed': True,
                            'stdout': retained(work, f'raw/{label}.stdout', item.expected_stdout),
                            'stderr': retained(work, f'raw/{label}.stderr', b''),
                            'status_file': retained(work, f'raw/{label}.status', b'0\n'),
                        })
            report = {
                'schema': facades.SCHEMA, 'capability': 'runtime.private-facades',
                'family': 'ldso.dynamic-runtime', 'target': facades.TARGET,
                'toolchain': 'nightly-2026-09-15', 'features': list(facades.FEATURES),
                'normal_dependencies': list(facades.EXPECTED_PACKAGES), 'source': source, 'product': product,
                'probes': probes, 'products': {'dsos': dsos, 'executables': executables},
                'executions': executions, 'family_qualified': False, 'promotion_ready': False,
                'public_support': False, 'limits': list(facades.LIMITS),
            }
            report_path = work / 'report.json'
            report_path.write_text(json.dumps(report), encoding='utf-8')
            with mock.patch.object(facades, 'source_identity', return_value=source), \
                    mock.patch.object(facades, 'product_identity', return_value=product), \
                    mock.patch.object(facades, 'pinned_channel', return_value='nightly-2026-09-15'), \
                    mock.patch.object(facades, 'llvm_tools', return_value={}), \
                    mock.patch.object(
                        facades, 'inspect_probe',
                        side_effect=lambda _tools, item, _obj, _work: copy.deepcopy(probes[item.example]),
                    ), \
                    mock.patch.object(facades.product_evidence, 'validate_multi_object_link') as validate_link, \
                    mock.patch.object(facades.timer_evidence, '_validate_shared_receipt') as validate_dso_receipt, \
                    mock.patch.object(facades.timer_evidence, '_validate_tls_elf'):
                self.assertEqual(facades.validate_report(
                    report_path, expected_source=source, dynamic_product=Path(temporary),
                    dynamic_libc_sha256=product['libc']['sha256'],
                ), report)
                self.assertEqual(validate_link.call_count, len(executables))
                self.assertEqual(validate_dso_receipt.call_count, len(dsos))
                changed = copy.deepcopy(report)
                changed['probes']['x86_64_cfile_facade_probe']['undefined'].append('memcpy')
                report_path.write_text(json.dumps(changed), encoding='utf-8')
                with self.assertRaisesRegex(facades.EvidenceError, 'differ from retained ELF object'):
                    facades.validate_report(
                        report_path, expected_source=source, dynamic_product=Path(temporary),
                        dynamic_libc_sha256=product['libc']['sha256'],
                    )
                changed = copy.deepcopy(report)
                changed['executions'].pop()
                report_path.write_text(json.dumps(changed), encoding='utf-8')
                with self.assertRaisesRegex(facades.EvidenceError, 'execution matrix differs'):
                    facades.validate_report(
                        report_path, expected_source=source, dynamic_product=Path(temporary),
                        dynamic_libc_sha256=product['libc']['sha256'],
                    )

    def test_rechecks_each_retained_artifact_bytes_and_mode(self) -> None:
        scratch = ROOT / ".work/runtime-private-facades-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            root = Path(temporary)
            retained = root / "raw/probe.stdout"
            retained.parent.mkdir()
            retained.write_bytes(b"runtime probe ok\n")
            identity = facades.artifact_identity(retained, root)
            self.assertEqual(facades._artifact_path(root, identity, "probe stdout"), retained)
            retained.chmod(0o600)
            with self.assertRaisesRegex(facades.EvidenceError, "artifact bytes differ"):
                facades._artifact_path(root, identity, "probe stdout")
            retained.chmod(identity["mode"])
            retained.write_bytes(b"changed\n")
            with self.assertRaisesRegex(facades.EvidenceError, "artifact bytes differ"):
                facades._artifact_path(root, identity, "probe stdout")


if __name__ == "__main__":
    unittest.main()
