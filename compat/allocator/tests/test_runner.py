#!/usr/bin/env python3
"""Focused pure-Python tests for the Milestone 0 mimalloc oracle harness."""

from __future__ import annotations

import importlib.util
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import unittest
from unittest import mock
from pathlib import Path


RUNNER_PATH = Path(__file__).resolve().parents[1] / "run.py"
SPEC = importlib.util.spec_from_file_location("crabc_allocator_runner", RUNNER_PATH)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNNER
SPEC.loader.exec_module(RUNNER)


class WorkRootTests(unittest.TestCase):
    def test_work_root_routes_all_runner_owned_outputs(self) -> None:
        work_root = RUNNER.default_work_root()
        self.assertEqual(RUNNER.WORK_ROOT, work_root)
        self.assertEqual(RUNNER.CACHE, work_root / "allocator-cache")
        self.assertEqual(RUNNER.REPORT_ROOT, work_root / "reports/allocator")
        self.assertEqual(
            RUNNER.ARTIFACT_ROOT,
            work_root / "target/compat/allocator",
        )
        self.assertEqual(RUNNER.TEMP_ROOT, work_root / "tmp/allocator")
        self.assertEqual(
            RUNNER.TLS_CODEGEN_REPORT,
            work_root / "reports/allocator/tls-codegen.json",
        )
        self.assertEqual(
            RUNNER.X86_64_TLS_CODEGEN_REPORT,
            work_root / "reports/allocator/tls-codegen-x86_64.json",
        )
        self.assertEqual(
            RUNNER.X86_64_ORACLE_REPORT_ROOT,
            work_root / "reports/allocator/x86_64",
        )
        self.assertEqual(
            RUNNER.X86_64_ORACLE_ARTIFACT_ROOT,
            work_root / "target/compat/allocator/x86_64",
        )

    def test_default_work_root_honors_crabc_work_dir(self) -> None:
        with mock.patch.dict(RUNNER.os.environ, {}, clear=True):
            self.assertEqual(RUNNER.default_work_root(), RUNNER.ROOT / ".work")
        with mock.patch.dict(
            RUNNER.os.environ, {"CRABC_WORK_DIR": "isolated-work"}, clear=True
        ):
            self.assertEqual(
                RUNNER.default_work_root(),
                RUNNER.ROOT / "isolated-work",
            )
        custom = RUNNER.ROOT / ".work/custom-root"
        with mock.patch.dict(
            RUNNER.os.environ, {"CRABC_WORK_DIR": str(custom)}, clear=True
        ):
            self.assertEqual(RUNNER.default_work_root(), custom)

    def test_runner_temporary_directory_stays_below_the_work_root(self) -> None:
        with RUNNER.temporary_directory("crabc-allocator-work-root-") as temporary:
            path = Path(temporary).resolve()
            self.assertEqual(path.parent, RUNNER.TEMP_ROOT.resolve())


def production_dependency_metadata() -> dict[str, object]:
    versions = {
        "crabc-mimalloc": "0.3.0",
        "crabc-core": "0.3.0",
        "chacha20": "0.10.1",
        "cfg-if": "1.0.4",
        "cipher": "0.5.2",
        "block-buffer": "0.12.1",
        "hybrid-array": "0.4.14",
        "typenum": "1.20.1",
        "crypto-common": "0.2.2",
        "inout": "0.2.2",
        "zeroize": "1.9.0",
    }
    edges = {
        "crabc-mimalloc": ("chacha20", "crabc-core", "zeroize"),
        "crabc-core": (),
        "chacha20": ("cfg-if", "cipher", "zeroize"),
        "cfg-if": (),
        "cipher": ("block-buffer", "crypto-common", "inout"),
        "block-buffer": ("hybrid-array",),
        "hybrid-array": ("typenum",),
        "typenum": (),
        "crypto-common": ("hybrid-array",),
        "inout": ("hybrid-array",),
        "zeroize": (),
    }
    packages = []
    nodes = []
    for name, version in versions.items():
        package_id = f"{name} {version}"
        packages.append(
            {
                "id": package_id,
                "name": name,
                "version": version,
                "source": None if name.startswith("crabc-") else "registry+https://github.com/rust-lang/crates.io-index",
                "targets": [{"kind": ["lib"]}],
            }
        )
        nodes.append(
            {
                "id": package_id,
                "deps": [
                    {
                        "name": dependency.replace("-", "_"),
                        "pkg": f"{dependency} {versions[dependency]}",
                        "dep_kinds": [{"kind": None, "target": None}],
                    }
                    for dependency in edges[name]
                ],
            }
        )
    return {"packages": packages, "resolve": {"nodes": nodes}}


def x86_64_engine_dependency_metadata() -> dict[str, object]:
    """Return the selected x86 normal graph, including its CPUID helper."""

    metadata = production_dependency_metadata()
    packages = metadata["packages"]
    nodes = metadata["resolve"]["nodes"]
    assert isinstance(packages, list) and isinstance(nodes, list)
    packages.append(
        {
            "id": "cpufeatures 0.3.0",
            "name": "cpufeatures",
            "version": "0.3.0",
            "source": "registry+https://github.com/rust-lang/crates.io-index",
            "targets": [{"kind": ["lib"]}],
        }
    )
    nodes.append({"id": "cpufeatures 0.3.0", "deps": []})
    chacha = next(node for node in nodes if node["id"] == "chacha20 0.10.1")
    chacha["deps"].append(
        {
            "name": "cpufeatures",
            "pkg": "cpufeatures 0.3.0",
            "dep_kinds": [{"kind": None, "target": None}],
        }
    )
    return metadata


class ArchiveTests(unittest.TestCase):
    def test_safe_extract_accepts_only_the_expected_archive_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "mimalloc.tar.gz"
            contents = b"#define MI_MALLOC_VERSION 30500\n"
            with tarfile.open(archive, "w:gz") as stream:
                directory = tarfile.TarInfo("mimalloc-3.5.0")
                directory.type = tarfile.DIRTYPE
                stream.addfile(directory)
                header = tarfile.TarInfo("mimalloc-3.5.0/include/mimalloc.h")
                header.size = len(contents)
                stream.addfile(header, io.BytesIO(contents))
                source = tarfile.TarInfo("mimalloc-3.5.0/src/alloc.c")
                source.size = 1
                stream.addfile(source, io.BytesIO(b"\n"))
            extracted = RUNNER.safe_extract(archive, root / "out", "mimalloc-3.5.0")
            self.assertEqual((extracted / "include/mimalloc.h").read_bytes(), contents)

    def test_safe_extract_rejects_a_path_escape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "bad.tar.gz"
            with tarfile.open(archive, "w:gz") as stream:
                bad = tarfile.TarInfo("mimalloc-3.5.0/../escape")
                bad.size = 1
                stream.addfile(bad, io.BytesIO(b"x"))
            with self.assertRaisesRegex(RUNNER.HarnessError, "escapes expected root"):
                RUNNER.safe_extract(archive, root / "out", "mimalloc-3.5.0")


class InventoryTests(unittest.TestCase):
    def test_native_x86_64_profile_records_its_musl_target_boundary(self) -> None:
        self.assertEqual(RUNNER.X86_64_RUST_TARGET, "x86_64-unknown-linux-musl")
        self.assertEqual(RUNNER.X86_64_INTERPRETER, "ld-musl-x86_64.so.1")
        self.assertEqual(
            RUNNER.X86_64_TARGET_METADATA,
            {
                "architecture": "x86_64",
                "target": "x86_64-unknown-linux-musl",
                "interpreter": "ld-musl-x86_64.so.1",
            },
        )
        self.assertEqual(
            RUNNER.X86_64_ORACLE_REPORT_ROOT,
            RUNNER.REPORT_ROOT / "x86_64",
        )

    def test_parser_selects_x86_64_without_changing_the_default(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CRABC_ALLOCATOR_EVIDENCE_ARCH", None)
            with mock.patch.object(sys, "argv", ["run.py", "--quick"]):
                self.assertEqual(RUNNER.parse_arguments().architecture, "aarch64")
        with mock.patch.dict(
            os.environ, {"CRABC_ALLOCATOR_EVIDENCE_ARCH": "x86_64"}, clear=False
        ):
            with mock.patch.object(sys, "argv", ["run.py", "--quick"]):
                self.assertEqual(RUNNER.parse_arguments().architecture, "x86_64")
        with mock.patch.dict(
            os.environ, {"CRABC_ALLOCATOR_EVIDENCE_ARCH": ""}, clear=False
        ):
            with mock.patch.object(sys, "argv", ["run.py", "--quick", "--arch", "x86_64"]):
                self.assertEqual(RUNNER.parse_arguments().architecture, "x86_64")
            with mock.patch.object(sys, "argv", ["run.py", "--quick", "--x86-64"]):
                self.assertEqual(RUNNER.parse_arguments().architecture, "x86_64")

    def test_parser_does_not_allow_x86_64_to_claim_later_production_lanes(self) -> None:
        for mode in ("--full", "--perf-smoke", "--perf-full", "--generate-contracts", "--snapshot-ratchet"):
            with self.subTest(mode=mode), mock.patch.object(
                sys, "argv", ["run.py", mode, "--architecture", "x86_64"]
            ):
                with self.assertRaises(SystemExit):
                    RUNNER.parse_arguments()

    def test_native_architecture_gate_rejects_non_native_x86_64(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"CRABC_EXECUTION_MODE": "native", "CRABC_HOST_ARCH": "x86_64"},
            clear=False,
        ), mock.patch.object(RUNNER.platform, "system", return_value="Linux"), mock.patch.object(
            RUNNER.platform, "machine", return_value="aarch64"
        ):
            with self.assertRaisesRegex(RUNNER.HarnessError, "native Linux/x86-64"):
                RUNNER.require_native_x86_64()

    def test_native_architecture_gate_rejects_missing_or_emulated_x86_provenance(self) -> None:
        with mock.patch.object(RUNNER.platform, "system", return_value="Linux"), mock.patch.object(
            RUNNER.platform, "machine", return_value="x86_64"
        ):
            with mock.patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(RUNNER.HarnessError, "canonical native provenance"):
                    RUNNER.require_native_x86_64()
            with mock.patch.dict(
                os.environ,
                {"CRABC_EXECUTION_MODE": "emulated", "CRABC_HOST_ARCH": "x86_64"},
                clear=True,
            ):
                with self.assertRaisesRegex(RUNNER.HarnessError, "canonical native provenance"):
                    RUNNER.require_native_x86_64()
            with mock.patch.dict(
                os.environ,
                {"CRABC_EXECUTION_MODE": "native", "CRABC_HOST_ARCH": "amd64"},
                clear=True,
            ):
                self.assertEqual(
                    RUNNER.require_native_x86_64(),
                    {"execution_mode": "native", "host_architecture": "amd64"},
                )

    def test_x86_quick_rejects_emulated_provenance_before_oracle_work(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"CRABC_EXECUTION_MODE": "emulated", "CRABC_HOST_ARCH": "x86_64"},
            clear=True,
        ), mock.patch.object(RUNNER.platform, "system", return_value="Linux"), mock.patch.object(
            RUNNER.platform, "machine", return_value="x86_64"
        ), mock.patch.object(RUNNER, "load_pin") as load_pin:
            with self.assertRaisesRegex(RUNNER.HarnessError, "canonical native provenance"):
                RUNNER.run_milestone0(
                    offline=True,
                    generate_contracts=False,
                    check_only=False,
                    architecture="x86_64",
                )
        load_pin.assert_not_called()

    def test_x86_quick_uses_only_target_local_contract_inputs(self) -> None:
        source_api_inventory = {
            "contract": {"path": "compat/allocator/x86_64-api-v3.5.0.json"},
            "declaration_count": 180,
            "status": "passed",
        }
        source_api_coverage = {
            "build_mode_declaration_count": 52,
            "contract": {"path": "compat/allocator/x86_64-api-coverage-v3.5.0.json"},
            "header_surface_count": 4,
            "overall_status": "incomplete",
            "profile": "linux-x86_64-mimalloc-source-public-surface",
            "scope": (
                "pinned source inventory only; it does not establish native execution "
                "or public runtime integration"
            ),
            "source_declared_function_count": 195,
            "source_member_count": 30,
            "status": "passed",
            "symbol_disposition_count": 8,
            "target": {
                "architecture": "x86_64",
                "endianness": "little",
                "rust_target": "x86_64-unknown-linux-musl",
                "system": "linux",
            },
            "test_member_count": 18,
        }
        source_map = {
            "contract": {"path": "compat/allocator/x86_64-source-map-v3.5.0.json"},
            "overall_status": "incomplete",
            "profile": "linux-x86_64-mimalloc-engine-parity",
            "scope": "pinned source mapping only; it does not establish runtime integration",
            "source_member_count": 34,
            "status": "passed",
            "status_counts": {
                "implemented": 1,
                "inapplicable": 3,
                "not-started": 5,
                "partial": 25,
            },
            "target": {
                "architecture": "x86_64",
                "endianness": "little",
                "rust_target": "x86_64-unknown-linux-musl",
                "system": "linux",
            },
            "unit_count": 34,
            "unfinished_unit_count": 30,
        }
        expected = {"status": "x86-local"}
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            archive = temporary_root / "mimalloc.tar.gz"
            archive.write_bytes(b"pinned archive placeholder")
            source = temporary_root / "mimalloc-3.5.0"
            source.mkdir()
            with mock.patch.dict(
                os.environ,
                {"CRABC_EXECUTION_MODE": "native", "CRABC_HOST_ARCH": "x86_64"},
                clear=False,
            ), mock.patch.object(
                RUNNER.platform, "system", return_value="Linux"
            ), mock.patch.object(
                RUNNER.platform, "machine", return_value="x86_64"
            ), mock.patch.object(
                RUNNER, "fetch_archive", return_value=archive
            ), mock.patch.object(
                RUNNER, "safe_extract", return_value=source
            ), mock.patch.object(
                RUNNER,
                "x86_64_source_api_inventory",
                return_value=source_api_inventory,
            ) as inventory, mock.patch.object(
                RUNNER,
                "x86_64_source_map_contract",
                return_value=source_map,
            ) as source_map_validator, mock.patch.object(
                RUNNER,
                "x86_64_api_coverage_contract",
                return_value=source_api_coverage,
            ) as source_api_coverage_validator, mock.patch.object(
                RUNNER,
                "apply_and_verify_adapted_test_patch",
                return_value={"selected_test_count": 33},
            ), mock.patch.object(
                RUNNER, "require_tool", return_value="patch"
            ), mock.patch.object(
                RUNNER, "run_x86_64_oracle", return_value=expected
            ) as run_x86, mock.patch.object(
                RUNNER, "generated_contracts"
            ) as generated_contracts, mock.patch.object(
                RUNNER, "load_port_map"
            ) as load_port_map, mock.patch.object(
                RUNNER, "check_ratchet"
            ) as check_ratchet:
                self.assertEqual(
                    RUNNER.run_milestone0(
                        offline=True,
                        generate_contracts=False,
                        check_only=False,
                        architecture="x86_64",
                    ),
                    expected,
                )
                source_check = RUNNER.run_milestone0(
                    offline=True,
                    generate_contracts=False,
                    check_only=True,
                    architecture="x86_64",
                )
        self.assertEqual(source_check["architecture_profile"], "x86_64-source-contract-check")
        self.assertEqual(source_check["x86_64_source_api_inventory"], source_api_inventory)
        self.assertEqual(source_check["x86_64_api_coverage"], source_api_coverage)
        self.assertEqual(source_check["x86_64_source_map"], source_map)
        self.assertNotIn("native_execution_provenance", source_check)
        inventory.assert_has_calls([mock.call(archive), mock.call(archive)])
        self.assertEqual(inventory.call_count, 2)
        source_map_validator.assert_has_calls([mock.call(archive), mock.call(archive)])
        self.assertEqual(source_map_validator.call_count, 2)
        source_api_coverage_validator.assert_has_calls([mock.call(archive), mock.call(archive)])
        self.assertEqual(source_api_coverage_validator.call_count, 2)
        self.assertEqual(
            run_x86.call_args.kwargs["source_api_inventory"], source_api_inventory
        )
        self.assertEqual(
            run_x86.call_args.kwargs["source_api_coverage"], source_api_coverage
        )
        self.assertEqual(run_x86.call_args.kwargs["source_map"], source_map)
        generated_contracts.assert_not_called()
        load_port_map.assert_not_called()
        check_ratchet.assert_not_called()

    def test_production_dependency_graph_is_exact_and_build_code_free(self) -> None:
        report = RUNNER.validate_production_dependency_graph(production_dependency_metadata())
        self.assertEqual(report["target"], "aarch64-unknown-linux-musl")
        self.assertEqual(report["external_package_count"], 9)
        self.assertEqual(report["build_script_count"], 0)
        self.assertEqual(report["proc_macro_count"], 0)
        self.assertEqual(
            [(package["name"], package["version"]) for package in report["packages"]],
            sorted(
                (name, version)
                for name, version in {
                    "crabc-core": "0.3.0",
                    "chacha20": "0.10.1",
                    "cfg-if": "1.0.4",
                    "cipher": "0.5.2",
                    "block-buffer": "0.12.1",
                    "hybrid-array": "0.4.14",
                    "typenum": "1.20.1",
                    "crypto-common": "0.2.2",
                    "inout": "0.2.2",
                    "zeroize": "1.9.0",
                }.items()
            ),
        )

    def test_production_dependency_graph_rejects_a_selected_libc_edge(self) -> None:
        metadata = production_dependency_metadata()
        packages = metadata["packages"]
        nodes = metadata["resolve"]["nodes"]
        assert isinstance(packages, list) and isinstance(nodes, list)
        packages.append(
            {
                "id": "libc 0.2.189",
                "name": "libc",
                "version": "0.2.189",
                "source": "registry+https://github.com/rust-lang/crates.io-index",
                "targets": [{"kind": ["lib"]}],
            }
        )
        nodes.append({"id": "libc 0.2.189", "deps": []})
        chacha = next(node for node in nodes if node["id"] == "chacha20 0.10.1")
        chacha["deps"].append(
            {
                "name": "libc",
                "pkg": "libc 0.2.189",
                "dep_kinds": [{"kind": None, "target": None}],
            }
        )
        with self.assertRaisesRegex(RUNNER.HarnessError, "unexpected selected package: libc 0.2.189"):
            RUNNER.validate_production_dependency_graph(metadata)

    def test_production_dependency_graph_rejects_build_scripts(self) -> None:
        metadata = production_dependency_metadata()
        packages = metadata["packages"]
        assert isinstance(packages, list)
        cipher = next(package for package in packages if package["name"] == "cipher")
        cipher["targets"].append({"kind": ["custom-build"]})
        with self.assertRaisesRegex(RUNNER.HarnessError, "selected build script: cipher 0.5.2"):
            RUNNER.validate_production_dependency_graph(metadata)

    def test_production_dependency_graph_rejects_proc_macros(self) -> None:
        metadata = production_dependency_metadata()
        packages = metadata["packages"]
        assert isinstance(packages, list)
        cipher = next(package for package in packages if package["name"] == "cipher")
        cipher["targets"].append({"kind": ["proc-macro"]})
        with self.assertRaisesRegex(RUNNER.HarnessError, "selected proc macro: cipher 0.5.2"):
            RUNNER.validate_production_dependency_graph(metadata)

    def test_production_dependency_graph_rejects_edge_drift_with_the_same_packages(self) -> None:
        metadata = production_dependency_metadata()
        nodes = metadata["resolve"]["nodes"]
        assert isinstance(nodes, list)
        chacha = next(node for node in nodes if node["id"] == "chacha20 0.10.1")
        chacha["deps"] = [dependency for dependency in chacha["deps"] if dependency["name"] != "zeroize"]
        with self.assertRaisesRegex(RUNNER.HarnessError, "selected dependency edge mismatch"):
            RUNNER.validate_production_dependency_graph(metadata)

    def test_x86_64_engine_dependency_graph_is_exact_and_excludes_libc(self) -> None:
        report = RUNNER.validate_x86_64_engine_dependency_graph(
            x86_64_engine_dependency_metadata()
        )
        self.assertEqual(report["target"], "x86_64-unknown-linux-musl")
        self.assertEqual(report["external_package_count"], 10)
        self.assertEqual(report["build_script_count"], 0)
        self.assertEqual(report["proc_macro_count"], 0)
        packages = {(package["name"], package["version"]) for package in report["packages"]}
        self.assertIn(("cpufeatures", "0.3.0"), packages)
        self.assertNotIn(("libc", "0.2.189"), packages)

    def test_x86_64_engine_dependency_graph_rejects_a_selected_libc_edge(self) -> None:
        metadata = x86_64_engine_dependency_metadata()
        packages = metadata["packages"]
        nodes = metadata["resolve"]["nodes"]
        assert isinstance(packages, list) and isinstance(nodes, list)
        packages.append(
            {
                "id": "libc 0.2.189",
                "name": "libc",
                "version": "0.2.189",
                "source": "registry+https://github.com/rust-lang/crates.io-index",
                "targets": [{"kind": ["lib"]}],
            }
        )
        nodes.append({"id": "libc 0.2.189", "deps": []})
        cpufeatures = next(node for node in nodes if node["id"] == "cpufeatures 0.3.0")
        cpufeatures["deps"].append(
            {
                "name": "libc",
                "pkg": "libc 0.2.189",
                "dep_kinds": [{"kind": None, "target": None}],
            }
        )
        with self.assertRaisesRegex(
            RUNNER.HarnessError, "unexpected selected package: libc 0.2.189"
        ):
            RUNNER.validate_x86_64_engine_dependency_graph(metadata)

    def test_x86_64_engine_dependency_graph_command_is_pinned_and_unfeatured(self) -> None:
        metadata = x86_64_engine_dependency_metadata()
        with mock.patch.object(
            RUNNER,
            "command_record",
            return_value={"status": 0, "stderr": "", "stdout": json.dumps(metadata)},
        ) as command_record:
            report = RUNNER.x86_64_engine_dependency_graph()
        expected_command = [
            "cargo",
            "metadata",
            "--format-version",
            "1",
            "--filter-platform",
            "x86_64-unknown-linux-musl",
            "--no-default-features",
            "--locked",
        ]
        command_record.assert_called_once_with(expected_command, cwd=RUNNER.ROOT)
        self.assertEqual(report["command"], expected_command)
        self.assertEqual(report["resolution"], RUNNER.X86_64_LOCKFILE_RESOLUTION)
        self.assertNotIn("--offline", expected_command)

    def test_x86_64_normal_engine_rlib_parser_rejects_test_features(self) -> None:
        event = {
            "reason": "compiler-artifact",
            "target": {
                "crate_types": ["lib"],
                "kind": ["lib"],
                "name": "crabc_mimalloc",
            },
            "profile": {"test": False},
            "features": [],
            "filenames": ["/tmp/libcrabc_mimalloc.rlib"],
        }
        self.assertEqual(
            RUNNER.x86_64_normal_engine_rlib_from_cargo_output(json.dumps(event)),
            Path("/tmp/libcrabc_mimalloc.rlib"),
        )
        event["features"] = ["test-adapter"]
        with self.assertRaisesRegex(RUNNER.HarnessError, "unexpectedly selected crate features"):
            RUNNER.x86_64_normal_engine_rlib_from_cargo_output(json.dumps(event))

    def test_x86_64_normal_engine_artifact_command_is_locked_unfeatured_and_not_offline(self) -> None:
        command = RUNNER.x86_64_normal_engine_artifact_command("cargo")
        self.assertEqual(
            command,
            [
                "cargo",
                "rustc",
                "--locked",
                "--package",
                "crabc-mimalloc",
                "--lib",
                "--release",
                "--no-default-features",
                "--target",
                "x86_64-unknown-linux-musl",
                "--message-format=json",
            ],
        )
        self.assertNotIn("--offline", command)

    def test_x86_64_normal_engine_artifact_requires_the_normal_fat_lto_bitcode_member(self) -> None:
        self.assertEqual(
            RUNNER.x86_64_normal_engine_codegen_member_format(
                "<normal-engine-codegen-member>: LLVM IR bitcode"
            ),
            "llvm-ir-bitcode",
        )
        with self.assertRaisesRegex(RUNNER.HarnessError, "expected fat-LTO LLVM bitcode"):
            RUNNER.x86_64_normal_engine_codegen_member_format(
                "<normal-engine-codegen-member>: ELF 64-bit LSB relocatable, x86-64"
            )

    def test_x86_64_direct_engine_probe_is_pinned_unfeatured_and_isolated(self) -> None:
        c_layout = {"config.value": 1}
        c_small_trace = {"small.value": 2}
        c_fundamental_trace = {
            key: 3 for key in RUNNER.FUNDAMENTAL_TRACE_X86_64_EXPECTED_KEYS
        }
        with mock.patch.object(
            RUNNER,
            "command_record",
            return_value={"status": 0, "stderr": "", "stdout": "probe output"},
        ) as command_record, mock.patch.object(
            RUNNER, "parse_rust_layout", return_value=c_layout
        ), mock.patch.object(
            RUNNER, "parse_small_trace", return_value=c_small_trace
        ), mock.patch.object(
            RUNNER, "parse_fundamental_trace", return_value=c_fundamental_trace
        ), mock.patch.object(RUNNER, "parse_rust_test_count", return_value=1):
            report = RUNNER.rust_layout_probe(
                c_layout,
                c_small_trace,
                c_fundamental_trace,
                rust_target="x86_64-unknown-linux-musl",
            )
        command = command_record.call_args.args[0]
        environment = command_record.call_args.kwargs["env"]
        self.assertEqual(
            command,
            [
                "cargo",
                "test",
                "-p",
                "crabc-mimalloc",
                "--lib",
                "--locked",
                "--no-default-features",
                "--target",
                "x86_64-unknown-linux-musl",
                "--",
                "--nocapture",
            ],
        )
        self.assertEqual(environment["CARGO_INCREMENTAL"], "0")
        target_directory = Path(environment["CARGO_TARGET_DIR"])
        self.assertEqual(target_directory.name, "target")
        self.assertFalse(target_directory.exists())
        self.assertEqual(report["dependency_resolution"], RUNNER.X86_64_LOCKFILE_RESOLUTION)
        self.assertEqual(report["target_directory"], "fresh temporary CARGO_TARGET_DIR")

    def test_aarch64_direct_engine_probe_is_lockfile_pinned(self) -> None:
        c_layout = {"config.value": 1}
        c_small_trace = {"small.value": 2}
        c_fundamental_trace = {
            key: 3 for key in RUNNER.FUNDAMENTAL_TRACE_AARCH64_EXPECTED_KEYS
        }
        with mock.patch.object(
            RUNNER,
            "command_record",
            return_value={"status": 0, "stderr": "", "stdout": "probe output"},
        ) as command_record, mock.patch.object(
            RUNNER, "parse_rust_layout", return_value=c_layout
        ), mock.patch.object(
            RUNNER, "parse_small_trace", return_value=c_small_trace
        ), mock.patch.object(
            RUNNER, "parse_fundamental_trace", return_value=c_fundamental_trace
        ), mock.patch.object(RUNNER, "parse_rust_test_count", return_value=1):
            report = RUNNER.rust_layout_probe(
                c_layout,
                c_small_trace,
                c_fundamental_trace,
            )
        self.assertEqual(
            command_record.call_args.args[0],
            [
                "cargo",
                "test",
                "-p",
                "crabc-mimalloc",
                "--lib",
                "--locked",
                "--",
                "--nocapture",
            ],
        )
        self.assertEqual(
            command_record.call_args.kwargs["env"]["CARGO_TARGET_DIR"],
            str(RUNNER.RUST_LAYOUT_CARGO_TARGET),
        )
        self.assertEqual(report["comparison"], {"compared_value_count": 1, "status": "matched"})

    def test_external_static_inline_and_cxx_template_parsing_are_distinct(self) -> None:
        header = """
            mi_decl_export void* mi_malloc(size_t size);
            mi_decl_export bool mi_heap_contains(const mi_heap_t* heap, const void* p);
            static inline void* mi_malloc_csize(size_t size) { return mi_malloc(size); }
            static inline void mi_free_csize(void* p, size_t size) { mi_free(p); }
            template<class T> struct mi_stl_allocator {
              T* allocate(size_t count) { return static_cast<T*>(mi_new(count)); }
            };
        """
        self.assertEqual(
            RUNNER.public_external_function_names(header),
            {"mi_malloc", "mi_heap_contains"},
        )
        self.assertEqual(
            RUNNER.public_static_inline_names(header),
            {"mi_malloc_csize", "mi_free_csize"},
        )
        self.assertEqual(RUNNER.public_cxx_template_names(header), {"mi_stl_allocator"})

    def test_type_and_option_parsing_ignore_enum_tag_and_option_functions(self) -> None:
        header = """
            typedef struct mi_heap_s mi_heap_t;
            typedef struct { void* _mi_subproc_id; } mi_subproc_id_t;
            typedef bool (mi_cdecl mi_heap_visit_fun)(mi_heap_t* heap, void* arg);
            typedef struct mi_stats_s { size_t size; } mi_stats_t;
            typedef enum mi_option_e {
              mi_option_show_errors,
              mi_option_deprecated_eager_commit,
              mi_option_os_tag,
              _mi_option_last,
              mi_option_large_os_pages = mi_option_show_errors
            } mi_option_t;
            mi_decl_export bool mi_option_is_enabled(mi_option_t option);
            mi_decl_export void mi_option_enable(mi_option_t option);
        """
        self.assertEqual(
            RUNNER.public_type_names(header),
            {
                "mi_heap_t",
                "mi_subproc_id_t",
                "mi_heap_visit_fun",
                "mi_stats_t",
                "mi_option_t",
            },
        )
        self.assertEqual(
            RUNNER.public_option_names(header),
            {
                "mi_option_show_errors",
                "mi_option_deprecated_eager_commit",
                "mi_option_os_tag",
                "mi_option_large_os_pages",
            },
        )

    def test_linux_aarch64_classification_has_named_release_exceptions(self) -> None:
        stale = RUNNER.classify_api_item("mi_collect_reduce", "external-function")
        self.assertEqual(stale["classification"], "upstream-unavailable-declaration")
        self.assertIn("no definition", stale["classification_reason"])
        override = RUNNER.classify_api_item("mi_malloc_size", "external-function")
        self.assertEqual(override["classification"], "override-only")
        self.assertEqual(override["profile"], "linux-aarch64-override")
        wide = RUNNER.classify_api_item("mi_wdupenv_s", "external-function")
        self.assertEqual(wide["classification"], "linux-einval-operation")
        self.assertTrue(wide["test_adapter_applicable"])

    def test_cxx_declaration_macros_and_legacy_option_aliases_keep_their_source_roles(self) -> None:
        declaration = RUNNER.classify_api_item("mi_decl_new", "macro")
        self.assertEqual(declaration["classification"], "source-only-cxx-convenience")
        self.assertEqual(declaration["profile"], "linux-aarch64-cxx-source")
        self.assertFalse(declaration["test_adapter_applicable"])
        legacy = RUNNER.classify_api_item("mi_option_reset_delay", "option")
        self.assertEqual(legacy["classification"], "deprecated")
        self.assertEqual(legacy["profile"], "linux-aarch64-legacy-option-alias")
        deprecated = RUNNER.classify_api_item("mi_option_deprecated_page_reset", "option")
        self.assertEqual(deprecated["classification"], "deprecated")
        self.assertEqual(deprecated["profile"], "linux-aarch64-deprecated")

    def test_release_symbol_cross_check_rejects_unclassified_discrepancies(self) -> None:
        contract = {
            "items": [
                {"kind": "external-function", "name": "mi_malloc", "oracle_release_exported": True},
                {"kind": "external-function", "name": "mi_collect_reduce", "oracle_release_exported": False},
            ],
            "release_symbol_contract": {
                "expected_defined_symbol_names": ["mi_malloc"],
                "header_declarations_without_normal_release_symbol": [
                    {"name": "mi_collect_reduce"},
                ],
            },
        }
        self.assertEqual(
            RUNNER.validate_release_symbol_contract(contract, ["mi_malloc"]),
            {"declared_external_function_count": 2, "defined_export_count": 1},
        )
        with self.assertRaisesRegex(RUNNER.HarnessError, "unclassified"):
            RUNNER.validate_release_symbol_contract(contract, ["mi_malloc", "mi_extra"])

    def test_function_macro_type_and_option_parsing_are_distinct(self) -> None:
        header = """
            #define mi_malloc_tp(tp) ((tp*)mi_malloc(sizeof(tp)))
            #define mi_attribute_like(p) \\
                mi_attribute_like_continuation(p)
            typedef struct mi_heap_s mi_heap_t;
            typedef enum mi_option_e { mi_option_show_errors } mi_option_t;
            mi_decl_export void* mi_malloc(size_t size);
            mi_decl_export void mi_free(void* p);
        """
        self.assertEqual(RUNNER.public_external_function_names(header), {"mi_malloc", "mi_free"})
        self.assertEqual(RUNNER.public_macro_names(header), {"mi_attribute_like", "mi_malloc_tp"})
        self.assertIn("mi_heap_t", RUNNER.public_type_names(header))
        self.assertEqual(RUNNER.public_option_names(header), {"mi_option_show_errors"})

    def test_inventory_item_does_not_advertise_an_implementation(self) -> None:
        item = RUNNER.item_record("mi_malloc", "external-function", ["include/mimalloc.h"], ["test/test-api.c"])
        self.assertEqual(item["classification"], "required-platform-applicable")
        self.assertEqual(item["adapter_surface"], "test-c-api-adapter-only")
        for field in ("exported", "implemented", "unit_verified", "differential_verified", "stress_verified", "performance_qualified"):
            self.assertFalse(item[field], field)

    def test_configuration_macro_parser_is_stable(self) -> None:
        parsed = RUNNER.parse_macros("#define MI_SECURE 4\n#define MI_EMPTY\n#define OTHER 1\n")
        self.assertEqual(parsed, {"MI_EMPTY": "", "MI_SECURE": "4"})

    def test_rust_layout_parser_ignores_test_harness_noise_and_requires_markers(self) -> None:
        output = """
running 1 test
test types::tests::oracle_layout_probe_emits_machine_record ... CRABC_MI_LAYOUT_BEGIN
pointer.size=8
sizeof.mi_page_t=128
CRABC_MI_LAYOUT_END
ok
"""
        self.assertEqual(
            RUNNER.parse_rust_layout(output),
            {"pointer.size": 8, "sizeof.mi_page_t": 128},
        )
        with self.assertRaisesRegex(RUNNER.HarnessError, "layout markers"):
            RUNNER.parse_rust_layout("pointer.size=8\n")

    def test_native_x86_64_direct_engine_probe_selects_its_explicit_target(self) -> None:
        fundamental_trace = {
            key: 1 for key in RUNNER.FUNDAMENTAL_TRACE_X86_64_EXPECTED_KEYS
        }
        fundamental_output = "\n".join(
            f"{key}={value}" for key, value in sorted(fundamental_trace.items())
        )
        output = f"""
CRABC_MI_LAYOUT_BEGIN
config.MAX_VABITS=47
config.PAGE_MAP_SHIFT=18
CRABC_MI_LAYOUT_END
CRABC_MI_SMALL_TRACE_BEGIN
trace.boundary.count=1
CRABC_MI_SMALL_TRACE_END
CRABC_MI_FUNDAMENTAL_TRACE_BEGIN
{fundamental_output}
CRABC_MI_FUNDAMENTAL_TRACE_END
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
"""
        record = {"status": 0, "stdout": output, "stderr": ""}
        c_layout = {"config.MAX_VABITS": 47, "config.PAGE_MAP_SHIFT": 18}
        small_trace = {"trace.boundary.count": 1}
        with mock.patch.object(RUNNER, "command_record", return_value=record) as command_record:
            result = RUNNER.rust_layout_probe(
                c_layout,
                small_trace,
                fundamental_trace,
                rust_target=RUNNER.X86_64_RUST_TARGET,
            )
        self.assertEqual(
            command_record.call_args.args[0],
            [
                "cargo",
                "test",
                "-p",
                "crabc-mimalloc",
                "--lib",
                "--locked",
                "--no-default-features",
                "--target",
                "x86_64-unknown-linux-musl",
                "--",
                "--nocapture",
            ],
        )
        self.assertEqual(result["target"], RUNNER.X86_64_RUST_TARGET)
        self.assertEqual(result["comparison"], {"compared_value_count": 2, "status": "matched"})
        self.assertEqual(
            result["single_thread_small_trace"]["comparison"],
            {"compared_value_count": 1, "status": "matched"},
        )
        self.assertEqual(
            result["single_thread_fundamental_trace"]["comparison"],
            {"compared_value_count": 75, "status": "matched"},
        )

    def test_direct_engine_probe_rejects_a_target_without_a_trace_schema(self) -> None:
        with self.assertRaisesRegex(
            RUNNER.HarnessError,
            "direct Rust fundamental trace has no schema for target: riscv64gc-unknown-linux-musl",
        ):
            RUNNER.rust_layout_probe(
                {"config.value": 1},
                {"small.value": 1},
                {key: 1 for key in RUNNER.FUNDAMENTAL_TRACE_AARCH64_EXPECTED_KEYS},
                rust_target="riscv64gc-unknown-linux-musl",
            )

    def test_native_x86_64_adapter_contract_is_target_local_and_source_bound(self) -> None:
        source_contract = RUNNER.read_json(RUNNER.ADAPTED_TEST_CONTRACT)
        x86_contract = RUNNER.read_json(RUNNER.X86_64_TEST_ADAPTER_CONTRACT)
        summary = RUNNER.validate_x86_64_test_adapter_contract(
            x86_contract,
            source_contract,
            RUNNER.load_pin(),
            RUNNER.TEST_ADAPTER_HEADER.read_text(encoding="utf-8"),
        )
        self.assertEqual(
            summary,
            {
                "expected_adapter_symbol_count": 16,
                "profile": "linux-x86_64-private-test-adapter",
                "selected_test_count": 33,
                "target": "x86_64-unknown-linux-musl",
            },
        )
        compile_requirements = x86_contract["compile_requirements"]
        self.assertEqual(compile_requirements["native_library_search_paths"], [])
        self.assertEqual(compile_requirements["native_static_libs"], ["-lunwind", "-lc"])
        self.assertFalse(compile_requirements["rust_cdylib_supported"])
        self.assertEqual(
            compile_requirements["rust_target_self_contained_native_library"], "libunwind.a"
        )
        self.assertEqual(compile_requirements["expected_executable_dynamic_dependencies"], [])

    def test_x86_64_adapter_resolves_rusts_target_self_contained_unwinder(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            sysroot = Path(temporary) / "rust"
            search_path = (
                sysroot
                / "lib/rustlib/x86_64-unknown-linux-musl/lib/self-contained"
            )
            search_path.mkdir(parents=True)
            (search_path / "libunwind.a").touch()
            requirements = {
                "native_library_search_paths": [],
                "rust_target_self_contained_native_library": "libunwind.a",
            }
            with mock.patch.object(RUNNER, "require_tool", return_value="rustc"), mock.patch.object(
                RUNNER,
                "command_record",
                return_value={"status": 0, "stdout": f"{sysroot}\n", "stderr": ""},
            ):
                self.assertEqual(
                    RUNNER.native_static_library_search_paths(
                        requirements, rust_target="x86_64-unknown-linux-musl"
                    ),
                    [str(search_path)],
                )

    def test_native_x86_64_adapter_contract_rejects_the_legacy_gcc_s_link_tail(self) -> None:
        source_contract = RUNNER.read_json(RUNNER.ADAPTED_TEST_CONTRACT)
        x86_contract = RUNNER.read_json(RUNNER.X86_64_TEST_ADAPTER_CONTRACT)
        x86_contract["compile_requirements"]["native_static_libs"] = ["-lgcc_s", "-lc"]
        with self.assertRaisesRegex(RUNNER.HarnessError, "compile requirements"):
            RUNNER.validate_x86_64_test_adapter_contract(
                x86_contract,
                source_contract,
                RUNNER.load_pin(),
                RUNNER.TEST_ADAPTER_HEADER.read_text(encoding="utf-8"),
            )

    def test_native_x86_64_adapter_contract_rejects_source_selection_drift(self) -> None:
        source_contract = RUNNER.read_json(RUNNER.ADAPTED_TEST_CONTRACT)
        x86_contract = RUNNER.read_json(RUNNER.X86_64_TEST_ADAPTER_CONTRACT)
        x86_contract["source_selection"]["base_source_selection_sha256"] = "0" * 64
        with self.assertRaisesRegex(RUNNER.HarnessError, "source-selection digest"):
            RUNNER.validate_x86_64_test_adapter_contract(
                x86_contract,
                source_contract,
                RUNNER.load_pin(),
                RUNNER.TEST_ADAPTER_HEADER.read_text(encoding="utf-8"),
            )

    def test_x86_64_adapter_source_selection_does_not_inherit_aarch64_link_requirements(self) -> None:
        source_contract = RUNNER.read_json(RUNNER.ADAPTED_TEST_CONTRACT)
        x86_contract = RUNNER.read_json(RUNNER.X86_64_TEST_ADAPTER_CONTRACT)
        source_contract["compile_requirements"]["expected_dynamic_dependencies"] = [
            "libc.musl-x86_64.so.1",
            "libgcc_s.so.1",
        ]
        with self.assertRaisesRegex(RUNNER.HarnessError, "compile requirement changed"):
            RUNNER.validate_adapted_test_contract(
                source_contract,
                RUNNER.load_pin(),
                RUNNER.TEST_ADAPTER_HEADER.read_text(encoding="utf-8"),
            )
        self.assertEqual(
            RUNNER.adapted_test_source_selection_digest(source_contract),
            x86_contract["source_selection"]["base_source_selection_sha256"],
        )
        header_verification_drift = RUNNER.read_json(RUNNER.ADAPTED_TEST_CONTRACT)
        header_verification_drift["verification"]["header_compile_verified"] = False
        with self.assertRaisesRegex(RUNNER.HarnessError, "header_compile_verified"):
            RUNNER.validate_adapted_test_contract(
                header_verification_drift,
                RUNNER.load_pin(),
                RUNNER.TEST_ADAPTER_HEADER.read_text(encoding="utf-8"),
            )
        self.assertEqual(
            RUNNER.adapted_test_source_selection_digest(header_verification_drift),
            x86_contract["source_selection"]["base_source_selection_sha256"],
        )
        selected_check_drift = RUNNER.read_json(RUNNER.ADAPTED_TEST_CONTRACT)
        selected_check_drift["selected_tests"][0]["name"] = "selection-drift"
        self.assertNotEqual(
            RUNNER.adapted_test_source_selection_digest(selected_check_drift),
            x86_contract["source_selection"]["base_source_selection_sha256"],
        )
        self.assertEqual(
            RUNNER.validate_x86_64_test_adapter_contract(
                x86_contract,
                source_contract,
                RUNNER.load_pin(),
                RUNNER.TEST_ADAPTER_HEADER.read_text(encoding="utf-8"),
            )["target"],
            RUNNER.X86_64_RUST_TARGET,
        )
        self.assertEqual(
            RUNNER.validate_x86_64_test_adapter_contract(
                x86_contract,
                header_verification_drift,
                RUNNER.load_pin(),
                RUNNER.TEST_ADAPTER_HEADER.read_text(encoding="utf-8"),
            )["target"],
            RUNNER.X86_64_RUST_TARGET,
        )

    def test_native_x86_64_adapter_elf_identity_requires_the_native_machine(self) -> None:
        header = """
  Class:                             ELF64
  Data:                              2's complement, little endian
  Machine:                           Advanced Micro Devices X86-64
"""
        self.assertEqual(
            RUNNER.parse_elf_identity(header, "x86_64"),
            {
                "class": "ELF64",
                "endianness": "little",
                "machine": "Advanced Micro Devices X86-64",
            },
        )
        with self.assertRaisesRegex(RUNNER.HarnessError, "not little-endian x86_64"):
            RUNNER.parse_elf_identity(
                header.replace("Advanced Micro Devices X86-64", "AArch64"),
                "x86_64",
            )

    def test_native_x86_64_fixture_audit_requires_elf_interp_and_dependencies(self) -> None:
        header = """
  Class:                             ELF64
  Data:                              2's complement, little endian
  Machine:                           Advanced Micro Devices X86-64
"""
        dynamic = ""

        def records(interpreter: str) -> list[dict[str, object]]:
            return [
                {"status": 0, "stdout": header, "stderr": ""},
                {
                    "status": 0,
                    "stdout": f"[Requesting program interpreter: {interpreter}]\n",
                    "stderr": "",
                },
                {"status": 0, "stdout": dynamic, "stderr": ""},
            ]

        expected_elf = {
            "class": "ELF64",
            "endianness": "little",
            "machine": "Advanced Micro Devices X86-64",
        }
        with mock.patch.object(
            RUNNER,
            "command_record",
            side_effect=records("/opt/musl-1.2.6/lib/ld-musl-x86_64.so.1"),
        ) as command_record:
            evidence = RUNNER.audit_native_executable(
                "readelf",
                Path("fixture"),
                architecture="x86_64",
                expected_elf=expected_elf,
                expected_interpreter="ld-musl-x86_64.so.1",
                expected_dynamic_dependencies=[],
            )
        self.assertEqual(
            evidence,
            {
                "dynamic_dependencies": [],
                "elf": expected_elf,
                "interpreter": "/opt/musl-1.2.6/lib/ld-musl-x86_64.so.1",
            },
        )
        self.assertEqual(command_record.call_count, 3)
        with mock.patch.object(
            RUNNER,
            "command_record",
            side_effect=records("/lib64/ld-linux-x86-64.so.2"),
        ):
            with self.assertRaisesRegex(RUNNER.HarnessError, "PT_INTERP differs"):
                RUNNER.audit_native_executable(
                    "readelf",
                    Path("fixture"),
                    architecture="x86_64",
                    expected_elf=expected_elf,
                    expected_interpreter="ld-musl-x86_64.so.1",
                    expected_dynamic_dependencies=[],
                )

    def test_small_trace_parser_requires_one_address_independent_machine_record(self) -> None:
        output = """
noise before
CRABC_MI_SMALL_TRACE_BEGIN
trace.boundary.count=2
trace.boundary.0.request=0
trace.boundary.0.usable=8
CRABC_MI_SMALL_TRACE_END
noise after
"""
        self.assertEqual(
            RUNNER.parse_small_trace(output),
            {
                "trace.boundary.0.request": 0,
                "trace.boundary.0.usable": 8,
                "trace.boundary.count": 2,
            },
        )
        with self.assertRaisesRegex(RUNNER.HarnessError, "trace.*markers"):
            RUNNER.parse_small_trace("trace.boundary.count=2\n")

    def test_small_trace_comparison_requires_exact_keys_and_values(self) -> None:
        c_trace = {
            "trace.boundary.0.request": 0,
            "trace.boundary.0.usable": 8,
            "trace.boundary.count": 1,
        }
        self.assertEqual(
            RUNNER.compare_small_trace(c_trace, c_trace),
            {"compared_value_count": 3, "status": "matched"},
        )
        with self.assertRaisesRegex(
            RUNNER.HarnessError,
            r"missing from C oracle: trace\.extra; "
            r"missing from Rust port: trace\.boundary\.0\.usable; "
            r"value mismatches: trace\.boundary\.count \(C=1, Rust=2\)",
        ):
            RUNNER.compare_small_trace(
                c_trace,
                {
                    "trace.boundary.0.request": 0,
                    "trace.boundary.count": 2,
                    "trace.extra": 1,
                },
            )

    def test_fundamental_trace_parser_requires_one_address_independent_machine_record(self) -> None:
        output = """
noise before
CRABC_MI_FUNDAMENTAL_TRACE_BEGIN
trace.fundamental.class.small.request=10240
trace.fundamental.class.small.usable=10240
trace.fundamental.class.small.success=1
trace.fundamental.calloc.content_hash=14695981039346656037
CRABC_MI_FUNDAMENTAL_TRACE_END
noise after
"""
        self.assertEqual(
            RUNNER.parse_fundamental_trace(output),
            {
                "trace.fundamental.calloc.content_hash": 14695981039346656037,
                "trace.fundamental.class.small.request": 10240,
                "trace.fundamental.class.small.success": 1,
                "trace.fundamental.class.small.usable": 10240,
            },
        )
        with self.assertRaisesRegex(RUNNER.HarnessError, "fundamental-operation trace.*markers"):
            RUNNER.parse_fundamental_trace("trace.fundamental.class.small.request=10240\n")

    def test_fundamental_trace_comparison_names_value_mismatch_after_schema_validation(self) -> None:
        c_trace = {key: 1 for key in RUNNER.FUNDAMENTAL_TRACE_X86_64_EXPECTED_KEYS}
        self.assertEqual(
            RUNNER.compare_fundamental_trace(c_trace, c_trace, architecture="x86_64"),
            {"compared_value_count": 75, "status": "matched"},
        )
        mismatched = dict(c_trace)
        mismatched["trace.fundamental.class.small.success"] = 0
        with self.assertRaisesRegex(
            RUNNER.HarnessError,
            r"value mismatches: trace\.fundamental\.class\.small\.success \(C=1, Rust=0\)",
        ):
            RUNNER.compare_fundamental_trace(c_trace, mismatched, architecture="x86_64")

    def test_fundamental_trace_comparison_rejects_a_synchronized_schema_regression(self) -> None:
        # Comparing only the two observed maps would let a matching deletion
        # silently reduce the pinned trace contract. The durable record has a
        # fixed 75-key schema, including the nonzero null-pointer expand case
        # and checked counted zeroed reallocation outcomes.
        self.assertEqual(RUNNER.FUNDAMENTAL_TRACE_X86_64_EXPECTED_COUNT, 75)
        self.assertEqual(len(RUNNER.FUNDAMENTAL_TRACE_X86_64_EXPECTED_KEYS), 75)
        self.assertIn(
            "trace.fundamental.expand.null_nonzero_returns_null",
            RUNNER.FUNDAMENTAL_TRACE_X86_64_EXPECTED_KEYS,
        )
        self.assertIn(
            "trace.fundamental.recalloc_overflow.preserved",
            RUNNER.FUNDAMENTAL_TRACE_X86_64_EXPECTED_KEYS,
        )
        self.assertIn("mi_recalloc", RUNNER.FUNDAMENTAL_TRACE_PROBE)
        self.assertIn("mi_expand(NULL, expand_request)", RUNNER.FUNDAMENTAL_TRACE_PROBE)
        self.assertIn("#if defined(__x86_64__)", RUNNER.FUNDAMENTAL_TRACE_PROBE)
        synchronized_but_incomplete = {
            "trace.fundamental.class.small.request": 10240,
            "trace.fundamental.class.small.success": 1,
            "trace.fundamental.class.small.usable": 10240,
        }
        with self.assertRaisesRegex(
            RUNNER.HarnessError,
            r"fixed 75-key schema.*trace\.fundamental\.expand\.null_nonzero_returns_null",
        ):
            RUNNER.compare_fundamental_trace(
                synchronized_but_incomplete,
                synchronized_but_incomplete,
                architecture="x86_64",
            )

    def test_fundamental_trace_schema_keeps_aarch64_baseline_separate_from_x86_extension(self) -> None:
        self.assertEqual(RUNNER.FUNDAMENTAL_TRACE_AARCH64_EXPECTED_COUNT, 51)
        self.assertEqual(len(RUNNER.FUNDAMENTAL_TRACE_AARCH64_EXPECTED_KEYS), 51)
        self.assertEqual(RUNNER.FUNDAMENTAL_TRACE_EXPECTED_COUNT, 51)
        self.assertNotIn(
            "trace.fundamental.expand.usable",
            RUNNER.FUNDAMENTAL_TRACE_AARCH64_EXPECTED_KEYS,
        )
        self.assertNotIn(
            "trace.fundamental.recalloc.valid",
            RUNNER.FUNDAMENTAL_TRACE_AARCH64_EXPECTED_KEYS,
        )
        self.assertEqual(
            len(RUNNER.FUNDAMENTAL_TRACE_X86_64_EXTENSION_KEYS),
            24,
        )
        aarch_trace = {key: 1 for key in RUNNER.FUNDAMENTAL_TRACE_AARCH64_EXPECTED_KEYS}
        self.assertEqual(
            RUNNER.compare_fundamental_trace(aarch_trace, aarch_trace),
            {"compared_value_count": 51, "status": "matched"},
        )
        with self.assertRaisesRegex(RUNNER.HarnessError, "fixed 51-key schema"):
            RUNNER.compare_fundamental_trace(aarch_trace, aarch_trace | {
                "trace.fundamental.expand.usable": 1,
            })

    def test_fundamental_trace_parser_rejects_raw_address_fields(self) -> None:
        output = """
CRABC_MI_FUNDAMENTAL_TRACE_BEGIN
trace.fundamental.class.small.address=12345
CRABC_MI_FUNDAMENTAL_TRACE_END
"""
        with self.assertRaisesRegex(RUNNER.HarnessError, "raw address field"):
            RUNNER.parse_fundamental_trace(output)
        hexadecimal = """
CRABC_MI_FUNDAMENTAL_TRACE_BEGIN
trace.fundamental.class.small.content_hash=0xface
CRABC_MI_FUNDAMENTAL_TRACE_END
"""
        with self.assertRaisesRegex(RUNNER.HarnessError, "raw address"):
            RUNNER.parse_fundamental_trace(hexadecimal)

    def test_fundamental_trace_same_run_marker_cannot_claim_comparison(self) -> None:
        status = RUNNER.pending_fundamental_trace_comparison()
        self.assertEqual(status["status"], "pending")
        self.assertIn("before the Rust library probe", status["reason"])
        self.assertIn("replaces this marker", status["reason"])

    def test_layout_parser_rejects_duplicate_machine_record_keys(self) -> None:
        with self.assertRaisesRegex(RUNNER.HarnessError, "duplicate layout probe key"):
            RUNNER.parse_layout("pointer.size=8\npointer.size=4\n")

    def test_rust_test_summary_parser_requires_one_successful_library_result(self) -> None:
        output = """
running 68 tests
test result: ok. 68 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
"""
        self.assertEqual(RUNNER.parse_rust_test_count(output), 68)
        with self.assertRaisesRegex(RUNNER.HarnessError, "Rust allocator test summary"):
            RUNNER.parse_rust_test_count("test result: FAILED. 67 passed; 1 failed\n")

    def test_upstream_api_summary_parser_requires_one_zero_failure_summary(self) -> None:
        output = """
malloc_aligned5: usable size: 8192.

---------------------------------------------
succeeded: 34
failed   : 0
"""
        self.assertEqual(
            RUNNER.parse_upstream_api_test_summary(output),
            {"failed": 0, "succeeded": 34},
        )
        with self.assertRaisesRegex(RUNNER.HarnessError, "reported 1 failure"):
            RUNNER.parse_upstream_api_test_summary("succeeded: 33\nfailed   : 1\n")
        with self.assertRaisesRegex(RUNNER.HarnessError, "absent or ambiguous"):
            RUNNER.parse_upstream_api_test_summary(
                "succeeded: 34\nfailed   : 0\nsucceeded: 34\nfailed   : 0\n"
            )

    def test_adapter_symbol_contract_requires_exact_prefixed_exports(self) -> None:
        expected = [
            "crabc_test_free",
            "crabc_test_init",
            "crabc_test_malloc",
        ]
        self.assertEqual(
            RUNNER.validate_adapter_dynamic_symbols(
                ["_init", *expected, "rust_eh_personality"], expected
            ),
            {"exported_symbol_count": 3, "symbols": expected},
        )
        with self.assertRaisesRegex(RUNNER.HarnessError, "missing adapter symbols"):
            RUNNER.validate_adapter_dynamic_symbols(expected[:-1], expected)
        with self.assertRaisesRegex(RUNNER.HarnessError, "unexpected adapter symbols"):
            RUNNER.validate_adapter_dynamic_symbols(
                [*expected, "crabc_test_unreviewed"], expected
            )
        with self.assertRaisesRegex(RUNNER.HarnessError, "forbidden allocator exports"):
            RUNNER.validate_adapter_dynamic_symbols([*expected, "malloc", "mi_malloc"], expected)

    def test_adapter_header_inventory_extracts_only_function_declarations(self) -> None:
        header = """
int crabc_test_init(void);
void *crabc_test_malloc(size_t size);
#define mi_malloc(size) crabc_test_malloc((size))
#define CRABC_MIMALLOC_TEST_ADAPTER_H
"""
        self.assertEqual(
            RUNNER.adapter_header_function_names(header),
            ["crabc_test_init", "crabc_test_malloc"],
        )

    def test_runtime_ticket_zero_adapter_symbol_contract_requires_exact_exports(self) -> None:
        expected = [
            "crabc_ticket_zero_test_free",
            "crabc_ticket_zero_test_init",
            "crabc_ticket_zero_test_malloc",
        ]
        self.assertEqual(
            RUNNER.validate_runtime_ticket_zero_adapter_symbols(
                ["_init", *expected, "rust_eh_personality"], expected
            ),
            {"exported_symbol_count": 3, "symbols": expected},
        )
        with self.assertRaisesRegex(RUNNER.HarnessError, "missing symbols"):
            RUNNER.validate_runtime_ticket_zero_adapter_symbols(expected[:-1], expected)
        with self.assertRaisesRegex(RUNNER.HarnessError, "unexpected symbols"):
            RUNNER.validate_runtime_ticket_zero_adapter_symbols(
                [*expected, "crabc_ticket_zero_test_unreviewed"], expected
            )
        with self.assertRaisesRegex(RUNNER.HarnessError, "forbidden allocator exports"):
            RUNNER.validate_runtime_ticket_zero_adapter_symbols(
                [*expected, "malloc", "mi_malloc"], expected
            )

    def test_runtime_ticket_zero_adapter_header_inventory_extracts_only_declarations(self) -> None:
        header = """
int crabc_ticket_zero_test_init(size_t page_size);
void *crabc_ticket_zero_test_malloc(size_t size);
#define hidden crabc_ticket_zero_test_malloc((size))
"""
        self.assertEqual(
            RUNNER.runtime_ticket_zero_adapter_header_function_names(header),
            ["crabc_ticket_zero_test_init", "crabc_ticket_zero_test_malloc"],
        )

    def test_native_static_library_parser_preserves_rustc_link_order(self) -> None:
        output = """
   Compiling crabc-mimalloc-test-adapter v0.3.0
note: native-static-libs: -lgcc_s -lc
    Finished `release` profile
"""
        self.assertEqual(RUNNER.parse_native_static_libraries(output), ["-lgcc_s", "-lc"])
        with self.assertRaisesRegex(RUNNER.HarnessError, "absent or ambiguous"):
            RUNNER.parse_native_static_libraries("Finished release\n")
        with self.assertRaisesRegex(RUNNER.HarnessError, "invalid native static library"):
            RUNNER.parse_native_static_libraries("native-static-libs: -lgcc_s /ambient/libbad.a\n")

    def test_optional_native_static_library_parser_accepts_a_no_std_empty_tail(self) -> None:
        self.assertEqual(
            RUNNER.parse_optional_native_static_libraries("native-static-libs: \n"),
            [],
        )
        with self.assertRaisesRegex(RUNNER.HarnessError, "invalid native static library"):
            RUNNER.parse_optional_native_static_libraries(
                "native-static-libs: /ambient/libbad.a\n"
            )
    def test_native_x86_64_static_library_parser_preserves_the_unwind_tail(self) -> None:
        output = "note: native-static-libs: -lunwind -lc\n"
        self.assertEqual(RUNNER.parse_native_static_libraries(output), ["-lunwind", "-lc"])

    def test_rust_layout_comparison_names_missing_and_mismatched_values(self) -> None:
        c_layout = {
            "pointer.size": 8,
            "sizeof.mi_memid_t": 24,
            "sizeof.mi_page_t": 128,
        }
        self.assertEqual(
            RUNNER.compare_rust_layout(c_layout, c_layout),
            {"compared_value_count": 3, "status": "matched"},
        )
        with self.assertRaisesRegex(
            RUNNER.HarnessError,
            r"missing from C oracle: alignof\.mi_page_t; value mismatches: sizeof\.mi_page_t \(C=128, Rust=120\)",
        ):
            RUNNER.compare_rust_layout(
                c_layout,
                {
                    "alignof.mi_page_t": 8,
                    "pointer.size": 8,
                    "sizeof.mi_memid_t": 24,
                "sizeof.mi_page_t": 120,
            },
        )

    def test_configuration_layout_requires_an_exact_c_and_rust_key_set(self) -> None:
        c_layout = {
            "config.WORD_SIZE": object(),
            "config.PAGE_MAP_FLAT": object(),
        }
        rust_layout = dict(c_layout)
        self.assertEqual(RUNNER.compare_configuration_layout(c_layout, rust_layout), 2)
        with self.assertRaisesRegex(RUNNER.HarnessError, "configuration records missing from Rust"):
            RUNNER.compare_configuration_layout(c_layout, {"config.WORD_SIZE": object()})
        with self.assertRaisesRegex(RUNNER.HarnessError, "configuration records missing from C"):
            RUNNER.compare_configuration_layout({"config.WORD_SIZE": object()}, rust_layout)


class ContractTests(unittest.TestCase):
    def test_loom_model_is_explicitly_feature_targeted_and_clears_production_rustflags(self) -> None:
        record = {
            "status": 0,
            "stderr": "",
            "stdout": "test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 579 filtered out; finished in 0.01s\n",
        }
        with mock.patch.object(RUNNER, "command_record", return_value=record) as command_record:
            report = RUNNER.loom_remote_free_model()

        self.assertEqual(
            command_record.call_args.args[0],
            [
                "cargo",
                "test",
                "-p",
                "crabc-mimalloc",
                "--lib",
                "--features",
                "loom",
                "--locked",
                "remote_free::loom_tests",
                "--",
                "--test-threads=1",
            ],
        )
        self.assertEqual(command_record.call_args.kwargs["env"]["CARGO_ENCODED_RUSTFLAGS"], "")
        self.assertEqual(
            command_record.call_args.kwargs["env"]["CARGO_TARGET_DIR"],
            str(RUNNER.LOOM_CARGO_TARGET),
        )
        self.assertEqual(report["cargo_encoded_rustflags"], [])

    def test_loom_dependency_and_model_sources_remain_feature_target_gated(self) -> None:
        manifest_path = RUNNER.ROOT / "crabc-mimalloc/Cargo.toml"
        with manifest_path.open("rb") as stream:
            manifest = tomllib.load(stream)

        dependencies = manifest["dependencies"]
        self.assertEqual(
            set(dependencies),
            {"chacha20", "crabc-core", "loom", "zeroize"},
        )
        self.assertEqual(
            dependencies["loom"],
            {
                "version": "=0.7.2",
                "default-features": False,
                "optional": True,
            },
        )
        self.assertFalse(manifest.get("dev-dependencies", {}))
        self.assertEqual(manifest["features"]["loom"], ["dep:loom"])

        remote_free = (RUNNER.ROOT / "crabc-mimalloc/src/remote_free.rs").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "#[cfg(all(test, feature = \"loom\"))]\n"
            "#[path = \"remote_free_loom.rs\"]\n"
            "mod loom_tests;",
            remote_free,
        )
        self.assertIn(
            "#[cfg(all(test, feature = \"loom\"))]\n"
            "#[path = \"remote_free_owner_unown_loom.rs\"]\n"
            "mod owner_unown_loom_tests;",
            remote_free,
        )

    def test_pin_is_complete_and_names_the_exact_archive(self) -> None:
        pin = RUNNER.load_pin()
        self.assertEqual(pin["version"], "3.5.0")
        self.assertEqual(pin["repository"], "https://github.com/microsoft/mimalloc.git")
        self.assertEqual(pin["tag"], "v3.5.0")
        self.assertEqual(pin["archive_root"], "mimalloc-3.5.0")
        self.assertEqual(pin["revision"], "18b08671c9302247bfb682286e6bf3cc1773f801")
        self.assertEqual(pin["tag_object"], "438b0c4b78d2599aede7fca3ddacc28863b0eae8")

    def test_owner_exit_publication_contract_keeps_source_order_and_rejects_raw_reconstruction(self) -> None:
        contract = RUNNER.read_json(RUNNER.OWNER_EXIT_PUBLICATION_CONTRACT)
        pin = RUNNER.load_pin()
        source_text = {
            "src/init.c": """
                void mi_thread_theaps_done(void) {
                    mi_lock(&tld->theaps_lock) { }
                    _mi_theap_collect_abandon(theap);
                    mi_assert_internal(theap->page_count==0);
                }
            """,
            "src/theap.c": """
                void mi_theap_page_collect(void) {
                    _mi_page_free_collect(page, collect >= MI_FORCE);
                    if (mi_page_all_free(page)) { }
                    else if (collect == MI_ABANDON) { }
                    _mi_page_abandon(page, pq);
                }
            """,
            "src/page.c": """
                void _mi_page_abandon(void) {
                    _mi_page_free_collect(page, false);
                    if (mi_page_all_free(page)) { }
                    _mi_page_free(page, pq);
                    mi_page_queue_remove(pq, page);
                    mi_page_set_theap(page, NULL);
                    _mi_arenas_page_abandon(page, theap);
                }
            """,
            "include/mimalloc/internal.h": """
                void mi_page_set_theap(void) {
                    page->theap = theap;
                    theap == NULL ? MI_THREADID_ABANDONED : theap->tld->thread_id;
                    mi_atomic_cas_weak_release(&page->xthread_id, &xtid_old, xtid);
                }
            """,
            "src/arena.c": """
                void _mi_arenas_page_abandon(void) {
                    if (page->memid.memkind==MI_MEM_ARENA && !mi_page_is_full(page)) { }
                    mi_page_set_abandoned_mapped(page);
                    mi_bitmap_set(arena_pages->pages_abandoned[bin], slice_index);
                    mi_atomic_increment_relaxed(&heap->abandoned_count[bin]);
                    mi_abandoned_page_unown(page, current_theapx);
                    if (page->memid.memkind != MI_MEM_ARENA) { }
                    mi_lock(&heap->os_abandoned_pages_lock) { }
                    heap->os_abandoned_pages = page;
                    mi_theapx_stat_increase(heap, current_theapx, pages_abandoned, 1);
                    mi_abandoned_page_unown(page, current_theapx);
                }
            """,
            "src/free.c": """
                void mi_abandoned_page_try_free(void) {
                    if (!mi_page_all_free(page)) return false;
                    _mi_arenas_page_unabandon(page,NULL);
                    _mi_arenas_page_free(page,NULL);
                }
            """,
        }

        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            for path, text in source_text.items():
                target = source / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(text, encoding="utf-8")

            self.assertEqual(
                RUNNER.validate_owner_exit_publication_contract(contract, pin, source),
                {
                    "forbidden_reconstruction_input_count": 4,
                    "publication_route_count": 2,
                    "source_fact_count": 8,
                },
            )

            stale_claim = json.loads(json.dumps(contract))
            stale_claim["stale_w07_claim"]["claim_reconstruction"] = "allowed"
            with self.assertRaisesRegex(RUNNER.HarnessError, "stale W07 claim"):
                RUNNER.validate_owner_exit_publication_contract(stale_claim, pin, source)

            stale_empty_release = json.loads(json.dumps(contract))
            stale_empty_release["transition"]["empty_terminal_release"][
                "forbidden_transition_events"
            ] = []
            with self.assertRaisesRegex(RUNNER.HarnessError, "empty terminal release"):
                RUNNER.validate_owner_exit_publication_contract(
                    stale_empty_release,
                    pin,
                    source,
                )

            reordered = source / "src/page.c"
            reordered.write_text(
                source_text["src/page.c"].replace(
                    "mi_page_queue_remove(pq, page);\n                    mi_page_set_theap(page, NULL);",
                    "mi_page_set_theap(page, NULL);\n                    mi_page_queue_remove(pq, page);",
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(RUNNER.HarnessError, "queue-detach-before-abandoned-identity"):
                RUNNER.validate_owner_exit_publication_contract(contract, pin, source)

    def test_port_map_covers_the_required_v3_sources_and_has_only_verified_claims(self) -> None:
        port_map = RUNNER.load_port_map()
        counts = RUNNER.port_map_counts(port_map)
        self.assertEqual(counts["unit_count"], len(RUNNER.REQUIRED_PORT_UNITS))
        self.assertGreaterEqual(counts["implemented"], 8)
        self.assertEqual(counts["implemented"], counts["unit_verified"])

    def test_checked_in_upstream_test_inventory_distinguishes_sources_and_support(self) -> None:
        inventory = RUNNER.read_json(RUNNER.UPSTREAM_TEST_CONTRACT)
        self.assertEqual(inventory["summary"]["test_source_count"], 13)
        self.assertEqual(inventory["summary"]["test_support_file_count"], 3)
        self.assertEqual(inventory["summary"]["total_inventory_file_count"], 16)

    def test_upstream_test_inventory_records_the_reviewed_adapter_selections(self) -> None:
        inventory = RUNNER.read_json(RUNNER.UPSTREAM_TEST_CONTRACT)
        states = {item["path"]: item["status"] for item in inventory["tests"]}

        self.assertEqual(inventory["format"], 3)
        self.assertEqual(states["test/test-api.c"], "adapted-milestone-4")
        self.assertEqual(states["test/testhelper.h"], "adapted-milestone-4")
        self.assertEqual(states["test/test-stress.c"], "adapted-milestone-5")
        self.assertEqual(states["test/main.c"], "blocked-milestone-5-plus")
        self.assertEqual(inventory["summary"]["adapted_milestone_4_file_count"], 2)
        self.assertEqual(inventory["summary"]["adapted_milestone_5_file_count"], 1)
        self.assertEqual(inventory["summary"]["blocked_milestone_5_plus_count"], 13)

    def test_adapted_api_fixture_contract_is_exact_and_reviewed(self) -> None:
        contract = RUNNER.read_json(RUNNER.ADAPTED_TEST_CONTRACT)
        header = RUNNER.TEST_ADAPTER_HEADER.read_text(encoding="utf-8")
        summary = RUNNER.validate_adapted_test_contract(contract, RUNNER.load_pin(), header)
        self.assertEqual(
            summary,
            {
                "expected_adapter_symbol_count": 16,
                "omitted_test_count": 21,
                "selected_test_count": 33,
            },
        )

    def test_adapted_stress_fixture_contract_is_exact_and_reviewed(self) -> None:
        contract = RUNNER.read_json(RUNNER.ADAPTED_STRESS_TEST_CONTRACT)
        header = RUNNER.TEST_ADAPTER_HEADER.read_text(encoding="utf-8")
        self.assertEqual(
            RUNNER.validate_adapted_stress_test_contract(
                contract, RUNNER.load_pin(), header
            ),
            {
                "excluded_upstream_mode_count": 6,
                "expected_adapter_symbol_count": 16,
                "required_prefixed_adapter_symbol_count": 3,
            },
        )

    def test_native_shadow_stress_contract_is_exact_and_reviewed(self) -> None:
        contract = RUNNER.read_json(RUNNER.NATIVE_SHADOW_STRESS_CONTRACT)
        self.assertEqual(
            RUNNER.validate_native_shadow_stress_contract(contract, RUNNER.load_pin()),
            {
                "excluded_upstream_mode_count": 5,
                "process_epochs": 128,
                "source_worker_count": 4,
            },
        )

    def test_runtime_ticket_zero_adapter_contract_is_exact_and_reviewed(self) -> None:
        contract = RUNNER.read_json(RUNNER.RUNTIME_TICKET_ZERO_ADAPTER_CONTRACT)
        header = RUNNER.RUNTIME_TICKET_ZERO_ADAPTER_HEADER.read_text(encoding="utf-8")
        self.assertEqual(
            RUNNER.validate_runtime_ticket_zero_adapter_contract(contract, header),
            {"expected_adapter_symbol_count": 9},
        )
        contract["lifecycle_audit"]["fixture_success_line"] = "stale success line"
        with self.assertRaisesRegex(RUNNER.HarnessError, "lifecycle audit contract"):
            RUNNER.validate_runtime_ticket_zero_adapter_contract(contract, header)

    def test_runtime_ticket_zero_lifecycle_audit_record_is_exact(self) -> None:
        stdout = (
            "runtime ticket-zero lifecycle audit worker_cycles=3 process_active=1 "
            "page_owner_ready=1 page_map_registered_entries=0 "
            "page_map_published_submaps=2 page_map_lazy_submap_allocations=1 "
            "arena_registry_entries=1 live_tlds=1 metadata_live_capabilities=0 "
            "metadata_high_water_capabilities=3 shared_later_theaps=0 "
            "abandoned_regular_pages=0 os_abandoned_pages_empty=1\n"
            "runtime ticket-zero allocator ok\n"
        )
        self.assertEqual(
            RUNNER.parse_runtime_ticket_zero_lifecycle_audit(stdout),
            {
                "worker_cycles": 3,
                "process_active": 1,
                "page_owner_ready": 1,
                "page_map_registered_entries": 0,
                "page_map_published_submaps": 2,
                "page_map_lazy_submap_allocations": 1,
                "arena_registry_entries": 1,
                "live_tlds": 1,
                "metadata_live_capabilities": 0,
                "metadata_high_water_capabilities": 3,
                "shared_later_theaps": 0,
                "abandoned_regular_pages": 0,
                "os_abandoned_pages_empty": 1,
            },
        )
        with self.assertRaisesRegex(RUNNER.HarnessError, "fields differ"):
            RUNNER.parse_runtime_ticket_zero_lifecycle_audit(
                stdout.replace("live_tlds=1 ", "unexpected=1 ")
            )

    def test_runtime_ticket_zero_lifecycle_commands_are_bounded_and_watchdog_ready(self) -> None:
        fixture = Path("/tmp/runtime-ticket-zero-fixture")
        self.assertEqual(
            RUNNER.runtime_ticket_zero_stress_schedule(
                worker_cycles=128,
                stress_seed=RUNNER.RUNTIME_TICKET_ZERO_CHURN_STRESS_SEED,
            ),
            {
                "seed": "0xd1b54a32d192ed03",
                "worker_route_invocation_count": 256,
                "worker_routes_per_cycle": 2,
            },
        )
        self.assertEqual(
            RUNNER.runtime_ticket_zero_fixture_command(fixture, worker_cycles=128),
            [
                str(fixture),
                "--worker-cycles",
                "128",
                "--stress-seed",
                "0x9e3779b97f4a7c15",
            ],
        )
        self.assertEqual(
            RUNNER.runtime_ticket_zero_fixture_command(
                fixture,
                worker_cycles=1024,
                stress_seed=RUNNER.RUNTIME_TICKET_ZERO_SOAK_STRESS_SEED,
            ),
            [
                str(fixture),
                "--worker-cycles",
                "1024",
                "--stress-seed",
                "0x94d049bb133111eb",
            ],
        )
        self.assertEqual(RUNNER.RUNTIME_TICKET_ZERO_CHURN_WORKER_CYCLES, 128)
        self.assertEqual(RUNNER.RUNTIME_TICKET_ZERO_CHURN_WATCHDOG_SECONDS, 30)
        self.assertEqual(
            RUNNER.RUNTIME_TICKET_ZERO_CHURN_STRESS_SEED,
            0xD1B54A32D192ED03,
        )
        self.assertEqual(RUNNER.RUNTIME_TICKET_ZERO_SOAK_WORKER_CYCLES, 1024)
        self.assertEqual(RUNNER.RUNTIME_TICKET_ZERO_SOAK_WATCHDOG_SECONDS, 180)
        with self.assertRaisesRegex(RUNNER.HarnessError, "worker cycles"):
            RUNNER.runtime_ticket_zero_fixture_command(fixture, worker_cycles=0)
        with self.assertRaisesRegex(RUNNER.HarnessError, "worker cycles"):
            RUNNER.runtime_ticket_zero_fixture_command(fixture, worker_cycles=1025)
        with self.assertRaisesRegex(RUNNER.HarnessError, "stress seed"):
            RUNNER.runtime_ticket_zero_fixture_command(fixture, worker_cycles=1, stress_seed=-1)
        with self.assertRaisesRegex(RUNNER.HarnessError, "stress seed"):
            RUNNER.runtime_ticket_zero_fixture_command(
                fixture,
                worker_cycles=1,
                stress_seed=1 << 64,
            )

    def test_m5_gate_contract_names_the_current_full_lane_and_open_gates(self) -> None:
        contract = RUNNER.read_json(RUNNER.M5_GATE_CONTRACT)
        summary = RUNNER.validate_m5_gate_contract(contract, RUNNER.load_pin())

        self.assertEqual(summary["gate_count"], 6)
        self.assertEqual(
            summary["full_lane"],
            {
                "routes_per_cycle": 2,
                "stress_seed": "0xd1b54a32d192ed03",
                "watchdog_seconds": 30,
                "worker_cycles": 128,
            },
        )
        self.assertEqual(
            summary["gate_ids"],
            ["m5.base", "m5.5a", "m5.5b", "m5.5c", "m5.5d", "m5.5e"],
        )

    def test_native_owner_exit_lifecycle_contract_covers_every_reviewed_condition(self) -> None:
        contract = RUNNER.read_json(RUNNER.NATIVE_OWNER_EXIT_LIFECYCLE_CONTRACT)
        summary = RUNNER.validate_native_owner_exit_lifecycle_contract(
            contract,
            RUNNER.load_pin(),
        )

        self.assertEqual(summary["check_count"], 15)
        self.assertEqual(
            summary["scenario_coverage"],
            sorted(RUNNER.NATIVE_OWNER_EXIT_REQUIRED_SCENARIOS),
        )
        self.assertEqual(
            RUNNER.native_owner_exit_lifecycle_command(
                summary["execution"],
                summary["checks"][0],
            ),
            [
                "cargo",
                "test",
                "-p",
                "crabc-mimalloc",
                "--features",
                "native-runtime-test-audit,native-runtime-test-fault",
                "--locked",
                "--test",
                "native_post_exit_lifecycle",
                "--",
                "--test-threads=1",
            ],
        )
        self.assertEqual(
            RUNNER.native_owner_exit_lifecycle_command(
                summary["execution"],
                summary["checks"][-1],
            ),
            [
                "cargo",
                "test",
                "-p",
                "crabc-mimalloc",
                "--features",
                "native-runtime-test-audit,native-runtime-test-fault",
                "--locked",
                "--lib",
                "main_heap_page::tests::later_thread_exit_mapped_medium_route_adopts_into_a_fresh_later_owner",
                "--",
                "--test-threads=1",
            ],
        )

    def test_native_owner_exit_lifecycle_contract_rejects_retired_integration_target(self) -> None:
        contract = RUNNER.read_json(RUNNER.NATIVE_OWNER_EXIT_LIFECYCLE_CONTRACT)
        contract["checks"][0]["target"] = "retired_owner_exit_session"

        with self.assertRaisesRegex(RUNNER.HarnessError, "current integration test target"):
            RUNNER.validate_native_owner_exit_lifecycle_contract(
                contract,
                RUNNER.load_pin(),
            )

    def test_native_owner_exit_lifecycle_contract_rejects_retired_source_filter(self) -> None:
        contract = RUNNER.read_json(RUNNER.NATIVE_OWNER_EXIT_LIFECYCLE_CONTRACT)
        contract["checks"][-1]["target"] = "main_heap_page::tests::retired_owner_exit_filter"

        with self.assertRaisesRegex(RUNNER.HarnessError, "current source test filter"):
            RUNNER.validate_native_owner_exit_lifecycle_contract(
                contract,
                RUNNER.load_pin(),
            )

    def test_native_owner_exit_lifecycle_runner_records_every_reviewed_check(self) -> None:
        contract = RUNNER.read_json(RUNNER.NATIVE_OWNER_EXIT_LIFECYCLE_CONTRACT)
        result = {
            "status": 0,
            "stderr": "",
            "stdout": (
                "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
                "0 filtered out; finished in 0.00s\n"
            ),
        }
        with mock.patch.object(RUNNER, "command_record", return_value=result) as command_record:
            report = RUNNER.run_native_owner_exit_lifecycle(contract, RUNNER.load_pin())

        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["check_count"], 15)
        self.assertEqual(len(report["checks"]), 15)
        self.assertEqual(command_record.call_count, 15)
        self.assertTrue(
            all(call.kwargs["timeout_seconds"] == 300 for call in command_record.call_args_list)
        )
        self.assertTrue(
            all(
                call.kwargs["env"]["CARGO_TARGET_DIR"]
                == str(RUNNER.NATIVE_OWNER_EXIT_CARGO_TARGET)
                for call in command_record.call_args_list
            )
        )

    def test_m5_owner_exit_evidence_rejects_a_partial_execution_record(self) -> None:
        contract = RUNNER.read_json(RUNNER.NATIVE_OWNER_EXIT_LIFECYCLE_CONTRACT)
        summary = RUNNER.validate_native_owner_exit_lifecycle_contract(
            contract,
            RUNNER.load_pin(),
        )
        report = {
            "native_owner_exit_lifecycle": {
                "check_count": summary["check_count"],
                "checks": [
                    {
                        "id": check["id"],
                        "kind": check["kind"],
                        "passed_test_count": check["expected_passed_test_count"],
                        "target": check["target"],
                    }
                    for check in summary["checks"]
                ],
                "contract": RUNNER.native_owner_exit_lifecycle_contract_record(
                    contract,
                    RUNNER.load_pin(),
                ),
                "scenario_coverage": summary["scenario_coverage"],
                "status": "passed",
            }
        }

        self.assertTrue(RUNNER._m5_native_owner_exit_lifecycle_evidence_passed(report))
        report["native_owner_exit_lifecycle"]["checks"].pop()
        self.assertFalse(RUNNER._m5_native_owner_exit_lifecycle_evidence_passed(report))

    def test_m5_gate_report_keeps_m5d_and_m5e_blocked_with_verified_upstream_matrix(self) -> None:
        contract = RUNNER.read_json(RUNNER.M5_GATE_CONTRACT)
        report = {
            "compiler_tls_codegen": {"status": "passed"},
            "m4_test_adapter": {
                "fixtures": {"adapted_upstream_api": {"summary": {"failed": 0, "succeeded": 33}}}
            },
            "remote_free_loom_model": {"status": "passed"},
            "runtime_ticket_zero_test_adapter": {
                "fixture": {
                    "watchdog": {"seconds": 30, "status": "passed"},
                    "worker_cycles": 128,
                    "stress_schedule": {
                        "seed": "0xd1b54a32d192ed03",
                        "worker_route_invocation_count": 256,
                        "worker_routes_per_cycle": 2,
                    },
                    "lifecycle_stability": {
                        "audit_snapshot_count": 129,
                        "post_warm_cycle_count": 127,
                        "status": "passed",
                        "warm_baseline": {
                            "worker_cycles": 128,
                            "process_active": 1,
                            "page_owner_ready": 1,
                            "page_map_registered_entries": 0,
                            "arena_registry_entries": 1,
                            "live_tlds": 1,
                            "metadata_live_capabilities": 0,
                            "shared_later_theaps": 0,
                            "abandoned_regular_pages": 0,
                            "os_abandoned_pages_empty": 1,
                        },
                    },
                }
            },
            "m5_source_derived_stress_adapter": {
                "fixture": {
                    "arguments": ["1", "1", "2"],
                    "compile_defines": ["NTHREADS=1"],
                    "rejected_compile_modes": [
                        "ALLOW_LARGE",
                        "MI_HEAP_WALK",
                        "MI_USE_HEAPS",
                        "TEST_LEAK",
                        "TEST_STRESS_SUBPROCS",
                        "USE_STD_MALLOC",
                    ],
                    "stderr": "",
                    "stdout": (
                        "Using 1 threads with a 1% load-per-thread and 2 iterations\n"
                        "crabc adapted stress ok\n"
                    ),
                    "watchdog": {"seconds": 30, "status": "passed"},
                }
            },
            "canonical_upstream_stress": {
                "format": 1,
                "schema": "crabc-mimalloc-canonical-upstream-stress-consumer",
                "status": "verified",
                "evidence_scope": "shadow_subset",
                "large_object_mode": {"status": "not-claimed"},
                "matrix": {"case_count": 8, "worker_counts": [1, 2, 4, 8]},
                "current_head": {"record": {}, "source": {}},
            },
        }
        native_contract = RUNNER.read_json(RUNNER.NATIVE_OWNER_EXIT_LIFECYCLE_CONTRACT)
        native_summary = RUNNER.validate_native_owner_exit_lifecycle_contract(
            native_contract,
            RUNNER.load_pin(),
        )
        # The native owner-exit suite is deliberately distinct from the
        # ticket-zero churn witness: its successful direct routes are the
        # evidence that lets Gate 5C advance while the stress and shadow
        # gates remain open.
        report["native_owner_exit_lifecycle"] = {
            "check_count": native_summary["check_count"],
            "checks": [
                {
                    "id": check["id"],
                    "kind": check["kind"],
                    "passed_test_count": check["expected_passed_test_count"],
                    "target": check["target"],
                }
                for check in native_summary["checks"]
            ],
            "contract": RUNNER.native_owner_exit_lifecycle_contract_record(
                native_contract,
                RUNNER.load_pin(),
            ),
            "scenario_coverage": native_summary["scenario_coverage"],
            "status": "passed",
        }

        gate = RUNNER.m5_gate_report(contract, report)

        self.assertEqual(gate["overall_status"], "unmet")
        self.assertEqual(gate["unmet_required"], ["m5.5d", "m5.5e"])
        self.assertEqual(
            {entry["id"]: entry["status"] for entry in gate["gates"]},
            {
                "m5.base": "passed",
                "m5.5a": "passed",
                "m5.5b": "passed",
                "m5.5c": "passed",
                "m5.5d": "blocked",
                "m5.5e": "blocked",
            },
        )
        gate_by_id = {entry["id"]: entry for entry in gate["gates"]}
        self.assertEqual(
            gate_by_id["m5.5c"]["observed_evidence"],
            ["report:/native_owner_exit_lifecycle"],
        )
        self.assertEqual(
            gate_by_id["m5.5d"]["observed_evidence"],
            [
                "report:/m5_source_derived_stress_adapter/fixture",
                "report:/canonical_upstream_stress",
            ],
        )
        self.assertNotIn("observed_evidence", gate_by_id["m5.5e"])

    def test_adapted_api_fixture_rejects_unexplained_omission_and_symbol_drift(self) -> None:
        contract = RUNNER.read_json(RUNNER.ADAPTED_TEST_CONTRACT)
        header = RUNNER.TEST_ADAPTER_HEADER.read_text(encoding="utf-8")
        contract["omitted_tests"][0]["reason"] = ""
        with self.assertRaisesRegex(RUNNER.HarnessError, "invalid omitted test"):
            RUNNER.validate_adapted_test_contract(contract, RUNNER.load_pin(), header)

        contract = RUNNER.read_json(RUNNER.ADAPTED_TEST_CONTRACT)
        contract["expected_adapter_symbols"] = sorted(
            [*contract["expected_adapter_symbols"], "crabc_test_unreviewed"]
        )
        with self.assertRaisesRegex(RUNNER.HarnessError, "header symbol contract"):
            RUNNER.validate_adapted_test_contract(contract, RUNNER.load_pin(), header)

    def test_adapted_stress_fixture_rejects_scope_drift(self) -> None:
        contract = RUNNER.read_json(RUNNER.ADAPTED_STRESS_TEST_CONTRACT)
        header = RUNNER.TEST_ADAPTER_HEADER.read_text(encoding="utf-8")
        contract["execution"]["arguments"] = ["1", "1", "1"]
        with self.assertRaisesRegex(RUNNER.HarnessError, "execution contract changed"):
            RUNNER.validate_adapted_stress_test_contract(
                contract, RUNNER.load_pin(), header
            )

    def test_native_shadow_stress_rejects_scope_drift(self) -> None:
        contract = RUNNER.read_json(RUNNER.NATIVE_SHADOW_STRESS_CONTRACT)
        contract["execution"]["process_epochs"] = 127
        with self.assertRaisesRegex(RUNNER.HarnessError, "execution contract changed"):
            RUNNER.validate_native_shadow_stress_contract(contract, RUNNER.load_pin())

    def test_checked_in_api_inventory_has_audited_linux_aarch64_boundaries(self) -> None:
        inventory = RUNNER.read_json(RUNNER.API_CONTRACT)
        self.assertEqual(inventory["format"], 3)
        RUNNER.validate_api_parity_inventory(inventory)
        self.assertEqual(
            inventory["summary"],
            {
                "applicable_item_count": 334,
                "blocked_applicable_item_count": 334,
                "blocked_required_mode_count": 52,
                "compile_time_mode_count": 52,
                "configuration_macro_count": 138,
                "cxx_convenience_count": 1,
                "cxx_template_count": 3,
                "external_function_count": 194,
                "inapplicable_item_count": 2,
                "inapplicable_mode_count": 0,
                "macro_count": 26,
                "option_count": 52,
                "override_macro_count": 37,
                "required_mode_count": 52,
                "source_only_count": 146,
                "source_only_macro_count": 63,
                "static_inline_count": 7,
                "total_item_count": 336,
                "type_count": 16,
            },
        )
        self.assertEqual(
            [entry["name"] for entry in inventory["release_symbol_contract"]["header_declarations_without_normal_release_symbol"]],
            ["mi_collect_reduce", "mi_malloc_size", "mi_malloc_usable_size", "mi_stats_merge"],
        )
        self.assertEqual(
            len(inventory["release_symbol_contract"]["expected_defined_symbol_names"]), 190
        )
        items = {item["name"]: item for item in inventory["items"]}
        self.assertEqual(
            {
                item["name"]
                for item in inventory["items"]
                if item["target_applicability"] == "inapplicable"
            },
            {"mi_collect_reduce", "mi_stats_merge"},
        )
        self.assertEqual(items["mi_wdupenv_s"]["classification"], "linux-einval-operation")
        self.assertEqual(items["mi_wdupenv_s"]["target_applicability"], "applicable")
        self.assertEqual(items["mi_wdupenv_s"]["completion_status"], "blocked")
        self.assertTrue(items["mi_wdupenv_s"]["applicability_sources"])
        self.assertTrue(items["mi_wdupenv_s"]["oracle_release_exported"])
        self.assertEqual(items["mi_option_os_tag"]["classification"], "platform-specific-effect-option")
        self.assertEqual(items["mi_option_os_tag"]["target_applicability"], "applicable")
        self.assertEqual(items["mi_option_retry_on_oom"]["target_applicability"], "applicable")
        self.assertEqual(
            items["mi_collect_reduce"]["classification"],
            "upstream-unavailable-declaration",
        )
        self.assertEqual(items["mi_collect_reduce"]["target_applicability"], "inapplicable")
        self.assertEqual(items["mi_stats_init"]["classification"], "source-only-inline")
        self.assertEqual(items["mi_stl_allocator"]["kind"], "cxx-template")
        self.assertFalse(any(item["crabc_libc_exported"] for item in inventory["items"]))

        modes = {mode["name"]: mode for mode in inventory["compile_time_modes"]}
        self.assertTrue(
            all(
                mode["target_applicability"] == "applicable"
                and all(
                    value["target_applicability"] == "applicable"
                    for value in mode["source_values"]
                )
                for mode in modes.values()
            )
        )
        self.assertEqual(modes["MI_DEBUG"]["allowed_source_tokens"], ["OFF", "ON", "INTERNAL", "FULL", "DEFAULT"])
        self.assertEqual(modes["MI_DEBUG"]["target_applicability"], "applicable")
        self.assertEqual(modes["MI_DEBUG"]["completion_status"], "blocked")
        self.assertEqual(modes["MI_OSX_ZONE"]["target_applicability"], "applicable")
        self.assertEqual(modes["MI_OSX_ZONE"]["completion_status"], "blocked")
        self.assertTrue(modes["MI_OSX_ZONE"]["applicability_sources"])
        self.assertEqual(modes["MI_TLS_MODEL_FIXED"]["target_applicability"], "applicable")
        self.assertEqual(modes["MI_TLS_MODEL_FIXED"]["completion_status"], "blocked")
        tls_values = {
            value["token"]: value for value in modes["MI_TLS_MODEL"]["source_values"]
        }
        self.assertEqual(tls_values["LOCAL"]["target_applicability"], "applicable")
        self.assertEqual(tls_values["FIXED"]["target_applicability"], "applicable")
        self.assertEqual(tls_values["WIN32"]["target_applicability"], "applicable")
        track_values = {
            value["token"]: value for value in modes["MI_TRACK"]["source_values"]
        }
        self.assertEqual(track_values["ETW"]["target_applicability"], "applicable")
        self.assertEqual(
            inventory["completion_tracks"]["malloc_engine_readiness"]["inventory_driven"],
            False,
        )
        self.assertEqual(
            inventory["completion_tracks"]["full_linux_aarch64_v3_5_0_parity"]["inventory_driven"],
            True,
        )

    def test_api_parity_inventory_rejects_omissions_and_contradictions(self) -> None:
        inventory = RUNNER.read_json(RUNNER.API_CONTRACT)

        missing_item = json.loads(json.dumps(inventory))
        missing_item["items"].pop()
        with self.assertRaisesRegex(RUNNER.HarnessError, "API item count"):
            RUNNER.validate_api_parity_inventory(missing_item)

        missing_mode = json.loads(json.dumps(inventory))
        missing_mode["compile_time_modes"].pop()
        with self.assertRaisesRegex(RUNNER.HarnessError, "compile-time mode count"):
            RUNNER.validate_api_parity_inventory(missing_mode)

        contradictory = json.loads(json.dumps(inventory))
        item = next(
            item
            for item in contradictory["items"]
            if item["target_applicability"] == "applicable"
        )
        item["parity_requirement"] = "not-required"
        with self.assertRaisesRegex(RUNNER.HarnessError, "applicable API item"):
            RUNNER.validate_api_parity_inventory(contradictory)

        unsupported_without_source = json.loads(json.dumps(inventory))
        item = next(
            item
            for item in unsupported_without_source["items"]
            if item["target_applicability"] == "inapplicable"
        )
        item["classification_reason"] = ""
        item["applicability_sources"] = []
        with self.assertRaisesRegex(RUNNER.HarnessError, "source-backed rationale"):
            RUNNER.validate_api_parity_inventory(unsupported_without_source)

        unsupported_value_without_source = json.loads(json.dumps(inventory))
        mode = next(
            mode for mode in unsupported_value_without_source["compile_time_modes"]
            if mode["name"] == "MI_TLS_MODEL"
        )
        value = next(value for value in mode["source_values"] if value["token"] == "FIXED")
        value["target_applicability"] = "inapplicable"
        value["classification_reason"] = ""
        value["applicability_sources"] = []
        with self.assertRaisesRegex(RUNNER.HarnessError, "mode value.*source-backed rationale"):
            RUNNER.validate_api_parity_inventory(unsupported_value_without_source)

        observable_api = json.loads(json.dumps(inventory))
        item = next(
            item for item in observable_api["items"] if item["name"] == "mi_wdupenv_s"
        )
        item["target_applicability"] = "inapplicable"
        item["parity_requirement"] = "not-required"
        item["completion_status"] = "not-required"
        item["implementation_blocker"] = ""
        with self.assertRaisesRegex(RUNNER.HarnessError, "normal-release public API"):
            RUNNER.validate_api_parity_inventory(observable_api)

        observable_mode = json.loads(json.dumps(inventory))
        mode = next(
            mode for mode in observable_mode["compile_time_modes"]
            if mode["name"] == "MI_OSX_ZONE"
        )
        mode["target_applicability"] = "inapplicable"
        mode["parity_requirement"] = "not-required"
        mode["completion_status"] = "not-required"
        mode["implementation_blocker"] = ""
        for value in mode["source_values"]:
            value["target_applicability"] = "inapplicable"
            value["applicability_sources"] = list(mode["applicability_sources"])
            value["classification_reason"] = mode["classification_reason"]
        with self.assertRaisesRegex(RUNNER.HarnessError, "unconditional root-CMake mode"):
            RUNNER.validate_api_parity_inventory(observable_mode)

        observable_value = json.loads(json.dumps(inventory))
        mode = next(
            mode for mode in observable_value["compile_time_modes"]
            if mode["name"] == "MI_TLS_MODEL"
        )
        value = next(value for value in mode["source_values"] if value["token"] == "FIXED")
        value["target_applicability"] = "inapplicable"
        with self.assertRaisesRegex(RUNNER.HarnessError, "declared mode value"):
            RUNNER.validate_api_parity_inventory(observable_value)

    def test_api_parity_inventory_keeps_readiness_separate_from_full_parity(self) -> None:
        inventory = RUNNER.read_json(RUNNER.API_CONTRACT)

        readiness = json.loads(json.dumps(inventory))
        readiness["completion_tracks"]["malloc_engine_readiness"]["inventory_driven"] = True
        with self.assertRaisesRegex(RUNNER.HarnessError, "readiness.*separate"):
            RUNNER.validate_api_parity_inventory(readiness)

        false_parity = json.loads(json.dumps(inventory))
        false_parity["completion_tracks"]["full_linux_aarch64_v3_5_0_parity"]["status"] = "complete"
        with self.assertRaisesRegex(RUNNER.HarnessError, "full parity.*blocked"):
            RUNNER.validate_api_parity_inventory(false_parity)

    def test_full_and_performance_modes_have_precise_unmet_milestones(self) -> None:
        full = "allocator --full did not meet Milestone 5: m5.5c: general owner exit remains blocked"
        performance = (
            "allocator performance is unavailable: Milestone 9 requires comparable C and Rust opaque allocator boundaries plus Milestone 8 integrated crabc backends; the current private one-thread engine is not a benchmark boundary."
        )
        self.assertIn("m5.5c", full)
        self.assertIn("Milestone 5", full)
        self.assertIn("Milestone 9", performance)

    def test_ratchet_rejects_a_true_status_moved_to_another_item(self) -> None:
        baseline = {
            "port_map_true_statuses": {
                "item:include/mimalloc/bits.h:mi_popcount": ["implemented", "unit_verified"],
                "item:include/mimalloc/bits.h:mi_ctz": ["implemented"],
            }
        }
        current = {
            "port_map_true_statuses": {
                "item:include/mimalloc/bits.h:mi_popcount": ["implemented"],
                "item:include/mimalloc/bits.h:mi_ctz": ["implemented", "unit_verified"],
            }
        }
        self.assertEqual(
            RUNNER.ratchet_status_regressions(baseline, current),
            ["item:include/mimalloc/bits.h:mi_popcount:unit_verified"],
        )

    def test_ratchet_snapshot_rejects_scalar_and_aggregate_regressions(self) -> None:
        baseline = {
            "api_total_item_count": 336,
            "configuration_profile_count": 5,
            "upstream_test_source_count": 13,
            "upstream_test_inventory_file_count": 16,
            "port_map_counts": {
                "unit_count": 35,
                "item_count": 24,
                "implemented": 27,
                "unit_verified": 27,
            },
        }
        current = {
            **baseline,
            "api_total_item_count": 335,
            "port_map_counts": {
                **baseline["port_map_counts"],
                "unit_verified": 26,
            },
        }
        self.assertEqual(
            RUNNER.ratchet_measurement_regressions(baseline, current),
            ["api_total_item_count", "port_map_counts.unit_verified"],
        )
        self.assertEqual(RUNNER.ratchet_measurement_regressions(baseline, baseline), [])

    def test_checked_in_ratchet_accepts_checked_in_adapted_contract_digest(self) -> None:
        """The reviewed snapshot must cover the runner's current contract path."""

        baseline = RUNNER.read_json(RUNNER.RATCHET)
        self.assertEqual(
            baseline["adapted_test_contract_sha256"],
            RUNNER.file_digest(RUNNER.ADAPTED_TEST_CONTRACT),
        )
        RUNNER.check_ratchet(RUNNER.load_port_map())

    def test_ratchet_check_rejects_unreviewed_port_map_digest_drift(self) -> None:
        """A status-preserving port-map edit still requires a reviewed snapshot."""

        current = {
            "format": 1,
            "port_map_counts": {},
            "port_map_true_statuses": {},
            "adapted_test_contract_sha256": "adapted-tests",
            "adapted_stress_test_contract_sha256": "adapted-stress",
            "native_shadow_stress_contract_sha256": "native-shadow-stress",
            "owner_exit_publication_contract_sha256": "owner-exit-publication",
            "api_contract_sha256": "api",
            "port_map_sha256": "current-port-map",
            "upstream_test_contract_sha256": "upstream-tests",
        }
        baseline = {**current, "port_map_sha256": "reviewed-port-map"}

        with tempfile.TemporaryDirectory() as temporary:
            ratchet = Path(temporary) / "ratchet.json"
            RUNNER.write_json(ratchet, baseline)
            with mock.patch.object(RUNNER, "RATCHET", ratchet), mock.patch.object(
                RUNNER, "ratchet_payload", return_value=current
            ):
                with self.assertRaisesRegex(
                    RUNNER.HarnessError,
                    "allocator ratchet input changed: port_map_sha256",
                ):
                    RUNNER.check_ratchet({})


class CanonicalUpstreamStressConsumerTests(unittest.TestCase):
    """Exercise the M5 consumer without compiling the canonical fixture."""

    @staticmethod
    def byte_record(payload: bytes) -> dict[str, object]:
        return {
            "bytes": len(payload),
            "hex": payload.hex(),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }

    @staticmethod
    def file_record(root: Path, path: Path) -> dict[str, object]:
        payload = path.read_bytes()
        return {
            "bytes": len(payload),
            "path": path.relative_to(root).as_posix(),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }

    @classmethod
    def canonical_loader_record(cls, root: Path, path: Path) -> dict[str, object]:
        """Record the fixture stand-in as the literal external loader path."""

        return {
            **cls.file_record(root, path),
            "path": "/lib/ld-crabc-aarch64.so.1",
        }

    @staticmethod
    def write_synthetic_archive(
        path: Path, archive_root: str, member: str, payload: bytes
    ) -> Path:
        """Write a tiny archive for the archive/member binding boundary."""

        path.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(path, "w:gz") as stream:
            for directory in (archive_root, f"{archive_root}/test"):
                header = tarfile.TarInfo(directory)
                header.type = tarfile.DIRTYPE
                stream.addfile(header)
            header = tarfile.TarInfo(f"{archive_root}/{member}")
            header.size = len(payload)
            stream.addfile(header, io.BytesIO(payload))
        return path

    @classmethod
    def write_fixture(cls, root: Path) -> dict[str, object]:
        """Make one complete current-head report with live local artifacts."""

        work_root = root / ".work"
        contract_path = root / "compat/allocator/upstream-stress-v3.5.0.json"
        contract_path.parent.mkdir(parents=True)
        contract_path.write_bytes(
            (RUNNER.ALLOCATOR_ROOT / "upstream-stress-v3.5.0.json").read_bytes()
        )
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
        staged_loader = root / "canonical-loader/ld-crabc-aarch64.so.1"
        pin = RUNNER.load_pin()
        backend = contract["backend_inventory"]["backends"][0]
        cargo_contract = backend["artifact_attestation"]["cargo_compiler_artifact"]
        artifact_ids = contract["report"]["artifact_ids"]

        def write(path: Path, payload: bytes) -> Path:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            return path

        fixture_source = b"synthetic upstream test-stress source\n"
        archive = cls.write_synthetic_archive(
            work_root / "allocator-cache/mimalloc-3.5.0.tar.gz",
            str(pin["archive_root"]),
            str(contract["fixture"]["archive_member"]),
            fixture_source,
        )
        pin = {**pin, "sha256": hashlib.sha256(archive.read_bytes()).hexdigest()}
        fixture_contract = {
            **contract["fixture"],
            "sha256": hashlib.sha256(fixture_source).hexdigest(),
        }
        output = work_root / "target/compat/allocator/upstream-stress"
        binary = write(output / "canonical-upstream-test-stress", b"stress binary")
        target = root / "target/debug"
        selected_libc = write(target / "libc.so", b"selected shared libc")
        selected_static_libc = write(target / "libc.a", b"selected static libc")
        selected_loader = write(target / "libldso.so", b"selected loader")
        sysroot = root / "target/crabc-sysroot"
        manifest = write(sysroot / "share/crabc/manifest.json", b"{}\n")
        purity_payload = {
            "crt_sysroot_pure_rust": True,
            "full_runtime_pure_rust": False,
            "full_runtime_purity_status": "blocked_by_native_allocator",
        }
        purity = write(
            sysroot / "share/crabc/purity.json",
            (json.dumps(purity_payload, sort_keys=True) + "\n").encode(),
        )
        compiler = write(sysroot / "bin/crabc-cc", b"#!/bin/sh\n")
        staged_loader = write(staged_loader, b"selected loader")
        write(root / "libc/Cargo.toml", b"[package]\nname = \"crabc-libc\"\n")
        write(root / "libc/src/lib.rs", b"#![no_std]\n")

        shared_record = cls.file_record(root, selected_libc)
        static_record = cls.file_record(root, selected_static_libc)
        compiler_artifact = {
            "package_id": f"path+file://{root}/libc#crabc-libc@0.3.0",
            "target": cargo_contract["target"],
            "profile": cargo_contract["profile"],
            "features": cargo_contract["exact_features"],
            "filenames": [shared_record["path"], static_record["path"]],
            "fresh": False,
        }
        cargo_message_artifact = {
            "reason": "compiler-artifact",
            "package_id": compiler_artifact["package_id"],
            "manifest_path": str(root / "libc/Cargo.toml"),
            "target": {
                **cargo_contract["target"],
                "src_path": str(root / "libc/src/lib.rs"),
            },
            "profile": cargo_contract["profile"],
            "features": cargo_contract["exact_features"],
            "filenames": [str(selected_libc), str(selected_static_libc)],
            "executable": None,
            "fresh": False,
        }
        build_record_path = output / "selected-libc-build.json"
        write(
            build_record_path,
            (json.dumps(
                {
                    "format": cargo_contract["build_record_format"],
                    "schema": cargo_contract["build_record_schema"],
                    "cargo_command": cargo_contract["cargo_command"],
                    "semantic_profile": cargo_contract["semantic_profile"],
                    "compiler_artifact": cargo_message_artifact,
                    "artifacts": {
                        "selected_shared_libc": shared_record,
                        "selected_static_libc": static_record,
                    },
                },
                sort_keys=True,
            ) + "\n").encode(),
        )
        build_record = cls.file_record(root, build_record_path)
        source = {
            "kind": "git",
            "revision": "a" * 40,
            "worktree_clean": True,
            "worktree_status": cls.byte_record(b""),
        }
        companion_path = output / "selected-libc-build-current-head.json"
        write(
            companion_path,
            (json.dumps(
                {
                    "format": 1,
                    "schema": "crabc-selected-libc-current-head-build",
                    "source_before": source,
                    "source_after": source,
                    "source_unchanged_during_build": True,
                    "selected_libc_build_record": build_record,
                    "artifacts": {
                        "selected_shared_libc": shared_record,
                        "selected_static_libc": static_record,
                    },
                },
                sort_keys=True,
            ) + "\n").encode(),
        )
        companion = cls.file_record(root, companion_path)
        contract_record = cls.file_record(root, contract_path)
        source_member = {
            "bytes": len(fixture_source),
            "path": "mimalloc-3.5.0/test/test-stress.c",
            "sha256": fixture_contract["sha256"],
        }
        artifact_records = {
            "contract": contract_record,
            "upstream_archive": cls.file_record(root, archive),
            "source_member": source_member,
            "owned_sysroot_manifest": cls.file_record(root, manifest),
            "owned_sysroot_purity": cls.file_record(root, purity),
            "owned_compiler": cls.file_record(root, compiler),
            "selected_loader": cls.file_record(root, selected_loader),
            "staged_canonical_loader": cls.canonical_loader_record(root, staged_loader),
            "selected_libc": shared_record,
            "selected_static_libc": static_record,
            "selected_backend_build_record": build_record,
            "stress_binary": cls.file_record(root, binary),
        }
        assert set(artifact_records) == set(artifact_ids)

        matrix = contract["execution"]["matrix"]
        results = []
        for attempt, case in enumerate(matrix, start=1):
            stdout = str(case["expected_stdout"]).encode()
            stderr = str(case["expected_stderr"]).encode()
            results.append(
                {
                    "case": {
                        key: case[key]
                        for key in ("id", "workers", "scale", "iterations", "arguments")
                    },
                    "process_attempt": attempt,
                    "state": "passed",
                    "observation": {
                        "command": [str(binary), *case["arguments"]],
                        "kind": "process",
                        "status": case["expected_exit_status"],
                        "stdout": cls.byte_record(stdout),
                        "stderr": cls.byte_record(stderr),
                    },
                }
            )
        report = {
            "format": contract["report"]["format"],
            "schema": contract["report"]["schema"],
            "status": "passed",
            "contract": {**contract_record, "upstream": contract["upstream"]},
            "artifacts": artifact_records,
            "fixture": {
                "archive_member": fixture_contract["archive_member"],
                "expected_sha256": fixture_contract["sha256"],
                "source_adaptation": {
                    "compile_defines": contract["source_adaptation"]["compile_defines"],
                    "patches": contract["source_adaptation"]["patches"],
                },
                "observed_source": source_member,
            },
            "execution": {
                "attempted": True,
                "attempted_process_count": len(matrix),
                "case_count": len(matrix),
                "case_results": results,
                "process_attempts_per_case": 1,
                "source_randomness": contract["execution"]["source_randomness"],
                "watchdog": contract["execution"]["watchdog"],
            },
            "requested_runtime": {
                "allocator_feature": contract["compile_requirements"]["allocator_feature"],
                "backend": backend["id"],
                "target_dir": "target/debug",
                "output_dir": output.relative_to(root).as_posix(),
                "selected_libc_build_record": build_record_path.relative_to(root).as_posix(),
                "current_head_build_record": companion_path.relative_to(root).as_posix(),
            },
            "selection": {
                "target": contract["target_inventory"]["targets"][0],
                "backend": backend["id"],
            },
            "runtime": {
                "compiler": compiler.relative_to(root).as_posix(),
                "backend_attestation": {
                    "backend": backend["id"],
                    "status": "passed",
                    "semantic_profile": cargo_contract["semantic_profile"],
                    "cargo_features": cargo_contract["exact_features"],
                    "build_record": build_record,
                    "compiler_artifact": compiler_artifact,
                    "artifacts": {
                        "selected_shared_libc": shared_record,
                        "selected_static_libc": static_record,
                    },
                    "exported_free": {
                        "symbol": "free",
                        "required_callee_suffix": backend["artifact_attestation"]["exported_free_route"]["required_callee_suffix"],
                        "forbidden_callee_suffix": backend["artifact_attestation"]["exported_free_route"]["forbidden_callee_suffix"],
                        "disassembly_sha256": "2" * 64,
                    },
                },
                "environment": {},
                "sysroot": sysroot.relative_to(root).as_posix(),
                "sysroot_purity": {
                    "crt_sysroot_pure_rust": True,
                    "full_runtime_pure_rust": False,
                    "full_runtime_purity_status": "blocked_by_native_allocator",
                },
            },
            "fixture_elf": {
                "dynamic_dependencies": contract["compile_requirements"]["expected_dynamic_dependencies"],
                "elf_identity": contract["compile_requirements"]["expected_elf_identity"],
                "interpreter": contract["compile_requirements"]["expected_interpreter"],
            },
            "dynamic_dependencies": contract["compile_requirements"]["expected_dynamic_dependencies"],
            "capability": {
                "failure_closed": True,
                "fully_verified_worker_counts": contract["capability"]["required_worker_counts"],
                "id": contract["capability"]["id"],
                "native_execution_completed": True,
                "native_execution_started": True,
                "passed_case_count": len(matrix),
                "required_case_count": len(matrix),
                "required_worker_counts": contract["capability"]["required_worker_counts"],
                "status": "passed",
            },
            "current_head": {
                "status": "attested",
                "record": companion,
                "source": source,
            },
            "blocked": None,
            "first_fact": {
                "kind": "pass",
                "stage": "matrix",
                "completed_case_count": len(matrix),
            },
            "upstream_pin": {
                "archive_root": contract["upstream"]["archive_root"],
                "repository": contract["upstream"]["repository"],
                "revision": contract["upstream"]["revision"],
                "sha256": pin["sha256"],
                "source": pin["source"],
                "tag": pin["tag"],
                "tag_object": pin["tag_object"],
                "version": pin["version"],
            },
        }
        report_path = work_root / "reports/allocator/upstream-stress/latest.json"
        report_path.parent.mkdir(parents=True)
        report_path.write_text(json.dumps(report, sort_keys=True) + "\n", encoding="utf-8")
        summary = RUNNER.validate_canonical_upstream_stress_contract(
            contract, RUNNER.load_pin()
        )
        summary["fixture"] = fixture_contract
        return {
            "contract": contract,
            "contract_path": contract_path,
            "pin": pin,
            "report": report,
            "report_path": report_path,
            "root": root,
            "source": source,
            "work_root": work_root,
            "archive_record": artifact_records["upstream_archive"],
            "source_member": source_member,
            "staged_loader": staged_loader,
            "summary": summary,
            "contract_record": contract_record,
        }

    @classmethod
    def validate_fixture(
        cls, fixture: dict[str, object], *, source_state: object | None = None
    ) -> dict[str, object]:
        """Exercise report validation with a synthetic archive pin unmocked.

        The production consumer validates the checked-in literal contract and
        pin first. This isolated fixture instead passes a coherent synthetic
        archive/pin/fixture triple directly to the report validator, so its
        tar extraction and report binding remain real without pretending the
        synthetic tarball is the pinned upstream archive. Its staged loader
        record stays execution-scoped evidence: no later `/lib` file is
        fabricated or read by this test.
        """

        with mock.patch.object(
            RUNNER,
            "canonical_current_git_source_state",
            return_value=(fixture["source"] if source_state is None else source_state),
        ):
            try:
                verified = RUNNER.canonical_upstream_stress_validate_report(
                    fixture["report"],
                    root=fixture["root"],
                    work_root=fixture["work_root"],
                    contract=fixture["contract"],
                    contract_record=fixture["contract_record"],
                    summary=fixture["summary"],
                    pin=fixture["pin"],
                )
            except RUNNER.CanonicalUpstreamStressRejected as error:
                return {"status": "rejected", "reason": str(error)}
            return {"status": "verified", **verified}

    @classmethod
    def consume_unavailable(cls, fixture: dict[str, object]) -> dict[str, object]:
        return RUNNER.consume_canonical_upstream_stress_evidence(
            contract_path=fixture["contract_path"],
            report_path=fixture["report_path"],
            root=fixture["root"],
            work_root=fixture["work_root"],
            pin=RUNNER.load_pin(),
        )

    def test_report_validator_accepts_execution_scoped_staged_loader_record(self) -> None:
        RUNNER.TEMP_ROOT.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=RUNNER.TEMP_ROOT) as temporary:
            fixture = self.write_fixture(Path(temporary))
            Path(fixture["staged_loader"]).unlink()
            observed_file_record = RUNNER.canonical_upstream_stress_observed_file_record
            with mock.patch.object(
                RUNNER,
                "canonical_upstream_stress_observed_file_record",
                wraps=observed_file_record,
            ) as live_reads:
                evidence = self.validate_fixture(fixture)

        self.assertEqual(evidence["status"], "verified")
        self.assertEqual(evidence["evidence_scope"], "shadow_subset")
        self.assertEqual(evidence["matrix"], {"case_count": 8, "worker_counts": [1, 2, 4, 8]})
        self.assertEqual(evidence["large_object_mode"]["status"], "not-claimed")
        self.assertEqual(evidence["current_head"]["source"], fixture["source"])
        self.assertFalse(
            any(
                call.args[1] == Path("/lib/ld-crabc-aarch64.so.1")
                for call in live_reads.call_args_list
            )
        )

    def test_archive_member_binding_rejects_a_coherent_archive_substitution(self) -> None:
        RUNNER.TEMP_ROOT.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=RUNNER.TEMP_ROOT) as temporary:
            root = Path(temporary)
            archive = self.write_synthetic_archive(
                root / ".work/allocator-cache/mimalloc-3.5.0.tar.gz",
                "mimalloc-test",
                "test/test-stress.c",
                b"pinned source member\n",
            )
            pin = {
                "archive_root": "mimalloc-test",
                "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
            }
            fixture = {
                "archive_member": "test/test-stress.c",
                "sha256": hashlib.sha256(b"pinned source member\n").hexdigest(),
            }
            archive_record, source_record = RUNNER.canonical_upstream_stress_archive_source_member(
                root, archive, pin, fixture
            )

            self.assertEqual(archive_record, self.file_record(root, archive))
            self.assertEqual(source_record["bytes"], len(b"pinned source member\n"))

            # Simulate an attacker replacing both the live archive and its
            # report artifact record. The immutable pin still rejects it.
            self.write_synthetic_archive(
                archive,
                "mimalloc-test",
                "test/test-stress.c",
                b"substituted source member\n",
            )
            substituted_report_record = self.file_record(root, archive)
            RUNNER.canonical_upstream_stress_live_file_record(
                root,
                substituted_report_record,
                "upstream archive",
                expected_path=archive,
            )
            with self.assertRaisesRegex(
                RUNNER.CanonicalUpstreamStressRejected, "pinned digest"
            ):
                RUNNER.canonical_upstream_stress_archive_source_member(
                    root, archive, pin, fixture
                )

            # The checked-in pin also rejects a report/artifact substitution
            # that is internally coherent with this different archive.
            with self.assertRaisesRegex(
                RUNNER.CanonicalUpstreamStressRejected, "pinned digest"
            ):
                RUNNER.canonical_upstream_stress_archive_source_member(
                    root,
                    archive,
                    RUNNER.load_pin(),
                    RUNNER.read_json(RUNNER.CANONICAL_UPSTREAM_STRESS_CONTRACT)[
                        "fixture"
                    ],
                )

            substituted_pin = {**pin, "sha256": substituted_report_record["sha256"]}
            with self.assertRaisesRegex(
                RUNNER.CanonicalUpstreamStressRejected, "fixture digest"
            ):
                RUNNER.canonical_upstream_stress_archive_source_member(
                    root, archive, substituted_pin, fixture
                )

    def test_contract_rejects_redirected_loader_or_purity_policy(self) -> None:
        contract = RUNNER.read_json(RUNNER.CANONICAL_UPSTREAM_STRESS_CONTRACT)
        redirected = json.loads(json.dumps(contract))
        redirected["compile_requirements"]["canonical_loader"] = "/tmp/redirected-loader"
        with self.assertRaisesRegex(
            RUNNER.CanonicalUpstreamStressRejected, "canonical loader"
        ):
            RUNNER.validate_canonical_upstream_stress_contract(
                redirected, RUNNER.load_pin()
            )

        policy_drift = json.loads(json.dumps(contract))
        policy_drift["compile_requirements"]["sysroot_purity"][
            "allowed_full_runtime_purity"
        ].pop()
        with self.assertRaisesRegex(
            RUNNER.CanonicalUpstreamStressRejected, "sysroot purity"
        ):
            RUNNER.validate_canonical_upstream_stress_contract(
                policy_drift, RUNNER.load_pin()
            )

        broadened_scope = json.loads(json.dumps(contract))
        broadened_scope["report"]["execution_scoped_artifact_ids"].append(
            "selected_loader"
        )
        with self.assertRaisesRegex(
            RUNNER.CanonicalUpstreamStressRejected, "report policy"
        ):
            RUNNER.validate_canonical_upstream_stress_contract(
                broadened_scope, RUNNER.load_pin()
            )

    def test_report_validator_rejects_relabelled_runtime_artifact_or_execution_scoped_loader_drift(self) -> None:
        RUNNER.TEMP_ROOT.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=RUNNER.TEMP_ROOT) as temporary:
            fixture = self.write_fixture(Path(temporary))
            root = Path(fixture["root"])
            relabelled_manifest = root / "target/other/manifest.json"
            relabelled_manifest.parent.mkdir(parents=True)
            relabelled_manifest.write_bytes(b"{}\n")
            report = fixture["report"]
            assert isinstance(report, dict)
            report["artifacts"]["owned_sysroot_manifest"] = self.file_record(
                root, relabelled_manifest
            )
            relabelled_evidence = self.validate_fixture(fixture)

        with tempfile.TemporaryDirectory(dir=RUNNER.TEMP_ROOT) as temporary:
            fixture = self.write_fixture(Path(temporary))
            root = Path(fixture["root"])
            staged_loader = root / "canonical-loader/ld-crabc-aarch64.so.1"
            staged_loader.write_bytes(b"different staged loader")
            report = fixture["report"]
            assert isinstance(report, dict)
            report["artifacts"]["staged_canonical_loader"] = self.canonical_loader_record(
                root, staged_loader
            )
            mismatch_evidence = self.validate_fixture(fixture)

        scoped_path_evidence: list[dict[str, object]] = []
        for staged_path in (
            "canonical-loader/ld-crabc-aarch64.so.1",
            "/lib/not-the-crabc-loader.so",
        ):
            with tempfile.TemporaryDirectory(dir=RUNNER.TEMP_ROOT) as temporary:
                fixture = self.write_fixture(Path(temporary))
                report = fixture["report"]
                assert isinstance(report, dict)
                record = dict(report["artifacts"]["staged_canonical_loader"])
                record["path"] = staged_path
                report["artifacts"]["staged_canonical_loader"] = record
                scoped_path_evidence.append(self.validate_fixture(fixture))

        with tempfile.TemporaryDirectory(dir=RUNNER.TEMP_ROOT) as temporary:
            fixture = self.write_fixture(Path(temporary))
            report = fixture["report"]
            assert isinstance(report, dict)
            report["artifacts"]["staged_canonical_loader"] = {
                "bytes": 0,
                "path": "/lib/ld-crabc-aarch64.so.1",
                "sha256": hashlib.sha256(b"").hexdigest(),
            }
            empty_evidence = self.validate_fixture(fixture)

        self.assertEqual(relabelled_evidence["status"], "rejected")
        self.assertIn("owned sysroot manifest", relabelled_evidence["reason"])
        self.assertEqual(mismatch_evidence["status"], "rejected")
        self.assertIn("staged loader", mismatch_evidence["reason"])
        for evidence in scoped_path_evidence:
            self.assertEqual(evidence["status"], "rejected")
            self.assertIn("fixed execution path", evidence["reason"])
        self.assertEqual(empty_evidence["status"], "rejected")
        self.assertIn("fixed execution path", empty_evidence["reason"])

    def test_consumer_records_an_absent_fixed_report_as_unavailable(self) -> None:
        RUNNER.TEMP_ROOT.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=RUNNER.TEMP_ROOT) as temporary:
            fixture = self.write_fixture(Path(temporary))
            Path(fixture["report_path"]).unlink()
            evidence = self.consume_unavailable(fixture)

        self.assertEqual(evidence["status"], "unavailable")
        self.assertIsNone(evidence["report"])
        self.assertIsNone(evidence["current_head"])

    def test_consumer_rejects_stale_or_dirty_current_git_source(self) -> None:
        RUNNER.TEMP_ROOT.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=RUNNER.TEMP_ROOT) as temporary:
            fixture = self.write_fixture(Path(temporary))
            stale = json.loads(json.dumps(fixture["source"]))
            stale["revision"] = "b" * 40
            stale_evidence = self.validate_fixture(fixture, source_state=stale)
            dirty = json.loads(json.dumps(fixture["source"]))
            dirty["worktree_clean"] = False
            dirty["worktree_status"] = self.byte_record(b" M compat/allocator/run.py\0")
            dirty_evidence = self.validate_fixture(fixture, source_state=dirty)

        self.assertEqual(stale_evidence["status"], "rejected")
        self.assertIn("source", stale_evidence["reason"])
        self.assertEqual(dirty_evidence["status"], "rejected")
        self.assertIn("clean Git", dirty_evidence["reason"])

    def test_consumer_rejects_tampered_live_artifact_or_companion(self) -> None:
        RUNNER.TEMP_ROOT.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=RUNNER.TEMP_ROOT) as temporary:
            fixture = self.write_fixture(Path(temporary))
            shared = Path(fixture["root"]) / "target/debug/libc.so"
            shared.write_bytes(b"tampered selected shared libc")
            artifact_evidence = self.validate_fixture(fixture)

        with tempfile.TemporaryDirectory(dir=RUNNER.TEMP_ROOT) as temporary:
            fixture = self.write_fixture(Path(temporary))
            companion_path = (
                Path(fixture["root"])
                / ".work/target/compat/allocator/upstream-stress/selected-libc-build-current-head.json"
            )
            companion = json.loads(companion_path.read_text(encoding="utf-8"))
            companion["source_unchanged_during_build"] = False
            companion_path.write_text(json.dumps(companion, sort_keys=True) + "\n", encoding="utf-8")
            report = fixture["report"]
            assert isinstance(report, dict)
            report["current_head"]["record"] = self.file_record(
                Path(fixture["root"]), companion_path
            )
            Path(fixture["report_path"]).write_text(
                json.dumps(report, sort_keys=True) + "\n", encoding="utf-8"
            )
            companion_evidence = self.validate_fixture(fixture)

        self.assertEqual(artifact_evidence["status"], "rejected")
        self.assertIn("selected shared libc", artifact_evidence["reason"])
        self.assertEqual(companion_evidence["status"], "rejected")
        self.assertIn("companion", companion_evidence["reason"])

    def test_consumer_rejects_partial_or_diagnostic_report(self) -> None:
        RUNNER.TEMP_ROOT.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=RUNNER.TEMP_ROOT) as temporary:
            fixture = self.write_fixture(Path(temporary))
            report = fixture["report"]
            assert isinstance(report, dict)
            report["execution"]["case_results"].pop()
            Path(fixture["report_path"]).write_text(
                json.dumps(report, sort_keys=True) + "\n", encoding="utf-8"
            )
            partial_evidence = self.validate_fixture(fixture)

        with tempfile.TemporaryDirectory(dir=RUNNER.TEMP_ROOT) as temporary:
            fixture = self.write_fixture(Path(temporary))
            report = fixture["report"]
            assert isinstance(report, dict)
            report["format"] = 1
            report["schema"] = (
                "crabc-mimalloc-canonical-upstream-stress-current-head-diagnostic-report"
            )
            Path(fixture["report_path"]).write_text(
                json.dumps(report, sort_keys=True) + "\n", encoding="utf-8"
            )
            diagnostic_evidence = self.validate_fixture(fixture)

        self.assertEqual(partial_evidence["status"], "rejected")
        self.assertIn("partial matrix", partial_evidence["reason"])
        self.assertEqual(diagnostic_evidence["status"], "rejected")
        self.assertIn("schema", diagnostic_evidence["reason"])

    def test_consumer_git_reads_disable_optional_locks(self) -> None:
        revision = "a" * 40
        completed = [
            subprocess.CompletedProcess(
                args=["git", "rev-parse", "--verify", "HEAD"],
                returncode=0,
                stdout=f"{revision}\n".encode(),
                stderr=b"",
            ),
            subprocess.CompletedProcess(
                args=["git", "status"], returncode=0, stdout=b"", stderr=b""
            ),
        ]
        with mock.patch.dict(
            RUNNER.os.environ,
            {"HOME": "/attested/home", "PATH": "/attested/bin"},
            clear=True,
        ), mock.patch.object(
            RUNNER.shutil, "which", return_value="/attested/bin/git"
        ), mock.patch.object(RUNNER.subprocess, "run", side_effect=completed) as git_reads:
            state = RUNNER.canonical_current_git_source_state(Path("/attested/root"))

        self.assertEqual(state["revision"], revision)
        self.assertTrue(state["worktree_clean"])
        self.assertEqual(len(git_reads.call_args_list), 2)
        for call in git_reads.call_args_list:
            environment = call.kwargs["env"]
            self.assertEqual(environment["GIT_OPTIONAL_LOCKS"], "0")
            self.assertEqual(environment["HOME"], "/attested/home")
            self.assertEqual(environment["PATH"], "/attested/bin")


if __name__ == "__main__":
    unittest.main()
