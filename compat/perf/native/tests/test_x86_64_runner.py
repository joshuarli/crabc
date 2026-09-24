"""Focused contract tests for the native x86 Rust-facade companion runner."""

from __future__ import annotations

import copy
import json
import contextlib
import io
import importlib.util
import os
import sys
import signal
import time
import tempfile
import tomllib
import unittest
import unittest.mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
MODULE = ROOT / "compat/perf/native/x86_64_runner.py"
SPEC = importlib.util.spec_from_file_location("crabc_perf_native_x86", MODULE)
assert SPEC is not None and SPEC.loader is not None
native_x86 = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = native_x86
SPEC.loader.exec_module(native_x86)


ROW_NAMES = (
    "native_x86::caller_buffer",
    "native_x86::missing_error",
    "native_x86::frozen::clock_gettime",
    "native_x86::frozen::getpid",
    "native_x86::frozen::open_close",
)
RESOURCE_KEYS = (
    "user_cpu_ns",
    "system_cpu_ns",
    "voluntary_context_switches",
    "involuntary_context_switches",
    "minor_page_faults",
    "major_page_faults",
    "rss_bytes",
    "pss_bytes",
)

CORRECTNESS_OUTPUT = """native_x86
├─ caller_buffer
├─ missing_error
╰─ frozen
   ├─ clock_gettime
   ├─ getpid
   ╰─ open_close

"""


def raw_report(*, sample_count: int = 2, sample_size: int = 3) -> dict[str, object]:
    benchmarks: list[dict[str, object]] = []
    for index, name in enumerate(ROW_NAMES):
        resources: dict[str, object] = {
            "status": "supported",
            "memory_status": "supported",
        }
        resources.update({key: index + 1 for key in RESOURCE_KEYS})
        benchmarks.append(
            {
                "name": name,
                "median_ns": index + 10,
                "alloc_count": index,
                "alloc_bytes": index * 8,
                "max_alloc_count": index,
                "max_alloc_bytes": index * 8,
                "sample_count": sample_count,
                "iter_count": sample_count * sample_size,
                "process_resources": resources,
            }
        )
    return {"schema": 1, "benchmarks": benchmarks}


def synthetic_metadata(
    profile: dict[str, object],
    backend: str,
    *,
    workspace_manifest: str = "/workspace/.work/x86_64/native-facade-test/workspace/Cargo.toml",
    cargo_home_execution: str = "/workspace/.work/x86_64/native-facade-test/cargo-home",
) -> tuple[dict[str, object], str]:
    """Construct one complete, target-filtered Cargo metadata graph in memory."""
    expected = profile["dependency_policy"][f"active_{backend}"]  # type: ignore[index]
    packages: list[dict[str, object]] = []
    nodes: list[dict[str, object]] = []
    root_id = "path+file:///workspace/.work/x86_64/native-facade-test/workspace#crabc-perf-native-x86@0.0.0"
    for entry in expected:  # type: ignore[union-attr]
        name, version = entry.rsplit("@", 1)
        key = f"{name}@{version}"
        source_kind = native_x86.PATH_DEPENDENCY_SOURCE_KINDS.get(key, "cargo-registry")
        package_id = root_id if key == "crabc-perf-native-x86@0.0.0" else f"package:{key}"
        if source_kind == "workspace":
            manifest_path = workspace_manifest
        elif source_kind == "rustybench":
            suffix = "macros/Cargo.toml" if name == "rustybench-macros" else "Cargo.toml"
            manifest_path = f"/inputs/rustybench/{suffix}"
        elif source_kind == "rustix":
            manifest_path = "/inputs/rustix/Cargo.toml"
        elif source_kind == "crabc-rs":
            manifest_path = "/workspace/crabc-rs/Cargo.toml"
        elif source_kind == "crabc-core":
            manifest_path = "/workspace/crabc-core/Cargo.toml"
        else:
            manifest_path = (
                f"{cargo_home_execution}/registry/src/"
                f"index.crates.io-1949cf8c6b5b557f/{name}-{version}/Cargo.toml"
            )
        packages.append(
            {
                "id": package_id,
                "name": name,
                "version": version,
                "source": None if source_kind != "cargo-registry" else "registry+https://github.com/rust-lang/crates.io-index",
                "manifest_path": manifest_path,
            }
        )
        nodes.append(
            {
                "id": package_id,
                "features": list(native_x86.EXPECTED_ACTIVE_FEATURES[backend][key]),
            }
        )
    return {
        "packages": packages,
        "resolve": {"root": root_id, "nodes": nodes},
        "workspace_root": workspace_manifest.removesuffix("/Cargo.toml"),
        "workspace_members": [root_id],
        "workspace_default_members": [root_id],
    }, workspace_manifest


def command_record(
    root: Path,
    directory: Path,
    *,
    cwd: Path,
    cpu: int,
    argv: list[str] | None = None,
    stdout_bytes: bytes = b"",
) -> dict[str, object]:
    """Retain a minimal successful command record for reader-boundary tests."""

    stdout = directory / "stdout"
    stderr = directory / "stderr"
    status = directory / "status"
    stdout.write_bytes(stdout_bytes)
    stderr.write_bytes(b"")
    status.write_text(f"Pid:\t12345\nCpus_allowed_list:\t{cpu}\n", encoding="utf-8")
    return {
        "argv": ["true"] if argv is None else argv,
        "cwd": native_x86._work_relative(root, cwd),
        "returncode": 0,
        "child_pid": 12345,
        "elapsed_wall_ns": 1,
        "stdout": {"path": native_x86._work_relative(root, stdout), **native_x86.file_identity(stdout)},
        "stderr": {"path": native_x86._work_relative(root, stderr), **native_x86.file_identity(stderr)},
        "status": {"path": native_x86._work_relative(root, status), **native_x86.file_identity(status)},
    }


def metadata_graph_fixture(directory: Path, backend: str) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    """Make a physical, minimal source closure for dependency-reader replay."""

    profile = native_x86.load_profile(ROOT)
    workspace = directory / "workspace"
    cargo_home = directory / "cargo-home"
    rustybench = directory / "rustybench"
    rustix = directory / "rustix"
    workspace.mkdir()
    cargo_home.mkdir()
    rustybench.mkdir()
    (rustybench / "macros").mkdir()
    rustix.mkdir()
    for path in (workspace / "Cargo.toml", rustybench / "Cargo.toml", rustybench / "macros/Cargo.toml", rustix / "Cargo.toml"):
        path.write_text("[package]\nname = 'fixture'\nversion = '0.0.0'\n", encoding="utf-8")

    workspace_manifest = native_x86._execution_path_for_logical(
        f"{native_x86._work_relative(ROOT, workspace)}/Cargo.toml", "fixture workspace manifest",
    )
    cargo_home_execution = native_x86._execution_path_for_logical(
        native_x86._work_relative(ROOT, cargo_home), "fixture Cargo home",
    )
    metadata, _ = synthetic_metadata(
        profile,
        backend,
        workspace_manifest=workspace_manifest,
        cargo_home_execution=cargo_home_execution,
    )
    registry_packages = [package for package in metadata["packages"] if package["source"] is not None]
    for package in registry_packages:
        source_root = cargo_home / "registry/src/index.crates.io-1949cf8c6b5b557f" / f"{package['name']}-{package['version']}"
        source_root.mkdir(parents=True)
        (source_root / "Cargo.toml").write_text(
            f"[package]\nname = {package['name']!r}\nversion = {package['version']!r}\n",
            encoding="utf-8",
        )
    lock_lines = ["version = 4", ""]
    for package in registry_packages:
        lock_lines.extend(
            (
                "[[package]]",
                f"name = {package['name']!r}",
                f"version = {package['version']!r}",
                f"source = {package['source']!r}",
                f"checksum = {'a' * 64!r}",
                "",
            )
        )
    (workspace / "Cargo.lock").write_text("\n".join(lock_lines), encoding="utf-8")
    # Collection runs inside Docker, so its source paths are host paths only
    # while this focused host fixture captures tree identities.  Replay then
    # receives the real retained `/workspace` and `/inputs` metadata bytes.
    capture_metadata = copy.deepcopy(metadata)
    for package in capture_metadata["packages"]:
        raw_manifest = package["manifest_path"]
        if raw_manifest.startswith("/inputs/rustybench/"):
            package["manifest_path"] = str(rustybench / raw_manifest.removeprefix("/inputs/rustybench/"))
        elif raw_manifest.startswith("/inputs/rustix/"):
            package["manifest_path"] = str(rustix / raw_manifest.removeprefix("/inputs/rustix/"))
        elif raw_manifest.startswith("/workspace/crabc-rs/"):
            package["manifest_path"] = str(ROOT / "crabc-rs" / raw_manifest.removeprefix("/workspace/crabc-rs/"))
        elif raw_manifest.startswith("/workspace/crabc-core/"):
            package["manifest_path"] = str(ROOT / "crabc-core" / raw_manifest.removeprefix("/workspace/crabc-core/"))
        elif raw_manifest.startswith(f"{cargo_home_execution}/"):
            package["manifest_path"] = str(cargo_home / raw_manifest.removeprefix(f"{cargo_home_execution}/"))
        elif raw_manifest == workspace_manifest:
            package["manifest_path"] = str(workspace / "Cargo.toml")
        else:
            raise AssertionError(f"unmapped fixture manifest {raw_manifest!r}")
    capture_metadata["workspace_root"] = str(workspace)
    metadata_path = directory / "metadata.json"
    metadata_path.write_text(json.dumps(capture_metadata, sort_keys=True), encoding="utf-8")
    captured = native_x86._capture_dependency_graph(
        ROOT,
        profile,
        invocation=directory,
        workspace=workspace,
        cargo_home=cargo_home,
        rustybench_source=rustybench,
        rustix_source=rustix,
        backend=backend,
        command={"stdout_path": metadata_path},
    )
    metadata_path.write_text(json.dumps(metadata, sort_keys=True), encoding="utf-8")
    metadata_record = {
        "path": native_x86._work_relative(ROOT, metadata_path),
        **native_x86.file_identity(metadata_path),
    }
    graph = {"metadata": metadata_record, "packages": captured["packages"]}
    metadata_command = {
        "argv": ["cargo", "metadata", "--manifest-path", workspace_manifest],
        "stdout": metadata_record,
    }
    context = {
        "profile": profile,
        "workspace": workspace,
        "cargo_home": cargo_home,
        "rustybench": rustybench,
        "rustix": rustix,
        "cargo_home_execution": cargo_home_execution,
        "metadata_path": metadata_path,
    }
    return context, graph, metadata_command


class RawReportTests(unittest.TestCase):
    def test_exact_five_row_raw_report_recomputes_derived_metrics(self) -> None:
        result = native_x86.validate_benchmark_report(
            raw_report(), ROW_NAMES, sample_count=2, sample_size=3,
        )
        self.assertEqual(result["row_count"], 5)
        self.assertEqual(result["total_median_ns"], sum(range(10, 15)))
        self.assertEqual(result["total_user_cpu_ns"], sum(range(1, 6)))
        self.assertEqual(result["total_minor_page_faults"], sum(range(1, 6)))
        self.assertEqual(result["total_max_alloc_bytes"], sum(index * 8 for index in range(5)))

    def test_raw_report_rejects_duplicate_missing_and_absent_resource_values(self) -> None:
        duplicate = raw_report()
        duplicate["benchmarks"][1]["name"] = ROW_NAMES[0]  # type: ignore[index]
        with self.assertRaisesRegex(native_x86.RunnerError, "duplicate|missing"):
            native_x86.validate_benchmark_report(duplicate, ROW_NAMES, sample_count=2, sample_size=3)

        missing_resource = raw_report()
        del missing_resource["benchmarks"][0]["process_resources"]["pss_bytes"]  # type: ignore[index]
        with self.assertRaisesRegex(native_x86.RunnerError, "pss_bytes"):
            native_x86.validate_benchmark_report(
                missing_resource, ROW_NAMES, sample_count=2, sample_size=3,
            )

        null_resource = raw_report()
        null_resource["benchmarks"][0]["process_resources"]["user_cpu_ns"] = None  # type: ignore[index]
        with self.assertRaisesRegex(native_x86.RunnerError, "user_cpu_ns"):
            native_x86.validate_benchmark_report(
                null_resource, ROW_NAMES, sample_count=2, sample_size=3,
            )

    def test_raw_report_rejects_sample_and_iteration_drift(self) -> None:
        drifted = raw_report()
        drifted["benchmarks"][0]["iter_count"] = 5  # type: ignore[index]
        with self.assertRaisesRegex(native_x86.RunnerError, "iter_count"):
            native_x86.validate_benchmark_report(drifted, ROW_NAMES, sample_count=2, sample_size=3)


class AdmissionAndPathTests(unittest.TestCase):
    def test_full_mode_waits_for_every_ordered_predecessor_gate(self) -> None:
        with self.assertRaisesRegex(native_x86.RunnerError, "capability.accounting: ready, no qualification execution receipt"):
            native_x86.require_admitted_mode("full", ROOT)
        admitted = {"status": "available", "owner": "ordered chain", "unmet": []}
        with unittest.mock.patch.object(native_x86, "correctness_admission", return_value=admitted):
            self.assertEqual(native_x86.require_admitted_mode("full", ROOT), (5, 100, 1000))

    def test_cli_refuses_full_mode_before_it_requires_any_source_argument(self) -> None:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self.assertEqual(native_x86.main(["--mode", "full", "--report", "/unused.json"]), 2)
        self.assertIn("full mode is unavailable pending", stderr.getvalue())
        self.assertIn("compat.abi-differential: ready, no qualification execution receipt", stderr.getvalue())

    def test_full_admission_query_fails_closed_and_names_open_gates(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            self.assertEqual(native_x86.main(["--full-admission"]), 2)
        self.assertEqual(json.loads(stdout.getvalue())["status"], "unavailable")
        self.assertIn("capability.accounting: ready, no qualification execution receipt", stderr.getvalue())

    def test_timed_invocations_follow_correctness_and_alternate_backend_order(self) -> None:
        self.assertEqual(native_x86.invocation_roster(1), [
            ("crabc", "correctness"), ("rustix", "correctness"), ("crabc", "reduced"), ("rustix", "reduced"),
        ])
        full = native_x86.invocation_roster(5)
        self.assertEqual(full[:2], [("crabc", "correctness"), ("rustix", "correctness")])
        timed = full[2:]
        self.assertEqual(len(timed), 10)
        self.assertEqual([timed[index][0] for index in range(0, 10, 2)], ["crabc", "rustix", "crabc", "rustix", "crabc"])
        self.assertEqual(sum(backend == "crabc" for backend, _kind in timed), 5)

    def test_smoke_mode_is_the_fixed_reduced_geometry(self) -> None:
        self.assertEqual(native_x86.require_admitted_mode("smoke"), (1, 2, 3))

    def test_direct_rustybench_invocations_explicitly_select_the_bench_action(self) -> None:
        artifact = Path("/private/target/native_x86")
        self.assertEqual(
            native_x86.rustybench_invocation_argv(artifact, kind="correctness"),
            [str(artifact), "--test"],
        )
        self.assertEqual(
            native_x86.rustybench_invocation_argv(
                artifact, kind="reduced", sample_count=2, sample_size=3,
            ),
            [
                str(artifact), "--bench", "--format", "json", "--sample-count", "2",
                "--sample-size", "3",
            ],
        )
        with self.assertRaisesRegex(native_x86.RunnerError, "geometry"):
            native_x86.rustybench_invocation_argv(
                artifact, kind="reduced", sample_count=0, sample_size=3,
            )
        with self.assertRaisesRegex(native_x86.RunnerError, "unknown"):
            native_x86.rustybench_invocation_argv(artifact, kind="foreign")

    def test_correctness_discovery_is_an_exact_five_row_roster(self) -> None:
        native_x86.validate_correctness_stdout(CORRECTNESS_OUTPUT)
        with self.assertRaisesRegex(native_x86.RunnerError, "roster"):
            native_x86.validate_correctness_stdout(CORRECTNESS_OUTPUT + "├─ foreign\n")

    def test_profile_contract_rejects_a_changed_row_source_or_image(self) -> None:
        with (ROOT / "compat/perf/native/x86_64_profile.toml").open("rb") as stream:
            profile = tomllib.load(stream)
        native_x86.validate_profile_contract(profile)

        changed_row = copy.deepcopy(profile)
        changed_row["rows"][0]["source"] = "frozen"
        with self.assertRaisesRegex(native_x86.RunnerError, "row contract"):
            native_x86.validate_profile_contract(changed_row)

        changed_image = copy.deepcopy(profile)
        changed_image["execution"]["image"] = "untrusted"
        with self.assertRaisesRegex(native_x86.RunnerError, "image"):
            native_x86.validate_profile_contract(changed_image)

    def test_active_dependency_roster_rejects_a_subset_or_extra_package(self) -> None:
        with (ROOT / "compat/perf/native/x86_64_profile.toml").open("rb") as stream:
            profile = tomllib.load(stream)
        expected = profile["dependency_policy"]["active_crabc"]
        records = [
            {"name": item.rsplit("@", 1)[0], "version": item.rsplit("@", 1)[1]}
            for item in expected
        ]
        native_x86.validate_active_dependency_roster(profile, "crabc", records)
        with self.assertRaisesRegex(native_x86.RunnerError, "roster"):
            native_x86.validate_active_dependency_roster(profile, "crabc", records[:-1])
        with self.assertRaisesRegex(native_x86.RunnerError, "roster"):
            native_x86.validate_active_dependency_roster(
                profile, "crabc", [*records, {"name": "foreign", "version": "9"}],
            )

    def test_dependency_source_kind_cannot_substitute_a_registry_copy_for_a_pinned_path_input(self) -> None:
        native_x86.validate_dependency_source_kinds(
            "crabc",
            [
                {
                    "name": "rustybench",
                    "version": "0.1.0",
                    "source_kind": "rustybench",
                    "source": None,
                },
                {
                    "name": "itoa",
                    "version": "1.0.18",
                    "source_kind": "cargo-registry",
                    "source": "registry+https://github.com/rust-lang/crates.io-index",
                },
            ],
        )
        with self.assertRaisesRegex(native_x86.RunnerError, "source root"):
            native_x86.validate_dependency_source_kinds(
                "crabc",
                [
                    {
                        "name": "rustybench",
                        "version": "0.1.0",
                        "source_kind": "cargo-registry",
                        "source": "registry+https://github.com/rust-lang/crates.io-index",
                    },
                ],
            )

    def test_report_and_work_paths_must_stay_in_this_checkout_work_boundary(self) -> None:
        work_root = ROOT / ".work/x86_64"
        self.assertEqual(native_x86.require_private_work_path(ROOT, work_root), work_root.resolve())
        with self.assertRaisesRegex(native_x86.RunnerError, "below"):
            native_x86.require_private_work_path(ROOT, ROOT / "compat")
        with tempfile.TemporaryDirectory(dir=work_root) as temporary_text:
            temporary = Path(temporary_text)
            foreign = temporary / "escape"
            foreign.symlink_to(ROOT / "compat", target_is_directory=True)
            with self.assertRaisesRegex(native_x86.RunnerError, "physical"):
                native_x86.require_private_work_path(ROOT, foreign)


class ReaderBoundaryTests(unittest.TestCase):
    def _validate_graph(
        self,
        context: dict[str, object],
        graph: dict[str, object],
        metadata_command: dict[str, object],
        backend: str,
    ) -> None:
        native_x86._validate_dependency_graph(
            ROOT,
            context["profile"],  # type: ignore[arg-type]
            graph,
            workspace=context["workspace"],  # type: ignore[arg-type]
            cargo_home=context["cargo_home"],  # type: ignore[arg-type]
            rustybench_source=context["rustybench"],  # type: ignore[arg-type]
            rustix_source=context["rustix"],  # type: ignore[arg-type]
            execution_sources=native_x86.EXPECTED_EXECUTION_SOURCES,
            cargo_home_execution=context["cargo_home_execution"],  # type: ignore[arg-type]
            metadata_command=metadata_command,
            backend=backend,
        )

    def _refresh_metadata_identity(
        self,
        context: dict[str, object],
        graph: dict[str, object],
        metadata_command: dict[str, object],
    ) -> None:
        metadata_path = context["metadata_path"]
        assert isinstance(metadata_path, Path)
        metadata_record = {
            "path": native_x86._work_relative(ROOT, metadata_path),
            **native_x86.file_identity(metadata_path),
        }
        graph["metadata"] = metadata_record
        metadata_command["stdout"] = metadata_record

    def test_dependency_reader_rebuilds_claims_from_raw_metadata_resolve(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".work/x86_64") as temporary_text:
            context, graph, metadata_command = metadata_graph_fixture(Path(temporary_text), "crabc")
            self._validate_graph(context, graph, metadata_command, "crabc")
            detached_command = copy.deepcopy(metadata_command)
            detached_command["stdout"]["sha256"] = "0" * 64
            with self.assertRaisesRegex(native_x86.RunnerError, "metadata command stdout"):
                self._validate_graph(context, graph, detached_command, "crabc")

            # Keep the complete expected name/version roster but make raw Cargo
            # select a different same-named package id.  The old reader parsed
            # this file only for lock checksums and accepted the retained graph.
            metadata_path = context["metadata_path"]
            assert isinstance(metadata_path, Path)
            forged = json.loads(metadata_path.read_text(encoding="utf-8"))
            original = next(package for package in forged["packages"] if package["name"] == "crabc-rs")
            replacement = dict(original)
            replacement["id"] = "package:forged-crabc-rs@0.3.0"
            forged["packages"].append(replacement)
            for node in forged["resolve"]["nodes"]:
                if node["id"] == original["id"]:
                    node["id"] = replacement["id"]
            metadata_path.write_text(json.dumps(forged, sort_keys=True), encoding="utf-8")
            self._refresh_metadata_identity(context, graph, metadata_command)
            with self.assertRaisesRegex(native_x86.RunnerError, "raw Cargo metadata"):
                self._validate_graph(context, graph, metadata_command, "crabc")

    def test_dependency_reader_replays_exact_target_filtered_features(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".work/x86_64") as temporary_text:
            context, graph, metadata_command = metadata_graph_fixture(Path(temporary_text), "rustix")
            self._validate_graph(context, graph, metadata_command, "rustix")
            metadata_path = context["metadata_path"]
            assert isinstance(metadata_path, Path)
            forged = json.loads(metadata_path.read_text(encoding="utf-8"))
            rustix_node = next(node for node in forged["resolve"]["nodes"] if node["id"] == "package:rustix@1.1.4")
            rustix_node["features"] = ["std"]
            metadata_path.write_text(json.dumps(forged, sort_keys=True), encoding="utf-8")
            self._refresh_metadata_identity(context, graph, metadata_command)
            with self.assertRaisesRegex(native_x86.RunnerError, "feature"):
                self._validate_graph(context, graph, metadata_command, "rustix")

    def test_tool_record_replay_rejects_commit_version_and_target_drift(self) -> None:
        valid = {
            "rustc": (
                "rustc 1.100.0-nightly (574ff7d98 2026-09-14)\n"
                "binary: rustc\n"
                "commit-hash: 574ff7d98bd6d037e5236a8453029173b32631fd\n"
                "commit-date: 2026-09-14\n"
                "host: x86_64-unknown-linux-musl\n"
                "release: 1.100.0-nightly\n"
            ),
            "cargo": "cargo 1.100.0-nightly (7941be6fb 2026-09-11)\n",
            "rustup": "x86_64-unknown-linux-musl\n",
        }
        drifted = {
            "rustc": valid["rustc"].replace("574ff7d98bd6d037e5236a8453029173b32631fd", "0" * 40),
            "cargo": "cargo 9.9.9\n",
            "rustup": "x86_64-unknown-linux-musl\naarch64-unknown-linux-musl\n",
        }
        cpu = min(os.sched_getaffinity(0))
        with tempfile.TemporaryDirectory(dir=ROOT / ".work/x86_64") as temporary_text:
            temporary = Path(temporary_text)
            for name in ("rustc", "cargo", "rustup"):
                directory = temporary / name
                directory.mkdir()
                tool_file = directory / name
                tool_file.write_text("tool identity fixture\n", encoding="utf-8")
                valid_command = command_record(
                    ROOT,
                    directory,
                    cwd=directory,
                    cpu=cpu,
                    argv=native_x86._tool_argv(name),
                    stdout_bytes=valid[name].encode("utf-8"),
                )
                valid_record = {
                    "path": f"/tool/{name}",
                    "file": native_x86.file_identity(tool_file),
                    "command": valid_command,
                }
                native_x86._validate_tool_record(ROOT, valid_record, cpu=cpu, name=name)

                drifted_command = command_record(
                    ROOT,
                    directory,
                    cwd=directory,
                    cpu=cpu,
                    argv=native_x86._tool_argv(name),
                    stdout_bytes=drifted[name].encode("utf-8"),
                )
                drifted_record = {**valid_record, "command": drifted_command}
                with self.assertRaisesRegex(native_x86.RunnerError, "commit|cargo|target roster"):
                    native_x86._validate_tool_record(ROOT, drifted_record, cpu=cpu, name=name)

    def test_existing_invocation_reader_binds_execution_prefix_and_workspace_cwd(self) -> None:
        cpu = min(os.sched_getaffinity(0))
        profile = native_x86.load_profile(ROOT)
        with tempfile.TemporaryDirectory(dir=ROOT / ".work/x86_64") as temporary_text:
            temporary = Path(temporary_text)
            workspace = temporary / "workspace"
            sibling = temporary / "sibling"
            workspace.mkdir()
            sibling.mkdir()
            artifact = workspace / "native_x86"
            artifact.write_bytes(b"fixture executable\n")
            artifact.chmod(0o700)
            logical_program = native_x86._work_relative(ROOT, artifact)

            def invocation(cwd: Path, raw_program: str) -> dict[str, object]:
                command = command_record(
                    ROOT,
                    temporary,
                    cwd=cwd,
                    cpu=cpu,
                    argv=[raw_program, "--test"],
                    stdout_bytes=CORRECTNESS_OUTPUT.encode("utf-8"),
                )
                command["logical_argv"] = [logical_program, "--test"]
                return {"backend": "crabc", "kind": "correctness", "command": command}

            with self.assertRaisesRegex(native_x86.RunnerError, "workspace cwd"):
                native_x86._validate_invocation(
                    ROOT,
                    profile,
                    invocation(sibling, f"/workspace/{logical_program}"),
                    expected_backend="crabc",
                    expected_kind="correctness",
                    artifact=artifact,
                    workspace=workspace,
                    cpu=cpu,
                    mode="smoke",
                )
            with self.assertRaisesRegex(native_x86.RunnerError, "execution path"):
                native_x86._validate_invocation(
                    ROOT,
                    profile,
                    invocation(workspace, f"/foreign/{logical_program}"),
                    expected_backend="crabc",
                    expected_kind="correctness",
                    artifact=artifact,
                    workspace=workspace,
                    cpu=cpu,
                    mode="smoke",
                )

            regular = temporary / "not-a-directory"
            regular.write_text("not a cwd\n", encoding="utf-8")
            regular_command = command_record(ROOT, temporary, cwd=regular, cpu=cpu)
            with self.assertRaisesRegex(native_x86.RunnerError, "directory"):
                native_x86._validate_command(ROOT, regular_command, cpu=cpu, label="regular cwd")

    def test_completed_command_cleans_a_descendant_process_group(self) -> None:
        cpu = min(os.sched_getaffinity(0))
        with tempfile.TemporaryDirectory(dir=ROOT / ".work/x86_64") as temporary_text:
            invocation = Path(temporary_text)
            descendant_path = invocation / "descendant.pid"
            script = (
                "import pathlib, subprocess, sys; "
                "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)']); "
                f"pathlib.Path({str(descendant_path)!r}).write_text(str(child.pid)); "
            )
            descendant_pid: int | None = None
            try:
                result = native_x86._run_retained_command(
                    invocation,
                    stage="leader-with-descendant",
                    argv=[sys.executable, "-c", script],
                    cwd=invocation,
                    environment={"PATH": os.environ.get("PATH", "")},
                    cpu=cpu,
                    timeout_seconds=5,
                )
                self.assertEqual(result["returncode"], 0)
                descendant_pid = int(descendant_path.read_text(encoding="utf-8"))
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    status = Path(f"/proc/{descendant_pid}/stat")
                    try:
                        stat_text = status.read_text(encoding="utf-8")
                    except FileNotFoundError:
                        break
                    # SIGKILL can leave an orphan as a short-lived zombie until
                    # the container init/subreaper reaps it.  That is already
                    # terminated; only a non-zombie member means the owned
                    # process group escaped its cleanup.
                    suffix = stat_text.rsplit(")", 1)[-1].split()
                    if suffix and suffix[0] == "Z":
                        break
                    time.sleep(0.02)
                else:
                    self.fail("completed command left its descendant process alive")
            finally:
                if descendant_pid is not None:
                    try:
                        os.kill(descendant_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        os.waitpid(descendant_pid, os.WNOHANG)
                    except ChildProcessError:
                        pass


class ProvenanceTests(unittest.TestCase):
    def test_static_pie_elf_contract_rejects_a_dynamic_interpreter(self) -> None:
        header = "\n".join(
            (
                "Class:                             ELF64",
                "Data:                              2's complement, little endian",
                "Type:                              DYN (Position-Independent Executable file)",
                "Machine:                           Advanced Micro Devices X86-64",
            )
        )
        native_x86._validate_elf_text(header, "test")
        with self.assertRaisesRegex(native_x86.RunnerError, "dynamic runtime"):
            native_x86._validate_elf_text(header + "\n  INTERP", "test")

    def test_tree_identity_rejects_a_changed_source_byte(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".work/x86_64") as temporary_text:
            source = Path(temporary_text) / "source"
            source.mkdir()
            tracked = source / "fixture.rs"
            tracked.write_text("original\n", encoding="utf-8")
            identity = native_x86.tree_identity(source)
            native_x86.verify_tree_identity(source, identity, "test source")
            tracked.write_text("changed\n", encoding="utf-8")
            with self.assertRaisesRegex(native_x86.RunnerError, "tree identity"):
                native_x86.verify_tree_identity(source, identity, "test source")

    def test_file_identity_rejects_a_changed_frozen_source_byte(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".work/x86_64") as temporary_text:
            source = Path(temporary_text) / "main.rs"
            source.write_text("frozen\n", encoding="utf-8")
            identity = native_x86.file_identity(source)
            source.write_text("mutated\n", encoding="utf-8")
            with self.assertRaisesRegex(native_x86.RunnerError, "sha256"):
                native_x86.verify_file_identity(source, identity, "frozen route source")


if __name__ == "__main__":
    unittest.main()
