#!/usr/bin/env python3
"""Contract checks for the bounded installed math/fenv all-entry component."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import owned_dynamic_qualification as catalog
import owned_math_fenv_all_entry_contract as contract
import owned_math_fenv_all_entry_evidence as evidence
import owned_math_fenv_all_entry_receipt as receipt
import validate_owned_math_fenv_all_entry as stream

RUNNER = ROOT / "compat/x86_64/run_owned_math_fenv_all_entry.sh"
DISPATCHER = ROOT / "scripts/dev-x86_64.sh"
CATALOG = ROOT / "compat/x86_64/owned_dynamic_qualification.py"
DRIVER = ROOT / "compat/x86_64/owned_math_fenv_all_entry_driver.c"


def binary80_feature_fixture(work: Path, *, changed_baseline: bool = False,
                             extra_symbol: str | None = None,
                             strong_alias: bool = False,
                             alias_member: bool = False,
                             alias_section: bool = False,
                             duplicate_member_name: bool = False) -> Path:
    toolchain = ("/usr/bin/cc", "/usr/bin/ld", "/usr/bin/ar", "/usr/bin/nm", "/usr/bin/readelf")
    if not all(Path(tool).is_file() for tool in toolchain):
        raise unittest.SkipTest("requires the pinned native archive and ELF tools")
    work.mkdir(parents=True)
    root = work.parents[4]

    def file_identity(path: Path) -> dict[str, object]:
        data = path.read_bytes()
        return {"path": str(path), "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}

    baseline_source = work / "baseline.S"
    baseline_source.write_text(
        ".text\n.globl fixture_base\n.type fixture_base,@function\nfixture_base:\nret\n",
        encoding="utf-8",
    )
    feature_lines = [
        ".text", ".globl exp10l", ".type exp10l,@function", "exp10l:", "ret",
        ".text", ".globl fdiml", ".type fdiml,@function", "fdiml:", "ret",
    ]
    if alias_member or duplicate_member_name:
        alias_source = work / "alias.S"
        alias_source.write_text(
            ".text\n.weak pow10l\n.type pow10l,@function\npow10l:\nret\n", encoding="utf-8",
        )
    elif alias_section:
        feature_lines.extend((".section .text.pow10l,\"ax\",@progbits", ".weak pow10l",
                              ".type pow10l,@function", "pow10l:", "ret"))
    else:
        feature_lines.extend((".weak pow10l" if not strong_alias else ".globl pow10l",
                              ".type pow10l,@function", ".set pow10l,exp10l"))
    if extra_symbol is not None:
        feature_lines.extend((f".globl {extra_symbol}", f".type {extra_symbol},@function",
                              f"{extra_symbol}:", "ret"))
    feature_source = work / "feature.S"
    feature_source.write_text("\n".join(feature_lines) + "\n", encoding="utf-8")
    sources = [baseline_source, feature_source]
    if alias_member or duplicate_member_name:
        sources.append(alias_source)
    objects = []
    for source in sources:
        if source == baseline_source:
            object_directory = work / "baseline-member"
            object_name = "c.baseline.rcgu.o"
        elif source == feature_source:
            object_directory = work / "feature-member"
            object_name = "c.provider.rcgu.o" if duplicate_member_name else "c.feature.rcgu.o"
        else:
            object_directory = work / "alias-member"
            object_name = "c.provider.rcgu.o" if duplicate_member_name else "c.alias.rcgu.o"
        object_directory.mkdir()
        object_path = object_directory / object_name
        built = subprocess.run([toolchain[0], "-c", str(source), "-o", str(object_path)],
                               cwd=work, capture_output=True, text=True, check=False)
        if built.returncode:
            raise AssertionError(built.stderr)
        objects.append(object_path)

    feature_objects = list(objects)
    if changed_baseline:
        changed_source = work / "changed-baseline.S"
        changed_source.write_text(
            ".data\n.globl fixture_base\n.type fixture_base,@object\nfixture_base:\n.quad 1\n",
            encoding="utf-8",
        )
        changed_directory = work / "changed-baseline-member"
        changed_directory.mkdir()
        changed_object = changed_directory / "c.changed-baseline.rcgu.o"
        built = subprocess.run([toolchain[0], "-c", str(changed_source), "-o", str(changed_object)],
                               cwd=work, capture_output=True, text=True, check=False)
        if built.returncode:
            raise AssertionError(built.stderr)
        feature_objects[0] = changed_object

    archive_paths = {}
    source_runtime_records = {}
    audit_paths = {}
    for name, archive_objects, features in (
        ("baseline", [objects[0]], ""),
        ("feature", feature_objects, ""),
    ):
        target_name = "base-target" if name == "baseline" else "feature-target"
        archive = work / target_name / "x86_64-unknown-linux-musl" / "debug/libc.a"
        archive.parent.mkdir(parents=True)
        mode = "q" if name == "feature" and duplicate_member_name else "rcs"
        packed = subprocess.run([toolchain[2], mode, str(archive), *(str(path) for path in archive_objects)],
                                cwd=work, capture_output=True, text=True, check=False)
        if packed.returncode:
            raise AssertionError(packed.stderr)
        if name == "feature" and duplicate_member_name:
            indexed = subprocess.run([toolchain[2], "s", str(archive)],
                                     cwd=work, capture_output=True, text=True, check=False)
            if indexed.returncode:
                raise AssertionError(indexed.stderr)
        graph = work / f"source-runtime-{name if name == 'baseline' else 'feature'}"
        graph_archive = graph / "cargo-target" / "x86_64-unknown-linux-musl" / "debug/libc.a"
        graph_archive.parent.mkdir(parents=True)
        shutil.copyfile(archive, graph_archive)
        stdout = graph / "cargo.stdout.jsonl"
        stderr = graph / "cargo.stderr.log"
        stdout.write_bytes(b"{}\n")
        stderr.write_bytes(b"cargo invocation retained\n")
        command = [
            "/opt/cargo/bin/rustup", "run", receipt.source_runtime.TOOLCHAIN, "cargo",
            "-Zbuild-std=core,alloc,compiler_builtins", "rustc", "--locked", "--offline", "-vv",
            "--message-format=json-render-diagnostics", "-p", "crabc-libc", "--lib", "--target",
            "x86_64-unknown-linux-musl",
        ]
        if features:
            command.extend(("--features", features))
        build_receipt = {
            "schema": 1,
            "profile": receipt.source_runtime.source_runtime_profile(features)["name"],
            "features": features,
            "cargo_profile": "dev",
            "libc_rustc_arguments": [],
            "scope": "private-native-static-source-runtime-closure-not-product-or-dynamic-qualification",
            "target": "x86_64-unknown-linux-musl",
            "toolchain": receipt.source_runtime.TOOLCHAIN,
            "pinned_rustup": {},
            "cargo_command": command,
            "cargo_profile_dev_debug": 0,
            "cargo_profile_dev_codegen_units": 65536,
            "c_environment": {},
            "runtime_flags": list(receipt.source_runtime.runtime_flags("static")),
            "cargo_stdout": file_identity(stdout),
            "cargo_stderr": file_identity(stderr),
            "rust_source": "/opt/rustup/toolchains/source",
            "vendor": {},
            "source_runtime_artifacts": {},
            "source_runtime_rustc": {},
            "primary_rustc": {},
            "allocator_rustc": None,
            "staticlib_closure": {"archive": file_identity(graph_archive)},
            "immediate_abort_semantics": "development-only Rust panics abort immediately instead of using static_c_abi.rs's nonreturning spin panic handler",
        }
        graph_receipt = graph / "receipt.json"
        graph_receipt.write_text(json.dumps(build_receipt, sort_keys=True) + "\n", encoding="utf-8")
        copied_receipt = Path(f"{archive}.source-runtime.json")
        shutil.copyfile(graph_receipt, copied_receipt)
        archive_paths[name] = archive
        source_runtime_records[name] = (graph, copied_receipt)
        audit = {}
        audit_names = {
            "baseline": {
                "nm_symbols": "base-archive-symbols",
                "nm_globals": "base-archive-globals",
                "readelf_symbols": "base-archive-readelf",
            },
            "feature": {
                "nm_symbols": "archive-symbols",
                "nm_globals": "archive-globals",
                "readelf_symbols": "feature-archive-readelf",
            },
        }
        for field, command in (
            ("nm_symbols", [toolchain[3], "-A", "--defined-only", str(archive)]),
            ("nm_globals", [toolchain[3], "-A", "-g", "--defined-only", str(archive)]),
            ("readelf_symbols", [toolchain[4], "--symbols", "--wide", str(archive)]),
        ):
            completed = subprocess.run(command, cwd=work, capture_output=True, check=False)
            if completed.returncode:
                raise AssertionError(completed.stderr.decode(errors="replace"))
            output = work / audit_names[name][field]
            output.write_bytes(completed.stdout)
            audit[field] = output
        audit_paths[name] = audit

    consumer_source = work / "consumer.c"
    consumer_source.write_text(
        "extern long double exp10l(long double), pow10l(long double);\n"
        "extern long double fdiml(long double, long double);\n"
        "void _start(void) { volatile long double (*a)(long double) = exp10l; "
        "volatile long double (*b)(long double) = pow10l; "
        "volatile long double (*c)(long double, long double) = fdiml; "
        "a(1.0L); b(2.0L); c(3.0L, 1.0L); for (;;) {} }\n",
        encoding="utf-8",
    )
    consumer_object = work / "consumer.o"
    compiled = subprocess.run(
        [toolchain[0], "-c", "-ffreestanding", "-fno-pie", "-fno-stack-protector", "-fno-builtin",
         str(consumer_source), "-o", str(consumer_object)],
        cwd=work, capture_output=True, text=True, check=False,
    )
    if compiled.returncode:
        raise AssertionError(compiled.stderr)
    candidate = work / "crabc-candidate"
    linked = subprocess.run(
        [toolchain[1], "-static", "-e", "_start", "-o", str(candidate),
         str(consumer_object), str(archive_paths["feature"])],
        cwd=work, capture_output=True, text=True, check=False,
    )
    if linked.returncode:
        raise AssertionError(linked.stderr)
    candidate.chmod(0o755)
    oracle = work / "musl-reference"
    shutil.copyfile(candidate, oracle)
    oracle.chmod(0o755)

    for name, archive in archive_paths.items():
        graph, copied_receipt = source_runtime_records[name]
        archive_paths[name] = archive
        audit_paths[name]["archive"] = archive
        audit_paths[name]["receipt"] = copied_receipt
        audit_paths[name]["graph"] = graph

    stream = b"\0" * (247 * 42)
    oracle_records = work / "reference.records"
    candidate_records = work / "candidate.records"
    oracle_records.write_bytes(stream)
    candidate_records.write_bytes(stream)
    oracle_stderr = work / "reference.stderr"
    candidate_stderr = work / "candidate.stderr"
    oracle_stderr.write_bytes(b"")
    candidate_stderr.write_bytes(b"")
    oracle_status = work / "reference.status"
    candidate_status = work / "candidate.status"
    oracle_status.write_text("0\n", encoding="ascii")
    candidate_status.write_text("0\n", encoding="ascii")
    oracle_link_argv = work / "oracle-link.argv.json"
    oracle_run_argv = work / "oracle-run.argv.json"
    consumer_link_argv = work / "consumer-link.argv.json"
    consumer_run_argv = work / "consumer-run.argv.json"
    oracle_link_argv.write_text(json.dumps([
        "/usr/local/bin/crabc-x86_64-musl-gcc", "-std=c11", "-D_GNU_SOURCE", f"-I{ROOT / 'include'}",
        "-fno-builtin", "-frounding-math", "-fno-stack-protector",
        "compat/x86_64/libc_math_long_double_completion_probe.c", "-lm", "-o", str(oracle),
    ]) + "\n", encoding="utf-8")
    oracle_run_argv.write_text(json.dumps([str(oracle)]) + "\n", encoding="utf-8")
    consumer_link_argv.write_text(json.dumps([
        "/usr/local/bin/crabc-x86_64-musl-gcc", "-std=c11", "-D_GNU_SOURCE",
        "-DCRABC_MATH_LONG_DOUBLE_COMPLETION_FREESTANDING", f"-I{ROOT / 'include'}", "-nostdlib", "-static",
        "-fno-pie", "-no-pie", "-ffreestanding", "-fno-builtin", "-frounding-math",
        "-fno-stack-protector", "-Wl,-e,_start", "-Wl,--no-undefined", "-Wl,--gc-sections",
        "compat/x86_64/libc_math_long_double_completion_probe.c",
        "compat/x86_64/libc_math_long_double_completion_start.S", str(archive_paths["feature"]),
        "-o", str(candidate),
    ]) + "\n", encoding="utf-8")
    consumer_run_argv.write_text(json.dumps([str(candidate)]) + "\n", encoding="utf-8")
    candidate_symbols = work / "candidate-symbols"
    symbols = subprocess.run(["/usr/bin/readelf", "--symbols", "--wide", str(candidate)],
                             cwd=work, capture_output=True, check=False)
    candidate_symbols.write_bytes(symbols.stdout)
    return work


def native_source_runtime_records(work: Path) -> tuple[Path, Path]:
    graph = work / "source-runtime-feature"
    receipt_path = graph / "receipt.json"
    receipt_data = json.loads(receipt_path.read_text(encoding="utf-8"))
    target = graph / "cargo-target"
    target_dir = target / "x86_64-unknown-linux-musl" / "debug" / "deps"
    target_dir.mkdir(parents=True)
    rust_source = Path("/opt/rustup/toolchains") / f"{receipt.source_runtime.TOOLCHAIN}-x86_64-unknown-linux-musl" / "lib/rustlib/src/rust/library"
    toolchain_root = Path("/opt/rustup/toolchains") / f"{receipt.source_runtime.TOOLCHAIN}-x86_64-unknown-linux-musl"
    archive_tool = receipt.source_runtime.required_tool(toolchain_root, "llvm-ar")
    undefined_tool = receipt.source_runtime.required_tool(toolchain_root, "llvm-nm")

    def identity(path: Path) -> dict[str, object]:
        data = path.read_bytes()
        return {"path": str(path), "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}

    runtime_objects: dict[str, Path] = {}
    artifacts: dict[str, tuple[Path, Path]] = {}
    cargo_records = []
    for name, relative in receipt.source_runtime.RUNTIME_SOURCES.items():
        source = rust_source / relative
        rlib = target_dir / f"lib{name}-fixture.rlib"
        rmeta = target_dir / f"lib{name}-fixture.rmeta"
        source_file = target_dir / f"{name}-fixture.c"
        object_file = target_dir / f"{name}.runtime.o"
        source_file.write_text(f"static int {name}_fixture(void) {{ return 1; }}\n", encoding="utf-8")
        compiled = subprocess.run(["/usr/bin/cc", "-c", str(source_file), "-o", str(object_file)],
                                  capture_output=True, text=True, check=False)
        if compiled.returncode:
            raise AssertionError(compiled.stderr)
        packed = subprocess.run([str(archive_tool), "rcs", str(rlib), str(object_file)],
                                capture_output=True, text=True, check=False)
        if packed.returncode:
            raise AssertionError(packed.stderr)
        runtime_objects[name] = object_file
        rmeta.write_bytes(f"{name} rust metadata artifact".encode("ascii"))
        artifacts[name] = (rlib, rmeta)
        crate_features = {
            "core": [],
            "compiler_builtins": ["arch", "compiler-builtins", "default", "unmangled-names"],
            "alloc": [],
        }[name]
        cargo_records.append({
            "reason": "compiler-artifact",
            "package_id": f"path+file:///fixture/{name}#0.0.0",
            "target": {
                "name": name, "src_path": str(source), "kind": ["lib"],
                "crate_types": ["lib"], "edition": "2021", "test": False,
            },
            "features": crate_features,
            "profile": {
                "opt_level": "2", "debuginfo": 0, "debug_assertions": True,
                "overflow_checks": False, "test": False,
            },
            "filenames": [str(rlib), str(rmeta)],
        })
    archive = graph / "cargo-target" / "x86_64-unknown-linux-musl" / "debug" / "libc.a"
    copied_archive = work / "feature-target/x86_64-unknown-linux-musl/debug/libc.a"
    for candidate in (archive, copied_archive):
        packed = subprocess.run(
            [str(archive_tool), "rcs", str(candidate), str(runtime_objects["core"]),
             str(runtime_objects["compiler_builtins"])],
            capture_output=True, text=True, check=False,
        )
        if packed.returncode:
            raise AssertionError(packed.stderr)
    cargo_records.append({
        "reason": "compiler-artifact",
        "package_id": "path+file:///fixture/crabc-libc#0.3.0",
        "target": {
            "name": "c", "src_path": str(ROOT / "libc/src/lib.rs"), "kind": ["staticlib"],
            "crate_types": ["staticlib"], "edition": "2021", "test": False,
        },
        "features": ["default"],
        "profile": {
            "opt_level": "2", "debuginfo": 0, "debug_assertions": True,
            "overflow_checks": False, "test": False,
        },
        "filenames": [str(archive)],
    })
    stdout = graph / "cargo.stdout.jsonl"
    stdout.write_text("".join(json.dumps(record, sort_keys=True) + "\n" for record in cargo_records), encoding="utf-8")

    def rustc_command(crate: str, source: Path, extern_names: tuple[str, ...]) -> list[str]:
        command = [
            str(receipt.source_runtime.native_build_tools.KACHE),
            str(Path("/opt/rustup/toolchains") / f"{receipt.source_runtime.TOOLCHAIN}-x86_64-unknown-linux-musl" / "bin/rustc"),
            "--crate-name", crate, "--edition=2021", str(source),
            "--crate-type", "lib", "--target", receipt.source_runtime.TARGET,
            "-Copt-level=2", "-Cstrip=debuginfo", "-Cdebug-assertions=on",
            "-Coverflow-checks=off", "-Ccodegen-units=65536",
            *receipt.source_runtime.RUNTIME_FLAGS,
        ]
        crate_features = {
            "core": [],
            "compiler_builtins": ["arch", "compiler-builtins", "default", "unmangled-names"],
            "alloc": [],
            "c": ["default"],
        }[crate]
        for feature in crate_features:
            command.extend(("--cfg", f'feature="{feature}"'))
        for name in extern_names:
            modifiers = ("priv",) if crate == "alloc" and name == "compiler_builtins" else (
                ("noprelude", "nounused") if crate == "c" else ()
            )
            prefix = "" if not modifiers else f"{','.join(modifiers)}:"
            for path in artifacts[name]:
                command.extend(("--extern", f"{prefix}{name}={path}"))
        return command

    commands = [
        rustc_command("core", rust_source / receipt.source_runtime.RUNTIME_SOURCES["core"], ()),
        rustc_command("compiler_builtins", rust_source / receipt.source_runtime.RUNTIME_SOURCES["compiler_builtins"], ("core",)),
        rustc_command("alloc", rust_source / receipt.source_runtime.RUNTIME_SOURCES["alloc"], ("compiler_builtins", "core")),
        rustc_command("c", ROOT / "libc/src/lib.rs", ("alloc", "compiler_builtins", "core")),
    ]
    for command in commands:
        command[command.index("--crate-type") + 1] = "staticlib" if command[command.index("--crate-name") + 1] == "c" else "lib"
    stderr = graph / "cargo.stderr.log"
    stderr.write_text("".join(
        f"     Running `{shlex.join(command)}`\n   Compiling fixture\n" for command in commands
    ) + "    Finished `dev` profile [optimized + debuginfo] target(s) in 1.00s\n", encoding="utf-8")

    parsed = receipt.source_runtime.cargo_records(stdout)
    emitted = receipt.source_runtime.emitted_artifacts(parsed, target)
    runtime_sources = {name: rust_source / relative for name, relative in receipt.source_runtime.RUNTIME_SOURCES.items()}
    source_commands = receipt.source_runtime.cargo_commands(stderr)
    source_runtime_rustc = {
        name: receipt.source_runtime.command_record(
            receipt.source_runtime.invocation_for(source_commands, name), target, {}, emitted, name, source,
            flags=receipt.source_runtime.RUNTIME_FLAGS,
        )
        for name, source in runtime_sources.items()
    }
    libc_command = receipt.source_runtime.invocation_for(source_commands, "c")
    libc_externs = receipt.source_runtime.derived_libc_externs(libc_command, "fixture Cargo crabc-libc rustc")
    primary = receipt.source_runtime.command_record(
        libc_command, target, runtime_sources, emitted, "crabc-libc", ROOT / "libc/src/lib.rs",
        extern_matrix=libc_externs, flags=receipt.source_runtime.RUNTIME_FLAGS,
    )
    receipt_data["compiler_tools"] = receipt.source_runtime.compiler_tools(toolchain_root)
    receipt_data["native_build_environment"] = receipt.source_runtime.native_build_tools.environment()
    receipt_data["cargo_stdout"] = identity(stdout)
    receipt_data["cargo_stderr"] = identity(stderr)
    receipt_data["cargo_command"] = receipt.source_runtime.retained_cargo_command("")
    receipt_data["source_runtime_artifacts"] = {
        name: identity(paths[0]) for name, paths in artifacts.items()
    }
    receipt_data["source_runtime_rustc"] = source_runtime_rustc
    receipt_data["primary_rustc"] = primary
    receipt_data["pinned_rustup"] = receipt.source_runtime.pinned_rustup_frontend(
        receipt.source_runtime.PINNED_RUSTUP_FRONTEND, receipt.source_runtime.PINNED_RUSTUP_TARGET,
    )
    receipt_data["vendor"] = {
        "project_vendor_root": str(ROOT / ".work/x86_64/cargo/native-static-source-runtime-vendor"),
        "private_vendor_root": str(graph / "cargo-vendor"),
        "packages": [{"name": "core", "version": "1.0.0", "package_checksum": "a" * 64}],
    }
    receipt_data["rust_source"] = str(rust_source)
    closure = receipt.source_runtime.staticlib_closure(
        archive_tool, undefined_tool, archive,
        {name: paths[0] for name, paths in artifacts.items()}, graph, None,
    )
    receipt_data["staticlib_closure"] = closure
    receipt_path.write_text(json.dumps(receipt_data, sort_keys=True) + "\n", encoding="utf-8")
    copied = Path(f"{work}/feature-target/x86_64-unknown-linux-musl/debug/libc.a.source-runtime.json")
    shutil.copyfile(receipt_path, copied)
    return graph, copied


class OwnedMathFenvAllEntryTests(unittest.TestCase):
    def test_binary80_roster_is_the_command_default_archive(self) -> None:
        baseline, feature = receipt.feature_archive_roster(ROOT)
        self.assertEqual(feature, baseline)
        self.assertTrue({"exp10l", "fdiml", "pow10l"} <= set(baseline))

    def test_retired_math_feature_profile_is_unconditional(self) -> None:
        self.assertEqual(
            receipt.source_runtime.retained_package_features(""), frozenset({"default"}),
        )
        for retired in ("x86-math-long-double-completion", "x86-owned-allocator-lifecycle-test-audit"):
            with self.subTest(retired=retired), self.assertRaisesRegex(
                receipt.source_runtime.ClosureError,
                "does not support this requested feature profile",
            ):
                receipt.source_runtime.retained_package_features(retired)

    def test_binary80_feature_receipt_replays_isolated_archive_and_consumer_evidence(self) -> None:
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        expected = tuple(sorted(("fixture_base", "exp10l", "fdiml", "pow10l")))

        def validate(work: Path) -> dict[str, object]:
            def replay(graph: Path, _features: str, _scratch: Path) -> object:
                archive = graph / "cargo-target/x86_64-unknown-linux-musl/debug/libc.a"
                listed = subprocess.run(["/usr/bin/ar", "t", str(archive)], capture_output=True,
                                        text=True, check=False)
                if listed.returncode:
                    raise AssertionError(listed.stderr)
                return receipt.source_runtime.RetainedStaticlibEvidence(
                    frozenset(), frozenset(listed.stdout.splitlines()),
                )

            with mock.patch.object(receipt, "feature_archive_roster",
                                   return_value=(("fixture_base",), expected)), \
                 mock.patch.object(receipt.binary80_stream, "parse", return_value=[]), \
                 mock.patch.object(receipt.binary80_stream, "validate"), \
                 mock.patch.object(receipt.source_runtime, "replay_retained_graph", side_effect=replay):
                return receipt.validate_binary80_feature_work(ROOT, work.relative_to(ROOT))

        with tempfile.TemporaryDirectory(prefix="binary80-feature-receipt.", dir=scratch) as temporary:
            fixture_root = Path(temporary)
            valid = binary80_feature_fixture(fixture_root / "valid")
            result = validate(valid)
            self.assertEqual(set(result), {
                "work", "baseline_features", "enabled_features", "additions",
                "baseline_archive", "feature_archive", "archive_symbols", "consumer_symbols",
            })
            self.assertEqual(result["baseline_features"], [])
            self.assertEqual(result["enabled_features"], [])
            self.assertEqual(result["additions"], [])
            self.assertTrue(set(result["archive_symbols"]) == {"exp10l", "fdiml", "pow10l"})
            archive_symbols = result["archive_symbols"]
            consumer_symbols = result["consumer_symbols"]
            self.assertEqual(archive_symbols["fdiml"]["binding"], "GLOBAL")
            self.assertEqual(archive_symbols["exp10l"]["binding"], "GLOBAL")
            self.assertEqual(archive_symbols["pow10l"]["binding"], "WEAK")
            self.assertEqual(archive_symbols["exp10l"]["member_index"],
                             archive_symbols["pow10l"]["member_index"])
            self.assertEqual(archive_symbols["exp10l"]["member"], archive_symbols["pow10l"]["member"])
            self.assertEqual(archive_symbols["exp10l"]["section"], archive_symbols["pow10l"]["section"])
            self.assertEqual(archive_symbols["exp10l"]["value"], archive_symbols["pow10l"]["value"])
            self.assertEqual(consumer_symbols["exp10l"]["value"], consumer_symbols["pow10l"]["value"])
            self.assertEqual(result["work"], valid.relative_to(ROOT).as_posix())

            cases = (
                ("aggregate-archive-substitution", {"extra_symbol": "sin"}, None),
                ("changed-baseline-archive", {}, "changed-baseline"),
                ("unexpected-export", {"extra_symbol": "unowned_export"}, None),
                ("baseline-binding-mutation", {"changed_baseline": True}, None),
                ("strong-alias", {"strong_alias": True}, None),
                ("different-alias-member", {"alias_member": True}, None),
                ("different-alias-section", {"alias_section": True}, None),
                ("duplicate-member-name", {"duplicate_member_name": True}, None),
            )
            for name, options, mutation in cases:
                with self.subTest(name=name):
                    work = binary80_feature_fixture(fixture_root / name, **options)
                    if mutation == "changed-baseline":
                        archive = work / "base-target/x86_64-unknown-linux-musl/debug/libc.a"
                        archive.write_bytes(archive.read_bytes() + b"changed")
                    elif mutation == "extra-feature":
                        for path in (
                            work / "source-runtime-feature/receipt.json",
                            work / "feature-target/x86_64-unknown-linux-musl/debug/libc.a.source-runtime.json",
                        ):
                            receipt_data = json.loads(path.read_text(encoding="utf-8"))
                            enabled = "default,x86-math-complex"
                            receipt_data["features"] = enabled
                            command = receipt_data["cargo_command"]
                            command[command.index("--features") + 1] = enabled
                            path.write_text(json.dumps(receipt_data, sort_keys=True) + "\n", encoding="utf-8")
                    elif mutation == "raw-graph":
                        path = work / "source-runtime-feature/cargo.stderr.log"
                        path.write_bytes(path.read_bytes() + b"mutated\n")
                    with self.assertRaises(receipt.ReceiptError):
                        validate(work)

    def test_binary80_source_runtime_rejects_rustc_rows_that_disagree_with_cargo_streams(self) -> None:
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        replay_scratch = ROOT / ".work/tmp"
        replay_scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="binary80-source-runtime-replay.", dir=scratch) as temporary:
            work = binary80_feature_fixture(Path(temporary) / "feature")
            graph, copied = native_source_runtime_records(work)
            receipt_path = graph / "receipt.json"
            original = json.loads(receipt_path.read_text(encoding="utf-8"))
            graph_evidence = receipt.source_runtime.replay_cargo_graph(
                graph, "",
            )
            self.assertEqual(
                graph_evidence.archive,
                graph / "cargo-target/x86_64-unknown-linux-musl/debug/libc.a",
            )
            archive = work / "feature-target/x86_64-unknown-linux-musl/debug/libc.a"
            with mock.patch.object(
                receipt.source_runtime, "replay_private_vendor", return_value=original["vendor"],
            ):
                with tempfile.TemporaryDirectory(prefix="staticlib-replay.", dir=replay_scratch) as temporary:
                    staticlib_evidence = receipt.source_runtime.replay_retained_graph(
                        graph, "", Path(temporary),
                    )
            self.assertEqual(staticlib_evidence.source_runtime_members, frozenset({
                "core.runtime.o", "compiler_builtins.runtime.o",
            }))

            stdout_path = graph / "cargo.stdout.jsonl"
            stderr_path = graph / "cargo.stderr.log"
            original_stdout = stdout_path.read_bytes()
            original_stderr = stderr_path.read_bytes()

            compiler = str(Path("/opt/rustup/toolchains") / f"{receipt.source_runtime.TOOLCHAIN}-x86_64-unknown-linux-musl" / "bin/rustc")
            for old, new, message in (
                (b"/usr/local/bin/kache ", b"/ambient/wrapper ", "exact pinned kache"),
                (compiler.encode(), b"/ambient/rustc", "exact pinned kache"),
                (b"Running `", b"Running `KACHE_LOCAL_ONLY=0 ", "fixed native build environment"),
                (b"Running `", b"Running `KACHE_AUTO_SHARE_TARGET_FILES=1 ", "fixed native build environment"),
            ):
                with self.subTest(resealed_stream=new):
                    stderr_path.write_bytes(original_stderr.replace(old, new))
                    changed = json.loads(json.dumps(original))
                    changed["cargo_stderr"] = receipt.source_runtime.file_record(stderr_path, "resealed fixture stream")
                    receipt_path.write_text(json.dumps(changed), encoding="utf-8")
                    with self.assertRaisesRegex(receipt.source_runtime.ClosureError, message):
                        receipt.source_runtime.replay_cargo_graph(graph, "")
            stderr_path.write_bytes(original_stderr)
            for field, name in (("compiler_tools", "wrapper"), ("native_build_environment", "KACHE_AUTO_CLEAN_UNUSED_UNITS_DAYS")):
                changed = json.loads(json.dumps(original))
                if field == "compiler_tools":
                    changed[field][name]["sha256"] = "0" * 64
                    message = "compiler tool identities differ"
                else:
                    changed[field][name] = "1"
                    message = "native build environment differs"
                receipt_path.write_text(json.dumps(changed), encoding="utf-8")
                with self.subTest(resealed_receipt=field), self.assertRaisesRegex(receipt.source_runtime.ClosureError, message):
                    receipt.source_runtime.replay_cargo_graph(graph, "")
            receipt_path.write_text(json.dumps(original), encoding="utf-8")

            rows = receipt.source_runtime.cargo_records(stdout_path)
            cargo_row = receipt.source_runtime.artifact_record_for_source(
                rows, ROOT / "libc/src/lib.rs", "c",
            )
            extra_feature = "x86-owned-allocator-lifecycle-test-audit"
            cargo_row["features"].append(extra_feature)
            stdout_path.write_text(
                "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8",
            )
            commands = receipt.source_runtime.cargo_commands(stderr_path)
            libc_command = receipt.source_runtime.invocation_for(commands, "c")
            libc_command.extend(("--cfg", f'feature="{extra_feature}"'))
            stderr_path.write_text("".join(
                f"     Running `{shlex.join(command)}`\n   Compiling fixture\n" for command in commands
            ) + "    Finished `dev` profile [optimized + debuginfo] target(s) in 1.00s\n", encoding="utf-8")
            emitted = receipt.source_runtime.emitted_artifacts(rows, graph / "cargo-target")
            runtime_sources = {
                name: Path(original["rust_source"]) / relative
                for name, relative in receipt.source_runtime.RUNTIME_SOURCES.items()
            }
            changed = json.loads(json.dumps(original))
            changed["cargo_stdout"] = receipt.source_runtime.file_record(
                stdout_path, "fixture Cargo JSON stream",
            )
            changed["cargo_stderr"] = receipt.source_runtime.file_record(
                stderr_path, "fixture Cargo diagnostics",
            )
            changed["primary_rustc"] = receipt.source_runtime.command_record(
                libc_command, graph / "cargo-target", runtime_sources, emitted,
                "crabc-libc", ROOT / "libc/src/lib.rs",
                extern_matrix=receipt.source_runtime.derived_libc_externs(
                    libc_command, "fixture Cargo crabc-libc rustc",
                ),
                flags=receipt.source_runtime.RUNTIME_FLAGS,
            )
            receipt_path.write_text(json.dumps(changed, sort_keys=True) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(
                receipt.source_runtime.ClosureError, "feature closure differs from the requested",
            ):
                receipt.source_runtime.replay_cargo_graph(graph, "")
            stdout_path.write_bytes(original_stdout)
            stderr_path.write_bytes(original_stderr)
            receipt_path.write_text(json.dumps(original, sort_keys=True) + "\n", encoding="utf-8")

            for mismatch, mutate in (
                ("cargo-profile", lambda record: record["profile"].__setitem__("opt_level", "3")),
                ("cargo-features", lambda record: record["features"].remove("default")),
            ):
                with self.subTest(mismatch=mismatch):
                    stdout_path.write_bytes(original_stdout)
                    rows = receipt.source_runtime.cargo_records(graph / "cargo.stdout.jsonl")
                    cargo_row = receipt.source_runtime.artifact_record_for_source(
                        rows, ROOT / "libc/src/lib.rs", "c",
                    )
                    mutate(cargo_row)
                    (graph / "cargo.stdout.jsonl").write_text(
                        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8",
                    )
                    changed = json.loads(json.dumps(original))
                    changed["cargo_stdout"] = receipt.source_runtime.file_record(
                        graph / "cargo.stdout.jsonl", "fixture Cargo JSON stream",
                    )
                    receipt_path.write_text(json.dumps(changed, sort_keys=True) + "\n", encoding="utf-8")
                    with self.assertRaises(receipt.source_runtime.ClosureError):
                        receipt.source_runtime.replay_cargo_graph(graph, "")
                    stdout_path.write_bytes(original_stdout)
                    receipt_path.write_text(json.dumps(original, sort_keys=True) + "\n", encoding="utf-8")

            stderr_path.write_bytes(original_stderr)
            commands = receipt.source_runtime.cargo_commands(stderr_path)
            libc_command = receipt.source_runtime.invocation_for(commands, "c")
            feature_cfg = libc_command.index('feature="default"')
            del libc_command[feature_cfg - 1:feature_cfg + 1]
            stderr_path.write_text("".join(
                f"     Running `{shlex.join(command)}`\n   Compiling fixture\n" for command in commands
            ) + "    Finished `dev` profile [optimized + debuginfo] target(s) in 1.00s\n", encoding="utf-8")
            changed = json.loads(json.dumps(original))
            changed["cargo_stderr"] = receipt.source_runtime.file_record(
                stderr_path, "fixture Cargo diagnostics",
            )
            receipt_path.write_text(json.dumps(changed, sort_keys=True) + "\n", encoding="utf-8")
            with self.assertRaises(receipt.source_runtime.ClosureError):
                receipt.source_runtime.replay_cargo_graph(graph, "")
            stderr_path.write_bytes(original_stderr)
            receipt_path.write_text(json.dumps(original, sort_keys=True) + "\n", encoding="utf-8")

            stale_closure = json.loads(json.dumps(original))
            stale_closure["staticlib_closure"]["source_runtime_members"][0]["sha256"] = "0" * 64
            serialized = json.dumps(stale_closure, sort_keys=True) + "\n"
            receipt_path.write_text(serialized, encoding="utf-8")
            copied.write_text(serialized, encoding="utf-8")
            with mock.patch.object(
                receipt.source_runtime, "replay_private_vendor", return_value=original["vendor"],
            ):
                with tempfile.TemporaryDirectory(prefix="staticlib-replay-negative.", dir=replay_scratch) as temporary:
                    with self.assertRaisesRegex(
                        receipt.source_runtime.ClosureError, "member closure differs",
                    ):
                        receipt.source_runtime.replay_retained_graph(
                            graph, "", Path(temporary),
                        )

            def wrong_primary(value: dict[str, object]) -> None:
                value["primary_rustc"]["arguments"] = [
                    "rustc", "--crate-name", "c", "--target", "aarch64-unknown-linux-musl",
                ]

            def wrong_source_runtime(value: dict[str, object]) -> None:
                value["source_runtime_rustc"]["core"]["arguments"] = [
                    "rustc", "--crate-name", "core", "--target", "aarch64-unknown-linux-musl",
                ]

            def wrong_runtime_flags(value: dict[str, object]) -> None:
                value["runtime_flags"] = []

            def wrong_extern_edge(value: dict[str, object]) -> None:
                value["primary_rustc"]["all_externs"]["core"]["path"] = "unbound-core.rlib"

            def missing_runtime_artifact(value: dict[str, object]) -> None:
                del value["source_runtime_artifacts"]["alloc"]

            def extra_cargo_feature(value: dict[str, object]) -> None:
                value["cargo_command"].append("--all-features")

            def wrong_feature(value: dict[str, object]) -> None:
                features = "default,x86-math-complex"
                value["features"] = features
                value["cargo_command"] = receipt.source_runtime.retained_cargo_command(features)

            mutations = (
                ("primary-rustc", wrong_primary),
                ("source-runtime-rustc", wrong_source_runtime),
                ("runtime-flags", wrong_runtime_flags),
                ("extern-edge", wrong_extern_edge),
                ("source-runtime-artifact", missing_runtime_artifact),
                ("cargo-command", extra_cargo_feature),
                ("features", wrong_feature),
            )
            for name, mutate in mutations:
                with self.subTest(mutation=name):
                    mutated = json.loads(json.dumps(original))
                    mutate(mutated)
                    serialized = json.dumps(mutated, sort_keys=True) + "\n"
                    receipt_path.write_text(serialized, encoding="utf-8")
                    copied.write_text(serialized, encoding="utf-8")
                    with self.assertRaises(receipt.ReceiptError):
                        receipt.validate_feature_build(
                            ROOT, archive, copied, graph, "", "feature",
                        )

            graph_receipt = json.loads(json.dumps(original))
            stderr = graph / "cargo.stderr.log"
            stderr.write_bytes(stderr.read_bytes() + b"unbound diagnostics\n")
            serialized = json.dumps(graph_receipt, sort_keys=True) + "\n"
            receipt_path.write_text(serialized, encoding="utf-8")
            copied.write_text(serialized, encoding="utf-8")
            with self.assertRaises(receipt.ReceiptError):
                receipt.validate_feature_build(
                    ROOT, archive, copied, graph, "", "feature",
                )

    def test_archive_public_bindings_rejects_unaccounted_archive_members(self) -> None:
        for member in ("unexpected.o", "compiler_builtins.extra.rcgu.o"):
            with self.subTest(member=member), self.assertRaisesRegex(
                receipt.ReceiptError, "unaccounted archive member",
            ):
                receipt.archive_public_bindings(
                    f"libc.a:{member}:00000000 T foreign_export\n",
                    "fixture archive", frozenset(), frozenset({member}),
                )

    def test_archive_public_bindings_excludes_only_replayed_runtime_members(self) -> None:
        bindings = receipt.archive_public_bindings(
            "libc.a:core.rcgu.o:00000000 T runtime_symbol\n"
            "libc.a:c.math.rcgu.o:00000000 T fdiml\n",
            "fixture archive", frozenset({"core.rcgu.o"}),
            frozenset({"core.rcgu.o", "c.math.rcgu.o"}),
        )

        self.assertEqual(bindings, {"fdiml": {"T"}})

    def test_decimal_logarithms_run_in_parent_and_joined_workers(self) -> None:
        compiler = Path("/usr/local/bin/crabc-x86_64-musl-gcc")
        if not compiler.is_file():
            self.skipTest("requires the pinned native musl compiler")
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="math-log-composition.", dir=scratch) as temporary:
            work = Path(temporary)
            source = work / "composition.c"
            source.write_text(f'''#define log10 observed_log10
#define log10f observed_log10f
#define main composed_main
#include "{DRIVER}"
#undef main
#undef log10
#undef log10f
extern double log10(double);
extern float log10f(float);
static pthread_t parent_thread;
static unsigned int double_calls, float_calls, parent_double_calls, parent_float_calls;
double observed_log10(double input) {{
    __atomic_fetch_add(&double_calls, 1, __ATOMIC_RELAXED);
    if (pthread_equal(pthread_self(), parent_thread))
        __atomic_fetch_add(&parent_double_calls, 1, __ATOMIC_RELAXED);
    return log10(input);
}}
float observed_log10f(float input) {{
    __atomic_fetch_add(&float_calls, 1, __ATOMIC_RELAXED);
    if (pthread_equal(pthread_self(), parent_thread))
        __atomic_fetch_add(&parent_float_calls, 1, __ATOMIC_RELAXED);
    return log10f(input);
}}
int main(void) {{
    parent_thread = pthread_self();
    if (check_worker_environment() != 0)
        return 41;
    return double_calls == 12 && float_calls == 12 &&
        parent_double_calls == 4 && parent_float_calls == 4 ? 0 : 42;
}}
''', encoding="utf-8")
            binary = work / "composition"
            built = subprocess.run(
                [str(compiler), "-std=c11", "-D_GNU_SOURCE", "-fno-builtin",
                 "-frounding-math", "-ffunction-sections", "-fdata-sections",
                 "-Wl,--gc-sections", str(source), "-pthread", "-lm", "-o", str(binary)],
                cwd=ROOT, capture_output=True, text=True, check=False,
            )
            self.assertEqual(built.returncode, 0, built.stderr)
            observed = subprocess.run([str(binary)], cwd=ROOT, capture_output=True,
                                      text=True, check=False)
            self.assertEqual(observed.returncode, 0, observed.stderr)

    def test_rehashed_transplanted_product_source_cannot_reseal(self) -> None:
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="owned-math-fenv-source.", dir=scratch) as temporary:
            work = Path(temporary)
            static = work / "static"
            dynamic = work / "dynamic"
            static.mkdir()
            dynamic.mkdir()
            static_manifest = static / "manifest.json"
            dynamic_manifest = dynamic / "manifest.json"
            static_manifest.write_text("static\n")
            dynamic_manifest.write_text("dynamic\n")
            state_path = dynamic / "share/crabc/dynamic-product-state.json"
            state_path.parent.mkdir(parents=True)
            state = {"schema": "crabc.x86_64-owned-dynamic-materialization/v1",
                     "status": "materialized-unqualified", "source_sha256": "a" * 64}
            state_path.write_text(json.dumps(state) + "\n")
            with mock.patch.object(receipt.product_evidence, "_validate_static_product", return_value=(static_manifest, {})), \
                 mock.patch.object(receipt.product_evidence, "_validate_dynamic_product", return_value=(dynamic_manifest, {})), \
                 mock.patch.object(catalog, "source_digest", return_value="a" * 64):
                sealed = receipt.expected_source_product_seal(ROOT, static, dynamic)
                self.assertEqual(sealed["dynamic"]["tree"], receipt.family.snapshot(dynamic))

                state["source_sha256"] = "b" * 64
                state_path.write_text(json.dumps(state) + "\n")
                sealed["dynamic"]["tree"] = receipt.family.snapshot(dynamic)
                for phase in ("before", "after"):
                    path = work / f"source-product-{phase}.json"
                    path.write_text(json.dumps(sealed, sort_keys=True, separators=(",", ":")) + "\n")
                    retained = json.loads(path.read_text())
                    self.assertEqual(retained["dynamic"]["tree"]["share/crabc/dynamic-product-state.json"]["sha256"],
                                     receipt.digest(state_path))
                with self.assertRaisesRegex(receipt.ReceiptError, "dynamic product source differs"):
                    receipt.expected_source_product_seal(ROOT, static, dynamic)

    def assert_usage(self, *arguments: str) -> None:
        result = subprocess.run(
            ["bash", str(RUNNER), *arguments], cwd=ROOT, capture_output=True,
            env={"PATH": "/usr/bin:/bin", "BASH_ENV": ""}, text=True, check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(
            result.stderr,
            f"usage: {RUNNER} [[--static-sysroot STATIC_SYSROOT] DYNAMIC_SYSROOT]\n",
        )

    def test_exact_four_contract_roster_has_206_distinct_entries(self) -> None:
        roster = contract.load_roster(ROOT)
        self.assertEqual(
            {name: len(symbols) for name, symbols in roster.items()},
            {
                "math.elementary-long-double": 35,
                "math.elementary-fenv-sensitive": 15,
                "math.special": 90,
                "math.complex": 66,
            },
        )
        all_symbols = tuple(symbol for symbols in roster.values() for symbol in symbols)
        self.assertEqual(len(all_symbols), 206)
        self.assertEqual(len(set(all_symbols)), 206)
        self.assertIn("sqrtl", roster["math.elementary-long-double"])
        self.assertNotIn("sqrt", all_symbols)
        self.assertNotIn("sqrtf", all_symbols)
        self.assertTrue({"csqrt", "csqrtf", "csqrtl"}.issubset(roster["math.complex"]))

    def test_object_roster_reuses_the_complete_existing_observations(self) -> None:
        self.assertEqual(
            contract.OBJECT_ROLES,
            (
                ("driver", "compat/x86_64/owned_math_fenv_all_entry_driver.c", None),
                ("elementary-long-double", "compat/x86_64/libc_math_elementary_long_double_probe.c", "CRABC_MATH_ELEMENTARY_LONG_DOUBLE_FREESTANDING"),
                ("fenv-sensitive-aggregate", "compat/x86_64/libc_math_elementary_fenv_sensitive_aggregate_probe.c", None),
                ("fenv-rounding", "compat/x86_64/libc_fenv_rounding_probe.c", "CRABC_FENV_ROUNDING_FREESTANDING"),
                ("fdim", "compat/x86_64/libc_fdim_probe.c", "CRABC_FDIM_FREESTANDING"),
                ("exp10", "compat/x86_64/libc_math_exp10_probe.c", "CRABC_MATH_EXP10_COMPOSED"),
                ("exp10f", "compat/x86_64/libc_math_exp10f_probe.c", "CRABC_MATH_EXP10F_FREESTANDING"),
                ("long-double-completion", "compat/x86_64/libc_math_long_double_completion_probe.c", "CRABC_MATH_LONG_DOUBLE_COMPLETION_FREESTANDING"),
                ("special", "compat/x86_64/libc_math_special_probe.c", "CRABC_MATH_SPECIAL_FREESTANDING"),
                ("complex", "compat/x86_64/libc_math_complex_complete_probe.c", "CRABC_MATH_COMPLEX_COMPLETE_FREESTANDING"),
                ("abi-boundary", "compat/x86_64/libc_math_abi_boundary_probe.c", "CRABC_MATH_ABI_BOUNDARY_FREESTANDING"),
            ),
        )
        for _, relative, _ in contract.OBJECT_ROLES:
            self.assertTrue((ROOT / relative).is_file(), relative)

        for relative, accessor in (
            ("compat/x86_64/libc_math_exp10_probe.c", "crabc_x86_64_math_exp10_record_data"),
            ("compat/x86_64/libc_math_exp10f_probe.c", "crabc_x86_64_math_exp10f_record_data"),
        ):
            self.assertIn(accessor, (ROOT / relative).read_text(encoding="utf-8"))

    def test_driver_composes_every_existing_probe_and_distinguishes_sqrt_boundary(self) -> None:
        source = DRIVER.read_text(encoding="utf-8")
        for callable_name in (
            "crabc_x86_64_math_elementary_fenv_sensitive_aggregate_probe",
            "crabc_x86_64_fenv_rounding_probe",
            "crabc_x86_64_fdim_probe",
            "crabc_x86_64_math_exp10_probe",
            "crabc_x86_64_math_exp10f_probe",
            "crabc_x86_64_math_long_double_completion_probe",
            "crabc_x86_64_math_special_probe",
            "crabc_x86_64_math_complex_complete_probe",
            "crabc_x86_64_math_elementary_long_double_probe",
            "crabc_x86_64_math_abi_boundary_probe",
        ):
            self.assertIn(callable_name, source)

    def test_driver_reads_each_producer_extent_after_its_accessor_returns(self) -> None:
        source = DRIVER.read_text(encoding="utf-8")
        # The initial installed oracle run reached exp10, then emitted stage
        # status -1 because the compositor loaded its zero-initialized extent
        # before calling the accessor. Keep the returned pointer and extent
        # together at the producer boundary.
        self.assertIn("emit_record_data_from_accessor", source)
        for accessor in (
            "crabc_x86_64_math_exp10_record_data",
            "crabc_x86_64_math_exp10f_record_data",
        ):
            self.assertIn(f"emit_record_data_from_accessor({accessor})", source)

    def test_stream_validator_requires_the_fixed_stage_order_and_size(self) -> None:
        # Each body uses the byte extent emitted by its independent probe
        # workload. Keep the fixture independent of the validator's table so
        # a stale body extent cannot validate its own synthetic stream.
        body_sizes = (
            0, 392 * (39 + 31 + 43), 0, 3408 * 40, 1320 * 32, 247 * 42,
            2764 * 40, 5544 * 32, 7604 * 64, 58984 * 64,
        )
        pieces = []
        for (stage, _, _), body_size in zip(stream.STAGES, body_sizes, strict=True):
            pieces.append(stream.FRAME.pack(
                stream.MAGIC, stage, 1, 0,
                stream.CALLER_ROUNDING, stream.CALLER_EXCEPTIONS,
            ))
            pieces.append(b"\0" * body_size)
            pieces.append(stream.FRAME.pack(
                stream.MAGIC, stage, 2, 0,
                stream.CALLER_ROUNDING, stream.CALLER_EXCEPTIONS,
            ))
        records = b"".join(pieces)
        self.assertEqual(len(records), stream.EXPECTED_SIZE)
        stream.validate_bytes(records)
        with self.assertRaises(stream.ValidationError):
            stream.validate_bytes(records[:-1])

        rounding_body_start = 3 * stream.FRAME.size
        missing_rounding = records[:rounding_body_start] + records[rounding_body_start + body_sizes[1]:]
        with self.assertRaisesRegex(stream.ValidationError, "stream has"):
            stream.validate_bytes(missing_rounding)

        # A begin frame records the driver's pre-call boundary and must be
        # clean just as the post-restoration frame is.  This guards a probe
        # that reports a failure before it can alter its caller environment.
        begin_failure = bytearray(records)
        begin_failure[8] = 7
        with self.assertRaises(stream.ValidationError):
            stream.validate_bytes(bytes(begin_failure))

        # Equal begin/end environments alone do not prove the driver installed
        # its specified FE_UPWARD + DIVBYZERO|INEXACT caller boundary.
        coherent_wrong_environment = bytearray(records)
        offset = 0
        for body_size in body_sizes:
            for frame_offset in (offset, offset + stream.FRAME.size + body_size):
                stream.FRAME.pack_into(
                    coherent_wrong_environment, frame_offset, stream.MAGIC,
                    stream.FRAME.unpack_from(coherent_wrong_environment, frame_offset)[1],
                    stream.FRAME.unpack_from(coherent_wrong_environment, frame_offset)[2],
                    0, 0, 0,
                )
            offset += 2 * stream.FRAME.size + body_size
        with self.assertRaises(stream.ValidationError):
            stream.validate_bytes(bytes(coherent_wrong_environment))

        wrong_stage = bytearray(records)
        stream.FRAME.pack_into(
            wrong_stage, 0, stream.MAGIC, 2, 1, 0,
            stream.CALLER_ROUNDING, stream.CALLER_EXCEPTIONS,
        )
        with self.assertRaises(stream.ValidationError):
            stream.validate_bytes(bytes(wrong_stage))

        altered = bytearray(records)
        altered[stream.FRAME.size - 1] ^= 1
        with self.assertRaises(stream.ValidationError):
            stream.validate_bytes(bytes(altered))

    def test_runner_usage_and_path_boundary(self) -> None:
        for arguments in (
            ("--static-sysroot",), ("--static-sysroot", ""), ("--static-sysroot", "/one"),
            ("--static-sysroot", "-x"), ("",), ("-x",),
            ("--static-sysroot", "/one", "--static-sysroot", "/two"),
            ("/one", "/two"),
        ):
            with self.subTest(arguments=arguments):
                self.assert_usage(*arguments)

        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="owned-math-fenv-path.", dir=scratch) as temporary:
            base = Path(temporary)
            product = base / "product"
            product.mkdir()
            alias = base / "product-alias"
            alias.symlink_to(product, target_is_directory=True)
            parent = base / "parent"
            parent.mkdir()
            for argument in (alias, parent / ".." / "product", ROOT):
                with self.subTest(argument=argument):
                    result = subprocess.run(
                        ["bash", str(RUNNER), str(argument)], cwd=ROOT,
                        env={**os.environ, "PATH": "/usr/bin:/bin", "TMPDIR": str(base)}, capture_output=True,
                        text=True, check=False,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("owned math/fenv all-entry dynamic product", result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(set(base.iterdir()), {product, alias, parent})

    def test_dynamic_catalog_registers_the_exact_component(self) -> None:
        self.assertEqual(catalog.CASES["math-fenv-all-entry"],
                         ("run_owned_math_fenv_all_entry.sh", None))

    def test_binary_provider_reader_binds_all_selected_imports_and_definitions(self) -> None:
        symbols = tuple(symbol for group in contract.load_roster(ROOT).values() for symbol in group)
        aliases = {"pow10": "exp10", "pow10f": "exp10f", "pow10l": "exp10l"}
        imports = "\n".join(f"{name} U" for name in symbols) + "\n"
        dynamic = "\n".join(
            f"{index}: {index if name not in aliases else symbols.index(aliases[name]) + 1:016x} "
            f"0 FUNC {'WEAK' if name in aliases else 'GLOBAL'} DEFAULT 1 {name}"
            for index, name in enumerate(symbols, start=1)
        ) + "\n"
        static = "\n".join(
            f"libc.a:owner-{index}.o: {name} T 0 1"
            for index, name in enumerate(symbols, start=1)
        ) + "\n"
        record = evidence.validate(ROOT, imports, dynamic, static)
        self.assertEqual(record["et_rel_imports"], sorted(symbols))
        self.assertEqual(set(record["dynamic_providers"]), set(symbols))
        self.assertEqual(set(record["static_provider_members"]), set(symbols))

        missing_sqrtl = dynamic.replace(
            next(line for line in dynamic.splitlines() if line.endswith(" sqrtl")) + "\n", "",
        )
        with self.assertRaises(evidence.EvidenceError):
            evidence.validate(ROOT, imports, missing_sqrtl, static)

    def test_binary_provider_reader_rejects_role_argv_and_ambient_header_drift(self) -> None:
        dynamic = ROOT / ".work/x86_64/provider-fixture/dynamic"
        work = ROOT / ".work/x86_64/provider-fixture/work"
        compiler = Path("/sealed/fixed-image-gcc")
        work.mkdir(parents=True, exist_ok=True)
        self.addCleanup(lambda: shutil.rmtree(work.parent, ignore_errors=True))
        (dynamic / "share/crabc").mkdir(parents=True, exist_ok=True)
        (dynamic / "share/crabc/crabc_cc_static.py").write_text("HOSTED_TRANSLATION_FLAGS = ('-fstack-protector-strong',)\n", encoding="utf-8")
        trace = "".join(f". {dynamic / 'usr/include' / header}\n"
                        for header in evidence.INSTALLED_HEADERS)
        for role, relative, define in contract.OBJECT_ROLES:
            (work / f"compile-{role}.argv.json").write_text(
                json.dumps(evidence.compile_argv(ROOT, work, dynamic, role, relative, define)),
                encoding="utf-8",
            )
            (work / f"header-{role}.argv.json").write_text(
                json.dumps(evidence.header_argv(ROOT, dynamic, compiler, relative, define)),
                encoding="utf-8",
            )
            (work / f"header-{role}.stderr").write_text(trace, encoding="utf-8")
        evidence.validate_invocations(ROOT, work, dynamic, compiler)
        (work / "header-driver.stderr").write_text(". /usr/include/math.h\n", encoding="utf-8")
        with self.assertRaises(evidence.EvidenceError):
            evidence.validate_invocations(ROOT, work, dynamic, compiler)
        (work / "header-driver.stderr").write_text(trace, encoding="utf-8")
        path = work / "compile-exp10.argv.json"
        command = json.loads(path.read_text(encoding="utf-8"))
        command.remove("-DCRABC_MATH_EXP10_COMPOSED")
        path.write_text(json.dumps(command), encoding="utf-8")
        with self.assertRaises(evidence.EvidenceError):
            evidence.validate_invocations(ROOT, work, dynamic, compiler)

    def test_receipt_rejects_rehashed_provider_text_that_disagrees_with_artifacts(self) -> None:
        root = ROOT / ".work/x86_64/owned-math-fenv-provider-replay-fixture"
        root.mkdir(parents=True, exist_ok=True)
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        work = root / "work"
        static = root / "static"
        dynamic = root / "dynamic"
        work.mkdir()
        (static / "usr/lib").mkdir(parents=True)
        (dynamic / "usr/include").mkdir(parents=True)
        (dynamic / "usr/lib").mkdir(parents=True)
        (dynamic / "bin").mkdir(parents=True)
        (dynamic / "share/crabc").mkdir(parents=True)

        # These physical inputs stand in for the independently authenticated
        # ET_REL object, DSO, and archive. The old receipt reader never reads
        # them while accepting a fully coherent, rehashed provider claim.
        (work / "workload.o").write_bytes(b"actual workload artifact")
        (dynamic / "usr/lib/libc.so").write_bytes(b"actual dynamic artifact")
        (static / "usr/lib/libc.a").write_bytes(b"actual static artifact")
        compiler = dynamic / "bin/fixed-image-gcc"
        compiler.write_bytes(b"fixed image compiler")
        (dynamic / "share/crabc/crabc_cc_static.py").write_text(
            f"HOSTED_TRANSLATION_FLAGS = ('-fstack-protector-strong',)\ndef compiler():\n    return {str(compiler)!r}\n", encoding="utf-8"
        )

        trace = "".join(f". {dynamic / 'usr/include' / header}\n"
                        for header in evidence.INSTALLED_HEADERS)
        for role, relative, define in contract.OBJECT_ROLES:
            (work / f"compile-{role}.argv.json").write_text(
                json.dumps(evidence.compile_argv(ROOT, work, dynamic, role, relative, define)),
                encoding="utf-8",
            )
            (work / f"header-{role}.argv.json").write_text(
                json.dumps(evidence.header_argv(ROOT, dynamic, compiler, relative, define)),
                encoding="utf-8",
            )
            (work / f"header-{role}.stderr").write_text(trace, encoding="utf-8")

        symbols = tuple(symbol for group in contract.load_roster(ROOT).values() for symbol in group)
        aliases = {"pow10": "exp10", "pow10f": "exp10f", "pow10l": "exp10l"}
        imports = "\n".join(f"{symbol} U" for symbol in symbols) + "\n"
        static_definitions = "\n".join(
            f"libc.a:owner-{index}.o: {symbol} T 0 1"
            for index, symbol in enumerate(symbols, start=1)
        ) + "\n"

        def dynamic_definitions(offset: int) -> str:
            values = {symbol: index + offset for index, symbol in enumerate(symbols, start=1)}
            for alias, target in aliases.items():
                values[alias] = values[target]
            return "\n".join(
                f"{index}: {values[symbol]:016x} 0 FUNC "
                f"{'WEAK' if symbol in aliases else 'GLOBAL'} DEFAULT 1 {symbol}"
                for index, symbol in enumerate(symbols, start=1)
            ) + "\n"

        def identity(path: Path) -> dict[str, object]:
            data = path.read_bytes()
            return {
                "path": path.relative_to(ROOT).as_posix(),
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            }

        retained_dynamic = dynamic_definitions(0x1000)
        actual_dynamic = dynamic_definitions(0)
        result = evidence.validate(
            ROOT, imports, retained_dynamic, static_definitions, work, dynamic,
        )
        provider = work / "provider.json"
        provider.write_text(json.dumps(result), encoding="utf-8")
        encoded = json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n"
        command_paths = {}
        for stem, output in (
            ("workload-imports", imports),
            ("dynamic-provider-symbols", retained_dynamic),
            ("static-provider-symbols", static_definitions),
            ("component-preflight", encoded),
            ("component-collector", encoded),
        ):
            path = work / f"{stem}.stdout"
            path.write_text(output, encoding="utf-8")
            command_paths[stem] = {"stdout": path}

        def completed(stdout: str) -> subprocess.CompletedProcess[bytes]:
            return subprocess.CompletedProcess([], 0, stdout.encode("utf-8"), b"")

        # The positive control proves that the reader accepts its retained
        # projection when the independently observed three views match it.
        with mock.patch.object(receipt.subprocess, "run", side_effect=[
            completed(imports), completed(retained_dynamic), completed(static_definitions),
        ]) as positive_replay:
            self.assertEqual(
                receipt.validate_provider_record(
                    ROOT, identity(provider), command_paths, work, dynamic, static,
                ),
                provider,
            )

        # Rehashing the retained symbol text and provider JSON can keep all
        # parser, roster, and alias-address checks coherent. It cannot make
        # the retained dynamic address projection true of the actual DSO.
        forged_dynamic = dynamic_definitions(0x2000)
        result = evidence.validate(ROOT, imports, forged_dynamic, static_definitions, work, dynamic)
        provider.write_text(json.dumps(result), encoding="utf-8")
        encoded = json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n"
        command_paths["dynamic-provider-symbols"]["stdout"].write_text(forged_dynamic, encoding="utf-8")
        for stem in ("component-preflight", "component-collector"):
            command_paths[stem]["stdout"].write_text(encoded, encoding="utf-8")
        with mock.patch.object(receipt.subprocess, "run", side_effect=[
            completed(imports), completed(actual_dynamic), completed(static_definitions),
        ]):
            with self.assertRaises(receipt.ReceiptError):
                receipt.validate_provider_record(
                    ROOT, identity(provider), command_paths, work, dynamic, static,
                )
        self.assertEqual(
            [call.args[0] for call in positive_replay.call_args_list],
            [
                ["/usr/bin/nm", "--undefined-only", "--format=posix", str(work / "workload.o")],
                ["/usr/bin/readelf", "--dyn-syms", "-W", str(dynamic / "usr/lib/libc.so")],
                ["/usr/bin/nm", "-A", "-g", "--defined-only", "--format=posix", str(static / "usr/lib/libc.a")],
            ],
        )
        with mock.patch.object(receipt.subprocess, "run", return_value=subprocess.CompletedProcess(
            [], 7, b"partial output", b"inspection failed",
        )):
            with self.assertRaisesRegex(receipt.ReceiptError, "exited with status 7"):
                receipt.validate_provider_record(
                    ROOT, identity(provider), command_paths, work, dynamic, static,
                )
        with mock.patch.object(receipt.subprocess, "run", return_value=subprocess.CompletedProcess(
            [], 0, imports.encode("utf-8"), b"unexpected diagnostic",
        )):
            with self.assertRaisesRegex(receipt.ReceiptError, "wrote stderr"):
                receipt.validate_provider_record(
                    ROOT, identity(provider), command_paths, work, dynamic, static,
                )

    def test_receipt_output_reader_requires_a_valid_pinned_oracle_stream(self) -> None:
        root = ROOT / ".work/x86_64/owned-math-fenv-stream-fixture"
        root.mkdir(parents=True, exist_ok=True)
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))

        records = bytearray()
        for stage, _name, body_size in stream.STAGES:
            records.extend(stream.FRAME.pack(
                stream.MAGIC, stage, 1, 0,
                stream.CALLER_ROUNDING, stream.CALLER_EXCEPTIONS,
            ))
            records.extend(b"\0" * body_size)
            records.extend(stream.FRAME.pack(
                stream.MAGIC, stage, 2, 0,
                stream.CALLER_ROUNDING, stream.CALLER_EXCEPTIONS,
            ))
        expected = bytes(records)
        self.assertEqual(len(expected), stream.EXPECTED_SIZE)

        def result_paths(prefix: str, stdout: bytes) -> dict[str, Path]:
            paths = {
                "stdout": root / f"{prefix}.stdout",
                "stderr": root / f"{prefix}.stderr",
                "status": root / f"{prefix}.status",
            }
            paths["stdout"].write_bytes(stdout)
            paths["stderr"].write_bytes(b"")
            paths["status"].write_bytes(b"0\n")
            return paths

        oracle = result_paths("oracle", expected)
        receipt.output_matches_oracle(result_paths("matching", expected), "matching", oracle)
        changed = bytearray(expected)
        # Change exp10's retained raw record after its begin frame so the
        # stream framing remains valid and
        # the rejection below proves byte-for-byte oracle comparison.
        exp10_body_start = sum(
            2 * stream.FRAME.size + body_size
            for _stage, _label, body_size in stream.STAGES[:3]
        ) + stream.FRAME.size
        changed[exp10_body_start] ^= 1
        stream.validate_bytes(bytes(changed))
        with self.assertRaises(receipt.ReceiptError):
            receipt.output_matches_oracle(result_paths("changed", bytes(changed)), "changed", oracle)

    def test_receipt_replays_link_semantics_after_a_link_record_is_rehashed(self) -> None:
        root = ROOT / ".work/x86_64/owned-math-fenv-link-receipt-fixture"
        root.mkdir(parents=True, exist_ok=True)
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        work = root / "work"
        work.mkdir()
        static, dynamic = root / "static", root / "dynamic"
        static.mkdir()
        dynamic.mkdir()
        link = work / "static.product-link.json"
        link.write_text(json.dumps({"linkage": "static", "product": "forged"}), encoding="utf-8")
        data = link.read_bytes()
        identity = {
            "path": link.relative_to(ROOT).as_posix(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
        }
        expected = {"linkage": "static", "product": "replayed"}
        with mock.patch.object(receipt.product_evidence, "validate_link", return_value=expected):
            with self.assertRaises(receipt.ReceiptError):
                receipt.validate_link(ROOT, {}, {"static": identity}, work, static, dynamic, "static")

    def test_receipt_replays_link_validate_stdout_after_identity_rehash(self) -> None:
        root = ROOT / ".work/x86_64/owned-math-fenv-link-validate-fixture"
        root.mkdir(parents=True, exist_ok=True)
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        work = root / "work"
        work.mkdir()
        static, dynamic = root / "static", root / "dynamic"
        static.mkdir()
        dynamic.mkdir()
        expected = {"linkage": "static", "product": "replayed"}
        link = work / "static.product-link.json"
        link.write_text(json.dumps(expected, sort_keys=True, separators=(",", ":")), encoding="utf-8")

        def identity(path: Path) -> dict[str, object]:
            data = path.read_bytes()
            return {
                "path": path.relative_to(ROOT).as_posix(),
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            }

        validate_stdout = work / "static-validate.stdout"
        validate_stdout.write_text(
            json.dumps(expected, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
        )
        paths = {"static-validate": {"stdout": validate_stdout}}
        with mock.patch.object(receipt.product_evidence, "validate_link", return_value=expected):
            receipt.validate_link(ROOT, paths, {"static": identity(link)}, work, static, dynamic, "static")

            # The report's command identity can be recomputed over changed
            # bytes, but that cannot replace replay of the public reader.
            altered = {"linkage": "static", "product": "altered"}
            validate_stdout.write_text(
                json.dumps(altered, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
            )
            self.assertEqual(
                receipt.validate_identity(ROOT, identity(validate_stdout), "static validate stdout"),
                validate_stdout,
            )
            with self.assertRaises(receipt.ReceiptError):
                receipt.validate_link(ROOT, paths, {"static": identity(link)}, work, static, dynamic, "static")

    def test_receipt_maps_dynamic_report_linkages_to_the_public_reader(self) -> None:
        root = ROOT / ".work/x86_64/owned-math-fenv-dynamic-linkage-fixture"
        root.mkdir(parents=True, exist_ok=True)
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        work = root / "work"
        work.mkdir()
        static, dynamic = root / "static", root / "dynamic"
        static.mkdir()
        dynamic.mkdir()
        link = work / "dynamic-pie.crabc-link.json"
        expected = {"linkage": "pie", "product": "replayed"}
        link.write_text(json.dumps(expected), encoding="utf-8")
        data = link.read_bytes()
        identity = {
            "path": link.relative_to(ROOT).as_posix(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
        }
        validate_stdout = work / "dynamic-pie-validate.stdout"
        validate_stdout.write_text(
            json.dumps(expected, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
        )
        with mock.patch.object(receipt.product_evidence, "validate_link", return_value=expected) as validate:
            receipt.validate_link(
                ROOT, {"dynamic-pie-validate": {"stdout": validate_stdout}},
                {"dynamic-pie": identity}, work, static, dynamic, "dynamic-pie",
            )
        validate.assert_called_once_with(
            dynamic, work / "workload.o", work / "dynamic-pie",
            Path(str(work / "dynamic-pie") + ".crabc-link.json"), "pie",
        )

    def test_receipt_rejects_final_and_intermediate_identity_symlink_hops(self) -> None:
        root = ROOT / ".work/x86_64/owned-math-fenv-symlink-fixture"
        root.mkdir(parents=True, exist_ok=True)
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        target = root / "target.json"
        target.write_text("{}", encoding="utf-8")
        final_link = root / "final.json"
        final_link.symlink_to(target.name)
        nested = root / "nested"
        nested.mkdir()
        (nested / "value.json").write_text("{}", encoding="utf-8")
        intermediate = root / "intermediate"
        intermediate.symlink_to(nested.name, target_is_directory=True)
        with self.assertRaises(receipt.ReceiptError):
            receipt.physical(ROOT, final_link.relative_to(ROOT).as_posix())
        with self.assertRaises(receipt.ReceiptError):
            receipt.physical(ROOT, (intermediate / "value.json").relative_to(ROOT).as_posix())

    def test_provider_header_trace_rejects_an_ambient_include(self) -> None:
        root = ROOT / ".work/x86_64/owned-math-fenv-header-trace-fixture"
        root.mkdir(parents=True, exist_ok=True)
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        dynamic = root / "dynamic"
        work = root / "work"
        work.mkdir()
        include = dynamic / "usr/include"
        valid_trace = "".join(f". {include / header}\n" for header in evidence.INSTALLED_HEADERS)
        for role, _relative, _define in contract.OBJECT_ROLES:
            (work / f"header-{role}.stderr").write_text(valid_trace, encoding="utf-8")
        evidence.validate_header_traces(work, dynamic)
        (work / "header-driver.stderr").write_text(". /usr/include/math.h\n", encoding="utf-8")
        with self.assertRaises(evidence.EvidenceError):
            evidence.validate_header_traces(work, dynamic)

    def test_runner_remains_shell_syntax_valid(self) -> None:
        result = subprocess.run(["bash", "-n", str(RUNNER)], cwd=ROOT,
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
