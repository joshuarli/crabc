#!/usr/bin/env python3
"""Build, assemble, and prove the crabc-owned application sysroot.

This is the native Docker-side implementation behind ``scripts/dev.sh
sysroot``. It deliberately performs two fresh production builds in separate
disposable build directories. Rust path remapping keeps their installed output
reproducible while the distinct roots prove that no object or absolute build
path was accidentally reused.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Sequence


ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "target"
PRIMARY_BUILD_ROOT = TARGET / "crabc-sysroot-build-primary"
COMPARISON_BUILD_ROOT = TARGET / "crabc-sysroot-build-comparison"
PRIMARY_SYSROOT = TARGET / "crabc-sysroot"
COMPARISON_SYSROOT = TARGET / "crabc-sysroot-repro"
REPORT = ROOT / "compat/reports/sysroot/latest.json"
TARGET_TRIPLE = "aarch64-unknown-linux-musl"
CANONICAL_INTERPRETER = "/lib/ld-crabc-aarch64.so.1"


class BuildError(RuntimeError):
    """A production build or evidence boundary failed."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def repository_source_identity() -> dict[str, object]:
    """Bind generated evidence to the exact checked-out source inputs.

    The working tree is intentionally allowed to be dirty while this command
    runs.  Hashing tracked and non-ignored untracked regular files therefore
    records the actual sources consumed by both production builds instead of
    merely naming the repository's last commit.
    """

    environment = deterministic_environment()
    try:
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        ).stdout.decode("ascii").strip()
        tracked = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        ).stdout.split(b"\0")
        untracked = subprocess.run(
            ["git", "ls-files", "--others", "--exclude-standard", "-z"],
            cwd=ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        ).stdout.split(b"\0")
    except (OSError, subprocess.CalledProcessError) as error:
        raise BuildError("cannot bind sysroot evidence to the source tree") from error

    tracked_paths = {Path(value.decode("utf-8")) for value in tracked if value}
    untracked_paths = {Path(value.decode("utf-8")) for value in untracked if value}
    files = sorted(tracked_paths | untracked_paths)
    digest = hashlib.sha256()
    included = 0
    for relative in files:
        path = ROOT / relative
        if not path.is_file() and not path.is_symlink():
            continue
        digest.update(relative.as_posix().encode("utf-8"))
        digest.update(b"\0")
        if path.is_symlink():
            digest.update(b"symlink\0")
            digest.update(os.readlink(path).encode("utf-8"))
        else:
            digest.update(b"file\0")
            digest.update(sha256_file(path).encode("ascii"))
        digest.update(b"\0")
        included += 1
    return {
        "git_head": head,
        "tree_sha256": digest.hexdigest(),
        "tracked_file_count": len(tracked_paths),
        "untracked_file_count": len(untracked_paths),
        "hashed_file_count": included,
    }


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def deterministic_environment() -> dict[str, str]:
    environment = dict(os.environ)
    # The C wrapper itself seals all target search variables. Removing them
    # here as well keeps production artifact construction independent from a
    # developer shell that happens to point at another sysroot.
    for key in (
        "CPATH",
        "C_INCLUDE_PATH",
        "CPLUS_INCLUDE_PATH",
        "OBJC_INCLUDE_PATH",
        "LIBRARY_PATH",
        "COMPILER_PATH",
        "GCC_EXEC_PREFIX",
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_BUILD_RUSTFLAGS",
    ):
        environment.pop(key, None)
    for key in tuple(environment):
        if key.startswith("CARGO_TARGET_") and key.endswith(("_LINKER", "_RUSTFLAGS")):
            environment.pop(key, None)
    # Cargo artifacts are produced under two deliberately different target
    # roots below. Keep paths from either tree out of object/debug metadata so
    # the installed comparison proves reproducibility rather than path reuse.
    environment["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join(
        (
            "-C",
            "link-dead-code",
            "-C",
            "target-feature=-crt-static",
            f"--remap-path-prefix={ROOT}=/crabc",
        )
    )
    environment.update({"SOURCE_DATE_EPOCH": "0", "LC_ALL": "C", "LANG": "C", "TZ": "UTC"})
    return environment


def run_checked(command: Sequence[str], records: list[dict[str, object]], *, cwd: Path = ROOT) -> bytes:
    completed = subprocess.run(
        list(command),
        cwd=cwd,
        env=deterministic_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    record = {
        "command": list(command),
        "status": completed.returncode,
        "stdout_sha256": hashlib.sha256(completed.stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(completed.stderr).hexdigest(),
    }
    records.append(record)
    if completed.returncode != 0:
        rendered = " ".join(command)
        raise BuildError(
            f"command failed ({completed.returncode}): {rendered}\n"
            f"stdout:\n{completed.stdout.decode(errors='replace')}\n"
            f"stderr:\n{completed.stderr.decode(errors='replace')}"
        )
    return completed.stdout


def remove_generated_build_root(build_root: Path) -> None:
    """Remove only this tool's exact disposable build directory."""

    if not build_root.exists():
        return
    if build_root.is_symlink() or not build_root.is_dir():
        raise BuildError(f"refusing to remove non-directory generated build root: {build_root}")
    shutil.rmtree(build_root)


def remove_owned_sysroot(path: Path) -> None:
    """Replace only a prior sysroot marked with crabc's installed manifest."""

    if not path.exists():
        return
    if path.is_symlink() or not path.is_dir():
        raise BuildError(f"refusing to replace non-directory sysroot output: {path}")
    manifest = path / "share/crabc/manifest.json"
    try:
        value = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise BuildError(f"refusing to replace unrecognized existing sysroot: {path}") from error
    if value.get("target") != TARGET_TRIPLE or value.get("canonical_interpreter") != CANONICAL_INTERPRETER:
        raise BuildError(f"refusing to replace unrecognized existing sysroot: {path}")
    shutil.rmtree(path)


def assert_native_target() -> None:
    if platform.system() != "Linux" or platform.machine() != "aarch64":
        raise BuildError("owned sysroot production evidence requires native Linux/AArch64")


def build_once(output: Path, build_root: Path) -> dict[str, object]:
    """Perform one clean runtime build and assemble exactly one sysroot."""

    remove_generated_build_root(build_root)
    build_root.mkdir(parents=True)
    records: list[dict[str, object]] = []
    cargo = shutil.which("cargo")
    if cargo is None:
        raise BuildError("cargo is unavailable")
    python = sys.executable
    cargo_target = build_root / "cargo"
    run_checked(
        [cargo, "build", "--workspace", "--release", "--locked", "--target-dir", str(cargo_target)], records
    )
    root_metadata = run_checked([cargo, "metadata", "--locked", "--format-version", "1"], records)
    builtins_metadata = run_checked(
        [cargo, "metadata", "--locked", "--format-version", "1", "--manifest-path", "builtins/Cargo.toml"], records
    )
    root_metadata_path = build_root / "cargo-metadata.json"
    builtins_metadata_path = build_root / "builtins-cargo-metadata.json"
    root_metadata_path.write_bytes(root_metadata)
    builtins_metadata_path.write_bytes(builtins_metadata)

    crt_dir = build_root / "crt"
    run_checked([python, "crt/build.py", "--out-dir", str(crt_dir)], records)
    builtins_dir = build_root / "builtins"
    builtins_archive = builtins_dir / "libcrabc-builtins.a"
    run_checked(
        [python, "builtins/build.py", "--output", str(builtins_archive), "--verify-reproducible"], records
    )
    builtins_provenance = builtins_archive.with_suffix(".a.provenance.json")
    builtins_commands = builtins_archive.with_suffix(".a.commands.json")
    if not builtins_provenance.is_file():
        raise BuildError(f"compiler-helper builder did not write provenance: {builtins_provenance}")
    if not builtins_commands.is_file():
        raise BuildError(f"compiler-helper builder did not write producer-command record: {builtins_commands}")
    if not (crt_dir / "commands.json").is_file():
        raise BuildError(f"CRT builder did not write producer-command record: {crt_dir / 'commands.json'}")

    remove_owned_sysroot(output)
    runtime = cargo_target / "release"
    assembly = [
        python,
        "scripts/crabc_sysroot.py",
        "assemble",
        "--output",
        str(output),
        "--include-dir",
        "include",
        "--libc-shared",
        str(runtime / "libc.so"),
        "--libc-static",
        str(runtime / "libc.a"),
        "--loader",
        str(runtime / "libldso.so"),
        "--crt-dir",
        str(crt_dir),
        "--crt-provenance",
        str(crt_dir / "objects.json"),
        "--crt-commands",
        str(crt_dir / "commands.json"),
        "--builtins",
        str(builtins_archive),
        "--builtins-provenance",
        str(builtins_provenance),
        "--builtins-commands",
        str(builtins_commands),
        "--runtime-source-root",
        "libc/src",
        "--runtime-source-root",
        "ldso/src",
        "--runtime-source-root",
        "crabc-mimalloc/src",
        "--runtime-source-root",
        "crt/src",
        "--runtime-source-root",
        "builtins/src",
        "--cargo-manifest",
        "libc/Cargo.toml",
        "--cargo-manifest",
        "ldso/Cargo.toml",
        "--cargo-manifest",
        "crabc-mimalloc/Cargo.toml",
        "--cargo-manifest",
        "crt/Cargo.toml",
        "--cargo-manifest",
        "builtins/Cargo.toml",
        "--cargo-metadata",
        str(root_metadata_path),
        "--cargo-metadata",
        str(builtins_metadata_path),
    ]
    run_checked(assembly, records)
    record_path = build_root / "build-record.json"
    write_json(record_path, {"schema": 1, "commands": records})

    purity_path = output / "share/crabc/purity.json"
    purity = json.loads(purity_path.read_text(encoding="utf-8"))
    if purity.get("crt_sysroot_pure_rust") is not True:
        raise BuildError("assembled sysroot did not satisfy the CRT/sysroot purity contract")
    if purity.get("full_runtime_pure_rust") is False and purity.get("full_runtime_purity_status") != "blocked_by_native_allocator":
        raise BuildError("full-runtime purity is false for an undocumented reason")
    return {
        "output": str(output),
        "build_record": str(record_path),
        "runtime": {
            name: {"path": str(runtime / name), "sha256": sha256_file(runtime / name)}
            for name in ("libc.so", "libc.a", "libldso.so")
        },
        "purity": purity,
    }


def regular_file_hashes(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)): sha256_file(path)
        for path in sorted(root.rglob("*"))
        if path.is_file() and not path.is_symlink()
    }


def write_reproducibility_status(outputs: Sequence[Path]) -> None:
    """Record the successful clean comparison identically in both trees."""

    for output in outputs:
        purity_path = output / "share/crabc/purity.json"
        purity = json.loads(purity_path.read_text(encoding="utf-8"))
        purity["reproducible"] = {
            "status": "passed",
            "method": "two clean production builds in separate roots with remapped source paths",
        }
        write_json(purity_path, purity)
    first, second = (regular_file_hashes(output) for output in outputs)
    differences = sorted(key for key in set(first) | set(second) if first.get(key) != second.get(key))
    if differences:
        raise BuildError("post-report sysroot trees diverged: " + ", ".join(differences))


def run_focused_contract_tests(records: list[dict[str, object]]) -> list[dict[str, object]]:
    """Run the producer/driver parser tests inside the pinned native image."""

    commands = (
        (
            "sysroot_driver_and_evidence_parsers",
            [sys.executable, "compat/sysroot/tests/test_runner.py"],
        ),
        (
            "crt_object_contracts",
            [sys.executable, "crt/tests/test_build.py"],
        ),
        (
            "crt_static_pie_contracts",
            [sys.executable, "crt/tests/test_static_pie_link.py"],
        ),
        (
            "builtins_source_contracts",
            [sys.executable, "builtins/tests/test_build.py"],
        ),
        (
            "builtins_link_contracts",
            [sys.executable, "builtins/tests/test_link.py"],
        ),
    )
    evidence: list[dict[str, object]] = []
    for name, command in commands:
        run_checked(command, records)
        evidence.append({"name": name, **records[-1]})
    return evidence


def bind_report_evidence(
    report: dict[str, object],
    first: dict[str, object],
    second: dict[str, object],
    focused_tests: Sequence[dict[str, object]],
    static_pthread_record: dict[str, object],
) -> None:
    """Attach production and supplemental proof without weakening report status."""

    production_builds: list[dict[str, object]] = []
    for name, result in (("primary", first), ("comparison", second)):
        record_path = Path(str(result["build_record"]))
        if not record_path.is_file():
            raise BuildError(f"missing {name} source-bound build record: {record_path}")
        runtime = result.get("runtime")
        if not isinstance(runtime, dict):
            raise BuildError(f"{name} build record lacks runtime hashes")
        production_builds.append(
            {
                "name": name,
                "build_record": {"path": str(record_path), "sha256": sha256_file(record_path)},
                "runtime": runtime,
            }
        )

    static_report = ROOT / "compat/reports/static-pthread-tls/latest.json"
    if not static_report.is_file():
        raise BuildError("static pthread/TLS runner did not write its report")
    try:
        static_result = json.loads(static_report.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise BuildError("static pthread/TLS report is invalid JSON") from error
    if static_result.get("passed") is not True:
        raise BuildError("static pthread/TLS candidate evidence is not passing")

    report["source_identity"] = repository_source_identity()
    report["production_builds"] = production_builds
    report["supplementary_evidence"] = {
        "focused_contract_tests": list(focused_tests),
        "static_pthread_tls": {
            "command": static_pthread_record,
            "report": str(static_report),
            "sha256": sha256_file(static_report),
            "passed": True,
        },
    }


def parse_args(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument(
        "--no-stage-canonical-loader",
        action="store_true",
        help="diagnostic-only: omit the required normal-kernel interpreter execution proof",
    )
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    args = parse_args(arguments)
    try:
        assert_native_target()
        if args.timeout <= 0 or args.timeout > 300:
            raise BuildError("--timeout must be > 0 and <= 300")
        first = build_once(PRIMARY_SYSROOT, PRIMARY_BUILD_ROOT)
        second = build_once(COMPARISON_SYSROOT, COMPARISON_BUILD_ROOT)
        evidence_records: list[dict[str, object]] = []
        focused_tests = run_focused_contract_tests(evidence_records)
        runner = [
            sys.executable,
            "compat/sysroot/run.py",
            "--sysroot",
            str(PRIMARY_SYSROOT),
            "--comparison-sysroot",
            str(COMPARISON_SYSROOT),
            "--report",
            str(REPORT),
            "--timeout",
            str(args.timeout),
        ]
        if not args.no_stage_canonical_loader:
            runner.append("--stage-canonical-loader")
        run_checked(runner, evidence_records)
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        if report.get("passed") is not True:
            raise BuildError("owned sysroot evidence report is not passing")
        write_reproducibility_status((PRIMARY_SYSROOT, COMPARISON_SYSROOT))
        static_pthread_command = [
            sys.executable,
            "compat/static-pthread-tls/run.py",
            "--sysroot",
            str(PRIMARY_SYSROOT),
            "--timeout",
            str(args.timeout),
        ]
        run_checked(static_pthread_command, evidence_records)
        report["purity"] = json.loads(
            (PRIMARY_SYSROOT / "share/crabc/purity.json").read_text(encoding="utf-8")
        )
        bind_report_evidence(report, first, second, focused_tests, evidence_records[-1])
        # The harness writes atomically; retain that property after binding
        # the producer and static-link evidence it intentionally does not own.
        report_path = REPORT
        temporary = report_path.with_name(f".{report_path.name}.{os.getpid()}.tmp")
        write_json(temporary, report)
        os.replace(temporary, report_path)
        print(
            json.dumps(
                {
                    "schema": 1,
                    "primary": first,
                    "comparison": second,
                    "report": str(REPORT),
                    "evidence_commands": evidence_records,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    except BuildError as error:
        print(f"crabc-owned-sysroot: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
