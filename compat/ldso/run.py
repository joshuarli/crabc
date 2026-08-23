#!/usr/bin/env python3
"""Synthetic AArch64 dynamic-loader differential suite.

Each fixture is compiled once with pinned musl headers, then linked and run
under the pinned musl interpreter and under crabc's ``libldso.so``/``libc.so``.
The runner preserves raw process outcome bytes rather than normalizing loader
differences.  ``readelf`` evidence is recorded for every relocation assertion
so a fixture cannot pass merely because its intended relocation disappeared.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import pathlib
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import re
from typing import Mapping, Sequence


ROOT = pathlib.Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "compat" / "ldso" / "fixtures"
TARGET = ROOT / "target" / "debug"
REPORT = ROOT / "compat" / "reports" / "ldso" / "latest.json"
MUSL_REFERENCE_LIBDIR = pathlib.Path(
    os.environ.get("MUSL_REFERENCE_LIBDIR", "/opt/musl-1.2.6/lib")
)


@dataclasses.dataclass(frozen=True)
class ProcessResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool

    def json(self) -> dict[str, object]:
        return {
            "argv": list(self.argv),
            "returncode": self.returncode,
            "stdout_hex": self.stdout.hex(),
            "stderr_hex": self.stderr.hex(),
            "timed_out": self.timed_out,
        }


class LoaderSuiteError(RuntimeError):
    """A fixture or runner invariant failed."""


def require_aarch64() -> None:
    machine = platform.machine().lower()
    if machine not in {"aarch64", "arm64"}:
        raise LoaderSuiteError(
            f"synthetic loader evidence requires native AArch64, got {machine!r}"
        )


def run(
    argv: Sequence[os.PathLike[str] | str],
    *,
    env: Mapping[str, str] | None = None,
    timeout: float,
    cwd: pathlib.Path | None = None,
) -> ProcessResult:
    rendered = tuple(str(arg) for arg in argv)
    try:
        completed = subprocess.run(
            rendered,
            check=False,
            cwd=cwd,
            env=dict(env) if env is not None else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        return ProcessResult(
            rendered,
            -1,
            error.stdout or b"",
            error.stderr or b"",
            True,
        )
    return ProcessResult(
        rendered,
        completed.returncode,
        completed.stdout,
        completed.stderr,
        False,
    )


def checked(
    argv: Sequence[os.PathLike[str] | str], *, cwd: pathlib.Path, timeout: float
) -> ProcessResult:
    result = run(argv, cwd=cwd, timeout=timeout)
    if result.returncode != 0 or result.timed_out:
        raise LoaderSuiteError(
            f"command failed: {' '.join(result.argv)}\n"
            f"stdout={result.stdout.decode(errors='replace')}\n"
            f"stderr={result.stderr.decode(errors='replace')}"
        )
    return result


def compiler() -> str:
    selected = os.environ.get("CC", "musl-gcc")
    if shutil.which(selected) is None:
        raise LoaderSuiteError(f"required pinned-musl compiler is unavailable: {selected}")
    return selected


def candidate_env(library_dir: pathlib.Path) -> dict[str, str]:
    environment = os.environ.copy()
    # The candidate must get exactly its own libc, while the DSO graph is
    # found through DT_RUNPATH in this initial case.  Do not inherit a host
    # loader path from the test process.
    environment["LD_LIBRARY_PATH"] = str(TARGET)
    environment.pop("LD_PRELOAD", None)
    environment["CRABC_SYNTHETIC_DSO_DIR"] = str(library_dir)
    return environment


def reference_env(library_dir: pathlib.Path) -> dict[str, str]:
    environment = os.environ.copy()
    # The main and middle object each carry their own absolute RUNPATH.  Keep
    # this environment empty of candidate paths so pinned musl remains the
    # complete reference runtime.
    environment.pop("LD_LIBRARY_PATH", None)
    environment.pop("LD_PRELOAD", None)
    environment["CRABC_SYNTHETIC_DSO_DIR"] = str(library_dir)
    return environment


def relocation_types(readelf_output: bytes) -> set[str]:
    names: set[str] = set()
    for line in readelf_output.decode("utf-8", errors="replace").splitlines():
        for word in line.split():
            if word.startswith("R_AARCH64_"):
                names.add(word)
    return names


def compile_nested_graph(work: pathlib.Path, timeout: float) -> tuple[pathlib.Path, pathlib.Path]:
    cc = compiler()
    leaf = work / "libnested_leaf.so"
    mid = work / "libnested_mid.so"
    reference = work / "nested-reference"
    candidate = work / "nested-candidate"

    checked(
        [cc, "-shared", "-fPIC", FIXTURES / "nested_leaf.c", "-o", leaf],
        cwd=work,
        timeout=timeout,
    )
    # This is intentionally an absolute runpath.  The case tests graph
    # traversal/rebinding before the separate $ORIGIN search-path case, and it
    # makes the graph's exact loader-visible edge explicit in readelf output.
    checked(
        [
            cc,
            "-shared",
            "-fPIC",
            FIXTURES / "nested_mid.c",
            "-L",
            work,
            f"-Wl,-rpath,{work}",
            "-Wl,--no-as-needed",
            "-lnested_leaf",
            "-o",
            mid,
        ],
        cwd=work,
        timeout=timeout,
    )
    readelf = checked(["readelf", "-d", mid], cwd=work, timeout=timeout)
    if "libnested_leaf.so" not in readelf.stdout.decode("utf-8", errors="replace"):
        raise LoaderSuiteError("middle fixture lost its intended DT_NEEDED edge")
    relocations = checked(["readelf", "-Wr", mid], cwd=work, timeout=timeout)
    relocation_names = relocation_types(relocations.stdout)
    if "R_AARCH64_JUMP_SLOT" not in relocation_names:
        raise LoaderSuiteError(
            "middle fixture does not exercise R_AARCH64_JUMP_SLOT for its leaf call; "
            f"observed={sorted(relocation_names)}"
        )

    common = [
        cc,
        "-fPIE",
        "-pie",
        FIXTURES / "nested_main.c",
        "-L",
        work,
        f"-Wl,-rpath,{work}",
        "-Wl,--no-as-needed",
        "-lnested_mid",
        "-Wl,--as-needed",
    ]
    checked([*common, "-o", reference], cwd=work, timeout=timeout)
    ldso = TARGET / "libldso.so"
    libc = TARGET / "libc.so"
    if not ldso.is_file() or not libc.is_file():
        raise LoaderSuiteError("build crabc before running the synthetic loader suite")
    checked(
        [
            *common,
            "-Wl,--dynamic-linker",
            ldso,
            "-L",
            TARGET,
            "-lc",
            "-o",
            candidate,
        ],
        cwd=work,
        timeout=timeout,
    )
    return reference, candidate


def compare_nested_graph(work: pathlib.Path, timeout: float) -> dict[str, object]:
    reference, candidate = compile_nested_graph(work, timeout)
    ref = run([reference], env=reference_env(work), cwd=work, timeout=timeout)
    got = run([candidate], env=candidate_env(work), cwd=work, timeout=timeout)
    expected = ProcessResult(ref.argv, 0, b"nested=42\n", b"", False)
    if ref != expected:
        raise LoaderSuiteError(
            "pinned musl reference failed the nested DT_NEEDED fixture: "
            f"{ref.json()}"
        )
    if got != ProcessResult(got.argv, ref.returncode, ref.stdout, ref.stderr, ref.timed_out):
        raise LoaderSuiteError(
            "crabc differs from pinned musl for nested DT_NEEDED traversal: "
            f"reference={ref.json()} candidate={got.json()}"
        )
    return {"result": "pass", "reference": ref.json(), "candidate": got.json()}


def compare_nested_dlopen(work: pathlib.Path, timeout: float) -> dict[str, object]:
    # Reuse the exact same two-DSO graph as startup loading. This variant
    # forces `__ldso_dlopen` to discover the leaf before it applies mid's
    # JUMP_SLOT relocation and exposes its exported function through dlsym.
    compile_nested_graph(work, timeout)
    cc = compiler()
    reference = work / "nested-dlopen-reference"
    candidate = work / "nested-dlopen-candidate"
    common = [cc, "-fPIE", "-pie", FIXTURES / "nested_dlopen.c", "-ldl"]
    checked([*common, "-o", reference], cwd=work, timeout=timeout)
    checked(
        [
            *common,
            "-Wl,--dynamic-linker",
            TARGET / "libldso.so",
            "-L",
            TARGET,
            "-lc",
            "-o",
            candidate,
        ],
        cwd=work,
        timeout=timeout,
    )
    ref_env = reference_env(work)
    ref_env["LD_LIBRARY_PATH"] = str(work)
    got_env = candidate_env(work)
    got_env["LD_LIBRARY_PATH"] = f"{TARGET}:{work}"
    ref = run([reference], env=ref_env, cwd=work, timeout=timeout)
    got = run([candidate], env=got_env, cwd=work, timeout=timeout)
    expected = ProcessResult(ref.argv, 0, b"nested-dlopen=42\n", b"", False)
    if ref != expected:
        raise LoaderSuiteError(
            "pinned musl reference failed the nested dlopen fixture: "
            f"{ref.json()}"
        )
    if got != ProcessResult(got.argv, ref.returncode, ref.stdout, ref.stderr, ref.timed_out):
        raise LoaderSuiteError(
            "crabc differs from pinned musl for recursive dlopen traversal: "
            f"reference={ref.json()} candidate={got.json()}"
        )
    return {"result": "pass", "reference": ref.json(), "candidate": got.json()}


def compile_search_dso(
    cc: str, directory: pathlib.Path, value: int, timeout: float
) -> None:
    directory.mkdir()
    checked(
        [
            cc,
            "-shared",
            "-fPIC",
            f"-DSEARCH_VALUE={value}",
            FIXTURES / "search_dso.c",
            "-o",
            directory / "libsearch.so",
        ],
        cwd=directory,
        timeout=timeout,
    )


def compile_search_main(
    *,
    work: pathlib.Path,
    output: pathlib.Path,
    rpath: pathlib.Path,
    rpath_mode: str,
    candidate: bool,
    timeout: float,
) -> None:
    cc = compiler()
    if rpath_mode == "runpath":
        path_flags = [f"-Wl,-rpath,{rpath}"]
    elif rpath_mode == "rpath":
        path_flags = ["-Wl,--disable-new-dtags", f"-Wl,-rpath,{rpath}"]
    else:
        raise LoaderSuiteError(f"unknown search-path mode: {rpath_mode}")
    argv: list[os.PathLike[str] | str] = [
        cc,
        "-fPIE",
        "-pie",
        FIXTURES / "search_main.c",
        *path_flags,
        "-ldl",
    ]
    if candidate:
        argv.extend(["-Wl,--dynamic-linker", TARGET / "libldso.so", "-L", TARGET, "-lc"])
    argv.extend(["-o", output])
    checked(argv, cwd=work, timeout=timeout)
    dynamic = checked(["readelf", "-dW", output], cwd=work, timeout=timeout)
    expected_tag = "RUNPATH" if rpath_mode == "runpath" else "RPATH"
    if f"({expected_tag})" not in dynamic.stdout.decode("utf-8", errors="replace"):
        raise LoaderSuiteError(
            f"{output.name} did not retain its intended DT_{expected_tag} fixture tag"
        )


def compare_search_path(work: pathlib.Path, timeout: float) -> dict[str, object]:
    """Compare musl's RPATH/RUNPATH and LD_LIBRARY_PATH precedence exactly."""

    cc = compiler()
    environment_dir = work / "environment"
    runpath_dir = work / "runpath"
    rpath_dir = work / "rpath"
    compile_search_dso(cc, environment_dir, 11, timeout)
    compile_search_dso(cc, runpath_dir, 22, timeout)
    compile_search_dso(cc, rpath_dir, 33, timeout)

    results: dict[str, object] = {}
    for mode, directory in (("runpath", runpath_dir), ("rpath", rpath_dir)):
        reference = work / f"search-{mode}-reference"
        candidate = work / f"search-{mode}-candidate"
        compile_search_main(
            work=work,
            output=reference,
            rpath=directory,
            rpath_mode=mode,
            candidate=False,
            timeout=timeout,
        )
        compile_search_main(
            work=work,
            output=candidate,
            rpath=directory,
            rpath_mode=mode,
            candidate=True,
            timeout=timeout,
        )
        for lookup, ld_directory in (("environment", environment_dir), ("embedded", None)):
            ref_env = reference_env(work)
            got_env = candidate_env(work)
            if ld_directory is not None:
                # Preserve the normal LD_LIBRARY_PATH precedence check while
                # also exercising a failed component and an empty component.
                # Empty components must not turn the current directory into a
                # hidden search root, and the candidate's loader directory
                # remains first only so it can find crabc's libc.
                missing = work / "missing-library-path-component"
                ref_env["LD_LIBRARY_PATH"] = f"{missing}::{ld_directory}"
                got_env["LD_LIBRARY_PATH"] = f"{TARGET}:{missing}::{ld_directory}"
            ref = run([reference], env=ref_env, cwd=work, timeout=timeout)
            got = run([candidate], env=got_env, cwd=work, timeout=timeout)
            if ref.returncode != 0 or ref.stderr or ref.timed_out or ref.stdout not in {
                b"search=11\n",
                b"search=22\n",
                b"search=33\n",
            }:
                raise LoaderSuiteError(
                    f"pinned musl {mode}/{lookup} reference did not select a fixture: {ref.json()}"
                )
            if got != ProcessResult(got.argv, ref.returncode, ref.stdout, ref.stderr, ref.timed_out):
                raise LoaderSuiteError(
                    f"crabc differs from pinned musl {mode}/{lookup} search precedence: "
                    f"reference={ref.json()} candidate={got.json()}"
                )
            results[f"{mode}/{lookup}"] = {
                "reference": ref.json(),
                "candidate": got.json(),
            }
    return {"result": "pass", "lookups": results}


def compare_dso_origin(work: pathlib.Path, timeout: float) -> dict[str, object]:
    """Resolve a transitive DSO dependency through that DSO's `$ORIGIN`."""

    cc = compiler()
    bundle = work / "bundle"
    bundle.mkdir()
    leaf = bundle / "liborigin_leaf.so"
    middle = bundle / "liborigin_mid.so"
    reference = work / "origin-reference"
    candidate = work / "origin-candidate"
    checked(
        [cc, "-shared", "-fPIC", FIXTURES / "origin_leaf.c", "-o", leaf],
        cwd=work,
        timeout=timeout,
    )
    checked(
        [
            cc,
            "-shared",
            "-fPIC",
            FIXTURES / "origin_mid.c",
            "-L",
            bundle,
            "-Wl,-rpath,$ORIGIN",
            "-Wl,--no-as-needed",
            "-lorigin_leaf",
            "-Wl,--as-needed",
            "-o",
            middle,
        ],
        cwd=work,
        timeout=timeout,
    )
    dynamic = checked(["readelf", "-dW", middle], cwd=work, timeout=timeout)
    dynamic_text = dynamic.stdout.decode("utf-8", errors="replace")
    if "(RUNPATH)" not in dynamic_text or "$ORIGIN" not in dynamic_text:
        raise LoaderSuiteError("origin middle DSO lost its intended DT_RUNPATH")
    if "liborigin_leaf.so" not in dynamic_text:
        raise LoaderSuiteError("origin middle DSO lost its intended DT_NEEDED edge")

    common = [cc, "-fPIE", "-pie", FIXTURES / "origin_main.c", "-ldl"]
    checked([*common, "-o", reference], cwd=work, timeout=timeout)
    checked(
        [
            *common,
            "-Wl,--dynamic-linker",
            TARGET / "libldso.so",
            "-L",
            TARGET,
            "-lc",
            "-o",
            candidate,
        ],
        cwd=work,
        timeout=timeout,
    )
    ref = run([reference], env=reference_env(work), cwd=work, timeout=timeout)
    got = run([candidate], env=candidate_env(work), cwd=work, timeout=timeout)
    expected = ProcessResult(ref.argv, 0, b"origin=18\n", b"", False)
    if ref != expected:
        raise LoaderSuiteError(f"pinned musl DSO-local $ORIGIN reference failed: {ref.json()}")
    if got != ProcessResult(got.argv, ref.returncode, ref.stdout, ref.stderr, ref.timed_out):
        raise LoaderSuiteError(
            "crabc differs from pinned musl DSO-local $ORIGIN traversal: "
            f"reference={ref.json()} candidate={got.json()}"
        )
    return {"result": "pass", "reference": ref.json(), "candidate": got.json()}


def compare_initial_tls(work: pathlib.Path, timeout: float) -> dict[str, object]:
    """Exercise a PT_TLS DSO loaded with the initial dependency graph."""

    cc = compiler()
    dso = work / "libinitial_tls.so"
    reference = work / "initial-tls-reference"
    candidate = work / "initial-tls-candidate"
    checked(
        [cc, "-shared", "-fPIC", FIXTURES / "initial_tls_dso.c", "-o", dso],
        cwd=work,
        timeout=timeout,
    )
    program_headers = checked(["readelf", "-lW", dso], cwd=work, timeout=timeout)
    if " TLS " not in program_headers.stdout.decode("utf-8", errors="replace"):
        raise LoaderSuiteError("initial TLS DSO is missing its intended PT_TLS segment")
    common = [
        cc,
        "-fPIE",
        "-pie",
        FIXTURES / "initial_tls_main.c",
        "-L",
        work,
        f"-Wl,-rpath,{work}",
        "-Wl,--no-as-needed",
        "-linitial_tls",
        "-Wl,--as-needed",
    ]
    checked([*common, "-o", reference], cwd=work, timeout=timeout)
    checked(
        [
            *common,
            "-Wl,--dynamic-linker",
            TARGET / "libldso.so",
            "-L",
            TARGET,
            "-lc",
            "-o",
            candidate,
        ],
        cwd=work,
        timeout=timeout,
    )
    ref = run([reference], env=reference_env(work), cwd=work, timeout=timeout)
    got = run([candidate], env=candidate_env(work), cwd=work, timeout=timeout)
    expected = ProcessResult(ref.argv, 0, b"initial-tls=7,8\n", b"", False)
    if ref != expected:
        raise LoaderSuiteError(f"pinned musl initial TLS reference failed: {ref.json()}")
    if got != ProcessResult(got.argv, ref.returncode, ref.stdout, ref.stderr, ref.timed_out):
        raise LoaderSuiteError(
            "crabc differs from pinned musl initial TLS setup: "
            f"reference={ref.json()} candidate={got.json()}"
        )
    return {"result": "pass", "reference": ref.json(), "candidate": got.json()}


def compare_dlerror(work: pathlib.Path, timeout: float) -> dict[str, object]:
    """Require one-shot dlerror state for failed dlopen and dlsym calls."""

    cc = compiler()
    dso = work / "libdlerror.so"
    reference = work / "dlerror-reference"
    candidate = work / "dlerror-candidate"
    checked(
        [cc, "-shared", "-fPIC", FIXTURES / "dlerror_dso.c", "-o", dso],
        cwd=work,
        timeout=timeout,
    )
    common = [cc, "-fPIE", "-pie", FIXTURES / "dlerror_main.c", "-ldl"]
    checked([*common, "-o", reference], cwd=work, timeout=timeout)
    checked(
        [
            *common,
            "-Wl,--dynamic-linker",
            TARGET / "libldso.so",
            "-L",
            TARGET,
            "-lc",
            "-o",
            candidate,
        ],
        cwd=work,
        timeout=timeout,
    )
    ref_env = reference_env(work)
    ref_env["LD_LIBRARY_PATH"] = str(work)
    got_env = candidate_env(work)
    got_env["LD_LIBRARY_PATH"] = f"{TARGET}:{work}"
    ref = run([reference], env=ref_env, cwd=work, timeout=timeout)
    got = run([candidate], env=got_env, cwd=work, timeout=timeout)
    expected = ProcessResult(ref.argv, 0, b"dlerror=ok\n", b"", False)
    if ref != expected:
        raise LoaderSuiteError(f"pinned musl dlerror reference failed: {ref.json()}")
    if got != ProcessResult(got.argv, ref.returncode, ref.stdout, ref.stderr, ref.timed_out):
        raise LoaderSuiteError(
            "crabc differs from pinned musl dlerror state handling: "
            f"reference={ref.json()} candidate={got.json()}"
        )
    return {"result": "pass", "reference": ref.json(), "candidate": got.json()}


def compare_hash_formats(work: pathlib.Path, timeout: float) -> dict[str, object]:
    """Resolve identical exports from GNU-hash and SysV-hash DSOs."""

    cc = compiler()
    libraries = (
        ("gnu", "gnu", 13),
        ("sysv", "sysv", 29),
    )
    for label, hash_style, value in libraries:
        dso = work / f"libhash_{label}.so"
        checked(
            [
                cc,
                "-shared",
                "-fPIC",
                f"-DHASH_VALUE={value}",
                FIXTURES / "hash_dso.c",
                f"-Wl,--hash-style={hash_style}",
                "-o",
                dso,
            ],
            cwd=work,
            timeout=timeout,
        )
        dynamic = checked(["readelf", "-dW", dso], cwd=work, timeout=timeout)
        expected_tag = "GNU_HASH" if hash_style == "gnu" else "HASH"
        text = dynamic.stdout.decode("utf-8", errors="replace")
        if f"({expected_tag})" not in text:
            raise LoaderSuiteError(f"{dso.name} is missing its intended DT_{expected_tag}")

    reference = work / "hash-reference"
    candidate = work / "hash-candidate"
    common = [cc, "-fPIE", "-pie", FIXTURES / "hash_main.c", "-ldl"]
    checked([*common, "-o", reference], cwd=work, timeout=timeout)
    checked(
        [
            *common,
            "-Wl,--dynamic-linker",
            TARGET / "libldso.so",
            "-L",
            TARGET,
            "-lc",
            "-o",
            candidate,
        ],
        cwd=work,
        timeout=timeout,
    )
    ref_env = reference_env(work)
    ref_env["LD_LIBRARY_PATH"] = str(work)
    got_env = candidate_env(work)
    got_env["LD_LIBRARY_PATH"] = f"{TARGET}:{work}"
    ref = run([reference], env=ref_env, cwd=work, timeout=timeout)
    got = run([candidate], env=got_env, cwd=work, timeout=timeout)
    expected = ProcessResult(ref.argv, 0, b"hash=13,29\n", b"", False)
    if ref != expected:
        raise LoaderSuiteError(f"pinned musl hash-format reference failed: {ref.json()}")
    if got != ProcessResult(got.argv, ref.returncode, ref.stdout, ref.stderr, ref.timed_out):
        raise LoaderSuiteError(
            "crabc differs from pinned musl GNU/SysV hash lookup: "
            f"reference={ref.json()} candidate={got.json()}"
        )
    return {"result": "pass", "reference": ref.json(), "candidate": got.json()}


def compare_many_symbol_hash_lookup(work: pathlib.Path, timeout: float) -> dict[str, object]:
    """Resolve first and last exports from a DSO with 1,025 hash-indexed names."""

    cc = compiler()
    dso = work / "libhash_many.so"
    source = work / "hash_many_dso.c"
    source.write_text(
        "\n".join(
            f"__attribute__((visibility(\"default\"))) int hash_many_{index}(void) {{ return {index}; }}"
            for index in range(1025)
        )
        + "\n",
        encoding="utf-8",
    )
    checked(
        [
            cc,
            "-shared",
            "-fPIC",
            source,
            "-Wl,--hash-style=both",
            "-o",
            dso,
        ],
        cwd=work,
        timeout=timeout,
    )
    symbols = checked(["readelf", "--dyn-syms", "--wide", dso], cwd=work, timeout=timeout)
    exported = sum(
        "hash_many_" in line
        for line in symbols.stdout.decode("utf-8", errors="replace").splitlines()
    )
    if exported != 1025:
        raise LoaderSuiteError(
            f"many-symbol fixture exported {exported} hash_many symbols, expected 1025"
        )

    reference = work / "hash-many-reference"
    candidate = work / "hash-many-candidate"
    common = [cc, "-fPIE", "-pie", FIXTURES / "hash_many_main.c", "-ldl"]
    checked([*common, "-o", reference], cwd=work, timeout=timeout)
    checked(
        [
            *common,
            "-Wl,--dynamic-linker",
            TARGET / "libldso.so",
            "-L",
            TARGET,
            "-lc",
            "-o",
            candidate,
        ],
        cwd=work,
        timeout=timeout,
    )
    ref_env = reference_env(work)
    ref_env["LD_LIBRARY_PATH"] = str(work)
    got_env = candidate_env(work)
    got_env["LD_LIBRARY_PATH"] = f"{TARGET}:{work}"
    ref = run([reference], env=ref_env, cwd=work, timeout=timeout)
    got = run([candidate], env=got_env, cwd=work, timeout=timeout)
    expected = ProcessResult(ref.argv, 0, b"hash-many=1024,0\n", b"", False)
    if ref != expected:
        raise LoaderSuiteError(f"pinned musl many-symbol hash reference failed: {ref.json()}")
    if got != ProcessResult(got.argv, ref.returncode, ref.stdout, ref.stderr, ref.timed_out):
        raise LoaderSuiteError(
            "crabc differs from pinned musl many-symbol hash lookup: "
            f"reference={ref.json()} candidate={got.json()}"
        )
    return {"result": "pass", "reference": ref.json(), "candidate": got.json()}


def compare_relro(work: pathlib.Path, timeout: float) -> dict[str, object]:
    """Require GNU_RELRO memory to reject a post-relocation child write."""

    cc = compiler()
    dso = work / "librelro.so"
    reference = work / "relro-reference"
    candidate = work / "relro-candidate"
    checked(
        [
            cc,
            "-shared",
            "-fPIC",
            FIXTURES / "relro_dso.c",
            "-Wl,-z,relro,-z,now",
            "-o",
            dso,
        ],
        cwd=work,
        timeout=timeout,
    )
    program_headers = checked(["readelf", "-lW", dso], cwd=work, timeout=timeout)
    if "GNU_RELRO" not in program_headers.stdout.decode("utf-8", errors="replace"):
        raise LoaderSuiteError("RELRO DSO is missing its intended PT_GNU_RELRO segment")
    relocations = checked(["readelf", "-Wr", dso], cwd=work, timeout=timeout)
    if "R_AARCH64_RELATIVE" not in relocation_types(relocations.stdout):
        raise LoaderSuiteError("RELRO DSO is missing the relocatable protected pointer")

    common = [cc, "-fPIE", "-pie", FIXTURES / "relro_main.c", "-ldl"]
    checked([*common, "-o", reference], cwd=work, timeout=timeout)
    checked(
        [
            *common,
            "-Wl,--dynamic-linker",
            TARGET / "libldso.so",
            "-L",
            TARGET,
            "-lc",
            "-o",
            candidate,
        ],
        cwd=work,
        timeout=timeout,
    )
    ref_env = reference_env(work)
    ref_env["LD_LIBRARY_PATH"] = str(work)
    got_env = candidate_env(work)
    got_env["LD_LIBRARY_PATH"] = f"{TARGET}:{work}"
    ref = run([reference], env=ref_env, cwd=work, timeout=timeout)
    got = run([candidate], env=got_env, cwd=work, timeout=timeout)
    expected = ProcessResult(ref.argv, 0, b"relro=protected\n", b"", False)
    if ref != expected:
        raise LoaderSuiteError(f"pinned musl RELRO reference failed: {ref.json()}")
    if got != ProcessResult(got.argv, ref.returncode, ref.stdout, ref.stderr, ref.timed_out):
        raise LoaderSuiteError(
            "crabc differs from pinned musl GNU_RELRO protection: "
            f"reference={ref.json()} candidate={got.json()}"
        )
    return {"result": "pass", "reference": ref.json(), "candidate": got.json()}


def compare_auxv(work: pathlib.Path, timeout: float) -> dict[str, object]:
    """Preserve loader-relevant auxv entries, including the kernel vDSO base."""

    cc = compiler()
    reference = work / "auxv-reference"
    candidate = work / "auxv-candidate"
    common = [cc, "-fPIE", "-pie", FIXTURES / "auxv_main.c"]
    checked([*common, "-o", reference], cwd=work, timeout=timeout)
    checked(
        [
            *common,
            "-Wl,--dynamic-linker",
            TARGET / "libldso.so",
            "-L",
            TARGET,
            "-lc",
            "-o",
            candidate,
        ],
        cwd=work,
        timeout=timeout,
    )
    ref = run([reference], env=reference_env(work), cwd=work, timeout=timeout)
    got = run([candidate], env=candidate_env(work), cwd=work, timeout=timeout)
    expected = ProcessResult(ref.argv, 0, b"auxv=ok\n", b"", False)
    if ref != expected:
        raise LoaderSuiteError(f"pinned musl auxv/vDSO reference failed: {ref.json()}")
    if got != ProcessResult(got.argv, ref.returncode, ref.stdout, ref.stderr, ref.timed_out):
        raise LoaderSuiteError(
            "crabc differs from pinned musl auxv/vDSO handoff: "
            f"reference={ref.json()} candidate={got.json()}"
        )
    return {"result": "pass", "reference": ref.json(), "candidate": got.json()}


def compare_legacy_lifecycle(work: pathlib.Path, timeout: float) -> dict[str, object]:
    """Compare legacy DT_INIT/DT_FINI ordering with init/fini arrays."""

    cc = compiler()
    dso = work / "liblegacy_lifecycle.so"
    reference = work / "legacy-lifecycle-reference"
    candidate = work / "legacy-lifecycle-candidate"
    checked(
        [
            cc,
            "-shared",
            "-fPIC",
            FIXTURES / "legacy_lifecycle_dso.c",
            "-Wl,-init,legacy_init",
            "-Wl,-fini,legacy_fini",
            "-o",
            dso,
        ],
        cwd=work,
        timeout=timeout,
    )
    dynamic = checked(["readelf", "-dW", dso], cwd=work, timeout=timeout)
    tags = dynamic.stdout.decode("utf-8", errors="replace")
    for tag in ("(INIT)", "(FINI)", "(INIT_ARRAY)", "(FINI_ARRAY)"):
        if tag not in tags:
            raise LoaderSuiteError(f"legacy lifecycle DSO is missing intended {tag}")
    common = [cc, "-fPIE", "-pie", FIXTURES / "legacy_lifecycle_main.c", "-ldl"]
    checked([*common, "-o", reference], cwd=work, timeout=timeout)
    checked(
        [
            *common,
            "-Wl,--dynamic-linker",
            TARGET / "libldso.so",
            "-L",
            TARGET,
            "-lc",
            "-o",
            candidate,
        ],
        cwd=work,
        timeout=timeout,
    )
    ref_env = reference_env(work)
    ref_env["LD_LIBRARY_PATH"] = str(work)
    got_env = candidate_env(work)
    got_env["LD_LIBRARY_PATH"] = f"{TARGET}:{work}"
    ref = run([reference], env=ref_env, cwd=work, timeout=timeout)
    got = run([candidate], env=got_env, cwd=work, timeout=timeout)
    expected = ProcessResult(
        ref.argv,
        0,
        b"legacy-array-init\nlegacy-value\nlegacy-array-fini\n",
        b"",
        False,
    )
    if ref != expected:
        raise LoaderSuiteError(f"pinned musl legacy lifecycle reference failed: {ref.json()}")
    if got != ProcessResult(got.argv, ref.returncode, ref.stdout, ref.stderr, ref.timed_out):
        raise LoaderSuiteError(
            "crabc differs from pinned musl legacy init/fini ordering: "
            f"reference={ref.json()} candidate={got.json()}"
        )
    return {"result": "pass", "reference": ref.json(), "candidate": got.json()}


def compare_lookup_scope(work: pathlib.Path, timeout: float) -> dict[str, object]:
    """Distinguish a handle-local export from RTLD_DEFAULT global scope."""

    cc = compiler()
    for name, source in (
        ("libscope_local.so", "scope_local.c"),
        ("libscope_global.so", "scope_global.c"),
    ):
        checked(
            [cc, "-shared", "-fPIC", FIXTURES / source, "-o", work / name],
            cwd=work,
            timeout=timeout,
        )
    reference = work / "scope-reference"
    candidate = work / "scope-candidate"
    common = [cc, "-fPIE", "-pie", FIXTURES / "scope_main.c", "-ldl"]
    checked([*common, "-o", reference], cwd=work, timeout=timeout)
    checked(
        [
            *common,
            "-Wl,--dynamic-linker",
            TARGET / "libldso.so",
            "-L",
            TARGET,
            "-lc",
            "-o",
            candidate,
        ],
        cwd=work,
        timeout=timeout,
    )
    ref_env = reference_env(work)
    ref_env["LD_LIBRARY_PATH"] = str(work)
    got_env = candidate_env(work)
    got_env["LD_LIBRARY_PATH"] = f"{TARGET}:{work}"
    ref = run([reference], env=ref_env, cwd=work, timeout=timeout)
    got = run([candidate], env=got_env, cwd=work, timeout=timeout)
    expected = ProcessResult(ref.argv, 0, b"scope=21,34\n", b"", False)
    if ref != expected:
        raise LoaderSuiteError(f"pinned musl lookup-scope reference failed: {ref.json()}")
    if got != ProcessResult(got.argv, ref.returncode, ref.stdout, ref.stderr, ref.timed_out):
        raise LoaderSuiteError(
            "crabc differs from pinned musl local/global lookup scope: "
            f"reference={ref.json()} candidate={got.json()}"
        )
    return {"result": "pass", "reference": ref.json(), "candidate": got.json()}


def compare_visibility(work: pathlib.Path, timeout: float) -> dict[str, object]:
    """Keep hidden definitions out of dlsym while exposing default symbols."""

    cc = compiler()
    dso = work / "libvisibility.so"
    reference = work / "visibility-reference"
    candidate = work / "visibility-candidate"
    checked(
        [cc, "-shared", "-fPIC", FIXTURES / "visibility_dso.c", "-o", dso],
        cwd=work,
        timeout=timeout,
    )
    symbols = checked(["readelf", "--dyn-syms", "--wide", dso], cwd=work, timeout=timeout)
    text = symbols.stdout.decode("utf-8", errors="replace")
    if "visibility_public" not in text or "visibility_hidden" in text:
        raise LoaderSuiteError("visibility fixture did not retain the intended dynamic surface")
    common = [cc, "-fPIE", "-pie", FIXTURES / "visibility_main.c", "-ldl"]
    checked([*common, "-o", reference], cwd=work, timeout=timeout)
    checked(
        [
            *common,
            "-Wl,--dynamic-linker",
            TARGET / "libldso.so",
            "-L",
            TARGET,
            "-lc",
            "-o",
            candidate,
        ],
        cwd=work,
        timeout=timeout,
    )
    ref_env = reference_env(work)
    ref_env["LD_LIBRARY_PATH"] = str(work)
    got_env = candidate_env(work)
    got_env["LD_LIBRARY_PATH"] = f"{TARGET}:{work}"
    ref = run([reference], env=ref_env, cwd=work, timeout=timeout)
    got = run([candidate], env=got_env, cwd=work, timeout=timeout)
    expected = ProcessResult(ref.argv, 0, b"visibility=ok\n", b"", False)
    if ref != expected:
        raise LoaderSuiteError(f"pinned musl visibility reference failed: {ref.json()}")
    if got != ProcessResult(got.argv, ref.returncode, ref.stdout, ref.stderr, ref.timed_out):
        raise LoaderSuiteError(
            "crabc differs from pinned musl dlsym visibility handling: "
            f"reference={ref.json()} candidate={got.json()}"
        )
    return {"result": "pass", "reference": ref.json(), "candidate": got.json()}


def compare_constructor_order(work: pathlib.Path, timeout: float) -> dict[str, object]:
    """Require dependency constructors before siblings and the main PIE."""

    cc = compiler()
    leaf = work / "liborder_leaf.so"
    middle = work / "liborder_mid.so"
    sibling = work / "liborder_sibling.so"
    reference = work / "order-reference"
    candidate = work / "order-candidate"
    checked(
        [cc, "-shared", "-fPIC", FIXTURES / "order_leaf.c", "-o", leaf],
        cwd=work,
        timeout=timeout,
    )
    checked(
        [
            cc,
            "-shared",
            "-fPIC",
            FIXTURES / "order_mid.c",
            "-L",
            work,
            f"-Wl,-rpath,{work}",
            "-Wl,--no-as-needed",
            "-lorder_leaf",
            "-Wl,--as-needed",
            "-o",
            middle,
        ],
        cwd=work,
        timeout=timeout,
    )
    checked(
        [cc, "-shared", "-fPIC", FIXTURES / "order_sibling.c", "-o", sibling],
        cwd=work,
        timeout=timeout,
    )
    common = [
        cc,
        "-fPIE",
        "-pie",
        FIXTURES / "order_main.c",
        "-L",
        work,
        f"-Wl,-rpath,{work}",
        "-Wl,--no-as-needed",
        "-lorder_mid",
        "-lorder_sibling",
        "-Wl,--as-needed",
    ]
    checked([*common, "-o", reference], cwd=work, timeout=timeout)
    checked(
        [
            *common,
            "-Wl,--dynamic-linker",
            TARGET / "libldso.so",
            "-L",
            TARGET,
            "-lc",
            "-o",
            candidate,
        ],
        cwd=work,
        timeout=timeout,
    )
    ref = run([reference], env=reference_env(work), cwd=work, timeout=timeout)
    got = run([candidate], env=candidate_env(work), cwd=work, timeout=timeout)
    expected = ProcessResult(
        ref.argv,
        0,
        b"order-leaf\norder-mid\norder-sibling\norder-main-init\norder-main\n",
        b"",
        False,
    )
    if ref != expected:
        raise LoaderSuiteError(f"pinned musl constructor-order reference failed: {ref.json()}")
    if got != ProcessResult(got.argv, ref.returncode, ref.stdout, ref.stderr, ref.timed_out):
        raise LoaderSuiteError(
            "crabc differs from pinned musl dependency constructor order: "
            f"reference={ref.json()} candidate={got.json()}"
        )
    return {"result": "pass", "reference": ref.json(), "candidate": got.json()}


def compare_main_handle(work: pathlib.Path, timeout: float) -> dict[str, object]:
    """Make dlopen(NULL)'s global process handle safely closable."""

    cc = compiler()
    reference = work / "main-handle-reference"
    candidate = work / "main-handle-candidate"
    common = [
        cc,
        "-fPIE",
        "-pie",
        FIXTURES / "main_handle_main.c",
        "-Wl,--export-dynamic",
        "-ldl",
    ]
    checked([*common, "-o", reference], cwd=work, timeout=timeout)
    checked(
        [
            *common,
            "-Wl,--dynamic-linker",
            TARGET / "libldso.so",
            "-L",
            TARGET,
            "-lc",
            "-o",
            candidate,
        ],
        cwd=work,
        timeout=timeout,
    )
    ref = run([reference], env=reference_env(work), cwd=work, timeout=timeout)
    got = run([candidate], env=candidate_env(work), cwd=work, timeout=timeout)
    expected = ProcessResult(ref.argv, 0, b"main-handle=ok\n", b"", False)
    if ref != expected:
        raise LoaderSuiteError(f"pinned musl main-handle reference failed: {ref.json()}")
    if got != ProcessResult(got.argv, ref.returncode, ref.stdout, ref.stderr, ref.timed_out):
        raise LoaderSuiteError(
            "crabc differs from pinned musl dlopen(NULL)/dlclose handling: "
            f"reference={ref.json()} candidate={got.json()}"
        )
    return {"result": "pass", "reference": ref.json(), "candidate": got.json()}


def compare_lifecycle(work: pathlib.Path, timeout: float) -> dict[str, object]:
    """Exercise DSO init/fini arrays through dlopen, close, and process exit."""

    cc = compiler()
    dso = work / "liblifecycle.so"
    reference = work / "lifecycle-reference"
    candidate = work / "lifecycle-candidate"
    checked(
        [cc, "-shared", "-fPIC", FIXTURES / "lifecycle_dso.c", "-o", dso],
        cwd=work,
        timeout=timeout,
    )
    dynamic = checked(["readelf", "-dW", dso], cwd=work, timeout=timeout)
    tags = dynamic.stdout.decode("utf-8", errors="replace")
    for tag in ("(INIT_ARRAY)", "(FINI_ARRAY)"):
        if tag not in tags:
            raise LoaderSuiteError(f"lifecycle DSO is missing intended {tag} evidence")
    common = [cc, "-fPIE", "-pie", FIXTURES / "lifecycle_main.c", "-ldl"]
    checked([*common, "-o", reference], cwd=work, timeout=timeout)
    checked(
        [
            *common,
            "-Wl,--dynamic-linker",
            TARGET / "libldso.so",
            "-L",
            TARGET,
            "-lc",
            "-o",
            candidate,
        ],
        cwd=work,
        timeout=timeout,
    )
    ref_env = reference_env(work)
    ref_env["LD_LIBRARY_PATH"] = str(work)
    got_env = candidate_env(work)
    got_env["LD_LIBRARY_PATH"] = f"{TARGET}:{work}"
    ref = run([reference], env=ref_env, cwd=work, timeout=timeout)
    got = run([candidate], env=got_env, cwd=work, timeout=timeout)
    if ref.returncode != 0 or ref.stderr or ref.timed_out:
        raise LoaderSuiteError(f"pinned musl lifecycle reference failed: {ref.json()}")
    for marker in (
        b"ctor\n",
        b"lifecycle=73\n",
        b"after-close\n",
        b"reopened=73\n",
        b"dtor\n",
    ):
        if marker not in ref.stdout:
            raise LoaderSuiteError(
                f"pinned musl lifecycle reference omitted {marker!r}: {ref.json()}"
            )
    if got != ProcessResult(got.argv, ref.returncode, ref.stdout, ref.stderr, ref.timed_out):
        raise LoaderSuiteError(
            "crabc differs from pinned musl DSO constructor/destructor lifecycle: "
            f"reference={ref.json()} candidate={got.json()}"
        )
    return {"result": "pass", "reference": ref.json(), "candidate": got.json()}


def compare_preload(work: pathlib.Path, timeout: float) -> dict[str, object]:
    """Prove LD_PRELOAD interposes a startup dependency before relocation."""

    cc = compiler()
    target = work / "libpreload_target.so"
    override = work / "libpreload_override.so"
    reference = work / "preload-reference"
    candidate = work / "preload-candidate"
    checked(
        [cc, "-shared", "-fPIC", FIXTURES / "preload_target.c", "-o", target],
        cwd=work,
        timeout=timeout,
    )
    checked(
        [cc, "-shared", "-fPIC", FIXTURES / "preload_override.c", "-o", override],
        cwd=work,
        timeout=timeout,
    )
    common = [
        cc,
        "-fPIE",
        "-pie",
        FIXTURES / "preload_main.c",
        "-L",
        work,
        f"-Wl,-rpath,{work}",
        "-Wl,--no-as-needed",
        "-lpreload_target",
        "-Wl,--as-needed",
    ]
    checked([*common, "-o", reference], cwd=work, timeout=timeout)
    checked(
        [
            *common,
            "-Wl,--dynamic-linker",
            TARGET / "libldso.so",
            "-L",
            TARGET,
            "-lc",
            "-o",
            candidate,
        ],
        cwd=work,
        timeout=timeout,
    )
    dynamic = checked(["readelf", "-dW", reference], cwd=work, timeout=timeout)
    if "libpreload_target.so" not in dynamic.stdout.decode("utf-8", errors="replace"):
        raise LoaderSuiteError("preload fixture lost its intended startup dependency")
    ref_env = reference_env(work)
    ref_env["LD_LIBRARY_PATH"] = str(work)
    ref_env["LD_PRELOAD"] = "libpreload_override.so"
    got_env = candidate_env(work)
    got_env["LD_LIBRARY_PATH"] = f"{TARGET}:{work}"
    got_env["LD_PRELOAD"] = "libpreload_override.so"
    ref = run([reference], env=ref_env, cwd=work, timeout=timeout)
    got = run([candidate], env=got_env, cwd=work, timeout=timeout)
    expected = ProcessResult(ref.argv, 0, b"preload=9\n", b"", False)
    if ref != expected:
        raise LoaderSuiteError(f"pinned musl preload reference failed: {ref.json()}")
    if got != ProcessResult(got.argv, ref.returncode, ref.stdout, ref.stderr, ref.timed_out):
        raise LoaderSuiteError(
            "crabc differs from pinned musl LD_PRELOAD interposition: "
            f"reference={ref.json()} candidate={got.json()}"
        )
    return {"result": "pass", "reference": ref.json(), "candidate": got.json()}


def aslr_bases(result: ProcessResult) -> tuple[int, int]:
    if result.returncode != 0 or result.stderr or result.timed_out:
        raise LoaderSuiteError(f"ASLR fixture did not exit cleanly: {result.json()}")
    match = re.fullmatch(
        rb"aslr=7 main=0x([0-9a-fA-F]+) dso=0x([0-9a-fA-F]+)\n", result.stdout
    )
    if match is None:
        raise LoaderSuiteError(f"ASLR fixture produced an unexpected stream: {result.json()}")
    return int(match.group(1), 16), int(match.group(2), 16)


def compare_aslr(work: pathlib.Path, timeout: float) -> dict[str, object]:
    """Require separate process starts to receive distinct DSO load bases."""

    cc = compiler()
    dso = work / "libaslr.so"
    reference = work / "aslr-reference"
    candidate = work / "aslr-candidate"
    checked(
        [cc, "-shared", "-fPIC", FIXTURES / "aslr_dso.c", "-o", dso],
        cwd=work,
        timeout=timeout,
    )
    common = [cc, "-fPIE", "-pie", "-D_GNU_SOURCE", FIXTURES / "aslr_main.c", "-ldl"]
    checked([*common, "-o", reference], cwd=work, timeout=timeout)
    checked(
        [
            *common,
            "-Wl,--dynamic-linker",
            TARGET / "libldso.so",
            "-L",
            TARGET,
            "-lc",
            "-o",
            candidate,
        ],
        cwd=work,
        timeout=timeout,
    )
    ref_env = reference_env(work)
    ref_env["LD_LIBRARY_PATH"] = str(work)
    got_env = candidate_env(work)
    got_env["LD_LIBRARY_PATH"] = f"{TARGET}:{work}"
    ref_runs = [run([reference], env=ref_env, cwd=work, timeout=timeout) for _ in range(2)]
    got_runs = [run([candidate], env=got_env, cwd=work, timeout=timeout) for _ in range(2)]
    ref_bases = [aslr_bases(result) for result in ref_runs]
    got_bases = [aslr_bases(result) for result in got_runs]
    if ref_bases[0][0] == ref_bases[1][0] or ref_bases[0][1] == ref_bases[1][1]:
        raise LoaderSuiteError(f"pinned musl did not randomize this fixture: {ref_bases!r}")
    if got_bases[0][0] == got_bases[1][0] or got_bases[0][1] == got_bases[1][1]:
        raise LoaderSuiteError(
            "crabc reused a PIE or DSO base across independent process starts: "
            f"{got_bases!r}"
        )
    return {
        "result": "pass",
        "reference": [item.json() for item in ref_runs],
        "candidate": [item.json() for item in got_runs],
    }


def compare_dynamic_tls(work: pathlib.Path, timeout: float) -> dict[str, object]:
    """Verify a late TLS module initializes both current and older threads."""

    cc = compiler()
    dso = work / "libfixture_tls.so"
    reference = work / "tls-reference"
    candidate = work / "tls-candidate"
    checked(
        [cc, "-shared", "-fPIC", FIXTURES / "tls_dso.c", "-o", dso],
        cwd=work,
        timeout=timeout,
    )
    relocations = checked(["readelf", "-Wr", dso], cwd=work, timeout=timeout)
    names = relocation_types(relocations.stdout)
    if "R_AARCH64_TLSDESC" not in names:
        raise LoaderSuiteError(f"TLS fixture lacks a TLSDESC relocation: {sorted(names)}")
    common = [cc, "-fPIE", "-pie", FIXTURES / "tls_main.c", "-ldl", "-lpthread"]
    checked([*common, "-o", reference], cwd=work, timeout=timeout)
    checked(
        [
            *common,
            "-Wl,--dynamic-linker",
            TARGET / "libldso.so",
            "-L",
            TARGET,
            "-lc",
            "-o",
            candidate,
        ],
        cwd=work,
        timeout=timeout,
    )
    ref_env = reference_env(work)
    ref_env["LD_LIBRARY_PATH"] = str(work)
    got_env = candidate_env(work)
    got_env["LD_LIBRARY_PATH"] = f"{TARGET}:{work}"
    ref = run([reference], env=ref_env, cwd=work, timeout=timeout)
    got = run([candidate], env=got_env, cwd=work, timeout=timeout)
    expected = ProcessResult(ref.argv, 0, b"tls=6/5\n", b"", False)
    if ref != expected:
        raise LoaderSuiteError(f"pinned musl dynamic TLS reference failed: {ref.json()}")
    if got != ProcessResult(got.argv, ref.returncode, ref.stdout, ref.stderr, ref.timed_out):
        raise LoaderSuiteError(
            "crabc differs from pinned musl late-loaded TLS behavior: "
            f"reference={ref.json()} candidate={got.json()}"
        )
    return {"result": "pass", "reference": ref.json(), "candidate": got.json()}


def compare_relocations(work: pathlib.Path, timeout: float) -> dict[str, object]:
    """Exercise actual RELATIVE, ABS64, GLOB_DAT, and JUMP_SLOT relocations."""

    cc = compiler()
    provider = work / "libreloc_provider.so"
    consumer = work / "libreloc_consumer.so"
    reference = work / "reloc-reference"
    candidate = work / "reloc-candidate"
    checked(
        [cc, "-shared", "-fPIC", FIXTURES / "reloc_provider.c", "-o", provider],
        cwd=work,
        timeout=timeout,
    )
    checked(
        [
            cc,
            "-shared",
            "-fPIC",
            FIXTURES / "reloc_consumer.c",
            "-L",
            work,
            f"-Wl,-rpath,{work}",
            "-Wl,--no-as-needed",
            "-lreloc_provider",
            "-o",
            consumer,
        ],
        cwd=work,
        timeout=timeout,
    )
    relocation_names = relocation_types(
        checked(["readelf", "-Wr", consumer], cwd=work, timeout=timeout).stdout
    )
    required = {
        "R_AARCH64_RELATIVE",
        "R_AARCH64_ABS64",
        "R_AARCH64_GLOB_DAT",
        "R_AARCH64_JUMP_SLOT",
    }
    missing = required - relocation_names
    if missing:
        raise LoaderSuiteError(
            "relocation fixture lacks required AArch64 classes: "
            f"missing={sorted(missing)} observed={sorted(relocation_names)}"
        )
    common = [
        cc,
        "-fPIE",
        "-pie",
        FIXTURES / "reloc_main.c",
        "-L",
        work,
        f"-Wl,-rpath,{work}",
        "-Wl,--no-as-needed",
        "-lreloc_consumer",
        "-Wl,--as-needed",
    ]
    checked([*common, "-o", reference], cwd=work, timeout=timeout)
    checked(
        [
            *common,
            "-Wl,--dynamic-linker",
            TARGET / "libldso.so",
            "-L",
            TARGET,
            "-lc",
            "-o",
            candidate,
        ],
        cwd=work,
        timeout=timeout,
    )
    ref = run([reference], env=reference_env(work), cwd=work, timeout=timeout)
    got = run([candidate], env=candidate_env(work), cwd=work, timeout=timeout)
    expected = ProcessResult(ref.argv, 0, b"reloc=42\n", b"", False)
    if ref != expected:
        raise LoaderSuiteError(f"pinned musl relocation reference failed: {ref.json()}")
    if got != ProcessResult(got.argv, ref.returncode, ref.stdout, ref.stderr, ref.timed_out):
        raise LoaderSuiteError(
            "crabc differs from pinned musl AArch64 relocation handling: "
            f"reference={ref.json()} candidate={got.json()}"
        )
    return {"result": "pass", "reference": ref.json(), "candidate": got.json()}


def compare_weak_strong(work: pathlib.Path, timeout: float) -> dict[str, object]:
    """Preserve musl's first-definition lookup across weak and strong symbols."""

    cc = compiler()
    weak = work / "libweak_provider.so"
    strong = work / "libstrong_provider.so"
    reference = work / "weak-strong-reference"
    candidate = work / "weak-strong-candidate"
    checked(
        [cc, "-shared", "-fPIC", FIXTURES / "weak_provider.c", "-o", weak],
        cwd=work,
        timeout=timeout,
    )
    checked(
        [cc, "-shared", "-fPIC", FIXTURES / "strong_provider.c", "-o", strong],
        cwd=work,
        timeout=timeout,
    )
    common = [
        cc,
        "-fPIE",
        "-pie",
        FIXTURES / "weak_strong_main.c",
        "-L",
        work,
        f"-Wl,-rpath,{work}",
        "-Wl,--no-as-needed",
        "-lweak_provider",
        "-lstrong_provider",
        "-Wl,--as-needed",
    ]
    checked([*common, "-o", reference], cwd=work, timeout=timeout)
    checked(
        [
            *common,
            "-Wl,--dynamic-linker",
            TARGET / "libldso.so",
            "-L",
            TARGET,
            "-lc",
            "-o",
            candidate,
        ],
        cwd=work,
        timeout=timeout,
    )
    dynamic = checked(["readelf", "-dW", reference], cwd=work, timeout=timeout)
    text = dynamic.stdout.decode("utf-8", errors="replace")
    weak_at = text.find("libweak_provider.so")
    strong_at = text.find("libstrong_provider.so")
    if weak_at < 0 or strong_at < 0 or weak_at >= strong_at:
        raise LoaderSuiteError("weak/strong fixture lost its intended DT_NEEDED order")
    ref = run([reference], env=reference_env(work), cwd=work, timeout=timeout)
    got = run([candidate], env=candidate_env(work), cwd=work, timeout=timeout)
    # This is deliberately not a generic ELF-strength rule. In this lookup
    # scope pinned musl resolves the earlier weak definition before it reaches
    # the later strong provider. Keep that observed loader contract explicit.
    expected = ProcessResult(ref.argv, 0, b"lookup=1\n", b"", False)
    if ref != expected:
        raise LoaderSuiteError(f"pinned musl weak/strong reference failed: {ref.json()}")
    if got != ProcessResult(got.argv, ref.returncode, ref.stdout, ref.stderr, ref.timed_out):
        raise LoaderSuiteError(
            "crabc differs from pinned musl weak/strong symbol lookup: "
            f"reference={ref.json()} candidate={got.json()}"
        )
    return {"result": "pass", "reference": ref.json(), "candidate": got.json()}


def execute(selected: set[str], timeout: float) -> dict[str, object]:
    cases: dict[str, object] = {}
    with tempfile.TemporaryDirectory(prefix="crabc-ldso-") as temporary:
        work = pathlib.Path(temporary)
        if "nested-needed" in selected:
            cases["nested-needed"] = compare_nested_graph(work, timeout)
        if "nested-dlopen" in selected:
            cases["nested-dlopen"] = compare_nested_dlopen(work, timeout)
        if "search-path" in selected:
            cases["search-path"] = compare_search_path(work, timeout)
        if "dso-origin" in selected:
            cases["dso-origin"] = compare_dso_origin(work, timeout)
        if "initial-tls" in selected:
            cases["initial-tls"] = compare_initial_tls(work, timeout)
        if "dlerror" in selected:
            cases["dlerror"] = compare_dlerror(work, timeout)
        if "hash-formats" in selected:
            cases["hash-formats"] = compare_hash_formats(work, timeout)
        if "hash-many" in selected:
            cases["hash-many"] = compare_many_symbol_hash_lookup(work, timeout)
        if "relro" in selected:
            cases["relro"] = compare_relro(work, timeout)
        if "auxv" in selected:
            cases["auxv"] = compare_auxv(work, timeout)
        if "legacy-lifecycle" in selected:
            cases["legacy-lifecycle"] = compare_legacy_lifecycle(work, timeout)
        if "lookup-scope" in selected:
            cases["lookup-scope"] = compare_lookup_scope(work, timeout)
        if "visibility" in selected:
            cases["visibility"] = compare_visibility(work, timeout)
        if "constructor-order" in selected:
            cases["constructor-order"] = compare_constructor_order(work, timeout)
        if "main-handle" in selected:
            cases["main-handle"] = compare_main_handle(work, timeout)
        if "lifecycle" in selected:
            cases["lifecycle"] = compare_lifecycle(work, timeout)
        if "preload" in selected:
            cases["preload"] = compare_preload(work, timeout)
        if "aslr" in selected:
            cases["aslr"] = compare_aslr(work, timeout)
        if "dynamic-tls" in selected:
            cases["dynamic-tls"] = compare_dynamic_tls(work, timeout)
        if "relocations" in selected:
            cases["relocations"] = compare_relocations(work, timeout)
        if "weak-strong" in selected:
            cases["weak-strong"] = compare_weak_strong(work, timeout)
    return cases


def write_report(report: dict[str, object]) -> None:
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    temporary = REPORT.with_suffix(".tmp")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(REPORT)


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--case",
        action="append",
        choices=(
            "nested-needed",
            "nested-dlopen",
            "search-path",
            "dso-origin",
            "initial-tls",
            "dlerror",
            "hash-formats",
            "hash-many",
            "relro",
            "auxv",
            "legacy-lifecycle",
            "lookup-scope",
            "visibility",
            "constructor-order",
            "main-handle",
            "lifecycle",
            "preload",
            "aslr",
            "dynamic-tls",
            "relocations",
            "weak-strong",
        ),
        help="run one named synthetic loader case (repeatable)",
    )
    parser.add_argument("--timeout", type=float, default=5.0)
    return parser.parse_args(argv)


def main(argv: Sequence[str]) -> int:
    args = parse_args(argv)
    started = time.time()
    report: dict[str, object] = {
        "schema": 1,
        "runner": "compat/ldso/run.py",
        "architecture": platform.machine(),
        "reference": {"kind": "pinned-musl", "libdir": str(MUSL_REFERENCE_LIBDIR)},
        "candidate": {"ldso": str(TARGET / "libldso.so"), "libc": str(TARGET / "libc.so")},
        "selected": args.case
        or [
            "nested-needed",
            "nested-dlopen",
            "search-path",
            "dso-origin",
            "initial-tls",
            "dlerror",
            "hash-formats",
            "relro",
            "auxv",
            "legacy-lifecycle",
            "lookup-scope",
            "visibility",
            "constructor-order",
            "main-handle",
            "lifecycle",
            "preload",
            "aslr",
            "dynamic-tls",
            "relocations",
            "weak-strong",
        ],
        "timeout_seconds": args.timeout,
    }
    try:
        require_aarch64()
        selected = set(
            args.case
            or [
                "nested-needed",
                "nested-dlopen",
                "search-path",
                "dso-origin",
                "initial-tls",
                "dlerror",
                "hash-formats",
                "hash-many",
                "relro",
                "auxv",
                "legacy-lifecycle",
                "lookup-scope",
                "visibility",
                "constructor-order",
                "main-handle",
                "lifecycle",
                "preload",
                "aslr",
                "dynamic-tls",
                "relocations",
                "weak-strong",
            ]
        )
        report["cases"] = execute(selected, args.timeout)
        report["result"] = "pass"
    except (LoaderSuiteError, OSError) as error:
        report["result"] = "fail"
        report["error"] = str(error)
        write_report(report)
        print(f"ldso: FAIL: {error}", file=sys.stderr)
        return 1
    report["elapsed_seconds"] = round(time.time() - started, 3)
    write_report(report)
    print(f"ldso: PASS: {len(report['cases'])} synthetic case(s)")
    print(f"ldso: report: {REPORT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
