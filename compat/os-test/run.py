#!/usr/bin/env python3
"""Compare a pinned, POSIX-oriented os-test profile under musl and crabc.

The runner deliberately drives os-test's own make targets.  That preserves its
modern feature-test-macro, header, namespace, compile, and execution checks
instead of reducing the suite to hand-written smoke tests.  Each runtime gets
an isolated copy of the immutable checkout, so generated binaries and reports
cannot cross-contaminate the other oracle or the repository.
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
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal


MUSL_VERSION = "1.2.6"
OS_TEST_REVISION = "5e9456d510612f83b6ec8b1a0c06d6b1303a2512"
DEFAULT_MUSL_ROOT = Path(f"/opt/musl-{MUSL_VERSION}")
DEFAULT_OS_TEST_ROOT = Path("/opt/os-test")
# These are the portable standards-facing suites from Stage 7. Resolver and
# loopback behavior have dedicated M6 stress runners; deliberately excluding
# os-test's externally-routed UDP probes keeps this profile offline and avoids
# turning public-network reachability into a pass.
DEFAULT_SUITES = (
    "include",
    "namespace",
    "basic",
    "io",
    "limits",
    "malloc",
    "process",
    "pty",
    "signal",
    "stdio",
)

# os-test's namespace suite encodes its source oracle: a conforming probe
# writes exactly ``good\n``. Pinned musl 1.2.6 reports pollution for several
# probes, so comparing crabc to that incidental result would require copying a
# known namespace failure. Evaluate crabc directly against the suite's
# declared result and retain musl as an audit observation. The generated
# include suite remains a byte-for-byte musl comparison: its matrix contains
# musl-scoped optional and extension declarations for which `good` is not the
# portable expectation.
SOURCE_ORACLE_SUITES = frozenset(("namespace",))
SOURCE_ORACLE_OUTCOME = b"good\n"

# These three generated namespace probes request headers that the pinned musl
# profile intentionally does not provide. The explicit `missing_header`
# result is the suite's skip outcome, not namespace pollution. Keep this
# list exact so another missing header cannot become an accidental pass.
SOURCE_ORACLE_EXPECTATIONS = {
    ("namespace", "devctl-xsi.out"): b"missing_header\n",
    ("namespace", "devctl.out"): b"missing_header\n",
    ("namespace", "ndbm-xsi.out"): b"missing_header\n",
}

# The basic target's normal source contract is a clean executable exit. The
# only named alternate outcome is os-test's musl-scoped devctl header skip.
# This contract does not replace the musl differential oracle: it is used only
# to recognize a candidate result that is strictly cleaner than a diagnostic
# emitted by the pinned musl run. A non-clean candidate outcome is never an
# improvement and remains subject to the ordinary musl comparison.
BASIC_SOURCE_OUTCOME = b"exit: 0\n"
BASIC_SOURCE_EXPECTATIONS = {
    "devctl/posix_devctl.out": b"missing_header\n",
}


class RunnerError(Exception):
    """Raised for an invalid runner configuration, not an oracle mismatch."""


@dataclass(frozen=True)
class Runtime:
    name: str
    include: Path
    ld_library_path: str | None
    ldflags: str


@dataclass(frozen=True)
class ExceptionRule:
    """One evidence-backed, exact os-test comparison exception.

    Rules are deliberately data, rather than path/pattern filters hidden in
    the comparison loop.  The report serializes the rule identity and scope,
    while the original bytes/statuses remain in the raw runtime report and
    difference entry.
    """

    id: str
    suite: str
    kind: Literal["make_status", "outcome"]
    case: str
    reason: str
    source_test: str
    source_expectation: str | None = None
    reference_outcome: str | None = None
    candidate_outcome: str | None = None
    reference_status: int | None = None
    candidate_status: int | None = None

    def descriptor(self) -> dict[str, Any]:
        """Return the machine-readable manifest entry for a report."""

        return {
            "id": self.id,
            "suite": self.suite,
            "kind": self.kind,
            "case": self.case,
            "reason": self.reason,
            "source": {
                "test": self.source_test,
                "expectation": self.source_expectation,
                "revision": OS_TEST_REVISION,
            },
        }


@dataclass(frozen=True)
class FrontierRule:
    """A measured but unresolved case, never used to make a suite pass."""

    id: str
    suite: str
    case: str
    reason: str
    source_test: str

    def descriptor(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "suite": self.suite,
            "case": self.case,
            "status": "unresolved",
            "reason": self.reason,
            "source": {
                "test": self.source_test,
                "revision": OS_TEST_REVISION,
            },
        }


# These are the only accepted differences in this runner.  Keep each process
# case separate: the pinned sources are three distinct tests and a new or
# renamed case must not inherit an exception accidentally.
MAKE_STATUS_EXCEPTIONS = (
    ExceptionRule(
        id="basic.dlfcn.dlclose.shared-no-main-link",
        suite="basic",
        kind="make_status",
        case="dlfcn/dlclose.so",
        reason=(
            "The pinned basic .c.so rule links dlfcn/dlclose.c with SHARED; "
            "the source has no main in that branch, so both pinned invocations "
            "stop at the linker's status 2."
        ),
        source_test="basic/GNUmakefile:.c.so dlfcn/dlclose.so",
        reference_status=2,
        candidate_status=2,
    ),
)

OUTCOME_EXCEPTIONS = (
    ExceptionRule(
        id="process.waitpid-pgid-empty-on-setpgid-rejoin.musl-alarm",
        suite="process",
        kind="outcome",
        case="waitpid-pgid-empty-on-setpgid-rejoin.out",
        reason=(
            "The pinned source documents ECHILD as correct, but pinned musl "
            "waitpid remains blocked until the test's SIGALRM handler exits 1."
        ),
        source_test="process/waitpid-pgid-empty-on-setpgid-rejoin.c",
        source_expectation="process.expect/waitpid-pgid-empty-on-setpgid-rejoin.1",
        reference_outcome="SIGALRM\n",
        candidate_outcome="exit: 1\n",
    ),
    ExceptionRule(
        id="process.waitpid-pgid-empty-on-setpgid.musl-alarm",
        suite="process",
        kind="outcome",
        case="waitpid-pgid-empty-on-setpgid.out",
        reason=(
            "The pinned source documents ECHILD as correct, but pinned musl "
            "waitpid remains blocked until the test's SIGALRM handler exits 1."
        ),
        source_test="process/waitpid-pgid-empty-on-setpgid.c",
        source_expectation="process.expect/waitpid-pgid-empty-on-setpgid.1",
        reference_outcome="SIGALRM\n",
        candidate_outcome="exit: 1\n",
    ),
    ExceptionRule(
        id="process.waitpid-pgid-empty-on-setsid.musl-alarm",
        suite="process",
        kind="outcome",
        case="waitpid-pgid-empty-on-setsid.out",
        reason=(
            "The pinned source documents ECHILD as correct, but pinned musl "
            "waitpid remains blocked until the test's SIGALRM handler exits 1."
        ),
        source_test="process/waitpid-pgid-empty-on-setsid.c",
        source_expectation="process.expect/waitpid-pgid-empty-on-setsid.1",
        reference_outcome="SIGALRM\n",
        candidate_outcome="exit: 1\n",
    ),
)

UNRESOLVED_FRONTIER: tuple[FrontierRule, ...] = ()


def repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--suite",
        action="append",
        choices=DEFAULT_SUITES,
        help="profile suite to run (repeatable; defaults to the whole M6 profile)",
    )
    parser.add_argument(
        "--os-test-root",
        type=Path,
        default=Path(os.environ.get("OS_TEST_ROOT", DEFAULT_OS_TEST_ROOT)),
        help="pinned os-test checkout (default: OS_TEST_ROOT or %(default)s)",
    )
    parser.add_argument(
        "--musl-root",
        type=Path,
        default=Path(os.environ.get("MUSL_ROOT", DEFAULT_MUSL_ROOT)),
        help="pinned musl installation (default: MUSL_ROOT or %(default)s)",
    )
    parser.add_argument(
        "--target-dir",
        type=Path,
        default=Path(os.environ.get("CRABC_TARGET_DIR", repository_root() / "target/debug")),
        help="directory containing candidate libc.so and libldso.so",
    )
    parser.add_argument(
        "--musl-cc",
        default=os.environ.get("MUSL_CC", "musl-gcc"),
        help="pinned-musl compiler command (default: MUSL_CC or musl-gcc)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=float(os.environ.get("CRABC_OS_TEST_TIMEOUT", "180")),
        help="timeout per os-test suite in seconds (default: %(default)s)",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=None,
        help="JSON result path (default: compat/reports/os-test/latest.json)",
    )
    return parser.parse_args()


def resolve(path: Path) -> Path:
    return path.expanduser().resolve()


def check_inputs(args: argparse.Namespace) -> tuple[Path, Path, Path, list[str]]:
    if platform.machine() != "aarch64":
        raise RunnerError(f"requires native AArch64 (platform.machine() was {platform.machine()})")
    if args.timeout <= 0:
        raise RunnerError(f"--timeout must be positive: {args.timeout}")

    os_test = resolve(args.os_test_root)
    musl = resolve(args.musl_root)
    target = resolve(args.target_dir)
    revision = os_test / ".crabc-revision"
    if not (os_test / "GNUmakefile").is_file() or not (os_test / "misc/suites.list").is_file():
        raise RunnerError(f"pinned os-test checkout not found: {os_test}")
    if not revision.is_file() or revision.read_text(encoding="ascii").strip() != OS_TEST_REVISION:
        raise RunnerError(f"os-test revision marker is not {OS_TEST_REVISION}: {revision}")
    if musl.name != f"musl-{MUSL_VERSION}" or not (musl / "include").is_dir():
        raise RunnerError(f"pinned musl-{MUSL_VERSION} headers not found: {musl / 'include'}")
    if not (target / "libc.so").is_file() or not (target / "libldso.so").is_file():
        raise RunnerError(f"crabc artifacts not found in {target}")
    compiler = args.musl_cc.split()
    if not compiler or shutil.which(compiler[0]) is None:
        raise RunnerError(f"compiler not found: {args.musl_cc}")
    if shutil.which("make") is None:
        raise RunnerError("make is required by pinned os-test")
    return os_test, musl, target, compiler


def stream_snapshot(stream: bytes) -> dict[str, Any]:
    return {
        "byte_length": len(stream),
        "sha256": hashlib.sha256(stream).hexdigest(),
        "text": stream.decode("utf-8", errors="replace"),
    }


def atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", prefix=f".{path.name}.", suffix=".tmp", dir=path.parent,
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def make_command(
    suite: str,
    compiler: list[str],
    runtime: Runtime,
    source_root: Path,
) -> list[str]:
    # CC is deliberately a single make assignment.  os-test's recipes expand
    # it as a shell command, while the remaining variables carry only paths or
    # linker switches that are valid after this expansion.
    return [
        "make",
        "-C",
        str(source_root),
        "-j1",
        f"{suite}-test",
        f"CC={' '.join(compiler)}",
        # Preserve the native AArch64 long-double ABI.  The candidate and
        # pinned musl must be compared under the same compiler contract.
        "CFLAGS=-fPIE",
        f"CPPFLAGS=-I{runtime.include}",
        f"LDFLAGS={runtime.ldflags}",
        "EXTRA_LDFLAGS=",
        # os-test's namespace analyzer is a host-side reporting tool; it must
        # not accidentally become another candidate-runtime test binary.
        "CC_FOR_BUILD=cc",
        "CFLAGS_FOR_BUILD=",
        "CPPFLAGS_FOR_BUILD=",
        "LDFLAGS_FOR_BUILD=",
    ]


def run_make(command: list[str], environment: dict[str, str], timeout: float) -> tuple[int | str, bytes, bytes]:
    try:
        completed = subprocess.run(
            command,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
        )
        return completed.returncode, completed.stdout, completed.stderr
    except subprocess.TimeoutExpired as error:
        return "TIMEOUT", error.stdout or b"", error.stderr or b""


def collect_outcomes(root: Path, suite: str) -> dict[str, bytes]:
    outcome_root = root / "out/linux" / suite
    if not outcome_root.is_dir():
        return {}
    return {
        path.relative_to(outcome_root).as_posix(): path.read_bytes()
        for path in sorted(outcome_root.rglob("*.out"))
    }


def compare_outcomes(reference: dict[str, bytes], candidate: dict[str, bytes]) -> list[dict[str, str]]:
    differences: list[dict[str, str]] = []
    for name in sorted(set(reference) | set(candidate)):
        left = reference.get(name)
        right = candidate.get(name)
        if left == right:
            continue
        differences.append(
            {
                "case": name,
                "musl": "missing" if left is None else left.decode("utf-8", errors="replace"),
                "crabc": "missing" if right is None else right.decode("utf-8", errors="replace"),
            }
        )
    return differences


def compare_source_oracle_outcomes(
    suite: str,
    expected_cases: set[str] | list[str] | tuple[str, ...],
    outcomes: dict[str, bytes],
) -> list[dict[str, str]]:
    """Return header-suite failures against os-test's explicit ``good`` oracle.

    An absent output is a failure in the same way as a diagnostic-bearing
    output.  The complete candidate bytes are retained so a report can be
    audited without rerunning the native suite.
    """

    return [
        source_oracle_difference(suite, name, value)
        for name in sorted(set(expected_cases) | set(outcomes))
        if (value := outcomes.get(name)) != source_oracle_expected(suite, name)
    ]


def source_oracle_expected(suite: str, case: str) -> bytes:
    """Return this named header probe's source-defined expected outcome."""

    return SOURCE_ORACLE_EXPECTATIONS.get((suite, case), SOURCE_ORACLE_OUTCOME)


def source_oracle_difference(suite: str, case: str, value: bytes | None) -> dict[str, str]:
    expected = source_oracle_expected(suite, case)
    return {
        "case": case,
        "expected": expected.decode("utf-8", errors="replace"),
        "crabc": "missing" if value is None else value.decode("utf-8", errors="replace"),
    }


def basic_source_expected(case: str) -> bytes:
    """Return basic's exact source-defined outcome for this test case."""

    return BASIC_SOURCE_EXPECTATIONS.get(case, BASIC_SOURCE_OUTCOME)


def basic_source_differences(outcomes: dict[str, bytes]) -> list[dict[str, str]]:
    """Report basic diagnostics against its own exit-success contract.

    This observation remains separate from the musl-differential pass/fail
    decision. It prevents a raw differential match from being mistaken for a
    successful basic source run when both runtimes emit the same diagnostic.
    """

    return [
        {
            "case": case,
            "expected": basic_source_expected(case).decode("utf-8", errors="replace"),
            "crabc": value.decode("utf-8", errors="replace"),
        }
        for case, value in sorted(outcomes.items())
        if value != basic_source_expected(case)
    ]


def source_contract_passed(suite: str, candidate: dict[str, bytes]) -> bool:
    """Return whether the candidate meets basic's direct source contract.

    A source improvement over musl is valuable evidence, but it cannot turn a
    suite green while crabc still emits another basic diagnostic. The other
    suites keep their existing differential/source-oracle gates.
    """

    return suite != "basic" or not basic_source_differences(candidate)


def suite_result_passed(
    suite: str,
    candidate: dict[str, bytes],
    make_status_ok: bool,
    unaccepted_difference_count: int,
) -> bool:
    """Apply the final green gate shared by the report and contract tests."""

    return bool(
        make_status_ok
        and candidate
        and source_contract_passed(suite, candidate)
        and unaccepted_difference_count == 0
    )


def classify_basic_source_improvements(
    reference: dict[str, bytes],
    candidate: dict[str, bytes],
    differences: list[dict[str, str]],
) -> list[dict[str, str]]:
    """Classify only strict basic improvements over a failing musl outcome.

    The candidate must equal the named source outcome exactly, and musl must
    have produced a present, different outcome. This cannot accept a timeout,
    a missing result, or a differently failing candidate result.
    """

    improvements: list[dict[str, str]] = []
    for difference in differences:
        case = difference["case"]
        expected = basic_source_expected(case)
        reference_value = reference.get(case)
        candidate_value = candidate.get(case)
        if (
            reference_value is not None
            and reference_value != expected
            and candidate_value == expected
        ):
            improvements.append(
                {
                    "case": case,
                    "expected": expected.decode("utf-8", errors="replace"),
                    "musl": difference["musl"],
                    "crabc": difference["crabc"],
                    "source_test": f"basic/{case.removesuffix('.out')}.c",
                }
            )
    return improvements


def classify_outcome_difference(
    suite: str,
    difference: dict[str, str],
) -> ExceptionRule | None:
    """Classify one raw outcome difference against the exact manifest.

    Matching requires suite, relative outcome path, and both complete decoded
    outcome texts.  In particular, a missing outcome or an extra diagnostic
    cannot be accepted by a rule for the corresponding test.
    """

    for rule in OUTCOME_EXCEPTIONS:
        if (
            rule.suite == suite
            and rule.case == difference.get("case")
            and rule.reference_outcome == difference.get("musl")
            and rule.candidate_outcome == difference.get("crabc")
        ):
            return rule
    return None


def classify_make_status_exception(
    suite: str,
    runtime_reports: dict[str, dict[str, Any]],
) -> ExceptionRule | None:
    """Classify the one pinned basic make failure, retaining stderr evidence."""

    if suite != "basic":
        return None
    musl = runtime_reports.get("musl", {})
    crabc = runtime_reports.get("crabc", {})
    musl_status = musl.get("make_status")
    crabc_status = crabc.get("make_status")
    musl_stderr = musl.get("stderr", {}).get("text", "")
    crabc_stderr = crabc.get("stderr", {}).get("text", "")
    for rule in MAKE_STATUS_EXCEPTIONS:
        if (
            rule.suite == suite
            and musl_status == rule.reference_status
            and crabc_status == rule.candidate_status
            # The target and no-main linker diagnostic are source-derived
            # anchors.  Equal stderr ensures both oracle invocations stopped
            # for the same reason, rather than merely sharing an exit code.
            and musl_stderr == crabc_stderr
            and rule.case in musl_stderr
            and "undefined reference to `main'" in musl_stderr
        ):
            return rule
    return None


def exception_report(
    rule: ExceptionRule,
    raw_difference: dict[str, str] | None = None,
    runtime_reports: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Serialize a matched rule with the raw evidence that made it match."""

    result = rule.descriptor()
    if raw_difference is not None:
        # Keep this alongside (and not instead of) the suite's differences
        # list, so consumers can audit accepted exceptions without rerunning.
        result["raw_difference"] = raw_difference
    if runtime_reports is not None:
        result["raw_make_status"] = {
            name: runtime_reports[name].get("make_status")
            for name in ("musl", "crabc")
            if name in runtime_reports
        }
        result["raw_stderr"] = {
            name: runtime_reports[name].get("stderr")
            for name in ("musl", "crabc")
            if name in runtime_reports
        }
    return result


def classify_unresolved_frontier(
    suite: str,
    reference: dict[str, bytes],
    candidate: dict[str, bytes],
) -> list[dict[str, Any]]:
    """Expose named precision gaps with their raw bytes without accepting them."""

    result: list[dict[str, Any]] = []
    for rule in UNRESOLVED_FRONTIER:
        if rule.suite != suite or (rule.case not in reference and rule.case not in candidate):
            continue
        entry = rule.descriptor()
        entry["raw_outcomes"] = {
            "musl": stream_snapshot(reference[rule.case]) if rule.case in reference else "missing",
            "crabc": stream_snapshot(candidate[rule.case]) if rule.case in candidate else "missing",
        }
        result.append(entry)
    return result


def run_profile(args: argparse.Namespace) -> bool:
    os_test, musl, target, compiler = check_inputs(args)
    suites = tuple(args.suite) if args.suite else DEFAULT_SUITES
    report_path = resolve(args.report) if args.report else repository_root() / "compat/reports/os-test/latest.json"
    candidate_include = repository_root() / "include"
    runtimes = (
        Runtime("musl", musl / "include", None, "-pie -lc"),
        Runtime(
            "crabc",
            candidate_include,
            str(target),
            f"-pie -Wl,--dynamic-linker={target / 'libldso.so'} -L{target} -Wl,--allow-shlib-undefined -lc",
        ),
    )
    report: dict[str, Any] = {
        # v3 distinguishes direct source-oracle header checks from runtime
        # musl-vs-crabc comparisons. Raw observations from both runtimes are
        # retained in every case.
        "schema_version": 3,
        "runner": "pinned-os-test",
        "os_test_revision": OS_TEST_REVISION,
        "musl_version": MUSL_VERSION,
        "platform": platform.machine(),
        "exception_manifest": [
            rule.descriptor()
            for rule in (*MAKE_STATUS_EXCEPTIONS, *OUTCOME_EXCEPTIONS)
        ],
        "unresolved_frontier_manifest": [
            rule.descriptor() for rule in UNRESOLVED_FRONTIER
        ],
        "suites": [],
        "passed": True,
    }

    with tempfile.TemporaryDirectory(prefix="crabc-os-test-") as temporary_name:
        temporary = Path(temporary_name)
        for suite in suites:
            runtime_reports: dict[str, Any] = {}
            for runtime in runtimes:
                work = temporary / runtime.name / suite
                shutil.copytree(os_test, work, symlinks=True)
                environment = os.environ.copy()
                environment["TMPDIR"] = str(temporary / "tmp" / runtime.name / suite)
                Path(environment["TMPDIR"]).mkdir(parents=True, exist_ok=True)
                if runtime.ld_library_path is None:
                    environment.pop("LD_LIBRARY_PATH", None)
                else:
                    environment["LD_LIBRARY_PATH"] = runtime.ld_library_path
                command = make_command(suite, compiler, runtime, work)
                status, stdout, stderr = run_make(command, environment, args.timeout)
                outcomes = collect_outcomes(work, suite)
                runtime_reports[runtime.name] = {
                    "make_status": status,
                    "stdout": stream_snapshot(stdout),
                    "stderr": stream_snapshot(stderr),
                    "outcome_count": len(outcomes),
                    "outcomes": {
                        name: stream_snapshot(value)
                        for name, value in outcomes.items()
                    },
                }
            reference = collect_outcomes(temporary / "musl" / suite, suite)
            candidate = collect_outcomes(temporary / "crabc" / suite, suite)
            source_oracle = suite in SOURCE_ORACLE_SUITES
            if source_oracle:
                expected_cases = set(reference) | set(candidate)
                differences = compare_source_oracle_outcomes(suite, expected_cases, candidate)
                musl_source_oracle_differences = compare_source_oracle_outcomes(
                    suite, expected_cases, reference
                )
                runtime_differences = compare_outcomes(reference, candidate)
            else:
                differences = compare_outcomes(reference, candidate)
                musl_source_oracle_differences = []
                runtime_differences = differences
            unresolved_frontier = classify_unresolved_frontier(
                suite, reference, candidate
            )
            candidate_source_differences = (
                basic_source_differences(candidate) if suite == "basic" else []
            )
            musl_source_differences = (
                basic_source_differences(reference) if suite == "basic" else []
            )
            source_improvements = (
                classify_basic_source_improvements(reference, candidate, runtime_differences)
                if suite == "basic"
                else []
            )
            accepted_outcomes = [
                exception_report(rule, raw_difference=difference)
                for difference in differences
                if (rule := classify_outcome_difference(suite, difference)) is not None
            ]
            accepted_make = classify_make_status_exception(suite, runtime_reports)
            # Keep outcome and make exceptions in distinct lists: the shared
            # basic make-status exception must not consume an outcome-diff
            # allowance when computing this suite's differential result.
            accepted_exceptions = [*accepted_outcomes]
            if accepted_make is not None:
                accepted_exceptions.append(
                    exception_report(accepted_make, runtime_reports=runtime_reports)
                )
            unaccepted_difference_count = (
                len(differences) - len(accepted_outcomes) - len(source_improvements)
            )
            make_status_ok = all(
                runtime_reports[runtime.name]["make_status"] == 0
                for runtime in runtimes
            ) or accepted_make is not None
            # A byte-for-byte musl match is not enough for basic: the
            # generated source contract requires every candidate outcome
            # to be the source-defined clean exit (or its one named header
            # skip). Keep this gate separate from differential exceptions so
            # a shared diagnostic cannot make the suite green by accident.
            suite_passed = suite_result_passed(
                suite, candidate, make_status_ok, unaccepted_difference_count
            )
            report["suites"].append(
                {
                    "suite": suite,
                    "passed": suite_passed,
                    "result": (
                        "pass-with-source-improvements"
                        if suite_passed and source_improvements
                        else "fail-source-contract"
                        if suite == "basic" and candidate_source_differences
                        else "pass" if suite_passed else "fail"
                    ),
                    "runtimes": runtime_reports,
                    "difference_count": len(differences),
                    "differences": differences,
                    "oracle": (
                        "os-test-source-good" if source_oracle else "pinned-musl-differential"
                    ),
                    "runtime_difference_count": len(runtime_differences),
                    "runtime_differences": runtime_differences,
                    "musl_source_oracle_difference_count": len(musl_source_oracle_differences),
                    "musl_source_oracle_differences": musl_source_oracle_differences,
                    "candidate_source_failure_count": len(candidate_source_differences),
                    "candidate_source_failures": candidate_source_differences,
                    "source_contract_passed": (
                        source_contract_passed(suite, candidate)
                        if suite == "basic"
                        else None
                    ),
                    "musl_source_failure_count": len(musl_source_differences),
                    "musl_source_failures": musl_source_differences,
                    "source_improvement_count": len(source_improvements),
                    "source_improvements": source_improvements,
                    "accepted_exception_count": len(accepted_exceptions),
                    "accepted_exceptions": accepted_exceptions,
                    "unaccepted_difference_count": unaccepted_difference_count,
                    "unresolved_frontier_count": len(unresolved_frontier),
                    "unresolved_frontier": unresolved_frontier,
                }
            )
            report["passed"] = bool(report["passed"] and suite_passed)

    atomic_write_json(report_path, report)
    totals = report["suites"]
    passed = sum(item["passed"] for item in totals)
    print(f"os-test: {'PASS' if report['passed'] else 'FAIL'}: {passed}/{len(totals)} suite(s)")
    print(f"os-test: report: {report_path}")
    return bool(report["passed"])


def main() -> int:
    try:
        return 0 if run_profile(parse_args()) else 1
    except RunnerError as error:
        print(f"os-test: ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
