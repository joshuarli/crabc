#!/usr/bin/env python3
"""The C-ABI provider-closure reader rejects every musl metadata drift."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat" / "x86_64"))

import owned_c_abi_provider_closure as reader  # noqa: E402

RUNNER = ROOT / "compat/x86_64/run_owned_process_globals.sh"
PROCESS_GLOBALS = reader.frozen_roster(["process.globals"])

# Pinned musl 1.2.6 x86-64 process.globals storage groups: canonical first.
GROUPS = (
    ("__environ", "environ", "_environ", "___environ"),
    ("__optreset", "optreset"),
    ("__progname", "program_invocation_short_name"),
    ("__progname_full", "program_invocation_name"),
    ("__signgam", "signgam"),
    ("__timezone", "timezone"),
    ("__daylight", "daylight"),
    ("__tzname", "tzname"),
    ("getopt", "__posix_getopt"),
    ("__optpos",), ("h_errno",), ("optarg",), ("opterr",), ("optind",), ("optopt",),
    ("__h_errno_location",), ("getenv",), ("putenv",), ("getopt_long",),
    ("getopt_long_only",),
)
FUNCTION_NAMES = frozenset({
    "__h_errno_location", "__posix_getopt", "getenv", "getopt", "getopt_long",
    "getopt_long_only", "putenv",
})
SIZES = {
    "__environ": 8, "__progname": 8, "__progname_full": 8, "__timezone": 8,
    "__tzname": 16, "optarg": 8,
}


def rows(
    *,
    member: str = "",
    binding: dict[str, str] | None = None,
    size: dict[str, int] | None = None,
    value: dict[str, int] | None = None,
    suffix: dict[str, str] | None = None,
    omit: frozenset[str] = frozenset(),
    extra: tuple[str, ...] = (),
) -> str:
    """Render a musl-shaped `readelf --wide` symbol transcript."""
    lines = [f"File: libc.a({member})"] if member else []
    lines.append("   Num:    Value          Size Type    Bind   Vis      Ndx Name")
    index = 1
    for group_index, group in enumerate(GROUPS):
        for position, name in enumerate(group):
            if name in omit:
                continue
            kind = "FUNC" if name in FUNCTION_NAMES else "OBJECT"
            bind = (binding or {}).get(name, "GLOBAL" if position == 0 else "WEAK")
            width = (size or {}).get(name, SIZES.get(group[0], 4) if kind == "OBJECT" else 32)
            address = (value or {}).get(name, 0x1000 + 0x40 * group_index)
            spelling = name + (suffix or {}).get(name, "")
            lines.append(
                f"  {index:4d}: {address:016x} {width:5d} {kind:<7} {bind:<6} DEFAULT   20 {spelling}"
            )
            index += 1
    lines.extend(extra)
    return "\n".join(lines) + "\n"


def row(index: int, name: str, value: int, *, kind: str = "FUNC", bind: str = "GLOBAL",
        visibility: str = "DEFAULT") -> str:
    return f"  {index:4d}: {value:016x}    32 {kind:<7} {bind:<6} {visibility:<8} 20 {name}"


def armap(member: str, names: tuple[str, ...], omit: frozenset[str] = frozenset()) -> str:
    return "Archive index:\n" + "".join(
        f"{name} in {member}\n" for name in names if name not in omit
    )


class ProviderClosureReaderTests(unittest.TestCase):
    def test_roster_comes_from_the_frozen_ledger(self) -> None:
        self.assertEqual(len(PROCESS_GLOBALS.names), 31)
        helper = reader.frozen_roster(["numeric.qsort-helper"])
        self.assertEqual(helper.names, ("__qsort_r",))
        self.assertEqual(helper.candidate_only, frozenset({"__qsort_r"}))
        with self.assertRaisesRegex(reader.ProviderClosureError, "must name no.such once"):
            reader.frozen_roster(["no.such"])
        with self.assertRaisesRegex(reader.ProviderClosureError, "duplicate capability"):
            reader.frozen_roster(["process.globals", "process.globals"])

    def test_matching_shared_and_static_metadata_passes(self) -> None:
        shared = reader.audit_shared(PROCESS_GLOBALS, rows(), rows(), rows(member="env.lo"))
        self.assertEqual(shared["names"], 31)
        self.assertIn(["___environ", "__environ", "_environ", "environ"], shared["aliases"])
        static = reader.audit_static(
            PROCESS_GLOBALS, rows(member="c.o"), armap("c.o", PROCESS_GLOBALS.names),
            rows(member="env.lo"), armap("env.lo", PROCESS_GLOBALS.names),
        )
        self.assertEqual(static["members"], ["c.o"])

    def test_undefined_and_local_rows_are_not_providers(self) -> None:
        extra = (
            "     9: 0000000000000000     0 OBJECT  GLOBAL DEFAULT  UND optind",
            "    10: 0000000000002000     4 OBJECT  LOCAL  DEFAULT   20 optopt",
        )
        report = reader.audit_shared(PROCESS_GLOBALS, rows(extra=extra), rows(), rows())
        self.assertEqual(report["names"], 31)

    def test_metadata_drift_is_rejected(self) -> None:
        cases = {
            "binding": rows(binding={"environ": "GLOBAL"}),
            "size": rows(size={"__tzname": 8, "tzname": 8}),
            "optreset shares storage with": rows(value={"optreset": 0x9000}),
            "unversioned": rows(suffix={"getenv": "@@CRABC_1"}),
            "does not define": rows(omit=frozenset({"__signgam"})),
            "2 times": rows(extra=(
                "    90: 0000000000009000     4 OBJECT  GLOBAL DEFAULT   20 h_errno",
            )),
        }
        for message, candidate in cases.items():
            with self.subTest(message=message):
                with self.assertRaisesRegex(reader.ProviderClosureError, message):
                    reader.audit_shared(PROCESS_GLOBALS, candidate, rows(), rows())

    def test_folded_entry_points_outside_the_roster_are_rejected(self) -> None:
        # An identical-body fold of a roster function with an unrelated
        # library function is visible through function-pointer comparison.
        folded = row(90, "unrelated_destroy", 0x1000 + 0x40 * 16)
        distinct = row(90, "unrelated_destroy", 0x8000)
        reader.audit_shared(PROCESS_GLOBALS, rows(extra=(distinct,)), rows(extra=(distinct,)), rows())
        with self.assertRaisesRegex(
            reader.ProviderClosureError, r"getenv shares storage with \['unrelated_destroy'\]"
        ):
            reader.audit_shared(PROCESS_GLOBALS, rows(extra=(folded,)), rows(extra=(distinct,)), rows())

    def test_candidate_only_export_follows_the_static_oracle(self) -> None:
        helper = reader.frozen_roster(["numeric.qsort-helper"])
        musl_static = "\n".join((
            "File: libc.a(qsort.lo)",
            row(1, "__qsort_r", 0x100, visibility="HIDDEN"),
            row(2, "qsort_r", 0x100, bind="WEAK"),
        ))
        musl_shared = row(1, "qsort_r", 0x100, bind="WEAK")
        exported = "\n".join((row(1, "__qsort_r", 0x500), row(2, "qsort_r", 0x500, bind="WEAK")))
        self.assertEqual(
            reader.audit_shared(helper, exported, musl_shared, musl_static)["candidate_only"],
            ["__qsort_r"],
        )
        hidden = "\n".join((row(1, "__qsort_r", 0x500, visibility="HIDDEN"),
                             row(2, "qsort_r", 0x500, bind="WEAK")))
        with self.assertRaisesRegex(reader.ProviderClosureError, "must export candidate-only"):
            reader.audit_shared(helper, hidden, musl_shared, musl_static)
        split = "\n".join((row(1, "__qsort_r", 0x500), row(2, "qsort_r", 0x600, bind="WEAK")))
        with self.assertRaisesRegex(reader.ProviderClosureError, "musl libc.a shares it with"):
            reader.audit_shared(helper, split, musl_shared, musl_static)
        with self.assertRaisesRegex(reader.ProviderClosureError, "exports candidate-only"):
            reader.audit_shared(helper, exported, exported, musl_static)

    def test_static_provider_must_be_archive_extractable(self) -> None:
        with self.assertRaisesRegex(
            reader.ProviderClosureError, "archive index does not extract daylight"
        ):
            reader.audit_static(
                PROCESS_GLOBALS,
                rows(member="c.o"), armap("c.o", PROCESS_GLOBALS.names, frozenset({"daylight"})),
                rows(member="tz.lo"), armap("tz.lo", PROCESS_GLOBALS.names),
            )

    def test_non_pie_consumer_requires_copy_storage_for_each_group(self) -> None:
        relocations = "\n".join(
            f"0000000000404d60  0000003100000005 R_X86_64_COPY          0000000000404d60 {group[0]} + 0"
            for group in GROUPS if group[0] not in FUNCTION_NAMES
        )
        library = rows()
        executable = rows(omit=FUNCTION_NAMES)
        audit = reader.audit_copy_executable
        report = audit(PROCESS_GLOBALS, executable, relocations, library, library, "fixture")
        self.assertEqual(report["groups"], 14)
        with self.assertRaisesRegex(reader.ProviderClosureError, "does not own COPY storage for tzname"):
            audit(PROCESS_GLOBALS, rows(omit=FUNCTION_NAMES | {"tzname"}), relocations, library,
                  library, "fixture")
        with self.assertRaisesRegex(reader.ProviderClosureError, "no R_X86_64_COPY"):
            audit(PROCESS_GLOBALS, executable, relocations.replace("optind", "stdout"), library,
                  library, "fixture")
        with self.assertRaisesRegex(reader.ProviderClosureError, "COPY alias partition"):
            audit(PROCESS_GLOBALS, rows(omit=FUNCTION_NAMES, value={"_environ": 0x9000}),
                  relocations, library, library, "fixture")


class ProcessGlobalsRunnerTests(unittest.TestCase):
    def assert_usage(self, *arguments: str) -> None:
        scratch = ROOT / ".work" / "x86_64" / "tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="owned-process-globals-parser.", dir=scratch) as temporary:
            tools = Path(temporary) / "tools"
            tools.mkdir()
            python = tools / "python3"
            python.write_text("#!/bin/sh\nexit 79\n", encoding="utf-8")
            python.chmod(0o755)
            environment = dict(os.environ)
            environment["PATH"] = f"{tools}{os.pathsep}{environment['PATH']}"
            result = subprocess.run(
                ["bash", str(RUNNER), *arguments], cwd=ROOT, env=environment,
                capture_output=True, text=True, check=False,
            )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(
            result.stderr,
            f"usage: {RUNNER} [--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]\n",
        )

    def test_runner_requires_both_products_or_neither(self) -> None:
        self.assert_usage("--static-sysroot", "static")
        self.assert_usage("dynamic")
        self.assert_usage("--static-sysroot")
        self.assert_usage("--unknown")


if __name__ == "__main__":
    unittest.main()
