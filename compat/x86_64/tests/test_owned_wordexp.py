#!/usr/bin/env python3
"""Focused contracts for the owned x86 wordexp installed-product slice."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
MODULE = ROOT / "libc/src/c_abi/x86_64/owned_wordexp.rs"
SPAWN = ROOT / "libc/src/c_abi/x86_64/owned_spawn.rs"
ENGINE = ROOT / "libc/src/c_abi/x86_64/owned_wordexp_engine.rs"
PROCESS = ROOT / "libc/src/c_abi/x86_64/owned_wordexp_process.rs"
RESULTS = ROOT / "libc/src/c_abi/x86_64/owned_wordexp_results.rs"
PROBE = ROOT / "compat/x86_64/owned_wordexp_probe.c"
POSIX_PROBE = ROOT / "compat/x86_64/owned_wordexp_posix_probe.c"
RUNNER = ROOT / "compat/x86_64/run_libc_owned_wordexp.sh"
EVIDENCE = ROOT / "compat/x86_64/owned_wordexp_evidence.py"
DISPATCHER = ROOT / "scripts/dev-x86_64.sh"


class OwnedWordexpContracts(unittest.TestCase):
    def test_probe_has_source_mode_and_allocation_lifecycle_boundaries(self) -> None:
        source = PROBE.read_text(encoding="utf-8")
        for boundary in (
            "WRDE_DOOFFS | WRDE_APPEND", "WRDE_REUSE", "WRDE_NOCMD",
            "WRDE_CMDSUB", "WRDE_BADCHAR", "WRDE_SYNTAX", "WRDE_UNDEF",
            "check_freed", "--shell-unavailable", "unavailable_shell_case",
            "--nocmd-source", "source_nocmd_case", "owned-wordexp-nocmd-source: PASS",
            "$((case $A in a) echo x ;; *) echo y ;; esac))",
            "errno = ERANGE", "errno != ERANGE", "owned-wordexp: PASS",
            "owned-wordexp-shell-unavailable: PASS",
            '#include "owned_wordexp_posix_probe.c"',
        ):
            self.assertIn(boundary, source)

    def test_posix_probe_captures_the_corrections_frames_and_unqualified_boundary(self) -> None:
        source = POSIX_PROBE.read_text(encoding="utf-8")
        for boundary in (
            "posix_quiet_case", "pipe(diagnostics)", "dup2", "read_count",
            "WRDE_SYNTAX", "ERANGE", "posix_nocmd_case", "${FOO}",
            "${X} ${Y}", "${UNSET_X-${UNSET_Y-default}}", "deeply_nested",
            "literal_open_brace", "WORDEXP_NOCMD_LITERAL_OPEN",
            "${WORDEXP_NOCMD_LITERAL_OPEN-{}",
            "{; printf marker > /wordexp-nocmd-marker",
            "${WORDEXP_NOCMD_LITERAL_OPEN-{}$(printf marker > /wordexp-nocmd-marker)",
            "private lexical depth limit",
            "$(( ${UNSET_X-2} + ${UNSET_Y-3} ))", "\\\\${FOO}",
            "WORDEXP_NOCMD_MARKER", "WRDE_CMDSUB", "WRDE_BADCHAR",
            "posix_nocmd_escaped_brace_control_case",
            "posix_nocmd_arithmetic_command_control_case",
            "posix_nocmd_pattern_control_case",
            "posix_nocmd_arithmetic_delimiter_control_case",
            "posix_nocmd_continuation_command_control_case",
            "posix_nocmd_dollar_single_control_case",
            "posix_nocmd_comment_control_case", "# \\\"\\n",
            "posix_nocmd_positional_case", "${10}", "${#1}", "${#10}",
            "portable wordexp transcript",
            "posix_undef_source_observation", "WRDE_BADVAL",
        ):
            self.assertIn(boundary, source)

    def test_selected_adapter_has_one_record_owner_and_explicit_typed_boundaries(self) -> None:
        source = MODULE.read_text(encoding="utf-8")
        engine = ENGINE.read_text(encoding="utf-8")
        results = RESULTS.read_text(encoding="utf-8")
        self.assertIn("WordexpResultRecord as Wordexp", source)
        self.assertNotIn("struct Wordexp {", source)
        self.assertIn("struct WordexpResultRecord", results)
        for boundary in ("WordexpSyntax::parse", "syntax.has_commands()", "evaluate_wordexp_into",
                         "WordexpResultTransaction::begin", "commit_completed", "WordexpError::NoSpace",
                         "WordexpError::UndefinedVariable => WRDE_BADVAL",
                         "WordexpEnvironmentSnapshot::capture", "NativeWordexpPaths::new"):
            self.assertIn(boundary, source)
        self.assertIn("trait WordexpResultSink", engine)
        self.assertIn("trait WordexpDiagnosticSink", engine)
        self.assertNotIn("include!(", source)
        self.assertNotIn("getdelim", source)
        self.assertNotIn("WORDEXP_QUIET_SCRIPT", source)

    def test_only_process_adapter_owns_spawn_and_child_failure_translation(self) -> None:
        module = MODULE.read_text(encoding="utf-8")
        process = PROCESS.read_text(encoding="utf-8")
        spawn = SPAWN.read_text(encoding="utf-8")
        self.assertNotIn("owned_spawn", module)
        self.assertIn("spawn_with_outcome", process)
        self.assertIn("SpawnOutcome::ChildFailure", process)
        self.assertIn("errno_before_spawn", process)
        self.assertIn("WordexpError::Syntax", process)
        self.assertIn("pub(super) enum SpawnOutcome", spawn)
        self.assertIn("ParentFailure", spawn)
        self.assertIn("ChildFailure", spawn)
        self.assertIn("pub(super) unsafe fn spawn(", spawn)

    def test_runner_preserves_default_boundary_and_proves_both_installed_modes(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        for boundary in (
            "frozen default archive unexpectedly exports",
            "--features x86-owned-static-runtime", "-static-pie",
            "pinned-musl wordexp oracle is not static ET_EXEC",
            "TMPDIR physically escapes checkout .work",
            "retained failure evidence", "run_installed_mode -static et-exec",
            "run_installed_mode -static-pie static-pie",
            "make_private_shell_root", "missing inaccessible invalid",
            "audit_linker_trace", "runtime allowlist or exact application-object receipt drifted",
            "chroot_command", "controlled-shell.sha256", "run_same_object_wordexp_cases",
            "same-object-wordexp", "workload.sha256", "WORD_EXP_CASES", "_case_spec",
            "compare_wordexp_streams", "_assert_case_results", "selectors.tsv",
            "POSIX_PROBE", "FOO=field X=left Y=right", ".status",
            "SET=1", "mknod", "character device 1:3 mode 666",
            "TMPDIR=/wordexp-tmp", "source/candidate policies",
            "local audit_root=\"$(dirname \"$candidate\")\"",
        ):
            self.assertIn(boundary, source)
        self.assertNotIn("--wrap=", source)
        self.assertNotIn('env -i CRABC_WORDEXP=\'bar baz\' "$candidate"', source)

    def test_retained_six_mode_evidence_keeps_source_reds_separate_from_positive_cells(self) -> None:
        source = EVIDENCE.read_text(encoding="utf-8")
        for boundary in (
            'crabc.x86_64-owned-wordexp-products/v4', "POSIX_PROBE",
            "WORD_EXP_CASES", "CELL_ENVIRONMENT", "posix-quiet-source-red",
            "posix-nocmd-source-red", "posix-nocmd-arithmetic-source-red",
            "posix-nocmd-continuation-source-red", "posix-nocmd-dollar-single-source-red",
            "posix-nocmd-comment-source-red", "posix-nocmd-positional-source-red",
            "fixture_devices", "char-device", "_null_device_identity", "undef-source-observation",
            "_assert_case_results", "required=False", "SOURCE-RED diagnostic-present",
            "SOURCE-RED parameter-brace-rejected", "SOURCE-RED positional-parameter-rejected",
            "MODULE = \"libc/src/c_abi/x86_64/owned_wordexp.rs\"",
            "ENGINE = \"libc/src/c_abi/x86_64/owned_wordexp_engine.rs\"",
            "installed header trace omitted the POSIX correction cells",
        ):
            self.assertIn(boundary, source)

    def test_dispatcher_exposes_the_dedicated_native_gate(self) -> None:
        source = DISPATCHER.read_text(encoding="utf-8")
        self.assertIn("libc-owned-wordexp", source)
        self.assertIn("run_libc_owned_wordexp.sh", source)
        self.assertIn("run_in_chroot_cap_container bash /workspace/compat/x86_64/run_libc_owned_wordexp.sh", source)


if __name__ == "__main__":
    unittest.main()
