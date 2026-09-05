#!/usr/bin/env python3
"""Structural contract for the private x86 installed-header-tree closure gate."""

from __future__ import annotations

import os
import shlex
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "compat" / "x86_64" / "run_installed_header_tree_closure.sh"


class InstalledHeaderTreeClosureTests(unittest.TestCase):
    def test_materialized_runner_owns_its_oracle_scratch(self) -> None:
        scratch_root = ROOT / ".work/x86_64/installed-header-tree-tests"
        scratch_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch_root) as temporary:
            project = Path(temporary) / "checkout"
            harness = project / "compat/x86_64"
            harness.mkdir(parents=True)
            (project / "include").mkdir()
            (project / "include/example.h").write_text("/* test header */\n")
            scratch = project / ".work/x86_64/tmp"
            scratch.mkdir(parents=True)
            runner = harness / RUNNER.name
            shutil.copy2(RUNNER, runner)
            for name in ("musl_oracle_probe.c", "public_headers.txt", "header_cxx_closure.cpp"):
                (harness / name).write_text("")
            oracle = (ROOT / "compat/x86_64/run_musl_oracle.sh").read_text()
            # Execute the actual oracle preflight, stopping before native tools.
            oracle = oracle.split("require_native_linux_x86_64\nrequire_tool readelf", 1)[0]
            (harness / "run_musl_oracle.sh").write_text(oracle)
            (harness / "run_linux_5_10_uapi.sh").write_text("#!/bin/sh\nexit 0\n")
            candidate = harness / "run_candidate_header_closure.sh"
            candidate.write_text('''#!/usr/bin/env bash
set -euo pipefail
readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh"
mkdir -p "$ROOT_DIR/compat/reports/x86_64/candidate-header-closure"
cat > "$ROOT_DIR/compat/reports/x86_64/candidate-header-closure/latest.tsv" <<'REPORT'
# record_count=1337
# pinned_public_header_count=183
# candidate_public_header_count=191
# profiles=c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict
# status.reference-not-applicable=2
# result=pass
REPORT
''')
            for path in harness.glob("*.sh"):
                path.chmod(0o755)
            mock_bin = Path(temporary) / "bin"
            mock_bin.mkdir()
            mktemp = mock_bin / "mktemp"
            real_mktemp = shlex.quote(shutil.which("mktemp"))
            # Contain the pre-fix runner's literal /tmp request in this fixture.
            mktemp.write_text(f'''#!/bin/sh
if [ "$1" = -d ] && [ "$2" = /tmp/crabc-x86-64-installed-header-tree-closure.XXXXXX ]; then
    exec {real_mktemp} -d "$TMPDIR/crabc-x86-64-installed-header-tree-closure.XXXXXX"
fi
exec {real_mktemp} "$@"
''')
            mktemp.chmod(0o755)
            result = subprocess.run(
                ["bash", str(runner)], cwd=project,
                env={**os.environ, "PATH": f"{mock_bin}:{os.environ['PATH']}", "TMPDIR": str(scratch)},
                text=True, capture_output=True, timeout=20, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("x86 installed header-tree closure: PASS", result.stdout)

    def test_runner_is_executable_and_shell_valid(self) -> None:
        result = subprocess.run(
            ["bash", "-n", str(RUNNER)],
            cwd=ROOT,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(stat.S_IMODE(RUNNER.stat().st_mode), 0o755)

    def test_runner_materializes_and_closes_only_the_installed_tree(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")

        for phrase in (
            "readonly CANDIDATE_CLOSURE_RUNNER=",
            "readonly EXPECTED_PINNED_PUBLIC_HEADER_COUNT=183",
            "readonly EXPECTED_CANDIDATE_PUBLIC_HEADER_COUNT=191",
            "readonly EXPECTED_PROFILE_COUNT=7",
            "readonly EXPECTED_RECORD_COUNT=1337",
            "readonly -a ORACLE_NOT_APPLICABLE_ROWS=(aio.h:c11-strict aio.h:cxx17-strict)",
            "materialize_header_tree",
            'installed_include="$materialized_project/usr/include"',
            "validate_regular_header_tree",
            "source header tree contains a symlink",
            "source header tree contains a non-regular path",
            "write_manifest",
            "sha256sum",
            "installed header manifest differs from source tree",
            "run_candidate_header_closure.sh",
            'readonly PROJECT_INCLUDE="$ROOT_DIR/usr/include"',
            '"# pinned_public_header_count=$EXPECTED_PINNED_PUBLIC_HEADER_COUNT"',
            '"# candidate_public_header_count=$EXPECTED_CANDIDATE_PUBLIC_HEADER_COUNT"',
            "# profiles=c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict",
            "# record_count=$EXPECTED_RECORD_COUNT",
            "# status.reference-not-applicable=2",
            "exactly two aio strict oracle-N/A rows",
            "candidate include trace reached source include tree",
            "candidate include trace reached pinned musl despite -nostdinc",
            "candidate include trace escaped installed-tree/builtin/Linux-5.10 roots",
            "-nostdinc",
            "-nostdinc++",
            "# `-H` trace accepts that tree",
            "# schema=crabc.x86_64-installed-header-tree-closure/v1",
            "# scope=header-tree closure only; not ABI/layout/linkage/sysroot/promotion/public-support parity",
            "x86 installed header-tree closure: PASS",
        ):
            self.assertIn(phrase, runner)

        self.assertNotIn("--report-only", runner)
        self.assertNotIn("installed-header completion", runner)


if __name__ == "__main__":
    unittest.main()
