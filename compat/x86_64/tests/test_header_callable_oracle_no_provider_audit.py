#!/usr/bin/env python3
"""Regression checks for the pinned-musl declared-but-unprovided audit."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat" / "x86_64" / "header_callable_oracle_no_provider_audit.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


AUDIT = load_module("header_callable_oracle_no_provider_audit_test", SCRIPT)


class HeaderCallableOracleNoProviderAuditTests(unittest.TestCase):
    def test_inspection_failure_is_not_an_absence(self) -> None:
        with self.assertRaisesRegex(AUDIT.OracleNoProviderAuditError, "nm failed"):
            AUDIT.require_successful_inspection("nm", 1, "cannot read archive")

    def test_global_and_weak_symbols_are_providers(self) -> None:
        providers = AUDIT.global_or_weak_providers(
            """libc.a(member.o): declared_global T 0 0
libc.a(member.o): declared_weak W 0 0
libc.a(member.o): unrelated T 0 0
""",
            {"declared_global", "declared_weak"},
        )

        self.assertEqual(set(providers), {"declared_global", "declared_weak"})
        with self.assertRaisesRegex(AUDIT.OracleNoProviderAuditError, "declared_weak"):
            AUDIT.require_no_providers(providers, "pinned libc.a")

    def test_link_failure_rejects_an_unrelated_undefined_symbol(self) -> None:
        stderr = """ld: object.o: undefined reference to `pthread_mutexattr_getprioceiling'
ld: object.o: undefined reference to `unexpected_startup_symbol'
collect2: error: ld returned 1 exit status
"""

        with self.assertRaisesRegex(AUDIT.OracleNoProviderAuditError, "unexpected_startup_symbol"):
            AUDIT.require_exact_undefined_reference(
                stderr,
                "pthread_mutexattr_getprioceiling",
            )

    def test_link_failure_requires_its_intended_undefined_symbol(self) -> None:
        with self.assertRaisesRegex(AUDIT.OracleNoProviderAuditError, "does not name"):
            AUDIT.require_exact_undefined_reference(
                "ld: object.o: undefined reference to `another_symbol'\n",
                "pthread_mutexattr_getprioceiling",
            )


if __name__ == "__main__":
    unittest.main()
