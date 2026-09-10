#!/usr/bin/env python3
"""Regression checks for the pinned-musl declared-but-unprovided audit."""

from __future__ import annotations

import importlib.util
import json
import sys
from tempfile import TemporaryDirectory
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

    def test_every_selected_defined_posix_nm_binding_is_a_provider(self) -> None:
        providers = AUDIT.global_or_weak_providers(
            """libc.a(member.o): indirect_provider i 0 0
unique_provider u 0 0
""",
            {"indirect_provider", "unique_provider"},
        )

        self.assertEqual(
            providers,
            {"indirect_provider": ["i"], "unique_provider": ["u"]},
        )

    def test_malformed_selected_posix_nm_row_fails_closed(self) -> None:
        with self.assertRaisesRegex(AUDIT.OracleNoProviderAuditError, "malformed selected nm row"):
            AUDIT.global_or_weak_providers("truncated_provider i 0\n", {"truncated_provider"})

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

    def test_link_failure_rejects_an_unrelated_fatal_diagnostic(self) -> None:
        stderr = """ld: object.o: in function `main':
ld: object.o:(.text+0x0): undefined reference to `pthread_mutexattr_getprioceiling'
ld: cannot find -lnot-an-oracle-input
collect2: error: ld returned 1 exit status
"""

        with self.assertRaisesRegex(AUDIT.OracleNoProviderAuditError, "cannot find"):
            AUDIT.require_exact_undefined_reference(
                stderr,
                "pthread_mutexattr_getprioceiling",
            )

    def test_link_failure_accepts_the_pinned_gcc_ld_context_shape(self) -> None:
        AUDIT.require_exact_undefined_reference(
            """/toolchain/bin/ld: object.o: in function `main':
probe.c:(.text+0x10): undefined reference to `pthread_mutexattr_getprioceiling'
collect2: error: ld returned 1 exit status
""",
            "pthread_mutexattr_getprioceiling",
        )

    def test_checked_members_need_a_pinned_reference_external_declaration(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            contract = root / "disposition.toml"
            inventory = root / "inventory.json"
            contract.write_text(
                """[[deferred_owner_group]]
resolution = "oracle-declared-no-provider"
members = ["declared_without_reference"]
""",
                encoding="utf-8",
            )
            inventory.write_text(
                json.dumps(
                    {
                        "schema": AUDIT.INVENTORY_SCHEMA,
                        "callables": [
                            {
                                "classification": "external",
                                "declaration_kind": "function",
                                "declaring_header": "example.h",
                                "name": "declared_without_reference",
                                "tree": "candidate",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(AUDIT.OracleNoProviderAuditError, "pinned reference"):
                AUDIT.checked_no_provider_members(contract, inventory)


if __name__ == "__main__":
    unittest.main()
