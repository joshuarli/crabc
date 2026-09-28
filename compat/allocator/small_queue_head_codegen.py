#!/usr/bin/env python3
"""Trace the ordinary 8 KiB allocation through the shared codegen audit."""

from compat.allocator import codegen_audit_x86_64 as audit


def main() -> int:
    audit.SCENARIOS = (
        audit.Scenario(
            "local_8192",
            "trace_local",
            {"size": 8192},
            ("malloc", "free"),
            "initial-thread regular small queue allocation and free",
        ),
    )
    return audit.main()


if __name__ == "__main__":
    raise SystemExit(main())
