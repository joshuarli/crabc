#!/usr/bin/env python3
"""Exercise a guarded indirect CIE personality pointer through the provider.

This is standalone provider evidence only. It does not qualify arbitrary
DWARF expressions, loader callbacks, DSO lifetime, or an owned runtime
consumer.
"""
from metadata_bounds import run_fixture


EXPECTED_OUTPUT = 'indirect personality pointer rejected\n'


def main() -> None:
    print(run_fixture(
        'unwinder-indirect-personality-bounds-runs',
        'indirect_personality.rs',
        EXPECTED_OUTPUT,
        'standalone guarded indirect CIE personality provider regression',
        'indirect-personality-execution.log',
        'indirect-personality',
    ))


if __name__ == '__main__':
    main()
