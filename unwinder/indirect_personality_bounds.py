#!/usr/bin/env python3
"""Exercise guarded late indirect metadata through the provider.

This is standalone provider evidence only. It does not qualify arbitrary
DWARF expressions, loader callbacks, DSO lifetime, or an owned runtime
consumer.
"""
from metadata_bounds import run_fixture


EXPECTED_OUTPUT = 'guarded late indirect metadata rejected\n'


def main() -> None:
    print(run_fixture(
        'unwinder-indirect-personality-bounds-runs',
        'indirect_personality.rs',
        EXPECTED_OUTPUT,
        'standalone guarded late indirect metadata provider regression',
        'indirect-personality-execution.log',
        'indirect-personality',
    ))


if __name__ == '__main__':
    main()
