#!/usr/bin/env python3
"""Exercise direct CIE personality and FDE LSDA targets through the provider.

This is standalone provider evidence only. It does not qualify arbitrary
DWARF expressions, loader callbacks, DSO lifetime, or an owned runtime
consumer.
"""
from metadata_bounds import run_fixture


EXPECTED_OUTPUT = 'direct metadata targets rejected\n'


def main() -> None:
    print(run_fixture(
        'unwinder-metadata-target-bounds-runs',
        'metadata_targets.rs',
        EXPECTED_OUTPUT,
        'standalone guarded direct CIE personality and FDE LSDA target provider regression',
        'metadata-targets-execution.log',
        'metadata-targets',
    ))


if __name__ == '__main__':
    main()
