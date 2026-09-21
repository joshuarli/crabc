#!/usr/bin/env python3
"""Exercise guarded PT_DYNAMIC table bounds through the provider.

This is standalone provider evidence only. It does not qualify arbitrary
metadata, loader callbacks, DSO lifetime, or an owned runtime consumer.
"""
from metadata_bounds import run_fixture


EXPECTED_OUTPUT = 'guarded dynamic table rejected\n'


def main() -> None:
    print(run_fixture(
        'unwinder-dynamic-bounds-runs',
        'truncated_dynamic.rs',
        EXPECTED_OUTPUT,
        'standalone guarded PT_DYNAMIC provider regression',
        'truncated-dynamic-execution.log',
        'truncated-dynamic',
    ))


if __name__ == '__main__':
    main()
