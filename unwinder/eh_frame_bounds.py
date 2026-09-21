#!/usr/bin/env python3
"""Exercise guarded decoded-.eh_frame pointer boundaries through the provider.

This is standalone provider evidence only. It does not qualify arbitrary DWARF,
loader callbacks, DSO lifetime, or an owned runtime consumer.
"""
from metadata_bounds import run_fixture


EXPECTED_OUTPUT = 'guarded EH frame pointers rejected\n'


def main() -> None:
    print(run_fixture(
        'unwinder-eh-frame-bounds-runs',
        'guarded_eh_frame.rs',
        EXPECTED_OUTPUT,
        'standalone guarded decoded .eh_frame provider regression',
        'guarded-eh-frame-execution.log',
        'guarded-eh-frame',
    ))


if __name__ == '__main__':
    main()
