#!/usr/bin/env python3
"""Exercise CFI and expression error propagation through the selected provider."""
from metadata_bounds import run_fixture


def main() -> None:
    print(run_fixture(
        'unwinder-frame-bounds-runs',
        'frame_rules.rs',
        'CFI and expression errors rejected\n',
        'standalone guarded CFI and expression provider regression',
        'frame-rules-execution.log',
        'frame-rules',
    ))
    print(run_fixture(
        'unwinder-frame-bounds-runs',
        'guarded_register_rule.rs',
        'guarded register rule rejected\n',
        'standalone guarded register-rule provider regression',
        'guarded-register-rule-execution.log',
        'guarded-register-rule',
    ))
    print(run_fixture(
        'unwinder-frame-bounds-runs',
        'forked_self_read.rs',
        'allowed probe=8\nallowed unwind=5\nallowed wait=0\n'
        'denied probe=-1 errno=1\ndenied unwind=3\ndenied wait=0\n'
        'forked self-read policy respected\n',
        'standalone forked self-read provider regression',
        'forked-self-read-execution.log',
        'forked-self-read',
    ))


if __name__ == '__main__':
    main()
