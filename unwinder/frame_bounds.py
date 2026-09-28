#!/usr/bin/env python3
"""Exercise CFI, expression, and callback-lifetime errors through the provider."""
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
    print(run_fixture(
        'unwinder-frame-bounds-runs',
        'eh_frame_lifetime.rs',
        'mapped unwind=5\nmapped wait=0\nunmapped unwind=3\nunmapped wait=0\n'
        'unreadable unwind=3\nunreadable wait=0\n'
        'oversized unwind=3\noversized wait=0\n'
        'truncated unwind=3\ntruncated wait=0\n'
        'long-fde unwind=5\nlong-fde wait=0\n'
        'EH frame lifetime guarded\n',
        'standalone EH-frame remote reader regression',
        'eh-frame-lifetime-execution.log',
        'eh-frame-lifetime',
    ))


if __name__ == '__main__':
    main()
