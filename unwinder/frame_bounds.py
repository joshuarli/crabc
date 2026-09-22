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


if __name__ == '__main__':
    main()
