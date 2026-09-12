#!/usr/bin/env python3
"""Run one exact allocator unit test inside the pinned native environment.

Cargo succeeds when a filter selects zero tests. This development helper
requires one executed, passing libtest case; it produces no milestone receipt.
The host launcher owns target admission and checkout-local mutable state.
"""

from __future__ import annotations

import re
import subprocess
import sys
from typing import Sequence


TEST_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)+")
ONE_PASS = re.compile(
    r"test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; "
    r"[0-9]+ filtered out; finished in .+"
)


def main(arguments: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if arguments is None else arguments)
    if len(arguments) != 1 or TEST_NAME.fullmatch(arguments[0]) is None:
        print("ERROR: expected one fully qualified Rust test name", file=sys.stderr)
        return 2
    command = [
        "cargo", "test", "--locked", "--target", "x86_64-unknown-linux-musl",
        "-p", "crabc-mimalloc", "--lib", "--no-default-features", arguments[0],
        "--", "--exact", "--nocapture", "--test-threads=1",
    ]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    sys.stdout.write(result.stdout)
    if result.returncode != 0:
        return result.returncode if result.returncode > 0 else 128 - result.returncode
    summaries = [line for line in result.stdout.splitlines() if line.startswith("test result:")]
    if len(summaries) != 1 or ONE_PASS.fullmatch(summaries[0]) is None:
        print("ERROR: exact allocator unit selection did not execute one passing test", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
