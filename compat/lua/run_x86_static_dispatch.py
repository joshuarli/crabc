#!/usr/bin/env python3
"""Invoke one isolated native x86 Lua static source-build qualification."""

from __future__ import annotations

import argparse
import json
import math
import sys
from typing import Sequence

import run as LUA


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jobs", type=int, default=LUA.DEFAULT_JOBS)
    parser.add_argument("--timeout", type=float, default=120.0)
    args = parser.parse_args(argv)
    if args.jobs < 1 or args.jobs > LUA.MAX_JOBS:
        parser.error(f"--jobs must be an integer from 1 through {LUA.MAX_JOBS}")
    if not math.isfinite(args.timeout) or args.timeout <= 0 or args.timeout > 300:
        parser.error("--timeout must be > 0 and <= 300")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        report, report_path, latest = LUA.run_x86_static_dispatch(jobs=args.jobs, timeout=args.timeout)
    except LUA.RunnerError as error:
        print(f"x86 Lua static source-build dispatcher failed: {error}", file=sys.stderr)
        return 1
    result = {
        "state_root": str(report_path.parent),
        "report": str(report_path),
        "latest_report": str(latest) if latest is not None else None,
        "passed": report.get("passed") is True,
    }
    print(json.dumps(result, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
