#!/usr/bin/env python3
"""Exercise concurrent hermetic DNS fixtures while the legacy address is busy."""

from __future__ import annotations

import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[2]


def main() -> None:
    def interrupted(_signal: int, _frame: object) -> None:
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    executable = Path(sys.argv[1]).resolve(strict=True)
    workspace = ROOT / ".work" / "resolver-fixture-checks"
    for directory in (ROOT / ".work", workspace):
        if directory.is_symlink() or directory.resolve() != directory:
            raise SystemExit("resolver fixture scratch must be a physical checkout path")
        directory.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=workspace) as temporary, socket.socket(
        socket.AF_INET, socket.SOCK_DGRAM
    ) as occupied:
        # Binding the former shared endpoint makes the pre-fix failure
        # deterministic, rather than relying on a concurrent scheduling race.
        occupied.bind(("127.0.0.1", 53))
        workers: list[tuple[subprocess.Popen[bytes], Path, int]] = []
        try:
            for index in range(5):
                fixture = Path(temporary) / str(index)
                fixture.mkdir()
                expected = 3 if index == 4 else 0
                if not expected:
                    (fixture / "etc").mkdir()
                    (fixture / "etc" / "hosts").write_text(
                        "192.0.2.44 host.fixture host-alias\n", encoding="ascii"
                    )
                    # The old probe needs a configuration to reach the address
                    # collision. The fixed probe replaces it after reserving its
                    # own loopback endpoint, before any resolver call.
                    (fixture / "etc" / "resolv.conf").write_text(
                        "nameserver 127.0.0.1\nsearch fixture.test\n"
                        "options ndots:1 timeout:1 attempts:1\n", encoding="ascii"
                    )
                process = subprocess.Popen(
                    [str(executable), str(fixture)],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    start_new_session=True,
                )
                workers.append((process, fixture, expected))
            addresses = set()
            for process, fixture, expected in workers:
                stdout, stderr = process.communicate(timeout=15)
                if process.returncode != expected:
                    raise RuntimeError(
                        f"concurrent resolver fixture exited {process.returncode}: "
                        f"{stdout!r} {stderr!r}"
                    )
                if not expected:
                    addresses.add((fixture / "etc" / "resolv.conf").read_text().splitlines()[0])
                try:
                    os.killpg(process.pid, 0)
                except ProcessLookupError:
                    pass
                else:
                    raise RuntimeError("resolver fixture left a descendant after completion")
            if len(addresses) != 4 or "nameserver 127.0.0.1" in addresses:
                raise RuntimeError("resolver fixtures did not reserve distinct loopback endpoints")
        finally:
            for process, _, _ in workers:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
    print("resolver fixture concurrent endpoint isolation and failure cleanup: PASS")


if __name__ == "__main__":
    main()
