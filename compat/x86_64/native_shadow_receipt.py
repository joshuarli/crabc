#!/usr/bin/env python3
"""Revision-bound receipts for the installed native-shadow allocator runners.

The runtime-launcher runners that exercise the selected native-mimalloc
shadow products (`libc-native-mimalloc-shadow-pthread-teardown`,
`owned-native-allocator-stress`, and any later `owned-native-allocator-*`
runner) execute only under `scripts/dev-x86_64.sh`, against sysroots and
candidates they build themselves. A milestone gate in another container can
therefore not rerun them; it consumes one receipt per runner instead.

A receipt is a directory `<reports>/native-shadow/<runner>/latest/` holding
`receipt.json` and a `logs/` copy of every raw log it cites:

* `source`: the checkout seal: the `HEAD` revision plus the SHA-256 of the
  working tree's difference from it (tracked changes and untracked,
  non-ignored files). A receipt is valid only for the exact tree it names.
* `products`: SHA-256 and size of every executed program and of the product
  provenance files that name its inputs.
* `cases`: one record per executed case with its exit status and the logs it
  produced, in execution order.
* `parameters` and `canonical`: the runner's workload knobs and whether all
  of them held their reviewed defaults. A development run with reduced
  knobs is recorded honestly but cannot satisfy a gate.

`write` is the producer CLI the runners call after their last case.
`read_receipt` is the one reader both allocator milestone gates import (M5
through `compat/allocator/x86_64_m5_gate.py`, M8 through lane m4's gate); it
fails closed on any stale seal, digest mismatch, missing log, non-canonical
run, or failed case.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

SCHEMA = "crabc.x86_64-native-shadow-runner-receipt/v1"
ROOT = Path(__file__).resolve().parents[2]
RECEIPTS = Path(".work/x86_64/reports/native-shadow")
RUNNER_RE = re.compile(r"[a-z0-9][a-z0-9-]*\Z")
CASE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
REVISION_RE = re.compile(r"[0-9a-f]{40}\Z")


class ReceiptError(Exception):
    """A receipt that cannot satisfy its consumer."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _git(root: Path, *arguments: str) -> bytes:
    # Receipt producers and readers run as container root over a checkout the
    # host user owns; the seal is read-only and must not depend on that.
    completed = subprocess.run(
        ["git", "-c", "safe.directory=*", "-C", str(root), *arguments],
        check=False, capture_output=True, env=dict(os.environ, GIT_OPTIONAL_LOCKS="0"),
    )
    if completed.returncode != 0:
        raise ReceiptError(f"git {' '.join(arguments)} failed: {completed.stderr.decode(errors='replace').strip()}")
    return completed.stdout


def source_seal(root: Path = ROOT) -> dict[str, str]:
    """The checkout's `HEAD` revision and a digest of its difference from it."""

    revision = _git(root, "rev-parse", "--verify", "HEAD").decode().strip()
    digest = hashlib.sha256()
    digest.update(_git(root, "diff", "--binary", "HEAD", "--"))
    untracked = _git(root, "ls-files", "--others", "--exclude-standard", "-z").split(b"\0")
    for name in sorted(entry for entry in untracked if entry):
        path = root / name.decode()
        digest.update(b"untracked\0" + name + b"\0")
        if path.is_file() and not path.is_symlink():
            digest.update(_sha256(path).encode())
    return {"revision": revision, "worktree_sha256": digest.hexdigest()}


def receipt_directory(root: Path, runner: str) -> Path:
    if not RUNNER_RE.match(runner):
        raise ReceiptError(f"invalid native-shadow runner name {runner!r}")
    return root / RECEIPTS / runner / "latest"


def _file_record(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise ReceiptError(f"{path}: not a regular file")
    return {"sha256": _sha256(path), "size": path.stat().st_size}


def write_receipt(
    root: Path,
    runner: str,
    work: Path,
    products: Mapping[str, Path],
    cases: Sequence[tuple[str, int, Sequence[Path]]],
    parameters: Mapping[str, str],
    canonical: bool,
) -> Path:
    """Copy the cited logs and atomically publish the runner's latest receipt."""

    destination = receipt_directory(root, runner)
    destination.parent.mkdir(parents=True, exist_ok=True)
    staged = Path(tempfile.mkdtemp(prefix=".latest.", dir=destination.parent))
    try:
        logs_root = staged / "logs"
        case_records = []
        seen: set[str] = set()
        for case_id, status, logs in cases:
            if not CASE_RE.match(case_id) or case_id in seen:
                raise ReceiptError(f"invalid or repeated case {case_id!r}")
            seen.add(case_id)
            log_records = {}
            for log in logs:
                relative = log.resolve().relative_to(work.resolve()).as_posix()
                target = logs_root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(log, target)
                log_records[relative] = _file_record(target)
            case_records.append({"id": case_id, "logs": log_records, "status": int(status)})
        receipt = {
            "canonical": bool(canonical),
            "cases": case_records,
            "parameters": dict(sorted(parameters.items())),
            "products": {name: _file_record(path) for name, path in sorted(products.items())},
            "runner": runner,
            "schema": SCHEMA,
            "source": source_seal(root),
            "work": work.resolve().relative_to(root.resolve()).as_posix(),
        }
        (staged / "receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
        for path in [staged, *staged.rglob("*")]:
            path.chmod(0o755 if path.is_dir() else 0o644)
        if destination.exists():
            retired = Path(tempfile.mkdtemp(prefix=".retired.", dir=destination.parent))
            os.replace(destination, retired / "latest")
            os.replace(staged, destination)
            shutil.rmtree(retired)
        else:
            os.replace(staged, destination)
    except BaseException:
        shutil.rmtree(staged, ignore_errors=True)
        raise
    return destination / "receipt.json"


@dataclass(frozen=True)
class Receipt:
    """A validated receipt. `cases` keeps the recorded execution order."""

    path: Path
    runner: str
    source: Mapping[str, str]
    products: Mapping[str, Mapping[str, Any]]
    cases: Sequence[Mapping[str, Any]]
    parameters: Mapping[str, str]

    def case_ids(self, prefix: str = "") -> list[str]:
        return [case["id"] for case in self.cases if case["id"].startswith(prefix)]


def read_receipt(
    root: Path,
    runner: str,
    *,
    case_prefix: str = "",
    seal: Mapping[str, str] | None = None,
) -> Receipt:
    """Validate one runner's latest receipt against the current checkout.

    `case_prefix` names the case family the consumer needs; at least one such
    case must exist, and every case must have passed. `seal` defaults to the
    live checkout seal and exists for the reader's own tests.
    """

    directory = receipt_directory(root, runner)
    path = directory / "receipt.json"
    if not path.is_file():
        raise ReceiptError(f"{runner}: no receipt at {path.relative_to(root)}; run the runner on this tree")
    try:
        receipt = json.loads(path.read_text())
    except (OSError, ValueError) as error:
        raise ReceiptError(f"{runner}: unreadable receipt: {error}") from error
    if not isinstance(receipt, dict) or set(receipt) != {
        "canonical", "cases", "parameters", "products", "runner", "schema", "source", "work",
    }:
        raise ReceiptError(f"{runner}: receipt has an unexpected shape")
    if receipt["schema"] != SCHEMA or receipt["runner"] != runner:
        raise ReceiptError(f"{runner}: receipt schema or runner mismatch")
    source = receipt["source"]
    if (
        not isinstance(source, dict)
        or set(source) != {"revision", "worktree_sha256"}
        or not REVISION_RE.match(str(source["revision"]))
        or not SHA_RE.match(str(source["worktree_sha256"]))
    ):
        raise ReceiptError(f"{runner}: receipt has a malformed source seal")
    current = dict(source_seal(root) if seal is None else seal)
    if dict(source) != current:
        raise ReceiptError(
            f"{runner}: receipt seals {source['revision'][:12]}/{source['worktree_sha256'][:12]}, "
            f"checkout is {current['revision'][:12]}/{current['worktree_sha256'][:12]}; rerun the runner"
        )
    if receipt["canonical"] is not True:
        raise ReceiptError(f"{runner}: receipt records a non-canonical development run: {receipt['parameters']}")
    products = receipt["products"]
    if not isinstance(products, dict) or not products or not all(
        isinstance(record, dict) and set(record) == {"sha256", "size"}
        and SHA_RE.match(str(record["sha256"])) and isinstance(record["size"], int)
        for record in products.values()
    ):
        raise ReceiptError(f"{runner}: receipt lacks product digests")
    cases = receipt["cases"]
    if not isinstance(cases, list) or not cases:
        raise ReceiptError(f"{runner}: receipt records no cases")
    ids = []
    for case in cases:
        if not isinstance(case, dict) or set(case) != {"id", "logs", "status"} or not CASE_RE.match(str(case["id"])):
            raise ReceiptError(f"{runner}: receipt has a malformed case")
        ids.append(case["id"])
        if case["status"] != 0:
            raise ReceiptError(f"{runner}: case {case['id']} exited {case['status']}")
        if not isinstance(case["logs"], dict) or not case["logs"]:
            raise ReceiptError(f"{runner}: case {case['id']} cites no raw log")
        for relative, record in case["logs"].items():
            log = directory / "logs" / relative
            if ".." in Path(relative).parts or not log.is_file() or log.is_symlink():
                raise ReceiptError(f"{runner}: case {case['id']} log {relative} is missing")
            if _file_record(log) != record:
                raise ReceiptError(f"{runner}: case {case['id']} log {relative} does not match its digest")
    if len(set(ids)) != len(ids):
        raise ReceiptError(f"{runner}: receipt repeats a case")
    if not any(case_id.startswith(case_prefix) for case_id in ids):
        raise ReceiptError(f"{runner}: receipt has no {case_prefix!r} case")
    return Receipt(
        path=path, runner=runner, source=source, products=products,
        cases=cases, parameters=receipt["parameters"],
    )


def _pairs(values: Iterable[str], subject: str) -> dict[str, str]:
    result = {}
    for value in values:
        name, separator, rest = value.partition("=")
        if not separator or not name or name in result:
            raise ReceiptError(f"invalid or repeated {subject} {value!r}")
        result[name] = rest
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="write or check a native-shadow runner receipt")
    commands = parser.add_subparsers(dest="command", required=True)
    write = commands.add_parser("write", help="publish a runner's latest receipt")
    write.add_argument("--runner", required=True)
    write.add_argument("--work", required=True, type=Path, help="the run's evidence directory")
    write.add_argument("--product", action="append", default=[], metavar="NAME=PATH")
    write.add_argument("--case", action="append", default=[], metavar="ID=STATUS:LOG[,LOG...]",
        help="LOG paths are relative to --work")
    write.add_argument("--parameter", action="append", default=[], metavar="NAME=VALUE")
    write.add_argument("--canonical", choices=("yes", "no"), required=True)
    check = commands.add_parser("check", help="validate a runner's latest receipt on this tree")
    check.add_argument("--runner", required=True)
    check.add_argument("--case-prefix", default="")
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "check":
            receipt = read_receipt(ROOT, arguments.runner, case_prefix=arguments.case_prefix)
            print(f"{arguments.runner}: {len(receipt.case_ids(arguments.case_prefix))} passing cases at "
                  f"{receipt.source['revision'][:12]}; {receipt.path.relative_to(ROOT)}")
            return 0
        work = arguments.work.resolve()
        cases = []
        for value in arguments.case:
            case_id, _, rest = value.partition("=")
            status, _, logs = rest.partition(":")
            if not status.lstrip("-").isdigit() or not logs:
                raise ReceiptError(f"invalid case {value!r}")
            cases.append((case_id, int(status), [work / log for log in logs.split(",")]))
        products = {name: Path(path) for name, path in _pairs(arguments.product, "product").items()}
        path = write_receipt(
            ROOT, arguments.runner, work, products, cases,
            _pairs(arguments.parameter, "parameter"), arguments.canonical == "yes",
        )
        print(f"{arguments.runner} receipt: {path}")
        return 0
    except (ReceiptError, OSError, ValueError) as error:
        print(f"native-shadow receipt: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
