#!/usr/bin/env python3
"""Replay the complete native-shadow synthetic-loader workload receipt."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Mapping

import native_shadow_receipt as shared


ROOT = Path(__file__).resolve().parents[2]
RUNNER = "owned-loader-synthetic"
PARAMETERS = {
    "BACKEND": "native-shadow", "CASES": "21-frozen", "CASE_TIMEOUT": "20",
    "ORACLE": "pinned-musl", "PRODUCT": "supplied-dynamic-sysroot",
}
PRODUCT_PATHS = {
    "dynamic-loader": "lib/ld-crabc-x86_64.so.1",
    "dynamic-libc": "usr/lib/libc.so",
    "dynamic-driver": "bin/crabc-cc-dynamic",
    "dynamic-driver-shared": "share/crabc/crabc_cc_static.py",
    "dynamic-manifest": "share/crabc/manifest.json",
    "dynamic-libc-provenance": "share/crabc/libc-shared.provenance.json",
    "dynamic-product-state": "share/crabc/dynamic-product-state.json",
    "dynamic-scrt": "usr/lib/Scrt1.o",
    "dynamic-crti": "usr/lib/crti.o",
    "dynamic-crtn": "usr/lib/crtn.o",
    "dynamic-attach": "usr/lib/crabc-dynamic-attach.o",
    "dynamic-builtins": "usr/lib/libcrabc-builtins.a",
}
PINNED_PRODUCTS = {"pinned-musl-libc", "pinned-musl-compiler"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise shared.ReceiptError(f"{RUNNER}: {message}")


def json_file(path: Path) -> dict:
    try:
        value = json.loads(path.read_text())
    except (OSError, ValueError) as error:
        raise shared.ReceiptError(f"{RUNNER}: unreadable {path.name}: {error}") from error
    require(isinstance(value, dict), f"{path.name} is not an object")
    return value


def digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def tree_entries(tree: object, label: str) -> dict[str, dict]:
    require(isinstance(tree, dict) and set(tree) == {"entries", "sha256"}, f"{label} tree seal is malformed")
    entries = tree["entries"]
    require(isinstance(entries, list) and digest(entries) == tree["sha256"], f"{label} tree digest differs")
    indexed = {}
    for entry in entries:
        require(isinstance(entry, dict) and isinstance(entry.get("path"), str), f"{label} tree entry is malformed")
        require(entry["path"] not in indexed, f"{label} repeats a tree path")
        indexed[entry["path"]] = entry
    return indexed


def observations(value: object):
    if isinstance(value, dict):
        fields = {"argv", "returncode", "stdout_hex", "stderr_hex", "timed_out"}
        if fields <= set(value):
            yield {name: value[name] for name in fields}
        else:
            for nested in value.values():
                yield from observations(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from observations(nested)


def safe_fixture_path(value: object, name: str) -> str:
    require(isinstance(value, str), f"{name} fixture path is malformed")
    path = Path(value)
    require(not path.is_absolute() and ".." not in path.parts and len(path.parts) >= 3
            and path.parts[:2] == ("cases", name), f"{name} fixture path escapes its workload")
    return value


def _read_loader_synthetic_receipt(
    root: Path = ROOT, *, seal: Mapping[str, str] | None = None,
) -> shared.Receipt:
    receipt = shared.read_receipt(root, RUNNER, seal=seal)
    directory = receipt.path.parent
    require(dict(receipt.parameters) == PARAMETERS, "canonical parameters differ")

    sys.path.insert(0, str(ROOT / "compat/ldso"))
    from run_x86 import CASES, source_seal

    roster = list(CASES)
    require([case["id"] for case in receipt.cases] == [*roster, "runner"], "workload roster is incomplete or reordered")
    raw_receipt = json_file(receipt.path)
    work = raw_receipt.get("work")
    require(isinstance(work, str) and Path(work).parent == Path(".work/x86_64")
            and Path(work).name.startswith("owned-loader-synthetic."), "workload directory is invalid")
    report = json_file(directory / "logs/report.json")
    require(report.get("schema") == 2 and report.get("runner") == "compat/ldso/run_x86.py"
            and report.get("architecture") == "x86_64", "loader report identity differs")
    require(report.get("component_complete") is True and report.get("selected_passed") is True
            and report.get("family_complete") is False, "loader report is not a completed component")
    require(report.get("selected") == roster and isinstance(report.get("cases"), dict)
            and set(report["cases"]) == set(roster), "report workload roster differs")
    for name in ("source", "product", "oracle", "producer_linker"):
        require(report.get(name + "_before") == report.get(name + "_after"), f"{name} changed during collection")
    require(report.get("source_before") == source_seal(), "source seal differs from checkout")

    products = receipt.products
    fixed = set(PRODUCT_PATHS) | PINNED_PRODUCTS | {"fixture-map"}
    require(fixed <= set(products) and all(name in fixed or name.startswith("fixture-") for name in products),
            "product roster differs")
    baseline = tree_entries(report["product_before"], "supplied product")
    manifest = json_file(directory / "products/dynamic-manifest")
    provenance = json_file(directory / "products/dynamic-libc-provenance")
    state = json_file(directory / "products/dynamic-product-state")
    require(manifest.get("target") == "x86_64-unknown-linux-musl"
            and isinstance(manifest.get("files"), dict), "installed product manifest differs")
    require(provenance.get("allocator_backend") == "native-shadow"
            and state.get("allocator_backend") == "native-shadow", "product backend differs")
    for name, relative in PRODUCT_PATHS.items():
        record = products[name]
        entry = baseline.get(relative)
        require(isinstance(entry, dict) and entry.get("kind") == "file"
                and entry.get("sha256") == record["sha256"] and entry.get("size") == record["size"],
                f"{name} differs from supplied product seal")
        if name != "dynamic-manifest":
            require(manifest["files"].get(relative) == record["sha256"], f"{name} differs from installed manifest")
    oracle = report["oracle_before"]
    require(oracle.get("libc") == "/opt/musl-1.2.6/lib/libc.so"
            and oracle.get("compiler") == "/usr/local/bin/crabc-x86_64-musl-gcc"
            and oracle.get("libc_sha256") == products["pinned-musl-libc"]["sha256"]
            and oracle.get("compiler_sha256") == products["pinned-musl-compiler"]["sha256"],
            "pinned musl identity differs")

    fixture_map = json_file(directory / "products/fixture-map")
    require(set(fixture_map) == {"fixtures", "symlinks"}
            and isinstance(fixture_map["fixtures"], list)
            and isinstance(fixture_map["symlinks"], list), "fixture map is malformed")
    fixture_by_path: dict[str, dict] = {}
    fixture_by_case: dict[str, set[str]] = {name: set() for name in roster}
    fixture_names = set()
    for item in fixture_map["fixtures"]:
        require(isinstance(item, dict) and set(item) == {"path", "product", "sha256"}, "fixture entry is malformed")
        path = item["path"]
        require(isinstance(path, str) and len(Path(path).parts) >= 3, "fixture path is malformed")
        name = Path(path).parts[1]
        safe_fixture_path(path, name)
        require(name in fixture_by_case and item["product"].startswith(f"fixture-{name}-")
                and path not in fixture_by_path and item["product"] not in fixture_names,
                f"{name} fixture mapping differs")
        require(item["product"] in products and item["sha256"] == products[item["product"]]["sha256"],
                f"{name} fixture digest differs")
        fixture_by_path[path] = item
        fixture_names.add(item["product"])
        fixture_by_case[name].add(item["sha256"])
    require(fixture_names == set(products) - fixed, "fixture product roster differs")

    symlinks = set()
    for item in fixture_map["symlinks"]:
        require(isinstance(item, dict) and set(item) == {"path", "target"}, "fixture symlink is malformed")
        path = item["path"]
        require(isinstance(path, str) and len(Path(path).parts) >= 4, "fixture symlink path is malformed")
        name = Path(path).parts[1]
        safe_fixture_path(path, name)
        require(name in fixture_by_case and isinstance(item["target"], str), "fixture symlink target is malformed")
        symlinks.add((path, item["target"]))
    require(len(symlinks) == len(fixture_map["symlinks"]), "fixture symlink repeats")

    expected_symlinks = set()
    expected_root_fixtures = set()
    case_records = {case["id"]: case for case in receipt.cases}
    for name in roster:
        case = report["cases"][name]
        require(isinstance(case, dict) and case.get("result") == "pass" and case.get("status") == "pass",
                f"{name} workload did not pass")
        log_prefix = f"cases/{name}/"
        expected_case = f"{log_prefix}case.json"
        logs = set(case_records[name]["logs"])
        require(expected_case in logs and json_file(directory / "logs" / expected_case) == case,
                f"{name} case report differs")
        raw_logs = {path for path in logs if path.startswith(log_prefix + "raw/")}
        require(logs == raw_logs | {expected_case} and raw_logs, f"{name} raw log roster differs")
        stems = {Path(path).with_suffix("").as_posix() for path in raw_logs}
        require(all({stem + ".json", stem + ".stdout", stem + ".stderr"} <= raw_logs for stem in stems)
                and len(raw_logs) == 3 * len(stems), f"{name} raw observation trio differs")
        indices = sorted(int(Path(stem).name.split("-", 1)[0]) for stem in stems)
        require(indices == list(range(1, len(stems) + 1)), f"{name} raw command sequence differs")
        recorded = []
        for stem in sorted(stems):
            command = json_file(directory / "logs" / (stem + ".json"))
            require(set(command) == {"argv", "cwd", "environment", "returncode", "stdout_hex", "stderr_hex", "timed_out"}
                    and type(command["returncode"]) is int and command["returncode"] == 0
                    and command["timed_out"] is False,
                    f"{name} raw command is malformed")
            try:
                stdout = bytes.fromhex(command["stdout_hex"])
                stderr = bytes.fromhex(command["stderr_hex"])
            except (TypeError, ValueError) as error:
                raise shared.ReceiptError(f"{RUNNER}: {name} raw stream is malformed") from error
            require(stdout == (directory / "logs" / (stem + ".stdout")).read_bytes()
                    and stderr == (directory / "logs" / (stem + ".stderr")).read_bytes(),
                    f"{name} raw command streams differ")
            recorded.append({key: command[key] for key in ("argv", "returncode", "stdout_hex", "stderr_hex", "timed_out")})
        for observation in observations(case):
            require(observation in recorded, f"{name} reported observation lacks raw transcript")

        roots = case.get("execution_roots")
        require(isinstance(roots, dict) and set(roots) == {"oracle", "candidate"},
                f"{name} execution roots differ")
        for arm in ("oracle", "candidate"):
            entries = tree_entries(roots[arm], f"{name} {arm} execution root")
            for relative, entry in entries.items():
                path = f"cases/{name}/{arm}-root/{relative}"
                if entry.get("kind") == "symlink":
                    expected_symlinks.add((path, entry.get("target")))
                elif entry.get("kind") == "file":
                    source = baseline.get(relative) if arm == "candidate" else None
                    if source and source.get("kind") == "file" and source.get("sha256") == entry.get("sha256"):
                        continue
                    if arm == "oracle" and relative in {"lib/ld-musl-x86_64.so.1", "usr/lib/libc.so"}:
                        require(entry.get("sha256") == oracle["libc_sha256"], f"{name} oracle libc differs")
                        continue
                    mapped = fixture_by_path.get(path)
                    require(mapped is not None and mapped["sha256"] == entry.get("sha256")
                            and products[mapped["product"]]["size"] == entry.get("size"),
                            f"{name} execution fixture is unretained")
                    expected_root_fixtures.add(path)
        hashes = fixture_by_case[name]
        require(any(path.startswith(f"cases/{name}/oracle-root/") for path in fixture_by_path)
                and any(path.startswith(f"cases/{name}/candidate-root/") for path in fixture_by_path),
                f"{name} lacks both fixture arms")
        for link in case.get("links", []):
            require(isinstance(link, dict) and link.get("output_sha256") in hashes
                    and link.get("object_sha256") in hashes,
                    f"{name} linked output or object is unretained")
            require(all(dependency.get("sha256") in hashes for dependency in link.get("dependencies", [])),
                    f"{name} linked dependency is unretained")
        for role in case.get("objects", []):
            require(isinstance(role, dict) and role.get("sha256") in hashes
                    and role.get("header_trace_sha256") in hashes,
                    f"{name} compiled role is unretained")
    require(symlinks == expected_symlinks, "fixture symlink map differs from execution roots")
    mapped_root_fixtures = {path for path in fixture_by_path
                            if Path(path).parts[2] in {"oracle-root", "candidate-root"}}
    require(mapped_root_fixtures == expected_root_fixtures, "execution fixture map differs from roots")

    runner_logs = set(case_records["runner"]["logs"])
    require(runner_logs == {"report.json", "runner.stdout", "runner.stderr", "runner.status"},
            "runner raw logs differ")
    require((directory / "logs/runner.status").read_text() == "0\n"
            and (directory / "logs/runner.stderr").read_bytes() == b""
            and b"owned synthetic loader: PASS\n" in (directory / "logs/runner.stdout").read_bytes(),
            "runner transcript differs")
    return receipt


def read_loader_synthetic_receipt(
    root: Path = ROOT, *, seal: Mapping[str, str] | None = None,
) -> shared.Receipt:
    """Require every frozen workload and its retained raw and physical inputs."""

    try:
        return _read_loader_synthetic_receipt(root, seal=seal)
    except (AttributeError, IndexError, KeyError, OSError, TypeError, ValueError) as error:
        raise shared.ReceiptError(f"{RUNNER}: malformed semantic receipt: {error}") from error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("check", choices=["check"])
    args = parser.parse_args()
    try:
        result = read_loader_synthetic_receipt()
    except shared.ReceiptError as error:
        parser.exit(1, f"{error}\n")
    print(f"{RUNNER}: {len(result.cases) - 1} complete workloads; {result.path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
