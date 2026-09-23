#!/usr/bin/env python3
"""Read the finite installed BSD random product receipt and replay its witnesses.

The shell runner owns execution. This reader reconstructs its fixed artifact and
scenario roster from physical files, current sources, and current product links.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

import owned_posix_product_evidence as products


ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "crabc.x86_64-owned-bsd-random-receipt/v2"
ORACLE_CC = Path("/usr/local/bin/crabc-x86_64-musl-gcc")
ORACLE_GCC = Path("/usr/bin/gcc")
ORACLE_SPECS = Path("/opt/musl-1.2.6/lib/musl-gcc.specs")
ORACLE_LINK_FLAGS = ("-static", "-fno-pie", "-no-pie", "-pthread")
SCENARIOS = ("core", "state", "fork-active", "concurrent-random", "concurrent-state")
LINKS = {
    "static-et-exec": ("static", "static"),
    "static-pie": ("static", "static-pie"),
    "dynamic-pie": ("dynamic", "pie"),
    "dynamic-non-pie": ("dynamic", "non-pie"),
}
SYMBOLS = ("random", "srandom", "initstate", "setstate")
SOURCE_NAMES = (
    "compat/x86_64/owned_bsd_random_probe.c",
    "compat/x86_64/run_owned_bsd_random.sh",
    "compat/x86_64/owned_bsd_random_receipt.py",
    "include/stdlib.h",
    "libc/src/c_abi/x86_64/bsd_random.rs",
)
FIXED_FILES = (
    "source-before.json", "source-after.json", "source-receipt.json",
    "product-inputs.json", "source-input.sha256", "source-header.o",
    "oracle-header.o", "workload.o", "oracle", "static-symbols.txt",
    "dynamic-symbols.txt",
)


class ReceiptError(ValueError):
    """The physical evidence does not satisfy the installed BSD random contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReceiptError(message)


def physical(path: Path, *, directory: bool = False) -> Path:
    require(path.is_absolute() and ".." not in path.parts, f"nonphysical path: {path}")
    cursor = Path(path.anchor)
    try:
        for part in path.parts[1:]:
            cursor /= part
            require(not cursor.is_symlink(), f"symlink path: {cursor}")
        mode = path.lstat().st_mode
    except OSError as error:
        raise ReceiptError(f"missing path: {path}") from error
    require(stat.S_ISDIR(mode) if directory else stat.S_ISREG(mode), f"wrong node type: {path}")
    return path


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_record(work: Path, name: str) -> dict[str, object]:
    path = physical(work / name)
    value = path.read_bytes()
    return {"sha256": digest(value), "size": len(value), "mode": stat.S_IMODE(path.stat().st_mode)}


def tool_record(path: Path) -> dict[str, object]:
    path = physical(path)
    value = path.read_bytes()
    return {"path": str(path), "sha256": digest(value), "size": len(value),
            "mode": stat.S_IMODE(path.stat().st_mode)}


def oracle_link_contract(work: Path) -> dict[str, object]:
    """Name the pinned compiler chain and the exact original link inputs."""
    return {
        "compiler": tool_record(ORACLE_CC),
        "gcc": tool_record(ORACLE_GCC),
        "specs": tool_record(ORACLE_SPECS),
        "argv": [str(ORACLE_CC), *ORACLE_LINK_FLAGS, str(work / "workload.o"),
                 "-o", str(work / "oracle")],
        "workload": file_record(work, "workload.o"),
        "oracle": file_record(work, "oracle"),
    }


def authenticate_oracle_link(work: Path, retained: object) -> None:
    """Recreate the oracle from the same object before trusting its transcript."""
    require(retained == oracle_link_contract(work), "pinned-musl oracle link contract differs")
    with tempfile.TemporaryDirectory(prefix="bsd-random-oracle-relink-", dir=work.parent) as scratch:
        rebuilt = Path(scratch) / "oracle"
        argv = [str(ORACLE_CC), *ORACLE_LINK_FLAGS, str(work / "workload.o"),
                "-o", str(rebuilt)]
        completed = subprocess.run(argv, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        require(completed.returncode == 0 and not completed.stdout and not completed.stderr,
                "pinned-musl oracle relink failed")
        require(physical(rebuilt).read_bytes() == (work / "oracle").read_bytes(),
                "pinned-musl oracle differs from exact rebuilt link")


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_json(path: Path) -> object:
    try:
        return json.loads(physical(path).read_text(encoding="utf-8"), object_pairs_hook=unique_object,
                          parse_constant=lambda value: (_ for _ in ()).throw(ReceiptError(f"invalid JSON constant: {value}")))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ReceiptError(f"invalid JSON: {path}") from error


def expected_labels() -> tuple[str, ...]:
    labels = [f"oracle-{scenario}" for scenario in SCENARIOS]
    for mode in LINKS:
        entries = ("kernel", "direct") if mode.startswith("dynamic-") else (None,)
        for entry in entries:
            for scenario in SCENARIOS:
                labels.append(f"{mode}-{entry}-{scenario}" if entry else f"{mode}-{scenario}")
    return tuple(labels)


def scenario_root(work: Path, label: str) -> Path:
    # The dynamic runner executes kernel and direct entry against the same
    # copied product tree for each scenario; only the output labels differ.
    for mode in LINKS:
        if mode.startswith("dynamic-"):
            for entry in ("kernel", "direct"):
                prefix = f"{mode}-{entry}-"
                if label.startswith(prefix):
                    return work / f"{mode}-{label[len(prefix):]}-root"
    return work / f"{label}-root"


def tree_rows(root: Path) -> list[tuple[str, str, int, str]]:
    """Describe a product or chroot without following any contained symlink."""
    physical(root, directory=True)
    rows: list[tuple[str, str, int, str]] = []
    for parent, directories, files in os.walk(root, followlinks=False):
        for name in directories + files:
            path = Path(parent) / name
            mode = path.lstat().st_mode
            relative = path.relative_to(root).as_posix()
            if stat.S_ISLNK(mode):
                kind, payload = "symlink", os.readlink(path)
            elif stat.S_ISDIR(mode):
                kind, payload = "directory", ""
            elif stat.S_ISREG(mode):
                kind, payload = "file", digest(path.read_bytes())
            elif stat.S_ISCHR(mode) and relative == "dev/null" and os.major(path.stat().st_rdev) == 1 and os.minor(path.stat().st_rdev) == 3:
                kind, payload = "null-device", "1:3"
            else:
                raise ReceiptError(f"unexpected node in scenario root: {path}")
            rows.append((relative, kind, stat.S_IMODE(mode), payload))
    return sorted(rows)


def tree_record(root: Path) -> str:
    """Seal a chroot copy including modes, symlinks, and the /dev/null node."""
    return digest(json.dumps(tree_rows(root), separators=(",", ":")).encode())


def source_snapshot() -> dict[str, object]:
    def git(*args: str) -> bytes:
        return subprocess.check_output(("git", "-C", str(ROOT), *args))
    names = sorted(set(git("ls-files", "-z", "--cached", "--others", "--exclude-standard").split(b"\0")) - {b""})
    tree = hashlib.sha256()
    for raw_name in names:
        path = ROOT / os.fsdecode(raw_name)
        mode = path.lstat().st_mode
        data = os.fsencode(os.readlink(path)) if stat.S_ISLNK(mode) else path.read_bytes()
        tree.update(raw_name + b"\0" + str(stat.S_IMODE(mode)).encode() + b"\0")
        tree.update(hashlib.sha256(data).digest())
    return {
        "schema": "crabc.x86_64-owned-bsd-random-source-snapshot/v1",
        "revision": git("rev-parse", "HEAD").decode().strip(),
        "status": git("status", "--porcelain=v1", "--untracked-files=all").decode(),
        "tree_sha256": tree.hexdigest(),
        "selected_files": {name: digest((ROOT / name).read_bytes()) for name in sorted(SOURCE_NAMES)},
    }


def source_and_products(work: Path) -> dict[str, Path]:
    before = read_json(work / "source-before.json")
    after = read_json(work / "source-after.json")
    require(before == after == source_snapshot(), "source snapshot differs from current checkout")
    source = read_json(work / "source-receipt.json")
    require(type(source) is dict and set(source) == {"schema", "root_source", "inputs", "products"}
            and source["schema"] == "crabc.x86_64-owned-bsd-random-source/v1", "source receipt shape differs")
    require(source["root_source"] == {"before": before, "after": after, "unchanged": True}, "source receipt snapshots differ")
    inputs = source["inputs"]
    expected = {"probe": SOURCE_NAMES[0], "runner": SOURCE_NAMES[1], "reader": SOURCE_NAMES[2],
                "port": SOURCE_NAMES[4], "installed_object": "workload.o"}
    require(type(inputs) is dict and set(inputs) == set(expected), "source input roster differs")
    for key, relative in expected.items():
        path = work / relative if key == "installed_object" else ROOT / relative
        require(type(inputs[key]) is dict and inputs[key].get("sha256") == digest(physical(path).read_bytes()),
                f"source input differs: {key}")
        require(inputs[key].get("path") == str(path), f"source input path differs: {key}")
    expected_checksum = b"".join(
        f"{digest((ROOT / name).read_bytes())}  {ROOT / name}\n".encode()
        for name in (SOURCE_NAMES[0], SOURCE_NAMES[1], SOURCE_NAMES[2], SOURCE_NAMES[4])
    )
    require((work / "source-input.sha256").read_bytes() == expected_checksum,
            "source input checksum transcript differs")
    products_record = read_json(work / "product-inputs.json")
    require(source["products"] == products_record, "source receipt product reference differs")
    require(type(products_record) is dict and set(products_record) == {"schema", "roles", "products", "extracted_provenance"}
            and products_record["schema"] == "crabc.x86_64-owned-bsd-random-product-inputs/v1",
            "product input shape differs")
    roles = products_record["roles"]
    require(roles in ({"static": "provided-static", "dynamic": "provided-dynamic"},
                      {"static": "extracted-static", "dynamic": "extracted-dynamic"}), "product roles differ")
    require((products_record["extracted_provenance"] is None) == (roles["static"] == "provided-static"),
            "extracted provenance differs")
    result = {}
    for kind, validator in (("static", products._validate_static_product), ("dynamic", products._validate_dynamic_product)):
        value = products_record["products"].get(kind)
        require(type(value) is dict and set(value) == {"path", "manifest_sha256"}, f"{kind} product record differs")
        path = physical(Path(value["path"]), directory=True)
        require(path.is_relative_to(ROOT / ".work"), f"{kind} product escapes checkout .work")
        manifest, _ = validator(path)
        require(value["manifest_sha256"] == digest(manifest.read_bytes()), f"{kind} manifest differs")
        result[kind] = path
    require(result["static"] != result["dynamic"], "static and dynamic products coincide")
    return result


def provider_symbols(work: Path, product_paths: dict[str, Path]) -> None:
    for kind, artifact, raw_name, command in (
        ("static", "usr/lib/libc.a", "static-symbols.txt", ("nm", "-g", "--defined-only")),
        ("dynamic", "usr/lib/libc.so", "dynamic-symbols.txt", ("readelf", "--dyn-syms", "-W")),
    ):
        actual = subprocess.run((*command, str(product_paths[kind] / artifact)), capture_output=True, check=False)
        require(actual.returncode == 0 and actual.stderr == b"", f"{kind} provider replay failed")
        require(actual.stdout == (work / raw_name).read_bytes(), f"{kind} provider transcript differs")
        counts: Counter[str] = Counter()
        for line in actual.stdout.decode().splitlines():
            fields = line.split()
            if kind == "static" and len(fields) == 3 and fields[1] == "T" and fields[2] in SYMBOLS:
                counts[fields[2]] += 1
            elif kind == "dynamic" and len(fields) == 8 and fields[3:6] == ["FUNC", "GLOBAL", "DEFAULT"] and fields[6] != "UND" and fields[7] in SYMBOLS:
                counts[fields[7]] += 1
        require(counts == Counter(SYMBOLS), f"{kind} provider quartet differs: {counts}")


def link_paths(work: Path, mode: str) -> tuple[Path, Path, Path]:
    executable = work / mode
    receipt = work / (mode + (".receipt.json" if mode.startswith("static-") else ".crabc-link.json"))
    identity = work / (mode + ".link-identity.json")
    return executable, receipt, identity


def validate_report(report_path: Path, *, static_product: Path | None = None,
                    dynamic_product: Path | None = None, replay: bool = True) -> dict[str, object]:
    report_path = physical(report_path)
    require(report_path.name == "report.json", "BSD random report filename differs")
    work = physical(report_path.parent, directory=True)
    require(work.is_relative_to(ROOT / ".work"), "BSD random report escapes checkout .work")
    report = read_json(report_path)
    require(type(report) is dict and set(report) == {"schema", "scope", "files", "products", "oracle_link", "scenario_roots"}
            and report["schema"] == SCHEMA and report["scope"] == "installed-bsd-random-component",
            "BSD random report contract differs")
    names = set(FIXED_FILES)
    for mode in LINKS:
        executable, receipt, identity = link_paths(work, mode)
        names.update((executable.name, receipt.name, identity.name))
    for label in expected_labels():
        names.update(f"{label}.{suffix}" for suffix in ("status", "stdout", "stderr"))
    files = report["files"]
    require(type(files) is dict and set(files) == names, "BSD random retained file roster differs")
    for name in names:
        require(files[name] == file_record(work, name), f"retained file differs: {name}")
    product_paths = source_and_products(work)
    authenticate_oracle_link(work, report["oracle_link"])
    require(report["products"] == read_json(work / "product-inputs.json"), "report product binding differs")
    for kind, supplied in (("static", static_product), ("dynamic", dynamic_product)):
        if supplied is not None:
            require(physical(supplied, directory=True) == product_paths[kind],
                    f"{kind} product differs from selected same-source product")
    provider_symbols(work, product_paths)
    for mode, (kind, linkage) in LINKS.items():
        executable, receipt, identity = link_paths(work, mode)
        observed = products.validate_link(product_paths[kind], work / "workload.o", executable, receipt, linkage)
        require(read_json(identity) == observed, f"{mode} link identity differs")
    require((work / "oracle").is_file(), "pinned musl oracle executable is absent")
    roots = report["scenario_roots"]
    require(type(roots) is dict and set(roots) == set(expected_labels()), "scenario root roster differs")
    for label in expected_labels():
        scenario = next(name for name in sorted(SCENARIOS, key=len, reverse=True)
                        if label.endswith("-" + name))
        root = physical(scenario_root(work, label), directory=True)
        require(roots[label] == tree_record(root), f"{label} execution root differs")
        executable = work / ("oracle" if label.startswith("oracle-") else next(mode for mode in LINKS if label.startswith(mode + "-")))
        require(digest((root / "consumer").read_bytes()) == digest(executable.read_bytes()),
                f"{label} chroot consumer differs")
        actual_rows = {row[0]: row for row in tree_rows(root)}
        require(actual_rows.pop("consumer")[1] == "file" and actual_rows.pop("dev/null")[1] == "null-device",
                f"{label} chroot special entries differ")
        if label.startswith("dynamic-"):
            expected_rows = {row[0]: row for row in tree_rows(product_paths["dynamic"])}
            if "dev" not in expected_rows:
                actual_rows.pop("dev", None)
            require(actual_rows == expected_rows, f"{label} chroot product copy differs")
        else:
            require(set(actual_rows) == {"dev"}, f"{label} chroot has unexpected payload")
        status = (work / (label + ".status")).read_bytes()
        stdout = (work / (label + ".stdout")).read_bytes()
        stderr = (work / (label + ".stderr")).read_bytes()
        require(status == b"0\n" and stdout and stderr == b"", f"{label} raw execution failed")
        if not label.startswith("oracle-"):
            for suffix in ("status", "stdout", "stderr"):
                require((work / f"{label}.{suffix}").read_bytes() == (work / f"oracle-{scenario}.{suffix}").read_bytes(),
                        f"{label} differs from pinned musl: {suffix}")
        if replay:
            entry = "/lib/ld-crabc-x86_64.so.1" if "-direct-" in label else None
            argv = ["chroot", str(root)]
            if entry:
                argv.append(entry)
            argv.extend(("/consumer", scenario))
            result = subprocess.run(argv, env={"PATH": os.environ.get("PATH", ""), "TZ": "UTC"},
                                    capture_output=True, timeout=50, check=False)
            require(result.returncode == 0 and result.stdout == stdout and result.stderr == stderr,
                    f"{label} host replay differs")
    return report


def collect_report(work: Path) -> Path:
    work = physical(work, directory=True)
    require(work.is_relative_to(ROOT / ".work"), "BSD random work escapes checkout .work")
    names = set(FIXED_FILES)
    for mode in LINKS:
        names.update(path.name for path in link_paths(work, mode))
    for label in expected_labels():
        names.update(f"{label}.{suffix}" for suffix in ("status", "stdout", "stderr"))
    report = {
        "schema": SCHEMA,
        "scope": "installed-bsd-random-component",
        "files": {name: file_record(work, name) for name in sorted(names)},
        "products": read_json(work / "product-inputs.json"),
        "oracle_link": oracle_link_contract(work),
        "scenario_roots": {label: tree_record(scenario_root(work, label)) for label in expected_labels()},
    }
    report_path = work / "report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    validate_report(report_path, replay=False)
    return report_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("collect-report").add_argument("work", type=Path)
    commands.add_parser("validate-report").add_argument("report", type=Path)
    arguments = parser.parse_args()
    try:
        if arguments.command == "collect-report":
            print(collect_report(arguments.work))
        else:
            validate_report(arguments.report)
            print("owned BSD random receipt: valid; host replay passed")
    except (ReceiptError, products.ProductEvidenceError, OSError, subprocess.SubprocessError, ValueError) as error:
        parser.exit(1, f"owned BSD random receipt failed: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
