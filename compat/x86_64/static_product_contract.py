#!/usr/bin/env python3
"""Validate the owned static product contract and its source-bound receipt.

`static-product.toml` declares the finite static product suite: every case the
installed-product runner links and executes in ordinary static ET_EXEC and
static-PIE modes, from both the primary installed tree and the tree extracted
from its package, and the cases that prove each coverage obligation.

Operations:

* ``--check`` validates the contract and prints a compact summary.
* ``--suite-paths`` prints the declared per-mode evidence paths, one per line.
* ``--source-digest`` prints the live nonignored-source digest.
* ``collect --work-dir DIR --source-sha256 DIGEST`` runs inside the runner
  after all of its own checks pass, with the digest observed before its first
  build. It copies compact evidence into a fresh directory below
  ``.work/x86_64/reports/owned-static-product/`` and writes ``receipt.json``.
* ``validate --receipt PATH`` is the independent reader: it rehashes retained
  evidence, re-inspects the ELF, link-trace, and receipt facts, and requires the
  live source and contract to match.
* ``publish --receipt PATH`` binds a validated receipt to a clean revision
  through the ignored ``.work/x86_64/owned-static-qualification.json`` pointer.

A published receipt qualifies the static product for the campaign report; it
never completes a family, promotes x86, or enables public support.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = ROOT / "compat" / "x86_64" / "static-product.toml"
CONTRACT_SCHEMA = "crabc.x86_64-owned-static-product/v1"
RECEIPT_SCHEMA = "crabc.x86_64-owned-static-qualification/v1"
PUBLICATION = ROOT / ".work" / "x86_64" / "owned-static-qualification.json"
REPORT_ROOT = ROOT / ".work" / "x86_64" / "reports" / "owned-static-product"
OWNER_FAMILY = "sysroot.static-tls"
PRODUCTS = ("primary", "extracted")
MODE_PATHS = ("static-et-exec", "static-pie")
CONTRACT_STATUS = "implemented-unqualified"
QUALIFIED_STATUS = "qualified"
RUNNER = "compat/x86_64/run_owned_static_sysroot.sh"
COMMAND = "./scripts/dev-x86_64.sh owned-static-sysroot"
INSTALLED_MANIFEST = "share/crabc/manifest.json"
# Every sealed-driver link retains these files; the map and symbol table are
# bound by digest only because their size scales with the linked archive.
RETAINED_CASE_FILES = (
    "link.receipt.json",
    "link.receipt.trace",
    "file-header",
    "program-headers",
    "dynamic",
    "relocations",
    "candidate.sha256",
)
DIGEST_ONLY_CASE_FILES = ("link.receipt.map", "symbols", "candidate")
# Observable outputs written by individual consumers, retained when present.
CASE_RECORD_FILES = (
    "startup-records",
    "termination-records",
    "system-records",
    "calendar-records",
    "tzif-invariants",
    "backend-records",
    "extension-records",
    "wide-records",
    "scan-records",
    "numeric-records",
    "printf-matrix-output",
)
RUNTIME_INPUTS = {
    "static-et-exec": ("crt1.o", "ET_EXEC", False),
    "static-pie": ("rcrt1.o", "ET_DYN", True),
}


class StaticProductError(ValueError):
    """The contract, retained evidence, or publication is invalid."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise StaticProductError(message)


def digest(path: Path) -> str:
    require(path.is_file() and not path.is_symlink(), f"missing or unsafe evidence file: {path}")
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def string_list(value: object, context: str) -> list[str]:
    require(
        isinstance(value, list) and value and all(isinstance(item, str) and item for item in value),
        f"{context} must be a non-empty string array",
    )
    assert isinstance(value, list)
    require(len(value) == len(set(value)), f"{context} has duplicate entries")
    return list(value)


def load_contract(path: Path = CONTRACT_PATH) -> dict[str, Any]:
    try:
        with path.open("rb") as stream:
            value = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise StaticProductError(f"cannot load static product contract: {error}") from error
    require(isinstance(value, dict), "static product contract must be a TOML table")
    return value


def contract_sha256(path: Path = CONTRACT_PATH) -> str:
    return digest(path)


def suite_cases(contract: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Return the ordered case roster after structural validation."""
    suite = contract.get("suite")
    require(isinstance(suite, Mapping), "static product contract has no suite table")
    require(
        set(suite) == {"runner", "command", "products", "mode_paths", "compiler_helper_rejection", "case"},
        "static product suite keys drifted",
    )
    require(suite.get("runner") == RUNNER, "static product suite runner drifted")
    require(suite.get("command") == COMMAND, "static product suite command drifted")
    require(tuple(string_list(suite.get("products"), "suite.products")) == PRODUCTS,
            "static product suite must run the primary and extracted products")
    require(tuple(string_list(suite.get("mode_paths"), "suite.mode_paths")) == MODE_PATHS,
            "static product suite mode roots drifted")
    require(tuple(string_list(suite.get("compiler_helper_rejection"), "suite.compiler_helper_rejection"))
            == MODE_PATHS, "static product must reject a no-builtins link in both modes")
    runner_text = (ROOT / RUNNER).read_text(encoding="utf-8")
    cases = suite.get("case")
    require(isinstance(cases, list) and cases, "static product suite has no cases")
    identifiers: set[str] = set()
    paths: set[str] = set()
    roster: list[dict[str, Any]] = []
    for index, case in enumerate(cases):
        context = f"suite.case[{index}]"
        require(isinstance(case, Mapping) and set(case) == {"id", "probe", "paths"}, f"{context} keys drifted")
        identifier = case["id"]
        require(isinstance(identifier, str) and re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", identifier) is not None,
                f"{context}.id is invalid")
        require(identifier not in identifiers, f"duplicate static product case {identifier}")
        identifiers.add(identifier)
        probe = case["probe"]
        require(isinstance(probe, str) and probe.startswith("compat/x86_64/") and probe.endswith(".c"),
                f"{identifier} probe must be a compat/x86_64 C source")
        require((ROOT / probe).is_file(), f"{identifier} probe is missing: {probe}")
        require(Path(probe).name in runner_text, f"{identifier} probe is not linked by the runner")
        case_paths = string_list(case["paths"], f"{context}.paths")
        require(len(case_paths) == len(MODE_PATHS), f"{identifier} must name one path per static mode")
        for mode, case_path in zip(MODE_PATHS, case_paths):
            parts = case_path.split("/")
            require(len(parts) in (1, 2) and all(re.fullmatch(r"[a-z0-9-]+", part) for part in parts),
                    f"{identifier} path is invalid: {case_path}")
            expected_suffix = "-et-exec" if mode == "static-et-exec" else "-pie"
            require(parts[0] == mode or parts[0].endswith(expected_suffix),
                    f"{identifier} path {case_path} is not rooted in its {mode} job")
            require(case_path not in paths, f"duplicate static product evidence path {case_path}")
            paths.add(case_path)
        roster.append({"id": identifier, "probe": probe, "paths": case_paths})
    return roster


def coverage_map(contract: Mapping[str, Any], case_ids: set[str]) -> dict[str, list[str]]:
    coverage = contract.get("coverage")
    require(isinstance(coverage, Mapping) and set(coverage) == {"required", "evidence"},
            "static product coverage keys drifted")
    required = string_list(coverage.get("required"), "coverage.required")
    evidence = coverage.get("evidence")
    require(isinstance(evidence, list), "coverage.evidence must be an array of tables")
    mapped: dict[str, list[str]] = {}
    for index, entry in enumerate(evidence):
        require(isinstance(entry, Mapping) and set(entry) == {"requirement", "cases"},
                f"coverage.evidence[{index}] keys drifted")
        requirement = entry["requirement"]
        require(requirement in required, f"coverage evidence names an undeclared obligation: {requirement}")
        require(requirement not in mapped, f"coverage obligation is mapped twice: {requirement}")
        cases = string_list(entry["cases"], f"coverage.evidence[{index}].cases")
        unknown = sorted(set(cases) - case_ids)
        require(not unknown, f"coverage obligation names unknown cases: {unknown}")
        mapped[requirement] = cases
    require(list(mapped) == required, "every coverage obligation needs exactly one ordered evidence entry")
    unused = sorted(case_ids - {case for cases in mapped.values() for case in cases})
    require(not unused, f"suite cases support no coverage obligation: {unused}")
    return mapped


def validate_contract(contract: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the product-owned suite and qualification sections."""
    require(contract.get("schema") == CONTRACT_SCHEMA, "static product contract schema is invalid")
    require(contract.get("owner_family") == OWNER_FAMILY, "static product owner family drifted")
    require(contract.get("status") == CONTRACT_STATUS,
            "checked-in static product status must stay implemented-unqualified; receipts qualify it")
    roster = suite_cases(contract)
    mapped = coverage_map(contract, {case["id"] for case in roster})
    qualification = contract.get("qualification")
    require(isinstance(qualification, Mapping), "static product contract has no qualification table")
    require(
        dict(qualification) == {
            "validator": "compat/x86_64/static_product_contract.py",
            "receipt": "source-bound receipt under .work/x86_64/reports/owned-static-product",
            "publication": ".work/x86_64/owned-static-qualification.json",
            "source": "live nonignored source content and modes; clean revision at publication",
            "family_completion": False,
            "promotion_ready": False,
            "public_support": False,
        },
        "static product qualification boundary drifted",
    )
    return {
        "schema": CONTRACT_SCHEMA,
        "owner_family": OWNER_FAMILY,
        "status": CONTRACT_STATUS,
        "case_count": len(roster),
        "evidence_path_count": sum(len(case["paths"]) for case in roster),
        "coverage_obligations": len(mapped),
    }


def declared_paths(contract: Mapping[str, Any]) -> list[str]:
    return [path for case in suite_cases(contract) for path in case["paths"]]


def git(*arguments: str) -> bytes:
    return subprocess.check_output(["git", "-c", f"safe.directory={ROOT}", *arguments], cwd=ROOT)


def source_digest() -> str:
    """Hash live nonignored source names, modes, and bytes.

    This is the dynamic product's source identity rule: untracked source is
    included so a new fixture cannot escape binding during development, and
    generated `.work` evidence is ignored, so there is no self-hash cycle.
    """
    names = sorted(set(git("ls-files", "-z", "--cached", "--others", "--exclude-standard").split(b"\0")) - {b""})
    result = hashlib.sha256()
    for name in names:
        path = ROOT / os.fsdecode(name)
        mode = path.lstat().st_mode
        data = os.fsencode(os.readlink(path)) if stat.S_ISLNK(mode) else path.read_bytes()
        result.update(name + b"\0" + str(stat.S_IMODE(mode)).encode() + b"\0")
        result.update(hashlib.sha256(data).digest())
    return result.hexdigest()


def require_clean_source() -> str:
    require(not git("status", "--porcelain", "--untracked-files=all").strip(),
            "static product publication requires clean source")
    return git("rev-parse", "HEAD").decode().strip()


def evidence_directory(path: Path) -> Path:
    path = path.absolute()
    require(path.resolve() == path and path.is_relative_to(ROOT / ".work"),
            "static product evidence must be a physical checkout .work path")
    return path


def relative(path: Path) -> str:
    return evidence_directory(path).relative_to(ROOT).as_posix()


def copy_file(source: Path, destination: Path) -> str:
    require(source.is_file() and not source.is_symlink(), f"missing or unsafe runner evidence: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    os.chmod(destination, 0o644)
    return digest(destination)


def collect(work_dir: Path, started_source: str) -> Path:
    """Copy compact evidence from one passing runner work tree into a receipt.

    ``started_source`` is the source digest the runner observed before its
    first build; a source edit during the run cannot be attributed to it.
    """
    contract = load_contract()
    validate_contract(contract)
    work_dir = evidence_directory(work_dir)
    source = source_digest()
    require(source == started_source, "source changed during the static product run")
    REPORT_ROOT.mkdir(parents=True, exist_ok=True)
    report = Path(tempfile.mkdtemp(prefix="run.", dir=REPORT_ROOT))
    os.chmod(report, 0o755)
    files: dict[str, str] = {}

    def retain(source_path: Path, name: str) -> None:
        files[name] = copy_file(source_path, report / name)

    for product, tree in (("primary", "primary"), ("reproduction", "reproduction"),
                          ("extracted", "extracted-tree/crabc-x86_64-owned-static-sysroot")):
        retain(work_dir / tree / INSTALLED_MANIFEST, f"products/{product}/manifest.json")
    for name in ("primary-tree.sha256", "reproduction-tree.sha256", "primary-build.json", "reproduction-build.json"):
        retain(work_dir / name, f"reproducibility/{name}")
    archives = {name: digest(work_dir / name) for name in ("primary.tar.xz", "reproduction.tar.xz")}
    for reference in sorted((work_dir / "header-consumer").glob("printf-matrix-reference*")):
        retain(reference, f"references/{reference.name}")
    retain(work_dir / "consumer-matrix-logs" / "summary.json", "consumer-matrix/summary.json")

    observed: dict[str, dict[str, dict[str, str]]] = {}
    for product in PRODUCTS:
        consumer = work_dir / f"{product}-consumer"
        for case in suite_cases(contract):
            for case_path in case["paths"]:
                mode_root = consumer / case_path
                for name in RETAINED_CASE_FILES:
                    retain(mode_root / name, f"cases/{product}/{case_path}/{name}")
                for name in CASE_RECORD_FILES:
                    if (mode_root / name).is_file():
                        retain(mode_root / name, f"cases/{product}/{case_path}/{name}")
                observed.setdefault(case_path, {})[product] = {
                    name: digest(mode_root / name) for name in DIGEST_ONLY_CASE_FILES
                }
    for mode in MODE_PATHS:
        retain(work_dir / "primary-consumer" / mode / "without-builtins.stderr",
               f"compiler-helper-rejection/{mode}.stderr")

    require(source == source_digest(), "source changed while collecting static product evidence")
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "status": "qualified-pending-review",
        "report": relative(report),
        "source_sha256": source,
        "contract_sha256": contract_sha256(),
        "archives": archives,
        "files": dict(sorted(files.items())),
        "observed": observed,
        "coverage": coverage_map(contract, {case["id"] for case in suite_cases(contract)}),
        "family_completion": False,
        "promotion_ready": False,
        "public_support": False,
    }
    receipt_path = report / "receipt.json"
    with receipt_path.open("x", encoding="utf-8") as stream:
        json.dump(receipt, stream, indent=2, sort_keys=True)
        stream.write("\n")
    os.chmod(receipt_path, 0o644)
    validate_receipt(receipt_path)
    return receipt_path


def read_json(path: Path) -> dict[str, Any]:
    digest(path)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise StaticProductError(f"unreadable evidence JSON {path}: {error}") from error
    require(isinstance(value, dict), f"evidence JSON is not an object: {path}")
    return value


def inspect_case(report: Path, product: str, mode: str, case_path: str,
                 observed: Mapping[str, str], manifest: Mapping[str, Any]) -> None:
    """Re-derive the final-image boundary from one retained case."""
    base = report / "cases" / product / case_path
    label = f"{product}/{case_path}"
    entry, elf_type, pie = RUNTIME_INPUTS[mode]
    candidate = (base / "candidate.sha256").read_text(encoding="ascii").strip()
    require(re.fullmatch(r"[0-9a-f]{64}", candidate) is not None and candidate == observed["candidate"],
            f"{label} candidate digest differs from the observed executable")
    link = read_json(base / "link.receipt.json")
    require(link.get("format") == "crabc-x86-64-sealed-static-driver-v1"
            and link.get("target") == "x86_64-unknown-linux-musl", f"{label} link receipt format drifted")
    require(link.get("output") == {"path": "candidate", "sha256": candidate}, f"{label} link output drifted")
    require(link.get("map", {}).get("sha256") == observed["link.receipt.map"]
            and link.get("trace", {}).get("sha256") == digest(base / "link.receipt.trace"),
            f"{label} link map/trace binding drifted")
    mode_record = link.get("mode")
    require(isinstance(mode_record, Mapping) and mode_record.get("id") == mode
            and mode_record.get("elf_type") == elf_type and mode_record.get("crt_object") == entry
            and mode_record.get("interpreter") == "absent", f"{label} link mode drifted")
    installed_record = manifest.get("installed")
    installed = installed_record.get("files") if isinstance(installed_record, Mapping) else None
    require(isinstance(installed, Mapping), "installed manifest has no file roster")
    records = link.get("input_receipts")
    require(isinstance(records, list) and len(records) == 8, f"{label} input roster size drifted")
    expected_runtime = [("crt-entry", entry), ("crt-prologue", "crti.o"), ("libc", "libc.a"),
                        ("builtins", "libcrabc-builtins.a"), ("crt-epilogue", "crtn.o")]
    for record, (role, name) in zip(records[:5], expected_runtime):
        path = f"usr/lib/{name}"
        require(record == {"role": role, "path": path, "sha256": installed.get(path)},
                f"{label} runtime input {role} is not the installed {name}")
    require([Path(str(record.get("path"))).name for record in records[5:]] == ["probe.o", "peer.o", "builtins.o"]
            and all(record.get("role") == "application" for record in records[5:]),
            f"{label} application inputs drifted")

    # Every resolved runtime input must come from this product's own installed
    # root inside the runner's private work tree; application objects must
    # come from this case's own consumer directory.
    trace = [line for line in (base / "link.receipt.trace").read_text(encoding="utf-8").splitlines() if line]
    tree = r"primary" if product == "primary" else r"extracted-tree/crabc-x86_64-owned-static-sysroot"
    work = r"/[^()]*/crabc-x86-64-owned-static-sysroot\.[A-Za-z0-9]+"
    runtime = re.compile(work + "/" + tree + r"/usr/lib/(" + re.escape(entry)
                         + r"|crti\.o|crtn\.o|(libc\.a|libcrabc-builtins\.a)\(([^()/]+)\))")
    application = re.compile(work + "/" + re.escape(f"{product}-consumer/{case_path}")
                             + r"/(probe|peer|builtins)\.o")
    saw_builtins_member = False
    for line in trace:
        if application.fullmatch(line):
            continue
        match = runtime.fullmatch(line)
        require(match is not None, f"{label} link trace names an undeclared input: {line}")
        saw_builtins_member |= match.group(2) == "libcrabc-builtins.a" and match.group(3) == "crabc-builtins.o"
    require(saw_builtins_member, f"{label} did not extract the owned compiler-helper member")

    header = (base / "file-header").read_text(encoding="utf-8")
    require(re.search(r"Machine:\s+Advanced Micro Devices X86-64", header) is not None, f"{label} is not EM_X86_64")
    require(re.search(r"Type:\s+" + ("DYN" if pie else "EXEC") + r"\b", header) is not None,
            f"{label} ELF type is not {elf_type}")
    rows = [line.split() for line in (base / "program-headers").read_text(encoding="utf-8").splitlines()]
    kinds = [row[0] for row in rows if row and row[0].isupper() and len(row) >= 7]
    require("INTERP" not in kinds, f"{label} selects an interpreter")
    require(kinds.count("TLS") == 1 and kinds.count("GNU_RELRO") == 1 and kinds.count("GNU_STACK") == 1,
            f"{label} lacks one TLS, GNU_RELRO, and GNU_STACK segment")
    stack = next(row for row in rows if row and row[0] == "GNU_STACK")
    require("E" not in stack[-2], f"{label} has an executable stack")
    if pie:
        require("PHDR" in kinds, f"{label} static PIE lacks PT_PHDR")
    dynamic = (base / "dynamic").read_text(encoding="utf-8")
    require(re.search(r"\((NEEDED|JMPREL|PLTGOT)\)", dynamic) is None, f"{label} has dynamic dependencies")
    relocations = (base / "relocations").read_text(encoding="utf-8")
    kinds = set(re.findall(r"\bR_X86_64_[A-Z0-9_]+", relocations))
    require(kinds <= ({"R_X86_64_RELATIVE"} if pie else set()),
            f"{label} retains non-relative dynamic relocations: {sorted(kinds)}")


def validate_receipt(path: Path) -> dict[str, Any]:
    """Independently re-read one receipt and all of its retained evidence."""
    path = evidence_directory(path)
    receipt = read_json(path)
    require(set(receipt) == {"schema", "status", "report", "source_sha256", "contract_sha256", "archives",
                             "files", "observed", "coverage", "family_completion", "promotion_ready",
                             "public_support"}, "static product receipt fields drifted")
    require(receipt["schema"] == RECEIPT_SCHEMA and receipt["status"] == "qualified-pending-review",
            "static product receipt schema or status drifted")
    require(receipt["family_completion"] is False and receipt["promotion_ready"] is False
            and receipt["public_support"] is False, "static product receipt must remain non-promoting")
    report = evidence_directory(ROOT / str(receipt["report"]))
    require(path == report / "receipt.json", "static product receipt is outside its report")
    contract = load_contract()
    validate_contract(contract)
    require(receipt["contract_sha256"] == contract_sha256(), "static product contract changed since the receipt")
    require(receipt["source_sha256"] == source_digest(), "static product source changed since the receipt")
    files = receipt["files"]
    require(isinstance(files, Mapping) and files, "static product receipt retains no files")
    retained = {entry.relative_to(report).as_posix() for entry in report.rglob("*")
                if entry.is_file() or entry.is_symlink()} - {"receipt.json"}
    require(retained == set(files), "static product report contains missing or unlisted evidence")
    for name, expected in files.items():
        require(digest(report / name) == expected, f"retained static product evidence changed: {name}")

    manifests = {product: read_json(report / "products" / product / "manifest.json")
                 for product in ("primary", "reproduction", "extracted")}
    require(manifests["primary"] == manifests["reproduction"] == manifests["extracted"],
            "installed manifests differ across clean builds and extraction")
    require(manifests["primary"].get("format") == "crabc-x86-64-owned-static-sysroot-v1",
            "installed manifest format drifted")
    require(files["reproducibility/primary-tree.sha256"] == files["reproducibility/reproduction-tree.sha256"],
            "two clean installed trees are not byte-identical")
    archives = receipt["archives"]
    require(isinstance(archives, Mapping) and set(archives) == {"primary.tar.xz", "reproduction.tar.xz"}
            and len(set(archives.values())) == 1, "independent static packages differ")

    roster = suite_cases(contract)
    observed = receipt["observed"]
    require(isinstance(observed, Mapping) and set(observed) == set(declared_paths(contract)),
            "static product receipt does not cover exactly the declared suite")
    for case in roster:
        for mode, case_path in zip(MODE_PATHS, case["paths"]):
            per_product = observed[case_path]
            require(isinstance(per_product, Mapping) and set(per_product) == set(PRODUCTS),
                    f"{case_path} lacks primary and extracted execution")
            for product in PRODUCTS:
                inspect_case(report, product, mode, case_path, per_product[product], manifests[product])
            require(per_product["primary"]["candidate"] == per_product["extracted"]["candidate"],
                    f"{case_path} executable differs after package extraction")
            for name in CASE_RECORD_FILES:
                primary = f"cases/primary/{case_path}/{name}"
                extracted = f"cases/extracted/{case_path}/{name}"
                require((primary in files) == (extracted in files)
                        and (primary not in files or files[primary] == files[extracted]),
                        f"{case_path} {name} differs between primary and extracted products")
    for mode in MODE_PATHS:
        stderr = (report / "compiler-helper-rejection" / f"{mode}.stderr").read_text(encoding="utf-8")
        require("__udivti3" in stderr, f"{mode} no-builtins link did not fail at the owned helper boundary")
    summary = read_json(report / "consumer-matrix" / "summary.json")
    jobs = summary.get("jobs")
    require(isinstance(jobs, list) and jobs and all(isinstance(job, Mapping) and job.get("status") == "passed"
                                                    for job in jobs), "consumer matrix did not pass every job")
    require(receipt["coverage"] == coverage_map(contract, {case["id"] for case in roster}),
            "static product receipt coverage map differs from the contract")
    return receipt


def publish_receipt(path: Path) -> None:
    """Atomically replace the reviewed pointer after revalidating the receipt."""
    revision = require_clean_source()
    receipt = validate_receipt(path)
    receipt_hash = digest(path)
    destination = evidence_directory(PUBLICATION)
    destination.parent.mkdir(parents=True, exist_ok=True)
    pointer = {"schema": RECEIPT_SCHEMA, "receipt": relative(path), "receipt_sha256": receipt_hash,
               "source_revision": revision}
    staged: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", prefix=".static-publication-",
                                         suffix=".json", dir=destination.parent, delete=False) as output:
            staged = Path(output.name)
            os.fchmod(output.fileno(), 0o644)
            json.dump(pointer, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        require(require_clean_source() == revision and source_digest() == receipt["source_sha256"]
                and digest(path) == receipt_hash, "source or receipt changed during publication")
        os.replace(staged, destination)
        staged = None
    finally:
        if staged is not None:
            staged.unlink(missing_ok=True)


def load_publication() -> dict[str, Any] | None:
    """Return the published receipt only while it proves the current clean source."""
    if not PUBLICATION.exists():
        return None
    published = read_json(PUBLICATION)
    require(set(published) == {"schema", "receipt", "receipt_sha256", "source_revision"},
            "static product publication fields drifted")
    require(published["schema"] == RECEIPT_SCHEMA, "static product publication schema drifted")
    try:
        if published["source_revision"] != require_clean_source():
            return None
        receipt = evidence_directory(ROOT / str(published["receipt"]))
        require(digest(receipt) == published["receipt_sha256"], "published static receipt hash mismatch")
        return validate_receipt(receipt)
    except (StaticProductError, OSError, ValueError, subprocess.SubprocessError):
        return None


def load_current_report() -> dict[str, Any]:
    """Contract summary plus the live qualification state for campaign reporting."""
    report = validate_contract(load_contract())
    receipt = load_publication()
    if receipt is not None:
        report["status"] = QUALIFIED_STATUS
        report["qualification_source_sha256"] = receipt["source_sha256"]
    return report


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="validate the contract and print its summary")
    parser.add_argument("--suite-paths", action="store_true", help="print declared evidence paths")
    parser.add_argument("--source-digest", action="store_true", help="print the live source digest")
    parser.add_argument("operation", nargs="?", choices=("collect", "validate", "publish"))
    parser.add_argument("--work-dir", type=Path)
    parser.add_argument("--source-sha256", help="source digest observed when the run started")
    parser.add_argument("--receipt", type=Path)
    parsed = parser.parse_args(arguments)
    try:
        if parsed.check:
            print(json.dumps(validate_contract(load_contract()), indent=2, sort_keys=True))
        elif parsed.suite_paths:
            print("\n".join(declared_paths(load_contract())))
        elif parsed.source_digest:
            print(source_digest())
        elif parsed.operation == "collect":
            require(parsed.work_dir is not None and parsed.source_sha256 is not None,
                    "collect requires --work-dir and --source-sha256")
            print(f"owned static product receipt: {relative(collect(parsed.work_dir, parsed.source_sha256))}")
        elif parsed.operation in ("validate", "publish"):
            require(parsed.receipt is not None, f"{parsed.operation} requires --receipt")
            if parsed.operation == "publish":
                publish_receipt(parsed.receipt)
            else:
                validate_receipt(parsed.receipt)
            print(f"owned static product receipt {parsed.operation}d; family and platform gates remain independent")
        else:
            parser.error("choose --check, --suite-paths, collect, validate, or publish")
    except (StaticProductError, OSError, subprocess.SubprocessError) as error:
        print(f"static product contract: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
