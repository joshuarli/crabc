#!/usr/bin/env python3
"""Read retained native loader and package-corpus component receipts.

The two producers deliberately remain component runners.  This reader only
proves that one retained full receipt was produced from the current source and
one supplied owned dynamic product.  It never builds, executes, mounts, or
chroots a runtime, and it never turns a component result into family closure.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path, PurePosixPath
import stat
import sys
from typing import Any, Iterable, Mapping


ROOT = Path(__file__).resolve().parents[2]
SHA256_HEX = frozenset("0123456789abcdef")


class LoaderCorpusEvidenceError(RuntimeError):
    """A retained loader/corpus receipt does not prove its component result."""


def _fail(message: str) -> None:
    raise LoaderCorpusEvidenceError(message)


def _require(condition: bool, message: str) -> None:
    if not condition:
        _fail(message)


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"JSON object repeats key {key!r}")
        result[key] = value
    return result


def _json(path: Path, description: str) -> dict[str, Any]:
    path = _physical_file(path, description)
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_object_pairs)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise LoaderCorpusEvidenceError(f"{description} is not valid JSON") from error
    _require(isinstance(value, dict), f"{description} must be a JSON object")
    return value


def _keys(value: object, expected: Iterable[str], description: str) -> dict[str, Any]:
    expected_set = set(expected)
    _require(isinstance(value, dict) and set(value) == expected_set, f"{description} fields drifted")
    return value


def _digest(value: object, description: str) -> str:
    _require(isinstance(value, str) and len(value) == 64 and set(value) <= SHA256_HEX,
             f"{description} is not a lowercase SHA-256")
    return value


def _sha256(path: Path) -> str:
    path = _physical_file(path, "hashed retained artifact")
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as error:
        raise LoaderCorpusEvidenceError(f"cannot hash retained artifact: {path}") from error
    return digest.hexdigest()


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(path))


def _without_symlink_components(path: Path, description: str) -> Path:
    _require(".." not in path.parts, f"{description} has parent traversal")
    absolute = _absolute(path)
    current = Path(absolute.anchor)
    try:
        for component in absolute.parts[1:]:
            current /= component
            if stat.S_ISLNK(current.lstat().st_mode):
                _fail(f"{description} traverses a symlink: {path}")
    except OSError as error:
        raise LoaderCorpusEvidenceError(f"{description} is unavailable: {path}") from error
    return absolute


def _physical_directory(path: Path, description: str) -> Path:
    absolute = _without_symlink_components(path, description)
    try:
        _require(stat.S_ISDIR(absolute.lstat().st_mode), f"{description} is not a physical directory")
    except OSError as error:
        raise LoaderCorpusEvidenceError(f"{description} is unavailable: {path}") from error
    return absolute


def _physical_file(path: Path, description: str) -> Path:
    absolute = _without_symlink_components(path, description)
    try:
        _require(stat.S_ISREG(absolute.lstat().st_mode), f"{description} is not a physical regular file")
    except OSError as error:
        raise LoaderCorpusEvidenceError(f"{description} is unavailable: {path}") from error
    return absolute


def _checked_root(root: Path) -> Path:
    checkout = _physical_directory(root, "checkout root")
    _require(checkout == _physical_directory(ROOT, "reader checkout root"),
             "reader root must be this physical checkout")
    _physical_directory(checkout / ".work", "checkout .work")
    return checkout


def _safe_mount(value: object) -> str:
    _require(isinstance(value, str), "recorded source mount is not text")
    mount = PurePosixPath(value)
    _require(mount.is_absolute() and value != "/" and ".." not in mount.parts and "." not in mount.parts,
             "recorded source mount is unsafe")
    return value.rstrip("/")


def mounted_path(root: Path, source_mount: str, value: object) -> Path:
    """Translate one retained container path through the supplied checkout.

    The report is allowed to name a safe absolute mount other than
    ``/workspace``.  Only its lexical descendant is admitted, and that suffix
    is resolved under this checkout without accepting a symlink escape.
    """

    checkout = _checked_root(root)
    mount = _safe_mount(source_mount)
    _require(isinstance(value, str), "retained path is not text")
    recorded = PurePosixPath(value)
    _require(recorded.is_absolute() and ".." not in recorded.parts and "." not in recorded.parts,
             "retained path is unsafe")
    prefix = mount + "/"
    _require(value.startswith(prefix), "retained path escapes its source mount")
    suffix = value[len(prefix):]
    relative = PurePosixPath(suffix)
    _require(relative.parts and all(part not in {"", ".", ".."} for part in relative.parts),
             "retained path has an invalid checkout suffix")
    candidate = checkout.joinpath(*relative.parts)
    _require(candidate.is_relative_to(checkout), "retained path escapes checkout")
    return candidate


def recorded_path(root: Path, source_mount: str, path: Path) -> str:
    """Return the producer spelling for one physical checkout descendant."""

    checkout = _checked_root(root)
    mount = _safe_mount(source_mount)
    absolute = _absolute(path)
    _require(absolute.is_relative_to(checkout), "retained path escapes checkout")
    return mount + "/" + absolute.relative_to(checkout).as_posix()


def _retained_directory(root: Path, source_mount: str, value: object, description: str) -> Path:
    path = mounted_path(root, source_mount, value)
    _require(path.is_relative_to(root / ".work"), f"{description} must stay below checkout .work")
    return _physical_directory(path, description)


def _retained_file(root: Path, source_mount: str, value: object, description: str) -> Path:
    path = mounted_path(root, source_mount, value)
    _require(path.is_relative_to(root / ".work"), f"{description} must stay below checkout .work")
    return _physical_file(path, description)


def _load_module(name: str, relative: str) -> Any:
    path = ROOT / relative
    _physical_file(path, f"{name} source")
    directory = str(path.parent)
    if directory not in sys.path:
        sys.path.insert(0, directory)
    spec = importlib.util.spec_from_file_location(name, path)
    _require(spec is not None and spec.loader is not None, f"cannot load {name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _loader() -> Any:
    return _load_module("_owned_loader_corpus_loader", "compat/ldso/run_x86.py")


def _corpus() -> Any:
    return _load_module("_owned_loader_corpus_corpus", "compat/corpus/run_x86.py")


def _product_reader() -> Any:
    return _load_module("_owned_loader_corpus_product", "compat/x86_64/owned_posix_product_evidence.py")


def _loader_cases() -> tuple[str, ...]:
    cases = tuple(_loader().CASES)
    _require(len(cases) == 21 and len(set(cases)) == len(cases), "current loader roster drifted")
    return cases


LOADER_CASES = _loader_cases()


def _corpus_cases() -> tuple[Any, ...]:
    manifest = _corpus().load_manifest()
    cases = tuple(manifest.cases)
    _require(len(cases) == 34 and len({case.id for case in cases}) == len(cases),
             "current package-corpus roster drifted")
    return cases


def current_loader_source(root: Path = ROOT) -> dict[str, object]:
    _checked_root(root)
    return _loader().source_seal()


def current_corpus_source(root: Path = ROOT) -> dict[str, object]:
    _checked_root(root)
    corpus = _corpus()
    return corpus.source_identity(corpus.load_manifest())


def loader_tree_seal(root: Path) -> dict[str, object]:
    return _loader().tree_seal(_physical_directory(root, "loader product tree"))


def _product_identity(product: Path) -> tuple[Path, str, dict[str, str]]:
    product = _physical_directory(product, "supplied owned dynamic product")
    try:
        manifest, files = _product_reader()._validate_dynamic_product(product)
    except Exception as error:
        raise LoaderCorpusEvidenceError(f"supplied owned dynamic product is invalid: {error}") from error
    return manifest, _sha256(manifest), files


def _normalised_mode(recorded: int, actual: int, kind: str) -> bool:
    _require(type(recorded) is int and 0 <= recorded <= 0o7777, "retained tree has an invalid mode")
    if actual == recorded:
        return True
    if kind == "directory":
        return actual == (recorded | 0o555)
    if kind == "file":
        return actual == (recorded | 0o444)
    return False


def _loader_tree_entries(path: Path) -> list[dict[str, object]]:
    root = _physical_directory(path, "retained loader tree")
    entries: list[dict[str, object]] = []
    try:
        found = sorted(root.rglob("*"), key=lambda value: value.relative_to(root).as_posix())
    except OSError as error:
        raise LoaderCorpusEvidenceError(f"cannot enumerate retained loader tree: {root}") from error
    for item in found:
        relative = item.relative_to(root).as_posix()
        mode = item.lstat().st_mode
        data: dict[str, object] = {"path": relative, "mode": stat.S_IMODE(mode)}
        if stat.S_ISLNK(mode):
            data.update(kind="symlink", target=os.readlink(item))
        elif stat.S_ISREG(mode):
            data.update(kind="file", sha256=_sha256(item), size=item.stat().st_size)
        elif stat.S_ISDIR(mode):
            data.update(kind="directory")
        else:
            _fail(f"retained loader tree has an unsupported entry: {relative}")
        entries.append(data)
    return entries


def _validate_retained_loader_tree(path: Path, seal: object, description: str) -> None:
    value = _keys(seal, {"entries", "sha256"}, description)
    entries = value["entries"]
    _digest(value["sha256"], f"{description} hash")
    _require(isinstance(entries, list), f"{description} entries are not a list")
    canonical = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
    _require(hashlib.sha256(canonical).hexdigest() == value["sha256"], f"{description} seal hash differs")
    actual = _loader_tree_entries(path)
    _require(len(entries) == len(actual), f"{description} entry roster differs")
    for expected, observed in zip(entries, actual):
        _require(isinstance(expected, dict), f"{description} has a non-object entry")
        kind = expected.get("kind")
        expected_keys = {
            "directory": {"path", "mode", "kind"},
            "file": {"path", "mode", "kind", "sha256", "size"},
            "symlink": {"path", "mode", "kind", "target"},
        }.get(kind)
        _require(expected_keys is not None and set(expected) == expected_keys, f"{description} entry schema drifted")
        _require(expected["path"] == observed["path"] and expected["kind"] == observed["kind"],
                 f"{description} entry identity differs")
        _require(_normalised_mode(expected["mode"], observed["mode"], str(kind)),
                 f"{description} entry mode differs outside retained readability normalization")
        for name in expected_keys - {"mode"}:
            _require(expected[name] == observed[name], f"{description} entry {expected['path']} differs")


def _hash_within(root: Path, relative: str, description: str) -> str:
    candidate = root / relative
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise LoaderCorpusEvidenceError(f"{description} is unavailable") from error
    _require(resolved.is_relative_to(root.resolve()), f"{description} escapes its retained root")
    return _sha256(resolved)


def _process(value: object, description: str) -> tuple[str, int, bytes, bytes, bool]:
    record = _keys(value, {"argv", "returncode", "stdout_hex", "stderr_hex", "timed_out"}, description)
    _require(isinstance(record["argv"], list) and record["argv"] and all(isinstance(item, str) for item in record["argv"]),
             f"{description} argv differs")
    _require(type(record["returncode"]) is int and type(record["timed_out"]) is bool,
             f"{description} status differs")
    try:
        stdout = bytes.fromhex(record["stdout_hex"])
        stderr = bytes.fromhex(record["stderr_hex"])
    except (TypeError, ValueError) as error:
        raise LoaderCorpusEvidenceError(f"{description} stream is not hexadecimal") from error
    return (json.dumps(record["argv"], separators=(",", ":")), record["returncode"], stdout, stderr, record["timed_out"])


def _summary_processes(value: object, output: list[tuple[str, int, bytes, bytes, bool]], description: str) -> None:
    if isinstance(value, dict):
        keys = set(value)
        process_keys = {"argv", "returncode", "stdout_hex", "stderr_hex", "timed_out"}
        if keys == process_keys:
            output.append(_process(value, description))
            return
        if {"oracle", "candidate"} <= keys:
            oracle, candidate = value["oracle"], value["candidate"]
            if isinstance(oracle, dict) and isinstance(candidate, dict) and set(oracle) == process_keys and set(candidate) == process_keys:
                _require(_process(oracle, description + " oracle") == _process(candidate, description + " candidate"),
                         f"{description} candidate observation differs from oracle")
                direct = value.get("candidate_direct")
                if direct is not None and isinstance(direct, dict) and set(direct) == process_keys:
                    _require(_process(oracle, description + " oracle") == _process(direct, description + " direct"),
                             f"{description} direct candidate observation differs from oracle")
        for name, child in value.items():
            _summary_processes(child, output, description + "." + str(name))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _summary_processes(child, output, f"{description}[{index}]")


def _validate_loader_raw(raw: Path, case_record: dict[str, object], description: str) -> None:
    raw = _physical_directory(raw, description + " raw directory")
    try:
        children = sorted(raw.iterdir())
    except OSError as error:
        raise LoaderCorpusEvidenceError(f"cannot inspect {description} raw directory") from error
    json_files = [path for path in children if path.name.endswith(".json")]
    _require(json_files, f"{description} has no raw process records")
    expected_names: set[str] = set()
    raw_observations: list[tuple[str, int, bytes, bytes, bool]] = []
    for record_path in json_files:
        stem = record_path.name[:-5]
        stdout_path, stderr_path = raw / (stem + ".stdout"), raw / (stem + ".stderr")
        expected_names |= {record_path.name, stdout_path.name, stderr_path.name}
        record = _keys(_json(record_path, description + " raw process"),
                       {"cwd", "environment", "argv", "returncode", "stdout_hex", "stderr_hex", "timed_out"},
                       description + " raw process")
        _require(isinstance(record["cwd"], str) and isinstance(record["environment"], dict)
                 and all(isinstance(key, str) and isinstance(item, str) for key, item in record["environment"].items()),
                 f"{description} raw process invocation differs")
        observation = _process({key: record[key] for key in ("argv", "returncode", "stdout_hex", "stderr_hex", "timed_out")},
                               description + " raw process")
        _require(_physical_file(stdout_path, description + " raw stdout").read_bytes() == observation[2],
                 f"{description} raw stdout differs")
        _require(_physical_file(stderr_path, description + " raw stderr").read_bytes() == observation[3],
                 f"{description} raw stderr differs")
        _require(observation[1] == 0 and not observation[4], f"{description} raw process did not succeed")
        raw_observations.append(observation)
    _require({path.name for path in children} == expected_names, f"{description} raw artifact roster differs")
    summaries: list[tuple[str, int, bytes, bytes, bool]] = []
    _summary_processes(case_record, summaries, description)
    _require(summaries, f"{description} has no summarized process observations")
    retained = Counter(raw_observations)
    for observation, count in Counter(summaries).items():
        _require(retained[observation] >= count, f"{description} summary observation lacks matching raw receipt")


def _oracle_seal(value: object) -> dict[str, Any]:
    oracle = _keys(value, {"compiler", "compiler_sha256", "libc", "libc_sha256"}, "synthetic loader oracle")
    _require(all(isinstance(oracle[name], str) and Path(oracle[name]).is_absolute() for name in ("compiler", "libc")),
             "synthetic loader oracle paths differ")
    _digest(oracle["compiler_sha256"], "synthetic loader compiler")
    _digest(oracle["libc_sha256"], "synthetic loader libc")
    return oracle


def _validate_loader_case(root: Path, source_mount: str, report_root: Path, product: Path,
                          product_files: Mapping[str, str], oracle: Mapping[str, Any],
                          name: str, value: object) -> None:
    case = _require_case(value, name)
    _require(case["status"] == "pass" and case.get("result") == "pass", f"loader case {name} did not pass")
    raw = _retained_directory(root, source_mount, case["raw_directory"], f"loader case {name}")
    _require(raw == report_root / "cases" / name / "raw", f"loader case {name} raw path differs")
    case_json = _json(raw.parent / "case.json", f"loader case {name} raw case")
    _require(case_json == case, f"loader case {name} raw case receipt differs")
    _validate_loader_raw(raw, case, f"loader case {name}")
    roots = _keys(case["execution_roots"], {"oracle", "candidate"}, f"loader case {name} roots")
    for arm in ("oracle", "candidate"):
        retained_root = report_root / "cases" / name / (arm + "-root")
        _validate_retained_loader_tree(retained_root, roots[arm], f"loader case {name} {arm} root")
    _require(_hash_within(report_root / "cases" / name / "oracle-root", "lib/ld-musl-x86_64.so.1", "loader oracle") == oracle["libc_sha256"],
             f"loader case {name} oracle loader differs")
    _require(_hash_within(report_root / "cases" / name / "oracle-root", "usr/lib/libc.so", "loader oracle") == oracle["libc_sha256"],
             f"loader case {name} oracle libc differs")
    candidate = report_root / "cases" / name / "candidate-root"
    _require(_hash_within(candidate, "lib/ld-crabc-x86_64.so.1", "loader candidate") == product_files["lib/ld-crabc-x86_64.so.1"],
             f"loader case {name} candidate loader differs from supplied product")
    _require(_hash_within(candidate, "usr/lib/libc.so", "loader candidate") == product_files["usr/lib/libc.so"],
             f"loader case {name} candidate libc differs from supplied product")


def _require_case(value: object, name: str) -> dict[str, Any]:
    _require(isinstance(value, dict), f"loader case {name} is not an object")
    required = {"status", "result", "raw_directory", "execution_roots"}
    _require(required <= set(value), f"loader case {name} omits retained evidence")
    _require(isinstance(value["raw_directory"], str), f"loader case {name} raw directory differs")
    return value


def validate_loader_report(report_path: Path, dynamic_product: Path, *, root: Path = ROOT) -> dict[str, object]:
    """Validate one complete retained 21-case synthetic-loader report."""

    checkout = _checked_root(root)
    report_path = _physical_file(report_path, "synthetic-loader report")
    _require(report_path.is_relative_to(checkout / ".work"), "synthetic-loader report must stay below checkout .work")
    report_root = report_path.parent
    report = _json(report_path, "synthetic-loader report")
    required = {"schema", "runner", "architecture", "source_mount", "selected_passed", "component_complete",
                "family_complete", "selected", "source_before", "source_after", "product_before", "product_after",
                "oracle_before", "oracle_after", "cases", "elapsed_seconds"}
    _keys(report, required, "synthetic-loader report")
    _require((report["schema"], report["runner"], report["architecture"]) == (1, "compat/ldso/run_x86.py", "x86_64"),
             "synthetic-loader report identity differs")
    source_mount = _safe_mount(report["source_mount"])
    _require(report["selected_passed"] is True and report["component_complete"] is True and report["family_complete"] is False,
             "synthetic-loader report makes an invalid completion claim")
    _require(isinstance(report["elapsed_seconds"], (int, float)) and not isinstance(report["elapsed_seconds"], bool)
             and math.isfinite(report["elapsed_seconds"]) and report["elapsed_seconds"] >= 0,
             "synthetic-loader elapsed time differs")
    selected = report["selected"]
    _require(isinstance(selected, list) and all(isinstance(name, str) for name in selected)
             and len(selected) == len(set(selected)) and set(selected) == set(LOADER_CASES),
             "synthetic-loader selection is not the complete frozen roster")
    _require(isinstance(report["cases"], dict) and set(report["cases"]) == set(LOADER_CASES),
             "synthetic-loader case roster differs")
    source = current_loader_source(checkout)
    _require(report["source_before"] == source and report["source_after"] == source,
             "synthetic-loader receipt source is stale or changed during execution")
    manifest, manifest_sha256, product_files = _product_identity(dynamic_product)
    product_seal = loader_tree_seal(dynamic_product)
    _require(report["product_before"] == product_seal and report["product_after"] == product_seal,
             "synthetic-loader receipt product differs from supplied product")
    _require(any(entry.get("path") == "share/crabc/manifest.json" and entry.get("sha256") == manifest_sha256
                 for entry in product_seal["entries"]),
             "synthetic-loader product seal does not bind its manifest")
    oracle = _oracle_seal(report["oracle_before"])
    _require(report["oracle_after"] == oracle, "synthetic-loader pinned oracle changed during execution")
    for name in LOADER_CASES:
        _validate_loader_case(checkout, source_mount, report_root, dynamic_product, product_files, oracle, name, report["cases"][name])
    return {"component": "synthetic-loader", "case_count": len(LOADER_CASES),
            "product_manifest": str(manifest), "product_manifest_sha256": manifest_sha256,
            "family_complete": False}


def stream_snapshot(value: bytes) -> dict[str, object]:
    return {"byte_length": len(value), "sha256": hashlib.sha256(value).hexdigest(), "hex": value.hex()}


def _stream(value: object, description: str) -> bytes:
    snapshot = _keys(value, {"byte_length", "sha256", "hex"}, description)
    _require(type(snapshot["byte_length"]) is int and snapshot["byte_length"] >= 0, f"{description} length differs")
    _digest(snapshot["sha256"], description + " hash")
    try:
        data = bytes.fromhex(snapshot["hex"])
    except (TypeError, ValueError) as error:
        raise LoaderCorpusEvidenceError(f"{description} is not hexadecimal") from error
    _require(len(data) == snapshot["byte_length"] and hashlib.sha256(data).hexdigest() == snapshot["sha256"],
             f"{description} bytes differ from its snapshot")
    return data


def validate_corpus_comparison(value: object) -> None:
    comparison = _keys(value, {"passed", "normalization", "status_match", "stdout_match", "stderr_match", "oracle", "candidate"},
                       "package-corpus comparison")
    _require(comparison["normalization"] == "none" and all(comparison[name] is True for name in ("passed", "status_match", "stdout_match", "stderr_match")),
             "package-corpus comparison claims success without exact equality")
    observations: dict[str, tuple[int, bool, bytes, bytes]] = {}
    for arm in ("oracle", "candidate"):
        record = _keys(comparison[arm], {"status", "timed_out", "stdout", "stderr"}, f"package-corpus {arm} observation")
        _require(type(record["status"]) is int and type(record["timed_out"]) is bool,
                 f"package-corpus {arm} status differs")
        observations[arm] = (record["status"], record["timed_out"],
                             _stream(record["stdout"], f"package-corpus {arm} stdout"),
                             _stream(record["stderr"], f"package-corpus {arm} stderr"))
    _require(observations["oracle"] == observations["candidate"] and observations["oracle"][0] == 0
             and not observations["oracle"][1],
             "package-corpus comparison success claim differs from recorded observations")


def _corpus_oracle(value: object) -> dict[str, Any]:
    oracle = _keys(value, {"root", "runtime", "loader", "source_manifest"}, "package-corpus oracle")
    _require(isinstance(oracle["root"], str) and Path(oracle["root"]).is_absolute(), "package-corpus oracle root differs")
    runtime = _keys(oracle["runtime"], {"path", "sha256"}, "package-corpus oracle runtime")
    loader = _keys(oracle["loader"], {"path", "target", "resolved_path"}, "package-corpus oracle loader")
    source = _keys(oracle["source_manifest"], {"path", "sha256"}, "package-corpus oracle source manifest")
    root = oracle["root"].rstrip("/")
    _require(runtime["path"] == root + "/lib/libc.so" and loader["path"] == root + "/lib/ld-musl-x86_64.so.1"
             and loader["resolved_path"] == runtime["path"] and isinstance(loader["target"], str) and loader["target"],
             "package-corpus oracle runtime path differs")
    for item, description in ((runtime, "runtime"), (source, "source manifest")):
        _require(isinstance(item["path"], str) and Path(item["path"]).is_absolute(), f"package-corpus oracle {description} path differs")
        _digest(item["sha256"], "package-corpus oracle " + description)
    return oracle


def _validate_corpus_tools(value: object) -> dict[str, Any]:
    tools = _keys(value, {"path", "sha256", "version", "keys", "readelf"}, "package-corpus tools")
    _require(isinstance(tools["path"], str) and Path(tools["path"]).is_absolute() and isinstance(tools["version"], str),
             "package-corpus tools identity differs")
    _digest(tools["sha256"], "package-corpus apk tool")
    _require(isinstance(tools["keys"], dict) and tools["keys"], "package-corpus key roster is empty")
    for key, digest in tools["keys"].items():
        _require(isinstance(key, str) and key.endswith(".pub"), "package-corpus key name differs")
        _digest(digest, "package-corpus key")
    readelf = _keys(tools["readelf"], {"path", "sha256"}, "package-corpus readelf")
    _require(isinstance(readelf["path"], str) and Path(readelf["path"]).is_absolute(), "package-corpus readelf path differs")
    _digest(readelf["sha256"], "package-corpus readelf")
    return tools


def _validate_corpus_inputs(value: object, manifest: Any) -> None:
    inputs = _keys(value, {"verification_before", "after"}, "package-corpus inputs")
    before = _keys(inputs["verification_before"], {"identity", "index_signature", "archive_signatures"},
                   "package-corpus input verification")
    identity = _keys(before["identity"], {"directory", "index", "archives"}, "package-corpus input identity")
    _require(isinstance(identity["directory"], str) and Path(identity["directory"]).is_absolute(), "package-corpus input directory differs")
    index = _keys(identity["index"], {"path", "sha256"}, "package-corpus index")
    _require(isinstance(index["path"], str) and Path(index["path"]).is_absolute() and index["sha256"] == manifest.index_sha256,
             "package-corpus index differs from frozen manifest")
    _require(isinstance(identity["archives"], dict) and set(identity["archives"]) == set(manifest.archive_roster),
             "package-corpus archive roster differs")
    for name, digest in manifest.archive_roster.items():
        item = _keys(identity["archives"][name], {"sha256"}, "package-corpus archive")
        _require(item["sha256"] == digest, f"package-corpus archive {name} differs from frozen manifest")
    index_signature = _keys(before["index_signature"], {"stdout", "stderr"}, "package-corpus index signature")
    _require(all(isinstance(index_signature[name], str) for name in index_signature),
             "package-corpus index signature stream differs")
    signatures = before["archive_signatures"]
    _require(isinstance(signatures, dict) and set(signatures) == set(manifest.archive_roster),
             "package-corpus archive signature roster differs")
    for name, item in signatures.items():
        metadata = _keys(item, {"metadata", "signature_stdout", "signature_stderr"}, "package-corpus archive signature")
        _require(isinstance(metadata["signature_stdout"], str) and isinstance(metadata["signature_stderr"], str),
                 "package-corpus archive signature stream differs")
        fields = _keys(metadata["metadata"], {"pkgname", "pkgver", "arch"}, "package-corpus archive metadata")
        _require(fields["arch"] in {"x86_64", "noarch"} and name == f"{fields['pkgname']}-{fields['pkgver']}.apk",
                 "package-corpus archive metadata differs")
    _require(inputs["after"] == identity, "package-corpus inputs changed during execution")


def _base_fixtures(manifest: Any) -> dict[str, object]:
    return {"image_files": dict(manifest.base_image_files),
            "directories": {"/tmp": {"mode": 0o1777}, "/root": {"mode": 0o700}, "/dev": {"mode": 0o755}},
            "device": {"path": "/dev/null", "kind": "character", "mode": 0o666, "major": 1, "minor": 3}}


def _validate_corpus_root(root: Path, value: object, expected_case: Any, arm: str, product: Path,
                          product_files: Mapping[str, str], oracle: Mapping[str, Any], source_mount: str,
                          checkout: Path, corpus: Any) -> None:
    record = _keys(value, {"base_fixtures", "runtime", "execution_tree_before_sha256", "execution_tree_after_sha256", "executable"},
                   f"package-corpus {expected_case.id} {arm} root")
    _require(record["base_fixtures"] == _base_fixtures(corpus.load_manifest()),
             f"package-corpus {expected_case.id} {arm} base fixture differs")
    before = _digest(record["execution_tree_before_sha256"], "package-corpus execution tree before")
    after = _digest(record["execution_tree_after_sha256"], "package-corpus execution tree after")
    _require(before == after, f"package-corpus {expected_case.id} execution root changed during execution")
    try:
        current = corpus.tree_sha256(root, f"package-corpus {expected_case.id} {arm} retained root")
    except Exception as error:
        raise LoaderCorpusEvidenceError(f"package-corpus {expected_case.id} {arm} retained root is unreadable: {error}") from error
    _require(current == after, f"package-corpus {expected_case.id} {arm} retained root differs from its after seal")
    runtime = _keys(record["runtime"], {"loader", "libc", "canonical_interpreter", "canonical_libc"},
                    f"package-corpus {expected_case.id} {arm} runtime")
    _require(runtime["canonical_interpreter"] == corpus.CANONICAL_INTERPRETER and runtime["canonical_libc"] == corpus.CANONICAL_LIBC,
             f"package-corpus {expected_case.id} {arm} canonical runtime differs")
    for name in ("loader", "libc"):
        item = _keys(runtime[name], {"source", "resolved_source", "sha256"}, f"package-corpus {expected_case.id} {arm} {name}")
        _require(isinstance(item["source"], str) and isinstance(item["resolved_source"], str),
                 f"package-corpus {expected_case.id} {arm} {name} source differs")
        _digest(item["sha256"], f"package-corpus {expected_case.id} {arm} {name}")
    if arm == "candidate":
        loader = recorded_path(checkout, source_mount, product / "lib/ld-crabc-x86_64.so.1")
        libc = recorded_path(checkout, source_mount, product / "usr/lib/libc.so")
        _require(runtime["loader"]["source"] == loader and runtime["loader"]["resolved_source"] == loader
                 and runtime["loader"]["sha256"] == product_files["lib/ld-crabc-x86_64.so.1"],
                 f"package-corpus {expected_case.id} candidate loader differs from supplied product")
        _require(runtime["libc"]["source"] == libc and runtime["libc"]["resolved_source"] == libc
                 and runtime["libc"]["sha256"] == product_files["usr/lib/libc.so"],
                 f"package-corpus {expected_case.id} candidate libc differs from supplied product")
    else:
        _require(runtime["loader"]["source"] == oracle["loader"]["path"] and runtime["loader"]["resolved_source"] == oracle["runtime"]["path"]
                 and runtime["loader"]["sha256"] == oracle["runtime"]["sha256"],
                 f"package-corpus {expected_case.id} oracle loader differs from pinned oracle")
        _require(runtime["libc"]["source"] == oracle["runtime"]["path"] and runtime["libc"]["resolved_source"] == oracle["runtime"]["path"]
                 and runtime["libc"]["sha256"] == oracle["runtime"]["sha256"],
                 f"package-corpus {expected_case.id} oracle libc differs from pinned oracle")
    _require(_hash_within(root, corpus.CANONICAL_INTERPRETER.lstrip("/"), f"package-corpus {expected_case.id} {arm} loader") == runtime["loader"]["sha256"],
             f"package-corpus {expected_case.id} {arm} retained loader differs")
    _require(_hash_within(root, corpus.CANONICAL_LIBC.lstrip("/"), f"package-corpus {expected_case.id} {arm} libc") == runtime["libc"]["sha256"],
             f"package-corpus {expected_case.id} {arm} retained libc differs")
    executable = _keys(record["executable"], {"path", "sha256", "interpreter", "dt_relr"},
                       f"package-corpus {expected_case.id} {arm} executable")
    _require(executable["path"] == expected_case.path and executable["interpreter"] == corpus.CANONICAL_INTERPRETER
             and executable["dt_relr"] is expected_case.requires_dt_relr,
             f"package-corpus {expected_case.id} {arm} executable contract differs")
    _digest(executable["sha256"], f"package-corpus {expected_case.id} {arm} executable")
    _require(_hash_within(root, expected_case.path.lstrip("/"), f"package-corpus {expected_case.id} {arm} executable") == executable["sha256"],
             f"package-corpus {expected_case.id} {arm} retained executable differs")


def _validate_corpus_payload(root: Path, record: object, manifest: Any, corpus: Any) -> None:
    payload = _keys(record, {"path", "sha256", "package_library_dirs", "elf_closure"}, "package-corpus application payload")
    # The path is translated by the caller; keeping this shape check local
    # avoids a second generic artifact framework.
    _digest(payload["sha256"], "package-corpus application payload")
    _require(payload["package_library_dirs"] == list(manifest.package_library_dirs), "package-corpus library directories differ")
    _require(isinstance(payload["elf_closure"], list) and payload["elf_closure"], "package-corpus ELF closure is empty")
    paths: set[str] = set()
    for item in payload["elf_closure"]:
        entry = _keys(item, {"path", "sha256", "search_paths", "needed"}, "package-corpus ELF closure entry")
        _require(isinstance(entry["path"], str) and entry["path"].startswith("/") and isinstance(entry["search_paths"], list)
                 and all(path in manifest.package_library_dirs for path in entry["search_paths"]),
                 "package-corpus ELF closure path differs")
        _require(entry["path"] not in paths and ".." not in PurePosixPath(entry["path"]).parts,
                 "package-corpus ELF closure has an unsafe or duplicate path")
        paths.add(entry["path"])
        _digest(entry["sha256"], "package-corpus ELF closure artifact")
        _require(_hash_within(root, entry["path"].lstrip("/"), "package-corpus ELF closure artifact") == entry["sha256"],
                 "package-corpus ELF closure artifact differs")
        _require(isinstance(entry["needed"], dict), "package-corpus ELF closure dependencies differ")
        for soname, provider in entry["needed"].items():
            _require(isinstance(soname, str) and soname and "/" not in soname, "package-corpus ELF SONAME differs")
            _require(isinstance(provider, dict) and provider.get("kind") in {"sealed-runtime", "package-payload"}
                     and isinstance(provider.get("path"), str) and provider["path"].startswith("/"),
                     "package-corpus ELF provider differs")
            if provider["kind"] == "sealed-runtime":
                _require(set(provider) in ({"kind", "path"}, {"kind", "path", "sha256"}),
                         "package-corpus sealed runtime provider differs")
            else:
                _require(set(provider) == {"kind", "path", "sha256"}, "package-corpus package provider differs")
            if "sha256" in provider:
                _digest(provider["sha256"], "package-corpus ELF provider")


def validate_corpus_report(report_path: Path, dynamic_product: Path, *, root: Path = ROOT) -> dict[str, object]:
    """Validate one complete retained 34-case owned package-corpus report."""

    checkout = _checked_root(root)
    report_path = _physical_file(report_path, "package-corpus report")
    _require(report_path.is_relative_to(checkout / ".work"), "package-corpus report must stay below checkout .work")
    report = _json(report_path, "package-corpus report")
    required = {"schema", "source_mount", "passed", "source", "tools", "inputs", "oracle", "candidate_product",
                "application_payload", "execution_root", "report_path", "case_count", "outcomes"}
    _keys(report, required, "package-corpus report")
    corpus = _corpus()
    _require(report["schema"] == corpus.SCHEMA and report["passed"] is True, "package-corpus report does not claim success")
    source_mount = _safe_mount(report["source_mount"])
    execution_root = _retained_directory(checkout, source_mount, report["execution_root"], "package-corpus execution root")
    _require(report_path == execution_root / "report.json" and _retained_file(checkout, source_mount, report["report_path"], "package-corpus recorded report") == report_path,
             "package-corpus report path differs from its retained root")
    manifest = corpus.load_manifest()
    expected_source = corpus.source_identity(manifest)
    source = _keys(report["source"], {"before", "after"}, "package-corpus source")
    _require(source["before"] == expected_source and source["after"] == expected_source,
             "package-corpus receipt source is stale or changed during execution")
    tools = _validate_corpus_tools(report["tools"].get("before") if isinstance(report["tools"], dict) else None)
    _require(_keys(report["tools"], {"before", "after"}, "package-corpus tools")["after"] == tools,
             "package-corpus tools changed during execution")
    _validate_corpus_inputs(report["inputs"], manifest)
    oracle = _corpus_oracle(_keys(report["oracle"], {"before", "after"}, "package-corpus oracle")["before"])
    _require(report["oracle"]["after"] == oracle, "package-corpus oracle changed during execution")
    manifest_path, manifest_sha256, product_files = _product_identity(dynamic_product)
    try:
        product_record = corpus.validate_product(dynamic_product)
    except Exception as error:
        raise LoaderCorpusEvidenceError(f"supplied corpus product is invalid: {error}") from error
    product_record = dict(product_record)
    product_record["path"] = recorded_path(checkout, source_mount, dynamic_product)
    candidate_product = _keys(report["candidate_product"], {"before", "after"}, "package-corpus candidate product")
    _require(candidate_product["before"] == product_record and candidate_product["after"] == product_record,
             "package-corpus receipt product differs from supplied product")
    _require(product_record["manifest_sha256"] == manifest_sha256 and manifest_path.name == "manifest.json",
             "package-corpus product manifest identity differs")
    payload_path = _retained_directory(checkout, source_mount, report["application_payload"]["path"], "package-corpus application payload")
    _require(payload_path == execution_root / "application-payload", "package-corpus application payload path differs")
    _validate_corpus_payload(payload_path, report["application_payload"], manifest, corpus)
    try:
        _require(corpus.tree_sha256(payload_path, "package-corpus retained application payload") == report["application_payload"]["sha256"],
                 "package-corpus retained application payload differs")
    except LoaderCorpusEvidenceError:
        raise
    except Exception as error:
        raise LoaderCorpusEvidenceError(f"package-corpus retained application payload is unreadable: {error}") from error
    expected_cases = {case.id: case for case in _corpus_cases()}
    _require(type(report["case_count"]) is int and report["case_count"] == len(expected_cases), "package-corpus case count differs")
    _require(isinstance(report["outcomes"], list) and len(report["outcomes"]) == len(expected_cases),
             "package-corpus outcome roster is incomplete")
    observed_ids: set[str] = set()
    for outcome in report["outcomes"]:
        record = _keys(outcome, {"id", "tier", "package", "path", "argv", "environment", "stateful", "requires_dt_relr", "roots", "comparison"},
                       "package-corpus outcome")
        case_id = record["id"]
        _require(isinstance(case_id, str) and case_id in expected_cases and case_id not in observed_ids,
                 "package-corpus outcome has a duplicate, missing, or extra case")
        observed_ids.add(case_id)
        expected = expected_cases[case_id]
        _require((record["tier"], record["package"], record["path"], record["argv"], record["environment"], record["stateful"], record["requires_dt_relr"])
                 == (expected.tier, expected.package, expected.path, list(expected.argv), corpus.CASE_ENVIRONMENT, expected.stateful, expected.requires_dt_relr),
                 f"package-corpus {case_id} frozen invocation differs")
        validate_corpus_comparison(record["comparison"])
        roots = _keys(record["roots"], {"oracle", "candidate"}, f"package-corpus {case_id} roots")
        for arm in ("oracle", "candidate"):
            private_root = execution_root / f"{case_id}-{arm}"
            _validate_corpus_root(private_root, roots[arm], expected, arm, dynamic_product, product_files, oracle,
                                  source_mount, checkout, corpus)
    _require(observed_ids == set(expected_cases), "package-corpus outcome roster differs from frozen manifest")
    return {"component": "package-corpus", "case_count": len(expected_cases),
            "product_manifest": str(manifest_path), "product_manifest_sha256": manifest_sha256,
            "family_complete": False}


def validate_reports(loader_report: Path, corpus_report: Path, dynamic_product: Path, *, root: Path = ROOT) -> dict[str, dict[str, object]]:
    """Validate both component reports against the exact same supplied product."""

    loader = validate_loader_report(loader_report, dynamic_product, root=root)
    corpus = validate_corpus_report(corpus_report, dynamic_product, root=root)
    _require(loader["product_manifest_sha256"] == corpus["product_manifest_sha256"],
             "loader and corpus receipts used different product manifests")
    return {"loader": loader, "corpus": corpus}
