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


def _dynamic_receipt() -> Any:
    return _load_module("_owned_loader_corpus_dynamic_receipt", "compat/x86_64/owned_dynamic_receipt.py")


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


def _resolved_file_within(root: Path, relative: str, description: str) -> Path:
    """Resolve a payload alias only when its physical target remains private."""

    candidate = root / relative
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise LoaderCorpusEvidenceError(f"{description} is unavailable") from error
    _require(resolved.is_relative_to(root.resolve()), f"{description} escapes its retained root")
    return _physical_file(resolved, description)


def _hash_within(root: Path, relative: str, description: str) -> str:
    return _sha256(_resolved_file_within(root, relative, description))


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
        for name, child in value.items():
            _summary_processes(child, output, description + "." + str(name))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _summary_processes(child, output, f"{description}[{index}]")


class _RawMatcher:
    """Consume the complete finite raw-command receipt for one loader case."""

    def __init__(self, records: list[dict[str, Any]], description: str) -> None:
        self.records = records
        self.description = description
        self.used: set[int] = set()

    def take(self, argv: list[str], cwd: str, environment: Mapping[str, str], description: str,
             *, stdout: bytes | None = None, stderr: bytes | None = None) -> dict[str, Any]:
        matches = []
        for index, item in enumerate(self.records):
            if index in self.used:
                continue
            if item["argv"] != argv or item["cwd"] != cwd or item["environment"] != dict(environment):
                continue
            if stdout is not None and bytes.fromhex(item["stdout_hex"]) != stdout:
                continue
            if stderr is not None and bytes.fromhex(item["stderr_hex"]) != stderr:
                continue
            matches.append(index)
        _require(matches, f"{description} lacks its exact raw command receipt")
        self.used.add(matches[0])
        return self.records[matches[0]]

    def assert_complete(self) -> None:
        _require(len(self.used) == len(self.records), f"{self.description} raw receipt contains an unexpected command")


def _validate_loader_raw(raw: Path, case_record: dict[str, object], description: str) -> _RawMatcher:
    raw = _physical_directory(raw, description + " raw directory")
    try:
        children = sorted(raw.iterdir())
    except OSError as error:
        raise LoaderCorpusEvidenceError(f"cannot inspect {description} raw directory") from error
    json_files = [path for path in children if path.name.endswith(".json")]
    _require(json_files, f"{description} has no raw process records")
    expected_names: set[str] = set()
    raw_observations: list[tuple[str, int, bytes, bytes, bool]] = []
    records: dict[tuple[str, int, bytes, bytes, bool], list[dict[str, Any]]] = {}
    all_records: list[dict[str, Any]] = []
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
        records.setdefault(observation, []).append(record)
        all_records.append(record)
    _require({path.name for path in children} == expected_names, f"{description} raw artifact roster differs")
    summaries: list[tuple[str, int, bytes, bytes, bool]] = []
    _summary_processes(case_record, summaries, description)
    _require(summaries, f"{description} has no summarized process observations")
    retained = Counter(raw_observations)
    for observation, count in Counter(summaries).items():
        _require(retained[observation] >= count, f"{description} summary observation lacks matching raw receipt")
    return _RawMatcher(all_records, description)


def _expected_oracle(value: Mapping[str, object]) -> tuple[str, str]:
    _require(isinstance(value, Mapping) and set(value) == {"runtime_sha256", "compiler_wrapper_sha256"},
             "expected oracle must contain only runtime_sha256 and compiler_wrapper_sha256")
    return (_digest(value["runtime_sha256"], "expected oracle runtime"),
            _digest(value["compiler_wrapper_sha256"], "expected oracle compiler wrapper"))


def _oracle_seal(value: object, expected_oracle: Mapping[str, object]) -> dict[str, Any]:
    oracle = _keys(value, {"compiler", "compiler_sha256", "libc", "libc_sha256"}, "synthetic loader oracle")
    _require(all(isinstance(oracle[name], str) and Path(oracle[name]).is_absolute() for name in ("compiler", "libc")),
             "synthetic loader oracle paths differ")
    _digest(oracle["compiler_sha256"], "synthetic loader compiler")
    _digest(oracle["libc_sha256"], "synthetic loader libc")
    runtime_sha256, compiler_sha256 = _expected_oracle(expected_oracle)
    _require(oracle["libc_sha256"] == runtime_sha256 and oracle["compiler_sha256"] == compiler_sha256,
             "synthetic-loader oracle differs from the prepared pinned oracle")
    return oracle


def _loader_object_roles(loader: Any, name: str) -> list[tuple[str, tuple[str, ...], bool]]:
    """Return the exact one-time role order used by the frozen recipe."""

    if name in loader.SPECS and name != "relocations":
        spec = loader.SPECS[name]
        return [(source, tuple(defines), False) for _, source, defines in spec.dsos] + [(spec.main, (), False)]
    if name == "relocations":
        return [(source, (), False) for source in ("reloc_provider.c", "reloc_consumer.c", "reloc_relative_x86_adapter.c", "reloc_relative_x86_companion.c")]
    if name == "hash-formats":
        return [("hash_dso.c", ("-DHASH_VALUE=13",), False), ("hash_dso.c", ("-DHASH_VALUE=29",), False), ("hash_main.c", (), False)]
    if name == "hash-many":
        return [("hash-many-1025.c", (), True), ("hash_many_main.c", (), False)]
    if name == "search-path":
        return [("search_dso.c", (f"-DSEARCH_VALUE={value}",), False) for value in (11, 22, 33)] + [("search_main.c", (), False)]
    if name == "dso-origin":
        return [(source, (), False) for source in ("origin_leaf.c", "origin_mid.c", "origin_main.c")]
    _fail(f"unknown frozen loader case {name}")


def _loader_link_plan(loader: Any, name: str) -> list[tuple[str, str, str]]:
    if name in loader.SPECS and name != "relocations":
        plan = []
        for arm in ("oracle", "candidate"):
            plan.extend((arm, "shared", "usr/lib/" + dso) for dso, _, _ in loader.SPECS[name].dsos)
            plan.append((arm, "executable", "consumer"))
        return plan
    if name == "relocations":
        plan = []
        for arm in ("oracle", "candidate"):
            plan.extend((arm, "shared", "usr/lib/" + dso) for dso in ("libreloc_provider.so", "libreloc_consumer.so", "libreloc_relative_x86_adapter.so"))
            plan.append((arm, "executable", "consumer"))
        return plan
    if name == "hash-formats":
        return [("oracle", "shared", "usr/lib/libhash_gnu.so"), ("oracle", "shared", "usr/lib/libhash_sysv.so"),
                ("candidate", "shared", "usr/lib/libhash_gnu.so"), ("candidate", "shared", "usr/lib/libhash_sysv.so"),
                ("oracle", "executable", "consumer"), ("candidate", "executable", "consumer")]
    if name == "hash-many":
        return [(arm, kind, output) for arm, kind, output in (("oracle", "shared", "usr/lib/libhash_many.so"), ("candidate", "shared", "usr/lib/libhash_many.so"), ("oracle", "executable", "consumer"), ("candidate", "executable", "consumer"))]
    if name == "search-path":
        # The recipe builds every shared image first, then both RUNPATH
        # executables, then both legacy-RPATH executables.  Keep this exact
        # order: it binds a receipt's recorded object/link list to the finite
        # producer recipe instead of merely counting links per arm.
        return ([(arm, "shared", "usr/lib/libsearch.so")
                 for arm in ("oracle", "oracle", "oracle", "candidate", "candidate", "candidate")]
                + [("oracle", "executable", "consumer-runpath"),
                   ("candidate", "executable", "consumer-runpath"),
                   ("oracle", "executable", "consumer-rpath"),
                   ("candidate", "executable", "consumer-rpath")])
    if name == "dso-origin":
        return [("oracle", "shared", "usr/lib/liborigin_leaf.so"),
                ("oracle", "shared", "usr/lib/liborigin_mid.so"),
                ("candidate", "shared", "usr/lib/liborigin_leaf.so"),
                ("candidate", "shared", "usr/lib/liborigin_mid.so"),
                ("oracle", "executable", "consumer"),
                ("candidate", "executable", "consumer")]
    _fail(f"unknown frozen loader case {name}")


def _loader_link_counts(loader: Any, name: str) -> dict[str, int]:
    return dict(Counter(arm for arm, _, _ in _loader_link_plan(loader, name)))


def _loader_case_shape(name: str, loader: Any) -> set[str]:
    common = {"result", "execution_roots", "objects", "links", "raw_directory", "status"}
    if name == "search-path":
        return common | {"dynamic", "behavior"}
    if name == "hash-formats":
        return common | {"dynamic", "oracle", "candidate", "candidate_direct"}
    if name == "hash-many":
        return common | {"symbol_count", "dynamic", "oracle", "candidate", "candidate_direct"}
    if name == "relocations":
        return common | {"consumer_relocations", "adapter_relocations", "adapter_dynamic", "oracle", "candidate", "candidate_direct"}
    if name == "dso-origin":
        return common | {"dynamic", "oracle", "candidate", "candidate_direct"}
    if name in loader.SPECS:
        return common | {"properties", "oracle", "candidate", "candidate_direct"}
    _fail(f"unknown frozen loader case {name}")


def _loader_link_bindings(loader: Any, name: str) -> list[tuple[int, tuple[str, ...]]]:
    """Return the object role and preceding link outputs for every link.

    This mirrors the finite calls to ``FixtureBuilder.shared`` and
    ``FixtureBuilder.executable``.  It deliberately describes only retained
    recipe data; it never attempts to emulate a linker.
    """

    if name in loader.SPECS and name != "relocations":
        spec = loader.SPECS[name]
        dependency_names = {
            "libnested_mid.so": ("libnested_leaf.so",),
            "liborder_mid.so": ("liborder_leaf.so",),
        }
        bindings: list[tuple[int, tuple[str, ...]]] = []
        for _arm in ("oracle", "candidate"):
            for index, (dso, _source, _defines) in enumerate(spec.dsos):
                bindings.append((index, tuple("usr/lib/" + item for item in dependency_names.get(dso, ()))))
            linked: list[str] = []
            def include(item: str) -> None:
                if item in linked:
                    return
                linked.append(item)
                for child in dependency_names.get(item, ()):
                    include(child)
            for item in spec.initial:
                include(item)
            bindings.append((len(spec.dsos), tuple("usr/lib/" + item for item in linked)))
        return bindings
    if name == "relocations":
        one_arm = [(0, ()), (1, ("usr/lib/libreloc_provider.so",)), (2, ()),
                   (3, ("usr/lib/libreloc_consumer.so", "usr/lib/libreloc_relative_x86_adapter.so", "usr/lib/libreloc_provider.so"))]
        return one_arm * 2
    if name == "hash-formats":
        return [(0, ()), (1, ()), (0, ()), (1, ()), (2, ()), (2, ())]
    if name == "hash-many":
        return [(0, ()), (0, ()), (1, ()), (1, ())]
    if name == "search-path":
        return [(0, ()), (1, ()), (2, ()), (0, ()), (1, ()), (2, ()), (3, ()), (3, ()), (3, ()), (3, ())]
    if name == "dso-origin":
        return [(0, ()), (1, ("usr/lib/liborigin_leaf.so",)), (0, ()), (1, ("usr/lib/liborigin_leaf.so",)), (2, ()), (2, ())]
    _fail(f"unknown frozen loader case {name}")


def _validate_loader_objects(root: Path, source_mount: str, work: Path, product: Path, name: str,
                             case: Mapping[str, Any], loader: Any, raw: _RawMatcher) -> list[Path]:
    roles = _loader_object_roles(loader, name)
    objects = case["objects"]
    _require(isinstance(objects, list) and len(objects) == len(roles), f"loader case {name} object roster differs")
    retained: list[Path] = []
    for index, (record, (source_name, defines, generated)) in enumerate(zip(objects, roles)):
        item = _keys(record, {"source", "defines", "header_trace", "header_trace_sha256", "object", "sha256"},
                     f"loader case {name} object")
        source = work / source_name if generated else root / "compat/ldso/fixtures" / source_name
        object_path = work / "objects" / f"{index:03d}-{Path(source_name).stem}.o"
        trace_path = object_path.with_suffix(".headers.i")
        _require(item["source"] == recorded_path(root, source_mount, source) and item["defines"] == list(defines)
                 and item["header_trace"] == recorded_path(root, source_mount, trace_path)
                 and item["object"] == recorded_path(root, source_mount, object_path),
                 f"loader case {name} object recipe differs")
        if generated:
            expected_source = "\n".join(
                f"int hash_many_{item}(void) {{ return {item}; }}" for item in range(1025)
            ) + "\n"
            _require(_physical_file(source, f"loader case {name} generated source").read_bytes()
                     == expected_source.encode("utf-8"),
                     f"loader case {name} generated source differs")
        _require(_digest(item["header_trace_sha256"], f"loader case {name} header trace") == _sha256(trace_path)
                 and _digest(item["sha256"], f"loader case {name} object") == _sha256(object_path),
                 f"loader case {name} object bytes differ")
        raw.take([str(loader.ORACLE_CC), "-nostdinc", "-isystem", recorded_path(root, source_mount, product / "usr/include"),
                  *defines, "-H", "-E", item["source"], "-o", item["header_trace"]],
                 recorded_path(root, source_mount, work), {}, f"loader case {name} header role {index}")
        raw.take([recorded_path(root, source_mount, product / "bin/crabc-cc-dynamic"), "--dynamic-shared-object",
                  *defines, "-c", item["source"], "-o", item["object"]],
                 recorded_path(root, source_mount, work), {}, f"loader case {name} compile role {index}")
        retained.append(object_path)
    return retained


def _loader_link_settings(name: str, kind: str, output: str) -> tuple[str, str, str, bool]:
    """Return the declared search/hash/export state for one frozen link."""

    output_name = Path(output).name
    hash_style = "both" if name == "hash-many" and kind == "shared" else (
        "gnu" if name == "hash-formats" and output_name == "libhash_gnu.so" else "sysv"
    )
    search_kind = "rpath" if name == "search-path" and output_name == "consumer-rpath" else "runpath"
    search_path = ("$ORIGIN" if name == "dso-origin" and output_name == "liborigin_mid.so" else
                   "/rpath" if search_kind == "rpath" else
                   "/runpath" if name == "search-path" and kind == "executable" else "/usr/lib")
    return search_kind, search_path, hash_style, name == "main-handle" and kind == "executable"


def _loader_link_argv(loader: Any, name: str, link: Mapping[str, Any], product: Path,
                     root: Path, source_mount: str, work: Path) -> list[str]:
    """Reconstruct one exact finite producer linker invocation."""

    arm, kind = link["arm"], link["kind"]
    output, object_file = link["output"], link["object"]
    dependencies = [item["path"] for item in link["dependencies"]]
    output_name = Path(output).name
    search_kind, runpath, hash_style, export_dynamic = _loader_link_settings(name, kind, output)
    driver = recorded_path(root, source_mount, product / "bin/crabc-cc-dynamic")
    if arm == "candidate":
        if kind == "shared":
            argv = [driver, "--dynamic-shared-object", "--application-hash-style", hash_style,
                    "--application-runpath", runpath, object_file]
        else:
            argv = [driver, "--dynamic-pie", "--application-hash-style", hash_style,
                    "--application-" + search_kind, runpath]
            if export_dynamic:
                argv.append("-rdynamic")
            argv.append(object_file)
        for dependency in dependencies:
            argv.extend(("--application-dso", dependency))
        return argv + ["-o", output]
    if name == "hash-many" and kind == "shared":
        return [str(loader.ORACLE_CC), "-shared", "-Wl,-soname,libhash_many.so", object_file,
                "-Wl,--hash-style=both", "-o", output]
    if name == "hash-formats" and kind == "shared":
        return [str(loader.ORACLE_CC), "-shared", object_file, "-Wl,--hash-style=" + hash_style, "-o", output]
    if kind == "shared":
        return [str(loader.ORACLE_CC), "-shared", "-Wl,-soname," + output_name, object_file, *dependencies,
                "-Wl,--hash-style=" + hash_style, "-Wl,-rpath," + runpath, "-o", output]
    argv = [str(loader.ORACLE_CC), "-fPIE", "-pie", object_file, *dependencies, "-Wl,--hash-style=" + hash_style]
    if search_kind == "rpath":
        argv.append("-Wl,--disable-new-dtags")
    argv.extend(("-Wl,-rpath," + runpath,
                 "-Wl,-rpath-link," + recorded_path(root, source_mount, work / (arm + "-root") / "usr/lib"),
                 "-Wl,--dynamic-linker,/lib/ld-musl-x86_64.so.1"))
    if export_dynamic:
        argv.append("-Wl,--export-dynamic")
    return argv + ["-o", output]


def _validate_loader_links(root: Path, source_mount: str, work: Path, product: Path, name: str,
                           case: Mapping[str, Any], objects: list[Path], loader: Any, raw: _RawMatcher) -> None:
    links = case["links"]
    counts = _loader_link_counts(loader, name)
    plan = _loader_link_plan(loader, name)
    bindings = _loader_link_bindings(loader, name)
    _require(isinstance(links, list) and len(links) == len(plan), f"loader case {name} link roster differs")
    _require(len(bindings) == len(plan), f"loader case {name} internal link plan drifted")
    observed_counts = Counter()
    output_hashes: dict[tuple[str, str], str] = {}
    for record, (expected_arm, expected_kind, relative_output), (object_index, expected_dependencies) in zip(links, plan, bindings):
        link = _keys(record, {"kind", "arm", "output", "output_sha256", "object", "object_sha256", "dependencies"},
                     f"loader case {name} link")
        _require((link["kind"], link["arm"]) == (expected_kind, expected_arm), f"loader case {name} link role differs")
        observed_counts[link["arm"]] += 1
        object_path = mounted_path(root, source_mount, link["object"])
        _require(object_index < len(objects) and object_path == objects[object_index]
                 and _digest(link["object_sha256"], f"loader case {name} link object") == _sha256(object_path),
                 f"loader case {name} link object differs")
        output = mounted_path(root, source_mount, link["output"])
        arm_root = work / (str(link["arm"]) + "-root")
        _require(output == arm_root / relative_output, f"loader case {name} link output recipe differs")
        output_hash = _digest(link["output_sha256"], f"loader case {name} link output")
        if output.exists():
            _require(_sha256(output) == output_hash, f"loader case {name} link output differs")
        else:
            # Search and ORIGIN deliberately move a just-linked DSO.  Its
            # retained byte identity must still occur once below the same arm.
            moved = [candidate for candidate in arm_root.rglob(output.name)
                     if candidate.is_file() and not candidate.is_symlink() and _sha256(candidate) == output_hash]
            _require(len(moved) == 1, f"loader case {name} moved link output differs")
        dependencies = link["dependencies"]
        _require(isinstance(dependencies, list) and len(dependencies) == len(expected_dependencies),
                 f"loader case {name} link dependencies differ")
        for dependency, relative_dependency in zip(dependencies, expected_dependencies):
            item = _keys(dependency, {"path", "sha256"}, f"loader case {name} link dependency")
            expected_path = arm_root / relative_dependency
            expected_hash = output_hashes.get((expected_arm, relative_dependency))
            _require(expected_hash is not None and item["path"] == recorded_path(root, source_mount, expected_path)
                     and _digest(item["sha256"], f"loader case {name} dependency") == expected_hash,
                     f"loader case {name} link dependency differs")
        raw.take(_loader_link_argv(loader, name, link, product, root, source_mount, work),
                 recorded_path(root, source_mount, work), {}, f"loader case {name} {expected_arm} {expected_kind} link")
        output_hashes[(expected_arm, relative_output)] = output_hash
    _require(dict(observed_counts) == counts, f"loader case {name} link arm roster differs")


def _loader_retained_output(name: str, arm: str, kind: str, original: str,
                            search_shared_index: int | None) -> str:
    """Name the final retained location of one finite link artifact."""

    if name == "search-path" and kind == "shared":
        _require(search_shared_index is not None and 0 <= search_shared_index < 3,
                 "loader search-path link plan drifted")
        return ("environment", "runpath", "rpath")[search_shared_index] + "/libsearch.so"
    if name == "dso-origin" and kind == "shared":
        return "bundle/" + Path(original).name
    return original


def _loader_dynamic_runtime(product: Path, kind: str) -> tuple[Path, ...]:
    library = product / "usr/lib"
    runtime = [library / "crti.o", library / "libc.so", library / "crtn.o"]
    if kind == "executable":
        runtime.extend((library / "Scrt1.o", library / "crabc-dynamic-attach.o"))
    return tuple(runtime)


def _loader_sidecar_command(linker: str, root: Path, source_mount: str, product: Path, link: Mapping[str, Any],
                            search_kind: str, search_path: str, hash_style: str,
                            export_dynamic: bool) -> list[str]:
    """Rebuild the owned driver's finite LLD argv recorded by a sidecar."""

    kind = link["kind"]
    library = product / "usr/lib"
    recorded = lambda path: recorded_path(root, source_mount, path)
    command = [linker, "-shared" if kind == "shared" else "-pie", "--hash-style=" + hash_style,
               "-z", "relro", "-z", "now", "-z", "noexecstack", "-z", "text", "--no-undefined",
               "--allow-shlib-undefined", "--disable-new-dtags" if search_kind == "rpath" else "--enable-new-dtags",
               "-rpath", search_path]
    if export_dynamic:
        command.append("--export-dynamic")
    if kind == "executable":
        command.extend(("--dynamic-linker", "/lib/ld-musl-x86_64.so.1", recorded(library / "Scrt1.o"),
                        recorded(library / "crabc-dynamic-attach.o")))
    command.extend((recorded(library / "crti.o"), link["object"],
                    *(item["path"] for item in link["dependencies"]), recorded(library / "libc.so"),
                    recorded(library / "libcrabc-builtins.a"), recorded(library / "crtn.o"), "-o", link["output"]))
    return command


def _validate_loader_sidecar(root: Path, source_mount: str, product: Path, name: str,
                             link: Mapping[str, Any], path: Path, producer_linker: Mapping[str, str]) -> None:
    """Bind a candidate artifact to its v2 owned-driver link receipt."""

    receipt = _json(path, f"loader case {name} dynamic link sidecar")
    contract = _dynamic_receipt()
    product_reader = _product_reader()
    search = contract.validate(receipt, format=product_reader.DYNAMIC_PRODUCT_FORMAT,
                               label=f"loader case {name} dynamic link sidecar", fail=_fail)
    _require(search.schema == 2, f"loader case {name} dynamic link sidecar is not schema 2")
    kind = link["kind"]
    search_kind, search_path, hash_style, export_dynamic = _loader_link_settings(name, kind, link["output"])
    _require((receipt["mode"], receipt["binding"], receipt["runtime_imports"], receipt["campaign_complete"])
             == ("shared" if kind == "shared" else "pie", "now", [], False),
             f"loader case {name} dynamic link sidecar mode differs")
    _require((search.kind, search.path, search.hash_style) == (search_kind, search_path, hash_style),
             f"loader case {name} dynamic link sidecar search contract differs")
    _require(receipt["output_path"] == link["output"]
             and _digest(receipt["output_sha256"], f"loader case {name} sidecar output") == link["output_sha256"],
             f"loader case {name} dynamic link sidecar output differs")
    manifest = product / "share/crabc/manifest.json"
    _require(_digest(receipt["manifest_sha256"], f"loader case {name} sidecar manifest") == _sha256(manifest),
             f"loader case {name} dynamic link sidecar manifest differs")
    dependencies = link["dependencies"]
    expected_dsos = {Path(item["path"]).name: item["sha256"] for item in dependencies}
    _require(receipt["application_dsos"] == expected_dsos,
             f"loader case {name} dynamic link sidecar DSO roster differs")
    runtime = _loader_dynamic_runtime(product, kind)
    archive = product / "usr/lib/libcrabc-builtins.a"
    _require(receipt["owned_runtime_inputs"] == sorted(
        path.relative_to(product).as_posix() for path in (*runtime, archive)),
             f"loader case {name} dynamic link sidecar runtime roster differs")
    expected_inputs = [
        *((recorded_path(root, source_mount, path), _sha256(path)) for path in runtime),
        (link["object"], link["object_sha256"]),
        *((item["path"], item["sha256"]) for item in dependencies),
        (recorded_path(root, source_mount, archive), _sha256(archive)),
    ]
    inputs = receipt["input_receipts"]
    _require(isinstance(inputs, list) and len(inputs) == len(expected_inputs),
             f"loader case {name} dynamic link sidecar input roster differs")
    for item, (expected_path, expected_sha256) in zip(inputs, expected_inputs):
        record = _keys(item, {"path", "sha256"}, f"loader case {name} sidecar input")
        _require(record["path"] == expected_path
                 and _digest(record["sha256"], f"loader case {name} sidecar input") == expected_sha256,
                 f"loader case {name} dynamic link sidecar input differs")
    linker = _keys(receipt["resolved_linker"], {"path", "sha256"}, f"loader case {name} sidecar linker")
    _require(linker == producer_linker,
             f"loader case {name} dynamic link sidecar linker differs from the sealed producer linker")
    _require(receipt["link_command"] == _loader_sidecar_command(
        linker["path"], root, source_mount, product, link, search_kind, search_path, hash_style, export_dynamic
    ), f"loader case {name} dynamic link sidecar command differs")
    trace = receipt["link_trace"]
    direct = {recorded_path(root, source_mount, path) for path in runtime}
    direct.add(link["object"])
    direct.update(item["path"] for item in dependencies)
    recorded_archive = recorded_path(root, source_mount, archive)
    _require(isinstance(trace, list) and all(isinstance(item, str) for item in trace)
             and direct <= set(trace)
             and all(item in direct or item == recorded_archive
                     or item.startswith(recorded_archive + "(") and item.endswith(")") for item in trace),
             f"loader case {name} dynamic link sidecar trace differs")


def _loader_root_entries(root: Path) -> dict[str, dict[str, object]]:
    entries = _loader_tree_entries(root)
    result = {entry["path"]: entry for entry in entries}
    _require(len(result) == len(entries), "retained loader root has duplicate paths")
    return result


def _loader_add_parent_directories(expected: dict[str, str], path: str) -> None:
    current = PurePosixPath(path).parent
    while current.parts:
        name = current.as_posix()
        prior = expected.setdefault(name, "directory")
        _require(prior == "directory", "loader root generated path conflicts with a file")
        current = current.parent


def _loader_require_file(entries: Mapping[str, Mapping[str, object]], relative: str, digest: str | None,
                         description: str) -> None:
    entry = entries.get(relative)
    _require(entry is not None and entry.get("kind") == "file", f"{description} is missing or not a file")
    if digest is not None:
        _require(entry.get("sha256") == digest, f"{description} bytes differ")


def _validate_loader_execution_root(checkout: Path, execution_root: Path, source_mount: str, product: Path, oracle: Mapping[str, Any],
                                    producer_linker: Mapping[str, str], name: str, case: Mapping[str, Any], loader: Any, arm: str) -> None:
    """Require the exact recipe-derived root, rather than trusting its seal.

    The producer seal proves that retained bytes did not change after it was
    written.  This second check proves what those bytes were allowed to be:
    the supplied product for the candidate, the pinned musl runtime for the
    oracle, and only the finite link artifacts/sidecars made by this case.
    """

    entries = _loader_root_entries(execution_root)
    expected: dict[str, str] = {}
    product_entries = {entry["path"]: entry for entry in loader_tree_seal(product)["entries"]}
    if arm == "candidate":
        for relative, product_entry in product_entries.items():
            retained = entries.get(relative)
            _require(retained is not None and retained.get("kind") == product_entry.get("kind"),
                     f"loader case {name} candidate product entry {relative} differs")
            _require(_normalised_mode(product_entry["mode"], retained["mode"], str(product_entry["kind"])),
                     f"loader case {name} candidate product mode {relative} differs")
            for field in set(product_entry) - {"mode"}:
                _require(retained.get(field) == product_entry[field],
                         f"loader case {name} candidate product entry {relative} differs")
            expected[relative] = str(product_entry["kind"])
    else:
        expected.update({"lib": "directory", "usr": "directory", "usr/lib": "directory",
                         "lib/ld-musl-x86_64.so.1": "file", "usr/lib/libc.so": "file"})
        _loader_require_file(entries, "lib/ld-musl-x86_64.so.1", oracle["libc_sha256"],
                             f"loader case {name} oracle loader")
        _loader_require_file(entries, "usr/lib/libc.so", oracle["libc_sha256"],
                             f"loader case {name} oracle libc")

    search_indexes = {"oracle": 0, "candidate": 0}
    plan = _loader_link_plan(loader, name)
    links = case["links"]
    for link, (link_arm, kind, original) in zip(links, plan):
        if link_arm != arm:
            continue
        ordinal = search_indexes[arm] if name == "search-path" and kind == "shared" else None
        if ordinal is not None:
            search_indexes[arm] += 1
        retained = _loader_retained_output(name, arm, kind, original, ordinal)
        _require(retained not in expected, f"loader case {name} generated artifact replaces a sealed root entry")
        expected[retained] = "file"
        _loader_add_parent_directories(expected, retained)
        _loader_require_file(entries, retained, link["output_sha256"],
                             f"loader case {name} {arm} linked artifact {retained}")
        if arm == "candidate":
            sidecar = (original + ".crabc-link.json" if name == "dso-origin" and kind == "shared"
                       else retained + ".crabc-link.json")
            _require(sidecar not in expected, f"loader case {name} sidecar conflicts with a sealed root entry")
            expected[sidecar] = "file"
            _loader_add_parent_directories(expected, sidecar)
            sidecar_path = execution_root / sidecar
            _loader_require_file(entries, sidecar, None, f"loader case {name} candidate sidecar {sidecar}")
            _validate_loader_sidecar(checkout, source_mount, product, name, link, sidecar_path, producer_linker)
    _require(set(entries) == set(expected), f"loader case {name} {arm} root contains an unexpected or missing entry")
    for relative, kind in expected.items():
        _require(entries[relative]["kind"] == kind,
                 f"loader case {name} {arm} root entry type differs: {relative}")


def _loader_runtime_observation(root: Path, source_mount: str, work: Path, raw_records: _RawMatcher,
                                value: object, arm: str, program: str, direct: bool, environment: Mapping[str, str],
                                description: str, expected: bytes | set[bytes] | None, lifecycle: bool = False) -> bytes:
    observation = _process(value, description)
    record = _keys(value, {"argv", "returncode", "stdout_hex", "stderr_hex", "timed_out"}, description)
    arm_root = work / (arm + "-root")
    argv = ["/usr/sbin/chroot", recorded_path(root, source_mount, arm_root)]
    argv += ["/lib/ld-musl-x86_64.so.1", "/" + program] if direct else ["/" + program]
    _require(record["argv"] == argv and observation[1] == 0 and not observation[4] and observation[3] == b"",
             f"{description} command or status differs")
    raw_records.take(argv, recorded_path(root, source_mount, work), environment, description,
                     stdout=observation[2], stderr=observation[3])
    if lifecycle:
        _require(all(marker in observation[2] for marker in (b"ctor\n", b"lifecycle=73\n", b"after-close\n", b"reopened=73\n", b"dtor\n")),
                 f"{description} lifecycle stream differs")
    elif isinstance(expected, set):
        _require(observation[2] in expected, f"{description} output is outside its frozen grammar")
    elif expected is not None:
        _require(observation[2] == expected, f"{description} output differs")
    return observation[2]


def _loader_environment(loader: Any, name: str, extra: Mapping[str, str] | None = None) -> dict[str, str]:
    environment = {"PATH": "/usr/bin:/bin"}
    if name in loader.SPECS:
        environment.update(dict(loader.SPECS[name].environment))
    if name in {"hash-formats", "hash-many"}:
        environment["LD_LIBRARY_PATH"] = "/usr/lib"
    if extra:
        environment.update(extra)
    return environment


def _loader_readelf(raw: _RawMatcher, root: Path, source_mount: str, work: Path, argv: list[str],
                    stdout: str, description: str) -> None:
    _require(isinstance(stdout, str), f"{description} is not text")
    raw.take(argv, recorded_path(root, source_mount, work), {}, description,
             stdout=stdout.encode("utf-8"), stderr=b"")


def _loader_needed_readelf(raw: _RawMatcher, root: Path, source_mount: str, work: Path, argv: list[str],
                           expected: list[str], loader: Any, description: str) -> None:
    item = raw.take(argv, recorded_path(root, source_mount, work), {}, description, stderr=b"")
    _require(loader.needed_names(bytes.fromhex(item["stdout_hex"])) == expected,
             f"{description} differs from its raw readelf receipt")


def _validate_loader_properties(name: str, properties: object, loader: Any, raw: _RawMatcher,
                                root: Path, source_mount: str, work: Path) -> None:
    _require(isinstance(properties, dict), f"loader case {name} properties differ")
    expected_keys = {
        "initial-tls": {"program_headers"}, "relro": {"program_headers", "relocations"},
        "visibility": {"symbols"}, "lifecycle": {"dynamic"}, "legacy-lifecycle": {"dynamic"},
        "dynamic-tls": {"relocations"}, "nested-needed": {"middle_needed"},
        "constructor-order": {"middle_needed"}, "weak-strong": {"needed"},
    }.get(name, set())
    _require(set(properties) == expected_keys, f"loader case {name} property schema differs")
    candidate = recorded_path(root, source_mount, work / "candidate-root")
    def image(relative: str) -> str:
        return candidate + "/" + relative
    if name == "initial-tls":
        _require(isinstance(properties["program_headers"], str) and " TLS " in properties["program_headers"], "loader initial TLS headers differ")
        _loader_readelf(raw, root, source_mount, work, ["readelf", "-lW", image("usr/lib/libinitial_tls.so")], properties["program_headers"], "loader initial TLS readelf")
    if name == "relro":
        _require(isinstance(properties["program_headers"], str) and "GNU_RELRO" in properties["program_headers"] and isinstance(properties["relocations"], str) and "R_X86_64_64" in properties["relocations"], "loader RELRO properties differ")
        _loader_readelf(raw, root, source_mount, work, ["readelf", "-lW", image("usr/lib/librelro.so")], properties["program_headers"], "loader RELRO program headers")
        _loader_readelf(raw, root, source_mount, work, ["readelf", "-Wr", image("usr/lib/librelro.so")], properties["relocations"], "loader RELRO relocations")
    if name == "visibility":
        _require(isinstance(properties["symbols"], str) and "visibility_public" in properties["symbols"] and "visibility_hidden" not in properties["symbols"], "loader visibility symbols differ")
        _loader_readelf(raw, root, source_mount, work, ["readelf", "--dyn-syms", "--wide", image("usr/lib/libvisibility.so")], properties["symbols"], "loader visibility symbols")
    if name == "lifecycle":
        _require(isinstance(properties["dynamic"], str) and "(INIT_ARRAY)" in properties["dynamic"] and "(FINI_ARRAY)" in properties["dynamic"], "loader lifecycle tags differ")
        _loader_readelf(raw, root, source_mount, work, ["readelf", "-dW", image("usr/lib/liblifecycle.so")], properties["dynamic"], "loader lifecycle tags")
    if name == "legacy-lifecycle":
        _require(isinstance(properties["dynamic"], str) and all(tag in properties["dynamic"] for tag in ("(INIT)", "(FINI)", "(INIT_ARRAY)", "(FINI_ARRAY)")), "loader legacy lifecycle tags differ")
        _loader_readelf(raw, root, source_mount, work, ["readelf", "-dW", image("usr/lib/liblegacy_lifecycle.so")], properties["dynamic"], "loader legacy lifecycle tags")
    if name == "dynamic-tls":
        _require(isinstance(properties["relocations"], str) and any(tag in properties["relocations"] for tag in ("R_X86_64_DTPMOD64", "R_X86_64_DTPOFF64")), "loader dynamic TLS relocations differ")
        _loader_readelf(raw, root, source_mount, work, ["readelf", "-Wr", image("usr/lib/libfixture_tls.so")], properties["relocations"], "loader dynamic TLS relocations")
    if name in {"nested-needed", "constructor-order"}:
        edge = "libnested_leaf.so" if name == "nested-needed" else "liborder_leaf.so"
        _require(properties["middle_needed"] == [edge, "libc.so"], f"loader case {name} dependency edge differs")
        middle = "libnested_mid.so" if name == "nested-needed" else "liborder_mid.so"
        _loader_needed_readelf(raw, root, source_mount, work, ["readelf", "-dW", image("usr/lib/" + middle)],
                               properties["middle_needed"], loader, f"loader {name} needed tags")
    if name == "weak-strong":
        needed = properties["needed"]
        _require(isinstance(needed, list) and all(isinstance(item, str) for item in needed)
                 and "libweak_provider.so" in needed and "libstrong_provider.so" in needed
                 and needed.index("libweak_provider.so") < needed.index("libstrong_provider.so"),
                 "loader weak/strong dependency order differs")
        _loader_needed_readelf(raw, root, source_mount, work, ["readelf", "-dW", candidate + "/consumer"],
                               needed, loader, "loader weak/strong needed tags")


def _validate_loader_behavior(name: str, case: Mapping[str, Any], raw_records: _RawMatcher,
                              root: Path, source_mount: str, work: Path, loader: Any) -> None:
    if name == "aslr":
        _validate_loader_properties(name, case["properties"], loader, raw_records, root, source_mount, work)
        for arm, direct in (("oracle", False), ("candidate", False), ("candidate", True)):
            values = case["candidate_direct" if direct else arm]
            _require(isinstance(values, list) and len(values) == 2, f"loader ASLR {arm} observation count differs")
            pairs = []
            for index, value in enumerate(values):
                stdout = _loader_runtime_observation(root, source_mount, work, raw_records, value,
                                                     "candidate" if direct else arm, "consumer", direct,
                                                     _loader_environment(loader, name), f"loader ASLR {arm}[{index}]", None)
                match = loader.ASLR.fullmatch(stdout)
                _require(match is not None, f"loader ASLR {arm} stream differs")
                pairs.append((int(match.group(1), 16), int(match.group(2), 16)))
            _require(pairs[0][0] != pairs[1][0] and pairs[0][1] != pairs[1][1], f"loader ASLR {arm} bases did not change")
        return
    if name == "search-path":
        _require(set(case["dynamic"]) == {"candidate-runpath", "candidate-rpath"} and all(isinstance(value, str) for value in case["dynamic"].values())
                 and "(RUNPATH)" in case["dynamic"]["candidate-runpath"] and "(RPATH)" not in case["dynamic"]["candidate-runpath"]
                 and "(RPATH)" in case["dynamic"]["candidate-rpath"] and "(RUNPATH)" not in case["dynamic"]["candidate-rpath"], "loader search-path tags differ")
        candidate = recorded_path(root, source_mount, work / "candidate-root")
        _loader_readelf(raw_records, root, source_mount, work, ["readelf", "-dW", candidate + "/consumer-runpath"],
                        case["dynamic"]["candidate-runpath"], "loader RUNPATH tags")
        _loader_readelf(raw_records, root, source_mount, work, ["readelf", "-dW", candidate + "/consumer-rpath"],
                        case["dynamic"]["candidate-rpath"], "loader RPATH tags")
        behavior = _keys(case["behavior"], {"runpath-environment", "runpath-embedded", "rpath-environment", "rpath-embedded"}, "loader search-path behavior")
        for scenario, expected, program, extra in (("runpath-environment", b"search=11\n", "consumer-runpath", {"LD_LIBRARY_PATH": "/environment"}), ("runpath-embedded", b"search=22\n", "consumer-runpath", {}), ("rpath-environment", {b"search=11\n", b"search=22\n", b"search=33\n"}, "consumer-rpath", {"LD_LIBRARY_PATH": "/environment"}), ("rpath-embedded", {b"search=11\n", b"search=22\n", b"search=33\n"}, "consumer-rpath", {})):
            triple = _keys(behavior[scenario], {"oracle", "candidate", "candidate_direct"}, f"loader {scenario}")
            observations: list[bytes] = []
            for arm, direct, field in (("oracle", False, "oracle"), ("candidate", False, "candidate"), ("candidate", True, "candidate_direct")):
                observations.append(_loader_runtime_observation(root, source_mount, work, raw_records, triple[field], arm, program, direct,
                                                               _loader_environment(loader, name, extra), f"loader {scenario} {field}", expected))
            _require(observations[0] == observations[1] == observations[2],
                     f"loader {scenario} candidate observation differs from pinned musl")
        return
    expected = (loader.SPECS[name].expected if name in loader.SPECS and name != "relocations" else
                {"hash-formats": b"hash=13,29\n", "hash-many": b"hash-many=1024,0\n", "relocations": b"reloc=42 relative=73\n", "dso-origin": b"origin=18\n"}[name])
    if name == "hash-formats":
        _require(set(case["dynamic"]) == {"oracle-gnu", "oracle-sysv", "candidate-gnu", "candidate-sysv"}
                 and "(GNU_HASH)" in case["dynamic"]["oracle-gnu"] and "(HASH)" in case["dynamic"]["oracle-sysv"]
                 and "(GNU_HASH)" in case["dynamic"]["candidate-gnu"], "loader hash-format tags differ")
        oracle = recorded_path(root, source_mount, work / "oracle-root" / "usr/lib")
        candidate = recorded_path(root, source_mount, work / "candidate-root" / "usr/lib")
        objects = case["objects"]
        raw_records.take([str(loader.ORACLE_CC), "-shared", objects[0]["object"], "-Wl,--hash-style=gnu", "-o", oracle + "/libhash_gnu.so"],
                 recorded_path(root, source_mount, work), {}, "loader hash GNU oracle link")
        raw_records.take([str(loader.ORACLE_CC), "-shared", objects[1]["object"], "-Wl,--hash-style=sysv", "-o", oracle + "/libhash_sysv.so"],
                 recorded_path(root, source_mount, work), {}, "loader hash SysV oracle link")
        for field, path in (("oracle-gnu", oracle + "/libhash_gnu.so"), ("oracle-sysv", oracle + "/libhash_sysv.so"),
                            ("candidate-gnu", candidate + "/libhash_gnu.so"), ("candidate-sysv", candidate + "/libhash_sysv.so")):
            _loader_readelf(raw_records, root, source_mount, work, ["readelf", "-dW", path], case["dynamic"][field],
                            "loader hash-format " + field + " tags")
    if name == "hash-many":
        _require(case["symbol_count"] == 1025 and isinstance(case["dynamic"], str) and "(GNU_HASH)" in case["dynamic"] and "(HASH)" in case["dynamic"], "loader hash-many evidence differs")
        image = recorded_path(root, source_mount, work / "candidate-root/usr/lib/libhash_many.so")
        symbols = raw_records.take(["readelf", "--dyn-syms", "--wide", image], recorded_path(root, source_mount, work), {},
                           "loader hash-many symbols", stderr=b"")
        _require(sum("hash_many_" in line for line in bytes.fromhex(symbols["stdout_hex"]).decode("utf-8", "replace").splitlines()) == 1025,
                 "loader hash-many symbol receipt differs")
        _loader_readelf(raw_records, root, source_mount, work, ["readelf", "-dW", image], case["dynamic"], "loader hash-many tags")
    if name == "relocations":
        _require(all(isinstance(case[key], str) for key in ("consumer_relocations", "adapter_relocations", "adapter_dynamic"))
                 and all(tag in case["consumer_relocations"] for tag in ("R_X86_64_64", "R_X86_64_GLOB_DAT", "R_X86_64_JUMP_SLOT"))
                 and "R_X86_64_RELATIVE" in case["adapter_relocations"]
                 and not any("(" + tag + ")" in case["adapter_dynamic"] for tag in ("RELR", "RELRSZ", "RELRENT")), "loader relocation evidence differs")
        candidate = recorded_path(root, source_mount, work / "candidate-root/usr/lib")
        _loader_readelf(raw_records, root, source_mount, work, ["readelf", "-Wr", candidate + "/libreloc_consumer.so"], case["consumer_relocations"], "loader consumer relocations")
        _loader_readelf(raw_records, root, source_mount, work, ["readelf", "-Wr", candidate + "/libreloc_relative_x86_adapter.so"], case["adapter_relocations"], "loader adapter relocations")
        _loader_readelf(raw_records, root, source_mount, work, ["readelf", "-dW", candidate + "/libreloc_relative_x86_adapter.so"], case["adapter_dynamic"], "loader adapter dynamic tags")
    if name == "dso-origin":
        _require(isinstance(case["dynamic"], str) and "(RUNPATH)" in case["dynamic"] and "$ORIGIN" in case["dynamic"] and "liborigin_leaf.so" in case["dynamic"], "loader ORIGIN evidence differs")
        image = recorded_path(root, source_mount, work / "candidate-root/bundle/liborigin_mid.so")
        _loader_readelf(raw_records, root, source_mount, work, ["readelf", "-dW", image], case["dynamic"], "loader ORIGIN tags")
    if name in loader.SPECS and name != "relocations":
        _validate_loader_properties(name, case["properties"], loader, raw_records, root, source_mount, work)
    for arm, direct, field in (("oracle", False, "oracle"), ("candidate", False, "candidate"), ("candidate", True, "candidate_direct")):
        _loader_runtime_observation(root, source_mount, work, raw_records, case[field], arm, "consumer", direct,
                                    _loader_environment(loader, name), f"loader case {name} {field}", expected,
                                    lifecycle=name == "lifecycle")


def _validate_loader_case(root: Path, source_mount: str, report_root: Path, product: Path,
                          product_files: Mapping[str, str], oracle: Mapping[str, Any], producer_linker: Mapping[str, str],
                          name: str, value: object) -> None:
    loader = _loader()
    case = _require_case(value, name, loader)
    _require(case["status"] == "pass" and case["result"] == "pass", f"loader case {name} did not pass")
    raw = _retained_directory(root, source_mount, case["raw_directory"], f"loader case {name}")
    _require(raw == report_root / "cases" / name / "raw", f"loader case {name} raw path differs")
    case_json = _json(raw.parent / "case.json", f"loader case {name} raw case")
    _require(case_json == case, f"loader case {name} raw case receipt differs")
    raw_records = _validate_loader_raw(raw, case, f"loader case {name}")
    work = raw.parent
    objects = _validate_loader_objects(root, source_mount, work, product, name, case, loader, raw_records)
    _validate_loader_links(root, source_mount, work, product, name, case, objects, loader, raw_records)
    roots = _keys(case["execution_roots"], {"oracle", "candidate"}, f"loader case {name} roots")
    for arm in ("oracle", "candidate"):
        retained_root = report_root / "cases" / name / (arm + "-root")
        _validate_retained_loader_tree(retained_root, roots[arm], f"loader case {name} {arm} root")
        _validate_loader_execution_root(root, retained_root, source_mount, product, oracle, producer_linker, name, case, loader, arm)
    _require(_hash_within(report_root / "cases" / name / "oracle-root", "lib/ld-musl-x86_64.so.1", "loader oracle") == oracle["libc_sha256"],
             f"loader case {name} oracle loader differs")
    _require(_hash_within(report_root / "cases" / name / "oracle-root", "usr/lib/libc.so", "loader oracle") == oracle["libc_sha256"],
             f"loader case {name} oracle libc differs")
    candidate = report_root / "cases" / name / "candidate-root"
    _require(_hash_within(candidate, "lib/ld-crabc-x86_64.so.1", "loader candidate") == product_files["lib/ld-crabc-x86_64.so.1"],
             f"loader case {name} candidate loader differs from supplied product")
    _require(_hash_within(candidate, "usr/lib/libc.so", "loader candidate") == product_files["usr/lib/libc.so"],
             f"loader case {name} candidate libc differs from supplied product")
    _validate_loader_behavior(name, case, raw_records, root, source_mount, work, loader)
    raw_records.assert_complete()


def _require_case(value: object, name: str, loader: Any) -> dict[str, Any]:
    _require(isinstance(value, dict) and set(value) == _loader_case_shape(name, loader), f"loader case {name} schema differs")
    _require(isinstance(value["raw_directory"], str), f"loader case {name} raw directory differs")
    return value


def _loader_producer_linker(value: object) -> dict[str, str]:
    linker = _keys(value, {"path", "sha256"}, "synthetic-loader producer linker")
    _require(isinstance(linker["path"], str) and Path(linker["path"]).is_absolute()
             and ".." not in Path(linker["path"]).parts and Path(linker["path"]).name == "ld.lld",
             "synthetic-loader producer linker path differs")
    return {"path": linker["path"], "sha256": _digest(linker["sha256"], "synthetic-loader producer linker")}


def validate_loader_report(report_path: Path, dynamic_product: Path, *, expected_oracle: Mapping[str, object],
                           root: Path = ROOT) -> dict[str, object]:
    """Validate one complete retained 21-case synthetic-loader report."""

    checkout = _checked_root(root)
    report_path = _physical_file(report_path, "synthetic-loader report")
    _require(report_path.is_relative_to(checkout / ".work"), "synthetic-loader report must stay below checkout .work")
    report_root = report_path.parent
    report = _json(report_path, "synthetic-loader report")
    required = {"schema", "runner", "architecture", "source_mount", "selected_passed", "component_complete",
                "family_complete", "selected", "source_before", "source_after", "product_before", "product_after",
                "oracle_before", "oracle_after", "producer_linker_before", "producer_linker_after", "cases", "elapsed_seconds"}
    _keys(report, required, "synthetic-loader report")
    _require((report["schema"], report["runner"], report["architecture"]) == (2, "compat/ldso/run_x86.py", "x86_64"),
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
    oracle = _oracle_seal(report["oracle_before"], expected_oracle)
    _require(report["oracle_after"] == oracle, "synthetic-loader pinned oracle changed during execution")
    producer_linker = _loader_producer_linker(report["producer_linker_before"])
    _require(report["producer_linker_after"] == producer_linker,
             "synthetic-loader pinned producer linker changed during execution")
    for name in LOADER_CASES:
        _validate_loader_case(checkout, source_mount, report_root, dynamic_product, product_files, oracle, producer_linker,
                              name, report["cases"][name])
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


def _corpus_oracle(value: object, expected_oracle: Mapping[str, object]) -> dict[str, Any]:
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
    runtime_sha256, _ = _expected_oracle(expected_oracle)
    _require(runtime["sha256"] == runtime_sha256,
             "package-corpus oracle differs from the prepared pinned oracle")
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


def _retention_modes(value: object, description: str) -> dict[str, int]:
    _require(isinstance(value, dict), f"{description} retention modes are not an object")
    result: dict[str, int] = {}
    for relative, mode in value.items():
        candidate = PurePosixPath(relative) if isinstance(relative, str) else None
        _require(candidate is not None and not candidate.is_absolute() and candidate.parts
                 and all(part not in {"", ".", ".."} for part in candidate.parts)
                 and type(mode) is int and 0 <= mode <= 0o7777,
                 f"{description} retention mode differs")
        result[relative] = mode
    return result


def _corpus_tree_sha256(corpus: Any, root: Path, label: str, retention_modes: dict[str, int]) -> str:
    """Use the v3 producer's exact retained-mode reconstruction helper."""

    return corpus.tree_sha256(root, label, retention_modes=retention_modes)


def _elf_has_dt_relr(path: Path, description: str) -> bool:
    """Read just enough ELF64 little-endian metadata to bind DT_RELR bytes.

    Corpus execution already used readelf.  Receipt validation must not run
    host tools, so a case that *requires* RELR is checked directly against the
    retained executable instead of trusting its report field.  Optional RELR
    stays optional: its presence must not invalidate a case whose manifest did
    not require it.
    """

    path = _physical_file(path, description)
    try:
        data = path.read_bytes()
    except OSError as error:
        raise LoaderCorpusEvidenceError(f"cannot read {description}") from error
    _require(len(data) >= 64 and data[:4] == b"\x7fELF" and data[4:6] == b"\x02\x01",
             f"{description} is not a little-endian ELF64 file")
    program_offset = int.from_bytes(data[32:40], "little")
    program_size = int.from_bytes(data[54:56], "little")
    program_count = int.from_bytes(data[56:58], "little")
    _require(program_size >= 56 and program_count > 0
             and program_offset <= len(data)
             and program_count <= (len(data) - program_offset) // program_size,
             f"{description} has unsafe program headers")
    for index in range(program_count):
        offset = program_offset + index * program_size
        header = data[offset:offset + program_size]
        if int.from_bytes(header[:4], "little") != 2:  # PT_DYNAMIC
            continue
        dynamic_offset = int.from_bytes(header[8:16], "little")
        dynamic_size = int.from_bytes(header[32:40], "little")
        _require(dynamic_offset <= len(data) and dynamic_size <= len(data) - dynamic_offset
                 and dynamic_size % 16 == 0,
                 f"{description} has unsafe dynamic entries")
        for entry_offset in range(dynamic_offset, dynamic_offset + dynamic_size, 16):
            tag = int.from_bytes(data[entry_offset:entry_offset + 8], "little", signed=True)
            if tag == 0:  # DT_NULL
                break
            if tag == 36:  # DT_RELR
                return True
    return False


def _corpus_root_entries(root: Path) -> dict[str, dict[str, object]]:
    """Enumerate the bounded private-root entry types admitted by corpus v3."""

    root = _physical_directory(root, "package-corpus retained root")
    entries: dict[str, dict[str, object]] = {}
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            children = sorted(directory.iterdir(), key=lambda child: child.name, reverse=True)
        except OSError as error:
            raise LoaderCorpusEvidenceError(f"package-corpus retained root is unreadable: {directory}") from error
        for child in children:
            relative = child.relative_to(root).as_posix()
            try:
                metadata = child.lstat()
            except OSError as error:
                raise LoaderCorpusEvidenceError(f"package-corpus retained root entry is unreadable: {relative}") from error
            mode = metadata.st_mode
            item: dict[str, object] = {"mode": stat.S_IMODE(mode)}
            if stat.S_ISREG(mode):
                item.update(kind="file", sha256=_sha256(child), size=metadata.st_size)
            elif stat.S_ISDIR(mode):
                item["kind"] = "directory"
                pending.append(child)
            elif stat.S_ISLNK(mode):
                item.update(kind="symlink", target=os.readlink(child))
            elif stat.S_ISCHR(mode) and relative == "dev/null":
                item.update(kind="character", major=os.major(metadata.st_rdev), minor=os.minor(metadata.st_rdev))
            else:
                _fail(f"package-corpus retained root has an unsupported entry: {relative}")
            _require(relative not in entries, "package-corpus retained root has duplicate entries")
            entries[relative] = item
    return entries


def _corpus_add_parent_directories(expected: dict[str, str], relative: str) -> None:
    current = PurePosixPath(relative).parent
    while current.parts:
        parent = current.as_posix()
        prior = expected.setdefault(parent, "directory")
        _require(prior == "directory", "package-corpus root entry conflicts with a parent directory")
        current = current.parent


def _corpus_expected_entry(expected: dict[str, str], relative: str, kind: str) -> None:
    prior = expected.setdefault(relative, kind)
    _require(prior == kind, f"package-corpus root entry type conflicts: {relative}")
    _corpus_add_parent_directories(expected, relative)


def _corpus_original_mode(entry: Mapping[str, object], relative: str, kind: str,
                          retention_modes: Mapping[str, int], description: str) -> int:
    """Recover a file or directory's producer-time mode without mutating it."""

    observed = entry.get("mode")
    _require(type(observed) is int, f"{description} mode is absent")
    original = retention_modes.get(relative)
    if original is None:
        return observed
    added = 0o444 if kind == "file" else 0o555 if kind == "directory" else 0
    _require(added and observed != original and observed == original | added,
             f"{description} retained mode differs")
    return original


def _corpus_retained_mode(entry: Mapping[str, object], expected: int, relative: str,
                          kind: str, retention_modes: Mapping[str, int], description: str) -> None:
    _require(_corpus_original_mode(entry, relative, kind, retention_modes, description) == expected,
             f"{description} mode differs")


# ``stateful`` is the frozen Tier B--D coverage marker, rather than a claim
# that a workload leaves its private root unchanged.  The finite plans below
# bind the exact frozen argv that create, remove, or rewrite private paths.
# Their absence is the retained-root immutability contract for all other cases.
_CORPUS_MUTATION_PLANS: dict[str, tuple[tuple[str, ...], dict[str, object]]] = {
    "tier-a-mkdir": (("mkdir", "-p", "/tmp/crabc-corpus-mkdir"),
                      {"created": {"tmp/crabc-corpus-mkdir": ("directory", None)}}),
    "tier-a-cp": (("cp", "/tmp/crabc-corpus-input", "/tmp/crabc-corpus-output"),
                   {"created": {"tmp/crabc-corpus-output": ("file", b"input\n")}}),
    "tier-a-mv": (("mv", "/tmp/crabc-corpus-input", "/tmp/crabc-corpus-moved"),
                   {"removed": {"tmp/crabc-corpus-input"},
                    "created": {"tmp/crabc-corpus-moved": ("file", b"input\n")}}),
    "tier-a-rm": (("rm", "/tmp/crabc-corpus-input"),
                   {"removed": {"tmp/crabc-corpus-input"}}),
    "tier-b-sed-in-place": (("sed", "-i", "s/old/new/", "/tmp/crabc-corpus-sed-state"),
                              {"replaced": {"tmp/crabc-corpus-sed-state": b"new\n"}}),
    "tier-b-tar-create": (("tar", "-cf", "/tmp/crabc-corpus-tar-output.tar", "-C", "/tmp", "crabc-corpus-tar-input"),
                            {"created": {"tmp/crabc-corpus-tar-output.tar": ("file", None)}}),
    "tier-b-sqlite-state": (("sqlite3", "/tmp/crabc-corpus-sqlite.db", "CREATE TABLE items (id INTEGER PRIMARY KEY, value TEXT); INSERT INTO items(value) VALUES ('state'); SELECT id || ':' || value FROM items;"),
                            {"created": {"tmp/crabc-corpus-sqlite.db": ("file", None)}}),
    "tier-d-git-init": (("git", "init", "--quiet", "/tmp/crabc-corpus-git-repository"),
                         {"subtrees": {"tmp/crabc-corpus-git-repository"}}),
    "tier-d-python-file-state": (("python3", "-c", r"from pathlib import Path; p = Path('/tmp/crabc-corpus-python-state'); p.write_text('python payload\n'); print(p.read_text(), end='')"),
                                 {"replaced": {"tmp/crabc-corpus-python-state": b"python payload\n"}}),
}


def _corpus_mutation_plan(case: Any) -> Mapping[str, object] | None:
    item = _CORPUS_MUTATION_PLANS.get(case.id)
    if item is None:
        return None
    argv, plan = item
    _require(tuple(case.argv) == argv, f"package-corpus {case.id} frozen mutation argv differs")
    return plan


def _corpus_entry_bytes(entry: Mapping[str, object], contents: bytes, description: str) -> None:
    _require(entry.get("kind") == "file"
             and entry.get("sha256") == hashlib.sha256(contents).hexdigest()
             and entry.get("size") == len(contents),
             f"{description} bytes differ")


def _validate_corpus_base_fixtures(root: Path, record: Mapping[str, Any], manifest: Any,
                                    retention_modes: Mapping[str, int], description: str) -> None:
    """Recheck retained base bytes, ownership, device identity, and normalized modes."""

    base = _keys(record["base_fixtures"], {"image_files", "directories", "device"}, description + " base fixture")
    _require(base == _base_fixtures(manifest), f"{description} base fixture differs")
    for virtual, expected in manifest.base_image_files.items():
        relative = virtual.lstrip("/")
        candidate = _physical_file(root / relative, f"{description} base image {virtual}")
        metadata = candidate.lstat()
        observed = {"sha256": _sha256(candidate), "mode": stat.S_IMODE(metadata.st_mode),
                    "uid": metadata.st_uid, "gid": metadata.st_gid}
        _require(observed["sha256"] == expected["sha256"]
                 and observed["uid"] == expected["uid"] and observed["gid"] == expected["gid"],
                 f"{description} base image {virtual} differs")
        _corpus_retained_mode(observed, expected["mode"], relative, "file", retention_modes,
                              f"{description} base image {virtual}")
    for virtual, expected in base["directories"].items():
        relative = virtual.lstrip("/")
        candidate = _without_symlink_components(root / relative, f"{description} base directory {virtual}")
        metadata = candidate.lstat()
        _require(stat.S_ISDIR(metadata.st_mode), f"{description} base directory {virtual} differs")
        _corpus_retained_mode({"mode": stat.S_IMODE(metadata.st_mode)}, expected["mode"], relative,
                              "directory", retention_modes, f"{description} base directory {virtual}")
    device = base["device"]
    candidate = _without_symlink_components(root / device["path"].lstrip("/"), description + " base device")
    metadata = candidate.lstat()
    _require(stat.S_ISCHR(metadata.st_mode)
             and stat.S_IMODE(metadata.st_mode) == device["mode"]
             and os.major(metadata.st_rdev) == device["major"] and os.minor(metadata.st_rdev) == device["minor"],
             f"{description} base device differs")


def _validate_corpus_root_layout(payload: Path, root: Path, expected_case: Any, arm: str,
                                  manifest: Any, corpus: Any, payload_retention_modes: Mapping[str, int],
                                  retention_modes: Mapping[str, int]) -> None:
    """Bind every immutable root entry and the finite argv-derived mutations."""

    payload_entries = _corpus_root_entries(payload)
    root_entries = _corpus_root_entries(root)
    expected: dict[str, str] = {}
    for relative, entry in payload_entries.items():
        _corpus_expected_entry(expected, relative, str(entry["kind"]))
        observed = root_entries.get(relative)
        _require(observed is not None and observed.get("kind") == entry.get("kind"),
                 f"package-corpus {expected_case.id} {arm} package payload entry {relative} differs")
        for field in ("sha256", "size", "target"):
            if field in entry:
                _require(observed.get(field) == entry[field],
                         f"package-corpus {expected_case.id} {arm} package payload entry {relative} differs")
        if entry["kind"] in {"file", "directory"}:
            payload_mode = _corpus_original_mode(entry, relative, str(entry["kind"]), payload_retention_modes,
                                                  f"package-corpus payload entry {relative}")
            root_mode = _corpus_original_mode(observed, relative, str(entry["kind"]), retention_modes,
                                               f"package-corpus {expected_case.id} {arm} package payload entry {relative}")
            _require(root_mode == payload_mode,
                     f"package-corpus {expected_case.id} {arm} package payload entry {relative} mode differs")

    for virtual in manifest.base_image_files:
        _corpus_expected_entry(expected, virtual.lstrip("/"), "file")
    for virtual in ("/tmp", "/root", "/dev"):
        _corpus_expected_entry(expected, virtual.lstrip("/"), "directory")
    _corpus_expected_entry(expected, "dev/null", "character")
    for relative in (corpus.CANONICAL_INTERPRETER.lstrip("/"), corpus.CANONICAL_LIBC.lstrip("/")):
        _corpus_expected_entry(expected, relative, "file")

    plan = _corpus_mutation_plan(expected_case)
    removed = set(plan.get("removed", set())) if plan is not None else set()
    replaced = dict(plan.get("replaced", {})) if plan is not None else {}
    for setup in expected_case.setup:
        relative = setup.path.lstrip("/")
        if relative in removed:
            _require(relative not in root_entries,
                     f"package-corpus {expected_case.id} {arm} removed setup {setup.path} remains")
            continue
        _corpus_expected_entry(expected, relative, "file")
        observed = root_entries.get(relative)
        _require(observed is not None and observed.get("kind") == "file",
                 f"package-corpus {expected_case.id} {arm} setup {setup.path} differs")
        contents = replaced.get(relative, setup.contents)
        _corpus_entry_bytes(observed, contents, f"package-corpus {expected_case.id} {arm} setup {setup.path}")
        if relative not in replaced:
            _corpus_retained_mode(observed, 0o600, relative, "file", retention_modes,
                                  f"package-corpus {expected_case.id} {arm} setup {setup.path}")

    created = dict(plan.get("created", {})) if plan is not None else {}
    for relative, (kind, contents) in created.items():
        _corpus_expected_entry(expected, relative, kind)
        observed = root_entries.get(relative)
        _require(observed is not None and observed.get("kind") == kind,
                 f"package-corpus {expected_case.id} {arm} created output {relative} differs")
        if contents is not None:
            _corpus_entry_bytes(observed, contents,
                                f"package-corpus {expected_case.id} {arm} created output {relative}")

    cwd = expected_case.cwd.lstrip("/")
    _corpus_expected_entry(expected, cwd, "directory")
    observed_cwd = root_entries.get(cwd)
    _require(observed_cwd is not None and observed_cwd.get("kind") == "directory",
             f"package-corpus {expected_case.id} {arm} cwd differs")
    subtrees = set(plan.get("subtrees", set())) if plan is not None else set()
    for subtree in subtrees:
        _corpus_expected_entry(expected, subtree, "directory")
        observed = root_entries.get(subtree)
        _require(observed is not None and observed.get("kind") == "directory",
                 f"package-corpus {expected_case.id} {arm} mutable subtree {subtree} differs")

    permitted_mutable = tuple(subtree + "/" for subtree in subtrees)
    for relative, entry in root_entries.items():
        kind = entry["kind"]
        if relative in expected:
            _require(kind == expected[relative], f"package-corpus {expected_case.id} {arm} root entry type differs: {relative}")
            continue
        _require(kind in {"file", "directory", "symlink"}
                 and any(relative.startswith(prefix) for prefix in permitted_mutable),
                 f"package-corpus {expected_case.id} {arm} has an unsealed root entry: {relative}")


def _validate_corpus_root(root: Path, value: object, expected_case: Any, arm: str, product: Path,

                          product_files: Mapping[str, str], oracle: Mapping[str, Any], source_mount: str,
                          checkout: Path, corpus: Any, payload: Path, manifest: Any,
                          payload_retention_modes: Mapping[str, int]) -> None:
    record = _keys(value, {"base_fixtures", "runtime", "execution_tree_before_sha256", "execution_tree_after_sha256", "retention_modes", "executable"},
                   f"package-corpus {expected_case.id} {arm} root")
    before = _digest(record["execution_tree_before_sha256"], "package-corpus execution tree before")
    after = _digest(record["execution_tree_after_sha256"], "package-corpus execution tree after")
    retention_modes = _retention_modes(record["retention_modes"], f"package-corpus {expected_case.id} {arm}")
    _validate_corpus_base_fixtures(root, record, manifest, retention_modes,
                                   f"package-corpus {expected_case.id} {arm}")
    _validate_corpus_root_layout(payload, root, expected_case, arm, manifest, corpus,
                                  payload_retention_modes, retention_modes)
    try:
        current = _corpus_tree_sha256(corpus, root, f"package-corpus {expected_case.id} {arm} retained root", retention_modes)
    except Exception as error:
        raise LoaderCorpusEvidenceError(f"package-corpus {expected_case.id} {arm} retained root is unreadable: {error}") from error
    _require(current == after, f"package-corpus {expected_case.id} {arm} retained root differs from its after seal")
    if _corpus_mutation_plan(expected_case) is None:
        _require(before == after,
                 f"package-corpus {expected_case.id} {arm} immutable root changed during execution")
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
             and type(executable["dt_relr"]) is bool,
             f"package-corpus {expected_case.id} {arm} executable contract differs")
    _digest(executable["sha256"], f"package-corpus {expected_case.id} {arm} executable")
    executable_path = _resolved_file_within(root, expected_case.path.lstrip("/"),
                                             f"package-corpus {expected_case.id} {arm} executable")
    _require(_hash_within(root, expected_case.path.lstrip("/"), f"package-corpus {expected_case.id} {arm} executable") == executable["sha256"],
             f"package-corpus {expected_case.id} {arm} retained executable differs")
    if expected_case.requires_dt_relr:
        _require(executable["dt_relr"] is True and _elf_has_dt_relr(executable_path,
                                                                      f"package-corpus {expected_case.id} {arm} executable"),
                 f"package-corpus {expected_case.id} {arm} executable lacks required DT_RELR")


def _validate_corpus_payload(root: Path, record: object, manifest: Any, corpus: Any) -> None:
    payload = _keys(record, {"path", "sha256", "retention_modes", "package_library_dirs", "elf_closure"}, "package-corpus application payload")
    # The path is translated by the caller; keeping this shape check local
    # avoids a second generic artifact framework.
    _digest(payload["sha256"], "package-corpus application payload")
    _retention_modes(payload["retention_modes"], "package-corpus application payload")
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


def validate_corpus_report(report_path: Path, dynamic_product: Path, *, expected_oracle: Mapping[str, object],
                           root: Path = ROOT) -> dict[str, object]:
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
    oracle = _corpus_oracle(_keys(report["oracle"], {"before", "after"}, "package-corpus oracle")["before"], expected_oracle)
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
    payload_retention_modes = _retention_modes(report["application_payload"]["retention_modes"],
                                               "package-corpus application payload")
    try:
        _require(_corpus_tree_sha256(corpus, payload_path, "package-corpus retained application payload",
                                     payload_retention_modes) == report["application_payload"]["sha256"],
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
                                  source_mount, checkout, corpus, payload_path, manifest, payload_retention_modes)
    _require(observed_ids == set(expected_cases), "package-corpus outcome roster differs from frozen manifest")
    return {"component": "package-corpus", "case_count": len(expected_cases),
            "product_manifest": str(manifest_path), "product_manifest_sha256": manifest_sha256,
            "family_complete": False}


def validate_reports(loader_report: Path, corpus_report: Path, dynamic_product: Path, *, expected_oracle: Mapping[str, object],
                     root: Path = ROOT) -> dict[str, dict[str, object]]:
    """Validate both component reports against the exact same supplied product."""

    loader = validate_loader_report(loader_report, dynamic_product, expected_oracle=expected_oracle, root=root)
    corpus = validate_corpus_report(corpus_report, dynamic_product, expected_oracle=expected_oracle, root=root)
    _require(loader["product_manifest_sha256"] == corpus["product_manifest_sha256"],
             "loader and corpus receipts used different product manifests")
    return {"loader": loader, "corpus": corpus}
