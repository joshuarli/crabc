#!/usr/bin/env python3
"""Validate non-promoting installed pthread/TLS family evidence.

The prerequisite POSIX family matrix already validates the sealed static and
three dynamic products, their pinned musl identity, and its own raw workload
artifacts. This coordinator consumes that immutable receipt. It never builds a
product, reinterprets a private source-only leaf as installed behavior, or
promotes a family.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
from pathlib import Path
import sys
import tomllib
from typing import Any

import owned_posix_family_execution as family

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "crabc.x86_64-owned-pthread-family/v1"
ROSTER_SCHEMA = "crabc.x86_64-owned-pthread-family-roster/v1"
ROSTER_PATH = ROOT / "compat/x86_64/pthread-family.toml"
CAPABILITIES = (
    "process.atfork-exit-hooks",
    "thread.pthread-c11",
    "time.posix-timer-thread-notify",
)
NONPROMOTING_FLAGS = {
    "component_complete": True,
    "family_completion": False,
    "promotion_ready": False,
    "public_support": False,
}

# A parsed TOML list alone must not make omitted modes look intentionally out
# of scope.  This fixed map is the admission contract for the finite roster.
# The prose associated with a row may grow more precise, but a row cannot shed
# a behavior, change capability ownership, or quietly drop a product cell.
EXPECTED_ROWS = {
    "c11-tls-synchronization-composition": ("thread.pthread-c11", "composition", "all", None),
    "atfork-static-fork": ("process.atfork-exit-hooks", "matrix", "static", "static-fork"),
    "atfork-dynamic-fork": ("process.atfork-exit-hooks", "matrix", "dynamic", "fork"),
    "atfork-registry": ("process.atfork-exit-hooks", "dynamic-qualification", "dynamic", "atfork-registry"),
    "pthread-exit-tls": ("thread.pthread-c11", "dynamic-qualification", "dynamic", "pthread-exit"),
    "pthread-signal": ("thread.pthread-c11", "matrix", "all", "pthread-signal"),
    "timer-thread-notify-tls-dtv": ("time.posix-timer-thread-notify", "matrix", "all", "posix-timers"),
    "pthread-join-cancel": ("thread.pthread-c11", "dynamic-qualification", "dynamic", "pthread-join-cancel"),
    "pthread-cond-cancel": ("thread.pthread-c11", "dynamic-qualification", "dynamic", "pthread-cond-cancel"),
    "pthread-cond-timed": ("thread.pthread-c11", "dynamic-qualification", "dynamic", "pthread-cond-timed"),
    "pthread-mutex": ("thread.pthread-c11", "dynamic-qualification", "dynamic", "pthread-mutex"),
    "pthread-spin": ("thread.pthread-c11", "dynamic-qualification", "dynamic", "pthread-spin"),
    "pthread-getattr": ("thread.pthread-c11", "dynamic-qualification", "dynamic", "pthread-getattr"),
    "pthread-scheduling": ("thread.pthread-c11", "dynamic-qualification", "dynamic", "pthread-scheduling"),
    "pthread-cpuclock": ("thread.pthread-c11", "dynamic-qualification", "dynamic", "pthread-cpuclock"),
}


class PthreadFamilyError(RuntimeError):
    """The exact installed behavior roster or its receipt is incomplete."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PthreadFamilyError(message)


def stable_hash(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def _load(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as source:
            value = tomllib.load(source)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise PthreadFamilyError(f"cannot read pthread family roster: {error}") from error
    require(isinstance(value, dict), "pthread family roster must be a table")
    return value


def _modes(value: object, description: str) -> tuple[str, ...]:
    require(isinstance(value, list) and value and all(isinstance(mode, str) and mode for mode in value),
            f"{description} modes must be a nonempty string list")
    result = tuple(value)
    require(len(result) == len(set(result)), f"{description} modes duplicate a cell")
    return result


def load_roster(path: Path = ROSTER_PATH) -> dict[str, Any]:
    roster = _load(path)
    require(set(roster) == {"schema", "family", "capabilities", "cross_cut", "mode_sets", "required"},
            "pthread family roster fields differ")
    require(roster["schema"] == ROSTER_SCHEMA and roster["family"] == "libc.pthread-tls",
            "pthread family roster identity differs")
    require(tuple(roster["capabilities"]) == CAPABILITIES, "pthread family capabilities differ")
    require(roster["cross_cut"] == "tls-dtv", "pthread family cross-cut differs")
    mode_sets = roster["mode_sets"]
    require(isinstance(mode_sets, dict) and set(mode_sets) == {"static", "dynamic", "all"},
            "pthread family mode sets differ")
    static = _modes(mode_sets["static"], "static")
    dynamic = _modes(mode_sets["dynamic"], "dynamic")
    all_modes = _modes(mode_sets["all"], "all")
    require(len(static) == 6 and len(dynamic) == 12 and all_modes == static + dynamic,
            "pthread family exact 6+12 mode roster differs")
    required = roster["required"]
    require(isinstance(required, list) and required, "pthread family has no required behaviors")
    identifiers: set[str] = set()
    known_modes = set(all_modes)
    for entry in required:
        require(isinstance(entry, dict), "pthread family behavior is not a table")
        kind = entry.get("kind")
        expected = {"id", "capability", "kind", "modes", "behavior"}
        if kind == "matrix":
            expected.add("workload")
        elif kind == "dynamic-qualification":
            expected.add("case")
        elif kind == "composition":
            expected.update(("runner", "source"))
        else:
            raise PthreadFamilyError("pthread family behavior kind differs")
        require(set(entry) == expected, "pthread family behavior fields differ")
        identifier = entry["id"]
        require(isinstance(identifier, str) and identifier and identifier not in identifiers,
                "pthread family behavior identity differs")
        identifiers.add(identifier)
        require(entry["capability"] in CAPABILITIES and isinstance(entry["behavior"], str) and entry["behavior"],
                "pthread family behavior contract differs")
        modes = _modes(entry["modes"], identifier)
        require(set(modes).issubset(known_modes), "pthread family behavior names an unknown mode")
        if kind == "matrix":
            require(isinstance(entry["workload"], str) and entry["workload"], "matrix workload differs")
        elif kind == "dynamic-qualification":
            require(isinstance(entry["case"], str) and entry["case"], "dynamic qualification case differs")
            require(set(modes).issubset(set(dynamic)), "dynamic qualification cannot claim a static cell")
        else:
            for name in ("runner", "source"):
                candidate = entry[name]
                require(isinstance(candidate, str) and candidate and not Path(candidate).is_absolute()
                        and ".." not in Path(candidate).parts, "composition source escapes checkout")
    require(identifiers == set(EXPECTED_ROWS), "pthread family behavior roster differs")
    mode_lookup = {"static": static, "dynamic": dynamic, "all": all_modes}
    for entry in required:
        expected_capability, expected_kind, expected_modes, expected_target = EXPECTED_ROWS[entry["id"]]
        require((entry["capability"], entry["kind"], tuple(entry["modes"]))
                == (expected_capability, expected_kind, mode_lookup[expected_modes]),
                "pthread family required behavior/mode contract differs")
        if expected_kind == "matrix":
            require(entry["workload"] == expected_target, "pthread family required workload contract differs")
        elif expected_kind == "dynamic-qualification":
            require(entry["case"] == expected_target, "pthread family required qualification case differs")
    composition = next(entry for entry in required if entry["kind"] == "composition")
    require(composition["runner"] == "compat/x86_64/run_owned_pthread_family_composition.sh"
            and composition["source"] == "compat/x86_64/owned_pthread_family_composition.c",
            "pthread family composition implementation differs")
    return {"capabilities": list(CAPABILITIES), "cross_cut": "tls-dtv", "mode_sets": {"static": list(static), "dynamic": list(dynamic), "all": list(all_modes)}, "required": required}


def _relative_physical(root: Path, value: object, name: str) -> Path:
    require(isinstance(value, str) and value and not Path(value).is_absolute() and ".." not in Path(value).parts,
            f"{name} must be a checkout-relative path")
    path = family.physical(root, root / value)
    require(path.is_relative_to(root / ".work"), f"{name} must be under checkout .work")
    return path


def validate_request(root: Path, request: object) -> Path:
    require(isinstance(request, dict) and set(request) == {"schema", "family_execution"},
            "pthread family request fields differ")
    require(request["schema"] == SCHEMA, "pthread family request schema differs")
    path = _relative_physical(root, request["family_execution"], "family execution")
    require(path.name == "execution.json", "pthread family requires a POSIX execution.json receipt")
    family.validate_receipt(root, path)
    return path


def matrix_request(root: Path, matrix: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, dict[str, Path]]]:
    """Recover the sealed POSIX request, including its execution source mount.

    A native run records `/workspace` in its invocation. Host-side replay must
    retain that mount spelling when it verifies the same invocation instead of
    rebuilding it from the host checkout path.
    """

    require(isinstance(matrix, dict) and isinstance(matrix.get("request"), dict)
            and isinstance(matrix.get("inputs"), dict), "pthread family POSIX matrix inputs differ")
    identity = _current_identity(root, matrix["request"], "POSIX execution request")
    request_path = _relative_physical(root, identity["path"], "POSIX execution request")
    request = family.read(request_path)
    inputs, products = family.input_products(root, request)
    require(family.same_json(inputs, matrix["inputs"]), "pthread family POSIX matrix inputs changed")
    return request, inputs, products


def require_complete_cells(required: dict[str, Any], cells: dict[str, Any]) -> None:
    modes = _modes(required.get("modes"), str(required.get("id", "required behavior")))
    require(set(cells) == set(modes), f"{required.get('id', 'required behavior')} missing required mode")
    require(all(isinstance(value, dict) for value in cells.values()), "pthread family cell evidence differs")


def _matrix_pair(product: str) -> str:
    pairs = {dynamic: static for static, dynamic in family.PAIRS.items()}
    require(product in pairs, "pthread family names an unknown dynamic product")
    return pairs[product]


def _mode_parts(cell: str) -> tuple[str, str, str | None]:
    product, separator, mode = cell.partition(":")
    require(separator and product and mode, "pthread family mode spelling differs")
    if mode in ("static-et-exec", "static-pie"):
        require(product in family.PAIRS, "pthread family static product differs")
        return product, mode, None
    for prefix in ("dynamic-pie-", "dynamic-non-pie-"):
        if mode.startswith(prefix):
            entry = mode.removeprefix(prefix)
            require(entry in ("kernel", "direct"), "pthread family dynamic entry differs")
            return _matrix_pair(product), mode, product
    raise PthreadFamilyError("pthread family mode kind differs")


def matrix_cells(matrix: dict[str, Any], required: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Bind one exact matrix workload receipt to each named product/mode cell.

    The POSIX matrix has already parsed its retained raw observations.  This
    bridge keeps the immutable run receipt, leaf snapshot, and observation
    digest reachable without copying or normalizing any raw stream.
    """

    require(isinstance(matrix, dict) and isinstance(matrix.get("runs"), dict),
            "pthread family matrix runs differ")
    workload = required.get("workload")
    require(isinstance(workload, str) and workload, "pthread family matrix workload differs")
    result: dict[str, dict[str, Any]] = {}
    for cell in _modes(required.get("modes"), str(required.get("id", "matrix behavior"))):
        pair, mode, dynamic_product = _mode_parts(cell)
        runs = matrix["runs"].get(pair)
        require(isinstance(runs, dict) and workload in runs, f"missing matrix workload: {pair}/{workload}")
        run = runs[workload]
        require(isinstance(run, dict) and run.get("workload") == workload, "matrix workload identity differs")
        if dynamic_product is None:
            require(run.get("static_product") == pair, "matrix static product binding differs")
        else:
            require(run.get("dynamic_product") == dynamic_product, "matrix dynamic product binding differs")
        receipt = run.get("receipt")
        require(isinstance(receipt, dict) and set(receipt) == {"path", "sha256", "size"},
                "matrix run receipt identity differs")
        require(isinstance(run.get("leaf"), str) and isinstance(run.get("artifacts"), dict)
                and isinstance(run.get("observations"), dict), "matrix retained artifacts differ")
        result[cell] = {
            "kind": "posix-family-matrix",
            "product_pair": pair,
            "dynamic_product": dynamic_product,
            "mode": mode,
            "run_receipt": receipt,
            "leaf": run["leaf"],
            "artifact_snapshot_sha256": stable_hash(run["artifacts"]),
            "observation_sha256": stable_hash(run["observations"]),
        }
    require_complete_cells(required, result)
    return result


def dynamic_qualification_cells(root: Path, qualification: dict[str, Any],
                                required: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Bind each dynamic mode to its validated per-product case receipt.

    ``owned_dynamic_qualification.validate_receipt`` is the semantic judge for
    the runner, its source, raw log and product.  This function only keeps the
    exact case identities reachable from the pthread family receipt and rejects
    a caller-supplied path that the prerequisite did not seal.
    """

    require(isinstance(qualification, dict), "dynamic qualification differs")
    work = _relative_physical(root, qualification.get("work"), "dynamic qualification work")
    case_hashes = qualification.get("cases")
    require(isinstance(case_hashes, dict), "dynamic qualification case map differs")
    case = required.get("case")
    require(isinstance(case, str) and case, "pthread family dynamic case differs")
    result: dict[str, dict[str, Any]] = {}
    for cell in _modes(required.get("modes"), str(required.get("id", "dynamic behavior"))):
        pair, mode, product = _mode_parts(cell)
        require(product is not None, "dynamic qualification behavior names a static cell")
        path = family.physical(root, work / "qualification-cases" / product / (case + ".json"))
        relative = path.relative_to(root).as_posix()
        require(relative in case_hashes and isinstance(case_hashes[relative], str)
                and family.digest(path) == case_hashes[relative],
                f"missing dynamic qualification case: {product}/{case}")
        record = family.read(path)
        require(isinstance(record, dict) and record.get("product") == product and record.get("case") == case,
                "dynamic qualification case identity differs")
        result[cell] = {
            "kind": "dynamic-qualification",
            "product_pair": pair,
            "dynamic_product": product,
            "mode": mode,
            "case_receipt": family.file_identity(root, path),
            "case_sha256": case_hashes[relative],
        }
    require_complete_cells(required, result)
    return result


def _current_identity(root: Path, value: object, description: str) -> dict[str, Any]:
    require(isinstance(value, dict) and set(value) == {"path", "sha256", "size"},
            f"{description} identity differs")
    path = _relative_physical(root, value["path"], description)
    actual = family.file_identity(root, path)
    require(family.same_json(actual, value), f"{description} changed")
    return actual


def _checkout_identity(root: Path, value: object, description: str) -> dict[str, Any]:
    """Seal one source-controlled regular file outside mutable evidence work."""

    require(isinstance(value, dict) and set(value) == {"path", "sha256", "size"},
            f"{description} identity differs")
    relative = value["path"]
    require(isinstance(relative, str) and relative and not Path(relative).is_absolute()
            and ".." not in Path(relative).parts, f"{description} path differs")
    path = root / relative
    require(path.is_file() and not path.is_symlink() and path.resolve() == path,
            f"{description} must be a physical checkout file")
    actual = {"path": relative, "sha256": family.digest(path), "size": path.stat().st_size}
    require(family.same_json(actual, value), f"{description} changed")
    return actual


def _product_identity(root: Path, value: object, expected: Path, description: str) -> None:
    require(isinstance(value, dict) and set(value) == {"path", "manifest"},
            f"{description} product fields differ")
    require(value["path"] == expected.relative_to(root).as_posix(), f"{description} product path differs")
    require(family.same_json(value["manifest"], family.file_identity(root, expected / "share/crabc/manifest.json")),
            f"{description} product manifest differs")


COMMAND_STEMS = (
    "compile", "oracle-link", "oracle", "static-link", "static-validate", "static-run",
    "static-pie-link", "static-pie-validate", "static-pie-run", "dynamic-pie-link",
    "dynamic-pie-validate", "dynamic-pie-kernel", "dynamic-pie-direct", "dynamic-non-pie-link",
    "dynamic-non-pie-validate", "dynamic-non-pie-kernel", "dynamic-non-pie-direct",
)
LINKS = {
    "static": ("static", "static", "static.crabc-link.json", "static.link.json", "static"),
    "static-pie": ("static-pie", "static-pie", "static-pie.crabc-link.json", "static-pie.link.json", "static"),
    "dynamic-pie": ("pie", "dynamic-pie", "dynamic-pie.crabc-link.json", "dynamic-pie.link.json", "dynamic"),
    "dynamic-non-pie": ("non-pie", "dynamic-non-pie", "dynamic-non-pie.crabc-link.json", "dynamic-non-pie.link.json", "dynamic"),
}
RAW_STEMS = (
    "oracle", "static-run", "static-pie-run", "dynamic-pie-kernel", "dynamic-pie-direct",
    "dynamic-non-pie-kernel", "dynamic-non-pie-direct",
)
TOOL_ROLES = ("oracle", "static_driver", "dynamic_driver", "compiler", "linker")


def _leaf_identity(root: Path, leaf: Path, value: object, expected_name: str, description: str) -> dict[str, Any]:
    identity = _current_identity(root, value, description)
    require(identity["path"] == (leaf / expected_name).relative_to(root).as_posix(),
            f"{description} path differs")
    return identity


def _mounted(root: Path, path: Path, source_mount: str) -> str:
    return family.mounted(root, path, source_mount)


def _tool_roster(root: Path, value: object, static_product: Path, dynamic_product: Path,
                 source_mount: str) -> dict[str, dict[str, Any]]:
    """Accept only the sealed native compiler/linker roster, never host probes."""

    require(source_mount == "/workspace", "composition retained source mount differs")
    require(isinstance(value, dict) and set(value) == set(TOOL_ROLES), "composition tool roster differs")
    result: dict[str, dict[str, Any]] = {}
    for role in TOOL_ROLES:
        item = value[role]
        require(isinstance(item, dict) and set(item) == {"path", "sha256", "size"},
                "composition tool identity differs")
        path, digest, size = item["path"], item["sha256"], item["size"]
        require(isinstance(path, str) and Path(path).is_absolute() and ".." not in Path(path).parts
                and isinstance(digest, str) and len(digest) == 64
                and all(character in "0123456789abcdef" for character in digest)
                and type(size) is int and size >= 0, "composition tool identity is malformed")
        result[role] = item
    for role, path in (("static_driver", static_product / "bin/crabc-cc"),
                       ("dynamic_driver", dynamic_product / "bin/crabc-cc-dynamic")):
        expected = family.file_identity(root, path)
        require(result[role] == {"path": _mounted(root, path, source_mount),
                                 "sha256": expected["sha256"], "size": expected["size"]},
                "composition installed driver seal differs")
    require(result["oracle"]["path"] == "/usr/local/bin/crabc-x86_64-musl-gcc",
            "composition oracle compiler tool differs")
    require(Path(result["compiler"]["path"]).name == "gcc"
            and Path(result["linker"]["path"]).name == "ld.lld",
            "composition compiler/linker tool differs")
    return result


def composition_command(root: Path, products: dict[str, Path], roster_entry: dict[str, Any],
                        source_mount: str) -> list[str]:
    return ["bash", str(Path(source_mount) / roster_entry["runner"]), "--static-sysroot",
            _mounted(root, products["static"], source_mount), _mounted(root, products["dynamic"], source_mount)]


def _expected_commands(root: Path, leaf: Path, static_product: Path, dynamic_product: Path,
                       roster_entry: dict[str, Any], source_mount: str) -> dict[str, list[str]]:
    leaf_mount = _mounted(root, leaf, source_mount)
    static_mount = _mounted(root, static_product, source_mount)
    dynamic_mount = _mounted(root, dynamic_product, source_mount)
    source = str(Path(source_mount) / roster_entry["source"])
    executable = lambda name: f"{leaf_mount}/{name}"
    return {
        "compile": [f"{dynamic_mount}/bin/crabc-cc-dynamic", "--dynamic-pie", "-std=c11", "-D_GNU_SOURCE",
                    "-fno-builtin", "-c", source, "-o", executable("workload.o")],
        "oracle-link": ["/usr/local/bin/crabc-x86_64-musl-gcc", "-std=c11", "-D_GNU_SOURCE", "-pthread",
                        executable("workload.o"), "-o", executable("oracle")],
        "oracle": ["env", "-i", executable("oracle")],
        "static-link": [f"{static_mount}/bin/crabc-cc", "-static", "--link-receipt",
                        "static.crabc-link.json", executable("workload.o"), "-o", executable("static")],
        "static-validate": ["python3", "-B", "-", source_mount, static_mount, executable("workload.o"),
                            executable("static"), executable("static.crabc-link.json"), "static"],
        "static-run": ["env", "-i", executable("static")],
        "static-pie-link": [f"{static_mount}/bin/crabc-cc", "-static-pie", "--link-receipt",
                            "static-pie.crabc-link.json", executable("workload.o"), "-o",
                            executable("static-pie")],
        "static-pie-validate": ["python3", "-B", "-", source_mount, static_mount, executable("workload.o"),
                                executable("static-pie"), executable("static-pie.crabc-link.json"), "static-pie"],
        "static-pie-run": ["env", "-i", executable("static-pie")],
        "dynamic-pie-link": [f"{dynamic_mount}/bin/crabc-cc-dynamic", "--dynamic-pie", "-std=c11",
                             executable("workload.o"), "-o", executable("dynamic-pie")],
        "dynamic-pie-validate": ["python3", "-B", "-", source_mount, dynamic_mount, executable("workload.o"),
                                 executable("dynamic-pie"), executable("dynamic-pie.crabc-link.json"), "pie"],
        "dynamic-pie-kernel": ["chroot", executable("dynamic-root"), "/consumer-pie"],
        "dynamic-pie-direct": ["chroot", executable("dynamic-root"), "/lib/ld-crabc-x86_64.so.1", "/consumer-pie"],
        "dynamic-non-pie-link": [f"{dynamic_mount}/bin/crabc-cc-dynamic", "--dynamic-non-pie", "-std=c11",
                                 executable("workload.o"), "-o", executable("dynamic-non-pie")],
        "dynamic-non-pie-validate": ["python3", "-B", "-", source_mount, dynamic_mount, executable("workload.o"),
                                     executable("dynamic-non-pie"), executable("dynamic-non-pie.crabc-link.json"), "non-pie"],
        "dynamic-non-pie-kernel": ["chroot", executable("dynamic-root"), "/consumer-non-pie"],
        "dynamic-non-pie-direct": ["chroot", executable("dynamic-root"), "/lib/ld-crabc-x86_64.so.1", "/consumer-non-pie"],
    }


def _validate_oracle(report: object, oracle: object, tools: dict[str, dict[str, Any]]) -> None:
    require(isinstance(report, dict) and set(report) == {"compiler", "runtime", "pin"},
            "composition oracle identity differs")
    require(isinstance(oracle, dict) and isinstance(oracle.get("files"), dict),
            "POSIX matrix oracle identity differs")
    expected = {
        "compiler": ("/usr/local/bin/crabc-x86_64-musl-gcc", oracle.get("compiler_wrapper_sha256")),
        "runtime": ("/opt/musl-1.2.6/lib/libc.so", oracle.get("runtime_sha256")),
        "pin": ("/opt/musl-1.2.6/.crabc-oracle", oracle["files"].get("source_manifest")),
    }
    for name, (path, digest) in expected.items():
        item = report[name]
        require(isinstance(item, dict) and set(item) == {"path", "sha256", "size"}
                and item.get("path") == path and item.get("sha256") == digest
                and isinstance(digest, str) and len(digest) == 64 and type(item.get("size")) is int,
                "composition pinned oracle identity differs")
    require(report["compiler"] == tools["oracle"], "composition oracle compiler tool seal differs")


def _validate_link(root: Path, leaf: Path, report: object, static_product: Path, dynamic_product: Path,
                   source_mount: str, tools: dict[str, dict[str, Any]]) -> None:
    import owned_posix_product_evidence as products

    require(isinstance(report, dict) and set(report) == set(LINKS), "composition link roster differs")
    workload = leaf / "workload.o"
    for name, (linkage, executable_name, receipt_name, validated_name, product_kind) in LINKS.items():
        entry = report[name]
        require(isinstance(entry, dict) and set(entry) == {"linkage", "executable", "receipt", "validated"}
                and entry["linkage"] == linkage, "composition link record differs")
        executable = _leaf_identity(root, leaf, entry["executable"], executable_name,
                                    f"composition {name} executable")
        receipt = _leaf_identity(root, leaf, entry["receipt"], receipt_name,
                                 f"composition {name} receipt")
        validated = _leaf_identity(root, leaf, entry["validated"], validated_name,
                                  f"composition {name} validation")
        product = static_product if product_kind == "static" else dynamic_product
        observed = products.validate_retained_link(
            root, source_mount, product, workload, root / executable["path"], root / receipt["path"], linkage,
            {"path": tools["linker"]["path"], "sha256": tools["linker"]["sha256"]},
        )
        try:
            retained = json.loads((root / validated["path"]).read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise PthreadFamilyError(f"composition {name} validation is not JSON") from error
        expected = dict(observed)
        expected["product"] = _mounted(root, product, source_mount)
        require(family.same_json(retained, expected), "composition sealed link validation differs")


def _validate_execution_root(root: Path, leaf: Path, dynamic_product: Path) -> dict[str, Any]:
    """Reconstruct the exact copied runtime tree consumed by both dynamic entries."""

    import owned_crypt_runtime_evidence as copies

    execution_root = leaf / "dynamic-root"
    consumers = {
        "pie": (leaf / "dynamic-pie", execution_root / "consumer-pie"),
        "non-pie": (leaf / "dynamic-non-pie", execution_root / "consumer-non-pie"),
    }
    try:
        product, manifest, files, aliases = copies.dynamic_product(dynamic_product)
        copies.assert_execution_tree(execution_root, files, aliases,
                                     tuple(execution for _, execution in consumers.values()))
        copies.copied_file(manifest, execution_root / "share/crabc/manifest.json",
                           "composition execution manifest")
        for name in files:
            copies.copied_file(product / name, execution_root / name,
                               f"composition execution payload {name}")
        for name, target in aliases.items():
            copies.copied_alias(product / name, execution_root / name, target,
                                f"composition execution alias {name}")
        for linkage, (source, execution) in consumers.items():
            copies.copied_file(source, execution, f"composition {linkage} execution consumer")
    except copies.CryptRuntimeEvidenceError as error:
        raise PthreadFamilyError(str(error)) from error
    return {
        "root": execution_root.relative_to(root).as_posix(),
        "product_manifest": family.file_identity(root, manifest),
        "consumers": {linkage: {
            "source": family.file_identity(root, source),
            "execution": family.file_identity(root, execution),
        } for linkage, (source, execution) in consumers.items()},
        "snapshot_sha256": stable_hash(family.snapshot(execution_root)),
    }


def _composition_report(root: Path, leaf: Path, static_product: Path, dynamic_product: Path,
                        roster_entry: dict[str, Any], source_mount: str, oracle: object) -> dict[str, Any]:
    report_path = family.physical(root, leaf / "composition.json")
    report = family.read(report_path)
    require(isinstance(report, dict) and set(report) == {
        "schema", "source", "workload", "products", "tools", "oracle", "commands", "links", "raw"
    }, "pthread family composition report fields differ")
    require(report["schema"] == "crabc.x86_64-owned-pthread-family-composition/v1",
            "pthread family composition report schema differs")
    source = _checkout_identity(root, report["source"], "composition source")
    require(source["path"] == roster_entry["source"], "composition source selection differs")
    workload = _current_identity(root, report["workload"], "composition workload")
    require(workload["path"] == (leaf / "workload.o").relative_to(root).as_posix(),
            "composition workload path differs")
    products = report["products"]
    require(isinstance(products, dict) and set(products) == {"static", "dynamic"},
            "composition product roster differs")
    _product_identity(root, products["static"], static_product, "composition static")
    _product_identity(root, products["dynamic"], dynamic_product, "composition dynamic")
    tools = report["tools"]
    require(isinstance(tools, dict) and set(tools) == {"before", "after"}, "composition tool seals differ")
    before_identity = _leaf_identity(root, leaf, tools["before"], "tools-before.json", "composition tools before")
    after_identity = _leaf_identity(root, leaf, tools["after"], "tools-after.json", "composition tools after")
    try:
        before_value = json.loads((root / before_identity["path"]).read_text(encoding="utf-8"))
        after_value = json.loads((root / after_identity["path"]).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PthreadFamilyError("composition tool seal is not JSON") from error
    before = _tool_roster(root, before_value, static_product, dynamic_product, source_mount)
    after = _tool_roster(root, after_value, static_product, dynamic_product, source_mount)
    require(family.same_json(before, after), "composition compiler/linker tools changed during execution")
    _validate_oracle(report["oracle"], oracle, before)
    commands = report["commands"]
    require(isinstance(commands, dict) and set(commands) == set(COMMAND_STEMS),
            "composition command roster differs")
    expected_commands = _expected_commands(root, leaf, static_product, dynamic_product, roster_entry, source_mount)
    for name, streams in commands.items():
        require(isinstance(streams, dict) and set(streams) == {"argv", "stdout", "stderr", "status"},
                "composition command record differs")
        argv = _leaf_identity(root, leaf, streams["argv"], f"{name}.argv.json", f"composition {name} argv")
        try:
            argv_value = json.loads((root / argv["path"]).read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise PthreadFamilyError(f"composition {name} argv is not JSON") from error
        require(argv_value == expected_commands[name],
                "composition command argv differs")
        for stream in ("stdout", "stderr", "status"):
            _leaf_identity(root, leaf, streams[stream], f"{name}.{stream}", f"composition {name} {stream}")
        require((root / streams["status"]["path"]).read_bytes() == b"0\n",
                "composition command status differs")
    _validate_link(root, leaf, report["links"], static_product, dynamic_product, source_mount, before)
    execution = _validate_execution_root(root, leaf, dynamic_product)
    raw = report["raw"]
    require(isinstance(raw, dict) and set(raw) == set(RAW_STEMS), "composition raw roster differs")
    for name, streams in raw.items():
        require(isinstance(streams, dict) and set(streams) == {"stdout", "stderr", "status"},
                "composition raw stream roster differs")
        stdout = _leaf_identity(root, leaf, streams["stdout"], f"{name}.stdout", f"composition {name} stdout")
        stderr = _leaf_identity(root, leaf, streams["stderr"], f"{name}.stderr", f"composition {name} stderr")
        status = _leaf_identity(root, leaf, streams["status"], f"{name}.status", f"composition {name} status")
        require((root / stdout["path"]).read_bytes() == b"pthread-family-composition-ok\n"
                and (root / stderr["path"]).read_bytes() == b""
                and (root / status["path"]).read_bytes() == b"0\n",
                "composition raw result differs")
    return {"report": family.file_identity(root, report_path), "leaf": leaf.relative_to(root).as_posix(),
            "workload": workload, "execution": execution,
            "artifact_snapshot_sha256": stable_hash(family.snapshot(leaf))}


def composition_cells(root: Path, work: Path, matrix: dict[str, Any],
                      roster_entry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Read three no-rebuild composition replays and bind their 6+12 cells."""

    request, inputs, products = matrix_request(root, matrix)
    source_mount = request["source_mount"]
    reports: dict[str, dict[str, Any]] = {}
    for pair in family.PAIRS:
        step = family.physical(root, work / "runs" / pair)
        command = composition_command(root, products[pair], roster_entry, source_mount)
        environment = family.case_environment(root, step, source_mount)
        family.check_step(root, step, command, environment, source_mount=source_mount)
        leaf = family.leaf_directory(root, step, source_mount)
        reports[pair] = _composition_report(root, leaf, products[pair]["static"], products[pair]["dynamic"],
                                             roster_entry, source_mount, inputs["oracle"])
        require(set((step / "tmp").iterdir()) == {leaf}, "composition step has undeclared scratch")
    require(len({record["workload"]["sha256"] for record in reports.values()}) == 1,
            "composition workload object differs across product pairs")
    cells: dict[str, dict[str, Any]] = {}
    for cell in _modes(roster_entry["modes"], roster_entry["id"]):
        pair, mode, dynamic_product = _mode_parts(cell)
        cells[cell] = {"kind": "pthread-family-composition", "product_pair": pair,
                       "dynamic_product": dynamic_product, "mode": mode, **reports[pair]}
    require_complete_cells(roster_entry, cells)
    return cells


def _dynamic_qualification(root: Path, matrix: dict[str, Any]) -> dict[str, Any]:
    import owned_dynamic_qualification as dynamic
    inputs = matrix.get("inputs")
    require(isinstance(inputs, dict) and isinstance(inputs.get("dynamic_qualification"), dict),
            "pthread family matrix dynamic qualification input differs")
    path = _relative_physical(root, inputs["dynamic_qualification"].get("path"), "dynamic qualification receipt")
    return dynamic.validate_receipt(path)


def collect(root: Path, work: Path) -> dict[str, Any]:
    work = family.physical(root, work)
    request = family.read(work / "request.json")
    matrix_path = validate_request(root, request)
    matrix = family.validate_receipt(root, matrix_path)
    require(matrix.get("schema") == family.SCHEMA and matrix.get("status") == "workload-matrix-verified"
            and matrix.get("family") == "libc.posix-runtime", "pthread family requires the POSIX product matrix")
    require(all(matrix.get(name) is False for name in ("native_aggregate_complete", "family_completion", "public_support")),
            "pthread family matrix promotion boundary differs")
    matrix_request(root, matrix)
    roster = load_roster()
    dynamic = _dynamic_qualification(root, matrix)
    coverage: dict[str, Any] = {}
    for required in roster["required"]:
        if required["kind"] == "matrix":
            cells = matrix_cells(matrix, required)
        elif required["kind"] == "dynamic-qualification":
            cells = dynamic_qualification_cells(root, dynamic, required)
        else:
            cells = composition_cells(root, work, matrix, required)
        require_complete_cells(required, cells)
        coverage[required["id"]] = {"capability": required["capability"], "behavior": required["behavior"],
                                      "cells": cells}
    inputs = {
        "family_execution": family.file_identity(root, matrix_path),
        "execution_request": matrix["request"],
        "source": matrix["inputs"]["source"],
        "oracle": matrix["inputs"]["oracle"],
        "dynamic_qualification": matrix["inputs"]["dynamic_qualification"],
    }
    return {
        "schema": SCHEMA, "status": "installed-behavior-component-verified", "family": "libc.pthread-tls",
        "inputs": inputs, "roster": family.file_identity(root, ROSTER_PATH), "coverage": coverage,
        **NONPROMOTING_FLAGS,
    }


def _fresh_work(root: Path, value: Path) -> Path:
    if value.is_absolute():
        path = value
    else:
        require(".." not in value.parts, "pthread family output must not traverse parents")
        path = root / value
    require(path.parent.is_dir() and path.parent.resolve() == path.parent and path.parent.is_relative_to(root / ".work"),
            "pthread family output parent must be physical checkout .work")
    require(not path.exists(), "pthread family output must be fresh")
    return path


def execute(root: Path, family_execution: Path, output: Path, jobs: int) -> Path:
    receipt = family.physical(root, family_execution)
    request = {"schema": SCHEMA, "family_execution": receipt.relative_to(root).as_posix()}
    matrix_path = validate_request(root, request)
    matrix = family.validate_receipt(root, matrix_path)
    roster = load_roster()
    composition = next(entry for entry in roster["required"] if entry["kind"] == "composition")
    work = _fresh_work(root, output)
    require(type(jobs) is int and 1 <= jobs <= len(family.PAIRS), "pthread family jobs must be in [1, 3]")
    matrix_request_value, _, products = matrix_request(root, matrix)
    source_mount = matrix_request_value["source_mount"]
    work.mkdir(parents=True)
    family.static_products.write_new(work / "request.json", request)
    errors: list[BaseException] = []

    def run_pair(pair: str) -> None:
        step = work / "runs" / pair
        command = composition_command(root, products[pair], composition, source_mount)
        try:
            family.run_step(root, step, command, family.case_environment(root, step, source_mount))
        finally:
            if step.exists():
                family.static_products.make_retained_evidence_readable(step)

    with ThreadPoolExecutor(max_workers=jobs, thread_name_prefix="pthread-family") as executor:
        pending = {executor.submit(run_pair, pair): pair for pair in family.PAIRS}
        for future in as_completed(pending):
            try:
                future.result()
            except BaseException as error:
                errors.append(error)
    if errors:
        raise PthreadFamilyError(f"pthread family composition failed: {errors[0]}")
    record = collect(root, work)
    path = work / "receipt.json"
    family.static_products.write_new(path, record)
    family.static_products.make_retained_evidence_readable(work)
    return path


def validate_receipt(root: Path, path: Path) -> dict[str, Any]:
    path = family.physical(root, path)
    require(path.name == "receipt.json", "pthread family receipt must be named receipt.json")
    observed = collect(root, path.parent)
    require(family.same_json(family.read(path), observed), "pthread family receipt changed")
    return observed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run")
    run.add_argument("--family-execution", type=Path, required=True)
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--jobs", type=int, default=3)
    validate = commands.add_parser("validate")
    validate.add_argument("receipt", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "run":
            print(execute(ROOT, args.family_execution, args.output, args.jobs))
        else:
            validate_receipt(ROOT, args.receipt)
            print("pthread/TLS installed behavior receipt valid; family and platform gates remain independent")
    except (PthreadFamilyError, OSError, ValueError) as error:
        parser.exit(1, f"pthread family: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
