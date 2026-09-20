#!/usr/bin/env python3
"""Replay the non-promoting installed text/math/locale/stdio component set.

The coordinator admits only immutable component evidence for the current
three-pair POSIX product matrix. It validates the matrix and pthread boundary,
asks each behavior owner's public reader to reconstruct its retained evidence,
and checks each component against the exact static/dynamic pair. Bounded
locale, numeric, and stdio receipts are required corroboration only; only their
separately declared complete behavior components can credit the affected
capabilities. This module neither produces a product nor selects parity rows,
completes a family, or promotes native x86 support.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import importlib
import json
from pathlib import Path
import stat
import tomllib
from typing import Any, Callable, Mapping

import owned_posix_family_execution as family
import owned_pthread_family as pthread


ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "crabc.x86_64-owned-text-math-locale-stdio-family/v1"
ROSTER_SCHEMA = "crabc.x86_64-owned-text-math-locale-stdio-family-roster/v1"
ROSTER_PATH = ROOT / "compat/x86_64/text-math-locale-stdio-family.toml"
FAMILY = "libc.text-math-locale-stdio"
PAIRS = tuple(family.PAIRS)
PAIR_MODES = (
    "static-et-exec", "static-pie",
    "dynamic-pie-kernel", "dynamic-pie-direct",
    "dynamic-non-pie-kernel", "dynamic-non-pie-direct",
)
STATIC_MODES = tuple(f"{pair}:{mode}" for pair in PAIRS for mode in PAIR_MODES[:2])
DYNAMIC_MODES = tuple(f"{pair}:{mode}" for pair in PAIRS for mode in PAIR_MODES[2:])
ALL_MODES = STATIC_MODES + DYNAMIC_MODES
CAPABILITIES = (
    "numeric.parse-float-locale",
    "math.elementary-long-double",
    "math.elementary-fenv-sensitive",
    "math.special",
    "math.complex",
    "locale.core",
    "text.wide-multibyte",
    "text.iconv",
    "pattern.regex",
    "pattern.wordexp",
    "stdio.path-stream",
    "stdio.fopen64-alias",
    "stdio.stream-io",
    "stdio.position-buffering",
    "stdio.format-scan",
    "time.clock-calendar",
)
TEXT_LOCALE_NUMERIC_ROWS = (
    "numeric.parse-float-locale/float-parse",
    "locale.core/ctype-locators",
    "locale.core/narrow-ctype-collation",
    "locale.core/object-wide",
    "locale.core/alias-contract",
    "locale.core/strfmon",
    "text.wide-multibyte/locale-object-wide",
    "text.wide-multibyte/multibyte",
    "text.wide-multibyte/wide-character",
    "text.wide-multibyte/wide-conversion",
    "text.iconv/utf16-32-iconv",
)
STDIO_ENGINE_ROWS = (
    "stdio.file-backends",
    "stdio.process-streams",
    "stdio.wide-stream",
    "stdio.wide-format",
    "stdio.file-extensions",
    "stdio.printf-float",
    "stdio.scanf",
)
STDIO_COMPONENT_CELLS = (
    "dynamic-pie-kernel", "dynamic-pie-direct",
    "dynamic-non-pie-kernel", "dynamic-non-pie-direct",
    "static", "static-pie",
)
STDIO_ENGINE_CELLS = (
    "static", "static-pie",
    "dynamic-pie-kernel", "dynamic-pie-direct",
    "dynamic-non-pie-kernel", "dynamic-non-pie-direct",
)
CALENDAR_ROWS = (
    "calendar-posix-tz-format",
    "calendar-tzif-specification",
    "calendar-strptime",
    "calendar-getdate-global",
    "calendar-clock-adjustment-safe",
)
TEXT_COMPONENT_MODES = (
    "static-run", "static-pie-run",
    "dynamic-pie-kernel", "dynamic-pie-direct",
    "dynamic-non-pie-kernel", "dynamic-non-pie-direct",
)
TEXT_TO_FAMILY_MODE = dict(zip(TEXT_COMPONENT_MODES, PAIR_MODES, strict=True))


class FamilyError(RuntimeError):
    """A declared immutable component input is incomplete or mismatched."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise FamilyError(message)


def same(left: object, right: object) -> bool:
    return json.dumps(left, sort_keys=True, separators=(",", ":"), allow_nan=False) == json.dumps(
        right, sort_keys=True, separators=(",", ":"), allow_nan=False
    )


@dataclass(frozen=True)
class ComponentSpec:
    """One public behavior reader, its required rows, and credited coverage."""

    reader: str
    scope: tuple[str, ...]
    credits: tuple[str, ...]
    rows: tuple[str, ...] = ()
    request_kind: str = "pairs"


COMPONENTS = {
    "locale": ComponentSpec(
        "compat/x86_64/owned_locale_component_receipt.py",
        ("locale.core", "text.wide-multibyte", "text.iconv"), (),
    ),
    "numeric": ComponentSpec(
        "compat/x86_64/owned_numeric_calendar_component_receipt.py",
        ("numeric.parse-float-locale", "time.clock-calendar"), (),
    ),
    "text-locale-numeric": ComponentSpec(
        "compat/x86_64/owned_text_locale_numeric_component_receipt.py",
        ("numeric.parse-float-locale", "locale.core", "text.wide-multibyte", "text.iconv"),
        ("numeric.parse-float-locale", "locale.core", "text.wide-multibyte", "text.iconv"),
        TEXT_LOCALE_NUMERIC_ROWS, "aggregate",
    ),
    "math": ComponentSpec(
        "compat/x86_64/owned_math_fenv_all_entry_receipt.py",
        ("math.elementary-long-double", "math.elementary-fenv-sensitive", "math.special", "math.complex"),
        ("math.elementary-long-double", "math.elementary-fenv-sensitive", "math.special", "math.complex"),
    ),
    "wordexp": ComponentSpec(
        "compat/x86_64/owned_wordexp_evidence.py", ("pattern.wordexp",), ("pattern.wordexp",),
        request_kind="wordexp-pairs",
    ),
    "stdio": ComponentSpec(
        "compat/x86_64/owned_stdio_component_receipt.py",
        ("stdio.path-stream", "stdio.stream-io", "stdio.position-buffering", "stdio.format-scan", "stdio.fopen64-alias"),
        (), ("stdio.fopen64-alias",),
    ),
    "stdio-engine": ComponentSpec(
        "compat/x86_64/owned_stdio_file_engine_receipt.py",
        STDIO_ENGINE_ROWS,
        ("stdio.path-stream", "stdio.fopen64-alias", "stdio.stream-io", "stdio.position-buffering", "stdio.format-scan"),
        STDIO_ENGINE_ROWS,
    ),
    "regex": ComponentSpec(
        "compat/x86_64/owned_regex_component_receipt.py", ("pattern.regex",), ("pattern.regex",),
    ),
    "calendar": ComponentSpec(
        "compat/x86_64/owned_calendar_component_receipt.py", ("time.clock-calendar",), ("time.clock-calendar",),
        CALENDAR_ROWS,
    ),
}


@dataclass(frozen=True)
class ComponentRequest:
    """Declared retained component inputs, with no implicit report discovery."""

    reports: Mapping[str, Path]
    expected_inputs: Mapping[str, Path] | None = None
    receipt: Path | None = None
    evidence_roots: Mapping[str, Path] | None = None


@dataclass(frozen=True)
class ComponentEvidence:
    """A normalized replay result produced only after a public reader succeeds."""

    source: object
    products: Mapping[str, Path]
    modes: tuple[str, ...]
    scope: tuple[str, ...]
    rows: Mapping[str, object]


@dataclass(frozen=True)
class MatrixContext:
    """The already-validated POSIX matrix inputs made available to readers."""

    source: object
    inputs: Mapping[str, object]
    products: Mapping[str, Mapping[str, Path]]
    static_preparation: Path
    dynamic_qualification: Path


@dataclass(frozen=True)
class _DirectorySnapshot:
    description: str
    path: Path
    contents: dict[str, object]


@dataclass(frozen=True)
class _FileSnapshot:
    description: str
    path: Path
    identity: dict[str, object]


ComponentAdapter = Callable[[Path, ComponentRequest, MatrixContext], dict[str, ComponentEvidence]]


def _strict_json(path: Path, description: str) -> dict[str, Any]:
    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            if key in result:
                raise FamilyError(f"duplicate JSON key in {description}")
            result[key] = value
        return result

    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise FamilyError(f"cannot read {description}: {error}") from error
    require(isinstance(value, dict), f"{description} must be a JSON object")
    return value


def _aggregate_pair_evidence_roots(root: Path, receipt: Path) -> dict[str, Path]:
    """Resolve the finite raw roots that an aggregate reader must authenticate."""

    aggregate = _strict_json(receipt, "text-locale-numeric aggregate receipt")
    roots = aggregate.get("pair_evidence_roots")
    pairs = aggregate.get("pairs")
    require(isinstance(roots, Mapping) and set(roots) == set(PAIRS)
            and isinstance(pairs, Mapping) and set(pairs) == set(PAIRS),
            "text-locale-numeric aggregate pair-evidence roster differs")
    resolved: dict[str, Path] = {}
    for pair in PAIRS:
        root_value = roots[pair]
        require(isinstance(root_value, str), f"text-locale-numeric {pair} evidence root differs")
        evidence_root = _physical(
            root, root_value, f"text-locale-numeric {pair} evidence root", directory=True, below_work=True,
        )
        require(evidence_root != root / ".work", "aggregate evidence root cannot cover the whole .work tree")
        record = pairs[pair]
        require(isinstance(record, Mapping) and set(record) == {
            "report", "report_sha256", "execution_cells",
        } and isinstance(record.get("report"), str)
                and isinstance(record.get("report_sha256"), str)
                and len(record["report_sha256"]) == 64
                and all(character in "0123456789abcdef" for character in record["report_sha256"])
                and isinstance(record.get("execution_cells"), list)
                and tuple(record["execution_cells"]) == TEXT_COMPONENT_MODES,
                f"text-locale-numeric {pair} aggregate report record differs")
        report = _physical(root, record["report"], f"text-locale-numeric {pair} aggregate report", below_work=True)
        require(report.parent == evidence_root
                and hashlib.sha256(report.read_bytes()).hexdigest() == record["report_sha256"],
                f"text-locale-numeric {pair} aggregate report differs")
        resolved[pair] = evidence_root
    return resolved


def _physical(root: Path, value: Path | str, description: str, *, directory: bool = False,
              below_work: bool = False) -> Path:
    root = root.resolve(strict=True)
    candidate = Path(value)
    require(not candidate.is_absolute() and candidate.parts and ".." not in candidate.parts,
            f"{description} path escapes checkout")
    path = root / candidate
    current = root
    try:
        for part in candidate.parts:
            current /= part
            require(not current.is_symlink(), f"{description} path traverses a symbolic link")
        metadata = path.lstat()
    except OSError as error:
        raise FamilyError(f"{description} path is unreadable") from error
    expected = stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
    require(expected and not path.is_symlink(),
            f"{description} is not a physical {'directory' if directory else 'regular file'}")
    if below_work:
        require(path.is_relative_to(root / ".work"), f"{description} must stay below checkout .work")
    return path


def _reported_product(root: Path, value: object, description: str, *, source_mount: str = "/workspace") -> Path:
    require(isinstance(value, str) and value, f"{description} is missing")
    path = Path(value)
    if path.is_absolute():
        root = root.resolve(strict=True)
        # Component reports may retain either their source-container mount or
        # the exact checkout path. Only those two namespaces are projected
        # back to this checkout; every other absolute product path is refused.
        relative = None
        for mount in (Path(source_mount), root, Path("/workspace")):
            if path.is_relative_to(mount):
                relative = path.relative_to(mount)
                break
        if relative is None:
            raise FamilyError(f"{description} escapes checkout")
    else:
        relative = path
    return _physical(root, relative, description, directory=True, below_work=True)


def _identity(root: Path, path: Path) -> dict[str, object]:
    """Use the POSIX evidence identity only for retained .work files."""

    return family.file_identity(root, path)


def _source_file_identity(root: Path, path: Path) -> dict[str, object]:
    """Identify one tracked reader/roster input without widening into .work."""

    path = _physical(root, path.relative_to(root), "source input")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return {
        "path": path.relative_to(root).as_posix(),
        "sha256": digest,
        "size": path.stat().st_size,
        "mode": stat.S_IMODE(path.stat().st_mode),
    }


def _snapshot_file_identity(root: Path, path: Path) -> dict[str, object]:
    if path.is_relative_to(root / ".work"):
        return _identity(root, path)
    return _source_file_identity(root, path)


def _snapshot_identity(root: Path, path: Path) -> dict[str, object]:
    snapshot = family.snapshot(path)
    encoded = json.dumps(snapshot, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return {
        "path": path.relative_to(root).as_posix(),
        "entry_count": len(snapshot),
        "snapshot_sha256": hashlib.sha256(encoded).hexdigest(),
    }


def current_source_identity(root: Path) -> dict[str, object]:
    """Use the product owner's full current clean-source identity."""

    return family.static_products.source_identity(root)


def _roster_identity(root: Path, roster: Path) -> dict[str, object]:
    return _source_file_identity(root, _physical(root, roster.relative_to(root), "family roster"))


def _load_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as stream:
            value = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise FamilyError(f"cannot read text/math/locale/stdio family roster: {error}") from error
    require(isinstance(value, dict), "text/math/locale/stdio family roster must be a table")
    return value


def _string_tuple(value: object, description: str) -> tuple[str, ...]:
    require(isinstance(value, list) and all(isinstance(item, str) and item for item in value),
            f"{description} must be a string list")
    result = tuple(value)
    require(len(result) == len(set(result)), f"{description} duplicates a value")
    return result


def load_roster(path: Path = ROSTER_PATH) -> dict[str, Any]:
    roster = _load_toml(path)
    require(set(roster) == {"schema", "family", "capabilities", "mode_sets", "components"},
            "text/math/locale/stdio family roster fields differ")
    require(roster["schema"] == ROSTER_SCHEMA and roster["family"] == FAMILY,
            "text/math/locale/stdio family roster identity differs")
    require(_string_tuple(roster["capabilities"], "family capabilities") == CAPABILITIES,
            "text/math/locale/stdio family capabilities differ")
    modes = roster["mode_sets"]
    require(isinstance(modes, dict) and set(modes) == {"static", "dynamic", "all"},
            "text/math/locale/stdio family mode sets differ")
    require(_string_tuple(modes["static"], "static modes") == STATIC_MODES
            and _string_tuple(modes["dynamic"], "dynamic modes") == DYNAMIC_MODES
            and _string_tuple(modes["all"], "all modes") == ALL_MODES,
            "text/math/locale/stdio family exact 6+12 mode roster differs")
    components = roster["components"]
    require(isinstance(components, dict) and set(components) == set(COMPONENTS),
            "text/math/locale/stdio family component roster differs")
    credited: list[str] = []
    for name, specification in COMPONENTS.items():
        record = components[name]
        expected_fields = {"reader", "scope", "credits"} | ({"rows"} if specification.rows else set())
        require(isinstance(record, dict) and set(record) == expected_fields,
                f"{name} component roster fields differ")
        require(record["reader"] == specification.reader
                and _string_tuple(record["scope"], f"{name} component scope") == specification.scope
                and _string_tuple(record["credits"], f"{name} component credits") == specification.credits,
                f"{name} component contract differs")
        if specification.rows:
            require(_string_tuple(record["rows"], f"{name} component rows") == specification.rows,
                    f"{name} required behavior rows differ")
        credited.extend(specification.credits)
    require(set(credited) == set(CAPABILITIES) and len(credited) == len(set(credited)),
            "text/math/locale/stdio family capability ownership differs")
    return roster


def _request(root: Path, path: Path) -> tuple[dict[str, Any], Path, Path, dict[str, ComponentRequest]]:
    request_path = _physical(root, path, "family request", below_work=True)
    request = _strict_json(request_path, "family request")
    require(set(request) == {"schema", "family_execution", "pthread_family", "components"}
            and request["schema"] == SCHEMA, "family request fields differ")
    matrix = _physical(root, request["family_execution"], "family execution receipt", below_work=True)
    pthread_receipt = _physical(root, request["pthread_family"], "pthread family receipt", below_work=True)
    components = request["components"]
    require(isinstance(components, dict) and set(components) == set(COMPONENTS),
            "family request component roster differs")
    parsed: dict[str, ComponentRequest] = {}
    for name, specification in COMPONENTS.items():
        value = components[name]
        if specification.request_kind == "aggregate":
            require(isinstance(value, dict) and set(value) == {"receipt"},
                    f"{name} aggregate request fields differ")
            receipt = _physical(root, value["receipt"], f"{name} aggregate receipt", below_work=True)
            parsed[name] = ComponentRequest(
                reports={}, receipt=receipt, evidence_roots=_aggregate_pair_evidence_roots(root, receipt),
            )
            continue
        require(isinstance(value, dict) and set(value) == set(PAIRS), f"{name} product-pair roster differs")
        reports: dict[str, Path] = {}
        expected: dict[str, Path] | None = {} if specification.request_kind == "wordexp-pairs" else None
        for pair in PAIRS:
            pair_value = value[pair]
            if specification.request_kind == "wordexp-pairs":
                require(isinstance(pair_value, dict) and set(pair_value) == {"report", "expected_inputs"},
                        "wordexp product-pair request fields differ")
                reports[pair] = _physical(root, pair_value["report"], f"wordexp {pair} report", below_work=True)
                assert expected is not None
                expected[pair] = _physical(
                    root, pair_value["expected_inputs"], f"wordexp {pair} expected inputs", below_work=True,
                )
            else:
                reports[pair] = _physical(root, pair_value, f"{name} {pair} report", below_work=True)
        parsed[name] = ComponentRequest(reports=reports, expected_inputs=expected)
    return request, matrix, pthread_receipt, parsed


def _require_matrix(value: object) -> dict[str, Any]:
    require(isinstance(value, dict) and value.get("schema") == family.SCHEMA
            and value.get("status") == "workload-matrix-verified"
            and value.get("family") == "libc.posix-runtime", "family requires the POSIX product matrix")
    require(value.get("native_aggregate_complete") is False
            and value.get("family_completion") is False and value.get("public_support") is False,
            "POSIX matrix completion boundary differs")
    require(isinstance(value.get("request"), dict) and isinstance(value.get("inputs"), dict)
            and isinstance(value["inputs"].get("source"), dict), "POSIX matrix inputs differ")
    return value


def _product_pairs(root: Path, matrix: dict[str, Any]) -> tuple[dict[str, Any], dict[str, dict[str, Path]]]:
    # The matrix seals its producer request as a file identity, not inline
    # request fields. Authenticate that file before replaying its products.
    request_path = _input_receipt(root, matrix, "request")
    request = _strict_json(request_path, "POSIX matrix request")
    try:
        inputs, pairs = family.input_products(root, request)
    except (family.ExecutionError, OSError, ValueError) as error:
        raise FamilyError(f"POSIX product receipt rejected: {error}") from error
    require(same(inputs, matrix["inputs"]), "POSIX matrix product inputs differ")
    require(isinstance(pairs, dict) and tuple(pairs) == PAIRS, "POSIX matrix product-pair roster differs")
    checked: dict[str, dict[str, Path]] = {}
    for pair in PAIRS:
        entry = pairs[pair]
        require(isinstance(entry, dict) and set(entry) == {"static", "dynamic"},
                f"POSIX matrix {pair} product pair differs")
        checked[pair] = {
            kind: _reported_product(root, str(entry[kind]), f"POSIX matrix {pair} {kind} product", source_mount=str(root))
            for kind in ("static", "dynamic")
        }
    require(len({(values["static"], values["dynamic"]) for values in checked.values()}) == len(PAIRS),
            "POSIX matrix reuses a product pair")
    return inputs, checked


def _input_receipt(root: Path, inputs: Mapping[str, object], name: str) -> Path:
    record = inputs.get(name)
    require(isinstance(record, Mapping) and isinstance(record.get("path"), str),
            f"POSIX matrix {name} identity differs")
    path = _physical(root, record["path"], f"POSIX matrix {name}", below_work=True)
    require(same(_identity(root, path), record), f"POSIX matrix {name} receipt changed")
    return path


def _require_pthread(root: Path, receipt: Path, matrix_identity: dict[str, object], source: object) -> dict[str, Any]:
    try:
        result = pthread.validate_receipt(root, receipt)
    except (pthread.PthreadFamilyError, family.ExecutionError, OSError, ValueError) as error:
        raise FamilyError(f"pthread family receipt rejected: {error}") from error
    require(isinstance(result, dict) and result.get("schema") == pthread.SCHEMA
            and result.get("status") == "installed-behavior-component-verified"
            and result.get("family") == "libc.pthread-tls", "pthread family receipt contract differs")
    inputs = result.get("inputs")
    require(isinstance(inputs, dict) and same(inputs.get("family_execution"), matrix_identity)
            and same(inputs.get("source"), source), "pthread family source or POSIX matrix differs")
    require(result.get("family_completion") is False and result.get("promotion_ready") is False
            and result.get("public_support") is False, "pthread family receipt is promoting")
    return result


def _source_after_reader(root: Path) -> dict[str, object]:
    try:
        return current_source_identity(root)
    except (family.static_products.PreparationError, OSError, ValueError) as error:
        raise FamilyError(f"current source identity rejected: {error}") from error


def _normal_products(root: Path, value: object, description: str, *, source_mount: str = "/workspace") -> dict[str, Path]:
    require(isinstance(value, Mapping) and set(value) == {"static", "dynamic"},
            f"{description} product mapping differs")
    return {
        kind: _reported_product(root, value[kind], f"{description} {kind} product", source_mount=source_mount)
        for kind in ("static", "dynamic")
    }


def _report_adapter(module_name: str, schema: str, component: str) -> ComponentAdapter:
    def validate(root: Path, request: ComponentRequest, _context: MatrixContext) -> dict[str, ComponentEvidence]:
        try:
            module = importlib.import_module(module_name)
        except ImportError as error:
            raise FamilyError(f"{component} public reader is unavailable: {error}") from error
        results: dict[str, ComponentEvidence] = {}
        for pair in PAIRS:
            try:
                report = module.validate_report(root, request.reports[pair], require_static=True)
            except Exception as error:
                raise FamilyError(f"{component} {pair} public receipt rejected: {error}") from error
            require(isinstance(report, Mapping) and report.get("schema") == schema
                    and tuple(report.get("scope", ())) == COMPONENTS[component].scope
                    and report.get("execution_mode") == "full-six-mode"
                    and report.get("family_completion") is False and report.get("promotion_ready") is False
                    and report.get("public_support") is False,
                    f"{component} {pair} public receipt contract differs")
            source_mount = report.get("source_mount")
            require(isinstance(source_mount, str) and Path(source_mount).is_absolute(),
                    f"{component} {pair} source mount differs")
            results[pair] = ComponentEvidence(
                source=_source_after_reader(root),
                products=_normal_products(root, report.get("products"), component, source_mount=source_mount),
                modes=PAIR_MODES, scope=tuple(report["scope"]), rows={},
            )
        return results
    return validate


def _math_adapter(root: Path, request: ComponentRequest, context: MatrixContext) -> dict[str, ComponentEvidence]:
    try:
        module = importlib.import_module("owned_math_fenv_all_entry_receipt")
        result = module.collect(
            root,
            context.static_preparation.relative_to(root),
            context.dynamic_qualification.relative_to(root),
            {pair: request.reports[pair].relative_to(root) for pair in PAIRS},
        )
    except Exception as error:
        raise FamilyError(f"math public receipt rejected: {error}") from error
    require(isinstance(result, Mapping) and result.get("schema") == "crabc.x86_64-owned-math-fenv-all-entry-receipt/v1"
            and tuple(result.get("scope", ())) == COMPONENTS["math"].scope
            and same(result.get("inputs"), context.inputs)
            and result.get("cell_count") == len(PAIRS) * len(PAIR_MODES)
            and result.get("family_completion") is False and result.get("promotion_ready") is False
            and result.get("public_support") is False, "math public receipt contract differs")
    pair_records = result.get("pairs")
    require(isinstance(pair_records, Mapping) and set(pair_records) == set(PAIRS),
            "math public receipt pair roster differs")
    values: dict[str, ComponentEvidence] = {}
    for pair in PAIRS:
        record = pair_records[pair]
        require(isinstance(record, Mapping) and tuple(record.get("cells", ())) == (
            "static", "static-pie", "dynamic-pie-kernel", "dynamic-pie-direct",
            "dynamic-non-pie-kernel", "dynamic-non-pie-direct",
        ), f"math {pair} mode roster differs")
        values[pair] = ComponentEvidence(
            source=_source_after_reader(root), products=context.products[pair], modes=PAIR_MODES,
            scope=COMPONENTS["math"].scope, rows={},
        )
    return values


def _wordexp_adapter(root: Path, request: ComponentRequest, _context: MatrixContext) -> dict[str, ComponentEvidence]:
    try:
        module = importlib.import_module("owned_wordexp_evidence")
    except ImportError as error:
        raise FamilyError(f"wordexp public reader is unavailable: {error}") from error
    require(request.expected_inputs is not None, "wordexp expected-input roster is missing")
    result: dict[str, ComponentEvidence] = {}
    for pair in PAIRS:
        expected = _strict_json(request.expected_inputs[pair], f"wordexp {pair} expected inputs")
        try:
            report = module.validate_report(root, request.reports[pair], expected)
        except Exception as error:
            raise FamilyError(f"wordexp {pair} public receipt rejected: {error}") from error
        require(isinstance(report, Mapping) and report.get("schema") == "crabc.x86_64-owned-wordexp-products/v5"
                and report.get("status") == "component-verified-not-family-qualified"
                and report.get("links") is not None and report.get("cells") is not None,
                f"wordexp {pair} public receipt contract differs")
        inputs = report.get("inputs")
        require(isinstance(inputs, Mapping) and same(inputs.get("before"), inputs.get("after")),
                f"wordexp {pair} source/product seals differ")
        products = inputs["before"].get("products") if isinstance(inputs.get("before"), Mapping) else None
        require(isinstance(products, Mapping) and isinstance(products.get("static"), Mapping)
                and isinstance(products.get("dynamic"), Mapping), f"wordexp {pair} lacks a static/dynamic pair")
        source_mount = getattr(module, "SOURCE_MOUNT", "/workspace")
        converted: dict[str, Path] = {}
        for kind in ("static", "dynamic"):
            record = products[kind]
            require(isinstance(record, Mapping) and isinstance(record.get("root"), str),
                    f"wordexp {pair} {kind} product record differs")
            converted[kind] = _reported_product(
                root, record["root"], f"wordexp {pair} {kind} product", source_mount=source_mount,
            )
        result[pair] = ComponentEvidence(
            source=_source_after_reader(root), products=converted, modes=PAIR_MODES,
            scope=COMPONENTS["wordexp"].scope, rows={},
        )
    return result


def _stdio_adapter(root: Path, request: ComponentRequest, _context: MatrixContext) -> dict[str, ComponentEvidence]:
    try:
        module = importlib.import_module("owned_stdio_component_receipt")
    except ImportError as error:
        raise FamilyError(f"stdio public reader is unavailable: {error}") from error
    result: dict[str, ComponentEvidence] = {}
    for pair in PAIRS:
        try:
            report = module.validate_report(request.reports[pair], root, require_static=True)
        except Exception as error:
            raise FamilyError(f"stdio {pair} public receipt rejected: {error}") from error
        require(isinstance(report, Mapping) and report.get("schema") == "crabc.x86_64-owned-stdio-products/v3"
                and report.get("matrix") == "supplied-static" and report.get("cells") == len(PAIR_MODES)
                and tuple(report.get("scope", ())) == COMPONENTS["stdio"].scope
                and report.get("family_completion") is False and report.get("promotion_ready") is False
                and report.get("public_support") is False,
                f"stdio {pair} public receipt contract differs")
        rows = report.get("rows")
        require(isinstance(rows, Mapping) and tuple(rows) == COMPONENTS["stdio"].rows
                and isinstance(rows["stdio.fopen64-alias"], Mapping), "stdio required behavior rows differ")
        row = rows["stdio.fopen64-alias"]
        required = {
            "feature", "macro", "target", "pointer_equality", "object_import", "header_profiles", "runtime_cells",
        }
        require(set(row) == required and row["feature"] == "_LARGEFILE64_SOURCE=1"
                and row["macro"] == "fopen64" and row["target"] == "fopen"
                and row["pointer_equality"] is True and row["object_import"] == "fopen"
                and tuple(row["runtime_cells"]) == STDIO_COMPONENT_CELLS, "stdio fopen64 behavior row differs")
        result[pair] = ComponentEvidence(
            source=_source_after_reader(root),
            products=_normal_products(root, report.get("products"), "stdio", source_mount=str(root)),
            modes=PAIR_MODES, scope=tuple(report["scope"]), rows=rows,
        )
    return result


def _text_locale_numeric_adapter(root: Path, request: ComponentRequest, context: MatrixContext) -> dict[str, ComponentEvidence]:
    require(request.receipt is not None, "text-locale-numeric aggregate receipt is missing")
    try:
        module = importlib.import_module("owned_text_locale_numeric_component_receipt")
        report = module.validate(root, _strict_json(request.receipt, "text-locale-numeric aggregate receipt"))
    except Exception as error:
        raise FamilyError(f"text-locale-numeric public receipt rejected: {error}") from error
    require(isinstance(report, Mapping)
            and report.get("schema") == "crabc.x86_64-owned-text-locale-numeric-receipt/v1"
            and same(report.get("source"), context.source)
            and report.get("cell_count") == len(PAIRS) * len(TEXT_COMPONENT_MODES)
            and report.get("family_completion") is False and report.get("promotion_ready") is False
            and report.get("public_support") is False,
            "text-locale-numeric public receipt contract differs")
    # The aggregate owns an ordered row list and per-pair execution cells.
    # Normalize only after its public reader has reconstructed those records.
    raw_rows = report.get("rows")
    require(isinstance(raw_rows, list)
            and all(isinstance(row, dict) and isinstance(row.get("id"), str)
                    and isinstance(row.get("capability"), str) for row in raw_rows)
            and len(raw_rows) == len(TEXT_LOCALE_NUMERIC_ROWS),
            "text-locale-numeric required behavior rows differ")
    rows = {row["capability"] + "/" + row["id"]: row for row in raw_rows}
    require(tuple(rows) == TEXT_LOCALE_NUMERIC_ROWS, "text-locale-numeric required behavior rows differ")
    require(request.evidence_roots is not None and set(request.evidence_roots) == set(PAIRS),
            "text-locale-numeric aggregate evidence roots are missing")
    raw_roots = report.get("pair_evidence_roots")
    pair_records = report.get("pairs")
    require(isinstance(raw_roots, Mapping) and set(raw_roots) == set(PAIRS)
            and isinstance(pair_records, Mapping) and set(pair_records) == set(PAIRS),
            "text-locale-numeric aggregate pair-evidence roster differs")
    products = report.get("products")
    require(isinstance(products, Mapping) and set(products) == set(PAIRS),
            "text-locale-numeric aggregate product roster differs")
    result: dict[str, ComponentEvidence] = {}
    for pair in PAIRS:
        require(isinstance(raw_roots[pair], str)
                and _physical(root, raw_roots[pair], f"text-locale-numeric {pair} evidence root",
                              directory=True, below_work=True) == request.evidence_roots[pair],
                f"text-locale-numeric {pair} evidence root differs")
        pair_record = pair_records[pair]
        require(isinstance(pair_record, Mapping) and set(pair_record) == {
            "report", "report_sha256", "execution_cells",
        } and isinstance(pair_record.get("report"), str)
                and isinstance(pair_record.get("report_sha256"), str)
                and len(pair_record["report_sha256"]) == 64
                and all(character in "0123456789abcdef" for character in pair_record["report_sha256"])
                and isinstance(pair_record.get("execution_cells"), list)
                and tuple(pair_record["execution_cells"]) == TEXT_COMPONENT_MODES,
                f"text-locale-numeric {pair} aggregate report record differs")
        report_path = _physical(root, pair_record["report"], f"text-locale-numeric {pair} aggregate report",
                                below_work=True)
        require(report_path.parent == request.evidence_roots[pair]
                and hashlib.sha256(report_path.read_bytes()).hexdigest() == pair_record["report_sha256"],
                f"text-locale-numeric {pair} aggregate report differs")
        raw_cells = pair_record["execution_cells"]
        require(isinstance(raw_cells, list) and tuple(raw_cells) == TEXT_COMPONENT_MODES,
                f"text-locale-numeric {pair} mode roster differs")
        result[pair] = ComponentEvidence(
            source=report["source"], products=_normal_products(root, products[pair], f"text-locale-numeric {pair}"),
            modes=tuple(TEXT_TO_FAMILY_MODE[cell] for cell in raw_cells),
            scope=COMPONENTS["text-locale-numeric"].scope, rows=rows,
        )
    return result


def _stdio_engine_adapter(root: Path, request: ComponentRequest, _context: MatrixContext) -> dict[str, ComponentEvidence]:
    try:
        module = importlib.import_module("owned_stdio_file_engine_receipt")
    except ImportError as error:
        raise FamilyError(f"stdio-engine public reader is unavailable: {error}") from error
    result: dict[str, ComponentEvidence] = {}
    for pair in PAIRS:
        try:
            report = module.validate_report(request.reports[pair], root, require_static=True)
        except Exception as error:
            raise FamilyError(f"stdio-engine {pair} public receipt rejected: {error}") from error
        require(isinstance(report, Mapping)
                and report.get("schema") == "crabc.x86_64-owned-stdio-file-engine/v1"
                and report.get("matrix") == "supplied-static" and report.get("cells") == len(PAIR_MODES)
                and tuple(report.get("scope", ())) == STDIO_ENGINE_ROWS
                and report.get("family_completion") is False and report.get("promotion_ready") is False
                and report.get("public_support") is False,
                f"stdio-engine {pair} public receipt contract differs")
        rows = report.get("rows")
        require(isinstance(rows, Mapping) and set(rows) == set(STDIO_ENGINE_ROWS),
                "stdio-engine required behavior rows differ")
        cells = report.get("execution_cells")
        require(isinstance(cells, list) and tuple(cells) == STDIO_ENGINE_CELLS,
                f"stdio-engine {pair} mode roster differs")
        result[pair] = ComponentEvidence(
            source=_source_after_reader(root),
            products=_normal_products(root, report.get("products"), "stdio-engine", source_mount=str(root)),
            modes=PAIR_MODES, scope=tuple(report["scope"]), rows=rows,
        )
    return result


def _calendar_source_product_seals(root: Path, report_path: Path, report: Mapping[str, object]) -> None:
    """Bind the reader's two retained source/product snapshots directly."""

    seals = report.get("seals")
    require(isinstance(seals, Mapping) and set(seals) == {
        "source-product-before", "source-product-after", "tools-before", "tools-after",
    }, "calendar source/product seal roster differs")
    values: dict[str, dict[str, object]] = {}
    for name in seals:
        record = seals[name]
        require(isinstance(record, Mapping) and set(record) == {"path", "sha256", "size"}
                and isinstance(record.get("path"), str), f"calendar {name} identity differs")
        path = _physical(root, record["path"], f"calendar {name}", below_work=True)
        require(path.parent == report_path.parent and path.name == name + ".json"
                and same(_identity(root, path), record), f"calendar {name} receipt differs")
        values[name] = _strict_json(path, f"calendar {name}")
    require(same(values["source-product-before"], values["source-product-after"]),
            "calendar source/product seals differ")
    require(same(values["tools-before"], values["tools-after"]), "calendar tool seals differ")


def _calendar_adapter(root: Path, request: ComponentRequest, _context: MatrixContext) -> dict[str, ComponentEvidence]:
    try:
        module = importlib.import_module("owned_calendar_component_receipt")
    except ImportError as error:
        raise FamilyError(f"calendar public reader is unavailable: {error}") from error
    result: dict[str, ComponentEvidence] = {}
    for pair in PAIRS:
        try:
            report = module.validate_report(root, request.reports[pair], require_static=True)
        except Exception as error:
            raise FamilyError(f"calendar {pair} public receipt rejected: {error}") from error
        require(isinstance(report, Mapping) and report.get("schema") == "crabc.x86_64-owned-calendar-products/v1"
                and tuple(report.get("scope", ())) == COMPONENTS["calendar"].scope
                and report.get("family_completion") is False and report.get("promotion_ready") is False
                and report.get("public_support") is False,
                f"calendar {pair} public receipt contract differs")
        rows = report.get("rows")
        require(isinstance(rows, Mapping) and set(rows) == set(CALENDAR_ROWS),
                "calendar required behavior rows differ")
        _calendar_source_product_seals(root, request.reports[pair], report)
        products = report.get("products")
        require(isinstance(products, Mapping) and set(products) == {"static", "dynamic"}
                and all(isinstance(products[kind], str) for kind in ("static", "dynamic")),
                f"calendar {pair} product identity differs")
        cells = report.get("execution_cells")
        require(isinstance(cells, list) and tuple(cells) == PAIR_MODES,
                f"calendar {pair} mode roster differs")
        result[pair] = ComponentEvidence(
            source=_source_after_reader(root),
            products=_normal_products(root, products, f"calendar {pair}", source_mount=str(root)),
            modes=tuple(cells), scope=tuple(report["scope"]), rows=rows,
        )
    return result


def _reader_adapters() -> dict[str, ComponentAdapter]:
    """Expose only concrete public readers; a missing interface is rejected."""

    return {
        "locale": _report_adapter("owned_locale_component_receipt", "crabc.x86_64-owned-locale-products/v3", "locale"),
        "numeric": _report_adapter(
            "owned_numeric_calendar_component_receipt", "crabc.x86_64-owned-numeric-calendar-products/v2", "numeric",
        ),
        "text-locale-numeric": _text_locale_numeric_adapter,
        "math": _math_adapter,
        "wordexp": _wordexp_adapter,
        "stdio": _stdio_adapter,
        "stdio-engine": _stdio_engine_adapter,
        "regex": _report_adapter("owned_regex_component_receipt", "crabc.x86_64-owned-regex-products/v2", "regex"),
        "calendar": _calendar_adapter,
    }


def _snapshot_directories(root: Path, candidates: list[tuple[str, Path]]) -> tuple[_DirectorySnapshot, ...]:
    seen: set[Path] = set()
    snapshots: list[_DirectorySnapshot] = []
    work = root.resolve(strict=True) / ".work"
    for description, path in candidates:
        path = _physical(root, path.relative_to(root), description, directory=True, below_work=True)
        require(path != work, "declared input snapshot cannot cover the whole .work tree")
        if path not in seen:
            seen.add(path)
            snapshots.append(_DirectorySnapshot(description, path, family.snapshot(path)))
    return tuple(snapshots)


def _snapshot_files(root: Path, candidates: list[tuple[str, Path]]) -> tuple[_FileSnapshot, ...]:
    seen: set[Path] = set()
    snapshots: list[_FileSnapshot] = []
    for description, path in candidates:
        path = _physical(root, path.relative_to(root), description, below_work=path.is_relative_to(root / ".work"))
        if path not in seen:
            seen.add(path)
            snapshots.append(_FileSnapshot(description, path, _snapshot_file_identity(root, path)))
    return tuple(snapshots)


def _require_snapshots_current(root: Path, directories: tuple[_DirectorySnapshot, ...],
                               files: tuple[_FileSnapshot, ...], source: object) -> None:
    for snapshot in directories:
        require(same(family.snapshot(snapshot.path), snapshot.contents),
                f"declared input changed during collection: {snapshot.description}")
    for snapshot in files:
        require(same(_snapshot_file_identity(root, snapshot.path), snapshot.identity),
                f"declared input changed during collection: {snapshot.description}")
    require(same(current_source_identity(root), source), "current source changed during collection")


def _require_component(name: str, values: object, products: Mapping[str, Mapping[str, Path]], source: object) -> None:
    require(isinstance(values, dict) and set(values) == set(PAIRS), f"{name} public reader pair roster differs")
    specification = COMPONENTS[name]
    for pair in PAIRS:
        evidence = values[pair]
        require(isinstance(evidence, ComponentEvidence) and same(evidence.source, source)
                and tuple(evidence.scope) == specification.scope and tuple(evidence.modes) == PAIR_MODES,
                f"{name} {pair} source, scope, or mode roster differs")
        actual = evidence.products
        require(isinstance(actual, Mapping) and set(actual) == {"static", "dynamic"}
                and actual["static"] == products[pair]["static"] and actual["dynamic"] == products[pair]["dynamic"],
                f"{name} {pair} product pair differs")
        if specification.rows:
            require(isinstance(evidence.rows, Mapping) and set(evidence.rows) == set(specification.rows),
                    f"{name} required behavior rows differ")
        else:
            require(not evidence.rows, f"{name} has unexpected family behavior rows")


def _pair_record(root: Path, request: ComponentRequest, pair: str, evidence: ComponentEvidence) -> dict[str, Any]:
    source: dict[str, object]
    if request.receipt is not None:
        source = {"receipt": _identity(root, request.receipt)}
    else:
        source = {"report": _identity(root, request.reports[pair])}
    record: dict[str, Any] = {
        **source,
        "modes": list(evidence.modes),
        "products": {kind: _snapshot_identity(root, path) for kind, path in evidence.products.items()},
        "rows": dict(evidence.rows),
    }
    if request.evidence_roots is not None:
        record["evidence_root"] = _snapshot_identity(root, request.evidence_roots[pair])
    if request.expected_inputs is not None:
        record["expected_inputs"] = _identity(root, request.expected_inputs[pair])
    return record


def _input_snapshots(root: Path, request_path: Path, matrix_path: Path, pthread_path: Path,
                     context: MatrixContext, requests: Mapping[str, ComponentRequest]) -> tuple[
                         tuple[_DirectorySnapshot, ...], tuple[_FileSnapshot, ...]
                     ]:
    directory_inputs = [
        ("POSIX family evidence", matrix_path.parent),
        ("pthread family evidence", pthread_path.parent),
    ]
    for name, request in requests.items():
        if request.receipt is not None:
            directory_inputs.append((f"{name} aggregate evidence", request.receipt.parent))
            require(request.evidence_roots is not None and set(request.evidence_roots) == set(PAIRS),
                    f"{name} aggregate evidence roots are missing")
            directory_inputs.extend(
                (f"{name} {pair} aggregate pair evidence", request.evidence_roots[pair]) for pair in PAIRS
            )
        else:
            directory_inputs.extend(
                (f"{name} {pair} component evidence", request.reports[pair].parent) for pair in PAIRS
            )
    directory_inputs.extend(
        (f"{pair} {kind} product", context.products[pair][kind])
        for pair in PAIRS for kind in ("static", "dynamic")
    )
    file_inputs = [
        ("family request", _physical(root, request_path, "family request", below_work=True)),
        ("family roster", _physical(root, ROSTER_PATH.relative_to(root), "family roster")),
        ("POSIX matrix receipt", matrix_path),
        ("pthread family receipt", pthread_path),
        ("POSIX static preparation", context.static_preparation),
        ("POSIX dynamic qualification", context.dynamic_qualification),
    ]
    for specification in COMPONENTS.values():
        file_inputs.append((
            "component reader source " + specification.reader,
            _physical(root, specification.reader, "component reader source"),
        ))
    for request in requests.values():
        if request.expected_inputs is not None:
            file_inputs.extend(("wordexp expected inputs " + pair, request.expected_inputs[pair]) for pair in PAIRS)
        if request.receipt is not None:
            file_inputs.append(("text-locale-numeric aggregate receipt", request.receipt))
    return _snapshot_directories(root, directory_inputs), _snapshot_files(root, file_inputs)


def collect(root: Path, request_path: Path) -> dict[str, Any]:
    """Replay declared current receipts without producing or executing anything."""

    root = root.resolve(strict=True)
    load_roster(ROSTER_PATH)
    _request_value, matrix_path, pthread_path, requests = _request(root, request_path)
    source_before = current_source_identity(root)
    matrix_identity = _identity(root, matrix_path)
    try:
        matrix = _require_matrix(family.validate_receipt(root, matrix_path))
    except (family.ExecutionError, OSError, ValueError) as error:
        raise FamilyError(f"POSIX family receipt rejected: {error}") from error
    require(same(matrix["inputs"]["source"], source_before), "current source differs from POSIX matrix")
    inputs, products = _product_pairs(root, matrix)
    static_preparation = _input_receipt(root, inputs, "static_preparation")
    dynamic_qualification = _input_receipt(root, inputs, "dynamic_qualification")
    context = MatrixContext(source_before, inputs, products, static_preparation, dynamic_qualification)
    _require_pthread(root, pthread_path, matrix_identity, source_before)
    directories, files = _input_snapshots(root, request_path, matrix_path, pthread_path, context, requests)

    adapters = _reader_adapters()
    require(tuple(adapters) == tuple(COMPONENTS), "public component reader roster differs")
    observed: dict[str, dict[str, ComponentEvidence]] = {}
    for name in COMPONENTS:
        observed[name] = adapters[name](root, requests[name], context)
        _require_component(name, observed[name], products, source_before)

    _require_snapshots_current(root, directories, files, source_before)
    try:
        final_matrix = _require_matrix(family.validate_receipt(root, matrix_path))
    except (family.ExecutionError, OSError, ValueError) as error:
        raise FamilyError(f"POSIX family receipt changed during collection: {error}") from error
    final_inputs, final_products = _product_pairs(root, final_matrix)
    require(same(final_matrix, matrix) and final_inputs == inputs and final_products == products,
            "POSIX family receipt changed during collection")
    _require_pthread(root, pthread_path, matrix_identity, source_before)
    final_adapters = _reader_adapters()
    require(tuple(final_adapters) == tuple(COMPONENTS), "public component reader roster changed")
    for name in COMPONENTS:
        replayed = final_adapters[name](root, requests[name], context)
        _require_component(name, replayed, products, source_before)
        require(replayed == observed[name], f"{name} public reader changed during collection")

    # _pair_record seals retained product trees while constructing the output.
    # Recheck every declared root afterwards so a mutation in that final read
    # cannot enter an otherwise-valid immutable coordinator receipt.
    components = {
        name: {
            "scope": list(COMPONENTS[name].scope),
            "credits": list(COMPONENTS[name].credits),
            "pairs": {pair: _pair_record(root, requests[name], pair, observed[name][pair]) for pair in PAIRS},
        }
        for name in COMPONENTS
    }
    # Construct every retained identity before the final input check. No read
    # used for the return value is allowed to occur after that check.
    source_after = current_source_identity(root)
    result = {
        "schema": SCHEMA,
        "status": "immutable-component-coordination-verified",
        "family": FAMILY,
        "capabilities": list(CAPABILITIES),
        "inputs": {
            "request": _identity(root, _physical(root, request_path, "family request", below_work=True)),
            "family_execution": matrix_identity,
            "pthread_family": _identity(root, pthread_path),
            "source_before": source_before,
            "source_after": source_after,
            "roster": _roster_identity(root, ROSTER_PATH),
        },
        "components": components,
        "component_complete": False,
        "family_completion": False,
        "promotion_ready": False,
        "public_support": False,
    }
    _require_snapshots_current(root, directories, files, source_before)
    require(same(source_after, source_before), "current source changed during output construction")
    return result


def _fresh_output(root: Path, path: Path) -> Path:
    require(not path.is_absolute() and path.parts and ".." not in path.parts,
            "family output path escapes checkout")
    root = root.resolve(strict=True)
    output = root / path
    require(output.name == "receipt.json" and output.parent.is_relative_to(root / ".work"),
            "family output parent must be a checkout .work directory")
    current = root
    for part in path.parts[:-1]:
        current /= part
        try:
            metadata = current.lstat()
        except OSError as error:
            raise FamilyError("family output parent is unreadable") from error
        require(stat.S_ISDIR(metadata.st_mode) and not current.is_symlink(),
                "family output parent traverses a symbolic link")
    try:
        output.lstat()
    except FileNotFoundError:
        pass
    except OSError as error:
        raise FamilyError("family output path is unreadable") from error
    else:
        raise FamilyError("family output must be a fresh receipt.json")
    return output


def execute(root: Path, request_path: Path, output: Path) -> Path:
    root = root.resolve(strict=True)
    receipt = _fresh_output(root, output)
    value = collect(root, request_path)
    try:
        with receipt.open("x", encoding="utf-8") as stream:
            stream.write(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n")
    except FileExistsError as error:
        raise FamilyError("family output is no longer fresh") from error
    receipt.chmod(0o444)
    return receipt


def validate_receipt(root: Path, receipt: Path) -> dict[str, Any]:
    root = root.resolve(strict=True)
    receipt = _physical(root, receipt, "family receipt", below_work=True)
    require(receipt.name == "receipt.json", "family receipt must be named receipt.json")
    retained = _strict_json(receipt, "family receipt")
    inputs = retained.get("inputs")
    require(isinstance(inputs, dict) and isinstance(inputs.get("request"), dict),
            "family receipt request identity differs")
    request_identity = inputs["request"]
    require(isinstance(request_identity.get("path"), str), "family receipt request path differs")
    request = _physical(root, request_identity["path"], "family receipt request", below_work=True)
    require(same(_identity(root, request), request_identity), "family receipt request changed")
    observed = collect(root, request)
    require(same(retained, observed), "family receipt differs from reconstructed evidence")
    return observed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    collect_parser = commands.add_parser("collect", help="replay immutable component receipts without native execution")
    collect_parser.add_argument("--request", type=Path, required=True)
    write_parser = commands.add_parser("write", help="write one immutable non-promoting coordinator receipt")
    write_parser.add_argument("--request", type=Path, required=True)
    write_parser.add_argument("--output", type=Path, required=True)
    validate_parser = commands.add_parser("validate", help="reconstruct one coordinator receipt")
    validate_parser.add_argument("--receipt", type=Path, required=True)
    values = parser.parse_args()
    try:
        if values.command == "collect":
            print(json.dumps(collect(ROOT, values.request), sort_keys=True, separators=(",", ":")))
        elif values.command == "write":
            print(execute(ROOT, values.request, values.output))
        else:
            validate_receipt(ROOT, values.receipt)
            print("immutable text/math/locale/stdio component coordination valid; family and promotion remain pending")
    except (FamilyError, OSError, ValueError) as error:
        parser.exit(1, f"owned text/math/locale/stdio family: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
