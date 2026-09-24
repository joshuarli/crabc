#!/usr/bin/env python3
"""Sealed materialized dynamic driver (not campaign completion).

The static driver's input/ELF/tool checks are reused verbatim from the installed
package. This owner adds dynamic linkage, executable-direct application DSOs,
and an explicitly receipt-validated transitive DSO closure. The interpreter
name is canonical; run applications in the installed root.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass

# Installed tools are immutable payload, including when callers do not set a
# Python environment policy. Importing the shared checks must not create a
# bytecode cache inside the validated installation.
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "share/crabc"))
import crabc_cc_static as shared
import owned_dynamic_elf as elf_inspection
import owned_dynamic_receipt as receipt_contract

FORMAT = "crabc-x86-64-owned-dynamic-sysroot-v1"
INTERPRETER = "/lib/ld-crabc-x86_64.so.1"
ALIASES = {"lib/ld-musl-x86_64.so.1": "ld-crabc-x86_64.so.1"}
REQUIRED = {"usr/lib/libc.so", "usr/lib/crt1.o", "usr/lib/Scrt1.o", "usr/lib/crti.o", "usr/lib/crtn.o",
            "usr/lib/crabc-dynamic-attach.o", "usr/lib/libcrabc-builtins.a", "lib/ld-crabc-x86_64.so.1",
            "share/crabc/owned_dynamic_receipt.py", "share/crabc/owned_dynamic_elf.py"}
APPLICATION_DSO_BASENAME = re.compile(r"[^/\x00]+\.so(?:\.[0-9]+)*\Z")
RECEIPT_V1_FIELDS = receipt_contract.V1_FIELDS
RECEIPT_V2_FIELDS = receipt_contract.V2_FIELDS
RECEIPT_V3_FIELDS = receipt_contract.V3_FIELDS
RETAIN_LINK_EVIDENCE_ENV = "CRABC_X86_64_RETAIN_LINK_EVIDENCE"
MANIFEST = "share/crabc/manifest.json"
# A combined four-mode sysroot (scripts/build_x86_64_owned_combined_sysroot.py)
# owns MANIFEST and keeps this product's own manifest at a fixed placement.
COMBINED_FORMAT = shared.COMBINED_SYSROOT_FORMAT
COMBINED_PRODUCT_MANIFEST = "share/crabc/dynamic/manifest.json"


def application_dso_basename(path: Path) -> str:
    """Admit ordinary application DSOs and numeric ELF ABI-version suffixes.

    A versioned library such as Lua's ``liblua.so.5.4`` remains an explicit
    caller-owned application input.  Its full basename continues to bind the
    SONAME and receipt hash, so accepting the conventional numeric chain does
    not turn it into a library-search or target-runtime escape.
    """

    name = path.name
    if APPLICATION_DSO_BASENAME.fullmatch(name) is None:
        raise shared.DriverError("unowned application DSO")
    if receipt_contract.is_reserved_application_dso_name(name):
        raise shared.DriverError("reserved application DSO")
    return name


@contextmanager
def reserve_receipt(path: Path):
    """Claim a new sidecar before tools; never replace an existing inode.

    The held descriptor is the write authority. A failed invocation removes
    only its own still-empty reservation, not a pathname replaced by another
    publisher. Existing files, symlinks and hardlinks fail with EEXIST.
    """
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    except OSError as error:
        raise shared.DriverError(f"cannot reserve dynamic link receipt: {path}: {error}") from error
    identity = os.fstat(descriptor)
    complete = False
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        def publish(payload: str):
            nonlocal complete
            current = path.lstat()
            if (current.st_dev, current.st_ino, current.st_nlink) != (identity.st_dev, identity.st_ino, 1):
                raise shared.DriverError("dynamic receipt reservation identity changed")
            stream.write(payload)
            stream.flush()
            complete = True
        try:
            yield publish
        finally:
            if not complete:
                try:
                    current = path.lstat()
                    if (current.st_dev, current.st_ino, current.st_nlink) == (identity.st_dev, identity.st_ino, 1):
                        path.unlink()
                except FileNotFoundError:
                    pass


@contextmanager
def reserve_link_map(path: Path):
    """Claim LLD's map sidecar name before linking; drop it if the link fails.

    LLD writes the map itself, so the claimed empty file is replaced in place
    by the successful link. An existing path, symlink or hardlink is rejected
    before any tool runs, exactly like the JSON sidecars.
    """
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    except OSError as error:
        raise shared.DriverError(f"cannot reserve dynamic link map: {path}: {error}") from error
    os.close(descriptor)
    complete = False

    def accept() -> None:
        nonlocal complete
        shared.require_regular(path, "dynamic link map")
        complete = True

    try:
        yield accept
    finally:
        if not complete:
            try:
                if path.is_file() and not path.is_symlink():
                    path.unlink()
            except FileNotFoundError:
                pass


def final_elf_inspection(output: Path, expected: elf_inspection.Expectation, link_map: Path) -> dict:
    """Inspect one just-linked output before any caller can execute it.

    A rejected output is removed: LLD has already replaced the requested path,
    and a runnable artifact without a receipt must not survive the failure.
    """
    try:
        facts = elf_inspection.inspect(output)
        elf_inspection.require_expected(facts, expected)
    except (elf_inspection.InspectionError, OSError) as error:
        try:
            output.unlink()
        except FileNotFoundError:
            pass
        raise shared.DriverError(f"final ELF inspection rejected {output}: {error}") from error
    return elf_inspection.record(output, facts, expected, output_format=FORMAT, link_map=link_map)


def retain_link_evidence() -> bool:
    """Return the one explicit retention mode accepted by this installed driver.

    Normal callers keep the historical temporary-directory cleanup. The
    registry collector uses the exact opt-in only for its dlfcn receipts,
    whose source objects are replay inputs with their original paths.
    """

    value = os.environ.get(RETAIN_LINK_EVIDENCE_ENV)
    if value is None:
        return False
    if value != "1":
        raise shared.DriverError(f"{RETAIN_LINK_EVIDENCE_ENV} must be exactly '1' to retain link evidence")
    return True


@contextmanager
def link_evidence_workspace(parent: Path, *, retain: bool):
    """Create the private per-link workspace, retaining it only on explicit opt-in."""

    if retain:
        # Preserve the compiler's original path and bytes beneath the caller's
        # own work root. No receipt path is rewritten or copied elsewhere.
        yield Path(tempfile.mkdtemp(prefix="crabc-dynamic-link.", dir=parent))
        return
    with tempfile.TemporaryDirectory(prefix="crabc-dynamic-link.", dir=parent) as temporary:
        yield Path(temporary)


def validate(root: Path) -> dict:
    manifest = root / "share/crabc/manifest.json"
    shared.require_regular(manifest, "dynamic manifest")
    try:
        record = json.loads(manifest.read_text())
    except (ValueError, OSError) as error:
        raise shared.DriverError(f"invalid dynamic manifest: {error}") from error
    if not isinstance(record, dict) or type(record.get("schema")) is not int or record.get("schema") != 1 or record.get("format") != FORMAT or record.get("target") != shared.TARGET or record.get("symlinks") != ALIASES:
        raise shared.DriverError("wrong installed dynamic product contract")
    files = record.get("files")
    if not isinstance(files, dict) or not REQUIRED <= files.keys():
        raise shared.DriverError("incomplete installed dynamic payload")
    observed = set()
    aliases = {}
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            aliases[relative] = os.readlink(path)
        elif path.is_file():
            if relative != "share/crabc/manifest.json":
                observed.add(relative)
        elif not path.is_dir():
            raise shared.DriverError(f"nonregular installed payload: {relative}")
    if observed != files.keys() or aliases != ALIASES:
        raise shared.DriverError("installed payload differs from exact manifest roster")
    for relative, digest in files.items():
        if Path(relative).is_absolute() or ".." in Path(relative).parts or not re.fullmatch("[0-9a-f]{64}", str(digest)):
            raise shared.DriverError("unsafe manifest payload entry")
        if shared.sha256_file(root / relative) != digest:
            raise shared.DriverError(f"installed payload hash mismatch: {relative}")
    return record


def validate_combined(root: Path) -> dict:
    """Validate a combined four-mode sysroot that embeds this dynamic product.

    ``scripts/build_x86_64_owned_combined_sysroot.py`` composes the static and
    dynamic products into one tree, moves each product manifest below
    ``share/crabc/<product>/`` and writes the combined manifest in its place.
    This driver runs there only when the whole tree equals that manifest's exact
    roster and hashes, its only aliases are this product's, and every file the
    embedded dynamic product manifest names is installed unchanged at its own
    path; only product metadata may move within ``share/crabc/``.
    """
    record = json.loads((root / MANIFEST).read_text())
    files, links = record.get("files"), record.get("symlinks")
    products = record.get("products")
    if (type(record.get("schema")) is not int or record.get("schema") != 1 or record.get("target") != shared.TARGET
            or not isinstance(files, dict) or links != ALIASES or not isinstance(products, dict)
            or not isinstance(products.get("dynamic"), dict)):
        raise shared.DriverError("wrong installed combined sysroot contract")
    product = products["dynamic"]
    placements = product.get("placements")
    if (product.get("format") != FORMAT or product.get("manifest") != COMBINED_PRODUCT_MANIFEST
            or COMBINED_PRODUCT_MANIFEST not in files or not isinstance(placements, dict)):
        raise shared.DriverError("combined sysroot does not embed this dynamic product")
    observed, aliases = set(), {}
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            aliases[relative] = os.readlink(path)
        elif path.is_file():
            if relative != MANIFEST:
                observed.add(relative)
        elif not path.is_dir():
            raise shared.DriverError(f"nonregular installed payload: {relative}")
    if observed != files.keys() or aliases != ALIASES:
        raise shared.DriverError("installed payload differs from exact combined manifest roster")
    for relative, digest in files.items():
        if Path(relative).is_absolute() or ".." in Path(relative).parts or not re.fullmatch("[0-9a-f]{64}", str(digest)):
            raise shared.DriverError("unsafe combined manifest payload entry")
        if shared.sha256_file(root / relative) != digest:
            raise shared.DriverError(f"installed payload hash mismatch: {relative}")
    try:
        embedded = json.loads((root / COMBINED_PRODUCT_MANIFEST).read_text())
    except (ValueError, OSError) as error:
        raise shared.DriverError(f"invalid embedded dynamic manifest: {error}") from error
    embedded_files = embedded.get("files") if isinstance(embedded, dict) else None
    if (not isinstance(embedded_files, dict) or embedded.get("format") != FORMAT
            or embedded.get("symlinks") != ALIASES or not REQUIRED <= embedded_files.keys()):
        raise shared.DriverError("wrong embedded dynamic product contract")
    for relative, digest in embedded_files.items():
        placed = placements.get(relative)
        # Only product metadata may move, and only within share/crabc/.
        movable = (relative not in REQUIRED and relative.startswith(shared.PRODUCT_METADATA_PREFIX)
                   and isinstance(placed, str) and placed.startswith(shared.PRODUCT_METADATA_PREFIX))
        if placed != relative and not movable:
            raise shared.DriverError(f"combined sysroot moved dynamic payload: {relative}")
        if files.get(placed) != digest:
            raise shared.DriverError(f"combined sysroot does not install dynamic payload unchanged: {relative}")
    return record


def validate_installation(root: Path) -> dict:
    """Admit this driver's own product tree or a combined tree embedding it.

    Anything that does not identify a combined tree is left to the product
    contract, which reports a missing or malformed manifest itself.
    """
    manifest = root / MANIFEST
    identity = None
    if manifest.is_file() and not manifest.is_symlink():
        try:
            record = json.loads(manifest.read_text())
        except (ValueError, OSError):
            record = None
        identity = record.get("format") if isinstance(record, dict) else None
    return validate_combined(root) if identity == COMBINED_FORMAT else validate(root)


def run(command: list[str], temporary: Path) -> str:
    environment = shared.clean_environment()
    environment["TMPDIR"] = str(temporary)
    result = subprocess.run(command, env=environment, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode:
        raise shared.DriverError(f"command failed: {command[0]}\n{result.stdout}{result.stderr}")
    return result.stdout


def dso_receipt_runpath(record: object, path: Path) -> str:
    """Return an application DSO's RUNPATH from a closed declared receipt.

    Schema 1 retains its exact historical fields and an implicit SysV hash
    style. Schema 2 states search kind and hash style explicitly. Schema 3
    adds an explicitly typed closure. Application DSOs admit RUNPATH only, so
    executable-only RPATH cannot authorize them.
    """

    if not isinstance(record, dict):
        raise shared.DriverError("application DSO receipt is not an object")
    def fail(message: str) -> None:
        raise shared.DriverError(message)

    contract = receipt_contract.validate(
        record, format=FORMAT, label="application DSO receipt", fail=fail,
        allow_application_dso_closure=True,
    )
    if (record["mode"] != "shared" or record["output_sha256"] != shared.sha256_file(path)
            or record["output_path"] != str(path.resolve())):
        raise shared.DriverError("application DSO receipt does not bind this shared object")
    if contract.kind != "runpath":
        raise shared.DriverError("application DSO receipt does not declare RUNPATH")
    return contract.path


def dso_metadata_detail(path: Path, temporary: Path) -> tuple[str, list[str], list[str]]:
    """Inspect one physical DSO without treating its dependencies as inputs.

    The detail form keeps the observed RUNPATH for schema-3 sidecar proof.
    ``dso_metadata`` remains the historical two-value helper used by direct
    declarations and narrow unit tests.
    """

    data = path.read_bytes()
    if len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01" or int.from_bytes(data[16:18], "little") != 3 or int.from_bytes(data[18:20], "little") != 62:
        raise shared.DriverError(f"application DSO is not native ET_DYN: {path}")
    segments = run(["/usr/bin/readelf", "-lW", str(path)], temporary)
    dynamic = run(["/usr/bin/readelf", "-dW", str(path)], temporary)
    if "INTERP" in segments or "TEXTREL" in dynamic or "(RPATH)" in dynamic:
        raise shared.DriverError("application DSO contains forbidden interpreter/textrel/RPATH")
    sonames = re.findall(r"\(SONAME\).*\[([^\]]+)\]", dynamic)
    if sonames != [path.name] or "/" in path.name:
        raise shared.DriverError("application DSO must own exactly its basename SONAME")
    needed = re.findall(r"\(NEEDED\).*\[([^\]]+)\]", dynamic)
    if any("/" in name for name in needed):
        raise shared.DriverError("application DSO contains pathname DT_NEEDED")
    runpaths = re.findall(r"\(RUNPATH\).*\[([^\]]*)\]", dynamic)
    if runpaths not in ([], ["/usr/lib"]):
        receipt = Path(str(path) + ".crabc-link.json")
        shared.require_regular(receipt, "application search path receipt")
        try:
            record = json.loads(receipt.read_text())
        except (ValueError, OSError) as error:
            raise shared.DriverError(f"invalid application search path receipt: {error}") from error
        if runpaths != [dso_receipt_runpath(record, path)]:
            raise shared.DriverError("application DSO has an undeclared runtime search path")
    return path.name, needed, runpaths


def dso_metadata(path: Path, temporary: Path) -> tuple[str, list[str]]:
    name, needed, _ = dso_metadata_detail(path, temporary)
    return name, needed


@dataclass(frozen=True)
class ApplicationDso:
    """One caller-owned closure node admitted by the installed driver."""

    path: Path
    name: str
    needed: tuple[str, ...]
    role: str
    receipt: dict[str, object] | None = None
    search: receipt_contract.SearchContract | None = None
    runtime_imports: frozenset[str] = frozenset()


def receipt_failure(message: str) -> None:
    raise shared.DriverError(message)


def application_dso_sidecar(
    root: Path, path: Path, runpaths: list[str]
) -> tuple[dict[str, object], receipt_contract.SearchContract, frozenset[str]]:
    """Load the normal owned receipt which authorizes one closure DSO.

    A schema-3 declaration is an ownership assertion, rather than a route to
    let LLD discover a file. Every graph node therefore has to bind the
    current installed manifest, its physical DSO bytes, normal shared-output
    mode and observed RUNPATH before the closure can be used.
    """

    sidecar = Path(str(path) + ".crabc-link.json")
    shared.require_regular(sidecar, "application DSO closure receipt")
    try:
        record = json.loads(sidecar.read_text())
    except (ValueError, OSError) as error:
        raise shared.DriverError(f"invalid application DSO closure receipt: {error}") from error
    if not isinstance(record, dict):
        raise shared.DriverError("application DSO closure receipt is not an object")
    search = receipt_contract.validate(
        record, format=FORMAT, label="application DSO closure receipt", fail=receipt_failure,
        allow_application_dso_closure=True,
    )
    if (record["mode"] != "shared" or record["output_path"] != str(path.resolve())
            or record["output_sha256"] != shared.sha256_file(path)):
        raise shared.DriverError("application DSO closure receipt does not bind its shared object")
    if record["manifest_sha256"] != shared.sha256_file(root / "share/crabc/manifest.json"):
        raise shared.DriverError("application DSO closure receipt binds another installed product")
    if record["campaign_complete"] is not False or record["binding"] not in ("now", "lazy"):
        raise shared.DriverError("application DSO closure receipt has an invalid link contract")
    imports = record["runtime_imports"]
    if (not isinstance(imports, list) or not all(isinstance(symbol, str)
            and re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", symbol) is not None for symbol in imports)
            or len(set(imports)) != len(imports)
            or (imports and record["binding"] != "lazy")):
        raise shared.DriverError("application DSO closure receipt runtime imports are invalid")
    if search.kind != "runpath" or runpaths != [search.path]:
        raise shared.DriverError("application DSO closure receipt runtime search path differs from ELF")
    library = root / "usr/lib"
    expected_runtime = sorted(
        item.relative_to(root).as_posix()
        for item in (library / "crti.o", library / "libc.so", library / "crtn.o",
                     library / "libcrabc-builtins.a")
    )
    if record["owned_runtime_inputs"] != expected_runtime:
        raise shared.DriverError("application DSO closure receipt runtime roster differs")
    return record, search, frozenset(imports)


def closure_node(root: Path, path: Path, role: str, temporary: Path) -> ApplicationDso:
    """Admit one direct or validation-only DSO and require its sidecar."""

    path = shared.require_application_file(root, path, "DSO")
    name, needed, runpaths = dso_metadata_detail(path, temporary)
    receipt, search, imports = application_dso_sidecar(root, path, runpaths)
    return ApplicationDso(path, name, tuple(needed), role, receipt, search, imports)


def closure_reachable(
    roots: list[str], nodes: dict[str, ApplicationDso], *, omit: str | None = None
) -> set[str]:
    """Return reachable closure names while allowing cycles and a local omit."""

    reached: set[str] = set()
    pending = list(roots)
    while pending:
        name = pending.pop()
        if name == omit or name in reached:
            continue
        reached.add(name)
        pending.extend(needed for needed in nodes[name].needed if needed in nodes)
    return reached


def validate_closure_graph(nodes: dict[str, ApplicationDso], direct_names: list[str]) -> None:
    """Require the declared input graph to be complete, closed and reachable.

    The shared object being linked is deliberately not an input node. An input
    back-edge to that output therefore needs a separate self-output identity
    contract and is rejected here before LLD can publish a receipt.
    """

    names = set(nodes)
    for node in nodes.values():
        if len(set(node.needed)) != len(node.needed):
            raise shared.DriverError(f"application DSO has duplicate DT_NEEDED entries: {node.path}")
        if not set(node.needed) <= {"libc.so", *names}:
            raise shared.DriverError(f"undeclared transitive dependency of {node.path}")
    if closure_reachable(direct_names, nodes) != names:
        raise shared.DriverError("application DSO closure has an unreachable declared node")


def _sidecar_raw_application_inputs(record: dict[str, object]) -> list[dict[str, object]]:
    """Return schema-1/2 input records after retaining their historical shape."""

    inputs = record["input_receipts"]
    if not isinstance(inputs, list) or not all(
        isinstance(item, dict) and set(item) == {"path", "sha256"}
        and isinstance(item["path"], str) and item["path"] and "\0" not in item["path"]
        and isinstance(item["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is not None
        for item in inputs
    ):
        raise shared.DriverError("application DSO closure receipt input roster is invalid")
    return inputs


def validate_closure_sidecar(
    node: ApplicationDso, nodes: dict[str, ApplicationDso]
) -> None:
    """Bind a node's normal receipt to the actual graph it was built against.

    Direct-only receipts describe only immediate DSO children because every
    one was an LLD input at that historical boundary. Schema 3 records the
    full reachable child closure. This relation is checked without assuming a
    DAG for cycles within declared input nodes. The shared output itself is
    absent from that input closure, so a back-edge to it remains rejected at
    ``validate_closure_graph`` until a separate self-output contract exists.
    """

    assert node.receipt is not None and node.search is not None
    children = [name for name in node.needed if name in nodes]
    expected_immediate = {name: shared.sha256_file(nodes[name].path) for name in children}
    identities = node.receipt["application_dsos"]
    command = node.receipt["link_command"]
    trace = node.receipt["link_trace"]
    if (not isinstance(command, list) or not isinstance(trace, list)
            or not all(isinstance(item, str) for item in [*command, *trace])):
        raise shared.DriverError("application DSO closure receipt link evidence is invalid")

    if node.search.schema in (1, 2):
        if not isinstance(identities, dict) or identities != expected_immediate:
            raise shared.DriverError("application DSO closure receipt dependency identities differ")
        inputs = _sidecar_raw_application_inputs(node.receipt)
        for child in children:
            path = str(nodes[child].path)
            digest = expected_immediate[child]
            if sum(item["path"] == path and item["sha256"] == digest for item in inputs) != 1:
                raise shared.DriverError("application DSO closure receipt does not bind its direct dependency")
            if command.count(path) != 1 or trace.count(path) != 1:
                raise shared.DriverError("application DSO closure receipt did not link its direct dependency")
        forbidden = {str(candidate.path) for name, candidate in nodes.items()
                     if name not in children and name != node.name}
        if any(item in forbidden for item in [*command, *trace]):
            raise shared.DriverError("application DSO closure receipt linked an undeclared graph node")
        return

    recorded = {item.name: item for item in node.search.application_dso_closure}
    expected_names = closure_reachable(children, nodes, omit=node.name)
    expected_identities = {
        name: shared.sha256_file(nodes[name].path) for name in expected_names
    }
    if not isinstance(identities, dict) or identities != expected_identities:
        raise shared.DriverError("application DSO closure receipt dependency identities differ")
    if set(recorded) != expected_names:
        raise shared.DriverError("application DSO closure receipt does not close its transitive graph")
    if {name for name, item in recorded.items() if item.role == "direct"} != set(children):
        raise shared.DriverError("application DSO closure receipt direct roles differ from DT_NEEDED")
    for name, item in recorded.items():
        expected = nodes[name]
        if (item.path != str(expected.path) or item.sha256 != shared.sha256_file(expected.path)
                or item.needed != expected.needed):
            raise shared.DriverError("application DSO closure receipt graph identity differs from ELF")


def validate_closure_runtime_imports(nodes: dict[str, ApplicationDso], temporary: Path, library: Path) -> set[str]:
    """Resolve every DSO import or match it to its own deliberate exception."""

    provided, _ = dynamic_symbols(library / "libc.so", temporary)
    requirements: dict[str, set[str]] = {}
    for name, node in nodes.items():
        definitions, required = dynamic_symbols(node.path, temporary)
        provided.update(definitions)
        requirements[name] = required
    for name, node in nodes.items():
        unresolved = requirements[name] - provided
        if unresolved != node.runtime_imports:
            raise shared.DriverError(
                f"application DSO runtime imports differ from its declared contract: {name}"
            )
    return provided


def elf_needed(path: Path, temporary: Path) -> list[str]:
    """Read ordered DT_NEEDED names from a just-linked executable or DSO."""

    dynamic = run(["/usr/bin/readelf", "-dW", str(path)], temporary)
    return re.findall(r"\(NEEDED\).*\[([^\]]+)\]", dynamic)


def dynamic_symbols(path: Path, temporary: Path, *, object_symbols: bool = False) -> tuple[set[str], set[str]]:
    definitions, required = set(), set()
    for line in run(["/usr/bin/readelf", "--symbols" if object_symbols else "--dyn-syms", "-W", str(path)], temporary).splitlines():
        fields = line.split()
        if len(fields) < 8 or not fields[0].endswith(":"): continue
        kind, binding, visibility, section, name = fields[3:8]
        if binding not in ("GLOBAL", "WEAK"): continue
        if "@" in name or kind == "IFUNC":
            raise shared.DriverError("symbol versions and IFUNC are not admitted by this initial product")
        if section == "UND":
            if binding == "GLOBAL": required.add(name)
        elif object_symbols or visibility in ("DEFAULT", "PROTECTED"):
            definitions.add(name)
    return definitions, required


def application_quote_include_dir(root: Path, path: Path) -> Path:
    """Admit one physical, caller-owned directory for quoted C headers.

    The installed product remains the only authority for angle-bracket
    headers.  This deliberately does not open a general ``-I`` surface: an
    upstream source tree can name its own ``#include "test.h"`` support
    headers, but cannot replace installed C headers or route the compiler
    through the immutable sysroot.  Reject every existing symlink component
    so the declared directory is the physical input that reaches GCC.
    """

    shared.reject_existing_symlink_components(path, "application quote include")
    resolved = shared.resolved_path(path, "application quote include")
    if not resolved.is_dir() or path.is_symlink():
        raise shared.DriverError(f"application quote include is missing or unsafe: {path}")
    if shared.is_within_installed_root(root, resolved):
        raise shared.DriverError(
            f"application quote include is inside the installed sysroot: {path}"
        )
    return resolved


def execute(root: Path, arguments: list[str]) -> None:
    validate_installation(root)
    retain_evidence = retain_link_evidence()
    mode = None
    binding = None
    application_runpath = None
    application_rpath = None
    application_hash_style = "sysv"
    application_hash_style_explicit = False
    runtime_imports = set()
    dsos = []
    transitive_dsos = []
    common = []
    quote_include_inputs = []
    dependency_file = None
    rounding_math = False
    export_dynamic = False
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument in ("--dynamic-pie", "-pie", "--dynamic-non-pie", "-no-pie", "--dynamic-shared-object", "-shared"):
            if mode is not None: raise shared.DriverError("select exactly one dynamic mode")
            mode = ("shared" if argument in ("-shared", "--dynamic-shared-object") else
                    "exec" if argument in ("--dynamic-non-pie", "-no-pie") else "pie")
        elif argument in ("--binding", "--runtime-import"):
            index += 1
            if index == len(arguments): raise shared.DriverError(f"missing {argument} value")
            value = arguments[index]
            if argument == "--binding":
                if binding is not None or value not in ("now", "lazy"):
                    raise shared.DriverError("select one binding: now or lazy")
                binding = value
            else:
                if not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", value) or value in runtime_imports:
                    raise shared.DriverError("invalid or duplicate runtime import")
                runtime_imports.add(value)
        elif argument == "--application-runpath":
            index += 1
            if index == len(arguments) or application_runpath is not None or application_rpath is not None:
                raise shared.DriverError("select one application RUNPATH")
            application_runpath = arguments[index]
            if not application_runpath or len(application_runpath.encode()) >= 4096 or "\0" in application_runpath:
                raise shared.DriverError("invalid application RUNPATH")
        elif argument == "--application-rpath":
            index += 1
            if index == len(arguments) or application_runpath is not None or application_rpath is not None:
                raise shared.DriverError("select one application search path")
            application_rpath = arguments[index]
            if not application_rpath or len(application_rpath.encode()) >= 4096 or "\0" in application_rpath:
                raise shared.DriverError("invalid application RPATH")
        elif argument == "--application-hash-style":
            index += 1
            if index == len(arguments) or application_hash_style_explicit or arguments[index] not in ("sysv", "gnu", "both"):
                raise shared.DriverError("select one application hash style: sysv, gnu, or both")
            application_hash_style = arguments[index]
            application_hash_style_explicit = True
        elif argument == "--application-dso":
            index += 1
            if index == len(arguments): raise shared.DriverError("missing application DSO")
            path = Path(arguments[index])
            if shared.rejects_runtime_object(path):
                raise shared.DriverError("unowned application DSO")
            application_dso_basename(path)
            dsos.append(path)
        elif argument == "--transitive-application-dso":
            index += 1
            if index == len(arguments): raise shared.DriverError("missing transitive application DSO")
            path = Path(arguments[index])
            if shared.rejects_runtime_object(path):
                raise shared.DriverError("unowned transitive application DSO")
            application_dso_basename(path)
            transitive_dsos.append(path)
        elif argument == "--application-quote-include-dir":
            index += 1
            if index == len(arguments) or arguments[index].startswith("-"):
                raise shared.DriverError("--application-quote-include-dir requires one directory path")
            quote_include_inputs.append(Path(arguments[index]))
        elif argument == "--application-dependency-file":
            index += 1
            if index == len(arguments) or arguments[index].startswith("-") or dependency_file is not None:
                raise shared.DriverError("--application-dependency-file requires one output path")
            dependency_file = Path(arguments[index])
        elif argument == "-frounding-math":
            if rounding_math:
                raise shared.DriverError("-frounding-math may be specified only once")
            rounding_math = True
        elif argument == "-rdynamic":
            if export_dynamic:
                raise shared.DriverError("-rdynamic may be specified only once")
            export_dynamic = True
        elif argument in ("-static", "--static-et-exec", "-static-pie", "--static-pie"):
            raise shared.DriverError("static linkage is not a dynamic mode")
        else:
            common.append(argument)
        index += 1
    if mode is None: raise shared.DriverError("select --dynamic-pie, --dynamic-non-pie or --dynamic-shared-object")
    application_search_kind = "rpath" if application_rpath is not None else "runpath"
    if application_search_kind == "runpath":
        application_runpath = application_runpath if application_runpath is not None else "/usr/lib"
    application_search_path = application_rpath if application_search_kind == "rpath" else application_runpath
    binding = binding or "now"
    if runtime_imports and (mode != "shared" or binding != "lazy"):
        raise shared.DriverError("runtime imports require a lazy shared object")
    invocation = shared.parse_invocation(common)
    if invocation.compile_only and (application_search_path != "/usr/lib" or application_search_kind != "runpath"):
        raise shared.DriverError("compile-only accepts no application RUNPATH")
    if invocation.compile_only and application_hash_style_explicit:
        raise shared.DriverError("compile-only accepts no application hash style")
    if invocation.compile_only and (runtime_imports or binding != "now"):
        raise shared.DriverError("compile-only accepts no binding/import contract")
    if invocation.compile_only and (dsos or transitive_dsos):
        raise shared.DriverError("compile-only accepts no DSO")
    if dependency_file is not None and not invocation.compile_only:
        raise shared.DriverError("--application-dependency-file is available only for a compile-only invocation")
    if transitive_dsos and not dsos:
        raise shared.DriverError("transitive application DSOs require one direct --application-dso")
    if invocation.link_receipt is not None:
        raise shared.DriverError("dynamic link receipt path is derived from -o")
    if export_dynamic and (mode == "shared" or invocation.compile_only):
        raise shared.DriverError("-rdynamic requires a dynamic executable link")
    if application_search_kind == "rpath" and mode == "shared":
        raise shared.DriverError("--application-rpath requires a dynamic executable link")
    if invocation.print_link_plan and (quote_include_inputs or rounding_math):
        raise shared.DriverError("link plan accepts no application translation options")
    quote_include_dirs = []
    for path in quote_include_inputs:
        directory = application_quote_include_dir(root, path)
        if directory in quote_include_dirs:
            raise shared.DriverError("duplicate application quote include directory")
        quote_include_dirs.append(directory)
    library = root / "usr/lib"
    link = [shared.linker(root), *(["-shared"] if mode == "shared" else ["-pie"] if mode == "pie" else []), f"--hash-style={application_hash_style}",
            "-z", "relro", "-z", binding, "-z", "noexecstack", "-z", "text", *([] if runtime_imports else ["--no-undefined"]),
            "--allow-shlib-undefined", "--disable-new-dtags" if application_search_kind == "rpath" else "--enable-new-dtags", "-rpath", application_search_path]
    if export_dynamic:
        link.append("--export-dynamic")
    entry_object = "Scrt1.o" if mode == "pie" else "crt1.o"
    if mode != "shared":
        link += ["--dynamic-linker", INTERPRETER, str(library / entry_object),
                 str(library / "crabc-dynamic-attach.o")]
    if invocation.print_link_plan:
        if dsos or transitive_dsos: raise shared.DriverError("link plan accepts no application inputs")
        print(json.dumps({"format": FORMAT, "mode": mode, "binding": binding,
                          "runtime_imports": sorted(runtime_imports), "application_runpath": application_runpath,
                          "application_rpath": application_rpath, "application_search_kind": application_search_kind,
                          "application_hash_style": application_hash_style, "linker": link,
                          "campaign_complete": False}, sort_keys=True))
        return
    output = (invocation.output or Path("a.out")).absolute()
    shared.validate_application_output(root, output)
    shared.validate_application_output_disjoint(
        output, invocation.sources + invocation.objects + tuple(dsos) + tuple(transitive_dsos)
    )
    dependency_output = None
    if dependency_file is not None:
        dependency_output = dependency_file.absolute()
        shared.validate_application_output(root, dependency_output)
        shared.validate_application_output_disjoint(
            dependency_output, invocation.sources + invocation.objects + (output,)
        )
    receipt = Path(str(output) + ".crabc-link.json")
    inspection_path, map_path = elf_inspection.sidecar_paths(output)
    for sidecar in (receipt, inspection_path, map_path):
        shared.validate_application_output(root, sidecar)
        shared.validate_application_output_disjoint(
            sidecar, invocation.sources + invocation.objects + tuple(dsos)
            + tuple(transitive_dsos) + (output,)
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    with (nullcontext(None) if invocation.compile_only else reserve_receipt(receipt)) as receipt_stream, \
         (nullcontext(None) if invocation.compile_only else reserve_receipt(inspection_path)) as inspection_stream, \
         (nullcontext(None) if invocation.compile_only else reserve_link_map(map_path)) as accept_map, \
         link_evidence_workspace(output.parent, retain=retain_evidence) as temporary:
        objects = [shared.require_x86_64_relocatable_object(root, path) for path in invocation.objects]
        for index, source in enumerate(invocation.sources):
            source = shared.require_application_file(root, source, "source")
            obj = output if invocation.compile_only else temporary / f"source-{index}.o"
            run([shared.compiler(), "-nostdinc",
                 *(item for directory in quote_include_dirs for item in ("-iquote", str(directory))),
                 "-isystem", str(root / "usr/include"),
                 "-ffreestanding", "-fno-builtin", "-fstack-protector-strong",
                 *invocation.compiler_flags, *(["-frounding-math"] if rounding_math else []),
                 *(["-MD", "-MF", str(dependency_output)] if dependency_output is not None else []),
                 "-fPIC" if mode == "shared" else "-fPIE" if mode == "pie" else "-fno-pie",
                 "-c", str(source), "-o", str(obj)], temporary)
            objects.append(obj)
        if invocation.compile_only:
            return
        closure_enabled = bool(transitive_dsos)
        closure_nodes: dict[str, ApplicationDso] = {}
        direct_dso_paths: list[Path] = []
        if closure_enabled:
            direct_names: list[str] = []
            for role, candidates in (("direct", dsos), ("transitive", transitive_dsos)):
                for candidate in candidates:
                    node = closure_node(root, candidate, role, temporary)
                    if node.name in closure_nodes:
                        raise shared.DriverError("duplicate application SONAME")
                    if any(node.path == existing.path for existing in closure_nodes.values()):
                        raise shared.DriverError("duplicate application DSO path")
                    closure_nodes[node.name] = node
                    if role == "direct":
                        direct_names.append(node.name)
                        direct_dso_paths.append(node.path)
            validate_closure_graph(closure_nodes, direct_names)
            for node in closure_nodes.values():
                validate_closure_sidecar(node, closure_nodes)
            provided = validate_closure_runtime_imports(closure_nodes, temporary, library)
        else:
            # Keep the long-standing direct-only path and schema-2 output
            # unchanged. The schema-3 closure contract is selected only by
            # the new transitive-only declaration spelling.
            declared = {}
            for path in dsos:
                path = shared.require_application_file(root, path, "DSO")
                name, needed = dso_metadata(path, temporary)
                if name in declared: raise shared.DriverError("duplicate application SONAME")
                declared[name] = (path, needed)
            for path, needed in declared.values():
                if not set(needed) <= {"libc.so", *declared.keys()}:
                    raise shared.DriverError(f"undeclared transitive dependency of {path}")
            provided, _ = dynamic_symbols(library / "libc.so", temporary)
            requirements = set()
            for path, _ in declared.values():
                definitions, required = dynamic_symbols(path, temporary)
                provided.update(definitions)
                requirements.update(required)
            if requirements - provided:
                raise shared.DriverError(f"application DSOs have unresolved runtime imports: {sorted(requirements - provided)}")
            direct_dso_paths = [path for path, _ in declared.values()]
        if runtime_imports:
            # Removing --no-undefined is authorized only by an exact symbol
            # contract, checked against all owned objects before linking. No
            # incidental missing import or ambient provider is accepted.
            # ELF x86 PIC objects name this linker-synthesized table anchor;
            # it is not an import from a target runtime library.
            object_provided, object_required = {*provided, "_GLOBAL_OFFSET_TABLE_"}, set()
            for path in [*objects, library / "libcrabc-builtins.a"]:
                definitions, required = dynamic_symbols(path, temporary, object_symbols=True)
                object_provided.update(definitions)
                if path in objects: object_required.update(required)
            if object_required - object_provided != runtime_imports:
                raise shared.DriverError(f"runtime imports differ from exact unresolved object symbols: {sorted(object_required - object_provided)}")
        if mode == "shared": link += ["-soname", output.name]
        link += [str(library / "crti.o"), *(str(path) for path in objects),
                 *(str(path) for path in direct_dso_paths), str(library / "libc.so"),
                 str(library / "libcrabc-builtins.a"), str(library / "crtn.o"), "-o", str(output)]
        trace = run([*link[:-2], "--trace", f"-Map={map_path}", *link[-2:]], temporary).splitlines()
        runtime = [library / name for name in ("crti.o", "libc.so", "crtn.o")]
        if mode != "shared": runtime += [library / entry_object, library / "crabc-dynamic-attach.o"]
        direct = [*runtime, *objects, *direct_dso_paths]
        archive = library / "libcrabc-builtins.a"
        # LLD may not extract an archive member. Every other input must appear,
        # and no ambient startup, library, script or helper input is permitted.
        seen = set()
        for line in trace:
            if line in {str(path) for path in direct}:
                seen.add(line)
            elif line == str(archive) or (line.startswith(str(archive) + "(") and line.endswith(")")):
                continue
            else:
                raise shared.DriverError(f"unadmitted dynamic link trace input: {line}")
        if seen != {str(path) for path in direct}:
            raise shared.DriverError("dynamic link trace omitted an explicit input")
        if runtime_imports:
            _, output_required = dynamic_symbols(output, temporary)
            if output_required - provided != runtime_imports:
                raise shared.DriverError("linked runtime imports differ from declared contract")
        if closure_enabled:
            expected_needed = [
                node.name for node in closure_nodes.values() if node.role == "direct"
            ] + ["libc.so"]
            if elf_needed(output, temporary) != expected_needed:
                raise shared.DriverError("linked executable DT_NEEDED differs from declared direct DSO roots")
        # Every direct application DSO owns exactly its basename SONAME, and
        # this link never uses --as-needed: DT_NEEDED is their link order then
        # libc.so. The inspection is complete before any receipt exists.
        inspection = final_elf_inspection(output, elf_inspection.Expectation(
            mode=mode, interpreter=INTERPRETER,
            needed=(*(path.name for path in direct_dso_paths), "libc.so"),
            soname=output.name if mode == "shared" else None,
            search_kind=application_search_kind, search_path=application_search_path,
            binding=binding, hash_style=application_hash_style,
            runtime_imports=frozenset(runtime_imports), provided_symbols=frozenset(provided),
        ), map_path)
        record = {"schema": 3 if closure_enabled else 2, "format": FORMAT, "mode": mode, "binding": binding,
                  "runtime_imports": sorted(runtime_imports), "application_runpath": application_runpath,
                  "application_rpath": application_rpath, "application_search_kind": application_search_kind,
                  "application_hash_style": application_hash_style,
                  "output_path": str(output.resolve()),
                  "output_sha256": shared.sha256_file(output),
                  "manifest_sha256": shared.sha256_file(root / "share/crabc/manifest.json"),
                  "application_dsos": (
                      {name: shared.sha256_file(node.path) for name, node in closure_nodes.items()}
                      if closure_enabled else
                      {name: shared.sha256_file(path) for name, (path, _) in declared.items()}
                  ),
                  "owned_runtime_inputs": sorted(path.relative_to(root).as_posix() for path in [*runtime, archive]),
                  "input_receipts": (
                      [
                          {"role": "linker-input", "path": str(path), "sha256": shared.sha256_file(path)}
                          for path in [*runtime, *objects]
                      ]
                      + [
                          {"role": "direct-application-dso", "name": node.name,
                           "path": str(node.path), "sha256": shared.sha256_file(node.path)}
                          for node in closure_nodes.values() if node.role == "direct"
                      ]
                      + [{"role": "linker-input", "path": str(archive), "sha256": shared.sha256_file(archive)}]
                      + [
                          {"role": "transitive-application-dso", "name": node.name,
                           "path": str(node.path), "sha256": shared.sha256_file(node.path)}
                          for node in closure_nodes.values() if node.role == "transitive"
                      ]
                      if closure_enabled else
                      [{"path": str(path), "sha256": shared.sha256_file(path)} for path in [*direct, archive]]
                  ),
                  "resolved_linker": {"path": link[0], "sha256": shared.sha256_file(Path(link[0]))},
                  "link_command": link, "link_trace": trace, "campaign_complete": False}
        if closure_enabled:
            record["application_dso_roles"] = {
                name: node.role for name, node in closure_nodes.items()
            }
            record["application_dso_needed"] = {
                name: list(node.needed) for name, node in closure_nodes.items()
            }
        accept_map()
        inspection_stream(json.dumps(inspection, indent=2, sort_keys=True) + "\n")
        receipt_stream(json.dumps(record, indent=2, sort_keys=True) + "\n")


def main() -> int:
    try:
        execute(ROOT, sys.argv[1:])
    except (shared.DriverError, OSError) as error:
        print(f"crabc-cc-dynamic: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
