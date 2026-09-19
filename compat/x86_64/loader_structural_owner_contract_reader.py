#!/usr/bin/env python3
"""Collect and replay the finite x86 loader structural-owner receipt.

This component records source proof for the selected loader graph separately
from ordinary C observations.  The observations use public ``dl*`` and
pthread APIs; they cannot prove private stage call order by themselves.
Neither collection nor replay creates an ELF authority, selector projection,
or family-completion claim.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tomllib
from typing import Any, Mapping, Sequence

MODULE_DIR = Path(__file__).resolve().parent
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))

import loader_debug_abi_evidence as loader_debug
import loader_runtime_registry_evidence as runtime_registry
import native_abi_elf_facts as elf_facts
import native_abi_inventory as inventory
import owned_posix_product_evidence as product_evidence


ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = ROOT / "compat/x86_64/loader-structural-owner-receipt.toml"
SCHEMA = "crabc.x86_64-loader-structural-owner-receipt/v1"
STATUS = "component-verified"
COMPONENT = "loader-structural-owner"
TARGET = "x86_64-unknown-linux-musl"
PINNED_IMAGE = "sha256:5990e55b88db10c7dc82bb57b8087be74282ddb0c50f1dc88f05cec63ce95b8d"
SOURCE_MOUNT = "/workspace"
IMAGE_INPUT_PATHS = {
    "oracle_compiler": "/usr/local/bin/crabc-x86_64-musl-gcc",
    "musl_shared": "/opt/musl-1.2.6/lib/libc.so",
    "timeout": "/usr/bin/timeout",
    "chroot": "/usr/sbin/chroot",
}
IMAGE_MANIFEST_SOURCE = "compat/x86_64/owned-resolver-alias-image-inputs.json"
IDENTITIES = (
    "__dls2b", "__dls3", "_dlstart", "__ldso_register_dlopen",
    "__ldso_register_dlsym", "__ldso_register_dlclose",
    "__ldso_register_dlerror", "__ldso_register_mark_multithreaded",
)
STARTUP_IDENTITIES = IDENTITIES[:3]
REGISTRATION_IDENTITIES = IDENTITIES[3:]
MODES = (
    "dynamic-pie-kernel", "dynamic-pie-direct",
    "dynamic-non-pie-kernel", "dynamic-non-pie-direct",
)
LANES = ("pinned-musl-1.2.6", "candidate")
PROBES = (
    "startup-entry-public-dlfcn",
    "registration-replacement-before-worker",
)
PROBE_SOURCES = {
    "startup-entry-public-dlfcn": "compat/x86_64/loader_structural_owner_startup_probe.c",
    "registration-replacement-before-worker": "compat/x86_64/loader_structural_owner_registration_probe.c",
}
PLUGIN_SOURCE = "compat/x86_64/loader_structural_owner_plugin.c"
RUNNER_PATH = "compat/x86_64/run_loader_structural_owner_contract.sh"
READER_PATH = "compat/x86_64/loader_structural_owner_contract_reader.py"
CONTRACT_SOURCE = "compat/x86_64/loader-structural-owner-receipt.toml"
DOCUMENTATION_SOURCE = "compat/x86_64/loader-structural-owner-receipt.md"
SOURCE_CONTRACT_PATHS = (
    CONTRACT_SOURCE, DOCUMENTATION_SOURCE, READER_PATH, RUNNER_PATH,
    *PROBE_SOURCES.values(), PLUGIN_SOURCE,
    "ldso/Cargo.toml", "ldso/build.rs", "ldso/src/x86_64_initial_graph.rs",
    "ldso/src/x86_64_general_initial_graph.rs",
    "ldso/src/x86_64_general_initial_lifecycle.rs",
    "ldso/src/x86_64_direct_entry.rs", "ldso/src/x86_64_runtime_lock.rs",
    "ldso/src/x86_64_initial_worker_tls.rs", "ldso/src/x86_64_runtime_registry.rs",
    "libc/Cargo.toml", "libc/src/c_abi/x86_64/static_c_abi.rs",
    "libc/src/c_abi/x86_64/general_dlfcn.rs",
    "libc/src/c_abi/x86_64/dynamic_tls.rs",
    "libc/src/c_abi/x86_64/pthread_create_join.rs",
    "crt/src/x86_64_dynamic_startup.rs",
    "compat/x86_64/loader_runtime_registry_evidence.py",
    "compat/x86_64/loader_debug_abi_evidence.py",
    "compat/x86_64/owned_posix_product_evidence.py", IMAGE_MANIFEST_SOURCE,
)
SOURCE_ALGORITHM_PATHS = (
    "ldso/Cargo.toml", "ldso/build.rs", "ldso/src/x86_64_initial_graph.rs",
    "ldso/src/x86_64_general_initial_graph.rs",
    "ldso/src/x86_64_general_initial_lifecycle.rs",
    "ldso/src/x86_64_direct_entry.rs", "ldso/src/x86_64_runtime_lock.rs",
    "ldso/src/x86_64_initial_worker_tls.rs", "ldso/src/x86_64_runtime_registry.rs",
    "libc/Cargo.toml", "libc/src/c_abi/x86_64/static_c_abi.rs",
    "libc/src/c_abi/x86_64/general_dlfcn.rs",
    "libc/src/c_abi/x86_64/dynamic_tls.rs",
    "libc/src/c_abi/x86_64/pthread_create_join.rs",
    "crt/src/x86_64_dynamic_startup.rs",
)
# These are hashes of comment-elided, brace-balanced selected bodies reviewed
# with this receipt contract.  String and character literals remain present:
# cfg feature spellings and resolver names are source semantics, not comment
# noise.  They are deliberately not the collection's self-retained source
# hash: they bind the finite source algorithms below, while the source cohort
# separately binds the complete current checkout.  A source change therefore
# needs an explicit contract review rather than merely resealing its own bytes.
REVIEWED_FUNCTION_FINGERPRINTS = {
    "graph_run": "621bee5b4b83e030e8d9b01f084f9d03d48dac6d54e6a1487f72e7fa09edd3bd",
    "graph_selected": "034855b63cc2c0142f667172acecd2175ed812abd43c9c4f2662f08c65fc3488",
    "crt_tail": "7afc978d54e383ded07b7a6f220b4f600f6ba8146770a9231a679b2733de062f",
    "lock_atomic_acquire": "0b271ab321a5dbdcfa0a166dbf08b7e44cee4bb1b3b9bb8cb65097759361256a",
    "lock_runtime_acquire": "bba026a7267826ec2cb081217ee6d493ba3586a330b047d0c8b5c01e377b95be",
    "lock_runtime_drop": "6e5de7aff25767e3a28ed117c8ed37d13cc3a94ac1d8b8a928749bd2f7b91f46",
    "worker_tls_allocate": "28bd02edb866ccf4967b0b9088714ddbac5a2bc8125a0ca9f2da68a799265ade",
    "pthread_creator": "bd5e3c65105a1a20c158bd90cca9bd4244783aec5e983e66c362540bea2f2cee",
    "registry_runtime_function": "65032fa5c8f30985477192262e23cf77cff3b84b5a9ebf8a0dfbd0df70ecbf4d",
    "dlfcn_dlopen": "490cf95c67cec7a8c8197d7a9cef2309888f4d02349f0170f1edb57e33db488c",
    "dlfcn_dlsym": "4614bddb7798e9fbf0073bea8f13d7f94dc56ef60b99311ad9d71e41072083ed",
    "dlfcn_dlclose": "a301639c4ba11f3b889af23fadd76639667139edacec4bdab121b6e021636077",
    "dlfcn_dladdr": "9f5f5d24c84523e96f9e965618e066979313bd687c9752d640ba342721623e1c",
    "dlfcn_dlinfo": "0dd91517c082f16c322a5893f66006ddae008485c8545b336f05cd18d52816e5",
    "dlfcn_dl_iterate_phdr": "ee4cd3492be18dbc908d0d7668915a11ee92a4c46b96c3fa882539ef87a33156",
}
# `pthread_creator` remains this receipt's token-before-clone algorithm.  The
# native shadow additions reviewed in 795440db are a control-record field and
# a parent-side post-clone handshake, both gated by `native-mimalloc-shadow`.
# `static_c_abi.rs` rejects that feature with x86-owned-dynamic-runtime, so
# they do not change the selected dynamic route.  Worker entry and exit own
# allocator lifecycle behavior and are deliberately outside this receipt.
NATIVE_MIMALLOC_SHADOW_CONTROL_FIELD = (
    '#[cfg(feature = "native-mimalloc-shadow")]\n'
    '                native_mimalloc_attach: AtomicI32::new(NATIVE_MIMALLOC_ATTACH_PENDING),'
)
NATIVE_MIMALLOC_SHADOW_POST_CLONE_HANDSHAKE = (
    '#[cfg(feature = "native-mimalloc-shadow")]\n'
    '    match unsafe { selected_worker_native_mimalloc_attached(control) } {'
)
STATIC_ROLES = {
    "static_driver": "bin/crabc-cc",
    "static_crt1": "usr/lib/crt1.o",
    "static_rcrt1": "usr/lib/rcrt1.o",
    "static_crti": "usr/lib/crti.o",
    "static_crtn": "usr/lib/crtn.o",
    "static_libc": "usr/lib/libc.a",
    "static_builtins": "usr/lib/libcrabc-builtins.a",
}
DYNAMIC_ROLES = {
    "dynamic_driver": "bin/crabc-cc-dynamic",
    "dynamic_crt1": "usr/lib/crt1.o",
    "dynamic_scrt1": "usr/lib/Scrt1.o",
    "dynamic_crti": "usr/lib/crti.o",
    "dynamic_crtn": "usr/lib/crtn.o",
    "dynamic_libc": "usr/lib/libc.so",
    "dynamic_builtins": "usr/lib/libcrabc-builtins.a",
    "dynamic_attach": "usr/lib/crabc-dynamic-attach.o",
    "dynamic_loader": "lib/ld-crabc-x86_64.so.1",
}
INPUT_NAMES = (
    "reader", "runner", "contract", "documentation", "startup_probe",
    "registration_probe", "plugin_probe", "image_manifest", *IMAGE_INPUT_PATHS,
    *STATIC_ROLES, *DYNAMIC_ROLES, "static_preparation", "base_inventory",
    "full_facts", "loader_debug_report", "loader_runtime_registry_report",
)
SOURCE_FIELDS = ("revision", "tree", "source_sha256")
REPORT_FIELD_ORDER = (
    "schema", "status", "component", "target", "collection", "selected_source",
    "collector", "inputs", "selected_products", "static_preparation",
    "base_inventory", "full_facts", "source_contract", "source_cohort",
    "source_algorithm", "selected_runtime", "normal_consumer_matrix",
    "commands", "runtime", "artifacts", "coverage", "limits",
)
REPORT_FIELDS = set(REPORT_FIELD_ORDER)
COMMAND_ENVIRONMENT = {
    "LC_ALL": "C", "LANG": "C", "TZ": "UTC",
    "PATH": "/opt/cargo/bin:/opt/musl-1.2.6/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
}


class LoaderStructuralOwnerError(RuntimeError):
    """A finite loader structural-owner receipt does not reconstruct."""


def fail(message: str) -> None:
    raise LoaderStructuralOwnerError(f"loader structural-owner receipt: {message}")


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def same(left: object, right: object) -> bool:
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(same(value, right[key]) for key, value in left.items())
    if isinstance(left, list):
        return len(left) == len(right) and all(same(a, b) for a, b in zip(left, right))
    return left == right


def _physical_regular(path: Path, label: str) -> Path:
    try:
        return inventory.physical_regular(Path(path), label)
    except inventory.InventoryError as error:
        raise LoaderStructuralOwnerError(str(error)) from error


def _physical_directory(path: Path, label: str) -> Path:
    try:
        return inventory.physical_directory(Path(path), label)
    except inventory.InventoryError as error:
        raise LoaderStructuralOwnerError(str(error)) from error


def _read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        return inventory.read_json(path, label)
    except inventory.InventoryError as error:
        raise LoaderStructuralOwnerError(str(error)) from error


def _identity(path: Path, logical_path: str) -> dict[str, object]:
    try:
        return inventory.file_record(_physical_regular(path, logical_path), logical_path=logical_path)
    except inventory.InventoryError as error:
        raise LoaderStructuralOwnerError(str(error)) from error


def _sha256(path: Path) -> str:
    return hashlib.sha256(_physical_regular(path, "hashed input").read_bytes()).hexdigest()


def _exact(value: object, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        fail(f"{label} fields changed")
    return value


def _git(root: Path, *args: str) -> str:
    try:
        return subprocess.check_output(
            ["git", "-c", f"safe.directory={root}", *args], cwd=root, stderr=subprocess.PIPE,
        ).decode("ascii").strip()
    except (OSError, subprocess.CalledProcessError, UnicodeDecodeError) as error:
        raise LoaderStructuralOwnerError("cannot read current source Git identity") from error


def current_source_identity(root: Path = ROOT) -> dict[str, str]:
    root = _physical_directory(root, "component checkout")
    try:
        seal = inventory.collector_source_seal()
    except inventory.InventoryError as error:
        raise LoaderStructuralOwnerError(str(error)) from error
    revision = _git(root, "rev-parse", "HEAD")
    tree = _git(root, "rev-parse", "HEAD^{tree}")
    require(seal == inventory.collector_source_seal(), "current collector source changed while reading identity")
    require(seal["revision"] == revision and seal["clean"] is True, "current source is not one clean checkout")
    return {"revision": revision, "tree": tree, "source_sha256": str(seal["content_sha256"])}


def component_projection() -> dict[str, object]:
    return {
        "identities": list(IDENTITIES),
        "component_complete": True,
        "family_completion": False,
        "runtime_qualification": False,
        "promotion_ready": False,
        "public_support": False,
    }


def rust_function_body(text: str, marker: str) -> str:
    """Extract one brace-balanced Rust body; a file-wide search is not proof."""
    code = _rust_code(text)
    selected = _rust_code(marker)
    start = code.find(selected)
    require(start >= 0 and code.count(selected) == 1, f"selected function is absent or duplicated: {marker}")
    brace = code.find("{", start)
    require(brace >= 0, f"selected function has no body: {marker}")
    depth = 0
    quote: str | None = None
    escaped = False
    line_comment = False
    block_comment = 0
    index = brace
    while index < len(text):
        character = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if line_comment:
            if character == "\n":
                line_comment = False
        elif block_comment:
            if character == "/" and following == "*":
                block_comment += 1
                index += 1
            elif character == "*" and following == "/":
                block_comment -= 1
                index += 1
        elif quote is not None:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
        elif character == "/" and following == "/":
            line_comment = True
            index += 1
        elif character == "/" and following == "*":
            block_comment = 1
            index += 1
        elif character == "\"" or (character == "'" and _single_quoted_literal(text, index)):
            quote = character
        elif character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return text[brace:index + 1]
        index += 1
    fail(f"selected function body is unbalanced: {marker}")


def _reviewed_body(name: str, body: str) -> None:
    actual = hashlib.sha256(_rust_without_comments(body).encode("utf-8")).hexdigest()
    require(actual == REVIEWED_FUNCTION_FINGERPRINTS[name],
            f"reviewed selected source body differs: {name}")


def _single_quoted_literal(text: str, opening: int) -> bool:
    """Distinguish a Rust character literal from a lifetime such as ``'static``.

    This deliberately small lexer only needs to identify brace-bearing source
    bodies.  A lifetime reaches a Rust token delimiter before another quote;
    a character literal closes first (including a short escape).  It avoids
    treating the selected function's return lifetime as an unterminated string.
    """
    escaped = False
    for index in range(opening + 1, min(len(text), opening + 64)):
        character = text[index]
        if escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == "'":
            return True
        elif character.isspace() or character in ";,(){}[]":
            return False
    return False


def _rust_code(text: str) -> str:
    """Erase comments and quoted text without changing source offsets."""
    result = list(text)
    quote: str | None = None
    escaped = False
    line_comment = False
    block_comment = 0
    index = 0
    while index < len(text):
        character = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if line_comment:
            if character == "\n":
                line_comment = False
            else:
                result[index] = " "
        elif block_comment:
            result[index] = " "
            if character == "/" and following == "*":
                result[index + 1] = " "
                block_comment += 1
                index += 1
            elif character == "*" and following == "/":
                result[index + 1] = " "
                block_comment -= 1
                index += 1
        elif quote is not None:
            result[index] = " "
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
        elif character == "/" and following == "/":
            result[index] = result[index + 1] = " "
            line_comment = True
            index += 1
        elif character == "/" and following == "*":
            result[index] = result[index + 1] = " "
            block_comment = 1
            index += 1
        elif character == "\"" or (character == "'" and _single_quoted_literal(text, index)):
            result[index] = " "
            quote = character
        index += 1
    return "".join(result)


def _rust_without_comments(text: str) -> str:
    """Erase Rust comments while retaining attribute string literals."""
    result = list(text)
    quote: str | None = None
    escaped = False
    line_comment = False
    block_comment = 0
    index = 0
    while index < len(text):
        character = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if line_comment:
            if character == "\n":
                line_comment = False
            else:
                result[index] = " "
        elif block_comment:
            result[index] = " "
            if character == "/" and following == "*":
                result[index + 1] = " "
                block_comment += 1
                index += 1
            elif character == "*" and following == "/":
                result[index + 1] = " "
                block_comment -= 1
                index += 1
        elif quote is not None:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
        elif character == "\"" or (character == "'" and _single_quoted_literal(text, index)):
            quote = character
        elif character == "/" and following == "/":
            result[index] = result[index + 1] = " "
            line_comment = True
            index += 1
        elif character == "/" and following == "*":
            result[index] = result[index + 1] = " "
            block_comment = 1
            index += 1
        index += 1
    return "".join(result)


def _matching_brace(code: str, opening: int, label: str) -> int:
    require(opening < len(code) and code[opening] == "{", f"{label} block is malformed")
    depth = 0
    for index in range(opening, len(code)):
        if code[index] == "{":
            depth += 1
        elif code[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    fail(f"{label} block is unbalanced")


def _false_guard_ranges(code: str) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    for match in re.finditer(r"\bif\s+(?:false|0\s*==\s*1)\s*\{", code):
        opening = code.find("{", match.start(), match.end())
        ranges.append((opening, _matching_brace(code, opening, "false selected branch")))
    return ranges


def _ordered(body: str, terms: Sequence[str], label: str) -> list[int]:
    code = _rust_code(body)
    false_ranges = _false_guard_ranges(code)
    offsets = []
    for term in terms:
        offset = code.find(term)
        require(offset >= 0, f"{label} omits {term}")
        require(code.count(term) == 1, f"{label} duplicates {term}")
        require(not any(start < offset < end for start, end in false_ranges),
                f"{label} places {term} in an unselected false branch")
        offsets.append(offset)
    require(offsets == sorted(offsets), f"{label} order changed")
    return offsets


def validate_selected_graph_body(body: str) -> dict[str, object]:
    terms = (
        "discover_needed(graph, objects, 0)",
        "select_canonical_initial_libc(graph, objects)",
        "state.plan_initial_tls()",
        "relocate_initial_graph_with_debugger(graph, objects, &debugger)",
        "state.mark_relocated()",
        "protect_segments(&objects[index])",
        "apply_relro(&objects[index])",
        "apply_self_relro(ldso_base as u64)",
        "preflight_dependency_initializers(graph, objects)",
        "PreparedInitialRegistry::prepare(",
        "state.attach_lifecycle(",
        "state.reserve_publication()",
        "state.reserve_runtime_v1_publication()",
        "state.reserve_conventional_startup_publication()",
        "state.materialize_initial_tls()",
        "let conventional_startup = unsafe { state.commit_runtime_v1(installed) };",
        "runtime_registry.publish(ldso_base)",
        "jump(main_entry as usize, sp)",
    )
    offsets = _ordered(body, terms, "selected graph")
    require("#[cfg(not(all(crabc_general_initial_lifecycle, crabc_dynamic_main_thread_runtime_v1)))]\n    unsafe { dispatch_dependency_initializers(&initializers) };" in body,
            "selected graph does not constrain in-function constructor dispatch")
    return {"function": "run_with_initial_tls", "ordered_terms": list(terms), "offsets": offsets}


def validate_feature_routes(ldso_cargo: str, libc_cargo: str, graph: str, static_c_abi: str) -> None:
    try:
        ldso_features = tomllib.loads(ldso_cargo)["features"]
        libc_features = tomllib.loads(libc_cargo)["features"]
    except (tomllib.TOMLDecodeError, KeyError, TypeError) as error:
        raise LoaderStructuralOwnerError("selected feature manifest is malformed") from error
    require(ldso_features.get("x86_64-owned-dynamic-runtime") == [
        "x86_64-general-initial-lifecycle",
        "x86_64-general-initial-tls-runtime-v1-dynamic-main-thread-interpreter",
    ] and "x86-owned-dynamic-runtime" not in ldso_features, "ldso feature route differs")
    require(libc_features.get("x86-owned-dynamic-runtime") == ["x86-owned-static-runtime"]
            and "x86_64-owned-dynamic-runtime" not in libc_features, "libc feature route differs")
    graph_body = rust_function_body(graph, "pub(super) unsafe fn run")
    graph_code = _rust_without_comments(graph_body)
    require(graph_code.count('#[cfg(feature = "x86_64-owned-dynamic-runtime")]') >= 1,
            "selected ldso graph is not gated by its crate feature")
    static_code = _rust_without_comments(static_c_abi)
    module = '#[cfg_attr(feature = "x86-owned-dynamic-runtime", path = "general_dlfcn.rs")]\n#[cfg_attr(not(feature = "x86-owned-dynamic-runtime"), path = "fixed_graph_dlfcn.rs")]\nmod fixed_graph_dlfcn;'
    require(static_code.count(module) == 1, "selected libc dlfcn module route differs")


def validate_runtime_lock_source(lock: str) -> None:
    code = _rust_code(lock)
    require(code.count("static LOCK: AtomicI32 = AtomicI32::new(0);") == 1,
            "always-atomic graph lock declaration differs")
    acquire = rust_function_body(lock, "fn acquire(lock: &AtomicI32)")
    _ordered(acquire, ("lock.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)",), "always-atomic graph lock")
    _reviewed_body("lock_atomic_acquire", acquire)
    runtime_impl = lock[lock.find("impl RuntimeGuard"):]
    runtime_acquire = rust_function_body(runtime_impl, "pub(super) fn acquire()")
    require(_rust_code(runtime_acquire).count("acquire(&LOCK);") == 1,
            "RuntimeGuard acquire bypasses the graph lock")
    _reviewed_body("lock_runtime_acquire", runtime_acquire)
    runtime_drop = lock[lock.find("impl Drop for RuntimeGuard"):]
    drop = rust_function_body(runtime_drop, "fn drop(&mut self)")
    require(_rust_code(drop).count("release(&LOCK);") == 1,
            "RuntimeGuard release bypasses the graph lock")
    _reviewed_body("lock_runtime_drop", drop)


def validate_native_shadow_creator_handoff(body: str) -> None:
    """Keep the optional native-shadow handoff out of the selected dynamic route."""
    # Unlike `_rust_code`, this preserves cfg string literals for the exact
    # feature spelling while still excluding comments from the source proof.
    code = _rust_without_comments(body)
    require(code.count(NATIVE_MIMALLOC_SHADOW_CONTROL_FIELD) == 1,
            "native shadow control field guard differs")
    require(code.count(NATIVE_MIMALLOC_SHADOW_POST_CLONE_HANDSHAKE) == 1,
            "native shadow post-clone handshake guard differs")
    _ordered(body, (
        "__crabc_x86_pthread_clone(",
        "selected_worker_native_mimalloc_attached(control)",
    ), "native shadow post-clone handshake")


def validate_registry_body(body: str) -> None:
    expected = runtime_registry.RESOLVERS
    found = dict(re.findall(r'b"([^"]+)"\s*=>\s*Some\((\w+)\s+as\s+\*const\s*\(\)', _rust_without_comments(body)))
    require(found == expected, "selected runtime registry resolver target differs")
    _reviewed_body("registry_runtime_function", body)


def _source(root: Path, relative: str) -> str:
    return _physical_regular(root / relative, f"source {relative}").read_text(encoding="utf-8")


def _braced_body(text: str, marker: str, description: str) -> str:
    """Return the one selected non-function Rust branch body."""
    code = _rust_code(text)
    start = text.find(marker)
    require(start >= 0 and text.count(marker) == 1,
            f"selected {description} is absent or duplicated")
    brace = code.find("{", start)
    require(brace >= 0, f"selected {description} has no body")
    depth = 0
    for index in range(brace, len(code)):
        if code[index] == "{":
            depth += 1
        elif code[index] == "}":
            depth -= 1
            if depth == 0:
                return text[brace:index + 1]
    fail(f"selected {description} body is unbalanced")


def validate_build_feature_routes(build: str) -> None:
    """Bind the selected Cargo feature branches to their five exact cfgs."""
    lifecycle = _braced_body(build,
        'if std::env::var_os("CARGO_FEATURE_X86_64_GENERAL_INITIAL_LIFECYCLE").is_some()',
        'initial lifecycle build feature branch')
    require(re.findall(r'cargo::rustc-cfg=([^"]+)', _rust_without_comments(lifecycle))
            == ['crabc_general_initial_lifecycle'], 'initial lifecycle build cfg differs')
    feature = 'CARGO_FEATURE_X86_64_GENERAL_INITIAL_TLS_RUNTIME_V1_DYNAMIC_MAIN_THREAD_INTERPRETER'
    branch = _braced_body(build, f'if std::env::var_os(\n        "{feature}",\n    )\n    .is_some()',
                          'dynamic main interpreter build feature branch')
    cfgs = (
        'crabc_general_initial_graph', 'crabc_general_initial_tls_materialization_v1',
        'crabc_general_loader_libc_tls_runtime_v1', 'crabc_dynamic_main_thread_runtime_v1',
    )
    require(re.findall(r'cargo::rustc-cfg=([^"]+)', _rust_without_comments(branch)) == list(cfgs),
            'dynamic main interpreter build cfg route differs')


def validate_dynamic_tls_bridge(body: str) -> None:
    code = _rust_code(body)
    call = '__crabc_x86_64_initial_tls_allocate(block.as_mut_ptr())'
    require(code.count(call) == 1 and _ordered(body, ('if !is_ready()', call, 'Some(unsafe { block.assume_init() })'),
            'selected dynamic TLS allocation bridge'),
            'selected dynamic TLS allocation bridge differs')


def validate_dlfcn_routes(dlfcn: str, registry: str) -> None:
    """Bind installed public dlfcn leaves to the closed runtime registry table."""
    routes = (
        ('dlfcn_dlopen', 'pub unsafe extern "C" fn dlopen', '__crabc_x86_64_runtime_open(', 'runtime_open'),
        ('dlfcn_dlsym', 'unsafe extern "C" fn __crabc_x86_general_dlsym', '__crabc_x86_64_runtime_symbol(', 'runtime_symbol'),
        ('dlfcn_dlclose', 'pub unsafe extern "C" fn dlclose', '__crabc_x86_64_runtime_close(', 'runtime_close'),
        ('dlfcn_dladdr', 'pub unsafe extern "C" fn dladdr', '__crabc_x86_64_runtime_address(', 'runtime_address_info'),
        ('dlfcn_dlinfo', 'pub unsafe extern "C" fn dlinfo', '__crabc_x86_64_runtime_information(', 'runtime_information'),
        ('dlfcn_dl_iterate_phdr', 'pub unsafe extern "C" fn dl_iterate_phdr', '__crabc_x86_64_runtime_iterate(', 'runtime_iterate'),
    )
    registry_body = rust_function_body(registry, 'pub(super) fn runtime_function')
    registry_code = _rust_without_comments(registry_body)
    for fingerprint, marker, import_name, target in routes:
        route = f'b"{import_name.removesuffix("(")}" => Some({target} as *const () as usize as u64)'
        body = rust_function_body(dlfcn, marker)
        require(_rust_code(body).count(import_name) == 1 and registry_code.count(route) == 1,
                f'selected dlfcn runtime route differs: {marker}')
        _reviewed_body(fingerprint, body)


def validate_source_algorithms(root: Path = ROOT) -> dict[str, object]:
    root = _physical_directory(root, "component checkout")
    graph = _source(root, "ldso/src/x86_64_general_initial_graph.rs")
    build = _source(root, "ldso/build.rs")
    validate_build_feature_routes(build)
    run = rust_function_body(graph, "pub(super) unsafe fn run")
    selected = rust_function_body(graph, "unsafe fn run_with_initial_tls")
    validate_feature_routes(
        _source(root, "ldso/Cargo.toml"), _source(root, "libc/Cargo.toml"), graph,
        _source(root, "libc/src/c_abi/x86_64/static_c_abi.rs"),
    )
    _ordered(run, (
        "x86_64_direct_entry::prepare(sp, ldso_base)",
        "run_with_initial_tls(main, main_entry, sp, ldso_base)",
    ), "selected run entry")
    require("parse_mapped(main_base, main_phdr, main_phnum, ObjectRole::Main, false, true)" in run,
            "selected kernel entry branch is absent")
    graph_order = validate_selected_graph_body(selected)
    _reviewed_body("graph_run", run)
    _reviewed_body("graph_selected", selected)
    lifecycle = _source(root, "ldso/src/x86_64_general_initial_lifecycle.rs")
    crt = _source(root, "crt/src/x86_64_dynamic_startup.rs")
    require("dependency_constructors: owned_dependency_constructors" in lifecycle,
            "selected lifecycle does not retain owned constructor plan")
    crt_body = rust_function_body(crt, "pub unsafe extern \"C\" fn __crabc_x86_64_dynamic_executable_init")
    _ordered(crt_body, (
        "__crabc_preinit_array_start_address()", "if let Some(callback) = dependency_constructors",
        "callback();", "_init();", "__crabc_init_array_start_address()",
    ), "owned CRT constructor tail")
    _reviewed_body("crt_tail", crt_body)
    lock = _source(root, "ldso/src/x86_64_runtime_lock.rs")
    validate_runtime_lock_source(lock)
    worker = _source(root, "ldso/src/x86_64_initial_worker_tls.rs")
    dynamic_tls = _source(root, "libc/src/c_abi/x86_64/dynamic_tls.rs")
    validate_dynamic_tls_bridge(rust_function_body(dynamic_tls, "pub(super) unsafe fn allocate_thread"))
    allocate = rust_function_body(worker, "unsafe extern \"C\" fn allocate")
    _ordered(allocate, ("let _guard = Guard::acquire();", "materialize_initial_tls(", "register_allocation("),
             "selected worker TLS token")
    _reviewed_body("worker_tls_allocate", allocate)
    pthread = _source(root, "libc/src/c_abi/x86_64/pthread_create_join.rs")
    creator = rust_function_body(pthread, "unsafe fn create_selected_worker_with_attributes")
    _ordered(creator, ("static_tls::allocate_thread()", "__crabc_x86_pthread_clone("), "selected worker clone")
    validate_native_shadow_creator_handoff(creator)
    _reviewed_body("pthread_creator", creator)
    dlfcn = _source(root, "libc/src/c_abi/x86_64/general_dlfcn.rs")
    registry = _source(root, "ldso/src/x86_64_runtime_registry.rs")
    validate_dlfcn_routes(dlfcn, registry)
    for name in (
        "__crabc_x86_64_runtime_open", "__crabc_x86_64_runtime_symbol",
        "__crabc_x86_64_runtime_close", "__crabc_x86_64_runtime_address",
        "__crabc_x86_64_runtime_information", "__crabc_x86_64_runtime_iterate",
    ):
        require(f"fn {name}(" in dlfcn and f'b"{name}"' in registry,
                f"selected direct dlfcn route omits {name}")
    validate_registry_body(rust_function_body(registry, "pub(super) fn runtime_function"))
    return {
        "ldso_feature": "x86_64-owned-dynamic-runtime",
        "libc_feature": "x86-owned-dynamic-runtime",
        "selected_graph": "ldso/src/x86_64_general_initial_graph.rs::run_with_initial_tls",
        "graph_order": graph_order,
        "direct_entry_and_kernel_branch": True,
        "owned_crt_constructor_tail": True,
        "always_atomic_graph_lock": True,
        "worker_tls_token_before_clone": True,
        "direct_dlfcn_registry_route": True,
        "build_feature_cfg_closure": True,
        "dynamic_tls_allocate_bridge": True,
    }


def project_structural_facts(rows: Sequence[Mapping[str, Any]]) -> dict[str, object]:
    """Filter named candidates only after retaining the complete fact input."""
    startup: list[dict[str, object]] = []
    candidate: list[dict[str, object]] = []
    for index, row in enumerate(rows):
        raw = row.get("row")
        if not isinstance(raw, Mapping):
            fail("complete fact row is malformed")
        name = raw.get("name")
        if name not in IDENTITIES:
            continue
        if name in STARTUP_IDENTITIES:
            required = (row.get("artifact_key") == "reference-shared" and row.get("table") in {".dynsym", ".symtab"}
                        and row.get("role") == "definition" and raw.get("type") == "FUNC"
                        and raw.get("binding") == "GLOBAL" and raw.get("visibility") == "DEFAULT")
            require(required, f"reference startup occurrence differs: {name}")
            startup.append({"source_index": index, "identity": name, "table": str(row["table"])})
        else:
            candidate.append({"source_index": index, "identity": name})
    require(len(startup) == 6, "reference startup occurrence count differs")
    require({item["identity"] for item in startup} == set(STARTUP_IDENTITIES)
            and {item["table"] for item in startup} == {".dynsym", ".symtab"},
            "reference startup table coverage differs")
    require(not candidate, "invented candidate occurrence for structural identity")
    return {
        "full_occurrence_count": len(rows),
        "unnamed_occurrence_count": sum(raw.get("name") is None
                                         for raw in (row["row"] for row in rows)
                                         if isinstance(raw, Mapping)),
        "named_identity_filter": list(IDENTITIES),
        "reference_startup_rows": len(startup),
        "candidate_rows": candidate,
    }


def _flatten_fact_rows(facts: Mapping[str, Any]) -> list[dict[str, Any]]:
    observed: list[dict[str, Any]] = []
    source = facts.get("facts")
    require(isinstance(source, Mapping), "complete ELF facts have no fact roster")
    for artifact, value in source.items():
        units = value if isinstance(value, list) else [value]
        require(isinstance(units, list) and units,
                "complete ELF fact artifact is malformed")
        for unit in units:
            require(isinstance(unit, Mapping), "complete ELF fact archive member is malformed")
            archive_member: dict[str, object] = {}
            if isinstance(value, list):
                for key in ("member", "member_index", "member_occurrence"):
                    require(key in unit, "complete ELF fact archive member identity is malformed")
                    archive_member[key] = unit[key]
            tables = unit.get("symbol_tables")
            require(isinstance(tables, list), "complete ELF fact table roster is malformed")
            for table in tables:
                require(isinstance(table, Mapping) and isinstance(table.get("name"), str)
                        and isinstance(table.get("rows"), list), "complete ELF fact table is malformed")
                for row in table["rows"]:
                    require(isinstance(row, Mapping), "complete ELF fact row is malformed")
                    observed.append({"artifact_key": artifact, "table": table["name"],
                                     "role": "definition" if row.get("section_index") != "UND" else "import",
                                     "archive_member": archive_member, "row": dict(row)})
    return observed


def _contract() -> dict[str, Any]:
    try:
        contract = tomllib.loads(_physical_regular(CONTRACT_PATH, "component contract").read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise LoaderStructuralOwnerError("component contract is unreadable") from error
    require(contract.get("schema") == "crabc.x86_64-loader-structural-owner-contract/v1"
        and contract.get("id") == "x86-loader-structural-owner"
        and contract.get("status") == "implemented-unqualified" and contract.get("target") == TARGET,
            "component contract identity differs")
    require(tuple(contract.get("selection", {}).get("identities", ())) == IDENTITIES
            and contract["selection"].get("expected_placements") == [],
            "component contract identity scope differs")
    implementation = _exact(contract.get("implementation"), {"reader", "runner", "probes", "replay"},
                            "component implementation contract")
    require(implementation["reader"] == READER_PATH and implementation["runner"] == RUNNER_PATH
            and implementation["probes"] == [*PROBE_SOURCES.values(), PLUGIN_SOURCE]
            and implementation["replay"] == "retained bytes and current same-clean-source supplied-product admission; no ambient target tools",
            "component implementation route differs")
    source_contract = _exact(contract.get("source_contract"), {"paths"}, "component source contract")
    require(tuple(source_contract["paths"]) == SOURCE_CONTRACT_PATHS, "component source contract roster differs")
    report = _exact(contract.get("report"), {"schema", "status", "fields", "coverage", "fact_filter", "limits"},
                    "component report contract")
    require(report["schema"] == SCHEMA and report["status"] == STATUS and tuple(report["fields"]) == REPORT_FIELD_ORDER,
            "component report identity differs")
    require(report["coverage"] == {"fields": ["identities", "groups", "fact_filter", "source_functions",
                                                  "selected_runtime_cells", "normal_consumer_cells", "normal_consumer_pairs"]}
            and report["fact_filter"] == {"fields": ["full_occurrence_count", "unnamed_occurrence_count",
                                                        "named_identity_filter", "reference_startup_rows", "candidate_rows"]}
            and report["limits"] == {"family_completion": False, "promotion_ready": False, "public_support": False,
                                      "runtime_qualification": False, "selector_admission": False},
            "component report contract fields differ")
    return contract


def _source_record(root: Path, output: Path, relative: str) -> dict[str, object]:
    source = _physical_regular(root / relative, f"source {relative}")
    destination = output / "retained/source" / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    os.chmod(destination, stat.S_IMODE(source.stat().st_mode))
    return {"path": relative, "sha256": _sha256(source), "size": source.stat().st_size,
            "mode": stat.S_IMODE(source.stat().st_mode), "retained": f"retained/source/{relative}"}


def _validate_source_record(root: Path, output: Path, relative: str, record: object) -> dict[str, object]:
    row = _exact(record, {"path", "sha256", "size", "mode", "retained"}, f"source record {relative}")
    require(row["path"] == relative and row["retained"] == f"retained/source/{relative}",
            f"source record path differs: {relative}")
    current = _physical_regular(root / relative, f"source {relative}")
    retained = _physical_regular(output / str(row["retained"]), f"retained source {relative}")
    expected = {"path": relative, "sha256": _sha256(current), "size": current.stat().st_size,
                "mode": stat.S_IMODE(current.stat().st_mode), "retained": row["retained"]}
    require(same(row, expected), f"current source differs: {relative}")
    require(retained.read_bytes() == current.read_bytes()
            and stat.S_IMODE(retained.stat().st_mode) == stat.S_IMODE(current.stat().st_mode),
            f"retained source differs: {relative}")
    return expected


def _input_paths(root: Path, *, static_product: Path, dynamic_product: Path, static_preparation: Path,
                 base_inventory: Path, full_facts: Path, loader_debug_report: Path,
                 loader_runtime_registry_report: Path, oracle_compiler: Path, musl_shared: Path) -> dict[str, Path]:
    values = {
        "reader": root / READER_PATH, "runner": root / RUNNER_PATH,
        "contract": root / CONTRACT_SOURCE, "documentation": root / DOCUMENTATION_SOURCE,
        "startup_probe": root / PROBE_SOURCES[PROBES[0]],
        "registration_probe": root / PROBE_SOURCES[PROBES[1]], "plugin_probe": root / PLUGIN_SOURCE,
        "image_manifest": root / IMAGE_MANIFEST_SOURCE,
        "oracle_compiler": oracle_compiler, "musl_shared": musl_shared,
        "timeout": Path(IMAGE_INPUT_PATHS["timeout"]), "chroot": Path(IMAGE_INPUT_PATHS["chroot"]),
    }
    values.update({name: static_product / relative for name, relative in STATIC_ROLES.items()})
    values.update({name: dynamic_product / relative for name, relative in DYNAMIC_ROLES.items()})
    values.update({
        "static_preparation": static_preparation, "base_inventory": base_inventory,
        "full_facts": full_facts, "loader_debug_report": loader_debug_report,
        "loader_runtime_registry_report": loader_runtime_registry_report,
    })
    require(tuple(values) == INPUT_NAMES, "component input roster differs")
    return values


def _trusted_image_manifest(root: Path) -> dict[str, object]:
    """Read the existing pinned-image authority for this exact invocation set."""
    manifest = _read_json(_physical_regular(root / IMAGE_MANIFEST_SOURCE, "pinned image manifest"),
                          "pinned image manifest")
    require(manifest.get("image") == PINNED_IMAGE and manifest.get("path") == COMMAND_ENVIRONMENT["PATH"],
            "pinned image manifest identity differs")
    files = manifest.get("files")
    require(isinstance(files, Mapping), "pinned image manifest file roster differs")
    for name, invocation in IMAGE_INPUT_PATHS.items():
        row = files.get(invocation)
        require(isinstance(row, Mapping) and set(row) == {"path", "sha256", "size", "mode"}
                and isinstance(row["path"], str) and Path(row["path"]).is_absolute()
                and all(type(row[field]) is int if field in {"size", "mode"} else isinstance(row[field], str)
                        for field in ("sha256", "size", "mode")),
                f"pinned image manifest input differs: {name}")
    return manifest


def _image_input_physical(source: Path, name: str, manifest: Mapping[str, object]) -> tuple[Path, Mapping[str, object]]:
    invocation = IMAGE_INPUT_PATHS[name]
    files = manifest["files"]
    require(isinstance(files, Mapping) and isinstance(files.get(invocation), Mapping),
            f"pinned image manifest input differs: {name}")
    expected = files[invocation]
    try:
        physical = Path(source).resolve(strict=True)
    except OSError as error:
        raise LoaderStructuralOwnerError(f"pinned image invocation is unavailable: {name}") from error
    require(physical == Path(str(expected["path"])), f"pinned image invocation target differs: {name}")
    current = _identity(physical, str(expected["path"]))
    require(all(current[field] == expected[field] for field in ("sha256", "size", "mode")),
            f"pinned image invocation bytes differ: {name}")
    return physical, expected


def _collector_path(root: Path, source: Path, name: str) -> str:
    """Use the one native checkout spelling or an exact image-owned path."""
    source = Path(source).absolute()
    if name in IMAGE_INPUT_PATHS:
        require(str(source) == IMAGE_INPUT_PATHS[name], f"image input path differs: {name}")
        return IMAGE_INPUT_PATHS[name]
    root = _physical_directory(root, "component checkout")
    source = (_physical_directory(source, f"component input {name}") if source.is_dir()
              else _physical_regular(source, f"component input {name}"))
    require(source.is_relative_to(root), f"component input escapes collector checkout: {name}")
    return str(Path(SOURCE_MOUNT) / source.relative_to(root))


def _native_collector(root: Path) -> bool:
    return str(Path(root).absolute()) == SOURCE_MOUNT


def _capture_inputs(root: Path, output: Path, **paths: Path) -> dict[str, object]:
    captured: dict[str, object] = {}
    image_manifest = _trusted_image_manifest(root)
    for name in INPUT_NAMES:
        source = _physical_regular(paths[name], f"component input {name}") if name not in IMAGE_INPUT_PATHS \
            else _image_input_physical(paths[name], name, image_manifest)[0]
        destination = output / "retained/inputs" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        os.chmod(destination, stat.S_IMODE(source.stat().st_mode))
        captured[name] = {
            "path": IMAGE_INPUT_PATHS[name] if name in IMAGE_INPUT_PATHS else _collector_path(root, source, name),
            "sha256": _sha256(source), "size": source.stat().st_size,
            "mode": stat.S_IMODE(source.stat().st_mode), "retained": f"retained/inputs/{name}",
        }
    return captured


def _validate_inputs(root: Path, output: Path, inputs: object, **paths: Path) -> dict[str, object]:
    require(isinstance(inputs, Mapping) and set(inputs) == set(INPUT_NAMES), "component input roster changed")
    image_manifest = _trusted_image_manifest(root)
    observed: dict[str, object] = {}
    for name in INPUT_NAMES:
        row = _exact(inputs[name], {"path", "sha256", "size", "mode", "retained"}, f"component input {name}")
        retained = _physical_regular(output / str(row["retained"]), f"retained component input {name}")
        require(row["retained"] == f"retained/inputs/{name}", f"retained component input path differs: {name}")
        retained_identity = {"sha256": _sha256(retained), "size": retained.stat().st_size,
                             "mode": stat.S_IMODE(retained.stat().st_mode)}
        require(all(row[key] == retained_identity[key] for key in retained_identity),
                f"retained component input differs: {name}")
        if name in IMAGE_INPUT_PATHS:
            expected = image_manifest["files"][IMAGE_INPUT_PATHS[name]]
            require(row["path"] == IMAGE_INPUT_PATHS[name]
                    and all(row[field] == expected[field] for field in ("sha256", "size", "mode")),
                    f"image input path differs: {name}")
            if _native_collector(root):
                source, _expected = _image_input_physical(paths[name], name, image_manifest)
                require(source.read_bytes() == retained.read_bytes()
                        and stat.S_IMODE(source.stat().st_mode) == retained_identity["mode"],
                        f"current image input differs: {name}")
        else:
            source = _physical_regular(paths[name], f"component input {name}")
            require(row["path"] == _collector_path(root, source, name)
                    and source.read_bytes() == retained.read_bytes()
                    and stat.S_IMODE(source.stat().st_mode) == retained_identity["mode"],
                    f"current component input differs: {name}")
        expected = {"path": row["path"], **retained_identity, "retained": row["retained"]}
        observed[name] = expected
    return observed


def _validate_input_modes(inputs: Mapping[str, Any]) -> None:
    for role, relative in STATIC_ROLES.items():
        if role == "static_driver":
            require(inputs[role]["mode"] & 0o111, "selected static driver is not executable")
        else:
            require(inputs[role]["mode"] == product_evidence.STATIC_LINK_INPUT_MODES[relative],
                    f"selected static link-input mode differs: {relative}")
    for role, relative in DYNAMIC_ROLES.items():
        if role in {"dynamic_driver", "dynamic_loader"}:
            require(inputs[role]["mode"] & 0o111, f"selected {role} is not executable")
        else:
            require(inputs[role]["mode"] == product_evidence.DYNAMIC_LINK_INPUT_MODES[relative],
                    f"selected dynamic link-input mode differs: {relative}")


def _validate_upstream(root: Path, *, base_inventory: Path, full_facts: Path, static_preparation: Path,
                       static_product: Path, dynamic_product: Path, loader_debug_report: Path,
                       loader_runtime_registry_report: Path) -> dict[str, object]:
    try:
        facts = elf_facts.validate_report(full_facts, base_inventory=base_inventory, static_product=static_product,
                                          dynamic_product=dynamic_product, static_preparation=static_preparation)
        loader_debug.validate_report(loader_debug_report)
        registry = runtime_registry.validate_report(
            loader_runtime_registry_report, base_inventory=base_inventory, elf_report=full_facts,
            static_preparation=static_preparation, static_product=static_product,
            dynamic_product=dynamic_product,
        )
    except (inventory.InventoryError, runtime_registry.RuntimeRegistryEvidenceError,
            loader_debug.EvidenceError, OSError, ValueError, KeyError, TypeError) as error:
        raise LoaderStructuralOwnerError("supplied product or nested receipt is not current and valid") from error
    facts_projection = project_structural_facts(_flatten_fact_rows(facts))
    return {
        "base_inventory": _identity(base_inventory, "base-inventory-report.json"),
        "full_facts": _identity(full_facts, "full-elf-facts-report.json"),
        "static_preparation": _identity(static_preparation, "static-preparation.json"),
        "loader_debug": _identity(loader_debug_report, "loader-debug-report.json"),
        "loader_runtime_registry": _identity(loader_runtime_registry_report, "loader-runtime-registry-report.json"),
        "facts_projection": facts_projection,
        "registry_schema": registry["schema"],
    }


def _command_names() -> tuple[str, ...]:
    result = ["compile-startup-entry-public-dlfcn", "compile-registration-replacement-before-worker", "compile-plugin",
              "link-plugin-pinned-musl-1.2.6", "link-plugin-candidate"]
    for probe in PROBES:
        for lane in LANES:
            for mode in MODES:
                prefix = f"{probe}-{lane}-{mode}"
                result.extend((f"{prefix}-link", f"{prefix}-run"))
    return tuple(result)


PROBE_STDOUT = {
    "startup-entry-public-dlfcn": b"loader-structural-startup-public-dlfcn-ok\n",
    "registration-replacement-before-worker": b"loader-structural-registration-before-worker-ok\n",
}


def _expected_command_argv(name: str, collector_output: str, inputs: Mapping[str, object]) -> list[str]:
    """Rebuild each finite native command from retained role paths and cell names."""
    require(name in _command_names(), f"unknown component command: {name}")
    output = Path(collector_output)
    paths = {role: str(_exact(inputs[role], {"path", "sha256", "size", "mode", "retained"},
                                      f"component input {role}")["path"])
             for role in INPUT_NAMES}
    compile_rows = {
        "compile-startup-entry-public-dlfcn": [paths["dynamic_driver"], "--dynamic-pie", "-std=c11", "-fno-builtin",
                                                "-fno-stack-protector", "-pthread", "-c", paths["startup_probe"], "-o",
                                                str(output / "objects/startup-entry-public-dlfcn.o")],
        "compile-registration-replacement-before-worker": [paths["dynamic_driver"], "--dynamic-pie", "-std=c11", "-fno-builtin",
                                                              "-fno-stack-protector", "-pthread", "-c", paths["registration_probe"], "-o",
                                                              str(output / "objects/registration-replacement-before-worker.o")],
        "compile-plugin": [paths["dynamic_driver"], "--dynamic-shared-object", "-std=c11", "-fno-builtin",
                            "-fno-stack-protector", "-c", paths["plugin_probe"], "-o",
                            str(output / "objects/loader-structural-owner-plugin.o")],
        "link-plugin-candidate": [paths["dynamic_driver"], "--dynamic-shared-object",
                                  str(output / "objects/loader-structural-owner-plugin.o"), "-o",
                                  str(output / "plugins/candidate-plugin.so")],
        "link-plugin-pinned-musl-1.2.6": [paths["oracle_compiler"], "-shared",
                                            str(output / "objects/loader-structural-owner-plugin.o"), "-o",
                                            str(output / "plugins/pinned-musl-plugin.so")],
    }
    if name in compile_rows:
        return compile_rows[name]
    match = re.fullmatch(
        r"(startup-entry-public-dlfcn|registration-replacement-before-worker)-(pinned-musl-1\.2\.6|candidate)-"
        r"(dynamic-pie-kernel|dynamic-pie-direct|dynamic-non-pie-kernel|dynamic-non-pie-direct)-(link|run)", name)
    require(match is not None, f"component command name is malformed: {name}")
    probe, lane, mode, action = match.groups()
    link_mode = "pie" if mode.startswith("dynamic-pie-") else "non-pie"
    directory = output / "executables" / probe / lane / mode
    consumer = str(directory / "consumer")
    if action == "link":
        if lane == "candidate":
            return [paths["dynamic_driver"], f"--dynamic-{link_mode}", "-pthread",
                    str(output / "objects" / f"{probe}.o"), "-o", consumer]
        flags = ["-fPIE", "-pie"] if link_mode == "pie" else ["-fno-pie", "-no-pie"]
        return [paths["oracle_compiler"], "-pthread", *flags,
                "-Wl,--dynamic-linker,/lib/ld-musl-x86_64.so.1", str(output / "objects" / f"{probe}.o"), "-o", consumer]
    root = str(output / "roots" / probe / lane / mode)
    executable = "/consumer" if mode.endswith("-kernel") else (
        "/lib/ld-crabc-x86_64.so.1" if lane == "candidate" else "/lib/ld-musl-x86_64.so.1")
    return [paths["timeout"], "30", paths["chroot"], root, executable, *([] if executable == "/consumer" else ["/consumer"])]


def _expected_command_streams(name: str) -> tuple[bytes, bytes]:
    for probe, stdout in PROBE_STDOUT.items():
        if name == f"{probe}-pinned-musl-1.2.6-dynamic-pie-kernel-run" or name == f"{probe}-candidate-dynamic-pie-kernel-run" \
                or name == f"{probe}-pinned-musl-1.2.6-dynamic-pie-direct-run" or name == f"{probe}-candidate-dynamic-pie-direct-run" \
                or name == f"{probe}-pinned-musl-1.2.6-dynamic-non-pie-kernel-run" or name == f"{probe}-candidate-dynamic-non-pie-kernel-run" \
                or name == f"{probe}-pinned-musl-1.2.6-dynamic-non-pie-direct-run" or name == f"{probe}-candidate-dynamic-non-pie-direct-run":
            return stdout, b""
    return b"", b""


def _read_command(output: Path, name: str, *, collector_output: str, inputs: Mapping[str, object]) -> dict[str, object]:
    directory = output / "commands"
    argv_path, stdout_path, stderr_path, status_path = (directory / f"{name}.{suffix}" for suffix in ("argv.json", "stdout", "stderr", "status"))
    argv = _read_json(argv_path, f"command {name} argv")
    expected_argv = _expected_command_argv(name, collector_output, inputs)
    expected_stdout, expected_stderr = _expected_command_streams(name)
    require(set(argv) == {"argv", "cwd", "environment", "stdin"}
            and argv["argv"] == expected_argv and argv["cwd"] == collector_output and argv["environment"] == COMMAND_ENVIRONMENT
            and argv["stdin"] == "/dev/null", f"command {name} invocation differs")
    for path in (stdout_path, stderr_path, status_path):
        _physical_regular(path, f"command {name} stream")
    require(status_path.read_bytes() == b"0\n", f"command did not succeed: {name}")
    require(stdout_path.read_bytes() == expected_stdout and stderr_path.read_bytes() == expected_stderr,
            f"command transcript differs: {name}")
    return {
        "argv": argv, "stdout": _identity(stdout_path, f"commands/{name}.stdout"),
        "stderr": _identity(stderr_path, f"commands/{name}.stderr"),
        "status": _identity(status_path, f"commands/{name}.status"),
    }


def _snapshot_tree(root: Path) -> list[dict[str, object]]:
    root = _physical_directory(root, "runtime root")
    rows: list[dict[str, object]] = []
    for path in [root, *sorted(root.rglob("*"))]:
        relative = "." if path == root else path.relative_to(root).as_posix()
        mode = stat.S_IMODE(path.lstat().st_mode)
        if path.is_symlink():
            rows.append({"path": relative, "kind": "symlink", "mode": mode, "target": os.readlink(path)})
        elif path.is_dir():
            rows.append({"path": relative, "kind": "directory", "mode": mode})
        elif path.is_file():
            rows.append({"path": relative, "kind": "regular", "mode": mode,
                         "size": path.stat().st_size, "sha256": _sha256(path)})
        else:
            fail(f"runtime root entry is not a regular file, directory, or symlink: {relative}")
    return rows


def capture_runtime_root(*, output: Path, root: Path, probe: str, lane: str, mode: str, phase: str) -> dict[str, object]:
    require(probe in PROBES and lane in LANES and mode in MODES and phase in {"before", "after"},
            "runtime root capture name differs")
    output = _physical_directory(output, "component output")
    root = _physical_directory(root, "runtime root")
    record = {"probe": probe, "lane": lane, "mode": mode, "phase": phase, "tree": _snapshot_tree(root)}
    destination = output / "runtime" / probe / lane / f"{mode}.{phase}.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(record, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return record


def _runtime_record(output: Path, probe: str, lane: str, mode: str, phase: str) -> dict[str, object]:
    relative = f"runtime/{probe}/{lane}/{mode}.{phase}.json"
    path = _physical_regular(output / relative, f"runtime root {probe}/{lane}/{mode}/{phase}")
    record = _read_json(path, f"runtime root {probe}/{lane}/{mode}/{phase}")
    require(record.get("probe") == probe and record.get("lane") == lane and record.get("mode") == mode
            and record.get("phase") == phase and isinstance(record.get("tree"), list),
            "runtime root record differs")
    return {"record": _identity(path, relative), "tree": record["tree"]}


def _tree_by_path(rows: object, label: str) -> dict[str, Mapping[str, object]]:
    require(isinstance(rows, list), f"{label} tree is malformed")
    result: dict[str, Mapping[str, object]] = {}
    for row in rows:
        require(isinstance(row, Mapping) and isinstance(row.get("path"), str) and row["path"] not in result,
                f"{label} tree row is malformed")
        result[str(row["path"])] = row
    return result


def _tree_file_identity(row: Mapping[str, object], label: str) -> dict[str, object]:
    require(row.get("kind") == "regular" and type(row.get("mode")) is int and type(row.get("size")) is int
            and isinstance(row.get("sha256"), str), f"{label} file identity differs")
    return {key: row[key] for key in ("mode", "size", "sha256")}


def _expected_pinned_tree(executable: Mapping[str, object], plugin: Mapping[str, object],
                          musl_shared: Mapping[str, object]) -> dict[str, dict[str, object]]:
    def directory() -> dict[str, object]:
        return {"kind": "directory", "mode": 0o755}
    def regular(identity: Mapping[str, object]) -> dict[str, object]:
        return {"kind": "regular", **{key: identity[key] for key in ("mode", "size", "sha256")}}
    return {
        ".": directory(), "lib": directory(), "usr": directory(), "usr/lib": directory(),
        "lib/ld-musl-x86_64.so.1": {"kind": "regular", "mode": 0o755,
                                      "size": musl_shared["size"], "sha256": musl_shared["sha256"]},
        "usr/lib/libc.so": {"kind": "regular", "mode": 0o755,
                              "size": musl_shared["size"], "sha256": musl_shared["sha256"]},
        "consumer": regular(executable), "usr/lib/libloader-structural-owner-plugin.so": regular(plugin),
    }


def _validate_runtime(output: Path, dynamic_product: Path, matrix: Mapping[str, object],
                      inputs: Mapping[str, object]) -> dict[str, object]:
    product_tree = _tree_by_path(_snapshot_tree(dynamic_product), "selected dynamic product")
    result: dict[str, object] = {}
    for probe in PROBES:
        probe_cells = _exact(matrix[probe], {"objects", "cells"}, f"normal consumer {probe}")["cells"]
        for lane in LANES:
            for mode in MODES:
                before = _runtime_record(output, probe, lane, mode, "before")
                after = _runtime_record(output, probe, lane, mode, "after")
                require(before["tree"] == after["tree"], f"runtime root changed: {probe}/{lane}/{mode}")
                cell = _exact(probe_cells[f"{lane}/{mode}"],
                              {"consumer_object", "plugin_object", "plugin_dso", "executable", "link_command", "runtime_command"},
                              f"normal consumer cell {probe}/{lane}/{mode}")
                tree = _tree_by_path(before["tree"], f"runtime root {probe}/{lane}/{mode}")
                consumer = _tree_file_identity(tree.get("consumer", {}), f"runtime consumer {probe}/{lane}/{mode}")
                require(consumer == {key: cell["executable"][key] for key in ("mode", "size", "sha256")},
                        f"runtime consumer does not bind sealed executable: {probe}/{lane}/{mode}")
                plugin = _tree_file_identity(tree.get("usr/lib/libloader-structural-owner-plugin.so", {}),
                                             f"runtime plugin {probe}/{lane}/{mode}")
                require(plugin == {key: cell["plugin_dso"][key] for key in ("mode", "size", "sha256")},
                        f"runtime plugin does not bind sealed DSO: {probe}/{lane}/{mode}")
                if lane == "candidate":
                    expected = {path: {key: value for key, value in row.items() if key != "path"}
                                for path, row in product_tree.items()}
                    require("consumer" not in expected and "usr/lib/libloader-structural-owner-plugin.so" not in expected,
                            "selected dynamic product already contains component runtime additions")
                    expected["consumer"] = {"kind": "regular", **consumer}
                    expected["usr/lib/libloader-structural-owner-plugin.so"] = {"kind": "regular", **plugin}
                else:
                    expected = _expected_pinned_tree(cell["executable"], cell["plugin_dso"],
                                                     _exact(inputs["musl_shared"], {"path", "sha256", "size", "mode", "retained"},
                                                            "pinned musl input"))
                if lane == "candidate":
                    actual = {path: {key: value for key, value in row.items() if key != "path"} for path, row in tree.items()}
                    require(actual == expected, f"candidate runtime root differs from selected product projection: {probe}/{mode}")
                else:
                    require(set(tree) == set(expected), f"pinned runtime root roster differs: {probe}/{mode}")
                    for path, expected_row in expected.items():
                        actual = {key: value for key, value in tree[path].items() if key != "path"}
                        require(actual == expected_row, f"pinned runtime root differs: {probe}/{mode}")
                result[f"{probe}/{lane}/{mode}"] = {"before": before["record"], "after": after["record"]}
    return result


def _normal_matrix(output: Path, commands: Mapping[str, object]) -> dict[str, object]:
    matrix: dict[str, object] = {}
    for probe in PROBES:
        objects = {
            "consumer": _identity(output / "objects" / f"{probe}.o", f"objects/{probe}.o"),
            "plugin": _identity(output / "objects" / "loader-structural-owner-plugin.o", "objects/loader-structural-owner-plugin.o"),
        }
        cells: dict[str, object] = {}
        for lane in LANES:
            for mode in MODES:
                key = f"{lane}/{mode}"
                prefix = f"{probe}-{lane}-{mode}"
                executable = _identity(output / "executables" / probe / lane / mode / "consumer",
                                       f"executables/{probe}/{lane}/{mode}/consumer")
                plugin_dso = _identity(output / "plugins" / ("candidate-plugin.so" if lane == "candidate" else "pinned-musl-plugin.so"),
                                       f"plugins/{'candidate-plugin.so' if lane == 'candidate' else 'pinned-musl-plugin.so'}")
                cells[key] = {"consumer_object": objects["consumer"], "plugin_object": objects["plugin"],
                              "plugin_dso": plugin_dso, "executable": executable, "link_command": commands[f"{prefix}-link"],
                              "runtime_command": commands[f"{prefix}-run"]}
        for mode in MODES:
            pinned = cells[f"pinned-musl-1.2.6/{mode}"]
            candidate = cells[f"candidate/{mode}"]
            require(same(pinned["consumer_object"], candidate["consumer_object"])
                    and same(pinned["plugin_object"], candidate["plugin_object"]),
                    f"same-mode probe objects differ: {probe}/{mode}")
        matrix[probe] = {"objects": objects, "cells": cells}
    return matrix


def _validate_matrix(matrix: object, commands: Mapping[str, object]) -> dict[str, object]:
    require(isinstance(matrix, Mapping) and set(matrix) == set(PROBES), "normal consumer probe roster differs")
    for probe in PROBES:
        row = _exact(matrix[probe], {"objects", "cells"}, f"normal consumer {probe}")
        objects = _exact(row["objects"], {"consumer", "plugin"}, f"normal consumer objects {probe}")
        require(isinstance(row["cells"], Mapping) and set(row["cells"]) == {f"{lane}/{mode}" for lane in LANES for mode in MODES},
                f"normal consumer cell roster differs: {probe}")
        for lane in LANES:
            for mode in MODES:
                cell = _exact(row["cells"][f"{lane}/{mode}"],
                              {"consumer_object", "plugin_object", "plugin_dso", "executable", "link_command", "runtime_command"},
                              f"normal consumer cell {probe}/{lane}/{mode}")
                require(same(cell["consumer_object"], objects["consumer"])
                        and same(cell["plugin_object"], objects["plugin"]),
                        f"normal consumer object relation differs: {probe}/{lane}/{mode}")
                prefix = f"{probe}-{lane}-{mode}"
                require(same(cell["link_command"], commands[f"{prefix}-link"])
                        and same(cell["runtime_command"], commands[f"{prefix}-run"]),
                        f"normal consumer command relation differs: {probe}/{lane}/{mode}")
        for mode in MODES:
            one, two = row["cells"][f"pinned-musl-1.2.6/{mode}"], row["cells"][f"candidate/{mode}"]
            require(same(one["consumer_object"], two["consumer_object"])
                    and same(one["plugin_object"], two["plugin_object"]),
                    f"same-mode probe pairing differs: {probe}/{mode}")
    return dict(matrix)


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def _selected_runtime_projection() -> dict[str, object]:
    selected = _contract()["selected_runtime"]
    return {"cfg": selected["cfg"], "candidate_cells": list(MODES),
            "constructor_owner": selected["constructor_owner"]}


def _begin_fields() -> set[str]:
    return {"schema", "image", "output", "selected_source", "collector", "contract", "inputs",
            "source_contract", "source_algorithm", "upstream"}


def _validate_begin_record(begin: object, *, source: Mapping[str, object], contract: Mapping[str, object],
                           collector_output: str, inputs: Mapping[str, object],
                           source_contract: Mapping[str, object], source_algorithm: Mapping[str, object],
                           upstream: Mapping[str, object]) -> dict[str, object]:
    """Bind every pre-execution admission record to the final cohort."""
    row = _exact(begin, _begin_fields(), "component begin record")
    require(row["schema"] == "crabc.x86_64-loader-structural-owner-begin/v1" and row["image"] == PINNED_IMAGE
            and row["output"] == collector_output and same(row["selected_source"], source)
            and same(row["collector"], source)
            and same(row["contract"], {"schema": contract["schema"], "id": contract["id"]})
            and same(row["inputs"], inputs) and same(row["source_contract"], source_contract)
            and same(row["source_algorithm"], source_algorithm) and same(row["upstream"], upstream),
            "component begin admission differs")
    return row


def begin_collection(*, root: Path, output: Path, static_product: Path, dynamic_product: Path,
                     static_preparation: Path, base_inventory: Path, full_facts: Path,
                     loader_debug_report: Path, loader_runtime_registry_report: Path,
                     oracle_compiler: Path, musl_shared: Path, image: str) -> dict[str, object]:
    """Admit and retain the complete current cohort before the runner executes."""
    require(image == PINNED_IMAGE, "pinned collection image differs")
    root = _physical_directory(root, "component checkout")
    output = Path(output).absolute()
    require(not output.exists(), "component output already exists")
    output.mkdir(parents=True)
    source = current_source_identity(root)
    contract = _contract()
    algorithm = validate_source_algorithms(root)
    upstream = _validate_upstream(root, base_inventory=base_inventory, full_facts=full_facts,
                                  static_preparation=static_preparation, static_product=static_product,
                                  dynamic_product=dynamic_product, loader_debug_report=loader_debug_report,
                                  loader_runtime_registry_report=loader_runtime_registry_report)
    paths = _input_paths(root, static_product=static_product, dynamic_product=dynamic_product,
                         static_preparation=static_preparation, base_inventory=base_inventory, full_facts=full_facts,
                         loader_debug_report=loader_debug_report,
                         loader_runtime_registry_report=loader_runtime_registry_report,
                         oracle_compiler=oracle_compiler, musl_shared=musl_shared)
    inputs = _capture_inputs(root, output, **paths)
    _validate_input_modes(inputs)
    source_contract = {relative: _source_record(root, output, relative) for relative in SOURCE_CONTRACT_PATHS}
    result = {"schema": "crabc.x86_64-loader-structural-owner-begin/v1", "image": image,
              "output": _collector_path(root, output, "collection output"),
              "selected_source": source, "collector": source, "contract": {"schema": contract["schema"], "id": contract["id"]},
              "inputs": inputs, "source_contract": source_contract, "source_algorithm": algorithm,
              "upstream": upstream}
    _write_json(output / "begin.json", result)
    return result


def _collection_paths(root: Path, values: Mapping[str, Path]) -> dict[str, Path]:
    return _input_paths(root, static_product=values["static_product"], dynamic_product=values["dynamic_product"],
                        static_preparation=values["static_preparation"], base_inventory=values["base_inventory"],
                        full_facts=values["full_facts"], loader_debug_report=values["loader_debug_report"],
                        loader_runtime_registry_report=values["loader_runtime_registry_report"],
                        oracle_compiler=values["oracle_compiler"], musl_shared=values["musl_shared"])


def collect_report(*, root: Path, output: Path, static_product: Path, dynamic_product: Path,
                   static_preparation: Path, base_inventory: Path, full_facts: Path,
                   loader_debug_report: Path, loader_runtime_registry_report: Path,
                   oracle_compiler: Path, musl_shared: Path, image: str) -> dict[str, object]:
    """Seal a completed normal-consumer matrix after a second full admission."""
    root, output = _physical_directory(root, "component checkout"), _physical_directory(output, "component output")
    begin = _exact(_read_json(output / "begin.json", "component begin record"), _begin_fields(), "component begin record")
    require(begin["schema"] == "crabc.x86_64-loader-structural-owner-begin/v1" and begin["image"] == image == PINNED_IMAGE,
            "component begin record differs")
    collector_output = _collector_path(root, output, "collection output")
    require(begin.get("output") == collector_output, "component begin output path differs")
    paths = _collection_paths(root, {"static_product": static_product, "dynamic_product": dynamic_product,
                                     "static_preparation": static_preparation, "base_inventory": base_inventory,
                                     "full_facts": full_facts, "loader_debug_report": loader_debug_report,
                                     "loader_runtime_registry_report": loader_runtime_registry_report,
                                     "oracle_compiler": oracle_compiler, "musl_shared": musl_shared})
    source = current_source_identity(root)
    require(same(begin.get("selected_source"), source) and same(begin.get("collector"), source),
            "source changed during component collection")
    inputs = _validate_inputs(root, output, begin.get("inputs"), **paths)
    _validate_input_modes(inputs)
    sources = {relative: _validate_source_record(root, output, relative, row)
               for relative, row in _exact(begin.get("source_contract"), set(SOURCE_CONTRACT_PATHS), "source contract").items()}
    algorithm = validate_source_algorithms(root)
    require(same(begin.get("source_algorithm"), algorithm), "selected source algorithm changed during collection")
    upstream = _validate_upstream(root, base_inventory=base_inventory, full_facts=full_facts,
                                  static_preparation=static_preparation, static_product=static_product,
                                  dynamic_product=dynamic_product, loader_debug_report=loader_debug_report,
                                  loader_runtime_registry_report=loader_runtime_registry_report)
    require(same(begin.get("upstream"), upstream), "supplied product or nested receipt changed during collection")
    _validate_begin_record(begin, source=source, contract=_contract(), collector_output=collector_output,
                           inputs=inputs, source_contract=sources, source_algorithm=algorithm, upstream=upstream)
    commands = {name: _read_command(output, name, collector_output=collector_output, inputs=inputs)
                for name in _command_names()}
    matrix = _normal_matrix(output, commands)
    runtime = _validate_runtime(output, dynamic_product, matrix, inputs)
    coverage = {"identities": list(IDENTITIES), "groups": ["loader-entry-stages", "loader-registration-operations", "loader-always-atomic-guard"],
                "fact_filter": upstream["facts_projection"], "source_functions": list(SOURCE_ALGORITHM_PATHS),
                "selected_runtime_cells": list(MODES), "normal_consumer_cells": [f"{lane}/{mode}" for lane in LANES for mode in MODES],
                "normal_consumer_pairs": list(MODES)}
    report = {
        "schema": SCHEMA, "status": STATUS, "component": COMPONENT, "target": TARGET,
        "collection": {"image": image, "output": collector_output, "begin": _identity(output / "begin.json", "begin.json")},
        "selected_source": source, "collector": source, "inputs": inputs,
        "selected_products": {"static": inputs["static_libc"], "dynamic_libc": inputs["dynamic_libc"],
                              "dynamic_loader": inputs["dynamic_loader"], "loader_debug": upstream["loader_debug"],
                              "loader_runtime_registry": upstream["loader_runtime_registry"]},
        "static_preparation": upstream["static_preparation"], "base_inventory": upstream["base_inventory"],
        "full_facts": upstream["full_facts"], "source_contract": sources,
        "source_cohort": {"relation": "one-current-clean-source", "identity": source},
        "source_algorithm": algorithm,
        "selected_runtime": _selected_runtime_projection(),
        "normal_consumer_matrix": matrix, "commands": commands, "runtime": runtime,
        "artifacts": {"begin": _identity(output / "begin.json", "begin.json")}, "coverage": coverage,
        "limits": {"family_completion": False, "promotion_ready": False, "public_support": False,
                   "runtime_qualification": False, "selector_admission": False},
    }
    _write_json(output / "report.json", report)
    return report


def validate_report(report_path: Path, *, root: Path, static_product: Path, dynamic_product: Path,
                    static_preparation: Path, base_inventory: Path, full_facts: Path,
                    loader_debug_report: Path, loader_runtime_registry_report: Path,
                    oracle_compiler: Path, musl_shared: Path) -> dict[str, object]:
    """Replay retained bytes and the same current supplied cohort without target tools."""
    report_path = _physical_regular(report_path, "component report")
    output, root = _physical_directory(report_path.parent, "component output"), _physical_directory(root, "component checkout")
    report_identity = _identity(report_path, "report.json")
    report = _exact(_read_json(report_path, "component report"), REPORT_FIELDS, "component report")
    require((report["schema"], report["status"], report["component"], report["target"]) == (SCHEMA, STATUS, COMPONENT, TARGET),
            "component report identity differs")
    require(report["limits"] == {"family_completion": False, "promotion_ready": False, "public_support": False,
                                 "runtime_qualification": False, "selector_admission": False},
            "component report crossed its non-promoting boundary")
    source = current_source_identity(root)
    require(same(report["selected_source"], source) and same(report["collector"], source)
            and report["source_cohort"] == {"relation": "one-current-clean-source", "identity": source},
            "component source cohort differs")
    paths = _collection_paths(root, {"static_product": static_product, "dynamic_product": dynamic_product,
                                     "static_preparation": static_preparation, "base_inventory": base_inventory,
                                     "full_facts": full_facts, "loader_debug_report": loader_debug_report,
                                     "loader_runtime_registry_report": loader_runtime_registry_report,
                                     "oracle_compiler": oracle_compiler, "musl_shared": musl_shared})
    inputs = _validate_inputs(root, output, report["inputs"], **paths)
    _validate_input_modes(inputs)
    sources = {relative: _validate_source_record(root, output, relative, row)
               for relative, row in _exact(report["source_contract"], set(SOURCE_CONTRACT_PATHS), "source contract").items()}
    require(same(report["source_algorithm"], validate_source_algorithms(root)), "selected source algorithm differs")
    upstream = _validate_upstream(root, base_inventory=base_inventory, full_facts=full_facts,
                                  static_preparation=static_preparation, static_product=static_product,
                                  dynamic_product=dynamic_product, loader_debug_report=loader_debug_report,
                                  loader_runtime_registry_report=loader_runtime_registry_report)
    require(report["base_inventory"] == upstream["base_inventory"] and report["full_facts"] == upstream["full_facts"]
            and report["static_preparation"] == upstream["static_preparation"], "upstream cohort binding differs")
    expected_products = {"static": inputs["static_libc"], "dynamic_libc": inputs["dynamic_libc"],
                         "dynamic_loader": inputs["dynamic_loader"], "loader_debug": upstream["loader_debug"],
                         "loader_runtime_registry": upstream["loader_runtime_registry"]}
    require(same(report["selected_products"], expected_products), "selected product binding differs")
    begin_identity = _identity(output / "begin.json", "begin.json")
    require(same(report["collection"], {"image": PINNED_IMAGE, "output": _collector_path(root, output, "collection output"),
                                         "begin": begin_identity})
            and same(report["artifacts"], {"begin": begin_identity})
            and same(report["selected_runtime"], _selected_runtime_projection()),
            "component collection or selected runtime binding differs")
    begin = _validate_begin_record(
        _read_json(output / "begin.json", "component begin record"), source=source, contract=_contract(),
        collector_output=_collector_path(root, output, "collection output"), inputs=inputs,
        source_contract=sources, source_algorithm=validate_source_algorithms(root), upstream=upstream,
    )
    require(report["collection"] == {"image": PINNED_IMAGE, "output": begin["output"],
                                     "begin": _identity(output / "begin.json", "begin.json")},
            "component collection record differs")
    commands = {name: _read_command(output, name, collector_output=begin["output"], inputs=inputs)
                for name in _command_names()}
    require(same(report["commands"], commands), "retained command record differs")
    expected_matrix = _normal_matrix(output, commands)
    require(same(_validate_matrix(report["normal_consumer_matrix"], commands), expected_matrix),
            "normal consumer matrix differs")
    runtime = _validate_runtime(output, dynamic_product, expected_matrix, inputs)
    require(same(report["runtime"], runtime), "retained runtime root differs")
    expected_coverage = {"identities": list(IDENTITIES), "groups": ["loader-entry-stages", "loader-registration-operations", "loader-always-atomic-guard"],
                         "fact_filter": upstream["facts_projection"], "source_functions": list(SOURCE_ALGORITHM_PATHS),
                         "selected_runtime_cells": list(MODES), "normal_consumer_cells": [f"{lane}/{mode}" for lane in LANES for mode in MODES],
                         "normal_consumer_pairs": list(MODES)}
    require(same(report["coverage"], expected_coverage), "component coverage differs")
    # Final transaction recheck: no source, supplied product, nested receipt,
    # retained input, or report byte may change while this replay reconstructs.
    final_source = current_source_identity(root)
    final_inputs = _validate_inputs(root, output, report["inputs"], **paths)
    final_sources = {relative: _validate_source_record(root, output, relative, row)
                     for relative, row in _exact(report["source_contract"], set(SOURCE_CONTRACT_PATHS), "source contract").items()}
    final_algorithm = validate_source_algorithms(root)
    final_upstream = _validate_upstream(root, base_inventory=base_inventory, full_facts=full_facts,
                                        static_preparation=static_preparation, static_product=static_product,
                                        dynamic_product=dynamic_product, loader_debug_report=loader_debug_report,
                                        loader_runtime_registry_report=loader_runtime_registry_report)
    final_products = {"static": final_inputs["static_libc"], "dynamic_libc": final_inputs["dynamic_libc"],
                      "dynamic_loader": final_inputs["dynamic_loader"], "loader_debug": final_upstream["loader_debug"],
                      "loader_runtime_registry": final_upstream["loader_runtime_registry"]}
    require(same(report["selected_source"], final_source)
            and same(report["collector"], final_source)
            and same(report["inputs"], final_inputs)
            and same(report["source_contract"], final_sources)
            and same(report["source_algorithm"], final_algorithm)
            and report["base_inventory"] == final_upstream["base_inventory"]
            and report["full_facts"] == final_upstream["full_facts"]
            and report["static_preparation"] == final_upstream["static_preparation"]
            and same(report["selected_products"], final_products)
            and report["coverage"]["fact_filter"] == final_upstream["facts_projection"]
            and _identity(report_path, "report.json") == report_identity,
            "component input changed during retained replay")
    return report


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)
    collect = commands.add_parser("begin-collection", allow_abbrev=False)
    seal = commands.add_parser("collect-report", allow_abbrev=False)
    validate = commands.add_parser("validate-report", allow_abbrev=False)
    capture = commands.add_parser("capture-runtime-root", allow_abbrev=False)
    for current in (collect, seal, validate):
        current.add_argument("--root", type=Path, required=True)
        current.add_argument("--static-product", type=Path, required=True)
        current.add_argument("--dynamic-product", type=Path, required=True)
        current.add_argument("--static-preparation", type=Path, required=True)
        current.add_argument("--base-inventory", type=Path, required=True)
        current.add_argument("--full-facts", type=Path, required=True)
        current.add_argument("--loader-debug-report", type=Path, required=True)
        current.add_argument("--loader-runtime-registry-report", type=Path, required=True)
        current.add_argument("--oracle-compiler", type=Path, required=True)
        current.add_argument("--musl-shared", type=Path, required=True)
    collect.add_argument("--output", type=Path, required=True)
    collect.add_argument("--image", required=True)
    seal.add_argument("--output", type=Path, required=True)
    seal.add_argument("--image", required=True)
    validate.add_argument("report", type=Path)
    capture.add_argument("--output", type=Path, required=True)
    capture.add_argument("--runtime-root", type=Path, required=True)
    capture.add_argument("--probe", choices=PROBES, required=True)
    capture.add_argument("--lane", choices=LANES, required=True)
    capture.add_argument("--mode", choices=MODES, required=True)
    capture.add_argument("--phase", choices=("before", "after"), required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "capture-runtime-root":
            capture_runtime_root(output=args.output, root=args.runtime_root, probe=args.probe, lane=args.lane,
                                 mode=args.mode, phase=args.phase)
            return 0
        values = {key: getattr(args, key) for key in (
            "root", "static_product", "dynamic_product", "static_preparation", "base_inventory", "full_facts",
            "loader_debug_report", "loader_runtime_registry_report", "oracle_compiler", "musl_shared",
        )}
        if args.command == "begin-collection":
            begin_collection(output=args.output, image=args.image, **values)
        elif args.command == "collect-report":
            collect_report(output=args.output, image=args.image, **values)
        else:
            validate_report(args.report, **values)
        print("loader structural-owner component: validated; unqualified")
        return 0
    except (LoaderStructuralOwnerError, OSError, ValueError, KeyError, TypeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
