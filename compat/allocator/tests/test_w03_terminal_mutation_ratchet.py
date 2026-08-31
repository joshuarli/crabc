#!/usr/bin/env python3
"""Ratchet W03's terminal PageMap acquisition away from ordinary busy refusal.

The source `mi_free_block_mt(..., allow_collect=true)` CAS decides which
same-page producer owns the abandoned page's low bit.  W03 may acquire a
short structural PageMap boundary only after that page-local decision.  A
second page-bearing operation can make the ordinary nonblocking lifecycle
entry return `LifecycleBusy`; that conflict is not an OS/metadata release
failure and must not turn a valid claimed free into `Retained`.

This is a source-contract complement to the focused Rust PageMap test named
by the checked-in JSON contract.  It intentionally makes no promotion,
cross-thread allocator, or general concurrency claim.
"""

from __future__ import annotations

import copy
import json
import re
import tempfile
import unittest
from pathlib import Path
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[3]
CONTRACT_PATH = ROOT / "compat/allocator/w03-terminal-mutation-ratchet-v3.5.0.json"
EXPECTED_SCHEMA = "crabc-mimalloc-w03-terminal-mutation-ratchet"
EXPECTED_UPSTREAM = {
    "revision": "18b08671c9302247bfb682286e6bf3cc1773f801",
    "version": "3.5.0",
}


class RatchetError(RuntimeError):
    """The checked-in W03 source contract or its selected source drifted."""


def load_contract(path: Path = CONTRACT_PATH) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RatchetError(f"cannot read W03 terminal-mutation contract: {error}") from error
    if not isinstance(value, dict):
        raise RatchetError("W03 terminal-mutation contract root must be an object")
    validate_contract(value)
    return value


def require_exact_keys(value: Mapping[str, Any], expected: set[str], subject: str) -> None:
    if set(value) != expected:
        raise RatchetError(f"{subject} keys changed: expected {sorted(expected)!r}, got {sorted(value)!r}")


def require_nonempty_string(value: object, subject: str) -> str:
    if not isinstance(value, str) or not value:
        raise RatchetError(f"{subject} must be a nonempty string")
    return value


def validate_contract(contract: Mapping[str, Any]) -> None:
    require_exact_keys(contract, {"format", "page_map", "schema", "scope", "upstream", "w03"}, "contract")
    if contract["format"] != 1:
        raise RatchetError("W03 terminal-mutation contract format changed")
    if contract["schema"] != EXPECTED_SCHEMA:
        raise RatchetError("W03 terminal-mutation contract schema changed")

    upstream = contract["upstream"]
    if not isinstance(upstream, dict) or upstream != EXPECTED_UPSTREAM:
        raise RatchetError("W03 terminal-mutation contract upstream pin changed")

    scope = contract["scope"]
    if not isinstance(scope, dict):
        raise RatchetError("W03 terminal-mutation contract scope must be an object")
    require_exact_keys(scope, {"non_promotional", "same_page_concurrency", "terminal_busy_policy"}, "scope")
    if scope["non_promotional"] is not True:
        raise RatchetError("W03 terminal-mutation contract must remain non-promotional")
    for key in ("same_page_concurrency", "terminal_busy_policy"):
        require_nonempty_string(scope[key], f"scope.{key}")

    w03 = contract["w03"]
    if not isinstance(w03, dict):
        raise RatchetError("W03 contract entry must be an object")
    require_exact_keys(
        w03,
        {
            "legacy_nonblocking_method",
            "pointer_dispatch",
            "post_cas_continuation",
            "remote_publication",
            "source",
            "terminal_branch_count",
            "terminal_mutation_method",
            "terminal_mutation_owner",
        },
        "w03",
    )
    for key in (
        "legacy_nonblocking_method",
        "pointer_dispatch",
        "post_cas_continuation",
        "remote_publication",
        "source",
        "terminal_mutation_method",
        "terminal_mutation_owner",
    ):
        require_nonempty_string(w03[key], f"w03.{key}")
    if type(w03["terminal_branch_count"]) is not int or w03["terminal_branch_count"] < 1:
        raise RatchetError("W03 terminal branch count must be a positive integer")

    page_map = contract["page_map"]
    if not isinstance(page_map, dict):
        raise RatchetError("PageMap contract entry must be an object")
    require_exact_keys(page_map, {"helper", "ordinary_method", "regression_test", "source"}, "page_map")
    for key in ("helper", "ordinary_method", "regression_test", "source"):
        require_nonempty_string(page_map[key], f"page_map.{key}")

    if w03["terminal_mutation_method"] != page_map["helper"]:
        raise RatchetError("W03 terminal mutation helper must name the PageMap helper")
    if w03["legacy_nonblocking_method"] != page_map["ordinary_method"]:
        raise RatchetError("W03 legacy method must name the ordinary PageMap method")


def strip_rust_comments_and_literals(source: str) -> str:
    """Mask comments and literals while preserving source offsets and newlines."""

    result: list[str] = []
    index = 0
    block_depth = 0
    line_comment = False
    string_delimiter: str | None = None
    escaped = False
    while index < len(source):
        character = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if line_comment:
            result.append("\n" if character == "\n" else " ")
            if character == "\n":
                line_comment = False
            index += 1
            continue
        if block_depth:
            if character == "/" and following == "*":
                block_depth += 1
                result.extend((" ", " "))
                index += 2
            elif character == "*" and following == "/":
                block_depth -= 1
                result.extend((" ", " "))
                index += 2
            else:
                result.append("\n" if character == "\n" else " ")
                index += 1
            continue
        if string_delimiter is not None:
            result.append("\n" if character == "\n" else " ")
            if not escaped and character == string_delimiter:
                string_delimiter = None
            escaped = not escaped and character == "\\"
            if character != "\\":
                escaped = False
            index += 1
            continue
        if character == "/" and following == "/":
            line_comment = True
            result.extend((" ", " "))
            index += 2
        elif character == "/" and following == "*":
            block_depth = 1
            result.extend((" ", " "))
            index += 2
        elif character == '"':
            string_delimiter = character
            result.append(" ")
            index += 1
        elif character == "'" and re.match(r"'(?:\\.|[^\\'\n])'", source[index:]):
            literal = re.match(r"'(?:\\.|[^\\'\n])'", source[index:])
            assert literal is not None
            result.extend(" " for _ in range(literal.end()))
            index += literal.end()
        else:
            result.append(character)
            index += 1
    return "".join(result)


def balanced_end(source: str, opening: int) -> int:
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    raise RatchetError("selected Rust function has an unclosed body")


def rust_function_body(source: str, name: str) -> str:
    masked = strip_rust_comments_and_literals(source)
    declaration = re.search(
        rf"\b(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+)?fn\s+{re.escape(name)}\s*\(",
        masked,
    )
    if declaration is None:
        raise RatchetError(f"selected Rust function {name!r} is absent")
    opening = masked.find("{", declaration.end())
    if opening < 0:
        raise RatchetError(f"selected Rust function {name!r} has no body")
    return masked[opening + 1 : balanced_end(masked, opening)]


def call_count(source: str, receiver: str, method: str) -> int:
    return len(
        re.findall(
            rf"\b{re.escape(receiver)}\s*\.\s*{re.escape(method)}\s*\(\s*\)",
            source,
        )
    )


def assert_selected_source(contract: Mapping[str, Any], root: Path = ROOT) -> None:
    w03 = contract["w03"]
    page_map = contract["page_map"]
    assert isinstance(w03, dict)
    assert isinstance(page_map, dict)
    w03_source = (root / str(w03["source"])).read_text(encoding="utf-8")
    w03_body = rust_function_body(
        w03_source,
        str(w03["post_cas_continuation"]),
    )
    pointer_dispatch_body = rust_function_body(w03_source, str(w03["pointer_dispatch"]))
    publication = str(w03["remote_publication"])
    continuation = str(w03["post_cas_continuation"])
    if publication not in pointer_dispatch_body:
        raise RatchetError("W03 no longer publishes through the pinned page-local remote-free seam")
    if continuation not in pointer_dispatch_body:
        raise RatchetError("W03 no longer reaches its terminal continuation after source publication")
    if pointer_dispatch_body.find(publication) > pointer_dispatch_body.find(continuation):
        raise RatchetError("W03 must perform the page-local source publication before terminal continuation")

    helper = str(w03["terminal_mutation_method"])
    owner = str(w03["terminal_mutation_owner"])
    helper_count = call_count(w03_body, owner, helper)
    required_count = int(w03["terminal_branch_count"])
    if helper_count != required_count:
        raise RatchetError(
            "W03 regular and singleton terminal callbacks must each use the exact blocking "
            f"PageMap helper: expected {required_count}, found {helper_count}"
        )
    legacy_count = call_count(w03_body, owner, str(w03["legacy_nonblocking_method"]))
    if legacy_count:
        raise RatchetError(
            "W03 terminal callbacks still use ordinary nonblocking PageMap admission "
            f"({legacy_count} call(s)); LifecycleBusy would remain terminal Retained"
        )
    page_map_source = (root / str(page_map["source"])).read_text(encoding="utf-8")
    helper_body = rust_function_body(page_map_source, str(page_map["helper"]))
    if not helper_body.strip():
        raise RatchetError("exact W03 PageMap helper has an empty body")
    ordinary_body = rust_function_body(page_map_source, str(page_map["ordinary_method"]))
    if "try_lock" not in ordinary_body:
        raise RatchetError("ordinary PageMap lifecycle must retain its nonblocking busy refusal")

    test_name = str(page_map["regression_test"])
    test_pattern = rf"#\[test\]\s*fn\s+{re.escape(test_name)}\s*\(\s*\)"
    if re.search(test_pattern, strip_rust_comments_and_literals(page_map_source)) is None:
        raise RatchetError("PageMap helper lacks its focused contention regression")
    regression_body = rust_function_body(page_map_source, test_name)
    if call_count(regression_body, "lease", str(page_map["helper"])) != 1:
        raise RatchetError("focused PageMap regression must exercise the exact blocking W03 helper")
    if call_count(regression_body, "lease", str(page_map["ordinary_method"])) < 2:
        raise RatchetError("focused PageMap regression must prove ordinary admission remains nonblocking")
    if "LifecycleBusy" not in regression_body or "recv_timeout" not in regression_body:
        raise RatchetError("focused PageMap regression must observe busy refusal and delayed W03 completion")


class W03TerminalMutationRatchetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = load_contract()

    def test_checked_in_contract_binds_the_pinned_w03_busy_policy(self) -> None:
        self.assertEqual(self.contract["upstream"], EXPECTED_UPSTREAM)
        self.assertTrue(self.contract["scope"]["non_promotional"])
        self.assertEqual(self.contract["w03"]["terminal_branch_count"], 2)
        self.assertEqual(
            self.contract["w03"]["terminal_mutation_method"],
            self.contract["page_map"]["helper"],
        )

    def test_selected_w03_uses_the_exact_busy_wait_helper(self) -> None:
        assert_selected_source(self.contract)

    def test_contract_rejects_a_different_pin_or_a_promotional_scope(self) -> None:
        changed_pin = copy.deepcopy(self.contract)
        changed_pin["upstream"]["revision"] = "0" * 40
        with self.assertRaisesRegex(RatchetError, "upstream pin"):
            validate_contract(changed_pin)

        promotional = copy.deepcopy(self.contract)
        promotional["scope"]["non_promotional"] = False
        with self.assertRaisesRegex(RatchetError, "non-promotional"):
            validate_contract(promotional)

    def test_source_checker_rejects_the_pre_fix_nonblocking_terminal_callbacks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_path = root / self.contract["w03"]["source"]
            source_path.parent.mkdir(parents=True)
            source_path.write_text(
                """\
unsafe fn continue_post_owner_exit_live_allocation_with_terminal_marker() {
    let publication = remote_free::push_post_owner_exit_live_allocation(allocation);
    continue_post_owner_exit_remote_claim_with_process_page_facts();
}

unsafe fn continue_post_owner_exit_remote_claim_with_process_page_facts() {
    let regular = process.begin_page_lifecycle();
    let singleton = process.begin_page_lifecycle();
}
""",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(RatchetError, "blocking PageMap helper"):
                assert_selected_source(self.contract, root)

    def test_source_parser_ignores_comment_only_legacy_calls(self) -> None:
        source = """\
unsafe fn terminal() {
    // process.begin_page_lifecycle();
    process.begin_blocking_exact_post_owner_exit_mutation();
}
"""
        body = rust_function_body(source, "terminal")
        self.assertEqual(call_count(body, "process", "begin_page_lifecycle"), 0)
        self.assertEqual(
            call_count(body, "process", "begin_blocking_exact_post_owner_exit_mutation"),
            1,
        )


if __name__ == "__main__":
    unittest.main()
