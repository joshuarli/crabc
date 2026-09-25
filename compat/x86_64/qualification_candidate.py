#!/usr/bin/env python3
"""Run the complete native x86 qualification on one clean candidate checkout.

One command builds the product cohort once, runs every family aggregate in
dependency order, runs every qualification-gate producer and publishes its
receipt, checks that each family row which names a receipt names the one this
run produces, runs the ordered qualification chain and the parity ledger, and
writes one summary. Every step is an existing dispatcher command or reader;
this module only fixes their order, inputs, and output paths.

State lives below `--work` (a physical child of `.work/x86_64`). The run is
bound to the checkout's clean source identity: a restart on the same revision
skips every step whose recorded outputs still hash identically and resumes
from the first incomplete one; a failed attempt's output is renamed aside, so
each producer still receives a fresh output. Any other revision, a dirty
tree, or a changed completed output fails closed. `--dry-run` resolves the
whole plan, names every preflight blocker, and runs nothing.

The order follows `owned-posix-native-execution.md`'s admission sequence and
the dynamic-product lane's full preflight. Steps run sequentially: the only
independence the sequence allows (products; the matrix and its companions)
is not worth the contention it adds to timing-limited leaves.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tomllib
from typing import Callable, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "crabc.x86_64-qualification-candidate/v1"
DISPATCHER = "./scripts/dev-x86_64.sh"
MOUNT = "/workspace"
WORK_PARENT = Path(".work/x86_64")
PAIRS = {"primary": "installed", "reproduction": "second", "extracted": "extracted"}
# The text/math/locale/stdio family's per-pair producers and their reports,
# in the order `owned-text-math-locale-stdio-family.md` names them.
TEXT_PRODUCERS = (
    ("locale", "owned-locale", "owned-locale-products.json"),
    ("numeric", "owned-numeric-calendar", "owned-numeric-calendar-products.json"),
    ("text-locale-numeric", "owned-text-locale-numeric-component", "owned-text-locale-numeric.json"),
    ("math", "owned-math-fenv-all-entry", "owned-math-fenv-all-entry.json"),
    ("wordexp", "owned-wordexp", "owned-wordexp-products.json"),
    ("stdio", "owned-stdio", "owned-stdio-products.json"),
    ("stdio-engine", "owned-stdio-file-engine", "owned-stdio-file-engine.json"),
    ("regex", "owned-regex", "owned-regex-products.json"),
    ("calendar", "owned-calendar-component", "owned-calendar-products.json"),
)
SOURCE_ORACLES = (
    ".work/x86_64/source-oracles/os-test-5e9456d510612f83b6ec8b1a0c06d6b1303a2512",
    ".work/x86_64/source-oracles/laputa-libc-test-68edb8bd73dab8147ee54c8bec638f4d2b3cff37",
)
PACKAGE_CORPUS_INPUT = ".work/x86_64/owned-package-corpus-input/apks"
INPUT_KEYS = {
    "rust_std_lto": ("provider_vendor", "dependency_vendor"),
    "performance_release": ("runtime_c_collector", "native_facade_report", "rustybench_source",
                            "rustix_source", "allocator_reports"),
}


class CandidateError(RuntimeError):
    """The candidate run cannot proceed or its retained state is inconsistent."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CandidateError(message)


# ---------------------------------------------------------------------------
# Plan


@dataclass(frozen=True)
class Output:
    """One file a step produces, found either at a fixed path or in stdout."""

    name: str
    fixed: str | None = None      # checkout-relative path template
    printed: str | None = None    # basename to find among the step's printed paths
    glob: str | None = None       # checkout-relative glob that must match exactly once


@dataclass(frozen=True)
class Step:
    id: str
    family: str
    argv: Callable[["Context"], list[str]] | None
    outputs: tuple[Output, ...] = ()
    # Fresh producer outputs (checkout-relative templates). A failed
    # attempt's are renamed aside before a retry. Empty means the directory
    # holding the first fixed output.
    fresh: tuple[str, ...] = ()
    # Internal steps write their outputs without running a command.
    internal: Callable[["Context"], None] | None = None
    # Candidate inputs this step needs (keys of `--inputs`).
    needs_input: str | None = None
    # Ledger row (family, native_evidence command) whose `receipt` this
    # step's first output is.
    attaches: tuple[str, str] | None = None
    # `qualification-manifest --publish GATE PUBLICATION` of the first output.
    publishes: tuple[str, str] | None = None


@dataclass
class Context:
    """Paths known before a step runs; unknown step outputs render as placeholders."""

    root: Path
    work: Path
    inputs: Mapping[str, Mapping[str, object]]
    outputs: dict[str, dict[str, str]] = field(default_factory=dict)
    dry_run: bool = False

    def rel(self, path: Path) -> str:
        return path.relative_to(self.root).as_posix()

    def out(self, step: str, name: str) -> str:
        value = self.outputs.get(step, {}).get(name)
        if value is None:
            require(self.dry_run, f"step output {step}:{name} is not recorded")
            return f"<{step}:{name}>"
        return value

    def template(self, value: str) -> str:
        return value.format(work=self.rel(self.work), name=self.work.name)

    def static_pair(self, label: str) -> str:
        preparation = self.out("static-products", "preparation")
        if preparation.startswith("<"):
            return f"<static-products:{label}>"
        import owned_posix_static_products as static

        return self.rel(static.product_paths(self.root / Path(preparation).parent)[label])

    def dynamic_pair(self, label: str) -> str:
        qualification = self.out("dynamic-products", "qualification")
        if qualification.startswith("<"):
            return f"<dynamic-products:{PAIRS[label]}>"
        return (Path(qualification).parent / PAIRS[label]).as_posix()

    def cohort(self) -> list[str]:
        return ["--static-preparation", self.out("static-products", "preparation"),
                "--dynamic-qualification", self.out("dynamic-products", "qualification")]

    def products(self) -> list[str]:
        return ["--static-product", self.static_pair("primary"), "--dynamic-product", self.dynamic_pair("primary"),
                "--static-preparation", self.out("static-products", "preparation")]

    def given(self, group: str, key: str) -> object:
        value = self.inputs.get(group, {}).get(key)
        if value is None:
            require(self.dry_run, f"candidate input {group}.{key} is not supplied")
            return f"<input:{group}.{key}>"
        return value


def _d(*words: str) -> list[str]:
    return [DISPATCHER, *words]


def _pair_steps() -> list[Step]:
    steps = []
    for pair in PAIRS:
        for key, command, report in TEXT_PRODUCERS:
            if pair == "primary" and key == "wordexp":
                continue  # the POSIX wordexp companion is this report
            steps.append(Step(
                f"text-{pair}-{key}", "libc.text-math-locale-stdio",
                lambda c, command=command, pair=pair: _d(command, "--static-sysroot", c.static_pair(pair),
                                                         c.dynamic_pair(pair)),
                (Output("report", printed=report),)))
        if pair != "primary":
            steps.append(Step(
                f"text-{pair}-wordexp-inputs", "libc.text-math-locale-stdio",
                lambda c, pair=pair: _d("owned-wordexp-expected-inputs", "--static-sysroot", c.static_pair(pair),
                                        c.dynamic_pair(pair)),
                (Output("seal", printed="expected-native-inputs.json"),)))
    return steps


def _text_assemble(c: Context) -> list[str]:
    argv = _d("owned-text-math-locale-stdio-family", "assemble",
              "--family-execution", c.out("posix-family", "execution"),
              "--pthread-family", c.out("pthread-family", "receipt"))
    for pair in PAIRS:
        for key, _command, _report in TEXT_PRODUCERS:
            source = ("wordexp-profile", "report") if pair == "primary" and key == "wordexp" else (
                f"text-{pair}-{key}", "report")
            argv += ["--report", f"{key}:{pair}={c.out(*source)}"]
        seal = ("wordexp-inputs", "seal") if pair == "primary" else (f"text-{pair}-wordexp-inputs", "seal")
        argv += ["--wordexp-expected-input", f"{pair}={c.out(*seal)}"]
    return argv + ["--output", c.template("{work}/out/text-family")]


def _loader_request(c: Context) -> None:
    directory = c.root / c.template("{work}/out/loader-family")
    request = {
        "schema": "crabc.x86_64-owned-loader-family/v1",
        "qualification": c.out("dynamic-products", "qualification"),
        "inventories": {
            label: {"receipt": c.out(f"loader-inventory-{label}", "inventory"),
                    "oracle_capture": c.out(f"loader-inventory-{label}", "inventory") + ".inputs/oracle-capture.json",
                    "readelf_capture": c.out(f"loader-inventory-{label}", "inventory") + ".inputs/readelf-capture.json"}
            for label in PAIRS.values()
        },
    }
    directory.mkdir(parents=True)
    with (directory / "request.json").open("x", encoding="utf-8") as stream:
        json.dump(request, stream, indent=2, sort_keys=True)
        stream.write("\n")
    os.chmod(directory / "request.json", 0o444)


POSIX_NATIVE_COMMAND = (
    "./scripts/dev-x86_64.sh owned-posix-native --family-execution FILE --crypt-profile FILE "
    "--atomic-addressable-profile FILE --wordexp-profile FILE --wordexp-expected-native-inputs FILE --output NEW_DIR"
)


def plan(through: str | None = None) -> tuple[Step, ...]:
    """Return the fixed candidate sequence in dependency order.

    ``through`` selects the prefix ending at one step, for staged runs; the
    summary of a prefix is never complete qualification.
    """
    steps = _plan()
    if through is None:
        return steps
    identifiers = [step.id for step in steps]
    require(through in identifiers, f"unknown candidate step: {through}")
    return steps[: identifiers.index(through) + 1]


def _plan() -> tuple[Step, ...]:
    primary = lambda c: ["--static-sysroot", c.static_pair("primary"), c.dynamic_pair("primary")]  # noqa: E731
    steps: list[Step] = [
        # One product cohort for every family and gate.
        Step("static-products", "cohort",
             lambda c: _d("owned-posix-static-products", c.template("{work}/out/static")),
             (Output("preparation", fixed="{work}/out/static/preparation.json"),),
             fresh=("{work}/out/static",)),
        Step("dynamic-products", "cohort", lambda c: _d("materialized-dynamic-sysroot"),
             (Output("qualification", printed="qualification.json"),)),
        # libc.posix-runtime: matrix, four companions, native aggregate, admission.
        Step("posix-family", "libc.posix-runtime",
             lambda c: _d("owned-posix-family", *c.cohort(), "--output", c.template("{work}/out/posix-family")),
             (Output("execution", fixed="{work}/out/posix-family/execution.json"),)),
        Step("crypt-profile", "libc.posix-runtime", lambda c: _d("owned-crypt-runtime", *primary(c)),
             (Output("profile", printed="crypt-profile.json"),)),
        Step("atomic-profile", "libc.posix-runtime",
             lambda c: _d("owned-atomic-addressable-profile", c.dynamic_pair("primary")),
             (Output("profile", printed="atomic-addressable-profile.json"),)),
        Step("wordexp-profile", "libc.posix-runtime", lambda c: _d("owned-wordexp", *primary(c)),
             (Output("report", printed="owned-wordexp-products.json"),)),
        Step("wordexp-inputs", "libc.posix-runtime", lambda c: _d("owned-wordexp-expected-inputs", *primary(c)),
             (Output("seal", printed="expected-native-inputs.json"),)),
        Step("posix-native", "libc.posix-runtime",
             lambda c: _d("owned-posix-native", "--family-execution", c.out("posix-family", "execution"),
                          "--crypt-profile", c.out("crypt-profile", "profile"),
                          "--atomic-addressable-profile", c.out("atomic-profile", "profile"),
                          "--wordexp-profile", c.out("wordexp-profile", "report"),
                          "--wordexp-expected-native-inputs", c.out("wordexp-inputs", "seal"),
                          "--output", c.template("{work}/out/posix-native")),
             (Output("receipt", fixed="{work}/out/posix-native/native-execution.json"),),
             publishes=("compat.posix-process", "posix-native")),
        Step("posix-admission", "libc.posix-runtime",
             lambda c: ["python3", "-B", "compat/x86_64/owned_posix_native_execution.py", "admit",
                        "--native-execution", c.out("posix-native", "receipt"),
                        "--output", c.template("{work}/out/posix-admission")],
             (Output("receipt", fixed="{work}/out/posix-admission/family-admission.json"),),
             fresh=("{work}/out/posix-admission",),
             attaches=("libc.posix-runtime", POSIX_NATIVE_COMMAND)),
        # libc.pthread-tls.
        Step("pthread-family", "libc.pthread-tls",
             lambda c: _d("owned-pthread-family", "--family-execution", c.out("posix-family", "execution"),
                          "--output", c.template("{work}/out/pthread-family")),
             (Output("receipt", fixed="{work}/out/pthread-family/receipt.json"),),
             attaches=("libc.pthread-tls",
                       "./scripts/dev-x86_64.sh owned-pthread-family --family-execution FILE --output NEW_DIR")),
        # libc.text-math-locale-stdio: nine producers on each pair, then assembly.
        *_pair_steps(),
        Step("text-family", "libc.text-math-locale-stdio", _text_assemble,
             (Output("receipt", fixed="{work}/out/text-family/receipt.json"),)),
        # libc.resolver; its network step is the compat.resolver-network receipt.
        Step("resolver-family", "libc.resolver",
             lambda c: _d("owned-resolver-family", *c.cohort(), "--output", c.template("{work}/out/resolver-family")),
             (Output("assessment", fixed="{work}/out/resolver-family/assessment.json"),
              Output("network", glob="{work}/out/resolver-family/network/run-*/report.json")),
             attaches=("libc.resolver", "./scripts/dev-x86_64.sh owned-resolver-family --static-preparation FILE "
                                        "--dynamic-qualification FILE --output NEW_DIR")),
        # libc.c-abi-compat.
        Step("c-abi-compat-family", "libc.c-abi-compat",
             lambda c: _d("owned-c-abi-compat-family", *c.cohort(),
                          "--output", c.template("{work}/out/c-abi-compat-family")),
             (Output("assessment", fixed="{work}/out/c-abi-compat-family/assessment.json"),),
             attaches=("libc.c-abi-compat", "./scripts/dev-x86_64.sh owned-c-abi-compat-family --static-preparation "
                                            "FILE --dynamic-qualification FILE --output NEW_DIR")),
        # ldso.dynamic-runtime: one inventory per qualified dynamic product.
        *(Step(f"loader-inventory-{label}", "ldso.dynamic-runtime",
               lambda c, label=label, pair=pair: _d("owned-loader-inventory", c.dynamic_pair(pair),
                                                    c.template("{work}/out/loader-inventory/") + label + ".json"),
               (Output("inventory", fixed="{work}/out/loader-inventory/" + label + ".json"),),
               fresh=tuple("{work}/out/loader-inventory/" + label + suffix
                           for suffix in (".json", ".json.inputs", ".json.raw")))
          for pair, label in PAIRS.items()),
        Step("loader-request", "ldso.dynamic-runtime", None,
             (Output("request", fixed="{work}/out/loader-family/request.json"),),
             fresh=("{work}/out/loader-family",), internal=_loader_request),
        Step("loader-family", "ldso.dynamic-runtime",
             lambda c: _d("owned-loader-family", "--work", c.template("{work}/out/loader-family")),
             (Output("receipt", fixed="{work}/out/loader-family/receipt.json"),),
             fresh=("{work}/out/loader-family/receipt.json",),
             publishes=("compat.loader-corpus", "loader-family")),
        # crt and sysroot families, in dependency order.
        Step("crt-dynamic-startup", "crt.dynamic-startup",
             lambda c: _d("owned-crt-dynamic-startup", c.dynamic_pair("primary"))),
        Step("static-sysroot", "sysroot.static-tls", lambda c: _d("owned-static-sysroot")),
        Step("combined-sysroot", "sysroot.owned-artifact", lambda c: _d("owned-combined-sysroot")),
        # compat.abi-differential: one current-source evidence set.
        Step("abi-inventory", "compat.abi-differential",
             lambda c: _d("native-abi-inventory", "collect", *c.products(),
                          "--output", c.template(".work/x86_64/native-abi-inventory/candidate-{name}")),
             (Output("report", fixed=".work/x86_64/native-abi-inventory/candidate-{name}/report.json"),),
             fresh=(".work/x86_64/native-abi-inventory/candidate-{name}",)),
        Step("abi-elf-facts", "compat.abi-differential",
             lambda c: _d("native-abi-elf-facts", "collect", "--base-inventory", c.out("abi-inventory", "report"),
                          *c.products(), "--output", c.template("{work}/out/abi-elf-facts")),
             (Output("report", fixed="{work}/out/abi-elf-facts/report.json"),)),
        Step("abi-declarations", "compat.abi-differential",
             lambda c: _d("header-declaration-inventory", "collect", "--output",
                          c.template(".work/x86_64/header-declaration-inventory/candidate-{name}"), "--workers", "8"),
             (Output("report", fixed=".work/x86_64/header-declaration-inventory/candidate-{name}/report.json"),),
             fresh=(".work/x86_64/header-declaration-inventory/candidate-{name}",)),
        Step("abi-public-data", "compat.abi-differential",
             lambda c: _d("public-data-ordinary-link", "collect", *c.products(),
                          "--output", c.template(".work/x86_64/public-data-ordinary-link/candidate-{name}")),
             (Output("report", fixed=".work/x86_64/public-data-ordinary-link/candidate-{name}/report.json"),),
             fresh=(".work/x86_64/public-data-ordinary-link/candidate-{name}",)),
        Step("abi-evidence", "compat.abi-differential",
             lambda c: _d("abi-differential-evidence", "assemble", *c.products(),
                          "--native-abi-inventory", c.out("abi-inventory", "report"),
                          "--native-abi-elf-facts", c.out("abi-elf-facts", "report"),
                          "--header-declaration-inventory", c.out("abi-declarations", "report"),
                          "--public-data-ordinary-link", c.out("abi-public-data", "report"),
                          "--output", c.template(".work/x86_64/abi-differential/candidate-{name}")),
             (Output("receipt", fixed=".work/x86_64/abi-differential/candidate-{name}/abi-evidence.json"),),
             fresh=(".work/x86_64/abi-differential/candidate-{name}",),
             publishes=("compat.abi-differential", "abi-evidence")),
        # consumer gates.
        Step("rust-std-lto", "consumer.rust-std-lto",
             lambda c: _d("consumer-rust-std-lto", "run", *c.cohort(),
                          "--provider-vendor", str(c.given("rust_std_lto", "provider_vendor")),
                          "--dependency-vendor", str(c.given("rust_std_lto", "dependency_vendor")),
                          "--output", c.template("{work}/out/rust-std-lto")),
             (Output("receipt", fixed="{work}/out/rust-std-lto/receipt.json"),),
             needs_input="rust_std_lto", publishes=("consumer.rust-std-lto", "rust-std-lto")),
        Step("lua-static", "consumer.source-build", lambda c: _d("lua-static-source-build")),
        Step("lua-dynamic", "consumer.source-build", lambda c: _d("lua-dynamic-source-build")),
        Step("lua-admission", "consumer.source-build",
             lambda c: _d("lua-source-build-admission", "--output", c.template("{work}/out/lua-admission")),
             (Output("receipt", fixed="{work}/out/lua-admission/admission.json"),),
             publishes=("consumer.source-build", "lua-source-build")),
        # performance.release reads measurements taken on an uncontended host.
        Step("performance-release", "performance.release",
             lambda c: ["python3", "compat/x86_64/performance_release_gate.py", "evaluate",
                        "--runtime-c-collector", str(c.given("performance_release", "runtime_c_collector")),
                        "--native-facade-report", str(c.given("performance_release", "native_facade_report")),
                        "--rustybench-source", str(c.given("performance_release", "rustybench_source")),
                        "--rustix-source", str(c.given("performance_release", "rustix_source")),
                        *[item for report in _reports(c) for item in ("--allocator-report", report)],
                        "--output", c.template("{work}/out/performance-release")],
             (Output("receipt", fixed="{work}/out/performance-release/receipt.json"),),
             needs_input="performance_release", publishes=("performance.release", "performance-release")),
    ]
    # The resolver family's network run is the compat.resolver-network receipt.
    steps.append(Step("publish-resolver-network", "compat.resolver-network",
                      lambda c: _d("qualification-manifest", "--publish", "compat.resolver-network",
                                   "resolver-network", c.out("resolver-family", "network"))))
    steps.append(Step("qualification-chain", "qualification",
                      lambda c: _d("qualification-manifest"),
                      (Output("receipt", printed="receipt.json"),)))
    steps.append(Step("parity-ledger", "capability.accounting",
                      lambda c: ["python3", "compat/x86_64/validate_parity_ledger.py"]))
    return tuple(_with_publications(steps))


def _reports(c: Context) -> list[str]:
    value = c.given("performance_release", "allocator_reports")
    if isinstance(value, str):
        return [value]
    require(isinstance(value, list) and value and all(isinstance(item, str) for item in value),
            "candidate input performance_release.allocator_reports must be a list of paths")
    return value


def _with_publications(steps: list[Step]) -> list[Step]:
    """Follow each publishing producer with its `--publish` step."""

    result: list[Step] = []
    for step in steps:
        result.append(step)
        if step.publishes is not None:
            gate, publication = step.publishes
            name = step.outputs[0].name
            result.append(Step(f"publish-{publication}", gate,
                               lambda c, step=step.id, name=name, gate=gate, publication=publication:
                               _d("qualification-manifest", "--publish", gate, publication, c.out(step, name))))
    return result


# ---------------------------------------------------------------------------
# Preflight


def _load_inputs(root: Path, path: Path | None) -> dict[str, dict[str, object]]:
    if path is None:
        return {}
    try:
        value = json.loads((root / path if not path.is_absolute() else path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise CandidateError(f"candidate inputs are unreadable: {error}") from error
    require(isinstance(value, dict) and set(value) <= set(INPUT_KEYS), "candidate inputs name an unknown group")
    for group, fields in value.items():
        require(isinstance(fields, dict) and set(fields) == set(INPUT_KEYS[group]),
                f"candidate input {group} fields differ")
    return value


def _ledger_rows(root: Path) -> dict[str, Mapping[str, object]]:
    with (root / "compat/x86_64/parity.toml").open("rb") as stream:
        document = tomllib.load(stream)
    return {row["id"]: row for row in document.get("family", []) if isinstance(row, dict)}


def attachments(root: Path, context: Context, steps: Sequence[Step]) -> list[dict[str, object]]:
    """Check each receipt-bearing family row against the path this run produces.

    A candidate row names its receipt before the run (the path is fixed by
    `--work`); a row that names another path is a blocker. A row without a
    receipt is reported as unattached: the family stays planned.
    """

    rows = _ledger_rows(root)
    result = []
    for step in steps:
        if step.attaches is None:
            continue
        family, command = step.attaches
        produced = context.template(step.outputs[0].fixed or "")
        entries = [entry for entry in rows.get(family, {}).get("native_evidence", [])
                   if isinstance(entry, dict) and entry.get("command") == command]
        require(len(entries) == 1, f"{family} has no single native evidence row for {command}")
        named = entries[0].get("receipt")
        result.append({"family": family, "step": step.id, "receipt": produced,
                       "row_receipt": named,
                       "state": "unattached" if named is None else "attached" if named == produced else "mismatch"})
    return result


def preflight(root: Path, context: Context, steps: Sequence[Step]) -> list[str]:
    """Name every condition that would stop the run before its first step."""

    blockers = []
    try:
        import owned_posix_static_products as static

        static.source_identity(root)
    except Exception as error:  # noqa: BLE001 - any source-identity failure blocks the run
        blockers.append(f"clean committed source: {error}")
    for relative in SOURCE_ORACLES:
        if not (root / relative).is_dir():
            blockers.append(f"pinned source oracle is not seeded (the native container has no network): {relative}")
    if not (root / PACKAGE_CORPUS_INPUT).is_dir():
        blockers.append("package corpus input is absent: run ./scripts/dev-x86_64.sh owned-package-corpus-input")
    for step in steps:
        if step.needs_input is not None and step.needs_input not in context.inputs:
            blockers.append(f"{step.id}: candidate input {step.needs_input} is not supplied (--inputs)")
    for record in attachments(root, context, steps):
        if record["state"] == "mismatch":
            blockers.append(f"{record['family']} row names receipt {record['row_receipt']}, "
                            f"but this run produces {record['receipt']}")
    return blockers


# ---------------------------------------------------------------------------
# Execution and restart


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write(path: Path, value: object) -> None:
    staged = path.with_name(path.name + ".tmp")
    staged.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(staged, path)


def _host(root: Path, value: str) -> Path:
    if value.startswith(MOUNT + "/"):
        return root / value[len(MOUNT) + 1:]
    return root / value


def _discover(root: Path, context: Context, step: Step, stdout: str) -> dict[str, str]:
    found: dict[str, str] = {}
    printed = {_host(root, token.rstrip(".,;:)")) for token in re.findall(r"/workspace/\S+", stdout)}
    for output in step.outputs:
        if output.fixed is not None:
            path = root / context.template(output.fixed)
            require(path.is_file(), f"{step.id} did not produce {context.rel(path)}")
            matches = [path]
        elif output.glob is not None:
            matches = sorted(root.glob(context.template(output.glob)))
        else:
            assert output.printed is not None
            matches = sorted({path for path in printed if path.name == output.printed and path.is_file()}
                             | {path / output.printed for path in printed if (path / output.printed).is_file()})
        require(len(matches) == 1, f"{step.id} must produce exactly one {output.name}; found "
                                   f"{[context.rel(path) for path in matches]}")
        path = matches[0]
        require(path.resolve() == path and path.is_relative_to(root / ".work"),
                f"{step.id} {output.name} is not a physical checkout .work file")
        found[output.name] = context.rel(path)
    return found


def _completed(root: Path, record_path: Path, source: Mapping[str, str]) -> dict[str, str] | None:
    """Return a completed step's outputs only when every one is unchanged."""

    if not record_path.is_file():
        return None
    record = json.loads(record_path.read_text(encoding="utf-8"))
    if record.get("status") != "complete":
        return None
    require(record.get("source") == source, f"{record_path.parent.name} completed on another source")
    for name, identity in record["outputs"].items():
        path = root / identity["path"]
        require(path.is_file() and _digest(path) == identity["sha256"],
                f"{record_path.parent.name} output {name} changed after completion: {identity['path']}")
    return {name: identity["path"] for name, identity in record["outputs"].items()}


def fresh_paths(context: Context, step: Step) -> list[Path]:
    templates = step.fresh or tuple(str(Path(output.fixed).parent) for output in step.outputs[:1]
                                    if output.fixed is not None)
    return [context.root / context.template(template) for template in templates]


def _set_aside(path: Path) -> None:
    if not path.exists() and not path.is_symlink():
        return
    attempt = 1
    while path.with_name(f"{path.name}.failed-{attempt}").exists():
        attempt += 1
    path.rename(path.with_name(f"{path.name}.failed-{attempt}"))


Runner = Callable[[list[str], Path, Path], int]


def _run(argv: list[str], stdout: Path, stderr: Path) -> int:
    with stdout.open("wb") as out, stderr.open("wb") as err:
        return subprocess.run(argv, cwd=ROOT, stdin=subprocess.DEVNULL, stdout=out, stderr=err, check=False).returncode


def execute(root: Path, work: Path, inputs: Mapping[str, Mapping[str, object]], *,
            runner: Runner = _run, source: Mapping[str, str] | None = None,
            through: str | None = None) -> dict[str, object]:
    """Run or resume the candidate sequence; always write `summary.json`."""

    context = Context(root, work, inputs)
    steps = plan(through)
    blockers = preflight(root, context, steps)
    if source is None:
        import owned_posix_static_products as static

        source = static.source_identity(root)
    work.mkdir(parents=True, exist_ok=True)
    candidate = work / "candidate.json"
    identity = {"schema": SCHEMA, "source": dict(source)}
    if candidate.exists():
        require(json.loads(candidate.read_text(encoding="utf-8")) == identity,
                "candidate work belongs to another source revision; use a fresh --work")
    else:
        _write(candidate, identity)
    records: list[dict[str, object]] = []
    summary: dict[str, object] = {"schema": SCHEMA, "source": dict(source), "work": context.rel(work),
                                  "through": through,
                                  "preflight_blockers": blockers, "steps": records,
                                  "attachments": attachments(root, context, steps), "complete": False}
    try:
        require(not blockers, "preflight blockers: " + "; ".join(blockers))
        for index, step in enumerate(steps):
            directory = work / "steps" / f"{index:02d}-{step.id}"
            done = _completed(root, directory / "record.json", source)
            if done is not None:
                context.outputs[step.id] = done
                records.append({"step": step.id, "family": step.family, "status": "complete", "resumed": True,
                                "outputs": done})
                continue
            _set_aside(directory)
            for fresh in fresh_paths(context, step):
                _set_aside(fresh)
                fresh.parent.mkdir(parents=True, exist_ok=True)
            directory.mkdir(parents=True)
            print(f"qualification candidate {step.id}: running", flush=True)
            if step.internal is not None:
                argv, status = ["internal", step.id], 0
                _write(directory / "invocation.json", {"argv": argv})
                step.internal(context)
                (directory / "stdout").write_bytes(b"")
                (directory / "stderr").write_bytes(b"")
            else:
                assert step.argv is not None
                argv = step.argv(context)
                _write(directory / "invocation.json", {"argv": argv})
                status = runner(argv, directory / "stdout", directory / "stderr")
            (directory / "status").write_text(f"{status}\n", encoding="ascii")
            if status != 0:
                records.append({"step": step.id, "family": step.family, "status": "failed", "exit_status": status,
                                "log": context.rel(directory)})
                raise CandidateError(f"step {step.id} failed with status {status}; see {context.rel(directory)}")
            found = _discover(root, context, step, (directory / "stdout").read_text(errors="replace"))
            context.outputs[step.id] = found
            _write(directory / "record.json", {
                "schema": SCHEMA, "step": step.id, "status": "complete", "source": dict(source), "argv": argv,
                "outputs": {name: {"path": path, "sha256": _digest(root / path)} for name, path in found.items()},
            })
            records.append({"step": step.id, "family": step.family, "status": "complete", "outputs": found})
            print(f"qualification candidate {step.id}: PASS", flush=True)
        summary["complete"] = through is None
    except CandidateError as error:
        summary["error"] = str(error)
        done = {record["step"] for record in records}
        summary["not_run"] = [step.id for step in steps if step.id not in done]
    finally:
        _write(work / "summary.json", summary)
    return summary


def dry_run(root: Path, work: Path, inputs: Mapping[str, Mapping[str, object]],
            through: str | None = None) -> dict[str, object]:
    """Resolve every step's command with placeholders; run and write nothing."""

    context = Context(root, work, inputs, dry_run=True)
    steps = plan(through)
    rendered = []
    for step in steps:
        rendered.append({"step": step.id, "family": step.family,
                         "argv": ["internal", step.id] if step.internal is not None else step.argv(context),
                         "outputs": [context.template(output.fixed or output.glob or "") or f"printed {output.printed}"
                                     for output in step.outputs]})
    return {"schema": SCHEMA, "dry_run": True, "work": context.rel(work),
            "preflight_blockers": preflight(root, context, steps),
            "attachments": attachments(root, context, steps), "steps": rendered}


def _work(root: Path, value: Path) -> Path:
    path = Path(os.path.abspath(value if value.is_absolute() else root / value))
    require(path.is_relative_to(root / WORK_PARENT) and path != root / WORK_PARENT,
            "candidate --work must be below this checkout's .work/x86_64")
    require(path.parent.is_dir() and path.parent.resolve() == path.parent, "candidate --work parent is not physical")
    return path


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--inputs", type=Path, help="JSON naming pre-seeded vendors and performance measurements")
    parser.add_argument("--through", help="run only the prefix ending at this step")
    parser.add_argument("--dry-run", action="store_true")
    values = parser.parse_args(arguments)
    try:
        work = _work(ROOT, values.work)
        inputs = _load_inputs(ROOT, values.inputs)
        if values.dry_run:
            print(json.dumps(dry_run(ROOT, work, inputs, values.through), indent=2, sort_keys=True))
            return 0
        summary = execute(ROOT, work, inputs, through=values.through)
    except CandidateError as error:
        print(f"x86 qualification candidate: ERROR: {error}", file=sys.stderr)
        return 2
    if summary["complete"]:
        print(f"x86 qualification candidate: PASS; summary: {work / 'summary.json'}")
        return 0
    if values.through is not None and "error" not in summary:
        print(f"x86 qualification candidate: prefix through {values.through} complete (not qualification); "
              f"summary: {work / 'summary.json'}")
        return 0
    print(f"x86 qualification candidate: INCOMPLETE ({summary.get('error')}); summary: {work / 'summary.json'}",
          file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
