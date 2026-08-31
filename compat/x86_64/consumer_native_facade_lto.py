#!/usr/bin/env python3
"""Run the AArch64-shaped native facade workload through private x86 full LTO.

This builds on the separately recorded x86 O3/full-LTO consumer comparison.
It compiles a materially broader no-std application through `crabc-rs`, links
only the current owned static-PIE boundary, inspects the final ELF, and executes
the descriptor workload twice. It is not stock Rust `std`, an installed
sysroot, libc/loader integration, or promotion evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import platform
import sys
import tempfile
from pathlib import Path
from typing import Mapping


ROOT = Path(__file__).resolve().parents[2]
BASE_PATH = ROOT / "compat/x86_64/consumer_static_pie_lto.py"
BASE_SPEC = importlib.util.spec_from_file_location("consumer_static_pie_lto_base", BASE_PATH)
assert BASE_SPEC is not None and BASE_SPEC.loader is not None
BASE = importlib.util.module_from_spec(BASE_SPEC)
sys.modules[BASE_SPEC.name] = BASE
BASE_SPEC.loader.exec_module(BASE)

EvidenceError = BASE.EvidenceError
FIXTURE = ROOT / "compat/x86_64/consumer_native_facade_lto_fixture.rs"
AARCH64_FIXTURE = ROOT / "compat/lto/native-facade-lto-fixture/src/main.rs"
EXPECTED_STDOUT = b"x86-native-facade-lto:ok\n"
DEFAULT_REPORT = ROOT / "compat/reports/x86_64/consumer-native-facade-lto/latest.json"
WORKLOAD_ROUTES = (
    "crabc_rs_native_facade_getpid_witness",
    "fs::openat",
    "io::write",
    "pipe::pipe_with",
    "io::read",
    "eventfd(",
    "io::fcntl_getfd",
    "eventfd_write",
    "eventfd_read",
)
ROUTE_SOURCES = (
    ROOT / "crabc-core/src/error.rs",
    ROOT / "crabc-core/src/event_x86_64.rs",
    ROOT / "crabc-core/src/fs.rs",
    ROOT / "crabc-core/src/io.rs",
    ROOT / "crabc-core/src/pipe.rs",
    ROOT / "crabc-core/src/process.rs",
    ROOT / "crabc-core/src/syscall_x86_64.rs",
    ROOT / "crabc-rs/src/event_x86_64.rs",
    ROOT / "crabc-rs/src/fd.rs",
    ROOT / "crabc-rs/src/fs_x86_64.rs",
    ROOT / "crabc-rs/src/io.rs",
    ROOT / "crabc-rs/src/pipe.rs",
    ROOT / "crabc-rs/src/process_x86_64.rs",
)


def closed_link_inputs(
    *,
    crt: Path,
    application: Path,
    helper: Path,
    facade: Path,
    core: Path,
    bitflags: Path,
    toolchain_core: Path,
    memory: Path,
    builtins: Path,
    extras: tuple[Path, ...] = (),
) -> list[Path]:
    """Use the established closed static-PIE order without widening it."""

    return BASE.closed_link_inputs(
        crt=crt,
        application=application,
        helper=helper,
        facade=facade,
        core=core,
        bitflags=bitflags,
        toolchain_core=toolchain_core,
        memory=memory,
        builtins=builtins,
        extras=extras,
    )


def application_command(
    *,
    output: Path,
    helper: Path,
    facade: Path,
    core: Path,
) -> list[str]:
    return [
        *BASE.rustc_command(),
        "--crate-name", "crabc_x86_consumer_native_facade_lto",
        "--crate-type", "bin",
        "--edition=2021",
        "--target", BASE.TARGET,
        "--emit=obj",
        "-C", "panic=abort",
        "-C", "force-unwind-tables=no",
        "-C", "overflow-checks=off",
        "-C", "opt-level=3",
        "-C", "codegen-units=1",
        "-C", "debuginfo=0",
        "-C", "relocation-model=pic",
        "-C", "linker-plugin-lto=yes",
        "-C", "metadata=crabc-x86-native-facade-full-lto-v1",
        "--remap-path-prefix", f"{ROOT}=/crabc",
        "-L", f"dependency={output.parent}",
        "--extern", f"crabc_x86_consumer_lto_helper={helper}",
        "--extern", f"crabc_rs={facade}",
        "--extern", f"crabc_core={core}",
        str(FIXTURE),
        "-o", str(output),
    ]


def validate_workload_sources() -> dict[str, object]:
    x86_source = FIXTURE.read_text(encoding="utf-8")
    aarch64_source = AARCH64_FIXTURE.read_text(encoding="utf-8")
    missing_x86 = [route for route in WORKLOAD_ROUTES if route not in x86_source]
    missing_aarch64 = [route for route in WORKLOAD_ROUTES if route not in aarch64_source]
    if missing_x86 or missing_aarch64:
        raise EvidenceError(
            "native-facade workload mapping drifted: "
            f"x86_missing={missing_x86}, aarch64_missing={missing_aarch64}"
        )
    return {
        "aarch64_fixture": str(AARCH64_FIXTURE.relative_to(ROOT)),
        "aarch64_fixture_sha256": BASE.sha256(AARCH64_FIXTURE),
        "x86_fixture": str(FIXTURE.relative_to(ROOT)),
        "x86_fixture_sha256": BASE.sha256(FIXTURE),
        "required_routes": list(WORKLOAD_ROUTES),
        "route_mapping_complete": True,
        "same_source_claimed": False,
    }


def inspect_native_facade(path: Path, tools: Mapping[str, str]) -> dict[str, object]:
    inspection = BASE.inspect_executable(path, tools)
    symbols = inspection.get("defined_symbols")
    if not isinstance(symbols, list):
        raise EvidenceError("native-facade inspection returned no defined-symbol inventory")
    required = {
        "crabc_rs_native_facade_getpid_witness",
        "native_facade_direct_route",
        "crabc_x86_consumer_lto_route",
        "__udivti3",
    }
    missing = sorted(required.difference(symbols))
    if missing:
        raise EvidenceError(f"native-facade image lacks inspection anchors: {missing}")
    if inspection.get("helper_symbol_present") is not False:
        raise EvidenceError("native-facade full LTO did not internalize the helper boundary")
    inspection["native_facade_symbols"] = sorted(required)
    inspection["cross_crate_helper_internalized"] = True
    return inspection


def run(report_path: Path) -> dict[str, object]:
    if platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        raise EvidenceError(
            f"native Linux/x86-64 is required, got {platform.system()}/{platform.machine()}"
        )
    version = BASE.command_record([*BASE.rustc_command(), "-Vv"])
    BASE.require_success(version, "pinned rustc identity")
    if f"host: {BASE.TARGET}" not in BASE.command_text(version):
        raise EvidenceError(f"pinned rustc host is not {BASE.TARGET}")
    workload = validate_workload_sources()

    with tempfile.TemporaryDirectory(prefix="crabc-x86-native-facade-lto-") as temporary:
        work = Path(temporary)
        tools, tool_path = BASE.pinned_tools(work)
        environment = BASE.deterministic_environment(tool_path)
        toolchain_core = BASE.resolve_pinned_core(Path(tools["target_libdir"]))
        crt, crt_record = BASE.build_crt(work, environment)
        builtins, builtins_record = BASE.build_builtins(work, environment)
        memory, memory_record = BASE.build_memory_leaf(work, environment, tools)
        rust_inputs, rust_record = BASE.build_rust_inputs(
            work,
            environment,
            name="native-facade-full-lto",
            linker_plugin_lto=True,
        )

        application = work / "native-facade-full-lto.o"
        compile_record = BASE.command_record(
            application_command(
                output=application,
                helper=rust_inputs["helper"],
                facade=rust_inputs["facade"],
                core=rust_inputs["core"],
            ),
            environment=environment,
        )
        BASE.require_success(compile_record, "native-facade full-LTO application compile")

        executable = work / "x86-native-facade-full-lto"
        link_map = work / "native-facade-full-lto.map"
        inputs = closed_link_inputs(
            crt=crt,
            application=application,
            helper=rust_inputs["helper"],
            facade=rust_inputs["facade"],
            core=rust_inputs["core"],
            bitflags=rust_inputs["bitflags"],
            toolchain_core=toolchain_core,
            memory=memory,
            builtins=builtins,
        )
        link_command = [
            tools["linker"],
            "-pie",
            "-static",
            "--no-dynamic-linker",
            "--gc-sections",
            "--build-id=none",
            "-z", "noexecstack",
            "-z", "relro",
            "-z", "now",
            "-e", "_start",
            f"-Map={link_map}",
            "--trace-symbol=__udivti3",
            "--lto-O3",
            *(str(path) for path in inputs),
            "-o", str(executable),
        ]
        link_record = BASE.command_record(link_command, environment=environment)
        BASE.require_success(link_record, "native-facade closed full-LTO link")
        link_text = BASE.command_text(link_record) + link_map.read_text(
            encoding="utf-8", errors="replace"
        )
        rejected = BASE.forbidden_runtime_markers(link_text)
        if rejected:
            raise EvidenceError(f"native-facade link selected a forbidden runtime: {rejected}")
        if str(builtins) not in BASE.command_text(link_record):
            raise EvidenceError("native-facade link did not attribute __udivti3 to owned builtins")

        inspection = inspect_native_facade(executable, tools)
        executions: list[dict[str, object]] = []
        for _ in range(2):
            record = BASE.command_record(
                [str(executable)],
                environment={"PATH": "/bin:/usr/bin", "LC_ALL": "C"},
            )
            stdout = record.get("stdout")
            stderr = record.get("stderr")
            passed = (
                record.get("returncode") == 0
                and isinstance(stdout, Mapping)
                and stdout.get("sha256") == hashlib.sha256(EXPECTED_STDOUT).hexdigest()
                and stdout.get("byte_length") == len(EXPECTED_STDOUT)
                and isinstance(stderr, Mapping)
                and stderr.get("byte_length") == 0
            )
            record["passed"] = passed
            executions.append(record)
            if not passed:
                raise EvidenceError("native-facade execution differed from fixed output")

        report = {
            "schema": "crabc.x86_64-consumer-native-facade-lto/v1",
            "status": "passed",
            "target": BASE.TARGET,
            "toolchain": BASE.TOOLCHAIN,
            "scope": (
                "private no-std AArch64-shaped crabc-rs filesystem/pipe/eventfd/process-I/O "
                "workload through the current closed static-PIE full-LTO boundary; not stock std, "
                "installed sysroot, libc, loader, source build, family completion, promotion, or public support"
            ),
            "claims": {
                "native_execution": True,
                "aarch64_native_facade_workload_shape": True,
                "cross_crate_full_lto": True,
                "direct_crabc_rs_facade": True,
                "filesystem_pipe_eventfd": True,
                "closed_final_link_inputs": True,
                "owned_crt_and_builtins": True,
                "owned_memory_leaf": True,
                "pinned_toolchain_core": True,
                "ambient_target_libc": False,
                "ambient_crt": False,
                "ambient_loader": False,
                "ambient_compiler_runtime": False,
                "stock_rust_std": False,
                "owned_sysroot": False,
                "source_build": False,
                "promotion": False,
                "public_support": False,
            },
            "workload_mapping": workload,
            "sources": {
                "compat/x86_64/consumer_native_facade_lto.py": BASE.sha256(
                    ROOT / "compat/x86_64/consumer_native_facade_lto.py"
                ),
                str(FIXTURE.relative_to(ROOT)): BASE.sha256(FIXTURE),
                str(AARCH64_FIXTURE.relative_to(ROOT)): BASE.sha256(AARCH64_FIXTURE),
                "compat/x86_64/consumer_static_pie_lto.py": BASE.sha256(BASE_PATH),
                "compat/x86_64/consumer_static_pie_lto_helper.rs": BASE.sha256(BASE.HELPER_SOURCE),
                "Cargo.lock": BASE.sha256(ROOT / "Cargo.lock"),
                "rust-toolchain.toml": BASE.sha256(ROOT / "rust-toolchain.toml"),
                **{
                    str(source.relative_to(ROOT)): BASE.sha256(source)
                    for source in ROUTE_SOURCES
                },
            },
            "rustc": version,
            "tools": {
                name: {
                    "path": str(Path(tools[name]).resolve()),
                    "sha256": BASE.sha256(Path(tools[name]).resolve()),
                }
                for name in ("linker", "nm", "readelf", "objdump", "ar")
            },
            "crt": crt_record,
            "builtins": builtins_record,
            "memory": memory_record,
            "pinned_toolchain_core": {
                "path": str(toolchain_core),
                "sha256": BASE.sha256(toolchain_core),
                "byte_length": toolchain_core.stat().st_size,
                "target_libdir": tools["target_libdir"],
            },
            "rust_inputs": rust_record,
            "lane": {
                "status": "passed",
                "lto": "full-linker-plugin",
                "compile": compile_record,
                "application_object": {
                    "path": str(application),
                    "sha256": BASE.sha256(application),
                    "byte_length": application.stat().st_size,
                },
                "link": link_record,
                "closed_inputs": [
                    {
                        "path": str(path),
                        "sha256": BASE.sha256(path),
                        "byte_length": path.stat().st_size,
                    }
                    for path in inputs
                ],
                "link_map": {
                    "sha256": BASE.sha256(link_map),
                    "byte_length": link_map.stat().st_size,
                },
                "inspection": inspection,
                "executions": executions,
            },
        }
    BASE.atomic_write(report_path, report)
    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    report_path = arguments.report.expanduser().resolve()
    try:
        report = run(report_path)
    except EvidenceError as error:
        print(f"x86 native-facade LTO consumer: ERROR: {error}", file=sys.stderr)
        return 1
    print(
        "x86 native-facade LTO consumer: PASS "
        "(filesystem/pipe/eventfd crabc-rs full LTO; closed runtime; non-promoting)"
    )
    print(f"report: {report_path}")
    return 0 if report.get("status") == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
