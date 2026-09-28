#!/usr/bin/env python3
"""Run and reread direct backtrace calls through source-bound owned products."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import resource
import shutil
import subprocess
import sys
import tomllib
from typing import Any

import cleanup
import owned_cleanup as owned


COMPAT = owned.CHECKOUT / "compat/x86_64"
if str(COMPAT) not in sys.path:
    sys.path.insert(0, str(COMPAT))
import owned_dynamic_qualification as dynamic_qualification
import owned_posix_static_products as static_products

DSO_LABELS = ("dso-worker", "dso-main")
STATIC_LABELS = ("static-nested",)
GUARDED_CFI_OUTPUT = "mapped unwind=5\nmapped wait=0\nunreadable unwind=3\nunreadable wait=0\n"
GUARDED_CFI_HOST = owned.ROOT / "fixtures/guarded_dso_cfi_host.c"
GUARDED_CFI_PLUGIN = owned.ROOT / "fixtures/guarded_dso_cfi_plugin.c"


def require_record(record: dict[str, str], description: str) -> Path:
    owned.require(set(record) == {"path", "sha256"}, f"{description} file record is malformed")
    path = owned.physical(Path(record["path"]), description)
    owned.require(owned.record_file(path, description) == record, f"{description} changed after collection")
    return path


def image_identity(path: Path) -> tuple[dict[str, str], str]:
    path = owned.physical(path, "immutable core image inspection")
    inspection = json.loads(path.read_text(encoding="utf-8"))
    owned.require(isinstance(inspection, list) and len(inspection) == 1 and isinstance(inspection[0], dict),
                  "core image inspection is malformed")
    image = inspection[0]
    identity = image.get("Id")
    owned.require(isinstance(identity, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", identity) is not None
                  and image.get("Os") == "linux" and image.get("Architecture") == "amd64",
                  "core image inspection does not identify an immutable x86-64 Linux image")
    return owned.record_file(path, "immutable core image inspection"), identity


def source_products(static_path: Path, dynamic_path: Path) -> tuple[dict[str, str], dict[str, Any], dict[str, Any], dict[str, Any]]:
    static_path = owned.physical(static_path, "static preparation receipt")
    dynamic_path = owned.physical(dynamic_path, "dynamic qualification receipt")
    revision = dynamic_qualification.require_clean_source()
    source = dynamic_qualification.source_digest()
    static = static_products.validate_receipt(owned.CHECKOUT, static_path)
    dynamic = dynamic_qualification.validate_receipt(dynamic_path)
    owned.require(static["source"] == {"revision": revision, "content_sha256": source},
                  "static preparation differs from current source")
    owned.require(dynamic["source_sha256"] == source and dynamic["status"] == "qualified-pending-review",
                  "dynamic qualification differs from current source or failed its matrix")
    owned.require(len(dynamic["cases"]) == 3 * len(dynamic_qualification.CASES),
                  "dynamic qualification has an incomplete three-product matrix")
    static_primary = owned.product_snapshot(owned.CHECKOUT / static["products"]["primary"]["path"], "static")
    static_extracted = owned.product_snapshot(owned.CHECKOUT / static["products"]["extracted"]["path"], "static")
    dynamic_installed = owned.product_snapshot(dynamic_path.parent / "installed", "dynamic")
    dynamic_extracted = owned.product_snapshot(dynamic_path.parent / "extracted", "dynamic")
    owned.require(static_primary["manifest"]["sha256"] == static_extracted["manifest"]["sha256"],
                  "extracted static product differs from installed static product")
    owned.require(dynamic_installed["manifest"]["sha256"] == dynamic_extracted["manifest"]["sha256"],
                  "extracted dynamic product differs from installed dynamic product")
    products = {"static": static_primary, "static_extracted": static_extracted,
                "dynamic": dynamic_installed, "dynamic_extracted": dynamic_extracted}
    return {"revision": revision, "content_sha256": source}, products, static, dynamic


def capture(command: list[str], output: Path, *, timeout: int = 90) -> dict[str, Any]:
    try:
        result = subprocess.run(command, env=owned.clean_environment(), text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        code, out, err = result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired as error:
        code = 124
        out = error.stdout.decode(errors="replace") if isinstance(error.stdout, bytes) else error.stdout or ""
        err = error.stderr.decode(errors="replace") if isinstance(error.stderr, bytes) else error.stderr or ""
    stdout = output.with_suffix(".stdout")
    stderr = output.with_suffix(".stderr")
    status = output.with_suffix(".status")
    for path, value in ((stdout, out), (stderr, err), (status, f"{code}\n")):
        with path.open("x", encoding="utf-8") as stream:
            stream.write(value)
    return {"command": command, "status": code,
            "stdout": owned.record_file(stdout, "backtrace replay stdout"),
            "stderr": owned.record_file(stderr, "backtrace replay stderr"),
            "status_file": owned.record_file(status, "backtrace replay status")}


def capture_record(record: dict[str, Any]) -> tuple[int, str, str]:
    stdout = require_record(record["stdout"], "backtrace replay stdout").read_text(encoding="utf-8")
    stderr = require_record(record["stderr"], "backtrace replay stderr").read_text(encoding="utf-8")
    status = int(require_record(record["status_file"], "backtrace replay status").read_text(encoding="utf-8"))
    owned.require(status == record["status"] and isinstance(record["command"], list)
                  and all(isinstance(item, str) for item in record["command"]),
                  "backtrace replay command or exit status changed")
    return status, stdout, stderr


def replay(command: list[str], output: Path, labels: tuple[str, ...]) -> dict[str, Any]:
    record = capture(command, output)
    status, stdout, stderr = capture_record(record)
    record["backtrace"] = owned.assert_backtrace_execution(status, stdout, stderr, labels)
    return record


def replay_record(record: dict[str, Any], labels: tuple[str, ...]) -> list[dict[str, Any]]:
    status, stdout, stderr = capture_record(record)
    observations = owned.assert_backtrace_execution(status, stdout, stderr, labels)
    owned.require(observations == record["backtrace"], "backtrace replay frames changed after collection")
    return observations


def guarded_cfi_result(status: int, stdout: str, stderr: str) -> dict[str, dict[str, int]]:
    owned.require(status == 0 and stderr == "" and stdout == GUARDED_CFI_OUTPUT,
                  "guarded DSO CFI child faulted or changed its unwind phase result")
    return {"mapped": {"unwind": 5, "wait": 0}, "unreadable": {"unwind": 3, "wait": 0}}


def guarded_cfi_link_command(linker: Path, inputs: list[Path], plugin: Path) -> list[str]:
    return [str(linker), "-shared", "--hash-style=sysv", "--eh-frame-hdr", "-z", "relro", "-z", "now",
            "-z", "noexecstack", "-z", "text", "--no-undefined", "--allow-shlib-undefined",
            "--enable-new-dtags", "-rpath", "/usr/lib", "-soname", plugin.name, "-t",
            *(str(path) for path in inputs), "-o", str(plugin)]


def guarded_cfi_case(product: dict[str, Any], provider: dict[str, Any], output: Path) -> dict[str, Any]:
    """Add the guarded CFI worker to the installed DSO replay matrix."""
    output = owned.work_child(output, "guarded DSO replay output")
    output.mkdir(mode=0o755)
    output = owned.physical(output, "guarded DSO replay output", directory=True)
    root = Path(product["root"])
    channel = tomllib.loads((owned.CHECKOUT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    target = capture(["rustup", "run", channel, "rustc", "--target", owned.TARGET,
                      "--print", "target-libdir"], output / "target-libdir")
    status, target_text, stderr = capture_record(target)
    owned.require(status == 0 and stderr == "", "guarded DSO target library discovery failed")
    libdir = owned.physical(Path(target_text.strip()), "pinned target library directory", directory=True)
    linker = owned.physical(libdir.parent / "bin/gcc-ld/ld.lld", "pinned linker", executable=True)
    compiler_name = shutil.which("clang")
    owned.require(compiler_name is not None, "pinned C compiler is unavailable")
    compiler = owned.physical(Path(os.path.realpath(compiler_name)), "pinned C compiler", executable=True)
    object_file = output / "plugin.o"
    plugin = output / "libcrabc_guarded_dso_cfi.so"
    host = output / "guarded-host"
    compile_command = [str(compiler), "--target=x86_64-unknown-linux-musl", "-fPIC", "-O1",
                       "-fno-omit-frame-pointer", "-nostdinc", "-isystem", str(root / "usr/include"),
                       "-c", str(GUARDED_CFI_PLUGIN), "-o", str(object_file)]
    inputs = [root / "usr/lib/crti.o", object_file, Path(provider["archive"]["path"]),
              root / "usr/lib/libc.so", root / "usr/lib/libcrabc-builtins.a", root / "usr/lib/crtn.o"]
    steps = {"target": target}
    for name, command in (
        ("compile", compile_command),
        ("link", guarded_cfi_link_command(linker, inputs, plugin)),
        ("host", [str(root / "bin/crabc-cc-dynamic"), "--dynamic-pie", str(GUARDED_CFI_HOST),
                  "-o", str(host)]),
        ("fde", ["readelf", "-wf", str(plugin)]),
        ("dynamic", ["readelf", "-d", str(plugin)]),
    ):
        step = capture(command, output / name)
        step_status, _, step_stderr = capture_record(step)
        owned.require(step_status == 0 and step_stderr == "", f"guarded DSO {name} failed")
        steps[name] = step
    loader = owned.physical(root / "lib/ld-crabc-x86_64.so.1", "owned loader", executable=True)
    steps["execution"] = capture([str(loader), "--library-path", f"{output}:{root / 'usr/lib'}",
                                  str(host)], output / "execution", timeout=20)
    record = {
        "sources": [owned.record_file(path, "guarded DSO source") for path in (GUARDED_CFI_HOST, GUARDED_CFI_PLUGIN)],
        "compiler": owned.record_file(compiler, "pinned C compiler"),
        "linker": owned.record_file(linker, "pinned linker"),
        "object": owned.record_file(object_file, "guarded DSO object"),
        "plugin": owned.record_file(plugin, "guarded DSO plugin"),
        "host": owned.record_file(host, "guarded DSO host"),
        "host_link": owned.record_file(Path(str(host) + ".crabc-link.json"), "guarded host link receipt"),
        "link_inputs": [owned.record_file(path, "guarded DSO link input") for path in inputs],
        "steps": steps,
        "observed": guarded_cfi_result(*capture_record(steps["execution"])),
    }
    validate_guarded_cfi_case(record, product, provider)
    return record


def validate_guarded_cfi_case(record: dict[str, Any], product: dict[str, Any], provider: dict[str, Any]) -> None:
    root = Path(product["root"])
    owned.require([require_record(item, "guarded DSO source") for item in record["sources"]]
                  == [GUARDED_CFI_HOST, GUARDED_CFI_PLUGIN], "guarded DSO sources changed")
    compiler = require_record(record["compiler"], "pinned C compiler")
    linker = require_record(record["linker"], "pinned linker")
    object_file = require_record(record["object"], "guarded DSO object")
    plugin = require_record(record["plugin"], "guarded DSO plugin")
    host = require_record(record["host"], "guarded DSO host")
    host_link = owned.json_object(require_record(record["host_link"], "guarded host link receipt"),
                                  "guarded host link receipt")
    owned.require(host_link.get("output_sha256") == owned.digest(host)
                  and host_link.get("manifest_sha256") == product["manifest"]["sha256"]
                  and host_link.get("runtime_imports") == [], "guarded host used another runtime")
    inputs = [root / "usr/lib/crti.o", object_file, Path(provider["archive"]["path"]),
              root / "usr/lib/libc.so", root / "usr/lib/libcrabc-builtins.a", root / "usr/lib/crtn.o"]
    owned.require([require_record(item, "guarded DSO link input") for item in record["link_inputs"]] == inputs,
                  "guarded DSO link inputs changed")
    steps = record["steps"]
    for name in ("target", "compile", "link", "host", "fde", "dynamic"):
        status, _, stderr = capture_record(steps[name])
        owned.require(status == 0 and stderr == "", f"guarded DSO {name} observation changed")
    target_text = capture_record(steps["target"])[1]
    owned.require(Path(target_text.strip()).parent / "bin/gcc-ld/ld.lld" == linker,
                  "guarded DSO selected another linker")
    owned.require(steps["compile"]["command"] ==
                  [str(compiler), "--target=x86_64-unknown-linux-musl", "-fPIC", "-O1",
                   "-fno-omit-frame-pointer", "-nostdinc", "-isystem", str(root / "usr/include"),
                   "-c", str(GUARDED_CFI_PLUGIN), "-o", str(object_file)],
                  "guarded DSO compile command changed")
    owned.require(steps["link"]["command"] == guarded_cfi_link_command(linker, inputs, plugin)
                  and steps["host"]["command"] ==
                  [str(root / "bin/crabc-cc-dynamic"), "--dynamic-pie", str(GUARDED_CFI_HOST), "-o", str(host)],
                  "guarded DSO link command changed")
    trace = capture_record(steps["link"])[1]
    fde = capture_record(steps["fde"])[1]
    dynamic = capture_record(steps["dynamic"])[1]
    owned.require(str(provider["archive"]["path"]) in trace and str(root / "usr/lib/libc.so") in trace
                  and not any(name in trace for name in ("libgcc", "libunwind"))
                  and "DW_CFA_expression: r16 (rip) (DW_OP_breg3 (rbx): 0)" in fde
                  and "Shared library: [libc.so]" in dynamic
                  and "Library soname: [libcrabc_guarded_dso_cfi.so]" in dynamic,
                  "guarded DSO CFI ELF or selected provider changed")
    owned.require(steps["execution"]["command"] ==
                  [str(root / "lib/ld-crabc-x86_64.so.1"), "--library-path",
                   f"{plugin.parent}:{root / 'usr/lib'}", str(host)]
                  and guarded_cfi_result(*capture_record(steps["execution"])) == record["observed"],
                  "guarded DSO CFI child result changed")


def owned_receipt(path: Path, products: dict[str, Any]) -> dict[str, Any]:
    record = owned.json_object(path, "owned cleanup receipt")
    owned.assert_nonpromoting(record, "owned cleanup receipt")
    owned.require(record["source_inputs"] == owned.source_snapshot(), "owned cleanup source changed")
    owned.require(record["products"] == {"static": products["static"], "dynamic": products["dynamic"]},
                  "owned cleanup used different products")
    provider = record["provider"]
    archive = require_record(provider["archive"], "selected standalone provider archive")
    require_record(provider["provenance"], "selected standalone provider provenance")
    owned.require(owned.provider_snapshot(archive.parent, provider["record"]["toolchain"]) == provider,
                  "selected standalone provider changed")
    for mode in ("static", "dynamic"):
        consumer = record["stock_consumers"][mode]
        binary = require_record(consumer["binary"], f"stock {mode} executable")
        link_path = require_record(consumer["link_receipt"], f"stock {mode} link receipt")
        link = owned.json_object(link_path, f"stock {mode} link receipt")
        owned.require(link.get("output") == owned.record_file(binary, f"stock {mode} executable")
                      and link.get("provider_archive") == provider["archive"]
                      and link.get("resolved_input_trace") == consumer["link_trace"]
                      and link.get("command") == consumer["link_command"],
                      f"stock {mode} link inputs changed")
        owned.require("libcrabc-unwind.a" in consumer["link_trace"]
                      and not any(name in consumer["link_trace"] for name in ("libgcc", "libunwind")),
                      f"stock {mode} link admitted an ambient unwind provider")
        execution = consumer["execution"]
        stdout = require_record(execution["stdout"], f"stock {mode} stdout").read_text()
        stderr = require_record(execution["stderr"], f"stock {mode} stderr").read_text()
        cleanup.assert_execution(execution["status"], stdout + stderr)
    for name, labels in (("static", STATIC_LABELS), ("dynamic_dso", DSO_LABELS)):
        consumer = record["source_built_consumers"][name]
        parts = [(name, consumer)]
        if name == "dynamic_dso":
            parts.append(("plugin", consumer["plugin"]))
        for part_name, part in parts:
            binary = require_record(part["binary"], f"source-built {part_name} executable")
            link_path = require_record(part["link_receipt"], f"source-built {part_name} link receipt")
            link = owned.json_object(link_path, f"source-built {part_name} link receipt")
            lto = link.get("source_lto_object")
            owned.require(link.get("output") == owned.record_file(binary, f"source-built {part_name} executable")
                          and link.get("resolved_input_trace") == part["link_trace"]
                          and link.get("command") == part["link_command"]
                          and isinstance(lto, dict) and lto.get("defined_unwind_abi") == sorted(owned.build.UNWIND_ABI)
                          and "provider_archive" not in link and "omitted_source_built_rust_unwind" not in link,
                          f"source-built {part_name} link inputs changed")
            require_record(lto["retained_object"], f"source-built {part_name} fused unwind object")
            owned.require(not any(name in part["link_trace"] for name in ("libgcc", "libunwind")),
                          f"source-built {part_name} link admitted an ambient unwind provider")
        execution = consumer["execution"]
        stdout = require_record(execution["stdout"], f"source-built {name} stdout").read_text()
        stderr = require_record(execution["stderr"], f"source-built {name} stderr").read_text()
        observed = owned.assert_backtrace_execution(execution["status"], stdout, stderr, labels)
        owned.require(observed == execution["backtrace"], f"source-built {name} backtrace changed")
    return record


def run(static_path: Path, dynamic_path: Path, vendor: Path, image_inspect: Path, output: Path) -> Path:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    source, products, _, _ = source_products(static_path, dynamic_path)
    image_record, image_id = image_identity(image_inspect)
    output = owned.work_child(output, "installed backtrace output")
    output.mkdir(mode=0o755)
    output = owned.physical(output, "installed backtrace output", directory=True)
    native = owned.run(Path(products["static"]["root"]), Path(products["dynamic"]["root"]), vendor,
                       output / "owned-cleanup")
    native_receipt = owned.physical(native / "receipt.json", "owned cleanup receipt")
    selected = owned_receipt(native_receipt, products)
    static_binary = selected["source_built_consumers"]["static"]["binary"]["path"]
    dso = selected["source_built_consumers"]["dynamic_dso"]
    dso_binary = dso["binary"]["path"]
    plugin = Path(dso["plugin"]["binary"]["path"])
    static_replay = replay([static_binary], output / "static-replay", STATIC_LABELS)
    dso_replays = {}
    for name, product in (("installed", products["dynamic"]), ("extracted", products["dynamic_extracted"])):
        root = Path(product["root"])
        loader = owned.physical(root / "lib/ld-crabc-x86_64.so.1", f"{name} owned dynamic loader", executable=True)
        command = [str(loader), "--library-path", f"{plugin.parent}:{root / 'usr/lib'}", dso_binary]
        dso_replays[name] = replay(command, output / f"{name}-dso-replay", DSO_LABELS)
    dso_replays["guarded-cfi-installed"] = guarded_cfi_case(
        products["dynamic"], selected["provider"], output / "guarded-cfi-installed")
    owned.require([entry["label"] for entry in dso_replays["installed"]["backtrace"]]
                  == [entry["label"] for entry in dso_replays["extracted"]["backtrace"]],
                  "installed and extracted DSO completion differs")
    owned.require(dynamic_qualification.require_clean_source() == source["revision"]
                  and dynamic_qualification.source_digest() == source["content_sha256"],
                  "source changed during backtrace collection")
    for name, snapshot in products.items():
        mode = "static" if name.startswith("static") else "dynamic"
        owned.assert_same_product(snapshot, mode)
    receipt = {"schema": 1, "scope": "source-bound installed direct backtrace development proof",
               "qualified": False, "family_completion": False, "promotion_ready": False,
               "public_support": False, "source": source, "image": {"inspection": image_record, "id": image_id},
               "static_preparation": owned.record_file(static_path, "static preparation receipt"),
               "dynamic_qualification": owned.record_file(dynamic_path, "dynamic qualification receipt"),
               "products": products, "owned_cleanup": owned.record_file(native_receipt, "owned cleanup receipt"),
               "static_replay": static_replay, "dso_replays": dso_replays}
    with (output / "receipt.json").open("x", encoding="utf-8") as stream:
        json.dump(receipt, stream, indent=2, sort_keys=True)
        stream.write("\n")
    return output / "receipt.json"


def validate(path: Path) -> dict[str, Any]:
    receipt = owned.json_object(path, "installed backtrace receipt")
    owned.require(receipt.get("schema") == 1 and receipt.get("scope") ==
                  "source-bound installed direct backtrace development proof", "backtrace receipt schema changed")
    owned.assert_nonpromoting(receipt, "installed backtrace receipt")
    image_record = receipt["image"]["inspection"]
    current_image, image_id = image_identity(require_record(image_record, "immutable core image inspection"))
    owned.require(current_image == image_record and image_id == receipt["image"]["id"],
                  "immutable core image changed")
    static_path = require_record(receipt["static_preparation"], "static preparation receipt")
    dynamic_path = require_record(receipt["dynamic_qualification"], "dynamic qualification receipt")
    source, products, _, _ = source_products(static_path, dynamic_path)
    owned.require(source == receipt["source"] and products == receipt["products"],
                  "installed backtrace source or products changed")
    native_path = require_record(receipt["owned_cleanup"], "owned cleanup receipt")
    selected = owned_receipt(native_path, products)
    static_binary = selected["source_built_consumers"]["static"]["binary"]["path"]
    owned.require(receipt["static_replay"]["command"] == [static_binary],
                  "static replay did not select its retained executable")
    replay_record(receipt["static_replay"], STATIC_LABELS)
    dso = selected["source_built_consumers"]["dynamic_dso"]
    dso_binary = dso["binary"]["path"]
    plugin = Path(dso["plugin"]["binary"]["path"])
    for name, product in (("installed", products["dynamic"]), ("extracted", products["dynamic_extracted"])):
        root = Path(product["root"])
        command = [str(root / "lib/ld-crabc-x86_64.so.1"), "--library-path",
                   f"{plugin.parent}:{root / 'usr/lib'}", dso_binary]
        entry = receipt["dso_replays"][name]
        owned.require(entry["command"] == command, f"{name} DSO replay used another product")
        replay_record(entry, DSO_LABELS)
    validate_guarded_cfi_case(receipt["dso_replays"]["guarded-cfi-installed"],
                              products["dynamic"], selected["provider"])
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("run", "validate"))
    parser.add_argument("--static-preparation", type=Path)
    parser.add_argument("--dynamic-qualification", type=Path)
    parser.add_argument("--provider-vendor", type=Path)
    parser.add_argument("--image-inspect", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args()
    try:
        if args.operation == "run":
            owned.require(args.receipt is None and all((args.static_preparation, args.dynamic_qualification,
                          args.provider_vendor, args.image_inspect, args.output)), "run requires all physical inputs")
            print(run(args.static_preparation, args.dynamic_qualification, args.provider_vendor,
                      args.image_inspect, args.output))
        else:
            owned.require(args.receipt is not None and all(value is None for value in
                          (args.static_preparation, args.dynamic_qualification, args.provider_vendor,
                           args.image_inspect, args.output)), "validate requires only a receipt")
            validate(args.receipt)
            print("installed backtrace receipt: valid")
    except (owned.OwnedCleanupError, OSError, ValueError, KeyError, TypeError,
            subprocess.SubprocessError, json.JSONDecodeError) as error:
        print(f"installed backtrace: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
