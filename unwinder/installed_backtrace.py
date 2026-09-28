#!/usr/bin/env python3
"""Run and reread direct backtrace calls through source-bound owned products."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import resource
import subprocess
import sys
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


def replay(command: list[str], output: Path, labels: tuple[str, ...]) -> dict[str, Any]:
    try:
        result = subprocess.run(command, env=owned.clean_environment(), text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90)
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
    observations = owned.assert_backtrace_execution(code, out, err, labels)
    return {"command": command, "status": code,
            "stdout": owned.record_file(stdout, "backtrace replay stdout"),
            "stderr": owned.record_file(stderr, "backtrace replay stderr"),
            "status_file": owned.record_file(status, "backtrace replay status"),
            "backtrace": observations}


def replay_record(record: dict[str, Any], labels: tuple[str, ...]) -> list[dict[str, Any]]:
    stdout = require_record(record["stdout"], "backtrace replay stdout").read_text(encoding="utf-8")
    stderr = require_record(record["stderr"], "backtrace replay stderr").read_text(encoding="utf-8")
    status = int(require_record(record["status_file"], "backtrace replay status").read_text(encoding="utf-8"))
    owned.require(status == record["status"] and isinstance(record["command"], list)
                  and all(isinstance(item, str) for item in record["command"]),
                  "backtrace replay command or exit status changed")
    observations = owned.assert_backtrace_execution(status, stdout, stderr, labels)
    owned.require(observations == record["backtrace"], "backtrace replay frames changed after collection")
    return observations


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
