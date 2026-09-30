#!/usr/bin/env python3
"""Compare public external arena capacity, partial publication and destruction."""
import argparse
import json
import hashlib
import os
import re
import tarfile
from pathlib import Path
import shutil
import sys
import tempfile

import run as harness
import x86_64_m4_gate as m4
from x86_64_m6_heap_convenience import record, receipts
from x86_64_m6_upstream_heap_stress import stress

RUNNER = "allocator-management-capacity"
PROFILES = ("release", "debug-1", "stat-1", "stat-2")
DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m2_management_capacity_driver.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m2-management-capacity"
IMAGE_ID = "sha256:4815f7fbcc2cd03ea82574fff38441365f9aced034008b0468d0d2758aa286ec"
PARAMETERS = {"profiles": ",".join(PROFILES), "boundary": "native-mi-adapter", "watchdog-seconds": "60",
    "ownership": "external-capacity; partial-parent; child-destroy; caller-release"}
SOURCE_AUDIT = b"source.capacity=1,1,1,1,1\n"


def fingerprint(path):
    return {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "size": path.stat().st_size}


def c_command(source, binary, profile, compiler):
    return [compiler, "-std=c11", "-D_GNU_SOURCE", "-ftls-model=initial-exec",
        "-DMI_LIBC_MUSL=1", *m4.api_profile_flags(profile), "-UNDEBUG",
        "-I", str(source / "include"), "-I", str(source / "src"), "-DCRABC_SOURCE_AUDIT=1",
        "/workspace/compat/allocator/" + DRIVER.name, str(source / "src/static.c"), "-pthread", "-o", str(binary)]


def native_build_command(target, profile, cargo):
    return [cargo, "build", "--locked", "--offline", "--release", "--target", m4.RUST_TARGET,
        "-p", m4.ADAPTER_PACKAGE, "--target-dir", str(target),
        *(("--features", f"crabc-mimalloc/mi-{profile}") if profile != "release" else ())]


def native_link_command(source, binary, library, compiler):
    return [compiler, "-std=c11", "-D_GNU_SOURCE", "-UNDEBUG", "-I", str(source / "include"),
        "/workspace/compat/allocator/" + DRIVER.name, str(library), "-pthread", "-o", str(binary)]


def save_record(output, name, result):
    path = output / (name + ".json")
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(result, indent=2) + "\n")
    os.replace(temporary, path)


def numeric_trace(raw, header):
    # The retained pinned header supplies the public statistics fields and
    # bin dimensions. No field can disappear merely because both sides agree.
    fields = {"header": 2}
    definitions = header.split("#define MI_STAT_FIELDS()", 1)[1].split("// Size bins", 1)[0]
    for kind, name in re.findall(r"MI_STAT_(COUNT|COUNTER)\(([A-Za-z_][A-Za-z_0-9]*)\)", definitions):
        fields[name] = 3 if kind == "COUNT" else 1
    bins = int(re.search(r"#define MI_BIN_HUGE\s+\(([0-9]+)U\)", header)[1]) + 1
    chunk_definition = header.split("typedef enum mi_chunkbin_e", 1)[1].split("MI_CBIN_COUNT", 1)[0]
    chunks = len(re.findall(r"\bMI_CBIN_[A-Z]+\b", chunk_definition))
    for i in range(4):
        fields[f"reserved_count{i}"] = 3
        fields[f"reserved_counter{i}"] = 1
    for group, count in (("malloc_bin", bins), ("page_bin", bins), ("chunk_bin", chunks)):
        for i in range(count): fields[f"{group}{i}"] = 3
    expected = {f"stats.{phase}.{name}": width for phase in
        ("initial", "filled", "partial", "refused", "joined") for name, width in fields.items()}
    invariants = {
        "capacity.geometry": (33554432, 268435456, 160), "capacity.accepted": (159,),
        "capacity.partial": (1, 1, 17179869184, 1, 1, 1, 1),
        "capacity.refusal": (1, 1, 1, 1, 1), "capacity.terminal": (161, 161, 1, 1),
    }
    expected.update({key: len(values) for key, values in invariants.items()})
    lines = raw.decode("ascii").splitlines()
    if lines[:1] != ["CRABC_MI_MANAGEMENT_CAPACITY_BEGIN"] or lines[-1:] != ["CRABC_MI_MANAGEMENT_CAPACITY_END"]:
        raise receipts.ReceiptError("management capacity trace markers differ")
    values = {}
    for line in lines[1:-1]:
        key, separator, text = line.partition("=")
        if not separator or key not in expected or key in values:
            raise receipts.ReceiptError("management capacity numeric field roster differs")
        tokens = text.split(",")
        if len(tokens) != expected[key] or any(not re.fullmatch(r"0|-?[1-9][0-9]*", token) for token in tokens):
            raise receipts.ReceiptError("management capacity numeric value malformed")
        values[key] = tuple(map(int, tokens))
    if set(values) != set(expected) or any(values.get(key) != value for key, value in invariants.items()):
        raise receipts.ReceiptError("management capacity caller/mapping invariant differs")
    size = 16 + 8 * sum(width for name, width in fields.items() if name != "header")
    version = int(re.search(r"#define MI_STAT_VERSION\s+([0-9]+)", header)[1])
    if any(values[f"stats.{phase}.header"] != (size, version) for phase in
            ("initial", "filled", "partial", "refused", "joined")):
        raise receipts.ReceiptError("management capacity public statistics header differs")
    return values


def read():
    receipt = receipts.read_receipt(harness.ROOT, RUNNER)
    if dict(receipt.parameters) != PARAMETERS:
        raise receipts.ReceiptError("management capacity canonical parameters differ")
    expected_cases = [f"{profile}-{stage}" for profile in PROFILES for stage in ("c-link", "c-run")]
    expected_cases += [f"{profile}-{stage}" for profile in PROFILES for stage in
        ("native-build", "native-link", "native-run", "comparison")]
    if receipt.case_ids() != expected_cases:
        raise receipts.ReceiptError("management capacity fixed ordered case roster differs")
    pin = harness.load_pin()
    archive_name = f"mimalloc-{pin['version']}.tar.gz"
    expected_products = {"inputs.json", DRIVER.name, archive_name, "mimalloc.h", "mimalloc-stats.h", "LICENSE"}
    expected_products.update(f"{profile}-{name}" for profile in PROFILES for name in ("c", "native", "native-mi-adapter.a"))
    if set(receipt.products) != expected_products:
        raise receipts.ReceiptError("management capacity physical product roster differs")
    products = receipt.path.parent / "products"
    if (products / DRIVER.name).read_bytes() != DRIVER.read_bytes():
        raise receipts.ReceiptError("management capacity current caller bytes differ")
    if fingerprint(products / archive_name)["sha256"] != pin["sha256"]:
        raise receipts.ReceiptError("management capacity pinned archive differs")
    with tarfile.open(products / archive_name) as archive:
        for name, relative in (("mimalloc.h", "include/mimalloc.h"), ("mimalloc-stats.h", "include/mimalloc-stats.h"), ("LICENSE", "LICENSE")):
            if (products / name).read_bytes() != archive.extractfile(pin["archive_root"] + "/" + relative).read():
                raise receipts.ReceiptError("management capacity pinned header/license bytes differ")
    inputs = json.loads((products / "inputs.json").read_text())
    expected_inputs = {"source": dict(receipt.source), "execution": {"execution_mode": "native",
        "host_architecture": "x86_64", "image_id": IMAGE_ID}, "upstream": pin,
        "profiles": list(PROFILES), "boundary": "public native-mi-adapter over pinned musl",
        "ownership": "distinct external spans; live child; joined exit; destroy; caller release",
        "capacity": 160, "partial-parent-bytes": 17179869184, "runtime-watchdog-seconds": 60}
    if inputs != expected_inputs:
        raise receipts.ReceiptError("management capacity source/profile/execution inputs differ")
    manifest = json.loads(receipt.path.read_text())
    relative = manifest["work"]
    if not isinstance(relative, str) or not re.fullmatch(r"\.work/allocator-x86_64/target/compat/allocator/x86_64/m2-management-capacity/run-[a-z0-9_]+", relative):
        raise receipts.ReceiptError("management capacity canonical output namespace differs")
    work = Path("/workspace") / relative
    source = work / "source" / pin["archive_root"]
    logs = receipt.path.parent / "logs"
    cases = {case["id"]: case for case in receipt.cases}

    def command(name, argv, product, binding):
        names = {name + suffix for suffix in (".json", ".stdout", ".stderr")}
        if set(cases[name]["logs"]) != names:
            raise receipts.ReceiptError("management capacity command log roster differs")
        event = json.loads((logs / (name + ".json")).read_text())
        if (set(event) != {"command", "kind", "status", "stdout", "stderr", binding}
                or event["command"] != argv or event["kind"] != "process" or type(event["status"]) is not int
                or event["status"] != 0 or event[binding] != {argv[-1]: receipt.products[product]}):
            raise receipts.ReceiptError("management capacity command/product binding differs")
        for stream in ("stdout", "stderr"):
            if stress.byte_record_payload(event[stream], name) != (logs / (name + "." + stream)).read_bytes():
                raise receipts.ReceiptError("management capacity raw command streams differ")
        return (logs / (name + ".stdout")).read_bytes(), (logs / (name + ".stderr")).read_bytes()

    header = (products / "mimalloc-stats.h").read_text()
    for profile in PROFILES:
        c = work / profile / "c"
        native = work / profile / "native"
        library = work / profile / "native-mi-adapter.a"
        command(f"{profile}-c-link", c_command(source, c, profile, "/usr/local/bin/musl-gcc"), f"{profile}-c", "outputs")
        build = native_build_command(work / "cargo-target", profile, "/opt/cargo/bin/cargo")
        # Cargo's last argument is a feature for statistical profiles. Its
        # static archive is the selected output, not an argv tail convention.
        name = f"{profile}-native-build"
        event = json.loads((logs / (name + ".json")).read_text())
        actual_library = work / "cargo-target" / m4.RUST_TARGET / "release" / m4.ADAPTER_STATICLIB
        original_outputs = event.get("outputs")
        if original_outputs != {str(actual_library): receipt.products[f"{profile}-native-mi-adapter.a"]}:
            raise receipts.ReceiptError("management capacity native archive binding differs")
        # Share all raw record/stream checks while keeping the actual Cargo
        # invocation exact and its output path independent from flag position.
        names = {name + suffix for suffix in (".json", ".stdout", ".stderr")}
        if (set(cases[name]["logs"]) != names or set(event) != {"command", "kind", "status", "stdout", "stderr", "outputs"}
                or event["command"] != build or event["kind"] != "process" or type(event["status"]) is not int or event["status"] != 0):
            raise receipts.ReceiptError("management capacity native feature/build command differs")
        for stream in ("stdout", "stderr"):
            if stress.byte_record_payload(event[stream], name) != (logs / (name + "." + stream)).read_bytes():
                raise receipts.ReceiptError("management capacity native build stream differs")
        command(f"{profile}-native-link", native_link_command(source, native, library, "/usr/local/bin/musl-gcc"), f"{profile}-native", "outputs")
        c_out, c_err = command(f"{profile}-c-run", [str(c)], f"{profile}-c", "executed")
        native_out, native_err = command(f"{profile}-native-run", [str(native)], f"{profile}-native", "executed")
        if c_err != SOURCE_AUDIT or native_err != b"" or numeric_trace(c_out, header) != numeric_trace(native_out, header) or c_out != native_out:
            raise receipts.ReceiptError("management capacity actual C/native numeric or source audit differs")
        expected_logs = {**cases[f"{profile}-c-run"]["logs"], **cases[f"{profile}-native-run"]["logs"]}
        if cases[f"{profile}-comparison"]["logs"] != expected_logs:
            raise receipts.ReceiptError("management capacity comparison cites different executions")
    return receipt


def run():
    execution = harness.require_native_x86_64(require_image_identity=True)
    if execution["image_id"] != IMAGE_ID or harness.ROOT != Path("/workspace"):
        raise harness.HarnessError("management capacity requires its pinned canonical namespace")
    seal = receipts.source_seal(harness.ROOT)
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="run-", dir=ARTIFACTS))
    output.chmod(0o755)
    source = harness.safe_extract(archive, output / "source", pin["archive_root"])
    products, cases, failures, c_runs = {}, [], [], {}
    for original in (DRIVER, archive, source / "include/mimalloc.h",
                     source / "include/mimalloc-stats.h", source / "LICENSE"):
        retained = output / original.name
        shutil.copy2(original, retained)
        products[retained.name] = retained
    inputs = output / "inputs.json"
    inputs.write_text(json.dumps({"source": seal, "execution": execution, "upstream": pin,
        "profiles": PROFILES, "boundary": "public native-mi-adapter over pinned musl",
        "ownership": "distinct external spans; live child; joined exit; destroy; caller release",
        "capacity": 160, "partial-parent-bytes": 16 * 1024**3,
        "runtime-watchdog-seconds": 60}, indent=2) + "\n")
    products[inputs.name] = inputs
    print(f"Management capacity raw: {output}", flush=True)
    compiler = harness.require_tool("musl-gcc")

    def passed(name, argv, product, cwd=source):
        result, logs = record(output, name, argv, cwd)
        if result["kind"] != "process" or result["status"] != 0:
            raise harness.HarnessError(f"{name} failed; see {logs[0]}")
        result["outputs"] = {str(product): fingerprint(product)}
        save_record(output, name, result)
        cases.append((name, 0, logs))

    def runtime(profile, backend):
        binary = output / profile / backend
        products[f"{profile}-{backend}"] = binary
        before = fingerprint(binary)
        result, logs = record(output, f"{profile}-{backend}-run", [str(binary)], binary.parent, True)
        if fingerprint(binary) != before:
            raise harness.HarnessError("executed product changed during caller execution")
        result["executed"] = {str(binary): before}
        save_record(output, f"{profile}-{backend}-run", result)
        status = result.get("status", 1) if result["kind"] == "process" else 1
        cases.append((f"{profile}-{backend}-run", status, logs))
        if status != 0:
            failures.append(f"{profile}-{backend} runtime status {status}; see {logs[0]}")
        return result, logs

    # Establish every selected source configuration before building a native
    # candidate. The source assertions check real live identities and ranges.
    for profile in PROFILES:
        directory = output / profile
        directory.mkdir()
        binary = directory / "c"
        passed(f"{profile}-c-link", c_command(source, binary, profile, compiler), binary)
        result, logs = runtime(profile, "c")
        c_runs[profile] = result, logs
        if stress.byte_record_payload(result["stderr"], profile) != SOURCE_AUDIT:
            failures.append(f"{profile} pinned live source geometry/diagnostic audit differs; see {logs[0]}")
        print(f"Management capacity {profile}: original C caller completed", flush=True)
    if failures:
        raise harness.HarnessError("; ".join(failures))

    target = output / "cargo-target"
    for profile in PROFILES:
        directory = output / profile
        built_library = target / m4.RUST_TARGET / "release" / m4.ADAPTER_STATICLIB
        passed(f"{profile}-native-build", native_build_command(target, profile, harness.require_tool("cargo")),
            built_library, harness.ROOT)
        library = directory / "native-mi-adapter.a"
        shutil.copy2(target / m4.RUST_TARGET / "release" / m4.ADAPTER_STATICLIB, library)
        products[f"{profile}-native-mi-adapter.a"] = library
        binary = directory / "native"
        passed(f"{profile}-native-link", native_link_command(source, binary, library, compiler), binary)
        native, logs = runtime(profile, "native")
        c, c_logs = c_runs[profile]
        if (stress.byte_record_payload(native["stdout"], profile) != stress.byte_record_payload(c["stdout"], profile)
                or stress.byte_record_payload(native["stderr"], profile) != b""):
            failures.append(f"{profile} actual public caller/statistics/diagnostics differ; raw in {output}")
            cases.append((f"{profile}-comparison", 1, c_logs + logs))
        else:
            cases.append((f"{profile}-comparison", 0, c_logs + logs))
        print(f"Management capacity {profile}: actual C/native compared; failures={len(failures)}", flush=True)
    if receipts.source_seal(harness.ROOT) != seal:
        raise harness.HarnessError("source changed during management capacity matrix")
    if failures:
        raise harness.HarnessError("; ".join(failures))
    path = receipts.write_receipt(harness.ROOT, RUNNER, output, products, cases,
        PARAMETERS, True)
    read()
    print(f"Management capacity: PASS; {path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--read", action="store_true")
    parser.add_argument("--replay", action="store_true")
    args = parser.parse_args()
    if not (args.read or args.replay):
        run()
        return
    receipt = read()
    print("Management capacity exact-source physical receipt: PASS")
    if args.replay:
        execution = harness.require_native_x86_64(require_image_identity=True)
        inputs = json.loads((receipt.path.parent / "products/inputs.json").read_text())
        harness.native_execution_attestation(inputs["execution"], execution)
        harness.TEMP_ROOT.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix="management-capacity-replay-", dir=harness.TEMP_ROOT))
        for profile in PROFILES:
            for backend in ("c", "native"):
                binary = scratch / f"{profile}-{backend}"
                shutil.copyfile(receipt.path.parent / "products" / binary.name, binary)
                binary.chmod(0o755)
                result, _ = record(scratch, binary.name, [str(binary)], scratch, True)
                if result["kind"] != "process" or result["status"] != 0:
                    raise harness.HarnessError(f"retained {binary.name} failed; see {scratch}")
                case = next(c for c in receipt.cases if c["id"] == f"{binary.name}-run")
                for stream in ("stdout", "stderr"):
                    log = next(p for p in case["logs"] if p.endswith("." + stream))
                    if stress.byte_record_payload(result[stream], binary.name) != (receipt.path.parent / "logs" / log).read_bytes():
                        raise harness.HarnessError(f"retained {binary.name} {stream} differs; see {scratch}")
        print("Management capacity retained C/native replay: PASS")


if __name__ == "__main__":
    try:
        main()
    except (harness.HarnessError, stress.EvidenceError, receipts.ReceiptError) as error:
        print(f"Management capacity failed: {error}", file=sys.stderr)
        raise SystemExit(1)
