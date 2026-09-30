#!/usr/bin/env python3
"""Compare live public Heap statistics selection and merge order with pinned C."""
import argparse
import json
import re
from pathlib import Path
import shutil
import sys
import tempfile

import run as harness
import x86_64_m4_gate as m4
from x86_64_m6_heap_convenience import record, receipts
from x86_64_m6_upstream_heap_stress import stress

RUNNER = "allocator-heap-stats-profiles"
PROFILES = ("release", "debug-1", "stat-1", "stat-2")
DRIVER = harness.ALLOCATOR_ROOT / "x86_64_heap_stats_profiles_driver.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/heap-stats-profiles"


def comparable_trace(raw):
    # CPU time, RSS and faults belong to the host process rather than the
    # selected allocator owner. Keep every allocator statistic and commit
    # value, including all JSON bins and callback subprocess/Heap headers.
    lines = []
    for line in raw.splitlines():
        key, separator, value = line.partition(b"=")
        if separator and key.endswith(b".json"):
            document = json.loads(bytes.fromhex(value.decode("ascii")))
            for field in ("elapsed_msecs", "user_msecs", "system_msecs", "page_faults", "rss_current", "rss_peak"):
                document["process"][field] = 0
            value = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")
            line = key + separator + value
        elif separator and key.endswith(b".print"):
            text = bytes.fromhex(value.decode("ascii"))
            text = re.sub(rb"(?m)^(  elapsed\s*:).*?$", rb"\1 host-time", text)
            text = re.sub(rb"user: [0-9.]+ s, system: [0-9.]+ s, faults: [0-9]+, peak rss: [^,\n]+", b"user: host-time, system: host-time, faults: host-faults, peak rss: host-rss", text)
            line = key + separator + text.hex().encode("ascii")
        lines.append(line)
    return b"\n".join(lines)


def run():
    execution = harness.require_native_x86_64(require_image_identity=True)
    seal = receipts.source_seal(harness.ROOT)
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="run-", dir=ARTIFACTS))
    output.chmod(0o755)
    source = harness.safe_extract(archive, output / "source", pin["archive_root"])
    products, cases = {}, []
    failures = []
    for original in (DRIVER, source / "include/mimalloc.h", source / "include/mimalloc-stats.h", source / "LICENSE"):
        retained = output / original.name
        shutil.copy2(original, retained)
        products[retained.name] = retained
    inputs = output / "inputs.json"
    inputs.write_text(json.dumps({"source": seal, "execution": execution, "upstream": pin,
        "profiles": PROFILES, "boundary": "explicit native mi_*; pinned musl process/pthread substrate",
        "owners": "single live Heap owner; process-main and joined child",
        "runtime_watchdog_seconds": 60}, indent=2) + "\n")
    products[inputs.name] = inputs
    print(f"Heap statistics raw: {output}", flush=True)
    compiler = harness.require_tool("musl-gcc")
    for profile in PROFILES:
        directory = output / profile
        directory.mkdir()
        def passed(name, argv, cwd=source):
            result, logs = record(output, f"{profile}-{name}", argv, cwd)
            if result["kind"] != "process" or result["status"] != 0:
                raise harness.HarnessError(f"{profile}-{name} failed; see {logs[0]}")
            cases.append((f"{profile}-{name}", 0, logs))
        common = [compiler, "-std=c11", "-D_GNU_SOURCE", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
            *m4.api_profile_flags(profile), "-UNDEBUG", "-I", str(source / "include")]
        target = directory / "cargo-target"
        passed("native-build", [harness.require_tool("cargo"), "build", "--locked", "--offline", "--release",
            "--target", m4.RUST_TARGET, "-p", m4.ADAPTER_PACKAGE, "--target-dir", str(target),
            *(("--features", f"crabc-mimalloc/mi-{profile}") if profile != "release" else ())], harness.ROOT)
        library = directory / "native-mi-adapter.a"
        shutil.copy2(target / m4.RUST_TARGET / "release" / m4.ADAPTER_STATICLIB, library)
        products[f"{profile}-native-mi-adapter.a"] = library
        traces = {}
        for backend, allocator in (("c", source / "src/static.c"), ("native", library)):
            binary = directory / backend
            passed(f"{backend}-link", [*common, str(DRIVER), str(allocator), "-pthread", "-o", str(binary)])
            products[f"{profile}-{backend}"] = binary
            result, logs = record(output, f"{profile}-{backend}-run", [str(binary)], directory, True)
            if result["kind"] != "process" or result["status"] != 0:
                failures.append(f"{profile}-{backend} runtime failure; see {logs[0]}")
                continue
            traces[backend] = stress.byte_record_payload(result["stdout"], backend)
            cases.append((f"{profile}-{backend}-run", 0, logs))
        if len(traces) != 2:
            print(f"Heap statistics {profile}: runtime failure retained", flush=True)
        elif comparable_trace(traces["c"]) != comparable_trace(traces["native"]):
            failures.append(f"{profile} Heap statistics differ; raw in {output}")
            print(f"Heap statistics {profile}: differing raw traces retained", flush=True)
        else:
            print(f"Heap statistics {profile}: C/native PASS", flush=True)
    if receipts.source_seal(harness.ROOT) != seal:
        raise harness.HarnessError("source changed during Heap statistics matrix")
    if failures:
        raise harness.HarnessError("; ".join(failures))
    path = receipts.write_receipt(harness.ROOT, RUNNER, output, products, cases,
        {"profiles": ",".join(PROFILES), "boundary": "native-mi-adapter", "watchdog-seconds": "60",
         "ownership": "main-child; auxiliary/default/null Heap and rejected-output merge order"}, True)
    receipts.read_receipt(harness.ROOT, RUNNER)
    print(f"Heap statistics lifetime: PASS; {path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--read", action="store_true")
    parser.add_argument("--replay", action="store_true")
    args = parser.parse_args()
    if not (args.read or args.replay):
        run()
        return
    receipt = receipts.read_receipt(harness.ROOT, RUNNER)
    print("Heap statistics exact-source physical receipt: PASS")
    if args.replay:
        execution = harness.require_native_x86_64(require_image_identity=True)
        inputs = json.loads((receipt.path.parent / "products/inputs.json").read_text())
        harness.native_execution_attestation(inputs["execution"], execution)
        harness.TEMP_ROOT.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix="heap-stats-replay-", dir=harness.TEMP_ROOT))
        print(f"Reader raw: {scratch}", flush=True)
        for profile in PROFILES:
            for backend in ("c", "native"):
                binary = scratch / f"{profile}-{backend}"
                shutil.copyfile(receipt.path.parent / "products" / binary.name, binary)
                binary.chmod(0o755)
                result, _ = record(scratch, binary.name, [str(binary)], scratch, True)
                if result["kind"] != "process" or result["status"] != 0:
                    raise harness.HarnessError(f"retained {binary.name} failed; see {scratch}")
                case = next(c for c in receipt.cases if c["id"] == f"{binary.name}-run")
                stdout = next(p for p in case["logs"] if p.endswith(".stdout"))
                if comparable_trace(stress.byte_record_payload(result["stdout"], binary.name)) != comparable_trace((receipt.path.parent / "logs" / stdout).read_bytes()):
                    raise harness.HarnessError(f"retained {binary.name} statistics differ; see {scratch}")
        print("Heap statistics retained C/native replay: PASS")


if __name__ == "__main__":
    try:
        main()
    except (harness.HarnessError, stress.EvidenceError, receipts.ReceiptError) as error:
        print(f"Heap statistics failed: {error}", file=sys.stderr)
        raise SystemExit(1)
