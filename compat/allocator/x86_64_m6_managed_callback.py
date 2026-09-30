#!/usr/bin/env python3
"""Compare public callback-managed memory with pinned source."""

from pathlib import Path
import argparse
import hashlib
import json
import re
import resource
import shutil
import sys
import tempfile

import run as harness
import x86_64_m4_gate as m4
import x86_64_m7_gate as m7
from x86_64_m6_heap_convenience import record
from x86_64_m6_upstream_heap_stress import load_module, stress

receipts = load_module("managed_callback_receipts", harness.ROOT / "compat/x86_64/native_shadow_receipt.py")
PROFILES = ("release", "debug-1", "stat-1", "stat-2")


DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m6_managed_callback_driver.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-managed-callback"
BEGIN = "CRABC_MI_M6_MANAGED_CALLBACK_BEGIN"
END = "CRABC_MI_M6_MANAGED_CALLBACK_END"
EXPECTED = {
    "callback.reject": "1,1,1,1",
    "callback.manage": "1,1,1,1",
    "callback.allocation": "1,1",
    "callback.release": "1,6",
    "callback.event0": "1,0,589824,0",
    "callback.event1": "1,589824,65536,1",
    "callback.event2": "1,655360,65536,1",
    "callback.event3": "1,0,524288,0",
    "callback.event4": "0,589824,65536,0",
    "callback.event5": "0,655360,65536,0",
    "callback.terminal": "1,1,1",
}
WARNING = (
    "cannot use OS memory since it is not large enough "
    "(size 32767 KiB, minimum required is 32768 KiB)"
)


def run_differential() -> int:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    with harness.temporary_directory("crabc-mimalloc-m6-managed-callback-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        compiler = harness.require_tool("musl-gcc")
        c_driver = temporary / "managed-callback-c"
        c_build = harness.command_record(
            [compiler, "-std=c11", "-D_GNU_SOURCE", "-ftls-model=initial-exec",
             "-DMI_LIBC_MUSL=1", "-DCRABC_M6_SOURCE_INTERNAL=1",
             *harness.CONFIGURATION_PROFILES["release"],
             "-I", str(source / "include"), "-I", str(source / "src"),
             str(DRIVER), str(source / "src/static.c"), "-pthread", "-o", str(c_driver)],
            cwd=source,
        )
        (ARTIFACTS / "c-build.log").write_text(str(c_build["stdout"]) + str(c_build["stderr"]))
        harness.require_success(c_build, "Callback-managed C build")
        c_run = harness.command_record([str(c_driver)], cwd=temporary, env={}, timeout_seconds=60)
        (ARTIFACTS / "c.log").write_text(str(c_run["stdout"]) + str(c_run["stderr"]))
        harness.require_success(c_run, "Callback-managed C run")
        source_rows = dict(re.findall(r"^(source\.[a-z_]+)=([0-9,]+)$", str(c_run["stderr"]), re.MULTILINE))
        if source_rows != {"source.callback": "1,1"}:
            raise harness.HarnessError(f"pinned callback source image changed: {source_rows}")
        c_trace = m7.parse_options_trace(str(c_run["stdout"]), "C managed callback", BEGIN, END)
        if c_trace != EXPECTED:
            raise harness.HarnessError(f"pinned callback C trace changed: {c_trace}")
        if str(c_run["stderr"]).count(WARNING) != 1:
            raise harness.HarnessError("pinned callback rejection warning changed")
        library = m4.build_adapter_library(temporary)
        rust_driver = temporary / "managed-callback-rust"
        link = harness.command_record(
            [compiler, "-std=c11", "-D_GNU_SOURCE", "-O2", "-I", str(source / "include"),
             str(DRIVER), str(library), "-pthread", "-o", str(rust_driver)], cwd=source,
        )
        (ARTIFACTS / "rust-link.log").write_text(str(link["stdout"]) + str(link["stderr"]))
        harness.require_success(link, "Callback-managed Rust link")
        rust_run = harness.command_record([str(rust_driver)], cwd=temporary, env={}, timeout_seconds=60)
        (ARTIFACTS / "rust.log").write_text(str(rust_run["stdout"]) + str(rust_run["stderr"]))
        harness.require_success(rust_run, "Callback-managed Rust run")
        if str(rust_run["stderr"]).count(WARNING) != 1:
            raise harness.HarnessError("managed callback rejection warning differs")
        rust_trace = m7.parse_options_trace(str(rust_run["stdout"]), "Rust managed callback", BEGIN, END)
        m7.compare_options_traces(c_trace, rust_trace)
        return len(c_trace)

# Cross-process thread addresses identify different valid owners. Keep their raw
# diagnostics intact while requiring the complete warning and assertion records.
def check_diagnostics(client, backend, raw):
    assertion = ("source.child_callback=1,1,1" if "child" in client.DRIVER.name
                 else "source.callback=1,1")
    pattern = (r"mimalloc: warning: thread (0x[0-9A-Fa-f]+): "
               + re.escape(client.WARNING) + r"\n")
    if backend == "c":
        pattern += ("" if "child" in client.DRIVER.name else r"\n") + re.escape(assertion) + r"\n"
    match = re.fullmatch(pattern, raw.decode("utf-8"))
    if match is None or int(match.group(1), 16) == 0:
        raise harness.HarnessError(f"{backend} callback diagnostics differ: {raw!r}")


def profile_runner(client):
    return "allocator-" + ("child-" if "child" in client.DRIVER.name else "") + "managed-callback-profiles"


def run_profile_matrix(client):
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    execution = harness.require_native_x86_64(require_image_identity=True)
    seal = receipts.source_seal(harness.ROOT)
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    artifacts = client.ARTIFACTS / "profiles"
    artifacts.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="run-", dir=artifacts))
    output.chmod(0o755)
    print(f"Managed callback profile raw products: {output}", flush=True)
    source = harness.safe_extract(archive, output / "source", pin["archive_root"])
    products, cases = {}, []
    for original in (client.DRIVER, source / "include/mimalloc.h", source / "LICENSE"):
        retained = output / original.name
        shutil.copy2(original, retained)
        products[retained.name] = retained
    inputs = output / "inputs.json"
    inputs.write_text(json.dumps({"source": seal, "execution": execution, "upstream": pin,
        "profiles": PROFILES, "fixture_sha256": hashlib.sha256(client.DRIVER.read_bytes()).hexdigest(),
        "boundary": "explicit native mi_*; pinned musl supplies C and pthread substrate",
        "runtime_watchdog_seconds": 60}, indent=2) + "\n")
    products[inputs.name] = inputs
    compiler = harness.require_tool("musl-gcc")
    for profile in PROFILES:
        directory = output / profile
        directory.mkdir()

        def passed(name, argv, cwd=source, runtime=False):
            result, logs = record(output, f"{profile}-{name}", argv, cwd, runtime)
            if result["kind"] != "process" or result["status"] != 0:
                raise harness.HarnessError(f"{profile}-{name} failed; see {logs[0]}")
            cases.append((f"{profile}-{name}", 0, logs))
            return result

        common = ["-std=c11", "-D_GNU_SOURCE", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
                  *m4.api_profile_flags(profile), "-I", str(source / "include")]
        oracle = directory / "oracle.o"
        passed("oracle-build", [compiler, *common, "-c", str(source / "src/static.c"), "-o", str(oracle)])
        target = directory / "cargo-target"
        passed("native-build", [harness.require_tool("cargo"), "build", "--locked", "--offline", "--release",
            "--target", m4.RUST_TARGET, "-p", m4.ADAPTER_PACKAGE, "--target-dir", str(target),
            *(("--features", f"crabc-mimalloc/mi-{profile}") if profile != "release" else ())], harness.ROOT)
        library = directory / "native-mi-adapter.a"
        shutil.copy2(target / m4.RUST_TARGET / "release" / m4.ADAPTER_STATICLIB, library)
        products[f"{profile}-native-mi-adapter.a"] = library
        products[f"{profile}-oracle.o"] = oracle
        traces = {}
        for backend, allocator in (("c", oracle), ("native", library)):
            caller, binary = directory / f"{backend}.o", directory / backend
            internal = ["-DCRABC_M6_SOURCE_INTERNAL=1", "-I", str(source / "src")] if backend == "c" else []
            passed(f"{backend}-compile", [compiler, *common, *internal, "-c", str(client.DRIVER), "-o", str(caller)])
            passed(f"{backend}-imports", [harness.require_tool("nm"), "-u", str(caller)])
            passed(f"{backend}-link", [compiler, str(caller), str(allocator), "-pthread", "-o", str(binary)])
            products[f"{profile}-{backend}"] = binary
            products[f"{profile}-{backend}.o"] = caller
            result = passed(f"{backend}-run", [str(binary)], directory, True)
            stdout = stress.byte_record_payload(result["stdout"], backend)
            stderr = stress.byte_record_payload(result["stderr"], backend)
            check_diagnostics(client, backend, stderr)
            trace = m7.parse_options_trace(stdout.decode(), backend, client.BEGIN, client.END)
            if trace != client.EXPECTED:
                raise harness.HarnessError(f"{profile}-{backend}: callback trace differs: {trace}; raw in {output}")
            traces[backend] = stdout
        if traces["c"] != traces["native"]:
            raise harness.HarnessError(f"{profile}: C/native callback bytes differ; raw in {output}")
        print(f"Managed callback {profile}: complete C/native clients PASS", flush=True)
    if receipts.source_seal(harness.ROOT) != seal:
        raise harness.HarnessError("source changed during callback profile execution")
    path = receipts.write_receipt(harness.ROOT, profile_runner(client), output, products, cases,
        {"profiles": ",".join(PROFILES), "boundary": "explicit native-mi-adapter",
         "c-substrate": "pinned-musl-1.2.6", "watchdog-seconds": "60"}, True)
    receipts.read_receipt(harness.ROOT, profile_runner(client))
    print(f"Managed callback four-profile receipt: {path}")


def read_profiles(client, replay=False):
    receipt = receipts.read_receipt(harness.ROOT, profile_runner(client))
    print("Managed callback exact-source physical receipt: PASS")
    if not replay:
        return
    harness.require_native_x86_64(require_image_identity=True)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    harness.TEMP_ROOT.mkdir(parents=True, exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix="managed-callback-replay-", dir=harness.TEMP_ROOT))
    print(f"Managed callback replay raw executions: {scratch}", flush=True)
    for profile in PROFILES:
        for backend in ("c", "native"):
            product = f"{profile}-{backend}"
            binary = scratch / product
            shutil.copyfile(receipt.path.parent / "products" / product, binary)
            binary.chmod(0o755)
            result, _ = record(scratch, product, [str(binary)], scratch, True)
            if result["kind"] != "process" or result["status"] != 0:
                raise harness.HarnessError(f"retained {product} failed; see {scratch}")
            case = next(c for c in receipt.cases if c["id"] == f"{product}-run")
            for stream in ("stdout", "stderr"):
                original = next(p for p in case["logs"] if p.endswith(f".{stream}"))
                retained = (receipt.path.parent / "logs" / original).read_bytes()
                current = stress.byte_record_payload(result[stream], product)
                if stream == "stdout":
                    if current != retained:
                        raise harness.HarnessError(f"retained {product} output differs; see {scratch}")
                else:
                    check_diagnostics(client, backend, retained)
                    check_diagnostics(client, backend, current)
    print("Managed callback retained complete C/native callers: four profiles PASS")


def profile_main(client, arguments=None):
    parser = argparse.ArgumentParser(description=client.__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--matrix", action="store_true", help="execute complete C/native clients in all four profiles")
    modes.add_argument("--read", action="store_true", help="read exact-source physical matrix receipt")
    modes.add_argument("--replay", action="store_true", help="read receipt and execute all retained clients")
    args = parser.parse_args(arguments)
    if args.matrix:
        run_profile_matrix(client)
    elif args.read or args.replay:
        read_profiles(client, args.replay)
    else:
        print(f"Managed callback: {client.run_differential()} source-built C/Rust keys match")


def main(arguments=None):
    profile_main(sys.modules[__name__], arguments)


if __name__ == "__main__":
    try:
        main()
    except (harness.HarnessError, stress.EvidenceError, receipts.ReceiptError) as error:
        print(f"Managed callback failed: {error}", file=sys.stderr)
        raise SystemExit(1)
