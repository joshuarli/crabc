#!/usr/bin/env python3
"""Run pinned header-only Heap conveniences against C and native allocator exports.

C callers use pinned musl; C++ callers use the native image's musl/libstdc++
substrate. Neither caller overrides
global allocation. Only explicit mi_* calls exercise the allocator candidate.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import shutil
import signal
import sys
import tempfile

import run as harness
import x86_64_m4_gate as m4
from x86_64_m6_upstream_heap_stress import load_module, stress

receipts = load_module("heap_convenience_receipts", harness.ROOT / "compat/x86_64/native_shadow_receipt.py")
RUNNER = "allocator-heap-convenience"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-heap-convenience"
PROFILES = ("release", "debug-1", "stat-1", "stat-2")
C_SOURCE = harness.ALLOCATOR_ROOT / "x86_64_m6_heap_convenience_driver.c"
CXX_SOURCE = C_SOURCE.with_suffix(".cpp")


def record(output, name, argv, cwd, runtime=False):
    result = stress.command_record(argv, cwd=cwd,
        environment={} if runtime else dict(os.environ), timeout=60 if runtime else 3600)
    logs = [output / f"{name}.json"]
    logs[0].write_text(json.dumps(result, indent=2) + "\n")
    for stream in ("stdout", "stderr"):
        if stream not in result:
            continue
        path = output / f"{name}.{stream}"
        path.write_bytes(stress.byte_record_payload(result[stream], name))
        logs.append(path)
    return result, logs



def native_build_command(root, target, profile, cargo):
    """Select the adapter and its profile independently of the command cwd."""
    return [cargo, "build", "--locked", "--offline", "--release",
        "--target", m4.RUST_TARGET, "--manifest-path",
        str(root / "compat/allocator/native-mi-adapter/Cargo.toml"),
        "-p", m4.ADAPTER_PACKAGE, "--target-dir", str(target),
        *(("--features", f"crabc-mimalloc/mi-{profile}") if profile != "release" else ())]




def runtime_modes(language):
    return ("normal",) if language == "c" else ("normal", "overflow-handler", "refusal-handler", "overflow-throw", "refusal-throw", "overflow-abort")


def profile_commands(root, work, source, profile, tools):
    """Fix the source, compiler, allocator and caller roles for one profile."""
    directory = work / profile
    common = ["-D_GNU_SOURCE", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
              *m4.api_profile_flags(profile), "-I", str(source / "include")]
    commands = {
        "oracle-build": [tools["musl-gcc"], "-std=c11", *common, "-c", str(source / "src/static.c"), "-o", str(directory / "oracle.o")],
        "native-build": native_build_command(root, directory / "cargo-target", profile, tools["cargo"]),
    }
    for language, compiler, fixture, flags in (
        ("c", tools["musl-gcc"], root / "compat/allocator/x86_64_m6_heap_convenience_driver.c", ["-std=c11"]),
        ("cxx", tools["g++"], root / "compat/allocator/x86_64_m6_heap_convenience_driver.cpp",
         ["-std=c++17", "-static-libstdc++", "-static-libgcc", "-Wl,--wrap=mi_heap_delete", "-Wl,--wrap=mi_heap_destroy"]),
    ):
        for backend, allocator in (("c", directory / "oracle.o"), ("native", directory / "native-mi-adapter.a")):
            role = f"{language}-{backend}"
            caller, binary = directory / (role + ".o"), directory / role
            commands[role + "-compile"] = [compiler, *flags, *common, "-c", str(fixture), "-o", str(caller)]
            commands[role + "-imports"] = [tools["nm"], "-u", str(caller)]
            commands[role + "-link"] = [compiler, *flags, str(caller), str(allocator), "-pthread", "-o", str(binary)]
            for mode in runtime_modes(language):
                commands[role + "-" + mode] = [str(binary), *([] if mode == "normal" else [mode])]
    return commands


def read_convenience_authority(receipt):
    """Bind compiler roles and pinned inputs to the owning caller products.

    Recorded paths may use the producer's container prefix. The retained work
    suffix and original caller bytes bind that prefix before the manifest and
    profile commands are compared; the current checkout supplies the source.
    """
    work = json.loads(receipt.path.read_text())["work"]
    relative = Path(work)
    if (relative.is_absolute() or not relative.parts or relative.parts[0] != ".work" or
        relative.as_posix() != work or any(part in (".", "..") for part in work.split("/"))):
        raise harness.HarnessError("Heap convenience work path escapes checkout")
    cases = {case["id"]: case for case in receipt.cases}

    def raw(case_id):
        case = cases.get(case_id)
        if case is None:
            raise harness.HarnessError(f"Heap convenience command missing: {case_id}")
        logs = [path for path in case["logs"] if path.endswith(".json")]
        if len(logs) != 1:
            raise harness.HarnessError(f"Heap convenience command record differs: {case_id}")
        return json.loads((receipt.path.parent / "logs" / logs[0]).read_text())

    first = raw("release-c-native-normal").get("command")
    if not isinstance(first, list) or len(first) != 1 or not isinstance(first[0], str):
        raise harness.HarnessError("Heap convenience caller command differs")
    suffix = relative.parts + ("release", "c-native")
    executable = Path(first[0])
    if (not executable.is_absolute() or executable.as_posix() != first[0] or
        any(part in (".", "..") for part in first[0].split("/")) or
        len(executable.parts) <= len(suffix) or executable.parts[-len(suffix):] != suffix):
        raise harness.HarnessError("Heap convenience caller is unrelated to retained work")
    recorded_root = Path(*executable.parts[:-len(suffix)])
    tools = {name: harness.require_tool(name) for name in ("musl-gcc", "g++", "cargo", "nm")}
    pin = harness.load_pin()
    commands = {profile: profile_commands(recorded_root, recorded_root / relative,
        recorded_root / relative / "source" / pin["archive_root"], profile, tools) for profile in PROFILES}
    expected_cases = [f"{profile}-{step}" for profile in PROFILES for step in commands[profile]]
    if receipt.case_ids() != expected_cases:
        raise harness.HarnessError("Heap convenience ordered caller roster differs")
    parameters = {"profiles": ",".join(PROFILES), "boundary": "explicit native-mi-adapter",
        "c-substrate": "pinned-musl-1.2.6", "cxx-substrate": "native-image-musl-libstdc++",
        "expected-overflow-abort": "SIGABRT", "watchdog-seconds": "60"}
    if receipt.parameters != parameters:
        raise harness.HarnessError("Heap convenience caller parameters differ")
    products = receipt.path.parent / "products"
    names = {C_SOURCE.name, CXX_SOURCE.name, "mimalloc.h", "LICENSE", "static.c", "mimalloc-3.5.0.tar.gz", "inputs.json"}
    artifacts = ("native-mi-adapter.a", "oracle.o", "c-c", "c-native", "cxx-c", "cxx-native",
                 "c-c.o", "c-native.o", "cxx-c.o", "cxx-native.o")
    if set(receipt.products) != names | {f"{profile}-{name}" for profile in PROFILES for name in artifacts}:
        raise harness.HarnessError("Heap convenience retained products differ")
    for profile in PROFILES:
        for step, command in commands[profile].items():
            case_id = f"{profile}-{step}"
            result = raw(case_id)
            expected_status = -signal.SIGABRT if step.endswith("-overflow-abort") else 0
            if result.get("command") != command:
                raise harness.HarnessError(f"Heap convenience {case_id} command authority differs")
            if result.get("kind") != "process" or type(result.get("status")) is not int or result["status"] != expected_status:
                raise harness.HarnessError(f"Heap convenience {case_id} actual status differs")
            logs = {Path(path).suffix: receipt.path.parent / "logs" / path for path in cases[case_id]["logs"]}
            if set(logs) != {".json", ".stdout", ".stderr"} or len(cases[case_id]["logs"]) != 3:
                raise harness.HarnessError(f"Heap convenience {case_id} raw streams missing")
            for stream in ("stdout", "stderr"):
                if stress.byte_record_payload(result[stream], case_id) != logs["." + stream].read_bytes():
                    raise harness.HarnessError(f"Heap convenience {case_id} raw streams differ")
        for language in ("c", "cxx"):
            for mode in runtime_modes(language):
                left = raw(f"{profile}-{language}-c-{mode}")["stdout"]
                right = raw(f"{profile}-{language}-native-{mode}")["stdout"]
                if stress.byte_record_payload(left, mode) != stress.byte_record_payload(right, mode):
                    raise harness.HarnessError(f"Heap convenience {profile}-{language}-{mode} paired trace differs")

    def same_file(original, retained):
        if (original.is_symlink() or not original.is_file() or original.resolve() != original.absolute() or
            hashlib.sha256(original.read_bytes()).digest() != hashlib.sha256(retained.read_bytes()).digest()):
            raise harness.HarnessError(f"Heap convenience original input or product differs: {original}")

    original_work = harness.ROOT / relative
    inputs = json.loads((products / "inputs.json").read_text())
    execution = harness.require_native_x86_64(require_image_identity=True)
    harness.validate_native_execution_provenance(inputs["execution"], expected_image_id=execution["image_id"])
    if (inputs["source"] != receipt.source or inputs["upstream"] != pin or inputs["profiles"] != list(PROFILES) or
        inputs["boundary"] != "explicit native mi_*; host musl and C++ standard library substrate" or
        inputs["header_sha256"] != hashlib.sha256((products / "mimalloc.h").read_bytes()).hexdigest() or
        type(inputs["expected_abort"]) is not int or inputs["expected_abort"] != -signal.SIGABRT or
        type(inputs["runtime_watchdog_seconds"]) is not int or inputs["runtime_watchdog_seconds"] != 60):
        raise harness.HarnessError("Heap convenience input provenance differs")
    archive = products / "mimalloc-3.5.0.tar.gz"
    if hashlib.sha256(archive.read_bytes()).hexdigest() != pin["sha256"]:
        raise harness.HarnessError("Heap convenience oracle archive differs from pin")
    same_file(original_work / archive.name, archive)
    for driver in (C_SOURCE, CXX_SOURCE):
        same_file(original_work / driver.name, driver)
        same_file(products / driver.name, driver)
    harness.TEMP_ROOT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="heap-convenience-inputs-", dir=harness.TEMP_ROOT) as scratch:
        pinned = harness.safe_extract(archive, Path(scratch) / "source", pin["archive_root"])
        original = original_work / "source" / pin["archive_root"]
        members = [path.relative_to(pinned).as_posix() for path in pinned.rglob("*") if path.is_file()]
        original_members = [path.relative_to(original).as_posix() for path in original.rglob("*") if path.is_file()]
        if (set(members) != set(original_members) or any(path.is_symlink() for path in original.rglob("*")) or
            harness.source_file_records(original, members) != harness.source_file_records(pinned, members)):
            raise harness.HarnessError("Heap convenience original oracle source differs from pin")
        for member, name in (("include/mimalloc.h", "mimalloc.h"), ("src/static.c", "static.c"), ("LICENSE", "LICENSE")):
            same_file(products / name, pinned / member)
    for profile in PROFILES:
        for name in artifacts:
            same_file(original_work / profile / name, products / f"{profile}-{name}")
    return receipt


def run():
    # Expected abort processes need their signal and diagnostics, not core files.
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    execution = harness.require_native_x86_64(require_image_identity=True)
    seal = receipts.source_seal(harness.ROOT)
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="run-", dir=ARTIFACTS))
    output.chmod(0o755)
    # Keep inputs and products after a partial failure as well as after success.
    source = harness.safe_extract(archive, output / "source", pin["archive_root"])
    products, cases = {}, []
    for original in (C_SOURCE, CXX_SOURCE, source / "include/mimalloc.h", source / "LICENSE", source / "src/static.c", archive):
        retained = output / original.name
        shutil.copy2(original, retained)
        products[retained.name] = retained
    inputs = output / "inputs.json"
    inputs.write_text(json.dumps({"source": seal, "execution": execution, "upstream": pin,
        "profiles": PROFILES, "boundary": "explicit native mi_*; host musl and C++ standard library substrate",
        "header_sha256": hashlib.sha256((source / "include/mimalloc.h").read_bytes()).hexdigest(),
        "expected_abort": -signal.SIGABRT, "runtime_watchdog_seconds": 60}, indent=2) + "\n")
    products[inputs.name] = inputs
    print(f"Heap convenience raw products: {output}", flush=True)
    tools = {name: harness.require_tool(name) for name in ("musl-gcc", "g++", "cargo", "nm")}
    for profile in PROFILES:
        directory = output / profile
        directory.mkdir()

        def passed(name, argv, cwd=source):
            result, logs = record(output, f"{profile}-{name}", argv, cwd)
            if result["kind"] != "process" or result["status"] != 0:
                raise harness.HarnessError(f"{profile}-{name} failed; see {logs[0]}")
            cases.append((f"{profile}-{name}", 0, logs))

        commands = profile_commands(harness.ROOT, output, source, profile, tools)
        oracle = directory / "oracle.o"
        passed("oracle-build", commands["oracle-build"])
        target = directory / "cargo-target"
        passed("native-build", commands["native-build"], harness.ROOT)
        library = target / m4.RUST_TARGET / "release" / m4.ADAPTER_STATICLIB
        retained_library = directory / "native-mi-adapter.a"
        shutil.copy2(library, retained_library)
        products[f"{profile}-native-mi-adapter.a"] = retained_library
        products[f"{profile}-oracle.o"] = oracle
        for language in ("c", "cxx"):
            traces = {}
            for backend in ("c", "native"):
                binary = directory / f"{language}-{backend}"
                # Compile the actual caller separately, so the imported mi_*
                # entries can be inspected without attributing runtime code.
                caller = directory / f"{language}-{backend}.o"
                passed(f"{language}-{backend}-compile", commands[f"{language}-{backend}-compile"])
                passed(f"{language}-{backend}-imports", commands[f"{language}-{backend}-imports"])
                passed(f"{language}-{backend}-link", commands[f"{language}-{backend}-link"])
                products[f"{profile}-{language}-{backend}"] = binary
                products[f"{profile}-{language}-{backend}.o"] = caller
                modes = runtime_modes(language)
                for mode in modes:
                    name = f"{profile}-{language}-{backend}-{mode}"
                    result, logs = record(output, name, commands[f"{language}-{backend}-{mode}"], directory, True)
                    expected_status = -signal.SIGABRT if mode == "overflow-abort" else 0
                    if result["kind"] != "process" or result["status"] != expected_status:
                        raise harness.HarnessError(f"{name} unexpected runtime result; see {logs[0]}")
                    stdout = stress.byte_record_payload(result["stdout"], name)
                    traces[backend, mode] = stdout
                    # Status zero here means the ordered case contract passed;
                    # the raw process record retains actual SIGABRT unchanged.
                    cases.append((name, 0, logs))
            for mode in modes:
                if traces["c", mode] != traces["native", mode]:
                    raise harness.HarnessError(f"{profile}-{language}-{mode}: C/native caller traces differ; raw in {output}")
        print(f"Heap convenience {profile}: actual C/native callers PASS", flush=True)
    if receipts.source_seal(harness.ROOT) != seal:
        raise harness.HarnessError("source changed during Heap convenience execution")
    path = receipts.write_receipt(harness.ROOT, RUNNER, output, products, cases,
        {"profiles": ",".join(PROFILES), "boundary": "explicit native-mi-adapter",
         "c-substrate": "pinned-musl-1.2.6", "cxx-substrate": "native-image-musl-libstdc++",
         "expected-overflow-abort": "SIGABRT", "watchdog-seconds": "60"}, True)
    read_convenience_authority(receipts.read_receipt(harness.ROOT, RUNNER))
    print(f"Heap convenience: all four profiles PASS; {path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--read", action="store_true", help="read existing exact-source physical receipt")
    parser.add_argument("--replay", action="store_true", help="read receipt and rerun retained caller products in private scratch")
    args = parser.parse_args()
    if args.read or args.replay:
        receipt = read_convenience_authority(receipts.read_receipt(harness.ROOT, RUNNER))
        print("Heap convenience exact-source physical receipt: PASS")
        if args.replay:
            harness.require_native_x86_64(require_image_identity=True)
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            harness.TEMP_ROOT.mkdir(parents=True, exist_ok=True)
            scratch = Path(tempfile.mkdtemp(prefix="heap-convenience-replay-", dir=harness.TEMP_ROOT))
            print(f"Heap convenience reader raw executions: {scratch}", flush=True)
            for profile in PROFILES:
                for language in ("c", "cxx"):
                    for backend in ("c", "native"):
                        product = f"{profile}-{language}-{backend}"
                        binary = scratch / product
                        shutil.copyfile(receipt.path.parent / "products" / product, binary)
                        binary.chmod(0o755)
                        modes = runtime_modes(language)
                        for mode in modes:
                            case = f"{product}-{mode}"
                            result, _ = record(scratch, case, [str(binary), *([] if mode == "normal" else [mode])], scratch, True)
                            expected = -signal.SIGABRT if mode == "overflow-abort" else 0
                            if result["kind"] != "process" or result["status"] != expected:
                                raise harness.HarnessError(f"retained caller {case} failed; see {scratch}")
                            recorded = next(c for c in receipt.cases if c["id"] == case)
                            stdout = next(p for p in recorded["logs"] if p.endswith(".stdout"))
                            if stress.byte_record_payload(result["stdout"], case) != (receipt.path.parent / "logs" / stdout).read_bytes():
                                raise harness.HarnessError(f"retained caller {case} output differs; see {scratch}")
            print("Heap convenience retained C/C++ caller replay: four profiles PASS")
    else:
        run()


if __name__ == "__main__":
    try:
        main()
    except (harness.HarnessError, stress.EvidenceError, receipts.ReceiptError) as error:
        print(f"Heap convenience failed: {error}", file=sys.stderr)
        raise SystemExit(1)
