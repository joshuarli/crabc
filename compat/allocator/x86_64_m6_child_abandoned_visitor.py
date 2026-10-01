#!/usr/bin/env python3
"""Compare child Heap visitation with pinned mimalloc in selected profiles."""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile

import run as harness
import x86_64_m4_gate as m4
import x86_64_m7_gate as m7
from x86_64_m6_upstream_heap_stress import load_module, stress

DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m6_child_abandoned_visitor_driver.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-child-abandoned-visitor"
STAGES = ("areas", "blocks", "stop_regular_area", "stop_regular_block", "ordinary")
BEGIN = "CRABC_MI_M6_CHILD_ABANDONED_VISITOR_TRACE_BEGIN"
END = "CRABC_MI_M6_CHILD_ABANDONED_VISITOR_TRACE_END"
SOURCE_CHILD_ABANDONED_PAGES = {
    "child.areas": "1,1,1,0,0,0,2,1,RO",
    "child.blocks": "1,1,1,2,1,0,2,1,R13OS",
    "child.stop_regular_area": "0,1,0,0,0,0,2,0,R",
    "child.stop_regular_block": "0,1,0,1,0,0,2,0,R1",
    "child.ordinary": "1,1,1,2,1,0,2,1,R13OS",
}


def require_trace(trace: dict[str, str], side: str, *, profile="release", stderr="") -> dict[str, str]:
    expected = {f"child.{stage}" for stage in STAGES}
    if set(trace) != expected:
        raise harness.HarnessError(
            f"{side} child visitor keys differ: "
            f"missing={sorted(expected - set(trace))} extra={sorted(set(trace) - expected)}"
        )
    for stage in STAGES:
        if not re.fullmatch(r"[01](?:,[0-9]+){7},[RO13FS]*", trace[f"child.{stage}"]):
            raise harness.HarnessError(f"{side} child.{stage} is malformed")
    if profile == "secure-2":
        # Allocation shuffles client addresses; visitation still scans live
        # physical block indices. Derive its order from facts captured before
        # traversal, never from the observed callback sequence.
        if re.findall(r"^visitation\.secure=(.*)$", stderr, re.MULTILINE) != ["2"]:
            raise harness.HarnessError(f"{side} visitation profile does not bind secure-2")
        rows = stderr.splitlines()
        first_callback = next((index for index, row in enumerate(rows) if row.startswith(("geometry.", "placement."))), len(rows))
        captured = [index for index, row in enumerate(rows) if row.startswith(("client.", "visitation.secure="))]
        if len(captured) != 5 or any(index >= first_callback for index in captured):
            raise harness.HarnessError(f"{side} client geometry was not captured before traversal")
        clients = {}
        client_lines = re.findall(r"^client\.(.*)$", stderr, re.MULTILINE)
        for line in client_lines:
            match = re.fullmatch(r"([123S])=([0-9]+),([0-9]+),([0-9]+),([01])", line)
            if match is None or match[1] in clients:
                raise harness.HarnessError(f"{side} malformed or repeated client geometry")
            clients[match[1]] = tuple(map(int, match.groups()[1:]))
        if set(clients) != set("123S") or len({value[0] for value in clients.values()}) != 4:
            raise harness.HarnessError(f"{side} missing or overlapping client geometry")
        for tag, (address, requested, usable, live) in clients.items():
            wanted = (10241, 12288, 1) if tag == "S" else (128, 128, int(tag != "2"))
            if not 0 < address < 2**64 or (requested, usable, live) != wanted:
                raise harness.HarnessError(f"{side} client {tag} extent or live state changed")
        geometry, placements = {}, {}
        for prefix, destination, count in (("geometry", geometry, 7), ("placement", placements, 2)):
            for line in re.findall(r"^" + prefix + r"\.(.*)$", stderr, re.MULTILINE):
                match = re.fullmatch(r"([a-z_]+)=([RO13SF])," + r"([0-9]+)," * (count - 1) + r"([0-9]+)", line)
                if match is None or match[1] not in STAGES:
                    raise harness.HarnessError(f"{side} malformed {prefix} geometry")
                destination.setdefault(match[1], []).append((match[2], *map(int, match.groups()[2:])))
        blocks = placements.get("blocks", [])
        roots = {row[0]: row[1] for row in blocks if row[0] in "RO"}
        if set(roots) != set("RO") or len([row for row in blocks if row[0] in "RO"]) != 2:
            raise harness.HarnessError(f"{side} missing or repeated physical area origins")
        regular_start, os_start = roots["R"], roots["O"]
        if not (0 < regular_start < 2**64 - 65408 and 0 < os_start < 2**64 - 12288):
            raise harness.HarnessError(f"{side} area extent overflows")
        if not (regular_start + 65408 <= os_start or os_start + 12288 <= regular_start):
            raise harness.HarnessError(f"{side} selected areas overlap")
        for tag in "123":
            offset = clients[tag][0] - regular_start
            if offset < 0 or offset % 128 or offset + clients[tag][1] > 8192:
                raise harness.HarnessError(f"{side} client {tag} lies outside the committed block grid")
        if clients["S"][0] != os_start:
            raise harness.HarnessError(f"{side} OS client does not occupy its singleton block")
        order = "13" if clients["1"][0] < clients["3"][0] else "31"
        expected_trace = dict(SOURCE_CHILD_ABANDONED_PAGES)
        for key, value in expected_trace.items():
            expected_trace[key] = value.replace("R13", "R" + order)
        if order == "31":
            expected_trace["child.stop_regular_block"] = "0,1,0,1,0,0,2,0,R3"
        if trace != expected_trace:
            raise harness.HarnessError(f"{side} callbacks differ from the independent physical live-block model")
        # This selected source page commits 64 regular 128-byte slots in a
        # 64-KiB area with its first slot displaced by 128 bytes. The aligned
        # OS allocation is a single 12-KiB block. Keep those source extents,
        # payload bounds and used counts even when client addresses shuffle.
        for stage in STAGES:
            events = expected_trace['child.' + stage].rsplit(",", 1)[1]
            rows = geometry.get(stage, [])
            addresses = placements.get(stage, [])
            if len(rows) != len(events) or len(addresses) != len(events):
                raise harness.HarnessError(f"{side} {stage} callback geometry is incomplete or repeated")
            for event, row, placement in zip(events, rows, addresses):
                regular = event in "R13"
                scalar = (65408, 8192, 2, 128, 128, 128) if regular else (12288, 12288, 1, 12288, 12288, 12288)
                usable = 0 if event in "RO" else clients[event][2]
                origin = regular_start if regular else os_start
                offset = 0 if event in "RO" else clients[event][0] - origin
                if row != (event, *scalar, usable) or placement != (event, origin, offset):
                    raise harness.HarnessError(f"{side} {stage} area extent, stride or callback placement changed")
        # The verified stopping prefix can contain a different number of
        # clients in each independently shuffled allocation. Compare the
        # callback predicate and fixed area/client semantics across backends.
        model = {}
        for key, value in SOURCE_CHILD_ABANDONED_PAGES.items():
            if key == "child.stop_regular_block":
                continue
            scalars, events = value.rsplit(",", 1)
            regular_live = "1|3" if "1" in events else ""
            model[key] = (scalars + f";regular-live={regular_live};os-live={int('S' in events)}"
                          + f";regular-area={int('R' in events)};os-area={int('O' in events)};physical-grid")
        model['child.stop_regular_block'] = 'stop on first live client in ascending physical grid'
        for tag, (_, requested, usable, live) in clients.items():
            model["client." + tag] = f"{requested},{usable},{live}"
        return model
    if side == "c" and trace != SOURCE_CHILD_ABANDONED_PAGES:
        raise harness.HarnessError(f"pinned C child abandoned-page image changed: {trace}")
    return trace


PROFILES = ("release", "debug-1", "stat-1", "stat-2")
AVAILABLE_PROFILES = (*PROFILES, "secure-1", "secure-2")
RUNNER = "allocator-child-abandoned-visitor"
receipts = load_module("child_abandoned_visitor_receipts", harness.ROOT / "compat/x86_64/native_shadow_receipt.py")


def record(output, name, argv, cwd, runtime=False):
    result = stress.command_record(argv, cwd=cwd,
        environment={} if runtime else dict(os.environ), timeout=60 if runtime else 3600)
    logs = [output / f"{name}.json"]
    logs[0].write_text(json.dumps(result, indent=2) + "\n")
    for stream in ("stdout", "stderr"):
        if stream in result:
            path = output / f"{name}.{stream}"
            path.write_bytes(stress.byte_record_payload(result[stream], name))
            logs.append(path)
    if result["kind"] != "process" or result["status"] != 0:
        raise harness.HarnessError(f"{name} failed; actual process record: {logs[0]}")
    return result, logs


def run_profiles(profiles, *, canonical=False):
    if (not profiles or len(set(profiles)) != len(profiles)
            or any(profile not in AVAILABLE_PROFILES for profile in profiles)):
        raise harness.HarnessError("unknown or duplicate visitation profile selection")
    execution = harness.require_native_x86_64(require_image_identity=True)
    seal = receipts.source_seal(harness.ROOT)
    pin = harness.load_pin()
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="run-", dir=ARTIFACTS))
    output.chmod(0o755)
    source = harness.safe_extract(harness.fetch_archive(pin, True), output / "source", pin["archive_root"])
    products, cases = {}, []
    for original in (DRIVER, source / "include/mimalloc.h", source / "LICENSE"):
        retained = output / original.name
        shutil.copy2(original, retained)
        products[retained.name] = retained
    inputs = output / "inputs.json"
    inputs.write_text(json.dumps({"source": seal, "execution": execution, "upstream": pin,
        "profiles": profiles, "source_internal_checks": True,
        "boundary": "explicit mi_* native adapter; pinned musl provides pthreads",
        "runtime_watchdog_seconds": 60}, indent=2) + "\n")
    products[inputs.name] = inputs
    compiler = harness.require_tool("musl-gcc")
    print(f"child abandoned visitor raw products: {output}", flush=True)
    for profile in profiles:
        directory = output / profile
        directory.mkdir()

        def passed(name, argv, cwd=source, runtime=False):
            result, logs = record(output, f"{profile}-{name}", argv, cwd, runtime)
            cases.append((f"{profile}-{name}", 0, logs))
            return result

        common = ["-std=c11", "-D_GNU_SOURCE", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
                  *m4.api_profile_flags(profile), *(("-DCRABC_VISIT_SECURE=2",) if profile == "secure-2" else ()), "-I", str(source / "include"), "-I", str(source / "src")]
        c_binary = directory / "c"
        passed("c-build", [compiler, *common, "-DCRABC_M6_SOURCE_INTERNAL=1",
            str(DRIVER), str(source / "src/static.c"), "-pthread", "-o", str(c_binary)])
        products[f"{profile}-c"] = c_binary
        c_run = passed("c-run", [str(c_binary)], directory, True)
        c_stdout = stress.byte_record_payload(c_run["stdout"], profile).decode()
        c_stderr = stress.byte_record_payload(c_run["stderr"], profile).decode()
        if re.findall(r"^source\.transfer=([01]),([01]),([01]),([01]),([01])$", c_stderr, re.MULTILINE) != [("1",) * 5]:
            raise harness.HarnessError(f"{profile} pinned child page owners changed; raw {output}")
        c_trace = m7.parse_options_trace(c_stdout, "C child abandoned visitor", BEGIN, END)
        c_model = require_trace(c_trace, "c", profile=profile, stderr=c_stderr)
        target = directory / "cargo-target"
        passed("native-build", [harness.require_tool("cargo"), "build", "--locked", "--offline", "--release",
            "--target", m4.RUST_TARGET, "-p", m4.ADAPTER_PACKAGE, "--target-dir", str(target),
            *(("--features", f"crabc-mimalloc/mi-{profile}") if profile != "release" else ())], harness.ROOT)
        library = target / m4.RUST_TARGET / "release" / m4.ADAPTER_STATICLIB
        retained_library = directory / m4.ADAPTER_STATICLIB
        shutil.copy2(library, retained_library)
        products[f"{profile}-native-library"] = retained_library
        native_binary = directory / "native"
        passed("native-link", [compiler, *common, str(DRIVER), str(retained_library), "-pthread", "-o", str(native_binary)])
        products[f"{profile}-native"] = native_binary
        native_run = passed("native-run", [str(native_binary)], directory, True)
        native_stdout = stress.byte_record_payload(native_run["stdout"], profile).decode()
        native_trace = m7.parse_options_trace(native_stdout, "native", BEGIN, END)
        native_stderr = stress.byte_record_payload(native_run["stderr"], profile).decode()
        native_model = require_trace(native_trace, "native", profile=profile, stderr=native_stderr)
        m7.compare_options_traces(c_model, native_model)
        if profile != "secure-2" and (not re.findall(r"^geometry\..+$", c_stderr, re.MULTILINE) or re.findall(r"^geometry\..+$", c_stderr, re.MULTILINE) != re.findall(r"^geometry\..+$", native_stderr, re.MULTILINE)):
            raise harness.HarnessError(f"{profile} child client geometry differs; raw {output}")

        print(f"child abandoned visitor {profile}: {len(c_trace)} C/native keys PASS", flush=True)
    if receipts.source_seal(harness.ROOT) != seal:
        raise harness.HarnessError("source changed during child Heap visitation")
    canonical = canonical or tuple(profiles) == PROFILES
    path = receipts.write_receipt(harness.ROOT, RUNNER, output, products, cases,
        {"profiles": ",".join(profiles), "boundary": "explicit native-mi-adapter",
         "source-internal-checks": "true", "geometry": "ordered retained clients and areas", "watchdog-seconds": "60"}, canonical)
    if canonical:
        receipts.read_receipt(harness.ROOT, RUNNER)
    print(f"child abandoned visitor {'canonical requested-profile' if canonical else 'development-only'} receipt: {path}")
    return len(STAGES)


def run_differential() -> int:
    return run_profiles(("release",))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--profile", choices=AVAILABLE_PROFILES, help="development-only selected profile")
    selection.add_argument("--matrix", action="store_true", help="canonical four-profile visitation comparison")
    selection.add_argument("--profiles", nargs="+", choices=AVAILABLE_PROFILES,
        help="complete ordered profile cohort for production or retained reading")
    parser.add_argument("--read", action="store_true", help="read exact-source physical receipt")
    parser.add_argument("--replay", action="store_true", help="read and execute all retained C/native products")
    args = parser.parse_args()
    profiles = tuple(args.profiles) if args.profiles else PROFILES
    if len(set(profiles)) != len(profiles):
        parser.error("profile selection cannot contain duplicates")
    if args.read or args.replay:
        if args.profile or args.matrix:
            parser.error("reading a canonical receipt cannot select profiles")
        receipt = receipts.read_receipt(harness.ROOT, RUNNER)
        inputs = harness.read_json(receipt.path.parent / "products/inputs.json")
        wanted = [f"{profile}-{backend}-run" for profile in profiles for backend in ("c", "native")]
        recorded = [case for case in receipt.case_ids() if case.endswith("-run")]
        if (receipt.parameters.get("profiles") != ",".join(profiles)
                or inputs.get("profiles") != list(profiles) or recorded != wanted):
            raise receipts.ReceiptError("visitation receipt does not cover the exact requested profile cohort")
        if "secure-2" in profiles:
            models = []
            for backend in ("c", "native"):
                case = next(case for case in receipt.cases if case["id"] == f"secure-2-{backend}-run")
                payloads = {}
                for stream in ("stdout", "stderr"):
                    original = next(path for path in case["logs"] if path.endswith(f".{stream}"))
                    payloads[stream] = (receipt.path.parent / "logs" / original).read_text()
                if backend == "c" and re.findall(r"^source\.transfer=" + r"([01])," * 4 + r"([01])$", payloads["stderr"], re.MULTILINE) != [("1",) * 5]:
                    raise harness.HarnessError("retained secure-2 source page owners changed")
                trace = m7.parse_options_trace(payloads["stdout"], backend, BEGIN, END)
                models.append(require_trace(trace, backend, profile="secure-2", stderr=payloads["stderr"]))
            m7.compare_options_traces(*models)
        print("child abandoned visitor exact-source physical receipt: PASS")
        if args.replay:
            execution = harness.require_native_x86_64(require_image_identity=True)
            harness.native_execution_attestation(inputs.get("execution"), execution)
            harness.TEMP_ROOT.mkdir(parents=True, exist_ok=True)
            scratch = Path(tempfile.mkdtemp(prefix="child_abandoned_visitor-replay-", dir=harness.TEMP_ROOT))
            for profile in profiles:
                for backend in ("c", "native"):
                    product = f"{profile}-{backend}"
                    binary = scratch / product
                    shutil.copyfile(receipt.path.parent / "products" / product, binary)
                    binary.chmod(0o755)
                    result, _ = record(scratch, product, [str(binary)], scratch, True)
                    case = next(case for case in receipt.cases if case["id"] == f"{profile}-{backend}-run")
                    for stream in ("stdout",):
                        original = next(path for path in case["logs"] if path.endswith(f".{stream}"))
                        if profile != "secure-2" and stress.byte_record_payload(result[stream], product) != (receipt.path.parent / "logs" / original).read_bytes():
                            raise harness.HarnessError(f"retained {product} {stream} differs; raw {scratch}")
                    stderr = stress.byte_record_payload(result["stderr"], product).decode()
                    original = next(path for path in case["logs"] if path.endswith(".stderr"))
                    recorded_stderr = (receipt.path.parent / "logs" / original).read_text()
                    if profile == "secure-2":
                        original_stdout = next(path for path in case["logs"] if path.endswith(".stdout"))
                        recorded_trace = m7.parse_options_trace((receipt.path.parent / "logs" / original_stdout).read_text(), backend, BEGIN, END)
                        fresh_trace = m7.parse_options_trace(stress.byte_record_payload(result["stdout"], product).decode(), backend, BEGIN, END)
                        recorded_model = require_trace(recorded_trace, backend, profile=profile, stderr=recorded_stderr)
                        fresh_model = require_trace(fresh_trace, backend, profile=profile, stderr=stderr)
                        m7.compare_options_traces(recorded_model, fresh_model)
                    if profile != "secure-2" and re.findall(r"^geometry\..+$", stderr, re.MULTILINE) != re.findall(r"^geometry\..+$", recorded_stderr, re.MULTILINE):
                        raise harness.HarnessError(f"retained {product} client geometry differs; raw {scratch}")
                    if backend == "c" and re.findall(r"^source\.transfer=([01]),([01]),([01]),([01]),([01])$", stderr, re.MULTILINE) != [("1",) * 5]:
                        raise harness.HarnessError(f"retained {product} source owners differ; raw {scratch}")
            print(f"child abandoned visitor retained requested-profile products: PASS; raw {scratch}")
    else:
        if args.profiles:
            run_profiles(profiles, canonical=True)
        else:
            run_profiles(PROFILES if args.matrix else (args.profile or "release",))


if __name__ == "__main__":
    try:
        main()
    except (harness.HarnessError, receipts.ReceiptError, stress.EvidenceError) as error:
        print(f"child abandoned visitor failed: {error}", file=sys.stderr)
        raise SystemExit(1)
