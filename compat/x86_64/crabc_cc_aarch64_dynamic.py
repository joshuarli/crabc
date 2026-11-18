#!/usr/bin/env python3
"""Compile native AArch64 dynamic applications against the installed crabc sysroot."""
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
root = Path(__file__).resolve().parent.parent
lib = root / "usr/lib"
loader = importlib.machinery.SourceFileLoader("crabc_cc_static", str(root / "share/crabc/crabc_cc_static.py"))
spec = importlib.util.spec_from_loader(loader.name, loader)
shared = importlib.util.module_from_spec(spec)
sys.modules[loader.name] = shared
loader.exec_module(shared)


def execute(arguments):
    manifest = shared.load_manifest(root / "share/crabc/manifest.json", "dynamic product manifest")
    profile = shared.profile_from_manifest(manifest)
    interpreter = "/lib/ld-crabc-aarch64-hardened.so.1" if profile is shared.NativeRuntimeProfile.HARDENED else "/lib/ld-crabc-aarch64.so.1"
    common = []
    quote_dirs = []
    dsos = []
    mode = None
    runpath = None
    rounding = False
    export_dynamic = False
    index = 0
    while index < len(arguments):
        arg = arguments[index]
        if arg in ("--dynamic-pie", "-pie", "--dynamic-shared-object", "-shared"):
            if mode is not None:
                raise shared.DriverError("select exactly one dynamic mode")
            mode = "shared" if arg in ("--dynamic-shared-object", "-shared") else "pie"
        elif arg == "-o":
            index += 1
            if index == len(arguments):
                raise shared.DriverError("-o requires an output path")
            common.extend((arg, arguments[index]))
        elif arg in ("--application-quote-include-dir", "--application-runpath", "--application-dso"):
            index += 1
            if index == len(arguments) or arguments[index].startswith("-"):
                raise shared.DriverError(f"{arg} requires a value")
            value = arguments[index]
            if arg == "--application-quote-include-dir":
                path = Path(value)
                shared.reject_existing_symlink_components(path, "application quote include")
                path = shared.resolved_path(path, "application quote include")
                if not path.is_dir() or shared.is_within_installed_root(root, path) or path in quote_dirs:
                    raise shared.DriverError("application quote include is missing, duplicated, or unsafe")
                quote_dirs.append(path)
            elif arg == "--application-runpath":
                if runpath is not None or not value or len(value.encode()) >= 4096 or "\0" in value:
                    raise shared.DriverError("invalid application RUNPATH")
                runpath = value
            else:
                dsos.append(Path(value))
        elif arg == "-frounding-math":
            if rounding:
                raise shared.DriverError("duplicate rounding mode")
            rounding = True
        elif arg == "-rdynamic":
            if export_dynamic:
                raise shared.DriverError("duplicate export mode")
            export_dynamic = True
        elif arg.endswith(".so") and not arg.startswith("-"):
            dsos.append(Path(arg))
        else:
            common.append(arg)
        index += 1
    mode = mode or "pie"
    invocation = shared.parse_invocation(common)
    if invocation.link_receipt is not None:
        raise shared.DriverError("dynamic link receipt path is derived from -o")
    if invocation.print_link_plan:
        if quote_dirs or dsos or rounding or export_dynamic or runpath is not None:
            raise shared.DriverError("link plan accepts no application inputs")
        plan = ["/usr/bin/mold", "-shared" if mode == "shared" else "-pie", "--hash-style=sysv",
                "--eh-frame-hdr", "-z", "relro", "-z", "now", "-z", "noexecstack", "-z", "text",
                "--no-undefined", "--allow-shlib-undefined", "--enable-new-dtags", "-rpath", "/usr/lib",
                "--exclude-libs=libcrabc-builtins.a"]
        if mode == "pie":
            plan += ["-z", "dynamic-undefined-weak", "--dynamic-linker", interpreter, str(lib / "Scrt1.o")]
        else:
            plan += ["-soname", "<output-basename>"]
        plan += [str(lib / "crti.o"), shared.APPLICATION_OBJECTS, str(lib / "libcrabc-builtins.a"),
                 str(lib / "libc.so"), str(lib / "crtn.o"), "-o", shared.OUTPUT]
        print(json.dumps({"format": "crabc-aarch64-owned-dynamic-sysroot-v1", "mode": mode, "binding": "now",
                          "runtime_imports": [], "application_runpath": "/usr/lib", "application_rpath": None,
                          "application_search_kind": "runpath", "application_hash_style": "sysv", "linker": plan,
                          "campaign_complete": False}, sort_keys=True))
        return
    if invocation.compile_only and (dsos or runpath is not None or export_dynamic):
        raise shared.DriverError("compile-only accepts no link options")
    if mode == "shared" and export_dynamic:
        raise shared.DriverError("-rdynamic requires an executable")
    sources = [shared.require_application_file(root, path, "source") for path in invocation.sources]
    objects_in = [shared.require_x86_64_relocatable_object(root, path, architecture="aarch64") for path in invocation.objects]
    dso_inputs = [shared.require_application_file(root, path, "DSO") for path in dsos]
    for path in dso_inputs:
        if shared.rejects_runtime_object(path):
            raise shared.DriverError("unowned application DSO")
        with path.open("rb") as stream:
            data = stream.read(64)
        if len(data) != 64 or data[:7] != b"\x7fELF\x02\x01\x01" or int.from_bytes(data[16:18], "little") != 3 or int.from_bytes(data[18:20], "little") != 183:
            raise shared.DriverError(f"application DSO is not native ET_DYN: {path}")
        segments = subprocess.check_output(["/usr/bin/readelf", "-lW", str(path)], text=True)
        dynamic = subprocess.check_output(["/usr/bin/readelf", "-dW", str(path)], text=True)
        if ("INTERP" in segments or "TEXTREL" in dynamic or "(RPATH)" in dynamic
                or re.findall(r"\(SONAME\).*\[([^\]]+)\]", dynamic) != [path.name]
                or any("/" in value for value in re.findall(r"\(NEEDED\).*\[([^\]]+)\]", dynamic))
                or re.findall(r"\(RUNPATH\).*\[([^\]]*)\]", dynamic) not in ([], ["/usr/lib"])):
            raise shared.DriverError(f"application DSO metadata is not admitted: {path}")
    output = (invocation.output or (sources[0].with_suffix(".o") if invocation.compile_only else Path("a.out"))).absolute()
    shared.validate_application_output(root, output)
    shared.validate_application_output_disjoint(output, (*sources, *objects_in, *dso_inputs))
    with tempfile.TemporaryDirectory(prefix="crabc-aarch64-dynamic-") as temporary:
        objects = list(objects_in)
        for index, source in enumerate(sources):
            obj = output if invocation.compile_only else Path(temporary) / f"{index}.o"
            shared.run_checked([shared.compiler(), "-nostdinc", *(v for path in quote_dirs for v in ("-iquote", str(path))),
                                "-isystem", str(root / "usr/include"), *shared.HOSTED_TRANSLATION_FLAGS,
                                *invocation.compiler_flags, *(["-frounding-math"] if rounding else []),
                                "-fPIC" if mode == "shared" else "-fPIE", "-c", str(source), "-o", str(obj)])
            objects.append(obj)
        if invocation.compile_only:
            return
        receipt_path = Path(str(output) + ".crabc-link.json")
        shared.validate_application_output(root, receipt_path)
        shared.validate_application_output_disjoint(receipt_path, (*sources, *objects_in, *dso_inputs, output))
        runtime = [lib / name for name in ("crti.o", "libc.so", "crtn.o")]
        command = ["/usr/bin/mold", "-shared" if mode == "shared" else "-pie", "--hash-style=sysv",
                   "--eh-frame-hdr", "-z", "relro", "-z", "now", "-z", "noexecstack", "-z", "text", "--no-undefined",
                   "--allow-shlib-undefined", "--enable-new-dtags", "-rpath", runpath or "/usr/lib",
                   "--exclude-libs=libcrabc-builtins.a"]
        if export_dynamic:
            command.append("--export-dynamic")
        if mode == "pie":
            runtime.append(lib / "Scrt1.o")
            command += ["-z", "dynamic-undefined-weak", "--dynamic-linker", interpreter, str(lib / "Scrt1.o")]
        else:
            command += ["-soname", output.name]
        archive = lib / "libcrabc-builtins.a"
        command += [str(lib / "crti.o"), *(str(path) for path in objects), str(archive),
                    *(str(path) for path in dso_inputs), str(lib / "libc.so"), str(lib / "crtn.o"), "-o", str(output)]
        descriptor = os.open(receipt_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        try:
            completed = subprocess.run([*command[:-2], "--trace", *command[-2:]], text=True,
                                       stdout=subprocess.PIPE, check=True, env=shared.clean_environment())
            trace = completed.stdout.splitlines()
            direct = [*runtime, *objects, *dso_inputs]
            direct_text = {str(path) for path in direct}
            seen = set()
            for line in trace:
                line = line.removeprefix("trace: ")
                if line in direct_text:
                    seen.add(line)
                elif line == str(archive) or (line.startswith(str(archive) + "(") and line.endswith(")")):
                    continue
                else:
                    raise shared.DriverError(f"unadmitted dynamic link trace input: {line}")
            if seen != direct_text:
                raise shared.DriverError("dynamic link trace omitted an explicit input")
            header = subprocess.check_output(["/usr/bin/readelf", "-hW", str(output)], text=True)
            segments = subprocess.check_output(["/usr/bin/readelf", "-lW", str(output)], text=True)
            dynamic = subprocess.check_output(["/usr/bin/readelf", "-dW", str(output)], text=True)
            if ("AArch64" not in header or "DYN" not in header or "TEXTREL" in dynamic
                    or (mode == "pie" and interpreter not in segments)
                    or (mode == "shared" and "INTERP" in segments)):
                raise shared.DriverError("linked dynamic ELF does not match its native mode")
            record = {"schema": 2, "format": "crabc-aarch64-owned-dynamic-sysroot-v1", "mode": mode,
                      "binding": "now", "runtime_imports": [], "application_runpath": runpath or "/usr/lib",
                      "application_rpath": None, "application_search_kind": "runpath", "application_hash_style": "sysv",
                      "output_path": str(output.resolve()), "output_sha256": shared.sha256_file(output),
                      "manifest_sha256": shared.sha256_file(root / "share/crabc/manifest.json"),
                      "application_dsos": {path.name: shared.sha256_file(path) for path in dso_inputs},
                      "owned_runtime_inputs": sorted(path.relative_to(root).as_posix() for path in [*runtime, archive]),
                      "input_receipts": [{"path": str(path), "sha256": shared.sha256_file(path)} for path in [*direct, archive]],
                      "resolved_linker": {"path": command[0], "sha256": shared.sha256_file(Path(command[0]))},
                      "link_command": command, "link_trace": trace, "campaign_complete": False}
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                descriptor = -1
                json.dump(record, stream, indent=2, sort_keys=True)
                stream.write("\n")
        except BaseException:
            if descriptor != -1:
                os.close(descriptor)
            receipt_path.unlink(missing_ok=True)
            raise



try:
    execute(sys.argv[1:])
except (shared.DriverError, OSError, subprocess.SubprocessError) as error:
    sys.exit(f"crabc-cc-dynamic: {error}")
