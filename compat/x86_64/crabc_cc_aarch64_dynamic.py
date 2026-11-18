#!/usr/bin/env python3
"""Compile native AArch64 dynamic applications against the installed crabc sysroot."""
import importlib.machinery
import importlib.util
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
        if arg in ("--dynamic-pie", "--dynamic-shared-object"):
            if mode is not None:
                raise shared.DriverError("select exactly one dynamic mode")
            mode = "shared" if arg == "--dynamic-shared-object" else "pie"
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
    if invocation.print_link_plan or invocation.link_receipt is not None:
        raise shared.DriverError("arm64 link plans and receipts are unavailable")
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
    output = invocation.output or (sources[0].with_suffix(".o") if invocation.compile_only else Path("a.out"))
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
        command = ["/usr/bin/mold", "-shared" if mode == "shared" else "-pie", "-z", "dynamic-undefined-weak",
                   "--no-undefined", "--eh-frame-hdr", "-z", "relro", "-z", "now"]
        if mode == "pie":
            command += ["--dynamic-linker", "/lib/ld-crabc-aarch64.so.1", "-e", "_start", str(lib / "Scrt1.o")]
        else:
            command += ["-soname", output.name]
        if runpath is not None:
            command += ["--enable-new-dtags", "-rpath", runpath]
        if export_dynamic:
            command.append("--export-dynamic")
        command += [str(lib / "crti.o"), *(str(path) for path in objects), *(str(path) for path in dso_inputs),
                    str(lib / "libc.so"), str(lib / "libcrabc-builtins.a"), str(lib / "crtn.o"), "-o", str(output)]
        shared.run_checked(command)


try:
    execute(sys.argv[1:])
except (shared.DriverError, OSError, subprocess.SubprocessError) as error:
    sys.exit(f"crabc-cc-dynamic: {error}")
