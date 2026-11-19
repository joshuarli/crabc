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
sys.path.insert(0, str(root / "share/crabc"))
import owned_dynamic_elf as elf_inspection
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
    transitive_dsos = []
    mode = None
    runpath = None
    rpath = None
    hash_style = "sysv"
    hash_explicit = False
    dependency_file = None
    rounding = False
    export_dynamic = False
    binding_mode = None
    runtime_imports = set()
    index = 0
    while index < len(arguments):
        arg = arguments[index]
        if arg in ("--dynamic-pie", "-pie", "--dynamic-non-pie", "-no-pie", "--dynamic-shared-object", "-shared"):
            if mode is not None:
                raise shared.DriverError("select exactly one dynamic mode")
            mode = ("shared" if arg in ("--dynamic-shared-object", "-shared") else
                    "exec" if arg in ("--dynamic-non-pie", "-no-pie") else "pie")
        elif arg in ("--binding", "--runtime-import"):
            index += 1
            if index == len(arguments):
                raise shared.DriverError(f"missing {arg} value")
            value = arguments[index]
            if arg == "--binding":
                if binding_mode is not None or value not in ("now", "lazy"):
                    raise shared.DriverError("select one binding: now or lazy")
                binding_mode = value
            elif not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", value) or value in runtime_imports:
                raise shared.DriverError("invalid or duplicate runtime import")
            else:
                runtime_imports.add(value)
        elif arg == "--application-hash-style":
            index += 1
            if index == len(arguments) or hash_explicit or arguments[index] not in ("sysv", "gnu", "both"):
                raise shared.DriverError("select one application hash style: sysv, gnu, or both")
            hash_style = arguments[index]
            hash_explicit = True
        elif arg == "-o":
            index += 1
            if index == len(arguments):
                raise shared.DriverError("-o requires an output path")
            common.extend((arg, arguments[index]))
        elif arg in ("--application-quote-include-dir", "--application-runpath", "--application-rpath", "--application-dso", "--transitive-application-dso"):
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
            elif arg in ("--application-runpath", "--application-rpath"):
                if runpath is not None or rpath is not None or not value or len(value.encode()) >= 4096 or "\0" in value:
                    raise shared.DriverError("invalid application search path")
                if arg == "--application-rpath":
                    rpath = value
                else:
                    runpath = value
            elif arg == "--transitive-application-dso":
                transitive_dsos.append(Path(value))
            else:
                dsos.append(Path(value))
        elif arg == "--application-dependency-file":
            index += 1
            if index == len(arguments) or arguments[index].startswith("-") or dependency_file is not None:
                raise shared.DriverError("--application-dependency-file requires one output path")
            dependency_file = Path(arguments[index])
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
    if rpath is not None and mode == "shared":
        raise shared.DriverError("--application-rpath requires a dynamic executable link")
    binding_mode = binding_mode or "now"
    if profile is shared.NativeRuntimeProfile.HARDENED and mode == "exec":
        raise shared.DriverError("hardened dynamic product requires PIE")
    if profile is shared.NativeRuntimeProfile.HARDENED and binding_mode != "now":
        raise shared.DriverError("hardened dynamic products require eager binding")
    if runtime_imports and (mode != "shared" or binding_mode != "lazy"):
        raise shared.DriverError("runtime imports require a lazy shared object")
    invocation = shared.parse_invocation(common)
    if invocation.compile_only and (rpath is not None or (runpath is not None and runpath != "/usr/lib")):
        raise shared.DriverError("compile-only accepts no application RUNPATH")
    if invocation.compile_only and hash_explicit:
        raise shared.DriverError("compile-only accepts no application hash style")
    if invocation.compile_only and (runtime_imports or binding_mode != "now"):
        raise shared.DriverError("compile-only accepts no binding/import contract")
    if dependency_file is not None and not invocation.compile_only:
        raise shared.DriverError("--application-dependency-file is available only for a compile-only invocation")
    if invocation.link_receipt is not None:
        raise shared.DriverError("dynamic link receipt path is derived from -o")
    if invocation.print_link_plan:
        if quote_dirs or dsos or transitive_dsos or rounding or export_dynamic or runpath is not None:
            raise shared.DriverError("link plan accepts no application inputs")
        plan = ["/usr/bin/mold", *(["-shared"] if mode == "shared" else ["-pie"] if mode == "pie" else []), "--hash-style=" + hash_style,
                "--eh-frame-hdr", "-z", "relro", "-z", binding_mode, "-z", "noexecstack", "-z", "text",
                *([] if runtime_imports else ["--no-undefined"]), "--allow-shlib-undefined", "--disable-new-dtags" if rpath is not None else "--enable-new-dtags", "-rpath", rpath if rpath is not None else "/usr/lib",
                "--exclude-libs=libcrabc-builtins.a"]
        if mode != "shared":
            plan += ["-z", "dynamic-undefined-weak", "--dynamic-linker", interpreter, str(lib / ("Scrt1.o" if mode == "pie" else "crt1.o"))]
        else:
            plan += ["-soname", "<output-basename>"]
        plan += [str(lib / "crti.o"), *([str(lib / "crabc-dynamic-attach.o")] if mode == "exec" else []), shared.APPLICATION_OBJECTS, str(lib / "libcrabc-builtins.a"),
                 str(lib / "libc.so"), str(lib / "crtn.o"), "-o", shared.OUTPUT]
        print(json.dumps({"format": "crabc-aarch64-owned-dynamic-sysroot-v1", "mode": mode, "binding": binding_mode,
                          "runtime_imports": sorted(runtime_imports), "application_runpath": None if rpath is not None else "/usr/lib", "application_rpath": rpath,
                          "application_search_kind": "rpath" if rpath is not None else "runpath", "application_hash_style": hash_style, "linker": plan,
                          "campaign_complete": False}, sort_keys=True))
        return
    if invocation.compile_only and (dsos or transitive_dsos or runpath is not None or export_dynamic):
        raise shared.DriverError("compile-only accepts no link options")
    if transitive_dsos and not dsos:
        raise shared.DriverError("transitive application DSOs require one direct --application-dso")
    if mode == "shared" and export_dynamic:
        raise shared.DriverError("-rdynamic requires an executable")
    sources = [shared.require_application_file(root, path, "source") for path in invocation.sources]
    objects_in = [shared.require_x86_64_relocatable_object(root, path, architecture="aarch64") for path in invocation.objects]
    dso_inputs = [shared.require_application_file(root, path, "DSO") for path in dsos]
    transitive_inputs = [shared.require_application_file(root, path, "DSO") for path in transitive_dsos]
    nodes = {}
    for path in [*dso_inputs, *transitive_inputs]:
        if shared.rejects_runtime_object(path):
            raise shared.DriverError("unowned application DSO")
        with path.open("rb") as stream:
            data = stream.read(64)
        if len(data) != 64 or data[:7] != b"\x7fELF\x02\x01\x01" or int.from_bytes(data[16:18], "little") != 3 or int.from_bytes(data[18:20], "little") != 183:
            raise shared.DriverError(f"application DSO is not native ET_DYN: {path}")
        segments = subprocess.check_output(["/usr/bin/readelf", "-lW", str(path)], text=True)
        dynamic = subprocess.check_output(["/usr/bin/readelf", "-dW", str(path)], text=True)
        if not re.fullmatch(r"[^/\x00]+\.so(?:\.[0-9]+)*", path.name) or path.name in ("libc.so", "ld-crabc-aarch64.so.1", "ld-musl-aarch64.so.1"):
            raise shared.DriverError("unowned application DSO")
        if path.name in nodes or path in [node[0] for node in nodes.values()]:
            raise shared.DriverError("duplicate application DSO")
        needed = re.findall(r"\(NEEDED\).*\[([^\]]+)\]", dynamic)
        nodes[path.name] = (path, needed)
        runpaths = re.findall(r"\(RUNPATH\).*\[([^\]]*)\]", dynamic)
        if runpaths not in ([], ["/usr/lib"]):
            sidecar = Path(str(path) + ".crabc-link.json")
            shared.require_regular(sidecar, "application search path receipt")
            search = json.loads(sidecar.read_text())
            if (search.get("mode") != "shared" or search.get("output_path") != str(path)
                    or search.get("output_sha256") != shared.sha256_file(path)
                    or search.get("manifest_sha256") != shared.sha256_file(root / "share/crabc/manifest.json")
                    or search.get("application_search_kind") != "runpath"
                    or runpaths != [search.get("application_runpath")]):
                raise shared.DriverError("application DSO has an undeclared runtime search path")
        if ("INTERP" in segments or "TEXTREL" in dynamic or "(RPATH)" in dynamic
                or re.findall(r"\(SONAME\).*\[([^\]]+)\]", dynamic) != [path.name]
                or any("/" in value for value in re.findall(r"\(NEEDED\).*\[([^\]]+)\]", dynamic))
                ):
            raise shared.DriverError(f"application DSO metadata is not admitted: {path}")
    if transitive_inputs:
        names = set(nodes)
        def reachable(roots, omit=None):
            reached = set()
            pending = list(roots)
            while pending:
                name = pending.pop()
                if name != omit and name not in reached:
                    reached.add(name)
                    pending.extend(child for child in nodes[name][1] if child in nodes)
            return reached
        if reachable(path.name for path in dso_inputs) != names:
            raise shared.DriverError("application DSO closure has an unreachable declared node")
        provided, requirements = set(), {}
        for path in [lib / "libc.so", *(node[0] for node in nodes.values())]:
            defined, required = set(), set()
            symbols = subprocess.check_output(["/usr/bin/readelf", "--dyn-syms", "-W", str(path)], text=True)
            for line in symbols.splitlines():
                fields = line.split()
                if len(fields) < 8 or not fields[0].endswith(":") or fields[4] not in ("GLOBAL", "WEAK"):
                    continue
                kind, binding, visibility, section, name = fields[3:8]
                if "@" in name or kind == "IFUNC":
                    raise shared.DriverError("symbol versions and IFUNC are not admitted")
                if section == "UND" and binding == "GLOBAL":
                    required.add(name)
                elif section != "UND" and visibility in ("DEFAULT", "PROTECTED"):
                    defined.add(name)
            provided.update(defined)
            requirements[path.name] = required
        for path, needed in nodes.values():
            if len(needed) != len(set(needed)) or not set(needed) <= names | {"libc.so"}:
                raise shared.DriverError("application DSO closure is incomplete or duplicated")
            receipt = Path(str(path) + ".crabc-link.json")
            shared.require_regular(receipt, "application DSO closure receipt")
            record = json.loads(receipt.read_text())
            if (record.get("format") != "crabc-aarch64-owned-dynamic-sysroot-v1"
                    or record.get("mode") != "shared" or record.get("output_path") != str(path)
                    or record.get("output_sha256") != shared.sha256_file(path)
                    or record.get("manifest_sha256") != shared.sha256_file(root / "share/crabc/manifest.json")
                    or record.get("binding") != "now" or record.get("campaign_complete") is not False
                    or record.get("application_search_kind") != "runpath"
                    or record.get("runtime_imports") != []
                    or record.get("owned_runtime_inputs") != sorted("usr/lib/" + name for name in ("crti.o", "libc.so", "crtn.o", "libcrabc-builtins.a"))):
                raise shared.DriverError("application DSO closure receipt does not bind its product")
            observed_dynamic = subprocess.check_output(["/usr/bin/readelf", "-dW", str(path)], text=True)
            if re.findall(r"\(RUNPATH\).*\[([^\]]*)\]", observed_dynamic) != [record.get("application_runpath")]:
                raise shared.DriverError("application DSO closure receipt search path differs")
            if requirements[path.name] - provided:
                raise shared.DriverError("application DSO has unresolved runtime imports")
            children = {name for name in needed if name in nodes}
            expected = children if record.get("schema") == 2 else reachable(children, omit=path.name)
            identities = {name: shared.sha256_file(nodes[name][0]) for name in expected}
            if record.get("schema") not in (2, 3) or record.get("application_dsos") != identities:
                raise shared.DriverError("application DSO closure receipt dependency identities differ")
            command, trace, inputs = record.get("link_command", []), record.get("link_trace", []), record.get("input_receipts", [])
            if not isinstance(command, list) or not isinstance(trace, list) or not isinstance(inputs, list):
                raise shared.DriverError("invalid application DSO closure evidence")
            trace = [line.removeprefix("trace: ") for line in trace]
            forbidden = {str(node[0]) for name, node in nodes.items() if name not in expected and name != path.name}
            if any(item in forbidden for item in [*command, *trace]):
                raise shared.DriverError("application DSO closure receipt linked an undeclared graph node")
            if record["schema"] == 3:
                if record.get("application_dso_roles") != {name: "direct" if name in children else "transitive" for name in expected} or record.get("application_dso_needed") != {name: nodes[name][1] for name in expected}:
                    raise shared.DriverError("application DSO closure receipt graph differs")
            for name in expected:
                child = str(nodes[name][0])
                role = "direct-application-dso" if name in children else "transitive-application-dso"
                entry = {"path": child, "sha256": identities[name]}
                if record["schema"] == 3:
                    entry.update(role=role, name=name)
                if inputs.count(entry) != 1 or command.count(child) != (1 if name in children else 0) or trace.count(child) != (1 if name in children else 0):
                    raise shared.DriverError("application DSO closure receipt does not bind its dependency")
    output = (invocation.output or (sources[0].with_suffix(".o") if invocation.compile_only else Path("a.out"))).absolute()
    shared.validate_application_output(root, output)
    shared.validate_application_output_disjoint(output, (*sources, *objects_in, *dso_inputs, *transitive_inputs))
    dependency_output = None
    if dependency_file is not None:
        dependency_output = dependency_file.absolute()
        shared.validate_application_output(root, dependency_output)
        shared.validate_application_output_disjoint(dependency_output, (*sources, *objects_in, output))
    with tempfile.TemporaryDirectory(prefix="crabc-aarch64-dynamic-") as temporary:
        objects = list(objects_in)
        for index, source in enumerate(sources):
            obj = output if invocation.compile_only else Path(temporary) / f"{index}.o"
            shared.run_checked([shared.compiler(), "-nostdinc", *(v for path in quote_dirs for v in ("-iquote", str(path))),
                                "-isystem", str(root / "usr/include"), *shared.HOSTED_TRANSLATION_FLAGS,
                                *invocation.compiler_flags, *(["-frounding-math"] if rounding else []),
                                *(["-MD", "-MF", str(dependency_output)] if dependency_output is not None else []),
                   "-fPIC" if mode == "shared" else "-fPIE" if mode == "pie" else "-fno-pie", "-c", str(source), "-o", str(obj)])
            objects.append(obj)
        if invocation.compile_only:
            return
        receipt_path = Path(str(output) + ".crabc-link.json")
        shared.validate_application_output(root, receipt_path)
        shared.validate_application_output_disjoint(receipt_path, (*sources, *objects_in, *dso_inputs, *transitive_inputs, output))
        runtime = [lib / name for name in ("crti.o", "libc.so", "crtn.o")]
        command = ["/usr/bin/mold", *(["-shared"] if mode == "shared" else ["-pie"] if mode == "pie" else []), "--hash-style=" + hash_style,
                   "--eh-frame-hdr", "-z", "relro", "-z", binding_mode, "-z", "noexecstack", "-z", "text", *([] if runtime_imports else ["--no-undefined"]),
                   "--allow-shlib-undefined", "--disable-new-dtags" if rpath is not None else "--enable-new-dtags", "-rpath", rpath if rpath is not None else runpath or "/usr/lib",
                   "--exclude-libs=libcrabc-builtins.a"]
        if export_dynamic:
            command.append("--export-dynamic")
        if mode != "shared":
            entry = lib / ("Scrt1.o" if mode == "pie" else "crt1.o")
            runtime.append(entry)
            command += ["-z", "dynamic-undefined-weak", "--dynamic-linker", interpreter, str(entry)]
        else:
            command += ["-soname", output.name]
        attachment = [lib / "crabc-dynamic-attach.o"] if mode == "exec" else []
        runtime.extend(attachment)
        archive = lib / "libcrabc-builtins.a"
        if runtime_imports:
            provided, required = {"_GLOBAL_OFFSET_TABLE_"}, set()
            for path in [*objects, archive, lib / "libc.so", *dso_inputs]:
                symbols = subprocess.check_output(["/usr/bin/readelf", "-sW", str(path)], text=True)
                for line in symbols.splitlines():
                    fields = line.split()
                    if len(fields) < 8 or not fields[0].endswith(":") or fields[4] not in ("GLOBAL", "WEAK"):
                        continue
                    section, name = fields[6:8]
                    if section == "UND" and fields[4] == "GLOBAL" and path in objects:
                        required.add(name)
                    elif section != "UND":
                        provided.add(name)
            if required - provided != runtime_imports:
                raise shared.DriverError(f"runtime imports differ from exact unresolved object symbols: {sorted(required - provided)}")
        command += [str(lib / "crti.o"), *(str(path) for path in attachment), *(str(path) for path in objects), str(archive),
                    *(str(path) for path in dso_inputs), str(lib / "libc.so"), str(lib / "crtn.o"), "-o", str(output)]
        inspection_path, map_path = elf_inspection.sidecar_paths(output)
        for sidecar in (inspection_path, map_path):
            shared.validate_application_output(root, sidecar)
            shared.validate_application_output_disjoint(sidecar, (*sources, *objects_in, *dso_inputs, *transitive_inputs, output, receipt_path))
        descriptor = os.open(receipt_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        inspection_fd = map_fd = -1
        map_reserved = inspection_reserved = False
        try:
            inspection_fd = os.open(inspection_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
            inspection_reserved = True
            map_fd = os.open(map_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
            map_reserved = True
            os.close(map_fd)
            map_fd = -1
            completed = subprocess.run([*command[:-2], "--trace", f"-Map={map_path}", *command[-2:]], text=True,
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
            if ("AArch64" not in header or ("EXEC" if mode == "exec" else "DYN") not in header or "TEXTREL" in dynamic
                    or (binding_mode == "lazy" and re.search(r"\(BIND_NOW\)|\(FLAGS(?:_1)?\).*\bNOW\b", dynamic))
                    or (binding_mode == "now" and not re.search(r"\(BIND_NOW\)|\(FLAGS(?:_1)?\).*\bNOW\b", dynamic))
                    or (mode != "shared" and interpreter not in segments)
                    or (mode == "shared" and "INTERP" in segments)):
                raise shared.DriverError("linked dynamic ELF does not match its native mode")
            if runtime_imports:
                symbols = subprocess.check_output(["/usr/bin/readelf", "--dyn-syms", "-W", str(output)], text=True)
                unresolved = set()
                for line in symbols.splitlines():
                    fields = line.split()
                    if len(fields) >= 8 and fields[0].endswith(":") and fields[4] == "GLOBAL" and fields[6] == "UND":
                        unresolved.add(fields[7])
                if unresolved - provided != runtime_imports:
                    raise shared.DriverError("linked runtime imports differ from declared contract")
            try:
                facts = elf_inspection.inspect(output, architecture="aarch64")
                expected = elf_inspection.Expectation(
                    mode=mode, interpreter=interpreter, needed=(*(path.name for path in dso_inputs), "libc.so"),
                    soname=output.name if mode == "shared" else None,
                    search_kind="rpath" if rpath is not None else "runpath",
                    search_path=rpath if rpath is not None else runpath or "/usr/lib",
                    binding=binding_mode, hash_style=hash_style,
                    runtime_imports=frozenset(runtime_imports), provided_symbols=None,
                )
                elf_inspection.require_expected(facts, expected)
                inspection = elf_inspection.record(output, facts, expected,
                    output_format="crabc-aarch64-owned-dynamic-sysroot-v1", link_map=map_path)
            except (elf_inspection.InspectionError, OSError) as error:
                raise shared.DriverError(f"final ELF inspection rejected {output}: {error}") from error
            record = {"schema": 2, "format": "crabc-aarch64-owned-dynamic-sysroot-v1", "mode": mode,
                      "binding": binding_mode, "runtime_imports": sorted(runtime_imports), "application_runpath": None if rpath is not None else runpath or "/usr/lib",
                      "application_rpath": rpath, "application_search_kind": "rpath" if rpath is not None else "runpath", "application_hash_style": hash_style,
                      "output_path": str(output.resolve()), "output_sha256": shared.sha256_file(output),
                      "manifest_sha256": shared.sha256_file(root / "share/crabc/manifest.json"),
                      "application_dsos": {path.name: shared.sha256_file(path) for path in dso_inputs},
                      "owned_runtime_inputs": sorted(path.relative_to(root).as_posix() for path in [*runtime, archive]),
                      "input_receipts": [{"path": str(path), "sha256": shared.sha256_file(path)} for path in [*direct, archive]],
                      "resolved_linker": {"path": command[0], "sha256": shared.sha256_file(Path(command[0]))},
                      "link_command": command, "link_trace": trace, "campaign_complete": False}
            if transitive_inputs:
                record["schema"] = 3
                record["application_dsos"] = {name: shared.sha256_file(path) for name, (path, _) in nodes.items()}
                record["application_dso_roles"] = {name: "direct" if path in dso_inputs else "transitive" for name, (path, _) in nodes.items()}
                record["application_dso_needed"] = {name: needed for name, (_, needed) in nodes.items()}
                record["input_receipts"] = (
                    [{"role": "linker-input", "path": str(path), "sha256": shared.sha256_file(path)} for path in [*runtime, *objects, archive]]
                    + [{"role": record["application_dso_roles"][name] + "-application-dso", "name": name,
                        "path": str(path), "sha256": shared.sha256_file(path)} for name, (path, _) in nodes.items()])
            with os.fdopen(inspection_fd, "w", encoding="utf-8") as stream:
                inspection_fd = -1
                json.dump(inspection, stream, indent=2, sort_keys=True)
                stream.write("\n")
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                descriptor = -1
                json.dump(record, stream, indent=2, sort_keys=True)
                stream.write("\n")
        except BaseException:
            if descriptor != -1:
                os.close(descriptor)
            if inspection_fd != -1:
                os.close(inspection_fd)
            if map_fd != -1:
                os.close(map_fd)
            receipt_path.unlink(missing_ok=True)
            if inspection_reserved:
                inspection_path.unlink(missing_ok=True)
            if map_reserved:
                map_path.unlink(missing_ok=True)
            output.unlink(missing_ok=True)
            raise



try:
    execute(sys.argv[1:])
except (shared.DriverError, OSError, ValueError, subprocess.SubprocessError) as error:
    sys.exit(f"crabc-cc-dynamic: {error}")
