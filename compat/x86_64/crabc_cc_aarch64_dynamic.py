#!/usr/bin/env python3
"""Compile native AArch64 dynamic applications against the installed crabc sysroot."""
from contextlib import ExitStack
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
import crabc_cc_static as shared
import owned_dynamic_elf as elf_inspection
import crabc_cc_owned_dynamic as dynamic_shared
lib = root / "usr/lib"


def execute(arguments):
    manifest = dynamic_shared.validate_installation(root)
    profile = shared.profile_from_manifest(manifest)
    retain_evidence = dynamic_shared.retain_link_evidence()
    interpreter = "/lib/ld-crabc-aarch64-hardened.so.1" if profile is shared.NativeRuntimeProfile.HARDENED else "/lib/ld-crabc-aarch64.so.1"
    (mode, binding_mode, runpath, rpath, hash_style, hash_explicit, runtime_imports,
     dsos, transitive_dsos, common, quote_inputs, dependency_file, rounding,
     export_dynamic) = dynamic_shared.parse_dynamic_arguments(arguments, architecture="aarch64")
    if mode is None:
        raise shared.DriverError("select --dynamic-pie, --dynamic-non-pie or --dynamic-shared-object")
    if rpath is not None and mode == "shared":
        raise shared.DriverError("--application-rpath requires a dynamic executable link")
    binding_mode = binding_mode or "now"
    if profile is shared.NativeRuntimeProfile.HARDENED and mode == "exec":
        raise shared.DriverError("hardened dynamic product requires PIE")
    if profile is shared.NativeRuntimeProfile.HARDENED and binding_mode != "now":
        raise shared.DriverError("hardened dynamic products require eager binding")
    if runtime_imports and (mode != "shared" or binding_mode != "lazy"):
        raise shared.DriverError("runtime imports require a lazy shared object")
    if mode == "shared" and export_dynamic:
        raise shared.DriverError("-rdynamic requires an executable")
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
    if invocation.print_link_plan and (quote_inputs or rounding):
        raise shared.DriverError("link plan accepts no application translation options")
    quote_dirs = []
    for path in quote_inputs:
        directory = dynamic_shared.application_quote_include_dir(root, path)
        if directory in quote_dirs:
            raise shared.DriverError("duplicate application quote include directory")
        quote_dirs.append(directory)
    if invocation.print_link_plan:
        if dsos or transitive_dsos:
            raise shared.DriverError("link plan accepts no application inputs")
        plan = ["/usr/bin/mold", *(["-shared"] if mode == "shared" else ["-pie"] if mode == "pie" else []), "--hash-style=" + hash_style,
                "--eh-frame-hdr", "-z", "relro", "-z", binding_mode, "-z", "noexecstack", "-z", "text",
                *([] if runtime_imports else ["--no-undefined"]), "--allow-shlib-undefined", "--disable-new-dtags" if rpath is not None else "--enable-new-dtags", "-rpath", rpath if rpath is not None else runpath or "/usr/lib",
                "--exclude-libs=libcrabc-builtins.a"]
        if export_dynamic:
            plan.append("--export-dynamic")
        if mode != "shared":
            plan += ["-z", "dynamic-undefined-weak", "--dynamic-linker", interpreter, str(lib / ("Scrt1.o" if mode == "pie" else "crt1.o"))]
        else:
            plan += ["-soname", "<output-basename>"]
        plan += [str(lib / "crti.o"), *([str(lib / "crabc-dynamic-attach.o")] if mode == "exec" else []), shared.APPLICATION_OBJECTS, str(lib / "libcrabc-builtins.a"),
                 str(lib / "libc.so"), str(lib / "crtn.o"), "-o", shared.OUTPUT]
        print(json.dumps({"format": "crabc-aarch64-owned-dynamic-sysroot-v1", "mode": mode, "binding": binding_mode,
                          "runtime_imports": sorted(runtime_imports), "application_runpath": None if rpath is not None else runpath or "/usr/lib", "application_rpath": rpath,
                          "application_search_kind": "rpath" if rpath is not None else "runpath", "application_hash_style": hash_style, "linker": plan,
                          "campaign_complete": False}, sort_keys=True))
        return
    if invocation.compile_only and (dsos or transitive_dsos or export_dynamic):
        raise shared.DriverError("compile-only accepts no link options")
    if transitive_dsos and not dsos:
        raise shared.DriverError("transitive application DSOs require one direct --application-dso")
    output = (invocation.output or (invocation.sources[0].with_suffix(".o") if invocation.compile_only else Path("a.out"))).absolute()
    shared.validate_application_output(root, output)
    raw_inputs = (*invocation.sources, *invocation.objects, *dsos, *transitive_dsos)
    shared.validate_application_output_disjoint(output, raw_inputs)
    dependency_output = None
    if dependency_file is not None:
        dependency_output = dependency_file.absolute()
        shared.validate_application_output(root, dependency_output)
        shared.validate_application_output_disjoint(dependency_output, (*invocation.sources, *invocation.objects, output))
    receipt_path = Path(str(output) + ".crabc-link.json")
    inspection_path, map_path = elf_inspection.sidecar_paths(output)
    if not invocation.compile_only:
        for sidecar in (receipt_path, inspection_path, map_path):
            shared.validate_application_output(root, sidecar)
            shared.validate_application_output_disjoint(sidecar, (*raw_inputs, output))
    output.parent.mkdir(parents=True, exist_ok=True)
    with ExitStack() as reservations:
        if not invocation.compile_only:
            receipt_stream = reservations.enter_context(dynamic_shared.reserve_receipt(receipt_path))
            inspection_stream = reservations.enter_context(dynamic_shared.reserve_receipt(inspection_path))
            accept_map = reservations.enter_context(dynamic_shared.reserve_link_map(map_path))
        temporary = reservations.enter_context(dynamic_shared.link_evidence_workspace(output.parent, retain=retain_evidence))
        sources = [shared.require_application_file(root, path, "source") for path in invocation.sources]
        objects_in = [shared.require_x86_64_relocatable_object(root, path, architecture="aarch64") for path in invocation.objects]
        dso_inputs = [shared.require_application_file(root, path, "DSO") for path in dsos]
        transitive_inputs = [shared.require_application_file(root, path, "DSO") for path in transitive_dsos]
        nodes = {}
        for path in [*dso_inputs, *transitive_inputs]:
            if shared.rejects_runtime_object(path):
                raise shared.DriverError("unowned application DSO")
            dynamic_shared.application_dso_basename(path, architecture="aarch64")
            if path.name in nodes or path in [node[0] for node in nodes.values()]:
                raise shared.DriverError("duplicate application DSO")
            with tempfile.TemporaryDirectory(prefix="crabc-aarch64-dso-metadata-") as metadata_temp:
                _, needed, runpaths = dynamic_shared.dso_metadata_detail(path, Path(metadata_temp), architecture="aarch64")
            nodes[path.name] = (path, needed)
            if runpaths not in ([], ["/usr/lib"]):
                sidecar = Path(str(path) + ".crabc-link.json")
                shared.require_regular(sidecar, "application search path receipt")
                search = json.loads(sidecar.read_text())
                expected_path = dynamic_shared.dso_receipt_runpath(search, path, architecture="aarch64")
                if (search["manifest_sha256"] != shared.sha256_file(root / "share/crabc/manifest.json")
                        or runpaths != [expected_path]):
                    raise shared.DriverError("application DSO has an undeclared runtime search path")
        provided, requirements = set(), {}
        with tempfile.TemporaryDirectory(prefix="crabc-aarch64-dso-symbols-") as symbols_temp:
            for path in [lib / "libc.so", *(node[0] for node in nodes.values())]:
                defined, required = dynamic_shared.dynamic_symbols(path, Path(symbols_temp))
                provided.update(defined)
                requirements[path.name] = required
        for path, needed in nodes.values():
            if not set(needed) <= set(nodes) | {"libc.so"}:
                raise shared.DriverError(f"undeclared transitive dependency of {path}")
            if not transitive_inputs and requirements[path.name] - provided:
                raise shared.DriverError("application DSOs have unresolved runtime imports")
        if transitive_inputs:
            graph = {}
            for name, (path, needed) in nodes.items():
                dynamic = dynamic_shared.run(["/usr/bin/readelf", "-dW", str(path)], temporary)
                runpaths = re.findall(r"\(RUNPATH\).*\[([^\]]*)\]", dynamic)
                record, search, imports = dynamic_shared.application_dso_sidecar(root, path, runpaths, architecture="aarch64")
                graph[name] = dynamic_shared.ApplicationDso(path, name, tuple(needed),
                    "direct" if path in dso_inputs else "transitive", record, search, imports)
            dynamic_shared.validate_closure_graph(graph, [path.name for path in dso_inputs])
            for node in graph.values():
                dynamic_shared.validate_closure_sidecar(node, graph)
            with tempfile.TemporaryDirectory(prefix="crabc-aarch64-dso-closure-") as closure_temp:
                provided = dynamic_shared.validate_closure_runtime_imports(graph, Path(closure_temp), lib)
        objects = list(objects_in)
        for index, source in enumerate(sources):
            obj = output if invocation.compile_only else Path(temporary) / f"{index}.o"
            dynamic_shared.run([shared.compiler(), "-nostdinc", *(v for path in quote_dirs for v in ("-iquote", str(path))),
                                "-isystem", str(root / "usr/include"), *shared.HOSTED_TRANSLATION_FLAGS,
                                *invocation.compiler_flags, *(["-frounding-math"] if rounding else []),
                                *(["-MD", "-MF", str(dependency_output)] if dependency_output is not None else []),
                   "-fPIC" if mode == "shared" else "-fPIE" if mode == "pie" else "-fno-pie", "-c", str(source), "-o", str(obj)], temporary)
            objects.append(obj)
        if invocation.compile_only:
            return
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
            object_provided, required = {*provided, "_GLOBAL_OFFSET_TABLE_"}, set()
            for path in [*objects, archive]:
                definitions, imports = dynamic_shared.dynamic_symbols(path, temporary, object_symbols=True)
                object_provided.update(definitions)
                if path in objects:
                    required.update(imports)
            if required - object_provided != runtime_imports:
                raise shared.DriverError(f"runtime imports differ from exact unresolved object symbols: {sorted(required - object_provided)}")
        command += [str(lib / "crti.o"), *(str(path) for path in attachment), *(str(path) for path in objects), str(archive),
                    *(str(path) for path in dso_inputs), str(lib / "libc.so"), str(lib / "crtn.o"), "-o", str(output)]
        try:
            trace = dynamic_shared.run([*command[:-2], "--trace", f"-Map={map_path}", *command[-2:]], temporary).splitlines()
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
            header = dynamic_shared.run(["/usr/bin/readelf", "-hW", str(output)], temporary)
            segments = dynamic_shared.run(["/usr/bin/readelf", "-lW", str(output)], temporary)
            dynamic = dynamic_shared.run(["/usr/bin/readelf", "-dW", str(output)], temporary)
            if ("AArch64" not in header or ("EXEC" if mode == "exec" else "DYN") not in header or "TEXTREL" in dynamic
                    or (binding_mode == "lazy" and re.search(r"\(BIND_NOW\)|\(FLAGS(?:_1)?\).*\bNOW\b", dynamic))
                    or (binding_mode == "now" and not re.search(r"\(BIND_NOW\)|\(FLAGS(?:_1)?\).*\bNOW\b", dynamic))
                    or (mode != "shared" and interpreter not in segments)
                    or (mode == "shared" and "INTERP" in segments)):
                raise shared.DriverError("linked dynamic ELF does not match its native mode")
            if runtime_imports:
                _, unresolved = dynamic_shared.dynamic_symbols(output, temporary)
                if unresolved - provided != runtime_imports:
                    raise shared.DriverError("linked runtime imports differ from declared contract")
            expected = elf_inspection.Expectation(
                mode=mode, interpreter=interpreter, needed=(*(path.name for path in dso_inputs), "libc.so"),
                soname=output.name if mode == "shared" else None,
                search_kind="rpath" if rpath is not None else "runpath",
                search_path=rpath if rpath is not None else runpath or "/usr/lib",
                binding=binding_mode, hash_style=hash_style,
                runtime_imports=frozenset(runtime_imports), provided_symbols=frozenset(provided),
            )
            inspection = dynamic_shared.final_elf_inspection(output, expected, map_path, architecture="aarch64")
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
            accept_map()
            inspection_stream(json.dumps(inspection, indent=2, sort_keys=True) + "\n")
            receipt_stream(json.dumps(record, indent=2, sort_keys=True) + "\n")
        except BaseException:
            output.unlink(missing_ok=True)
            raise



if __name__ == "__main__":
    try:
        execute(sys.argv[1:])
    except (shared.DriverError, OSError, ValueError, subprocess.SubprocessError) as error:
        sys.exit(f"crabc-cc-dynamic: {error}")
