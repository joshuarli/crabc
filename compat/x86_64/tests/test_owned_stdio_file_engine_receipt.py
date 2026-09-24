"""Semantic regressions for the installed FILE-engine receipt reader."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import struct
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
MODULE = ROOT / "compat/x86_64/owned_stdio_file_engine_receipt.py"
spec = importlib.util.spec_from_file_location("owned_stdio_file_engine_receipt", MODULE)
assert spec is not None and spec.loader is not None
receipt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(receipt)


def identity(root: Path, path: Path) -> dict[str, object]:
    body = path.read_bytes()
    return {"path": str(path.relative_to(root)), "sha256": hashlib.sha256(body).hexdigest(),
            "size": len(body), "mode": stat.S_IMODE(path.stat().st_mode)}


def source_identity(root: Path, path: Path) -> dict[str, object]:
    value = identity(root, path)
    return {key: value[key] for key in ("path", "sha256", "mode")}


# A small stand-in for the frozen ledger: two credited symbols per capability,
# an uncredited macro capability, and an unrelated one the reader must ignore.
FIXTURE_SURFACE = {
    "stdio.path-stream": ("fopen", "popen"),
    "stdio.stream-io": ("fgetc", "getline"),
    "stdio.position-buffering": ("fseeko", "stdout"),
    "stdio.format-scan": ("__isoc99_sscanf", "vfscanf"),
}
FIXTURE_LEDGER_EXTRA = {"stdio.fopen64-alias": ("fopen64",), "stdio.memory-stream": ("fmemopen",)}


def elf_object(undefined: tuple[str, ...], defined: tuple[str, ...] = (), machine: int = 62) -> bytes:
    """Minimal ELF64 ET_REL: null, .strtab and .symtab sections only."""
    names = [*undefined, *defined]
    strings = b"\0" + b"".join(name.encode() + b"\0" for name in names)
    offsets, cursor = [], 1
    for name in names:
        offsets.append(cursor)
        cursor += len(name) + 1
    symbols = bytes(24) + b"".join(
        struct.pack("<IBBHQQ", offset, (1 << 4) | 2, 0, 1 if index >= len(undefined) else 0, 0, 0)
        for index, offset in enumerate(offsets))
    strtab_offset = 64
    symtab_offset = (strtab_offset + len(strings) + 7) & ~7
    shoff = (symtab_offset + len(symbols) + 7) & ~7
    header = struct.pack("<16sHHIQQQIHHHHHH", b"\x7fELF\x02\x01\x01" + bytes(9), 1, machine, 1, 0, 0,
                         shoff, 0, 64, 0, 0, 64, 3, 0)
    sections = (bytes(64)
                + struct.pack("<IIQQQQIIQQ", 0, 3, 0, 0, strtab_offset, len(strings), 0, 0, 1, 0)
                + struct.pack("<IIQQQQIIQQ", 0, 2, 0, 0, symtab_offset, len(symbols), 1, 1, 8, 24))
    body = bytearray(shoff)
    body[:64] = header
    body[strtab_offset:strtab_offset + len(strings)] = strings
    body[symtab_offset:symtab_offset + len(symbols)] = symbols
    return bytes(body) + sections


def fixture_workload_symbols(role: str, omit: frozenset[str]) -> tuple[str, ...]:
    """Spread the fixture surface across roles; the surface row adds the rest."""
    if role == "stdio.frozen-surface":
        chosen = ("getline", "__isoc99_sscanf", "fseeko", "fmemopen")
    else:
        chosen = {"stdio.file-backends": ("fopen", "fgetc", "stdout"), "stdio.process-streams": ("popen",),
                  "stdio.scanf": ("vfscanf",)}.get(role, ("fclose",))
    return tuple(symbol for symbol in chosen if symbol not in omit)


class ReceiptFixture:
    """A complete physical report; only product internals are mocked."""

    def __init__(self, root: Path, omit: frozenset[str] = frozenset()) -> None:
        self.root = root
        self.checkout = root / "checkout"
        self.work = self.checkout / ".work/file-engine"
        self.static = root / "static-product"
        self.dynamic = root / "dynamic-product"
        self.checkout.mkdir(parents=True)
        self.work.mkdir(parents=True)
        for product in (self.static, self.dynamic):
            (product / "share/crabc").mkdir(parents=True)
            (product / "share/crabc/manifest.json").write_text("{}\n")
        (self.static / "bin").mkdir()
        self.static_driver = self.static / "bin/crabc-cc"
        self.static_driver.write_bytes(b"static driver\n")
        self.static_driver.chmod(0o755)
        (self.dynamic / "bin").mkdir()
        self.dynamic_driver = self.dynamic / "bin/crabc-cc-dynamic"
        self.dynamic_driver.write_bytes(b"dynamic driver\n")
        self.dynamic_driver.chmod(0o755)
        (self.dynamic / "usr/include/bits").mkdir(parents=True)
        self.tool = self.work / "pinned-tool"
        self.tool.write_bytes(b"pinned tool\n")
        self.tool.chmod(0o755)
        self.control_busybox = self.root / "control-busybox"
        self.control_loader = self.root / "control-loader"
        self.control_mount = self.root / "control-mount"
        self.control_umount = self.root / "control-umount"
        for path, body in ((self.control_busybox, b"pinned busybox\n"), (self.control_loader, b"pinned loader\n"),
                           (self.control_mount, b"pinned mount\n"), (self.control_umount, b"pinned umount\n")):
            path.write_bytes(body)
            path.chmod(0o755)
        helper = self.dynamic / "share/crabc/crabc_cc_static.py"
        helper.write_text("def compiler():\n    return " + repr(str(self.tool)) + "\n\ndef linker(root):\n    return " + repr(str(self.tool)) + "\n")
        self.sources: dict[str, Path] = {}
        for role, metadata in receipt.ROLES.items():
            source = self.checkout / str(metadata["source"])
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text("/* " + role + " */\n")
            self.sources[role] = source
            for header in metadata["headers"]:
                header_path = self.dynamic / "usr/include" / header
                header_path.parent.mkdir(parents=True, exist_ok=True)
                header_path.touch()
        self.runner = self.checkout / "compat/x86_64/run_owned_stdio_file_engine.sh"
        self.runner.write_text("#!/usr/bin/env bash\n")
        self.runner.chmod(0o755)
        self.reader = self.checkout / "compat/x86_64/owned_stdio_file_engine_receipt.py"
        self.reader.write_text("# sealed reader\n")
        ledger = self.checkout / receipt.FROZEN_LEDGER
        ledger.parent.mkdir(parents=True, exist_ok=True)
        ledger.write_text("".join(
            f'[[capability]]\nid = "{capability}"\nsymbols = {json.dumps(list(symbols))}\n\n'
            for capability, symbols in {**FIXTURE_SURFACE, **FIXTURE_LEDGER_EXTRA}.items()))
        self.workloads: dict[str, Path] = {}
        for role in receipt.SCOPE:
            workload = self.work / f"{role}.o"
            workload.write_bytes(elf_object(fixture_workload_symbols(role, omit)))
            self.workloads[role] = workload
        self.control_sources: dict[str, Path] = {}
        self.control_objects: dict[str, Path] = {}
        self.control_launchers: dict[str, dict[str, Path]] = {}
        for applet in receipt.CONTROL_APPLETS:
            source = self.work / f"control-{applet}.c"
            source.write_bytes(receipt.control_launcher_source(applet))
            object_path = self.work / f"control-{applet}.o"
            object_path.write_bytes(("control " + applet + " object\n").encode())
            self.control_sources[applet], self.control_objects[applet] = source, object_path
            self.control_launchers[applet] = {}
            for linkage in ("oracle", "static", "static-pie", "pie", "non-pie"):
                binary = self.work / f"control-{applet}-{linkage}"
                binary.write_bytes(("control " + applet + " " + linkage + " launcher\n").encode())
                self.control_launchers[applet][linkage] = binary
        self._write_seals()
        self._write_commands()
        self._write_report()

    def write(self, name: str, body: bytes) -> Path:
        path = self.work / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
        return path

    def command(self, stem: str, argv: list[str], stdout: bytes = b"", stderr: bytes = b"", status: bytes = b"0\n") -> None:
        self.write(stem + ".argv.json", json.dumps(argv, separators=(",", ":")).encode() + b"\n")
        self.write(stem + ".stdout", stdout)
        self.write(stem + ".stderr", stderr)
        self.write(stem + ".status", status)

    def _product_seal(self, product: Path) -> dict[str, object]:
        manifest = product / "share/crabc/manifest.json"
        return {"path": str(product), "manifest": {"path": str(manifest), "sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(), "size": manifest.stat().st_size},
                "tree": receipt.tree_identity(product)}

    def _write_seals(self) -> None:
        sources = {role: source_identity(self.checkout, source) for role, source in self.sources.items()}
        sources["runner"] = source_identity(self.checkout, self.runner)
        sources["reader"] = source_identity(self.checkout, self.reader)
        seal = {"sources": sources, "static": self._product_seal(self.static), "dynamic": self._product_seal(self.dynamic)}
        for name in ("source-product-before.json", "source-product-after.json"):
            self.write(name, json.dumps(seal, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        def tool_identity(path: Path) -> dict[str, object]:
            body = path.read_bytes()
            return {"path": str(path), "sha256": hashlib.sha256(body).hexdigest(), "size": len(body), "mode": stat.S_IMODE(path.stat().st_mode)}
        tools = {"oracle": tool_identity(self.tool), "static_driver": tool_identity(self.static_driver),
                 "dynamic_driver": tool_identity(self.dynamic_driver), "compiler": tool_identity(self.tool),
                 "linker": tool_identity(self.tool), "control_busybox": tool_identity(self.control_busybox),
                 "control_loader": tool_identity(self.control_loader), "control_mount": tool_identity(self.control_mount),
                 "control_umount": tool_identity(self.control_umount)}
        for name in ("tools-before.json", "tools-after.json"):
            self.write(name, json.dumps(tools, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        sealed = [*(self.sources[role] for role in receipt.SCOPE), self.runner,
                  *(self.control_sources[applet] for applet in receipt.CONTROL_APPLETS),
                  *(self.workloads[role] for role in receipt.SCOPE),
                  *(self.control_objects[applet] for applet in receipt.CONTROL_APPLETS)]
        self.write("source-object-before.sha256", b"".join(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path}\n".encode() for path in sealed))
        self.write("source-object-after.txt", b"".join(f"{path}: OK\n".encode() for path in sealed))

    def _link(self, role: str, linkage: str, product: Path, executable: Path) -> dict[str, object]:
        return {"linkage": linkage, "product": str(product), "workload_sha256": hashlib.sha256(self.workloads[role].read_bytes()).hexdigest(),
                "executable_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(), "role": role}

    def _control_link(self, applet: str, linkage: str, product: Path, executable: Path) -> dict[str, object]:
        return {"linkage": linkage, "product": str(product),
                "workload_sha256": hashlib.sha256(self.control_objects[applet].read_bytes()).hexdigest(),
                "executable_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(), "applet": applet}

    def _write_control_commands(self) -> None:
        self.control_links: dict[str, dict[str, Path]] = {applet: {} for applet in receipt.CONTROL_APPLETS}
        for applet in receipt.CONTROL_APPLETS:
            source, object_path = self.control_sources[applet], self.control_objects[applet]
            trace = b"".join(f". {self.dynamic / 'usr/include' / header}\n".encode() for header in receipt.CONTROL_HEADERS)
            self.command(f"control-{applet}-header", receipt._expected_control_header_argv(str(self.tool), self.dynamic, source),
                         stdout=f'# 0 "{source}"\n'.encode(), stderr=trace)
            self.command(f"control-{applet}-compile", receipt._expected_control_compile_argv(str(self.dynamic_driver), source, object_path))
            oracle = self.control_launchers[applet]["oracle"]
            self.command(f"control-{applet}-oracle-link", [str(self.tool), "-static", "-fno-pie", "-no-pie", str(object_path), "-o", str(oracle)])
            for linkage in ("static", "static-pie", "pie", "non-pie"):
                product = self.static if linkage.startswith("static") else self.dynamic
                binary = self.control_launchers[applet][linkage]
                receipt_path = self.work / f"control-{applet}-{linkage}.crabc-link.json"
                receipt_path.write_text("{}\n")
                product_link = self.write(f"control-{applet}-{linkage}.product-link.json", json.dumps(
                    self._control_link(applet, linkage, product, binary), sort_keys=True, separators=(",", ":")).encode() + b"\n")
                self.control_links[applet][linkage] = product_link
                driver = self.static_driver if linkage.startswith("static") else self.dynamic_driver
                argv = ([str(driver), "-" + linkage, "--link-receipt", receipt_path.name, str(object_path), "-o", str(binary)]
                        if linkage.startswith("static") else
                        [str(driver), "--dynamic-" + linkage, *receipt.CONTROL_COMPILE_FLAGS, str(object_path), "-o", str(binary)])
                self.command(f"control-{applet}-{linkage}-link", argv)
        self.control_staged: dict[str, dict[str, Path]] = {}
        for linkage in ("oracle", "static", "static-pie", "pie", "non-pie"):
            root = receipt._control_root(self.work, linkage)
            (root / "control").mkdir(parents=True)
            (root / "bin").mkdir()
            (root / "scratch").mkdir()
            staged = {"busybox": root / "control/busybox", "loader": root / "control/ld-musl-x86_64.so.1"}
            for key, source in (("busybox", self.control_busybox), ("loader", self.control_loader)):
                staged[key].write_bytes(source.read_bytes())
                staged[key].chmod(stat.S_IMODE(source.stat().st_mode))
            for applet in receipt.CONTROL_APPLETS:
                staged[applet] = root / "bin" / applet
                linked = self.control_launchers[applet][linkage]
                staged[applet].write_bytes(linked.read_bytes())
                staged[applet].chmod(stat.S_IMODE(linked.stat().st_mode))
            self.control_staged[linkage] = staged

    def _write_commands(self) -> None:
        self.links: dict[str, Path] = {}
        self.payload_records: dict[tuple[str, str], Path] = {}
        self.side_effects: dict[str, Path] = {}
        self._write_control_commands()
        for role in receipt.SCOPE:
            meta = receipt.ROLES[role]
            source, workload = self.sources[role], self.workloads[role]
            flags = tuple(meta["flags"])
            trace = b"".join(f". {self.dynamic / 'usr/include' / header}\n".encode() for header in meta["headers"])
            self.command(role + "-header", receipt._expected_header_argv(str(self.tool), self.dynamic, source, flags),
                         stdout=f'# 0 "{source}"\n'.encode(), stderr=trace)
            self.command(role + "-compile", receipt._expected_compile_argv(str(self.dynamic_driver), source, workload, flags))
            oracle = self.work / f"oracle-{role}"
            oracle.write_bytes((role + " oracle executable\n").encode())
            self.command(role + "-oracle-link", [str(self.tool), "-std=c11", "-static", "-fno-pie", "-no-pie", str(workload), "-o", str(oracle)])
            oracle_raw = (role + " pinned-musl transcript\n").encode()
            if role == "stdio.process-streams":
                root = receipt._process_root(self.work, "oracle")
                root.mkdir(parents=True)
                (root / "scratch").mkdir()
                (root / "proc").mkdir()
                (root / "consumer").write_bytes(oracle.read_bytes())
                oracle_scratch = root / "scratch/stream"
                self.command(role + "-oracle-run", ["chroot", str(root), "/consumer", "/scratch/stream"], oracle_raw)
            else:
                oracle_scratch = self.work / f"oracle-{role}-stream"
                self.command(role + "-oracle-run", receipt._expected_run(oracle, oracle_scratch), oracle_raw)
            if meta["side_effect"] is not None:
                oracle_scratch.write_bytes(meta["side_effect"])
                self.command(role + "-oracle-run", receipt._expected_run(oracle, oracle_scratch), oracle_raw)
            for linkage in ("static", "static-pie"):
                executable = self.work / f"{role}-{linkage}"
                executable.write_bytes((role + linkage).encode())
                receipt_path = self.work / f"{role}-{linkage}.crabc-link.json"
                receipt_path.write_text("{}\n")
                product_link = self.write(f"{role}-{linkage}.product-link.json", json.dumps(
                    self._link(role, linkage, self.static, executable), sort_keys=True, separators=(",", ":")).encode() + b"\n")
                self.links[f"{role}-{linkage}"] = product_link
                self.command(role + f"-{linkage}-link", [str(self.static_driver), "-" + linkage, "--link-receipt", receipt_path.name,
                                                          str(workload), "-o", str(executable)])
                if role == "stdio.process-streams":
                    root = receipt._process_root(self.work, linkage)
                    root.mkdir(parents=True)
                    (root / "scratch").mkdir()
                    (root / "proc").mkdir()
                    (root / "consumer").write_bytes(executable.read_bytes())
                    scratch = root / "scratch/stream"
                    self.command(role + f"-{linkage}-run", ["chroot", str(root), "/consumer", "/scratch/stream"], oracle_raw)
                    self.command(role + f"-{linkage}-cleanup", ["test", "!", "-e", str(scratch)])
                else:
                    scratch = self.work / f"{role}-{linkage}-stream"
                    if meta["side_effect"] is None:
                        self.command(role + f"-{linkage}-run", receipt._expected_run(executable, scratch), oracle_raw)
                        self.command(role + f"-{linkage}-cleanup", ["test", "!", "-e", str(scratch)])
                    else:
                        scratch.write_bytes(meta["side_effect"])
                        effect = self.write(f"stdio.file-backends-{linkage}-exit", meta["side_effect"])
                        self.side_effects[f"{role}:{linkage}"] = effect
                        self.command(role + f"-{linkage}-run", receipt._expected_run(executable, scratch), oracle_raw)
            for linkage in ("pie", "non-pie"):
                executable = self.work / f"dynamic-{role}-{linkage}"
                executable.write_bytes((role + linkage).encode())
                receipt_path = executable.with_name(executable.name + ".crabc-link.json")
                receipt_path.write_text("{}\n")
                product_link = self.write(f"{role}-{linkage}.product-link.json", json.dumps(
                    self._link(role, linkage, self.dynamic, executable), sort_keys=True, separators=(",", ":")).encode() + b"\n")
                self.links[f"{role}-{linkage}"] = product_link
                self.command(role + f"-{linkage}-link", [str(self.dynamic_driver), "--dynamic-" + linkage,
                                                          *receipt.COMMON_FLAGS, str(workload), "-o", str(executable)])
                root = self.work / f"dynamic-{role}-{linkage}-root"
                (root / "scratch").mkdir(parents=True, exist_ok=True)
                consumer = root / "consumer"
                consumer.write_bytes(executable.read_bytes())
                payload = {"role": role, "linkage": linkage}
                record = self.write(f"{role}-{linkage}-execution-payload.json", json.dumps(payload, sort_keys=True, separators=(",", ":")).encode() + b"\n")
                self.payload_records[(role, linkage)] = record
                common = ["--product", str(self.dynamic), "--execution-root", str(root), "--source-consumer", str(executable),
                          "--execution-consumer", str(consumer), "--record", str(record)]
                self.command(role + f"-{linkage}-copy-before", ["python3", "-B", str(receipt.COPIES_PATH), "record", *common])
                audit = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode() + b"\n"
                self.command(role + f"-{linkage}-copy-audit-before", ["python3", "-B", str(receipt.COPIES_PATH), "audit", *common], audit)
                if role == "stdio.process-streams":
                    (root / "proc").mkdir()
                scratch = root / "scratch/stream"
                if meta["side_effect"] is not None:
                    scratch.write_bytes(meta["side_effect"])
                    kernel_effect = self.write(f"stdio.file-backends-dynamic-{linkage}-kernel-exit", meta["side_effect"])
                    direct_effect = self.write(f"stdio.file-backends-dynamic-{linkage}-direct-exit", meta["side_effect"])
                    self.side_effects[f"{role}:dynamic-{linkage}-kernel"] = kernel_effect
                    self.side_effects[f"{role}:dynamic-{linkage}-direct"] = direct_effect
                self.command(role + f"-{linkage}-kernel", ["chroot", str(root), "/consumer", "/scratch/stream"], oracle_raw)
                self.command(role + f"-{linkage}-direct", ["chroot", str(root), receipt.INTERPRETER, "/consumer", "/scratch/stream"], oracle_raw)
                self.command(role + f"-{linkage}-copy-audit-after", ["python3", "-B", str(receipt.COPIES_PATH), "audit", *common], audit)
                if meta["side_effect"] is None:
                    self.command(role + f"-{linkage}-cleanup", ["test", "!", "-e", str(scratch)])

    def _write_process_proc(self) -> None:
        self.process_proc: dict[str, dict[str, Path]] = {}
        for linkage in ("oracle", "static", "static-pie", "pie", "non-pie", "wide-format-pie", "wide-format-non-pie"):
            root = receipt._process_root(self.work, linkage)
            (root / "proc").mkdir(exist_ok=True)
            target = root / "proc"
            def snapshot(raw: bytes) -> dict[str, object]:
                return {"byte_length": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                        "text": raw.decode("utf-8", errors="replace")}
            outside = "pid:[123]"
            private = {
                "schema": "crabc.x86_64-owned-os-test-private-proc/v1", "mountpoint": str(target),
                "reservation": {"empty": True, "mode": 0o755},
                "mount": {"command": [str(receipt.CONTROL_PROC_MOUNT_COMMAND), "-t", "proc", "-o", "ro,nosuid,nodev,noexec", "proc", str(target)],
                          "status": 0, "stdout": snapshot(b""), "stderr": snapshot(b""), "target": str(target)},
                "namespace": {"outside": outside, "inside": {"command": ["/usr/sbin/chroot", str(root), "/control/ld-musl-x86_64.so.1", "/control/busybox", "readlink", "/proc/self/ns/pid"],
                              "status": 0, "stdout": snapshot((outside + "\n").encode()), "stderr": snapshot(b"")}, "matched": True},
                "unmount": {"command": [str(receipt.CONTROL_PROC_UMOUNT_COMMAND), str(target)], "status": 0,
                            "stdout": snapshot(b""), "stderr": snapshot(b"")},
            }
            receipt_path = self.write(f"process-{linkage}-private-proc.json", json.dumps(private, sort_keys=True, separators=(",", ":")).encode() + b"\n")
            mountinfo = self.write(f"process-{linkage}-proc-mountinfo.txt", f"1 2 0:1 / {target} ro,nosuid,nodev,noexec - proc proc ro,nosuid,nodev,noexec\n".encode())
            self.process_proc[linkage] = {"receipt": receipt_path, "mountinfo": mountinfo}

    def _write_report(self) -> None:
        self._write_process_proc()
        commands = {}
        for argv in sorted(self.work.glob("*.argv.json")):
            stem = argv.name.removesuffix(".argv.json")
            commands[stem] = {part: identity(self.work, self.work / (stem + suffix)) for part, suffix in
                              (("argv", ".argv.json"), ("stdout", ".stdout"), ("stderr", ".stderr"), ("status", ".status"))}
        payloads = {role: {linkage: {"record": identity(self.work, self.payload_records[(role, linkage)]),
                                      "before": identity(self.work, self.work / f"{role}-{linkage}-copy-audit-before.stdout"),
                                      "after": identity(self.work, self.work / f"{role}-{linkage}-copy-audit-after.stdout")}
                            for linkage in ("pie", "non-pie")} for role in receipt.SCOPE}
        effects = {cell: identity(self.work, self.side_effects[f"stdio.file-backends:{cell}"])
                   for cell in receipt.EXECUTION_CELLS}
        sources = {**self.sources, "runner": self.runner, "reader": self.reader}
        self.report = {
            "schema": receipt.SCHEMA, "scope": list(receipt.SCOPE),
            "rows": {role: receipt.row_value(role) for role in receipt.SCOPE},
            "source": receipt.source_map(self.checkout, sources),
            "workloads": {role: identity(self.work, self.workloads[role]) for role in receipt.SCOPE},
            "products": {"static": str(self.static), "dynamic": str(self.dynamic)},
            "seals": {name: identity(self.work, self.work / (name + ".json")) for name in
                      ("source-product-before", "source-product-after", "tools-before", "tools-after")},
            "object_seals": {"before": identity(self.work, self.work / "source-object-before.sha256"),
                             "after": identity(self.work, self.work / "source-object-after.txt")},
            "commands": commands,
            "links": {name: identity(self.work, path) for name, path in self.links.items()},
            "execution_payloads": payloads, "side_effects": {"stdio.file-backends": effects},
            "control": {
                "sources": {applet: identity(self.work, self.control_sources[applet]) for applet in receipt.CONTROL_APPLETS},
                "objects": {applet: identity(self.work, self.control_objects[applet]) for applet in receipt.CONTROL_APPLETS},
                "launchers": {applet: {linkage: identity(self.work, path) for linkage, path in self.control_launchers[applet].items()}
                              for applet in receipt.CONTROL_APPLETS},
                "links": {applet: {linkage: identity(self.work, path) for linkage, path in self.control_links[applet].items()}
                          for applet in receipt.CONTROL_APPLETS},
                "staged": {linkage: {name: identity(self.work, path) for name, path in stage.items()}
                           for linkage, stage in self.control_staged.items()},
            },
            "process_proc": {linkage: {name: identity(self.work, path) for name, path in item.items()}
                             for linkage, item in self.process_proc.items()},
            "family_completion": False, "promotion_ready": False, "public_support": False,
        }
        self.path = self.work / "owned-stdio-file-engine.json"
        self.write_report()

    def write_report(self) -> None:
        self.path.write_text(json.dumps(self.report, sort_keys=True, separators=(",", ":")) + "\n")

    def refresh(self, *groups: str) -> None:
        for group in groups:
            if group == "commands":
                for argv in sorted(self.work.glob("*.argv.json")):
                    stem = argv.name.removesuffix(".argv.json")
                    self.report["commands"][stem] = {part: identity(self.work, self.work / (stem + suffix)) for part, suffix in
                        (("argv", ".argv.json"), ("stdout", ".stdout"), ("stderr", ".stderr"), ("status", ".status"))}
            elif group == "tools":
                for name in ("tools-before", "tools-after"):
                    self.report["seals"][name] = identity(self.work, self.work / (name + ".json"))
            elif group == "links":
                for name, path in self.links.items():
                    self.report["links"][name] = identity(self.work, path)
            elif group == "payloads":
                for role in receipt.SCOPE:
                    for linkage in ("pie", "non-pie"):
                        record = self.payload_records[(role, linkage)]
                        self.report["execution_payloads"][role][linkage] = {
                            "record": identity(self.work, record),
                            "before": identity(self.work, self.work / f"{role}-{linkage}-copy-audit-before.stdout"),
                            "after": identity(self.work, self.work / f"{role}-{linkage}-copy-audit-after.stdout"),
                        }
            elif group == "effects":
                self.report["side_effects"]["stdio.file-backends"] = {
                    cell: identity(self.work, self.side_effects[f"stdio.file-backends:{cell}"])
                    for cell in receipt.EXECUTION_CELLS}
            elif group == "proc":
                self.report["process_proc"] = {
                    linkage: {name: identity(self.work, path) for name, path in item.items()}
                    for linkage, item in self.process_proc.items()}
            else:
                raise AssertionError(group)
        self.write_report()


class OwnedStdioFileEngineReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        (ROOT / ".work").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=ROOT / ".work")
        self.addCleanup(self.temporary.cleanup)
        self.patches: list[mock._patch] = []
        self.addCleanup(lambda: [patch.stop() for patch in reversed(self.patches)])
        self.use_fixture(ReceiptFixture(Path(self.temporary.name)))

    def use_fixture(self, fixture: ReceiptFixture) -> None:
        for patch in reversed(self.patches):
            patch.stop()
        self.fixture = fixture
        self.patches = [
            mock.patch.object(receipt, "ORACLE_COMPILER", str(self.fixture.tool)),
            mock.patch.object(receipt, "CONTROL_BUSYBOX", self.fixture.control_busybox),
            mock.patch.object(receipt, "CONTROL_LOADER", self.fixture.control_loader),
            mock.patch.object(receipt, "CONTROL_PROC_MOUNT", self.fixture.control_mount),
            mock.patch.object(receipt, "CONTROL_PROC_UMOUNT", self.fixture.control_umount),
            mock.patch.object(receipt.products, "_validate_static_product", return_value=(self.fixture.static / "share/crabc/manifest.json", {})),
            mock.patch.object(receipt.products, "_validate_dynamic_product", return_value=(self.fixture.dynamic / "share/crabc/manifest.json", {})),
            mock.patch.object(receipt.products, "validate_link", side_effect=self._link),
            mock.patch.object(receipt.copies, "audit_execution_payload", side_effect=self._payload),
        ]
        for patch in self.patches:
            patch.start()

    def _link(self, product: Path, workload: Path, executable: Path, _receipt: Path, linkage: str) -> dict[str, object]:
        expected_product = self.fixture.static if linkage.startswith("static") else self.fixture.dynamic
        self.assertEqual(product, expected_product)
        for role, item in self.fixture.workloads.items():
            if item == workload:
                return self.fixture._link(role, linkage, product, executable)
        applet = next(applet for applet, item in self.fixture.control_objects.items() if item == workload)
        return self.fixture._control_link(applet, linkage, product, executable)

    def _payload(self, _product: Path, root: Path, source: Path, _consumer: Path, _record: Path) -> dict[str, object]:
        role = next(role for role in receipt.SCOPE if f"dynamic-{role}-" in root.name)
        linkage = "non-pie" if root.name.endswith("non-pie-root") else "pie"
        self.assertEqual(source, self.fixture.work / f"dynamic-{role}-{linkage}")
        return {"role": role, "linkage": linkage}

    def validate(self) -> dict[str, object]:
        return receipt.validate_report(self.fixture.path, self.fixture.checkout, require_static=True)

    def test_scope_and_six_cell_contract_are_closed(self) -> None:
        self.assertEqual(receipt.SCOPE, (
            "stdio.file-backends", "stdio.process-streams", "stdio.wide-stream",
            "stdio.wide-format", "stdio.file-extensions", "stdio.printf-float", "stdio.scanf",
            "stdio.frozen-surface", "stdio.engine-model",
        ))
        self.assertEqual(receipt.FROZEN_CAPABILITIES, (
            "stdio.path-stream", "stdio.stream-io", "stdio.position-buffering", "stdio.format-scan",
        ))
        self.assertEqual(receipt.EXECUTION_CELLS, (
            "static", "static-pie", "dynamic-pie-kernel", "dynamic-pie-direct",
            "dynamic-non-pie-kernel", "dynamic-non-pie-direct",
        ))

    def test_complete_six_cell_report_reconstructs(self) -> None:
        report = self.validate()
        self.assertEqual(report["schema"], receipt.SCHEMA)
        self.assertEqual(report["cells"], 6)
        self.assertEqual(report["execution_cells"], list(receipt.EXECUTION_CELLS))
        self.assertEqual(report["products"], self.fixture.report["products"])
        self.assertEqual(report["source"], self.fixture.report["source"])
        self.assertEqual(report["frozen_surface"], {key: len(value) for key, value in FIXTURE_SURFACE.items()})

    def test_objects_must_reference_every_frozen_capability_symbol(self) -> None:
        self.use_fixture(ReceiptFixture(Path(self.temporary.name) / "missing", frozenset({"getline"})))
        with self.assertRaisesRegex(receipt.ReceiptError, "stdio.stream-io frozen symbols are not exercised: getline"):
            self.validate()

    def test_only_undefined_global_references_count_toward_the_surface(self) -> None:
        path = self.fixture.work / "probe.o"
        path.write_bytes(elf_object(("getc", "stdout"), defined=("fgetc",)))
        self.assertEqual(receipt.undefined_symbols(path), {"getc", "stdout"})
        path.write_bytes(elf_object(("getc",), machine=183))
        with self.assertRaisesRegex(receipt.ReceiptError, "not an x86-64 relocatable object"):
            receipt.undefined_symbols(path)
        path.write_bytes(b"getc object\n")
        with self.assertRaisesRegex(receipt.ReceiptError, "not a little-endian ELF64 object"):
            receipt.undefined_symbols(path)

    def test_requires_supplied_static_admission(self) -> None:
        with self.assertRaisesRegex(receipt.ReceiptError, "requires supplied-static"):
            receipt.validate_report(self.fixture.path, self.fixture.checkout, require_static=False)

    def test_recomputed_hashes_cannot_substitute_a_candidate_raw_transcript(self) -> None:
        path = self.fixture.work / "stdio.wide-format-non-pie-direct.stdout"
        path.write_bytes(b"forged transcript\n")
        self.fixture.refresh("commands")
        with self.assertRaisesRegex(receipt.ReceiptError, "wide-format dynamic non-pie direct raw output"):
            self.validate()

    def test_recomputed_hashes_cannot_trace_an_ambient_header(self) -> None:
        path = self.fixture.work / "stdio.scanf-header.stderr"
        path.write_bytes(path.read_bytes() + b". /usr/include/stdio.h\n")
        self.fixture.refresh("commands")
        with self.assertRaisesRegex(receipt.ReceiptError, "scanf header trace escapes"):
            self.validate()

    def test_recomputed_hashes_cannot_follow_an_installed_header_symlink(self) -> None:
        header = self.fixture.dynamic / "usr/include/stdio.h"
        replacement = self.fixture.work / "ambient-stdio.h"
        replacement.write_text("ambient header\n")
        header.unlink()
        header.symlink_to(replacement)
        self.fixture._write_seals()
        self.fixture.report["seals"] = {
            name: identity(self.fixture.work, self.fixture.work / (name + ".json"))
            for name in ("source-product-before", "source-product-after", "tools-before", "tools-after")
        }
        self.fixture.write_report()
        with self.assertRaisesRegex(receipt.ReceiptError, "header trace traverses a symlink"):
            self.validate()

    def test_recomputed_hashes_cannot_replace_helper_selected_compiler(self) -> None:
        replacement = self.fixture.work / "replacement-tool"
        replacement.write_bytes(b"replacement\n")
        replacement.chmod(0o755)
        record = {"path": str(replacement), "sha256": hashlib.sha256(replacement.read_bytes()).hexdigest(),
                  "size": replacement.stat().st_size, "mode": stat.S_IMODE(replacement.stat().st_mode)}
        for name in ("tools-before.json", "tools-after.json"):
            path = self.fixture.work / name
            value = json.loads(path.read_text())
            value["compiler"] = record
            path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
        self.fixture.refresh("tools")
        with self.assertRaisesRegex(receipt.ReceiptError, "compiler tool path differs from sealed helper"):
            self.validate()

    def test_recomputed_hashes_cannot_substitute_link_product_identity(self) -> None:
        path = self.fixture.links["stdio.file-backends-pie"]
        value = json.loads(path.read_text())
        value["product"] = str(self.fixture.root / "forged")
        path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
        self.fixture.refresh("links")
        with self.assertRaisesRegex(receipt.ReceiptError, "file-backends-pie link identity"):
            self.validate()

    def test_recomputed_hashes_cannot_forge_payload_audit(self) -> None:
        role, linkage = "stdio.process-streams", "pie"
        record = self.fixture.payload_records[(role, linkage)]
        record.write_text('{"linkage":"forged","role":"forged"}\n')
        for phase in ("before", "after"):
            path = self.fixture.work / f"{role}-{linkage}-copy-audit-{phase}.stdout"
            path.write_bytes(record.read_bytes())
        self.fixture.refresh("payloads", "commands")
        with self.assertRaisesRegex(receipt.ReceiptError, "process-streams dynamic pie before payload audit"):
            self.validate()

    def test_recomputed_hashes_cannot_forge_ordinary_exit_side_effect(self) -> None:
        path = self.fixture.side_effects["stdio.file-backends:dynamic-pie-kernel"]
        path.write_bytes(b"forged exit\n")
        self.fixture.refresh("effects")
        with self.assertRaisesRegex(receipt.ReceiptError, "ordinary-exit side effect"):
            self.validate()

    def test_recomputed_hashes_cannot_replace_private_proc_mount_semantics(self) -> None:
        path = self.fixture.process_proc["pie"]["receipt"]
        value = json.loads(path.read_text())
        value["mount"]["command"][4] = "proc-not-read-only"
        path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
        self.fixture.refresh("proc")
        with self.assertRaisesRegex(receipt.ReceiptError, "process pie proc mount command differs"):
            self.validate()

    def test_recomputed_hashes_cannot_drop_wide_format_private_proc_contract(self) -> None:
        path = self.fixture.process_proc["wide-format-pie"]["receipt"]
        value = json.loads(path.read_text())
        value["mount"]["command"][4] = "nosuid,nodev,noexec"
        path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
        self.fixture.refresh("proc")
        with self.assertRaisesRegex(receipt.ReceiptError, "process wide-format-pie proc mount command differs"):
            self.validate()

    def test_recomputed_hashes_cannot_replace_the_private_proc_mount_tool(self) -> None:
        replacement = self.fixture.work / "replacement-mount"
        replacement.write_bytes(b"replacement mount\n")
        replacement.chmod(0o755)
        record = {"path": str(replacement), "sha256": hashlib.sha256(replacement.read_bytes()).hexdigest(),
                  "size": replacement.stat().st_size, "mode": stat.S_IMODE(replacement.stat().st_mode)}
        for name in ("tools-before.json", "tools-after.json"):
            path = self.fixture.work / name
            value = json.loads(path.read_text())
            value["control_mount"] = record
            path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
        self.fixture.refresh("tools")
        with self.assertRaisesRegex(receipt.ReceiptError, "control proc mount tool path differs"):
            self.validate()

    def test_recomputed_hashes_cannot_substitute_a_staged_control_launcher(self) -> None:
        path = self.fixture.control_staged["pie"]["sh"]
        path.write_bytes(b"forged control shell\n")
        path.chmod(0o755)
        self.fixture.report["control"]["staged"]["pie"]["sh"] = identity(self.fixture.work, path)
        self.fixture.write_report()
        with self.assertRaisesRegex(receipt.ReceiptError, "control pie sh stage differs"):
            self.validate()

    def test_row_cannot_drop_a_runtime_cell(self) -> None:
        self.fixture.report["rows"]["stdio.scanf"]["runtime_cells"].pop()
        self.fixture.write_report()
        with self.assertRaisesRegex(receipt.ReceiptError, "report rows differ"):
            self.validate()

    def test_reader_rejects_a_symlink_hop_before_opening_report(self) -> None:
        link = self.fixture.root / "receipt-link"
        link.symlink_to(self.fixture.path)
        with self.assertRaisesRegex(receipt.ReceiptError, "symlink"):
            receipt.validate_report(link, self.fixture.checkout, require_static=True)


if __name__ == "__main__":
    unittest.main()
