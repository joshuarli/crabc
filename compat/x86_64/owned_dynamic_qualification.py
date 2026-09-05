#!/usr/bin/env python3
"""Execute and validate source-bound evidence for three owned dynamic products.

Build metadata never qualifies a runtime. Each registered subprocess owns one
case record; finishing validates the complete case/product matrix, installed
payloads, ordinary-driver receipts, base observations and reproducible archives.
Publication is a separate explicit operation after review, and conveys no family
completion or platform promotion. All generated state remains below .work.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "crabc.x86_64-owned-dynamic-qualification/v1"
PRODUCTS = ("installed", "second", "extracted")
PUBLICATION = ROOT / ".work/x86_64/owned-dynamic-qualification.json"
# The finite roster is the executable coverage map. A leaf may cover multiple
# behaviors, but no omitted product, alternate mode or required leaf is implied.
CASES = {
    "cycle": ("run_general_dynamic_cycle.sh", None),
    "cli": ("run_general_dynamic_cli.sh", None),
    "elf-scope-alias": ("run_general_dynamic_elf_scope.sh", None),
    "dlopen-pie": ("run_general_dynamic_dlopen.sh", "--dynamic-pie"),
    "dlopen-non-pie": ("run_general_dynamic_dlopen.sh", "--dynamic-non-pie"),
    "lazy-pie": ("run_general_dynamic_lazy.sh", "--dynamic-pie"),
    "lazy-non-pie": ("run_general_dynamic_lazy.sh", "--dynamic-non-pie"),
    "constructor-exit": ("run_general_dynamic_constructor_exit.sh", None),
    "pthread-signal": ("run_general_dynamic_pthread_signal.sh", None),
    "pthread-exit": ("run_general_dynamic_pthread_exit.sh", None),
    "fork": ("run_general_dynamic_fork.sh", None),
    "atfork-registry": ("run_owned_atfork_registry.sh", None),
    "pthread-scheduling": ("run_owned_pthread_scheduling.sh", None),
    "signal-helpers": ("run_owned_signal_helpers.sh", None),
    "fcntl": ("run_owned_fcntl.sh", None),
    "pthread-getattr": ("run_owned_pthread_getattr.sh", None),
    "pthread-join-cancel": ("run_owned_pthread_join_cancel.sh", None),
    "pthread-cond-cancel": ("run_owned_pthread_cond_cancel.sh", None),
    "pthread-cond-timed": ("run_owned_pthread_cond_timed.sh", None),
    "pthread-mutex": ("run_owned_pthread_mutex.sh", None),
    "io-cancellation": ("run_owned_dynamic_io_cancellation.sh", None),
    "system-cancellation": ("run_owned_system_cancellation.sh", None),
    "spawn": ("run_owned_dynamic_spawn.sh", None),
    "linux-control": ("run_owned_linux_control.sh", None),
    "assert": ("run_owned_assert.sh", None),
    "syslog": ("run_owned_syslog.sh", None),
    "pthread-spin": ("run_owned_pthread_spin.sh", None),
    "process-trio": ("run_owned_process_trio.sh", None),
}
MATERIALIZATION_PROFILE = "retained dlclose mappings; default NOW with declared lazy imports; runtime GD growth; new runtime IE rejected"
MATERIALIZATION_QUALIFICATION = "separate live three-product receipt and review required"
CONTRACTS = ("compat/x86_64/dynamic-product.toml", "compat/x86_64/loader-libc-tls-runtime-v1.toml")

ORACLE_FILES = {
    "runtime": Path("/opt/musl-1.2.6/lib/libc.so"),
    "compiler_wrapper": Path("/usr/local/bin/crabc-x86_64-musl-gcc"),
    "specs": Path("/opt/musl-1.2.6/lib/musl-gcc.specs"),
    "source_manifest": Path("/opt/musl-1.2.6/.crabc-oracle"),
    "specs_manifest": Path("/opt/musl-1.2.6/.crabc-musl-gcc-specs.sha256"),
}


class QualificationError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise QualificationError(message)


def digest(path: Path) -> str:
    require(path.is_file() and not path.is_symlink(), f"missing or unsafe evidence: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(*arguments: str) -> bytes:
    return subprocess.check_output(["git", "-c", f"safe.directory={ROOT}", *arguments], cwd=ROOT)


def source_digest() -> str:
    """Hash live nonignored source content, names and modes without a self-hash.

    Generated receipts are ignored. Include untracked source during component
    development so adding a file cannot silently escape build/source binding.
    Verified publication additionally requires a clean working tree.
    """
    names = sorted(set(git("ls-files", "-z", "--cached", "--others", "--exclude-standard").split(b"\0")) - {b""})
    result = hashlib.sha256()
    for name in names:
        path = ROOT / os.fsdecode(name)
        mode = path.lstat().st_mode
        data = os.fsencode(os.readlink(path)) if stat.S_ISLNK(mode) else path.read_bytes()
        result.update(name + b"\0" + str(stat.S_IMODE(mode)).encode() + b"\0")
        result.update(hashlib.sha256(data).digest())
    return result.hexdigest()


def require_clean_source() -> str:
    require(not git("status", "--porcelain", "--untracked-files=all").strip(), "qualification publication requires clean source")
    return git("rev-parse", "HEAD").decode().strip()


def contract_digests() -> dict[str, str]:
    # A matching byte hash cannot substitute for valid semantic contracts.
    import dynamic_product_contract as product_contract
    import validate_loader_libc_tls_runtime_v1 as tls_contract
    product_contract.validate_contract_and_state(
        product_contract.load_toml(product_contract.CONTRACT_PATH),
        json.loads(product_contract.STATE_PATH.read_text()))
    tls_contract.validate_contract(tls_contract.load_toml(tls_contract.CONTRACT_PATH))
    return {name: digest(ROOT / name) for name in CONTRACTS}


def evidence_path(path: Path) -> Path:
    path = path.absolute()
    require(path.resolve() == path and path.is_relative_to(ROOT / ".work"), "evidence must be a physical checkout .work path")
    return path


def relative(path: Path) -> str:
    return evidence_path(path).relative_to(ROOT).as_posix()


def write_new(path: Path, value: dict) -> None:
    evidence_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")


def read(path: Path) -> dict:
    digest(path)
    value = json.loads(path.read_text())
    require(isinstance(value, dict), "evidence record must be an object")
    return value


def product_identity(product: Path) -> str:
    import crabc_cc_owned_dynamic as driver
    try:
        manifest = driver.validate(product)
    except driver.shared.DriverError as error:
        raise QualificationError(f"installed product invalid: {error}") from error
    state = read(product / "share/crabc/dynamic-product-state.json")
    require(set(state) == {"schema", "status", "source_sha256", "contracts", "payload_files",
            "runtime_v1_published", "campaign_complete", "public_support", "modes", "runtime_profile", "qualification"},
            "materialization fields drifted")
    require(state.get("schema") == "crabc.x86_64-owned-dynamic-materialization/v1", "wrong materialization schema")
    require(state.get("payload_files") == {name: value for name, value in manifest["files"].items()
            if name != "share/crabc/dynamic-product-state.json"}, "materialization payload binding drifted")
    require(state.get("status") == "materialized-unqualified", "builder state must remain unqualified")
    require(state.get("source_sha256") == source_digest(), "installed product source is stale")
    require(state.get("contracts") == contract_digests(), "installed product contracts are stale")
    require(state.get("runtime_v1_published") is False and state.get("public_support") is False
            and state.get("campaign_complete") is False,
            "builder cannot publish runtime or public support")
    require(state["modes"] == ["dynamic-pie", "dynamic-non-pie", "dynamic-shared-object"]
            and state["runtime_profile"] == MATERIALIZATION_PROFILE
            and state["qualification"] == MATERIALIZATION_QUALIFICATION, "materialization profile drifted")
    return digest(product / "share/crabc/manifest.json")


def capture_oracle(work: Path) -> dict:
    destination = work / "qualification-oracle"
    destination.mkdir()
    for name, path in ORACLE_FILES.items():
        digest(path)
        with (destination / name).open("xb") as output:
            output.write(path.read_bytes())
    files = {name: digest(destination / name) for name in ORACLE_FILES}
    return {"version": "musl-1.2.6", "runtime_sha256": files["runtime"],
            "compiler_wrapper_sha256": files["compiler_wrapper"],
            "pins_sha256": digest(ROOT / "compat/upstreams.toml"), "files": files}


def validate_oracle(work: Path, oracle: dict) -> dict[str, str]:
    """Validate retained observed binaries and pinned source/specs provenance.

    The runtime hash identifies observed executable bytes, not a claimed
    reproducible-build hash of upstream musl. Source provenance is supplied by
    the pinned image build and the executed source/specs/version/mapping probe.
    """
    require(set(oracle) == {"version", "runtime_sha256", "compiler_wrapper_sha256", "pins_sha256", "files"}, "oracle identity missing")
    require(oracle["version"] == "musl-1.2.6" and oracle["pins_sha256"] == digest(ROOT / "compat/upstreams.toml"), "oracle pin identity drifted")
    files = oracle["files"]
    require(isinstance(files, dict) and set(files) == set(ORACLE_FILES), "oracle observed file roster drifted")
    directory = work / "qualification-oracle"
    require({path.name for path in directory.iterdir()} == set(files), "oracle retained file roster drifted")
    for name, expected in files.items():
        require(digest(directory / name) == expected, "oracle retained file identity differs")
    require(oracle["runtime_sha256"] == files["runtime"]
            and oracle["compiler_wrapper_sha256"] == files["compiler_wrapper"], "oracle identity differs from retained bytes")
    require(files["compiler_wrapper"] == digest(ROOT / "docker/x86_64-musl-oracle-gcc"), "oracle compiler wrapper differs from pinned source")
    pins = tomllib.loads((ROOT / "compat/upstreams.toml").read_text())["musl"]
    expected_manifest = ("format=crabc-pinned-musl-oracle-v1\n"
                         f"version={pins['version']}\nsource_sha256={pins['sha256']}\n"
                         f"fallback_revision={pins['fallback_revision']}\narchitecture=x86_64\n")
    require((directory / "source_manifest").read_text() == expected_manifest, "oracle source verification manifest drifted")
    require((directory / "specs_manifest").read_text() == f"{files['specs']}  /opt/musl-1.2.6/lib/musl-gcc.specs\n", "oracle specs verification manifest drifted")
    return {relative(directory / name): value for name, value in files.items()}


def require_live_oracle(work: Path, oracle: dict) -> None:
    validate_oracle(work, oracle)
    require({name: digest(path) for name, path in ORACLE_FILES.items()} == oracle["files"],
            "live oracle files differ from the validated preparation")


def prepare(work: Path) -> None:
    """Run the pinned oracle and nearest source/driver judges with kept logs."""
    work = evidence_path(work)
    # This is the evidence parent, not a runtime fixture root. Make even a
    # failed preparation log reachable from the host without recursive changes.
    os.chmod(work, stat.S_IMODE(work.stat().st_mode) | 0o555, follow_symlinks=False)
    source = source_digest()
    oracle = capture_oracle(work)
    require_live_oracle(work, oracle)
    commands = [
        ["python3", "-B", "-m", "unittest", "discover", "-s", str(ROOT / "compat/x86_64"), "-p", "test_owned_dynamic_driver.py"],
        ["python3", "-B", "-m", "unittest", "discover", "-s", str(ROOT / "crt/tests"), "-p", "test_x86_64_dynamic_modes.py"],
        ["rustc", "--edition=2021", "--test", "--cfg", "crabc_general_initial_graph",
         "--cfg", "crabc_general_initial_tls_materialization_v1", "--cfg", "crabc_general_loader_libc_tls_runtime_v1",
         "--cfg", "crabc_general_initial_lifecycle", "--cfg", "crabc_dynamic_main_thread_runtime_v1",
         "--cfg", 'feature="x86_64-owned-dynamic-runtime"',
         str(ROOT / "ldso/src/x86_64_general_initial_tls_runtime_v1_source_root.rs"), "-o", str(work / "loader-tests")],
        [str(work / "loader-tests")],
        ["bash", str(ROOT / "compat/x86_64/run_musl_oracle.sh")],
    ]
    log = work / "qualification-prepare.log"
    with log.open("xb") as output:
        os.fchmod(output.fileno(), stat.S_IMODE(os.fstat(output.fileno()).st_mode) | 0o444)
        for command in commands:
            completed = subprocess.run(command, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT)
            require(completed.returncode == 0, f"qualification preparation failed: {command[0]}; {log}")
    print(log.read_text(errors="replace"), end="", flush=True)
    require(source == source_digest(), "source changed during qualification preparation")
    require_live_oracle(work, oracle)
    write_new(work / "qualification-prepare.json", {
        "schema": SCHEMA, "source_sha256": source, "log": relative(log), "log_sha256": digest(log),
        "oracle": oracle,
        "checks": ["installed-driver", "owned-crt", "owned-loader-source", "pinned-musl-oracle"],
        "exit_status": 0,
    })


def preparation_evidence(work: Path, source: str) -> dict[str, str]:
    path = work / "qualification-prepare.json"
    record = read(path)
    require(set(record) == {"schema", "source_sha256", "log", "log_sha256", "oracle", "checks", "exit_status"}, "preparation fields drifted")
    require(record["schema"] == SCHEMA and record["source_sha256"] == source and record["exit_status"] == 0,
            "missing or stale preparation evidence")
    require(record["checks"] == ["installed-driver", "owned-crt", "owned-loader-source", "pinned-musl-oracle"], "preparation checks incomplete")
    oracle_files = validate_oracle(work, record["oracle"])
    log = evidence_path(ROOT / record["log"])
    require(log == work / "qualification-prepare.log" and digest(log) == record["log_sha256"], "preparation log is stale")
    return {relative(path): digest(path), relative(log): digest(log), **oracle_files}


def leaf_evidence_directories(log: Path, source_mount: str) -> set[Path]:
    """Find only the exact retained roots declared by a completed leaf.

    Paths in logs use the producer's container mount; record them relative to
    the checkout so host-side validation does not depend on /workspace.
    Symlinks and special fixture nodes are described without following them.
    """
    require(isinstance(source_mount, str) and Path(source_mount).is_absolute(), "invalid evidence source mount")
    prefix = source_mount.rstrip("/") + "/"
    directories = set()
    for name in re.findall(r"evidence: ([^\n]+)", log.read_text(errors="replace")):
        require(name.startswith(prefix), "leaf evidence escapes its source mount")
        path = evidence_path(ROOT / name[len(prefix):])
        require(path.is_dir() and not path.is_symlink(), "leaf evidence directory missing")
        directories.add(path)
    return directories


def make_retained_evidence_readable(root: Path) -> None:
    """After execution, add directory read/traverse and regular-file read bits.

    This mutates only the exact admitted evidence tree. Symlinks are described
    but never followed and special nodes stay unchanged. Regular-file execute
    and write bits and directory write bits stay intact. Runtime permissions have already
    been tested before this retention policy runs.
    """
    root = evidence_path(root)
    require(root.is_dir() and not root.is_symlink(), "retained evidence root must be a physical directory")
    pending = [root]
    while pending:
        path = pending.pop()
        require(path.is_relative_to(root), "retained evidence escapes its exact root")
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            os.chmod(path, stat.S_IMODE(mode) | 0o555, follow_symlinks=False)
            pending.extend(path.iterdir())
        elif stat.S_ISREG(mode):
            os.chmod(path, stat.S_IMODE(mode) | 0o444, follow_symlinks=False)


def artifact_snapshot(log: Path, source_mount: str) -> dict:
    """Seal post-execution evidence, including derived ELF and link receipts."""
    directories = leaf_evidence_directories(log, source_mount)
    require(directories, "leaf did not identify retained artifact evidence")
    result = {}
    for directory in sorted(directories):
        entries = {}
        for path in sorted(directory.rglob("*")):
            mode = path.lstat().st_mode
            entry = {"mode": stat.S_IMODE(mode), "type": stat.S_IFMT(mode)}
            if stat.S_ISREG(mode):
                entry["sha256"] = digest(path)
            elif stat.S_ISLNK(mode):
                entry["target"] = os.readlink(path)
            entries[path.relative_to(directory).as_posix()] = entry
        result[relative(directory)] = entries
    return result


def run_case(work: Path, product: str, case: str) -> None:
    require(product in PRODUCTS and case in CASES, "unknown product or coverage case")
    work = evidence_path(work)
    source = source_digest()
    oracle = read(work / "qualification-prepare.json")["oracle"]
    require_live_oracle(work, oracle)
    manifest = product_identity(work / product)
    script, mode = CASES[case]
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(("CRABC_GENERAL_DYNAMIC_", "LD_"))}
    if mode:
        environment["CRABC_GENERAL_DYNAMIC_ENTRY_MODE"] = mode
    destination = work / "qualification-cases" / product
    destination.mkdir(parents=True, exist_ok=True)
    log = destination / (case + ".log")
    command = ["bash", str(ROOT / "compat/x86_64" / script), str(work / product)]
    with log.open("xb") as output:
        completed = subprocess.run(command, cwd=ROOT, env=environment, stdout=output, stderr=subprocess.STDOUT)
    print(log.read_text(errors="replace"), end="", flush=True)
    for directory in leaf_evidence_directories(log, str(ROOT)):
        make_retained_evidence_readable(directory)
    require(completed.returncode == 0, f"coverage case failed: {product}/{case}; {log}")
    require_live_oracle(work, oracle)
    require(source_digest() == source and product_identity(work / product) == manifest,
            "source or installed product changed during coverage case")
    write_new(destination / (case + ".json"), {
        "schema": SCHEMA, "product": product, "case": case, "script": script,
        "entry_mode": mode, "source_sha256": source, "manifest_sha256": manifest,
        "log": relative(log), "log_sha256": digest(log), "exit_status": 0,
        "source_mount": str(ROOT), "artifacts": artifact_snapshot(log, str(ROOT)),
    })


def validate_case(record: dict, product: str, case: str, source: str, manifest: str) -> None:
    script, mode = CASES[case]
    expected = {"schema": SCHEMA, "product": product, "case": case, "script": script,
                "entry_mode": mode, "source_sha256": source, "manifest_sha256": manifest,
                "exit_status": 0}
    require(set(record) == set(expected) | {"log", "log_sha256", "source_mount", "artifacts"}, "coverage record fields drifted")
    require(all(record.get(key) == value for key, value in expected.items()), "stale or mismatched coverage record")
    log = evidence_path(ROOT / record["log"])
    require(digest(log) == record["log_sha256"], "coverage log hash mismatch")
    require(artifact_snapshot(log, record["source_mount"]) == record["artifacts"], "leaf artifact evidence changed")


def base_evidence(work: Path, manifests: dict[str, str]) -> dict[str, str]:
    expected = b"installed dynamic: allocation errno stdio threads\nordinary exit\n"
    require((work / "expected.stdout").read_bytes() == expected, "base expected observation drifted")
    require((work / "oracle.stdout").read_bytes() == expected, "base musl observation differs")
    result = {relative(work / name): digest(work / name) for name in ("expected.stdout", "oracle.stdout")}
    for product in PRODUCTS:
        for name, observation in ((f"{product}-consumer", expected), (f"non-pie-{product}", expected), (f"spawn-{product}", b"")):
            binary, output = work / name, work / (name + ".stdout")
            require(output.read_bytes() == observation, f"base observation differs: {name}")
            receipt_path = work / (name + ".crabc-link.json")
            receipt = read(receipt_path)
            source_mount = read(work / "qualification-cases" / product / "cycle.json")["source_mount"]
            expected_path = source_mount.rstrip("/") + "/" + binary.relative_to(ROOT).as_posix()
            runtime = sorted("usr/lib/" + entry for entry in
                             (("crt1.o" if name.startswith("non-pie-") else "Scrt1.o"),
                              "crabc-dynamic-attach.o", "crti.o", "libc.so", "libcrabc-builtins.a", "crtn.o"))
            require(receipt.get("schema") == 1 and receipt.get("format") == "crabc-x86-64-owned-dynamic-sysroot-v1"
                    and receipt.get("runtime_imports") == [] and receipt.get("output_path") == expected_path
                    and receipt.get("owned_runtime_inputs") == runtime, "base driver path or purity contract drifted")
            require(receipt.get("output_sha256") == digest(binary), "base executable receipt hash mismatch")
            require(receipt.get("manifest_sha256") == manifests[product], "base receipt uses another installed product")
            require(receipt.get("mode") == ("exec" if name.startswith("non-pie-") else "pie"), "base executable mode mismatch")
            require(receipt.get("campaign_complete") is False and receipt.get("binding") == "now", "base driver purity receipt drifted")
            require(receipt.get("link_trace") and receipt.get("owned_runtime_inputs"), "base driver purity evidence missing")
            for path in (binary, output, receipt_path):
                result[relative(path)] = digest(path)
    return result


def validate_archive(path: Path, product: Path) -> None:
    """Bind package bytes to this exact installed payload without extracting."""
    manifest = read(product / "share/crabc/manifest.json")
    expected = {**manifest["files"], "share/crabc/manifest.json": digest(product / "share/crabc/manifest.json")}
    with tarfile.open(path, "r:") as archive:
        members = archive.getmembers()
        require(len(members) == len(expected) + len(manifest["symlinks"]), "package member count differs")
        require({member.name for member in members} == set(expected) | set(manifest["symlinks"]), "package roster differs")
        for member in members:
            if member.name in manifest["symlinks"]:
                require(member.issym() and member.linkname == manifest["symlinks"][member.name], "package alias differs")
            else:
                require(member.isfile() and member.size == (product / member.name).stat().st_size, "package file shape differs")
                stream = archive.extractfile(member)
                require(stream is not None, "missing package payload")
                value = hashlib.sha256()
                while chunk := stream.read(1024 * 1024):
                    value.update(chunk)
                require(value.hexdigest() == expected[member.name], "package payload differs")


def collect(work: Path) -> dict:
    work = evidence_path(work)
    source = source_digest()
    manifests = {product: product_identity(work / product) for product in PRODUCTS}
    require(len(set(manifests.values())) == 1, "three product manifests differ")
    records = {}
    for product in PRODUCTS:
        directory = work / "qualification-cases" / product
        require(directory.is_dir(), f"missing product coverage: {product}")
        require({path.name for path in directory.iterdir()} == {case + suffix for case in CASES for suffix in (".json", ".log")}, "missing or extra coverage cases")
        for case in CASES:
            path = directory / (case + ".json")
            validate_case(read(path), product, case, source, manifests[product])
            records[relative(path)] = digest(path)
    archives = {relative(work / name): digest(work / name) for name in ("runtime.tar", "second-runtime.tar")}
    require(len(set(archives.values())) == 1, "independent product archives differ")
    validate_archive(work / "runtime.tar", work / "installed")
    validate_archive(work / "second-runtime.tar", work / "second")
    require(source == source_digest(), "source changed during qualification validation")
    return {"schema": SCHEMA, "status": "qualified-pending-review", "work": relative(work),
            "source_sha256": source, "contracts": contract_digests(), "products": manifests,
            "preparation": preparation_evidence(work, source), "cases": records, "base_evidence": base_evidence(work, manifests), "archives": archives,
            "runtime_v1_published": False, "family_completion": False,
            "promotion_ready": False, "public_support": False}


def validate_receipt(path: Path) -> dict:
    receipt = read(evidence_path(path))
    require(receipt == collect(ROOT / receipt.get("work", "")), "qualification receipt is stale or incomplete")
    return receipt


def publish_receipt(path: Path) -> None:
    """Atomically replace the reviewed pointer; never rewrite any receipt.

    Requalification after a source change creates a fresh receipt and may
    replace this mutable selection. Validate both before staging and just
    before replacement, so a concurrent source edit cannot publish stale proof.
    """
    revision = require_clean_source()
    receipt = validate_receipt(path)
    receipt_hash = digest(path)
    destination = evidence_path(PUBLICATION)
    destination.parent.mkdir(parents=True, exist_ok=True)
    pointer = {"schema": SCHEMA, "receipt": relative(path),
               "receipt_sha256": receipt_hash, "source_revision": revision}
    staged = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", prefix=".publication-", suffix=".json",
                                         dir=destination.parent, delete=False) as output:
            staged = Path(output.name)
            # Reports produced in the native container remain host-readable.
            os.fchmod(output.fileno(), 0o644)
            json.dump(pointer, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        require(require_clean_source() == revision and source_digest() == receipt["source_sha256"]
                and digest(path) == receipt_hash, "source or receipt changed during publication")
        os.replace(staged, destination)
        directory = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if staged is not None:
            staged.unlink(missing_ok=True)


def load_publication() -> dict | None:
    """Return current proof only; a stale selection is recoverably unqualified.

    The pointer and old immutable evidence stay available for inspection. An
    explicit validate operation still diagnoses stale/missing receipt inputs;
    neither status reporting nor fresh qualification consumes them as proof.
    Malformed pointer schemas remain errors rather than silently accepted state.
    """
    if not PUBLICATION.exists():
        return None
    published = read(PUBLICATION)
    require(set(published) == {"schema", "receipt", "receipt_sha256", "source_revision"}, "publication fields drifted")
    require(published["schema"] == SCHEMA, "publication schema drifted")
    try:
        if published["source_revision"] != require_clean_source():
            return None
        receipt = evidence_path(ROOT / published["receipt"])
        require(digest(receipt) == published["receipt_sha256"], "published receipt hash mismatch")
        return validate_receipt(receipt)
    except (QualificationError, OSError, ValueError, tarfile.TarError):
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("prepare", "run", "finish", "validate", "publish"))
    parser.add_argument("--work", type=Path)
    parser.add_argument("--product", choices=PRODUCTS)
    parser.add_argument("--case", choices=CASES)
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args()
    try:
        if args.operation == "prepare":
            require(args.work is not None, "prepare requires --work")
            prepare(args.work)
        elif args.operation == "run":
            require(args.work is not None, "run requires --work")
            run_case(args.work, args.product, args.case)
        elif args.operation == "finish":
            require(args.work is not None, "finish requires --work")
            make_retained_evidence_readable(args.work)
            write_new(args.work / "qualification.json", collect(args.work))
            print(f"dynamic product qualification ready for review: {args.work / 'qualification.json'}")
        else:
            require(args.receipt is not None, "operation requires --receipt")
            if args.operation == "publish":
                publish_receipt(args.receipt)
            else:
                validate_receipt(args.receipt)
            print("dynamic product receipt validated; family and platform gates remain independent")
    except (QualificationError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"dynamic qualification: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
