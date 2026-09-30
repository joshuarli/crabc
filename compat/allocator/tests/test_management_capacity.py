"""Reject generic success labels that do not prove the selected public caller."""
import json
import hashlib
import io
import tarfile
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import x86_64_m2_management_capacity as capacity


class ManagementCapacityAuthorityTests(unittest.TestCase):
    def setUp(self):
        scratch = capacity.harness.ROOT / ".work" / "management-capacity-authority-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.work = self.root / ".work/allocator-x86_64/target/compat/allocator/x86_64/m2-management-capacity/run-test"
        self.work.mkdir(parents=True)
        self.seal = {"revision": "a" * 40, "worktree_sha256": "b" * 64}
        self.patch = mock.patch.object(capacity.receipts, "source_seal", return_value=self.seal)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def forged(self, case="passed", inputs=None):
        log = self.work / "claimed.json"
        log.write_text(json.dumps({"kind": "process", "status": 0, "command": ["true"]}))
        product = self.work / "claimed-product"
        product.write_bytes(b"success")
        products = {"claimed-product": product}
        if inputs is not None:
            provenance = self.work / "inputs.json"
            provenance.write_text(json.dumps(inputs))
            products["inputs.json"] = provenance
        capacity.receipts.write_receipt(self.root, capacity.RUNNER, self.work, products,
            [(case, 0, [log])], {"profiles": ",".join(capacity.PROFILES)}, True)

    def read(self):
        with mock.patch.object(capacity.harness, "ROOT", self.root), mock.patch.object(sys, "argv", ["caller", "--read"]):
            capacity.main()

    def cohort(self):
        # These records model receipt authority; no synthetic product is run.
        header = """#define MI_STAT_VERSION 5
#define MI_STAT_FIELDS() MI_STAT_COUNT(reserved) MI_STAT_COUNTER(arena_count)
// Size bins
#define MI_BIN_HUGE (1U)
typedef enum mi_chunkbin_e { MI_CBIN_SMALL, MI_CBIN_OTHER, MI_CBIN_MEDIUM, MI_CBIN_LARGE, MI_CBIN_HUGE, MI_CBIN_COUNT } mi_chunkbin_t;
"""
        self.products = {}
        def product(name, data):
            path = self.work / name
            path.write_bytes(data)
            self.products[name] = path
        product(capacity.DRIVER.name, capacity.DRIVER.read_bytes())
        members = {"include/mimalloc.h": b"selected public header", "include/mimalloc-stats.h": header.encode(), "LICENSE": b"license"}
        archive = self.work / "mimalloc-3.5.0.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            for name, data in members.items():
                entry = tarfile.TarInfo("mimalloc-3.5.0/" + name)
                entry.size = len(data)
                tar.addfile(entry, io.BytesIO(data))
        self.products[archive.name] = archive
        for name, data in members.items(): product(Path(name).name, data)
        self.pin = {"version": "3.5.0", "archive_root": "mimalloc-3.5.0", "sha256": capacity.fingerprint(archive)["sha256"]}
        inputs = {"source": self.seal, "execution": {"execution_mode": "native", "host_architecture": "x86_64", "image_id": capacity.IMAGE_ID},
            "upstream": self.pin, "profiles": list(capacity.PROFILES), "boundary": "public native-mi-adapter over pinned musl",
            "ownership": "distinct external spans; live child; joined exit; destroy; caller release", "capacity": 160,
            "partial-parent-bytes": 17179869184, "runtime-watchdog-seconds": 60}
        product("inputs.json", json.dumps(inputs).encode())
        fields = {"header": (392, 5), "reserved": (0, 0, 0), "arena_count": (0,)}
        for i in range(4):
            fields[f"reserved_count{i}"] = (0, 0, 0)
            fields[f"reserved_counter{i}"] = (0,)
        for group, count in (("malloc_bin", 2), ("page_bin", 2), ("chunk_bin", 5)):
            for i in range(count): fields[f"{group}{i}"] = (0, 0, 0)
        rows = ["CRABC_MI_MANAGEMENT_CAPACITY_BEGIN"]
        for phase in ("initial", "filled", "partial", "refused", "joined"):
            rows.extend(f"stats.{phase}.{name}=" + ",".join(map(str, values)) for name, values in fields.items())
        rows.extend(["capacity.geometry=33554432,268435456,160", "capacity.accepted=159",
            "capacity.partial=1,1,17179869184,1,1,1,1", "capacity.refusal=1,1,1,1,1", "capacity.terminal=161,161,1,1", "CRABC_MI_MANAGEMENT_CAPACITY_END"])
        self.trace = ("\n".join(rows) + "\n").encode()
        work = Path("/workspace") / self.work.relative_to(self.root)
        source = work / "source/mimalloc-3.5.0"
        self.events, self.cases = {}, []
        def event(name, argv, output, binding, stdout=b"", stderr=b""):
            self.events[name] = {"command": argv, "kind": "process", "status": 0,
                "stdout": self.bytes_record(stdout), "stderr": self.bytes_record(stderr),
                binding: {str(output): capacity.fingerprint(self.products[name.rsplit("-", 2)[0] + "-" + ("native-mi-adapter.a" if name.endswith("native-build") else output.name)])}}
            self.cases.append((name, 0, [self.work / (name + suffix) for suffix in (".json", ".stdout", ".stderr")]))
        for profile in capacity.PROFILES:
            for backend in ("c", "native", "native-mi-adapter.a"): product(profile + "-" + backend, (profile + backend).encode())
        for profile in capacity.PROFILES:
            binary = work / profile / "c"
            event(profile + "-c-link", capacity.c_command(source, binary, profile, "/usr/local/bin/musl-gcc"), binary, "outputs")
            self.events[profile + "-c-link"]["outputs"] = {str(binary): capacity.fingerprint(self.products[profile + "-c"])}
            event(profile + "-c-run", [str(binary)], binary, "executed", self.trace, capacity.SOURCE_AUDIT)
            self.events[profile + "-c-run"]["executed"] = {str(binary): capacity.fingerprint(self.products[profile + "-c"])}
        for profile in capacity.PROFILES:
            library = work / profile / "native-mi-adapter.a"
            actual = work / "cargo-target" / capacity.m4.RUST_TARGET / "release" / capacity.m4.ADAPTER_STATICLIB
            event(profile + "-native-build", capacity.native_build_command(work / "cargo-target", profile, "/opt/cargo/bin/cargo"), actual, "outputs")
            binary = work / profile / "native"
            event(profile + "-native-link", capacity.native_link_command(source, binary, library, "/usr/local/bin/musl-gcc"), binary, "outputs")
            self.events[profile + "-native-link"]["outputs"] = {str(binary): capacity.fingerprint(self.products[profile + "-native"])}
            event(profile + "-native-run", [str(binary)], binary, "executed", self.trace)
            self.events[profile + "-native-run"]["executed"] = {str(binary): capacity.fingerprint(self.products[profile + "-native"])}
            self.cases.append((profile + "-comparison", 0, [self.work / (profile + "-" + backend + "-run" + suffix)
                for backend in ("c", "native") for suffix in (".json", ".stdout", ".stderr")]))
        patch = mock.patch.object(capacity.harness, "load_pin", return_value=self.pin)
        patch.start()
        self.addCleanup(patch.stop)

    @staticmethod
    def bytes_record(data):
        return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "hex": data.hex()}

    def publish(self):
        for name, event in self.events.items():
            (self.work / (name + ".json")).write_text(json.dumps(event))
            for stream in ("stdout", "stderr"):
                (self.work / (name + "." + stream)).write_bytes(bytes.fromhex(event[stream]["hex"]))
        capacity.receipts.write_receipt(self.root, capacity.RUNNER, self.work, self.products, self.cases, capacity.PARAMETERS, True)
        capacity.receipts.read_receipt(self.root, capacity.RUNNER)

    def test_complete_command_bound_metadata_control(self):
        self.cohort()
        self.publish()
        self.read()

    def test_rehashed_false_authority_is_rejected(self):
        self.cohort()
        original = json.loads(json.dumps(self.events))
        alterations = [
            ("release-c-link", lambda e: e["command"].remove("-UNDEBUG")),
            ("stat-2-native-build", lambda e: e["command"].__setitem__(-1, "crabc-mimalloc/mi-stat-1")),
            ("release-native-run", lambda e: e.__setitem__("command", ["true"])),
            ("release-native-run", lambda e: e.__setitem__("executed", {e["command"][0]: capacity.fingerprint(self.products["stat-2-native"])})),
            ("release-c-run", lambda e: e.__setitem__("stderr", self.bytes_record(b"source.capacity=1,1,1,1,0\n"))),
            ("release-native-run", lambda e: e.__setitem__("stdout", self.bytes_record(self.trace.replace(b"stats.initial.arena_count=0", b"stats.initial.arena_count=1")))),
        ]
        for name, change in alterations:
            with self.subTest(case=name, mutation=alterations.index((name, change))):
                self.events = json.loads(json.dumps(original))
                change(self.events[name])
                self.publish()
                with self.assertRaises(capacity.receipts.ReceiptError): self.read()

    def test_omitted_manifest_cannot_authorize_unbound_compiler_checkout(self):
        self.cohort()
        event = self.events["release-native-build"]
        if "--manifest-path" in event["command"]:
            index = event["command"].index("--manifest-path")
            del event["command"][index:index + 2]
        self.publish()
        with self.assertRaises(capacity.receipts.ReceiptError): self.read()

    def test_other_manifest_cannot_authorize_foreign_compiler_checkout(self):
        self.cohort()
        event = self.events["release-native-build"]
        if "--manifest-path" in event["command"]:
            event["command"][event["command"].index("--manifest-path") + 1] = "/foreign/Cargo.toml"
        else:
            event["command"] += ["--manifest-path", "/foreign/Cargo.toml"]
        self.publish()
        with self.assertRaises(capacity.receipts.ReceiptError): self.read()

    def test_rehashed_profile_caller_and_pinned_header_forgeries_are_rejected(self):
        self.cohort()
        for name in ("inputs.json", capacity.DRIVER.name, "mimalloc-stats.h"):
            with self.subTest(product=name):
                path = self.products[name]
                original = path.read_bytes()
                if name == "inputs.json":
                    data = json.loads(original)
                    data["profiles"] = ["release"]
                    path.write_text(json.dumps(data))
                else:
                    path.write_bytes(original + b" changed")
                self.publish()
                with self.assertRaises(capacity.receipts.ReceiptError): self.read()
                path.write_bytes(original)

    def test_agreeing_invalid_capacity_or_missing_statistic_is_rejected(self):
        self.cohort()
        original = json.loads(json.dumps(self.events))
        for trace in (self.trace.replace(b"capacity.terminal=161,161,1,1", b"capacity.terminal=161,160,1,1"),
                self.trace.replace(b"stats.initial.arena_count=0\n", b"")):
            self.events = json.loads(json.dumps(original))
            for backend in ("c", "native"):
                self.events["release-" + backend + "-run"]["stdout"] = self.bytes_record(trace)
            self.publish()
            with self.assertRaises(capacity.receipts.ReceiptError): self.read()

    def test_generic_success_label_cannot_qualify_missing_caller_cohort(self):
        self.forged()
        with self.assertRaises(capacity.receipts.ReceiptError):
            self.read()

    def test_expected_case_name_cannot_authorize_arbitrary_command(self):
        self.forged("release-c-run")
        with self.assertRaises(capacity.receipts.ReceiptError):
            self.read()

    def test_claimed_full_parameters_cannot_hide_reduced_physical_profiles(self):
        self.forged(inputs={"profiles": ["release"]})
        with self.assertRaises(capacity.receipts.ReceiptError):
            self.read()


if __name__ == "__main__":
    unittest.main()
