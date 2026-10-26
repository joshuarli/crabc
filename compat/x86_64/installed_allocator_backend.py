"""Validate the selected allocator identity of installed qualification products."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from typing import Literal, Mapping, cast

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts import build_x86_64_owned_sysroot as products
from native_shadow_receipt import ReceiptError


AllocatorBackend = Literal["accepted-c", "native-shadow", "native"]


def selected_backend(*identities: object) -> AllocatorBackend:
    if not identities or any(value not in ("accepted-c", *products.NATIVE_ALLOCATOR_BACKENDS) for value in identities):
        raise ReceiptError(f"unsupported installed allocator backend identities: {identities!r}")
    if any(value != identities[0] for value in identities):
        raise ReceiptError(f"installed allocator backend identities disagree: {identities!r}")
    return cast(AllocatorBackend, identities[0])


def dynamic_backend(root: Path, state: Mapping[str, object],
                    provenance: Mapping[str, object]) -> AllocatorBackend:
    backend = selected_backend(state.get("allocator_backend"), provenance.get("allocator_backend"))
    native = provenance.get("native_allocator")
    accepted = provenance.get("accepted_allocator")
    if backend in products.NATIVE_ALLOCATOR_BACKENDS:
        if not isinstance(native, dict) or native.get("path") != "crabc-mimalloc/UPSTREAM.md":
            raise ReceiptError("installed native allocator source marker is missing or has a wrong path")
        if native.get("sha256") != hashlib.sha256((root / native["path"]).read_bytes()).hexdigest():
            raise ReceiptError("installed native allocator source digest differs from the checkout")
        if accepted is not None:
            raise ReceiptError("native allocator source provenance claims an accepted C dependency")
    else:
        if native is not None:
            raise ReceiptError("accepted C products claim a native allocator source")
        if accepted != products.C_ALLOCATOR_PIN:
            raise ReceiptError("installed accepted allocator source differs from the reviewed C dependency")
    return backend


def static_and_dynamic_backend(root: Path, static_manifest: Mapping[str, object],
                               static_provenance: Mapping[str, object],
                               dynamic_state: Mapping[str, object],
                               dynamic_provenance: Mapping[str, object]) -> AllocatorBackend:
    backend = selected_backend(static_manifest.get("allocator_backend"),
                               dynamic_state.get("allocator_backend"),
                               dynamic_provenance.get("allocator_backend"))
    dynamic_backend(root, dynamic_state, dynamic_provenance)
    allocator = static_provenance.get("allocator_backend")
    if not isinstance(allocator, dict):
        raise ReceiptError("static allocator provenance is missing")
    if backend in products.NATIVE_ALLOCATOR_BACKENDS:
        if allocator.get("upstream_sha256") != dynamic_provenance["native_allocator"]["sha256"]:
            raise ReceiptError("static and dynamic libc provenance disagree on the native allocator source")
    else:
        if "upstream_sha256" in allocator:
            raise ReceiptError("accepted C products claim a native allocator source")
        if allocator.get("crate") != dynamic_provenance["accepted_allocator"]:
            raise ReceiptError("static and dynamic libc provenance disagree on the accepted allocator source")
    return backend


def main() -> int:
    try:
        records = [json.loads(Path(path).read_text()) for path in sys.argv[1:]]
        if any(not isinstance(record, dict) for record in records):
            raise ReceiptError("installed allocator provenance must be an object")
        root = Path(__file__).resolve().parents[2]
        if len(records) == 2:
            backend = dynamic_backend(root, *records)
        elif len(records) == 4:
            backend = static_and_dynamic_backend(root, *records)
        else:
            raise ReceiptError("expected dynamic state/provenance or static manifest/provenance and dynamic state/provenance")
        print(backend)
    except (OSError, ValueError, KeyError, ReceiptError) as error:
        print(f"installed allocator backend: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
