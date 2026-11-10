import hashlib
import json
from pathlib import Path
import shutil
import sys

COMPAT = Path(__file__).resolve().parents[1]


def seed_product_inputs(checkout: Path) -> None:
    """Copy the product inputs outside the product trees into a fixture checkout."""

    if str(COMPAT) not in sys.path:
        sys.path.insert(0, str(COMPAT))
    import source_seal

    for relative in source_seal.product_files(source_seal.ROOT):
        if relative.split("/", 1)[0] not in source_seal.PRODUCT_TREES:
            target = checkout / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_seal.ROOT / relative, target)


def write_compatibility_provenance(product: Path, *, dynamic: bool) -> None:
    metadata = product / "share/crabc"
    metadata.mkdir(parents=True, exist_ok=True)
    entry = "Scrt1.o" if dynamic else "rcrt1.o"
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    (metadata / "crt.provenance.json").write_text(json.dumps({
        "hardening_profile": "compatibility",
        "objects": {entry: {"sha256": digest(product / "usr/lib" / entry)}},
    }))
    if dynamic:
        (metadata / "loader.provenance.json").write_text(json.dumps({
            "cargo": {"rustflags": "-C panic=abort"},
            "artifact": {"path": "lib/ld-crabc-x86_64.so.1",
                         "sha256": digest(product / "lib/ld-crabc-x86_64.so.1")},
        }))
