import hashlib
import json
from pathlib import Path


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
