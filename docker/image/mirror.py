"""Stage every input of docker/image/sources.lock.json as one OCI artifact layout.

The layout's blobs/sha256/<hex> files are the content-addressed mirror: publish
the layout with `stuff publish oci --layout OUT --repository crabc/image-inputs`
(served at https://oci-blobs.17166969.xyz/sha256/<hex>) and upload the same blob
files, named by their hex digest, to the `image-inputs` release of
joshuarli/crabc. Both URL forms appear in each lock entry before its upstream.

Inputs come from the cache that `build.py --cache DIR fetch` fills; every file
is re-hashed before it is staged.

Usage: mirror.py --cache DIR --out DIR [--lock PATH]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
from pathlib import Path

ARTIFACT_TYPE = "application/vnd.crabc.image-inputs.v1"
EMPTY_CONFIG = b"{}"
EMPTY_CONFIG_TYPE = "application/vnd.oci.empty.v1+json"
INDEX_TYPE = "application/vnd.oci.image.index.v1+json"
LAYER_TYPE = "application/octet-stream"
MANIFEST_TYPE = "application/vnd.oci.image.manifest.v1+json"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def write_blob(blobs: Path, data: bytes) -> str:
    hexdigest = hashlib.sha256(data).hexdigest()
    (blobs / hexdigest).write_bytes(data)
    return hexdigest


def stage(lock: Path, cache: Path, out: Path) -> str:
    inputs = json.loads(lock.read_text(encoding="utf-8"))["inputs"]
    if out.exists():
        raise SystemExit(f"{out} already exists; stage into a new directory")
    blobs = out / "blobs/sha256"
    blobs.mkdir(parents=True)
    layers = {}
    for item in inputs:
        if item["role"] == "builder":
            continue
        source = cache / item["name"] / item["filename"]
        if source.is_symlink() or not source.is_file():
            raise SystemExit(f"{item['name']}: {source} is not a staged regular file")
        if sha256_file(source) != item["sha256"]:
            raise SystemExit(f"{item['name']}: {source} differs from the lock")
        if item["sha256"] in layers:
            continue
        destination = blobs / item["sha256"]
        try:
            os.link(source, destination)
        except OSError:
            shutil.copyfile(source, destination)
        layers[item["sha256"]] = {
            "mediaType": LAYER_TYPE,
            "digest": "sha256:" + item["sha256"],
            "size": source.stat().st_size,
            "annotations": {"org.opencontainers.image.title": item["filename"]},
        }
    config = write_blob(blobs, EMPTY_CONFIG)
    manifest = canonical({
        "schemaVersion": 2,
        "mediaType": MANIFEST_TYPE,
        "artifactType": ARTIFACT_TYPE,
        "config": {"mediaType": EMPTY_CONFIG_TYPE, "digest": "sha256:" + config,
                   "size": len(EMPTY_CONFIG)},
        "layers": [layers[key] for key in sorted(layers)],
    })
    manifest_hex = write_blob(blobs, manifest)
    (out / "oci-layout").write_bytes(canonical({"imageLayoutVersion": "1.0.0"}))
    (out / "index.json").write_bytes(canonical({
        "schemaVersion": 2,
        "mediaType": INDEX_TYPE,
        "manifests": [{"mediaType": MANIFEST_TYPE, "digest": "sha256:" + manifest_hex,
                       "size": len(manifest), "artifactType": ARTIFACT_TYPE}],
    }))
    return manifest_hex


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path,
                        default=Path(__file__).resolve().parent / "sources.lock.json")
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    manifest = stage(args.lock, args.cache, args.out)
    print(f"staged {args.out} manifest sha256:{manifest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
