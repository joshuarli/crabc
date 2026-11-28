"""The pinned native core-evidence image identities, per architecture.

Receipt readers and launchers admit only evidence produced in the image
pinned for its architecture. Rebuilding an image changes these values;
receipts produced in a different image are not admitted.
Executing this module prints the immutable Docker ID of one architecture:
`core_image.py [x86_64|aarch64]`; no argument selects x86_64.
"""

CORE_IMAGE_ID = "sha256:b243d937bf906259565a2e3e1b4162a6d1162a5209405995b12a62a9beccd394"
CORE_IMAGE_REFERENCE = "crabc-core-evidence@" + CORE_IMAGE_ID
AARCH64_CORE_IMAGE_ID = "sha256:7b7cd03d19a2e65ea35addb5358bcb849dd935e8cb717581e42233356d40d683"

_IMAGE_IDS = {"x86_64": CORE_IMAGE_ID, "aarch64": AARCH64_CORE_IMAGE_ID}


def core_image_id(architecture: str) -> str:
    try:
        return _IMAGE_IDS[architecture]
    except KeyError:
        raise SystemExit(f"unknown core-image architecture: {architecture!r} (expected x86_64 or aarch64)")


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 2:
        raise SystemExit("usage: core_image.py [x86_64|aarch64]")
    print(core_image_id(sys.argv[1] if len(sys.argv) == 2 else "x86_64"))
