"""The pinned native core-evidence image identities, per architecture.

Receipt readers and launchers admit only evidence produced in the image
pinned for its architecture. Rebuilding an image changes these values;
receipts produced in a different image are not admitted.
Executing this module prints the immutable Docker ID of one architecture:
`core_image.py [x86_64|aarch64]`; no argument selects x86_64.
"""

CORE_IMAGE_ID = "sha256:6610b2866d1794275adae0c08b17c0b4dcedcfa8d55009541df641aefe76efa5"
CORE_IMAGE_REFERENCE = "crabc-core-evidence@" + CORE_IMAGE_ID
AARCH64_CORE_IMAGE_ID = "sha256:2c1a6c7425e9c1216e8a61b02efcc0216602d437bc00d234e03575207970d550"

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
