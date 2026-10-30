"""The pinned native x86 core-evidence image identity.

Receipt readers and launchers admit only evidence produced in this image.
Rebuilding the image changes this one value; receipts produced in a
different image are not admitted.
Executing this module prints the immutable Docker ID used for native launches.
"""

CORE_IMAGE_ID = "sha256:3b9dcd3ee4ebd33a11fd4b0479fe557c9d737287c5eeaf948f7b347a6445a342"
CORE_IMAGE_REFERENCE = "crabc-core-evidence@" + CORE_IMAGE_ID


if __name__ == "__main__":
    print(CORE_IMAGE_ID)
