"""The pinned native x86 core-evidence image identity.

Receipt readers and launchers admit only evidence produced in this image.
Rebuilding the image changes this one value; receipts produced in a
different image are not admitted.
Executing this module prints the immutable Docker ID used for native launches.
"""

CORE_IMAGE_ID = "sha256:6e35810928ea01a472709cbd22d720d98b5367a16143c563d5ef1b70caa0129a"
CORE_IMAGE_REFERENCE = "crabc-core-evidence@" + CORE_IMAGE_ID


if __name__ == "__main__":
    print(CORE_IMAGE_ID)
