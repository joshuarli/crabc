"""The pinned native x86 core-evidence image identity.

Receipt readers and launchers admit only evidence produced in this image.
Rebuilding the image changes this one value; receipts produced in a
different image are not admitted.
Executing this module prints the immutable Docker ID used for native launches.
"""

CORE_IMAGE_ID = "sha256:8db4261ed9a1ffe5c973f090d7b339796099e7447c5dcddf6d1f015548dda3a6"
CORE_IMAGE_REFERENCE = "crabc-core-evidence@" + CORE_IMAGE_ID


if __name__ == "__main__":
    print(CORE_IMAGE_ID)
