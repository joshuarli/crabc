"""The pinned native x86 core-evidence image identity.

Receipt readers and launchers admit only evidence produced in this image.
Rebuilding the image changes this one value; receipts produced in a
different image are not admitted.
Executing this module prints the immutable Docker ID used for native launches.
"""

CORE_IMAGE_ID = "sha256:8585153fd2b5af9efb1d957afdb63ce97ded5f8471b6aa6a9b3b0aa19649fa34"
CORE_IMAGE_REFERENCE = "crabc-core-evidence@" + CORE_IMAGE_ID


if __name__ == "__main__":
    print(CORE_IMAGE_ID)
