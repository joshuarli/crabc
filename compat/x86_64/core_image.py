"""The pinned native x86 core-evidence image identity.

Receipt readers and launchers admit only evidence produced in this image.
Rebuilding the image changes this one value; receipts retained from an
earlier image are then historical, not current evidence.
"""

CORE_IMAGE_ID = "sha256:307d75f06680c631437f9faa5f7c726613fcea6f1875dda8cf368ad4b6da1b3d"
CORE_IMAGE_REFERENCE = "crabc-core-evidence@" + CORE_IMAGE_ID
