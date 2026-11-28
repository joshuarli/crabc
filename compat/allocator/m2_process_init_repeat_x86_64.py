#!/usr/bin/env python3
"""Compare pinned repeated explicit process initialization with the native runtime entry."""

import m2_direct_receiver


if __name__ == "__main__":
    m2_direct_receiver.main("initialization-repeated-native-process-init-c-rust-differential", __doc__)
