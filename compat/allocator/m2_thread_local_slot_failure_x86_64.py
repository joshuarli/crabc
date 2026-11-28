#!/usr/bin/env python3
"""Compare pinned regular thread-local slot growth failure with Rust Heap Theaps."""

import m2_direct_receiver


if __name__ == "__main__":
    m2_direct_receiver.main("thread-local-slot-failure-c-rust-differential", __doc__)
