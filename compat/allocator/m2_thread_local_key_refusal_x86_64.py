#!/usr/bin/env python3
"""Compare pinned thread-local key bitmap refusal with Rust Heap key ownership."""

import m2_direct_receiver


if __name__ == "__main__":
    m2_direct_receiver.main("thread-local-key-bitmap-refusal-c-rust-differential", __doc__)
