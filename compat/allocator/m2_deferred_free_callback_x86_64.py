#!/usr/bin/env python3
"""Compare the pinned deferred-free callback timing probe with the Rust owner phases."""

import m2_direct_receiver


if __name__ == "__main__":
    m2_direct_receiver.main("deferred-free-callback-c-rust-differential", __doc__)
