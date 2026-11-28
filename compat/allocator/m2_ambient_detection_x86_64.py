#!/usr/bin/env python3
"""Compare pinned process-start ambient memory detection with Rust startup."""

import m2_direct_receiver


if __name__ == "__main__":
    m2_direct_receiver.main("ambient-memory-detection-c-rust-differential", __doc__)
