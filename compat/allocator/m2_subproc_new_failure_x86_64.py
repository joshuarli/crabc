#!/usr/bin/env python3
"""Compare pinned mi_subproc_new failure cleanup with Rust child creation."""

import m2_direct_receiver


if __name__ == "__main__":
    m2_direct_receiver.main("subproc-new-failure-cleanup-c-rust-differential", __doc__)
