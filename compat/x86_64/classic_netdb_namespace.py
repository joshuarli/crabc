#!/usr/bin/env python3
"""Legacy fixed classic-netdb entry; shared DNS mechanics live in resolver_namespace."""
from pathlib import Path
from resolver_namespace import run_leaf

if __name__ == '__main__':
    run_leaf(Path(__file__).resolve().parent / 'run_owned_classic_netdb.sh')
