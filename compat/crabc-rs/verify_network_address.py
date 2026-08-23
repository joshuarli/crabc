#!/usr/bin/env python3
"""Verify that network-value and Ethernet codecs stay off the C ABI."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


# These probes must remain entirely in the native value layer. In particular,
# the Ethernet codec may not regress to any of the four C codec entry points,
# a neighboring C address/database helper, a byte-order/inet adapter, the
# allocator, or TLS errno. Generic compiler lowering such as memcpy is not
# listed: it is not evidence of a public libc call by this facade.
FORBIDDEN_SYMBOLS = (
    "htonl", "htons", "ntohl", "ntohs", "inet_addr", "inet_aton", "inet_ntoa",
    "inet_lnaof", "inet_makeaddr", "inet_netof", "inet_network",
    "inet_ntop", "inet_pton", "strtoul", "strtoul_l", "sprintf", "snprintf", "ether_aton", "ether_aton_r", "ether_ntoa", "ether_ntoa_r",
    "ether_hostton", "ether_line", "ether_ntohost", "getifaddrs", "freeifaddrs",
    "if_nameindex", "if_freenameindex", "__errno_location",
    "malloc", "calloc", "realloc", "free", "malloc_usable_size",
)


@dataclass(frozen=True)
class Probe:
    """One pure-native network value probe."""

    archive: str
    entrypoint: str


PROBES = {
    "network-address": Probe(
        "libnetwork_address_direct_probe.a",
        "crabc_rs_network_address_direct_probe",
    ),
    "ipaddr": Probe(
        "libnetwork_ipaddr_direct_probe.a",
        "crabc_rs_network_ipaddr_direct_probe",
    ),
    "ipv4-legacy": Probe(
        "libipv4_legacy_direct_probe.a",
        "crabc_rs_ipv4_legacy_direct_probe",
    ),
    "ipv4-classful": Probe(
        "libipv4_classful_direct_probe.a",
        "crabc_rs_ipv4_classful_direct_probe",
    ),
    "ethernet-address": Probe(
        "libethernet_address_direct_probe.a",
        "crabc_rs_ethernet_address_direct_probe",
    ),
    "ethers": Probe(
        "libethers_direct_probe.a",
        "crabc_rs_ethers_direct_probe",
    ),
}


class VerificationError(ValueError):
    """The fixture does not demonstrate the native network-order contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def tool_output(command: Sequence[str]) -> str:
    result = subprocess.run(command, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        stderr = result.stderr.decode("utf-8", "replace").strip()
        raise VerificationError(f"tool failed ({' '.join(command)}): {stderr}")
    return result.stdout.decode("utf-8", "replace")


def has_symbol(symbols: str, name: str) -> bool:
    return bool(re.search(rf"\b{re.escape(name)}(?:@[^\s]+)?\b", symbols))


def inspect(probe: Probe, readelf: str, undefined_symbols: str, defined_symbols: str) -> dict[str, object]:
    require("AArch64" in readelf, "fixture is not an AArch64 ELF archive member")
    require(
        probe.entrypoint in defined_symbols,
        "fixture does not define the required network probe entry point",
    )
    forbidden = tuple(name for name in FORBIDDEN_SYMBOLS if has_symbol(undefined_symbols, name))
    require(not forbidden, "fixture references forbidden C network/errno symbol(s): " + ", ".join(forbidden))
    return {"machine": "AArch64", "direct_native": True, "forbidden_symbols": []}


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("probe", choices=tuple(PROBES), nargs="?", default="network-address")
    parser.add_argument("--target-dir", type=Path, default=Path("target"))
    parser.add_argument("--readelf", default="llvm-readelf")
    parser.add_argument("--nm", default="llvm-nm")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    probe = PROBES[args.probe]
    archive = args.target_dir / "release" / "examples" / probe.archive
    try:
        require(archive.is_file(), f"{args.probe} probe archive does not exist: {archive}")
        report = inspect(
            probe,
            tool_output((args.readelf, "--file-header", str(archive))),
            tool_output((args.nm, "--undefined-only", str(archive))),
            tool_output((args.nm, "--defined-only", str(archive))),
        )
        print(f"native {args.probe} proof: PASS ({archive}) {report}")
    except VerificationError as error:
        print(f"native {args.probe} proof: ERROR: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
