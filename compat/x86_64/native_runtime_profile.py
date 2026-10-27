from enum import Enum


class NativeRuntimeProfile(str, Enum):
    COMPATIBILITY = "compatibility"
    HARDENED = "hardened"
