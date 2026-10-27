from enum import Enum


class NativeRuntimeProfile(str, Enum):
    COMPATIBILITY = "compatibility"
    HARDENED = "hardened"

    @property
    def interpreter(self) -> str:
        if self is NativeRuntimeProfile.HARDENED:
            return "/lib/ld-crabc-x86_64-hardened.so.1"
        return "/lib/ld-crabc-x86_64.so.1"

    @property
    def aliases(self) -> dict[str, str]:
        if self is NativeRuntimeProfile.HARDENED:
            return {}
        return {"lib/ld-musl-x86_64.so.1": "ld-crabc-x86_64.so.1"}

    @property
    def combined_modes(self) -> tuple[str, ...]:
        if self is NativeRuntimeProfile.HARDENED:
            return ("static-pie", "dynamic-pie", "dynamic-shared-object")
        return ("static-et-exec", "static-pie", "dynamic-pie", "dynamic-non-pie", "dynamic-shared-object")
