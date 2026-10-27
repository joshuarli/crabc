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
        dynamic = ("dynamic-pie", "dynamic-shared-object") if self is NativeRuntimeProfile.HARDENED else (
            "dynamic-pie", "dynamic-non-pie", "dynamic-shared-object")
        return tuple(mode["id"] for mode in self.static_modes) + dynamic

    @property
    def static_modes(self) -> list[dict[str, str]]:
        modes = ([{"id": "static-et-exec", "elf_type": "ET_EXEC", "crt_object": "crt1.o"}]
                 if self is NativeRuntimeProfile.COMPATIBILITY else [])
        return modes + [{"id": "static-pie", "elf_type": "ET_DYN", "crt_object": "rcrt1.o"}]
