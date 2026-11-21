from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from compat.x86_64.native_arch import native_arch


KACHE = Path("/usr/local/bin/kache")
MOLD = Path("/usr/bin/mold")
ARCHITECTURE = native_arch()
CARGO_LINKER = Path(ARCHITECTURE["linker"])


def environment() -> dict[str, str]:
    return {
        "RUSTC_WRAPPER": str(KACHE),
        "KACHE_CONFIG": "/dev/null",
        "KACHE_HOST_CONFIG": "",
        "KACHE_LOCAL_ONLY": "1",
        "KACHE_CACHE_DIR": f"/workspace/.work/{ARCHITECTURE['work_name']}/kache",
        "KACHE_AUTO_CLEAN_ORPHANED_TARGETS": "0",
        "KACHE_AUTO_CLEAN_UNUSED_UNITS_DAYS": "0",
        "KACHE_AUTO_SHARE_TARGET_FILES": "0",
        "KACHE_SEED_NEW_TARGETS": "0",
        ARCHITECTURE["linker_variable"]: str(CARGO_LINKER),
    }


def compile_command(compiler: Path) -> list[str]:
    if not compiler.is_absolute() or compiler.name != "rustc" or compiler.parent.name != "bin" or compiler.parent.parent.parent != Path("/opt/rustup/toolchains"):
        raise ValueError("native compilation requires the physical image-owned pinned rustc")
    return [str(KACHE), str(compiler)]
