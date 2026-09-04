/*
 * Direct pinned-musl x86 <sys/reboot.h> public-source assertions.  No
 * convenience header participates: this header itself owns the complete
 * reboot command vocabulary and the C declaration.
 */
#include <sys/reboot.h>

#if defined(LINUX_REBOOT_MAGIC1) || defined(LINUX_REBOOT_MAGIC2) || \
    defined(LINUX_REBOOT_MAGIC2A) || defined(LINUX_REBOOT_MAGIC2B) || \
    defined(LINUX_REBOOT_MAGIC2C) || defined(LINUX_REBOOT_CMD_RESTART) || \
    defined(LINUX_REBOOT_CMD_HALT) || defined(LINUX_REBOOT_CMD_CAD_ON) || \
    defined(LINUX_REBOOT_CMD_CAD_OFF) || \
    defined(LINUX_REBOOT_CMD_POWER_OFF) || \
    defined(LINUX_REBOOT_CMD_RESTART2) || \
    defined(LINUX_REBOOT_CMD_SW_SUSPEND) || defined(LINUX_REBOOT_CMD_KEXEC)
#error "<sys/reboot.h> must not leak Linux-private reboot macro names"
#endif

_Static_assert(RB_AUTOBOOT == 0x01234567, "RB_AUTOBOOT spelling");
_Static_assert(RB_HALT_SYSTEM == 0xcdef0123, "RB_HALT_SYSTEM spelling");
_Static_assert(RB_ENABLE_CAD == 0x89abcdef, "RB_ENABLE_CAD spelling");
_Static_assert(RB_DISABLE_CAD == 0, "RB_DISABLE_CAD spelling");
_Static_assert(RB_POWER_OFF == 0x4321fedc, "RB_POWER_OFF spelling");
_Static_assert(RB_SW_SUSPEND == 0xd000fce2, "RB_SW_SUSPEND spelling");
_Static_assert(RB_KEXEC == 0x45584543, "RB_KEXEC spelling");
_Static_assert(__builtin_types_compatible_p(__typeof__(&reboot), int (*)(int)),
    "reboot declaration");

int crabc_x86_reboot_header_source_form_probe(void)
{
    return RB_AUTOBOOT == 0x01234567 ? 0 : 1;
}
