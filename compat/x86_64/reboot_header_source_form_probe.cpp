// Direct pinned-musl x86 <sys/reboot.h> public-source and C-linkage assertions.
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

static_assert(RB_AUTOBOOT == 0x01234567);
static_assert(RB_HALT_SYSTEM == 0xcdef0123);
static_assert(RB_ENABLE_CAD == 0x89abcdef);
static_assert(RB_DISABLE_CAD == 0);
static_assert(RB_POWER_OFF == 0x4321fedc);
static_assert(RB_SW_SUSPEND == 0xd000fce2);
static_assert(RB_KEXEC == 0x45584543);
static_assert(__is_same(decltype(&reboot), int (*)(int)));

extern "C" int crabc_x86_reboot_header_source_form_probe_cpp(void)
{
    return reboot(RB_DISABLE_CAD);
}
