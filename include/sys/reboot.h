#ifndef _SYS_REBOOT_H
#define _SYS_REBOOT_H

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__x86_64__) /* pinned-musl form; the AArch64 branch stays frozen */
#define RB_AUTOBOOT     0x01234567
#define RB_HALT_SYSTEM  0xcdef0123
#define RB_ENABLE_CAD   0x89abcdef
#define RB_DISABLE_CAD  0
#define RB_POWER_OFF    0x4321fedc
#define RB_SW_SUSPEND   0xd000fce2
#define RB_KEXEC        0x45584543

#else

#define LINUX_REBOOT_MAGIC1  0xfee1dead
#define LINUX_REBOOT_MAGIC2  672274793
#define LINUX_REBOOT_MAGIC2A 85072278
#define LINUX_REBOOT_MAGIC2B 369367448
#define LINUX_REBOOT_MAGIC2C 537993216

#define LINUX_REBOOT_CMD_RESTART   0x01234567
#define LINUX_REBOOT_CMD_HALT      0xCDEF0123
#define LINUX_REBOOT_CMD_CAD_ON    0x89ABCDEF
#define LINUX_REBOOT_CMD_CAD_OFF   0x00000000
#define LINUX_REBOOT_CMD_POWER_OFF 0x4321FEDC
#define LINUX_REBOOT_CMD_RESTART2  0xA1B2C3D4
#define LINUX_REBOOT_CMD_SW_SUSPEND 0xD000FCE2
#define LINUX_REBOOT_CMD_KEXEC      0x45584543

/* musl's public names for the same Linux reboot command values. */
#define RB_AUTOBOOT     LINUX_REBOOT_CMD_RESTART
#define RB_HALT_SYSTEM  LINUX_REBOOT_CMD_HALT
#define RB_ENABLE_CAD   LINUX_REBOOT_CMD_CAD_ON
#define RB_DISABLE_CAD  LINUX_REBOOT_CMD_CAD_OFF
#define RB_POWER_OFF    LINUX_REBOOT_CMD_POWER_OFF
#define RB_SW_SUSPEND   LINUX_REBOOT_CMD_SW_SUSPEND
#define RB_KEXEC        LINUX_REBOOT_CMD_KEXEC

#endif

int reboot(int);

#ifdef __cplusplus
}
#endif

#endif
