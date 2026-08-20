#ifndef _CRABC_SYS_SYSMACROS_H
#define _CRABC_SYS_SYSMACROS_H

#define major(value) ((unsigned)((((value) >> 31 >> 1) & 0xfffff000) | (((value) >> 8) & 0x00000fff)))
#define minor(value) ((unsigned)((((value) >> 12) & 0xffffff00) | ((value) & 0x000000ff)))
#define makedev(major_value, minor_value) \
    ((((major_value) & 0xfffff000ULL) << 32) | (((major_value) & 0x00000fffULL) << 8) | \
     (((minor_value) & 0xffffff00ULL) << 12) | ((minor_value) & 0x000000ffULL))

#endif
