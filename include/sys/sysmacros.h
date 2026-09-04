#if defined(__x86_64__)
#ifndef _SYS_SYSMACROS_H
#define _SYS_SYSMACROS_H

#define major(x) \
	((unsigned)( (((x)>>31>>1) & 0xfffff000) | (((x)>>8) & 0x00000fff) ))
#define minor(x) \
	((unsigned)( (((x)>>12) & 0xffffff00) | ((x) & 0x000000ff) ))

#define makedev(x,y) ( \
        (((x)&0xfffff000ULL) << 32) | \
	(((x)&0x00000fffULL) << 8) | \
        (((y)&0xffffff00ULL) << 12) | \
	(((y)&0x000000ffULL)) )

#endif
#else
#ifndef _CRABC_SYS_SYSMACROS_H
#define _CRABC_SYS_SYSMACROS_H

#define major(value) ((unsigned)((((value) >> 31 >> 1) & 0xfffff000) | (((value) >> 8) & 0x00000fff)))
#define minor(value) ((unsigned)((((value) >> 12) & 0xffffff00) | ((value) & 0x000000ff)))
#define makedev(major_value, minor_value) \
    ((((major_value) & 0xfffff000ULL) << 32) | (((major_value) & 0x00000fffULL) << 8) | \
     (((minor_value) & 0xffffff00ULL) << 12) | ((minor_value) & 0x000000ffULL))

#endif
#endif
