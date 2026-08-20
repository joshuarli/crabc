#ifndef _CRABC_STDALIGN_H
#define _CRABC_STDALIGN_H

#ifndef __cplusplus
#if __STDC_VERSION__ < 201112L && defined(__GNUC__)
#define _Alignas(type) __attribute__((__aligned__(type)))
#define _Alignof(type) __alignof__(type)
#endif
#define alignas _Alignas
#define alignof _Alignof
#endif
#define __alignas_is_defined 1
#define __alignof_is_defined 1

#endif
