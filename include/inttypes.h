#ifndef _INTTYPES_H
#define _INTTYPES_H

#if defined(__x86_64__)

#ifdef __cplusplus
extern "C" {
#endif

#include <features.h>
#include <stdint.h>

#define __NEED_wchar_t
#include <bits/alltypes.h>

typedef struct { intmax_t quot, rem; } imaxdiv_t;

intmax_t imaxabs(intmax_t);
imaxdiv_t imaxdiv(intmax_t, intmax_t);

intmax_t strtoimax(const char *__restrict, char **__restrict, int);
uintmax_t strtoumax(const char *__restrict, char **__restrict, int);

intmax_t wcstoimax(const wchar_t *__restrict, wchar_t **__restrict, int);
uintmax_t wcstoumax(const wchar_t *__restrict, wchar_t **__restrict, int);

#if UINTPTR_MAX == UINT64_MAX
#define __PRI64  "l"
#define __PRIPTR "l"
#else
#define __PRI64  "ll"
#define __PRIPTR ""
#endif

#define PRId8  "d"
#define PRId16 "d"
#define PRId32 "d"
#define PRId64 __PRI64 "d"

#define PRIdLEAST8  "d"
#define PRIdLEAST16 "d"
#define PRIdLEAST32 "d"
#define PRIdLEAST64 __PRI64 "d"

#define PRIdFAST8  "d"
#define PRIdFAST16 "d"
#define PRIdFAST32 "d"
#define PRIdFAST64 __PRI64 "d"

#define PRIi8  "i"
#define PRIi16 "i"
#define PRIi32 "i"
#define PRIi64 __PRI64 "i"

#define PRIiLEAST8  "i"
#define PRIiLEAST16 "i"
#define PRIiLEAST32 "i"
#define PRIiLEAST64 __PRI64 "i"

#define PRIiFAST8  "i"
#define PRIiFAST16 "i"
#define PRIiFAST32 "i"
#define PRIiFAST64 __PRI64 "i"

#define PRIo8  "o"
#define PRIo16 "o"
#define PRIo32 "o"
#define PRIo64 __PRI64 "o"

#define PRIoLEAST8  "o"
#define PRIoLEAST16 "o"
#define PRIoLEAST32 "o"
#define PRIoLEAST64 __PRI64 "o"

#define PRIoFAST8  "o"
#define PRIoFAST16 "o"
#define PRIoFAST32 "o"
#define PRIoFAST64 __PRI64 "o"

#define PRIu8  "u"
#define PRIu16 "u"
#define PRIu32 "u"
#define PRIu64 __PRI64 "u"

#define PRIuLEAST8  "u"
#define PRIuLEAST16 "u"
#define PRIuLEAST32 "u"
#define PRIuLEAST64 __PRI64 "u"

#define PRIuFAST8  "u"
#define PRIuFAST16 "u"
#define PRIuFAST32 "u"
#define PRIuFAST64 __PRI64 "u"

#define PRIx8  "x"
#define PRIx16 "x"
#define PRIx32 "x"
#define PRIx64 __PRI64 "x"

#define PRIxLEAST8  "x"
#define PRIxLEAST16 "x"
#define PRIxLEAST32 "x"
#define PRIxLEAST64 __PRI64 "x"

#define PRIxFAST8  "x"
#define PRIxFAST16 "x"
#define PRIxFAST32 "x"
#define PRIxFAST64 __PRI64 "x"

#define PRIX8  "X"
#define PRIX16 "X"
#define PRIX32 "X"
#define PRIX64 __PRI64 "X"

#define PRIXLEAST8  "X"
#define PRIXLEAST16 "X"
#define PRIXLEAST32 "X"
#define PRIXLEAST64 __PRI64 "X"

#define PRIXFAST8  "X"
#define PRIXFAST16 "X"
#define PRIXFAST32 "X"
#define PRIXFAST64 __PRI64 "X"

#define PRIdMAX __PRI64 "d"
#define PRIiMAX __PRI64 "i"
#define PRIoMAX __PRI64 "o"
#define PRIuMAX __PRI64 "u"
#define PRIxMAX __PRI64 "x"
#define PRIXMAX __PRI64 "X"

#define PRIdPTR __PRIPTR "d"
#define PRIiPTR __PRIPTR "i"
#define PRIoPTR __PRIPTR "o"
#define PRIuPTR __PRIPTR "u"
#define PRIxPTR __PRIPTR "x"
#define PRIXPTR __PRIPTR "X"

#define SCNd8   "hhd"
#define SCNd16  "hd"
#define SCNd32  "d"
#define SCNd64  __PRI64 "d"

#define SCNdLEAST8  "hhd"
#define SCNdLEAST16 "hd"
#define SCNdLEAST32 "d"
#define SCNdLEAST64 __PRI64 "d"

#define SCNdFAST8  "hhd"
#define SCNdFAST16 "d"
#define SCNdFAST32 "d"
#define SCNdFAST64 __PRI64 "d"

#define SCNi8   "hhi"
#define SCNi16  "hi"
#define SCNi32  "i"
#define SCNi64  __PRI64 "i"

#define SCNiLEAST8  "hhi"
#define SCNiLEAST16 "hi"
#define SCNiLEAST32 "i"
#define SCNiLEAST64 __PRI64 "i"

#define SCNiFAST8  "hhi"
#define SCNiFAST16 "i"
#define SCNiFAST32 "i"
#define SCNiFAST64 __PRI64 "i"

#define SCNu8   "hhu"
#define SCNu16  "hu"
#define SCNu32  "u"
#define SCNu64  __PRI64 "u"

#define SCNuLEAST8  "hhu"
#define SCNuLEAST16 "hu"
#define SCNuLEAST32 "u"
#define SCNuLEAST64 __PRI64 "u"

#define SCNuFAST8 "hhu"
#define SCNuFAST16 "u"
#define SCNuFAST32 "u"
#define SCNuFAST64 __PRI64 "u"

#define SCNo8   "hho"
#define SCNo16  "ho"
#define SCNo32  "o"
#define SCNo64  __PRI64 "o"

#define SCNoLEAST8  "hho"
#define SCNoLEAST16 "ho"
#define SCNoLEAST32 "o"
#define SCNoLEAST64 __PRI64 "o"

#define SCNoFAST8  "hho"
#define SCNoFAST16 "o"
#define SCNoFAST32 "o"
#define SCNoFAST64 __PRI64 "o"

#define SCNx8   "hhx"
#define SCNx16  "hx"
#define SCNx32  "x"
#define SCNx64  __PRI64 "x"

#define SCNxLEAST8  "hhx"
#define SCNxLEAST16 "hx"
#define SCNxLEAST32 "x"
#define SCNxLEAST64 __PRI64 "x"

#define SCNxFAST8  "hhx"
#define SCNxFAST16 "x"
#define SCNxFAST32 "x"
#define SCNxFAST64 __PRI64 "x"

#define SCNdMAX __PRI64 "d"
#define SCNiMAX __PRI64 "i"
#define SCNoMAX __PRI64 "o"
#define SCNuMAX __PRI64 "u"
#define SCNxMAX __PRI64 "x"

#define SCNdPTR __PRIPTR "d"
#define SCNiPTR __PRIPTR "i"
#define SCNoPTR __PRIPTR "o"
#define SCNuPTR __PRIPTR "u"
#define SCNxPTR __PRIPTR "x"

#ifdef __cplusplus
}
#endif

#else
#include <stdint.h>
#define __NEED_wchar_t
#include <bits/alltypes.h>

typedef struct { intmax_t quot, rem; } imaxdiv_t;

#define PRId8 "d"
#define PRId16 "d"
#define PRId32 "d"
#define PRId64 "ld"
#define PRIdLEAST8 PRId8
#define PRIdLEAST16 PRId16
#define PRIdLEAST32 PRId32
#define PRIdLEAST64 PRId64
#define PRIdFAST8 PRId8
#define PRIdFAST16 PRId64
#define PRIdFAST32 PRId64
#define PRIdFAST64 PRId64
#define PRIdMAX PRId64
#define PRIdPTR PRId64
#define PRIi8 PRId8
#define PRIi16 PRId16
#define PRIi32 PRId32
#define PRIi64 PRId64
#define PRIiLEAST8 PRIi8
#define PRIiLEAST16 PRIi16
#define PRIiLEAST32 PRIi32
#define PRIiLEAST64 PRIi64
#define PRIiFAST8 PRIi8
#define PRIiFAST16 PRIi64
#define PRIiFAST32 PRIi64
#define PRIiFAST64 PRIi64
#define PRIiMAX PRIi64
#define PRIiPTR PRIi64
#define PRIo8 "o"
#define PRIo16 "o"
#define PRIo32 "o"
#define PRIo64 "lo"
#define PRIoLEAST8 PRIo8
#define PRIoLEAST16 PRIo16
#define PRIoLEAST32 PRIo32
#define PRIoLEAST64 PRIo64
#define PRIoFAST8 PRIo8
#define PRIoFAST16 PRIo64
#define PRIoFAST32 PRIo64
#define PRIoFAST64 PRIo64
#define PRIoMAX PRIo64
#define PRIoPTR PRIo64
#define PRIu8 "u"
#define PRIu16 "u"
#define PRIu32 "u"
#define PRIu64 "lu"
#define PRIuLEAST8 PRIu8
#define PRIuLEAST16 PRIu16
#define PRIuLEAST32 PRIu32
#define PRIuLEAST64 PRIu64
#define PRIuFAST8 PRIu8
#define PRIuFAST16 PRIu64
#define PRIuFAST32 PRIu64
#define PRIuFAST64 PRIu64
#define PRIuMAX PRIu64
#define PRIuPTR PRIu64
#define PRIx8 "x"
#define PRIx16 "x"
#define PRIx32 "x"
#define PRIx64 "lx"
#define PRIxLEAST8 PRIx8
#define PRIxLEAST16 PRIx16
#define PRIxLEAST32 PRIx32
#define PRIxLEAST64 PRIx64
#define PRIxFAST8 PRIx8
#define PRIxFAST16 PRIx64
#define PRIxFAST32 PRIx64
#define PRIxFAST64 PRIx64
#define PRIxMAX PRIx64
#define PRIxPTR PRIx64
#define PRIX8 "X"
#define PRIX16 "X"
#define PRIX32 "X"
#define PRIX64 "lX"
#define PRIXLEAST8 PRIX8
#define PRIXLEAST16 PRIX16
#define PRIXLEAST32 PRIX32
#define PRIXLEAST64 PRIX64
#define PRIXFAST8 PRIX8
#define PRIXFAST16 PRIX64
#define PRIXFAST32 PRIX64
#define PRIXFAST64 PRIX64
#define PRIXMAX PRIX64
#define PRIXPTR PRIX64

#define SCNd8 "hhd"
#define SCNd16 "hd"
#define SCNd32 "d"
#define SCNd64 "ld"
#define SCNdLEAST8 SCNd8
#define SCNdLEAST16 SCNd16
#define SCNdLEAST32 SCNd32
#define SCNdLEAST64 SCNd64
#define SCNdFAST8 SCNd8
#define SCNdFAST16 SCNd64
#define SCNdFAST32 SCNd64
#define SCNdFAST64 SCNd64
#define SCNdMAX SCNd64
#define SCNdPTR SCNd64
#define SCNi8 "hhi"
#define SCNi16 "hi"
#define SCNi32 "i"
#define SCNi64 "li"
#define SCNiLEAST8 SCNi8
#define SCNiLEAST16 SCNi16
#define SCNiLEAST32 SCNi32
#define SCNiLEAST64 SCNi64
#define SCNiFAST8 SCNi8
#define SCNiFAST16 SCNi64
#define SCNiFAST32 SCNi64
#define SCNiFAST64 SCNi64
#define SCNiMAX SCNi64
#define SCNiPTR SCNi64
#define SCNo8 "hho"
#define SCNo16 "ho"
#define SCNo32 "o"
#define SCNo64 "lo"
#define SCNoLEAST8 SCNo8
#define SCNoLEAST16 SCNo16
#define SCNoLEAST32 SCNo32
#define SCNoLEAST64 SCNo64
#define SCNoFAST8 SCNo8
#define SCNoFAST16 SCNo64
#define SCNoFAST32 SCNo64
#define SCNoFAST64 SCNo64
#define SCNoMAX SCNo64
#define SCNoPTR SCNo64
#define SCNu8 "hhu"
#define SCNu16 "hu"
#define SCNu32 "u"
#define SCNu64 "lu"
#define SCNuLEAST8 SCNu8
#define SCNuLEAST16 SCNu16
#define SCNuLEAST32 SCNu32
#define SCNuLEAST64 SCNu64
#define SCNuFAST8 SCNu8
#define SCNuFAST16 SCNu64
#define SCNuFAST32 SCNu64
#define SCNuFAST64 SCNu64
#define SCNuMAX SCNu64
#define SCNuPTR SCNu64
#define SCNx8 "hhx"
#define SCNx16 "hx"
#define SCNx32 "x"
#define SCNx64 "lx"
#define SCNxLEAST8 SCNx8
#define SCNxLEAST16 SCNx16
#define SCNxLEAST32 SCNx32
#define SCNxLEAST64 SCNx64
#define SCNxFAST8 SCNx8
#define SCNxFAST16 SCNx64
#define SCNxFAST32 SCNx64
#define SCNxFAST64 SCNx64
#define SCNxMAX SCNx64
#define SCNxPTR SCNx64

#ifdef __cplusplus
extern "C" {
#endif

intmax_t imaxabs(intmax_t);
imaxdiv_t imaxdiv(intmax_t, intmax_t);
intmax_t strtoimax(const char *__restrict, char **__restrict, int);
uintmax_t strtoumax(const char *__restrict, char **__restrict, int);
intmax_t wcstoimax(const wchar_t *__restrict, wchar_t **__restrict, int);
uintmax_t wcstoumax(const wchar_t *__restrict, wchar_t **__restrict, int);

#ifdef __cplusplus
}
#endif

#endif

#endif
