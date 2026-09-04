/* Direct syslog declaration and SYSLOG_NAMES consumer; compiled as C and C++. */
#include CRABC_SYSLOG_HEADER

#ifdef __cplusplus
#define CHECK static_assert
extern "C" {
#else
#define CHECK _Static_assert
#endif
void closelog(void);
void openlog(const char *, int, int);
int setlogmask(int);
void syslog(int, const char *, ...);
#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
void vsyslog(int, const char *, va_list);
#endif
#ifdef __cplusplus
}
#endif

CHECK(LOG_MASK(LOG_DEBUG) == 128, "debug mask");
CHECK(LOG_UPTO(LOG_DEBUG) == 255, "all priorities mask");
CHECK(LOG_PRI(LOG_MAKEPRI(LOG_LOCAL7, LOG_WARNING)) == LOG_WARNING,
    "priority extraction");
CHECK(LOG_FAC(LOG_MAKEPRI(LOG_LOCAL7, LOG_WARNING)) == 23,
    "facility extraction");

#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#ifndef _PATH_LOG
#error "GNU and BSD expose the conventional log socket path"
#endif
#if defined(SYSLOG_NAMES)
/* Read the first and sentinel records without retaining compound-literal pointers. */
int crabc_syslog_names(void)
{
    CODE priority = prioritynames[0];
    CODE facility = facilitynames[0];
    CODE priority_end = prioritynames[12];
    CODE facility_end = facilitynames[22];
    return priority.c_val == LOG_ALERT && facility.c_val == LOG_AUTH &&
        priority.c_name[0] == 'a' && facility.c_name[0] == 'a' &&
        priority_end.c_name == 0 && priority_end.c_val == -1 &&
        facility_end.c_name == 0 && facility_end.c_val == -1;
}
#endif
#else
#ifdef _PATH_LOG
#error "strict/POSIX/XOPEN profiles hide the log socket path"
#endif
#endif

#if !defined(SYSLOG_NAMES) || (!defined(_GNU_SOURCE) && !defined(_BSD_SOURCE))
#if defined(prioritynames) || defined(facilitynames) || defined(INTERNAL_NOPRI) || defined(INTERNAL_MARK)
#error "name tables require both SYSLOG_NAMES and GNU/BSD"
#endif
#endif

/* Object references prove that the C++ declarations retain C symbol spelling. */
void (*crabc_syslog_close)(void) = closelog;
void (*crabc_syslog_open)(const char *, int, int) = openlog;
int (*crabc_syslog_mask)(int) = setlogmask;
void (*crabc_syslog_log)(int, const char *, ...) = syslog;

#if defined(CRABC_REQUIRE_NAMES_HIDDEN)
CODE crabc_syslog_names_must_be_hidden;
#endif
