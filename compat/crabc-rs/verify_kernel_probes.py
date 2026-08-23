#!/usr/bin/env python3
"""Verify direct AArch64 syscall evidence for kernel-native probes."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


@dataclass(frozen=True)
class Probe:
    archive: str
    entrypoint: str
    syscalls: dict[int, str]
    forbidden_symbols: tuple[str, ...]


INTERFACE_NAMES_C_ABI_FORBIDDEN = (
    # The proof must show the netlink transaction itself, rather than a call
    # through either C enumeration entry point or a neighboring libc
    # address/database helper.
    "if_nameindex", "if_freenameindex", "if_nametoindex", "if_indextoname",
    "getifaddrs", "freeifaddrs",
    "inet_addr", "inet_aton", "inet_ntoa", "inet_ntop", "inet_pton",
    "inet_lnaof", "inet_makeaddr", "inet_netof", "inet_network",
    "htonl", "htons", "ntohl", "ntohs",
    "ether_aton", "ether_aton_r", "ether_ntoa", "ether_ntoa_r",
    "ether_hostton", "ether_line", "ether_ntohost",
    "malloc", "calloc", "realloc", "reallocarray", "free",
    "aligned_alloc", "posix_memalign", "memalign", "malloc_usable_size",
    "socket", "sendto", "recvfrom", "close", "__errno_location",
)

# The owned address snapshot is a different native API from the interface-name
# stream, but its proof has the same public-C boundary: the private fixed
# allocator in the probe is allowed; libc allocation and every C netlink/
# address helper remain forbidden.
INTERFACE_ADDRESSES_C_ABI_FORBIDDEN = INTERFACE_NAMES_C_ABI_FORBIDDEN


PROBES = {
    "fs-metadata": Probe(
        "libfs_metadata_direct_probe.a",
        "crabc_rs_fs_metadata_direct_probe",
        {43: "statfs", 44: "fstatfs"},
        ("statfs", "fstatfs", "statvfs", "fstatvfs", "open", "openat", "__errno_location"),
    ),
    "fs-canonicalize": Probe(
        "libfs_canonicalize_direct_probe.a",
        "crabc_rs_fs_canonicalize_direct_probe",
        {17: "getcwd", 56: "openat", 78: "readlinkat"},
        ("realpath", "canonicalize", "open", "openat", "readlink", "readlinkat", "getcwd", "__errno_location"),
    ),
    "fs-tempdir": Probe(
        "libfs_tempdir_direct_probe.a",
        "crabc_rs_fs_tempdir_direct_probe",
        {34: "mkdirat", 35: "unlinkat", 56: "openat", 57: "close", 278: "getrandom"},
        ("mkdtemp", "mkdir", "mkdirat", "getrandom", "open", "openat", "unlink", "unlinkat", "close", "__errno_location"),
    ),
    "fs-tempfile": Probe(
        "libfs_tempfile_direct_probe.a",
        "crabc_rs_fs_tempfile_direct_probe",
        {56: "openat", 57: "close", 62: "lseek", 63: "read", 64: "write"},
        ("mkstemp", "mkostemp", "tmpfile", "open", "openat", "read", "write", "lseek", "close", "__errno_location"),
    ),
    "fs-named-tempfile": Probe(
        "libfs_named_tempfile_direct_probe.a",
        "crabc_rs_fs_named_tempfile_direct_probe",
        {25: "fcntl", 35: "unlinkat", 56: "openat", 57: "close", 278: "getrandom"},
        ("mkstemp", "mkostemp", "mkstemps", "mkostemps", "tmpfile", "open", "openat", "fcntl", "unlink", "unlinkat", "getrandom", "close", "__errno_location"),
    ),
    "statx": Probe(
        "libstatx_direct_probe.a",
        "crabc_rs_statx_direct_probe",
        {291: "statx"},
        ("statx", "fstatat", "stat", "open", "openat", "__errno_location"),
    ),
    "positioned": Probe(
        "libpositioned_direct_probe.a",
        "crabc_rs_positioned_direct_probe",
        {67: "pread64", 68: "pwrite64"},
        ("pread", "pwrite", "pread64", "pwrite64", "open", "openat", "ftruncate", "read", "write", "lseek", "__errno_location"),
    ),
    "vectored": Probe(
        "libvectored_direct_probe.a",
        "crabc_rs_vectored_direct_probe",
        {65: "readv", 66: "writev"},
        ("readv", "writev", "read", "write", "fread", "fwrite", "open", "openat", "__errno_location"),
    ),
    "positioned-vectored": Probe(
        "libpositioned_vectored_direct_probe.a",
        "crabc_rs_positioned_vectored_direct_probe",
        {69: "preadv", 70: "pwritev"},
        ("preadv", "pwritev", "pread", "pwrite", "readv", "writev", "read", "write", "open", "openat", "__errno_location"),
    ),
    "directory": Probe(
        "libdirectory_direct_probe.a",
        "crabc_rs_directory_direct_probe",
        {56: "openat", 61: "getdents64"},
        ("opendir", "fdopendir", "readdir", "closedir", "scandir", "open", "openat", "getdents", "__errno_location"),
    ),
    "directory-position": Probe(
        "libdirectory_position_direct_probe.a",
        "crabc_rs_directory_position_direct_probe",
        {56: "openat", 61: "getdents64", 62: "lseek"},
        ("opendir", "fdopendir", "readdir", "closedir", "rewinddir", "seekdir", "scandir", "open", "openat", "getdents", "lseek", "__errno_location"),
    ),
    "pipe-tee": Probe(
        "libpipe_tee_direct_probe.a",
        "crabc_rs_pipe_tee_direct_probe",
        {59: "pipe2", 63: "read", 64: "write", 77: "tee"},
        ("tee", "splice", "vmsplice", "pipe", "pipe2", "read", "write", "open", "openat", "__errno_location"),
    ),
    "descriptor": Probe(
        "libdescriptor_direct_probe.a",
        "crabc_rs_descriptor_direct_probe",
        {25: "fcntl", 57: "close", 59: "pipe2", 62: "lseek", 63: "read", 64: "write", 75: "vmsplice", 76: "splice"},
        ("close", "posix_close", "lockf", "fcntl", "splice", "vmsplice", "tee", "lseek", "__errno_location"),
    ),
    "pipe-size": Probe(
        "libpipe_size_direct_probe.a",
        "crabc_rs_pipe_size_direct_probe",
        {25: "fcntl", 57: "close", 59: "pipe2"},
        ("fcntl", "tee", "splice", "vmsplice", "pipe", "pipe2", "open", "openat", "__errno_location"),
    ),
    "fcntl-seals": Probe(
        "libfcntl_seals_direct_probe.a",
        "crabc_rs_fcntl_seals_direct_probe",
        {25: "fcntl", 57: "close", 279: "memfd_create"},
        ("fcntl", "memfd_create", "open", "openat", "fopen", "__errno_location"),
    ),
    "fcntl-add-seals": Probe(
        "libfcntl_add_seals_direct_probe.a",
        "crabc_rs_fcntl_add_seals_direct_probe",
        {25: "fcntl", 57: "close", 279: "memfd_create"},
        ("fcntl", "memfd_create", "open", "openat", "fopen", "__errno_location"),
    ),
    "fcntl-getlk": Probe(
        "libfcntl_getlk_direct_probe.a",
        "crabc_rs_fcntl_getlk_direct_probe",
        {25: "fcntl", 57: "close", 279: "memfd_create"},
        ("fcntl", "lockf", "memfd_create", "open", "openat", "fopen", "__errno_location"),
    ),
    "memfd": Probe(
        "libmemfd_direct_probe.a",
        "crabc_rs_memfd_direct_probe",
        {279: "memfd_create"},
        ("memfd_create", "open", "openat", "fopen", "__errno_location"),
    ),
    "ppoll": Probe(
        "libppoll_direct_probe.a",
        "crabc_rs_ppoll_direct_probe",
        {73: "ppoll"},
        ("ppoll", "poll", "pselect", "select", "epoll_wait", "__errno_location"),
    ),
    "pause": Probe(
        "libpause_direct_probe.a",
        "crabc_rs_pause_direct_probe",
        {73: "ppoll"},
        ("pause", "ppoll", "poll", "__errno_location"),
    ),
    "readiness": Probe(
        "libreadiness_direct_probe.a",
        "crabc_rs_readiness_direct_probe",
        {20: "epoll_create1", 21: "epoll_ctl", 22: "epoll_pwait", 59: "pipe2", 72: "pselect6"},
        (
            "epoll_create",
            "epoll_create1",
            "epoll_ctl",
            "epoll_wait",
            "epoll_pwait",
            "pselect",
            "select",
            "poll",
            "ppoll",
            "__errno_location",
        ),
    ),
    "sleep": Probe(
        "libsleep_direct_probe.a",
        "crabc_rs_sleep_direct_probe",
        {101: "nanosleep"},
        ("nanosleep", "sleep", "usleep", "clock_nanosleep", "__errno_location"),
    ),
    "clock-sleep": Probe(
        "libclock_nanosleep_direct_probe.a",
        "crabc_rs_clock_nanosleep_direct_probe",
        {115: "clock_nanosleep"},
        ("clock_nanosleep", "nanosleep", "sleep", "usleep", "__errno_location"),
    ),
    "madvise": Probe(
        "libmadvise_direct_probe.a",
        "crabc_rs_madvise_direct_probe",
        {222: "mmap", 233: "madvise", 215: "munmap"},
        ("madvise", "posix_madvise", "mmap", "munmap", "__errno_location"),
    ),
    "memory-vm": Probe(
        "libmemory_vm_direct_probe.a",
        "crabc_rs_memory_vm_direct_probe",
        {
            214: "brk",
            215: "munmap",
            222: "mmap",
            230: "mlockall",
            231: "munlockall",
            233: "madvise",
            234: "remap_file_pages",
        },
        (
            "brk",
            "sbrk",
            "mlockall",
            "munlockall",
            "madvise",
            "posix_madvise",
            "remap_file_pages",
            "mmap",
            "munmap",
            "__errno_location",
        ),
    ),
    "identity": Probe(
        "libidentity_direct_probe.a",
        "crabc_rs_identity_direct_probe",
        {148: "getresuid", 150: "getresgid", 174: "getuid", 175: "geteuid", 176: "getgid", 177: "getegid"},
        ("getresuid", "getresgid", "getuid", "geteuid", "getgid", "getegid", "__errno_location"),
    ),
    "fallocate": Probe(
        "libfallocate_direct_probe.a",
        "crabc_rs_fallocate_direct_probe",
        {47: "fallocate"},
        ("fallocate", "posix_fallocate", "ftruncate", "open", "openat", "__errno_location"),
    ),
    "syncfs": Probe(
        "libsyncfs_direct_probe.a",
        "crabc_rs_syncfs_direct_probe",
        {267: "syncfs"},
        ("syncfs", "fsync", "fdatasync", "open", "openat", "__errno_location"),
    ),
    "rlimit": Probe(
        "librlimit_direct_probe.a",
        "crabc_rs_rlimit_direct_probe",
        {261: "prlimit64"},
        ("getrlimit", "setrlimit", "prlimit", "prlimit64", "__errno_location"),
    ),
    "rlimit-for": Probe(
        "librlimit_for_direct_probe.a",
        "crabc_rs_rlimit_for_direct_probe",
        {261: "prlimit64"},
        ("getrlimit", "setrlimit", "prlimit", "prlimit64", "__errno_location"),
    ),
    "process-limits-umask": Probe(
        "libprocess_limits_umask_direct_probe.a",
        "crabc_rs_process_limits_umask_direct_probe",
        {166: "umask", 261: "prlimit64"},
        ("umask", "getrlimit", "setrlimit", "prlimit", "prlimit64", "__errno_location"),
    ),
    "process-chroot": Probe(
        "libprocess_chroot_direct_probe.a",
        "crabc_rs_process_chroot_direct_probe",
        {51: "chroot"},
        ("chroot", "pivot_root", "open", "openat", "__errno_location"),
    ),
    "calendar-utc": Probe(
        "libcalendar_utc_direct_probe.a",
        "crabc_rs_calendar_utc_direct_probe",
        {113: "clock_gettime"},
        ("time", "difftime", "gmtime", "gmtime_r", "timegm", "localtime", "clock_gettime", "__errno_location"),
    ),
    "process-clock-id": Probe(
        "libprocess_clock_id_direct_probe.a",
        "crabc_rs_process_clock_id_direct_probe",
        {113: "clock_gettime", 114: "clock_getres"},
        ("clock_getcpuclockid", "clock_gettime", "clock_getres", "getpid", "__errno_location"),
    ),
    "param-auxv": Probe(
        "libparam_auxv_direct_probe.a",
        "crabc_rs_param_auxv_direct_probe",
        {56: "openat", 57: "close", 63: "read"},
        ("getauxval", "open", "openat", "read", "close", "__errno_location"),
    ),
    "network-interface-index": Probe(
        "libnetwork_interface_index_direct_probe.a",
        "crabc_rs_network_interface_index_direct_probe",
        {29: "ioctl", 57: "close", 198: "socket"},
        ("if_nametoindex", "ioctl", "socket", "close", "__errno_location"),
    ),
    "network-interface-index-name": Probe(
        "libnetwork_interface_index_name_direct_probe.a",
        "crabc_rs_network_interface_index_name_direct_probe",
        {29: "ioctl", 57: "close", 198: "socket"},
        ("if_indextoname", "ioctl", "socket", "close", "__errno_location"),
    ),
    "interface-names": Probe(
        "libinterface_names_direct_probe.a",
        "crabc_rs_interface_names_direct_probe",
        {57: "close", 198: "socket", 206: "sendto", 207: "recvfrom"},
        INTERFACE_NAMES_C_ABI_FORBIDDEN + (
            "__rust_alloc", "__rust_dealloc", "__rust_realloc",
        ),
    ),
    "interface-names-alloc": Probe(
        "libinterface_names_alloc_direct_probe.a",
        "crabc_rs_interface_names_alloc_direct_probe",
        {57: "close", 198: "socket", 206: "sendto", 207: "recvfrom"},
        INTERFACE_NAMES_C_ABI_FORBIDDEN,
    ),
    "interface-addresses": Probe(
        "libinterface_addresses_direct_probe.a",
        "crabc_rs_interface_addresses_direct_probe",
        {57: "close", 198: "socket", 206: "sendto", 207: "recvfrom"},
        INTERFACE_ADDRESSES_C_ABI_FORBIDDEN,
    ),
    "clock-set": Probe(
        "libtime_settime_direct_probe.a",
        "crabc_rs_time_settime_direct_probe",
        {112: "clock_settime"},
        ("clock_settime", "settimeofday", "stime", "adjtimex", "__errno_location"),
    ),
    "timespec-get": Probe(
        "libtime_timespec_get_direct_probe.a",
        "crabc_rs_time_timespec_get_direct_probe",
        {113: "clock_gettime"},
        ("timespec_get", "clock_gettime", "gettimeofday", "time", "__errno_location"),
    ),
    "realtime-millis": Probe(
        "libtime_realtime_millis_direct_probe.a",
        "crabc_rs_time_realtime_millis_direct_probe",
        {113: "clock_gettime"},
        (
            "clock_gettime",
            "__vdso_clock_gettime",
            "gettimeofday",
            "ftime",
            "time",
            "malloc",
            "calloc",
            "realloc",
            "free",
            "posix_memalign",
            "aligned_alloc",
            "__rust_alloc",
            "__rust_dealloc",
            "__rust_realloc",
            "__errno_location",
        ),
    ),
    "wall-clock": Probe(
        "libtime_direct_probe.a",
        "crabc_rs_time_direct_probe",
        {169: "gettimeofday"},
        ("gettimeofday", "clock_gettime", "time", "localtime", "gmtime", "__errno_location"),
    ),
    "process-cpu-time": Probe(
        "libprocess_cpu_time_direct_probe.a",
        "crabc_rs_process_cpu_time_direct_probe",
        {113: "clock_gettime"},
        ("clock", "clock_gettime", "gettimeofday", "time", "__errno_location"),
    ),
    "time-dynamic": Probe(
        "libtime_dynamic_direct_probe.a",
        "crabc_rs_time_dynamic_direct_probe",
        {113: "clock_gettime"},
        ("clock_gettime", "__vdso_clock_gettime", "clock_gettime_dynamic", "__errno_location"),
    ),
    "sched-rr-interval": Probe(
        "libsched_rr_interval_direct_probe.a",
        "crabc_rs_sched_rr_interval_direct_probe",
        {127: "sched_rr_get_interval"},
        ("sched_rr_get_interval", "sched_getaffinity", "sched_setaffinity", "sched_getscheduler", "__errno_location"),
    ),
    "sched-getaffinity": Probe(
        "libsched_getaffinity_direct_probe.a",
        "crabc_rs_sched_getaffinity_direct_probe",
        {123: "sched_getaffinity"},
        ("sched_getaffinity", "sched_setaffinity", "__errno_location"),
    ),
    "sched-setaffinity": Probe(
        "libsched_setaffinity_direct_probe.a",
        "crabc_rs_sched_setaffinity_direct_probe",
        {122: "sched_setaffinity", 123: "sched_getaffinity"},
        ("sched_setaffinity", "sched_getaffinity", "__errno_location"),
    ),
    "pidfd-open": Probe(
        "libpidfd_open_direct_probe.a",
        "crabc_rs_pidfd_open_direct_probe",
        {172: "getpid", 434: "pidfd_open"},
        ("pidfd_open", "pidfd_send_signal", "pidfd_getfd", "open", "openat", "__errno_location"),
    ),
    "network-socket": Probe(
        "libnetwork_socket_direct_probe.a",
        "crabc_rs_network_socket_direct_probe",
        {198: "socket", 210: "shutdown"},
        ("socket", "socketpair", "shutdown", "connect", "accept", "send", "recv", "__errno_location"),
    ),
    "network-socket-type": Probe(
        "libnetwork_socket_type_direct_probe.a",
        "crabc_rs_network_socket_type_direct_probe",
        {198: "socket", 209: "getsockopt"},
        ("socket", "socket_type", "getsockopt", "setsockopt", "connect", "bind", "accept", "send", "recv", "__errno_location"),
    ),
    "network-socket-protocol": Probe(
        "libnetwork_socket_protocol_direct_probe.a",
        "crabc_rs_network_socket_protocol_direct_probe",
        {198: "socket", 209: "getsockopt"},
        ("socket", "socket_protocol", "getsockopt", "setsockopt", "connect", "bind", "accept", "send", "recv", "__errno_location"),
    ),
    "network-socket-cookie": Probe(
        "libnetwork_socket_cookie_direct_probe.a",
        "crabc_rs_network_socket_cookie_direct_probe",
        {57: "close", 198: "socket", 209: "getsockopt"},
        ("socket", "socket_cookie", "getsockopt", "setsockopt", "connect", "bind", "accept", "send", "recv", "__errno_location"),
    ),
    "network-socket-domain": Probe(
        "libnetwork_socket_domain_direct_probe.a",
        "crabc_rs_network_socket_domain_direct_probe",
        {57: "close", 198: "socket", 209: "getsockopt"},
        ("socket", "socket_domain", "getsockopt", "setsockopt", "connect", "bind", "accept", "send", "recv", "__errno_location"),
    ),
    "network-socket-acceptconn": Probe(
        "libnetwork_socket_acceptconn_direct_probe.a",
        "crabc_rs_network_socket_acceptconn_direct_probe",
        {57: "close", 198: "socket", 201: "listen", 209: "getsockopt"},
        ("socket", "socket_acceptconn", "getsockopt", "setsockopt", "listen", "connect", "bind", "accept", "send", "recv", "__errno_location"),
    ),
    "network-socket-oobinline": Probe(
        "libnetwork_socket_oobinline_direct_probe.a",
        "crabc_rs_network_socket_oobinline_direct_probe",
        {57: "close", 198: "socket", 208: "setsockopt", 209: "getsockopt"},
        ("socket", "set_socket_oobinline", "socket_oobinline", "setsockopt", "getsockopt", "connect", "bind", "listen", "accept", "send", "recv", "__errno_location"),
    ),
    "network-socket-broadcast": Probe(
        "libnetwork_socket_broadcast_direct_probe.a",
        "crabc_rs_network_socket_broadcast_direct_probe",
        {57: "close", 198: "socket", 208: "setsockopt", 209: "getsockopt"},
        ("socket", "set_socket_broadcast", "socket_broadcast", "setsockopt", "getsockopt", "connect", "bind", "listen", "accept", "send", "recv", "__errno_location"),
    ),
    "network-connect": Probe(
        "libnetwork_connect_direct_probe.a",
        "crabc_rs_network_connect_direct_probe",
        {198: "socket", 203: "connect"},
        ("socket", "connect", "bind", "accept", "send", "recv", "__errno_location"),
    ),
    "preadv2": Probe(
        "libpreadv2_direct_probe.a",
        "crabc_rs_preadv2_direct_probe",
        {286: "preadv2", 287: "pwritev2"},
        ("preadv2", "pwritev2", "preadv", "pwritev", "readv", "writev", "open", "openat", "__errno_location"),
    ),
    "fadvise": Probe(
        "libfadvise_direct_probe.a",
        "crabc_rs_fadvise_direct_probe",
        {223: "fadvise64"},
        ("fadvise64", "posix_fadvise", "open", "openat", "__errno_location"),
    ),
    "fcntl-flags": Probe(
        "libfcntl_flags_direct_probe.a",
        "crabc_rs_fcntl_flags_direct_probe",
        {25: "fcntl", 57: "close", 59: "pipe2"},
        ("fcntl", "open", "openat", "pipe", "pipe2", "__errno_location"),
    ),
    "futimes": Probe(
        "libfutimes_direct_probe.a",
        "crabc_rs_futimes_direct_probe",
        {57: "close", 59: "pipe2", 88: "utimensat"},
        ("futimes", "futimens", "utimensat", "open", "openat", "pipe", "__errno_location"),
    ),
    "lutimes": Probe(
        "liblutimes_direct_probe.a",
        "crabc_rs_lutimes_direct_probe",
        {88: "utimensat"},
        ("lutimes", "utimes", "utimensat", "__errno_location"),
    ),
    "futimesat": Probe(
        "libfutimesat_direct_probe.a",
        "crabc_rs_futimesat_direct_probe",
        {56: "openat", 57: "close", 88: "utimensat"},
        ("futimesat", "futimens", "utimensat", "open", "openat", "__errno_location"),
    ),
    "utimes": Probe(
        "libutimes_direct_probe.a",
        "crabc_rs_utimes_direct_probe",
        {88: "utimensat"},
        ("utimes", "lutimes", "futimesat", "utimensat", "__errno_location"),
    ),
    "utime": Probe(
        "libutime_direct_probe.a",
        "crabc_rs_utime_direct_probe",
        {88: "utimensat"},
        ("utime", "utimes", "lutimes", "futimesat", "utimensat", "__errno_location"),
    ),
    "network-bind-getsockname": Probe(
        "libnetwork_bind_getsockname_direct_probe.a",
        "crabc_rs_network_bind_getsockname_direct_probe",
        {198: "socket", 200: "bind", 204: "getsockname"},
        ("socket", "bind", "getsockname", "connect", "accept", "send", "recv", "__errno_location"),
    ),
    "msync": Probe(
        "libmsync_direct_probe.a",
        "crabc_rs_msync_direct_probe",
        {215: "munmap", 222: "mmap", 227: "msync"},
        ("mmap", "msync", "munmap", "__errno_location"),
    ),
    "sendfile": Probe(
        "libsendfile_direct_probe.a",
        "crabc_rs_sendfile_direct_probe",
        {56: "openat", 71: "sendfile"},
        ("sendfile", "open", "openat", "__errno_location"),
    ),
    "network-getpeername": Probe(
        "libnetwork_getpeername_direct_probe.a",
        "crabc_rs_network_getpeername_direct_probe",
        {198: "socket", 203: "connect", 205: "getpeername"},
        ("socket", "connect", "getpeername", "bind", "accept", "send", "recv", "__errno_location"),
    ),
    "mincore": Probe(
        "libmincore_direct_probe.a",
        "crabc_rs_mincore_direct_probe",
        {215: "munmap", 222: "mmap", 232: "mincore"},
        ("mincore", "mmap", "munmap", "__errno_location"),
    ),
    "rusage": Probe(
        "librusage_direct_probe.a",
        "crabc_rs_rusage_direct_probe",
        {165: "getrusage"},
        ("getrusage", "__errno_location"),
    ),
    "getgroups": Probe(
        "libgetgroups_direct_probe.a",
        "crabc_rs_getgroups_direct_probe",
        {158: "getgroups"},
        ("getgroups", "getgid", "setgroups", "__errno_location"),
    ),
    "mlock": Probe(
        "libmlock_direct_probe.a",
        "crabc_rs_mlock_direct_probe",
        {215: "munmap", 222: "mmap", 228: "mlock", 229: "munlock", 284: "mlock2"},
        ("mlock", "mlock2", "munlock", "mmap", "munmap", "__errno_location"),
    ),
    "network-listen-accept": Probe(
        "libnetwork_listen_accept_direct_probe.a",
        "crabc_rs_network_listen_accept_direct_probe",
        {198: "socket", 200: "bind", 201: "listen", 202: "accept", 242: "accept4"},
        ("socket", "bind", "listen", "accept", "accept4", "connect", "send", "recv", "__errno_location"),
    ),
    "network-datagram": Probe(
        "libnetwork_datagram_direct_probe.a",
        "crabc_rs_network_datagram_direct_probe",
        {198: "socket", 200: "bind", 204: "getsockname", 206: "sendto", 207: "recvfrom"},
        ("socket", "bind", "getsockname", "sendto", "recvfrom", "send", "recv", "connect", "__errno_location"),
    ),
    "priority": Probe(
        "libpriority_direct_probe.a",
        "crabc_rs_priority_direct_probe",
        {141: "getpriority"},
        ("getpriority", "setpriority", "nice", "__errno_location"),
    ),
    "scheduler-priority-bounds": Probe(
        "libscheduler_priority_bounds_direct_probe.a",
        "crabc_rs_scheduler_priority_bounds_direct_probe",
        {125: "sched_get_priority_max", 126: "sched_get_priority_min"},
        ("sched_get_priority_max", "sched_get_priority_min", "sched_getscheduler", "sched_setscheduler", "__errno_location"),
    ),
    "setpriority": Probe(
        "libsetpriority_direct_probe.a",
        "crabc_rs_setpriority_direct_probe",
        {140: "setpriority"},
        ("setpriority", "getpriority", "nice", "__errno_location"),
    ),
    "mremap": Probe(
        "libmremap_direct_probe.a",
        "crabc_rs_mremap_direct_probe",
        {215: "munmap", 216: "mremap", 222: "mmap"},
        ("mremap", "mmap", "munmap", "__errno_location"),
    ),
    "network-socket-options": Probe(
        "libnetwork_socket_options_direct_probe.a",
        "crabc_rs_network_socket_options_direct_probe",
        {198: "socket", 208: "setsockopt", 209: "getsockopt"},
        ("socket", "setsockopt", "getsockopt", "connect", "bind", "accept", "send", "recv", "__errno_location"),
    ),
    "readahead": Probe(
        "libreadahead_direct_probe.a",
        "crabc_rs_readahead_direct_probe",
        {213: "readahead"},
        ("readahead", "posix_fadvise", "fadvise64", "__errno_location"),
    ),
    "getitimer": Probe(
        "libgetitimer_direct_probe.a",
        "crabc_rs_getitimer_direct_probe",
        {102: "getitimer"},
        ("getitimer", "setitimer", "alarm", "timer_create", "__errno_location"),
    ),
    "time-timers": Probe(
        "libtime_timers_direct_probe.a",
        "crabc_rs_time_timers_direct_probe",
        {
            103: "setitimer",
            107: "timer_create",
            108: "timer_gettime",
            109: "timer_getoverrun",
            110: "timer_settime",
            111: "timer_delete",
        },
        (
            "setitimer",
            "getitimer",
            "alarm",
            "ualarm",
            "timer_create",
            "timer_delete",
            "timer_getoverrun",
            "timer_gettime",
            "timer_settime",
            "__errno_location",
        ),
    ),
    "copy-file-range": Probe(
        "libcopy_file_range_direct_probe.a",
        "crabc_rs_copy_file_range_direct_probe",
        {285: "copy_file_range"},
        ("copy_file_range", "sendfile", "splice", "__errno_location"),
    ),
    "sync-file-range": Probe(
        "libsync_file_range_direct_probe.a",
        "crabc_rs_sync_file_range_direct_probe",
        {84: "sync_file_range"},
        ("sync_file_range", "fsync", "fdatasync", "__errno_location"),
    ),
    "network-messages": Probe(
        "libnetwork_messages_direct_probe.a",
        "crabc_rs_network_messages_direct_probe",
        {199: "socketpair", 211: "sendmsg", 212: "recvmsg"},
        ("socketpair", "sendmsg", "recvmsg", "send", "recv", "sendto", "recvfrom", "__errno_location"),
    ),
    "network-multimessage": Probe(
        "libnetwork_mmsg_direct_probe.a",
        "crabc_rs_network_mmsg_direct_probe",
        {29: "ioctl", 57: "close", 199: "socketpair", 243: "recvmmsg", 269: "sendmmsg"},
        (
            "socketpair",
            "sendmmsg",
            "recvmmsg",
            "sockatmark",
            "ioctl",
            "sendmsg",
            "recvmsg",
            "send",
            "recv",
            "__errno_location",
        ),
    ),
    "getcwd": Probe(
        "libgetcwd_direct_probe.a",
        "crabc_rs_getcwd_direct_probe",
        {17: "getcwd"},
        ("getcwd", "get_current_dir_name", "realpath", "__errno_location"),
    ),
    "current-dir-name": Probe(
        "libcurrent_dir_name_direct_probe.a",
        "crabc_rs_current_dir_name_direct_probe",
        {17: "getcwd", 79: "newfstatat"},
        ("get_current_dir_name", "getcwd", "stat", "fstatat", "newfstatat", "getenv", "realpath", "open", "openat", "__errno_location"),
    ),
    "eventfd": Probe(
        "libeventfd_direct_probe.a",
        "crabc_rs_eventfd_direct_probe",
        {19: "eventfd2", 63: "read", 64: "write"},
        ("eventfd", "eventfd_read", "eventfd_write", "read", "write", "__errno_location"),
    ),
    "inotify": Probe(
        "libinotify_direct_probe.a",
        "crabc_rs_inotify_direct_probe",
        {26: "inotify_init1", 57: "close"},
        ("inotify_init", "inotify_init1", "inotify_add_watch", "inotify_rm_watch", "close", "__errno_location"),
    ),
    "mqueue": Probe(
        "libipc_direct_probe.a",
        "crabc_rs_ipc_direct_probe",
        {57: "close", 180: "mq_open", 181: "mq_unlink", 182: "mq_timedsend", 183: "mq_timedreceive", 185: "mq_getsetattr"},
        (
            "mq_open", "mq_close", "mq_unlink", "mq_send", "mq_receive", "mq_getattr", "mq_setattr",
            "mq_timedsend", "mq_timedreceive", "close", "__errno_location",
        ),
    ),
    "users-databases": Probe(
        "libusers_databases_direct_probe.a",
        "crabc_rs_users_databases_direct_probe",
        {56: "openat", 57: "close", 63: "read"},
        (
            "getpwnam", "getpwuid", "getpwent", "getgrnam", "getgrgid", "getgrent",
            "open", "openat", "read", "close", "__errno_location",
        ),
    ),
    "times": Probe(
        "libtimes_direct_probe.a",
        "crabc_rs_times_direct_probe",
        {153: "times"},
        ("times", "clock", "sysconf", "__errno_location"),
    ),
    "session-observation": Probe(
        "libsession_observation_direct_probe.a",
        "crabc_rs_session_observation_direct_probe",
        {155: "getpgid", 156: "getsid"},
        ("getpgid", "getsid", "setpgid", "setsid", "getpgrp", "__errno_location"),
    ),
    "thread-identity": Probe(
        "libthread_identity_direct_probe.a",
        "crabc_rs_thread_identity_direct_probe",
        {178: "gettid"},
        ("gettid", "pthread_self", "__errno_location"),
    ),
    "futex": Probe(
        "libfutex_direct_probe.a",
        "crabc_rs_futex_direct_probe",
        {98: "futex"},
        ("futex", "pthread_", "__errno_location"),
    ),
    "access": Probe(
        "libaccess_direct_probe.a",
        "crabc_rs_access_direct_probe",
        {48: "faccessat"},
        ("access", "faccessat", "faccessat2", "open", "openat", "__errno_location"),
    ),
    "accessat": Probe(
        "libaccessat_direct_probe.a",
        "crabc_rs_accessat_direct_probe",
        {48: "faccessat", 439: "faccessat2"},
        ("access", "faccessat", "faccessat2", "eaccess", "euidaccess", "open", "openat", "__errno_location"),
    ),
    "truncate": Probe(
        "libtruncate_direct_probe.a",
        "crabc_rs_truncate_direct_probe",
        {45: "truncate"},
        ("truncate", "ftruncate", "open", "openat", "write", "lseek", "__errno_location"),
    ),
    "process-identity": Probe(
        "libprocess_identity_direct_probe.a",
        "crabc_rs_process_identity_direct_probe",
        {172: "getpid", 173: "getppid"},
        ("getpid", "getppid", "__errno_location"),
    ),
    "process-cwd": Probe(
        "libprocess_cwd_direct_probe.a",
        "crabc_rs_process_cwd_direct_probe",
        {49: "chdir", 50: "fchdir"},
        ("chdir", "fchdir", "getcwd", "__errno_location"),
    ),
    "sync": Probe(
        "libfilesystem_sync_probe.a",
        "crabc_rs_filesystem_sync_probe",
        {81: "sync"},
        ("sync", "fsync", "fdatasync", "syncfs", "__errno_location"),
    ),
    "sched-cpu": Probe(
        "libsched_cpu_direct_probe.a",
        "crabc_rs_sched_cpu_direct_probe",
        {168: "getcpu"},
        ("sched_getcpu", "getcpu", "pthread_self", "__errno_location"),
    ),
    "ownership": Probe(
        "libownership_direct_probe.a",
        "crabc_rs_ownership_direct_probe",
        {54: "fchownat", 55: "fchown", 175: "geteuid", 177: "getegid"},
        ("chown", "lchown", "fchown", "fchownat", "geteuid", "getegid", "__errno_location"),
    ),
    "special-nodes": Probe(
        "libspecial_nodes_direct_probe.a",
        "crabc_rs_special_nodes_direct_probe",
        {33: "mknodat", 35: "unlinkat"},
        ("mknod", "mknodat", "mkfifo", "mkfifoat", "unlink", "unlinkat", "__errno_location"),
    ),
    "system-names": Probe(
        "libsystem_names_direct_probe.a",
        "crabc_rs_system_names_direct_probe",
        {160: "uname"},
        ("uname", "gethostname", "getdomainname", "__errno_location"),
    ),
    "load-average": Probe(
        "libload_average_direct_probe.a",
        "crabc_rs_load_average_direct_probe",
        {179: "sysinfo"},
        ("getloadavg", "sysinfo", "__errno_location"),
    ),
    "getentropy": Probe(
        "libgetentropy_direct_probe.a",
        "crabc_rs_getentropy_direct_probe",
        {278: "getrandom"},
        ("getentropy", "getrandom", "arc4random", "__errno_location"),
    ),
    "create": Probe(
        "libcreate_direct_probe.a",
        "crabc_rs_create_direct_probe",
        {35: "unlinkat", 56: "openat", 57: "close", 63: "read", 64: "write"},
        ("creat", "open", "openat", "unlink", "unlinkat", "read", "write", "close", "__errno_location"),
    ),
    "ttyname": Probe(
        "libttyname_direct_probe.a",
        "crabc_rs_ttyname_direct_probe",
        {29: "ioctl", 56: "openat", 57: "close", 78: "readlinkat", 79: "newfstatat", 80: "fstat"},
        ("ttyname", "ttyname_r", "isatty", "fstat", "stat", "readlink", "open", "openat", "__errno_location"),
    ),
    "termios-exclusive": Probe(
        "libtermios_exclusive_direct_probe.a",
        "crabc_rs_termios_exclusive_direct_probe",
        {29: "ioctl", 56: "openat", 57: "close"},
        ("ioctl_tiocexcl", "ioctl_tiocnxcl", "tcgetattr", "tcsetattr", "open", "openat", "close", "__errno_location"),
    ),
    "termios-special-codes": Probe(
        "libtermios_special_codes_direct_probe.a",
        "crabc_rs_termios_special_codes_direct_probe",
        {29: "ioctl", 56: "openat", 57: "close"},
        ("tcgetattr", "tcsetattr", "open", "openat", "close", "__errno_location"),
    ),
    "thread-credentials": Probe(
        "libthread_credentials_direct_probe.a",
        "crabc_rs_thread_credentials_direct_probe",
        {147: "setresuid", 149: "setresgid"},
        ("setresuid", "setresgid", "seteuid", "setegid", "setuid", "setgid", "pthread_", "__errno_location"),
    ),
    "fs-credentials": Probe(
        "libfs_credentials_direct_probe.a",
        "crabc_rs_fs_credentials_direct_probe",
        {151: "setfsuid", 152: "setfsgid"},
        ("setfsuid", "setfsgid", "seteuid", "setegid", "setuid", "setgid", "pthread_", "__errno_location"),
    ),
    "termios-queue": Probe(
        "libtermios_queue_direct_probe.a",
        "crabc_rs_termios_queue_direct_probe",
        {29: "ioctl", 56: "openat", 57: "close"},
        ("tcdrain", "tcflush", "tcflow", "tcsendbreak", "ioctl", "open", "openat", "close", "__errno_location"),
    ),
    "terminal-control": Probe(
        "libterminal_control_direct_probe.a",
        "crabc_rs_terminal_control_direct_probe",
        {29: "ioctl"},
        ("tcgetattr", "tcsetattr", "tcgetpgrp", "tcsetpgrp", "tcgetsid", "ioctl", "__errno_location"),
    ),
    "pty-session": Probe(
        "libpty_session_direct_probe.a",
        "crabc_rs_pty_session_direct_probe",
        {29: "ioctl", 56: "openat", 57: "close", 157: "setsid", 260: "wait4"},
        (
            "openpty", "forkpty", "ptsname", "ptsname_r", "login_tty", "vhangup",
            "ioctl", "open", "openat", "close", "waitpid", "setsid", "__errno_location",
        ),
    ),
}


class VerificationError(ValueError):
    """The fixture does not demonstrate its direct-kernel contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def tool_output(command: Sequence[str]) -> str:
    result = subprocess.run(command, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        stderr = result.stderr.decode("utf-8", "replace").strip()
        raise VerificationError(f"tool failed ({' '.join(command)}): {stderr}")
    return result.stdout.decode("utf-8", "replace")


def syscall_pattern(number: int) -> re.Pattern[str]:
    return re.compile(rf"mov\s+w8,\s+#{number:#x}\b[\s\S]{{0,900}}?\bsvc\b")


def inspect(probe: Probe, readelf: str, disassembly: str, defined_symbols: str) -> dict[str, object]:
    require("AArch64" in readelf, "fixture is not an AArch64 ELF archive member")
    require(probe.entrypoint in defined_symbols, "fixture does not define the required probe entry point")
    missing = tuple(name for number, name in probe.syscalls.items() if not syscall_pattern(number).search(disassembly))
    require(not missing, "fixture is missing direct Linux/AArch64 syscall(s): " + ", ".join(missing))
    forbidden = tuple(
        symbol
        for symbol in probe.forbidden_symbols
        if re.search(rf"<{re.escape(symbol)}(?:@[^>]*)?>", disassembly)
    )
    require(not forbidden, "fixture references forbidden public C ABI/errno symbol(s): " + ", ".join(forbidden))
    return {
        "machine": "AArch64",
        "direct_svc": True,
        "direct_syscalls": list(probe.syscalls.values()),
        "forbidden_public_symbols": [],
    }


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("probe", choices=tuple(PROBES))
    parser.add_argument("--target-dir", type=Path, default=Path("target"))
    parser.add_argument("--readelf", default="llvm-readelf")
    parser.add_argument("--objdump", default="llvm-objdump")
    parser.add_argument("--nm", default="llvm-nm")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    probe = PROBES[args.probe]
    archive = args.target_dir / "release" / "examples" / probe.archive
    try:
        require(archive.is_file(), f"{args.probe} probe archive does not exist: {archive}")
        report = inspect(
            probe,
            tool_output((args.readelf, "--file-header", str(archive))),
            tool_output((args.objdump, "--disassemble", "--demangle", str(archive))),
            tool_output((args.nm, "--defined-only", str(archive))),
        )
        print(f"{args.probe} direct syscall proof: PASS ({archive}) {report}")
    except VerificationError as error:
        print(f"{args.probe} direct syscall proof: ERROR: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
