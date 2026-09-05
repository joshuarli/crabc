#!/usr/bin/env python3
"""Pass a read-only proc descriptor through an optional private chroot."""
import os
import shutil
import sys

root, executable, *arguments = sys.argv[1:]
proc_fd = os.open('/proc', os.O_RDONLY | os.O_DIRECTORY)
os.set_inheritable(proc_fd, True)
os.environ['CRABC_TEST_PROC_FD'] = str(proc_fd)
if root:
    chroot = shutil.which('chroot')
    os.execv(chroot, [chroot, root, executable, *arguments])
os.execv(executable, [executable, *arguments])
