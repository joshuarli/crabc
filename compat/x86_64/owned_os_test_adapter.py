"""Run the os-test compiler adapter as an imported module.

Make invokes this launcher for every compile and link. Importing
``owned_os_test`` instead of executing it as ``__main__`` lets the runner's
private bytecode cache serve its modules to every invocation.
"""

import sys

import owned_os_test

raise SystemExit(owned_os_test.main(sys.argv[1:]))
