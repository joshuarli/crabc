// M4 loader-startup entry points.
//
// musl's __dls2b and __dls3 are normally part of the same object as the
// dynamic linker.  __dls2b runs after the linker's relative relocations and
// establishes the early TLS state before dispatching to __dls3; __dls3 then
// loads dependencies, performs final relocations, and transfers control to
// the application entry point.
//
// crabc deliberately splits those responsibilities: ldso::run_main owns ELF
// mapping, relocation, TLS allocation, constructors, and the final jump,
// while libc owns the process globals consumed by libc startup.  These
// exports therefore implement the safe libc side of that ABI boundary.  A
// valid startup vector installs __auxv, __environ, and argv[0]-derived
// program names.  The loader's relocation and entry-transfer work remains in
// ldso and is never faked by these helpers.

// The musl ABI carries no length fields in these vectors.  Keep malformed
// externally supplied vectors from turning this compatibility boundary into
// an unbounded scan.  Kernel startup vectors are far below these limits.
const M4_DLS_STARTUP_MAX_ARGC: usize = 4096;
const M4_DLS_STARTUP_MAX_ENVC: usize = 4096;
const M4_DLS_STARTUP_MAX_AUX_ENTRIES: usize = 128;

/// Install libc's startup view of a valid musl stack/auxiliary-vector pair.
///
/// Safety: `sp` must point at the conventional argc/argv/envp startup layout
/// and `auxv` at a terminated `(tag, value)` vector.  The bounded scans below
/// reject vectors that do not contain their required terminators before any
/// process-global pointer is changed.
unsafe fn m4_dls_install_startup_state(sp: *mut usize, auxv: *mut usize) -> bool {
    if sp.is_null() || auxv.is_null() {
        return false;
    }

    let argc = *sp;
    if argc > M4_DLS_STARTUP_MAX_ARGC {
        return false;
    }

    let argv = sp.add(1) as *mut *mut c_char;
    if !(*argv.add(argc)).is_null() {
        return false;
    }
    let envp = argv.add(argc + 1);
    let mut envc = 0usize;
    while envc < M4_DLS_STARTUP_MAX_ENVC && !(*envp.add(envc)).is_null() {
        envc += 1;
    }
    if envc == M4_DLS_STARTUP_MAX_ENVC {
        return false;
    }

    let mut aux = auxv;
    let mut terminated = false;
    for _ in 0..M4_DLS_STARTUP_MAX_AUX_ENTRIES {
        if *aux == 0 {
            terminated = true;
            break;
        }
        aux = aux.add(2);
    }
    if !terminated {
        return false;
    }

    // Keep this ordering: all validation completes before libc-visible state
    // changes, so a malformed synthetic vector cannot leave a half-installed
    // environment behind.
    __auxv = auxv as *const usize;
    __environ = envp as *mut *mut c_char;
    sync_environ();
    if argc != 0 {
        let argv0 = *argv;
        if !argv0.is_null() {
            m4_set_program_names(argv0 as *const c_char);
        }
    }
    true
}

/// Stage 3's libc-visible startup work for crabc's split loader.
///
/// In musl this stage does not return because it eventually jumps to the
/// program entry point.  crabc has already moved that work into
/// `ldso::run_main`; returning here is consequently the only safe behavior
/// for a direct ABI probe, while still making the startup state observable.
#[no_mangle]
pub unsafe extern "C" fn __dls3(sp: *mut usize, auxv: *mut usize) {
    let _ = m4_dls_install_startup_state(sp, auxv);
}

/// Stage 2b dispatches to stage 3 after the early relocation/TLS barrier.
///
/// The barrier itself is established by crabc's ldso before libc startup, so
/// this split-runtime implementation preserves the ABI's stage ordering by
/// forwarding directly to `__dls3` after the loader has prepared the process.
#[no_mangle]
pub unsafe extern "C" fn __dls2b(sp: *mut usize, auxv: *mut usize) {
    __dls3(sp, auxv);
}
