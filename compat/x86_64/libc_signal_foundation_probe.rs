#[path = "../../libc/src/c_abi/x86_64/signal_foundation.rs"]
mod signal_foundation;

use core::ffi::c_void;

/// Source-only bridge used exclusively by `run_libc_signal_foundation.sh`.
///
/// The selected static archive uses the typed private packing helper directly;
/// retaining this C name only in the isolated probe prevents an accidental
/// public bridge export from entering `libc.a`.
#[no_mangle]
pub unsafe extern "C" fn crabc_x86_64_signal_action_pack(
    public: *const c_void,
    kernel: *mut c_void,
) {
    // SAFETY: the C probe gives exactly the public and kernel records required
    // by the source-only bridge contract.
    unsafe { signal_foundation::pack_public_action(public.cast(), kernel.cast()) };
}
