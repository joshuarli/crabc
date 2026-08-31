//! Isolated Linux/x86-64 legacy IPv4 textual-network C ABI.
//!
//! Pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417` maps
//! `src/network/inet_legacy.c` to four adjacent legacy functions:
//! `inet_network`, `inet_makeaddr`, `inet_lnaof`, and `inet_netof`. This
//! target-local leaf selects exactly [`inet_network`]. The musl body is
//! `return ntohl(inet_addr(p));`: its only cross-leaf dependency here is the
//! already selected [`super::inet_address::inet_addr`] parser. The local
//! scalar `swap_bytes` is the exact little-endian x86 equivalent of that
//! source-level `ntohl` operation; it deliberately does not select the
//! separately evidenced `ntohl` helper.
//!
//! The existing numeric parser retains its own historical base-zero grammar
//! and initial-TLS `errno` effects. This wrapper introduces no mutable state,
//! allocation, syscall, resolver configuration, DNS, `/etc/hosts`,
//! `/etc/resolv.conf`, netdb, interface, socket, `h_errno`, byte-order helper,
//! `inet_ntoa` scratch storage, classful arithmetic/extraction, or public x86
//! support. It is a private C ABI evidence leaf, not resolver progress.

use core::ffi::{c_char, c_uint};

// Keep the existing parser an object-level C ABI dependency rather than
// duplicating or inlining its historical grammar into this wrapper.
unsafe extern "C" {
    #[link_name = "inet_addr"]
    fn selected_inet_addr(source: *const c_char) -> c_uint;
}

/// Parse a legacy numeric IPv4 string and return musl's host-order network value.
///
/// # Safety
///
/// `source` must designate a readable NUL-terminated C string, exactly as
/// required by the selected [`super::inet_address::inet_addr`] implementation.
#[no_mangle]
pub unsafe extern "C" fn inet_network(source: *const c_char) -> c_uint {
    // SAFETY: the caller supplies the same valid C string required by inet_addr.
    let stored_network_order = unsafe { selected_inet_addr(source) };
    stored_network_order.swap_bytes()
}
