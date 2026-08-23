// Obsolescent cuserid is nevertheless a real exported musl ABI.  Its result
// is derived from the effective uid's passwd record, not from LOGNAME or a
// container-specific fallback.  The fixed 20-byte public bound is musl's
// L_cuserid contract: an overlong account name leaves a caller buffer empty
// and makes the NULL-buffer form fail.

static mut CABI_CUSERID_RESULT: [c_char; 20] = [0; 20];

#[no_mangle]
pub unsafe extern "C" fn cuserid(buffer: *mut c_char) -> *mut c_char {
    if !buffer.is_null() {
        *buffer = 0;
    }

    let mut password: CabiPasswd = core::mem::zeroed();
    let mut password_result: *mut CabiPasswd = core::ptr::null_mut();
    let mut scratch = [0 as c_char; 2048];
    if getpwuid_r(
        geteuid(),
        &mut password,
        scratch.as_mut_ptr(),
        scratch.len(),
        &mut password_result,
    ) != 0 || password_result.is_null() {
        return buffer;
    }

    let name_length = strnlen(password.pw_name as *const u8, 20);
    if name_length == 20 {
        return buffer;
    }
    let destination = if buffer.is_null() {
        core::ptr::addr_of_mut!(CABI_CUSERID_RESULT).cast::<c_char>()
    } else {
        buffer
    };
    core::ptr::copy_nonoverlapping(password.pw_name, destination, name_length + 1);
    destination
}
