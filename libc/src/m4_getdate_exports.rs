// POSIX getdate(3), ported from musl 1.2.6's intentionally small state
// machine. `strptime` owns partial-field semantics: `getdate` retains one
// static `tm` buffer and does not invent date or time defaults of its own.

#[no_mangle]
pub static mut getdate_err: c_int = 0;

static mut M4_GETDATE_TM: tm = tm {
    tm_sec: 0,
    tm_min: 0,
    tm_hour: 0,
    tm_mday: 0,
    tm_mon: 0,
    tm_year: 0,
    tm_wday: 0,
    tm_yday: 0,
    tm_isdst: 0,
    tm_gmtoff: 0,
    tm_zone: core::ptr::null(),
};

#[no_mangle]
pub unsafe extern "C" fn getdate(s: *const c_char) -> *mut tm {
    let mut result = core::ptr::null_mut();
    let datemsk = getenv(b"DATEMSK\0".as_ptr() as *const c_char);
    let mut file = core::ptr::null_mut();
    let mut format = [0 as c_char; 100];
    let mut previous_cancel_state = PTHREAD_CANCEL_ENABLE;

    // This exactly mirrors musl: getdate is a cancellation point, but the
    // cancellation type is temporarily made deferred while its static result
    // buffer and input stream are in use.
    let _ = pthread_setcancelstate(PTHREAD_CANCEL_DEFERRED, &mut previous_cancel_state);

    if datemsk.is_null() {
        getdate_err = 1;
    } else {
        file = fopen(datemsk, b"rbe\0".as_ptr() as *const c_char);
        if file.is_null() {
            getdate_err = if ERRNO == ENOMEM { 6 } else { 2 };
        } else {
            while !fgets(format.as_mut_ptr(), format.len() as c_int, file).is_null() {
                let parsed = strptime(s, format.as_ptr(), core::ptr::addr_of_mut!(M4_GETDATE_TM));
                if !parsed.is_null() && *parsed == 0 {
                    result = core::ptr::addr_of_mut!(M4_GETDATE_TM);
                    break;
                }
            }
            if result.is_null() {
                getdate_err = if ferror(file) != 0 { 5 } else { 7 };
            }
        }
    }

    if !file.is_null() {
        let _ = fclose(file);
    }
    let _ = pthread_setcancelstate(previous_cancel_state, core::ptr::null_mut());
    result
}
