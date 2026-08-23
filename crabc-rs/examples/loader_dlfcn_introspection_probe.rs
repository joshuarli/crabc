//! Runtime proof for copied loaded-image and per-handle metadata.

#![no_std]

use core::ffi::CStr;

use crabc_rs::dl::{Library, LoadedImageSnapshot, OpenFlags};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

const DSO: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(b"libloader_dlfcn_introspection.so\0") };

fn has_image(snapshot: &LoadedImageSnapshot) -> bool {
    snapshot.images().iter().any(|image| {
        image.image_name().is_some_and(|name| name.as_bytes() == DSO.to_bytes())
            && image.image_base().is_some()
            && image.program_headers().is_some()
            && image.program_header_count() != 0
    })
}

#[no_mangle]
pub extern "C" fn crabc_rs_loader_dlfcn_introspection_probe() -> i32 {
    let before = match LoadedImageSnapshot::capture() {
        Ok(snapshot) => snapshot,
        Err(_) => return 1,
    };
    let main = match Library::open_main(OpenFlags::NOW | OpenFlags::LOCAL) {
        Ok(main) => main,
        Err(_) => return 2,
    };
    let main_information = match main.information() {
        Ok(information) => information,
        Err(_) => return 3,
    };
    if main_information.image_base().is_none() || main_information.dynamic_address().is_none() {
        return 4;
    }
    let library = match Library::open(DSO, OpenFlags::NOW | OpenFlags::LOCAL) {
        Ok(library) => library,
        Err(_) => return 5,
    };
    let information = match library.information() {
        Ok(information) => information,
        Err(_) => return 6,
    };
    if information.image_base().is_none() || information.dynamic_address().is_none() {
        return 7;
    }
    let Some(image_name) = information.image_name() else {
        return 8;
    };
    if image_name.as_bytes() != DSO.to_bytes() {
        return 9;
    }
    let after = match LoadedImageSnapshot::capture() {
        Ok(snapshot) => snapshot,
        Err(_) => return 10,
    };
    if after.len() <= before.len() || !has_image(&after) {
        return 11;
    }
    if after.generation() < before.generation() {
        return 12;
    }
    0
}
