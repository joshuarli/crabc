//! Link-free `no_std` proof for the legacy numeric/collection seam.

#![no_std]

use core::cmp::Ordering;

use crabc_rs::collections::{CallbackSort, Search};
use crabc_rs::numeric::{DecodeStatus, EncodedLong};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_numeric_legacy_direct_probe() -> i32 {
    let encoded = EncodedLong::encode(-1);
    if encoded.value() != -1 || encoded.len() != 6 {
        return 1;
    }
    let decoded = EncodedLong::decode(encoded.as_bytes());
    if decoded.value != -1 || decoded.status != DecodeStatus::EndOfInput {
        return 2;
    }
    if EncodedLong::decode(b"2!").status
        != (DecodeStatus::InvalidByte {
            index: 1,
            byte: b'!',
        })
    {
        return 3;
    }

    let values = [1, 3, 5, 7];
    if Search::bsearch(&values, &5, |left, right| left.cmp(right)) != Some(2) {
        return 4;
    }
    if Search::lfind(&values, &6, |left, right| left.cmp(right)).is_some() {
        return 5;
    }

    let mut descending = true;
    let mut sortable = [1, 4, 2, 3];
    CallbackSort::unstable(&mut sortable, &mut descending, |reverse, left, right| {
        if *reverse {
            right.cmp(left)
        } else {
            left.cmp(right)
        }
    });
    if sortable != [4, 3, 2, 1] {
        return 6;
    }
    if Ordering::Greater != sortable[0].cmp(&sortable[1]) {
        return 7;
    }
    0
}
