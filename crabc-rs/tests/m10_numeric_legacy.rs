use core::cmp::Ordering;

use crabc_rs::collections::{CallbackSort, Search};
use crabc_rs::numeric::{DecodeStatus, EncodedLong, MAX_ENCODED_DIGITS, RADIX64_ALPHABET};

#[test]
fn encoded_long_matches_musl_alphabet_and_sign_extension() {
    assert!(EncodedLong::encode(0).is_empty());
    assert_eq!(EncodedLong::encode(0x2345_6789).as_bytes(), b"7SKFX");
    assert_eq!(EncodedLong::encode(0x1_0000_0001).value(), 1);
    assert_eq!(EncodedLong::encode(-1).value(), -1);
}

#[test]
fn encoded_long_decode_reports_the_exact_stop() {
    let invalid = EncodedLong::decode(b"2!");
    assert_eq!(invalid.value, 4);
    assert_eq!(invalid.consumed, 1);
    assert_eq!(
        invalid.status,
        DecodeStatus::InvalidByte {
            index: 1,
            byte: b'!',
        }
    );

    let nul = EncodedLong::decode(b"2\0tail");
    assert_eq!(nul.value, 4);
    assert_eq!(nul.status, DecodeStatus::Nul);

    let limited = EncodedLong::decode(b"......extra");
    assert_eq!(limited.consumed, MAX_ENCODED_DIGITS);
    assert_eq!(limited.status, DecodeStatus::DigitLimit);
}

#[test]
fn encoded_long_accepts_every_musl_radix64_digit() {
    for (digit, byte) in RADIX64_ALPHABET.iter().copied().enumerate() {
        let decoded = EncodedLong::decode(&[byte, 0]);
        assert_eq!(decoded.value, digit as i64, "digit {byte:?}");
        assert_eq!(decoded.consumed, 1, "digit {byte:?}");
        assert_eq!(decoded.status, DecodeStatus::Nul, "digit {byte:?}");
    }
}

#[test]
fn search_operations_are_typed_slice_operations() {
    let ordered = [1, 3, 5, 7, 9];
    let compare = |left: &i32, right: &i32| left.cmp(right);
    assert_eq!(Search::binary(&ordered, &7, compare), Some(3));
    assert_eq!(Search::linear_find(&ordered, &3, compare), Some(&3));
    assert_eq!(Search::bsearch(&ordered, &4, compare), None);
    assert_eq!(Search::lfind(&ordered, &9, compare), Some(4));
}

#[test]
fn lsearch_style_insertion_reports_found_and_inserted() {
    let mut values = vec![2, 4];
    let inserted = Search::try_lsearch(&mut values, 3, |left, right| left.cmp(right)).unwrap();
    assert!(inserted.inserted());
    assert_eq!(inserted.index(), 2);
    let found = Search::try_insert(&mut values, 3, |left, right| left.cmp(right)).unwrap();
    assert!(found.found());
    assert_eq!(values, [2, 4, 3]);
}

#[test]
fn callback_sort_receives_explicit_context() {
    let mut values = [1, 4, 2, 3];
    let mut reverse = true;
    CallbackSort::sort_unstable_with(&mut values, &mut reverse, |reverse, left, right| {
        if *reverse {
            right.cmp(left)
        } else {
            left.cmp(right)
        }
    });
    assert_eq!(values, [4, 3, 2, 1]);
    reverse = false;
    CallbackSort::sort_unstable_by_context(&mut values, &mut reverse, |reverse, left, right| {
        if *reverse {
            right.cmp(left)
        } else {
            left.cmp(right)
        }
    });
    assert_eq!(values, [1, 2, 3, 4]);
    assert_eq!(Ordering::Less, values[0].cmp(&values[1]));
}
