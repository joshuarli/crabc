use crabc_rs::memory::ByteOps;

#[test]
fn explicit_bzero_erases_the_entire_borrowed_range() {
    let mut secret = *b"secret bytes must disappear";

    ByteOps::explicit_bzero(&mut secret);

    assert_eq!(secret, [0; 27]);
}

#[test]
fn memccpy_returns_the_suffix_after_the_inclusive_match() {
    let mut destination = [0xcc; 8];
    let source = *b"abcde";

    {
        let suffix = ByteOps::memccpy(&mut destination, &source, b'c').expect("needle is present");
        assert_eq!(suffix, &[0xcc; 5]);
    }
    assert_eq!(&destination[..3], b"abc");
    assert_eq!(&destination[3..], &[0xcc; 5]);
}

#[test]
fn memccpy_copies_the_whole_source_when_the_needle_is_absent() {
    let mut destination = [0xcc; 6];

    assert!(ByteOps::memccpy(&mut destination, b"abc", b'z').is_none());
    assert_eq!(&destination[..3], b"abc");
    assert_eq!(&destination[3..], &[0xcc; 3]);
}

#[test]
fn mempcpy_returns_the_one_past_copy_suffix() {
    let mut destination = [0xcc; 7];

    {
        let suffix = ByteOps::mempcpy(&mut destination, b"copy");
        assert_eq!(suffix, &[0xcc; 3]);
    }
    assert_eq!(&destination[..4], b"copy");
}

#[test]
fn swab_swaps_pairs_and_preserves_an_odd_trailing_byte() {
    let source = *b"abcde";
    let mut destination = [0xcc; 5];

    ByteOps::swab(&source, &mut destination);

    assert_eq!(destination, [b'b', b'a', b'd', b'c', 0xcc]);
}

#[test]
fn zero_length_special_operations_are_noops() {
    let mut destination = [0x5a; 2];
    assert!(ByteOps::memccpy(&mut destination, b"", b'x').is_none());
    {
        let suffix = ByteOps::mempcpy(&mut destination, b"");
        assert_eq!(suffix, &[0x5a; 2]);
    }

    let before = destination;
    ByteOps::swab(&[], &mut destination);
    assert_eq!(destination, before);
}
