use crabc_rs::{io, pipe};

#[test]
fn tee_copies_a_bounded_prefix_without_consuming_source() {
    let (source_reader, source_writer) =
        pipe::pipe_with(pipe::PipeFlags::CLOEXEC).expect("create source pipe");
    let (destination_reader, destination_writer) =
        pipe::pipe_with(pipe::PipeFlags::CLOEXEC).expect("create destination pipe");

    assert_eq!(
        io::write(&source_writer, b"tee-payload").expect("write source payload"),
        11
    );
    assert_eq!(
        pipe::tee(
            &source_reader,
            &destination_writer,
            3,
            pipe::SpliceFlags::MOVE
                | pipe::SpliceFlags::NONBLOCK
                | pipe::SpliceFlags::MORE
                | pipe::SpliceFlags::GIFT,
        )
        .expect("duplicate source prefix"),
        3,
    );

    let mut copied = [0_u8; 3];
    assert_eq!(
        io::read(&destination_reader, &mut copied).expect("read duplicated prefix"),
        3
    );
    assert_eq!(&copied, b"tee");

    let mut original = [0_u8; 11];
    assert_eq!(
        io::read(&source_reader, &mut original).expect("read unconsumed source"),
        11
    );
    assert_eq!(&original, b"tee-payload");
}

#[test]
fn tee_preserves_short_results_and_kernel_errors() {
    let (source_reader, source_writer) = pipe::pipe().expect("create source pipe");
    let (destination_reader, destination_writer) = pipe::pipe().expect("create destination pipe");
    assert_eq!(
        io::write(&source_writer, b"short").expect("write short source payload"),
        5
    );

    assert_eq!(
        pipe::tee(
            &source_reader,
            &destination_writer,
            32,
            pipe::SpliceFlags::empty(),
        )
        .expect("duplicate available source bytes"),
        5,
    );

    let invalid = unsafe { crabc_rs::BorrowedFd::borrow_raw(9_999) };
    assert_eq!(
        pipe::tee(invalid, &destination_reader, 1, pipe::SpliceFlags::empty()).err(),
        Some(crabc_rs::Errno::BADF),
    );
}
