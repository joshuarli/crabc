use crabc_rs::{pipe, Errno};

#[test]
fn pipe_capacity_is_positive_and_shared_by_both_ends() {
    let (reader, writer) = pipe::pipe().expect("create pipe-capacity fixture");

    let reader_size = pipe::fcntl_getpipe_size(&reader).expect("read capacity from reader");
    let writer_size = pipe::fcntl_getpipe_size(&writer).expect("read capacity from writer");

    assert!(reader_size > 0);
    assert_eq!(reader_size, writer_size);
}

#[test]
fn pipe_capacity_preserves_non_pipe_kernel_error() {
    let file = std::fs::File::open("Cargo.toml").expect("open regular-file fixture");

    let error = pipe::fcntl_getpipe_size(&file).expect_err("a regular file is not a pipe");
    assert!(
        error == Errno::BADF || error == Errno::INVAL || error == Errno::NOTTY,
        "unexpected non-pipe F_GETPIPE_SZ error: {:?}",
        error,
    );

    // An invalid descriptor exercises the exact kernel error path without
    // depending on which non-pipe errno a particular Linux filesystem uses.
    let invalid = unsafe { crabc_rs::BorrowedFd::borrow_raw(9_999) };
    assert_eq!(pipe::fcntl_getpipe_size(invalid), Err(Errno::BADF));
}
