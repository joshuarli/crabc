use api::pipe;

fn main() {
    let (reader, writer) = pipe::pipe().expect("create pipe-capacity fixture");
    let reader_size = pipe::fcntl_getpipe_size(&reader).expect("read reader capacity");
    let writer_size = pipe::fcntl_getpipe_size(&writer).expect("read writer capacity");

    assert!(reader_size > 0);
    assert_eq!(reader_size, writer_size);
    println!("m10-pipe-size ok");
}
