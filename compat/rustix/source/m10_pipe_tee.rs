use api::{io, pipe};

fn main() {
    let (source_reader, source_writer) = pipe::pipe().expect("create source pipe");
    let (destination_reader, destination_writer) =
        pipe::pipe().expect("create destination pipe");
    assert_eq!(io::write(&source_writer, b"hello!"), Ok(6));
    assert_eq!(
        pipe::tee(
            &source_reader,
            &destination_writer,
            5,
            pipe::SpliceFlags::empty(),
        ),
        Ok(5),
    );

    let mut duplicated = [0_u8; 5];
    assert_eq!(io::read(&destination_reader, &mut duplicated), Ok(5));
    assert_eq!(&duplicated, b"hello");

    let mut source = [0_u8; 6];
    assert_eq!(io::read(&source_reader, &mut source), Ok(6));
    assert_eq!(&source, b"hello!");
    println!("m10-pipe-tee ok");
}
