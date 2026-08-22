use api::{io, pipe};

fn main() {
    let (source_reader, source_writer) = pipe::pipe().expect("create source pipe");
    let (destination_reader, destination_writer) =
        pipe::pipe().expect("create destination pipe");

    assert_eq!(io::write(&source_writer, b"splice"), Ok(6));
    assert_eq!(
        pipe::splice(
            &source_reader,
            None,
            &destination_writer,
            None,
            6,
            pipe::SpliceFlags::empty(),
        ),
        Ok(6),
    );
    let mut copied = [0_u8; 6];
    assert_eq!(io::read(&destination_reader, &mut copied), Ok(6));
    assert_eq!(&copied, b"splice");

    let source = [pipe::IoSliceRaw::from_slice(b"vmsplice")];
    assert_eq!(
        unsafe { pipe::vmsplice(&source_writer, &source, pipe::SpliceFlags::empty()) },
        Ok(8),
    );
    let mut transferred = [0_u8; 8];
    assert_eq!(io::read(&source_reader, &mut transferred), Ok(8));
    assert_eq!(&transferred, b"vmsplice");
    println!("m10-pipe-splice ok");
}
