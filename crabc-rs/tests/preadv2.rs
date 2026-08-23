use crabc_rs::fs::{self, Mode, OFlags, SeekFrom};
use crabc_rs::io::{self, ReadWriteFlags};
use crabc_rs::Errno;

const POSITIONED_PATH: &[u8] = b"/tmp/crabc-rs-native-preadv2-positioned";
const FLAGS_PATH: &[u8] = b"/tmp/crabc-rs-native-preadv2-flags";

#[test]
fn preadv2_and_pwritev2_support_positioned_sentinel_and_high_offsets() {
    let path = POSITIONED_PATH;
    let _ = fs::unlink(path);
    let file = fs::open(
        path,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL,
        Mode::RUSR | Mode::WUSR,
    )
    .expect("create preadv2 fixture");

    assert_eq!(io::write(&file, b"0123456789").expect("write fixture"), 10);
    fs::seek(&file, SeekFrom::Start(2)).expect("set current file position");

    let current_writes = [io::IoSlice::new(b"ab"), io::IoSlice::new(b"CD")];
    assert_eq!(
        io::pwritev2(
            &file,
            &current_writes,
            u64::MAX,
            ReadWriteFlags::empty(),
        )
        .expect("current-offset pwritev2"),
        4,
    );
    assert_eq!(fs::tell(&file).expect("position after sentinel pwritev2"), 6);

    fs::seek(&file, SeekFrom::Start(0)).expect("rewind after sentinel write");
    let mut content = [0_u8; 10];
    assert_eq!(io::read(&file, &mut content).expect("read sentinel result"), 10);
    assert_eq!(&content, b"01abCD6789");

    fs::seek(&file, SeekFrom::Start(2)).expect("set current read position");
    let mut first = [0_u8; 2];
    let mut second = [0_u8; 2];
    let mut current_reads = [
        io::IoSliceMut::new(&mut first),
        io::IoSliceMut::new(&mut second),
    ];
    assert_eq!(
        io::preadv2(
            &file,
            &mut current_reads,
            u64::MAX,
            ReadWriteFlags::empty(),
        )
        .expect("current-offset preadv2"),
        4,
    );
    assert_eq!(&first, b"ab");
    assert_eq!(&second, b"CD");
    assert_eq!(fs::tell(&file).expect("position after sentinel preadv2"), 6);

    // Preserve a high offset through both low/high AArch64 ABI words without
    // allocating the sparse hole between the existing data and this range.
    let high_offset = (1_u64 << 32) + 7;
    let high_writes = [io::IoSlice::new(b"hi"), io::IoSlice::new(b"GH")];
    assert_eq!(
        io::pwritev2(
            &file,
            &high_writes,
            high_offset,
            ReadWriteFlags::empty(),
        )
        .expect("high-offset pwritev2"),
        4,
    );
    assert_eq!(fs::tell(&file).expect("position after high-offset write"), 6);

    let mut high_first = [0_u8; 2];
    let mut high_second = [0_u8; 2];
    let mut high_reads = [
        io::IoSliceMut::new(&mut high_first),
        io::IoSliceMut::new(&mut high_second),
    ];
    assert_eq!(
        io::preadv2(
            &file,
            &mut high_reads,
            high_offset,
            ReadWriteFlags::empty(),
        )
        .expect("high-offset preadv2"),
        4,
    );
    assert_eq!(&high_first, b"hi");
    assert_eq!(&high_second, b"GH");
    assert_eq!(fs::tell(&file).expect("position after high-offset read"), 6);

    drop(file);
    fs::unlink(path).expect("remove preadv2 fixture");
}

#[test]
fn preadv2_rejects_unknown_flags_before_the_syscall() {
    let path = FLAGS_PATH;
    let _ = fs::unlink(path);
    let file = fs::open(
        path,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL,
        Mode::RUSR | Mode::WUSR,
    )
    .expect("create flag validation fixture");

    assert!(
        ReadWriteFlags::from_bits(0x20).is_none(),
        "newer RWF bits remain outside this bounded facade",
    );
    let mut destination = [0_u8; 1];
    let mut buffers = [io::IoSliceMut::new(&mut destination)];
    assert_eq!(
        io::preadv2(
            &file,
            &mut buffers,
            0,
            ReadWriteFlags::from_bits_retain(0x20),
        )
        .unwrap_err(),
        Errno::INVAL,
    );

    drop(file);
    fs::unlink(path).expect("remove flag validation fixture");
}
