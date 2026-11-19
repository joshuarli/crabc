pub(super) unsafe fn mask(auxv: *mut usize, limit: usize) -> bool {
    for index in 0..limit {
        let entry = unsafe { auxv.add(index * 2) };
        let kind = unsafe { entry.read() };
        if kind == 0 { return true; }
        let mask = match kind {
            16 => !((!0usize) << 42),
            26 => !((0xffusize << 23) | (0x3fusize << 37) | (0x3fusize << 57)),
            29 | 30 => {
                unsafe { entry.write(1); entry.add(1).write(0); }
                continue;
            }
            _ => continue,
        };
        unsafe { entry.add(1).write(entry.add(1).read() & mask); }
    }
    false
}
