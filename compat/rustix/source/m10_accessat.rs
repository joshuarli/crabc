use api::fs::{self, Access, AtFlags};

fn main() {
    fs::accessat(fs::CWD, "/", Access::EXISTS, AtFlags::empty())
        .expect("check root through faccessat");
    fs::accessat(
        fs::CWD,
        "/",
        Access::EXISTS,
        AtFlags::SYMLINK_NOFOLLOW,
    )
    .expect("check root through faccessat2");
    fs::accessat(fs::CWD, "/", Access::EXISTS, AtFlags::EACCESS)
        .expect("check root with effective credentials");
    println!("m10-accessat ok");
}
