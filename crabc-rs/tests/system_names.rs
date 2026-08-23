use crabc_rs::system;

#[test]
fn owned_uname_fields_are_the_native_hostname_and_domainname_observations() {
    let names = system::uname();
    let hostname = names.nodename();
    let domainname = names.domainname();

    // Linux's UTSNAME fields have 65 bytes including their terminator. The
    // typed CStr view cannot expose an unterminated or interior-NUL name.
    assert!(hostname.to_bytes().len() <= 64);
    assert!(domainname.to_bytes().len() <= 64);

    // This is the Rustix-approved native route for the C
    // gethostname/getdomainname information. It owns the complete UTS value
    // instead of making the caller allocate a C buffer or reason about its
    // truncation rules.
}
