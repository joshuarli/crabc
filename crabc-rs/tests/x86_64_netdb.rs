//! Native x86-64 regression for owned conventional netdb snapshots.
//!
//! These tests use caller bytes and read-only conventional-file smoke checks.
//! They deliberately do not select a C netdb ABI, NSS, `/etc/networks`, or any
//! process-global enumeration state.

use crabc_rs::net::{AddressFamily, IpAddress};
use crabc_rs::netdb::{
    HostDatabase, NetDbError, ProtocolDatabase, ServiceDatabase, ServiceProtocol,
};

#[test]
fn x86_64_hosts_snapshot_is_owned_and_system_loader_matches_direct_snapshot() {
    let mut input = b"192.0.2.17 canonical.example.test alias.example.test\n".to_vec();
    let hosts = HostDatabase::from_bytes(&input).expect("parse hosts fixture");
    input.fill(b'x');
    let copied_host = hosts
        .lookup("ALIAS.EXAMPLE.TEST", Some(AddressFamily::INET))
        .expect("case-insensitive owned host lookup");
    assert_eq!(copied_host.name(), "canonical.example.test");
    assert_eq!(copied_host.aliases(), &["alias.example.test"]);
    assert_eq!(copied_host.addresses(), &[IpAddress::V4([192, 0, 2, 17])]);
    drop(hosts);
    assert_eq!(copied_host.name(), "canonical.example.test");
    assert_eq!(
        HostDatabase::from_bytes(b"192.0.2.17 valid.example.test\nnot-an-address broken"),
        Err(NetDbError::InvalidInput)
    );

    let expected = HostDatabase::from_bytes(
        &std::fs::read("/etc/hosts").expect("read hosts fixture snapshot"),
    )
    .expect("parse hosts fixture snapshot");
    let direct = HostDatabase::from_system().expect("load direct hosts snapshot");
    assert_eq!(direct, expected);
    assert_eq!(direct.iter().count(), direct.len());
}

#[test]
fn x86_64_service_and_protocol_snapshots_are_owned_typed_and_ordered() {
    let mut services_input =
        b"https 443/tcp www\ndomain 53/udp\ncustom 4242/custom-proto alias\n".to_vec();
    let services = ServiceDatabase::from_bytes(&services_input).expect("parse services fixture");
    services_input.fill(b'x');
    assert_eq!(services.len(), 3);
    assert_eq!(services.entries()[0].name(), "https");
    let https = services
        .lookup("WWW", Some(ServiceProtocol::Tcp))
        .expect("case-insensitive service alias lookup");
    assert_eq!(https.port(), 443);
    assert_eq!(https.protocol(), ServiceProtocol::Tcp);
    assert_eq!(
        services
            .lookup_port(53, Some(ServiceProtocol::Udp))
            .expect("UDP port lookup")
            .name(),
        "domain"
    );
    let custom = services
        .lookup("alias", None)
        .expect("custom protocol alias lookup");
    assert_eq!(custom.protocol(), ServiceProtocol::Other);
    assert_eq!(custom.protocol_name(), "custom-proto");
    assert_eq!(custom.protocol().number(), 0);
    assert_eq!(services.iter().count(), services.len());
    let copied_service = services.lookup("https", None).expect("owned service copy");
    drop(services);
    assert_eq!(copied_service.name(), "https");
    assert_eq!(copied_service.aliases(), &["www"]);

    let mut protocols_input = b"tcp 6 TCP\nudp 17 UDP\ncustom 253 alias\n".to_vec();
    let protocols = ProtocolDatabase::from_bytes(&protocols_input).expect("parse protocols fixture");
    protocols_input.fill(b'x');
    assert_eq!(protocols.len(), 3);
    assert_eq!(protocols.entries()[0].name(), "tcp");
    assert_eq!(
        protocols
            .lookup_name("ALIAS")
            .expect("case-insensitive protocol alias lookup")
            .number(),
        253
    );
    assert_eq!(
        protocols
            .lookup_number(17)
            .expect("protocol-number lookup")
            .name(),
        "udp"
    );
    assert_eq!(protocols.iter().count(), protocols.len());
}

#[test]
fn x86_64_service_and_protocol_malformed_records_reject_the_complete_snapshot() {
    assert_eq!(
        ServiceDatabase::from_bytes(b"https 443/tcp\nbroken 80/tcp/extra"),
        Err(NetDbError::InvalidInput)
    );
    assert_eq!(
        ProtocolDatabase::from_bytes(b"tcp 6\nbroken 65536"),
        Err(NetDbError::Overflow)
    );
    assert_eq!(
        ProtocolDatabase::from_bytes(b"tcp 6\nbad\xff 1"),
        Err(NetDbError::InvalidInput)
    );
}

#[test]
fn x86_64_service_and_protocol_system_loaders_match_direct_snapshots() {
    let services_expected = ServiceDatabase::from_bytes(
        &std::fs::read("/etc/services").expect("read service fixture snapshot"),
    )
    .expect("parse service fixture snapshot");
    let services = ServiceDatabase::from_system().expect("load direct services snapshot");
    assert_eq!(services, services_expected);
    assert_eq!(services.iter().count(), services.len());

    let protocols_expected = ProtocolDatabase::from_bytes(
        &std::fs::read("/etc/protocols").expect("read protocol fixture snapshot"),
    )
    .expect("parse protocol fixture snapshot");
    let protocols = ProtocolDatabase::from_system().expect("load direct protocols snapshot");
    assert_eq!(protocols, protocols_expected);
    assert_eq!(protocols.iter().count(), protocols.len());
}
