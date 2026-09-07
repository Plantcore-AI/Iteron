use std::net::IpAddr;
use std::time::Duration;

use super::NetworkZone;
use super::OAuthHttpClient;
use super::classify_ip;

#[test]
fn network_zone_transitions_never_enter_a_more_privileged_network() {
    assert!(NetworkZone::Public.permits(NetworkZone::Public));
    assert!(!NetworkZone::Public.permits(NetworkZone::Private));
    assert!(!NetworkZone::Public.permits(NetworkZone::Loopback));

    assert!(NetworkZone::Private.permits(NetworkZone::Public));
    assert!(NetworkZone::Private.permits(NetworkZone::Private));
    assert!(!NetworkZone::Private.permits(NetworkZone::Loopback));

    assert!(NetworkZone::Loopback.permits(NetworkZone::Public));
    assert!(NetworkZone::Loopback.permits(NetworkZone::Private));
    assert!(NetworkZone::Loopback.permits(NetworkZone::Loopback));
}

#[tokio::test]
async fn public_oauth_discovery_refuses_local_networks_before_dispatch() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let client = OAuthHttpClient::with_source_zone(NetworkZone::Public);

    for target in [
        format!("https://127.0.0.1:{port}/metadata"),
        format!("https://localhost:{port}/metadata"),
        "https://10.0.0.1/metadata".to_owned(),
        "https://169.254.169.254/metadata".to_owned(),
        "https://[fe80::1]/metadata".to_owned(),
    ] {
        let error = client
            .get(&url::Url::parse(&target).unwrap(), "resource metadata")
            .await
            .expect_err("more privileged targets must be rejected before dispatch");
        assert!(
            error.to_string().contains("more privileged network zone"),
            "target={target} error={error:#}",
        );
    }

    assert!(
        tokio::time::timeout(Duration::from_millis(20), listener.accept())
            .await
            .is_err()
    );
}

#[test]
fn private_loopback_and_link_local_addresses_are_not_public() {
    for address in [
        "10.0.0.1",
        "172.16.0.1",
        "192.168.0.1",
        "169.254.169.254",
        "100.64.0.1",
        "fc00::1",
        "fe80::1",
    ] {
        assert_eq!(
            classify_ip(address.parse::<IpAddr>().unwrap()),
            NetworkZone::Private,
            "address={address}",
        );
    }
    for address in ["127.0.0.1", "::1", "::ffff:127.0.0.1"] {
        assert_eq!(
            classify_ip(address.parse::<IpAddr>().unwrap()),
            NetworkZone::Loopback,
            "address={address}",
        );
    }
}
