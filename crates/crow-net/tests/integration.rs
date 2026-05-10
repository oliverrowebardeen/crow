//! End-to-end integration tests for the Phase 1 step 3 work: a daemon
//! advertises on mDNS, a second daemon discovers it, and the second
//! daemon's QUIC client fetches a manifest from the first using the
//! mDNS-discovered address.

use std::net::SocketAddr;
use std::time::Duration;

use crow::{Crow, ErasureParams, FsStore, Identity, Manifest, Namespace};
use crow_net::{
    Client, ClusterToken, Discovery, LocalAdvert, PeerSnapshot, SelfInfo, peer_snapshot,
};
use tempfile::TempDir;

async fn wait_for<F: Fn() -> bool>(total: Duration, step: Duration, pred: F) -> bool {
    let deadline = std::time::Instant::now() + total;
    loop {
        if pred() {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(step).await;
    }
}

#[tokio::test]
async fn fetch_via_mdns_discovered_address() {
    // Daemon A puts a file into its store, then begins serving + advertising.
    let tmp_a = TempDir::new().unwrap();
    let id_a = Identity::random();
    let token = ClusterToken::random();

    let cap = {
        let store = FsStore::open(tmp_a.path()).unwrap();
        let crow = Crow::new(store);
        crow.put_bytes_with(
            b"shared by daemon A",
            "text/plain",
            ErasureParams::default(),
            240,
            &id_a,
        )
        .unwrap()
    };

    let store_a = FsStore::open(tmp_a.path()).unwrap();
    let server_a = crow_net::serve(store_a, token, "127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr_a = server_a.local_addr();

    let discovery_a = Discovery::start(Some(LocalAdvert {
        node_id: id_a.node_id(),
        port: addr_a.port(),
        friendly_name: Some("daemon-a".into()),
    }))
    .unwrap();

    // Daemon B browses only (no advert) and looks for A.
    let discovery_b = Discovery::start(None).unwrap();

    let id_a_node = id_a.node_id();
    assert!(
        wait_for(Duration::from_secs(8), Duration::from_millis(200), || {
            discovery_b.peers().iter().any(|p| p.node_id == id_a_node)
        },)
        .await,
        "B never discovered A via mDNS"
    );

    // Pull A's record out of B's discovered peer list. The contract `crow
    // fetch <node-id-prefix>` relies on is: mDNS gives us the right node_id,
    // friendly_name, and *port*, and the address(es) for that peer can be
    // used to QUIC-connect. We verify all of that.
    let peer = discovery_b
        .peers()
        .into_iter()
        .find(|p| p.node_id == id_a_node)
        .expect("peer in B's view");
    assert_eq!(peer.friendly_name.as_deref(), Some("daemon-a"));
    assert!(
        peer.addresses.iter().any(|a| a.port() == addr_a.port()),
        "advertised port should match server's bound port; got {:?}",
        peer.addresses,
    );

    // mdns-sd's auto-addr collection gives us whatever the OS network stack
    // serves on loopback, which on macOS is IPv6 link-local (`fe80::1`) —
    // and Quinn (correctly) rejects link-local without a scope id. The
    // production case is "peer advertises 192.168.1.x and we connect to
    // 192.168.1.x:port"; on loopback we synthesise the routable equivalent
    // using the verified discovered port.
    let socket_addr: SocketAddr = format!("127.0.0.1:{}", addr_a.port()).parse().unwrap();

    let client = Client::connect(socket_addr).await.unwrap();
    client.hello(token).await.unwrap();

    let manifest_hash = *cap.manifest_hash.inner();
    let encrypted_manifest = client
        .get(token, Namespace::Manifests, manifest_hash)
        .await
        .unwrap()
        .expect("daemon A should have the manifest");
    let manifest = Manifest::open(&encrypted_manifest, &cap.manifest_key).unwrap();
    assert_eq!(manifest.file_size, b"shared by daemon A".len() as u64);

    discovery_a.shutdown().unwrap();
    discovery_b.shutdown().unwrap();
    drop(server_a);
}

#[tokio::test]
async fn snapshot_roundtrips_discovered_peers() {
    // Daemon A advertises; daemon B browses; B builds and saves a snapshot
    // with the freshly-discovered peer; we load it back and verify all the
    // fields make it through the JSON roundtrip.
    let tmp = TempDir::new().unwrap();
    let id_a = Identity::random();
    let id_b = Identity::random();

    let advert_a = LocalAdvert {
        node_id: id_a.node_id(),
        port: 7777,
        friendly_name: Some("alpha".into()),
    };
    let disc_a = Discovery::start(Some(advert_a)).unwrap();
    let disc_b = Discovery::start(None).unwrap();

    assert!(
        wait_for(Duration::from_secs(8), Duration::from_millis(200), || {
            disc_b.peers().iter().any(|p| p.node_id == id_a.node_id())
        },)
        .await,
        "B never discovered A"
    );

    let snap = PeerSnapshot {
        snapshot_at: peer_snapshot::now_unix(),
        self_info: SelfInfo {
            node_id: id_b.node_id(),
            friendly_name: Some("bravo".into()),
            address: "127.0.0.1:7878".parse().unwrap(),
        },
        peers: disc_b.peers(),
    };
    let path = peer_snapshot::snapshot_path(tmp.path());
    peer_snapshot::save(&path, &snap).unwrap();

    let loaded = peer_snapshot::load(&path).unwrap().unwrap();
    assert_eq!(loaded.self_info.node_id, id_b.node_id());
    assert_eq!(loaded.self_info.friendly_name.as_deref(), Some("bravo"));
    assert!(!loaded.peers.is_empty());
    let recorded = loaded
        .peers
        .iter()
        .find(|p| p.node_id == id_a.node_id())
        .expect("A in the loaded snapshot");
    assert_eq!(recorded.friendly_name.as_deref(), Some("alpha"));
    assert!(recorded.addresses.iter().any(|a| a.port() == 7777));

    disc_a.shutdown().unwrap();
    disc_b.shutdown().unwrap();
}
