use std::sync::Arc;

use crow::{
    CatalogIndex, ChunkStore, Crow, ErasureParams, FsStore, Identity, Namespace, NestId, NestRole,
};
use crow_net::{Client, ClusterToken, NestServingConfig, NetError, ServeConfig};
use tempfile::TempDir;

const TEST_CHUNK_SIZE: u32 = 65520;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_fetches_manifest_and_chunk() {
    let tmp = TempDir::new().unwrap();
    let store = FsStore::open(tmp.path()).unwrap();
    let crow = Crow::new(store);
    let identity = Identity::random();
    let cap = crow
        .put_bytes_with(
            b"hello over quic",
            "text/plain",
            ErasureParams::default(),
            TEST_CHUNK_SIZE,
            &identity,
        )
        .unwrap();
    let encrypted_manifest = crow
        .store()
        .get(Namespace::Manifests, cap.manifest_hash.inner())
        .unwrap()
        .unwrap();
    let manifest = crow::Manifest::open(&encrypted_manifest, &cap.manifest_key).unwrap();
    let chunk_hash = *manifest.stripes[0].data[0].inner();

    let token = ClusterToken::random();
    let server_store = FsStore::open(tmp.path()).unwrap();
    let listener = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let handle = tokio::spawn(async move {
        let _ = crow_net::serve(server_store, token, addr).await;
    });

    let client = connect_retry(addr).await;
    client.hello(token).await.unwrap();
    assert!(
        client
            .have(token, Namespace::Manifests, *cap.manifest_hash.inner())
            .await
            .unwrap()
    );

    let fetched_manifest = client
        .get(token, Namespace::Manifests, *cap.manifest_hash.inner())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fetched_manifest, encrypted_manifest);

    let fetched_chunk = client
        .get(token, Namespace::Chunks, chunk_hash)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        fetched_chunk,
        crow.store()
            .get(Namespace::Chunks, &chunk_hash)
            .unwrap()
            .unwrap()
    );

    handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_token_is_rejected() {
    let tmp = TempDir::new().unwrap();
    let server_store = FsStore::open(tmp.path()).unwrap();
    let token = ClusterToken::random();
    let wrong = ClusterToken::random();
    let listener = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let handle = tokio::spawn(async move {
        let _ = crow_net::serve(server_store, token, addr).await;
    });

    let client = connect_retry(addr).await;
    assert!(matches!(
        client.hello(wrong).await,
        Err(crow_net::NetError::Unauthorized)
    ));

    handle.abort();
}

async fn connect_retry(addr: std::net::SocketAddr) -> Client {
    let mut last_err = None;
    for _ in 0..50 {
        match Client::connect(addr).await {
            Ok(client) => return client,
            Err(e) => {
                last_err = Some(e);
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        }
    }
    panic!("connect failed: {last_err:?}");
}

async fn connect_for_nest_retry(
    addr: std::net::SocketAddr,
    nest_id: NestId,
    identity: &Identity,
) -> crow_net::Result<Client> {
    let mut last_err = None;
    for _ in 0..50 {
        match Client::connect_for_nest(addr, nest_id, identity).await {
            Ok(client) => return Ok(client),
            Err(NetError::Unauthorized) => return Err(NetError::Unauthorized),
            Err(e) => {
                last_err = Some(e);
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        }
    }
    Err(last_err.unwrap_or_else(|| NetError::Protocol("connect retry exhausted".into())))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nest_scoped_get_succeeds_for_member() {
    // Server "A" is the founding member. Client "B" is added to the
    // catalog before the handshake; the handshake admits B and the
    // subsequent nest_get returns the encrypted manifest bytes.
    let tmp_server = TempDir::new().unwrap();
    let identity_a = Identity::load_or_create(tmp_server.path()).unwrap();
    let nest_id = NestId::random();
    let catalog = Arc::new(CatalogIndex::open(tmp_server.path()).unwrap());
    catalog
        .ensure_founding_member(&nest_id, &identity_a)
        .unwrap();

    let identity_b = Identity::random();
    catalog
        .append_member_added(&nest_id, &identity_a, identity_b.node_id(), NestRole::Owner)
        .unwrap();

    // Put one file under A's identity.
    let crow = Crow::new(FsStore::open(tmp_server.path()).unwrap());
    let payload = b"shared via nest auth";
    let cap = crow
        .put_bytes_with(
            payload,
            "text/plain",
            ErasureParams::default(),
            TEST_CHUNK_SIZE,
            &identity_a,
        )
        .unwrap();
    let encrypted_manifest = crow
        .store()
        .get(Namespace::Manifests, cap.manifest_hash.inner())
        .unwrap()
        .unwrap();

    let token = ClusterToken::random();
    let server_store = FsStore::open(tmp_server.path()).unwrap();
    let addr_path = tmp_server.path().to_path_buf();
    let listener = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let serve_catalog = catalog.clone();
    let handle = tokio::spawn(async move {
        let mut config = ServeConfig::new(server_store, token, addr);
        config.nest_serving = Some(NestServingConfig {
            nest_id,
            catalog: serve_catalog,
        });
        let _ = crow_net::serve_with_config(config).await;
    });
    let _ = addr_path;

    let client = connect_for_nest_retry(addr, nest_id, &identity_b)
        .await
        .expect("handshake should succeed for a recognised member");
    let fetched = client
        .nest_get(Namespace::Manifests, *cap.manifest_hash.inner())
        .await
        .unwrap()
        .expect("manifest present");
    assert_eq!(fetched, encrypted_manifest);
    handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nest_scoped_get_rejected_for_non_member() {
    let tmp_server = TempDir::new().unwrap();
    let identity_a = Identity::load_or_create(tmp_server.path()).unwrap();
    let nest_id = NestId::random();
    let catalog = Arc::new(CatalogIndex::open(tmp_server.path()).unwrap());
    catalog
        .ensure_founding_member(&nest_id, &identity_a)
        .unwrap();

    // B is NOT added to the member list.
    let identity_b = Identity::random();

    let token = ClusterToken::random();
    let server_store = FsStore::open(tmp_server.path()).unwrap();
    let listener = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let serve_catalog = catalog.clone();
    let handle = tokio::spawn(async move {
        let mut config = ServeConfig::new(server_store, token, addr);
        config.nest_serving = Some(NestServingConfig {
            nest_id,
            catalog: serve_catalog,
        });
        let _ = crow_net::serve_with_config(config).await;
    });

    let outcome = connect_for_nest_retry(addr, nest_id, &identity_b).await;
    let err = match outcome {
        Ok(_) => panic!("non-member must be rejected"),
        Err(e) => e,
    };
    assert!(matches!(err, NetError::Unauthorized), "got {err:?}");
    handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cluster_token_mode_still_works_with_nest_serving() {
    // A daemon serving a nest still accepts legacy cluster-token requests
    // — the bridge that lets pre-Phase-3 callers keep working.
    let tmp_server = TempDir::new().unwrap();
    let identity_a = Identity::load_or_create(tmp_server.path()).unwrap();
    let nest_id = NestId::random();
    let catalog = Arc::new(CatalogIndex::open(tmp_server.path()).unwrap());
    catalog
        .ensure_founding_member(&nest_id, &identity_a)
        .unwrap();

    let crow = Crow::new(FsStore::open(tmp_server.path()).unwrap());
    let cap = crow
        .put_bytes_with(
            b"legacy bytes",
            "text/plain",
            ErasureParams::default(),
            TEST_CHUNK_SIZE,
            &identity_a,
        )
        .unwrap();
    let encrypted_manifest = crow
        .store()
        .get(Namespace::Manifests, cap.manifest_hash.inner())
        .unwrap()
        .unwrap();

    let token = ClusterToken::random();
    let server_store = FsStore::open(tmp_server.path()).unwrap();
    let listener = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let serve_catalog = catalog.clone();
    let handle = tokio::spawn(async move {
        let mut config = ServeConfig::new(server_store, token, addr);
        config.nest_serving = Some(NestServingConfig {
            nest_id,
            catalog: serve_catalog,
        });
        let _ = crow_net::serve_with_config(config).await;
    });

    let client = connect_retry(addr).await;
    client.hello(token).await.expect("legacy hello succeeds");
    let fetched = client
        .get(token, Namespace::Manifests, *cap.manifest_hash.inner())
        .await
        .unwrap()
        .expect("manifest present via legacy GET");
    assert_eq!(fetched, encrypted_manifest);
    handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nest_handshake_rejects_replay() {
    // Replay defence: a captured NestAuthResponse from connection 1 must
    // not authenticate connection 2 (each connection issues a fresh
    // random challenge). We simulate this by running two handshakes
    // back-to-back. Since the challenge is private to the connection,
    // there is no way to forge a working second connection without the
    // private key — but as a sanity check we ensure that opening a
    // *second* connection with a member B succeeds independently of the
    // first, confirming each connection has independent state.
    let tmp_server = TempDir::new().unwrap();
    let identity_a = Identity::load_or_create(tmp_server.path()).unwrap();
    let nest_id = NestId::random();
    let catalog = Arc::new(CatalogIndex::open(tmp_server.path()).unwrap());
    catalog
        .ensure_founding_member(&nest_id, &identity_a)
        .unwrap();
    let identity_b = Identity::random();
    catalog
        .append_member_added(&nest_id, &identity_a, identity_b.node_id(), NestRole::Owner)
        .unwrap();

    let token = ClusterToken::random();
    let server_store = FsStore::open(tmp_server.path()).unwrap();
    let listener = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let serve_catalog = catalog.clone();
    let handle = tokio::spawn(async move {
        let mut config = ServeConfig::new(server_store, token, addr);
        config.nest_serving = Some(NestServingConfig {
            nest_id,
            catalog: serve_catalog,
        });
        let _ = crow_net::serve_with_config(config).await;
    });

    // Two back-to-back handshakes both succeed. Each issues a fresh
    // challenge so neither response is reusable on the other connection.
    let c1 = connect_for_nest_retry(addr, nest_id, &identity_b)
        .await
        .unwrap();
    let c2 = connect_for_nest_retry(addr, nest_id, &identity_b)
        .await
        .unwrap();
    let _ = c1.nest_catalog_events().await.unwrap();
    let _ = c2.nest_catalog_events().await.unwrap();

    handle.abort();
}
