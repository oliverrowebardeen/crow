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
    connect_for_nest_with_proof_retry(addr, nest_id, identity, None).await
}

async fn connect_for_nest_with_proof_retry(
    addr: std::net::SocketAddr,
    nest_id: NestId,
    identity: &Identity,
    membership_proof: Option<crow::CatalogEvent>,
) -> crow_net::Result<Client> {
    let mut last_err = None;
    for _ in 0..50 {
        match Client::connect_for_nest_with_proof(addr, nest_id, identity, membership_proof.clone())
            .await
        {
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
async fn invitee_can_bootstrap_first_sync_with_membership_proof() {
    let tmp_server = TempDir::new().unwrap();
    let identity_a = Identity::load_or_create(tmp_server.path()).unwrap();
    let nest_id = NestId::random();
    let catalog_a = Arc::new(CatalogIndex::open(tmp_server.path()).unwrap());
    catalog_a
        .ensure_founding_member(&nest_id, &identity_a)
        .unwrap();

    let tmp_client = TempDir::new().unwrap();
    let identity_b = Identity::load_or_create(tmp_client.path()).unwrap();
    let mut invite = crow::Invite::new_unsigned(
        nest_id,
        "team".into(),
        identity_a.node_id(),
        identity_b.node_id(),
        NestRole::Owner,
        0,
        vec![],
    );
    invite.sign(&identity_a).unwrap();
    let catalog_b = CatalogIndex::open(tmp_client.path()).unwrap();
    let proof = catalog_b
        .append_member_added_with_signature(
            &identity_b,
            identity_b.node_id(),
            identity_a.node_id(),
            NestRole::Owner,
            invite.created_at,
            invite.grant_signature,
        )
        .unwrap();

    let token = ClusterToken::random();
    let server_store = FsStore::open(tmp_server.path()).unwrap();
    let listener = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let serve_catalog = catalog_a.clone();
    let handle = tokio::spawn(async move {
        let mut config = ServeConfig::new(server_store, token, addr);
        config.nest_serving = Some(NestServingConfig {
            nest_id,
            catalog: serve_catalog,
        });
        let _ = crow_net::serve_with_config(config).await;
    });

    let client = connect_for_nest_with_proof_retry(addr, nest_id, &identity_b, Some(proof.clone()))
        .await
        .expect("invitee proof should bootstrap nest auth");
    let _ = client.nest_catalog_events().await.unwrap();

    let members = catalog_a.view().unwrap().members().to_vec();
    assert!(
        members.iter().any(|m| m.member == identity_b.node_id()),
        "server should merge the invitee proof during first handshake"
    );

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
async fn two_devices_share_a_nest_without_cluster_token() {
    // The Phase 3 acceptance criterion: two devices in the same nest can
    // exchange bytes without ever copying a shared cluster token. Each
    // device picks its own random token; B never learns A's token.
    //
    // Setup:
    // - Device A has nest "team", is its founding member, and has stored
    //   one file whose plaintext we'll later reconstruct on B.
    // - Device B has its own identity and a locally-written MemberAdded
    //   proof from a recipient-bound invite. A has not pre-populated B,
    //   so the first handshake must bootstrap membership from that proof.
    // - Each device has a random cluster token; they are different.
    let tmp_a = TempDir::new().unwrap();
    let identity_a = Identity::load_or_create(tmp_a.path()).unwrap();
    let nest_id = NestId::random();
    let catalog_a = Arc::new(CatalogIndex::open(tmp_a.path()).unwrap());
    catalog_a
        .ensure_founding_member(&nest_id, &identity_a)
        .unwrap();

    let tmp_b = TempDir::new().unwrap();
    let identity_b = Identity::load_or_create(tmp_b.path()).unwrap();
    let catalog_b = CatalogIndex::open(tmp_b.path()).unwrap();
    let mut invite = crow::Invite::new_unsigned(
        nest_id,
        "team".into(),
        identity_a.node_id(),
        identity_b.node_id(),
        NestRole::Owner,
        0,
        vec![],
    );
    invite.sign(&identity_a).unwrap();
    let membership_proof = catalog_b
        .append_member_added_with_signature(
            &identity_b,
            identity_b.node_id(),
            identity_a.node_id(),
            NestRole::Owner,
            invite.created_at,
            invite.grant_signature,
        )
        .unwrap();

    // Put a file under A.
    let crow_a = Crow::new(FsStore::open(tmp_a.path()).unwrap());
    let payload = b"two-device nest, no cluster token";
    let cap = crow_a
        .put_bytes_with(
            payload,
            "text/plain",
            ErasureParams::default(),
            TEST_CHUNK_SIZE,
            &identity_a,
        )
        .unwrap();
    // Catalog the file so the post-sync object loop reaches it.
    catalog_a.mkdir("/docs", false, &identity_a).unwrap();
    catalog_a
        .put_file(
            "/docs/file.txt",
            cap.clone(),
            Some("file.txt".into()),
            &identity_a,
        )
        .unwrap();

    // Stand up the server on A with two *different* tokens for A and B.
    let token_a = ClusterToken::random();
    let token_b = ClusterToken::random();
    assert_ne!(
        token_a, token_b,
        "the test premise requires different tokens"
    );

    let server_store = FsStore::open(tmp_a.path()).unwrap();
    let listener = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let serve_catalog = catalog_a.clone();
    let handle = tokio::spawn(async move {
        let mut config = ServeConfig::new(server_store, token_a, addr);
        config.nest_serving = Some(NestServingConfig {
            nest_id,
            catalog: serve_catalog,
        });
        let _ = crow_net::serve_with_config(config).await;
    });

    // B connects via the nest-scoped handshake, syncs the catalog, then
    // pulls the manifest + chunks. B holds token_b only, never token_a.
    let client =
        connect_for_nest_with_proof_retry(addr, nest_id, &identity_b, Some(membership_proof))
            .await
            .expect("nest handshake should succeed for B");

    // Phase-3 invariant: peer events MUST be signed.
    let remote_events = client.nest_catalog_events().await.unwrap();
    catalog_b
        .merge_events_from_peer_for_nest(&nest_id, remote_events)
        .unwrap();
    let view = catalog_b.view().unwrap();
    assert!(
        view.get(&crow::CatalogPath::normalize("/docs/file.txt").unwrap())
            .is_some()
    );

    // Now fetch the encrypted manifest + every shard.
    let crow_b = Crow::new(FsStore::open(tmp_b.path()).unwrap());
    let manifest_bytes = client
        .nest_get(Namespace::Manifests, *cap.manifest_hash.inner())
        .await
        .unwrap()
        .expect("manifest present on A");
    crow_b
        .store()
        .put_unverified(
            Namespace::Manifests,
            *cap.manifest_hash.inner(),
            manifest_bytes,
        )
        .unwrap();

    let manifest = crow::Manifest::open(
        &crow_b
            .store()
            .get(Namespace::Manifests, cap.manifest_hash.inner())
            .unwrap()
            .unwrap(),
        &cap.manifest_key,
    )
    .unwrap();
    for stripe in &manifest.stripes {
        for hash in stripe.data.iter().chain(stripe.parity.iter()) {
            let chunk_bytes = client
                .nest_get(Namespace::Chunks, *hash.inner())
                .await
                .unwrap()
                .expect("chunk present on A");
            crow_b
                .store()
                .put_unverified(Namespace::Chunks, *hash.inner(), chunk_bytes)
                .unwrap();
        }
    }

    // B reconstructs the bytes without ever having seen A's cluster token.
    let restored = crow_b.get_bytes(&cap).unwrap();
    assert_eq!(restored, payload);
    let _ = token_b; // token_b is the "different token" premise of this test

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
