use crow::{ChunkStore, Crow, ErasureParams, FsStore, Namespace};
use crow_net::{Client, ClusterToken};
use tempfile::TempDir;

const TEST_CHUNK_SIZE: u32 = 65520;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_fetches_manifest_and_chunk() {
    let tmp = TempDir::new().unwrap();
    let store = FsStore::open(tmp.path()).unwrap();
    let crow = Crow::new(store);
    let cap = crow
        .put_bytes_with(
            b"hello over quic",
            "text/plain",
            ErasureParams::default(),
            TEST_CHUNK_SIZE,
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
    assert!(client
        .have(token, Namespace::Manifests, *cap.manifest_hash.inner())
        .await
        .unwrap());

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
