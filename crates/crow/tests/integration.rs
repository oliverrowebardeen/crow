use bytes::Bytes;
use rand::RngCore;
use rand::rngs::OsRng;

use crow::{Cap, ChunkStore, Crow, ErasureParams, Error, Manifest, MemStore, Namespace};

/// Test-friendly chunk size: 65 520 bytes (= 64 KiB − 16). Picked so that
/// (chunk_size + AEAD tag) is exactly 64 KiB and aligns to the RS shard
/// requirement, while staying small enough that multi-stripe tests run fast
/// without storing huge per-share buffers.
const TEST_CHUNK_SIZE: u32 = 65520;

fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    OsRng.fill_bytes(&mut buf);
    buf
}

fn put(crow: &Crow<MemStore>, plaintext: &[u8]) -> Cap {
    crow.put_bytes_with(
        plaintext,
        "application/octet-stream",
        ErasureParams::default(),
        TEST_CHUNK_SIZE,
    )
    .expect("put_bytes_with succeeds")
}

#[test]
fn roundtrip_small() {
    let crow = Crow::new(MemStore::new());
    let payload = random_bytes(1024);
    let cap = put(&crow, &payload);
    assert_eq!(crow.get_bytes(&cap).unwrap(), payload);
}

#[test]
fn roundtrip_multi_stripe() {
    let crow = Crow::new(MemStore::new());
    let payload = random_bytes(5 * 1024 * 1024);
    let cap = put(&crow, &payload);
    assert_eq!(crow.get_bytes(&cap).unwrap(), payload);
}

#[test]
fn roundtrip_empty() {
    let crow = Crow::new(MemStore::new());
    let cap = put(&crow, &[]);
    assert!(crow.get_bytes(&cap).unwrap().is_empty());
}

#[test]
fn roundtrip_exact_chunk_size() {
    // File length exactly = chunk_size: no padding inside the chunk, but
    // padding inside the stripe (need K - 1 zero plaintext chunks).
    let crow = Crow::new(MemStore::new());
    let payload = random_bytes(TEST_CHUNK_SIZE as usize);
    let cap = put(&crow, &payload);
    assert_eq!(crow.get_bytes(&cap).unwrap(), payload);
}

#[test]
fn drop_n_minus_k_shares_still_recovers() {
    let crow = Crow::new(MemStore::new());
    let payload = random_bytes(5 * 1024 * 1024);
    let cap = put(&crow, &payload);

    // Pull the manifest open so we can reach the stripe shares directly.
    let encrypted = crow
        .store()
        .get(Namespace::Manifests, cap.manifest_hash.inner())
        .unwrap()
        .unwrap();
    let manifest = Manifest::open(&encrypted, &cap.manifest_key).unwrap();

    // Delete 2 of the 5 shares from stripe 0 (one data, one parity).
    let stripe0 = &manifest.stripes[0];
    let dropped_data = stripe0.data[0];
    let dropped_parity = stripe0.parity[0];
    assert!(
        crow.store()
            .delete(Namespace::Chunks, dropped_data.inner())
            .unwrap()
    );
    assert!(
        crow.store()
            .delete(Namespace::Chunks, dropped_parity.inner())
            .unwrap()
    );

    // Still recoverable: 3 shares present per stripe (at least), K = 3.
    assert_eq!(crow.get_bytes(&cap).unwrap(), payload);
}

#[test]
fn drop_too_many_shares_fails() {
    let crow = Crow::new(MemStore::new());
    let payload = random_bytes(5 * 1024 * 1024);
    let cap = put(&crow, &payload);

    let encrypted = crow
        .store()
        .get(Namespace::Manifests, cap.manifest_hash.inner())
        .unwrap()
        .unwrap();
    let manifest = Manifest::open(&encrypted, &cap.manifest_key).unwrap();

    // Drop 3 shares from stripe 0: 5 - 3 = 2 < K = 3.
    let s0 = &manifest.stripes[0];
    crow.store()
        .delete(Namespace::Chunks, s0.data[0].inner())
        .unwrap();
    crow.store()
        .delete(Namespace::Chunks, s0.data[1].inner())
        .unwrap();
    crow.store()
        .delete(Namespace::Chunks, s0.parity[0].inner())
        .unwrap();

    match crow.get_bytes(&cap) {
        Err(Error::NotEnoughShares { stripe, have, need }) => {
            assert_eq!(stripe, 0);
            assert_eq!(need, 3);
            assert_eq!(have, 2);
        }
        other => panic!("expected NotEnoughShares for stripe 0, got {other:?}"),
    }
}

#[test]
fn cap_with_wrong_manifest_key_fails() {
    let crow = Crow::new(MemStore::new());
    let payload = random_bytes(64);
    let cap = put(&crow, &payload);

    // Encode-decode (preserves all bytes), then tamper a byte of the manifest
    // key inside the decoded structure.
    let encoded = cap.encode();
    let mut decoded = Cap::decode(&encoded).unwrap();
    let mut key_bytes = *decoded.manifest_key.as_bytes();
    key_bytes[0] ^= 1;
    decoded.manifest_key = crow::ManifestKey::from_bytes(key_bytes);

    match crow.get_bytes(&decoded) {
        Err(Error::Aead) => {}
        other => panic!("expected Aead, got {other:?}"),
    }
}

#[test]
fn tampered_data_share_fails() {
    let crow = Crow::new(MemStore::new());
    let payload = random_bytes(2 * TEST_CHUNK_SIZE as usize);
    let cap = put(&crow, &payload);

    let encrypted = crow
        .store()
        .get(Namespace::Manifests, cap.manifest_hash.inner())
        .unwrap()
        .unwrap();
    let manifest = Manifest::open(&encrypted, &cap.manifest_key).unwrap();

    // Flip a byte in one stored data share.
    let target = manifest.stripes[0].data[0];
    let mut bytes = crow
        .store()
        .get(Namespace::Chunks, target.inner())
        .unwrap()
        .unwrap()
        .to_vec();
    bytes[0] ^= 1;
    crow.store()
        .put_unverified(Namespace::Chunks, *target.inner(), Bytes::from(bytes))
        .unwrap();

    match crow.get_bytes(&cap) {
        Err(Error::Aead) => {}
        other => panic!("expected Aead on tampered data share, got {other:?}"),
    }
}

#[test]
fn tampered_parity_share_fails_after_data_loss() {
    // Defence-in-depth: parity isn't AEAD-protected directly, but a tampered
    // parity share fed into RS-decode produces a wrong ciphertext that AEAD
    // then rejects. Force RS-decode by deleting one data share, then tamper
    // a parity share before reading.
    let crow = Crow::new(MemStore::new());
    let payload = random_bytes(2 * TEST_CHUNK_SIZE as usize);
    let cap = put(&crow, &payload);

    let encrypted = crow
        .store()
        .get(Namespace::Manifests, cap.manifest_hash.inner())
        .unwrap()
        .unwrap();
    let manifest = Manifest::open(&encrypted, &cap.manifest_key).unwrap();

    let s0 = &manifest.stripes[0];

    // Delete one data share so RS-decode must run.
    crow.store()
        .delete(Namespace::Chunks, s0.data[0].inner())
        .unwrap();

    // Tamper a parity share that the decoder will use.
    let parity_target = s0.parity[0];
    let mut bytes = crow
        .store()
        .get(Namespace::Chunks, parity_target.inner())
        .unwrap()
        .unwrap()
        .to_vec();
    bytes[0] ^= 1;
    crow.store()
        .put_unverified(
            Namespace::Chunks,
            *parity_target.inner(),
            Bytes::from(bytes),
        )
        .unwrap();

    match crow.get_bytes(&cap) {
        Err(Error::Aead) => {}
        other => panic!("expected Aead after parity tamper + RS-decode, got {other:?}"),
    }
}

#[test]
fn missing_manifest_returns_missing_chunk() {
    let crow = Crow::new(MemStore::new());
    let cap = put(&crow, b"x");
    crow.store()
        .delete(Namespace::Manifests, cap.manifest_hash.inner())
        .unwrap();
    match crow.get_bytes(&cap) {
        Err(Error::MissingChunk(_)) => {}
        other => panic!("expected MissingChunk, got {other:?}"),
    }
}

#[test]
fn cap_string_is_paste_friendly() {
    let crow = Crow::new(MemStore::new());
    let cap = put(&crow, b"share me");
    let encoded = cap.encode();
    assert!(encoded.starts_with("crow1"));
    assert!(encoded.chars().all(|c| c.is_ascii() && !c.is_whitespace()));
    let parsed = Cap::decode(&encoded).unwrap();
    assert_eq!(parsed.manifest_hash, cap.manifest_hash);
}
