use bytes::Bytes;
use rand::RngCore;
use rand::rngs::OsRng;
use tempfile::TempDir;

use std::fs;

use crow::{
    Cap, CatalogIndex, CatalogPath, ChunkStore, Crow, DirectoryEntry, DirectoryManifest,
    ErasureParams, Error, FsStore, GcOptions, Identity, Manifest, ManifestHash, ManifestKey,
    MemStore, Namespace, NestIndex, PinIndex, SignatureStatus, compute_live_set, sweep,
    targeted_remove,
};

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
    let identity = Identity::random();
    crow.put_bytes_with(
        plaintext,
        "application/octet-stream",
        ErasureParams::default(),
        TEST_CHUNK_SIZE,
        &identity,
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
fn put_bytes_writes_signed_manifest() {
    let crow = Crow::new(MemStore::new());
    let identity = Identity::random();
    let cap = crow
        .put_bytes_with(
            b"signed bytes",
            "text/plain",
            ErasureParams::default(),
            TEST_CHUNK_SIZE,
            &identity,
        )
        .unwrap();
    let encrypted = crow
        .store()
        .get(Namespace::Manifests, cap.manifest_hash.inner())
        .unwrap()
        .unwrap();
    let manifest = Manifest::open(&encrypted, &cap.manifest_key).unwrap();

    assert_eq!(
        manifest.signature_status().unwrap(),
        SignatureStatus::Signed {
            creator: identity.node_id()
        }
    );
}

#[test]
fn put_directory_manifest_writes_signed_manifest() {
    let crow = Crow::new(MemStore::new());
    let identity = Identity::random();
    let child = put(&crow, b"child");
    let manifest = DirectoryManifest::new(
        123,
        vec![DirectoryEntry::file(
            "child.txt",
            child,
            Some("child.txt".into()),
        )],
    )
    .unwrap();
    let cap = crow.put_directory_manifest(&manifest, &identity).unwrap();
    let opened = crow.open_directory_manifest(&cap).unwrap();

    assert_eq!(
        opened.signature_status().unwrap(),
        SignatureStatus::Signed {
            creator: identity.node_id()
        }
    );
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

// ----------------------------------------------------------------------
// Phase 1 — Step 1: pin / GC / daily-driver flows
// ----------------------------------------------------------------------

fn put_fs(crow: &Crow<FsStore>, plaintext: &[u8]) -> Cap {
    let identity = Identity::random();
    crow.put_bytes_with(
        plaintext,
        "application/octet-stream",
        ErasureParams::default(),
        TEST_CHUNK_SIZE,
        &identity,
    )
    .expect("put_bytes_with succeeds")
}

#[test]
fn pin_persists_across_handles_and_resolves_by_prefix() {
    let tmp = TempDir::new().unwrap();
    let payload = b"hello, persistent world";

    let cap = {
        let store = FsStore::open(tmp.path()).unwrap();
        let pins = PinIndex::open(tmp.path()).unwrap();
        let crow = Crow::new(store);
        let cap = put_fs(&crow, payload);
        pins.add(cap.clone(), Some("hello.txt".into()), None)
            .unwrap();
        cap
    };

    // Reopen at the same path and look up by 4-char prefix.
    let store = FsStore::open(tmp.path()).unwrap();
    let pins = PinIndex::open(tmp.path()).unwrap();
    let crow = Crow::new(store);

    let recs = pins.list().unwrap();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].name.as_deref(), Some("hello.txt"));

    let prefix = &cap.manifest_hash.to_string()[..4];
    let matches = pins.find_by_prefix(prefix).unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(crow.get_bytes(&matches[0].cap).unwrap(), payload);
}

#[test]
fn rm_deletes_target_chunks_but_preserves_other_pins() {
    let tmp = TempDir::new().unwrap();
    let store = FsStore::open(tmp.path()).unwrap();
    let crow = Crow::new(store);

    let alice = put_fs(&crow, b"alice");
    let bob = put_fs(&crow, b"bob");

    // Simulate `crow rm alice`: target = [alice], remaining = [bob].
    let report = targeted_remove(
        crow.store(),
        std::slice::from_ref(&alice),
        std::slice::from_ref(&bob),
        GcOptions::default(),
    )
    .unwrap();

    assert!(report.deleted_chunks > 0);
    assert!(report.deleted_manifests > 0);
    assert!(crow.get_bytes(&alice).is_err());
    assert_eq!(crow.get_bytes(&bob).unwrap(), b"bob");
}

#[test]
fn gc_full_sweep_reclaims_unpinned() {
    let tmp = TempDir::new().unwrap();
    let store = FsStore::open(tmp.path()).unwrap();
    let pins = PinIndex::open(tmp.path()).unwrap();
    let crow = Crow::new(store);

    let pinned = put_fs(&crow, b"keep me");
    let unpinned = put_fs(&crow, b"throw me away");

    pins.add(pinned.clone(), Some("keep".into()), None).unwrap();

    let pin_caps: Vec<Cap> = pins.list().unwrap().into_iter().map(|r| r.cap).collect();
    let live = compute_live_set(crow.store(), &pin_caps).unwrap();
    let report = sweep(crow.store(), &live, GcOptions::default()).unwrap();

    assert!(report.deleted_chunks > 0);
    assert!(report.deleted_manifests > 0);
    assert_eq!(crow.get_bytes(&pinned).unwrap(), b"keep me");
    assert!(crow.get_bytes(&unpinned).is_err());
}

#[test]
fn gc_dry_run_does_not_touch_disk() {
    let tmp = TempDir::new().unwrap();
    let store = FsStore::open(tmp.path()).unwrap();
    let crow = Crow::new(store);

    let cap = put_fs(&crow, b"phantom");
    let live = compute_live_set(crow.store(), &[]).unwrap();

    let report = sweep(crow.store(), &live, GcOptions { dry_run: true }).unwrap();
    assert!(report.deleted_chunks > 0);
    assert!(report.deleted_manifests > 0);

    // Nothing actually deleted: bytes still recoverable.
    assert_eq!(crow.get_bytes(&cap).unwrap(), b"phantom");
}

#[test]
fn rm_preserves_chunks_when_listed_in_remaining() {
    // Models the "shared chunk between two pins" case: even if target_caps
    // points at a manifest, listing it in remaining_caps must keep its
    // chunks alive.
    let tmp = TempDir::new().unwrap();
    let store = FsStore::open(tmp.path()).unwrap();
    let crow = Crow::new(store);

    let cap = put_fs(&crow, b"shared truth");

    let report = targeted_remove(
        crow.store(),
        std::slice::from_ref(&cap),
        std::slice::from_ref(&cap),
        GcOptions::default(),
    )
    .unwrap();
    assert_eq!(report.deleted_chunks, 0);
    assert_eq!(report.deleted_manifests, 0);
    assert_eq!(crow.get_bytes(&cap).unwrap(), b"shared truth");
}

#[test]
fn pin_prefix_collisions_are_detectable() {
    let tmp = TempDir::new().unwrap();
    let pins = PinIndex::open(tmp.path()).unwrap();

    // Two synthetic caps with distinct hex prefixes. Real-world hashes
    // rarely collide on more than a few characters; we just verify the
    // matching arithmetic.
    let cap_ab = Cap::new_read(
        ManifestHash::from_bytes([0xAB; 32]),
        ManifestKey::from_bytes([1; 32]),
    );
    let cap_cd = Cap::new_read(
        ManifestHash::from_bytes([0xCD; 32]),
        ManifestKey::from_bytes([2; 32]),
    );
    pins.add(cap_ab, None, None).unwrap();
    pins.add(cap_cd, None, None).unwrap();

    assert_eq!(pins.find_by_prefix("ab").unwrap().len(), 1);
    assert_eq!(pins.find_by_prefix("cd").unwrap().len(), 1);
    assert_eq!(pins.find_by_prefix("").unwrap().len(), 2);
    assert!(pins.find_by_prefix("ff").unwrap().is_empty());
}

#[test]
fn pinning_does_not_leak_into_chunk_store() {
    // Sanity check: PinIndex writes go to <home>/pins, not the chunk store
    // namespaces, so list and stat still reflect only chunks/manifests.
    let tmp = TempDir::new().unwrap();
    let store = FsStore::open(tmp.path()).unwrap();
    let pins = PinIndex::open(tmp.path()).unwrap();
    let crow = Crow::new(store);

    let cap = put_fs(&crow, b"x");
    pins.add(cap.clone(), Some("x".into()), None).unwrap();

    let chunks_count = crow.store().list(Namespace::Chunks).unwrap().len();
    let manifests_count = crow.store().list(Namespace::Manifests).unwrap().len();
    assert_eq!(manifests_count, 1);
    assert!(chunks_count >= 1);
    assert_eq!(pins.list().unwrap().len(), 1);
}

// ----------------------------------------------------------------------
// Phase 2 — nest foundation
// ----------------------------------------------------------------------

/// Pre-populate a legacy `<home>/{catalog,pins,chunks,manifests}` layout by
/// running the actual put pipeline against the home root, then drop the
/// returned handles so the migration in the next step starts from a clean
/// process state.
fn populate_legacy_home<P: AsRef<std::path::Path>>(
    home: P,
    payload: &[u8],
    identity: &Identity,
) -> Cap {
    let home = home.as_ref();
    let store = FsStore::open(home).expect("FsStore::open(home)");
    let pins = PinIndex::open(home).expect("PinIndex::open(home)");
    // Touch the catalog so the migration covers all four legacy directories.
    let catalog = CatalogIndex::open(home).expect("CatalogIndex::open(home)");
    catalog
        .mkdir("/inbox", false, identity)
        .expect("catalog mkdir");
    let crow = Crow::new(store);
    let cap = crow
        .put_bytes_with(
            payload,
            "application/octet-stream",
            ErasureParams::default(),
            TEST_CHUNK_SIZE,
            identity,
        )
        .expect("put_bytes_with");
    catalog
        .put_file("/inbox/file", cap.clone(), Some("file".into()), identity)
        .expect("catalog put_file");
    pins.add(cap.clone(), Some("legacy-file".into()), None)
        .expect("pin add");
    cap
}

#[test]
fn nest_migration_preserves_files() {
    // Lay down real put data at the legacy root, then run ensure_default and
    // confirm the bytes still reconstruct from the new nest dir.
    let tmp = TempDir::new().unwrap();
    let identity = Identity::random();
    let payload = random_bytes(64 * 1024); // 64 KiB
    let cap = populate_legacy_home(tmp.path(), &payload, &identity);

    let nests = NestIndex::ensure_default(tmp.path(), "test-device").unwrap();
    let nest_dir = nests.nest_dir(&nests.active().id);

    // Legacy paths should be gone.
    for sub in ["catalog", "pins", "chunks", "manifests"] {
        assert!(
            !tmp.path().join(sub).exists(),
            "<home>/{sub} should have moved into the nest dir"
        );
        assert!(
            nest_dir.join(sub).exists(),
            "{} should exist after migration",
            nest_dir.join(sub).display()
        );
    }

    // Bytes are still reconstructable through the nest-dir stores.
    let crow = Crow::new(FsStore::open(&nest_dir).unwrap());
    let restored = crow.get_bytes(&cap).expect("get_bytes after migration");
    assert_eq!(restored, payload);

    // The pin record was preserved under the nest dir.
    let pins = PinIndex::open(&nest_dir).unwrap();
    let listed = pins.list().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name.as_deref(), Some("legacy-file"));
}

#[test]
fn nest_isolation_keeps_pins_and_catalogs_separate() {
    // Create two nests, write different content in each, verify the other
    // nest's pins and catalog don't see it.
    let tmp = TempDir::new().unwrap();
    let mut nests = NestIndex::ensure_default(tmp.path(), "test-device").unwrap();
    let personal_id = nests.active().id;
    let work_id = nests.create("work", "test-device").unwrap().id;
    assert_ne!(personal_id, work_id);

    let personal_dir = nests.nest_dir(&personal_id);
    let work_dir = nests.nest_dir(&work_id);

    let personal_crow = Crow::new(FsStore::open(&personal_dir).unwrap());
    let personal_pins = PinIndex::open(&personal_dir).unwrap();
    let personal_catalog = CatalogIndex::open(&personal_dir).unwrap();
    let work_crow = Crow::new(FsStore::open(&work_dir).unwrap());
    let work_pins = PinIndex::open(&work_dir).unwrap();
    let work_catalog = CatalogIndex::open(&work_dir).unwrap();

    let identity = Identity::random();
    let personal_cap = personal_crow
        .put_bytes_with(
            b"personal bytes",
            "text/plain",
            ErasureParams::default(),
            240,
            &identity,
        )
        .unwrap();
    personal_pins
        .add(personal_cap.clone(), Some("personal".into()), None)
        .unwrap();
    personal_catalog
        .mkdir("/personal", false, &identity)
        .unwrap();
    personal_catalog
        .put_file(
            "/personal/file",
            personal_cap.clone(),
            Some("file".into()),
            &identity,
        )
        .unwrap();

    let work_cap = work_crow
        .put_bytes_with(
            b"work bytes",
            "text/plain",
            ErasureParams::default(),
            240,
            &identity,
        )
        .unwrap();
    work_pins
        .add(work_cap.clone(), Some("work".into()), None)
        .unwrap();
    work_catalog.mkdir("/work", false, &identity).unwrap();
    work_catalog
        .put_file(
            "/work/file",
            work_cap.clone(),
            Some("file".into()),
            &identity,
        )
        .unwrap();

    // Personal nest only sees personal pin + path.
    let personal_listed = personal_pins.list().unwrap();
    assert_eq!(personal_listed.len(), 1);
    assert_eq!(personal_listed[0].name.as_deref(), Some("personal"));
    let personal_view = personal_catalog.view().unwrap();
    assert!(personal_view.contains(&CatalogPath::normalize("/personal/file").unwrap()));
    assert!(!personal_view.contains(&CatalogPath::normalize("/work/file").unwrap()));

    // And vice versa.
    let work_listed = work_pins.list().unwrap();
    assert_eq!(work_listed.len(), 1);
    assert_eq!(work_listed[0].name.as_deref(), Some("work"));
    let work_view = work_catalog.view().unwrap();
    assert!(work_view.contains(&CatalogPath::normalize("/work/file").unwrap()));
    assert!(!work_view.contains(&CatalogPath::normalize("/personal/file").unwrap()));

    // The encrypted chunks live in disjoint directories on disk.
    assert!(personal_dir.join("chunks").exists());
    assert!(work_dir.join("chunks").exists());
}

#[test]
fn nest_partial_migration_recovers_without_data_loss() {
    // Simulate a crash mid-migration: legacy directories are gone, nest dir
    // exists with content, but nests.json was never written. ensure_default
    // must write nests.json and recognise the existing nest dir.
    let tmp = TempDir::new().unwrap();
    let identity = Identity::random();
    let marker_payload = b"survived";
    let cap = populate_legacy_home(tmp.path(), marker_payload, &identity);

    // Do the first half of the migration by hand to model the crashed state.
    let nest_id_str = "deadbeefcafef00d0102030405060708"; // 32 hex chars
    let nest_dir = tmp.path().join("nests").join(nest_id_str);
    fs::create_dir_all(&nest_dir).unwrap();
    for sub in ["catalog", "pins", "chunks", "manifests"] {
        fs::rename(tmp.path().join(sub), nest_dir.join(sub)).unwrap();
    }
    assert!(!tmp.path().join("nests.json").exists());

    // ensure_default should write nests.json pointing at the existing dir.
    let nests = NestIndex::ensure_default(tmp.path(), "test-device").unwrap();
    assert_eq!(nests.active().id.to_string(), nest_id_str);
    assert!(tmp.path().join("nests.json").exists());

    // And the bytes still reconstruct through the recovered nest dir.
    let crow = Crow::new(FsStore::open(&nest_dir).unwrap());
    assert_eq!(crow.get_bytes(&cap).unwrap(), marker_payload);
}
