//! End-to-end demo: random 5 MiB file → put → drop two shares per stripe →
//! reconstruct from cap → assert equal.
//!
//! Run with `cargo run -p crow --example roundtrip`.

use rand::RngCore;
use rand::rngs::OsRng;

use crow::{Cap, ChunkStore, Crow, ErasureParams, Manifest, MemStore, Namespace};

const PAYLOAD_BYTES: usize = 5 * 1024 * 1024;
const CHUNK_SIZE: u32 = 65520; // 64 KiB - 16, aligned for RS

fn main() {
    let crow = Crow::new(MemStore::new());

    let mut payload = vec![0u8; PAYLOAD_BYTES];
    OsRng.fill_bytes(&mut payload);
    println!(
        "[crow] generated {} bytes of random plaintext",
        payload.len()
    );

    let cap = crow
        .put_bytes_with(
            &payload,
            "application/octet-stream",
            ErasureParams::default(),
            CHUNK_SIZE,
        )
        .expect("put_bytes_with");
    let encoded = cap.encode();
    println!("[crow] cap         {encoded}");
    println!("[crow] cap length  {} chars", encoded.len());
    println!("[crow] store size  {} chunks", crow.store().len());

    drop_two_shares_per_stripe(&crow, &cap);

    let restored = crow.get_bytes(&cap).expect("get_bytes after share loss");
    assert_eq!(restored.len(), payload.len(), "length mismatch");
    assert_eq!(restored, payload, "content mismatch");
    println!(
        "[crow] reconstructed {} bytes from cap; bytes match",
        restored.len()
    );

    // Also verify the cap roundtrips through its bech32m form.
    let parsed = Cap::decode(&encoded).expect("cap decode");
    let again = crow.get_bytes(&parsed).expect("get_bytes via decoded cap");
    assert_eq!(again, payload);
    println!("[crow] roundtripped through encoded cap; bytes still match");
}

fn drop_two_shares_per_stripe(crow: &Crow<MemStore>, cap: &Cap) {
    let encrypted_manifest = crow
        .store()
        .get(Namespace::Manifests, cap.manifest_hash.inner())
        .unwrap()
        .unwrap();
    let manifest = Manifest::open(&encrypted_manifest, &cap.manifest_key).unwrap();

    let mut dropped = 0usize;
    for stripe in &manifest.stripes {
        // Drop one data share + one parity share = 2 shares per stripe.
        // 3-of-5 still recoverable from the remaining 3.
        crow.store()
            .delete(Namespace::Chunks, stripe.data[0].inner())
            .unwrap();
        crow.store()
            .delete(Namespace::Chunks, stripe.parity[0].inner())
            .unwrap();
        dropped += 2;
    }
    let remaining = crow.store().len();
    println!(
        "[crow] dropped {dropped} shares across {} stripes; {remaining} chunks remain",
        manifest.stripes.len()
    );
}
