use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;

use crate::cap::Cap;
use crate::chunk::{ChunkStore, Namespace};
use crate::crypto::{self, FileKey, ManifestKey};
use crate::erasure::{self, DEFAULT_CHUNK_SIZE, ErasureParams};
use crate::error::{Error, Result};
use crate::hash::{ChunkHash, Hash, ManifestHash};
use crate::manifest::{Algorithm, MANIFEST_VERSION, Manifest, Stripe};

/// Top-level facade tying chunk store, crypto, erasure, manifest, and cap
/// layers together. Generic over any [`ChunkStore`] backend.
pub struct Crow<S: ChunkStore> {
    store: S,
}

impl<S: ChunkStore> Crow<S> {
    pub fn new(store: S) -> Self {
        Self { store }
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    /// Encrypt, erasure-code, and store the bytes; return a read capability.
    /// Uses [`DEFAULT_CHUNK_SIZE`] for chunking.
    pub fn put_bytes(&self, plaintext: &[u8], mime: &str, params: ErasureParams) -> Result<Cap> {
        self.put_bytes_with(plaintext, mime, params, DEFAULT_CHUNK_SIZE)
    }

    /// Variant that lets callers tune `chunk_size` (must satisfy
    /// [`erasure::validate_chunk_size`]). Useful for tests; production code
    /// should generally stick with [`DEFAULT_CHUNK_SIZE`].
    pub fn put_bytes_with(
        &self,
        plaintext: &[u8],
        mime: &str,
        params: ErasureParams,
        chunk_size: u32,
    ) -> Result<Cap> {
        params.validate()?;
        erasure::validate_chunk_size(chunk_size)?;

        let k = params.k as usize;
        let chunk_size_usize = chunk_size as usize;

        let file_key = FileKey::random();
        let manifest_key = ManifestKey::random();

        let num_plaintext_chunks = if plaintext.is_empty() {
            0
        } else {
            plaintext.len().div_ceil(chunk_size_usize)
        };
        let num_stripes = num_plaintext_chunks.div_ceil(k);

        let mut stripes = Vec::with_capacity(num_stripes);

        for stripe_idx in 0..num_stripes {
            let mut data_ciphertexts: Vec<Vec<u8>> = Vec::with_capacity(k);

            for data_idx in 0..k {
                let global_chunk_idx = stripe_idx * k + data_idx;
                // Plaintext chunk: real bytes if we have them, padded with
                // zeros otherwise. Trailing zeros are recovered by truncating
                // to file_size at decode.
                let mut plain_chunk = vec![0u8; chunk_size_usize];
                if global_chunk_idx < num_plaintext_chunks {
                    let start = global_chunk_idx * chunk_size_usize;
                    let end = (start + chunk_size_usize).min(plaintext.len());
                    plain_chunk[..end - start].copy_from_slice(&plaintext[start..end]);
                }

                let ciphertext = crypto::seal_chunk(
                    &file_key,
                    stripe_idx as u64,
                    data_idx as u32,
                    &plain_chunk,
                )?;
                data_ciphertexts.push(ciphertext);
            }

            let parity_ciphertexts = erasure::encode_parity(params, &data_ciphertexts)?;

            let mut data_hashes = Vec::with_capacity(k);
            for ct in &data_ciphertexts {
                let h = Hash::of(ct);
                self.store
                    .put_unverified(Namespace::Chunks, h, Bytes::copy_from_slice(ct))?;
                data_hashes.push(ChunkHash(h));
            }

            let mut parity_hashes = Vec::with_capacity(parity_ciphertexts.len());
            for pc in &parity_ciphertexts {
                let h = Hash::of(pc);
                self.store
                    .put_unverified(Namespace::Chunks, h, Bytes::copy_from_slice(pc))?;
                parity_hashes.push(ChunkHash(h));
            }

            stripes.push(Stripe {
                data: data_hashes,
                parity: parity_hashes,
            });
        }

        let manifest = Manifest {
            version: MANIFEST_VERSION,
            algorithm: Algorithm::default(),
            file_size: plaintext.len() as u64,
            mime_type: mime.to_string(),
            file_key,
            erasure: params,
            chunk_size,
            stripes,
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            creator_pubkey: None,
            signature: None,
        };

        let sealed = manifest.seal(&manifest_key)?;
        let manifest_hash_inner = Hash::of(&sealed);
        let manifest_hash = ManifestHash(manifest_hash_inner);
        self.store.put_unverified(
            Namespace::Manifests,
            manifest_hash_inner,
            Bytes::from(sealed),
        )?;

        Ok(Cap::new_read(manifest_hash, manifest_key))
    }

    /// Reconstruct the bytes referenced by `cap`, using parity to recover any
    /// missing data shares.
    pub fn get_bytes(&self, cap: &Cap) -> Result<Vec<u8>> {
        let encrypted_manifest = self
            .store
            .get(Namespace::Manifests, cap.manifest_hash.inner())?
            .ok_or_else(|| Error::MissingChunk(format!("manifest {}", cap.manifest_hash)))?;

        let manifest = Manifest::open(&encrypted_manifest, &cap.manifest_key)?;

        let k = manifest.erasure.k as usize;
        let parity_count = manifest.erasure.parity_count() as usize;

        let mut plaintext = Vec::with_capacity(manifest.file_size as usize);

        for (stripe_idx, stripe) in manifest.stripes.iter().enumerate() {
            if stripe.data.len() != k || stripe.parity.len() != parity_count {
                return Err(Error::Manifest(format!(
                    "stripe {stripe_idx}: expected {k}+{parity_count} shares, \
                     got {}+{}",
                    stripe.data.len(),
                    stripe.parity.len(),
                )));
            }

            let mut data: Vec<Option<Vec<u8>>> = Vec::with_capacity(k);
            for h in &stripe.data {
                let bytes = self.store.get(Namespace::Chunks, h.inner())?;
                data.push(bytes.map(|b| b.to_vec()));
            }
            let mut parity: Vec<Option<Vec<u8>>> = Vec::with_capacity(parity_count);
            for h in &stripe.parity {
                let bytes = self.store.get(Namespace::Chunks, h.inner())?;
                parity.push(bytes.map(|b| b.to_vec()));
            }

            let have = data.iter().filter(|s| s.is_some()).count()
                + parity.iter().filter(|s| s.is_some()).count();
            if have < k {
                return Err(Error::NotEnoughShares {
                    stripe: stripe_idx,
                    have,
                    need: k,
                });
            }

            let data_ciphertexts = if data.iter().all(Option::is_some) {
                data.into_iter().map(Option::unwrap).collect()
            } else {
                erasure::decode_data(manifest.erasure, data, parity).map_err(|e| {
                    // Wrap the placeholder stripe-0 NotEnoughShares with the
                    // actual stripe index.
                    match e {
                        Error::NotEnoughShares { have, need, .. } => Error::NotEnoughShares {
                            stripe: stripe_idx,
                            have,
                            need,
                        },
                        other => other,
                    }
                })?
            };

            for (data_idx, ct) in data_ciphertexts.iter().enumerate() {
                let plain =
                    crypto::open_chunk(&manifest.file_key, stripe_idx as u64, data_idx as u32, ct)?;
                plaintext.extend_from_slice(&plain);
            }
        }

        plaintext.truncate(manifest.file_size as usize);
        Ok(plaintext)
    }
}
