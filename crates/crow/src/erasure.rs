use std::collections::HashMap;

use reed_solomon_simd::{ReedSolomonDecoder, ReedSolomonEncoder};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// AES-256-GCM tag length appended to every ciphertext.
pub const AEAD_TAG_LEN: usize = 16;

/// reed-solomon-simd requires shard size to be a multiple of this.
pub const RS_ALIGN: usize = 64;

/// Default plaintext chunk size: 1 MiB minus the AEAD tag, so the resulting
/// ciphertext (chunk_size + AEAD_TAG_LEN) is exactly 1 MiB and fits the RS
/// alignment without per-shard padding.
pub const DEFAULT_CHUNK_SIZE: u32 = 1024 * 1024 - AEAD_TAG_LEN as u32;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErasureParams {
    pub k: u8,
    pub n: u8,
}

impl Default for ErasureParams {
    fn default() -> Self {
        Self { k: 3, n: 5 }
    }
}

impl ErasureParams {
    pub const fn parity_count(self) -> u8 {
        self.n - self.k
    }

    pub fn validate(self) -> Result<()> {
        if self.k == 0 {
            return Err(Error::Erasure("k must be positive".into()));
        }
        if self.n <= self.k {
            return Err(Error::Erasure(format!(
                "n must exceed k (got k={}, n={})",
                self.k, self.n
            )));
        }
        Ok(())
    }
}

/// Verify that (chunk_size + AEAD tag) aligns to the RS shard requirement.
pub fn validate_chunk_size(chunk_size: u32) -> Result<()> {
    if chunk_size == 0 {
        return Err(Error::Erasure("chunk_size must be positive".into()));
    }
    let shard = chunk_size as usize + AEAD_TAG_LEN;
    if shard % RS_ALIGN != 0 {
        return Err(Error::Erasure(format!(
            "(chunk_size + AEAD tag) = {shard} must be a multiple of {RS_ALIGN}"
        )));
    }
    Ok(())
}

/// RS-encode K data shards into N - K parity shards. All shards are the same
/// length, which must be a multiple of RS_ALIGN.
pub fn encode_parity(
    params: ErasureParams,
    data_shards: &[Vec<u8>],
) -> Result<Vec<Vec<u8>>> {
    params.validate()?;
    if data_shards.len() != params.k as usize {
        return Err(Error::Erasure(format!(
            "expected {} data shards, got {}",
            params.k,
            data_shards.len()
        )));
    }
    let shard_bytes = data_shards[0].len();
    if shard_bytes == 0 || shard_bytes % RS_ALIGN != 0 {
        return Err(Error::Erasure(format!(
            "shard size {shard_bytes} must be a positive multiple of {RS_ALIGN}"
        )));
    }
    if !data_shards.iter().all(|s| s.len() == shard_bytes) {
        return Err(Error::Erasure("data shards have inconsistent sizes".into()));
    }

    let mut encoder = ReedSolomonEncoder::new(
        params.k as usize,
        params.parity_count() as usize,
        shard_bytes,
    )
    .map_err(|e| Error::Erasure(format!("encoder init: {e}")))?;

    for shard in data_shards {
        encoder
            .add_original_shard(shard)
            .map_err(|e| Error::Erasure(format!("add_original_shard: {e}")))?;
    }

    let result = encoder
        .encode()
        .map_err(|e| Error::Erasure(format!("encode: {e}")))?;

    Ok(result.recovery_iter().map(|s| s.to_vec()).collect())
}

/// Recover the K data shards from any K available shares (data + parity).
///
/// Inputs:
/// - `data`: K slots, `Some(bytes)` if the data shard is available, `None` if missing.
/// - `parity`: N - K slots, same shape.
///
/// The caller is responsible for ensuring at least K total shares are present
/// and for tracking the stripe index (so it can wrap any error with stripe
/// context). This function does the minimal counting check as defence in
/// depth, returning a placeholder NotEnoughShares { stripe: 0, .. } that the
/// pipeline overrides with the correct stripe.
pub fn decode_data(
    params: ErasureParams,
    data: Vec<Option<Vec<u8>>>,
    parity: Vec<Option<Vec<u8>>>,
) -> Result<Vec<Vec<u8>>> {
    params.validate()?;
    if data.len() != params.k as usize {
        return Err(Error::Erasure(format!(
            "expected {} data slots, got {}",
            params.k,
            data.len()
        )));
    }
    if parity.len() != params.parity_count() as usize {
        return Err(Error::Erasure(format!(
            "expected {} parity slots, got {}",
            params.parity_count(),
            parity.len()
        )));
    }

    if data.iter().all(Option::is_some) {
        return Ok(data.into_iter().map(Option::unwrap).collect());
    }

    let shard_bytes = data
        .iter()
        .chain(parity.iter())
        .find_map(|s| s.as_ref().map(|v| v.len()))
        .ok_or_else(|| Error::Erasure("no shares provided".into()))?;
    if shard_bytes == 0 || shard_bytes % RS_ALIGN != 0 {
        return Err(Error::Erasure(format!(
            "shard size {shard_bytes} must be a positive multiple of {RS_ALIGN}"
        )));
    }

    let have = data.iter().filter(|s| s.is_some()).count()
        + parity.iter().filter(|s| s.is_some()).count();
    let need = params.k as usize;
    if have < need {
        return Err(Error::NotEnoughShares {
            stripe: 0,
            have,
            need,
        });
    }

    let mut decoder = ReedSolomonDecoder::new(
        params.k as usize,
        params.parity_count() as usize,
        shard_bytes,
    )
    .map_err(|e| Error::Erasure(format!("decoder init: {e}")))?;

    for (i, shard) in data.iter().enumerate() {
        if let Some(s) = shard {
            decoder
                .add_original_shard(i, s)
                .map_err(|e| Error::Erasure(format!("add_original_shard {i}: {e}")))?;
        }
    }
    for (i, shard) in parity.iter().enumerate() {
        if let Some(s) = shard {
            decoder
                .add_recovery_shard(i, s)
                .map_err(|e| Error::Erasure(format!("add_recovery_shard {i}: {e}")))?;
        }
    }

    let result = decoder
        .decode()
        .map_err(|e| Error::Erasure(format!("decode: {e}")))?;
    let restored: HashMap<usize, Vec<u8>> = result
        .restored_original_iter()
        .map(|(i, s)| (i, s.to_vec()))
        .collect();

    let mut out = Vec::with_capacity(params.k as usize);
    for (i, shard) in data.into_iter().enumerate() {
        match shard {
            Some(s) => out.push(s),
            None => out.push(restored.get(&i).cloned().ok_or_else(|| {
                Error::Erasure(format!("RS did not restore data shard {i}"))
            })?),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shards(k: u8, size: usize) -> Vec<Vec<u8>> {
        (0..k)
            .map(|i| vec![i; size])
            .collect()
    }

    #[test]
    fn default_params_are_3_of_5() {
        let p = ErasureParams::default();
        assert_eq!(p.k, 3);
        assert_eq!(p.n, 5);
        assert_eq!(p.parity_count(), 2);
    }

    #[test]
    fn validate_rejects_bad_params() {
        assert!(ErasureParams { k: 0, n: 5 }.validate().is_err());
        assert!(ErasureParams { k: 5, n: 5 }.validate().is_err());
        assert!(ErasureParams { k: 6, n: 5 }.validate().is_err());
    }

    #[test]
    fn default_chunk_size_aligns() {
        validate_chunk_size(DEFAULT_CHUNK_SIZE).unwrap();
    }

    #[test]
    fn validate_chunk_size_rejects_misaligned() {
        // 1 MiB exact ciphertext means chunk_size = 1 MiB - 16. 1 MiB itself fails.
        assert!(validate_chunk_size(1024 * 1024).is_err());
        assert!(validate_chunk_size(0).is_err());
        assert!(validate_chunk_size(63).is_err());
    }

    #[test]
    fn encode_decode_no_loss() {
        let params = ErasureParams::default();
        let data = shards(params.k, 64);
        let parity = encode_parity(params, &data).unwrap();
        assert_eq!(parity.len(), params.parity_count() as usize);
        assert!(parity.iter().all(|s| s.len() == 64));

        // All data present: decode is a no-op pass-through.
        let restored = decode_data(
            params,
            data.iter().cloned().map(Some).collect(),
            parity.iter().cloned().map(Some).collect(),
        )
        .unwrap();
        assert_eq!(restored, data);
    }

    #[test]
    fn recover_one_missing_data_shard_from_parity() {
        let params = ErasureParams::default();
        let data = shards(params.k, 64);
        let parity = encode_parity(params, &data).unwrap();

        // Drop data shard 1.
        let mut data_opt: Vec<Option<Vec<u8>>> = data.iter().cloned().map(Some).collect();
        data_opt[1] = None;

        let restored = decode_data(
            params,
            data_opt,
            parity.iter().cloned().map(Some).collect(),
        )
        .unwrap();
        assert_eq!(restored, data);
    }

    #[test]
    fn recover_n_minus_k_missing_data_shards() {
        // 3-of-5: drop 2 data shards, recover from data[0] + both parity shards.
        let params = ErasureParams::default();
        let data = shards(params.k, 64);
        let parity = encode_parity(params, &data).unwrap();

        let data_opt: Vec<Option<Vec<u8>>> =
            vec![Some(data[0].clone()), None, None];
        let parity_opt: Vec<Option<Vec<u8>>> = parity.iter().cloned().map(Some).collect();

        let restored = decode_data(params, data_opt, parity_opt).unwrap();
        assert_eq!(restored, data);
    }

    #[test]
    fn rejects_too_few_shares() {
        let params = ErasureParams::default();
        // Only 2 shares total in a 3-of-5 setup → cannot reconstruct.
        let data: Vec<Option<Vec<u8>>> = vec![
            Some(vec![0u8; 64]),
            Some(vec![1u8; 64]),
            None,
        ];
        let parity: Vec<Option<Vec<u8>>> = vec![None, None];
        let err = decode_data(params, data, parity).unwrap_err();
        match err {
            Error::NotEnoughShares { have, need, .. } => {
                assert_eq!(have, 2);
                assert_eq!(need, 3);
            }
            other => panic!("expected NotEnoughShares, got {other:?}"),
        }
    }

    #[test]
    fn rejects_misaligned_shard_size() {
        let params = ErasureParams::default();
        let data = shards(params.k, 63); // not multiple of 64
        assert!(encode_parity(params, &data).is_err());
    }

    #[test]
    fn rejects_inconsistent_shard_sizes() {
        let params = ErasureParams::default();
        let data = vec![vec![0u8; 64], vec![1u8; 64], vec![2u8; 128]];
        assert!(encode_parity(params, &data).is_err());
    }

    #[test]
    fn rejects_wrong_data_count() {
        let params = ErasureParams::default();
        let data = shards(2, 64); // expected 3 for k=3
        assert!(encode_parity(params, &data).is_err());
    }
}
