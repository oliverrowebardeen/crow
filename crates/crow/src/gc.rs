//! Garbage collection for the chunk store.
//!
//! GC is mark-and-sweep with no daemon: a sweep runs only when something
//! invokes [`sweep`] (full sweep, used by `crow gc`) or [`targeted_remove`]
//! (single-pin sweep, used by `crow rm`). Both routines are owner-pinning:
//! a chunk lives if and only if some pinned manifest references it.

use std::collections::HashSet;

use crate::cap::Cap;
use crate::chunk::{ChunkStore, Namespace};
use crate::error::Result;
use crate::hash::Hash;
use crate::manifest::Manifest;

pub type LiveSet = HashSet<(Namespace, Hash)>;

#[derive(Clone, Copy, Debug, Default)]
pub struct GcOptions {
    /// If true, count what would be deleted but do not actually delete.
    pub dry_run: bool,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct GcReport {
    pub deleted_manifests: usize,
    pub deleted_chunks: usize,
    pub deleted_bytes: u64,
    pub kept_manifests: usize,
    pub kept_chunks: usize,
}

/// Walk each cap, decrypt its manifest, and accumulate every
/// `(Namespace, Hash)` it references — including the manifest itself.
///
/// Caps whose manifest is not in the store are silently skipped: the
/// manifest is gone and there's nothing for them to mark.
pub fn compute_live_set<S: ChunkStore>(store: &S, caps: &[Cap]) -> Result<LiveSet> {
    let mut live: LiveSet = HashSet::new();
    for cap in caps {
        let manifest_hash = *cap.manifest_hash.inner();
        let encrypted = match store.get(Namespace::Manifests, &manifest_hash)? {
            Some(b) => b,
            None => continue,
        };
        live.insert((Namespace::Manifests, manifest_hash));
        let manifest = Manifest::open(&encrypted, &cap.manifest_key)?;
        for stripe in &manifest.stripes {
            for chunk_hash in stripe.data.iter().chain(stripe.parity.iter()) {
                live.insert((Namespace::Chunks, *chunk_hash.inner()));
            }
        }
    }
    Ok(live)
}

/// Full-store sweep: delete every `(Namespace, Hash)` not present in `live`.
///
/// `live` is typically produced by `compute_live_set(store, &all_pinned_caps)`.
/// The two-call shape lets the caller reuse a live set across operations
/// (e.g. compute it once, sweep, then immediately use it again).
pub fn sweep<S: ChunkStore>(store: &S, live: &LiveSet, opts: GcOptions) -> Result<GcReport> {
    let mut report = GcReport::default();
    for ns in [Namespace::Manifests, Namespace::Chunks] {
        for hash in store.list(ns)? {
            if live.contains(&(ns, hash)) {
                match ns {
                    Namespace::Manifests => report.kept_manifests += 1,
                    Namespace::Chunks => report.kept_chunks += 1,
                }
                continue;
            }
            let size = store.size(ns, &hash)?.unwrap_or(0);
            if !opts.dry_run {
                store.delete(ns, &hash)?;
            }
            match ns {
                Namespace::Manifests => report.deleted_manifests += 1,
                Namespace::Chunks => report.deleted_chunks += 1,
            }
            report.deleted_bytes += size;
        }
    }
    Ok(report)
}

/// Targeted GC: delete every reference of `target_caps` that is not also
/// held by `remaining_caps`. Used by `crow rm` to clean up after one pin
/// without re-walking the whole store.
pub fn targeted_remove<S: ChunkStore>(
    store: &S,
    target_caps: &[Cap],
    remaining_caps: &[Cap],
    opts: GcOptions,
) -> Result<GcReport> {
    let target = compute_live_set(store, target_caps)?;
    let keep = compute_live_set(store, remaining_caps)?;
    let mut report = GcReport::default();
    for (ns, hash) in target.difference(&keep) {
        let size = store.size(*ns, hash)?.unwrap_or(0);
        if !opts.dry_run {
            store.delete(*ns, hash)?;
        }
        match ns {
            Namespace::Manifests => report.deleted_manifests += 1,
            Namespace::Chunks => report.deleted_chunks += 1,
        }
        report.deleted_bytes += size;
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunk::MemStore;
    use crate::erasure::ErasureParams;
    use crate::pipeline::Crow;

    fn put(crow: &Crow<MemStore>, payload: &[u8]) -> Cap {
        crow.put_bytes_with(payload, "application/octet-stream", ErasureParams::default(), 240)
            .expect("put_bytes_with")
    }

    #[test]
    fn live_set_covers_manifest_and_all_shares() {
        let crow = Crow::new(MemStore::new());
        let cap = put(&crow, b"hello");
        let live = compute_live_set(crow.store(), std::slice::from_ref(&cap)).unwrap();

        // Every (ns, hash) in the store should be in the live set, since
        // there's only one pinned manifest and nothing else.
        let total_manifests = crow.store().list(Namespace::Manifests).unwrap().len();
        let total_chunks = crow.store().list(Namespace::Chunks).unwrap().len();
        assert_eq!(live.len(), total_manifests + total_chunks);
    }

    #[test]
    fn sweep_with_no_live_caps_empties_store() {
        let crow = Crow::new(MemStore::new());
        put(&crow, b"goodbye");
        let live = LiveSet::new();
        let report = sweep(crow.store(), &live, GcOptions::default()).unwrap();
        assert!(report.deleted_chunks > 0);
        assert!(report.deleted_manifests > 0);
        assert_eq!(report.kept_chunks + report.kept_manifests, 0);
        assert_eq!(crow.store().list(Namespace::Chunks).unwrap().len(), 0);
        assert_eq!(crow.store().list(Namespace::Manifests).unwrap().len(), 0);
    }

    #[test]
    fn sweep_with_full_live_set_deletes_nothing() {
        let crow = Crow::new(MemStore::new());
        let cap = put(&crow, b"keep me");
        let live = compute_live_set(crow.store(), std::slice::from_ref(&cap)).unwrap();
        let report = sweep(crow.store(), &live, GcOptions::default()).unwrap();
        assert_eq!(report.deleted_chunks, 0);
        assert_eq!(report.deleted_manifests, 0);
        // Bytes can still be reconstructed.
        assert_eq!(crow.get_bytes(&cap).unwrap(), b"keep me");
    }

    #[test]
    fn dry_run_counts_without_deleting() {
        let crow = Crow::new(MemStore::new());
        put(&crow, b"phantom");
        let live = LiveSet::new();
        let before_chunks = crow.store().list(Namespace::Chunks).unwrap().len();
        let before_manifests = crow.store().list(Namespace::Manifests).unwrap().len();

        let report = sweep(crow.store(), &live, GcOptions { dry_run: true }).unwrap();
        assert!(report.deleted_chunks > 0);
        assert!(report.deleted_manifests > 0);

        // Disk unchanged.
        assert_eq!(
            crow.store().list(Namespace::Chunks).unwrap().len(),
            before_chunks
        );
        assert_eq!(
            crow.store().list(Namespace::Manifests).unwrap().len(),
            before_manifests
        );
    }

    #[test]
    fn targeted_remove_deletes_unique_chunks_only() {
        // Two unrelated payloads will produce disjoint chunk sets, so
        // targeted_remove on one cap deletes only its chunks.
        let crow = Crow::new(MemStore::new());
        let alice = put(&crow, b"alice");
        let bob = put(&crow, b"bob");

        let alice_chunks_before = compute_live_set(crow.store(), std::slice::from_ref(&alice))
            .unwrap()
            .len();

        let report = targeted_remove(
            crow.store(),
            std::slice::from_ref(&alice),
            std::slice::from_ref(&bob),
            GcOptions::default(),
        )
        .unwrap();

        // Everything alice referenced got deleted...
        assert_eq!(
            report.deleted_chunks + report.deleted_manifests,
            alice_chunks_before
        );
        // ...but bob's data still works.
        assert_eq!(crow.get_bytes(&bob).unwrap(), b"bob");
    }

    #[test]
    fn targeted_remove_preserves_shared_chunks() {
        // Synthetic shared-chunk scenario: insert a chunk into the store
        // under a hash, claim both pins reference it. We can't easily do that
        // through the real put pipeline (each put generates fresh keys, so
        // ciphertexts diverge), but we can simulate the protected case by
        // listing both caps in `remaining_caps`.
        let crow = Crow::new(MemStore::new());
        let alice = put(&crow, b"shared truth");
        let bob = put(&crow, b"shared truth"); // different cap, different chunks

        // alice's chunks would normally be deleted, but if we list bob _and_
        // alice as remaining, neither should be deleted.
        let report = targeted_remove(
            crow.store(),
            std::slice::from_ref(&alice),
            &[alice.clone(), bob.clone()],
            GcOptions::default(),
        )
        .unwrap();

        assert_eq!(report.deleted_chunks, 0);
        assert_eq!(report.deleted_manifests, 0);
        assert_eq!(crow.get_bytes(&alice).unwrap(), b"shared truth");
        assert_eq!(crow.get_bytes(&bob).unwrap(), b"shared truth");
    }

    #[test]
    fn missing_manifest_in_live_set_is_skipped() {
        let crow = Crow::new(MemStore::new());
        let cap = put(&crow, b"orphan");

        // Delete the manifest underneath the cap; the cap is now dangling.
        crow.store()
            .delete(Namespace::Manifests, cap.manifest_hash.inner())
            .unwrap();

        // compute_live_set should not error; it just produces an empty set.
        let live = compute_live_set(crow.store(), std::slice::from_ref(&cap)).unwrap();
        assert!(live.is_empty());
    }
}
