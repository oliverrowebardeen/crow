//! Garbage collection for the chunk store.
//!
//! GC is mark-and-sweep with no daemon: a sweep runs only when something
//! invokes [`sweep`] (full sweep, used by `crow gc`) or [`targeted_remove`]
//! (single-pin sweep, used by `crow rm`). Both routines are owner-pinning:
//! a chunk lives if and only if some pinned or cataloged manifest references it.

use std::collections::HashSet;

use crate::cap::Cap;
use crate::catalog::CatalogView;
use crate::chunk::{ChunkStore, Namespace};
use crate::dir_manifest::DirectoryManifest;
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
    let mut visited_manifests = HashSet::new();
    for cap in caps {
        mark_cap(store, cap, &mut live, &mut visited_manifests)?;
    }
    Ok(live)
}

fn mark_cap<S: ChunkStore>(
    store: &S,
    cap: &Cap,
    live: &mut LiveSet,
    visited_manifests: &mut HashSet<Hash>,
) -> Result<()> {
    let manifest_hash = *cap.manifest_hash.inner();
    if !visited_manifests.insert(manifest_hash) {
        return Ok(());
    }
    let encrypted = match store.get(Namespace::Manifests, &manifest_hash)? {
        Some(b) => b,
        None => return Ok(()),
    };
    live.insert((Namespace::Manifests, manifest_hash));

    match DirectoryManifest::open(&encrypted, &cap.manifest_key) {
        Ok(directory) => {
            for child_cap in directory.file_caps()? {
                mark_cap(store, &child_cap, live, visited_manifests)?;
            }
        }
        Err(_) => {
            let manifest = Manifest::open(&encrypted, &cap.manifest_key)?;
            for stripe in &manifest.stripes {
                for chunk_hash in stripe.data.iter().chain(stripe.parity.iter()) {
                    live.insert((Namespace::Chunks, *chunk_hash.inner()));
                }
            }
        }
    }
    Ok(())
}

/// Compute live chunks referenced by the current catalog view.
pub fn compute_live_set_from_catalog<S: ChunkStore>(
    store: &S,
    catalog: &CatalogView,
) -> Result<LiveSet> {
    compute_live_set(store, &catalog.file_caps())
}

/// Compute live chunks referenced by both flat caps and catalog paths.
///
/// This is the normal full-GC root set: legacy pins and path-based catalog
/// entries both keep content alive.
pub fn compute_live_set_from_roots<S: ChunkStore>(
    store: &S,
    caps: &[Cap],
    catalog: &CatalogView,
) -> Result<LiveSet> {
    let catalog_caps = catalog.file_caps();
    let mut all_caps = Vec::with_capacity(caps.len() + catalog_caps.len());
    all_caps.extend_from_slice(caps);
    all_caps.extend(catalog_caps);
    compute_live_set(store, &all_caps)
}

/// Full-store sweep: delete every `(Namespace, Hash)` not present in `live`.
///
/// `live` is typically produced by `compute_live_set_from_roots`.
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
    use crate::catalog::CatalogIndex;
    use crate::chunk::MemStore;
    use crate::dir_manifest::{DirectoryEntry, DirectoryManifest};
    use crate::erasure::ErasureParams;
    use crate::pipeline::Crow;
    use tempfile::TempDir;

    fn put(crow: &Crow<MemStore>, payload: &[u8]) -> Cap {
        crow.put_bytes_with(
            payload,
            "application/octet-stream",
            ErasureParams::default(),
            240,
        )
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

    #[test]
    fn catalog_live_set_keeps_cataloged_file() {
        let tmp = TempDir::new().unwrap();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        catalog.mkdir("/docs", false).unwrap();

        let crow = Crow::new(MemStore::new());
        let cap = put(&crow, b"path-rooted");
        catalog
            .put_file("/docs/report.txt", cap.clone(), Some("report.txt".into()))
            .unwrap();

        let view = catalog.view().unwrap();
        let live = compute_live_set_from_catalog(crow.store(), &view).unwrap();
        let report = sweep(crow.store(), &live, GcOptions::default()).unwrap();

        assert_eq!(report.deleted_chunks, 0);
        assert_eq!(report.deleted_manifests, 0);
        assert_eq!(crow.get_bytes(&cap).unwrap(), b"path-rooted");
    }

    #[test]
    fn root_live_set_combines_pins_and_catalog() {
        let tmp = TempDir::new().unwrap();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();

        let crow = Crow::new(MemStore::new());
        let pinned = put(&crow, b"flat pin");
        let cataloged = put(&crow, b"catalog path");
        catalog
            .put_file(
                "/cataloged.txt",
                cataloged.clone(),
                Some("cataloged.txt".into()),
            )
            .unwrap();

        let view = catalog.view().unwrap();
        let live = compute_live_set_from_roots(crow.store(), std::slice::from_ref(&pinned), &view)
            .unwrap();
        let report = sweep(crow.store(), &live, GcOptions::default()).unwrap();

        assert_eq!(report.deleted_chunks, 0);
        assert_eq!(report.deleted_manifests, 0);
        assert_eq!(crow.get_bytes(&pinned).unwrap(), b"flat pin");
        assert_eq!(crow.get_bytes(&cataloged).unwrap(), b"catalog path");
    }

    #[test]
    fn directory_manifest_cap_keeps_children_alive() {
        let crow = Crow::new(MemStore::new());
        let child = put(&crow, b"child bytes");
        let dir = DirectoryManifest::new(
            123,
            vec![DirectoryEntry::file(
                "child.txt",
                child.clone(),
                Some("child.txt".into()),
            )],
        )
        .unwrap();
        let dir_cap = crow.put_directory_manifest(&dir).unwrap();

        let live = compute_live_set(crow.store(), std::slice::from_ref(&dir_cap)).unwrap();
        let report = sweep(crow.store(), &live, GcOptions::default()).unwrap();

        assert_eq!(report.deleted_chunks, 0);
        assert_eq!(report.deleted_manifests, 0);
        assert_eq!(crow.get_bytes(&child).unwrap(), b"child bytes");
    }

    #[test]
    fn targeted_remove_preserves_child_held_by_directory_cap() {
        let crow = Crow::new(MemStore::new());
        let child = put(&crow, b"shared through dir");
        let dir = DirectoryManifest::new(
            123,
            vec![DirectoryEntry::file(
                "child.txt",
                child.clone(),
                Some("child.txt".into()),
            )],
        )
        .unwrap();
        let dir_cap = crow.put_directory_manifest(&dir).unwrap();

        let report = targeted_remove(
            crow.store(),
            std::slice::from_ref(&child),
            std::slice::from_ref(&dir_cap),
            GcOptions::default(),
        )
        .unwrap();

        assert_eq!(report.deleted_chunks, 0);
        assert_eq!(report.deleted_manifests, 0);
        assert_eq!(crow.get_bytes(&child).unwrap(), b"shared through dir");
    }
}
