use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::hash::Hash;

/// Logical partition of the chunk store.
///
/// Manifests live separately from data chunks so the future GC pass can scan
/// only one space, and a future on-disk backend can use separate trees per
/// namespace without churning the trait.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Namespace {
    Chunks,
    Manifests,
}

pub trait ChunkStore: Send + Sync {
    /// Hash the bytes and store under the resulting hash. Use this when the
    /// caller has not yet computed the hash.
    fn put(&self, ns: Namespace, bytes: Bytes) -> Result<Hash>;

    /// Store bytes under a caller-supplied hash without rehashing. The
    /// pipeline uses this on the hot path because it has just hashed the
    /// bytes itself for the manifest.
    fn put_unverified(&self, ns: Namespace, hash: Hash, bytes: Bytes) -> Result<()>;

    fn get(&self, ns: Namespace, hash: &Hash) -> Result<Option<Bytes>>;

    fn has(&self, ns: Namespace, hash: &Hash) -> Result<bool>;

    /// Remove a chunk. Returns whether anything was removed.
    fn delete(&self, ns: Namespace, hash: &Hash) -> Result<bool>;

    /// Enumerate every hash currently stored in `ns`. Used by garbage
    /// collection and `crow stat`. Order is unspecified.
    fn list(&self, ns: Namespace) -> Result<Vec<Hash>>;

    /// Byte size of a stored chunk. Returns None if the hash is absent.
    /// Default implementation reads the bytes — backends should override
    /// with a metadata-only path when one is available (e.g. fs::metadata
    /// for FsStore).
    fn size(&self, ns: Namespace, hash: &Hash) -> Result<Option<u64>> {
        Ok(self.get(ns, hash)?.map(|b| b.len() as u64))
    }
}

#[derive(Default)]
pub struct MemStore {
    inner: RwLock<HashMap<(Namespace, Hash), Bytes>>,
}

impl MemStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.inner.read().expect("memstore poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.read().expect("memstore poisoned").is_empty()
    }
}

impl ChunkStore for MemStore {
    fn put(&self, ns: Namespace, bytes: Bytes) -> Result<Hash> {
        let hash = Hash::of(&bytes);
        self.inner
            .write()
            .expect("memstore poisoned")
            .insert((ns, hash), bytes);
        Ok(hash)
    }

    fn put_unverified(&self, ns: Namespace, hash: Hash, bytes: Bytes) -> Result<()> {
        self.inner
            .write()
            .expect("memstore poisoned")
            .insert((ns, hash), bytes);
        Ok(())
    }

    fn get(&self, ns: Namespace, hash: &Hash) -> Result<Option<Bytes>> {
        Ok(self
            .inner
            .read()
            .expect("memstore poisoned")
            .get(&(ns, *hash))
            .cloned())
    }

    fn has(&self, ns: Namespace, hash: &Hash) -> Result<bool> {
        Ok(self
            .inner
            .read()
            .expect("memstore poisoned")
            .contains_key(&(ns, *hash)))
    }

    fn delete(&self, ns: Namespace, hash: &Hash) -> Result<bool> {
        Ok(self
            .inner
            .write()
            .expect("memstore poisoned")
            .remove(&(ns, *hash))
            .is_some())
    }

    fn list(&self, ns: Namespace) -> Result<Vec<Hash>> {
        Ok(self
            .inner
            .read()
            .expect("memstore poisoned")
            .keys()
            .filter_map(|(n, h)| (*n == ns).then_some(*h))
            .collect())
    }
}

impl<T: ChunkStore + ?Sized> ChunkStore for &T {
    fn put(&self, ns: Namespace, bytes: Bytes) -> Result<Hash> {
        (**self).put(ns, bytes)
    }
    fn put_unverified(&self, ns: Namespace, hash: Hash, bytes: Bytes) -> Result<()> {
        (**self).put_unverified(ns, hash, bytes)
    }
    fn get(&self, ns: Namespace, hash: &Hash) -> Result<Option<Bytes>> {
        (**self).get(ns, hash)
    }
    fn has(&self, ns: Namespace, hash: &Hash) -> Result<bool> {
        (**self).has(ns, hash)
    }
    fn delete(&self, ns: Namespace, hash: &Hash) -> Result<bool> {
        (**self).delete(ns, hash)
    }
    fn list(&self, ns: Namespace) -> Result<Vec<Hash>> {
        (**self).list(ns)
    }
    fn size(&self, ns: Namespace, hash: &Hash) -> Result<Option<u64>> {
        (**self).size(ns, hash)
    }
}

impl<T: ChunkStore + ?Sized> ChunkStore for Arc<T> {
    fn put(&self, ns: Namespace, bytes: Bytes) -> Result<Hash> {
        (**self).put(ns, bytes)
    }
    fn put_unverified(&self, ns: Namespace, hash: Hash, bytes: Bytes) -> Result<()> {
        (**self).put_unverified(ns, hash, bytes)
    }
    fn get(&self, ns: Namespace, hash: &Hash) -> Result<Option<Bytes>> {
        (**self).get(ns, hash)
    }
    fn has(&self, ns: Namespace, hash: &Hash) -> Result<bool> {
        (**self).has(ns, hash)
    }
    fn delete(&self, ns: Namespace, hash: &Hash) -> Result<bool> {
        (**self).delete(ns, hash)
    }
    fn list(&self, ns: Namespace) -> Result<Vec<Hash>> {
        (**self).list(ns)
    }
    fn size(&self, ns: Namespace, hash: &Hash) -> Result<Option<u64>> {
        (**self).size(ns, hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(s: &[u8]) -> Bytes {
        Bytes::copy_from_slice(s)
    }

    #[test]
    fn put_then_get_roundtrip() {
        let s = MemStore::new();
        let h = s.put(Namespace::Chunks, b(b"hello")).unwrap();
        assert_eq!(h, Hash::of(b"hello"));
        assert_eq!(s.get(Namespace::Chunks, &h).unwrap(), Some(b(b"hello")));
    }

    #[test]
    fn has_reports_presence() {
        let s = MemStore::new();
        let h = s.put(Namespace::Chunks, b(b"x")).unwrap();
        assert!(s.has(Namespace::Chunks, &h).unwrap());
        assert!(!s.has(Namespace::Chunks, &Hash::of(b"y")).unwrap());
    }

    #[test]
    fn delete_returns_whether_present() {
        let s = MemStore::new();
        let h = s.put(Namespace::Chunks, b(b"x")).unwrap();
        assert!(s.delete(Namespace::Chunks, &h).unwrap());
        assert!(!s.delete(Namespace::Chunks, &h).unwrap());
        assert_eq!(s.get(Namespace::Chunks, &h).unwrap(), None);
    }

    #[test]
    fn namespaces_are_disjoint() {
        // Same hash in Chunks and Manifests must address distinct entries —
        // otherwise GC could delete a manifest by scanning chunks, etc.
        let s = MemStore::new();
        let h = s.put(Namespace::Chunks, b(b"shared")).unwrap();
        s.put_unverified(Namespace::Manifests, h, b(b"manifest-bytes"))
            .unwrap();
        assert_eq!(s.get(Namespace::Chunks, &h).unwrap(), Some(b(b"shared")));
        assert_eq!(
            s.get(Namespace::Manifests, &h).unwrap(),
            Some(b(b"manifest-bytes"))
        );
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn put_unverified_does_not_rehash() {
        // Caller passes a hash that doesn't match the bytes. The store
        // accepts it — verification is the caller's responsibility on this
        // path, in exchange for skipping a BLAKE3 pass.
        let s = MemStore::new();
        let lying_hash = Hash::of(b"different");
        s.put_unverified(Namespace::Chunks, lying_hash, b(b"actual"))
            .unwrap();
        assert_eq!(
            s.get(Namespace::Chunks, &lying_hash).unwrap(),
            Some(b(b"actual"))
        );
    }

    #[test]
    fn missing_get_returns_none() {
        let s = MemStore::new();
        assert_eq!(
            s.get(Namespace::Chunks, &Hash::of(b"nothing")).unwrap(),
            None
        );
    }

    #[test]
    fn arc_blanket_impl_works() {
        let s: Arc<dyn ChunkStore> = Arc::new(MemStore::new());
        let h = s.put(Namespace::Chunks, b(b"arc")).unwrap();
        assert_eq!(s.get(Namespace::Chunks, &h).unwrap(), Some(b(b"arc")));
    }

    #[test]
    fn ref_blanket_impl_works() {
        let s = MemStore::new();
        fn use_store<S: ChunkStore>(s: S) -> Hash {
            s.put(Namespace::Chunks, Bytes::from_static(b"ref"))
                .unwrap()
        }
        let h = use_store(&s);
        assert_eq!(s.get(Namespace::Chunks, &h).unwrap(), Some(b(b"ref")));
    }

    #[test]
    fn list_returns_per_namespace_hashes() {
        let s = MemStore::new();
        let a = s.put(Namespace::Chunks, b(b"a")).unwrap();
        let b1 = s.put(Namespace::Chunks, b(b"b")).unwrap();
        let m = s.put(Namespace::Manifests, b(b"manifest")).unwrap();

        let mut chunks = s.list(Namespace::Chunks).unwrap();
        chunks.sort();
        let mut want_chunks = vec![a, b1];
        want_chunks.sort();
        assert_eq!(chunks, want_chunks);

        assert_eq!(s.list(Namespace::Manifests).unwrap(), vec![m]);
    }

    #[test]
    fn list_empty_namespace_is_empty() {
        let s = MemStore::new();
        assert!(s.list(Namespace::Chunks).unwrap().is_empty());
        assert!(s.list(Namespace::Manifests).unwrap().is_empty());
    }
}
