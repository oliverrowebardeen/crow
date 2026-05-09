use std::fs;
use std::path::{Path, PathBuf};

use bytes::Bytes;

use crate::chunk::{ChunkStore, Namespace};
use crate::error::{Error, Result};
use crate::hash::Hash;

/// On-disk [`ChunkStore`]: one file per chunk, named by its hex hash. Two
/// directories live under `root`: `chunks/` for data shares, `manifests/`
/// for sealed manifests. Writes go through a `<hash>.<pid>.tmp` file and
/// are renamed into place to be atomic on a single filesystem.
pub struct FsStore {
    root: PathBuf,
}

impl FsStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join("chunks"))?;
        fs::create_dir_all(root.join("manifests"))?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn ns_dir(&self, ns: Namespace) -> PathBuf {
        self.root.join(match ns {
            Namespace::Chunks => "chunks",
            Namespace::Manifests => "manifests",
        })
    }

    fn path(&self, ns: Namespace, hash: &Hash) -> PathBuf {
        self.ns_dir(ns).join(hash.to_string())
    }

    fn tmp_path(&self, ns: Namespace, hash: &Hash) -> PathBuf {
        self.ns_dir(ns)
            .join(format!("{hash}.{}.tmp", std::process::id()))
    }
}

impl ChunkStore for FsStore {
    fn put(&self, ns: Namespace, bytes: Bytes) -> Result<Hash> {
        let hash = Hash::of(&bytes);
        self.put_unverified(ns, hash, bytes)?;
        Ok(hash)
    }

    fn put_unverified(&self, ns: Namespace, hash: Hash, bytes: Bytes) -> Result<()> {
        let target = self.path(ns, &hash);
        if target.exists() {
            // Content-addressed: identical content already stored.
            return Ok(());
        }
        let tmp = self.tmp_path(ns, &hash);
        fs::write(&tmp, &bytes)?;
        // Rename is atomic within a filesystem and idempotent under races
        // because identical content produces identical bytes.
        fs::rename(&tmp, &target)?;
        Ok(())
    }

    fn get(&self, ns: Namespace, hash: &Hash) -> Result<Option<Bytes>> {
        match fs::read(self.path(ns, hash)) {
            Ok(bytes) => Ok(Some(Bytes::from(bytes))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::Io(e)),
        }
    }

    fn has(&self, ns: Namespace, hash: &Hash) -> Result<bool> {
        Ok(self.path(ns, hash).exists())
    }

    fn delete(&self, ns: Namespace, hash: &Hash) -> Result<bool> {
        match fs::remove_file(self.path(ns, hash)) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(Error::Io(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn b(s: &[u8]) -> Bytes {
        Bytes::copy_from_slice(s)
    }

    #[test]
    fn put_get_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let store = FsStore::open(tmp.path()).unwrap();
        let h = store.put(Namespace::Chunks, b(b"hello")).unwrap();
        assert_eq!(h, Hash::of(b"hello"));
        assert_eq!(store.get(Namespace::Chunks, &h).unwrap(), Some(b(b"hello")));
    }

    #[test]
    fn persistence_across_handles() {
        let tmp = TempDir::new().unwrap();
        let h = {
            let store = FsStore::open(tmp.path()).unwrap();
            store.put(Namespace::Chunks, b(b"persist me")).unwrap()
        };
        // Drop the first handle, reopen at the same path.
        let store = FsStore::open(tmp.path()).unwrap();
        assert_eq!(
            store.get(Namespace::Chunks, &h).unwrap(),
            Some(b(b"persist me"))
        );
    }

    #[test]
    fn namespaces_are_disjoint_on_disk() {
        let tmp = TempDir::new().unwrap();
        let store = FsStore::open(tmp.path()).unwrap();
        let h = store.put(Namespace::Chunks, b(b"shared")).unwrap();
        store
            .put_unverified(Namespace::Manifests, h, b(b"manifest"))
            .unwrap();
        assert_eq!(
            store.get(Namespace::Chunks, &h).unwrap(),
            Some(b(b"shared"))
        );
        assert_eq!(
            store.get(Namespace::Manifests, &h).unwrap(),
            Some(b(b"manifest"))
        );
    }

    #[test]
    fn delete_removes_file() {
        let tmp = TempDir::new().unwrap();
        let store = FsStore::open(tmp.path()).unwrap();
        let h = store.put(Namespace::Chunks, b(b"x")).unwrap();
        assert!(store.delete(Namespace::Chunks, &h).unwrap());
        assert!(!store.delete(Namespace::Chunks, &h).unwrap());
        assert_eq!(store.get(Namespace::Chunks, &h).unwrap(), None);
    }

    #[test]
    fn put_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        let store = FsStore::open(tmp.path()).unwrap();
        let h1 = store.put(Namespace::Chunks, b(b"twice")).unwrap();
        let h2 = store.put(Namespace::Chunks, b(b"twice")).unwrap();
        assert_eq!(h1, h2);
        assert_eq!(
            store.get(Namespace::Chunks, &h1).unwrap(),
            Some(b(b"twice"))
        );
    }
}
