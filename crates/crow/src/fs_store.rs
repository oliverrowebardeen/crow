use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use bytes::Bytes;

use crate::chunk::{ChunkStore, Namespace};
use crate::error::{Error, Result};
use crate::hash::Hash;

/// On-disk [`ChunkStore`]: one file per chunk, named by its hex hash. Two
/// directories live under `root`: `chunks/` for data shares, `manifests/`
/// for sealed manifests. Writes use unique temporary files in the same
/// directory and publish without replacing another writer's object.
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
        let mut tmp = tempfile::NamedTempFile::new_in(self.ns_dir(ns))?;
        tmp.write_all(&bytes)?;
        tmp.as_file().sync_all()?;
        match tmp.persist_noclobber(&target) {
            Ok(_) => Ok(()),
            Err(e) if e.error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(e) => Err(Error::Io(e.error)),
        }
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

    fn list(&self, ns: Namespace) -> Result<Vec<Hash>> {
        let dir = self.ns_dir(ns);
        let mut out = Vec::new();
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(Error::Io(e)),
        };
        for entry in entries {
            let entry = entry?;
            // Skip anything that isn't a 64-char hex hash file: in particular
            // temporary partial-write siblings.
            let name = match entry.file_name().into_string() {
                Ok(s) => s,
                Err(_) => continue,
            };
            if name.len() != 64 {
                continue;
            }
            if let Ok(h) = name.parse::<Hash>() {
                out.push(h);
            }
        }
        Ok(out)
    }

    fn size(&self, ns: Namespace, hash: &Hash) -> Result<Option<u64>> {
        match fs::metadata(self.path(ns, hash)) {
            Ok(m) => Ok(Some(m.len())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::Io(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn concurrent_identical_writes_are_atomic() {
        use std::sync::{Arc, Barrier};
        let tmp = TempDir::new().unwrap();
        let store = Arc::new(FsStore::open(tmp.path()).unwrap());
        let barrier = Arc::new(Barrier::new(16));
        let bytes = Bytes::from(vec![42; 1024 * 1024]);
        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..16)
                .map(|_| {
                    let store = store.clone();
                    let barrier = barrier.clone();
                    let bytes = bytes.clone();
                    scope.spawn(move || {
                        barrier.wait();
                        store.put(Namespace::Chunks, bytes)
                    })
                })
                .collect();
            for handle in handles {
                handle.join().unwrap().unwrap();
            }
        });
        assert_eq!(
            store.get(Namespace::Chunks, &Hash::of(&bytes)).unwrap(),
            Some(bytes)
        );
        assert_eq!(fs::read_dir(tmp.path().join("chunks")).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn stale_temporary_symlink_cannot_overwrite_another_file() {
        let tmp = TempDir::new().unwrap();
        let store = FsStore::open(tmp.path()).unwrap();
        let outside = tmp.path().join("outside");
        fs::write(&outside, b"keep").unwrap();
        let hash = Hash::of(b"new data");
        let old_tmp = tmp
            .path()
            .join("chunks")
            .join(format!("{hash}.{}.tmp", std::process::id()));
        std::os::unix::fs::symlink(&outside, old_tmp).unwrap();
        store.put(Namespace::Chunks, b(b"new data")).unwrap();
        assert_eq!(fs::read(outside).unwrap(), b"keep");
    }

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

    #[test]
    fn list_returns_stored_hashes_per_namespace() {
        let tmp = TempDir::new().unwrap();
        let store = FsStore::open(tmp.path()).unwrap();

        let a = store.put(Namespace::Chunks, b(b"a")).unwrap();
        let b1 = store.put(Namespace::Chunks, b(b"b")).unwrap();
        let m = store.put(Namespace::Manifests, b(b"manifest")).unwrap();

        let mut chunks = store.list(Namespace::Chunks).unwrap();
        chunks.sort();
        let mut want_chunks = vec![a, b1];
        want_chunks.sort();
        assert_eq!(chunks, want_chunks);

        assert_eq!(store.list(Namespace::Manifests).unwrap(), vec![m]);
    }

    #[test]
    fn list_skips_partial_write_tmp_files() {
        // A crashed put could leave <hash>.<pid>.tmp on disk. list must skip it.
        let tmp = TempDir::new().unwrap();
        let store = FsStore::open(tmp.path()).unwrap();
        let h = store.put(Namespace::Chunks, b(b"good")).unwrap();

        // Drop a fake leftover next to it.
        let leftover = tmp.path().join("chunks").join("dead.99999.tmp");
        fs::write(&leftover, b"junk").unwrap();

        // Also a hex-named-but-not-64-char file (defensive).
        let weird = tmp.path().join("chunks").join("deadbeef");
        fs::write(&weird, b"junk").unwrap();

        let listed = store.list(Namespace::Chunks).unwrap();
        assert_eq!(listed, vec![h]);
    }

    #[test]
    fn list_empty_dir_is_empty() {
        let tmp = TempDir::new().unwrap();
        let store = FsStore::open(tmp.path()).unwrap();
        assert!(store.list(Namespace::Chunks).unwrap().is_empty());
        assert!(store.list(Namespace::Manifests).unwrap().is_empty());
    }
}
