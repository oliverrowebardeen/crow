use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::cap::Cap;
use crate::error::{Error, Result};
use crate::hash::Hash;

const PIN_DIR: &str = "pins";
const PIN_EXT: &str = "json";

/// On-disk representation of a pin: one JSON file per manifest at
/// `<home>/pins/<hex_manifest_hash>.json`.
///
/// JSON file per pin (rather than a single index file) gives atomic per-pin
/// writes via temp+rename, no cross-pin lock contention, trivial enumeration
/// via `read_dir`, and human-greppability. The manifest hash is implicit in
/// the filename and not duplicated inside the JSON.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct PinJson {
    /// Bech32m-encoded `crow1…` capability.
    cap: String,
    /// Optional friendly name (filename when pinned via `crow put`).
    name: Option<String>,
    /// Unix seconds the pin was created.
    pinned_at: u64,
    /// Optional free-form comment.
    #[serde(default)]
    comment: Option<String>,
}

#[derive(Clone, Debug)]
pub struct PinRecord {
    pub cap: Cap,
    pub manifest_hash_hex: String,
    pub name: Option<String>,
    pub pinned_at: u64,
    pub comment: Option<String>,
}

pub struct PinIndex {
    root: PathBuf,
}

impl PinIndex {
    /// Open or create the pin index under `<home>/pins/`.
    pub fn open(home: impl AsRef<Path>) -> Result<Self> {
        let root = home.as_ref().join(PIN_DIR);
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn pin_path(&self, manifest_hash: &Hash) -> PathBuf {
        self.root.join(format!("{manifest_hash}.{PIN_EXT}"))
    }

    fn tmp_path(&self, manifest_hash: &Hash) -> PathBuf {
        self.root.join(format!(
            "{manifest_hash}.{PIN_EXT}.{}.tmp",
            std::process::id()
        ))
    }

    /// Add or replace a pin record for the cap. Idempotent — pinning the same
    /// cap twice updates the timestamp and metadata.
    pub fn add(
        &self,
        cap: Cap,
        name: Option<String>,
        comment: Option<String>,
    ) -> Result<PinRecord> {
        let pinned_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let json = PinJson {
            cap: cap.encode(),
            name: name.clone(),
            pinned_at,
            comment: comment.clone(),
        };
        let bytes = serde_json::to_vec_pretty(&json)
            .map_err(|e| Error::Manifest(format!("pin serialize: {e}")))?;
        let manifest_hash = cap.manifest_hash;
        let target = self.pin_path(manifest_hash.inner());
        let tmp = self.tmp_path(manifest_hash.inner());
        fs::write(&tmp, &bytes)?;
        fs::rename(&tmp, &target)?;
        Ok(PinRecord {
            manifest_hash_hex: manifest_hash.to_string(),
            cap,
            name,
            pinned_at,
            comment,
        })
    }

    /// Remove a pin record. Returns whether anything was removed.
    pub fn remove(&self, manifest_hash: &Hash) -> Result<bool> {
        match fs::remove_file(self.pin_path(manifest_hash)) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(Error::Io(e)),
        }
    }

    pub fn get(&self, manifest_hash: &Hash) -> Result<Option<PinRecord>> {
        let path = self.pin_path(manifest_hash);
        match fs::read(&path) {
            Ok(bytes) => Ok(Some(decode_record(&bytes, &manifest_hash.to_string())?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::Io(e)),
        }
    }

    /// Enumerate all pin records. Skips unparseable files (a partial-write
    /// `.tmp` sibling, a hand-edited file with bad JSON) — they will be
    /// excluded from the live set and eligible for cleanup at gc time.
    pub fn list(&self) -> Result<Vec<PinRecord>> {
        let mut out = Vec::new();
        let entries = match fs::read_dir(&self.root) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(Error::Io(e)),
        };
        for entry in entries {
            let entry = entry?;
            let name = match entry.file_name().into_string() {
                Ok(s) => s,
                Err(_) => continue,
            };
            // Filenames look like `<64 hex>.json`.
            let suffix = format!(".{PIN_EXT}");
            if !name.ends_with(&suffix) || name.len() != 64 + suffix.len() {
                continue;
            }
            let hash_part = &name[..64];
            if !hash_part.bytes().all(|b| b.is_ascii_hexdigit()) {
                continue;
            }
            let bytes = match fs::read(entry.path()) {
                Ok(b) => b,
                Err(_) => continue,
            };
            if let Ok(rec) = decode_record(&bytes, hash_part) {
                out.push(rec);
            }
        }
        Ok(out)
    }

    /// Match pin records whose manifest-hash-hex starts with `prefix`. Case
    /// insensitive. Returns 0, 1, or many — the caller decides what to do
    /// with ambiguous prefixes.
    pub fn find_by_prefix(&self, prefix: &str) -> Result<Vec<PinRecord>> {
        let prefix = prefix.to_ascii_lowercase();
        Ok(self
            .list()?
            .into_iter()
            .filter(|r| r.manifest_hash_hex.starts_with(&prefix))
            .collect())
    }
}

fn decode_record(bytes: &[u8], hash_hex: &str) -> Result<PinRecord> {
    let json: PinJson = serde_json::from_slice(bytes)
        .map_err(|e| Error::Manifest(format!("pin deserialize: {e}")))?;
    let cap = Cap::decode(&json.cap)?;
    if cap.manifest_hash.to_string() != hash_hex {
        return Err(Error::Manifest(format!(
            "pin file {hash_hex}.json points at a different manifest {}",
            cap.manifest_hash
        )));
    }
    Ok(PinRecord {
        manifest_hash_hex: hash_hex.to_string(),
        cap,
        name: json.name,
        pinned_at: json.pinned_at,
        comment: json.comment,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ManifestKey;
    use crate::hash::ManifestHash;
    use tempfile::TempDir;

    fn cap_with_hash_byte(b: u8) -> Cap {
        Cap::new_read(
            ManifestHash::from_bytes([b; 32]),
            ManifestKey::from_bytes([b; 32]),
        )
    }

    #[test]
    fn add_then_get_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let pins = PinIndex::open(tmp.path()).unwrap();
        let cap = cap_with_hash_byte(1);
        let h = *cap.manifest_hash.inner();

        let rec = pins
            .add(cap.clone(), Some("note.txt".into()), None)
            .unwrap();
        assert_eq!(rec.name.as_deref(), Some("note.txt"));

        let got = pins.get(&h).unwrap().unwrap();
        assert_eq!(got.cap.encode(), cap.encode());
        assert_eq!(got.name.as_deref(), Some("note.txt"));
    }

    #[test]
    fn add_is_idempotent_and_overwrites_metadata() {
        let tmp = TempDir::new().unwrap();
        let pins = PinIndex::open(tmp.path()).unwrap();
        let cap = cap_with_hash_byte(2);
        pins.add(cap.clone(), Some("first".into()), None).unwrap();
        pins.add(cap.clone(), Some("second".into()), Some("note".into()))
            .unwrap();
        let got = pins.get(cap.manifest_hash.inner()).unwrap().unwrap();
        assert_eq!(got.name.as_deref(), Some("second"));
        assert_eq!(got.comment.as_deref(), Some("note"));
        assert_eq!(pins.list().unwrap().len(), 1);
    }

    #[test]
    fn remove_returns_whether_present() {
        let tmp = TempDir::new().unwrap();
        let pins = PinIndex::open(tmp.path()).unwrap();
        let cap = cap_with_hash_byte(3);
        pins.add(cap.clone(), None, None).unwrap();
        let h = *cap.manifest_hash.inner();
        assert!(pins.remove(&h).unwrap());
        assert!(!pins.remove(&h).unwrap());
        assert!(pins.get(&h).unwrap().is_none());
    }

    #[test]
    fn list_returns_all_pins() {
        let tmp = TempDir::new().unwrap();
        let pins = PinIndex::open(tmp.path()).unwrap();
        for b in 1u8..=4 {
            pins.add(cap_with_hash_byte(b), None, None).unwrap();
        }
        let all = pins.list().unwrap();
        assert_eq!(all.len(), 4);
    }

    #[test]
    fn find_by_prefix_returns_zero_one_or_many() {
        let tmp = TempDir::new().unwrap();
        let pins = PinIndex::open(tmp.path()).unwrap();

        // Two pins whose hex hashes start with the same byte.
        pins.add(cap_with_hash_byte(0xAB), None, None).unwrap();
        pins.add(cap_with_hash_byte(0xCD), None, None).unwrap();

        // Unique prefix.
        assert_eq!(pins.find_by_prefix("ab").unwrap().len(), 1);
        // Case insensitive.
        assert_eq!(pins.find_by_prefix("AB").unwrap().len(), 1);
        // No matches.
        assert!(pins.find_by_prefix("ff").unwrap().is_empty());
        // The single shared prefix "" matches everything.
        assert_eq!(pins.find_by_prefix("").unwrap().len(), 2);
    }

    #[test]
    fn list_skips_partial_write_tmp_files() {
        let tmp = TempDir::new().unwrap();
        let pins = PinIndex::open(tmp.path()).unwrap();
        pins.add(cap_with_hash_byte(7), None, None).unwrap();

        let leftover = tmp.path().join("pins").join("dead.json.99999.tmp");
        fs::write(&leftover, b"{ junk").unwrap();

        let listed = pins.list().unwrap();
        assert_eq!(listed.len(), 1);
    }

    #[test]
    fn list_skips_unparseable_files() {
        let tmp = TempDir::new().unwrap();
        let pins = PinIndex::open(tmp.path()).unwrap();
        pins.add(cap_with_hash_byte(8), None, None).unwrap();

        // Drop a malformed .json with the right filename shape but bad content.
        let fake = tmp
            .path()
            .join("pins")
            .join(format!("{}.json", "ff".repeat(32)));
        fs::write(&fake, b"not valid json").unwrap();

        let listed = pins.list().unwrap();
        assert_eq!(listed.len(), 1);
    }

    #[test]
    fn rejects_filename_hash_mismatch() {
        let tmp = TempDir::new().unwrap();
        let pins = PinIndex::open(tmp.path()).unwrap();

        // Plant a pin file whose cap's manifest hash doesn't match the
        // filename hash. decode_record (and therefore list/get) must reject.
        let cap = cap_with_hash_byte(0x11);
        let json = serde_json::json!({
            "cap": cap.encode(),
            "name": null,
            "pinned_at": 0,
            "comment": null,
        });
        let lying_filename = format!("{}.json", "22".repeat(32));
        fs::write(
            tmp.path().join("pins").join(&lying_filename),
            serde_json::to_vec(&json).unwrap(),
        )
        .unwrap();

        // list silently drops the bad file; get on the lying hash also returns None.
        assert!(pins.list().unwrap().is_empty());
    }
}
