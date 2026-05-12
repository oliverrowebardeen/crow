//! Named encrypted vaults — "nests".
//!
//! A nest is the user-facing unit of trust in Crow: a named space with its
//! own catalog, pins, encrypted chunks/manifests, and (eventually) storage
//! policy. This module owns the on-disk metadata that describes which nests
//! exist on this device and which one is currently active.
//!
//! Layout under the device home directory:
//!
//! ```text
//! <home>/
//! ├── nests.json              # device-level index + active selection
//! └── nests/
//!     └── <nest-id>/          # one directory per nest
//!         ├── catalog/        # owned by crow::catalog
//!         ├── pins/           # owned by crow::pin
//!         ├── chunks/         # owned by crow::fs_store
//!         ├── manifests/      # owned by crow::fs_store
//!         └── policy.json     # placeholder for Phase 5 storage policy
//! ```
//!
//! Migration (`NestIndex::ensure_default`) is idempotent and crash-safe:
//! atomic temp+rename writes everywhere, plus a recovery path that completes
//! partial migrations by writing `nests.json` for an already-laid-out nest
//! directory.

use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const NESTS_FILE: &str = "nests.json";
const NESTS_DIR: &str = "nests";
const POLICY_FILE: &str = "policy.json";
const POLICY_PLACEHOLDER: &str = "{\n  \"version\": 1\n}\n";
const NESTS_INDEX_VERSION: u8 = 1;
const DEFAULT_NEST_NAME: &str = "personal";

/// Legacy top-level subdirectories that move under a nest during migration.
const LEGACY_DIRS: &[&str] = &["catalog", "pins", "chunks", "manifests"];

const MAX_NAME_LEN: usize = 32;

// ----------------------------------------------------------------------------
// NestId — 16-byte newtype with hex Display/FromStr and format-aware serde.
// ----------------------------------------------------------------------------

/// 16-byte stable identifier for a nest. Hex Display is 32 chars; serialised
/// as the hex string in human-readable formats (JSON, YAML) and as the raw
/// 16 bytes in binary formats (postcard, bincode).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NestId([u8; 16]);

impl NestId {
    pub const SIZE: usize = 16;

    pub fn random() -> Self {
        let mut bytes = [0u8; 16];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub fn short(&self) -> String {
        hex(&self.0[..4])
    }
}

impl std::fmt::Display for NestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex(&self.0))
    }
}

impl std::fmt::Debug for NestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NestId({})", self.short())
    }
}

impl FromStr for NestId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim();
        decode_hex16(s).map(Self).ok_or_else(|| {
            Error::Nest(format!(
                "NestId expects 32 hex characters, got {} ({:?})",
                s.len(),
                s
            ))
        })
    }
}

impl Serialize for NestId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&hex(&self.0))
        } else {
            s.serialize_bytes(&self.0)
        }
    }
}

impl<'de> Deserialize<'de> for NestId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = NestId;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("32-character hex string or 16-byte array")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> std::result::Result<NestId, E> {
                decode_hex16(v.trim())
                    .map(NestId)
                    .ok_or_else(|| E::custom(format!("invalid hex nest id: {v:?}")))
            }

            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> std::result::Result<NestId, E> {
                if v.len() != NestId::SIZE {
                    return Err(E::invalid_length(v.len(), &"16 bytes"));
                }
                let mut out = [0u8; 16];
                out.copy_from_slice(v);
                Ok(NestId(out))
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<NestId, A::Error> {
                let mut out = [0u8; 16];
                for (i, slot) in out.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &"16 bytes"))?;
                }
                Ok(NestId(out))
            }
        }

        if d.is_human_readable() {
            d.deserialize_str(V)
        } else {
            d.deserialize_bytes(V)
        }
    }
}

// ----------------------------------------------------------------------------
// Nest + NestIndex
// ----------------------------------------------------------------------------

/// Metadata for a single nest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nest {
    pub id: NestId,
    pub name: String,
    pub created_at: u64,
    pub creator_device_id: String,
}

/// Device-level index of every nest known on this machine, plus the active
/// selection. Backed by `<home>/nests.json`.
#[derive(Clone, Debug)]
pub struct NestIndex {
    home: PathBuf,
    active: NestId,
    nests: Vec<Nest>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct NestIndexJson {
    version: u8,
    active: NestId,
    nests: Vec<Nest>,
}

impl NestIndex {
    /// Path to `nests.json` under the given home directory.
    pub fn index_path(home: &Path) -> PathBuf {
        home.join(NESTS_FILE)
    }

    /// Directory holding all nests under the given home.
    pub fn nests_root(home: &Path) -> PathBuf {
        home.join(NESTS_DIR)
    }

    /// Full path to a particular nest's directory.
    pub fn nest_dir(&self, id: &NestId) -> PathBuf {
        Self::nests_root(&self.home).join(id.to_string())
    }

    pub fn home(&self) -> &Path {
        &self.home
    }

    pub fn active(&self) -> &Nest {
        self.nests
            .iter()
            .find(|n| n.id == self.active)
            .expect("active id must point at a known nest")
    }

    pub fn list(&self) -> &[Nest] {
        &self.nests
    }

    /// Open or initialise the nest index at `home`.
    ///
    /// Handles four cases idempotently:
    /// 1. `nests.json` already exists → load and return.
    /// 2. Partial migration: `<home>/nests/<id>/` exists but no `nests.json`.
    ///    Pick the (single) nest subdir, complete any pending legacy renames,
    ///    and write `nests.json`.
    /// 3. Legacy layout: any of `<home>/{catalog,pins,chunks,manifests}` exist
    ///    without a `nests/` or `nests.json`. Generate a fresh `NestId`, move
    ///    the four directories under `nests/<id>/`, and write `nests.json`.
    /// 4. Fresh home: write an empty default nest.
    ///
    /// Errors if `nests.json` exists *and* legacy directories also exist at
    /// the home root — that's an ambiguous state Crow won't silently resolve.
    pub fn ensure_default(home: &Path, creator_device_id: &str) -> Result<Self> {
        let index_path = Self::index_path(home);
        let nests_root = Self::nests_root(home);
        let has_index = index_path.exists();
        let legacy_present = LEGACY_DIRS.iter().any(|d| home.join(d).exists());

        if has_index && legacy_present {
            return Err(Error::Nest(format!(
                "{} exists alongside legacy top-level directories ({}); \
                 refusing to auto-migrate. Move the legacy directories under \
                 the appropriate nest in {} or delete them manually.",
                index_path.display(),
                LEGACY_DIRS.join(", "),
                nests_root.display(),
            )));
        }

        if has_index {
            return Self::load(home);
        }

        fs::create_dir_all(home)?;
        fs::create_dir_all(&nests_root)?;

        // Recovery: if nests/ already holds exactly one subdirectory, treat
        // that as the partially-migrated default nest.
        let existing = list_subdirs(&nests_root)?;
        let nest_id = match existing.len() {
            0 => NestId::random(),
            1 => parse_existing_nest_id(&existing[0])?,
            n => {
                return Err(Error::Nest(format!(
                    "found {n} subdirectories under {} but no nests.json; \
                     cannot disambiguate. Run `crow nest list` after writing a \
                     nests.json by hand, or remove the unwanted directories.",
                    nests_root.display(),
                )));
            }
        };

        let nest_dir = nests_root.join(nest_id.to_string());
        fs::create_dir_all(&nest_dir)?;

        // Move any legacy top-level dirs into the chosen nest dir. If the
        // target already exists, leave both in place rather than overwriting.
        for sub in LEGACY_DIRS {
            let legacy = home.join(sub);
            let target = nest_dir.join(sub);
            if legacy.exists() {
                if target.exists() {
                    return Err(Error::Nest(format!(
                        "both {} and {} exist; refusing to overwrite during migration",
                        legacy.display(),
                        target.display(),
                    )));
                }
                fs::rename(&legacy, &target)?;
            }
        }

        // Placeholder policy file (Phase 5 will populate).
        let policy_path = nest_dir.join(POLICY_FILE);
        if !policy_path.exists() {
            write_atomic(&policy_path, POLICY_PLACEHOLDER.as_bytes())?;
        }

        let nest = Nest {
            id: nest_id,
            name: DEFAULT_NEST_NAME.to_string(),
            created_at: now_unix(),
            creator_device_id: creator_device_id.to_string(),
        };
        let index = NestIndex {
            home: home.to_path_buf(),
            active: nest.id,
            nests: vec![nest],
        };
        index.save()?;
        Ok(index)
    }

    /// Load an existing nests.json without any migration.
    pub fn load(home: &Path) -> Result<Self> {
        let path = Self::index_path(home);
        let bytes = fs::read(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Error::Nest(format!("nest index not found at {}", path.display()))
            } else {
                Error::Io(e)
            }
        })?;
        let json: NestIndexJson = serde_json::from_slice(&bytes)
            .map_err(|e| Error::Nest(format!("deserialize {}: {e}", path.display())))?;
        if json.version != NESTS_INDEX_VERSION {
            return Err(Error::Nest(format!(
                "unsupported nest index version {}; this build supports {}",
                json.version, NESTS_INDEX_VERSION
            )));
        }
        if json.nests.is_empty() {
            return Err(Error::Nest("nest index has zero nests".into()));
        }
        if !json.nests.iter().any(|n| n.id == json.active) {
            return Err(Error::Nest(format!(
                "active nest {} not present in index",
                json.active
            )));
        }
        Ok(Self {
            home: home.to_path_buf(),
            active: json.active,
            nests: json.nests,
        })
    }

    fn save(&self) -> Result<()> {
        let json = NestIndexJson {
            version: NESTS_INDEX_VERSION,
            active: self.active,
            nests: self.nests.clone(),
        };
        let bytes =
            serde_json::to_vec_pretty(&json).map_err(|e| Error::Nest(format!("serialize: {e}")))?;
        write_atomic(&Self::index_path(&self.home), &bytes)
    }

    /// Add a new nest with `name`. Does not change the active selection.
    /// Errors if `name` is invalid or duplicates an existing nest's name.
    pub fn create(&mut self, name: &str, creator_device_id: &str) -> Result<&Nest> {
        let name = validate_name(name)?;
        if let Some(existing) = self.nests.iter().find(|n| n.name == name) {
            return Err(Error::Nest(format!(
                "nest name '{name}' already in use (id {})",
                existing.id
            )));
        }
        let nest = Nest {
            id: NestId::random(),
            name: name.to_string(),
            created_at: now_unix(),
            creator_device_id: creator_device_id.to_string(),
        };
        let nest_dir = self.nest_dir(&nest.id);
        fs::create_dir_all(&nest_dir)?;
        write_atomic(&nest_dir.join(POLICY_FILE), POLICY_PLACEHOLDER.as_bytes())?;
        self.nests.push(nest);
        self.save()?;
        Ok(self.nests.last().expect("just pushed; cannot be empty"))
    }

    /// Switch the active nest. `reference` can be a full hex id, an id
    /// prefix, or an exact name match.
    pub fn set_active(&mut self, reference: &str) -> Result<&Nest> {
        let id = self.resolve(reference)?.id;
        self.active = id;
        self.save()?;
        Ok(self.active())
    }

    /// Resolve a user-typed reference to one of the known nests.
    pub fn resolve(&self, reference: &str) -> Result<&Nest> {
        let reference = reference.trim();
        if reference.is_empty() {
            return Err(Error::Nest("empty nest reference".into()));
        }
        let lower = reference.to_ascii_lowercase();

        // Full hex id wins outright.
        if let Ok(id) = NestId::from_str(reference) {
            return self
                .nests
                .iter()
                .find(|n| n.id == id)
                .ok_or_else(|| Error::Nest(format!("no nest with id {reference}")));
        }

        // Then try hex prefix (must be all hex chars; up to 32).
        if reference.len() <= 32 && reference.bytes().all(|b| b.is_ascii_hexdigit()) {
            let matches: Vec<&Nest> = self
                .nests
                .iter()
                .filter(|n| n.id.to_string().starts_with(&lower))
                .collect();
            if matches.len() == 1 {
                return Ok(matches[0]);
            }
            if matches.len() > 1 {
                return Err(ambiguous_error(reference, &matches));
            }
        }

        // Fall back to exact-name match.
        let by_name: Vec<&Nest> = self.nests.iter().filter(|n| n.name == reference).collect();
        match by_name.len() {
            0 => Err(Error::Nest(format!(
                "no nest matches '{reference}' (tried full id, hex prefix, exact name)"
            ))),
            1 => Ok(by_name[0]),
            _ => Err(ambiguous_error(reference, &by_name)),
        }
    }
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

fn ambiguous_error(reference: &str, matches: &[&Nest]) -> Error {
    let mut msg = format!("ambiguous nest '{reference}' ({} matches):", matches.len());
    for n in matches {
        msg.push_str(&format!("\n  {}  {}", n.id.short(), n.name));
    }
    Error::Nest(msg)
}

/// Validate a user-typed nest name. Trimmed; non-empty; ≤ 32 chars; only the
/// characters used by `validate_device_name`.
fn validate_name(name: &str) -> Result<&str> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(Error::Nest("nest name cannot be empty".into()));
    }
    if trimmed.len() > MAX_NAME_LEN {
        return Err(Error::Nest(format!(
            "nest name must be at most {MAX_NAME_LEN} characters"
        )));
    }
    let ok = |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ' ');
    if !trimmed.chars().all(ok) {
        return Err(Error::Nest(format!(
            "nest name '{trimmed}' contains characters outside [A-Za-z0-9-_. ]"
        )));
    }
    Ok(trimmed)
}

fn list_subdirs(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(Error::Io(e)),
    };
    for entry in entries {
        let entry = entry?;
        let ft = entry.file_type()?;
        if ft.is_dir() {
            out.push(entry.path());
        }
    }
    Ok(out)
}

fn parse_existing_nest_id(path: &Path) -> Result<NestId> {
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| Error::Nest(format!("non-utf8 nest directory: {}", path.display())))?;
    NestId::from_str(name).map_err(|_| {
        Error::Nest(format!(
            "subdirectory {} is not a valid nest id (expected 32 hex chars)",
            path.display()
        ))
    })
}

fn write_atomic(target: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }
    let pid = std::process::id();
    let tmp_name = match target.file_name().and_then(|s| s.to_str()) {
        Some(s) => format!("{s}.{pid}.tmp"),
        None => return Err(Error::Nest("invalid target path".into())),
    };
    let tmp = target.with_file_name(tmp_name);
    fs::write(&tmp, bytes)?;
    fs::rename(&tmp, target)?;
    Ok(())
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn decode_hex16(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn home() -> TempDir {
        TempDir::new().expect("tempdir")
    }

    fn read_str(p: &Path) -> String {
        fs::read_to_string(p).unwrap_or_default()
    }

    // ------------------------------------------------------------------
    // NestId
    // ------------------------------------------------------------------

    #[test]
    fn nest_id_hex_roundtrip() {
        let id = NestId::from_bytes([0xABu8; 16]);
        let s = id.to_string();
        assert_eq!(s.len(), 32);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(NestId::from_str(&s).unwrap(), id);
    }

    #[test]
    fn nest_id_short_is_8_chars() {
        let id = NestId::from_bytes([0x12u8; 16]);
        assert_eq!(id.short().len(), 8);
        assert_eq!(id.short(), "12121212");
    }

    #[test]
    fn nest_id_rejects_bad_input() {
        assert!(NestId::from_str("").is_err());
        assert!(NestId::from_str("abc").is_err());
        assert!(NestId::from_str(&"z".repeat(32)).is_err());
        assert!(NestId::from_str(&"a".repeat(31)).is_err());
        assert!(NestId::from_str(&"a".repeat(33)).is_err());
    }

    #[test]
    fn nest_id_json_is_hex_string() {
        let id = NestId::from_bytes([0xCDu8; 16]);
        let s = serde_json::to_string(&id).unwrap();
        assert_eq!(s, format!("\"{}\"", "cd".repeat(16)));
        let back: NestId = serde_json::from_str(&s).unwrap();
        assert_eq!(back, id);
    }

    #[test]
    fn nest_id_postcard_is_raw_bytes() {
        let id = NestId::from_bytes([0xEFu8; 16]);
        let bytes = postcard::to_allocvec(&id).unwrap();
        // postcard prefixes bytes with a varint length; len=16 fits in 1 byte.
        assert_eq!(bytes.len(), 17);
        assert_eq!(bytes[0], 16);
        assert_eq!(&bytes[1..], &[0xEFu8; 16]);
        let back: NestId = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back, id);
    }

    // ------------------------------------------------------------------
    // ensure_default — fresh home
    // ------------------------------------------------------------------

    #[test]
    fn ensure_default_fresh_home_creates_personal_nest() {
        let h = home();
        let index = NestIndex::ensure_default(h.path(), "device-x").unwrap();
        assert_eq!(index.list().len(), 1);
        let nest = &index.list()[0];
        assert_eq!(nest.name, "personal");
        assert_eq!(nest.creator_device_id, "device-x");
        assert_eq!(index.active().id, nest.id);

        // nests.json + nests/<id>/policy.json exist.
        assert!(NestIndex::index_path(h.path()).exists());
        let nest_dir = index.nest_dir(&nest.id);
        assert!(nest_dir.exists());
        assert!(nest_dir.join("policy.json").exists());
    }

    #[test]
    fn ensure_default_is_idempotent() {
        let h = home();
        let first = NestIndex::ensure_default(h.path(), "device-x").unwrap();
        let first_json = read_str(&NestIndex::index_path(h.path()));
        let second = NestIndex::ensure_default(h.path(), "different-device").unwrap();
        let second_json = read_str(&NestIndex::index_path(h.path()));

        assert_eq!(first.active().id, second.active().id);
        assert_eq!(first_json, second_json); // re-running did not rewrite
    }

    // ------------------------------------------------------------------
    // ensure_default — legacy migration
    // ------------------------------------------------------------------

    #[test]
    fn ensure_default_migrates_legacy_layout() {
        let h = home();
        // Lay down a legacy <home>/{catalog,pins,chunks,manifests} with
        // marker files inside each.
        for sub in LEGACY_DIRS {
            let d = h.path().join(sub);
            fs::create_dir_all(&d).unwrap();
            fs::write(d.join("marker"), b"legacy").unwrap();
        }

        let index = NestIndex::ensure_default(h.path(), "device-x").unwrap();
        let nest_dir = index.nest_dir(&index.active().id);

        for sub in LEGACY_DIRS {
            assert!(
                !h.path().join(sub).exists(),
                "legacy <home>/{sub} should have moved"
            );
            let moved = nest_dir.join(sub).join("marker");
            assert!(
                moved.exists(),
                "marker {} missing after migration",
                moved.display()
            );
            assert_eq!(fs::read_to_string(moved).unwrap(), "legacy");
        }
    }

    #[test]
    fn ensure_default_migrates_partial_legacy() {
        // Only catalog/ and pins/ exist; chunks/ and manifests/ do not yet.
        let h = home();
        for sub in &["catalog", "pins"] {
            fs::create_dir_all(h.path().join(sub)).unwrap();
            fs::write(h.path().join(sub).join("marker"), b"x").unwrap();
        }
        let index = NestIndex::ensure_default(h.path(), "device-x").unwrap();
        let nest_dir = index.nest_dir(&index.active().id);
        assert!(nest_dir.join("catalog/marker").exists());
        assert!(nest_dir.join("pins/marker").exists());
        assert!(!nest_dir.join("chunks").exists());
        assert!(!nest_dir.join("manifests").exists());
    }

    // ------------------------------------------------------------------
    // ensure_default — partial-migration recovery
    // ------------------------------------------------------------------

    #[test]
    fn ensure_default_recovers_partial_migration() {
        // nests/<id>/ exists with content, but no nests.json yet.
        let h = home();
        let nest_id = NestId::random();
        let nest_dir = h.path().join(NESTS_DIR).join(nest_id.to_string());
        fs::create_dir_all(nest_dir.join("catalog")).unwrap();
        fs::write(nest_dir.join("catalog/marker"), b"survived").unwrap();

        let index = NestIndex::ensure_default(h.path(), "device-x").unwrap();
        assert_eq!(index.active().id, nest_id);
        assert!(NestIndex::index_path(h.path()).exists());
        assert!(nest_dir.join("catalog/marker").exists());
        assert_eq!(
            fs::read_to_string(nest_dir.join("catalog/marker")).unwrap(),
            "survived"
        );
    }

    #[test]
    fn ensure_default_fails_when_multiple_nest_subdirs_have_no_index() {
        let h = home();
        let a = NestId::random();
        let b = NestId::random();
        for id in [a, b] {
            fs::create_dir_all(h.path().join(NESTS_DIR).join(id.to_string())).unwrap();
        }
        let err = NestIndex::ensure_default(h.path(), "device-x").unwrap_err();
        assert!(matches!(err, Error::Nest(_)));
    }

    // ------------------------------------------------------------------
    // ensure_default — conflict: nests.json + legacy dirs both present
    // ------------------------------------------------------------------

    #[test]
    fn ensure_default_refuses_to_merge_legacy_into_existing_index() {
        let h = home();
        NestIndex::ensure_default(h.path(), "device-x").unwrap();
        fs::create_dir_all(h.path().join("catalog")).unwrap();
        let err = NestIndex::ensure_default(h.path(), "device-x").unwrap_err();
        match err {
            Error::Nest(msg) => assert!(msg.contains("legacy")),
            other => panic!("expected Nest error, got {other:?}"),
        }
    }

    // ------------------------------------------------------------------
    // create / set_active / resolve
    // ------------------------------------------------------------------

    #[test]
    fn create_adds_nest_without_changing_active() {
        let h = home();
        let mut index = NestIndex::ensure_default(h.path(), "device-x").unwrap();
        let original_active = index.active().id;
        let new_id = index.create("work", "device-x").unwrap().id;
        assert_eq!(index.list().len(), 2);
        assert_eq!(index.active().id, original_active);
        assert_ne!(new_id, original_active);
        // policy.json was created for the new nest.
        assert!(index.nest_dir(&new_id).join("policy.json").exists());
    }

    #[test]
    fn create_rejects_duplicate_name() {
        let h = home();
        let mut index = NestIndex::ensure_default(h.path(), "device-x").unwrap();
        let err = index.create("personal", "device-x").unwrap_err();
        match err {
            Error::Nest(msg) => assert!(msg.contains("already in use")),
            other => panic!("expected Nest error, got {other:?}"),
        }
    }

    #[test]
    fn create_rejects_invalid_name() {
        let h = home();
        let mut index = NestIndex::ensure_default(h.path(), "device-x").unwrap();
        assert!(index.create("", "device-x").is_err());
        assert!(index.create("   ", "device-x").is_err());
        assert!(index.create(&"a".repeat(33), "device-x").is_err());
        assert!(index.create("bad/name", "device-x").is_err());
        assert!(index.create("bad\nname", "device-x").is_err());
    }

    #[test]
    fn set_active_resolves_by_name() {
        let h = home();
        let mut index = NestIndex::ensure_default(h.path(), "device-x").unwrap();
        index.create("work", "device-x").unwrap();
        index.set_active("work").unwrap();
        assert_eq!(index.active().name, "work");
    }

    #[test]
    fn set_active_resolves_by_full_id() {
        let h = home();
        let mut index = NestIndex::ensure_default(h.path(), "device-x").unwrap();
        let work_id = index.create("work", "device-x").unwrap().id;
        index.set_active(&work_id.to_string()).unwrap();
        assert_eq!(index.active().id, work_id);
    }

    #[test]
    fn set_active_resolves_by_id_prefix() {
        let h = home();
        let mut index = NestIndex::ensure_default(h.path(), "device-x").unwrap();
        let work_id = index.create("work", "device-x").unwrap().id;
        let prefix = &work_id.to_string()[..4];
        index.set_active(prefix).unwrap();
        assert_eq!(index.active().id, work_id);
    }

    #[test]
    fn resolve_reports_ambiguous_prefix() {
        // Force a deterministic collision on the first hex char. We build
        // the index by hand instead of going through `create()` because we
        // need control over the exact NestId bytes; the test never touches
        // the filesystem so an unused tempdir is fine.
        let tmp = home();
        let index = NestIndex {
            home: tmp.path().to_path_buf(),
            active: NestId::from_bytes([0xABu8; 16]),
            nests: vec![
                Nest {
                    id: NestId::from_bytes([0xABu8; 16]),
                    name: "a".into(),
                    created_at: 0,
                    creator_device_id: "x".into(),
                },
                Nest {
                    id: NestId::from_bytes({
                        let mut b = [0xABu8; 16];
                        b[15] = 0xCD;
                        b
                    }),
                    name: "b".into(),
                    created_at: 0,
                    creator_device_id: "x".into(),
                },
            ],
        };
        let err = index.resolve("ab").unwrap_err();
        match err {
            Error::Nest(msg) => {
                assert!(msg.contains("ambiguous"));
                assert!(msg.contains("a"));
                assert!(msg.contains("b"));
            }
            other => panic!("expected Nest error, got {other:?}"),
        }
        // Sanity: the longer prefix disambiguates one way.
        let full = format!("{}cd", &"ab".repeat(15));
        assert_eq!(index.resolve(&full).unwrap().name, "b");
    }

    #[test]
    fn resolve_reports_missing() {
        let h = home();
        let index = NestIndex::ensure_default(h.path(), "device-x").unwrap();
        let err = index.resolve("does-not-exist").unwrap_err();
        match err {
            Error::Nest(msg) => assert!(msg.contains("no nest matches")),
            other => panic!("expected Nest error, got {other:?}"),
        }
    }

    // ------------------------------------------------------------------
    // load() edge cases
    // ------------------------------------------------------------------

    #[test]
    fn load_rejects_unknown_version() {
        let h = home();
        let bogus = serde_json::json!({
            "version": 99,
            "active": "00".repeat(16),
            "nests": [{
                "id": "00".repeat(16),
                "name": "personal",
                "created_at": 0,
                "creator_device_id": "x",
            }],
        });
        fs::write(
            NestIndex::index_path(h.path()),
            serde_json::to_vec(&bogus).unwrap(),
        )
        .unwrap();
        assert!(matches!(NestIndex::load(h.path()), Err(Error::Nest(_))));
    }

    #[test]
    fn load_rejects_active_not_in_list() {
        let h = home();
        let bogus = serde_json::json!({
            "version": 1,
            "active": "ff".repeat(16),
            "nests": [{
                "id": "00".repeat(16),
                "name": "personal",
                "created_at": 0,
                "creator_device_id": "x",
            }],
        });
        fs::write(
            NestIndex::index_path(h.path()),
            serde_json::to_vec(&bogus).unwrap(),
        )
        .unwrap();
        let err = NestIndex::load(h.path()).unwrap_err();
        match err {
            Error::Nest(msg) => assert!(msg.contains("not present in index")),
            other => panic!("expected Nest error, got {other:?}"),
        }
    }
}
