use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::cap::Cap;
use crate::crypto::{ManifestKey, open_manifest, seal_manifest};
use crate::error::{Error, Result};
use crate::identity::{Identity, NodeId};
use crate::manifest::{Signature, SignatureStatus};

use ed25519_dalek::{Signature as Ed25519Signature, Signer, Verifier, VerifyingKey};

pub const DIRECTORY_MANIFEST_VERSION: u8 = 1;
pub const DIRECTORY_MANIFEST_MAGIC: [u8; 4] = *b"CDIR";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryManifest {
    pub version: u8,
    pub magic: [u8; 4],
    pub created_at: u64,
    pub entries: Vec<DirectoryEntry>,
    /// Ed25519 public key of the directory snapshot creator. `None` means
    /// legacy unsigned data.
    pub creator_pubkey: Option<[u8; 32]>,
    /// Ed25519 signature over the canonical postcard encoding with this field
    /// taken as `None`.
    pub signature: Option<Signature>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryEntry {
    pub path: String,
    pub kind: DirectoryEntryKind,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DirectoryEntryKind {
    Dir,
    File { cap: String, name: Option<String> },
}

impl DirectoryManifest {
    pub fn new(created_at: u64, entries: Vec<DirectoryEntry>) -> Result<Self> {
        let entries = normalize_entries(entries)?;
        Ok(Self {
            version: DIRECTORY_MANIFEST_VERSION,
            magic: DIRECTORY_MANIFEST_MAGIC,
            created_at,
            entries,
            creator_pubkey: None,
            signature: None,
        })
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        postcard::to_allocvec(self)
            .map_err(|e| Error::Manifest(format!("directory serialize: {e}")))
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        let (manifest, rest) = postcard::take_from_bytes::<DirectoryManifest>(bytes)
            .map_err(|e| Error::Manifest(format!("directory deserialize: {e}")))?;
        if !rest.is_empty() {
            return Err(Error::Manifest(format!(
                "{} trailing bytes after directory manifest",
                rest.len()
            )));
        }
        manifest.validate()?;
        manifest.signature_status()?;
        Ok(manifest)
    }

    pub fn seal(&self, key: &ManifestKey) -> Result<Vec<u8>> {
        let plaintext = self.serialize()?;
        seal_manifest(key, &plaintext)
    }

    pub fn open(ciphertext: &[u8], key: &ManifestKey) -> Result<Self> {
        let plaintext = open_manifest(key, ciphertext)?;
        Self::deserialize(&plaintext)
    }

    pub fn sign(&mut self, identity: &Identity) -> Result<()> {
        let creator = identity.signing_pubkey();
        self.creator_pubkey = Some(creator);
        self.signature = None;
        let payload = self.signing_payload(creator)?;
        let signature: Ed25519Signature = identity.signing.sign(&payload);
        self.signature = Some(Signature(signature.to_bytes()));
        Ok(())
    }

    pub fn signature_status(&self) -> Result<SignatureStatus> {
        match (self.creator_pubkey, self.signature) {
            (None, None) => Ok(SignatureStatus::Unsigned),
            (Some(creator), Some(signature)) => {
                let payload = self.signing_payload(creator)?;
                let verifying_key = VerifyingKey::from_bytes(&creator)
                    .map_err(|e| Error::Manifest(format!("invalid creator public key: {e}")))?;
                let signature = Ed25519Signature::from_bytes(&signature.0);
                verifying_key
                    .verify(&payload, &signature)
                    .map_err(|_| Error::Manifest("invalid directory manifest signature".into()))?;
                Ok(SignatureStatus::Signed {
                    creator: NodeId::from_bytes(creator),
                })
            }
            _ => Err(Error::Manifest(
                "malformed directory manifest signature fields".into(),
            )),
        }
    }

    fn signing_payload(&self, creator: [u8; 32]) -> Result<Vec<u8>> {
        let mut canonical = self.clone();
        canonical.creator_pubkey = Some(creator);
        canonical.signature = None;
        canonical.serialize()
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != DIRECTORY_MANIFEST_VERSION {
            return Err(Error::Manifest(format!(
                "unsupported directory manifest version {}; this build supports {}",
                self.version, DIRECTORY_MANIFEST_VERSION
            )));
        }
        if self.magic != DIRECTORY_MANIFEST_MAGIC {
            return Err(Error::Manifest("not a directory manifest".into()));
        }
        let normalized = normalize_entries(self.entries.clone())?;
        if normalized != self.entries {
            return Err(Error::Manifest(
                "directory manifest entries are not canonical".into(),
            ));
        }
        Ok(())
    }

    pub fn file_caps(&self) -> Result<Vec<Cap>> {
        self.entries
            .iter()
            .filter_map(|entry| match &entry.kind {
                DirectoryEntryKind::Dir => None,
                DirectoryEntryKind::File { cap, .. } => Some(Cap::decode(cap)),
            })
            .collect()
    }

    pub fn file_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| matches!(entry.kind, DirectoryEntryKind::File { .. }))
            .count()
    }

    pub fn dir_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| matches!(entry.kind, DirectoryEntryKind::Dir))
            .count()
    }
}

impl DirectoryEntry {
    pub fn dir(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            kind: DirectoryEntryKind::Dir,
        }
    }

    pub fn file(path: impl Into<String>, cap: Cap, name: Option<String>) -> Self {
        Self {
            path: path.into(),
            kind: DirectoryEntryKind::File {
                cap: cap.encode(),
                name,
            },
        }
    }

    pub fn cap(&self) -> Result<Option<Cap>> {
        match &self.kind {
            DirectoryEntryKind::Dir => Ok(None),
            DirectoryEntryKind::File { cap, .. } => Ok(Some(Cap::decode(cap)?)),
        }
    }
}

fn normalize_entries(mut entries: Vec<DirectoryEntry>) -> Result<Vec<DirectoryEntry>> {
    for entry in &mut entries {
        entry.path = normalize_relative_path(&entry.path)?;
        if let DirectoryEntryKind::File { cap, .. } = &entry.kind {
            Cap::decode(cap)?;
        }
    }
    entries.sort_by(|a, b| {
        a.path
            .cmp(&b.path)
            .then_with(|| kind_rank(&a.kind).cmp(&kind_rank(&b.kind)))
    });

    let mut seen_paths = BTreeSet::new();
    for entry in &entries {
        if !seen_paths.insert(entry.path.clone()) {
            return Err(Error::Manifest(format!(
                "duplicate directory entry path {}",
                entry.path
            )));
        }
    }
    Ok(entries)
}

fn normalize_relative_path(path: &str) -> Result<String> {
    let path = path.trim();
    if path.is_empty() {
        return Err(Error::Manifest(
            "directory entry path must not be empty".into(),
        ));
    }
    if path.starts_with('/') {
        return Err(Error::Manifest(format!(
            "directory entry path must be relative: {path}"
        )));
    }
    let mut components = Vec::new();
    for component in path.split('/') {
        if component.is_empty() || component == "." {
            continue;
        }
        if component == ".." {
            return Err(Error::Manifest(
                ".. is not allowed in directory manifests".into(),
            ));
        }
        if component.contains('\0') {
            return Err(Error::Manifest(
                "NUL is not allowed in directory manifest paths".into(),
            ));
        }
        components.push(component);
    }
    if components.is_empty() {
        return Err(Error::Manifest(
            "directory entry path must not be empty".into(),
        ));
    }
    Ok(components.join("/"))
}

fn kind_rank(kind: &DirectoryEntryKind) -> u8 {
    match kind {
        DirectoryEntryKind::Dir => 0,
        DirectoryEntryKind::File { .. } => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::ManifestHash;
    use crate::identity::Identity;

    fn cap_with_hash_byte(b: u8) -> Cap {
        Cap::new_read(
            ManifestHash::from_bytes([b; 32]),
            ManifestKey::from_bytes([b; 32]),
        )
    }

    fn sample() -> DirectoryManifest {
        DirectoryManifest::new(
            123,
            vec![
                DirectoryEntry::dir("docs"),
                DirectoryEntry::file("docs/a.txt", cap_with_hash_byte(1), Some("a.txt".into())),
            ],
        )
        .unwrap()
    }

    fn signed_sample() -> (DirectoryManifest, Identity) {
        let identity = Identity::random();
        let mut manifest = sample();
        manifest.sign(&identity).unwrap();
        (manifest, identity)
    }

    #[test]
    fn directory_manifest_roundtrip() {
        let cap = cap_with_hash_byte(1);
        let manifest = DirectoryManifest::new(
            123,
            vec![
                DirectoryEntry::file("b.txt", cap.clone(), Some("b.txt".into())),
                DirectoryEntry::dir("a"),
                DirectoryEntry::file("a/c.txt", cap, Some("c.txt".into())),
            ],
        )
        .unwrap();

        let bytes = manifest.serialize().unwrap();
        let decoded = DirectoryManifest::deserialize(&bytes).unwrap();

        assert_eq!(decoded.entries[0].path, "a");
        assert_eq!(decoded.entries[1].path, "a/c.txt");
        assert_eq!(decoded.entries[2].path, "b.txt");
        assert_eq!(decoded.file_count(), 2);
        assert_eq!(decoded.dir_count(), 1);
    }

    #[test]
    fn directory_manifest_seal_open_roundtrip() {
        let key = ManifestKey::random();
        let manifest = DirectoryManifest::new(123, vec![DirectoryEntry::dir("docs")]).unwrap();
        let sealed = manifest.seal(&key).unwrap();
        let opened = DirectoryManifest::open(&sealed, &key).unwrap();
        assert_eq!(opened.entries[0].path, "docs");
    }

    #[test]
    fn sign_records_creator_and_signature() {
        let (manifest, identity) = signed_sample();

        assert_eq!(manifest.creator_pubkey, Some(identity.signing_pubkey()));
        assert!(manifest.signature.is_some());
        assert_eq!(
            manifest.signature_status().unwrap(),
            SignatureStatus::Signed {
                creator: identity.node_id()
            }
        );
    }

    #[test]
    fn signed_directory_manifest_seal_open_roundtrip() {
        let key = ManifestKey::random();
        let (manifest, _) = signed_sample();
        let sealed = manifest.seal(&key).unwrap();
        let opened = DirectoryManifest::open(&sealed, &key).unwrap();

        assert_eq!(manifest.serialize().unwrap(), opened.serialize().unwrap());
        assert!(matches!(
            opened.signature_status().unwrap(),
            SignatureStatus::Signed { .. }
        ));
    }

    #[test]
    fn signing_is_deterministic_for_same_manifest_and_identity() {
        let identity = Identity::random();
        let mut a = sample();
        let mut b = sample();

        a.sign(&identity).unwrap();
        b.sign(&identity).unwrap();

        assert_eq!(a.signature, b.signature);
        assert_eq!(a.serialize().unwrap(), b.serialize().unwrap());
    }

    #[test]
    fn unsigned_directory_manifest_is_legacy_compatible() {
        assert_eq!(
            sample().signature_status().unwrap(),
            SignatureStatus::Unsigned
        );
        let bytes = sample().serialize().unwrap();
        assert!(DirectoryManifest::deserialize(&bytes).is_ok());
    }

    #[test]
    fn signed_directory_manifest_rejects_tampering() {
        let (mut manifest, _) = signed_sample();
        manifest.created_at += 1;

        let err = manifest
            .signature_status()
            .expect_err("expected invalid signature");

        assert!(
            err.to_string()
                .contains("invalid directory manifest signature")
        );
        assert!(DirectoryManifest::deserialize(&manifest.serialize().unwrap()).is_err());
    }

    #[test]
    fn partial_signature_fields_are_rejected() {
        let identity = Identity::random();
        let mut creator_only = sample();
        creator_only.creator_pubkey = Some(identity.signing_pubkey());
        assert!(creator_only.signature_status().is_err());

        let mut signature_only = sample();
        signature_only.sign(&identity).unwrap();
        signature_only.creator_pubkey = None;
        assert!(signature_only.signature_status().is_err());
    }

    #[test]
    fn rejects_absolute_or_parent_paths() {
        let cap = cap_with_hash_byte(1);
        assert!(DirectoryManifest::new(1, vec![DirectoryEntry::dir("/abs")]).is_err());
        assert!(DirectoryManifest::new(1, vec![DirectoryEntry::dir("../x")]).is_err());
        assert!(DirectoryManifest::new(1, vec![DirectoryEntry::file("", cap, None)]).is_err());
    }

    #[test]
    fn rejects_duplicate_paths() {
        let manifest = DirectoryManifest::new(
            1,
            vec![DirectoryEntry::dir("docs"), DirectoryEntry::dir("docs")],
        );
        assert!(manifest.is_err());
    }
}
