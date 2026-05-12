use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use ed25519_dalek::{Signature as Ed25519Signature, Signer, Verifier, VerifyingKey};

use crate::cap::Cap;
use crate::error::{Error, Result};
use crate::identity::{Identity, NodeId};
use crate::manifest::Signature;
use crate::member::{MemberRecord, NestRole, member_grant_canonical_bytes};
use crate::nest::NestId;

const CATALOG_DIR: &str = "catalog";
const EVENTS_FILE: &str = "events.jsonl";
const DEVICE_ID_FILE: &str = "device-id";

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CatalogPath(String);

impl CatalogPath {
    pub fn normalize(input: &str) -> Result<Self> {
        let input = input.trim();
        if input.is_empty() {
            return Err(Error::Catalog("path must not be empty".into()));
        }
        let mut components = Vec::new();
        for component in input.split('/') {
            if component.is_empty() || component == "." {
                continue;
            }
            if component == ".." {
                return Err(Error::Catalog(".. is not allowed in catalog paths".into()));
            }
            if component.contains('\0') {
                return Err(Error::Catalog("NUL is not allowed in catalog paths".into()));
            }
            components.push(component);
        }
        if components.is_empty() {
            return Ok(Self("/".into()));
        }
        Ok(Self(format!("/{}", components.join("/"))))
    }

    pub fn root() -> Self {
        Self("/".into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn parent(&self) -> Option<Self> {
        if self.0 == "/" {
            return None;
        }
        let parent = self.0.rsplit_once('/').map(|(p, _)| p).unwrap_or("/");
        if parent.is_empty() {
            Some(Self::root())
        } else {
            Some(Self(parent.to_string()))
        }
    }

    pub fn file_name(&self) -> Option<&str> {
        (self.0 != "/").then(|| self.0.rsplit('/').next()).flatten()
    }

    fn is_descendant_of(&self, parent: &Self) -> bool {
        if parent.0 == "/" {
            return self.0 != "/";
        }
        self.0
            .strip_prefix(parent.as_str())
            .is_some_and(|rest| rest.starts_with('/'))
    }

    fn moved_under(&self, from: &Self, to: &Self) -> Self {
        if self == from {
            return to.clone();
        }
        let suffix = self.0.strip_prefix(from.as_str()).unwrap_or("");
        Self(format!("{}{}", to.as_str(), suffix))
    }
}

impl std::fmt::Display for CatalogPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogEvent {
    pub event_id: String,
    pub device_id: String,
    pub seq: u64,
    pub created_at: u64,
    pub op: CatalogOp,
    /// Ed25519 public key of the device that produced this event. None for
    /// legacy pre-Phase-3 events; rejected on peer merge but accepted on
    /// local replay.
    #[serde(default)]
    pub signer: Option<NodeId>,
    /// Ed25519 signature over the canonical postcard encoding of this event
    /// with `signature` set to `None`. Verified against `signer`.
    #[serde(default)]
    pub signature: Option<Signature>,
}

/// Did this event arrive locally (from our own events.jsonl) or from a peer?
/// Legacy unsigned events are tolerated on `Local` replay but rejected on
/// `Remote` merge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventOrigin {
    Local,
    Remote,
}

impl CatalogEvent {
    /// Sign this event with the given identity. Sets `signer` to the
    /// identity's pubkey and `signature` to the Ed25519 signature over the
    /// canonical-bytes-with-signature-zeroed payload.
    pub fn sign(&mut self, identity: &Identity) -> Result<()> {
        let signer = identity.node_id();
        self.signer = Some(signer);
        self.signature = None;
        let payload = self.signing_payload(signer)?;
        let signature: Ed25519Signature = identity.signing.sign(&payload);
        self.signature = Some(Signature(signature.to_bytes()));
        Ok(())
    }

    /// Verify the event's signature, if any. Returns `Ok(Some(signer))` for a
    /// signed-and-valid event, `Ok(None)` for an unsigned legacy event, and
    /// an error for tampered or malformed events.
    pub fn verify(&self) -> Result<Option<NodeId>> {
        match (self.signer, self.signature) {
            (None, None) => Ok(None),
            (Some(signer), Some(signature)) => {
                let payload = self.signing_payload(signer)?;
                let verifying_key = VerifyingKey::from_bytes(signer.as_bytes())
                    .map_err(|e| Error::Catalog(format!("invalid signer pubkey: {e}")))?;
                let signature = Ed25519Signature::from_bytes(&signature.0);
                verifying_key
                    .verify(&payload, &signature)
                    .map_err(|_| Error::Catalog("invalid catalog event signature".into()))?;
                Ok(Some(signer))
            }
            _ => Err(Error::Catalog(
                "malformed catalog event signature fields".into(),
            )),
        }
    }

    fn signing_payload(&self, signer: NodeId) -> Result<Vec<u8>> {
        let mut canonical = self.clone();
        canonical.signer = Some(signer);
        canonical.signature = None;
        postcard::to_allocvec(&canonical).map_err(|e| Error::Catalog(format!("encode: {e}")))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CatalogOp {
    Mkdir {
        path: String,
    },
    PutFile {
        path: String,
        cap: String,
        name: Option<String>,
    },
    Remove {
        path: String,
    },
    Move {
        from: String,
        to: String,
    },
    /// A member was added to the nest. `granter` must already be a member
    /// (founding case: `granter == member`, self-grant). `invite_signature`
    /// is the granter's Ed25519 signature over
    /// [`member_grant_canonical_bytes`]; a verifier rebuilds those bytes
    /// from the event and checks the signature against `granter`.
    MemberAdded {
        member: NodeId,
        granter: NodeId,
        role: NestRole,
        added_at: u64,
        invite_signature: Signature,
    },
    /// A member was revoked. Wire shape only — Phase 3 records the event
    /// but [`CatalogView::members`] still returns revoked members as
    /// current; CRDT merge semantics for revocation are Phase 5.
    MemberRevoked {
        member: NodeId,
        revoked_at: u64,
    },
}

#[derive(Clone, Debug)]
pub struct CatalogEntry {
    pub path: CatalogPath,
    pub kind: EntryKind,
}

#[derive(Clone, Debug)]
pub enum EntryKind {
    Dir,
    File { cap: Cap, name: Option<String> },
}

impl CatalogEntry {
    pub fn cap(&self) -> Option<&Cap> {
        match &self.kind {
            EntryKind::Dir => None,
            EntryKind::File { cap, .. } => Some(cap),
        }
    }

    pub fn is_dir(&self) -> bool {
        matches!(self.kind, EntryKind::Dir)
    }
}

#[derive(Clone, Debug)]
pub struct CatalogView {
    entries: BTreeMap<CatalogPath, CatalogEntry>,
    members: Vec<MemberRecord>,
}

impl CatalogView {
    pub fn get(&self, path: &CatalogPath) -> Option<&CatalogEntry> {
        self.entries.get(path)
    }

    pub fn contains(&self, path: &CatalogPath) -> bool {
        self.entries.contains_key(path)
    }

    pub fn has_children(&self, path: &CatalogPath) -> bool {
        self.entries.keys().any(|p| p.is_descendant_of(path))
    }

    pub fn list(&self, path: &CatalogPath) -> Vec<&CatalogEntry> {
        self.entries
            .values()
            .filter(|entry| entry.path.parent().as_ref() == Some(path))
            .collect()
    }

    pub fn files(&self) -> Vec<&CatalogEntry> {
        self.entries
            .values()
            .filter(|entry| matches!(entry.kind, EntryKind::File { .. }))
            .collect()
    }

    pub fn file_caps(&self) -> Vec<Cap> {
        self.files()
            .into_iter()
            .filter_map(|entry| entry.cap().cloned())
            .collect()
    }

    pub fn subtree_files(&self, path: &CatalogPath) -> Vec<&CatalogEntry> {
        self.entries
            .values()
            .filter(|entry| {
                matches!(entry.kind, EntryKind::File { .. })
                    && (&entry.path == path || entry.path.is_descendant_of(path))
            })
            .collect()
    }

    /// Current member set derived from the event log, in the order they
    /// were added. Phase 3 returns revoked members too (with `revoked_at`
    /// populated); follow-up work in Phase 5 will treat revocation as a
    /// CRDT-merge-aware removal.
    pub fn members(&self) -> &[MemberRecord] {
        &self.members
    }

    fn materialize(mut events: Vec<CatalogEvent>) -> Result<Self> {
        events.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.device_id.cmp(&b.device_id))
                .then_with(|| a.seq.cmp(&b.seq))
                .then_with(|| a.event_id.cmp(&b.event_id))
        });

        let mut entries = BTreeMap::new();
        entries.insert(
            CatalogPath::root(),
            CatalogEntry {
                path: CatalogPath::root(),
                kind: EntryKind::Dir,
            },
        );

        // Member ops are walked in the same time-ordered pass. We keep an
        // index from NodeId to slot so MemberRevoked can stamp the matching
        // record's `revoked_at` without scanning.
        let mut members: Vec<MemberRecord> = Vec::new();
        let mut member_idx: BTreeMap<NodeId, usize> = BTreeMap::new();

        for event in events {
            match event.op {
                CatalogOp::Mkdir { path } => {
                    let path = CatalogPath::normalize(&path)?;
                    entries.insert(
                        path.clone(),
                        CatalogEntry {
                            path,
                            kind: EntryKind::Dir,
                        },
                    );
                }
                CatalogOp::PutFile { path, cap, name } => {
                    let path = CatalogPath::normalize(&path)?;
                    entries.insert(
                        path.clone(),
                        CatalogEntry {
                            path,
                            kind: EntryKind::File {
                                cap: Cap::decode(&cap)?,
                                name,
                            },
                        },
                    );
                }
                CatalogOp::Remove { path } => {
                    let path = CatalogPath::normalize(&path)?;
                    let remove: Vec<_> = entries
                        .keys()
                        .filter(|p| **p == path || p.is_descendant_of(&path))
                        .cloned()
                        .collect();
                    for p in remove {
                        if p != CatalogPath::root() {
                            entries.remove(&p);
                        }
                    }
                }
                CatalogOp::Move { from, to } => {
                    let from = CatalogPath::normalize(&from)?;
                    let to = CatalogPath::normalize(&to)?;
                    let moving: Vec<_> = entries
                        .iter()
                        .filter(|(p, _)| **p == from || p.is_descendant_of(&from))
                        .map(|(p, e)| (p.clone(), e.clone()))
                        .collect();
                    for (old, _) in &moving {
                        entries.remove(old);
                    }
                    for (old, mut entry) in moving {
                        let new_path = old.moved_under(&from, &to);
                        entry.path = new_path.clone();
                        entries.insert(new_path, entry);
                    }
                }
                CatalogOp::MemberAdded {
                    member,
                    granter,
                    role,
                    added_at,
                    ..
                } => {
                    // Duplicate MemberAdded for the same member is a no-op;
                    // the first add wins so re-merging doesn't reshuffle
                    // the granter/role recorded the first time.
                    if let std::collections::btree_map::Entry::Vacant(e) = member_idx.entry(member)
                    {
                        e.insert(members.len());
                        members.push(MemberRecord {
                            member,
                            granter,
                            role,
                            added_at,
                            revoked_at: None,
                        });
                    }
                }
                CatalogOp::MemberRevoked { member, revoked_at } => {
                    if let Some(&slot) = member_idx.get(&member) {
                        // Earliest revocation wins so a later add+revoke
                        // pair can't undo an earlier one.
                        if members[slot].revoked_at.is_none() {
                            members[slot].revoked_at = Some(revoked_at);
                        }
                    }
                }
            }
        }

        Ok(Self { entries, members })
    }
}

pub struct CatalogIndex {
    root: PathBuf,
    events_path: PathBuf,
    device_id: String,
}

impl CatalogIndex {
    pub fn open(home: impl AsRef<Path>) -> Result<Self> {
        let root = home.as_ref().join(CATALOG_DIR);
        fs::create_dir_all(&root)?;
        let device_id_path = root.join(DEVICE_ID_FILE);
        let device_id = match fs::read_to_string(&device_id_path) {
            Ok(s) => parse_device_id(&s)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let id = random_hex_128();
                fs::write(&device_id_path, format!("{id}\n"))?;
                id
            }
            Err(e) => return Err(Error::Io(e)),
        };
        Ok(Self {
            events_path: root.join(EVENTS_FILE),
            root,
            device_id,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub fn view(&self) -> Result<CatalogView> {
        CatalogView::materialize(self.load_events()?)
    }

    pub fn load_events(&self) -> Result<Vec<CatalogEvent>> {
        let s = match fs::read_to_string(&self.events_path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(Error::Io(e)),
        };
        let mut out = Vec::new();
        for (idx, line) in s.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let event = serde_json::from_str(line)
                .map_err(|e| Error::Catalog(format!("event line {}: {e}", idx + 1)))?;
            out.push(event);
        }
        Ok(out)
    }

    /// Merge events from a remote peer. Signatures are required and verified;
    /// unsigned events are rejected. Use `merge_events` for the wider API
    /// that lets the caller declare origin explicitly.
    pub fn merge_events_from_peer(
        &self,
        events: impl IntoIterator<Item = CatalogEvent>,
    ) -> Result<usize> {
        self.merge_events_with_origin(events, EventOrigin::Remote)
    }

    /// Local replay of events (e.g. import from another local file). Legacy
    /// unsigned events are tolerated; tampered signatures still reject.
    pub fn merge_events(&self, events: impl IntoIterator<Item = CatalogEvent>) -> Result<usize> {
        self.merge_events_with_origin(events, EventOrigin::Local)
    }

    fn merge_events_with_origin(
        &self,
        events: impl IntoIterator<Item = CatalogEvent>,
        origin: EventOrigin,
    ) -> Result<usize> {
        let mut known: HashSet<String> = self
            .load_events()?
            .into_iter()
            .map(|event| event.event_id)
            .collect();
        let mut added = 0usize;
        for event in events {
            validate_event(&event)?;
            match event.verify()? {
                Some(_) => { /* signed + valid */ }
                None => {
                    if origin == EventOrigin::Remote {
                        return Err(Error::Catalog(format!(
                            "unsigned catalog event {} rejected from peer",
                            event.event_id
                        )));
                    }
                }
            }
            if known.insert(event.event_id.clone()) {
                self.append_event(&event)?;
                added += 1;
            }
        }
        Ok(added)
    }

    pub fn mkdir(
        &self,
        path: &str,
        parents: bool,
        identity: &Identity,
    ) -> Result<Vec<CatalogEvent>> {
        let target = CatalogPath::normalize(path)?;
        if target == CatalogPath::root() {
            return Ok(Vec::new());
        }
        let view = self.view()?;
        let mut events = Vec::new();
        for dir in missing_dirs(&view, &target, parents)? {
            events.push(self.append(
                CatalogOp::Mkdir {
                    path: dir.to_string(),
                },
                identity,
            )?);
        }
        Ok(events)
    }

    pub fn put_file(
        &self,
        path: &str,
        cap: Cap,
        name: Option<String>,
        identity: &Identity,
    ) -> Result<CatalogEvent> {
        let path = CatalogPath::normalize(path)?;
        if path == CatalogPath::root() {
            return Err(Error::Catalog("cannot put a file at /".into()));
        }
        let view = self.view()?;
        ensure_parent_exists(&view, &path)?;
        if view.get(&path).is_some_and(CatalogEntry::is_dir) {
            return Err(Error::Catalog(format!("{path} is a directory")));
        }
        self.append(
            CatalogOp::PutFile {
                path: path.to_string(),
                cap: cap.encode(),
                name,
            },
            identity,
        )
    }

    pub fn remove(&self, path: &str, identity: &Identity) -> Result<CatalogEvent> {
        let path = CatalogPath::normalize(path)?;
        if path == CatalogPath::root() {
            return Err(Error::Catalog("cannot remove /".into()));
        }
        let view = self.view()?;
        if !view.contains(&path) {
            return Err(Error::Catalog(format!("{path} does not exist")));
        }
        self.append(
            CatalogOp::Remove {
                path: path.to_string(),
            },
            identity,
        )
    }

    /// Append a `MemberAdded` event signed by `granter` (`identity`). The
    /// embedded `invite_signature` is produced over
    /// [`member_grant_canonical_bytes`] so a third device can verify the
    /// grant independent of `Invite` semantics.
    pub fn append_member_added(
        &self,
        nest_id: &NestId,
        identity: &Identity,
        member: NodeId,
        role: NestRole,
    ) -> Result<CatalogEvent> {
        let added_at = unix_now();
        let granter = identity.node_id();
        let payload = member_grant_canonical_bytes(nest_id, &granter, &member, role, added_at);
        let signature: Ed25519Signature = identity.signing.sign(&payload);
        self.append(
            CatalogOp::MemberAdded {
                member,
                granter,
                role,
                added_at,
                invite_signature: Signature(signature.to_bytes()),
            },
            identity,
        )
    }

    /// Append a `MemberAdded` event whose `invite_signature` was produced
    /// elsewhere (e.g. by decoding an Invite). The local device is the
    /// event's outer signer (the new member); `granter` is whoever
    /// authorised the grant. Phase 3 callers verify the invite signature
    /// before calling this; the catalog re-verifies after merge.
    pub fn append_member_added_with_signature(
        &self,
        identity: &Identity,
        member: NodeId,
        granter: NodeId,
        role: NestRole,
        added_at: u64,
        invite_signature: Signature,
    ) -> Result<CatalogEvent> {
        self.append(
            CatalogOp::MemberAdded {
                member,
                granter,
                role,
                added_at,
                invite_signature,
            },
            identity,
        )
    }

    /// Append a `MemberRevoked` event. Phase 3 ships this for wire-format
    /// stability; revocation is observable via `MemberRecord::revoked_at`
    /// but does not yet remove the member from
    /// [`CatalogView::members`] (CRDT merge semantics for revocation are
    /// Phase 5).
    pub fn append_member_revoked(
        &self,
        identity: &Identity,
        member: NodeId,
    ) -> Result<CatalogEvent> {
        self.append(
            CatalogOp::MemberRevoked {
                member,
                revoked_at: unix_now(),
            },
            identity,
        )
    }

    /// Idempotently ensure a founding-member event exists for *this nest*
    /// (not necessarily for this identity).
    ///
    /// - If the catalog already has at least one `MemberAdded` event, no-op.
    /// - Otherwise, append a self-granting event for the local identity.
    ///
    /// The second condition is the migration bridge for Phase-2 nests:
    /// the first device to open such a nest with Phase-3 code becomes
    /// the founding member. A *different* device opening a Phase-3 nest
    /// that already has a founding event does NOT silently self-grant —
    /// non-founders must join via an invite.
    pub fn ensure_founding_member(
        &self,
        nest_id: &NestId,
        identity: &Identity,
    ) -> Result<Option<CatalogEvent>> {
        let has_any_founding = self
            .load_events()?
            .iter()
            .any(|event| matches!(event.op, CatalogOp::MemberAdded { .. }));
        if has_any_founding {
            return Ok(None);
        }
        let me = identity.node_id();
        Ok(Some(self.append_member_added(
            nest_id,
            identity,
            me,
            NestRole::Owner,
        )?))
    }

    pub fn move_path(&self, from: &str, to: &str, identity: &Identity) -> Result<CatalogEvent> {
        let from = CatalogPath::normalize(from)?;
        let to = CatalogPath::normalize(to)?;
        if from == CatalogPath::root() || to == CatalogPath::root() {
            return Err(Error::Catalog("cannot move /".into()));
        }
        if to == from || to.is_descendant_of(&from) {
            return Err(Error::Catalog("cannot move a path into itself".into()));
        }
        let view = self.view()?;
        if !view.contains(&from) {
            return Err(Error::Catalog(format!("{from} does not exist")));
        }
        ensure_parent_exists(&view, &to)?;
        self.append(
            CatalogOp::Move {
                from: from.to_string(),
                to: to.to_string(),
            },
            identity,
        )
    }

    fn append(&self, op: CatalogOp, identity: &Identity) -> Result<CatalogEvent> {
        let seq = self.next_seq()?;
        let mut event = CatalogEvent {
            event_id: format!("{}:{seq}", self.device_id),
            device_id: self.device_id.clone(),
            seq,
            created_at: unix_now(),
            op,
            signer: None,
            signature: None,
        };
        event.sign(identity)?;
        self.append_event(&event)?;
        Ok(event)
    }

    fn append_event(&self, event: &CatalogEvent) -> Result<()> {
        if let Some(parent) = self.events_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.events_path)?;
        serde_json::to_writer(&mut f, event)
            .map_err(|e| Error::Catalog(format!("event serialize: {e}")))?;
        f.write_all(b"\n")?;
        Ok(())
    }

    fn next_seq(&self) -> Result<u64> {
        Ok(self
            .load_events()?
            .into_iter()
            .filter(|e| e.device_id == self.device_id)
            .map(|e| e.seq)
            .max()
            .unwrap_or(0)
            + 1)
    }
}

fn ensure_parent_exists(view: &CatalogView, path: &CatalogPath) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| Error::Catalog("path has no parent".into()))?;
    match view.get(&parent) {
        Some(entry) if entry.is_dir() => Ok(()),
        Some(_) => Err(Error::Catalog(format!(
            "parent {parent} is not a directory"
        ))),
        None => Err(Error::Catalog(format!("parent {parent} does not exist"))),
    }
}

fn validate_event(event: &CatalogEvent) -> Result<()> {
    if event.event_id.trim().is_empty() {
        return Err(Error::Catalog("catalog event id must not be empty".into()));
    }
    parse_device_id(&event.device_id)?;
    if event.seq == 0 {
        return Err(Error::Catalog("catalog event seq must be non-zero".into()));
    }
    match &event.op {
        CatalogOp::Mkdir { path } | CatalogOp::Remove { path } => {
            CatalogPath::normalize(path)?;
        }
        CatalogOp::PutFile { path, cap, .. } => {
            CatalogPath::normalize(path)?;
            Cap::decode(cap)?;
        }
        CatalogOp::Move { from, to } => {
            CatalogPath::normalize(from)?;
            CatalogPath::normalize(to)?;
        }
        CatalogOp::MemberAdded { .. } | CatalogOp::MemberRevoked { .. } => {
            // Member ops carry no paths to normalise. Cryptographic
            // verification of `invite_signature` is left to callers that
            // know the nest_id (it isn't in the event), via
            // [`verify_member_added_signature`].
        }
    }
    Ok(())
}

/// Verify that a `MemberAdded` event's `invite_signature` is a valid
/// Ed25519 signature by `granter` over the canonical member-grant payload
/// for the given `nest_id`.
///
/// Returns `Ok(true)` for a valid signature, `Ok(false)` if the event is
/// not a `MemberAdded` op, and an error on signature failure or malformed
/// signer key bytes.
pub fn verify_member_added_signature(event: &CatalogEvent, nest_id: &NestId) -> Result<bool> {
    let CatalogOp::MemberAdded {
        member,
        granter,
        role,
        added_at,
        invite_signature,
    } = &event.op
    else {
        return Ok(false);
    };
    let payload = member_grant_canonical_bytes(nest_id, granter, member, *role, *added_at);
    let granter_key = VerifyingKey::from_bytes(granter.as_bytes())
        .map_err(|e| Error::Catalog(format!("invalid granter pubkey: {e}")))?;
    let sig = Ed25519Signature::from_bytes(&invite_signature.0);
    granter_key
        .verify(&payload, &sig)
        .map_err(|_| Error::Catalog("invalid MemberAdded invite signature".into()))?;
    Ok(true)
}

fn missing_dirs(
    view: &CatalogView,
    target: &CatalogPath,
    parents: bool,
) -> Result<Vec<CatalogPath>> {
    let mut dirs = Vec::new();
    let mut current = CatalogPath::root();
    let components: Vec<_> = target
        .as_str()
        .trim_start_matches('/')
        .split('/')
        .filter(|c| !c.is_empty())
        .collect();
    for component in components {
        current = CatalogPath::normalize(&format!("{current}/{component}"))?;
        match view.get(&current) {
            Some(entry) if entry.is_dir() => {}
            Some(_) => return Err(Error::Catalog(format!("{current} is a file"))),
            None => dirs.push(current.clone()),
        }
    }
    if dirs.len() > 1 && !parents {
        return Err(Error::Catalog(format!(
            "parent {} does not exist; pass --parents",
            dirs.first()
                .and_then(CatalogPath::parent)
                .unwrap_or_else(CatalogPath::root)
        )));
    }
    Ok(dirs)
}

fn parse_device_id(s: &str) -> Result<String> {
    let s = s.trim();
    if s.len() != 32 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::Catalog("invalid catalog device id".into()));
    }
    Ok(s.to_ascii_lowercase())
}

fn random_hex_128() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    hex(&bytes)
}

fn unix_now() -> u64 {
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

    fn fresh_identity(tmp: &TempDir) -> Identity {
        Identity::load_or_create(tmp.path()).unwrap()
    }

    /// Build an unsigned (legacy) event — used for backward-compat replay
    /// tests of `merge_events` (the local-origin API).
    fn legacy_event(device_id: &str, seq: u64, created_at: u64, op: CatalogOp) -> CatalogEvent {
        CatalogEvent {
            event_id: format!("{device_id}:{seq}"),
            device_id: device_id.into(),
            seq,
            created_at,
            op,
            signer: None,
            signature: None,
        }
    }

    /// Build a signed event from a peer identity, mimicking what a real
    /// remote append would produce.
    fn signed_event(
        identity: &Identity,
        device_id: &str,
        seq: u64,
        created_at: u64,
        op: CatalogOp,
    ) -> CatalogEvent {
        let mut event = CatalogEvent {
            event_id: format!("{device_id}:{seq}"),
            device_id: device_id.into(),
            seq,
            created_at,
            op,
            signer: None,
            signature: None,
        };
        event.sign(identity).unwrap();
        event
    }

    #[test]
    fn normalize_paths() {
        assert_eq!(CatalogPath::normalize("/").unwrap().as_str(), "/");
        assert_eq!(
            CatalogPath::normalize("docs//report.pdf").unwrap().as_str(),
            "/docs/report.pdf"
        );
        assert!(CatalogPath::normalize("../x").is_err());
        assert!(CatalogPath::normalize("").is_err());
    }

    #[test]
    fn mkdir_put_remove_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let identity = fresh_identity(&tmp);
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        catalog.mkdir("/docs", false, &identity).unwrap();
        catalog
            .put_file(
                "/docs/report.pdf",
                cap_with_hash_byte(1),
                Some("report.pdf".into()),
                &identity,
            )
            .unwrap();

        let view = catalog.view().unwrap();
        assert!(
            view.get(&CatalogPath::normalize("/docs").unwrap())
                .unwrap()
                .is_dir()
        );
        assert!(
            view.get(&CatalogPath::normalize("/docs/report.pdf").unwrap())
                .unwrap()
                .cap()
                .is_some()
        );

        catalog.remove("/docs", &identity).unwrap();
        let view = catalog.view().unwrap();
        assert!(
            view.get(&CatalogPath::normalize("/docs").unwrap())
                .is_none()
        );
        assert!(
            view.get(&CatalogPath::normalize("/docs/report.pdf").unwrap())
                .is_none()
        );
    }

    #[test]
    fn mkdir_requires_parents_unless_requested() {
        let tmp = TempDir::new().unwrap();
        let identity = fresh_identity(&tmp);
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        assert!(catalog.mkdir("/a/b", false, &identity).is_err());
        catalog.mkdir("/a/b", true, &identity).unwrap();
        let view = catalog.view().unwrap();
        assert!(
            view.get(&CatalogPath::normalize("/a").unwrap())
                .unwrap()
                .is_dir()
        );
        assert!(
            view.get(&CatalogPath::normalize("/a/b").unwrap())
                .unwrap()
                .is_dir()
        );
    }

    #[test]
    fn move_path_moves_subtree() {
        let tmp = TempDir::new().unwrap();
        let identity = fresh_identity(&tmp);
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        catalog.mkdir("/docs", false, &identity).unwrap();
        catalog
            .put_file("/docs/report.pdf", cap_with_hash_byte(2), None, &identity)
            .unwrap();
        catalog.move_path("/docs", "/archive", &identity).unwrap();
        let view = catalog.view().unwrap();
        assert!(
            view.get(&CatalogPath::normalize("/docs").unwrap())
                .is_none()
        );
        assert!(
            view.get(&CatalogPath::normalize("/archive/report.pdf").unwrap())
                .is_some()
        );
    }

    #[test]
    fn replay_is_deterministic() {
        let cap = cap_with_hash_byte(3).encode();
        let a = CatalogEvent {
            event_id: "b:1".into(),
            device_id: "b".into(),
            seq: 1,
            created_at: 1,
            op: CatalogOp::Mkdir { path: "/x".into() },
            signer: None,
            signature: None,
        };
        let b = CatalogEvent {
            event_id: "a:1".into(),
            device_id: "a".into(),
            seq: 1,
            created_at: 2,
            op: CatalogOp::PutFile {
                path: "/x/f".into(),
                cap,
                name: None,
            },
            signer: None,
            signature: None,
        };
        let view = CatalogView::materialize(vec![b, a]).unwrap();
        assert!(view.get(&CatalogPath::normalize("/x/f").unwrap()).is_some());
    }

    #[test]
    fn file_caps_returns_live_file_caps() {
        let tmp = TempDir::new().unwrap();
        let identity = fresh_identity(&tmp);
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        let cap = cap_with_hash_byte(4);
        catalog.mkdir("/docs", false, &identity).unwrap();
        catalog
            .put_file("/docs/a", cap.clone(), None, &identity)
            .unwrap();
        let caps = catalog.view().unwrap().file_caps();
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0].manifest_hash, cap.manifest_hash);
    }

    #[test]
    fn merge_events_imports_remote_events_once() {
        let tmp = TempDir::new().unwrap();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        let device = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let cap = cap_with_hash_byte(5);
        let events = vec![
            legacy_event(
                device,
                1,
                1,
                CatalogOp::Mkdir {
                    path: "/docs".into(),
                },
            ),
            legacy_event(
                device,
                2,
                2,
                CatalogOp::PutFile {
                    path: "/docs/report.pdf".into(),
                    cap: cap.encode(),
                    name: Some("report.pdf".into()),
                },
            ),
        ];

        assert_eq!(catalog.merge_events(events.clone()).unwrap(), 2);
        assert_eq!(catalog.merge_events(events).unwrap(), 0);

        let view = catalog.view().unwrap();
        assert!(
            view.get(&CatalogPath::normalize("/docs").unwrap())
                .is_some()
        );
        assert_eq!(
            view.get(&CatalogPath::normalize("/docs/report.pdf").unwrap())
                .unwrap()
                .cap()
                .map(|cap| cap.manifest_hash),
            Some(cap.manifest_hash)
        );
        assert_eq!(catalog.load_events().unwrap().len(), 2);
    }

    #[test]
    fn merge_events_rejects_invalid_remote_event() {
        let tmp = TempDir::new().unwrap();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        let device = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let event = legacy_event(
            device,
            1,
            1,
            CatalogOp::PutFile {
                path: "/bad".into(),
                cap: "not-a-cap".into(),
                name: None,
            },
        );

        let err = catalog.merge_events(vec![event]).unwrap_err();

        assert!(err.to_string().contains("invalid"));
        assert!(catalog.load_events().unwrap().is_empty());
    }

    #[test]
    fn merge_events_replays_conflicts_deterministically() {
        let tmp = TempDir::new().unwrap();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        let a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let cap_a = cap_with_hash_byte(6);
        let cap_b = cap_with_hash_byte(7);

        catalog
            .merge_events(vec![
                legacy_event(
                    a,
                    1,
                    1,
                    CatalogOp::PutFile {
                        path: "/same.txt".into(),
                        cap: cap_a.encode(),
                        name: Some("a".into()),
                    },
                ),
                legacy_event(
                    b,
                    1,
                    1,
                    CatalogOp::PutFile {
                        path: "/same.txt".into(),
                        cap: cap_b.encode(),
                        name: Some("b".into()),
                    },
                ),
            ])
            .unwrap();

        let view = catalog.view().unwrap();
        assert_eq!(
            view.get(&CatalogPath::normalize("/same.txt").unwrap())
                .unwrap()
                .cap()
                .map(|cap| cap.manifest_hash),
            Some(cap_b.manifest_hash)
        );
    }

    #[test]
    fn rejects_file_where_parent_missing_or_file_parent() {
        let tmp = TempDir::new().unwrap();
        let identity = fresh_identity(&tmp);
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        assert!(
            catalog
                .put_file("/missing/a", cap_with_hash_byte(1), None, &identity)
                .is_err()
        );
        catalog
            .put_file("/file", cap_with_hash_byte(2), None, &identity)
            .unwrap();
        assert!(
            catalog
                .put_file("/file/child", cap_with_hash_byte(3), None, &identity)
                .is_err()
        );
    }

    #[test]
    fn sign_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let identity = fresh_identity(&tmp);
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        catalog.mkdir("/docs", false, &identity).unwrap();
        catalog
            .put_file("/docs/a.txt", cap_with_hash_byte(8), None, &identity)
            .unwrap();

        let events = catalog.load_events().unwrap();
        assert_eq!(events.len(), 2);
        for event in &events {
            let signer = event.verify().unwrap().expect("event is signed");
            assert_eq!(signer, identity.node_id());
        }
    }

    #[test]
    fn merge_rejects_tampered_event() {
        let tmp_a = TempDir::new().unwrap();
        let identity_a = fresh_identity(&tmp_a);
        let device = "cccccccccccccccccccccccccccccccc";
        let mut event = signed_event(
            &identity_a,
            device,
            1,
            1,
            CatalogOp::Mkdir {
                path: "/orig".into(),
            },
        );
        // Tamper with the op without re-signing.
        event.op = CatalogOp::Mkdir {
            path: "/evil".into(),
        };

        let tmp_b = TempDir::new().unwrap();
        let catalog = CatalogIndex::open(tmp_b.path()).unwrap();
        let err = catalog.merge_events_from_peer(vec![event]).unwrap_err();
        assert!(err.to_string().contains("invalid catalog event signature"));
    }

    #[test]
    fn merge_rejects_unsigned_from_peer() {
        let tmp = TempDir::new().unwrap();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        let device = "dddddddddddddddddddddddddddddddd";
        let event = legacy_event(
            device,
            1,
            1,
            CatalogOp::Mkdir {
                path: "/legacy".into(),
            },
        );
        let err = catalog.merge_events_from_peer(vec![event]).unwrap_err();
        assert!(
            err.to_string().contains("unsigned"),
            "expected unsigned-rejection, got: {err}"
        );
        assert!(catalog.load_events().unwrap().is_empty());
    }

    #[test]
    fn merge_accepts_legacy_unsigned_local() {
        let tmp = TempDir::new().unwrap();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        let device = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
        let event = legacy_event(
            device,
            1,
            1,
            CatalogOp::Mkdir {
                path: "/legacy".into(),
            },
        );
        assert_eq!(catalog.merge_events(vec![event]).unwrap(), 1);
        let view = catalog.view().unwrap();
        assert!(
            view.get(&CatalogPath::normalize("/legacy").unwrap())
                .is_some()
        );
    }

    #[test]
    fn merge_accepts_signed_from_peer() {
        // Sanity: a properly-signed remote event from a peer identity is
        // accepted by `merge_events_from_peer`.
        let tmp_a = TempDir::new().unwrap();
        let identity_a = fresh_identity(&tmp_a);
        let device = "ffffffffffffffffffffffffffffffff";
        let event = signed_event(
            &identity_a,
            device,
            1,
            1,
            CatalogOp::Mkdir {
                path: "/peer".into(),
            },
        );

        let tmp_b = TempDir::new().unwrap();
        let catalog = CatalogIndex::open(tmp_b.path()).unwrap();
        assert_eq!(catalog.merge_events_from_peer(vec![event]).unwrap(), 1);
    }

    #[test]
    fn ensure_founding_member_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        let identity = fresh_identity(&tmp);
        let nest_id = NestId::random();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();

        let first = catalog.ensure_founding_member(&nest_id, &identity).unwrap();
        assert!(first.is_some(), "first call must append the founding event");
        let second = catalog.ensure_founding_member(&nest_id, &identity).unwrap();
        assert!(second.is_none(), "second call must be a no-op");
        assert_eq!(
            catalog
                .load_events()
                .unwrap()
                .iter()
                .filter(|e| matches!(e.op, CatalogOp::MemberAdded { .. }))
                .count(),
            1
        );
    }

    #[test]
    fn ensure_founding_member_signature_verifies() {
        let tmp = TempDir::new().unwrap();
        let identity = fresh_identity(&tmp);
        let nest_id = NestId::random();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        let event = catalog
            .ensure_founding_member(&nest_id, &identity)
            .unwrap()
            .unwrap();
        // Outer event signature verifies.
        let signer = event.verify().unwrap().expect("event is signed");
        assert_eq!(signer, identity.node_id());
        // Inner invite_signature verifies against the canonical bytes.
        assert!(verify_member_added_signature(&event, &nest_id).unwrap());
        // ...and fails under a different nest_id.
        let other_nest = NestId::random();
        assert!(verify_member_added_signature(&event, &other_nest).is_err());
    }

    #[test]
    fn view_members_replay() {
        let tmp = TempDir::new().unwrap();
        let identity = fresh_identity(&tmp);
        let nest_id = NestId::random();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();

        // Founder self-grants.
        catalog.ensure_founding_member(&nest_id, &identity).unwrap();
        // Founder grants a second member.
        let other_a = NodeId::from_bytes([0xAAu8; 32]);
        catalog
            .append_member_added(&nest_id, &identity, other_a, NestRole::Owner)
            .unwrap();
        // Founder revokes the second member.
        catalog.append_member_revoked(&identity, other_a).unwrap();

        let view = catalog.view().unwrap();
        let members = view.members();
        assert_eq!(members.len(), 2);
        assert_eq!(members[0].member, identity.node_id());
        assert_eq!(members[0].granter, identity.node_id(), "self-grant");
        assert!(members[0].revoked_at.is_none());
        assert_eq!(members[1].member, other_a);
        assert!(members[1].revoked_at.is_some());
    }

    #[test]
    fn revoked_at_does_not_remove_yet() {
        // Phase 3 ships `MemberRevoked` for wire-format stability but
        // `members()` still returns revoked members as current (with
        // revoked_at populated). Phase 5 will treat this as a CRDT remove.
        let tmp = TempDir::new().unwrap();
        let identity = fresh_identity(&tmp);
        let nest_id = NestId::random();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();

        catalog.ensure_founding_member(&nest_id, &identity).unwrap();
        let to_revoke = NodeId::from_bytes([0xBBu8; 32]);
        catalog
            .append_member_added(&nest_id, &identity, to_revoke, NestRole::Owner)
            .unwrap();
        catalog.append_member_revoked(&identity, to_revoke).unwrap();

        let members = catalog.view().unwrap().members().to_vec();
        let revoked = members.iter().find(|m| m.member == to_revoke).unwrap();
        assert!(revoked.revoked_at.is_some(), "revoked_at must be populated");
        // …but they are still in the returned list (Phase-3 invariant).
        assert!(
            members.iter().any(|m| m.member == to_revoke),
            "revoked member still appears in members() in Phase 3"
        );
    }
}
