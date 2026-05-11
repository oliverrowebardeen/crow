use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::cap::Cap;
use crate::error::{Error, Result};

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
            }
        }

        Ok(Self { entries })
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

    pub fn merge_events(&self, events: impl IntoIterator<Item = CatalogEvent>) -> Result<usize> {
        let mut known: HashSet<String> = self
            .load_events()?
            .into_iter()
            .map(|event| event.event_id)
            .collect();
        let mut added = 0usize;
        for event in events {
            validate_event(&event)?;
            if known.insert(event.event_id.clone()) {
                self.append_event(&event)?;
                added += 1;
            }
        }
        Ok(added)
    }

    pub fn mkdir(&self, path: &str, parents: bool) -> Result<Vec<CatalogEvent>> {
        let target = CatalogPath::normalize(path)?;
        if target == CatalogPath::root() {
            return Ok(Vec::new());
        }
        let view = self.view()?;
        let mut events = Vec::new();
        for dir in missing_dirs(&view, &target, parents)? {
            events.push(self.append(CatalogOp::Mkdir {
                path: dir.to_string(),
            })?);
        }
        Ok(events)
    }

    pub fn put_file(&self, path: &str, cap: Cap, name: Option<String>) -> Result<CatalogEvent> {
        let path = CatalogPath::normalize(path)?;
        if path == CatalogPath::root() {
            return Err(Error::Catalog("cannot put a file at /".into()));
        }
        let view = self.view()?;
        ensure_parent_exists(&view, &path)?;
        if view.get(&path).is_some_and(CatalogEntry::is_dir) {
            return Err(Error::Catalog(format!("{path} is a directory")));
        }
        self.append(CatalogOp::PutFile {
            path: path.to_string(),
            cap: cap.encode(),
            name,
        })
    }

    pub fn remove(&self, path: &str) -> Result<CatalogEvent> {
        let path = CatalogPath::normalize(path)?;
        if path == CatalogPath::root() {
            return Err(Error::Catalog("cannot remove /".into()));
        }
        let view = self.view()?;
        if !view.contains(&path) {
            return Err(Error::Catalog(format!("{path} does not exist")));
        }
        self.append(CatalogOp::Remove {
            path: path.to_string(),
        })
    }

    pub fn move_path(&self, from: &str, to: &str) -> Result<CatalogEvent> {
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
        self.append(CatalogOp::Move {
            from: from.to_string(),
            to: to.to_string(),
        })
    }

    fn append(&self, op: CatalogOp) -> Result<CatalogEvent> {
        let seq = self.next_seq()?;
        let event = CatalogEvent {
            event_id: format!("{}:{seq}", self.device_id),
            device_id: self.device_id.clone(),
            seq,
            created_at: unix_now(),
            op,
        };
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
    }
    Ok(())
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

    fn remote_event(device_id: &str, seq: u64, created_at: u64, op: CatalogOp) -> CatalogEvent {
        CatalogEvent {
            event_id: format!("{device_id}:{seq}"),
            device_id: device_id.into(),
            seq,
            created_at,
            op,
        }
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
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        catalog.mkdir("/docs", false).unwrap();
        catalog
            .put_file(
                "/docs/report.pdf",
                cap_with_hash_byte(1),
                Some("report.pdf".into()),
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

        catalog.remove("/docs").unwrap();
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
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        assert!(catalog.mkdir("/a/b", false).is_err());
        catalog.mkdir("/a/b", true).unwrap();
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
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        catalog.mkdir("/docs", false).unwrap();
        catalog
            .put_file("/docs/report.pdf", cap_with_hash_byte(2), None)
            .unwrap();
        catalog.move_path("/docs", "/archive").unwrap();
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
        };
        let view = CatalogView::materialize(vec![b, a]).unwrap();
        assert!(view.get(&CatalogPath::normalize("/x/f").unwrap()).is_some());
    }

    #[test]
    fn file_caps_returns_live_file_caps() {
        let tmp = TempDir::new().unwrap();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        let cap = cap_with_hash_byte(4);
        catalog.mkdir("/docs", false).unwrap();
        catalog.put_file("/docs/a", cap.clone(), None).unwrap();
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
            remote_event(
                device,
                1,
                1,
                CatalogOp::Mkdir {
                    path: "/docs".into(),
                },
            ),
            remote_event(
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
        let event = remote_event(
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
                remote_event(
                    a,
                    1,
                    1,
                    CatalogOp::PutFile {
                        path: "/same.txt".into(),
                        cap: cap_a.encode(),
                        name: Some("a".into()),
                    },
                ),
                remote_event(
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
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        assert!(
            catalog
                .put_file("/missing/a", cap_with_hash_byte(1), None)
                .is_err()
        );
        catalog
            .put_file("/file", cap_with_hash_byte(2), None)
            .unwrap();
        assert!(
            catalog
                .put_file("/file/child", cap_with_hash_byte(3), None)
                .is_err()
        );
    }
}
