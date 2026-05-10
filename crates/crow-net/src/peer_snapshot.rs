//! On-disk snapshot of the local daemon's view of the LAN.
//!
//! `crow serve` writes this file periodically; `crow peers` reads it. Decouples
//! the daemon from the CLI so peer listing works without IPC. Snapshot is a
//! point-in-time view; staleness is detectable via [`PeerSnapshot::snapshot_at`].

use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crow::NodeId;
use serde::{Deserialize, Serialize};

use crate::discovery::PeerInfo;
use crate::{NetError, Result};

pub const PEER_SNAPSHOT_FILE: &str = "peers.json";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerSnapshot {
    pub snapshot_at: u64,
    #[serde(rename = "self")]
    pub self_info: SelfInfo,
    pub peers: Vec<PeerInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SelfInfo {
    pub node_id: NodeId,
    pub friendly_name: Option<String>,
    pub address: SocketAddr,
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn snapshot_path(home: &Path) -> std::path::PathBuf {
    home.join(PEER_SNAPSHOT_FILE)
}

pub fn save(path: &Path, snapshot: &PeerSnapshot) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(snapshot)
        .map_err(|e| NetError::Protocol(format!("encode snapshot: {e}")))?;
    let tmp = path.with_extension(format!("json.{}.tmp", std::process::id()));
    fs::write(&tmp, &bytes)?;
    replace_file(&tmp, path)?;
    Ok(())
}

#[cfg(not(windows))]
fn replace_file(tmp: &Path, path: &Path) -> Result<()> {
    fs::rename(tmp, path).map_err(NetError::Io)
}

#[cfg(windows)]
fn replace_file(tmp: &Path, path: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    let tmp = tmp
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let path = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();

    let flags = MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH;
    // Windows std::fs::rename refuses to overwrite. MoveFileExW gives the same
    // replace-existing behavior Unix rename already has.
    let ok = unsafe { MoveFileExW(tmp.as_ptr(), path.as_ptr(), flags) };
    if ok == 0 {
        return Err(NetError::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

pub fn load(path: &Path) -> Result<Option<PeerSnapshot>> {
    match fs::read(path) {
        Ok(bytes) => {
            let snap = serde_json::from_slice(&bytes)
                .map_err(|e| NetError::Protocol(format!("decode snapshot: {e}")))?;
            Ok(Some(snap))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(NetError::Io(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crow::Identity;
    use tempfile::TempDir;

    #[test]
    fn save_load_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let path = snapshot_path(tmp.path());
        let id = Identity::random();
        let snap = PeerSnapshot {
            snapshot_at: 1715184123,
            self_info: SelfInfo {
                node_id: id.node_id(),
                friendly_name: Some("device-x".into()),
                address: "192.168.1.5:7070".parse().unwrap(),
            },
            peers: vec![],
        };
        save(&path, &snap).unwrap();
        let loaded = load(&path).unwrap().unwrap();
        assert_eq!(loaded.snapshot_at, 1715184123);
        assert_eq!(loaded.self_info.node_id, id.node_id());
        assert_eq!(loaded.self_info.friendly_name.as_deref(), Some("device-x"));
        assert!(loaded.peers.is_empty());
    }

    #[test]
    fn save_replaces_existing_snapshot() {
        let tmp = TempDir::new().unwrap();
        let path = snapshot_path(tmp.path());
        let first = Identity::random();
        let second = Identity::random();

        save(
            &path,
            &PeerSnapshot {
                snapshot_at: 1,
                self_info: SelfInfo {
                    node_id: first.node_id(),
                    friendly_name: Some("old-device".into()),
                    address: "192.168.1.5:7070".parse().unwrap(),
                },
                peers: vec![],
            },
        )
        .unwrap();

        save(
            &path,
            &PeerSnapshot {
                snapshot_at: 2,
                self_info: SelfInfo {
                    node_id: second.node_id(),
                    friendly_name: Some("new-device".into()),
                    address: "192.168.1.6:7070".parse().unwrap(),
                },
                peers: vec![],
            },
        )
        .unwrap();

        let loaded = load(&path).unwrap().unwrap();
        assert_eq!(loaded.snapshot_at, 2);
        assert_eq!(loaded.self_info.node_id, second.node_id());
        assert_eq!(
            loaded.self_info.friendly_name.as_deref(),
            Some("new-device")
        );
    }

    #[test]
    fn load_missing_returns_none() {
        let tmp = TempDir::new().unwrap();
        let path = snapshot_path(tmp.path());
        assert!(load(&path).unwrap().is_none());
    }
}
