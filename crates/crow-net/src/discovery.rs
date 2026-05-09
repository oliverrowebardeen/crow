//! mDNS LAN peer discovery for crow.
//!
//! Wraps `mdns-sd` to advertise the local daemon and browse for other Crows
//! on the same network. Peers are kept in an in-memory cache keyed by
//! [`NodeId`]; a background task updates the cache from `mdns-sd`'s event
//! stream. The cache is unauthenticated — anything that advertises
//! `_crow._udp.local.` shows up — so the existing shared `ClusterToken` is
//! still what gates real chunk fetches.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use crow::NodeId;
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use serde::{Deserialize, Serialize};

use crate::{NetError, Result};

/// mDNS service type. The trailing `.local.` is required by mdns-sd.
pub const SERVICE_TYPE: &str = "_crow._udp.local.";
/// TXT record carrying the protocol version. Bumped when wire-incompatible
/// changes land so old peers can be filtered out.
pub const ADVERT_VERSION: &str = "1";

/// Best-effort friendly-name default: the OS hostname, if available.
pub fn default_friendly_name() -> Option<String> {
    hostname::get().ok().and_then(|h| h.into_string().ok())
}

/// What this node should advertise on the LAN.
#[derive(Clone, Debug)]
pub struct LocalAdvert {
    pub node_id: NodeId,
    pub port: u16,
    pub friendly_name: Option<String>,
}

/// One discovered peer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerInfo {
    pub node_id: NodeId,
    pub friendly_name: Option<String>,
    pub addresses: Vec<SocketAddr>,
    /// Unix seconds when this peer was last refreshed.
    pub last_seen_unix: u64,
}

/// Handle to the running discovery service.
///
/// Browses for `_crow._udp.local.` services, optionally publishes our own,
/// and maintains an in-memory peer cache. Drop or call [`Discovery::shutdown`]
/// to stop.
pub struct Discovery {
    daemon: ServiceDaemon,
    peers: Arc<RwLock<HashMap<NodeId, PeerInfo>>>,
    local: Option<LocalAdvert>,
    advertised_fullname: Option<String>,
    background: Option<tokio::task::JoinHandle<()>>,
}

impl Discovery {
    /// Start discovery. Pass `Some(LocalAdvert)` to also advertise this node;
    /// pass `None` to browse only (useful for read-only clients).
    pub fn start(advert: Option<LocalAdvert>) -> Result<Self> {
        let daemon = ServiceDaemon::new()
            .map_err(|e| NetError::Protocol(format!("mdns daemon init: {e}")))?;
        let receiver = daemon
            .browse(SERVICE_TYPE)
            .map_err(|e| NetError::Protocol(format!("mdns browse: {e}")))?;

        let peers: Arc<RwLock<HashMap<NodeId, PeerInfo>>> = Arc::default();
        let self_id = advert.as_ref().map(|a| a.node_id);

        let advertised_fullname = if let Some(advert) = advert.as_ref() {
            let info = make_service_info(advert)?;
            let fullname = info.get_fullname().to_string();
            daemon
                .register(info)
                .map_err(|e| NetError::Protocol(format!("mdns register: {e}")))?;
            Some(fullname)
        } else {
            None
        };

        let peers_for_task = peers.clone();
        let background = tokio::spawn(async move {
            while let Ok(event) = receiver.recv_async().await {
                match event {
                    ServiceEvent::ServiceResolved(info) => {
                        if let Some(peer) = peer_from_service_info(&info) {
                            if Some(peer.node_id) == self_id {
                                continue;
                            }
                            peers_for_task.write().unwrap().insert(peer.node_id, peer);
                        }
                    }
                    ServiceEvent::ServiceRemoved(_, fullname) => {
                        // mdns-sd gives us "<instance>.<service_type>"; the
                        // instance is the first 16 hex chars of node_id.
                        let instance = fullname.split('.').next().unwrap_or("");
                        let to_remove: Vec<NodeId> = peers_for_task
                            .read()
                            .unwrap()
                            .keys()
                            .filter(|nid| nid.short() == instance)
                            .copied()
                            .collect();
                        let mut map = peers_for_task.write().unwrap();
                        for nid in to_remove {
                            map.remove(&nid);
                        }
                    }
                    _ => {}
                }
            }
        });

        Ok(Self {
            daemon,
            peers,
            local: advert,
            advertised_fullname,
            background: Some(background),
        })
    }

    /// Snapshot of currently-known peers, sorted newest-seen first.
    pub fn peers(&self) -> Vec<PeerInfo> {
        let mut v: Vec<PeerInfo> = self.peers.read().unwrap().values().cloned().collect();
        v.sort_by(|a, b| b.last_seen_unix.cmp(&a.last_seen_unix));
        v
    }

    pub fn local(&self) -> Option<&LocalAdvert> {
        self.local.as_ref()
    }

    /// Stop advertising and tear down the daemon.
    pub fn shutdown(mut self) -> Result<()> {
        if let Some(fullname) = self.advertised_fullname.take() {
            let _ = self.daemon.unregister(&fullname);
        }
        // ServiceDaemon::shutdown returns a Receiver but we don't wait for
        // the goodbye to complete; the daemon stops accepting work.
        let _ = self.daemon.shutdown();
        if let Some(bg) = self.background.take() {
            bg.abort();
        }
        Ok(())
    }
}

impl Drop for Discovery {
    fn drop(&mut self) {
        if let Some(fullname) = self.advertised_fullname.take() {
            let _ = self.daemon.unregister(&fullname);
        }
        let _ = self.daemon.shutdown();
        if let Some(bg) = self.background.take() {
            bg.abort();
        }
    }
}

fn make_service_info(advert: &LocalAdvert) -> Result<ServiceInfo> {
    let instance = advert.node_id.short();
    let host_name = format!("crow-{instance}.local.");
    let mut props: HashMap<String, String> = HashMap::new();
    props.insert("v".to_string(), ADVERT_VERSION.to_string());
    props.insert("id".to_string(), advert.node_id.to_string());
    if let Some(name) = &advert.friendly_name {
        props.insert("name".to_string(), name.clone());
    }
    let info = ServiceInfo::new(
        SERVICE_TYPE,
        &instance,
        &host_name,
        "",
        advert.port,
        Some(props),
    )
    .map_err(|e| NetError::Protocol(format!("ServiceInfo::new: {e}")))?
    .enable_addr_auto();
    Ok(info)
}

fn peer_from_service_info(info: &ServiceInfo) -> Option<PeerInfo> {
    let props = info.get_properties();
    let id_str = txt_string(props, "id")?;
    let node_id = NodeId::from_str(&id_str).ok()?;

    let friendly_name = txt_string(props, "name");

    let port = info.get_port();
    let mut addresses: Vec<SocketAddr> = info
        .get_addresses()
        .iter()
        .map(|ip| SocketAddr::new(*ip, port))
        .collect();
    addresses.sort();

    let last_seen_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    Some(PeerInfo {
        node_id,
        friendly_name,
        addresses,
        last_seen_unix,
    })
}

fn txt_string(props: &mdns_sd::TxtProperties, key: &str) -> Option<String> {
    props
        .get_property_val(key)
        .flatten()
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crow::Identity;
    use std::time::Duration;

    fn advert_for(id: &Identity, port: u16, name: &str) -> LocalAdvert {
        LocalAdvert {
            node_id: id.node_id(),
            port,
            friendly_name: Some(name.to_string()),
        }
    }

    /// Wait up to `total` for `pred` to return true. Polls every `step`.
    async fn wait_for<F: Fn() -> bool>(total: Duration, step: Duration, pred: F) -> bool {
        let deadline = std::time::Instant::now() + total;
        loop {
            if pred() {
                return true;
            }
            if std::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(step).await;
        }
    }

    #[tokio::test]
    async fn two_daemons_discover_each_other() {
        let id_a = Identity::random();
        let id_b = Identity::random();
        let a = Discovery::start(Some(advert_for(&id_a, 7001, "device-a"))).unwrap();
        let b = Discovery::start(Some(advert_for(&id_b, 7002, "device-b"))).unwrap();

        let a_id = id_a.node_id();
        let b_id = id_b.node_id();

        let a_sees_b = wait_for(Duration::from_secs(8), Duration::from_millis(200), || {
            a.peers().iter().any(|p| p.node_id == b_id)
        })
        .await;
        let b_sees_a = wait_for(Duration::from_secs(8), Duration::from_millis(200), || {
            b.peers().iter().any(|p| p.node_id == a_id)
        })
        .await;

        assert!(a_sees_b, "a never saw b");
        assert!(b_sees_a, "b never saw a");

        let peer = a.peers().into_iter().find(|p| p.node_id == b_id).unwrap();
        assert_eq!(peer.friendly_name.as_deref(), Some("device-b"));
        assert!(!peer.addresses.is_empty());
        assert!(peer.addresses.iter().all(|a| a.port() == 7002));

        a.shutdown().unwrap();
        b.shutdown().unwrap();
    }

    #[tokio::test]
    async fn browse_only_does_not_advertise_self() {
        let id_a = Identity::random();
        let id_b = Identity::random();
        let advertiser = Discovery::start(Some(advert_for(&id_a, 7011, "advertiser"))).unwrap();
        let listener = Discovery::start(None).unwrap(); // no advert

        let a_id = id_a.node_id();
        let b_id = id_b.node_id();

        let listener_sees_advertiser =
            wait_for(Duration::from_secs(8), Duration::from_millis(200), || {
                listener.peers().iter().any(|p| p.node_id == a_id)
            })
            .await;
        assert!(listener_sees_advertiser, "listener never saw advertiser");

        // The listener has no advert, so the advertiser can't learn about it.
        let advertiser_does_not_see_listener =
            wait_for(Duration::from_secs(2), Duration::from_millis(200), || {
                advertiser.peers().iter().any(|p| p.node_id == b_id)
            })
            .await;
        assert!(
            !advertiser_does_not_see_listener,
            "advertiser somehow saw the listener"
        );

        advertiser.shutdown().unwrap();
        listener.shutdown().unwrap();
    }

    #[tokio::test]
    async fn does_not_self_discover() {
        let id = Identity::random();
        let d = Discovery::start(Some(advert_for(&id, 7021, "solo"))).unwrap();

        // Wait long enough for our own advertisement to come back via the
        // browse stream — the filter must drop it.
        tokio::time::sleep(Duration::from_secs(2)).await;

        assert!(
            d.peers().iter().all(|p| p.node_id != id.node_id()),
            "discovery returned self in peer list"
        );

        d.shutdown().unwrap();
    }
}
