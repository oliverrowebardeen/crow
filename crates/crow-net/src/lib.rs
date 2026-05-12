pub mod discovery;
pub mod peer_snapshot;

pub use discovery::{Discovery, LocalAdvert, PeerInfo, SERVICE_TYPE, default_friendly_name};
pub use peer_snapshot::{PEER_SNAPSHOT_FILE, PeerSnapshot, SelfInfo, snapshot_path};

use std::fmt;
use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bytes::Bytes;
use crow::{CatalogEvent, CatalogIndex, ChunkStore, FsStore, Hash, Namespace};
use quinn::{ClientConfig, Endpoint, RecvStream, SendStream, ServerConfig};
use rand::RngCore;
use rand::rngs::OsRng;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use serde::{Deserialize, Serialize};

pub const DEFAULT_BIND_ADDR: &str = "0.0.0.0:7070";
pub const TOKEN_FILE: &str = "cluster-token";
pub const PROTOCOL_VERSION: u16 = 1;
const ALPN: &[u8] = b"crow-1";
const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error("invalid token: {0}")]
    Token(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("hash mismatch for {namespace:?} {hash}: got {actual}")]
    HashMismatch {
        namespace: Namespace,
        hash: Hash,
        actual: Hash,
    },
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    QuinnConnect(#[from] quinn::ConnectError),
    #[error(transparent)]
    QuinnConnection(#[from] quinn::ConnectionError),
    #[error(transparent)]
    QuinnWrite(#[from] quinn::WriteError),
    #[error(transparent)]
    QuinnClosedStream(#[from] quinn::ClosedStream),
    #[error(transparent)]
    QuinnRead(#[from] quinn::ReadError),
    #[error(transparent)]
    QuinnReadExact(#[from] quinn::ReadExactError),
    #[error(transparent)]
    Rustls(#[from] rustls::Error),
    #[error("QUIC crypto setup failed: {0}")]
    QuinnCrypto(String),
    #[error(transparent)]
    Crow(#[from] crow::Error),
}

pub type Result<T> = std::result::Result<T, NetError>;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterToken([u8; 32]);

impl ClusterToken {
    pub fn random() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn encode(self) -> String {
        hex(&self.0)
    }

    pub fn decode(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.len() != 64 {
            return Err(NetError::Token(format!(
                "expected 64 hex chars, got {}",
                s.len()
            )));
        }
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            let pair = &s[i * 2..i * 2 + 2];
            *byte = u8::from_str_radix(pair, 16)
                .map_err(|e| NetError::Token(format!("invalid hex {pair:?}: {e}")))?;
        }
        Ok(Self(out))
    }
}

impl fmt::Debug for ClusterToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClusterToken(<redacted>)")
    }
}

pub struct TokenStore {
    path: PathBuf,
}

impl TokenStore {
    pub fn open(home: impl AsRef<Path>) -> Self {
        Self {
            path: home.as_ref().join(TOKEN_FILE),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    pub fn load(&self) -> Result<ClusterToken> {
        let s = fs::read_to_string(&self.path)?;
        ClusterToken::decode(&s)
    }

    pub fn save(&self, token: ClusterToken) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        write_private(&self.path, format!("{}\n", token.encode()).as_bytes())?;
        Ok(())
    }

    pub fn init(&self, force: bool) -> Result<ClusterToken> {
        if self.exists() && !force {
            return self.load();
        }
        let token = ClusterToken::random();
        self.save(token)?;
        Ok(token)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireNamespace {
    Chunks,
    Manifests,
}

impl From<Namespace> for WireNamespace {
    fn from(value: Namespace) -> Self {
        match value {
            Namespace::Chunks => Self::Chunks,
            Namespace::Manifests => Self::Manifests,
        }
    }
}

impl From<WireNamespace> for Namespace {
    fn from(value: WireNamespace) -> Self {
        match value {
            WireNamespace::Chunks => Self::Chunks,
            WireNamespace::Manifests => Self::Manifests,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    Hello {
        version: u16,
        token: ClusterToken,
    },
    Have {
        version: u16,
        token: ClusterToken,
        namespace: WireNamespace,
        hash: [u8; 32],
    },
    Get {
        version: u16,
        token: ClusterToken,
        namespace: WireNamespace,
        hash: [u8; 32],
    },
    CatalogEvents {
        version: u16,
        token: ClusterToken,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Response {
    Hello { version: u16 },
    Have { present: bool },
    Bytes { bytes: Vec<u8> },
    CatalogEvents { events: Vec<CatalogEvent> },
    Missing,
    Unauthorized,
    Error { message: String },
}

/// Long-lived QUIC chunk-fetch server.
///
/// Returned by [`serve`] once the endpoint has bound. Holds the actual
/// `local_addr` (so callers using `--bind 0.0.0.0:0` can learn which port
/// the OS gave them) and a join handle for the spawned accept loop.
pub struct Server {
    addr: SocketAddr,
    handle: tokio::task::JoinHandle<Result<()>>,
}

impl Server {
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Wait for the accept loop to exit. Returns whatever the loop returned
    /// (currently `Ok(())` once the endpoint stops accepting).
    pub async fn join(self) -> Result<()> {
        match self.handle.await {
            Ok(res) => res,
            Err(e) => Err(NetError::Protocol(format!("server task panicked: {e}"))),
        }
    }
}

/// Bind a QUIC endpoint and start accepting connections in a background task.
///
/// Returns once the bind has succeeded but before any connections are
/// accepted, so callers can read `Server::local_addr()` and start any
/// dependent services (e.g. mDNS advertisement) without racing the first
/// peer.
pub async fn serve(store: FsStore, token: ClusterToken, bind: SocketAddr) -> Result<Server> {
    serve_inner(store, None, token, bind).await
}

pub async fn serve_with_catalog(
    store: FsStore,
    catalog: CatalogIndex,
    token: ClusterToken,
    bind: SocketAddr,
) -> Result<Server> {
    serve_inner(store, Some(catalog), token, bind).await
}

async fn serve_inner(
    store: FsStore,
    catalog: Option<CatalogIndex>,
    token: ClusterToken,
    bind: SocketAddr,
) -> Result<Server> {
    let endpoint = Endpoint::server(server_config()?, bind)?;
    let addr = endpoint.local_addr()?;
    let store = Arc::new(store);
    let catalog = catalog.map(Arc::new);
    let handle = tokio::spawn(accept_loop(endpoint, store, catalog, token));
    Ok(Server { addr, handle })
}

async fn accept_loop(
    endpoint: Endpoint,
    store: Arc<FsStore>,
    catalog: Option<Arc<CatalogIndex>>,
    token: ClusterToken,
) -> Result<()> {
    while let Some(incoming) = endpoint.accept().await {
        let store = store.clone();
        let catalog = catalog.clone();
        tokio::spawn(async move {
            if let Ok(connection) = incoming.await {
                while let Ok((send, recv)) = connection.accept_bi().await {
                    let store = store.clone();
                    let catalog = catalog.clone();
                    tokio::spawn(async move {
                        let _ = handle_stream(store, catalog, token, send, recv).await;
                    });
                }
            }
        });
    }
    Ok(())
}

pub struct Client {
    connection: quinn::Connection,
}

impl Client {
    pub async fn connect(peer: SocketAddr) -> Result<Self> {
        let mut endpoint = Endpoint::client(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))?;
        endpoint.set_default_client_config(client_config()?);
        let connection = endpoint.connect(peer, "crow.local")?.await?;
        Ok(Self { connection })
    }

    pub async fn hello(&self, token: ClusterToken) -> Result<()> {
        match self
            .request(Request::Hello {
                version: PROTOCOL_VERSION,
                token,
            })
            .await?
        {
            Response::Hello {
                version: PROTOCOL_VERSION,
            } => Ok(()),
            Response::Unauthorized => Err(NetError::Unauthorized),
            other => Err(NetError::Protocol(format!(
                "unexpected hello response: {other:?}"
            ))),
        }
    }

    pub async fn have(
        &self,
        token: ClusterToken,
        namespace: Namespace,
        hash: Hash,
    ) -> Result<bool> {
        match self
            .request(Request::Have {
                version: PROTOCOL_VERSION,
                token,
                namespace: namespace.into(),
                hash: *hash.as_bytes(),
            })
            .await?
        {
            Response::Have { present } => Ok(present),
            Response::Unauthorized => Err(NetError::Unauthorized),
            other => Err(NetError::Protocol(format!(
                "unexpected have response: {other:?}"
            ))),
        }
    }

    pub async fn get(
        &self,
        token: ClusterToken,
        namespace: Namespace,
        hash: Hash,
    ) -> Result<Option<Bytes>> {
        match self
            .request(Request::Get {
                version: PROTOCOL_VERSION,
                token,
                namespace: namespace.into(),
                hash: *hash.as_bytes(),
            })
            .await?
        {
            Response::Bytes { bytes } => {
                let actual = Hash::of(&bytes);
                if actual != hash {
                    return Err(NetError::HashMismatch {
                        namespace,
                        hash,
                        actual,
                    });
                }
                Ok(Some(Bytes::from(bytes)))
            }
            Response::Missing => Ok(None),
            Response::Unauthorized => Err(NetError::Unauthorized),
            other => Err(NetError::Protocol(format!(
                "unexpected get response: {other:?}"
            ))),
        }
    }

    pub async fn catalog_events(&self, token: ClusterToken) -> Result<Vec<CatalogEvent>> {
        match self
            .request(Request::CatalogEvents {
                version: PROTOCOL_VERSION,
                token,
            })
            .await?
        {
            Response::CatalogEvents { events } => Ok(events),
            Response::Unauthorized => Err(NetError::Unauthorized),
            other => Err(NetError::Protocol(format!(
                "unexpected catalog events response: {other:?}"
            ))),
        }
    }

    async fn request(&self, request: Request) -> Result<Response> {
        let (mut send, mut recv) = self.connection.open_bi().await?;
        write_frame(&mut send, &request).await?;
        send.finish()?;
        read_frame(&mut recv).await
    }
}

async fn handle_stream(
    store: Arc<FsStore>,
    catalog: Option<Arc<CatalogIndex>>,
    token: ClusterToken,
    mut send: SendStream,
    mut recv: RecvStream,
) -> Result<()> {
    let response = match read_frame::<Request>(&mut recv).await {
        Ok(request) => handle_request(store, catalog, token, request).await,
        Err(e) => Response::Error {
            message: e.to_string(),
        },
    };
    write_frame(&mut send, &response).await?;
    send.finish()?;
    Ok(())
}

async fn handle_request(
    store: Arc<FsStore>,
    catalog: Option<Arc<CatalogIndex>>,
    token: ClusterToken,
    request: Request,
) -> Response {
    if request_token(&request) != Some(token) {
        return Response::Unauthorized;
    }
    if request_version(&request) != PROTOCOL_VERSION {
        return Response::Error {
            message: "unsupported protocol version".into(),
        };
    }
    match request {
        Request::Hello { .. } => Response::Hello {
            version: PROTOCOL_VERSION,
        },
        Request::Have {
            namespace, hash, ..
        } => {
            let hash = Hash::from_bytes(hash);
            match store.has(namespace.into(), &hash) {
                Ok(present) => Response::Have { present },
                Err(e) => Response::Error {
                    message: e.to_string(),
                },
            }
        }
        Request::Get {
            namespace, hash, ..
        } => {
            let hash = Hash::from_bytes(hash);
            match store.get(namespace.into(), &hash) {
                Ok(Some(bytes)) => Response::Bytes {
                    bytes: bytes.to_vec(),
                },
                Ok(None) => Response::Missing,
                Err(e) => Response::Error {
                    message: e.to_string(),
                },
            }
        }
        Request::CatalogEvents { .. } => match catalog {
            Some(catalog) => match catalog.load_events() {
                Ok(events) => Response::CatalogEvents { events },
                Err(e) => Response::Error {
                    message: e.to_string(),
                },
            },
            None => Response::Error {
                message: "catalog sync is not available on this server".into(),
            },
        },
    }
}

fn request_token(request: &Request) -> Option<ClusterToken> {
    match request {
        Request::Hello { token, .. }
        | Request::Have { token, .. }
        | Request::Get { token, .. }
        | Request::CatalogEvents { token, .. } => Some(*token),
    }
}

fn request_version(request: &Request) -> u16 {
    match request {
        Request::Hello { version, .. }
        | Request::Have { version, .. }
        | Request::Get { version, .. }
        | Request::CatalogEvents { version, .. } => *version,
    }
}

async fn write_frame<T: Serialize>(send: &mut SendStream, value: &T) -> Result<()> {
    let bytes =
        postcard::to_allocvec(value).map_err(|e| NetError::Protocol(format!("encode: {e}")))?;
    if bytes.len() > MAX_FRAME_LEN {
        return Err(NetError::Protocol(format!(
            "frame too large: {} bytes",
            bytes.len()
        )));
    }
    send.write_all(&(bytes.len() as u32).to_be_bytes()).await?;
    send.write_all(&bytes).await?;
    Ok(())
}

async fn read_frame<T: for<'de> Deserialize<'de>>(recv: &mut RecvStream) -> Result<T> {
    let mut len_bytes = [0u8; 4];
    recv.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len > MAX_FRAME_LEN {
        return Err(NetError::Protocol(format!("frame too large: {len} bytes")));
    }
    let mut bytes = vec![0u8; len];
    recv.read_exact(&mut bytes).await?;
    postcard::from_bytes(&bytes).map_err(|e| NetError::Protocol(format!("decode: {e}")))
}

fn server_config() -> Result<ServerConfig> {
    ensure_crypto_provider();
    let cert = rcgen::generate_simple_self_signed(vec!["crow.local".into()])
        .map_err(|e| NetError::Protocol(format!("generate cert: {e}")))?;
    let cert_der = cert.cert.der().clone();
    let key_der = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der.into())?;
    server_crypto.alpn_protocols = vec![ALPN.to_vec()];
    Ok(ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .map_err(|e| NetError::QuinnCrypto(e.to_string()))?,
    )))
}

fn client_config() -> Result<ClientConfig> {
    ensure_crypto_provider();
    let verifier = Arc::new(SkipServerVerification);
    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![ALPN.to_vec()];
    Ok(ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
            .map_err(|e| NetError::QuinnCrypto(e.to_string()))?,
    )))
}

fn ensure_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

#[derive(Debug)]
struct SkipServerVerification;

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut opts = fs::OpenOptions::new();
    opts.create(true).write(true).truncate(true).mode(0o600);
    std::io::Write::write_all(&mut opts.open(path)?, bytes)
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    fs::write(path, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn token_roundtrip() {
        let token = ClusterToken::random();
        let encoded = token.encode();
        assert_eq!(encoded.len(), 64);
        assert_eq!(ClusterToken::decode(&encoded).unwrap(), token);
    }

    #[test]
    fn token_rejects_bad_input() {
        assert!(ClusterToken::decode("abcd").is_err());
        assert!(ClusterToken::decode(&"z".repeat(64)).is_err());
    }

    #[test]
    fn token_store_init_set_load() {
        let tmp = tempfile::TempDir::new().unwrap();
        let store = TokenStore::open(tmp.path());
        let token = store.init(false).unwrap();
        assert_eq!(store.load().unwrap(), token);

        let second = ClusterToken::from_bytes([7u8; 32]);
        store.save(second).unwrap();
        assert_eq!(store.init(false).unwrap(), second);
        assert_ne!(store.init(true).unwrap(), second);
    }

    #[test]
    fn catalog_events_request_returns_events_for_valid_token() {
        let tmp = tempfile::TempDir::new().unwrap();
        let identity = crow::Identity::load_or_create(tmp.path()).unwrap();
        let store = Arc::new(FsStore::open(tmp.path()).unwrap());
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        catalog.mkdir("/docs", false, &identity).unwrap();
        let token = ClusterToken::random();
        let rt = tokio::runtime::Runtime::new().unwrap();

        let response = rt.block_on(handle_request(
            store,
            Some(Arc::new(catalog)),
            token,
            Request::CatalogEvents {
                version: PROTOCOL_VERSION,
                token,
            },
        ));

        match response {
            Response::CatalogEvents { events } => {
                assert_eq!(events.len(), 1);
                assert!(matches!(events[0].op, crow::CatalogOp::Mkdir { .. }));
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn catalog_events_request_rejects_wrong_token() {
        let tmp = tempfile::TempDir::new().unwrap();
        let store = Arc::new(FsStore::open(tmp.path()).unwrap());
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        let token = ClusterToken::random();
        let rt = tokio::runtime::Runtime::new().unwrap();

        let response = rt.block_on(handle_request(
            store,
            Some(Arc::new(catalog)),
            token,
            Request::CatalogEvents {
                version: PROTOCOL_VERSION,
                token: ClusterToken::random(),
            },
        ));

        assert_eq!(response, Response::Unauthorized);
    }
}
