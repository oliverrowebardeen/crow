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
use crow::{
    CatalogEvent, CatalogIndex, CatalogOp, ChunkStore, FsStore, Hash, Identity, Namespace, NestId,
    NodeId, Signature,
};
use quinn::{ClientConfig, Endpoint, RecvStream, SendStream, ServerConfig};
use rand::RngCore;
use rand::rngs::OsRng;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use serde::{Deserialize, Serialize};

pub const DEFAULT_BIND_ADDR: &str = "0.0.0.0:7070";
pub const TOKEN_FILE: &str = "cluster-token";
/// Wire protocol version. Bumped to 2 in Phase 3 (added nest-scoped
/// challenge-response variants). Servers and clients on the same version
/// understand both legacy ClusterToken requests and the new nest-scoped
/// flow; downgrade to v1 is not supported.
pub const PROTOCOL_VERSION: u16 = 2;
const ALPN: &[u8] = b"crow-1";
const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;
/// Domain tag for the nest-auth challenge signed by clients during the
/// handshake. Bumping it invalidates every in-flight handshake — only
/// change with a coordinated version bump.
const NEST_AUTH_DOMAIN_TAG: &[u8] = b"crow.nest-auth.v1";

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
    // ----- Legacy unscoped (cluster-token bearer) requests. -----
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

    // ----- Nest-scoped challenge-response (Phase 3). -----
    /// Step 1 of the handshake. Records (nest_id, signer) on the connection
    /// and prompts the server to issue a fresh random challenge.
    NestHello {
        version: u16,
        nest_id: NestId,
        signer: NodeId,
        membership_proof: Option<Box<CatalogEvent>>,
    },
    /// Step 2 of the handshake. Client signs
    /// `NEST_AUTH_DOMAIN_TAG || challenge || nest_id || signer` with
    /// the private key matching `signer`; server verifies and looks up
    /// membership.
    NestAuthResponse {
        version: u16,
        signature: Signature,
    },
    /// Like [`Request::Have`] but predicated on the connection's nest-auth
    /// flag.
    NestHave {
        version: u16,
        namespace: WireNamespace,
        hash: [u8; 32],
    },
    /// Like [`Request::Get`] but predicated on the connection's nest-auth
    /// flag.
    NestGet {
        version: u16,
        namespace: WireNamespace,
        hash: [u8; 32],
    },
    /// Like [`Request::CatalogEvents`] but predicated on the connection's
    /// nest-auth flag.
    NestCatalogEvents {
        version: u16,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Response {
    Hello {
        version: u16,
    },
    Have {
        present: bool,
    },
    Bytes {
        bytes: Vec<u8>,
    },
    CatalogEvents {
        events: Vec<CatalogEvent>,
    },
    Missing,
    Unauthorized,
    Error {
        message: String,
    },

    // ----- Nest-scoped responses. -----
    /// Issued in response to `NestHello`. Client must sign this challenge
    /// concatenated with `NEST_AUTH_DOMAIN_TAG`, nest_id, and signer.
    NestChallenge {
        challenge: [u8; 32],
    },
    /// Handshake succeeded. Subsequent NestHave/NestGet/NestCatalogEvents
    /// on the same connection are now authorised.
    NestAuthorised,
    /// Handshake rejected. Signature failed, signer is not a member of
    /// the named nest, or the server is not serving that nest.
    NestUnauthorised,
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
    serve_with_config(ServeConfig::new(store, token, bind)).await
}

pub async fn serve_with_catalog(
    store: FsStore,
    catalog: CatalogIndex,
    token: ClusterToken,
    bind: SocketAddr,
) -> Result<Server> {
    let mut config = ServeConfig::new(store, token, bind);
    config.legacy_catalog = Some(catalog);
    serve_with_config(config).await
}

/// Per-nest bundle the server needs to handle nest-scoped requests.
/// Holds the nest's id and a handle to its catalog (so the handshake can
/// look up the member list).
#[derive(Clone)]
pub struct NestServingConfig {
    pub nest_id: NestId,
    pub catalog: Arc<CatalogIndex>,
}

/// Server bring-up parameters. Direct fields rather than a builder so the
/// shape of legacy vs. nest-scoped flags is obvious at the call site.
pub struct ServeConfig {
    pub store: FsStore,
    pub bind: SocketAddr,
    /// Bearer token for legacy ClusterToken requests.
    pub legacy_token: ClusterToken,
    /// Catalog served via the legacy `CatalogEvents` request. The
    /// per-nest catalog used by `NestCatalogEvents` lives in
    /// `nest_serving` and may be the same instance.
    pub legacy_catalog: Option<CatalogIndex>,
    /// Nest this server is willing to authenticate clients into.
    /// `None` keeps the server cluster-token-only (Phase 2 behaviour).
    pub nest_serving: Option<NestServingConfig>,
}

impl ServeConfig {
    pub fn new(store: FsStore, legacy_token: ClusterToken, bind: SocketAddr) -> Self {
        Self {
            store,
            bind,
            legacy_token,
            legacy_catalog: None,
            nest_serving: None,
        }
    }
}

pub async fn serve_with_config(config: ServeConfig) -> Result<Server> {
    let endpoint = Endpoint::server(server_config()?, config.bind)?;
    let addr = endpoint.local_addr()?;
    let ctx = ServerCtx {
        store: Arc::new(config.store),
        legacy_token: config.legacy_token,
        legacy_catalog: config.legacy_catalog.map(Arc::new),
        nest_serving: config.nest_serving,
    };
    let handle = tokio::spawn(accept_loop(endpoint, ctx));
    Ok(Server { addr, handle })
}

/// Server-side state shared across every connection / stream task.
#[derive(Clone)]
struct ServerCtx {
    store: Arc<FsStore>,
    legacy_token: ClusterToken,
    legacy_catalog: Option<Arc<CatalogIndex>>,
    nest_serving: Option<NestServingConfig>,
}

/// Per-connection state. One `Arc<Mutex<ConnState>>` is created in the
/// connection-handler task and cloned into every spawned stream task on
/// that connection, so the handshake completed on stream 1 is visible to
/// requests on stream 2+.
#[derive(Default)]
struct ConnState {
    pending: Option<PendingNestAuth>,
    auth: Option<ConfirmedNestAuth>,
}

struct PendingNestAuth {
    nest_id: NestId,
    signer: NodeId,
    membership_proof: Option<CatalogEvent>,
    challenge: [u8; 32],
}

#[derive(Clone)]
struct ConfirmedNestAuth {
    nest_id: NestId,
    #[allow(dead_code)] // recorded for diagnostics
    member: NodeId,
}

async fn accept_loop(endpoint: Endpoint, ctx: ServerCtx) -> Result<()> {
    while let Some(incoming) = endpoint.accept().await {
        let ctx = ctx.clone();
        tokio::spawn(async move {
            if let Ok(connection) = incoming.await {
                let conn_state = Arc::new(tokio::sync::Mutex::new(ConnState::default()));
                while let Ok((send, recv)) = connection.accept_bi().await {
                    let ctx = ctx.clone();
                    let conn_state = conn_state.clone();
                    tokio::spawn(async move {
                        let _ = handle_stream(ctx, conn_state, send, recv).await;
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

    /// Open a connection and complete the nest-scoped handshake. Returns a
    /// `Client` whose subsequent `nest_have / nest_get / nest_catalog_events`
    /// calls will be authorised for `nest_id` until the connection is
    /// dropped.
    ///
    /// On signature rejection or non-membership the server returns
    /// `NestUnauthorised` and this method surfaces it as
    /// `NetError::Unauthorized`. The connection is dropped on the client
    /// side rather than continuing in an undefined state.
    pub async fn connect_for_nest(
        peer: SocketAddr,
        nest_id: NestId,
        identity: &Identity,
    ) -> Result<Self> {
        Self::connect_for_nest_with_proof(peer, nest_id, identity, None).await
    }

    /// Open a nest-scoped connection with an optional local `MemberAdded`
    /// proof. This lets a freshly joined invitee authenticate to the
    /// inviter before the inviter has synced the invitee's membership event.
    pub async fn connect_for_nest_with_proof(
        peer: SocketAddr,
        nest_id: NestId,
        identity: &Identity,
        membership_proof: Option<CatalogEvent>,
    ) -> Result<Self> {
        let client = Self::connect(peer).await?;
        client
            .nest_handshake(nest_id, identity, membership_proof)
            .await?;
        Ok(client)
    }

    async fn nest_handshake(
        &self,
        nest_id: NestId,
        identity: &Identity,
        membership_proof: Option<CatalogEvent>,
    ) -> Result<()> {
        let signer = identity.node_id();
        // Step 1: NestHello → NestChallenge.
        let challenge = match self
            .request(Request::NestHello {
                version: PROTOCOL_VERSION,
                nest_id,
                signer,
                membership_proof: membership_proof.map(Box::new),
            })
            .await?
        {
            Response::NestChallenge { challenge } => challenge,
            Response::NestUnauthorised => return Err(NetError::Unauthorized),
            other => {
                return Err(NetError::Protocol(format!(
                    "unexpected NestHello response: {other:?}"
                )));
            }
        };

        // Step 2: sign and submit NestAuthResponse.
        let payload = nest_auth_signing_payload(&challenge, &nest_id, &signer);
        let sig: ed25519_dalek::Signature =
            ed25519_dalek::Signer::sign(&identity.signing, &payload);
        match self
            .request(Request::NestAuthResponse {
                version: PROTOCOL_VERSION,
                signature: Signature(sig.to_bytes()),
            })
            .await?
        {
            Response::NestAuthorised => Ok(()),
            Response::NestUnauthorised => Err(NetError::Unauthorized),
            other => Err(NetError::Protocol(format!(
                "unexpected NestAuthResponse response: {other:?}"
            ))),
        }
    }

    pub async fn nest_have(&self, namespace: Namespace, hash: Hash) -> Result<bool> {
        match self
            .request(Request::NestHave {
                version: PROTOCOL_VERSION,
                namespace: namespace.into(),
                hash: *hash.as_bytes(),
            })
            .await?
        {
            Response::Have { present } => Ok(present),
            Response::NestUnauthorised => Err(NetError::Unauthorized),
            other => Err(NetError::Protocol(format!(
                "unexpected nest_have response: {other:?}"
            ))),
        }
    }

    pub async fn nest_get(&self, namespace: Namespace, hash: Hash) -> Result<Option<Bytes>> {
        match self
            .request(Request::NestGet {
                version: PROTOCOL_VERSION,
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
            Response::NestUnauthorised => Err(NetError::Unauthorized),
            other => Err(NetError::Protocol(format!(
                "unexpected nest_get response: {other:?}"
            ))),
        }
    }

    pub async fn nest_catalog_events(&self) -> Result<Vec<CatalogEvent>> {
        match self
            .request(Request::NestCatalogEvents {
                version: PROTOCOL_VERSION,
            })
            .await?
        {
            Response::CatalogEvents { events } => Ok(events),
            Response::NestUnauthorised => Err(NetError::Unauthorized),
            other => Err(NetError::Protocol(format!(
                "unexpected nest_catalog_events response: {other:?}"
            ))),
        }
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
    ctx: ServerCtx,
    conn_state: Arc<tokio::sync::Mutex<ConnState>>,
    mut send: SendStream,
    mut recv: RecvStream,
) -> Result<()> {
    let response = match read_frame::<Request>(&mut recv).await {
        Ok(request) => handle_request(&ctx, &conn_state, request).await,
        Err(e) => Response::Error {
            message: e.to_string(),
        },
    };
    write_frame(&mut send, &response).await?;
    send.finish()?;
    Ok(())
}

async fn handle_request(
    ctx: &ServerCtx,
    conn_state: &Arc<tokio::sync::Mutex<ConnState>>,
    request: Request,
) -> Response {
    if request_version(&request) != PROTOCOL_VERSION {
        return Response::Error {
            message: "unsupported protocol version".into(),
        };
    }

    // Legacy cluster-token branch: every legacy variant carries the
    // bearer token in-frame. Reject if mismatched without consulting
    // per-connection state.
    if let Some(token) = legacy_token(&request) {
        if token != ctx.legacy_token {
            return Response::Unauthorized;
        }
    }

    match request {
        Request::Hello { .. } => Response::Hello {
            version: PROTOCOL_VERSION,
        },
        Request::Have {
            namespace, hash, ..
        } => store_have(&ctx.store, namespace, hash),
        Request::Get {
            namespace, hash, ..
        } => store_get(&ctx.store, namespace, hash),
        Request::CatalogEvents { .. } => match &ctx.legacy_catalog {
            Some(catalog) => catalog_events_response(catalog),
            None => Response::Error {
                message: "catalog sync is not available on this server".into(),
            },
        },
        Request::NestHello {
            nest_id,
            signer,
            membership_proof,
            ..
        } => {
            handle_nest_hello(
                ctx,
                conn_state,
                nest_id,
                signer,
                membership_proof.map(|proof| *proof),
            )
            .await
        }
        Request::NestAuthResponse { signature, .. } => {
            handle_nest_auth_response(ctx, conn_state, signature).await
        }
        Request::NestHave {
            namespace, hash, ..
        } => match require_nest_auth(ctx, conn_state).await {
            Some(_) => store_have(&ctx.store, namespace, hash),
            None => Response::NestUnauthorised,
        },
        Request::NestGet {
            namespace, hash, ..
        } => match require_nest_auth(ctx, conn_state).await {
            Some(_) => store_get(&ctx.store, namespace, hash),
            None => Response::NestUnauthorised,
        },
        Request::NestCatalogEvents { .. } => match require_nest_auth(ctx, conn_state).await {
            Some(_) => match &ctx.nest_serving {
                Some(nest) => catalog_events_response(&nest.catalog),
                None => Response::NestUnauthorised,
            },
            None => Response::NestUnauthorised,
        },
    }
}

async fn handle_nest_hello(
    ctx: &ServerCtx,
    conn_state: &Arc<tokio::sync::Mutex<ConnState>>,
    nest_id: NestId,
    signer: NodeId,
    membership_proof: Option<CatalogEvent>,
) -> Response {
    let Some(nest) = ctx.nest_serving.as_ref() else {
        return Response::NestUnauthorised;
    };
    if nest.nest_id != nest_id {
        return Response::NestUnauthorised;
    }
    let mut challenge = [0u8; 32];
    OsRng.fill_bytes(&mut challenge);
    let mut state = conn_state.lock().await;
    state.pending = Some(PendingNestAuth {
        nest_id,
        signer,
        membership_proof,
        challenge,
    });
    // A new handshake on the same connection invalidates any prior
    // auth — a peer rotating identity must complete the new handshake
    // before issuing further nest requests.
    state.auth = None;
    Response::NestChallenge { challenge }
}

async fn handle_nest_auth_response(
    ctx: &ServerCtx,
    conn_state: &Arc<tokio::sync::Mutex<ConnState>>,
    signature: Signature,
) -> Response {
    let pending = {
        let mut state = conn_state.lock().await;
        // Single-use: consume the pending challenge regardless of outcome
        // so a captured response can't be replayed against a fresh
        // challenge on the same connection.
        state.pending.take()
    };
    let Some(pending) = pending else {
        return Response::NestUnauthorised;
    };
    let Some(nest) = ctx.nest_serving.as_ref() else {
        return Response::NestUnauthorised;
    };
    if nest.nest_id != pending.nest_id {
        return Response::NestUnauthorised;
    }
    let payload = nest_auth_signing_payload(&pending.challenge, &pending.nest_id, &pending.signer);
    let Ok(verifying_key) = ed25519_dalek::VerifyingKey::from_bytes(pending.signer.as_bytes())
    else {
        return Response::NestUnauthorised;
    };
    let sig = ed25519_dalek::Signature::from_bytes(&signature.0);
    if verifying_key.verify_strict(&payload, &sig).is_err() {
        return Response::NestUnauthorised;
    }

    // Look up membership in the nest's catalog. If this is the invitee's
    // first contact, accept a valid signed MemberAdded proof and merge it
    // before authorising the connection.
    let mut is_member = match nest.catalog.view() {
        Ok(view) => member_is_current(&view, pending.signer),
        Err(_) => return Response::NestUnauthorised,
    };
    if !is_member {
        let Some(proof) = pending.membership_proof else {
            return Response::NestUnauthorised;
        };
        if membership_proof_member(&proof) != Some(pending.signer) {
            return Response::NestUnauthorised;
        }
        if nest
            .catalog
            .merge_events_from_peer_for_nest(&pending.nest_id, [proof])
            .is_err()
        {
            return Response::NestUnauthorised;
        }
        is_member = match nest.catalog.view() {
            Ok(view) => member_is_current(&view, pending.signer),
            Err(_) => return Response::NestUnauthorised,
        };
    }
    if !is_member {
        return Response::NestUnauthorised;
    }

    let mut state = conn_state.lock().await;
    state.auth = Some(ConfirmedNestAuth {
        nest_id: pending.nest_id,
        member: pending.signer,
    });
    Response::NestAuthorised
}

fn member_is_current(view: &crow::CatalogView, member: NodeId) -> bool {
    view.members()
        .iter()
        .any(|m| m.member == member && m.revoked_at.is_none())
}

fn membership_proof_member(event: &CatalogEvent) -> Option<NodeId> {
    match &event.op {
        CatalogOp::MemberAdded { member, .. } => Some(*member),
        _ => None,
    }
}

async fn require_nest_auth(
    ctx: &ServerCtx,
    conn_state: &Arc<tokio::sync::Mutex<ConnState>>,
) -> Option<ConfirmedNestAuth> {
    let auth = conn_state.lock().await.auth.clone()?;
    let nest_id = ctx.nest_serving.as_ref().map(|n| n.nest_id)?;
    if auth.nest_id != nest_id {
        return None;
    }
    Some(auth)
}

fn store_have(store: &FsStore, namespace: WireNamespace, hash: [u8; 32]) -> Response {
    let hash = Hash::from_bytes(hash);
    match store.has(namespace.into(), &hash) {
        Ok(present) => Response::Have { present },
        Err(e) => Response::Error {
            message: e.to_string(),
        },
    }
}

fn store_get(store: &FsStore, namespace: WireNamespace, hash: [u8; 32]) -> Response {
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

fn catalog_events_response(catalog: &CatalogIndex) -> Response {
    match catalog.load_events() {
        Ok(events) => Response::CatalogEvents { events },
        Err(e) => Response::Error {
            message: e.to_string(),
        },
    }
}

/// Domain-separated payload a client signs in response to a server
/// challenge. Identical at both ends, by construction.
fn nest_auth_signing_payload(challenge: &[u8; 32], nest_id: &NestId, signer: &NodeId) -> Vec<u8> {
    let mut out = Vec::with_capacity(NEST_AUTH_DOMAIN_TAG.len() + 32 + 16 + 32);
    out.extend_from_slice(NEST_AUTH_DOMAIN_TAG);
    out.extend_from_slice(challenge);
    out.extend_from_slice(nest_id.as_bytes());
    out.extend_from_slice(signer.as_bytes());
    out
}

fn legacy_token(request: &Request) -> Option<ClusterToken> {
    match request {
        Request::Hello { token, .. }
        | Request::Have { token, .. }
        | Request::Get { token, .. }
        | Request::CatalogEvents { token, .. } => Some(*token),
        Request::NestHello { .. }
        | Request::NestAuthResponse { .. }
        | Request::NestHave { .. }
        | Request::NestGet { .. }
        | Request::NestCatalogEvents { .. } => None,
    }
}

fn request_version(request: &Request) -> u16 {
    match request {
        Request::Hello { version, .. }
        | Request::Have { version, .. }
        | Request::Get { version, .. }
        | Request::CatalogEvents { version, .. }
        | Request::NestHello { version, .. }
        | Request::NestAuthResponse { version, .. }
        | Request::NestHave { version, .. }
        | Request::NestGet { version, .. }
        | Request::NestCatalogEvents { version, .. } => *version,
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

    fn server_ctx_with_catalog(
        store: Arc<FsStore>,
        catalog: Arc<CatalogIndex>,
        token: ClusterToken,
    ) -> ServerCtx {
        ServerCtx {
            store,
            legacy_token: token,
            legacy_catalog: Some(catalog),
            nest_serving: None,
        }
    }

    #[test]
    fn catalog_events_request_returns_events_for_valid_token() {
        let tmp = tempfile::TempDir::new().unwrap();
        let identity = crow::Identity::load_or_create(tmp.path()).unwrap();
        let store = Arc::new(FsStore::open(tmp.path()).unwrap());
        let catalog = Arc::new(CatalogIndex::open(tmp.path()).unwrap());
        catalog.mkdir("/docs", false, &identity).unwrap();
        let token = ClusterToken::random();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let ctx = server_ctx_with_catalog(store, catalog, token);
        let conn_state = Arc::new(tokio::sync::Mutex::new(ConnState::default()));

        let response = rt.block_on(handle_request(
            &ctx,
            &conn_state,
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
        let catalog = Arc::new(CatalogIndex::open(tmp.path()).unwrap());
        let token = ClusterToken::random();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let ctx = server_ctx_with_catalog(store, catalog, token);
        let conn_state = Arc::new(tokio::sync::Mutex::new(ConnState::default()));

        let response = rt.block_on(handle_request(
            &ctx,
            &conn_state,
            Request::CatalogEvents {
                version: PROTOCOL_VERSION,
                token: ClusterToken::random(),
            },
        ));

        assert_eq!(response, Response::Unauthorized);
    }
}
