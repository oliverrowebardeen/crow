use std::collections::HashSet;
use std::fs;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use crow::{
    Cap, CatalogEntry, CatalogIndex, CatalogPath, CatalogView, ChunkStore, Crow,
    DEFAULT_CHUNK_SIZE, DirectoryEntry, DirectoryEntryKind, DirectoryManifest, EntryKind,
    ErasureParams, FsStore, GcOptions, Hash, Identity, Manifest, ManifestKind, Namespace, NodeId,
    PinIndex, PinRecord, SignatureStatus, compute_live_set, compute_live_set_from_roots,
    erasure::{AEAD_TAG_LEN, RS_ALIGN},
    sweep, targeted_remove,
};
use crow_net::{
    Client, ClusterToken, DEFAULT_BIND_ADDR, Discovery, LocalAdvert, PeerInfo, PeerSnapshot,
    SelfInfo, TokenStore, default_friendly_name, peer_snapshot,
};
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Parser)]
#[command(
    name = "crow",
    version,
    about = "Decentralized, content-addressed file storage.",
    long_about = "Decentralized, content-addressed file storage with Tahoe-LAFS-style \
                  capabilities. Files get chunked, encrypted, erasure-coded, and stored \
                  by the BLAKE3 hash of their bytes; the pointer to a file is a small \
                  bech32m \"crow1…\" capability that bundles the manifest hash and its \
                  decryption key.\n\
                  \n\
                  Quick start:\n\
                  \n  \
                  crow setup --name laptop       # initialize identity, token, device name\n  \
                  crow mkdir /docs                 # create a local catalog folder\n  \
                  crow put report.pdf /docs/       # store, pin, catalog by path\n  \
                  crow ls /docs                    # list catalog entries\n  \
                  crow cap /docs/report.pdf        # print a file cap\n  \
                  crow share /docs/report.pdf      # print cap + receive command\n  \
                  crow info /docs/report.pdf       # show metadata + pin status\n  \
                  crow get /docs/report.pdf out.pdf # retrieve\n  \
                  crow put-dir ./Photos /photos    # import a folder tree\n  \
                  crow get-dir /photos ./Photos    # export a folder tree\n  \
                  crow mv /docs/report.pdf /docs/q2.pdf\n  \
                  crow rm /docs/q2.pdf             # delete path and chunks\n  \
                  crow gc                          # sweep anything not pinned\n  \
                  crow serve                       # serve chunks + advertise on mDNS\n  \
                  crow peers                       # list LAN peers `crow serve` discovered\n  \
                  crow receive laptop <cap> /docs/report.pdf # fetch + catalog\n\
                  \n\
                  File commands accept catalog paths, full crow1… capabilities, or \
                  hex prefixes of pinned manifest hashes; ambiguous prefixes get an \
                  explicit error. Folders are local organization; file caps are still \
                  the shareable unit.\n\
                  \n\
                  Storage lives at $CROW_HOME, defaulting to $HOME/.crow.\n\
                  \n\
                  See `crow <command> --help` for per-command details."
)]
struct Cli {
    /// Storage directory. Defaults to $CROW_HOME, then $HOME/.crow.
    #[arg(long, env = "CROW_HOME")]
    home: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Store a file as a flat pin or at a catalog path.
    #[command(
        long_about = "Encrypt, chunk, erasure-code, and store the bytes; record either \
                      a flat pin or a local catalog path so chunks survive `crow gc`; \
                      print the resulting bech32m cap.\n\
                      \n\
                      The default pin name is the basename of the input file, or \
                      `(unnamed)` for stdin. Use --name to override.\n\
                      \n\
                      If DEST is supplied, it must be a catalog path. When DEST names \
                      an existing catalog directory or ends in '/', Crow writes the \
                      file under that directory using the input basename.\n\
                      \n\
                      Each `crow put` generates fresh keys, so the same input bytes \
                      produce a different cap each time. Content addressing happens at \
                      the share level, not the cap.\n\
                      \n\
                      Examples:\n  \
                      crow put report.pdf\n  \
                      crow mkdir /docs\n  \
                      crow put report.pdf /docs/\n  \
                      crow put report.pdf /docs/q2-report.pdf\n  \
                      crow put image.png --name screenshot.png\n  \
                      tar cf - ~/Documents | crow put -"
    )]
    Put {
        /// File to store. "-" reads from stdin.
        path: String,
        /// Optional catalog destination path, e.g. /docs/report.pdf or /docs/.
        dest: Option<String>,
        /// Override MIME type. Default: inferred from extension.
        #[arg(long)]
        mime: Option<String>,
        /// Override the pin name. Default: file basename, or `(unnamed)` for stdin.
        #[arg(long)]
        name: Option<String>,
        /// Override chunk size in bytes. Must satisfy (chunk_size + 16) % 64 == 0.
        #[arg(long)]
        chunk_size: Option<u32>,
    },
    /// Retrieve a file by catalog path, capability, or hash prefix.
    #[command(
        long_about = "Resolve a full crow1… capability or a hex prefix of the manifest \
                      hash, fetch the encrypted manifest, decrypt it, reconstruct the \
                      file (using parity to recover any missing data shares), and \
                      write it to <OUT>.\n\
                      \n\
                      <OUT> may be \"-\" for stdout, useful in pipelines.\n\
                      \n\
                      Examples:\n  \
                      crow get crow1qyq…m0r restored.pdf\n  \
                      crow get 3b52 ./out.bin\n  \
                      crow get <prefix> - | tar xf -"
    )]
    Get {
        /// Catalog path, full bech32m capability (`crow1…`), or hex prefix.
        cap_or_prefix: String,
        /// Output path. "-" writes to stdout.
        out: String,
    },
    /// Print a file's bytes to stdout.
    #[command(
        long_about = "Resolve a local catalog path, full crow1… capability, or pinned \
                      hash prefix; reconstruct the file; and write raw bytes to \
                      stdout. This is intentionally Unix-like and does not guard \
                      against binary or large output.\n\
                      \n\
                      Examples:\n  \
                      crow cat /docs/notes.md\n  \
                      crow cat /docs/notes.md | grep TODO"
    )]
    Cat {
        /// Catalog path, full bech32m capability (`crow1…`), or hex prefix.
        cap_or_prefix: String,
    },
    /// Print the full capability for a file reference.
    #[command(
        long_about = "Resolve a catalog file path, full crow1… capability, or pinned \
                      hash prefix and print the full crow1… cap only. This is the \
                      low-noise command for copy/paste and scripts.\n\
                      \n\
                      Catalog directories are mutable local organization and do not \
                      have stable caps. Use `crow share /dir` or `crow cap-dir /dir` \
                      to create an immutable directory snapshot cap."
    )]
    Cap {
        /// Catalog path, full bech32m capability (`crow1…`), or pinned hash prefix.
        cap_or_prefix: String,
    },
    /// Print a shareable cap and receive command for a file or directory.
    #[command(
        long_about = "Prepare a file or catalog directory for sharing. Files reuse \
                      their existing cap. Catalog directories are frozen into a new \
                      immutable directory snapshot cap and pinned locally. The default \
                      output avoids embedding your device name; use `crow peers` on \
                      the receiving device to choose a peer name, node-id prefix, or \
                      IP:port.\n\
                      \n\
                      Examples:\n  \
                      crow share /docs/report.pdf\n  \
                      crow share /docs --name docs-snapshot\n  \
                      crow share /docs/report.pdf --plain"
    )]
    Share {
        /// Catalog path, full bech32m capability (`crow1…`), or pinned hash prefix.
        cap_or_prefix: String,
        /// Friendly name for a new directory snapshot pin.
        #[arg(long)]
        name: Option<String>,
        /// Print only the cap.
        #[arg(long)]
        plain: bool,
    },
    /// Print metadata for a catalog path, capability, or hash prefix.
    #[command(
        long_about = "Decrypt and inspect the manifest behind a capability. Shows the \
                      manifest hash, file size, MIME type, erasure params, stripe and \
                      share counts, chunk size, creation timestamp, the algorithm \
                      tuple, and pin status (name + pinned timestamp, or `pinned no`).\n\
                      \n\
                      Accepts either a full crow1… capability or a hex prefix of the \
                      manifest hash. Caps that aren't pinned still resolve via their \
                      full string."
    )]
    Info {
        /// Catalog path, full bech32m capability (`crow1…`), or hex prefix.
        cap_or_prefix: String,
    },
    /// List catalog entries, or flat pins with --pins.
    #[command(
        long_about = "List a catalog directory. With no PATH, lists the catalog root \
                      when it has entries; otherwise falls back to the legacy flat pin \
                      list. Use --pins to force the flat pin list.\n\
                      \n\
                      Catalog folders are local-only organization. Files remain \
                      shareable via their crow1… capabilities."
    )]
    Ls {
        /// Optional catalog directory or file path.
        path: Option<String>,
        /// Show full hashes, full mime types, and ISO timestamps.
        #[arg(short, long)]
        long: bool,
        /// Show legacy flat pins instead of catalog entries.
        #[arg(long)]
        pins: bool,
    },
    /// Show a hierarchical catalog tree.
    #[command(
        long_about = "Print a tree view of the local catalog. With no PATH, starts at \
                      the catalog root. Directories are shown with a trailing slash. \
                      This is catalog-only metadata; it does not decrypt manifests or \
                      walk chunks.\n\
                      \n\
                      Examples:\n  \
                      crow tree\n  \
                      crow tree /docs"
    )]
    Tree {
        /// Optional catalog path to use as the tree root.
        path: Option<String>,
    },
    /// Find catalog entries by basename glob.
    #[command(
        long_about = "Search local catalog file and directory names with a simple \
                      basename glob. Supports `*` for any sequence and `?` for one \
                      character. Matching is case-sensitive and catalog-only; Crow \
                      does not decrypt manifests or walk chunks.\n\
                      \n\
                      Examples:\n  \
                      crow find '*.md'\n  \
                      crow find 'report-??.pdf'"
    )]
    Find {
        /// Basename glob pattern. Slash-separated path globs are not supported.
        pattern: String,
    },
    /// Search file contents with a regex.
    #[command(
        long_about = "Resolve a catalog file, catalog directory, full crow1… capability, \
                      or pinned hash prefix; reconstruct file bytes; and print matching \
                      lines as TARGET:LINE:TEXT. Directory targets recurse through \
                      cataloged files. This decrypts and reads file contents, so use \
                      `crow find` for cheap name-only searches.\n\
                      \n\
                      Examples:\n  \
                      crow grep TODO /docs\n  \
                      crow grep '^version =' /configs/app.toml"
    )]
    Grep {
        /// Rust regex pattern to search for.
        pattern: String,
        /// Catalog path, full bech32m capability, or pinned hash prefix.
        cap_or_prefix: String,
    },
    /// Summarize logical and local stored size for a catalog path.
    #[command(
        long_about = "Show size usage for a catalog file or directory. Logical size is \
                      the sum of file sizes from manifests. Stored size is the unique \
                      local manifest/chunk bytes currently present for the referenced \
                      caps, so copied/shared caps are counted once for storage.\n\
                      \n\
                      Examples:\n  \
                      crow du\n  \
                      crow du /docs"
    )]
    Du {
        /// Optional catalog path. Defaults to /.
        path: Option<String>,
    },
    /// Create a local catalog directory.
    #[command(
        long_about = "Create a local catalog directory. Directories organize file caps \
                      on this device; they are not yet shareable Crow objects.\n\
                      \n\
                      Examples:\n  \
                      crow mkdir /docs\n  \
                      crow mkdir -p /docs/projects/crow"
    )]
    Mkdir {
        /// Catalog directory path.
        path: String,
        /// Create missing parent directories.
        #[arg(short, long)]
        parents: bool,
    },
    /// Import a local directory tree into the catalog.
    #[command(
        long_about = "Recursively store regular files from a local directory and record \
                      them under a local catalog directory. This is a bulk file import: \
                      folders are local organization, not shareable Crow objects.\n\
                      \n\
                      Symlinks are rejected. Crow asks for y/N confirmation before \
                      storing unless --yes is passed.\n\
                      \n\
                      Examples:\n  \
                      crow put-dir ./Photos /photos\n  \
                      crow put-dir ./Project /archive/ --yes"
    )]
    PutDir {
        /// Local directory to import.
        source: String,
        /// Optional catalog destination directory. Defaults to /<source-basename>.
        dest: Option<String>,
        /// Skip confirmation.
        #[arg(short, long)]
        yes: bool,
    },
    /// Export a catalog directory tree to the local filesystem.
    #[command(
        long_about = "Recursively reconstruct files from a local catalog directory into \
                      a regular filesystem directory. Existing files are never \
                      overwritten.\n\
                      \n\
                      If OUT exists and is non-empty, Crow asks for y/N confirmation \
                      unless --yes is passed.\n\
                      \n\
                      Examples:\n  \
                      crow get-dir /photos ./RestoredPhotos\n  \
                      crow get-dir /archive/project ./Project --yes"
    )]
    GetDir {
        /// Catalog directory to export.
        path: String,
        /// Local output directory.
        out: String,
        /// Skip confirmation for non-empty output directories.
        #[arg(short, long)]
        yes: bool,
    },
    /// Freeze a local catalog directory into a shareable directory cap.
    #[command(
        long_about = "Build an immutable snapshot manifest for a local catalog directory, \
                      store it, pin it, and print its crow1… capability. Directory caps \
                      are snapshots: later catalog edits do not change the cap.\n\
                      \n\
                      Examples:\n  \
                      crow cap-dir /photos\n  \
                      crow cap-dir /docs --name docs-snapshot"
    )]
    CapDir {
        /// Local catalog directory to snapshot.
        path: String,
        /// Friendly name for the pinned directory cap.
        #[arg(long)]
        name: Option<String>,
    },
    /// Attach a directory snapshot cap into the local catalog.
    #[command(
        long_about = "Import an immutable directory snapshot cap into the local catalog. \
                      The destination path must not already exist. Child file caps are \
                      recorded as normal catalog file entries; this does not create a \
                      live shared folder.\n\
                      \n\
                      Examples:\n  \
                      crow add-dir crow1qyq... /shared/photos\n  \
                      crow add-dir <prefix> /imports/docs"
    )]
    AddDir {
        /// Full directory cap or hash prefix of a pinned directory cap.
        cap_or_prefix: String,
        /// Catalog destination path to create.
        dest: String,
    },
    /// Pin a capability so its chunks survive `crow gc`.
    #[command(
        long_about = "Add a pin record for an externally-supplied capability — for \
                      example, a cap shared by another device or a friend. The chunks \
                      themselves still need to be present in the local store; pinning \
                      a cap whose chunks aren't yet local is harmless and won't fetch \
                      anything (Phase 1 step 2 will).\n\
                      \n\
                      `crow put` already auto-pins, so this command is mostly used \
                      after `crow unpin` (re-pin) or with caps acquired out of band."
    )]
    Pin {
        /// Full bech32m capability (`crow1…`) to pin.
        cap: String,
        /// Friendly name for the pin (shown in `crow ls`).
        #[arg(long)]
        name: Option<String>,
    },
    /// Drop a flat pin or catalog path. Chunks linger until `crow gc`.
    #[command(
        long_about = "Remove a flat pin record or detach a local catalog path. The \
                      chunks themselves stay in the store until `crow gc` sweeps them \
                      — so `unpin` is reversible if you still have the cap.\n\
                      \n\
                      Directories require -r/--recursive so an accidental `crow unpin \
                      /docs` does not detach a whole subtree silently.\n\
                      \n\
                      Use `crow rm` instead if you want the chunks gone immediately."
    )]
    Unpin {
        /// Catalog path, full bech32m capability, or hex prefix of a pinned manifest.
        cap_or_prefix: String,
        /// Recursively detach a catalog directory subtree.
        #[arg(short, long)]
        recursive: bool,
    },
    /// Remove a pin or catalog path AND immediately delete unreferenced chunks.
    #[command(
        long_about = "Remove the pin record or catalog path AND delete this manifest's \
                      chunks (those not also held by another pin or catalog path). \
                      Targeted, immediate, not deferred — the unix-style \"delete now.\"\n\
                      \n\
                      Use --dry-run to see what would be deleted before committing.\n\
                      \n\
                      Use `crow unpin` instead if you might want to re-pin later."
    )]
    Rm {
        /// Catalog path, full bech32m capability, or hex prefix of a pinned manifest.
        cap_or_prefix: String,
        /// Print what would be deleted without touching disk.
        #[arg(long)]
        dry_run: bool,
    },
    /// Move or rename a local catalog path.
    #[command(
        long_about = "Move or rename a local catalog file or directory. This only \
                      changes catalog organization; file caps and encrypted chunks do \
                      not change.\n\
                      \n\
                      Examples:\n  \
                      crow mv /docs/report.pdf /docs/archive/report.pdf\n  \
                      crow mv /docs/report.pdf /archive/"
    )]
    Mv {
        /// Existing catalog path.
        from: String,
        /// Destination catalog path, or existing directory.
        to: String,
    },
    /// Copy a file reference to another catalog path.
    #[command(
        long_about = "Create another local catalog entry pointing at the same file cap. \
                      This is metadata-only: encrypted chunks are not duplicated. The \
                      destination must be a catalog path, and existing entries are \
                      never overwritten.\n\
                      \n\
                      Examples:\n  \
                      crow cp /docs/report.pdf /archive/report.pdf\n  \
                      crow cp /docs/report.pdf /archive/\n  \
                      crow cp <prefix> /imports/from-friend.pdf"
    )]
    Cp {
        /// Source catalog path, full bech32m capability, or pinned hash prefix.
        src: String,
        /// Destination catalog path, or existing directory.
        dst: String,
    },
    /// Sweep every chunk and manifest not referenced by any pin or catalog path.
    #[command(
        long_about = "Walk every chunk and manifest in the store; delete anything not \
                      referenced by a current pin or catalog path. The catch-all \
                      complement to `crow rm` — cleans up after `crow unpin`, crashed \
                      puts, manually-removed pins, etc.\n\
                      \n\
                      --dry-run reports what would be freed without touching disk; \
                      run it first if you're not sure."
    )]
    Gc {
        /// Print what would be deleted without touching disk.
        #[arg(long)]
        dry_run: bool,
    },
    /// Show storage stats or detailed metadata for one target.
    #[command(
        long_about = "With no argument, print the storage path, object counts, pin \
                      count, catalog file count, and how much would be freed by `crow \
                      gc`. With a catalog path, capability, or hash prefix, print \
                      detailed metadata for that one file, directory, or cap.\n\
                      \n\
                      Examples:\n  \
                      crow stat\n  \
                      crow stat /docs/report.pdf\n  \
                      crow stat <prefix>"
    )]
    Stat {
        /// Optional catalog path, full bech32m capability, or pinned hash prefix.
        cap_or_prefix: Option<String>,
    },
    /// Serve local manifests and chunks to trusted cluster devices.
    #[command(
        long_about = "Start a long-running QUIC server that serves encrypted manifests \
                      and chunks by hash to clients with the shared cluster token.\n\
                      \n\
                      The server never sees cap keys or plaintext. Run `crow token init` \
                      first, then copy the token to another trusted device with \
                      `crow token set <TOKEN>`."
    )]
    Serve {
        /// Address to listen on.
        #[arg(long, default_value = DEFAULT_BIND_ADDR)]
        bind: SocketAddr,
        /// Friendly name advertised to other Crows on the LAN. Defaults to the
        /// OS hostname.
        #[arg(long)]
        name: Option<String>,
    },
    /// Fetch missing manifest/chunk shares from a known peer.
    #[command(
        long_about = "Connect to a trusted Crow peer, fetch the manifest and missing \
                      shares for a cap, pin it locally, and verify local reconstruction.\n\
                      \n\
                      The <PEER> argument accepts three forms, resolved in order:\n  \
                      1. An IP:port (e.g. 192.168.1.42:7070).\n  \
                      2. A hex prefix of a peer's node id (e.g. abc1) — looked up in \
                         the snapshot at <home>/peers.json.\n  \
                      3. A peer's exact friendly name (e.g. laptop) — also looked up \
                         in the snapshot.\n\
                      \n\
                      Forms 2 and 3 require `crow serve` to be running somewhere on \
                      the LAN (so a fresh peer snapshot exists). Ambiguous prefixes \
                      and unknown names get explicit errors with the candidate list."
    )]
    Fetch {
        /// Peer: IP:port, node-id hex prefix, or friendly name.
        peer: String,
        /// Full bech32m capability (`crow1…`) or hex prefix of a pinned manifest.
        cap_or_prefix: String,
        /// Friendly name for the local pin.
        #[arg(long)]
        name: Option<String>,
    },
    /// Fetch a cap from a peer, then optionally catalog it.
    #[command(
        long_about = "Receive a shared cap from a trusted peer. This wraps `crow fetch` \
                      and, if CATALOG_DEST is supplied, records the fetched file or \
                      directory snapshot in the local catalog.\n\
                      \n\
                      Examples:\n  \
                      crow receive laptop crow1qyq... /docs/report.pdf\n  \
                      crow receive laptop crow1qyq... /imports/docs\n  \
                      crow receive 192.168.1.42:7070 crow1qyq... --name report.pdf"
    )]
    Receive {
        /// Peer: IP:port, node-id hex prefix, or friendly name.
        peer: String,
        /// Full bech32m capability (`crow1…`) or hex prefix of a pinned manifest.
        cap_or_prefix: String,
        /// Optional catalog destination path.
        catalog_dest: Option<String>,
        /// Friendly name for the local pin and directory destination inference.
        #[arg(long)]
        name: Option<String>,
    },
    /// List discovered LAN peers from the most recent `crow serve` snapshot.
    #[command(
        long_about = "Read <home>/peers.json — the snapshot a running `crow serve` \
                      writes every five seconds — and print every node it has seen \
                      via mDNS recently. Default columns: 16-char node id, friendly \
                      name, address, last-seen age. Use --long for the full hex id \
                      and ISO timestamps; --json for machine-readable output.\n\
                      \n\
                      If `crow serve` is not running, `crow peers` reports the absent \
                      snapshot rather than scanning the LAN itself. Start a daemon to \
                      populate the snapshot."
    )]
    Peers {
        /// Show full hex node ids and ISO timestamps.
        #[arg(short, long)]
        long: bool,
        /// Emit the snapshot as pretty JSON.
        #[arg(long)]
        json: bool,
    },
    /// Show or set this device's local Crow identity metadata.
    #[command(
        long_about = "Show this device's Crow identity, friendly name, token status, \
                      and peer snapshot status. Use `crow device name <NAME>` to set \
                      the friendly name advertised by `crow serve` on the LAN.\n\
                      \n\
                      Friendly names are local convenience metadata. They are never \
                      embedded in caps and are only advertised while `crow serve` is \
                      running."
    )]
    Device {
        #[command(subcommand)]
        command: Option<DeviceCommand>,
    },
    /// Initialize this device for personal-cluster use.
    #[command(
        long_about = "Create the local Crow identity if missing, configure an optional \
                      friendly device name, and create or import the shared \
                      personal-cluster token. This is a convenience wrapper around \
                      `crow device name`, `crow token init`, and `crow token set`.\n\
                      \n\
                      Examples:\n  \
                      crow setup --name laptop\n  \
                      crow setup --name phone --token <64-hex-token>"
    )]
    Setup {
        /// Persist a friendly name advertised by `crow serve`.
        #[arg(long)]
        name: Option<String>,
        /// Store a token copied from another trusted device.
        #[arg(long)]
        token: Option<String>,
        /// Replace an existing local token with a newly generated one.
        #[arg(long)]
        force_token: bool,
    },
    /// Manage the shared personal-cluster token.
    #[command(subcommand)]
    Token(TokenCommand),
}

#[derive(Subcommand)]
enum DeviceCommand {
    /// Persist the friendly name advertised by `crow serve`.
    Name {
        /// Short command-safe device name, e.g. laptop, phone, macbook-air.
        name: String,
    },
}

#[derive(Subcommand)]
enum TokenCommand {
    /// Create a token if one does not exist.
    Init {
        /// Replace an existing token.
        #[arg(long)]
        force: bool,
    },
    /// Print the local token.
    Show,
    /// Store a token copied from another trusted device.
    Set {
        /// 64-character hex cluster token.
        token: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("crow: {e}");
            ExitCode::FAILURE
        }
    }
}

type DynError = Box<dyn std::error::Error + Send + Sync>;
type DynResult<T> = std::result::Result<T, DynError>;

const DEVICE_CONFIG_FILE: &str = "device.json";

#[derive(Clone, Copy)]
struct StoreContext<'a> {
    home: &'a Path,
    crow: &'a Crow<FsStore>,
    pins: &'a PinIndex,
    catalog: &'a CatalogIndex,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct DeviceConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    name: Option<String>,
}

impl DeviceConfig {
    fn load(home: &Path) -> DynResult<Self> {
        let path = device_config_path(home);
        match fs::read(&path) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)
                .map_err(|e| format!("decode {}: {e}", path.display()))?),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(format!("read {}: {e}", path.display()).into()),
        }
    }

    fn save(&self, home: &Path) -> DynResult<()> {
        let path = device_config_path(home);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_vec_pretty(self)
            .map_err(|e| format!("encode {}: {e}", path.display()))?;
        fs::write(&path, json)?;
        Ok(())
    }
}

fn device_config_path(home: &Path) -> PathBuf {
    home.join(DEVICE_CONFIG_FILE)
}

fn validate_device_name(name: &str) -> DynResult<String> {
    let name = name.trim();
    if name.is_empty() {
        return Err("device name cannot be empty".into());
    }
    if name.len() > 32 {
        return Err("device name must be 32 characters or fewer".into());
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(
            "device name may only contain ASCII letters, numbers, '-', '_', and '.'".into(),
        );
    }
    Ok(name.to_string())
}

fn sanitize_device_name(name: &str) -> Option<String> {
    let mut out = String::new();
    let mut last_was_sep = false;
    for b in name.bytes() {
        let c = if b.is_ascii_alphanumeric() {
            last_was_sep = false;
            b as char
        } else if matches!(b, b'-' | b'_' | b'.') {
            if last_was_sep {
                continue;
            }
            last_was_sep = true;
            b as char
        } else {
            if last_was_sep {
                continue;
            }
            last_was_sep = true;
            '-'
        };
        out.push(c);
        if out.len() == 32 {
            break;
        }
    }
    let out = out
        .trim_matches(|c| matches!(c, '-' | '_' | '.'))
        .to_string();
    if out.is_empty() { None } else { Some(out) }
}

fn default_setup_name() -> Option<String> {
    default_friendly_name().and_then(|name| sanitize_device_name(&name))
}

fn configured_friendly_name(home: &Path) -> DynResult<Option<String>> {
    Ok(DeviceConfig::load(home)?.name)
}

fn resolve_serve_name(home: &Path, name_override: Option<String>) -> DynResult<Option<String>> {
    Ok(name_override
        .map(|name| validate_device_name(&name))
        .transpose()?
        .or(configured_friendly_name(home)?)
        .or_else(default_friendly_name))
}

fn run(cli: Cli) -> DynResult<()> {
    let home = resolve_home(cli.home)?;
    match cli.command {
        Command::Device { command } => cmd_device(&home, command),
        Command::Setup {
            name,
            token,
            force_token,
        } => cmd_setup(&home, name, token, force_token),
        Command::Token(command) => cmd_token(&home, command),
        Command::Serve { bind, name } => {
            let store = FsStore::open(&home)?;
            cmd_serve(&home, store, bind, name)
        }
        Command::Peers { long, json } => cmd_peers(&home, long, json),
        command => {
            let store = FsStore::open(&home)?;
            let pins = PinIndex::open(&home)?;
            let catalog = CatalogIndex::open(&home)?;
            let crow = Crow::new(store);

            match command {
                Command::Put {
                    path,
                    dest,
                    mime,
                    name,
                    chunk_size,
                } => cmd_put(
                    &crow,
                    &pins,
                    &catalog,
                    &Identity::load_or_create(&home)?,
                    PutArgs {
                        path: &path,
                        dest: dest.as_deref(),
                        mime,
                        name,
                        chunk_size,
                    },
                ),
                Command::Get { cap_or_prefix, out } => {
                    cmd_get(&crow, &pins, &catalog, &cap_or_prefix, &out)
                }
                Command::Cat { cap_or_prefix } => cmd_cat(&crow, &pins, &catalog, &cap_or_prefix),
                Command::Cap { cap_or_prefix } => cmd_cap(&pins, &catalog, &cap_or_prefix),
                Command::Share {
                    cap_or_prefix,
                    name,
                    plain,
                } => {
                    let identity = Identity::load_or_create(&home)?;
                    cmd_share(
                        StoreContext {
                            home: &home,
                            crow: &crow,
                            pins: &pins,
                            catalog: &catalog,
                        },
                        &identity,
                        ShareCliRequest {
                            arg: &cap_or_prefix,
                            name,
                            plain,
                        },
                    )
                }
                Command::Info { cap_or_prefix } => cmd_info(&crow, &pins, &catalog, &cap_or_prefix),
                Command::Ls {
                    path,
                    long,
                    pins: pins_only,
                } => cmd_ls(&crow, &pins, &catalog, path.as_deref(), long, pins_only),
                Command::Tree { path } => cmd_tree(&catalog, path.as_deref()),
                Command::Find { pattern } => cmd_find(&catalog, &pattern),
                Command::Grep {
                    pattern,
                    cap_or_prefix,
                } => cmd_grep(&crow, &pins, &catalog, &pattern, &cap_or_prefix),
                Command::Du { path } => cmd_du(&crow, &catalog, path.as_deref()),
                Command::Mkdir { path, parents } => cmd_mkdir(&catalog, &path, parents),
                Command::PutDir { source, dest, yes } => cmd_put_dir(
                    &crow,
                    &catalog,
                    &Identity::load_or_create(&home)?,
                    &source,
                    dest.as_deref(),
                    yes,
                ),
                Command::GetDir { path, out, yes } => {
                    cmd_get_dir(&crow, &pins, &catalog, &path, &out, yes)
                }
                Command::CapDir { path, name } => cmd_cap_dir(
                    &crow,
                    &pins,
                    &catalog,
                    &Identity::load_or_create(&home)?,
                    &path,
                    name,
                ),
                Command::AddDir {
                    cap_or_prefix,
                    dest,
                } => cmd_add_dir(&crow, &pins, &catalog, &cap_or_prefix, &dest),
                Command::Pin { cap, name } => cmd_pin(&pins, &cap, name),
                Command::Unpin {
                    cap_or_prefix,
                    recursive,
                } => cmd_unpin(&pins, &catalog, &cap_or_prefix, recursive),
                Command::Rm {
                    cap_or_prefix,
                    dry_run,
                } => cmd_rm(&crow, &pins, &catalog, &cap_or_prefix, dry_run),
                Command::Mv { from, to } => cmd_mv(&catalog, &from, &to),
                Command::Cp { src, dst } => cmd_cp(&pins, &catalog, &src, &dst),
                Command::Gc { dry_run } => cmd_gc(&crow, &pins, &catalog, dry_run),
                Command::Stat { cap_or_prefix } => {
                    cmd_stat(&crow, &pins, &catalog, cap_or_prefix.as_deref())
                }
                Command::Fetch {
                    peer,
                    cap_or_prefix,
                    name,
                } => cmd_fetch(&home, &crow, &pins, &peer, &cap_or_prefix, name),
                Command::Receive {
                    peer,
                    cap_or_prefix,
                    catalog_dest,
                    name,
                } => cmd_receive(
                    StoreContext {
                        home: &home,
                        crow: &crow,
                        pins: &pins,
                        catalog: &catalog,
                    },
                    ReceiveCliRequest {
                        peer: &peer,
                        arg: &cap_or_prefix,
                        dest: catalog_dest.as_deref(),
                        name,
                    },
                ),
                Command::Serve { .. }
                | Command::Peers { .. }
                | Command::Device { .. }
                | Command::Setup { .. }
                | Command::Token(_) => {
                    unreachable!("handled above")
                }
            }
        }
    }
}

fn resolve_home(explicit: Option<PathBuf>) -> DynResult<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p);
    }
    let home = std::env::var("HOME").map_err(|_| "HOME is not set; pass --home")?;
    Ok(PathBuf::from(home).join(".crow"))
}

struct PutArgs<'a> {
    path: &'a str,
    dest: Option<&'a str>,
    mime: Option<String>,
    name: Option<String>,
    chunk_size: Option<u32>,
}

fn cmd_put(
    crow: &Crow<FsStore>,
    pins: &PinIndex,
    catalog: &CatalogIndex,
    identity: &Identity,
    args: PutArgs<'_>,
) -> DynResult<()> {
    let catalog_dest = args
        .dest
        .map(|dest| resolve_put_destination(catalog, args.path, dest))
        .transpose()?;
    let bytes = read_all(args.path)?;
    let mime_str = args
        .mime
        .unwrap_or_else(|| guess_mime(args.path).to_string());
    let chunk_size = args
        .chunk_size
        .unwrap_or_else(|| auto_chunk_size(bytes.len()));

    let cap = crow.put_bytes_with(
        &bytes,
        &mime_str,
        ErasureParams::default(),
        chunk_size,
        identity,
    )?;
    let pin_name = args.name.or_else(|| default_name(args.path));
    if let Some(catalog_path) = catalog_dest {
        catalog.put_file(catalog_path.as_str(), cap.clone(), pin_name)?;
        println!("path {}", catalog_path);
    } else {
        pins.add(cap.clone(), pin_name, None)?;
    }
    println!("{}", cap.encode());
    Ok(())
}

fn cmd_get(
    crow: &Crow<FsStore>,
    pins: &PinIndex,
    catalog: &CatalogIndex,
    arg: &str,
    out: &str,
) -> DynResult<()> {
    let target = resolve_file_ref(catalog, pins, arg)?;
    let cap = target.cap;
    let bytes = crow.get_bytes(&cap)?;
    write_all(out, &bytes)?;
    Ok(())
}

fn cmd_cat(
    crow: &Crow<FsStore>,
    pins: &PinIndex,
    catalog: &CatalogIndex,
    arg: &str,
) -> DynResult<()> {
    let bytes = cat_bytes(crow, pins, catalog, arg)?;
    io::stdout().lock().write_all(&bytes)?;
    Ok(())
}

fn cat_bytes(
    crow: &Crow<FsStore>,
    pins: &PinIndex,
    catalog: &CatalogIndex,
    arg: &str,
) -> DynResult<Vec<u8>> {
    let target = resolve_file_ref(catalog, pins, arg)?;
    match crow.open_manifest_kind(&target.cap)? {
        ManifestKind::File(_) => Ok(crow.get_bytes(&target.cap)?),
        ManifestKind::Directory(_) => Err(format!("{} is a directory", arg.trim()).into()),
    }
}

fn cmd_cap(pins: &PinIndex, catalog: &CatalogIndex, arg: &str) -> DynResult<()> {
    println!("{}", cap_for_target(pins, catalog, arg)?.encode());
    Ok(())
}

fn cap_for_target(pins: &PinIndex, catalog: &CatalogIndex, arg: &str) -> DynResult<Cap> {
    let raw = arg.trim();
    if !raw.starts_with("crow1") {
        if let Ok(path) = CatalogPath::normalize(raw) {
            let view = catalog.view()?;
            if let Some(entry) = view.get(&path) {
                return match &entry.kind {
                    EntryKind::File { cap, .. } => Ok(cap.clone()),
                    EntryKind::Dir => Err(format!(
                        "{path} is a catalog directory; use `crow share {path}` or `crow cap-dir {path}` to create an immutable directory snapshot cap"
                    )
                    .into()),
                };
            }
            if raw.starts_with('/') {
                return Err(format!("catalog path not found: {path}").into());
            }
        }
    }

    Ok(resolve_file_ref(catalog, pins, raw)?.cap)
}

#[derive(Debug, PartialEq, Eq)]
enum ShareKind {
    File,
    DirectorySnapshot,
    Cap,
}

#[derive(Debug)]
struct ShareReport {
    kind: ShareKind,
    cap: Cap,
    suggested_dest: Option<CatalogPath>,
    token_configured: bool,
}

struct ShareRequest<'a> {
    arg: &'a str,
    name: Option<String>,
}

struct ShareCliRequest<'a> {
    arg: &'a str,
    name: Option<String>,
    plain: bool,
}

fn cmd_share(
    ctx: StoreContext<'_>,
    identity: &Identity,
    request: ShareCliRequest<'_>,
) -> DynResult<()> {
    let report = share_target(
        ctx.home,
        ctx.crow,
        ctx.pins,
        ctx.catalog,
        identity,
        ShareRequest {
            arg: request.arg,
            name: request.name,
        },
    )?;
    if request.plain {
        println!("{}", report.cap.encode());
        return Ok(());
    }

    println!("type      {}", share_kind_label(&report.kind));
    println!("cap       {}", report.cap.encode());
    if report.token_configured {
        println!("token     configured");
    } else {
        println!("token     missing (run `crow setup` before LAN fetch)");
    }
    let receive_dest = report
        .suggested_dest
        .as_ref()
        .map(|path| format!(" {path}"))
        .unwrap_or_default();
    println!(
        "receive   crow receive <peer> {}{}",
        report.cap.encode(),
        receive_dest
    );
    Ok(())
}

fn share_target(
    home: &Path,
    crow: &Crow<FsStore>,
    pins: &PinIndex,
    catalog: &CatalogIndex,
    identity: &Identity,
    request: ShareRequest<'_>,
) -> DynResult<ShareReport> {
    let token_configured = TokenStore::open(home).exists();
    let raw = request.arg.trim();
    if !raw.starts_with("crow1") {
        if let Ok(path) = CatalogPath::normalize(raw) {
            let view = catalog.view()?;
            if let Some(entry) = view.get(&path) {
                return match &entry.kind {
                    EntryKind::File { cap, .. } => Ok(ShareReport {
                        kind: ShareKind::File,
                        cap: cap.clone(),
                        suggested_dest: Some(path),
                        token_configured,
                    }),
                    EntryKind::Dir => {
                        let manifest = directory_manifest_from_catalog(&view, &path)?;
                        let cap = crow.put_directory_manifest(&manifest, identity)?;
                        let pin_name = request.name.or_else(|| directory_snapshot_name(&path));
                        pins.add(cap.clone(), pin_name, None)?;
                        Ok(ShareReport {
                            kind: ShareKind::DirectorySnapshot,
                            cap,
                            suggested_dest: Some(path),
                            token_configured,
                        })
                    }
                };
            }
            if raw.starts_with('/') {
                return Err(format!("catalog path not found: {path}").into());
            }
        }
    }

    Ok(ShareReport {
        kind: ShareKind::Cap,
        cap: resolve_file_ref(catalog, pins, raw)?.cap,
        suggested_dest: None,
        token_configured,
    })
}

fn share_kind_label(kind: &ShareKind) -> &'static str {
    match kind {
        ShareKind::File => "file",
        ShareKind::DirectorySnapshot => "directory snapshot",
        ShareKind::Cap => "cap",
    }
}

fn cmd_info(
    crow: &Crow<FsStore>,
    pins: &PinIndex,
    catalog: &CatalogIndex,
    arg: &str,
) -> DynResult<()> {
    let target = resolve_file_ref(catalog, pins, arg)?;
    let path = target.path;
    let cap = target.cap;

    if let Some(path) = &path {
        println!("path      {path}");
    }
    println!("hash      {}", cap.manifest_hash);
    match crow.open_manifest_kind(&cap)? {
        ManifestKind::File(manifest) => {
            let stripes = manifest.stripes.len();
            let shares: usize = manifest
                .stripes
                .iter()
                .map(|s| s.data.len() + s.parity.len())
                .sum();

            println!("type      file");
            println!("size      {}", format_size(manifest.file_size as usize));
            println!("mime      {}", manifest.mime_type);
            println!("erasure   {}-of-{}", manifest.erasure.k, manifest.erasure.n);
            println!("stripes   {stripes}");
            println!("shares    {shares}");
            println!(
                "chunk     {} ({})",
                manifest.chunk_size,
                format_size(manifest.chunk_size as usize)
            );
            println!("created   {}", format_iso_timestamp(manifest.created_at));
            println!(
                "algo      {:?} / {:?} / {:?}",
                manifest.algorithm.aead, manifest.algorithm.kdf, manifest.algorithm.erasure_code
            );
            print_signature_status(manifest.signature_status()?);
        }
        ManifestKind::Directory(manifest) => {
            println!("type      directory snapshot");
            println!("files     {}", manifest.file_count());
            println!("dirs      {}", manifest.dir_count());
            match directory_logical_size(crow, &manifest)? {
                Some(bytes) => println!("size      {}", format_size_u64(bytes)),
                None => println!("size      unknown (missing child manifests)"),
            }
            println!("created   {}", format_iso_timestamp(manifest.created_at));
            print_signature_status(manifest.signature_status()?);
        }
    }

    if let Some(rec) = pins.get(cap.manifest_hash.inner())? {
        let name = rec.name.as_deref().unwrap_or("(unnamed)");
        println!(
            "pinned    {} ({})",
            format_iso_timestamp(rec.pinned_at),
            name
        );
    } else {
        println!("pinned    no");
    }
    if path.is_some() {
        println!("cataloged yes");
    }
    Ok(())
}

fn print_signature_status(status: SignatureStatus) {
    println!("{}", format_signature_status(status));
}

fn format_signature_status(status: SignatureStatus) -> String {
    match status {
        SignatureStatus::Unsigned => "signed    no (legacy/unsigned)".into(),
        SignatureStatus::Signed { creator } => format!("signed    yes ({})", creator.short()),
    }
}

fn cmd_ls(
    crow: &Crow<FsStore>,
    pins: &PinIndex,
    catalog: &CatalogIndex,
    path: Option<&str>,
    long: bool,
    pins_only: bool,
) -> DynResult<()> {
    if pins_only {
        return cmd_ls_pins(crow, pins, long);
    }

    let view = catalog.view()?;
    let root = CatalogPath::root();
    if let Some(path) = path {
        let path = CatalogPath::normalize(path)?;
        return print_catalog_listing(crow, &view, &path, long);
    }

    if !view.list(&root).is_empty() {
        print_catalog_listing(crow, &view, &root, long)
    } else {
        cmd_ls_pins(crow, pins, long)
    }
}

fn cmd_ls_pins(crow: &Crow<FsStore>, pins: &PinIndex, long: bool) -> DynResult<()> {
    let mut records = pins.list()?;
    records.sort_by(|a, b| {
        b.pinned_at
            .cmp(&a.pinned_at)
            .then_with(|| a.manifest_hash_hex.cmp(&b.manifest_hash_hex))
    });
    if records.is_empty() {
        println!("(no pinned files)");
        return Ok(());
    }

    if long {
        println!(
            "{:<64}  {:>10}  {:<22}  {:<20}  NAME",
            "HASH", "SIZE", "MIME", "PINNED"
        );
        for r in &records {
            let (size, mime) = pin_listing_metadata(crow, &r.cap, true)?;
            let pinned = format_iso_timestamp(r.pinned_at);
            let name = r.name.as_deref().unwrap_or("(unnamed)");
            println!(
                "{}  {:>10}  {:<22}  {:<20}  {}",
                r.manifest_hash_hex,
                size,
                truncate(&mime, 22),
                pinned,
                name,
            );
        }
    } else {
        println!(
            "{:<8}  {:>10}  {:<18}  {:<10}  NAME",
            "HASH", "SIZE", "MIME", "PINNED"
        );
        for r in &records {
            let hash_short = &r.manifest_hash_hex[..8];
            let (size, mime) = pin_listing_metadata(crow, &r.cap, false)?;
            let mime = truncate(&mime, 18);
            let pinned = format_short_date(r.pinned_at);
            let name = r.name.as_deref().unwrap_or("(unnamed)");
            println!("{hash_short}  {size:>10}  {mime:<18}  {pinned:<10}  {name}");
        }
    }
    Ok(())
}

fn cmd_tree(catalog: &CatalogIndex, path: Option<&str>) -> DynResult<()> {
    let view = catalog.view()?;
    let root = match path {
        Some(path) => CatalogPath::normalize(path)?,
        None => CatalogPath::root(),
    };
    for line in catalog_tree_lines(&view, &root)? {
        println!("{line}");
    }
    Ok(())
}

fn catalog_tree_lines(view: &CatalogView, root: &CatalogPath) -> DynResult<Vec<String>> {
    let Some(entry) = view.get(root) else {
        return Err(format!("catalog path not found: {root}").into());
    };

    let mut lines = vec![catalog_tree_label(entry, true)];
    if entry.is_dir() {
        append_catalog_tree_children(view, root, "", &mut lines);
    }
    Ok(lines)
}

fn append_catalog_tree_children(
    view: &CatalogView,
    parent: &CatalogPath,
    prefix: &str,
    lines: &mut Vec<String>,
) {
    let children = view.list(parent);
    let count = children.len();
    for (idx, child) in children.into_iter().enumerate() {
        let is_last = idx + 1 == count;
        let connector = if is_last { "`-- " } else { "|-- " };
        lines.push(format!(
            "{prefix}{connector}{}",
            catalog_tree_label(child, false)
        ));
        if child.is_dir() {
            let next_prefix = if is_last {
                format!("{prefix}    ")
            } else {
                format!("{prefix}|   ")
            };
            append_catalog_tree_children(view, &child.path, &next_prefix, lines);
        }
    }
}

fn catalog_tree_label(entry: &CatalogEntry, is_root: bool) -> String {
    match &entry.kind {
        EntryKind::Dir => {
            if is_root {
                if entry.path.as_str() == "/" {
                    "/".into()
                } else {
                    format!("{}/", entry.path)
                }
            } else {
                format!("{}/", entry.path.file_name().unwrap_or(entry.path.as_str()))
            }
        }
        EntryKind::File { .. } => {
            if is_root {
                entry.path.as_str().to_string()
            } else {
                entry
                    .path
                    .file_name()
                    .map(str::to_string)
                    .unwrap_or_else(|| entry.path.as_str().to_string())
            }
        }
    }
}

fn cmd_find(catalog: &CatalogIndex, pattern: &str) -> DynResult<()> {
    let view = catalog.view()?;
    let matches = catalog_find_matches(&view, pattern)?;
    for path in matches {
        println!("{path}");
    }
    Ok(())
}

fn catalog_find_matches(view: &CatalogView, pattern: &str) -> DynResult<Vec<CatalogPath>> {
    let pattern = pattern.trim();
    if pattern.is_empty() {
        return Err("find pattern must not be empty".into());
    }
    if pattern.contains('/') {
        return Err("crow find matches basenames only; omit '/' from the pattern".into());
    }

    let root = CatalogPath::root();
    let mut stack = view.list(&root);
    let mut out = Vec::new();
    while let Some(entry) = stack.pop() {
        if let Some(name) = entry.path.file_name()
            && simple_glob_matches(pattern, name)
        {
            out.push(entry.path.clone());
        }
        if entry.is_dir() {
            stack.extend(view.list(&entry.path));
        }
    }
    out.sort();
    Ok(out)
}

fn simple_glob_matches(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    let mut dp = vec![vec![false; text.len() + 1]; pattern.len() + 1];
    dp[0][0] = true;
    for i in 1..=pattern.len() {
        if pattern[i - 1] == '*' {
            dp[i][0] = dp[i - 1][0];
        }
    }
    for i in 1..=pattern.len() {
        for j in 1..=text.len() {
            dp[i][j] = match pattern[i - 1] {
                '*' => dp[i - 1][j] || dp[i][j - 1],
                '?' => dp[i - 1][j - 1],
                c => c == text[j - 1] && dp[i - 1][j - 1],
            };
        }
    }
    dp[pattern.len()][text.len()]
}

#[derive(Debug, PartialEq, Eq)]
struct GrepMatch {
    display: String,
    line: usize,
    text: String,
}

#[derive(Debug, PartialEq, Eq)]
struct GrepReport {
    matches: Vec<GrepMatch>,
    errors: Vec<String>,
}

struct GrepTarget {
    display: String,
    cap: Cap,
}

fn cmd_grep(
    crow: &Crow<FsStore>,
    pins: &PinIndex,
    catalog: &CatalogIndex,
    pattern: &str,
    arg: &str,
) -> DynResult<()> {
    let report = grep_report(crow, pins, catalog, pattern, arg)?;
    for hit in &report.matches {
        println!("{}:{}:{}", hit.display, hit.line, hit.text);
    }
    for error in &report.errors {
        eprintln!("crow grep: {error}");
    }
    if report.errors.is_empty() {
        Ok(())
    } else {
        Err(format!("grep failed for {} file(s)", report.errors.len()).into())
    }
}

fn grep_report(
    crow: &Crow<FsStore>,
    pins: &PinIndex,
    catalog: &CatalogIndex,
    pattern: &str,
    arg: &str,
) -> DynResult<GrepReport> {
    let regex = Regex::new(pattern)?;
    let targets = grep_targets(catalog, pins, arg)?;
    let mut matches = Vec::new();
    let mut errors = Vec::new();

    for target in targets {
        let bytes = match grep_file_bytes(crow, &target.cap) {
            Ok(bytes) => bytes,
            Err(e) => {
                errors.push(format!("{}: {e}", target.display));
                continue;
            }
        };
        let text = String::from_utf8_lossy(&bytes);
        for (idx, line) in text.lines().enumerate() {
            if regex.is_match(line) {
                matches.push(GrepMatch {
                    display: target.display.clone(),
                    line: idx + 1,
                    text: line.to_string(),
                });
            }
        }
    }

    Ok(GrepReport { matches, errors })
}

fn grep_targets(catalog: &CatalogIndex, pins: &PinIndex, arg: &str) -> DynResult<Vec<GrepTarget>> {
    let raw = arg.trim();
    let view = catalog.view()?;
    if !raw.starts_with("crow1") {
        if let Ok(path) = CatalogPath::normalize(raw) {
            if let Some(entry) = view.get(&path) {
                return match &entry.kind {
                    EntryKind::Dir => Ok(catalog_subtree_entries(&view, &path)
                        .into_iter()
                        .filter_map(|entry| match &entry.kind {
                            EntryKind::File { cap, .. } => Some(GrepTarget {
                                display: entry.path.to_string(),
                                cap: cap.clone(),
                            }),
                            EntryKind::Dir => None,
                        })
                        .collect()),
                    EntryKind::File { cap, .. } => Ok(vec![GrepTarget {
                        display: path.to_string(),
                        cap: cap.clone(),
                    }]),
                };
            }
            if raw.starts_with('/') {
                return Err(format!("catalog path not found: {path}").into());
            }
        }
    }

    let target = resolve_file_ref(catalog, pins, raw)?;
    let display = target
        .path
        .map(|path| path.to_string())
        .unwrap_or_else(|| target.cap.manifest_hash.to_string()[..12].to_string());
    Ok(vec![GrepTarget {
        display,
        cap: target.cap,
    }])
}

fn grep_file_bytes(crow: &Crow<FsStore>, cap: &Cap) -> DynResult<Vec<u8>> {
    match crow.open_manifest_kind(cap)? {
        ManifestKind::File(_) => Ok(crow.get_bytes(cap)?),
        ManifestKind::Directory(_) => Err("is a directory snapshot".into()),
    }
}

#[derive(Debug, PartialEq, Eq)]
struct DuReport {
    path: CatalogPath,
    files: usize,
    directories: usize,
    logical_bytes: u64,
    unknown_files: usize,
    stored_manifests: usize,
    stored_chunks: usize,
    stored_bytes: u64,
}

fn cmd_du(crow: &Crow<FsStore>, catalog: &CatalogIndex, path: Option<&str>) -> DynResult<()> {
    let view = catalog.view()?;
    let path = match path {
        Some(path) => CatalogPath::normalize(path)?,
        None => CatalogPath::root(),
    };
    let report = catalog_du_report(crow, &view, &path)?;
    for line in format_du_report(&report) {
        println!("{line}");
    }
    Ok(())
}

fn catalog_du_report(
    crow: &Crow<FsStore>,
    view: &CatalogView,
    path: &CatalogPath,
) -> DynResult<DuReport> {
    let Some(entry) = view.get(path) else {
        return Err(format!("catalog path not found: {path}").into());
    };

    let entries: Vec<&CatalogEntry> = if entry.is_dir() {
        catalog_subtree_entries(view, path)
            .into_iter()
            .filter(|entry| matches!(entry.kind, EntryKind::File { .. }))
            .collect()
    } else {
        vec![entry]
    };

    let mut caps = Vec::new();
    let mut logical_bytes = 0u64;
    let mut unknown_files = 0usize;
    for entry in &entries {
        let Some(cap) = entry.cap() else {
            continue;
        };
        caps.push(cap.clone());
        match cap_logical_size(crow, cap)? {
            Some(bytes) => logical_bytes = logical_bytes.saturating_add(bytes),
            None => unknown_files += 1,
        }
    }

    let live = compute_live_set(crow.store(), &caps)?;
    let stored_manifests = live
        .iter()
        .filter(|(namespace, _)| *namespace == Namespace::Manifests)
        .count();
    let stored_chunks = live
        .iter()
        .filter(|(namespace, _)| *namespace == Namespace::Chunks)
        .count();
    let stored_bytes = live
        .iter()
        .filter_map(|(namespace, hash)| crow.store().size(*namespace, hash).ok().flatten())
        .sum();

    Ok(DuReport {
        path: path.clone(),
        files: entries.len(),
        directories: if entry.is_dir() {
            catalog_subtree_entries(view, path)
                .into_iter()
                .filter(|entry| entry.is_dir())
                .count()
        } else {
            0
        },
        logical_bytes,
        unknown_files,
        stored_manifests,
        stored_chunks,
        stored_bytes,
    })
}

fn cap_logical_size(crow: &Crow<FsStore>, cap: &Cap) -> DynResult<Option<u64>> {
    match crow.open_manifest_kind(cap) {
        Ok(ManifestKind::File(manifest)) => Ok(Some(manifest.file_size)),
        Ok(ManifestKind::Directory(manifest)) => directory_logical_size(crow, &manifest),
        Err(_) => Ok(None),
    }
}

fn format_du_report(report: &DuReport) -> Vec<String> {
    let mut lines = vec![
        format!("path          {}", report.path),
        format!("files         {}", report.files),
        format!("directories   {}", report.directories),
        format!("logical       {}", format_size_u64(report.logical_bytes)),
        format!("stored        {}", format_size_u64(report.stored_bytes)),
        format!(
            "objects       {} manifest{} / {} chunk{}",
            report.stored_manifests,
            if report.stored_manifests == 1 {
                ""
            } else {
                "s"
            },
            report.stored_chunks,
            if report.stored_chunks == 1 { "" } else { "s" },
        ),
    ];
    if report.unknown_files > 0 {
        lines.push(format!(
            "unknown       {} file{}",
            report.unknown_files,
            if report.unknown_files == 1 { "" } else { "s" }
        ));
    }
    lines
}

fn pin_listing_metadata(
    crow: &Crow<FsStore>,
    cap: &Cap,
    long: bool,
) -> DynResult<(String, String)> {
    match crow.open_manifest_kind(cap)? {
        ManifestKind::File(manifest) => Ok((
            format_size(manifest.file_size as usize),
            manifest.mime_type.to_string(),
        )),
        ManifestKind::Directory(manifest) => {
            let size = match directory_logical_size(crow, &manifest)? {
                Some(bytes) => format_size_u64(bytes),
                None if long => "unknown".into(),
                None => "?".into(),
            };
            Ok((size, "directory".into()))
        }
    }
}

fn cmd_mkdir(catalog: &CatalogIndex, path: &str, parents: bool) -> DynResult<()> {
    let path = CatalogPath::normalize(path)?;
    let events = catalog.mkdir(path.as_str(), parents)?;
    if events.is_empty() {
        println!("exists {path}");
    } else {
        println!("created {path}");
    }
    Ok(())
}

fn cmd_put_dir(
    crow: &Crow<FsStore>,
    catalog: &CatalogIndex,
    identity: &Identity,
    source: &str,
    dest: Option<&str>,
    yes: bool,
) -> DynResult<()> {
    let source_path = Path::new(source);
    if !source_path.is_dir() {
        return Err(format!("not a directory: {}", source_path.display()).into());
    }

    let dest_path = resolve_put_dir_destination(catalog, source_path, dest)?;
    let plan = scan_import_dir(source_path)?;
    confirm(
        &format!(
            "Import {} file{} / {} director{} ({}) into {dest_path}? [y/N] ",
            plan.files.len(),
            if plan.files.len() == 1 { "" } else { "s" },
            plan.dirs.len() + 1,
            if plan.dirs.len() + 1 == 1 { "y" } else { "ies" },
            format_size_u64(plan.bytes),
        ),
        yes,
    )?;

    catalog.mkdir(dest_path.as_str(), true)?;
    for dir in &plan.dirs {
        let path = join_catalog_relative(&dest_path, dir)?;
        catalog.mkdir(path.as_str(), true)?;
    }

    for file in &plan.files {
        let bytes = fs::read(&file.source)?;
        let source_name = file
            .source
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::to_string);
        let catalog_path = join_catalog_relative(&dest_path, &file.relative)?;
        let mime = guess_mime_path(&file.source).to_string();
        let cap = crow.put_bytes_with(
            &bytes,
            &mime,
            ErasureParams::default(),
            auto_chunk_size(bytes.len()),
            identity,
        )?;
        catalog.put_file(catalog_path.as_str(), cap, source_name)?;
    }

    println!(
        "stored {} file{} under {dest_path}",
        plan.files.len(),
        if plan.files.len() == 1 { "" } else { "s" },
    );
    Ok(())
}

fn cmd_cap_dir(
    crow: &Crow<FsStore>,
    pins: &PinIndex,
    catalog: &CatalogIndex,
    identity: &Identity,
    path: &str,
    name: Option<String>,
) -> DynResult<()> {
    let path = CatalogPath::normalize(path)?;
    let view = catalog.view()?;
    let Some(entry) = view.get(&path) else {
        return Err(format!("catalog path not found: {path}").into());
    };
    if !entry.is_dir() {
        return Err(format!("{path} is a file; directory caps require a directory").into());
    }

    let manifest = directory_manifest_from_catalog(&view, &path)?;
    let cap = crow.put_directory_manifest(&manifest, identity)?;
    let pin_name = name.or_else(|| directory_snapshot_name(&path));
    pins.add(cap.clone(), pin_name, None)?;
    println!("{}", cap.encode());
    Ok(())
}

fn cmd_add_dir(
    crow: &Crow<FsStore>,
    pins: &PinIndex,
    catalog: &CatalogIndex,
    arg: &str,
    dest: &str,
) -> DynResult<()> {
    let cap = resolve_cap(pins, arg)?;
    let report = add_directory_cap_to_catalog(crow, catalog, &cap, dest)?;
    println!(
        "added directory snapshot at {} ({} file{} / {} director{})",
        report.path,
        report.files,
        if report.files == 1 { "" } else { "s" },
        report.directories,
        if report.directories == 1 { "y" } else { "ies" },
    );
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct DirectoryImportReport {
    path: CatalogPath,
    files: usize,
    directories: usize,
}

fn add_directory_cap_to_catalog(
    crow: &Crow<FsStore>,
    catalog: &CatalogIndex,
    cap: &Cap,
    dest: &str,
) -> DynResult<DirectoryImportReport> {
    let manifest = crow.open_directory_manifest(cap)?;
    let dest = CatalogPath::normalize(dest)?;
    if dest.as_str() == "/" {
        return Err("refusing to add a directory snapshot at catalog root".into());
    }

    let view = catalog.view()?;
    if view.get(&dest).is_some() {
        return Err(format!("destination already exists: {dest}").into());
    }

    catalog.mkdir(dest.as_str(), true)?;
    for entry in &manifest.entries {
        match &entry.kind {
            DirectoryEntryKind::Dir => {
                let path = join_catalog_relative(&dest, Path::new(&entry.path))?;
                catalog.mkdir(path.as_str(), true)?;
            }
            DirectoryEntryKind::File { cap, name } => {
                let path = join_catalog_relative(&dest, Path::new(&entry.path))?;
                if let Some(parent) = path.parent() {
                    catalog.mkdir(parent.as_str(), true)?;
                }
                catalog.put_file(path.as_str(), Cap::decode(cap)?, name.clone())?;
            }
        }
    }

    Ok(DirectoryImportReport {
        path: dest,
        files: manifest.file_count(),
        directories: manifest.dir_count(),
    })
}

fn cmd_get_dir(
    crow: &Crow<FsStore>,
    pins: &PinIndex,
    catalog: &CatalogIndex,
    path: &str,
    out: &str,
    yes: bool,
) -> DynResult<()> {
    let raw_source = path.trim();
    let out = Path::new(out);
    prepare_get_dir_output(out, yes)?;

    let view = catalog.view()?;
    if let Ok(path) = CatalogPath::normalize(raw_source) {
        if let Some(entry) = view.get(&path) {
            if !entry.is_dir() {
                return Err(format!("{path} is a file; use `crow get`").into());
            }
            let restored_files = restore_catalog_dir(crow, &view, &path, out)?;
            println!(
                "restored {} file{} from {path} into {}",
                restored_files,
                if restored_files == 1 { "" } else { "s" },
                out.display(),
            );
            return Ok(());
        }
        if raw_source.starts_with('/') {
            return Err(format!("catalog path not found: {path}").into());
        }
    }

    let cap = resolve_cap(pins, raw_source)
        .map_err(|_| "directory source must be a catalog path or directory cap/prefix")?;
    let manifest = crow.open_directory_manifest(&cap)?;
    let restored_files = restore_directory_manifest(crow, &manifest, out)?;
    println!(
        "restored {} file{} from directory cap into {}",
        restored_files,
        if restored_files == 1 { "" } else { "s" },
        out.display(),
    );
    Ok(())
}

fn prepare_get_dir_output(out: &Path, yes: bool) -> DynResult<()> {
    if !out.exists() {
        return Ok(());
    }
    if !out.is_dir() {
        return Err(format!("output exists and is not a directory: {}", out.display()).into());
    }
    if out.read_dir()?.next().is_some() {
        confirm(
            &format!(
                "Output directory is non-empty: {}. Continue? [y/N] ",
                out.display()
            ),
            yes,
        )?;
    }
    Ok(())
}

fn restore_catalog_dir(
    crow: &Crow<FsStore>,
    view: &CatalogView,
    path: &CatalogPath,
    out: &Path,
) -> DynResult<usize> {
    let entries = catalog_subtree_entries(view, path);
    let mut restored_files = 0usize;
    fs::create_dir_all(out)?;
    for entry in entries.iter().filter(|entry| entry.is_dir()) {
        let rel = relative_catalog_path(path, &entry.path)?;
        if !rel.as_os_str().is_empty() {
            fs::create_dir_all(out.join(rel))?;
        }
    }

    for entry in entries {
        let EntryKind::File { cap, .. } = &entry.kind else {
            continue;
        };
        let rel = relative_catalog_path(path, &entry.path)?;
        let target = out.join(rel);
        if target.exists() {
            return Err(
                format!("refusing to overwrite existing file: {}", target.display()).into(),
            );
        }
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        let bytes = crow.get_bytes(cap)?;
        fs::write(&target, bytes)?;
        restored_files += 1;
    }
    Ok(restored_files)
}

fn restore_directory_manifest(
    crow: &Crow<FsStore>,
    manifest: &DirectoryManifest,
    out: &Path,
) -> DynResult<usize> {
    let mut restored_files = 0usize;
    fs::create_dir_all(out)?;

    for entry in manifest
        .entries
        .iter()
        .filter(|entry| matches!(entry.kind, DirectoryEntryKind::Dir))
    {
        fs::create_dir_all(out.join(&entry.path))?;
    }

    for entry in &manifest.entries {
        let DirectoryEntryKind::File { cap, .. } = &entry.kind else {
            continue;
        };
        let target = out.join(&entry.path);
        if target.exists() {
            return Err(
                format!("refusing to overwrite existing file: {}", target.display()).into(),
            );
        }
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        let cap = Cap::decode(cap)?;
        let bytes = crow.get_bytes(&cap)?;
        fs::write(&target, bytes)?;
        restored_files += 1;
    }

    Ok(restored_files)
}

fn cmd_pin(pins: &PinIndex, cap_str: &str, name: Option<String>) -> DynResult<()> {
    let cap = Cap::decode(cap_str.trim())?;
    let rec = pins.add(cap, name, None)?;
    println!("pinned {}", &rec.manifest_hash_hex[..16]);
    Ok(())
}

fn cmd_unpin(pins: &PinIndex, catalog: &CatalogIndex, arg: &str, recursive: bool) -> DynResult<()> {
    if let Ok(path) = CatalogPath::normalize(arg) {
        let view = catalog.view()?;
        if let Some(entry) = view.get(&path) {
            if path.as_str() == "/" {
                return Err("refusing to unpin catalog root".into());
            }
            if entry.is_dir() && !recursive {
                return Err(format!(
                    "{path} is a directory; use `crow unpin -r {path}` to detach it without deleting chunks"
                )
                .into());
            }
            let file_count = catalog_caps_under(&view, &path).len();
            catalog.remove(path.as_str())?;
            if entry.is_dir() {
                println!(
                    "unpinned catalog subtree {path} ({} file{})",
                    file_count,
                    if file_count == 1 { "" } else { "s" },
                );
            } else {
                println!("unpinned catalog path {path}");
            }
            println!("chunks kept; run `crow gc` to sweep unreferenced data");
            return Ok(());
        }
    }

    match resolve_pin(pins, arg) {
        Ok(rec) => {
            pins.remove(rec.cap.manifest_hash.inner())?;
            println!("unpinned {}", &rec.manifest_hash_hex[..16]);
            Ok(())
        }
        Err(e) => match catalog_matches_arg(catalog, arg)? {
            matches if matches.is_empty() => Err(e),
            matches => Err(format_catalog_unpin_hint(arg, &matches).into()),
        },
    }
}

fn cmd_rm(
    crow: &Crow<FsStore>,
    pins: &PinIndex,
    catalog: &CatalogIndex,
    arg: &str,
    dry_run: bool,
) -> DynResult<()> {
    if let Ok(path) = CatalogPath::normalize(arg) {
        let view = catalog.view()?;
        if view.get(&path).is_some() {
            return cmd_rm_catalog_path(crow, pins, catalog, &view, &path, dry_run);
        }
    }

    let target = resolve_pin(pins, arg)?;
    let target_cap = target.cap.clone();

    // Collect every other pinned cap so we don't delete chunks that are
    // shared with other pinned or cataloged manifests.
    let mut remaining_caps: Vec<Cap> = pins
        .list()?
        .into_iter()
        .filter(|r| r.manifest_hash_hex != target.manifest_hash_hex)
        .map(|r| r.cap)
        .collect();
    remaining_caps.extend(catalog.view()?.file_caps());

    if !dry_run {
        pins.remove(target_cap.manifest_hash.inner())?;
    }

    let report = targeted_remove(
        crow.store(),
        std::slice::from_ref(&target_cap),
        &remaining_caps,
        GcOptions { dry_run },
    )?;

    let action = if dry_run { "would remove" } else { "removed" };
    let name = target.name.as_deref().unwrap_or("(unnamed)");
    println!(
        "{action} pin {} ({})",
        &target.manifest_hash_hex[..16],
        name
    );
    let action = if dry_run { "would delete" } else { "deleted" };
    println!(
        "{action} {} manifest{} / {} chunk{} ({})",
        report.deleted_manifests,
        if report.deleted_manifests == 1 {
            ""
        } else {
            "s"
        },
        report.deleted_chunks,
        if report.deleted_chunks == 1 { "" } else { "s" },
        format_size_u64(report.deleted_bytes),
    );
    Ok(())
}

fn cmd_rm_catalog_path(
    crow: &Crow<FsStore>,
    pins: &PinIndex,
    catalog: &CatalogIndex,
    view: &CatalogView,
    path: &CatalogPath,
    dry_run: bool,
) -> DynResult<()> {
    if path.as_str() == "/" {
        return Err("refusing to remove catalog root".into());
    }

    let target_caps = catalog_caps_under(view, path);
    let mut remaining_caps: Vec<Cap> = pins.list()?.into_iter().map(|r| r.cap).collect();
    remaining_caps.extend(catalog_caps_not_under(view, path));

    if !dry_run {
        catalog.remove(path.as_str())?;
    }

    let report = targeted_remove(
        crow.store(),
        &target_caps,
        &remaining_caps,
        GcOptions { dry_run },
    )?;

    let action = if dry_run { "would remove" } else { "removed" };
    println!("{action} catalog path {path}");
    let action = if dry_run { "would delete" } else { "deleted" };
    println!(
        "{action} {} manifest{} / {} chunk{} ({})",
        report.deleted_manifests,
        if report.deleted_manifests == 1 {
            ""
        } else {
            "s"
        },
        report.deleted_chunks,
        if report.deleted_chunks == 1 { "" } else { "s" },
        format_size_u64(report.deleted_bytes),
    );
    Ok(())
}

fn cmd_mv(catalog: &CatalogIndex, from: &str, to: &str) -> DynResult<()> {
    let from = CatalogPath::normalize(from)?;
    if from.as_str() == "/" {
        return Err("refusing to move catalog root".into());
    }

    let view = catalog.view()?;
    let Some(source) = view.get(&from) else {
        return Err(format!("catalog path not found: {from}").into());
    };

    let raw_to = to.trim();
    let mut to = CatalogPath::normalize(raw_to)?;
    if raw_to.ends_with('/') || view.get(&to).is_some_and(|entry| entry.is_dir()) {
        let name = source
            .path
            .file_name()
            .ok_or("cannot infer destination name")?;
        to = join_catalog_path(&to, name)?;
    }

    if catalog_path_contains(&from, &to) {
        return Err(format!("cannot move {from} inside itself at {to}").into());
    }
    if view.get(&to).is_some() {
        return Err(format!("destination already exists: {to}").into());
    }
    if let Some(parent) = to.parent() {
        match view.get(&parent) {
            Some(entry) if entry.is_dir() => {}
            Some(_) => return Err(format!("destination parent is a file: {parent}").into()),
            None => return Err(format!("destination parent does not exist: {parent}").into()),
        }
    }

    catalog.move_path(from.as_str(), to.as_str())?;
    println!("moved {from} -> {to}");
    Ok(())
}

fn cmd_cp(pins: &PinIndex, catalog: &CatalogIndex, src: &str, dst: &str) -> DynResult<()> {
    let source = resolve_file_ref(catalog, pins, src)?;
    let view = catalog.view()?;
    let dst = resolve_copy_destination(pins, &view, &source, dst)?;

    if view.get(&dst).is_some() {
        return Err(format!("destination already exists: {dst}").into());
    }
    if let Some(parent) = dst.parent() {
        match view.get(&parent) {
            Some(entry) if entry.is_dir() => {}
            Some(_) => return Err(format!("destination parent is a file: {parent}").into()),
            None => return Err(format!("destination parent does not exist: {parent}").into()),
        }
    }

    let name = dst.file_name().map(str::to_string);
    catalog.put_file(dst.as_str(), source.cap, name)?;
    println!("copied {} -> {dst}", src.trim());
    Ok(())
}

fn resolve_copy_destination(
    pins: &PinIndex,
    view: &CatalogView,
    source: &ResolvedFile,
    dst: &str,
) -> DynResult<CatalogPath> {
    let raw_dst = dst.trim();
    let mut path = CatalogPath::normalize(raw_dst)?;
    let dst_is_dir = raw_dst.ends_with('/') || view.get(&path).is_some_and(|entry| entry.is_dir());
    if dst_is_dir {
        let name = copy_source_name(pins, source)?;
        path = join_catalog_path(&path, &name)?;
    }
    Ok(path)
}

fn copy_source_name(pins: &PinIndex, source: &ResolvedFile) -> DynResult<String> {
    if let Some(path) = &source.path {
        if let Some(name) = path.file_name() {
            return Ok(name.to_string());
        }
    }

    if let Some(pin) = pins.get(source.cap.manifest_hash.inner())? {
        if let Some(name) = pin.name {
            return Ok(name);
        }
    }

    Err(
        "destination is a directory; cap sources need a pinned name or full destination path"
            .into(),
    )
}

fn cmd_gc(
    crow: &Crow<FsStore>,
    pins: &PinIndex,
    catalog: &CatalogIndex,
    dry_run: bool,
) -> DynResult<()> {
    let pin_caps: Vec<Cap> = pins.list()?.into_iter().map(|r| r.cap).collect();
    let view = catalog.view()?;
    let live = compute_live_set_from_roots(crow.store(), &pin_caps, &view)?;
    let report = sweep(crow.store(), &live, GcOptions { dry_run })?;
    let action = if dry_run { "would delete" } else { "deleted" };
    if report.deleted_manifests + report.deleted_chunks == 0 {
        println!("{action} 0 manifests / 0 chunks (nothing to do)");
    } else {
        println!(
            "{action} {} manifest{} / {} chunk{} ({})",
            report.deleted_manifests,
            if report.deleted_manifests == 1 {
                ""
            } else {
                "s"
            },
            report.deleted_chunks,
            if report.deleted_chunks == 1 { "" } else { "s" },
            format_size_u64(report.deleted_bytes),
        );
    }
    println!(
        "kept {} manifest{} / {} chunk{}",
        report.kept_manifests,
        if report.kept_manifests == 1 { "" } else { "s" },
        report.kept_chunks,
        if report.kept_chunks == 1 { "" } else { "s" },
    );
    Ok(())
}

fn cmd_stat(
    crow: &Crow<FsStore>,
    pins: &PinIndex,
    catalog: &CatalogIndex,
    arg: Option<&str>,
) -> DynResult<()> {
    let lines = match arg {
        Some(arg) => stat_lines(crow, pins, catalog, arg)?,
        None => store_stat_lines(crow, pins, catalog)?,
    };
    for line in lines {
        println!("{line}");
    }
    Ok(())
}

fn store_stat_lines(
    crow: &Crow<FsStore>,
    pins: &PinIndex,
    catalog: &CatalogIndex,
) -> DynResult<Vec<String>> {
    let manifests = crow.store().list(Namespace::Manifests)?;
    let chunks = crow.store().list(Namespace::Chunks)?;
    let manifest_bytes: u64 = manifests
        .iter()
        .filter_map(|h| crow.store().size(Namespace::Manifests, h).ok().flatten())
        .sum();
    let chunk_bytes: u64 = chunks
        .iter()
        .filter_map(|h| crow.store().size(Namespace::Chunks, h).ok().flatten())
        .sum();

    let pin_records = pins.list()?;
    let pin_caps: Vec<Cap> = pin_records.iter().map(|r| r.cap.clone()).collect();
    let catalog_view = catalog.view()?;
    let catalog_files = catalog_view.files().len();
    let live = compute_live_set_from_roots(crow.store(), &pin_caps, &catalog_view)?;

    let mut unref_manifests = 0u64;
    let mut unref_chunks = 0u64;
    let mut unref_bytes = 0u64;
    for h in &manifests {
        if !live.contains(&(Namespace::Manifests, *h)) {
            unref_manifests += 1;
            unref_bytes += crow
                .store()
                .size(Namespace::Manifests, h)
                .ok()
                .flatten()
                .unwrap_or(0);
        }
    }
    for h in &chunks {
        if !live.contains(&(Namespace::Chunks, *h)) {
            unref_chunks += 1;
            unref_bytes += crow
                .store()
                .size(Namespace::Chunks, h)
                .ok()
                .flatten()
                .unwrap_or(0);
        }
    }

    Ok(vec![
        format!("store         {}", crow.store().root().display()),
        format!(
            "manifests     {} files / {}",
            manifests.len(),
            format_size_u64(manifest_bytes)
        ),
        format!(
            "chunks        {} files / {}",
            chunks.len(),
            format_size_u64(chunk_bytes)
        ),
        format!("pins          {}", pin_records.len()),
        format!("catalog files {}", catalog_files),
        format!(
            "unreferenced  {unref_manifests} manifests / {unref_chunks} chunks ({})",
            format_size_u64(unref_bytes),
        ),
    ])
}

fn stat_lines(
    crow: &Crow<FsStore>,
    pins: &PinIndex,
    catalog: &CatalogIndex,
    arg: &str,
) -> DynResult<Vec<String>> {
    let raw = arg.trim();
    let view = catalog.view()?;
    if !raw.starts_with("crow1") {
        if let Ok(path) = CatalogPath::normalize(raw) {
            if let Some(entry) = view.get(&path) {
                return match &entry.kind {
                    EntryKind::Dir => catalog_dir_stat_lines(crow, &view, &path),
                    EntryKind::File { cap, .. } => cap_stat_lines(crow, pins, Some(&path), cap),
                };
            }
            if raw.starts_with('/') {
                return Err(format!("catalog path not found: {path}").into());
            }
        }
    }

    let target = resolve_file_ref(catalog, pins, raw)?;
    cap_stat_lines(crow, pins, target.path.as_ref(), &target.cap)
}

fn catalog_dir_stat_lines(
    crow: &Crow<FsStore>,
    view: &CatalogView,
    path: &CatalogPath,
) -> DynResult<Vec<String>> {
    let report = catalog_du_report(crow, view, path)?;
    let size = if report.unknown_files == 0 {
        format_size_u64(report.logical_bytes)
    } else {
        format!(
            "unknown ({} missing file{})",
            report.unknown_files,
            if report.unknown_files == 1 { "" } else { "s" }
        )
    };

    Ok(vec![
        format!("path      {path}"),
        "type      catalog directory".into(),
        format!("files     {}", report.files),
        format!("dirs      {}", report.directories),
        format!("size      {size}"),
        "cataloged yes".into(),
    ])
}

fn cap_stat_lines(
    crow: &Crow<FsStore>,
    pins: &PinIndex,
    path: Option<&CatalogPath>,
    cap: &Cap,
) -> DynResult<Vec<String>> {
    let mut lines = Vec::new();
    if let Some(path) = path {
        lines.push(format!("path      {path}"));
    }

    match crow.open_manifest_kind(cap)? {
        ManifestKind::File(manifest) => {
            lines.push("type      file".into());
            lines.push(format!("cap       {}", cap.encode()));
            lines.push(format!("hash      {}", cap.manifest_hash));
            lines.push(format!(
                "size      {}",
                format_size(manifest.file_size as usize)
            ));
            lines.push(format!("mime      {}", manifest.mime_type));
            lines.push(format!(
                "created   {}",
                format_iso_timestamp(manifest.created_at)
            ));
            lines.push(format_signature_status(manifest.signature_status()?));
        }
        ManifestKind::Directory(manifest) => {
            lines.push("type      directory snapshot".into());
            lines.push(format!("cap       {}", cap.encode()));
            lines.push(format!("hash      {}", cap.manifest_hash));
            lines.push(format!("files     {}", manifest.file_count()));
            lines.push(format!("dirs      {}", manifest.dir_count()));
            match directory_logical_size(crow, &manifest)? {
                Some(bytes) => lines.push(format!("size      {}", format_size_u64(bytes))),
                None => lines.push("size      unknown (missing child manifests)".into()),
            }
            lines.push(format!(
                "created   {}",
                format_iso_timestamp(manifest.created_at)
            ));
            lines.push(format_signature_status(manifest.signature_status()?));
        }
    }

    if let Some(rec) = pins.get(cap.manifest_hash.inner())? {
        let name = rec.name.as_deref().unwrap_or("(unnamed)");
        lines.push(format!(
            "pinned    {} ({})",
            format_iso_timestamp(rec.pinned_at),
            name
        ));
    } else {
        lines.push("pinned    no".into());
    }
    lines.push(format!(
        "cataloged {}",
        if path.is_some() { "yes" } else { "no" }
    ));
    Ok(lines)
}

fn cmd_device(home: &Path, command: Option<DeviceCommand>) -> DynResult<()> {
    match command {
        Some(DeviceCommand::Name { name }) => {
            let name = validate_device_name(&name)?;
            let mut config = DeviceConfig::load(home)?;
            config.name = Some(name.clone());
            config.save(home)?;
            println!("device name {name}");
            Ok(())
        }
        None => {
            let identity = Identity::load_or_create(home)?;
            let config = DeviceConfig::load(home)?;
            let token_status = if TokenStore::open(home).exists() {
                "configured"
            } else {
                "missing"
            };
            let snapshot_path = peer_snapshot::snapshot_path(home);
            let snapshot_status = match peer_snapshot::load(&snapshot_path)? {
                Some(snap) => {
                    let age = peer_snapshot::now_unix().saturating_sub(snap.snapshot_at);
                    format!(
                        "{} peer{} ({}s old)",
                        snap.peers.len(),
                        if snap.peers.len() == 1 { "" } else { "s" },
                        age
                    )
                }
                None => "missing".into(),
            };

            println!("home      {}", home.display());
            println!("node      {}", identity.node_id());
            println!("short     {}", identity.node_id().short());
            println!(
                "name      {}",
                config.name.as_deref().unwrap_or("(not set)")
            );
            println!("token     {token_status}");
            println!("peers     {snapshot_status}");
            Ok(())
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum SetupTokenAction {
    Created,
    Existing,
    Imported,
    Replaced,
}

#[derive(Debug)]
struct SetupReport {
    node_id: NodeId,
    name: Option<String>,
    token: ClusterToken,
    token_action: SetupTokenAction,
}

fn cmd_setup(
    home: &Path,
    name: Option<String>,
    token: Option<String>,
    force_token: bool,
) -> DynResult<()> {
    let report = setup_device(home, name, token, force_token)?;
    println!("home      {}", home.display());
    println!("node      {}", report.node_id);
    println!("short     {}", report.node_id.short());
    println!(
        "name      {}",
        report.name.as_deref().unwrap_or("(not set)")
    );
    println!(
        "token     {}",
        setup_token_action_label(&report.token_action)
    );
    println!();
    println!("On another trusted device:");
    println!(
        "  crow setup --token {}{}",
        report.token.encode(),
        report
            .name
            .as_ref()
            .map(|name| format!(" --name {name}"))
            .unwrap_or_default()
    );
    println!();
    println!("Then run `crow serve` on the device that has chunks.");
    Ok(())
}

fn setup_device(
    home: &Path,
    name: Option<String>,
    token: Option<String>,
    force_token: bool,
) -> DynResult<SetupReport> {
    let identity = Identity::load_or_create(home)?;
    let mut config = DeviceConfig::load(home)?;
    let name = match name {
        Some(name) => Some(validate_device_name(&name)?),
        None => config.name.clone().or_else(default_setup_name),
    };
    if config.name != name {
        config.name = name.clone();
        config.save(home)?;
    }

    let tokens = TokenStore::open(home);
    let (token, token_action) = if let Some(token) = token {
        let token = ClusterToken::decode(&token)?;
        let existed = tokens.exists();
        tokens.save(token)?;
        (
            token,
            if existed {
                SetupTokenAction::Replaced
            } else {
                SetupTokenAction::Imported
            },
        )
    } else {
        let existed = tokens.exists();
        let token = tokens.init(force_token)?;
        (
            token,
            match (existed, force_token) {
                (true, true) => SetupTokenAction::Replaced,
                (true, false) => SetupTokenAction::Existing,
                (false, _) => SetupTokenAction::Created,
            },
        )
    };

    Ok(SetupReport {
        node_id: identity.node_id(),
        name,
        token,
        token_action,
    })
}

fn setup_token_action_label(action: &SetupTokenAction) -> &'static str {
    match action {
        SetupTokenAction::Created => "created",
        SetupTokenAction::Existing => "already configured",
        SetupTokenAction::Imported => "imported",
        SetupTokenAction::Replaced => "replaced",
    }
}

fn cmd_peers(home: &Path, long: bool, json: bool) -> DynResult<()> {
    let path = peer_snapshot::snapshot_path(home);
    let snap = match peer_snapshot::load(&path)? {
        Some(s) => s,
        None => {
            println!("no peer snapshot found at {}", path.display());
            println!("start `crow serve` to discover peers on the LAN");
            return Ok(());
        }
    };

    if json {
        let pretty =
            serde_json::to_string_pretty(&snap).map_err(|e| format!("encode snapshot: {e}"))?;
        println!("{pretty}");
        return Ok(());
    }

    if snap.peers.is_empty() {
        println!("(no peers discovered yet)");
    } else if long {
        for (i, p) in snap.peers.iter().enumerate() {
            if i > 0 {
                println!();
            }
            println!("node       {}", p.node_id);
            println!(
                "name       {}",
                p.friendly_name.as_deref().unwrap_or("(unnamed)")
            );
            for (j, addr) in p.addresses.iter().enumerate() {
                let label = if j == 0 { "address    " } else { "           " };
                println!("{label}{addr}");
            }
            println!(
                "seen       {} ({})",
                format_iso_timestamp(p.last_seen_unix),
                humanize_age(p.last_seen_unix)
            );
        }
    } else {
        println!(
            "{:<16}  {:<16}  {:<22}  LAST SEEN",
            "NODE", "NAME", "ADDRESS"
        );
        for p in &snap.peers {
            let node = p.node_id.short();
            let name = truncate(p.friendly_name.as_deref().unwrap_or("(unnamed)"), 16);
            let addr = p
                .addresses
                .first()
                .map(|a| a.to_string())
                .unwrap_or_else(|| "?".into());
            let age = humanize_age(p.last_seen_unix);
            println!("{node:<16}  {name:<16}  {addr:<22}  {age}");
        }
    }

    println!();
    let snap_age = peer_snapshot::now_unix().saturating_sub(snap.snapshot_at);
    let self_name = snap.self_info.friendly_name.as_deref().unwrap_or("unnamed");
    let self_node = snap.self_info.node_id.short();
    println!(
        "self: {self_node} {self_name} on {} (snapshot {}s old)",
        snap.self_info.address, snap_age
    );

    if snap_age > 30 {
        println!();
        println!("note: snapshot is {snap_age}s old — is `crow serve` running?");
    }
    Ok(())
}

/// Resolve a `<peer>` CLI argument to one or more SocketAddr candidates.
/// Three forms in order:
/// 1. Parse as SocketAddr.
/// 2. Hex prefix of a node id from the snapshot.
/// 3. Exact friendly name from the snapshot.
fn resolve_peer(home: &Path, arg: &str) -> DynResult<Vec<SocketAddr>> {
    let arg = arg.trim();

    if let Ok(addr) = arg.parse::<SocketAddr>() {
        return Ok(vec![addr]);
    }

    let snapshot_path = peer_snapshot::snapshot_path(home);
    let snap = peer_snapshot::load(&snapshot_path)?.ok_or_else(|| -> DynError {
        format!(
            "'{arg}' is not an IP:port and no peer snapshot exists at {} \
             (run `crow serve` somewhere on the LAN to populate it)",
            snapshot_path.display()
        )
        .into()
    })?;

    let lower = arg.to_ascii_lowercase();
    let id_matches: Vec<&PeerInfo> = snap
        .peers
        .iter()
        .filter(|p| p.node_id.to_string().starts_with(&lower))
        .collect();

    let candidates: Vec<&PeerInfo> = if !id_matches.is_empty() {
        id_matches
    } else {
        snap.peers
            .iter()
            .filter(|p| p.friendly_name.as_deref() == Some(arg))
            .collect()
    };

    match candidates.len() {
        0 => Err(format!(
            "no peer in {} matches '{arg}' (tried IP:port, node-id prefix, friendly name)",
            snapshot_path.display()
        )
        .into()),
        1 => {
            let addresses = candidates[0].addresses.clone();
            if addresses.is_empty() {
                return Err(format!(
                    "peer {} has no known address",
                    candidates[0].node_id.short()
                )
                .into());
            }
            Ok(addresses)
        }
        n => {
            let mut msg = format!("ambiguous peer '{arg}' ({n} matches):");
            for p in &candidates {
                msg.push_str("\n  ");
                msg.push_str(&format_peer_candidate(p));
            }
            msg.push_str("\nuse a longer node-id prefix or one of the listed IP:port addresses");
            Err(msg.into())
        }
    }
}

fn format_peer_candidate(peer: &PeerInfo) -> String {
    let name = peer.friendly_name.as_deref().unwrap_or("(unnamed)");
    let address = peer
        .addresses
        .first()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|| "?".into());
    format!("{} {name} {address}", peer.node_id.short())
}

fn humanize_age(unix: u64) -> String {
    let now = peer_snapshot::now_unix();
    if unix > now {
        return "just now".into();
    }
    let secs = now - unix;
    if secs < 60 {
        format!("{secs}s ago")
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else if secs < 86400 {
        format!("{}h ago", secs / 3600)
    } else {
        format!("{}d ago", secs / 86400)
    }
}

fn cmd_serve(
    home: &Path,
    store: FsStore,
    bind: SocketAddr,
    name_override: Option<String>,
) -> DynResult<()> {
    let token = load_token(home)?;
    let identity = Identity::load_or_create(home)?;
    let node_id = identity.node_id();
    let friendly_name = resolve_serve_name(home, name_override)?;
    let root = store.root().display().to_string();
    let snapshot_path = peer_snapshot::snapshot_path(home);

    let rt = runtime()?;
    rt.block_on(serve_loop(
        store,
        token,
        bind,
        node_id,
        friendly_name,
        root,
        snapshot_path,
    ))
}

async fn serve_loop(
    store: FsStore,
    token: ClusterToken,
    bind: SocketAddr,
    node_id: NodeId,
    friendly_name: Option<String>,
    root: String,
    snapshot_path: PathBuf,
) -> DynResult<()> {
    let server = crow_net::serve(store, token, bind).await?;
    let actual_addr = server.local_addr();

    let advert = LocalAdvert {
        node_id,
        port: actual_addr.port(),
        friendly_name: friendly_name.clone(),
    };
    let discovery = Discovery::start(Some(advert))?;

    println!("serving {root} on {actual_addr}");
    println!(
        "node {} ({})",
        node_id.short(),
        friendly_name.as_deref().unwrap_or("unnamed")
    );
    println!("cluster token: configured");
    println!("mDNS service: _crow._udp.local.");

    let self_info = SelfInfo {
        node_id,
        friendly_name: friendly_name.clone(),
        address: actual_addr,
    };

    let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    loop {
        tokio::select! {
            biased;
            _ = &mut ctrl_c => {
                println!();
                let _ = write_peer_snapshot(&snapshot_path, &self_info, &discovery);
                break;
            }
            _ = interval.tick() => {
                if let Err(e) = write_peer_snapshot(&snapshot_path, &self_info, &discovery) {
                    eprintln!("crow: failed to write peer snapshot: {e}");
                }
            }
        }
    }

    let _ = discovery.shutdown();
    drop(server);
    Ok(())
}

fn write_peer_snapshot(path: &Path, self_info: &SelfInfo, discovery: &Discovery) -> DynResult<()> {
    let snap = PeerSnapshot {
        snapshot_at: peer_snapshot::now_unix(),
        self_info: self_info.clone(),
        peers: discovery.peers(),
    };
    peer_snapshot::save(path, &snap)?;
    Ok(())
}

fn cmd_fetch(
    home: &Path,
    crow: &Crow<FsStore>,
    pins: &PinIndex,
    peer: &str,
    arg: &str,
    name: Option<String>,
) -> DynResult<()> {
    let token = load_token(home)?;
    let socket_addrs = resolve_peer(home, peer)?;
    let cap = resolve_cap(pins, arg)?;
    let rt = runtime()?;
    let (socket_addr, client) = connect_peer(&rt, token, peer, &socket_addrs)?;

    let mut counters = FetchCounters::default();
    let manifest_state = fetch_manifest_object(crow, &rt, &client, token, &cap, &mut counters)?;
    if matches!(manifest_state, FetchState::Missing) {
        println!("manifest      missing");
        println!("shares        0 local / 0 fetched / 0 missing");
        println!("stored        {}", format_size_u64(counters.fetched_bytes));
        println!("status        not reconstructable");
        return Err("peer does not have the manifest".into());
    }

    let manifest_kind = crow.open_manifest_kind(&cap)?;
    let (pin_name, pin_comment) = fetch_pin_metadata(pins, &cap, name)?;
    pins.add(cap.clone(), pin_name, pin_comment)?;

    let mut visited = HashSet::from([*cap.manifest_hash.inner()]);
    fetch_manifest_dependencies(
        crow,
        &rt,
        &client,
        token,
        &manifest_kind,
        &mut counters,
        &mut visited,
    )?;

    println!("manifest      {}", manifest_state.as_str());
    if let ManifestKind::Directory(directory) = &manifest_kind {
        println!(
            "directory     {} file{} / {} director{}",
            directory.file_count(),
            if directory.file_count() == 1 { "" } else { "s" },
            directory.dir_count(),
            if directory.dir_count() == 1 {
                "y"
            } else {
                "ies"
            },
        );
    }
    println!(
        "shares        {} local / {} fetched / {} missing",
        counters.local_shares, counters.fetched_shares, counters.missing_shares
    );
    println!(
        "objects       {} local / {} fetched / {} missing",
        counters.already_local, counters.fetched, counters.remote_missing
    );
    println!("stored        {}", format_size_u64(counters.fetched_bytes));
    println!("peer          {socket_addr}");
    println!(
        "pinned        {} {}",
        &cap.manifest_hash.to_string()[..8],
        pins.get(cap.manifest_hash.inner())?
            .and_then(|r| r.name)
            .unwrap_or_else(|| "(unnamed)".into())
    );

    match verify_cap_reconstructable(crow, &cap) {
        Ok(_) => {
            println!("status        reconstructable");
            Ok(())
        }
        Err(e) => {
            println!("status        not reconstructable ({e})");
            Err(format!("fetch incomplete: {e}").into())
        }
    }
}

struct ReceiveCliRequest<'a> {
    peer: &'a str,
    arg: &'a str,
    dest: Option<&'a str>,
    name: Option<String>,
}

fn cmd_receive(ctx: StoreContext<'_>, request: ReceiveCliRequest<'_>) -> DynResult<()> {
    let cap = resolve_cap(ctx.pins, request.arg)?;
    cmd_fetch(
        ctx.home,
        ctx.crow,
        ctx.pins,
        request.peer,
        request.arg,
        request.name.clone(),
    )?;

    receive_after_fetch(ctx, &cap, request.dest, request.name)
}

fn receive_after_fetch(
    ctx: StoreContext<'_>,
    cap: &Cap,
    dest: Option<&str>,
    name: Option<String>,
) -> DynResult<()> {
    if let Some(dest) = dest {
        match catalog_received_cap(ctx.crow, ctx.pins, ctx.catalog, cap, dest, name)? {
            ReceiveCatalogReport::File { path } => println!("cataloged     {path}"),
            ReceiveCatalogReport::Directory {
                path,
                files,
                directories,
            } => println!(
                "cataloged     {path} ({} file{} / {} director{})",
                files,
                if files == 1 { "" } else { "s" },
                directories,
                if directories == 1 { "y" } else { "ies" },
            ),
        }
    } else {
        match ctx.crow.open_manifest_kind(cap)? {
            ManifestKind::File(_) => {
                let suggested_name = receive_pin_name(ctx.pins, cap, None)?;
                let suffix = suggested_name
                    .map(|name| format!(" /path/{name}"))
                    .unwrap_or_else(|| " /path/name".into());
                println!(
                    "next          crow receive <peer> {}{}",
                    cap.encode(),
                    suffix
                );
            }
            ManifestKind::Directory(_) => {
                println!(
                    "next          crow receive <peer> {} /imports/name",
                    cap.encode()
                );
            }
        }
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum ReceiveCatalogReport {
    File {
        path: CatalogPath,
    },
    Directory {
        path: CatalogPath,
        files: usize,
        directories: usize,
    },
}

fn catalog_received_cap(
    crow: &Crow<FsStore>,
    pins: &PinIndex,
    catalog: &CatalogIndex,
    cap: &Cap,
    dest: &str,
    name: Option<String>,
) -> DynResult<ReceiveCatalogReport> {
    match crow.open_manifest_kind(cap)? {
        ManifestKind::File(_) => {
            let path = receive_file_destination(pins, catalog, cap, dest, name)?;
            catalog.put_file(
                path.as_str(),
                cap.clone(),
                path.file_name().map(str::to_string),
            )?;
            Ok(ReceiveCatalogReport::File { path })
        }
        ManifestKind::Directory(_) => {
            let report = add_directory_cap_to_catalog(crow, catalog, cap, dest)?;
            Ok(ReceiveCatalogReport::Directory {
                path: report.path,
                files: report.files,
                directories: report.directories,
            })
        }
    }
}

fn receive_file_destination(
    pins: &PinIndex,
    catalog: &CatalogIndex,
    cap: &Cap,
    dest: &str,
    name: Option<String>,
) -> DynResult<CatalogPath> {
    let raw_dest = dest.trim();
    let view = catalog.view()?;
    let mut path = CatalogPath::normalize(raw_dest)?;
    let dest_is_dir =
        raw_dest.ends_with('/') || view.get(&path).is_some_and(|entry| entry.is_dir());
    if dest_is_dir {
        let file_name = receive_pin_name(pins, cap, name)?
            .ok_or("destination is a directory; pass --name or a full catalog destination path")?;
        let file_name = validate_catalog_basename(&file_name)?;
        path = join_catalog_path(&path, &file_name)?;
    }

    if view.get(&path).is_some() {
        return Err(format!("destination already exists: {path}").into());
    }
    if let Some(parent) = path.parent() {
        match view.get(&parent) {
            Some(entry) if entry.is_dir() => {}
            Some(_) => return Err(format!("destination parent is a file: {parent}").into()),
            None => {
                catalog.mkdir(parent.as_str(), true)?;
            }
        }
    }

    Ok(path)
}

fn validate_catalog_basename(name: &str) -> DynResult<String> {
    let name = name.trim();
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return Err("catalog file name must be a single path segment".into());
    }
    Ok(name.to_string())
}

fn receive_pin_name(
    pins: &PinIndex,
    cap: &Cap,
    requested_name: Option<String>,
) -> DynResult<Option<String>> {
    if requested_name.is_some() {
        return Ok(requested_name);
    }
    Ok(pins.get(cap.manifest_hash.inner())?.and_then(|r| r.name))
}

fn fetch_pin_metadata(
    pins: &PinIndex,
    cap: &Cap,
    requested_name: Option<String>,
) -> DynResult<(Option<String>, Option<String>)> {
    let existing_pin = pins.get(cap.manifest_hash.inner())?;
    let name = requested_name.or_else(|| existing_pin.as_ref().and_then(|r| r.name.clone()));
    let comment = existing_pin.and_then(|r| r.comment);
    Ok((name, comment))
}

fn connect_peer(
    rt: &tokio::runtime::Runtime,
    token: ClusterToken,
    peer_arg: &str,
    addresses: &[SocketAddr],
) -> DynResult<(SocketAddr, Client)> {
    let mut failures = Vec::new();
    for addr in addresses {
        match rt.block_on(Client::connect(*addr)) {
            Ok(client) => match rt.block_on(client.hello(token)) {
                Ok(()) => return Ok((*addr, client)),
                Err(e) => failures.push(format!("{addr}: hello failed: {e}")),
            },
            Err(e) => failures.push(format!("{addr}: connect failed: {e}")),
        }
    }

    let mut msg = format!(
        "could not connect to peer '{peer_arg}' using {} candidate address{}",
        addresses.len(),
        if addresses.len() == 1 { "" } else { "es" },
    );
    for failure in failures {
        msg.push_str("\n  ");
        msg.push_str(&failure);
    }
    Err(msg.into())
}

fn cmd_token(home: &Path, command: TokenCommand) -> DynResult<()> {
    let tokens = TokenStore::open(home);
    match command {
        TokenCommand::Init { force } => {
            let existed = tokens.exists();
            let token = tokens.init(force)?;
            if existed && !force {
                println!("{}", token.encode());
                eprintln!("crow: existing token at {}", tokens.path().display());
            } else {
                println!("{}", token.encode());
            }
            Ok(())
        }
        TokenCommand::Show => {
            println!("{}", tokens.load()?.encode());
            Ok(())
        }
        TokenCommand::Set { token } => {
            let token = ClusterToken::decode(&token)?;
            tokens.save(token)?;
            println!("token set at {}", tokens.path().display());
            Ok(())
        }
    }
}

enum FetchState {
    Local,
    Fetched,
    Missing,
}

impl FetchState {
    fn as_str(&self) -> &'static str {
        match self {
            FetchState::Local => "local",
            FetchState::Fetched => "fetched",
            FetchState::Missing => "missing",
        }
    }
}

#[derive(Default)]
struct FetchCounters {
    fetched: usize,
    already_local: usize,
    remote_missing: usize,
    fetched_bytes: u64,
    local_shares: usize,
    fetched_shares: usize,
    missing_shares: usize,
}

impl FetchCounters {
    fn count_object(&mut self, state: &FetchState) {
        match state {
            FetchState::Local => self.already_local += 1,
            FetchState::Fetched => self.fetched += 1,
            FetchState::Missing => self.remote_missing += 1,
        }
    }

    fn count_share(&mut self, state: &FetchState) {
        match state {
            FetchState::Local => self.local_shares += 1,
            FetchState::Fetched => self.fetched_shares += 1,
            FetchState::Missing => self.missing_shares += 1,
        }
    }
}

fn fetch_manifest_object(
    crow: &Crow<FsStore>,
    rt: &tokio::runtime::Runtime,
    client: &Client,
    token: ClusterToken,
    cap: &Cap,
    counters: &mut FetchCounters,
) -> DynResult<FetchState> {
    let state = fetch_object(
        crow,
        rt,
        client,
        token,
        Namespace::Manifests,
        *cap.manifest_hash.inner(),
        &mut counters.fetched_bytes,
    )?;
    counters.count_object(&state);
    Ok(state)
}

fn fetch_share_object(
    crow: &Crow<FsStore>,
    rt: &tokio::runtime::Runtime,
    client: &Client,
    token: ClusterToken,
    hash: Hash,
    counters: &mut FetchCounters,
) -> DynResult<()> {
    let state = fetch_object(
        crow,
        rt,
        client,
        token,
        Namespace::Chunks,
        hash,
        &mut counters.fetched_bytes,
    )?;
    counters.count_object(&state);
    counters.count_share(&state);
    Ok(())
}

fn fetch_manifest_dependencies(
    crow: &Crow<FsStore>,
    rt: &tokio::runtime::Runtime,
    client: &Client,
    token: ClusterToken,
    kind: &ManifestKind,
    counters: &mut FetchCounters,
    visited: &mut HashSet<Hash>,
) -> DynResult<()> {
    match kind {
        ManifestKind::File(manifest) => {
            for hash in manifest
                .stripes
                .iter()
                .flat_map(|s| s.data.iter().chain(s.parity.iter()))
                .map(|h| *h.inner())
            {
                fetch_share_object(crow, rt, client, token, hash, counters)?;
            }
        }
        ManifestKind::Directory(manifest) => {
            for child_cap in manifest.file_caps()? {
                fetch_cap_recursive(crow, rt, client, token, &child_cap, counters, visited)?;
            }
        }
    }
    Ok(())
}

fn fetch_cap_recursive(
    crow: &Crow<FsStore>,
    rt: &tokio::runtime::Runtime,
    client: &Client,
    token: ClusterToken,
    cap: &Cap,
    counters: &mut FetchCounters,
    visited: &mut HashSet<Hash>,
) -> DynResult<()> {
    if !visited.insert(*cap.manifest_hash.inner()) {
        return Ok(());
    }
    if matches!(
        fetch_manifest_object(crow, rt, client, token, cap, counters)?,
        FetchState::Missing
    ) {
        return Ok(());
    }
    let kind = crow.open_manifest_kind(cap)?;
    fetch_manifest_dependencies(crow, rt, client, token, &kind, counters, visited)
}

fn verify_cap_reconstructable(crow: &Crow<FsStore>, cap: &Cap) -> DynResult<()> {
    let mut visited = HashSet::new();
    verify_cap_reconstructable_inner(crow, cap, &mut visited)
}

fn verify_cap_reconstructable_inner(
    crow: &Crow<FsStore>,
    cap: &Cap,
    visited: &mut HashSet<Hash>,
) -> DynResult<()> {
    if !visited.insert(*cap.manifest_hash.inner()) {
        return Ok(());
    }
    match crow.open_manifest_kind(cap)? {
        ManifestKind::File(_) => {
            crow.get_bytes(cap)?;
        }
        ManifestKind::Directory(manifest) => {
            for child_cap in manifest.file_caps()? {
                verify_cap_reconstructable_inner(crow, &child_cap, visited)?;
            }
        }
    }
    Ok(())
}

fn fetch_object(
    crow: &Crow<FsStore>,
    rt: &tokio::runtime::Runtime,
    client: &Client,
    token: ClusterToken,
    namespace: Namespace,
    hash: Hash,
    fetched_bytes: &mut u64,
) -> DynResult<FetchState> {
    if crow.store().has(namespace, &hash)? {
        return Ok(FetchState::Local);
    }
    match rt.block_on(client.get(token, namespace, hash))? {
        Some(bytes) => {
            *fetched_bytes += bytes.len() as u64;
            crow.store().put_unverified(namespace, hash, bytes)?;
            Ok(FetchState::Fetched)
        }
        None => Ok(FetchState::Missing),
    }
}

fn load_token(home: &Path) -> DynResult<ClusterToken> {
    TokenStore::open(home).load().map_err(|e| {
        format!(
            "{e}; run `crow token init` on one trusted device and `crow token set <token>` on the others"
        )
        .into()
    })
}

fn runtime() -> DynResult<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?)
}

fn open_manifest(crow: &Crow<FsStore>, cap: &Cap) -> DynResult<Manifest> {
    let encrypted = crow
        .store()
        .get(Namespace::Manifests, cap.manifest_hash.inner())?
        .ok_or("manifest not found in local store")?;
    Ok(Manifest::open(&encrypted, &cap.manifest_key)?)
}

struct ResolvedFile {
    cap: Cap,
    path: Option<CatalogPath>,
}

fn resolve_file_ref(catalog: &CatalogIndex, pins: &PinIndex, arg: &str) -> DynResult<ResolvedFile> {
    let arg = arg.trim();
    if !arg.starts_with("crow1") {
        if let Ok(path) = CatalogPath::normalize(arg) {
            let view = catalog.view()?;
            if let Some(entry) = view.get(&path) {
                return match &entry.kind {
                    EntryKind::File { cap, .. } => Ok(ResolvedFile {
                        cap: cap.clone(),
                        path: Some(path),
                    }),
                    EntryKind::Dir => Err(format!("{path} is a directory").into()),
                };
            }
        }
    }
    Ok(ResolvedFile {
        cap: resolve_cap(pins, arg)?,
        path: None,
    })
}

fn resolve_put_destination(
    catalog: &CatalogIndex,
    source: &str,
    dest: &str,
) -> DynResult<CatalogPath> {
    let dest_path = CatalogPath::normalize(dest)?;
    let view = catalog.view()?;
    let dest_is_dir =
        dest.trim_end().ends_with('/') || view.get(&dest_path).is_some_and(|entry| entry.is_dir());
    let final_path = if dest_is_dir {
        let name = default_name(source)
            .ok_or("destination is a directory; stdin puts need a full destination path")?;
        join_catalog_path(&dest_path, &name)?
    } else {
        dest_path
    };

    if let Some(parent) = final_path.parent() {
        match view.get(&parent) {
            Some(entry) if entry.is_dir() => {}
            Some(_) => return Err(format!("catalog parent is a file: {parent}").into()),
            None => {
                return Err(format!(
                    "catalog parent does not exist: {parent}; run `crow mkdir -p {parent}`"
                )
                .into());
            }
        }
    }
    Ok(final_path)
}

fn resolve_put_dir_destination(
    catalog: &CatalogIndex,
    source: &Path,
    dest: Option<&str>,
) -> DynResult<CatalogPath> {
    let source_name = source
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("source directory needs a UTF-8 basename; pass an explicit destination")?;

    let Some(dest) = dest else {
        return CatalogPath::normalize(&format!("/{source_name}")).map_err(Into::into);
    };

    let dest_path = CatalogPath::normalize(dest)?;
    let view = catalog.view()?;
    let dest_is_dir =
        dest.trim_end().ends_with('/') || view.get(&dest_path).is_some_and(|entry| entry.is_dir());
    if dest_is_dir {
        join_catalog_path(&dest_path, source_name)
    } else {
        Ok(dest_path)
    }
}

fn join_catalog_path(parent: &CatalogPath, name: &str) -> DynResult<CatalogPath> {
    let joined = if parent.as_str() == "/" {
        format!("/{name}")
    } else {
        format!("{}/{name}", parent.as_str().trim_end_matches('/'))
    };
    Ok(CatalogPath::normalize(&joined)?)
}

fn join_catalog_relative(base: &CatalogPath, relative: &Path) -> DynResult<CatalogPath> {
    let mut path = base.clone();
    for component in relative.components() {
        match component {
            std::path::Component::Normal(part) => {
                let part = part
                    .to_str()
                    .ok_or("catalog paths require UTF-8 file names")?;
                path = join_catalog_path(&path, part)?;
            }
            std::path::Component::CurDir => {}
            _ => return Err("catalog relative path cannot contain prefixes, roots, or ..".into()),
        }
    }
    Ok(path)
}

fn relative_catalog_path(base: &CatalogPath, child: &CatalogPath) -> DynResult<PathBuf> {
    if base.as_str() == child.as_str() {
        return Ok(PathBuf::new());
    }
    if !catalog_path_contains(base, child) {
        return Err(format!("{child} is not under {base}").into());
    }
    let relative = if base.as_str() == "/" {
        child.as_str().trim_start_matches('/')
    } else {
        child
            .as_str()
            .trim_start_matches(base.as_str())
            .trim_start_matches('/')
    };
    Ok(PathBuf::from(relative))
}

fn directory_manifest_from_catalog(
    view: &CatalogView,
    path: &CatalogPath,
) -> DynResult<DirectoryManifest> {
    let mut entries = Vec::new();
    for entry in catalog_subtree_entries(view, path) {
        let rel = relative_catalog_path(path, &entry.path)?;
        if rel.as_os_str().is_empty() {
            continue;
        }
        let rel = catalog_manifest_relative_path(&rel)?;
        match &entry.kind {
            EntryKind::Dir => entries.push(DirectoryEntry::dir(rel)),
            EntryKind::File { cap, name } => {
                entries.push(DirectoryEntry::file(rel, cap.clone(), name.clone()));
            }
        }
    }
    Ok(DirectoryManifest::new(unix_now(), entries)?)
}

fn directory_logical_size(
    crow: &Crow<FsStore>,
    manifest: &DirectoryManifest,
) -> DynResult<Option<u64>> {
    let mut total = 0u64;
    for cap in manifest.file_caps()? {
        let Ok(file_manifest) = open_manifest(crow, &cap) else {
            return Ok(None);
        };
        total = total.saturating_add(file_manifest.file_size);
    }
    Ok(Some(total))
}

fn directory_snapshot_name(path: &CatalogPath) -> Option<String> {
    Some(format!("{} snapshot", path.file_name().unwrap_or("root")))
}

fn catalog_manifest_relative_path(path: &Path) -> DynResult<String> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::Normal(part) => {
                parts.push(
                    part.to_str()
                        .ok_or("directory caps require UTF-8 catalog paths")?
                        .to_string(),
                );
            }
            std::path::Component::CurDir => {}
            _ => return Err("directory cap paths must be relative".into()),
        }
    }
    if parts.is_empty() {
        return Err("directory cap path must not be empty".into());
    }
    Ok(parts.join("/"))
}

fn catalog_caps_under(view: &CatalogView, path: &CatalogPath) -> Vec<Cap> {
    view.files()
        .into_iter()
        .filter(|entry| catalog_path_contains(path, &entry.path))
        .filter_map(|entry| entry.cap().cloned())
        .collect()
}

fn catalog_caps_not_under(view: &CatalogView, path: &CatalogPath) -> Vec<Cap> {
    view.files()
        .into_iter()
        .filter(|entry| !catalog_path_contains(path, &entry.path))
        .filter_map(|entry| entry.cap().cloned())
        .collect()
}

fn catalog_matches_arg(catalog: &CatalogIndex, arg: &str) -> DynResult<Vec<CatalogPath>> {
    let arg = arg.trim();
    let view = catalog.view()?;
    let mut paths: Vec<CatalogPath> = if arg.starts_with("crow1") {
        let cap = Cap::decode(arg)?;
        view.files()
            .into_iter()
            .filter(|entry| {
                entry
                    .cap()
                    .is_some_and(|entry_cap| entry_cap.manifest_hash == cap.manifest_hash)
            })
            .map(|entry| entry.path.clone())
            .collect()
    } else if !arg.is_empty() && arg.bytes().all(|b| b.is_ascii_hexdigit()) {
        let prefix = arg.to_ascii_lowercase();
        view.files()
            .into_iter()
            .filter(|entry| {
                entry.cap().is_some_and(|cap| {
                    cap.manifest_hash
                        .to_string()
                        .to_ascii_lowercase()
                        .starts_with(&prefix)
                })
            })
            .map(|entry| entry.path.clone())
            .collect()
    } else {
        Vec::new()
    };
    paths.sort();
    Ok(paths)
}

fn format_catalog_unpin_hint(arg: &str, paths: &[CatalogPath]) -> String {
    let mut msg = format!("'{arg}' is not a flat pin, but it is cataloged at:");
    for path in paths.iter().take(8) {
        msg.push_str("\n  ");
        msg.push_str(path.as_str());
    }
    if paths.len() > 8 {
        msg.push_str(&format!("\n  ... and {} more", paths.len() - 8));
    }
    msg.push_str("\nuse `crow unpin /path` to detach a catalog entry without deleting chunks");
    msg
}

fn catalog_path_contains(parent: &CatalogPath, child: &CatalogPath) -> bool {
    if parent.as_str() == "/" {
        return child.as_str() != "/";
    }
    child.as_str() == parent.as_str()
        || child
            .as_str()
            .starts_with(&format!("{}/", parent.as_str().trim_end_matches('/')))
}

fn catalog_subtree_entries<'a>(view: &'a CatalogView, path: &CatalogPath) -> Vec<&'a CatalogEntry> {
    let mut out = Vec::new();
    let mut stack = view.list(path);
    while let Some(entry) = stack.pop() {
        if entry.is_dir() {
            stack.extend(view.list(&entry.path));
        }
        out.push(entry);
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

fn print_catalog_listing(
    crow: &Crow<FsStore>,
    view: &CatalogView,
    path: &CatalogPath,
    long: bool,
) -> DynResult<()> {
    let Some(entry) = view.get(path) else {
        return Err(format!("catalog path not found: {path}").into());
    };

    if matches!(&entry.kind, EntryKind::File { .. }) {
        print_catalog_header(long);
        print_catalog_entry(crow, entry, long);
        return Ok(());
    }

    let entries = view.list(path);
    if entries.is_empty() {
        println!("(empty)");
        return Ok(());
    }

    print_catalog_header(long);
    for entry in entries {
        print_catalog_entry(crow, entry, long);
    }
    Ok(())
}

fn print_catalog_header(long: bool) {
    if long {
        println!(
            "{:<5}  {:>10}  {:<22}  {:<64}  PATH",
            "TYPE", "SIZE", "MIME", "HASH"
        );
    } else {
        println!(
            "{:<5}  {:>10}  {:<18}  {:<8}  NAME",
            "TYPE", "SIZE", "MIME", "HASH"
        );
    }
}

fn print_catalog_entry(crow: &Crow<FsStore>, entry: &CatalogEntry, long: bool) {
    match &entry.kind {
        EntryKind::Dir => {
            let name = catalog_display_name(entry, long);
            if long {
                println!(
                    "{:<5}  {:>10}  {:<22}  {:<64}  {}",
                    "dir", "-", "-", "-", name
                );
            } else {
                println!(
                    "{:<5}  {:>10}  {:<18}  {:<8}  {}",
                    "dir", "-", "-", "-", name
                );
            }
        }
        EntryKind::File { cap, .. } => {
            let hash = cap.manifest_hash.to_string();
            let hash_display = if long {
                hash.clone()
            } else {
                hash[..8].to_string()
            };
            let (size, mime) = match open_manifest(crow, cap) {
                Ok(manifest) => (
                    format_size(manifest.file_size as usize),
                    manifest.mime_type.to_string(),
                ),
                Err(_) => ("missing".into(), "missing".into()),
            };
            let name = catalog_display_name(entry, long);
            if long {
                println!(
                    "{:<5}  {:>10}  {:<22}  {:<64}  {}",
                    "file",
                    size,
                    truncate(&mime, 22),
                    hash_display,
                    name
                );
            } else {
                println!(
                    "{:<5}  {:>10}  {:<18}  {:<8}  {}",
                    "file",
                    size,
                    truncate(&mime, 18),
                    hash_display,
                    name
                );
            }
        }
    }
}

fn catalog_display_name(entry: &CatalogEntry, long: bool) -> String {
    if long {
        entry.path.as_str().to_string()
    } else {
        entry
            .path
            .file_name()
            .map(str::to_string)
            .unwrap_or_else(|| entry.path.as_str().to_string())
    }
}

fn resolve_cap(pins: &PinIndex, arg: &str) -> DynResult<Cap> {
    let arg = arg.trim();
    if arg.starts_with("crow1") {
        Ok(Cap::decode(arg)?)
    } else {
        Ok(resolve_pin(pins, arg)?.cap)
    }
}

fn default_name(path: &str) -> Option<String> {
    if path == "-" {
        None
    } else {
        Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
            .map(|s| s.to_string())
    }
}

fn resolve_pin(pins: &PinIndex, arg: &str) -> DynResult<PinRecord> {
    let arg = arg.trim();
    if let Some(rest) = arg.strip_prefix("crow1") {
        let _ = rest; // marker that this is a cap, not a hex prefix
        let cap = Cap::decode(arg)?;
        match pins.get(cap.manifest_hash.inner())? {
            Some(rec) => Ok(rec),
            None => Err(format!(
                "cap is valid but its manifest is not pinned in {}",
                pins.root().display()
            )
            .into()),
        }
    } else {
        let matches = pins.find_by_prefix(arg)?;
        match matches.len() {
            0 => Err(format!("no pinned manifest matches '{arg}'").into()),
            1 => Ok(matches.into_iter().next().unwrap()),
            n => {
                let mut msg = format!("ambiguous prefix '{arg}' ({n} matches):");
                for m in &matches {
                    msg.push_str("\n  ");
                    msg.push_str(&m.manifest_hash_hex[..16]);
                    if let Some(name) = &m.name {
                        msg.push_str("  ");
                        msg.push_str(name);
                    }
                }
                Err(msg.into())
            }
        }
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else if max <= 2 {
        s[..max].to_string()
    } else {
        format!("{}..", &s[..max - 2])
    }
}

fn format_short_date(unix_secs: u64) -> String {
    let (y, m, d) = civil_from_days((unix_secs / 86400) as i64);
    format!("{y:04}-{m:02}-{d:02}")
}

fn format_iso_timestamp(unix_secs: u64) -> String {
    let (y, m, d) = civil_from_days((unix_secs / 86400) as i64);
    let r = unix_secs % 86400;
    let h = r / 3600;
    let mi = (r % 3600) / 60;
    let s = r % 60;
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

struct ImportPlan {
    dirs: Vec<PathBuf>,
    files: Vec<ImportFile>,
    bytes: u64,
}

struct ImportFile {
    source: PathBuf,
    relative: PathBuf,
}

fn scan_import_dir(root: &Path) -> DynResult<ImportPlan> {
    let mut plan = ImportPlan {
        dirs: Vec::new(),
        files: Vec::new(),
        bytes: 0,
    };
    scan_import_dir_inner(root, Path::new(""), &mut plan)?;
    Ok(plan)
}

fn scan_import_dir_inner(abs: &Path, relative: &Path, plan: &mut ImportPlan) -> DynResult<()> {
    let mut entries = fs::read_dir(abs)?.collect::<std::result::Result<Vec<_>, io::Error>>()?;
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        let ty = entry.file_type()?;
        if ty.is_symlink() {
            return Err(format!("symlinks are not supported: {}", entry.path().display()).into());
        }
        let name = entry.file_name();
        let rel = relative.join(name);
        if ty.is_dir() {
            plan.dirs.push(rel.clone());
            scan_import_dir_inner(&entry.path(), &rel, plan)?;
        } else if ty.is_file() {
            let metadata = entry.metadata()?;
            plan.bytes += metadata.len();
            plan.files.push(ImportFile {
                source: entry.path(),
                relative: rel,
            });
        }
    }
    Ok(())
}

fn confirm(prompt: &str, yes: bool) -> DynResult<()> {
    if yes {
        return Ok(());
    }
    eprint!("{prompt}");
    io::stderr().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    match answer.trim().to_ascii_lowercase().as_str() {
        "y" | "yes" => Ok(()),
        _ => Err("aborted".into()),
    }
}

/// Howard Hinnant's `civil_from_days`: convert days-since-epoch to (Y, M, D),
/// proleptic Gregorian.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = y + if m <= 2 { 1 } else { 0 };
    (y, m as u32, d)
}

fn format_size_u64(bytes: u64) -> String {
    format_size(bytes as usize)
}

fn read_all(path: &str) -> io::Result<Vec<u8>> {
    if path == "-" {
        let mut buf = Vec::new();
        io::stdin().lock().read_to_end(&mut buf)?;
        Ok(buf)
    } else {
        fs::read(path)
    }
}

fn write_all(path: &str, bytes: &[u8]) -> io::Result<()> {
    if path == "-" {
        io::stdout().lock().write_all(bytes)?;
    } else {
        fs::write(path, bytes)?;
    }
    Ok(())
}

fn guess_mime(path: &str) -> &'static str {
    guess_mime_path(Path::new(path))
}

fn guess_mime_path(path: &Path) -> &'static str {
    let ext = path.extension().and_then(|e| e.to_str());
    match ext {
        Some("txt") | Some("md") | Some("log") => "text/plain",
        Some("html") | Some("htm") => "text/html",
        Some("css") => "text/css",
        Some("js") | Some("mjs") => "text/javascript",
        Some("json") => "application/json",
        Some("xml") => "application/xml",
        Some("yaml") | Some("yml") => "application/yaml",
        Some("toml") => "application/toml",
        Some("pdf") => "application/pdf",
        Some("zip") => "application/zip",
        Some("tar") => "application/x-tar",
        Some("gz") => "application/gzip",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("svg") => "image/svg+xml",
        Some("mp3") => "audio/mpeg",
        Some("wav") => "audio/wav",
        Some("mp4") => "video/mp4",
        Some("webm") => "video/webm",
        Some("rs") => "text/x-rust",
        Some("py") => "text/x-python",
        Some("c") | Some("h") => "text/x-c",
        Some("go") => "text/x-go",
        _ => "application/octet-stream",
    }
}

/// Pick a chunk size that aims for K=3 plaintext chunks per stripe so a
/// small file does not balloon to 5× the default 1 MiB share size.
fn auto_chunk_size(file_size: usize) -> u32 {
    const MIN: u32 = 240; // 240 + 16 = 256 (4 * 64)
    let target = file_size / 3;
    if target <= MIN as usize {
        return MIN;
    }
    if target >= DEFAULT_CHUNK_SIZE as usize {
        return DEFAULT_CHUNK_SIZE;
    }
    let aligned = (target + AEAD_TAG_LEN) / RS_ALIGN * RS_ALIGN;
    let candidate = aligned.saturating_sub(AEAD_TAG_LEN) as u32;
    candidate.clamp(MIN, DEFAULT_CHUNK_SIZE)
}

fn format_size(bytes: usize) -> String {
    const KIB: usize = 1024;
    const MIB: usize = KIB * 1024;
    const GIB: usize = MIB * 1024;
    if bytes >= GIB {
        format!("{:.2} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.2} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.2} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crow::{ManifestHash, ManifestKey};

    fn cap_with_hash_byte(b: u8) -> Cap {
        Cap::new_read(
            ManifestHash::from_bytes([b; 32]),
            ManifestKey::from_bytes([b; 32]),
        )
    }

    fn stored_cap(crow: &Crow<FsStore>, payload: &[u8]) -> Cap {
        let identity = Identity::random();
        crow.put_bytes(payload, "text/plain", ErasureParams::default(), &identity)
            .unwrap()
    }

    #[test]
    fn fetch_without_name_preserves_existing_pin_metadata() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pins = PinIndex::open(tmp.path()).unwrap();
        let cap = cap_with_hash_byte(0xAB);
        pins.add(
            cap.clone(),
            Some("report.pdf".into()),
            Some("important".into()),
        )
        .unwrap();

        let (name, comment) = fetch_pin_metadata(&pins, &cap, None).unwrap();
        assert_eq!(name.as_deref(), Some("report.pdf"));
        assert_eq!(comment.as_deref(), Some("important"));
    }

    #[test]
    fn fetch_name_override_preserves_existing_comment() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pins = PinIndex::open(tmp.path()).unwrap();
        let cap = cap_with_hash_byte(0xCD);
        pins.add(
            cap.clone(),
            Some("old.pdf".into()),
            Some("keep this".into()),
        )
        .unwrap();

        let (name, comment) = fetch_pin_metadata(&pins, &cap, Some("new.pdf".into())).unwrap();
        assert_eq!(name.as_deref(), Some("new.pdf"));
        assert_eq!(comment.as_deref(), Some("keep this"));
    }

    #[test]
    fn resolve_peer_socket_addr_bypasses_snapshot() {
        let tmp = tempfile::TempDir::new().unwrap();
        let addr = "127.0.0.1:7070".parse().unwrap();

        assert_eq!(
            resolve_peer(tmp.path(), "127.0.0.1:7070").unwrap(),
            vec![addr]
        );
    }

    #[test]
    fn resolve_peer_returns_all_snapshot_addresses() {
        let tmp = tempfile::TempDir::new().unwrap();
        let peer = Identity::random();
        let self_id = Identity::random();
        let addresses = vec![
            "169.254.1.2:7070".parse().unwrap(),
            "192.168.1.10:7070".parse().unwrap(),
        ];
        let snap = PeerSnapshot {
            snapshot_at: peer_snapshot::now_unix(),
            self_info: SelfInfo {
                node_id: self_id.node_id(),
                friendly_name: Some("self".into()),
                address: "127.0.0.1:7070".parse().unwrap(),
            },
            peers: vec![PeerInfo {
                node_id: peer.node_id(),
                friendly_name: Some("laptop".into()),
                addresses: addresses.clone(),
                last_seen_unix: peer_snapshot::now_unix(),
            }],
        };
        peer_snapshot::save(&peer_snapshot::snapshot_path(tmp.path()), &snap).unwrap();

        assert_eq!(
            resolve_peer(tmp.path(), &peer.node_id().short()).unwrap(),
            addresses
        );
        assert_eq!(resolve_peer(tmp.path(), "laptop").unwrap(), addresses);
    }

    #[test]
    fn resolve_peer_ambiguous_name_lists_node_prefixes_and_addresses() {
        let tmp = tempfile::TempDir::new().unwrap();
        let peer_a = Identity::random();
        let peer_b = Identity::random();
        let self_id = Identity::random();
        let snap = PeerSnapshot {
            snapshot_at: peer_snapshot::now_unix(),
            self_info: SelfInfo {
                node_id: self_id.node_id(),
                friendly_name: Some("self".into()),
                address: "127.0.0.1:7070".parse().unwrap(),
            },
            peers: vec![
                PeerInfo {
                    node_id: peer_a.node_id(),
                    friendly_name: Some("laptop".into()),
                    addresses: vec!["192.168.1.10:7070".parse().unwrap()],
                    last_seen_unix: peer_snapshot::now_unix(),
                },
                PeerInfo {
                    node_id: peer_b.node_id(),
                    friendly_name: Some("laptop".into()),
                    addresses: vec!["192.168.1.11:7070".parse().unwrap()],
                    last_seen_unix: peer_snapshot::now_unix(),
                },
            ],
        };
        peer_snapshot::save(&peer_snapshot::snapshot_path(tmp.path()), &snap).unwrap();

        let err = resolve_peer(tmp.path(), "laptop").unwrap_err();
        let msg = err.to_string();

        assert!(msg.contains("ambiguous peer 'laptop'"));
        assert!(msg.contains(&peer_a.node_id().short()));
        assert!(msg.contains(&peer_b.node_id().short()));
        assert!(msg.contains("192.168.1.10:7070"));
        assert!(msg.contains("192.168.1.11:7070"));
        assert!(msg.contains("use a longer node-id prefix"));
    }

    #[test]
    fn connect_peer_falls_back_to_later_address() {
        let bad_tmp = tempfile::TempDir::new().unwrap();
        let good_tmp = tempfile::TempDir::new().unwrap();
        let rt = runtime().unwrap();
        let token = ClusterToken::random();
        let wrong_token = ClusterToken::random();
        let bad_server = rt
            .block_on(crow_net::serve(
                FsStore::open(bad_tmp.path()).unwrap(),
                wrong_token,
                "127.0.0.1:0".parse().unwrap(),
            ))
            .unwrap();
        let good_server = rt
            .block_on(crow_net::serve(
                FsStore::open(good_tmp.path()).unwrap(),
                token,
                "127.0.0.1:0".parse().unwrap(),
            ))
            .unwrap();
        let addresses = vec![bad_server.local_addr(), good_server.local_addr()];

        let (connected_addr, _client) = connect_peer(&rt, token, "laptop", &addresses).unwrap();

        assert_eq!(connected_addr, good_server.local_addr());
    }

    #[test]
    fn signature_status_format_matches_info_output() {
        let identity = Identity::random();

        assert_eq!(
            format_signature_status(SignatureStatus::Unsigned),
            "signed    no (legacy/unsigned)"
        );
        assert_eq!(
            format_signature_status(SignatureStatus::Signed {
                creator: identity.node_id()
            }),
            format!("signed    yes ({})", identity.node_id().short())
        );
    }

    #[test]
    fn device_config_saves_and_loads_name() {
        let tmp = tempfile::TempDir::new().unwrap();
        let config = DeviceConfig {
            name: Some("laptop".into()),
        };

        config.save(tmp.path()).unwrap();

        assert_eq!(
            DeviceConfig::load(tmp.path()).unwrap().name.as_deref(),
            Some("laptop")
        );
    }

    #[test]
    fn device_name_validation_rejects_shell_hostile_names() {
        assert_eq!(validate_device_name("macbook-air").unwrap(), "macbook-air");
        assert!(validate_device_name("").is_err());
        assert!(validate_device_name("two words").is_err());
        assert!(validate_device_name("../../../x").is_err());
        assert!(validate_device_name(&"a".repeat(33)).is_err());
    }

    #[test]
    fn device_name_sanitizer_makes_hostname_command_safe() {
        assert_eq!(
            sanitize_device_name("Alice's MacBook Pro.local"),
            Some("Alice-s-MacBook-Pro.local".into())
        );
        assert_eq!(sanitize_device_name("///"), None);
        assert_eq!(sanitize_device_name(&"a".repeat(40)).unwrap().len(), 32);
    }

    #[test]
    fn serve_name_prefers_cli_override_then_saved_name() {
        let tmp = tempfile::TempDir::new().unwrap();
        DeviceConfig {
            name: Some("saved".into()),
        }
        .save(tmp.path())
        .unwrap();

        assert_eq!(
            resolve_serve_name(tmp.path(), Some("override".into()))
                .unwrap()
                .as_deref(),
            Some("override")
        );
        assert_eq!(
            resolve_serve_name(tmp.path(), None).unwrap().as_deref(),
            Some("saved")
        );
        assert!(resolve_serve_name(tmp.path(), Some("bad name".into())).is_err());
    }

    #[test]
    fn setup_creates_identity_token_and_device_name() {
        let tmp = tempfile::TempDir::new().unwrap();

        let report = setup_device(tmp.path(), Some("laptop".into()), None, false).unwrap();

        assert_eq!(report.name.as_deref(), Some("laptop"));
        assert_eq!(report.token_action, SetupTokenAction::Created);
        assert_eq!(
            DeviceConfig::load(tmp.path()).unwrap().name.as_deref(),
            Some("laptop")
        );
        assert_eq!(TokenStore::open(tmp.path()).load().unwrap(), report.token);
        assert_eq!(
            Identity::load_or_create(tmp.path()).unwrap().node_id(),
            report.node_id
        );
    }

    #[test]
    fn setup_imports_existing_token_and_reuses_it() {
        let tmp = tempfile::TempDir::new().unwrap();
        let token = ClusterToken::from_bytes([9u8; 32]);

        let imported = setup_device(
            tmp.path(),
            Some("phone".into()),
            Some(token.encode()),
            false,
        )
        .unwrap();
        let reused = setup_device(tmp.path(), None, None, false).unwrap();

        assert_eq!(imported.token_action, SetupTokenAction::Imported);
        assert_eq!(reused.token_action, SetupTokenAction::Existing);
        assert_eq!(reused.token, token);
        assert_eq!(reused.name.as_deref(), Some("phone"));
    }

    #[test]
    fn setup_force_token_replaces_existing_token() {
        let tmp = tempfile::TempDir::new().unwrap();
        let original = setup_device(tmp.path(), Some("laptop".into()), None, false)
            .unwrap()
            .token;

        let replaced = setup_device(tmp.path(), None, None, true).unwrap();

        assert_eq!(replaced.token_action, SetupTokenAction::Replaced);
        assert_ne!(replaced.token.encode(), original.encode());
    }

    #[test]
    fn tree_renders_nested_catalog() {
        let tmp = tempfile::TempDir::new().unwrap();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        catalog.mkdir("/docs/projects", true).unwrap();
        catalog.mkdir("/photos", false).unwrap();
        catalog
            .put_file(
                "/docs/notes.md",
                cap_with_hash_byte(0x41),
                Some("notes.md".into()),
            )
            .unwrap();
        catalog
            .put_file(
                "/docs/projects/crow.md",
                cap_with_hash_byte(0x42),
                Some("crow.md".into()),
            )
            .unwrap();

        let root = CatalogPath::root();
        let lines = catalog_tree_lines(&catalog.view().unwrap(), &root).unwrap();

        assert_eq!(
            lines,
            vec![
                "/",
                "|-- docs/",
                "|   |-- notes.md",
                "|   `-- projects/",
                "|       `-- crow.md",
                "`-- photos/",
            ]
        );
    }

    #[test]
    fn tree_can_start_at_file_or_directory() {
        let tmp = tempfile::TempDir::new().unwrap();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        catalog.mkdir("/docs", false).unwrap();
        catalog
            .put_file(
                "/docs/notes.md",
                cap_with_hash_byte(0x43),
                Some("notes.md".into()),
            )
            .unwrap();
        let view = catalog.view().unwrap();

        assert_eq!(
            catalog_tree_lines(&view, &CatalogPath::normalize("/docs").unwrap()).unwrap(),
            vec!["/docs/", "`-- notes.md"]
        );
        assert_eq!(
            catalog_tree_lines(&view, &CatalogPath::normalize("/docs/notes.md").unwrap()).unwrap(),
            vec!["/docs/notes.md"]
        );
    }

    #[test]
    fn tree_missing_path_errors() {
        let tmp = tempfile::TempDir::new().unwrap();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        let view = catalog.view().unwrap();

        let err =
            catalog_tree_lines(&view, &CatalogPath::normalize("/missing").unwrap()).unwrap_err();

        assert!(err.to_string().contains("catalog path not found"));
    }

    #[test]
    fn find_matches_catalog_basenames() {
        let tmp = tempfile::TempDir::new().unwrap();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        catalog.mkdir("/docs/projects", true).unwrap();
        catalog
            .put_file(
                "/docs/notes.md",
                cap_with_hash_byte(0x44),
                Some("notes.md".into()),
            )
            .unwrap();
        catalog
            .put_file(
                "/docs/projects/readme.md",
                cap_with_hash_byte(0x45),
                Some("readme.md".into()),
            )
            .unwrap();
        catalog
            .put_file(
                "/docs/projects/report-01.pdf",
                cap_with_hash_byte(0x46),
                Some("report-01.pdf".into()),
            )
            .unwrap();

        let matches = catalog_find_matches(&catalog.view().unwrap(), "*.md").unwrap();

        assert_eq!(
            matches.iter().map(CatalogPath::as_str).collect::<Vec<_>>(),
            vec!["/docs/notes.md", "/docs/projects/readme.md"]
        );
    }

    #[test]
    fn find_matches_question_mark_and_directories() {
        let tmp = tempfile::TempDir::new().unwrap();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        catalog.mkdir("/docs", false).unwrap();
        catalog.mkdir("/dogs", false).unwrap();
        catalog.mkdir("/docks", false).unwrap();
        catalog
            .put_file(
                "/docs/report-01.pdf",
                cap_with_hash_byte(0x47),
                Some("report-01.pdf".into()),
            )
            .unwrap();

        let dir_matches = catalog_find_matches(&catalog.view().unwrap(), "do?s").unwrap();
        let file_matches = catalog_find_matches(&catalog.view().unwrap(), "report-??.pdf").unwrap();

        assert_eq!(
            dir_matches
                .iter()
                .map(CatalogPath::as_str)
                .collect::<Vec<_>>(),
            vec!["/docs", "/dogs"]
        );
        assert_eq!(
            file_matches
                .iter()
                .map(CatalogPath::as_str)
                .collect::<Vec<_>>(),
            vec!["/docs/report-01.pdf"]
        );
    }

    #[test]
    fn find_rejects_path_patterns() {
        let tmp = tempfile::TempDir::new().unwrap();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        let err = catalog_find_matches(&catalog.view().unwrap(), "docs/*.md").unwrap_err();

        assert!(err.to_string().contains("basenames only"));
    }

    #[test]
    fn simple_glob_matching_supports_star_and_question_mark() {
        assert!(simple_glob_matches("*.md", "notes.md"));
        assert!(simple_glob_matches("report-??.pdf", "report-01.pdf"));
        assert!(!simple_glob_matches("report-??.pdf", "report-001.pdf"));
        assert!(!simple_glob_matches("*.md", "notes.MD"));
    }

    #[test]
    fn grep_searches_single_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pins = PinIndex::open(tmp.path()).unwrap();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        let crow = Crow::new(FsStore::open(tmp.path()).unwrap());
        let cap = stored_cap(&crow, b"alpha\nTODO one\nbeta\n");
        catalog
            .put_file("/notes.txt", cap, Some("notes.txt".into()))
            .unwrap();

        let report = grep_report(&crow, &pins, &catalog, "TODO", "/notes.txt").unwrap();

        assert_eq!(
            report,
            GrepReport {
                matches: vec![GrepMatch {
                    display: "/notes.txt".into(),
                    line: 2,
                    text: "TODO one".into(),
                }],
                errors: vec![],
            }
        );
    }

    #[test]
    fn grep_recurses_catalog_directory() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pins = PinIndex::open(tmp.path()).unwrap();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        let crow = Crow::new(FsStore::open(tmp.path()).unwrap());
        let a = stored_cap(&crow, b"TODO root\n");
        let b = stored_cap(&crow, b"skip\nTODO nested\n");
        catalog.mkdir("/docs/nested", true).unwrap();
        catalog
            .put_file("/docs/a.txt", a, Some("a.txt".into()))
            .unwrap();
        catalog
            .put_file("/docs/nested/b.txt", b, Some("b.txt".into()))
            .unwrap();

        let report = grep_report(&crow, &pins, &catalog, "TODO", "/docs").unwrap();
        let displays = report
            .matches
            .iter()
            .map(|hit| (hit.display.as_str(), hit.line, hit.text.as_str()))
            .collect::<Vec<_>>();

        assert_eq!(
            displays,
            vec![
                ("/docs/a.txt", 1, "TODO root"),
                ("/docs/nested/b.txt", 2, "TODO nested"),
            ]
        );
        assert!(report.errors.is_empty());
    }

    #[test]
    fn grep_no_matches_success() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pins = PinIndex::open(tmp.path()).unwrap();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        let crow = Crow::new(FsStore::open(tmp.path()).unwrap());
        let cap = stored_cap(&crow, b"nothing here\n");
        catalog
            .put_file("/notes.txt", cap, Some("notes.txt".into()))
            .unwrap();

        let report = grep_report(&crow, &pins, &catalog, "TODO", "/notes.txt").unwrap();

        assert!(report.matches.is_empty());
        assert!(report.errors.is_empty());
    }

    #[test]
    fn grep_invalid_regex_errors() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pins = PinIndex::open(tmp.path()).unwrap();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        let crow = Crow::new(FsStore::open(tmp.path()).unwrap());

        let err = grep_report(&crow, &pins, &catalog, "[", "/notes.txt").unwrap_err();

        assert!(err.to_string().contains("regex parse error"));
    }

    #[test]
    fn grep_reports_missing_files() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pins = PinIndex::open(tmp.path()).unwrap();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        let crow = Crow::new(FsStore::open(tmp.path()).unwrap());
        catalog
            .put_file(
                "/missing.txt",
                cap_with_hash_byte(0x51),
                Some("missing.txt".into()),
            )
            .unwrap();

        let report = grep_report(&crow, &pins, &catalog, "TODO", "/missing.txt").unwrap();

        assert!(report.matches.is_empty());
        assert_eq!(report.errors.len(), 1);
        assert!(report.errors[0].contains("/missing.txt"));
    }

    #[test]
    fn du_sums_logical_size_but_deduplicates_stored_objects() {
        let tmp = tempfile::TempDir::new().unwrap();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        let crow = Crow::new(FsStore::open(tmp.path()).unwrap());
        let cap = stored_cap(&crow, b"shared");
        catalog.mkdir("/docs/nested", true).unwrap();
        catalog
            .put_file("/docs/a.txt", cap.clone(), Some("a.txt".into()))
            .unwrap();
        catalog
            .put_file("/docs/nested/b.txt", cap, Some("b.txt".into()))
            .unwrap();
        let path = CatalogPath::normalize("/docs").unwrap();

        let report = catalog_du_report(&crow, &catalog.view().unwrap(), &path).unwrap();

        assert_eq!(report.files, 2);
        assert_eq!(report.directories, 1);
        assert_eq!(report.logical_bytes, 12);
        assert_eq!(report.unknown_files, 0);
        assert_eq!(report.stored_manifests, 1);
        assert_eq!(report.stored_chunks, 5);
        assert!(report.stored_bytes > report.logical_bytes);
    }

    #[test]
    fn du_reports_file_targets_and_missing_manifests() {
        let tmp = tempfile::TempDir::new().unwrap();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        let crow = Crow::new(FsStore::open(tmp.path()).unwrap());
        let missing = cap_with_hash_byte(0x48);
        catalog.mkdir("/docs", false).unwrap();
        catalog
            .put_file("/docs/missing.txt", missing, Some("missing.txt".into()))
            .unwrap();
        let path = CatalogPath::normalize("/docs/missing.txt").unwrap();

        let report = catalog_du_report(&crow, &catalog.view().unwrap(), &path).unwrap();

        assert_eq!(report.files, 1);
        assert_eq!(report.directories, 0);
        assert_eq!(report.logical_bytes, 0);
        assert_eq!(report.unknown_files, 1);
        assert_eq!(report.stored_manifests, 0);
        assert_eq!(report.stored_chunks, 0);
        assert!(
            format_du_report(&report)
                .iter()
                .any(|line| line == "unknown       1 file")
        );
    }

    #[test]
    fn du_missing_path_errors() {
        let tmp = tempfile::TempDir::new().unwrap();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        let crow = Crow::new(FsStore::open(tmp.path()).unwrap());
        let err = catalog_du_report(
            &crow,
            &catalog.view().unwrap(),
            &CatalogPath::normalize("/missing").unwrap(),
        )
        .unwrap_err();

        assert!(err.to_string().contains("catalog path not found"));
    }

    #[test]
    fn cat_reads_catalog_path_and_full_cap() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pins = PinIndex::open(tmp.path()).unwrap();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        let crow = Crow::new(FsStore::open(tmp.path()).unwrap());
        let cap = stored_cap(&crow, b"hello from cat\n");
        catalog.mkdir("/docs", false).unwrap();
        catalog
            .put_file("/docs/note.txt", cap.clone(), Some("note.txt".into()))
            .unwrap();

        assert_eq!(
            cat_bytes(&crow, &pins, &catalog, "/docs/note.txt").unwrap(),
            b"hello from cat\n"
        );
        assert_eq!(
            cat_bytes(&crow, &pins, &catalog, &cap.encode()).unwrap(),
            b"hello from cat\n"
        );
    }

    #[test]
    fn cat_reads_pinned_prefix() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pins = PinIndex::open(tmp.path()).unwrap();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        let crow = Crow::new(FsStore::open(tmp.path()).unwrap());
        let cap = stored_cap(&crow, b"prefix bytes");
        pins.add(cap.clone(), Some("prefix.txt".into()), None)
            .unwrap();
        let prefix = &cap.manifest_hash.to_string()[..8];

        assert_eq!(
            cat_bytes(&crow, &pins, &catalog, prefix).unwrap(),
            b"prefix bytes"
        );
    }

    #[test]
    fn cat_rejects_directories() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pins = PinIndex::open(tmp.path()).unwrap();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        let crow = Crow::new(FsStore::open(tmp.path()).unwrap());
        catalog.mkdir("/docs", false).unwrap();

        let err = cat_bytes(&crow, &pins, &catalog, "/docs").unwrap_err();

        assert!(err.to_string().contains("is a directory"));
    }

    #[test]
    fn cap_resolves_catalog_file_full_cap_and_pinned_prefix() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pins = PinIndex::open(tmp.path()).unwrap();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        let cap = cap_with_hash_byte(0x61);
        catalog
            .put_file("/note.txt", cap.clone(), Some("note.txt".into()))
            .unwrap();
        pins.add(cap.clone(), Some("note.txt".into()), None)
            .unwrap();
        let prefix = &cap.manifest_hash.to_string()[..8];

        assert_eq!(
            cap_for_target(&pins, &catalog, "/note.txt")
                .unwrap()
                .encode(),
            cap.encode()
        );
        assert_eq!(
            cap_for_target(&pins, &catalog, &cap.encode())
                .unwrap()
                .encode(),
            cap.encode()
        );
        assert_eq!(
            cap_for_target(&pins, &catalog, prefix).unwrap().encode(),
            cap.encode()
        );
    }

    #[test]
    fn cap_rejects_catalog_directories_and_missing_paths() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pins = PinIndex::open(tmp.path()).unwrap();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        catalog.mkdir("/docs", false).unwrap();

        let dir_err = cap_for_target(&pins, &catalog, "/docs").unwrap_err();
        let missing_err = cap_for_target(&pins, &catalog, "/missing.txt").unwrap_err();

        assert!(dir_err.to_string().contains("catalog directory"));
        assert!(dir_err.to_string().contains("crow share /docs"));
        assert!(missing_err.to_string().contains("catalog path not found"));
    }

    #[test]
    fn share_catalog_file_reports_existing_cap_and_token_state() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pins = PinIndex::open(tmp.path()).unwrap();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        let crow = Crow::new(FsStore::open(tmp.path()).unwrap());
        let identity = Identity::random();
        let cap = stored_cap(&crow, b"share me");
        TokenStore::open(tmp.path())
            .save(ClusterToken::from_bytes([1u8; 32]))
            .unwrap();
        catalog
            .put_file("/docs.txt", cap.clone(), Some("docs.txt".into()))
            .unwrap();

        let report = share_target(
            tmp.path(),
            &crow,
            &pins,
            &catalog,
            &identity,
            ShareRequest {
                arg: "/docs.txt",
                name: None,
            },
        )
        .unwrap();

        assert_eq!(report.kind, ShareKind::File);
        assert_eq!(report.cap.encode(), cap.encode());
        assert_eq!(
            report.suggested_dest.as_ref().map(CatalogPath::as_str),
            Some("/docs.txt")
        );
        assert!(report.token_configured);
    }

    #[test]
    fn share_full_cap_does_not_require_token() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pins = PinIndex::open(tmp.path()).unwrap();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        let crow = Crow::new(FsStore::open(tmp.path()).unwrap());
        let identity = Identity::random();
        let cap = cap_with_hash_byte(0x62);

        let report = share_target(
            tmp.path(),
            &crow,
            &pins,
            &catalog,
            &identity,
            ShareRequest {
                arg: &cap.encode(),
                name: None,
            },
        )
        .unwrap();

        assert_eq!(report.kind, ShareKind::Cap);
        assert_eq!(report.cap.encode(), cap.encode());
        assert!(!report.token_configured);
    }

    #[test]
    fn share_directory_creates_pinned_snapshot_cap() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pins = PinIndex::open(tmp.path()).unwrap();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        let crow = Crow::new(FsStore::open(tmp.path()).unwrap());
        let identity = Identity::random();
        let child = stored_cap(&crow, b"child");
        catalog.mkdir("/docs/nested", true).unwrap();
        catalog
            .put_file("/docs/nested/file.txt", child, Some("file.txt".into()))
            .unwrap();

        let report = share_target(
            tmp.path(),
            &crow,
            &pins,
            &catalog,
            &identity,
            ShareRequest {
                arg: "/docs",
                name: Some("docs shared".into()),
            },
        )
        .unwrap();

        assert_eq!(report.kind, ShareKind::DirectorySnapshot);
        let manifest = crow.open_directory_manifest(&report.cap).unwrap();
        assert_eq!(manifest.file_count(), 1);
        let pin = pins
            .get(report.cap.manifest_hash.inner())
            .unwrap()
            .expect("directory snapshot should be pinned");
        assert_eq!(pin.name.as_deref(), Some("docs shared"));
    }

    #[test]
    fn receive_catalogs_file_to_explicit_path_and_creates_parents() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pins = PinIndex::open(tmp.path()).unwrap();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        let crow = Crow::new(FsStore::open(tmp.path()).unwrap());
        let cap = stored_cap(&crow, b"received");

        let report =
            catalog_received_cap(&crow, &pins, &catalog, &cap, "/inbox/report.txt", None).unwrap();

        assert_eq!(
            report,
            ReceiveCatalogReport::File {
                path: CatalogPath::normalize("/inbox/report.txt").unwrap()
            }
        );
        let view = catalog.view().unwrap();
        assert!(
            view.get(&CatalogPath::normalize("/inbox").unwrap())
                .unwrap()
                .is_dir()
        );
        assert_eq!(
            view.get(&CatalogPath::normalize("/inbox/report.txt").unwrap())
                .unwrap()
                .cap()
                .map(Cap::encode),
            Some(cap.encode())
        );
    }

    #[test]
    fn receive_catalogs_file_into_directory_from_pin_name() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pins = PinIndex::open(tmp.path()).unwrap();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        let crow = Crow::new(FsStore::open(tmp.path()).unwrap());
        let cap = stored_cap(&crow, b"received");
        pins.add(cap.clone(), Some("report.txt".into()), None)
            .unwrap();
        catalog.mkdir("/inbox", false).unwrap();

        let report = catalog_received_cap(&crow, &pins, &catalog, &cap, "/inbox/", None).unwrap();

        assert_eq!(
            report,
            ReceiveCatalogReport::File {
                path: CatalogPath::normalize("/inbox/report.txt").unwrap()
            }
        );
    }

    #[test]
    fn receive_rejects_directory_destination_without_name_and_overwrites() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pins = PinIndex::open(tmp.path()).unwrap();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        let crow = Crow::new(FsStore::open(tmp.path()).unwrap());
        let cap = stored_cap(&crow, b"received");
        catalog.mkdir("/inbox", false).unwrap();
        catalog
            .put_file(
                "/inbox/existing.txt",
                cap.clone(),
                Some("existing.txt".into()),
            )
            .unwrap();

        let no_name =
            catalog_received_cap(&crow, &pins, &catalog, &cap, "/inbox/", None).unwrap_err();
        let overwrite =
            catalog_received_cap(&crow, &pins, &catalog, &cap, "/inbox/existing.txt", None)
                .unwrap_err();

        assert!(no_name.to_string().contains("pass --name"));
        assert!(overwrite.to_string().contains("destination already exists"));
    }

    #[test]
    fn receive_rejects_bad_inferred_file_name() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pins = PinIndex::open(tmp.path()).unwrap();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        let crow = Crow::new(FsStore::open(tmp.path()).unwrap());
        let cap = stored_cap(&crow, b"received");
        pins.add(cap.clone(), Some("bad/name.txt".into()), None)
            .unwrap();
        catalog.mkdir("/inbox", false).unwrap();

        let err = catalog_received_cap(&crow, &pins, &catalog, &cap, "/inbox/", None).unwrap_err();

        assert!(err.to_string().contains("single path segment"));
    }

    #[test]
    fn receive_imports_directory_snapshot() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pins = PinIndex::open(tmp.path()).unwrap();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        let crow = Crow::new(FsStore::open(tmp.path()).unwrap());
        let identity = Identity::random();
        let child = stored_cap(&crow, b"child");
        let manifest = DirectoryManifest::new(
            unix_now(),
            vec![
                DirectoryEntry::dir("nested"),
                DirectoryEntry::file("nested/file.txt", child, Some("file.txt".into())),
            ],
        )
        .unwrap();
        let dir_cap = crow.put_directory_manifest(&manifest, &identity).unwrap();

        let report =
            catalog_received_cap(&crow, &pins, &catalog, &dir_cap, "/imports/docs", None).unwrap();

        assert_eq!(
            report,
            ReceiveCatalogReport::Directory {
                path: CatalogPath::normalize("/imports/docs").unwrap(),
                files: 1,
                directories: 1
            }
        );
        assert!(
            catalog
                .view()
                .unwrap()
                .get(&CatalogPath::normalize("/imports/docs/nested/file.txt").unwrap())
                .is_some()
        );
    }

    #[test]
    fn cp_copies_catalog_file_to_new_path() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pins = PinIndex::open(tmp.path()).unwrap();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        let cap = cap_with_hash_byte(0x41);
        catalog.mkdir("/docs", false).unwrap();
        catalog.mkdir("/archive", false).unwrap();
        catalog
            .put_file("/docs/a.txt", cap.clone(), Some("a.txt".into()))
            .unwrap();

        cmd_cp(&pins, &catalog, "/docs/a.txt", "/archive/a-copy.txt").unwrap();

        let view = catalog.view().unwrap();
        let source = view
            .get(&CatalogPath::normalize("/docs/a.txt").unwrap())
            .unwrap();
        let copy = view
            .get(&CatalogPath::normalize("/archive/a-copy.txt").unwrap())
            .unwrap();
        assert_eq!(source.cap().map(Cap::encode), Some(cap.encode()));
        assert_eq!(copy.cap().map(Cap::encode), Some(cap.encode()));
        assert!(matches!(
            &copy.kind,
            EntryKind::File { name, .. } if name.as_deref() == Some("a-copy.txt")
        ));
    }

    #[test]
    fn cp_copies_into_existing_directory() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pins = PinIndex::open(tmp.path()).unwrap();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        let cap = cap_with_hash_byte(0x42);
        catalog.mkdir("/docs", false).unwrap();
        catalog.mkdir("/archive", false).unwrap();
        catalog
            .put_file("/docs/report.pdf", cap.clone(), Some("report.pdf".into()))
            .unwrap();

        cmd_cp(&pins, &catalog, "/docs/report.pdf", "/archive/").unwrap();

        let view = catalog.view().unwrap();
        let copy = view
            .get(&CatalogPath::normalize("/archive/report.pdf").unwrap())
            .unwrap();
        assert_eq!(copy.cap().map(Cap::encode), Some(cap.encode()));
        assert!(matches!(
            &copy.kind,
            EntryKind::File { name, .. } if name.as_deref() == Some("report.pdf")
        ));
    }

    #[test]
    fn cp_uses_pin_name_for_cap_source_into_directory() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pins = PinIndex::open(tmp.path()).unwrap();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        let cap = cap_with_hash_byte(0x43);
        pins.add(cap.clone(), Some("friend.txt".into()), None)
            .unwrap();
        catalog.mkdir("/imports", false).unwrap();
        let prefix = &cap.manifest_hash.to_string()[..8];

        cmd_cp(&pins, &catalog, prefix, "/imports/").unwrap();

        let view = catalog.view().unwrap();
        let copy = view
            .get(&CatalogPath::normalize("/imports/friend.txt").unwrap())
            .unwrap();
        assert_eq!(copy.cap().map(Cap::encode), Some(cap.encode()));
        assert!(matches!(
            &copy.kind,
            EntryKind::File { name, .. } if name.as_deref() == Some("friend.txt")
        ));
    }

    #[test]
    fn cp_refuses_overwrite_and_directory_source() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pins = PinIndex::open(tmp.path()).unwrap();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        let cap = cap_with_hash_byte(0x44);
        catalog.mkdir("/docs", false).unwrap();
        catalog
            .put_file("/docs/source.txt", cap.clone(), Some("source.txt".into()))
            .unwrap();
        catalog
            .put_file("/docs/existing.txt", cap, Some("existing.txt".into()))
            .unwrap();

        let overwrite = cmd_cp(&pins, &catalog, "/docs/source.txt", "/docs/existing.txt")
            .expect_err("expected overwrite error");
        assert!(overwrite.to_string().contains("destination already exists"));

        let dir_source =
            cmd_cp(&pins, &catalog, "/docs", "/copy").expect_err("expected directory error");
        assert!(dir_source.to_string().contains("is a directory"));
    }

    #[test]
    fn stat_no_arg_reports_store_stats() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pins = PinIndex::open(tmp.path()).unwrap();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        let crow = Crow::new(FsStore::open(tmp.path()).unwrap());

        let lines = store_stat_lines(&crow, &pins, &catalog).unwrap();

        assert!(lines.iter().any(|line| line.starts_with("store         ")));
        assert!(lines.iter().any(|line| line == "pins          0"));
        assert!(lines.iter().any(|line| line == "catalog files 0"));
    }

    #[test]
    fn stat_catalog_file_includes_cap_pin_and_mime() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pins = PinIndex::open(tmp.path()).unwrap();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        let crow = Crow::new(FsStore::open(tmp.path()).unwrap());
        let cap = stored_cap(&crow, b"stat bytes");
        pins.add(cap.clone(), Some("note.txt".into()), None)
            .unwrap();
        catalog.mkdir("/docs", false).unwrap();
        catalog
            .put_file("/docs/note.txt", cap.clone(), Some("note.txt".into()))
            .unwrap();

        let lines = stat_lines(&crow, &pins, &catalog, "/docs/note.txt").unwrap();

        assert!(lines.contains(&"path      /docs/note.txt".into()));
        assert!(lines.contains(&"type      file".into()));
        assert!(lines.contains(&format!("cap       {}", cap.encode())));
        assert!(lines.contains(&"mime      text/plain".into()));
        assert!(lines.iter().any(|line| line.starts_with("pinned    ")));
        assert!(lines.contains(&"cataloged yes".into()));
    }

    #[test]
    fn stat_catalog_dir_summarizes_subtree() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pins = PinIndex::open(tmp.path()).unwrap();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        let crow = Crow::new(FsStore::open(tmp.path()).unwrap());
        let a = stored_cap(&crow, b"abc");
        let b = stored_cap(&crow, b"de");
        catalog.mkdir("/docs/nested", true).unwrap();
        catalog
            .put_file("/docs/a.txt", a, Some("a.txt".into()))
            .unwrap();
        catalog
            .put_file("/docs/nested/b.txt", b, Some("b.txt".into()))
            .unwrap();

        let lines = stat_lines(&crow, &pins, &catalog, "/docs").unwrap();

        assert!(lines.contains(&"path      /docs".into()));
        assert!(lines.contains(&"type      catalog directory".into()));
        assert!(lines.contains(&"files     2".into()));
        assert!(lines.contains(&"dirs      1".into()));
        assert!(lines.contains(&"size      5 B".into()));
        assert!(lines.contains(&"cataloged yes".into()));
    }

    #[test]
    fn stat_full_cap_reports_not_cataloged() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pins = PinIndex::open(tmp.path()).unwrap();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        let crow = Crow::new(FsStore::open(tmp.path()).unwrap());
        let cap = stored_cap(&crow, b"loose");

        let lines = stat_lines(&crow, &pins, &catalog, &cap.encode()).unwrap();

        assert!(lines.contains(&"type      file".into()));
        assert!(lines.contains(&format!("cap       {}", cap.encode())));
        assert!(lines.contains(&"pinned    no".into()));
        assert!(lines.contains(&"cataloged no".into()));
    }

    #[test]
    fn unpin_catalog_file_detaches_without_deleting_chunks() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pins = PinIndex::open(tmp.path()).unwrap();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        let crow = Crow::new(FsStore::open(tmp.path()).unwrap());
        let cap = stored_cap(&crow, b"keep bytes");
        catalog
            .put_file("/note.txt", cap.clone(), Some("note.txt".into()))
            .unwrap();

        cmd_unpin(&pins, &catalog, "/note.txt", false).unwrap();

        let path = CatalogPath::normalize("/note.txt").unwrap();
        assert!(catalog.view().unwrap().get(&path).is_none());
        assert!(
            crow.store()
                .has(Namespace::Manifests, cap.manifest_hash.inner())
                .unwrap()
        );
        assert_eq!(crow.get_bytes(&cap).unwrap(), b"keep bytes");
    }

    #[test]
    fn unpin_catalog_dir_requires_recursive() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pins = PinIndex::open(tmp.path()).unwrap();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        let cap = cap_with_hash_byte(0x11);
        catalog.mkdir("/docs", false).unwrap();
        catalog
            .put_file("/docs/a.txt", cap, Some("a.txt".into()))
            .unwrap();

        let err = cmd_unpin(&pins, &catalog, "/docs", false).expect_err("expected error");

        assert!(err.to_string().contains("use `crow unpin -r /docs`"));
        let path = CatalogPath::normalize("/docs/a.txt").unwrap();
        assert!(catalog.view().unwrap().get(&path).is_some());
    }

    #[test]
    fn unpin_catalog_dir_recursive_detaches_subtree() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pins = PinIndex::open(tmp.path()).unwrap();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        catalog.mkdir("/docs/nested", true).unwrap();
        catalog
            .put_file(
                "/docs/a.txt",
                cap_with_hash_byte(0x21),
                Some("a.txt".into()),
            )
            .unwrap();
        catalog
            .put_file(
                "/docs/nested/b.txt",
                cap_with_hash_byte(0x22),
                Some("b.txt".into()),
            )
            .unwrap();

        cmd_unpin(&pins, &catalog, "/docs", true).unwrap();

        let docs = CatalogPath::normalize("/docs").unwrap();
        let nested = CatalogPath::normalize("/docs/nested/b.txt").unwrap();
        let view = catalog.view().unwrap();
        assert!(view.get(&docs).is_none());
        assert!(view.get(&nested).is_none());
    }

    #[test]
    fn unpin_full_cap_hint_lists_catalog_paths() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pins = PinIndex::open(tmp.path()).unwrap();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        let cap = cap_with_hash_byte(0x31);
        catalog
            .put_file("/cataloged.txt", cap.clone(), Some("cataloged.txt".into()))
            .unwrap();

        let err = cmd_unpin(&pins, &catalog, &cap.encode(), false).expect_err("expected error");

        assert!(err.to_string().contains("is cataloged at"));
        assert!(err.to_string().contains("/cataloged.txt"));
        assert!(err.to_string().contains("crow unpin /path"));
    }

    #[test]
    fn cap_dir_creates_pinned_directory_snapshot() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pins = PinIndex::open(tmp.path()).unwrap();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        let crow = Crow::new(FsStore::open(tmp.path()).unwrap());
        let child = stored_cap(&crow, b"snapshot bytes");
        catalog.mkdir("/docs/empty", true).unwrap();
        catalog
            .put_file("/docs/file.txt", child, Some("file.txt".into()))
            .unwrap();

        let identity = Identity::random();
        cmd_cap_dir(
            &crow,
            &pins,
            &catalog,
            &identity,
            "/docs",
            Some("docs cap".into()),
        )
        .unwrap();

        let records = pins.list().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].name.as_deref(), Some("docs cap"));
        let ManifestKind::Directory(manifest) = crow.open_manifest_kind(&records[0].cap).unwrap()
        else {
            panic!("expected directory manifest");
        };
        assert_eq!(manifest.file_count(), 1);
        assert_eq!(manifest.dir_count(), 1);
    }

    #[test]
    fn get_dir_restores_directory_snapshot_cap() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pins = PinIndex::open(tmp.path()).unwrap();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        let crow = Crow::new(FsStore::open(tmp.path()).unwrap());
        let child = stored_cap(&crow, b"restored bytes");
        let manifest = DirectoryManifest::new(
            123,
            vec![
                DirectoryEntry::dir("nested"),
                DirectoryEntry::file("nested/file.txt", child, Some("file.txt".into())),
            ],
        )
        .unwrap();
        let identity = Identity::random();
        let cap = crow.put_directory_manifest(&manifest, &identity).unwrap();

        let out = tmp.path().join("out");
        cmd_get_dir(
            &crow,
            &pins,
            &catalog,
            &cap.encode(),
            out.to_str().unwrap(),
            true,
        )
        .unwrap();

        assert_eq!(
            fs::read(out.join("nested/file.txt")).unwrap(),
            b"restored bytes"
        );
    }

    #[test]
    fn add_dir_imports_directory_snapshot_to_catalog() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pins = PinIndex::open(tmp.path()).unwrap();
        let catalog = CatalogIndex::open(tmp.path()).unwrap();
        let crow = Crow::new(FsStore::open(tmp.path()).unwrap());
        let child = stored_cap(&crow, b"imported bytes");
        let manifest = DirectoryManifest::new(
            123,
            vec![DirectoryEntry::file(
                "nested/file.txt",
                child.clone(),
                Some("file.txt".into()),
            )],
        )
        .unwrap();
        let identity = Identity::random();
        let cap = crow.put_directory_manifest(&manifest, &identity).unwrap();
        pins.add(cap.clone(), Some("dir".into()), None).unwrap();

        cmd_add_dir(
            &crow,
            &pins,
            &catalog,
            &cap.manifest_hash.to_string()[..8],
            "/imported",
        )
        .unwrap();

        let path = CatalogPath::normalize("/imported/nested/file.txt").unwrap();
        let view = catalog.view().unwrap();
        let entry = view.get(&path).unwrap();
        assert_eq!(entry.cap().unwrap().encode(), child.encode());
    }
}
