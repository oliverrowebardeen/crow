use std::fs;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use crow::{
    Cap, CatalogEntry, CatalogIndex, CatalogPath, CatalogView, ChunkStore, Crow,
    DEFAULT_CHUNK_SIZE, EntryKind, ErasureParams, FsStore, GcOptions, Hash, Manifest, Namespace,
    PinIndex, PinRecord, compute_live_set_from_roots,
    erasure::{AEAD_TAG_LEN, RS_ALIGN},
    sweep, targeted_remove,
};
use crow_net::{Client, ClusterToken, DEFAULT_BIND_ADDR, TokenStore};

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
                  crow mkdir /docs                 # create a local catalog folder\n  \
                  crow put report.pdf /docs/       # store, pin, catalog by path\n  \
                  crow ls /docs                    # list catalog entries\n  \
                  crow info /docs/report.pdf       # show metadata + pin status\n  \
                  crow get /docs/report.pdf out.pdf # retrieve\n  \
                  crow rm <prefix>                 # delete pin and chunks\n  \
                  crow gc                          # sweep anything not pinned\n  \
                  crow serve                       # serve chunks over QUIC\n\
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
    /// Drop a pin record. Chunks linger until `crow gc`.
    #[command(
        long_about = "Remove the pin record for a manifest. The chunks themselves stay \
                      in the store until `crow gc` sweeps them — so `unpin` is \
                      reversible (`crow pin <cap>` re-creates the pin and the data is \
                      still recoverable).\n\
                      \n\
                      Use `crow rm` instead if you want the chunks gone immediately."
    )]
    Unpin {
        /// Full bech32m capability or hex prefix of a pinned manifest.
        cap_or_prefix: String,
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
    /// Sweep every chunk and manifest not referenced by any pin.
    #[command(
        long_about = "Walk every chunk and manifest in the store; delete anything not \
                      referenced by a current pin. The catch-all complement to `crow \
                      rm` — cleans up after `crow unpin`, crashed puts, manually-\
                      removed pins, etc.\n\
                      \n\
                      --dry-run reports what would be freed without touching disk; \
                      run it first if you're not sure."
    )]
    Gc {
        /// Print what would be deleted without touching disk.
        #[arg(long)]
        dry_run: bool,
    },
    /// Show storage stats.
    #[command(
        long_about = "Print the storage path, total manifest and chunk counts and \
                      sizes, the number of pins, and how much would be freed by `crow \
                      gc` (unreferenced manifests + chunks)."
    )]
    Stat,
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
    },
    /// Fetch missing manifest/chunk shares from a known peer.
    #[command(
        long_about = "Connect to a trusted Crow peer, fetch the manifest and missing \
                      shares for a cap, pin it locally, and verify local reconstruction.\n\
                      \n\
                      This is manual Phase 1 personal-cluster fetch: no mDNS, peer list, \
                      automatic replication, or friend-scoped access yet."
    )]
    Fetch {
        /// Peer address, e.g. 192.168.1.42:7070.
        peer: SocketAddr,
        /// Full bech32m capability (`crow1…`) or hex prefix of a pinned manifest.
        cap_or_prefix: String,
        /// Friendly name for the local pin.
        #[arg(long)]
        name: Option<String>,
    },
    /// Manage the shared personal-cluster token.
    #[command(subcommand)]
    Token(TokenCommand),
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

fn run(cli: Cli) -> DynResult<()> {
    let home = resolve_home(cli.home)?;
    match cli.command {
        Command::Token(command) => cmd_token(&home, command),
        Command::Serve { bind } => {
            let store = FsStore::open(&home)?;
            cmd_serve(&home, store, bind)
        }
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
                    &path,
                    dest.as_deref(),
                    mime,
                    name,
                    chunk_size,
                ),
                Command::Get { cap_or_prefix, out } => {
                    cmd_get(&crow, &pins, &catalog, &cap_or_prefix, &out)
                }
                Command::Info { cap_or_prefix } => cmd_info(&crow, &pins, &catalog, &cap_or_prefix),
                Command::Ls {
                    path,
                    long,
                    pins: pins_only,
                } => cmd_ls(&crow, &pins, &catalog, path.as_deref(), long, pins_only),
                Command::Mkdir { path, parents } => cmd_mkdir(&catalog, &path, parents),
                Command::Pin { cap, name } => cmd_pin(&pins, &cap, name),
                Command::Unpin { cap_or_prefix } => cmd_unpin(&pins, &cap_or_prefix),
                Command::Rm {
                    cap_or_prefix,
                    dry_run,
                } => cmd_rm(&crow, &pins, &catalog, &cap_or_prefix, dry_run),
                Command::Mv { from, to } => cmd_mv(&catalog, &from, &to),
                Command::Gc { dry_run } => cmd_gc(&crow, &pins, &catalog, dry_run),
                Command::Stat => cmd_stat(&crow, &pins, &catalog),
                Command::Fetch {
                    peer,
                    cap_or_prefix,
                    name,
                } => cmd_fetch(&home, &crow, &pins, peer, &cap_or_prefix, name),
                Command::Serve { .. } | Command::Token(_) => unreachable!("handled above"),
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

fn cmd_put(
    crow: &Crow<FsStore>,
    pins: &PinIndex,
    catalog: &CatalogIndex,
    path: &str,
    dest: Option<&str>,
    mime: Option<String>,
    name: Option<String>,
    chunk_size: Option<u32>,
) -> DynResult<()> {
    let catalog_dest = dest
        .map(|dest| resolve_put_destination(catalog, path, dest))
        .transpose()?;
    let bytes = read_all(path)?;
    let mime_str = mime.unwrap_or_else(|| guess_mime(path).to_string());
    let chunk_size = chunk_size.unwrap_or_else(|| auto_chunk_size(bytes.len()));

    let cap = crow.put_bytes_with(&bytes, &mime_str, ErasureParams::default(), chunk_size)?;
    let pin_name = name.or_else(|| default_name(path));
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

fn cmd_info(
    crow: &Crow<FsStore>,
    pins: &PinIndex,
    catalog: &CatalogIndex,
    arg: &str,
) -> DynResult<()> {
    let target = resolve_file_ref(catalog, pins, arg)?;
    let path = target.path;
    let cap = target.cap;
    let manifest = open_manifest(crow, &cap)?;

    if let Some(path) = &path {
        println!("path      {path}");
    }
    let stripes = manifest.stripes.len();
    let shares: usize = manifest
        .stripes
        .iter()
        .map(|s| s.data.len() + s.parity.len())
        .sum();

    println!("hash      {}", cap.manifest_hash);
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
            let manifest = open_manifest(crow, &r.cap)?;
            let size = format_size(manifest.file_size as usize);
            let pinned = format_iso_timestamp(r.pinned_at);
            let name = r.name.as_deref().unwrap_or("(unnamed)");
            println!(
                "{}  {:>10}  {:<22}  {:<20}  {}",
                r.manifest_hash_hex,
                size,
                truncate(&manifest.mime_type, 22),
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
            let manifest = open_manifest(crow, &r.cap)?;
            let hash_short = &r.manifest_hash_hex[..8];
            let size = format_size(manifest.file_size as usize);
            let mime = truncate(&manifest.mime_type, 18);
            let pinned = format_short_date(r.pinned_at);
            let name = r.name.as_deref().unwrap_or("(unnamed)");
            println!("{hash_short}  {size:>10}  {mime:<18}  {pinned:<10}  {name}");
        }
    }
    Ok(())
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

fn cmd_pin(pins: &PinIndex, cap_str: &str, name: Option<String>) -> DynResult<()> {
    let cap = Cap::decode(cap_str.trim())?;
    let rec = pins.add(cap, name, None)?;
    println!("pinned {}", &rec.manifest_hash_hex[..16]);
    Ok(())
}

fn cmd_unpin(pins: &PinIndex, arg: &str) -> DynResult<()> {
    let rec = resolve_pin(pins, arg)?;
    pins.remove(rec.cap.manifest_hash.inner())?;
    println!("unpinned {}", &rec.manifest_hash_hex[..16]);
    Ok(())
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

fn cmd_stat(crow: &Crow<FsStore>, pins: &PinIndex, catalog: &CatalogIndex) -> DynResult<()> {
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

    println!("store         {}", crow.store().root().display());
    println!(
        "manifests     {} files / {}",
        manifests.len(),
        format_size_u64(manifest_bytes)
    );
    println!(
        "chunks        {} files / {}",
        chunks.len(),
        format_size_u64(chunk_bytes)
    );
    println!("pins          {}", pin_records.len());
    println!("catalog files {}", catalog_files);
    println!(
        "unreferenced  {unref_manifests} manifests / {unref_chunks} chunks ({})",
        format_size_u64(unref_bytes),
    );
    Ok(())
}

fn cmd_serve(home: &Path, store: FsStore, bind: SocketAddr) -> DynResult<()> {
    let token = load_token(home)?;
    let root = store.root().display().to_string();
    println!("serving {root} on {bind}");
    println!("cluster token: configured");
    runtime()?.block_on(crow_net::serve(store, token, bind))?;
    Ok(())
}

fn cmd_fetch(
    home: &Path,
    crow: &Crow<FsStore>,
    pins: &PinIndex,
    peer: SocketAddr,
    arg: &str,
    name: Option<String>,
) -> DynResult<()> {
    let token = load_token(home)?;
    let cap = resolve_cap(pins, arg)?;
    let rt = runtime()?;
    let client = rt.block_on(Client::connect(peer))?;
    rt.block_on(client.hello(token))?;

    let mut fetched = 0usize;
    let mut already_local = 0usize;
    let mut remote_missing = 0usize;
    let mut fetched_bytes = 0u64;

    let manifest_hash = *cap.manifest_hash.inner();
    let manifest_state = if crow.store().has(Namespace::Manifests, &manifest_hash)? {
        already_local += 1;
        "local"
    } else {
        match rt.block_on(client.get(token, Namespace::Manifests, manifest_hash))? {
            Some(bytes) => {
                fetched_bytes += bytes.len() as u64;
                crow.store()
                    .put_unverified(Namespace::Manifests, manifest_hash, bytes)?;
                fetched += 1;
                "fetched"
            }
            None => {
                remote_missing += 1;
                "missing"
            }
        }
    };

    if manifest_state == "missing" {
        println!("manifest      missing");
        println!("shares        0 local / 0 fetched / 0 missing");
        println!("stored        {}", format_size_u64(fetched_bytes));
        println!("status        not reconstructable");
        return Err("peer does not have the manifest".into());
    }

    let manifest = open_manifest(crow, &cap)?;
    let (pin_name, pin_comment) = fetch_pin_metadata(pins, &cap, name)?;
    pins.add(cap.clone(), pin_name, pin_comment)?;

    let mut local_shares = 0usize;
    let mut fetched_shares = 0usize;
    let mut missing_shares = 0usize;
    for hash in manifest
        .stripes
        .iter()
        .flat_map(|s| s.data.iter().chain(s.parity.iter()))
        .map(|h| *h.inner())
    {
        match fetch_object(
            crow,
            &rt,
            &client,
            token,
            Namespace::Chunks,
            hash,
            &mut fetched_bytes,
        )? {
            FetchState::Local => {
                already_local += 1;
                local_shares += 1;
            }
            FetchState::Fetched => {
                fetched += 1;
                fetched_shares += 1;
            }
            FetchState::Missing => {
                remote_missing += 1;
                missing_shares += 1;
            }
        }
    }

    println!("manifest      {manifest_state}");
    println!(
        "shares        {local_shares} local / {fetched_shares} fetched / {missing_shares} missing"
    );
    println!("objects       {already_local} local / {fetched} fetched / {remote_missing} missing");
    println!("stored        {}", format_size_u64(fetched_bytes));
    println!(
        "pinned        {} {}",
        &cap.manifest_hash.to_string()[..8],
        pins.get(cap.manifest_hash.inner())?
            .and_then(|r| r.name)
            .unwrap_or_else(|| "(unnamed)".into())
    );

    match crow.get_bytes(&cap) {
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

fn join_catalog_path(parent: &CatalogPath, name: &str) -> DynResult<CatalogPath> {
    let joined = if parent.as_str() == "/" {
        format!("/{name}")
    } else {
        format!("{}/{name}", parent.as_str().trim_end_matches('/'))
    };
    Ok(CatalogPath::normalize(&joined)?)
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

fn catalog_path_contains(parent: &CatalogPath, child: &CatalogPath) -> bool {
    if parent.as_str() == "/" {
        return child.as_str() != "/";
    }
    child.as_str() == parent.as_str()
        || child
            .as_str()
            .starts_with(&format!("{}/", parent.as_str().trim_end_matches('/')))
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
    let ext = Path::new(path).extension().and_then(|e| e.to_str());
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
}
