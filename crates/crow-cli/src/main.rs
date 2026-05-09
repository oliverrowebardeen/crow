use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use crow::{
    Cap, ChunkStore, Crow, DEFAULT_CHUNK_SIZE, ErasureParams, FsStore, GcOptions, Manifest,
    Namespace, PinIndex, PinRecord, compute_live_set,
    erasure::{AEAD_TAG_LEN, RS_ALIGN},
    sweep, targeted_remove,
};

#[derive(Parser)]
#[command(
    name = "crow",
    version,
    about = "decentralized, content-addressed file storage"
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
    /// Store a file; print its capability on stdout.
    Put {
        /// File to store. "-" reads from stdin.
        path: String,
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
    /// Retrieve a file by capability or hash prefix.
    Get {
        cap_or_prefix: String,
        /// Output path. "-" writes to stdout.
        out: String,
    },
    /// Print metadata for a capability or hash prefix.
    Info { cap_or_prefix: String },
    /// List every pinned manifest.
    Ls {
        /// Show full hashes, full mime types, and ISO timestamps.
        #[arg(short, long)]
        long: bool,
    },
    /// Pin a capability so its chunks survive `crow gc`.
    Pin {
        cap: String,
        #[arg(long)]
        name: Option<String>,
    },
    /// Remove a pin record. Chunks linger until `crow gc` runs.
    Unpin { cap_or_prefix: String },
    /// Remove a pin and immediately delete its chunks (those not held by
    /// another pin).
    Rm {
        cap_or_prefix: String,
        /// Print what would be deleted without touching disk.
        #[arg(long)]
        dry_run: bool,
    },
    /// Sweep every chunk and manifest not referenced by any current pin.
    Gc {
        /// Print what would be deleted without touching disk.
        #[arg(long)]
        dry_run: bool,
    },
    /// Show storage stats.
    Stat,
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
    let store = FsStore::open(&home)?;
    let pins = PinIndex::open(&home)?;
    let crow = Crow::new(store);

    match cli.command {
        Command::Put {
            path,
            mime,
            name,
            chunk_size,
        } => cmd_put(&crow, &pins, &path, mime, name, chunk_size),
        Command::Get { cap_or_prefix, out } => cmd_get(&crow, &pins, &cap_or_prefix, &out),
        Command::Info { cap_or_prefix } => cmd_info(&crow, &pins, &cap_or_prefix),
        Command::Ls { long } => cmd_ls(&crow, &pins, long),
        Command::Pin { cap, name } => cmd_pin(&pins, &cap, name),
        Command::Unpin { cap_or_prefix } => cmd_unpin(&pins, &cap_or_prefix),
        Command::Rm {
            cap_or_prefix,
            dry_run,
        } => cmd_rm(&crow, &pins, &cap_or_prefix, dry_run),
        Command::Gc { dry_run } => cmd_gc(&crow, &pins, dry_run),
        Command::Stat => cmd_stat(&crow, &pins),
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
    path: &str,
    mime: Option<String>,
    name: Option<String>,
    chunk_size: Option<u32>,
) -> DynResult<()> {
    let bytes = read_all(path)?;
    let mime_str = mime.unwrap_or_else(|| guess_mime(path).to_string());
    let chunk_size = chunk_size.unwrap_or_else(|| auto_chunk_size(bytes.len()));

    let cap = crow.put_bytes_with(&bytes, &mime_str, ErasureParams::default(), chunk_size)?;
    let pin_name = name.or_else(|| default_name(path));
    pins.add(cap.clone(), pin_name, None)?;
    println!("{}", cap.encode());
    Ok(())
}

fn cmd_get(crow: &Crow<FsStore>, pins: &PinIndex, arg: &str, out: &str) -> DynResult<()> {
    let cap = resolve_cap(pins, arg)?;
    let bytes = crow.get_bytes(&cap)?;
    write_all(out, &bytes)?;
    Ok(())
}

fn cmd_info(crow: &Crow<FsStore>, pins: &PinIndex, arg: &str) -> DynResult<()> {
    let cap = resolve_cap(pins, arg)?;
    let manifest = open_manifest(crow, &cap)?;

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
    Ok(())
}

fn cmd_ls(crow: &Crow<FsStore>, pins: &PinIndex, long: bool) -> DynResult<()> {
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

fn cmd_rm(crow: &Crow<FsStore>, pins: &PinIndex, arg: &str, dry_run: bool) -> DynResult<()> {
    let target = resolve_pin(pins, arg)?;
    let target_cap = target.cap.clone();

    // Collect every other pinned cap so we don't delete chunks that are
    // shared with other pinned manifests.
    let remaining_caps: Vec<Cap> = pins
        .list()?
        .into_iter()
        .filter(|r| r.manifest_hash_hex != target.manifest_hash_hex)
        .map(|r| r.cap)
        .collect();

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

fn cmd_gc(crow: &Crow<FsStore>, pins: &PinIndex, dry_run: bool) -> DynResult<()> {
    let pin_caps: Vec<Cap> = pins.list()?.into_iter().map(|r| r.cap).collect();
    let live = compute_live_set(crow.store(), &pin_caps)?;
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

fn cmd_stat(crow: &Crow<FsStore>, pins: &PinIndex) -> DynResult<()> {
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
    let live = compute_live_set(crow.store(), &pin_caps)?;

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
    println!(
        "unreferenced  {unref_manifests} manifests / {unref_chunks} chunks ({})",
        format_size_u64(unref_bytes),
    );
    Ok(())
}

fn open_manifest(crow: &Crow<FsStore>, cap: &Cap) -> DynResult<Manifest> {
    let encrypted = crow
        .store()
        .get(Namespace::Manifests, cap.manifest_hash.inner())?
        .ok_or("manifest not found in local store")?;
    Ok(Manifest::open(&encrypted, &cap.manifest_key)?)
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
