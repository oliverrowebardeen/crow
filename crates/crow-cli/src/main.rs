use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use crow::{
    Cap, ChunkStore, Crow, DEFAULT_CHUNK_SIZE, ErasureParams, FsStore, Manifest, Namespace,
    erasure::{AEAD_TAG_LEN, RS_ALIGN},
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
        /// Override chunk size in bytes. Must satisfy (chunk_size + 16) % 64 == 0.
        #[arg(long)]
        chunk_size: Option<u32>,
    },
    /// Retrieve a file by its capability.
    Get {
        cap: String,
        /// Output path. "-" writes to stdout.
        out: String,
    },
    /// Print metadata for a capability.
    Info { cap: String },
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
    let crow = Crow::new(store);

    match cli.command {
        Command::Put {
            path,
            mime,
            chunk_size,
        } => cmd_put(&crow, &path, mime, chunk_size),
        Command::Get { cap, out } => cmd_get(&crow, &cap, &out),
        Command::Info { cap } => cmd_info(&crow, &cap),
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
    path: &str,
    mime: Option<String>,
    chunk_size: Option<u32>,
) -> DynResult<()> {
    let bytes = read_all(path)?;
    let mime_str = mime.unwrap_or_else(|| guess_mime(path).to_string());
    let chunk_size = chunk_size.unwrap_or_else(|| auto_chunk_size(bytes.len()));

    let cap = crow.put_bytes_with(&bytes, &mime_str, ErasureParams::default(), chunk_size)?;
    println!("{}", cap.encode());
    Ok(())
}

fn cmd_get(crow: &Crow<FsStore>, cap_str: &str, out: &str) -> DynResult<()> {
    let cap = Cap::decode(cap_str.trim())?;
    let bytes = crow.get_bytes(&cap)?;
    write_all(out, &bytes)?;
    Ok(())
}

fn cmd_info(crow: &Crow<FsStore>, cap_str: &str) -> DynResult<()> {
    let cap = Cap::decode(cap_str.trim())?;
    let encrypted = crow
        .store()
        .get(Namespace::Manifests, cap.manifest_hash.inner())?
        .ok_or("manifest not found in local store")?;
    let manifest = Manifest::open(&encrypted, &cap.manifest_key)?;

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
    println!("created   {}", manifest.created_at);
    println!(
        "algo      {:?} / {:?} / {:?}",
        manifest.algorithm.aead, manifest.algorithm.kdf, manifest.algorithm.erasure_code
    );
    Ok(())
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
