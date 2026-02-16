use anyhow::{anyhow, bail, Context, Result};
use chrono::{SecondsFormat, Utc};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

const PACK_ID: &str = "PACK-001";
const PACK_PATH: &str = "data/pack.json";
const CUPOLA_IMPORT_PATH: &str = "data/cupola_import.json";
const OUT_HTML_PATH: &str = "out/DecisionPack.html";
const OUT_MANIFEST_PATH: &str = "out/DecisionPack.manifest.json";
const OUT_SEAL_PATH: &str = "out/DecisionPack.seal.json";

#[derive(Parser)]
#[command(name = "aegis")]
#[command(version)]
#[command(about = "AEGIS v0 CLI")]
#[command(arg_required_else_help = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Init,
    ImportCupola {
        path: PathBuf,
    },
    Bind {
        claim_id: String,
        slot_id: String,
        hit_index: usize,
    },
    Score {
        claim_id: String,
        #[arg(long, value_parser = clap::value_parser!(u8).range(0..=5))]
        score: u8,
        #[arg(long, value_parser = parse_severity, value_name = "Critical|High|Medium|Low")]
        severity: Severity,
        #[arg(long, value_parser = parse_status, value_name = "Pass|Partial|Fail|Unknown")]
        status: Status,
    },
    Export,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
enum Status {
    Pass,
    Partial,
    Fail,
    Unknown,
}

#[derive(Debug, Serialize, Deserialize)]
struct Pack {
    pack_id: String,
    created_at: String,
    claims: BTreeMap<String, ClaimRecord>,
    cupola_import_path: Option<String>,
}

impl Pack {
    fn new(created_at: String) -> Self {
        Self {
            pack_id: PACK_ID.to_string(),
            created_at,
            claims: BTreeMap::new(),
            cupola_import_path: None,
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct ClaimRecord {
    bindings: BTreeMap<String, usize>,
    score: Option<u8>,
    severity: Option<Severity>,
    status: Option<Status>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => cmd_init(),
        Commands::ImportCupola { path } => cmd_import_cupola(path),
        Commands::Bind {
            claim_id,
            slot_id,
            hit_index,
        } => cmd_bind(claim_id, slot_id, hit_index),
        Commands::Score {
            claim_id,
            score,
            severity,
            status,
        } => cmd_score(claim_id, score, severity, status),
        Commands::Export => cmd_export(),
    }
}

fn cmd_init() -> Result<()> {
    ensure_dirs()?;
    if Path::new(PACK_PATH).exists() {
        bail!("Pack already initialized at {PACK_PATH}");
    }

    let created_at = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    let pack = Pack::new(created_at);
    write_json(PACK_PATH, &pack)?;

    println!("Initialized {PACK_PATH}");
    Ok(())
}

fn cmd_import_cupola(path: PathBuf) -> Result<()> {
    ensure_dirs()?;
    let mut pack = load_pack()?;

    let raw = fs::read_to_string(&path)
        .with_context(|| format!("Failed to read cupola file: {}", path.display()))?;
    let parsed: Value = serde_json::from_str(&raw)
        .with_context(|| format!("Invalid JSON in {}", path.display()))?;
    validate_cupola_hits(&parsed)?;

    write_json(CUPOLA_IMPORT_PATH, &parsed)?;
    pack.cupola_import_path = Some(CUPOLA_IMPORT_PATH.to_string());
    save_pack(&pack)?;

    println!("Imported cupola JSON to {CUPOLA_IMPORT_PATH}");
    Ok(())
}

fn cmd_bind(claim_id: String, slot_id: String, hit_index: usize) -> Result<()> {
    let mut pack = load_pack()?;
    let hits_len = load_cupola_hits_len()?;
    if hit_index >= hits_len {
        bail!(
            "hit_index {hit_index} is out of range (hits length: {hits_len})"
        );
    }

    let claim = pack.claims.entry(claim_id.clone()).or_default();
    claim.bindings.insert(slot_id.clone(), hit_index);
    save_pack(&pack)?;

    println!("Bound claim '{claim_id}' slot '{slot_id}' to hit index {hit_index}");
    Ok(())
}

fn cmd_score(claim_id: String, score: u8, severity: Severity, status: Status) -> Result<()> {
    let mut pack = load_pack()?;

    let claim = pack.claims.entry(claim_id.clone()).or_default();
    claim.score = Some(score);
    claim.severity = Some(severity);
    claim.status = Some(status);
    save_pack(&pack)?;

    println!("Scored claim '{claim_id}'");
    Ok(())
}

fn cmd_export() -> Result<()> {
    ensure_dirs()?;
    let pack = load_pack()?;

    let canonical_pack_json = canonical_pack_json(&pack)?;
    let pack_sha256 = sha256_hex(&canonical_pack_json);

    let manifest = json!({
        "pack_id": pack.pack_id,
        "created_at": pack.created_at,
        "pack_sha256": pack_sha256,
        "pack_path": PACK_PATH,
        "cupola_import_path": pack.cupola_import_path,
        "claim_count": pack.claims.len()
    });

    let seal = json!({
        "pack_id": PACK_ID,
        "pack_sha256": pack_sha256,
        "algorithm": "sha256"
    });

    let html = render_html(&pack_sha256, &canonical_pack_json);

    write_string(OUT_HTML_PATH, &html)?;
    write_json(OUT_MANIFEST_PATH, &manifest)?;
    write_json(OUT_SEAL_PATH, &seal)?;

    println!("Exported DecisionPack: {pack_sha256}");
    Ok(())
}

fn ensure_dirs() -> Result<()> {
    fs::create_dir_all("data").context("Failed to create data directory")?;
    fs::create_dir_all("out").context("Failed to create out directory")?;
    Ok(())
}

fn load_pack() -> Result<Pack> {
    let raw = fs::read_to_string(PACK_PATH)
        .with_context(|| format!("Pack not initialized. Run 'init' first: {PACK_PATH}"))?;
    let pack: Pack = serde_json::from_str(&raw).context("Failed to parse data/pack.json")?;
    if pack.pack_id != PACK_ID {
        bail!("Unexpected pack_id '{}'; expected '{}'.", pack.pack_id, PACK_ID);
    }
    Ok(pack)
}

fn save_pack(pack: &Pack) -> Result<()> {
    write_json(PACK_PATH, pack)
}

fn load_cupola_hits_len() -> Result<usize> {
    let raw = fs::read_to_string(CUPOLA_IMPORT_PATH).with_context(|| {
        format!(
            "Cupola import missing. Run 'import-cupola <path>' first: {CUPOLA_IMPORT_PATH}"
        )
    })?;
    let parsed: Value = serde_json::from_str(&raw).context("Failed to parse data/cupola_import.json")?;
    let hits = parsed
        .get("hits")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("data/cupola_import.json is missing hits[]"))?;
    Ok(hits.len())
}

fn validate_cupola_hits(value: &Value) -> Result<()> {
    if value.get("hits").and_then(Value::as_array).is_none() {
        bail!("import-cupola requires top-level hits[] in the input JSON");
    }
    Ok(())
}

fn canonical_pack_json(pack: &Pack) -> Result<String> {
    let value = serde_json::to_value(pack).context("Failed to serialize pack")?;
    let canonical = canonicalize_json(&value);
    serde_json::to_string(&canonical).context("Failed to serialize canonical pack")
}

fn canonicalize_json(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();

            let mut sorted = serde_json::Map::new();
            for key in keys {
                if let Some(inner) = map.get(key) {
                    sorted.insert(key.clone(), canonicalize_json(inner));
                }
            }
            Value::Object(sorted)
        }
        Value::Array(values) => Value::Array(values.iter().map(canonicalize_json).collect()),
        _ => value.clone(),
    }
}

fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let digest = hasher.finalize();
    format!("{digest:x}")
}

fn write_json(path: &str, value: &impl Serialize) -> Result<()> {
    let content = serde_json::to_string_pretty(value)
        .with_context(|| format!("Failed to serialize JSON for {path}"))?;
    write_string(path, &(content + "\n"))
}

fn write_string(path: &str, content: &str) -> Result<()> {
    fs::write(path, content).with_context(|| format!("Failed to write {path}"))
}

fn render_html(pack_sha256: &str, canonical_pack_json: &str) -> String {
    let escaped_pack = escape_html(canonical_pack_json);

    format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n  <meta charset=\"utf-8\">\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n  <title>DecisionPack</title>\n  <style>\n    body {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; margin: 24px; line-height: 1.4; }}\n    h1 {{ margin: 0 0 8px 0; }}\n    .meta {{ margin-bottom: 16px; color: #444; }}\n    pre {{ background: #f5f5f5; padding: 12px; border-radius: 8px; overflow: auto; }}\n  </style>\n</head>\n<body>\n  <h1>DecisionPack</h1>\n  <div class=\"meta\">pack_sha256: <code>{}</code></div>\n  <pre>{}</pre>\n</body>\n</html>\n",
        pack_sha256, escaped_pack
    )
}

fn escape_html(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

fn parse_severity(input: &str) -> std::result::Result<Severity, String> {
    match input {
        "Critical" | "critical" => Ok(Severity::Critical),
        "High" | "high" => Ok(Severity::High),
        "Medium" | "medium" => Ok(Severity::Medium),
        "Low" | "low" => Ok(Severity::Low),
        _ => Err("expected one of: Critical, High, Medium, Low".to_string()),
    }
}

fn parse_status(input: &str) -> std::result::Result<Status, String> {
    match input {
        "Pass" | "pass" => Ok(Status::Pass),
        "Partial" | "partial" => Ok(Status::Partial),
        "Fail" | "fail" => Ok(Status::Fail),
        "Unknown" | "unknown" => Ok(Status::Unknown),
        _ => Err("expected one of: Pass, Partial, Fail, Unknown".to_string()),
    }
}