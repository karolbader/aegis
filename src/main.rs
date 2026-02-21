use anyhow::{anyhow, bail, Context, Result};
use chrono::{NaiveDate, SecondsFormat, Utc};
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

const PACK_ID: &str = "PACK-001";
const PACK_PATH: &str = "data/pack.json";
const CUPOLA_IMPORT_PATH: &str = "data/cupola_import.json";
const CUPOLA_SEARCH_RAW_PATH: &str = "data/cupola_search.raw.json";
const DEFAULT_CUPOLA_REPO: &str = r"E:\CupolaCore";

const DECISION_PACK_HTML: &str = "DecisionPack.html";
const DECISION_PACK_MANIFEST: &str = "DecisionPack.manifest.json";
const DECISION_PACK_SEAL: &str = "DecisionPack.seal.json";
const REPLAY_MD: &str = "REPLAY.md";
const CUPOLA_MANIFEST_FILE: &str = "cupola.manifest.json";
const QUOTE_JSON: &str = "Quote.json";
const QUOTE_MD: &str = "Quote.md";
const DATA_SHARE_CHECKLIST_MD: &str = "DataShareChecklist.md";

const MAX_QUERY_HITS_PER_QUERY: usize = 50;
const MAX_EVIDENCE_REFS_PER_CONTROL: usize = 256;

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
    ImportCupolaVault(ImportCupolaVaultArgs),
    Run(RunArgs),
    Quote(QuoteArgs),
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
    Export(ExportArgs),
}

#[derive(Debug, Clone, Args)]
struct ImportCupolaVaultArgs {
    #[arg(long, default_value = DEFAULT_CUPOLA_REPO)]
    cupola_repo: PathBuf,
    #[arg(long)]
    vault: PathBuf,
    #[arg(long)]
    q: String,
    #[arg(long, default_value_t = 20)]
    limit: usize,
}

#[derive(Debug, Clone, Args)]
struct ExportArgs {
    #[arg(long, conflicts_with = "out")]
    in_vault: Option<PathBuf>,
    #[arg(long)]
    out: Option<PathBuf>,
    #[arg(long, default_value = "client")]
    client_id: String,
    #[arg(long, default_value = "engagement")]
    engagement_id: String,
    #[arg(long, value_enum, default_value_t = PackType::DdResponse)]
    pack_type: PackType,
    #[arg(long, value_enum, default_value_t = LibraryPack::VendorSecurity)]
    library_pack: LibraryPack,
    #[arg(long, default_value = DEFAULT_CUPOLA_REPO)]
    cupola_repo: PathBuf,
    #[arg(
        long,
        value_name = "DATA_DIR",
        help = "Folder containing data/packs/... libraries"
    )]
    data_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
struct RunArgs {
    #[arg(long)]
    vault: PathBuf,
    #[arg(long, default_value = DEFAULT_CUPOLA_REPO)]
    cupola_repo: PathBuf,
    #[arg(long)]
    intake: PathBuf,
    #[arg(long, conflicts_with = "out")]
    in_vault: Option<PathBuf>,
    #[arg(long)]
    out: Option<PathBuf>,
    #[arg(
        long,
        value_name = "DATA_DIR",
        help = "Folder containing data/packs/... libraries"
    )]
    data_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
struct QuoteArgs {
    #[arg(long)]
    intake: PathBuf,
    #[arg(long, conflicts_with = "print")]
    out: Option<PathBuf>,
    #[arg(long)]
    print: bool,
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, ValueEnum, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum PackType {
    #[value(name = "dd_response", alias = "incident_response")]
    DdResponse,
    #[value(name = "trust_audit", alias = "gap_assessment")]
    TrustAudit,
    #[value(name = "governance_controls")]
    GovernanceControls,
}

impl PackType {
    fn label(self) -> &'static str {
        match self {
            PackType::DdResponse => "DD Response Pack",
            PackType::TrustAudit => "Trust Audit",
            PackType::GovernanceControls => "Governance & Controls",
        }
    }

    fn slug(self) -> &'static str {
        match self {
            PackType::DdResponse => "dd_response",
            PackType::TrustAudit => "trust_audit",
            PackType::GovernanceControls => "governance_controls",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, ValueEnum, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum LibraryPack {
    #[value(name = "vendor_security")]
    VendorSecurity,
    #[value(name = "iso_27001", alias = "iso27001")]
    #[serde(rename = "iso_27001", alias = "iso27001")]
    Iso27001,
    #[value(name = "nist_csf")]
    NistCsf,
    #[value(name = "vendorsecurity/v1", alias = "vendor_security_v1")]
    #[serde(rename = "vendorsecurity/v1", alias = "vendor_security_v1")]
    VendorSecurityV1,
    #[value(name = "dfir-lite/v1", alias = "dfir_lite_v1")]
    #[serde(rename = "dfir-lite/v1", alias = "dfir_lite_v1")]
    DfirLiteV1,
    #[value(name = "iso27001-lite/v1", alias = "iso27001_lite_v1")]
    #[serde(rename = "iso27001-lite/v1", alias = "iso27001_lite_v1")]
    Iso27001LiteV1,
}

impl LibraryPack {
    fn slug(self) -> &'static str {
        match self {
            LibraryPack::VendorSecurity => "vendor_security",
            LibraryPack::Iso27001 => "iso_27001",
            LibraryPack::NistCsf => "nist_csf",
            LibraryPack::VendorSecurityV1 => "vendorsecurity/v1",
            LibraryPack::DfirLiteV1 => "dfir-lite/v1",
            LibraryPack::Iso27001LiteV1 => "iso27001-lite/v1",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum OutputMode {
    InVault,
    OutDir,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
enum IntakeLane {
    #[default]
    Standard,
    Investigation,
}

impl IntakeLane {
    fn slug(self) -> &'static str {
        match self {
            IntakeLane::Standard => "standard",
            IntakeLane::Investigation => "investigation",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
enum DataSharingMode {
    #[default]
    ClientSide,
    RedactedUpload,
    RepoAccess,
}

impl DataSharingMode {
    fn slug(self) -> &'static str {
        match self {
            DataSharingMode::ClientSide => "client_side",
            DataSharingMode::RedactedUpload => "redacted_upload",
            DataSharingMode::RepoAccess => "repo_access",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
enum EvidenceReadiness {
    Organized,
    #[default]
    Mixed,
    Chaotic,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
enum RepoSizeBand {
    #[serde(rename = "<1GB")]
    Under1,
    #[serde(rename = "1-10GB")]
    OneTo10,
    #[serde(rename = "10-50GB")]
    TenTo50,
    #[serde(rename = "50GB+")]
    Over50,
}

impl RepoSizeBand {
    fn label(self) -> &'static str {
        match self {
            RepoSizeBand::Under1 => "<1GB",
            RepoSizeBand::OneTo10 => "1-10GB",
            RepoSizeBand::TenTo50 => "10-50GB",
            RepoSizeBand::Over50 => "50GB+",
        }
    }
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IntakeV1 {
    schema_version: String,
    client_id: String,
    engagement_id: String,
    pack_type: PackType,
    library_pack: LibraryPack,
    #[serde(default)]
    lane: IntakeLane,
    #[serde(default)]
    data_sharing_mode: DataSharingMode,
    #[serde(default)]
    evidence_readiness: EvidenceReadiness,
    #[serde(default)]
    scope_size: Option<IntakeScopeSize>,
    #[serde(default)]
    output_mode: Option<OutputMode>,
    #[serde(default)]
    scope: IntakeScope,
    #[serde(default)]
    claims: BTreeMap<String, bool>,
    #[serde(default)]
    deadlines: Option<IntakeDeadlines>,
    #[serde(default)]
    generated_at: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct IntakeScope {
    #[serde(default)]
    in_scope: String,
    #[serde(default)]
    out_of_scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IntakeDeadlines {
    due_date: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IntakeScopeSize {
    systems: u8,
    repos: u8,
    repo_size_band: RepoSizeBand,
}

impl IntakeV1 {
    fn new(
        generated_at: String,
        client_id: String,
        engagement_id: String,
        pack_type: PackType,
        library_pack: LibraryPack,
    ) -> Self {
        Self {
            schema_version: "aegis.intake.v1".to_string(),
            client_id,
            engagement_id,
            pack_type,
            library_pack,
            lane: IntakeLane::default(),
            data_sharing_mode: DataSharingMode::default(),
            evidence_readiness: EvidenceReadiness::default(),
            scope_size: None,
            output_mode: None,
            scope: IntakeScope::default(),
            claims: BTreeMap::new(),
            deadlines: None,
            generated_at: Some(generated_at),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CupolaSearch {
    #[serde(default)]
    schema_version: Option<String>,
    #[serde(default)]
    tool: Option<CupolaTool>,
    #[serde(default)]
    generated_at: Option<String>,
    #[serde(default)]
    vault: Option<CupolaVault>,
    #[serde(default)]
    query: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
    hits: Vec<CupolaHit>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CupolaTool {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    build: Option<String>,
    #[serde(default)]
    platform: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CupolaVault {
    #[serde(default)]
    vault_path: Option<String>,
    #[serde(default)]
    vault_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CupolaHit {
    chunk_id: String,
    rel_path: String,
    file_type: String,
    mtime_ns: Value,
    raw_blob_id: String,
    chunk_blob_id: String,
    start_line: u64,
    end_line: u64,
    excerpt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LibraryControl {
    control_id: String,
    title: String,
    description: String,
    #[serde(default)]
    objective: String,
    severity: u8,
    #[serde(default)]
    evidence_expectations: Vec<String>,
    tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LibraryQueries {
    version: String,
    queries: Vec<LibraryQuery>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LibraryQuery {
    query_id: String,
    query_text: String,
    tags: Vec<String>,
    #[serde(default = "default_query_limit")]
    limit: usize,
    #[serde(default)]
    control_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LibraryRubric {
    version: String,
    rules: Vec<RubricRule>,
    #[serde(default)]
    control_query_map: Vec<ControlQueryMap>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RubricRule {
    tag: String,
    min_hits_for_partial: usize,
    min_hits_for_met: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ControlQueryMap {
    control_id: String,
    query_ids: Vec<String>,
}

#[derive(Debug, Clone)]
struct LibraryPackData {
    controls: Vec<LibraryControl>,
    queries: LibraryQueries,
    rubric: LibraryRubric,
}

#[derive(Debug, Clone, Serialize)]
struct EvidenceBinding {
    claim_id: String,
    slot_id: String,
    hit_index: usize,
    hit: CupolaHit,
}

#[derive(Debug, Clone, Serialize)]
struct EvidenceRef {
    query_id: String,
    rank: usize,
    chunk_id: String,
    rel_path: String,
    start_line: u64,
    end_line: u64,
    excerpt: String,
}

#[derive(Debug, Clone, Serialize)]
struct QueryLogEntry {
    query_id: String,
    query_text: String,
    tags: Vec<String>,
    limit: usize,
    hit_count: usize,
    evidence_refs: Vec<EvidenceRef>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ControlStatus {
    Met,
    Partial,
    Gap,
}

#[derive(Debug, Clone, Serialize)]
struct ControlResultManifest {
    title: String,
    status: ControlStatus,
    severity: u8,
    evidence_count: usize,
    evidence_refs: Vec<EvidenceRef>,
}

#[derive(Debug, Clone)]
struct AutoEvaluation {
    query_log: Vec<QueryLogEntry>,
    control_results: BTreeMap<String, ControlResultManifest>,
    first_search: Option<CupolaSearch>,
}

#[derive(Debug, Clone, Serialize)]
struct ArtifactDigest {
    path: String,
    sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct QuoteMultiplierV1 {
    factor: f64,
    reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct QuoteMultipliersV1 {
    #[serde(rename = "S")]
    s: QuoteMultiplierV1,
    #[serde(rename = "E")]
    e: QuoteMultiplierV1,
    #[serde(rename = "D")]
    d: QuoteMultiplierV1,
    #[serde(rename = "I")]
    i: QuoteMultiplierV1,
    #[serde(rename = "R")]
    r: QuoteMultiplierV1,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct QuoteV1 {
    schema_version: String,
    currency: String,
    base_price_gbp: u64,
    multipliers: QuoteMultipliersV1,
    total_price_gbp: u64,
    deposit_gbp: u64,
}

#[derive(Debug, Clone, Serialize)]
struct CupolaContextV11 {
    schema_version: Option<String>,
    generated_at: Option<String>,
    query: Option<String>,
    limit: Option<usize>,
    vault_path: Option<String>,
    vault_id: Option<String>,
    tool: Option<CupolaTool>,
    tool_version: Option<String>,
    hit_count: usize,
    cupola_manifest_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hash_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    freeze_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verify_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    replay_status: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct AegisManifestV11 {
    schema_version: String,
    generated_at: String,
    pack_id: String,
    pack_sha256: String,
    pack_path: String,
    cupola_import_path: String,
    pack_type: PackType,
    library_pack: LibraryPack,
    pack_meta: PackMeta,
    claim_count: usize,
    intake: IntakeV1,
    cupola: CupolaContextV11,
    query_log: Vec<QueryLogEntry>,
    control_results: BTreeMap<String, ControlResultManifest>,
    evidence_bindings: Vec<EvidenceBinding>,
    quote_path: String,
    quote_sha256: String,
    data_share_checklist_path: String,
    artifacts: Vec<ArtifactDigest>,
}

#[derive(Debug, Serialize)]
struct AegisSealV1 {
    schema_version: String,
    generated_at: String,
    pack_id: String,
    algorithm: String,
    artifacts: Vec<ArtifactDigest>,
}

#[derive(Debug, Clone)]
struct RunCommandOverrides {
    auto_evaluation: AutoEvaluation,
    cupola_search: CupolaSearch,
}

struct DecisionPackBuild<'a> {
    pack: &'a Pack,
    intake: &'a IntakeV1,
    controls: &'a [LibraryControl],
    queries: &'a LibraryQueries,
    rubric: &'a LibraryRubric,
    query_log: &'a [QueryLogEntry],
    control_results: &'a BTreeMap<String, ControlResultManifest>,
    cupola: &'a CupolaSearch,
    cupola_import_path: &'a Path,
    export_dir: &'a Path,
    cupola_manifest_path_abs: &'a Path,
    hash_status: Option<String>,
    freeze_status: Option<String>,
    verify_status: Option<String>,
    replay_status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PackMeta {
    pack_type: String,
    library: String,
    client: String,
    engagement: String,
    pack_id: String,
}

fn build_pack_meta(intake: &IntakeV1, pack_id: &str) -> Result<PackMeta> {
    let pack_type = intake.pack_type.slug().trim().to_string();
    let library = intake.library_pack.slug().trim().to_string();
    let client = intake.client_id.trim().to_string();
    let engagement = intake.engagement_id.trim().to_string();
    let pack_id = pack_id.trim().to_string();

    if pack_type.is_empty() {
        bail!("pack_meta.pack_type is required");
    }
    if library.is_empty() {
        bail!("pack_meta.library is required");
    }
    if client.is_empty() {
        bail!("pack_meta.client is required");
    }
    if engagement.is_empty() {
        bail!("pack_meta.engagement is required");
    }
    if pack_id.is_empty() {
        bail!("pack_meta.pack_id is required");
    }

    Ok(PackMeta {
        pack_type,
        library,
        client,
        engagement,
        pack_id,
    })
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => cmd_init(),
        Commands::ImportCupola { path } => cmd_import_cupola(path),
        Commands::ImportCupolaVault(args) => cmd_import_cupola_vault(args),
        Commands::Run(args) => cmd_run(args),
        Commands::Quote(args) => cmd_quote(args),
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
        Commands::Export(args) => cmd_export(args),
    }
}

fn cmd_init() -> Result<()> {
    ensure_dirs()?;
    if Path::new(PACK_PATH).exists() {
        bail!("Pack already initialized at {PACK_PATH}");
    }

    let pack = Pack::new(now_utc_rfc3339());
    write_json(Path::new(PACK_PATH), &pack)?;

    println!("Initialized {PACK_PATH}");
    Ok(())
}

fn cmd_import_cupola(path: PathBuf) -> Result<()> {
    ensure_dirs()?;
    let mut pack = load_pack()?;

    let raw = fs::read_to_string(&path)
        .with_context(|| format!("Failed to read cupola file: {}", path.display()))?;
    let (parsed_json, parsed) = parse_cupola_search(&raw, &path.display().to_string())?;

    write_json(Path::new(CUPOLA_IMPORT_PATH), &parsed_json)?;
    pack.cupola_import_path = Some(CUPOLA_IMPORT_PATH.to_string());
    save_pack(&pack)?;

    println!(
        "Imported {} Cupola hits to {CUPOLA_IMPORT_PATH}",
        parsed.hits.len()
    );
    Ok(())
}

fn cmd_import_cupola_vault(args: ImportCupolaVaultArgs) -> Result<()> {
    ensure_dirs()?;
    let mut pack = load_pack()?;

    let raw_stdout = run_cupola_search(&args.cupola_repo, &args.vault, &args.q, args.limit)?;
    write_string(Path::new(CUPOLA_SEARCH_RAW_PATH), &raw_stdout)?;

    let (parsed_json, parsed) = parse_cupola_search(&raw_stdout, "cupola search stdout")?;
    write_json(Path::new(CUPOLA_IMPORT_PATH), &parsed_json)?;

    pack.cupola_import_path = Some(CUPOLA_IMPORT_PATH.to_string());
    save_pack(&pack)?;

    println!(
        "Imported {} Cupola hits from vault '{}' into {} (raw stdout: {})",
        parsed.hits.len(),
        args.vault.display(),
        CUPOLA_IMPORT_PATH,
        CUPOLA_SEARCH_RAW_PATH
    );
    Ok(())
}

fn run_cupola_command_output(cupola_repo: &Path, op_name: &str, args: &[String]) -> Result<String> {
    let output = Command::new("cargo")
        .arg("run")
        .arg("-p")
        .arg("cupola-cli")
        .arg("--")
        .args(args)
        .current_dir(cupola_repo)
        .output()
        .with_context(|| {
            format!(
                "Failed to run `cargo run -p cupola-cli -- {op_name}` in {}",
                cupola_repo.display()
            )
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let details = if !stderr.is_empty() { stderr } else { stdout };
        bail!("cupola {op_name} failed: {details}");
    }

    String::from_utf8(output.stdout).context("cupola command stdout was not UTF-8")
}

fn run_cupola_hash(cupola_repo: &Path, vault: &Path) -> Result<String> {
    let args = vec![
        "hash".to_string(),
        "--vault".to_string(),
        vault.display().to_string(),
    ];
    run_cupola_command_output(cupola_repo, "hash", &args)
}

fn run_cupola_search(
    cupola_repo: &Path,
    vault: &Path,
    query: &str,
    limit: usize,
) -> Result<String> {
    let args = vec![
        "search".to_string(),
        "--vault".to_string(),
        vault.display().to_string(),
        "--q".to_string(),
        query.to_string(),
        "--limit".to_string(),
        limit.to_string(),
        "--json".to_string(),
    ];
    let stdout = run_cupola_command_output(cupola_repo, "search", &args)?;
    if stdout.trim().is_empty() {
        bail!("cupola search returned empty stdout");
    }
    Ok(stdout)
}

fn run_cupola_freeze(cupola_repo: &Path, vault: &Path, manifest: &Path) -> Result<String> {
    let args = vec![
        "freeze".to_string(),
        "--vault".to_string(),
        vault.display().to_string(),
        "--out".to_string(),
        manifest.display().to_string(),
    ];
    run_cupola_command_output(cupola_repo, "freeze", &args)
}

fn run_cupola_verify(cupola_repo: &Path, vault: &Path, manifest: &Path) -> Result<String> {
    let args = vec![
        "verify".to_string(),
        "--vault".to_string(),
        vault.display().to_string(),
        "--manifest".to_string(),
        manifest.display().to_string(),
    ];
    run_cupola_command_output(cupola_repo, "verify", &args)
}

fn run_cupola_replay(cupola_repo: &Path, vault: &Path, manifest: &Path) -> Result<String> {
    let args = vec![
        "replay".to_string(),
        "--vault".to_string(),
        vault.display().to_string(),
        "--manifest".to_string(),
        manifest.display().to_string(),
    ];
    run_cupola_command_output(cupola_repo, "replay", &args)
}

fn cmd_bind(claim_id: String, slot_id: String, hit_index: usize) -> Result<()> {
    let mut pack = load_pack()?;
    let hits_len = load_cupola_hits_len(pack.cupola_import_path.as_deref())?;
    if hit_index >= hits_len {
        bail!("hit_index {hit_index} is out of range (hits length: {hits_len})");
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

fn cmd_run(args: RunArgs) -> Result<()> {
    cmd_run_inner(args, None)
}

fn cmd_run_inner(args: RunArgs, overrides: Option<RunCommandOverrides>) -> Result<()> {
    ensure_dirs()?;

    let mut intake = load_and_validate_intake_v1(&args.intake)?;
    if intake.generated_at.is_none() {
        intake.generated_at = Some(now_utc_rfc3339());
    }

    let export_dir = resolve_export_dir_for_run(&args, &intake, PACK_ID);
    let vault_path = normalized_absolute_path(&args.vault)?;
    let out_path = normalized_absolute_path(&export_dir)?;
    if is_within(&out_path, &vault_path) {
        bail!(
            "Refusing --out inside --vault (would invalidate Cupola manifest verification). Choose an output folder outside the vault."
        );
    }

    println!("Using output directory {}", out_path.display());
    fs::create_dir_all(&out_path)
        .with_context(|| format!("Failed to create export directory {}", out_path.display()))?;

    let library_pack_data =
        load_library_pack_data_with_data_dir(args.data_dir.as_deref(), intake.library_pack)?;
    let export_dir = out_path;

    let cupola_manifest_path_abs = absolute_path(&export_dir.join(CUPOLA_MANIFEST_FILE))?;
    let (auto, cupola, hash_status, freeze_status, verify_status, replay_status) = match overrides {
        Some(override_values) => {
            write_json(
                &cupola_manifest_path_abs,
                &serde_json::json!({"schema_version":"cupola.manifest.v0.test"}),
            )?;
            (
                override_values.auto_evaluation,
                override_values.cupola_search,
                Some("skipped(test_override)".to_string()),
                Some("skipped(test_override)".to_string()),
                Some("skipped(test_override)".to_string()),
                Some("skipped(test_override)".to_string()),
            )
        }
        None => {
            run_cupola_hash(&args.cupola_repo, &args.vault)?;
            let auto = run_auto_evaluation(
                &args.cupola_repo,
                &args.vault,
                &library_pack_data.queries,
                &library_pack_data.controls,
                &library_pack_data.rubric,
            )?;
            let cupola = auto.first_search.clone().ok_or_else(|| {
                anyhow!("run could not capture Cupola search metadata from query execution")
            })?;
            run_cupola_freeze(&args.cupola_repo, &args.vault, &cupola_manifest_path_abs)?;
            run_cupola_verify(&args.cupola_repo, &args.vault, &cupola_manifest_path_abs)?;
            run_cupola_replay(&args.cupola_repo, &args.vault, &cupola_manifest_path_abs)?;
            (
                auto,
                cupola,
                Some("ok".to_string()),
                Some("ok".to_string()),
                Some("ok".to_string()),
                Some("ok".to_string()),
            )
        }
    };

    write_json(Path::new(CUPOLA_IMPORT_PATH), &cupola)?;

    let mut pack = Pack::new(now_utc_rfc3339());
    pack.cupola_import_path = Some(CUPOLA_IMPORT_PATH.to_string());
    for claim_id in intake.claims.keys() {
        pack.claims.entry(claim_id.clone()).or_default();
    }

    write_decision_pack_outputs(DecisionPackBuild {
        pack: &pack,
        intake: &intake,
        controls: &library_pack_data.controls,
        queries: &library_pack_data.queries,
        rubric: &library_pack_data.rubric,
        query_log: &auto.query_log,
        control_results: &auto.control_results,
        cupola: &cupola,
        cupola_import_path: Path::new(CUPOLA_IMPORT_PATH),
        export_dir: &export_dir,
        cupola_manifest_path_abs: &cupola_manifest_path_abs,
        hash_status,
        freeze_status,
        verify_status,
        replay_status,
    })?;

    println!("Run complete for vault {}", args.vault.display());
    Ok(())
}

fn cmd_quote(args: QuoteArgs) -> Result<()> {
    let intake = load_and_validate_intake_v1_for_quote(&args.intake)?;
    let quote = compute_quote(&intake)?;
    let quote_json_content = json_pretty(&quote)?;
    let quote_md_content = render_quote_md(&intake, &quote);
    let checklist_md_content = render_data_share_checklist_md(&intake);

    if args.print {
        print!("{quote_md_content}");
        return Ok(());
    }

    let export_dir = resolve_export_dir_for_quote(args.out.as_deref(), &intake, PACK_ID);
    fs::create_dir_all(&export_dir)
        .with_context(|| format!("Failed to create export directory {}", export_dir.display()))?;
    write_string(&export_dir.join(QUOTE_JSON), &quote_json_content)?;
    write_string(&export_dir.join(QUOTE_MD), &quote_md_content)?;
    write_string(
        &export_dir.join(DATA_SHARE_CHECKLIST_MD),
        &checklist_md_content,
    )?;
    println!("Exported Quote to {}", export_dir.display());
    Ok(())
}

fn resolve_export_dir_for_run(args: &RunArgs, intake: &IntakeV1, pack_id: &str) -> PathBuf {
    if let Some(vault) = &args.in_vault {
        return vault.join(".aegis").join("exports").join(pack_id);
    }

    if let Some(out) = &args.out {
        return out
            .join(&intake.client_id)
            .join(&intake.engagement_id)
            .join(pack_id);
    }

    default_run_output_root()
}

fn resolve_export_dir_for_quote(out: Option<&Path>, intake: &IntakeV1, pack_id: &str) -> PathBuf {
    if let Some(out) = out {
        return out
            .join(&intake.client_id)
            .join(&intake.engagement_id)
            .join(pack_id);
    }

    PathBuf::from("out")
        .join(&intake.client_id)
        .join(&intake.engagement_id)
        .join(pack_id)
}

fn load_and_validate_intake_v1(path: &Path) -> Result<IntakeV1> {
    let intake: IntakeV1 = read_json_file(path)
        .with_context(|| format!("Failed to load intake JSON {}", path.display()))?;
    validate_intake_v1_for_pack(&intake)?;
    Ok(intake)
}

fn load_and_validate_intake_v1_for_quote(path: &Path) -> Result<IntakeV1> {
    let intake: IntakeV1 = read_json_file(path)
        .with_context(|| format!("Failed to load intake JSON {}", path.display()))?;
    validate_intake_v1_common(&intake)?;
    Ok(intake)
}

fn validate_intake_v1_for_pack(intake: &IntakeV1) -> Result<()> {
    validate_intake_v1_common(intake)?;
    if intake.scope.in_scope.trim().is_empty() {
        bail!("intake.scope.in_scope is required");
    }
    if intake.scope.out_of_scope.trim().is_empty() {
        bail!("intake.scope.out_of_scope is required");
    }
    Ok(())
}

fn validate_intake_v1_common(intake: &IntakeV1) -> Result<()> {
    if intake.schema_version != "aegis.intake.v1" {
        bail!(
            "Unsupported intake schema_version '{}'; expected 'aegis.intake.v1'",
            intake.schema_version
        );
    }
    if intake.client_id.trim().is_empty() {
        bail!("intake.client_id is required");
    }
    if intake.engagement_id.trim().is_empty() {
        bail!("intake.engagement_id is required");
    }
    if let Some(deadlines) = &intake.deadlines {
        NaiveDate::parse_from_str(&deadlines.due_date, "%Y-%m-%d").with_context(|| {
            format!(
                "intake.deadlines.due_date must be ISO date YYYY-MM-DD: {}",
                deadlines.due_date
            )
        })?;
    }
    Ok(())
}

fn cmd_export(args: ExportArgs) -> Result<()> {
    ensure_dirs()?;
    let pack = load_pack()?;

    let cupola_import_path = resolve_cupola_import_path(&pack)?;
    let cupola = load_cupola_search(&cupola_import_path)?;
    validate_pack_bindings(&pack, cupola.hits.len())?;

    let library_pack_data =
        load_library_pack_data_with_data_dir(args.data_dir.as_deref(), args.library_pack)?;
    let claims_have_scores = pack.claims.values().any(|claim| claim.score.is_some());
    let should_auto = pack.claims.is_empty()
        || !claims_have_scores
        || matches!(
            args.pack_type,
            PackType::TrustAudit | PackType::GovernanceControls
        );

    let (query_log, control_results) = if should_auto {
        let vault_path = cupola
            .vault
            .as_ref()
            .and_then(|vault| vault.vault_path.as_deref())
            .ok_or_else(|| {
                anyhow!(
                    "Cupola vault path is unknown in {}. Run 'import-cupola-vault --vault <PATH> --q <STRING>' first.",
                    cupola_import_path.display()
                )
            })?;
        let auto = run_auto_evaluation(
            &args.cupola_repo,
            Path::new(vault_path),
            &library_pack_data.queries,
            &library_pack_data.controls,
            &library_pack_data.rubric,
        )?;
        (auto.query_log, auto.control_results)
    } else {
        (
            Vec::new(),
            empty_control_results(&library_pack_data.controls),
        )
    };

    let export_dir = resolve_export_dir(&args, &pack.pack_id);
    fs::create_dir_all(&export_dir)
        .with_context(|| format!("Failed to create export directory {}", export_dir.display()))?;

    let generated_at = now_utc_rfc3339();
    let intake = IntakeV1::new(
        generated_at.clone(),
        args.client_id,
        args.engagement_id,
        args.pack_type,
        args.library_pack,
    );

    let cupola_manifest_path = export_dir.join(CUPOLA_MANIFEST_FILE);
    let cupola_manifest_path_abs = absolute_path(&cupola_manifest_path)?;
    let result = write_decision_pack_outputs(DecisionPackBuild {
        pack: &pack,
        intake: &intake,
        controls: &library_pack_data.controls,
        queries: &library_pack_data.queries,
        rubric: &library_pack_data.rubric,
        query_log: &query_log,
        control_results: &control_results,
        cupola: &cupola,
        cupola_import_path: &cupola_import_path,
        export_dir: &export_dir,
        cupola_manifest_path_abs: &cupola_manifest_path_abs,
        hash_status: None,
        freeze_status: None,
        verify_status: None,
        replay_status: None,
    });
    if result.is_ok() {
        println!(
            "Tip: prefer `aegis run --vault <PATH> --intake <FILE>` for end-to-end execution."
        );
    }
    result
}

fn write_decision_pack_outputs(build: DecisionPackBuild<'_>) -> Result<()> {
    let DecisionPackBuild {
        pack,
        intake,
        controls,
        queries,
        rubric,
        query_log,
        control_results,
        cupola,
        cupola_import_path,
        export_dir,
        cupola_manifest_path_abs,
        hash_status,
        freeze_status,
        verify_status,
        replay_status,
    } = build;

    let generated_at = now_utc_rfc3339();
    let canonical_pack_json = canonical_pack_json(pack)?;
    let pack_sha256 = sha256_hex(&canonical_pack_json);
    let pack_meta = build_pack_meta(intake, &pack.pack_id)?;
    let quote = compute_quote(intake)?;
    let quote_json_content = json_pretty(&quote)?;
    let quote_md_content = render_quote_md(intake, &quote);
    let checklist_md_content = render_data_share_checklist_md(intake);
    let html_content = render_html(
        &pack_sha256,
        &pack_meta,
        intake.pack_type,
        controls,
        queries,
        rubric,
        control_results,
        query_log,
    );
    let replay_content = render_replay_md(
        cupola.vault.as_ref().and_then(|v| v.vault_path.as_deref()),
        cupola_manifest_path_abs,
    );

    let quote_json_sha256 = sha256_hex(&quote_json_content);
    let quote_md_sha256 = sha256_hex(&quote_md_content);
    let checklist_sha256 = sha256_hex(&checklist_md_content);
    let html_sha256 = sha256_hex(&html_content);
    let replay_sha256 = sha256_hex(&replay_content);

    let evidence_bindings = collect_evidence_bindings(pack, cupola)?;
    let manifest = AegisManifestV11 {
        schema_version: "aegis.manifest.v1.1".to_string(),
        generated_at: generated_at.clone(),
        pack_id: pack.pack_id.clone(),
        pack_sha256: pack_sha256.clone(),
        pack_path: PACK_PATH.to_string(),
        cupola_import_path: cupola_import_path.to_string_lossy().to_string(),
        pack_type: intake.pack_type,
        library_pack: intake.library_pack,
        pack_meta: pack_meta.clone(),
        claim_count: pack.claims.len(),
        intake: intake.clone(),
        cupola: CupolaContextV11 {
            schema_version: cupola.schema_version.clone(),
            generated_at: cupola.generated_at.clone(),
            query: cupola.query.clone(),
            limit: cupola.limit,
            vault_path: cupola.vault.as_ref().and_then(|v| v.vault_path.clone()),
            vault_id: cupola.vault.as_ref().and_then(|v| v.vault_id.clone()),
            tool_version: cupola.tool.as_ref().and_then(|tool| tool.version.clone()),
            tool: cupola.tool.clone(),
            hit_count: cupola.hits.len(),
            cupola_manifest_path: Some(cupola_manifest_path_abs.to_string_lossy().to_string()),
            hash_status,
            freeze_status,
            verify_status,
            replay_status,
        },
        query_log: query_log.to_vec(),
        control_results: control_results.clone(),
        evidence_bindings,
        quote_path: QUOTE_JSON.to_string(),
        quote_sha256: quote_json_sha256.clone(),
        data_share_checklist_path: DATA_SHARE_CHECKLIST_MD.to_string(),
        artifacts: vec![
            ArtifactDigest {
                path: DECISION_PACK_HTML.to_string(),
                sha256: html_sha256.clone(),
            },
            ArtifactDigest {
                path: QUOTE_JSON.to_string(),
                sha256: quote_json_sha256.clone(),
            },
            ArtifactDigest {
                path: QUOTE_MD.to_string(),
                sha256: quote_md_sha256.clone(),
            },
            ArtifactDigest {
                path: DATA_SHARE_CHECKLIST_MD.to_string(),
                sha256: checklist_sha256.clone(),
            },
            ArtifactDigest {
                path: REPLAY_MD.to_string(),
                sha256: replay_sha256.clone(),
            },
        ],
    };

    let manifest_content = json_pretty(&manifest)?;
    let manifest_sha256 = sha256_hex(&manifest_content);

    let seal = AegisSealV1 {
        schema_version: "aegis.seal.v1".to_string(),
        generated_at,
        pack_id: pack.pack_id.clone(),
        algorithm: "sha256".to_string(),
        artifacts: vec![
            ArtifactDigest {
                path: DECISION_PACK_HTML.to_string(),
                sha256: html_sha256,
            },
            ArtifactDigest {
                path: DECISION_PACK_MANIFEST.to_string(),
                sha256: manifest_sha256,
            },
            ArtifactDigest {
                path: QUOTE_JSON.to_string(),
                sha256: quote_json_sha256,
            },
            ArtifactDigest {
                path: QUOTE_MD.to_string(),
                sha256: quote_md_sha256,
            },
            ArtifactDigest {
                path: DATA_SHARE_CHECKLIST_MD.to_string(),
                sha256: checklist_sha256,
            },
            ArtifactDigest {
                path: REPLAY_MD.to_string(),
                sha256: replay_sha256,
            },
        ],
    };

    let html_path = export_dir.join(DECISION_PACK_HTML);
    let manifest_path = export_dir.join(DECISION_PACK_MANIFEST);
    let seal_path = export_dir.join(DECISION_PACK_SEAL);
    let replay_path = export_dir.join(REPLAY_MD);
    let quote_json_path = export_dir.join(QUOTE_JSON);
    let quote_md_path = export_dir.join(QUOTE_MD);
    let checklist_path = export_dir.join(DATA_SHARE_CHECKLIST_MD);

    write_string(&html_path, &html_content)?;
    write_string(&quote_json_path, &quote_json_content)?;
    write_string(&quote_md_path, &quote_md_content)?;
    write_string(&checklist_path, &checklist_md_content)?;
    write_string(&replay_path, &replay_content)?;
    write_string(&manifest_path, &manifest_content)?;
    write_json(&seal_path, &seal)?;

    println!("Exported Decision Pack to {}", export_dir.display());
    println!("pack_sha256: {pack_sha256}");
    Ok(())
}

fn run_auto_evaluation(
    cupola_repo: &Path,
    vault: &Path,
    queries: &LibraryQueries,
    controls: &[LibraryControl],
    rubric: &LibraryRubric,
) -> Result<AutoEvaluation> {
    let mut query_log = Vec::new();
    let mut first_search = None;

    for query in &queries.queries {
        let effective_limit = query.limit.clamp(1, MAX_QUERY_HITS_PER_QUERY);
        let raw = run_cupola_search(cupola_repo, vault, &query.query_text, effective_limit)?;
        let (_, parsed) = parse_cupola_search(&raw, &format!("library query {}", query.query_id))?;
        if first_search.is_none() {
            first_search = Some(parsed.clone());
        }

        let evidence_refs: Vec<EvidenceRef> = parsed
            .hits
            .iter()
            .enumerate()
            .map(|(idx, hit)| evidence_ref_from_hit(&query.query_id, idx + 1, hit))
            .collect();

        query_log.push(QueryLogEntry {
            query_id: query.query_id.clone(),
            query_text: query.query_text.clone(),
            tags: query.tags.clone(),
            limit: effective_limit,
            hit_count: evidence_refs.len(),
            evidence_refs,
        });
    }

    let control_results = score_controls(controls, queries, &query_log, rubric);
    Ok(AutoEvaluation {
        query_log,
        control_results,
        first_search,
    })
}

fn score_controls(
    controls: &[LibraryControl],
    queries: &LibraryQueries,
    query_log: &[QueryLogEntry],
    rubric: &LibraryRubric,
) -> BTreeMap<String, ControlResultManifest> {
    let mut output = BTreeMap::new();
    let query_lookup: BTreeMap<String, &QueryLogEntry> = query_log
        .iter()
        .map(|query| (query.query_id.clone(), query))
        .collect();
    let query_tags_by_id: BTreeMap<String, BTreeSet<String>> = query_log
        .iter()
        .map(|query| (query.query_id.clone(), normalized_tag_set(&query.tags)))
        .collect();
    let control_query_map = build_control_query_map(controls, queries, &query_tags_by_id, rubric);

    for control in controls {
        let control_tags = normalized_tag_set(&control.tags);
        let mut evidence_refs = Vec::new();
        let mut seen = BTreeSet::new();
        let query_ids = control_query_map
            .get(&control.control_id)
            .cloned()
            .unwrap_or_default();

        for query_id in query_ids {
            let Some(query) = query_lookup.get(&query_id) else {
                continue;
            };
            for evidence in &query.evidence_refs {
                let key = format!(
                    "{}:{}:{}:{}",
                    evidence.chunk_id, evidence.rel_path, evidence.start_line, evidence.end_line
                );
                if seen.insert(key) {
                    evidence_refs.push(evidence.clone());
                }
            }
        }

        let evidence_count = evidence_refs.len();
        if evidence_refs.len() > MAX_EVIDENCE_REFS_PER_CONTROL {
            evidence_refs.truncate(MAX_EVIDENCE_REFS_PER_CONTROL);
        }

        let (min_partial, min_met) = thresholds_for_control(&control_tags, rubric);
        let status = if evidence_count >= min_met {
            ControlStatus::Met
        } else if evidence_count >= min_partial {
            ControlStatus::Partial
        } else {
            ControlStatus::Gap
        };

        output.insert(
            control.control_id.clone(),
            ControlResultManifest {
                title: control.title.clone(),
                status,
                severity: control.severity.min(5),
                evidence_count,
                evidence_refs,
            },
        );
    }

    output
}

fn build_control_query_map(
    controls: &[LibraryControl],
    queries: &LibraryQueries,
    query_tags_by_id: &BTreeMap<String, BTreeSet<String>>,
    rubric: &LibraryRubric,
) -> BTreeMap<String, Vec<String>> {
    let mut rubric_mapping: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let known_query_ids: BTreeSet<&str> = query_tags_by_id.keys().map(String::as_str).collect();

    for mapping in &rubric.control_query_map {
        let control_key = normalize_control_id(&mapping.control_id);
        let query_ids: Vec<String> = mapping
            .query_ids
            .iter()
            .filter(|query_id| known_query_ids.contains(query_id.as_str()))
            .cloned()
            .collect();
        if !query_ids.is_empty() {
            rubric_mapping.insert(control_key, dedupe_preserving_order(query_ids));
        }
    }

    let mut query_explicit_mapping: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for query in &queries.queries {
        if !known_query_ids.contains(query.query_id.as_str()) {
            continue;
        }
        for control_id in &query.control_ids {
            query_explicit_mapping
                .entry(normalize_control_id(control_id))
                .or_default()
                .push(query.query_id.clone());
        }
    }
    for query_ids in query_explicit_mapping.values_mut() {
        let deduped = dedupe_preserving_order(query_ids.clone());
        *query_ids = deduped;
    }

    let mut output = BTreeMap::new();
    for control in controls {
        let control_key = normalize_control_id(&control.control_id);
        let control_tags = normalized_tag_set(&control.tags);

        let mut query_ids = rubric_mapping
            .get(&control_key)
            .cloned()
            .or_else(|| query_explicit_mapping.get(&control_key).cloned())
            .unwrap_or_default();

        if query_ids.is_empty() {
            query_ids = query_tags_by_id
                .iter()
                .filter_map(|(query_id, query_tags)| {
                    if tag_sets_intersect(&control_tags, query_tags) {
                        Some(query_id.clone())
                    } else {
                        None
                    }
                })
                .collect();
        }

        output.insert(control.control_id.clone(), dedupe_preserving_order(query_ids));
    }

    output
}

fn thresholds_for_control(tags: &BTreeSet<String>, rubric: &LibraryRubric) -> (usize, usize) {
    let mut min_partial = 1;
    let mut min_met = 2;

    for rule in &rubric.rules {
        if tags.contains(&normalize_tag(&rule.tag)) {
            min_partial = min_partial.max(rule.min_hits_for_partial);
            min_met = min_met.max(rule.min_hits_for_met);
        }
    }

    if min_met < min_partial {
        min_met = min_partial;
    }

    (min_partial, min_met)
}

fn evidence_ref_from_hit(query_id: &str, rank: usize, hit: &CupolaHit) -> EvidenceRef {
    EvidenceRef {
        query_id: query_id.to_string(),
        rank,
        chunk_id: hit.chunk_id.clone(),
        rel_path: hit.rel_path.clone(),
        start_line: hit.start_line,
        end_line: hit.end_line,
        excerpt: hit.excerpt.clone(),
    }
}

fn normalized_tag_set(tags: &[String]) -> BTreeSet<String> {
    tags.iter().map(|tag| normalize_tag(tag)).collect()
}

fn normalize_tag(tag: &str) -> String {
    tag.trim().to_ascii_lowercase()
}

fn normalize_control_id(control_id: &str) -> String {
    control_id.trim().to_ascii_lowercase()
}

fn tag_sets_intersect(left: &BTreeSet<String>, right: &BTreeSet<String>) -> bool {
    left.iter().any(|tag| right.contains(tag))
}

fn dedupe_preserving_order(values: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut deduped = Vec::new();
    for value in values {
        if seen.insert(value.clone()) {
            deduped.push(value);
        }
    }
    deduped
}

fn empty_control_results(controls: &[LibraryControl]) -> BTreeMap<String, ControlResultManifest> {
    let mut output = BTreeMap::new();
    for control in controls {
        output.insert(control.control_id.clone(), default_control_result(control));
    }
    output
}

fn default_control_result(control: &LibraryControl) -> ControlResultManifest {
    ControlResultManifest {
        title: control.title.clone(),
        status: ControlStatus::Gap,
        severity: control.severity.min(5),
        evidence_count: 0,
        evidence_refs: Vec::new(),
    }
}

fn load_library_pack_data_with_data_dir(
    data_dir: Option<&Path>,
    library_pack: LibraryPack,
) -> Result<LibraryPackData> {
    let packs_root = resolve_packs_root(data_dir)?;
    let root = packs_root.join(library_pack.slug());
    let controls_path = root.join("controls.json");
    let queries_path = root.join("queries.json");
    let rubric_path = root.join("rubric.json");

    let controls: Vec<LibraryControl> = read_json_file(&controls_path)
        .with_context(|| format!("Failed to load {}", controls_path.display()))?;
    if controls.is_empty() {
        bail!("{} has no controls", controls_path.display());
    }
    let is_standard_pack = matches!(
        library_pack,
        LibraryPack::VendorSecurity | LibraryPack::Iso27001 | LibraryPack::NistCsf
    );
    let min_controls_required = match library_pack {
        LibraryPack::VendorSecurity => 80,
        LibraryPack::Iso27001 => 93,
        LibraryPack::NistCsf => 80,
        _ => 1,
    };
    if controls.len() < min_controls_required {
        bail!(
            "{} has {} controls, expected at least {}",
            controls_path.display(),
            controls.len(),
            min_controls_required
        );
    }
    let mut control_ids = BTreeSet::new();
    for control in &controls {
        if !(1..=5).contains(&control.severity) {
            bail!(
                "Control {} in {} has severity {}, expected 1..=5",
                control.control_id,
                controls_path.display(),
                control.severity
            );
        }
        if !control_ids.insert(control.control_id.clone()) {
            bail!(
                "Duplicate control_id {} found in {}",
                control.control_id,
                controls_path.display()
            );
        }
        if is_standard_pack && control.objective.trim().is_empty() {
            bail!(
                "Control {} in {} is missing objective",
                control.control_id,
                controls_path.display()
            );
        }
        if is_standard_pack && control.evidence_expectations.is_empty() {
            bail!(
                "Control {} in {} is missing evidence_expectations",
                control.control_id,
                controls_path.display()
            );
        }
    }

    let queries: LibraryQueries = read_json_file(&queries_path)
        .with_context(|| format!("Failed to load {}", queries_path.display()))?;
    if queries.queries.is_empty() {
        bail!("{} has no queries", queries_path.display());
    }
    let min_queries_required = match library_pack {
        LibraryPack::VendorSecurity => 40,
        LibraryPack::Iso27001 => 50,
        LibraryPack::NistCsf => 45,
        _ => 1,
    };
    if queries.queries.len() < min_queries_required {
        bail!(
            "{} has {} queries, expected at least {}",
            queries_path.display(),
            queries.queries.len(),
            min_queries_required
        );
    }
    let mut query_ids = BTreeSet::new();
    for query in &queries.queries {
        if !query_ids.insert(query.query_id.clone()) {
            bail!(
                "Duplicate query_id {} found in {}",
                query.query_id,
                queries_path.display()
            );
        }
        if is_standard_pack && query.limit < 25 {
            bail!(
                "Query {} in {} has limit {}, expected >=25 for standard packs",
                query.query_id,
                queries_path.display(),
                query.limit
            );
        }
    }

    let rubric: LibraryRubric = read_json_file(&rubric_path)
        .with_context(|| format!("Failed to load {}", rubric_path.display()))?;
    if rubric.rules.is_empty() {
        bail!("{} has no rubric rules", rubric_path.display());
    }
    if is_standard_pack && rubric.control_query_map.is_empty() {
        bail!(
            "{} has no control_query_map entries for standard pack {}",
            rubric_path.display(),
            library_pack.slug()
        );
    }
    for mapping in &rubric.control_query_map {
        if !control_ids.contains(&mapping.control_id) {
            bail!(
                "rubric mapping references unknown control_id {} in {}",
                mapping.control_id,
                rubric_path.display()
            );
        }
        if mapping.query_ids.is_empty() {
            bail!(
                "rubric mapping for control_id {} has no query_ids in {}",
                mapping.control_id,
                rubric_path.display()
            );
        }
        for query_id in &mapping.query_ids {
            if !query_ids.contains(query_id) {
                bail!(
                    "rubric mapping for control_id {} references unknown query_id {} in {}",
                    mapping.control_id,
                    query_id,
                    rubric_path.display()
                );
            }
        }
    }

    Ok(LibraryPackData {
        controls,
        queries,
        rubric,
    })
}

fn resolve_packs_root(data_dir: Option<&Path>) -> Result<PathBuf> {
    let data_root = if let Some(data_dir) = data_dir {
        normalized_absolute_path(data_dir)?
    } else {
        resolve_default_data_dir()?
    };
    Ok(data_root.join("packs"))
}

fn resolve_default_data_dir() -> Result<PathBuf> {
    let exe_path = std::env::current_exe().context("Failed to resolve executable path")?;
    let exe_dir = exe_path
        .parent()
        .context("Failed to resolve executable directory")?;
    let exe_data = normalize_lexical_path(&exe_dir.join("data"));
    if exe_data.exists() {
        return Ok(exe_data);
    }

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let target_dir = manifest_dir.join("target");
    if is_within(exe_dir, &target_dir) {
        return Ok(normalize_lexical_path(&manifest_dir.join("data")));
    }

    Ok(exe_data)
}

fn default_query_limit() -> usize {
    25
}

fn compute_quote(intake: &IntakeV1) -> Result<QuoteV1> {
    let base_price_gbp = match intake.pack_type {
        PackType::DdResponse => 1_500,
        PackType::TrustAudit => 3_500,
        PackType::GovernanceControls => 5_000,
    };

    let (s_bps, s_reason) = match intake.scope_size.as_ref() {
        Some(scope_size) => {
            let total = u16::from(scope_size.systems) + u16::from(scope_size.repos);
            let multiplier_bps = if total <= 2 {
                100
            } else if total <= 4 {
                125
            } else if total <= 7 {
                150
            } else {
                200
            };
            (
                multiplier_bps,
                format!(
                    "scope_size systems+repos={} (systems={}, repos={}, band={})",
                    total,
                    scope_size.systems,
                    scope_size.repos,
                    scope_size.repo_size_band.label()
                ),
            )
        }
        None => (100, "scope_size missing; default multiplier".to_string()),
    };

    let (e_bps, e_reason) = match intake.evidence_readiness {
        EvidenceReadiness::Organized => (100, "evidence_readiness=organized".to_string()),
        EvidenceReadiness::Mixed => (125, "evidence_readiness=mixed".to_string()),
        EvidenceReadiness::Chaotic => (150, "evidence_readiness=chaotic".to_string()),
    };

    let (d_bps, d_reason) = match intake.deadlines.as_ref() {
        Some(deadlines) => {
            let due_date = NaiveDate::parse_from_str(&deadlines.due_date, "%Y-%m-%d")
                .with_context(|| {
                    format!(
                        "intake.deadlines.due_date must be ISO date YYYY-MM-DD: {}",
                        deadlines.due_date
                    )
                })?;
            let today = Utc::now().date_naive();
            let days_until = due_date.signed_duration_since(today).num_days();
            if days_until <= 3 {
                (
                    150,
                    format!(
                        "due_date={} ({} day(s) from today UTC)",
                        deadlines.due_date, days_until
                    ),
                )
            } else if days_until <= 7 {
                (
                    125,
                    format!(
                        "due_date={} ({} day(s) from today UTC)",
                        deadlines.due_date, days_until
                    ),
                )
            } else {
                (
                    100,
                    format!(
                        "due_date={} ({} day(s) from today UTC)",
                        deadlines.due_date, days_until
                    ),
                )
            }
        }
        None => (100, "due_date missing; default multiplier".to_string()),
    };

    let (i_bps, i_reason, deposit_gbp) = match intake.lane {
        IntakeLane::Standard => (100, "lane=standard".to_string(), 0),
        IntakeLane::Investigation => (150, "lane=investigation".to_string(), 750),
    };
    let (r_bps, r_reason) = (100, "region multiplier fixed in v1".to_string());

    let total_price_gbp =
        round_total_to_nearest_250(base_price_gbp, [s_bps, e_bps, d_bps, i_bps, r_bps]);

    Ok(QuoteV1 {
        schema_version: "aegis.quote.v1".to_string(),
        currency: "GBP".to_string(),
        base_price_gbp,
        multipliers: QuoteMultipliersV1 {
            s: QuoteMultiplierV1 {
                factor: f64::from(s_bps) / 100.0,
                reason: s_reason,
            },
            e: QuoteMultiplierV1 {
                factor: f64::from(e_bps) / 100.0,
                reason: e_reason,
            },
            d: QuoteMultiplierV1 {
                factor: f64::from(d_bps) / 100.0,
                reason: d_reason,
            },
            i: QuoteMultiplierV1 {
                factor: f64::from(i_bps) / 100.0,
                reason: i_reason,
            },
            r: QuoteMultiplierV1 {
                factor: f64::from(r_bps) / 100.0,
                reason: r_reason,
            },
        },
        total_price_gbp,
        deposit_gbp,
    })
}

fn round_total_to_nearest_250(base_price_gbp: u64, multiplier_bps: [u16; 5]) -> u64 {
    let numerator = multiplier_bps
        .into_iter()
        .fold(u128::from(base_price_gbp), |acc, bps| acc * u128::from(bps));
    let denominator = u128::from(100_u64.pow(5));
    let rounding_bucket = denominator * 250;
    let rounded_units = (numerator + (rounding_bucket / 2)) / rounding_bucket;
    (rounded_units * 250) as u64
}

fn render_quote_md(intake: &IntakeV1, quote: &QuoteV1) -> String {
    format!(
        "# Quote\n\n- schema_version: `{}`\n- client_id: `{}`\n- engagement_id: `{}`\n- pack_type: `{}`\n- lane: `{}`\n- data_sharing_mode: `{}`\n- currency: `{}`\n- base_price_gbp: `{}`\n- total_price_gbp: `{}`\n- deposit_gbp: `{}`\n\n## Multipliers\n\n| Factor | Value | Reason |\n|---|---:|---|\n| S | {} | {} |\n| E | {} | {} |\n| D | {} | {} |\n| I | {} | {} |\n| R | {} | {} |\n",
        escape_markdown_cell(&quote.schema_version),
        escape_markdown_cell(&intake.client_id),
        escape_markdown_cell(&intake.engagement_id),
        escape_markdown_cell(intake.pack_type.slug()),
        escape_markdown_cell(intake.lane.slug()),
        escape_markdown_cell(intake.data_sharing_mode.slug()),
        escape_markdown_cell(&quote.currency),
        quote.base_price_gbp,
        quote.total_price_gbp,
        quote.deposit_gbp,
        quote.multipliers.s.factor,
        escape_markdown_cell(&quote.multipliers.s.reason),
        quote.multipliers.e.factor,
        escape_markdown_cell(&quote.multipliers.e.reason),
        quote.multipliers.d.factor,
        escape_markdown_cell(&quote.multipliers.d.reason),
        quote.multipliers.i.factor,
        escape_markdown_cell(&quote.multipliers.i.reason),
        quote.multipliers.r.factor,
        escape_markdown_cell(&quote.multipliers.r.reason),
    )
}

fn render_data_share_checklist_md(intake: &IntakeV1) -> String {
    let lane_checks = match intake.lane {
        IntakeLane::Standard => "- [ ] Standard lane: confirm normal SLA and response window.",
        IntakeLane::Investigation => {
            "- [ ] Investigation lane: confirm incident escalation contacts and legal authority."
        }
    };

    let mode_checks = match intake.data_sharing_mode {
        DataSharingMode::ClientSide => {
            "- [ ] Client-side mode: client runs Cupola locally and shares generated artifacts only."
        }
        DataSharingMode::RedactedUpload => {
            "- [ ] Redacted upload mode: sensitive fields are redacted before transfer."
        }
        DataSharingMode::RepoAccess => {
            "- [ ] Repo access mode: grant least-privilege read-only access and set expiry."
        }
    };

    format!(
        "# Data Share Checklist\n\n- lane: `{}`\n- data_sharing_mode: `{}`\n\n- [ ] Confirm scope and authorized data classes for this engagement.\n- [ ] Confirm due date and timezone assumptions.\n{}\n{}\n",
        escape_markdown_cell(intake.lane.slug()),
        escape_markdown_cell(intake.data_sharing_mode.slug()),
        lane_checks,
        mode_checks
    )
}

fn read_json_file<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("Failed to read JSON file {}", path.display()))?;
    serde_json::from_str(&raw)
        .with_context(|| format!("Failed to parse JSON file {}", path.display()))
}

fn render_html(
    pack_sha256: &str,
    pack_meta: &PackMeta,
    pack_type: PackType,
    controls: &[LibraryControl],
    queries: &LibraryQueries,
    rubric: &LibraryRubric,
    control_results: &BTreeMap<String, ControlResultManifest>,
    query_log: &[QueryLogEntry],
) -> String {
    let executive_summary = render_executive_summary(controls, control_results, rubric);
    let controls_table = render_full_controls_table(controls, control_results);
    let gap_register = render_gap_register(controls, control_results, rubric);
    let evidence_appendix =
        render_evidence_appendix(controls, queries, rubric, control_results, query_log);
    let query_section = render_query_log_section(query_log);
    let solution_body = format!(
        "{}{}{}{}{}",
        executive_summary, controls_table, gap_register, evidence_appendix, query_section
    );

    format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n  <meta charset=\"utf-8\">\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n  <title>DecisionPack</title>\n  <!-- civitas-branding:civitas-mark-v1 -->\n  <style>\n    :root {{\n      --paper: #F7F6F2;\n      --ink: #0B1220;\n      --muted: #475467;\n      --rule: #D7D3CA;\n      --accent: #1E3A5F;\n      --head-fill: #EFECE4;\n      --row-alt: #FAF8F3;\n      --space-1: 4px;\n      --space-2: 8px;\n      --space-3: 12px;\n      --space-4: 16px;\n      --space-5: 24px;\n      --space-6: 32px;\n    }}\n    @page {{ size: A4; margin: 0; }}\n    * {{ box-sizing: border-box; }}\n    html, body {{ margin: 0; padding: 0; }}\n    body {{\n      background: var(--paper);\n      color: var(--ink);\n      font-family: \"IBM Plex Sans\", ui-sans-serif, -apple-system, Segoe UI, sans-serif;\n      line-height: 1.45;\n      padding: var(--space-6);\n      position: relative;\n    }}\n    body::before {{\n      content: \"\";\n      position: fixed;\n      inset: 0;\n      pointer-events: none;\n      z-index: 0;\n      background:\n        radial-gradient(120% 88% at 10% 4%, rgba(255, 255, 255, 0.15) 0%, rgba(255, 255, 255, 0.06) 30%, rgba(255, 255, 255, 0) 64%),\n        linear-gradient(180deg, rgba(255, 255, 255, 0.07) 0%, rgba(255, 255, 255, 0) 42%, rgba(0, 0, 0, 0.03) 100%);\n      opacity: 0.1;\n    }}\n    .page {{ max-width: 1120px; margin: 0 auto; position: relative; z-index: 1; }}\n    h1, h2, h3 {{\n      font-family: \"IBM Plex Serif\", Georgia, serif;\n      letter-spacing: 0.01em;\n      color: var(--ink);\n      margin: 0;\n    }}\n    h2 {{\n      margin-top: var(--space-6);\n      padding-top: var(--space-4);\n      border-top: 1px solid var(--rule);\n      font-size: 1.2rem;\n    }}\n    h3 {{ margin-top: var(--space-5); font-size: 1.05rem; }}\n    p, li {{ margin-top: var(--space-2); }}\n    .masthead {{\n      display: flex;\n      justify-content: space-between;\n      align-items: flex-start;\n      gap: var(--space-5);\n      border-top: 1px solid var(--rule);\n      border-bottom: 1px solid var(--rule);\n      padding: var(--space-4) var(--space-3);\n      margin-bottom: var(--space-5);\n    }}\n    .masthead-left {{ display: flex; gap: var(--space-4); align-items: flex-start; }}\n    .mark {{ width: 44px; height: 44px; flex: 0 0 auto; }}\n    .title-group h1 {{ font-size: 1.85rem; margin: 0; }}\n    .motto {{ margin: var(--space-1) 0 0; color: var(--muted); font-size: 0.94rem; }}\n    .meta {{ min-width: 280px; max-width: 320px; font-size: 0.82rem; line-height: 1.25; text-align: right; background: var(--head-fill); border: 1px solid var(--rule); border-radius: 4px; padding: 8px 10px; margin-left: auto; color: var(--muted); }}\n    .meta code {{ color: var(--ink); }}\n    .meta dl {{ margin: 0; display: grid; grid-template-columns: 104px 1fr; row-gap: var(--space-1); column-gap: var(--space-2); }}\n    .meta dt {{ font-weight: 600; color: #2A3547; }}\n    .meta dd {{ margin: 0; }}\n    table {{\n      border-collapse: collapse;\n      width: 100%;\n      margin-top: var(--space-3);\n      border: 1px solid var(--rule);\n      background: #FFFEFC;\n    }}\n    th, td {{\n      border-bottom: 1px solid var(--rule);\n      padding: var(--space-2) var(--space-3);\n      vertical-align: top;\n      text-align: left;\n    }}\n    th {{\n      background: var(--head-fill);\n      font-size: 0.79rem;\n      letter-spacing: 0.02em;\n      text-transform: uppercase;\n      color: #334155;\n    }}\n    tbody tr:nth-child(even) {{ background: var(--row-alt); }}\n    .num {{ text-align: right; font-variant-numeric: tabular-nums; }}\n    code, pre {{\n      font-family: \"IBM Plex Mono\", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;\n      font-size: 0.88em;\n    }}\n    code {{\n      background: #F2EFE7;\n      border: 1px solid #E2DDD2;\n      border-radius: 3px;\n      padding: 0 4px;\n      overflow-wrap: anywhere;\n    }}\n    pre {{\n      background: #F8F6F1;\n      border: 1px solid #E2DDD2;\n      padding: var(--space-3);\n      border-radius: 4px;\n      overflow: auto;\n      margin: var(--space-2) 0;\n    }}\n    blockquote {{\n      margin: var(--space-2) 0;\n      padding: var(--space-2) var(--space-3);\n      border-left: 2px solid #B9B2A2;\n      background: #F5F2EA;\n      color: #253247;\n    }}\n    .status-met {{ color: #1E6A45; font-weight: 600; }}\n    .status-partial {{ color: #8A5A1D; font-weight: 600; }}\n    .status-gap {{ color: #8D2E24; font-weight: 600; }}\n    .muted {{ color: var(--muted); }}\n    @media (max-width: 900px) {{\n      body {{ padding: var(--space-4); }}\n      .masthead {{ flex-direction: column; gap: var(--space-4); }}\n      .meta {{ min-width: 0; width: 100%; }}\n      .meta dl {{ grid-template-columns: 96px 1fr; }}\n    }}\n  </style>\n</head>\n<body>\n  <div class=\"page\">\n    <header class=\"masthead\">\n      <div class=\"masthead-left\">\n        <svg class=\"mark\" viewBox=\"0 0 48 48\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\" aria-label=\"Civitas mark\" role=\"img\">\n          <rect x=\"4\" y=\"4\" width=\"40\" height=\"40\" rx=\"4\" stroke=\"#1E3A5F\" stroke-width=\"1.5\"/>\n          <path d=\"M12 12H36\" stroke=\"#1E3A5F\" stroke-width=\"2\" stroke-linecap=\"square\"/>\n          <path d=\"M14 34V15\" stroke=\"#1E3A5F\" stroke-width=\"2\" stroke-linecap=\"square\"/>\n          <path d=\"M24 34V11\" stroke=\"#1E3A5F\" stroke-width=\"2\" stroke-linecap=\"square\"/>\n          <path d=\"M34 34V15\" stroke=\"#1E3A5F\" stroke-width=\"2\" stroke-linecap=\"square\"/>\n          <path d=\"M12 36H36\" stroke=\"#1E3A5F\" stroke-width=\"2\" stroke-linecap=\"square\"/>\n        </svg>\n        <div class=\"title-group\">\n          <h1>{}</h1>\n          <p class=\"motto\">Civitas Analytica &mdash; Engineered truth.</p>\n        </div>\n      </div>\n      <aside class=\"meta\">\n        <dl>\n          <dt>pack_sha256</dt><dd><code>{}</code></dd>\n          <dt>pack_type</dt><dd><code>{}</code></dd>\n          <dt>library</dt><dd>{}</dd>\n          <dt>client</dt><dd>{}</dd>\n          <dt>engagement</dt><dd>{}</dd>\n        </dl>\n      </aside>\n    </header>\n    <main>\n      {}\n      {}\n    </main>\n  </div>\n</body>\n</html>\n",
        escape_html(pack_type.label()),
        escape_html(pack_sha256),
        escape_html(&pack_meta.pack_type),
        escape_html(&pack_meta.library),
        escape_html(&pack_meta.client),
        escape_html(&pack_meta.engagement),
        solution_body,
        query_section
    )
}

fn control_objective(control: &LibraryControl) -> &str {
    if control.objective.trim().is_empty() {
        &control.description
    } else {
        &control.objective
    }
}

fn control_expectations(control: &LibraryControl) -> String {
    if control.evidence_expectations.is_empty() {
        "No explicit evidence expectations listed.".to_string()
    } else {
        control.evidence_expectations.join("; ")
    }
}

fn render_executive_summary(
    controls: &[LibraryControl],
    control_results: &BTreeMap<String, ControlResultManifest>,
    rubric: &LibraryRubric,
) -> String {
    let mut met = 0usize;
    let mut partial = 0usize;
    let mut gaps = 0usize;
    let mut weighted_points = 0.0f64;
    let mut weighted_max = 0.0f64;
    let mut key_gaps: Vec<(u8, usize, String, String, &'static str)> = Vec::new();

    for control in controls {
        let result = control_results
            .get(&control.control_id)
            .cloned()
            .unwrap_or_else(|| default_control_result(control));
        let severity = result.severity.max(1);
        let status_factor = match result.status {
            ControlStatus::Met => {
                met += 1;
                1.0
            }
            ControlStatus::Partial => {
                partial += 1;
                0.5
            }
            ControlStatus::Gap => {
                gaps += 1;
                0.0
            }
        };
        weighted_points += f64::from(severity) * status_factor;
        weighted_max += f64::from(severity);

        if result.status != ControlStatus::Met {
            let (_, min_met) = thresholds_for_control(&normalized_tag_set(&control.tags), rubric);
            let missing = min_met.saturating_sub(result.evidence_count);
            key_gaps.push((
                result.severity,
                missing,
                control.control_id.clone(),
                control.title.clone(),
                control_status_label(result.status),
            ));
        }
    }

    key_gaps.sort_by(|left, right| {
        right
            .0
            .cmp(&left.0)
            .then(right.1.cmp(&left.1))
            .then(left.2.cmp(&right.2))
    });
    let key_gaps_html = if key_gaps.is_empty() {
        "<p class=\"muted\">No active gaps detected from current evidence.</p>".to_string()
    } else {
        let mut items = String::new();
        for (severity, missing, control_id, title, status) in key_gaps.into_iter().take(12) {
            items.push_str(&format!(
                "<li><code>{}</code> {} - <span class=\"status-gap\">{}</span> - severity {} - missing evidence {}</li>",
                escape_html(&control_id),
                escape_html(&title),
                escape_html(status),
                severity,
                missing
            ));
        }
        format!("<ul>{items}</ul>")
    };

    let weighted_score = if weighted_max <= f64::EPSILON {
        0.0
    } else {
        (weighted_points / weighted_max) * 100.0
    };

    format!(
        "<h2>Executive Summary</h2><table><tbody><tr><th>Severity-weighted score</th><td class=\"num\">{:.1}%</td></tr><tr><th>Total controls</th><td class=\"num\">{}</td></tr><tr><th>Met</th><td class=\"num\">{}</td></tr><tr><th>Partial</th><td class=\"num\">{}</td></tr><tr><th>Gap</th><td class=\"num\">{}</td></tr></tbody></table><h3>Key Gaps</h3>{}",
        weighted_score,
        controls.len(),
        met,
        partial,
        gaps,
        key_gaps_html
    )
}

fn render_full_controls_table(
    controls: &[LibraryControl],
    control_results: &BTreeMap<String, ControlResultManifest>,
) -> String {
    let mut rows = String::new();
    for control in controls {
        let result = control_results
            .get(&control.control_id)
            .cloned()
            .unwrap_or_else(|| default_control_result(control));
        rows.push_str(&format!(
            "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td><span class=\"{}\">{}</span></td><td class=\"num\">{}</td><td class=\"num\">{}</td></tr>",
            escape_html(&control.control_id),
            escape_html(&control.title),
            escape_html(control_objective(control)),
            escape_html(&control_expectations(control)),
            status_css_class(result.status),
            escape_html(control_status_label(result.status)),
            result.severity,
            result.evidence_count
        ));
    }

    format!(
        "<h2>Full Controls Table</h2><table><thead><tr><th>control_id</th><th>title</th><th>objective</th><th>evidence expectations</th><th>status</th><th class=\"num\">severity</th><th class=\"num\">evidence_count</th></tr></thead><tbody>{}</tbody></table>",
        rows
    )
}

fn render_gap_register(
    controls: &[LibraryControl],
    control_results: &BTreeMap<String, ControlResultManifest>,
    rubric: &LibraryRubric,
) -> String {
    let mut rows = String::new();
    for control in controls {
        let result = control_results
            .get(&control.control_id)
            .cloned()
            .unwrap_or_else(|| default_control_result(control));
        if result.status == ControlStatus::Met {
            continue;
        }
        let (_, min_met) = thresholds_for_control(&normalized_tag_set(&control.tags), rubric);
        let missing_evidence = min_met.saturating_sub(result.evidence_count);

        rows.push_str(&format!(
            "<tr><td><code>{}</code></td><td>{}</td><td><span class=\"{}\">{}</span></td><td class=\"num\">{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td><td>{}</td></tr>",
            escape_html(&control.control_id),
            escape_html(&control.title),
            status_css_class(result.status),
            escape_html(control_status_label(result.status)),
            result.severity,
            result.evidence_count,
            missing_evidence,
            escape_html(&control_expectations(control))
        ));
    }

    if rows.is_empty() {
        return "<h2>Gap Register</h2><p class=\"muted\">No gaps or partial controls detected.</p>"
            .to_string();
    }

    format!(
        "<h2>Gap Register</h2><table><thead><tr><th>control_id</th><th>title</th><th>status</th><th class=\"num\">severity</th><th class=\"num\">evidence_count</th><th class=\"num\">missing_evidence</th><th>evidence expectations</th></tr></thead><tbody>{}</tbody></table>",
        rows
    )
}

fn render_evidence_appendix(
    controls: &[LibraryControl],
    queries: &LibraryQueries,
    rubric: &LibraryRubric,
    control_results: &BTreeMap<String, ControlResultManifest>,
    query_log: &[QueryLogEntry],
) -> String {
    if query_log.is_empty() {
        return "<h2>Evidence Appendix</h2><p class=\"muted\">No automated queries were executed, so no evidence appendix can be generated.</p>".to_string();
    }

    let query_lookup: BTreeMap<String, &QueryLogEntry> = query_log
        .iter()
        .map(|entry| (entry.query_id.clone(), entry))
        .collect();
    let query_tags_by_id: BTreeMap<String, BTreeSet<String>> = query_log
        .iter()
        .map(|entry| (entry.query_id.clone(), normalized_tag_set(&entry.tags)))
        .collect();
    let control_query_map = build_control_query_map(controls, queries, &query_tags_by_id, rubric);

    let mut controls_html = String::new();
    for control in controls {
        let result = control_results
            .get(&control.control_id)
            .cloned()
            .unwrap_or_else(|| default_control_result(control));
        let mapped_queries = control_query_map
            .get(&control.control_id)
            .cloned()
            .unwrap_or_default();
        let mut query_blocks = String::new();

        for query_id in mapped_queries {
            let Some(entry) = query_lookup.get(&query_id) else {
                continue;
            };
            let evidence_list = if entry.evidence_refs.is_empty() {
                "<p class=\"muted\">No direct evidence hits for this query.</p>".to_string()
            } else {
                let mut evidence_items = String::new();
                for evidence in &entry.evidence_refs {
                    evidence_items.push_str(&format!(
                        "<li><code>{}</code> {}-{} (rank {})<blockquote>{}</blockquote></li>",
                        escape_html(&evidence.rel_path),
                        evidence.start_line,
                        evidence.end_line,
                        evidence.rank,
                        escape_html(&evidence.excerpt)
                    ));
                }
                format!("<ul>{evidence_items}</ul>")
            };

            query_blocks.push_str(&format!(
                "<section><h4><code>{}</code> - {}</h4><p class=\"muted\">tags: {} | hits: {}</p>{}</section>",
                escape_html(&entry.query_id),
                escape_html(&entry.query_text),
                escape_html(&entry.tags.join(", ")),
                entry.hit_count,
                evidence_list
            ));
        }

        if query_blocks.is_empty() {
            query_blocks = "<p class=\"muted\">No mapped queries for this control in current run.</p>"
                .to_string();
        }

        controls_html.push_str(&format!(
            "<section><h3><code>{}</code> - {}</h3><p><span class=\"{}\">{}</span> | severity {} | evidence_count {}</p><p>{}</p><p class=\"muted\">Expected evidence: {}</p>{}</section>",
            escape_html(&control.control_id),
            escape_html(&control.title),
            status_css_class(result.status),
            escape_html(control_status_label(result.status)),
            result.severity,
            result.evidence_count,
            escape_html(control_objective(control)),
            escape_html(&control_expectations(control)),
            query_blocks
        ));
    }

    format!("<h2>Evidence Appendix</h2>{controls_html}")
}

fn render_dd_response_section(
    controls: &[LibraryControl],
    control_results: &BTreeMap<String, ControlResultManifest>,
) -> String {
    let mut blocks = String::new();
    let mut gaps = Vec::new();

    for control in controls {
        let result = control_results
            .get(&control.control_id)
            .cloned()
            .unwrap_or_else(|| default_control_result(control));
        if result.status == ControlStatus::Gap {
            gaps.push(format!("{} - {}", control.control_id, control.title));
        }

        blocks.push_str(&format!(
            "<section><h3>Q: {} ({})</h3><p>{}</p><p>Status: <span class=\"{}\">{}</span> | Severity: {} | Evidence: {}</p>{}</section>",
            escape_html(&control.title),
            escape_html(&control.control_id),
            escape_html(&control.description),
            status_css_class(result.status),
            escape_html(control_status_label(result.status)),
            result.severity,
            result.evidence_count,
            render_evidence_refs(&result.evidence_refs, 3)
        ));
    }

    let gap_html = if gaps.is_empty() {
        "<p>No gaps detected from current evidence sample.</p>".to_string()
    } else {
        let mut items = String::new();
        for gap in gaps {
            items.push_str(&format!("<li>{}</li>", escape_html(&gap)));
        }
        format!("<ul>{items}</ul>")
    };

    format!(
        "<h2>DD Response Q/A</h2>{}<h2>Observed Gaps</h2>{}",
        blocks, gap_html
    )
}

fn render_trust_audit_section(
    controls: &[LibraryControl],
    control_results: &BTreeMap<String, ControlResultManifest>,
) -> String {
    let mut rows = String::new();

    for control in controls {
        let result = control_results
            .get(&control.control_id)
            .cloned()
            .unwrap_or_else(|| default_control_result(control));
        rows.push_str(&format!(
            "<tr><td><code>{}</code></td><td>{}</td><td><span class=\"{}\">{}</span></td><td class=\"num\">{}</td><td class=\"num\">{}</td></tr>",
            escape_html(&control.control_id),
            escape_html(&result.title),
            status_css_class(result.status),
            escape_html(control_status_label(result.status)),
            result.severity,
            result.evidence_count
        ));
    }

    format!(
        "<h2>Trust Audit Matrix</h2><table class=\"matrix-table\"><thead><tr><th>control_id</th><th>title</th><th>status</th><th class=\"num\">severity</th><th class=\"num\">evidence_count</th></tr></thead><tbody>{}</tbody></table>",
        rows
    )
}

fn render_governance_controls_section(
    controls: &[LibraryControl],
    control_results: &BTreeMap<String, ControlResultManifest>,
) -> String {
    let baseline = filter_controls_by_tags(
        controls,
        &["policy", "baseline", "access", "identity", "encryption"],
    );
    let cadence = filter_controls_by_tags(
        controls,
        &["cadence", "review", "monitoring", "metrics", "audit"],
    );
    let registers = filter_controls_by_tags(
        controls,
        &["register", "risk", "asset", "vendor", "third_party"],
    );

    format!(
        "<h2>Governance & Controls</h2>{}{}{}",
        render_governance_subsection("Policies Baseline", &baseline, control_results),
        render_governance_subsection("Cadence", &cadence, control_results),
        render_governance_subsection("Registers", &registers, control_results)
    )
}

fn filter_controls_by_tags<'a>(
    controls: &'a [LibraryControl],
    tags: &[&str],
) -> Vec<&'a LibraryControl> {
    let tags_set: BTreeSet<String> = tags.iter().map(|tag| normalize_tag(tag)).collect();
    controls
        .iter()
        .filter(|control| {
            control
                .tags
                .iter()
                .any(|tag| tags_set.contains(&normalize_tag(tag)))
        })
        .collect()
}

fn render_governance_subsection(
    title: &str,
    controls: &[&LibraryControl],
    control_results: &BTreeMap<String, ControlResultManifest>,
) -> String {
    let mut items = String::new();

    if controls.is_empty() {
        return format!(
            "<section><h3>{}</h3><p>No controls mapped to this subsection.</p></section>",
            escape_html(title)
        );
    }

    for control in controls {
        let result = control_results
            .get(&control.control_id)
            .cloned()
            .unwrap_or_else(|| default_control_result(control));
        let preview = result
            .evidence_refs
            .first()
            .map(|ref_item| {
                format!(
                    "Evidence: <code>{}</code> {}-{}",
                    escape_html(&ref_item.rel_path),
                    ref_item.start_line,
                    ref_item.end_line
                )
            })
            .unwrap_or_else(|| "Evidence: none".to_string());

        items.push_str(&format!(
            "<li><strong>{}</strong> (<code>{}</code>) - <span class=\"{}\">{}</span> - severity {} - {} </li>",
            escape_html(&control.title),
            escape_html(&control.control_id),
            status_css_class(result.status),
            escape_html(control_status_label(result.status)),
            result.severity,
            preview
        ));
    }

    format!(
        "<section><h3>{}</h3><ul>{}</ul></section>",
        escape_html(title),
        items
    )
}

fn render_query_log_section(query_log: &[QueryLogEntry]) -> String {
    if query_log.is_empty() {
        return "<h2>Query Log</h2><p class=\"muted\">No automated queries executed for this export.</p>"
            .to_string();
    }

    let mut rows = String::new();
    for entry in query_log {
        rows.push_str(&format!(
            "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td class=\"num\">{}</td></tr>",
            escape_html(&entry.query_id),
            escape_html(&entry.query_text),
            escape_html(&entry.tags.join(", ")),
            entry.hit_count
        ));
    }

    format!(
        "<h2>Query Log</h2><table class=\"query-table\"><thead><tr><th>query_id</th><th>query_text</th><th>tags</th><th class=\"num\">hits</th></tr></thead><tbody>{}</tbody></table>",
        rows
    )
}

fn render_evidence_refs(evidence_refs: &[EvidenceRef], max_items: usize) -> String {
    if evidence_refs.is_empty() {
        return "<p><em>No direct evidence hits.</em></p>".to_string();
    }

    let mut items = String::new();
    for evidence in evidence_refs.iter().take(max_items) {
        items.push_str(&format!(
            "<li><code>{}</code> lines {}-{} (rank {})<blockquote>{}</blockquote></li>",
            escape_html(&evidence.rel_path),
            evidence.start_line,
            evidence.end_line,
            evidence.rank,
            escape_html(&evidence.excerpt)
        ));
    }

    format!("<ul>{items}</ul>")
}

fn control_status_label(status: ControlStatus) -> &'static str {
    match status {
        ControlStatus::Met => "met",
        ControlStatus::Partial => "partial",
        ControlStatus::Gap => "gap",
    }
}

fn status_css_class(status: ControlStatus) -> &'static str {
    match status {
        ControlStatus::Met => "status-met",
        ControlStatus::Partial => "status-partial",
        ControlStatus::Gap => "status-gap",
    }
}

fn resolve_export_dir(args: &ExportArgs, pack_id: &str) -> PathBuf {
    if let Some(vault) = &args.in_vault {
        return vault.join(".aegis").join("exports").join(pack_id);
    }

    if let Some(out) = &args.out {
        return out
            .join(&args.client_id)
            .join(&args.engagement_id)
            .join(pack_id);
    }

    PathBuf::from("out")
}

fn resolve_cupola_import_path(pack: &Pack) -> Result<PathBuf> {
    if let Some(path) = &pack.cupola_import_path {
        return Ok(PathBuf::from(path));
    }

    if Path::new(CUPOLA_IMPORT_PATH).exists() {
        return Ok(PathBuf::from(CUPOLA_IMPORT_PATH));
    }

    bail!(
        "Cupola import missing. Run 'import-cupola <path>' or 'import-cupola-vault --vault <PATH> --q <STRING>' first."
    )
}

fn load_cupola_hits_len(path: Option<&str>) -> Result<usize> {
    let path = path.unwrap_or(CUPOLA_IMPORT_PATH);
    let cupola = load_cupola_search(Path::new(path)).with_context(|| {
        format!("Cupola import missing or invalid at {path}. Run an import command first.")
    })?;
    Ok(cupola.hits.len())
}

fn load_cupola_search(path: &Path) -> Result<CupolaSearch> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("Failed to read cupola import {}", path.display()))?;
    let (_, parsed) = parse_cupola_search(&raw, &path.display().to_string())?;
    Ok(parsed)
}

fn parse_cupola_search(raw: &str, source: &str) -> Result<(Value, CupolaSearch)> {
    let parsed: Value =
        serde_json::from_str(raw).with_context(|| format!("Invalid JSON in {source}"))?;
    validate_cupola_hits(&parsed)
        .map_err(|err| anyhow!("Invalid Cupola payload in {source}: {err}"))?;
    let typed: CupolaSearch = serde_json::from_value(parsed.clone())
        .with_context(|| format!("Cupola schema parse failed for {source}"))?;
    Ok((parsed, typed))
}

fn validate_pack_bindings(pack: &Pack, hits_len: usize) -> Result<()> {
    for (claim_id, claim) in &pack.claims {
        for (slot_id, hit_index) in &claim.bindings {
            if *hit_index >= hits_len {
                bail!(
                    "Claim '{}' slot '{}' references hit index {}, but only {} Cupola hits exist.",
                    claim_id,
                    slot_id,
                    hit_index,
                    hits_len
                );
            }
        }
    }
    Ok(())
}

fn collect_evidence_bindings(pack: &Pack, cupola: &CupolaSearch) -> Result<Vec<EvidenceBinding>> {
    let mut output = Vec::new();
    for (claim_id, claim) in &pack.claims {
        for (slot_id, hit_index) in &claim.bindings {
            let hit = cupola.hits.get(*hit_index).ok_or_else(|| {
                anyhow!(
                    "Claim '{}' slot '{}' references missing hit index {}.",
                    claim_id,
                    slot_id,
                    hit_index
                )
            })?;
            output.push(EvidenceBinding {
                claim_id: claim_id.clone(),
                slot_id: slot_id.clone(),
                hit_index: *hit_index,
                hit: hit.clone(),
            });
        }
    }
    Ok(output)
}

fn validate_cupola_hits(value: &Value) -> Result<()> {
    match value.get("hits") {
        Some(Value::Array(_)) => Ok(()),
        Some(_) => bail!("Cupola JSON must include top-level hits[] as an array"),
        None => bail!("Cupola JSON is missing top-level hits[]"),
    }
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
        bail!(
            "Unexpected pack_id '{}'; expected '{}'.",
            pack.pack_id,
            PACK_ID
        );
    }
    Ok(pack)
}

fn save_pack(pack: &Pack) -> Result<()> {
    write_json(Path::new(PACK_PATH), pack)
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

fn now_utc_rfc3339() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    let cwd = std::env::current_dir().context("Failed to resolve current directory")?;
    Ok(cwd.join(path))
}

fn default_run_output_root() -> PathBuf {
    let stamp = Utc::now().format("%Y%m%d-%H%M%S");
    std::env::temp_dir()
        .join("aegis")
        .join("runs")
        .join(format!("run-{stamp}"))
}

fn normalized_absolute_path(path: &Path) -> Result<PathBuf> {
    let absolute = absolute_path(path)?;
    Ok(normalize_lexical_path(&absolute))
}

fn normalize_lexical_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                let _ = normalized.pop();
            }
            _ => normalized.push(component.as_os_str()),
        }
    }
    normalized
}

fn is_within(child: &Path, parent: &Path) -> bool {
    let child_components = comparable_components(child);
    let parent_components = comparable_components(parent);
    !parent_components.is_empty()
        && child_components.len() >= parent_components.len()
        && child_components[..parent_components.len()] == parent_components[..]
}

fn comparable_components(path: &Path) -> Vec<String> {
    normalize_lexical_path(path)
        .components()
        .map(component_for_compare)
        .collect()
}

fn component_for_compare(component: Component<'_>) -> String {
    let token = match component {
        Component::Prefix(prefix) => prefix.as_os_str().to_string_lossy().into_owned(),
        Component::RootDir => std::path::MAIN_SEPARATOR.to_string(),
        Component::CurDir => ".".to_string(),
        Component::ParentDir => "..".to_string(),
        Component::Normal(part) => part.to_string_lossy().into_owned(),
    };
    if cfg!(windows) {
        token.to_ascii_lowercase()
    } else {
        token
    }
}

fn json_pretty(value: &impl Serialize) -> Result<String> {
    let content = serde_json::to_string_pretty(value).context("Failed to serialize JSON")?;
    Ok(format!("{content}\n"))
}

fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let digest = hasher.finalize();
    format!("{digest:x}")
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let content = json_pretty(value)?;
    write_string(path, &content)
}

fn write_string(path: &Path, content: &str) -> Result<()> {
    fs::write(path, content).with_context(|| format!("Failed to write {}", path.display()))
}

fn render_replay_md(vault_path: Option<&str>, cupola_manifest_path: &Path) -> String {
    let escaped_manifest = escape_powershell(&cupola_manifest_path.display().to_string());
    let escaped_repo = escape_powershell(DEFAULT_CUPOLA_REPO);

    match vault_path {
        Some(vault) => {
            let escaped_vault = escape_powershell(vault);
            format!(
                "# REPLAY\n\nGenerated at: {}\n\n```powershell\nSet-Location \"{}\"\n$vault = \"{}\"\n$manifest = \"{}\"\n\ncargo run -p cupola-cli -- freeze --vault $vault --out $manifest\ncargo run -p cupola-cli -- verify --vault $vault --manifest $manifest\ncargo run -p cupola-cli -- replay --vault $vault --manifest $manifest\n```\n",
                now_utc_rfc3339(),
                escaped_repo,
                escaped_vault,
                escaped_manifest
            )
        }
        None => format!(
            "# REPLAY\n\nGenerated at: {}\n\nVault path is unknown. Run `aegis run --vault <PATH> --intake <FILE>` (or `import-cupola-vault`) first to lock replay to a specific vault.\n\n```powershell\nSet-Location \"{}\"\n$vault = \"<VAULT_PATH_FROM_IMPORT>\"\n$manifest = \"{}\"\n\ncargo run -p cupola-cli -- freeze --vault $vault --out $manifest\ncargo run -p cupola-cli -- verify --vault $vault --manifest $manifest\ncargo run -p cupola-cli -- replay --vault $vault --manifest $manifest\n```\n",
            now_utc_rfc3339(),
            escaped_repo,
            escaped_manifest
        ),
    }
}

fn escape_powershell(input: &str) -> String {
    input.replace('`', "``").replace('"', "`\"")
}

fn escape_markdown_cell(input: &str) -> String {
    input.replace('|', "\\|").replace('\n', " ")
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_export_args() -> ExportArgs {
        ExportArgs {
            in_vault: None,
            out: None,
            client_id: "client".to_string(),
            engagement_id: "engagement".to_string(),
            pack_type: PackType::DdResponse,
            library_pack: LibraryPack::VendorSecurity,
            cupola_repo: PathBuf::from(DEFAULT_CUPOLA_REPO),
            data_dir: None,
        }
    }

    #[test]
    fn resolve_export_dir_for_out_includes_client_and_engagement() {
        let mut args = sample_export_args();
        args.out = Some(PathBuf::from("exports"));
        args.client_id = "acme".to_string();
        args.engagement_id = "q1".to_string();

        let resolved = resolve_export_dir(&args, PACK_ID);
        assert_eq!(
            resolved,
            PathBuf::from("exports")
                .join("acme")
                .join("q1")
                .join(PACK_ID)
        );
    }

    #[test]
    fn starter_library_packs_load() {
        let starter_packs = [
            LibraryPack::VendorSecurity,
            LibraryPack::Iso27001,
            LibraryPack::NistCsf,
        ];

        for library_pack in starter_packs {
            let data =
                load_library_pack_data_with_data_dir(None, library_pack).unwrap_or_else(|err| {
                    panic!("library {} failed to load: {err:#}", library_pack.slug())
                });
            assert!(!data.controls.is_empty());
            assert!(!data.queries.queries.is_empty());
            assert!(!data.rubric.rules.is_empty());
        }
    }

    #[test]
    #[cfg(windows)]
    fn is_within_true_for_child_under_parent() {
        assert!(is_within(
            Path::new(r"C:\vault\exports\acme\eng\PACK-001"),
            Path::new(r"C:\vault")
        ));
    }

    #[test]
    #[cfg(windows)]
    fn is_within_true_for_equal_paths() {
        assert!(is_within(Path::new(r"C:\vault"), Path::new(r"C:\vault")));
    }

    #[test]
    #[cfg(windows)]
    fn is_within_false_for_sibling() {
        assert!(!is_within(
            Path::new(r"C:\vault_sibling\exports"),
            Path::new(r"C:\vault")
        ));
    }

    #[test]
    #[cfg(windows)]
    fn is_within_false_for_different_drive() {
        assert!(!is_within(
            Path::new(r"D:\vault\exports"),
            Path::new(r"C:\vault")
        ));
    }

    #[test]
    #[cfg(windows)]
    fn is_within_handles_mixed_slashes_and_case() {
        assert!(is_within(
            Path::new(r"c:/VaUlT\Exports/Acme"),
            Path::new(r"C:\vault")
        ));
    }

    #[test]
    fn parse_cupola_search_requires_top_level_hits_array() {
        let bad = r#"{"schema_version":"x"}"#;
        let err = parse_cupola_search(bad, "test-input")
            .expect_err("parse should fail when hits[] is missing");
        assert!(err.to_string().contains("hits[]"));
    }

    #[test]
    fn trust_audit_render_includes_matrix_and_manifest_control_results() {
        let controls = vec![LibraryControl {
            control_id: "VS-001".to_string(),
            title: "Identity Platform Ownership".to_string(),
            description: "Own identity operations".to_string(),
            objective: "Own identity operations".to_string(),
            severity: 4,
            evidence_expectations: vec!["Policy and access logs".to_string()],
            tags: vec!["identity".to_string()],
        }];
        let queries = LibraryQueries {
            version: "2.0".to_string(),
            queries: vec![LibraryQuery {
                query_id: "VS-Q-001".to_string(),
                query_text: "identity provider policy".to_string(),
                tags: vec!["identity".to_string()],
                limit: 25,
                control_ids: vec!["VS-001".to_string()],
            }],
        };
        let rubric = LibraryRubric {
            version: "2.0".to_string(),
            rules: vec![RubricRule {
                tag: "identity".to_string(),
                min_hits_for_partial: 1,
                min_hits_for_met: 2,
            }],
            control_query_map: vec![ControlQueryMap {
                control_id: "VS-001".to_string(),
                query_ids: vec!["VS-Q-001".to_string()],
            }],
        };

        let mut control_results = BTreeMap::new();
        control_results.insert(
            "VS-001".to_string(),
            ControlResultManifest {
                title: "Identity Platform Ownership".to_string(),
                status: ControlStatus::Met,
                severity: 4,
                evidence_count: 2,
                evidence_refs: vec![EvidenceRef {
                    query_id: "VS-Q-001".to_string(),
                    rank: 1,
                    chunk_id: "chunk-1".to_string(),
                    rel_path: "policy.txt".to_string(),
                    start_line: 1,
                    end_line: 2,
                    excerpt: "TESTTOKEN123".to_string(),
                }],
            },
        );

        let intake = IntakeV1::new(
            "2026-02-16T00:00:00Z".to_string(),
            "client".to_string(),
            "engagement".to_string(),
            PackType::TrustAudit,
            LibraryPack::VendorSecurity,
        );

        let pack_meta = build_pack_meta(&intake, PACK_ID).expect("pack meta should build");
        let html = render_html(
            "abc123",
            &pack_meta,
            intake.pack_type,
            &controls,
            &queries,
            &rubric,
            &control_results,
            &[],
        );
        assert!(html.contains("Executive Summary"));
        assert!(html.contains("Full Controls Table"));
        assert!(html.contains("Gap Register"));
        assert!(html.contains("Evidence Appendix"));

        let manifest = AegisManifestV11 {
            schema_version: "aegis.manifest.v1.1".to_string(),
            generated_at: "2026-02-16T00:00:00Z".to_string(),
            pack_id: PACK_ID.to_string(),
            pack_sha256: "abc123".to_string(),
            pack_path: PACK_PATH.to_string(),
            cupola_import_path: CUPOLA_IMPORT_PATH.to_string(),
            pack_type: PackType::TrustAudit,
            library_pack: LibraryPack::VendorSecurity,
            pack_meta,
            claim_count: 0,
            intake,
            cupola: CupolaContextV11 {
                schema_version: None,
                generated_at: None,
                query: None,
                limit: None,
                vault_path: Some("E:\\CupolaCore\\_vault".to_string()),
                vault_id: None,
                tool: None,
                tool_version: Some("0.1.0".to_string()),
                hit_count: 0,
                cupola_manifest_path: Some("E:\\out\\Cupola.manifest.json".to_string()),
                hash_status: None,
                freeze_status: None,
                verify_status: None,
                replay_status: None,
            },
            query_log: vec![],
            control_results,
            evidence_bindings: vec![],
            quote_path: QUOTE_JSON.to_string(),
            quote_sha256: "q123".to_string(),
            data_share_checklist_path: DATA_SHARE_CHECKLIST_MD.to_string(),
            artifacts: vec![],
        };

        let manifest_json = serde_json::to_string(&manifest).expect("manifest should serialize");
        assert!(manifest_json.contains("control_results"));
        assert!(manifest_json.contains("trust_audit"));
    }

    #[test]
    fn compute_quote_rounds_to_nearest_250_and_applies_deposit() {
        let due_date = (Utc::now().date_naive() + chrono::Duration::days(1))
            .format("%Y-%m-%d")
            .to_string();

        let mut intake = IntakeV1::new(
            "2026-02-16T00:00:00Z".to_string(),
            "acme".to_string(),
            "eng42".to_string(),
            PackType::TrustAudit,
            LibraryPack::VendorSecurity,
        );
        intake.lane = IntakeLane::Investigation;
        intake.evidence_readiness = EvidenceReadiness::Chaotic;
        intake.scope_size = Some(IntakeScopeSize {
            systems: 4,
            repos: 4,
            repo_size_band: RepoSizeBand::OneTo10,
        });
        intake.deadlines = Some(IntakeDeadlines { due_date });

        let investigation_quote =
            compute_quote(&intake).expect("investigation quote should compute");
        assert_eq!(investigation_quote.total_price_gbp, 23_750);
        assert_eq!(investigation_quote.deposit_gbp, 750);

        intake.lane = IntakeLane::Standard;
        let standard_quote = compute_quote(&intake).expect("standard quote should compute");
        assert_eq!(standard_quote.deposit_gbp, 0);
    }

    #[test]
    fn quote_only_writes_schema_version_and_total() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time should be monotonic")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("aegis_quote_only_{stamp}"));
        let intake_path = root.join("intake.json");
        let out_root = root.join("out");
        fs::create_dir_all(&root).expect("should create temp test directory");

        let intake_doc = serde_json::json!({
            "schema_version": "aegis.intake.v1",
            "client_id": "acme",
            "engagement_id": "eng42",
            "pack_type": "trust_audit",
            "library_pack": "vendor_security",
            "lane": "investigation",
            "evidence_readiness": "chaotic",
            "scope_size": {
                "systems": 3,
                "repos": 2,
                "repo_size_band": "1-10GB"
            }
        });
        fs::write(
            &intake_path,
            serde_json::to_string_pretty(&intake_doc).expect("intake should serialize"),
        )
        .expect("should write temporary intake file");

        cmd_quote(QuoteArgs {
            intake: intake_path,
            out: Some(out_root.clone()),
            print: false,
        })
        .expect("quote command should succeed");

        let quote_path = out_root
            .join("acme")
            .join("eng42")
            .join(PACK_ID)
            .join(QUOTE_JSON);
        let quote_raw = fs::read_to_string(&quote_path).expect("quote json should exist");
        let quote: serde_json::Value =
            serde_json::from_str(&quote_raw).expect("quote json should parse");
        assert_eq!(quote["schema_version"], "aegis.quote.v1");
        assert_eq!(quote["total_price_gbp"], 11_750);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn run_smoke_with_temp_intake_writes_manifest_fields() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time should be monotonic")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("aegis_run_smoke_{stamp}"));
        let intake_path = root.join("intake.json");
        let out_root = root.join("out");
        fs::create_dir_all(&root).expect("should create temp test directory");

        let intake_doc = serde_json::json!({
            "schema_version": "aegis.intake.v1",
            "client_id": "acme",
            "engagement_id": "eng42",
            "pack_type": "trust_audit",
            "library_pack": "vendor_security",
            "output_mode": "out_dir",
            "scope": {
                "in_scope": "Vendor security review",
                "out_of_scope": "Penetration testing"
            },
            "claims": {
                "C-001": true
            },
            "deadlines": {
                "due_date": "2026-12-31"
            }
        });
        fs::write(
            &intake_path,
            serde_json::to_string_pretty(&intake_doc).expect("intake should serialize"),
        )
        .expect("should write temporary intake file");

        let query_log = vec![QueryLogEntry {
            query_id: "VS-Q-001".to_string(),
            query_text: "single sign-on SSO identity provider".to_string(),
            tags: vec!["identity".to_string()],
            limit: 5,
            hit_count: 1,
            evidence_refs: vec![EvidenceRef {
                query_id: "VS-Q-001".to_string(),
                rank: 1,
                chunk_id: "chunk-1".to_string(),
                rel_path: "notes.md".to_string(),
                start_line: 1,
                end_line: 2,
                excerpt: "TESTTOKEN123".to_string(),
            }],
        }];
        let mut control_results = BTreeMap::new();
        control_results.insert(
            "VS-001".to_string(),
            ControlResultManifest {
                title: "Identity Platform Ownership".to_string(),
                status: ControlStatus::Met,
                severity: 4,
                evidence_count: 1,
                evidence_refs: vec![EvidenceRef {
                    query_id: "VS-Q-001".to_string(),
                    rank: 1,
                    chunk_id: "chunk-1".to_string(),
                    rel_path: "notes.md".to_string(),
                    start_line: 1,
                    end_line: 2,
                    excerpt: "TESTTOKEN123".to_string(),
                }],
            },
        );
        let cupola_search = CupolaSearch {
            schema_version: Some("1.0.0".to_string()),
            tool: Some(CupolaTool {
                name: Some("cupola-cli".to_string()),
                version: Some("0.1.0".to_string()),
                build: Some("debug".to_string()),
                platform: Some("windows-x64".to_string()),
            }),
            generated_at: Some("2026-02-16T00:00:00Z".to_string()),
            vault: Some(CupolaVault {
                vault_path: Some("E:\\CupolaCore\\_vault_aegis_glue".to_string()),
                vault_id: None,
            }),
            query: Some("TESTTOKEN123".to_string()),
            limit: Some(5),
            hits: vec![CupolaHit {
                chunk_id: "chunk-1".to_string(),
                rel_path: "notes.md".to_string(),
                file_type: "md".to_string(),
                mtime_ns: serde_json::json!(0),
                raw_blob_id: "raw-1".to_string(),
                chunk_blob_id: "chunk-blob-1".to_string(),
                start_line: 1,
                end_line: 2,
                excerpt: "TESTTOKEN123".to_string(),
            }],
        };
        let overrides = RunCommandOverrides {
            auto_evaluation: AutoEvaluation {
                query_log,
                control_results,
                first_search: Some(cupola_search.clone()),
            },
            cupola_search,
        };
        let args = RunArgs {
            vault: PathBuf::from(r"E:\CupolaCore\_vault_aegis_glue"),
            cupola_repo: PathBuf::from(DEFAULT_CUPOLA_REPO),
            intake: intake_path.clone(),
            in_vault: None,
            out: Some(out_root.clone()),
            data_dir: None,
        };

        cmd_run_inner(args, Some(overrides)).expect("run should succeed with test overrides");

        let manifest_path = out_root
            .join("acme")
            .join("eng42")
            .join(PACK_ID)
            .join(DECISION_PACK_MANIFEST);
        let manifest_raw = fs::read_to_string(&manifest_path).expect("manifest should exist");
        let manifest: serde_json::Value =
            serde_json::from_str(&manifest_raw).expect("manifest should be valid JSON");

        assert_eq!(manifest["pack_type"], "trust_audit");
        assert_eq!(manifest["library_pack"], "vendor_security");
        assert_eq!(manifest["pack_meta"]["pack_type"], "trust_audit");
        assert_eq!(manifest["pack_meta"]["library"], "vendor_security");
        assert_eq!(manifest["pack_meta"]["client"], "acme");
        assert_eq!(manifest["pack_meta"]["engagement"], "eng42");
        assert!(manifest["query_log"]
            .as_array()
            .is_some_and(|entries| !entries.is_empty()));
        assert!(manifest["control_results"]
            .as_object()
            .is_some_and(|entries| !entries.is_empty()));
        assert_eq!(manifest["quote_path"], QUOTE_JSON);
        assert_eq!(
            manifest["data_share_checklist_path"],
            DATA_SHARE_CHECKLIST_MD
        );

        let quote_path = out_root
            .join("acme")
            .join("eng42")
            .join(PACK_ID)
            .join(QUOTE_JSON);
        let quote_raw = fs::read_to_string(&quote_path).expect("quote should exist");
        let quote: serde_json::Value =
            serde_json::from_str(&quote_raw).expect("quote should parse");
        assert_eq!(quote["schema_version"], "aegis.quote.v1");

        let _ = fs::remove_dir_all(&root);
    }
}
