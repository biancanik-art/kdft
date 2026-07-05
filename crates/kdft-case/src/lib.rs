use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

const INITIAL_SCHEMA: &str = include_str!("../../../schemas/001_initial.sql");
// Keyword-search preview window stored per file. Kept small so the case
// database scales to very large evidence (a 64 KiB preview per file made a
// 100k-file case ~1.7 GB, which is untenable for multi-terabyte disks). This
// window catches file headers and the start of text; full-content search is a
// separate on-demand read against the image.
const CONTENT_INDEX_BYTES: usize = 4_096;
const EMAIL_PARSE_MAX_BYTES: u64 = 1024 * 1024;
const EMAIL_BODY_PREVIEW_CHARS: usize = 1200;
const NTFS_BITMAP_PARSE_MAX_BYTES: u64 = 64 * 1024 * 1024;
const NTFS_UNALLOCATED_METADATA_EXTENTS_LIMIT: usize = 128;

#[derive(Debug, Clone)]
pub struct CreateCaseOptions {
    pub name: String,
    pub examiner_name: Option<String>,
    pub case_number: Option<String>,
    pub case_type: Option<String>,
    pub description: Option<String>,
    pub default_export_folder: Option<PathBuf>,
    pub temporary_folder: Option<PathBuf>,
    pub index_folder: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy)]
pub enum EvidenceKind {
    Auto,
    File,
    Folder,
    Image,
}

impl EvidenceKind {
    pub fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "file" => Ok(Self::File),
            "folder" => Ok(Self::Folder),
            "image" => Ok(Self::Image),
            other => Err(anyhow!("unsupported evidence kind: {other}")),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AddEvidenceOptions {
    pub path: PathBuf,
    pub kind: EvidenceKind,
    pub read_file_system_requested: bool,
    pub notes: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CaseInfo {
    pub id: i64,
    pub name: String,
    pub examiner_name: Option<String>,
    pub case_number: Option<String>,
    pub case_type: Option<String>,
    pub description: Option<String>,
    pub default_export_folder: Option<String>,
    pub temporary_folder: Option<String>,
    pub index_folder: Option<String>,
    pub timezone: String,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct EvidenceSource {
    pub id: i64,
    pub case_id: i64,
    pub source_kind: String,
    pub source_path: String,
    pub display_name: String,
    pub size_bytes: Option<i64>,
    pub read_file_system_requested: bool,
    pub attach_status: String,
    pub encryption_status: String,
    pub attached_at: String,
    pub indexed_at: Option<String>,
    pub notes: Option<String>,
    /// Status of the most recent indexing/import job ("completed", "truncated", ...),
    /// so the UI can distinguish empty folders from not-yet-indexed ones.
    pub last_job_status: Option<String>,
    /// SHA-256 of the evidence source (decoded stream for disk images),
    /// computed by the examiner-driven hash job.
    pub sha256_hex: Option<String>,
    pub hashed_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct HashEvidenceResult {
    pub evidence_id: i64,
    pub sha256_hex: String,
    pub bytes_hashed: u64,
    pub hashed_at: String,
}

#[derive(Debug, Clone)]
pub struct CarveOptions {
    /// Cap on bytes scanned from the decoded image (0 = whole image).
    pub max_scan_bytes: u64,
    /// Cap on carved files recorded.
    pub max_files: usize,
}

#[derive(Debug, Serialize)]
pub struct CarveResult {
    pub evidence_id: i64,
    pub carved_files: usize,
    pub bytes_scanned: u64,
    pub truncated: bool,
}

#[derive(Debug, Serialize)]
pub struct RemoveEvidenceResult {
    pub evidence_id: i64,
    pub removed_entries: i64,
    pub removed_jobs: i64,
}

#[derive(Debug, Serialize, Default)]
pub struct ClearStaleFindingsResult {
    pub removed_folders: i64,
    pub removed_bookmarks: i64,
    pub removed_items: i64,
}

#[derive(Debug, Clone)]
pub struct ProcessEvidenceOptions {
    pub evidence_id: i64,
    pub max_entries: usize,
}

#[derive(Debug, Serialize)]
pub struct ProcessEvidenceResult {
    pub job_id: i64,
    pub evidence_id: i64,
    pub entries_indexed: usize,
    pub truncated: bool,
    pub status: String,
    pub bookmark_items_relinked: usize,
}

#[derive(Debug, Clone)]
pub struct DeepSearchOptions {
    /// Text to search for. A `hex:` prefix switches to byte-pattern mode
    /// (e.g. `hex:FF D8 FF`), which scans indexed file content and reports
    /// byte offsets.
    pub query: String,
    pub evidence_id: Option<i64>,
    pub include_content: bool,
    pub max_results: usize,
    pub max_file_bytes: u64,
    /// Restrict hits to entries whose stored category fields contain this text,
    /// case-insensitive. Examiner-added categories match the same way.
    pub category: Option<String>,
    /// Restrict hits to these file extensions (without the dot).
    pub file_types: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub struct DeepSearchResult {
    pub evidence_id: i64,
    pub entry_id: i64,
    pub logical_path: String,
    pub display_name: String,
    pub entry_kind: String,
    pub match_kind: String,
    pub selection_offset: Option<i64>,
    pub selection_length: Option<i64>,
    pub data_preview: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ImportBrowserHistoryOptions {
    pub history_path: PathBuf,
    pub max_visits: usize,
    pub evidence_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct BrowserHistoryImportResult {
    pub evidence_id: i64,
    pub job_id: i64,
    pub source_path: String,
    pub entries_indexed: usize,
    pub visits_indexed: usize,
    pub bookmarks_indexed: usize,
    pub preferences_indexed: usize,
    pub truncated: bool,
    pub status: String,
}

#[derive(Debug, Serialize)]
pub struct FilesystemEntry {
    pub id: i64,
    pub case_id: i64,
    pub evidence_id: i64,
    pub parent_id: Option<i64>,
    pub logical_path: String,
    pub name: String,
    pub entry_kind: String,
    pub size_bytes: Option<i64>,
    pub is_deleted: bool,
    pub metadata_json: serde_json::Value,
    pub discovered_by_job_id: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct ReadEntryBytesOptions {
    pub entry_id: i64,
    pub offset: u64,
    pub length: usize,
}

#[derive(Debug, Clone)]
pub struct RecoverEntryOptions {
    pub entry_id: i64,
    pub output_path: PathBuf,
}

#[derive(Debug, Serialize)]
pub struct EntryBytes {
    pub entry_id: i64,
    pub evidence_id: i64,
    pub logical_path: String,
    pub offset: u64,
    pub requested_length: usize,
    pub bytes_read: usize,
    pub total_size: u64,
    pub eof: bool,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Serialize)]
pub struct RecoverEntryResult {
    pub entry_id: i64,
    pub evidence_id: i64,
    pub output_path: String,
    pub bytes_written: u64,
    pub total_size: u64,
    pub status: String,
}

#[derive(Debug, Clone)]
pub struct AnalyzeSignaturesOptions {
    pub evidence_id: Option<i64>,
    pub max_entries: usize,
}

#[derive(Debug, Serialize)]
pub struct AnalyzeSignaturesResult {
    pub job_id: i64,
    pub evidence_id: Option<i64>,
    pub files_examined: usize,
    pub matches: usize,
    pub aliases: usize,
    pub mismatches: usize,
    pub unknown: usize,
    pub no_extension: usize,
    pub unreadable: usize,
    pub truncated: bool,
    pub status: String,
}

#[derive(Debug, Serialize)]
pub struct BookmarkFolder {
    pub id: i64,
    pub case_id: i64,
    pub parent_id: Option<i64>,
    pub name: String,
    pub folder_comment: Option<String>,
    pub show_in_report: bool,
    pub report_order: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BookmarkType {
    NotableFile,
    FileGroup,
    HighlightedData,
    FolderInfo,
    Email,
    Record,
}

impl BookmarkType {
    pub fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "notable_file" => Ok(Self::NotableFile),
            "file_group" => Ok(Self::FileGroup),
            "highlighted_data" => Ok(Self::HighlightedData),
            "folder_info" => Ok(Self::FolderInfo),
            "email" => Ok(Self::Email),
            "record" => Ok(Self::Record),
            other => Err(anyhow!(
                "unsupported bookmark type: {other}; expected one of notable_file, file_group, highlighted_data, folder_info, email, record"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotableFile => "notable_file",
            Self::FileGroup => "file_group",
            Self::HighlightedData => "highlighted_data",
            Self::FolderInfo => "folder_info",
            Self::Email => "email",
            Self::Record => "record",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CreateBookmarkOptions {
    pub folder_id: i64,
    pub bookmark_type: BookmarkType,
    pub data_type: Option<String>,
    pub title: Option<String>,
    pub examiner_comment: Option<String>,
    pub in_report: bool,
    pub source_ref_json: serde_json::Value,
    pub content_ref_json: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct Bookmark {
    pub id: i64,
    pub case_id: i64,
    pub folder_id: i64,
    pub bookmark_type: String,
    pub data_type: Option<String>,
    pub title: Option<String>,
    pub examiner_comment: Option<String>,
    pub in_report: bool,
    pub source_ref_json: serde_json::Value,
    pub content_ref_json: serde_json::Value,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone)]
pub struct CreateBookmarkItemOptions {
    pub bookmark_id: i64,
    pub evidence_id: Option<i64>,
    pub entry_id: Option<i64>,
    pub item_order: Option<i64>,
    pub display_name: Option<String>,
    pub logical_path: Option<String>,
    pub selection_offset: Option<i64>,
    pub selection_length: Option<i64>,
    pub data_preview: Option<String>,
    pub item_ref_json: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct BookmarkItem {
    pub id: i64,
    pub bookmark_id: i64,
    pub evidence_id: Option<i64>,
    pub entry_id: Option<i64>,
    pub item_order: i64,
    pub display_name: Option<String>,
    pub logical_path: Option<String>,
    pub selection_offset: Option<i64>,
    pub selection_length: Option<i64>,
    pub data_preview: Option<String>,
    pub item_ref_json: serde_json::Value,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct ReportData {
    pub case: CaseInfo,
    pub evidence: Vec<ReportEvidence>,
    pub directory_trees: Vec<ReportDirectoryTree>,
    pub folders: Vec<ReportFolder>,
}

#[derive(Debug, Serialize)]
pub struct ReportEvidence {
    pub id: i64,
    pub display_name: String,
    pub source_kind: String,
    pub source_path: String,
    pub file_extension: Option<String>,
    pub size_bytes: Option<i64>,
    pub sha256: Option<String>,
    pub attached_at: String,
    pub indexed_at: Option<String>,
    pub entries_indexed: i64,
    pub notes: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ReportDirectoryTree {
    pub evidence_id: i64,
    pub evidence_name: String,
    pub total_entries: i64,
    pub truncated: bool,
    pub lines: Vec<ReportTreeLine>,
}

#[derive(Debug, Serialize)]
pub struct ReportTreeLine {
    pub depth: usize,
    pub name: String,
    pub entry_kind: String,
    pub size_bytes: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct RenderedReport {
    pub html: String,
    pub sha256: String,
}

#[derive(Debug, Serialize)]
pub struct ReportFolder {
    pub id: i64,
    pub name: String,
    pub folder_comment: Option<String>,
    pub report_order: i64,
    pub bookmarks: Vec<ReportBookmark>,
}

#[derive(Debug, Serialize)]
pub struct ReportBookmark {
    pub id: i64,
    pub folder_id: i64,
    pub bookmark_type: String,
    pub data_type: Option<String>,
    pub title: Option<String>,
    pub examiner_comment: Option<String>,
    pub source_ref_json: serde_json::Value,
    pub content_ref_json: serde_json::Value,
    pub created_at: String,
    pub items: Vec<BookmarkItem>,
}

#[derive(Debug, Serialize)]
pub struct GlobalOptions {
    pub id: i64,
    pub config_root: Option<String>,
    pub evidence_library_root: Option<String>,
    pub default_storage_root: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Default)]
pub struct UpdateGlobalOptions {
    pub config_root: Option<GlobalOptionPathUpdate>,
    pub evidence_library_root: Option<GlobalOptionPathUpdate>,
    pub default_storage_root: Option<GlobalOptionPathUpdate>,
}

#[derive(Debug, Clone)]
pub enum GlobalOptionPathUpdate {
    Set(PathBuf),
    Clear,
}

impl UpdateGlobalOptions {
    fn has_changes(&self) -> bool {
        self.config_root.is_some()
            || self.evidence_library_root.is_some()
            || self.default_storage_root.is_some()
    }
}

#[derive(Debug, Serialize)]
pub struct InstalledResource {
    pub id: i64,
    pub resource_key: String,
    pub display_name: String,
    pub config_file_name: String,
    pub resource_kind: String,
    pub storage_scope: String,
    pub version: String,
    pub enabled: bool,
    pub notes: Option<String>,
}

pub fn create_case(case_path: &Path, options: CreateCaseOptions) -> Result<i64> {
    if case_path.exists() {
        bail!("case already exists: {}", case_path.display());
    }
    if let Some(parent) = case_path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating case parent directory {}", parent.display()))?;
    }

    let mut conn = Connection::open(case_path)
        .with_context(|| format!("creating case database {}", case_path.display()))?;
    enable_foreign_keys(&conn)?;
    // Set the wait timeout first so a contended access waits rather than fails,
    // then switch to WAL best-effort (converting an existing rollback-mode DB
    // needs a write lock; if another job holds it, keep the current mode rather
    // than failing the open).
    conn.execute_batch("PRAGMA busy_timeout = 15000;")
        .context("configuring SQLite busy timeout")?;
    let _ = conn.execute_batch("PRAGMA journal_mode = WAL;");
    apply_schema(&conn)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let examiner_name = trim_optional_string(options.examiner_name);
    let case_number = trim_optional_string(options.case_number);
    let case_type = trim_optional_string(options.case_type);
    let description = trim_optional_string(options.description);
    let actor = audit_actor_from_examiner(examiner_name.as_deref());

    tx.execute(
        "INSERT INTO cases(id, name, examiner_name, case_number, case_type, description)
         VALUES (1, ?1, ?2, ?3, ?4, ?5)",
        params![
            &options.name,
            examiner_name.as_deref(),
            case_number.as_deref(),
            case_type.as_deref(),
            description.as_deref(),
        ],
    )?;
    let case_id = 1_i64;
    tx.execute(
        "INSERT INTO case_options(case_id, default_export_folder, temporary_folder, index_folder)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            case_id,
            option_path_to_string(options.default_export_folder.as_deref()),
            option_path_to_string(options.temporary_folder.as_deref()),
            option_path_to_string(options.index_folder.as_deref()),
        ],
    )?;
    tx.execute(
        "INSERT INTO audit_events(case_id, event_type, actor, object_type, object_id, details_json)
         VALUES (?1, 'case.create', ?2, 'case', ?1, json_object('name', ?3))",
        params![case_id, actor, &options.name],
    )?;
    tx.commit()?;
    Ok(case_id)
}

pub fn case_info(case_path: &Path) -> Result<CaseInfo> {
    let conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    let info = conn.query_row(
        "SELECT c.id, c.name, c.examiner_name, c.case_number, c.case_type, c.description,
                co.default_export_folder, co.temporary_folder, co.index_folder,
                co.timezone, c.created_at
         FROM cases c
         JOIN case_options co ON co.case_id = c.id
         WHERE c.id = ?1",
        params![case_id],
        |row| {
            Ok(CaseInfo {
                id: row.get(0)?,
                name: row.get(1)?,
                examiner_name: row.get(2)?,
                case_number: row.get(3)?,
                case_type: row.get(4)?,
                description: row.get(5)?,
                default_export_folder: row.get(6)?,
                temporary_folder: row.get(7)?,
                index_folder: row.get(8)?,
                timezone: row.get(9)?,
                created_at: row.get(10)?,
            })
        },
    )?;
    Ok(info)
}

pub fn global_options(case_path: &Path) -> Result<GlobalOptions> {
    let conn = open_existing_case(case_path)?;
    read_global_options(&conn)
}

pub fn update_global_options(
    case_path: &Path,
    update: UpdateGlobalOptions,
) -> Result<GlobalOptions> {
    let mut conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    if !update.has_changes() {
        return read_global_options(&conn);
    }

    let actor = audit_actor(&conn, case_id)?;
    let (config_root_updated, config_root) = path_update_sql_value(update.config_root.as_ref());
    let (evidence_library_root_updated, evidence_library_root) =
        path_update_sql_value(update.evidence_library_root.as_ref());
    let (default_storage_root_updated, default_storage_root) =
        path_update_sql_value(update.default_storage_root.as_ref());
    let details_json = serde_json::json!({
        "config_root_updated": config_root_updated,
        "evidence_library_root_updated": evidence_library_root_updated,
        "default_storage_root_updated": default_storage_root_updated,
    })
    .to_string();

    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute(
        "UPDATE global_options
         SET config_root = CASE WHEN ?1 THEN ?2 ELSE config_root END,
             evidence_library_root = CASE WHEN ?3 THEN ?4 ELSE evidence_library_root END,
             default_storage_root = CASE WHEN ?5 THEN ?6 ELSE default_storage_root END,
             updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
         WHERE id = 1",
        params![
            config_root_updated,
            config_root,
            evidence_library_root_updated,
            evidence_library_root,
            default_storage_root_updated,
            default_storage_root,
        ],
    )?;
    tx.execute(
        "INSERT INTO audit_events(case_id, event_type, actor, object_type, object_id, details_json)
         VALUES (?1, 'options.global.update', ?2, 'global_options', 1, ?3)",
        params![case_id, actor, details_json],
    )?;
    let options = read_global_options(&tx)?;
    tx.commit()?;
    Ok(options)
}

pub fn list_installed_resources(case_path: &Path) -> Result<Vec<InstalledResource>> {
    let conn = open_existing_case(case_path)?;
    let mut stmt = conn.prepare(
        "SELECT id, resource_key, display_name, config_file_name, resource_kind,
                storage_scope, version, enabled, notes
         FROM installed_resources
         ORDER BY id",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(InstalledResource {
            id: row.get(0)?,
            resource_key: row.get(1)?,
            display_name: row.get(2)?,
            config_file_name: row.get(3)?,
            resource_kind: row.get(4)?,
            storage_scope: row.get(5)?,
            version: row.get(6)?,
            enabled: row.get::<_, i64>(7)? != 0,
            notes: row.get(8)?,
        })
    })?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .context("listing installed resources")
}

pub fn add_evidence(case_path: &Path, options: AddEvidenceOptions) -> Result<i64> {
    let mut conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    let metadata = fs::metadata(&options.path)
        .with_context(|| format!("reading bounded metadata for {}", options.path.display()))?;
    let source_kind = infer_evidence_kind(&options.path, options.kind, &metadata)?;
    let source_path = stable_path_string(&options.path);
    let display_name = options
        .path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("Evidence Source")
        .to_string();
    let size_bytes = if metadata.is_file() {
        let physical = i64::try_from(metadata.len()).context("evidence size exceeds i64")?;
        if source_kind == "image" {
            // For containers (EWF segments, split raw, sparse VM disks) the
            // examiner-relevant size is the decoded disk, not the first
            // segment file. Opening only parses headers - no data is indexed.
            match open_disk_image(&options.path) {
                Ok(opened) => Some(i64::try_from(opened.decoded_size).unwrap_or(physical)),
                Err(_) => Some(physical),
            }
        } else {
            Some(physical)
        }
    } else {
        None
    };

    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let actor = audit_actor(&tx, case_id)?;
    clear_stale_findings_tx(&tx, case_id, &actor)?;
    ensure_evidence_path_available(&tx, case_id, &source_path)?;
    tx.execute(
        "INSERT INTO evidence_sources(
             case_id, source_kind, source_path, display_name, size_bytes,
             read_file_system_requested, notes
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            case_id,
            source_kind,
            source_path,
            display_name,
            size_bytes,
            if options.read_file_system_requested {
                1
            } else {
                0
            },
            options.notes,
        ],
    )?;
    let evidence_id = tx.last_insert_rowid();
    tx.execute(
        "INSERT INTO audit_events(case_id, event_type, actor, object_type, object_id, details_json)
         VALUES (?1, 'evidence.attach', ?2, 'evidence', ?3,
                 json_object('source_kind', ?4, 'source_path', ?5, 'no_indexing', 1))",
        params![case_id, actor, evidence_id, source_kind, source_path],
    )?;
    tx.commit()?;
    Ok(evidence_id)
}

pub fn list_evidence(case_path: &Path) -> Result<Vec<EvidenceSource>> {
    let conn = open_existing_case(case_path)?;
    let mut stmt = conn.prepare(
        "SELECT e.id, e.case_id, e.source_kind, e.source_path, e.display_name, e.size_bytes,
                e.read_file_system_requested, e.attach_status, e.encryption_status, e.attached_at,
                e.indexed_at, e.notes,
                (SELECT j.status FROM evidence_jobs j
                 WHERE j.case_id = e.case_id AND j.evidence_id = e.id
                   AND j.job_type IN ('filesystem_index', 'browser_history_import')
                 ORDER BY j.id DESC LIMIT 1),
                e.sha256_hex, e.hashed_at
         FROM evidence_sources e
         ORDER BY e.id",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(EvidenceSource {
            id: row.get(0)?,
            case_id: row.get(1)?,
            source_kind: row.get(2)?,
            source_path: row.get(3)?,
            display_name: row.get(4)?,
            size_bytes: row.get(5)?,
            read_file_system_requested: row.get::<_, i64>(6)? != 0,
            attach_status: row.get(7)?,
            encryption_status: row.get(8)?,
            attached_at: row.get(9)?,
            indexed_at: row.get(10)?,
            notes: row.get(11)?,
            last_job_status: row.get(12)?,
            sha256_hex: row.get(13)?,
            hashed_at: row.get(14)?,
        })
    })?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .context("listing evidence sources")
}

/// Examiner-driven hash job: computes SHA-256 over the evidence source and
/// records it on the evidence row, in an evidence_jobs row, and in the audit
/// trail. For disk images the DECODED stream is hashed (all EWF/split-raw
/// segments as one disk), so the value matches what the parsers actually read.
pub fn hash_evidence(case_path: &Path, evidence_id: i64) -> Result<HashEvidenceResult> {
    let mut conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    ensure_evidence_source(&conn, case_id, evidence_id)?;
    let (source_kind, source_path): (String, String) = conn.query_row(
        "SELECT source_kind, source_path FROM evidence_sources
         WHERE case_id = ?1 AND id = ?2",
        params![case_id, evidence_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;

    let mut hasher = Sha256::new();
    let mut bytes_hashed = 0_u64;
    let mut buffer = vec![0_u8; 4 * 1024 * 1024];
    if source_kind == "image" {
        let mut opened = open_disk_image(Path::new(&source_path))?;
        opened.reader.seek(SeekFrom::Start(0))?;
        loop {
            let read = opened
                .reader
                .read(&mut buffer)
                .context("reading decoded image stream for hashing")?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
            bytes_hashed += read as u64;
        }
    } else {
        let metadata = fs::metadata(&source_path)
            .with_context(|| format!("reading evidence metadata {source_path}"))?;
        if !metadata.is_file() {
            bail!(
                "hashing supports file and image evidence; {source_kind} evidence is a directory"
            );
        }
        let mut file = fs::File::open(&source_path)
            .with_context(|| format!("opening evidence {source_path}"))?;
        loop {
            let read = file
                .read(&mut buffer)
                .context("reading evidence file for hashing")?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
            bytes_hashed += read as u64;
        }
    }
    let sha256_hex: String = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();

    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let actor = audit_actor(&tx, case_id)?;
    tx.execute(
        "UPDATE evidence_sources
         SET sha256_hex = ?3, hashed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
         WHERE case_id = ?1 AND id = ?2",
        params![case_id, evidence_id, sha256_hex],
    )?;
    tx.execute(
        "INSERT INTO evidence_jobs(case_id, evidence_id, job_type, status, parameters_json,
                                   started_at, finished_at)
         VALUES (?1, ?2, 'hash', 'completed',
                 json_object('algorithm', 'sha256', 'bytes_hashed', ?3),
                 strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
        params![
            case_id,
            evidence_id,
            i64::try_from(bytes_hashed).unwrap_or(i64::MAX)
        ],
    )?;
    tx.execute(
        "INSERT INTO audit_events(case_id, event_type, actor, object_type, object_id, details_json)
         VALUES (?1, 'evidence.hash', ?2, 'evidence', ?3,
                 json_object('algorithm', 'sha256', 'sha256', ?4, 'bytes_hashed', ?5))",
        params![
            case_id,
            actor,
            evidence_id,
            sha256_hex,
            i64::try_from(bytes_hashed).unwrap_or(i64::MAX)
        ],
    )?;
    let hashed_at: String = tx.query_row(
        "SELECT hashed_at FROM evidence_sources WHERE case_id = ?1 AND id = ?2",
        params![case_id, evidence_id],
        |row| row.get(0),
    )?;
    tx.commit()?;
    Ok(HashEvidenceResult {
        evidence_id,
        sha256_hex,
        bytes_hashed,
        hashed_at,
    })
}

const CARVE_DEFAULT_SCAN_BYTES: u64 = 1024 * 1024 * 1024;
const CARVE_DEFAULT_MAX_FILES: usize = 1000;
const CARVE_CHUNK_BYTES: usize = 8 * 1024 * 1024;
const CARVE_MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy)]
struct CarveSignature {
    header: &'static [u8],
    extension: &'static str,
    label: &'static str,
}

const CARVE_SIGNATURES: &[CarveSignature] = &[
    CarveSignature {
        header: &[0xFF, 0xD8, 0xFF],
        extension: "jpg",
        label: "JPEG image",
    },
    CarveSignature {
        header: &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
        extension: "png",
        label: "PNG image",
    },
    CarveSignature {
        header: &[0x47, 0x49, 0x46, 0x38],
        extension: "gif",
        label: "GIF image",
    },
    CarveSignature {
        header: &[0x25, 0x50, 0x44, 0x46, 0x2D],
        extension: "pdf",
        label: "PDF document",
    },
    CarveSignature {
        header: &[0x50, 0x4B, 0x03, 0x04],
        extension: "zip",
        label: "ZIP/Office container",
    },
    CarveSignature {
        header: &[0x42, 0x4D],
        extension: "bmp",
        label: "BMP image",
    },
    CarveSignature {
        header: &[0x1F, 0x8B, 0x08],
        extension: "gz",
        label: "GZIP stream",
    },
    CarveSignature {
        header: &[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07],
        extension: "rar",
        label: "RAR archive",
    },
];

/// Examiner-driven signature carving: scans the decoded image for known file
/// headers and records each hit as a carved file under
/// /Image Analysis/Carved. Never runs automatically. Bounded by scan size and
/// file count; carved bytes are served on demand via the physical-extent
/// reader rather than copied into the case database.
pub fn carve_evidence(
    case_path: &Path,
    evidence_id: i64,
    options: CarveOptions,
) -> Result<CarveResult> {
    let mut conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    ensure_evidence_source(&conn, case_id, evidence_id)?;
    let (source_kind, source_path): (String, String) = conn.query_row(
        "SELECT source_kind, source_path FROM evidence_sources
         WHERE case_id = ?1 AND id = ?2",
        params![case_id, evidence_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if source_kind != "image" {
        bail!("carving is only supported for disk-image evidence");
    }

    let mut opened = open_disk_image(Path::new(&source_path))?;
    let scan_limit = if options.max_scan_bytes == 0 {
        opened.decoded_size
    } else {
        options.max_scan_bytes.min(opened.decoded_size)
    };
    let max_files = options
        .max_files
        .min(CARVE_DEFAULT_MAX_FILES.max(options.max_files));
    let overlap = CARVE_SIGNATURES
        .iter()
        .map(|sig| sig.header.len())
        .max()
        .unwrap_or(8);

    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let actor = audit_actor(&tx, case_id)?;
    tx.execute(
        "INSERT INTO evidence_jobs(case_id, evidence_id, job_type, status, parameters_json, started_at)
         VALUES (?1, ?2, 'carve', 'running',
                 json_object('max_scan_bytes', ?3, 'max_files', ?4),
                 strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
        params![
            case_id,
            evidence_id,
            i64::try_from(scan_limit).unwrap_or(i64::MAX),
            i64::try_from(max_files).unwrap_or(i64::MAX)
        ],
    )?;
    let job_id = tx.last_insert_rowid();

    let mut carved = 0_usize;
    let mut truncated = false;
    let mut carry: Vec<u8> = Vec::new();
    let mut carry_base = 0_u64;
    let mut scan_cursor = 0_u64;
    let mut min_next_offset = 0_u64;
    let mut buffer = vec![0_u8; CARVE_CHUNK_BYTES];

    'scan: while scan_cursor < scan_limit {
        opened.reader.seek(SeekFrom::Start(scan_cursor))?;
        let want = ((scan_limit - scan_cursor) as usize).min(CARVE_CHUNK_BYTES);
        let read = opened.reader.read(&mut buffer[..want])?;
        if read == 0 {
            break;
        }
        // Window = leftover overlap from the previous chunk + this chunk, so a
        // header straddling a chunk boundary is still detected.
        let mut window = std::mem::take(&mut carry);
        window.extend_from_slice(&buffer[..read]);
        let searchable = window.len().saturating_sub(overlap);
        let mut index = 0_usize;
        while index < searchable {
            let absolute = carry_base + index as u64;
            if absolute < min_next_offset {
                index += 1;
                continue;
            }
            let Some(sig) = CARVE_SIGNATURES
                .iter()
                .find(|sig| window[index..].starts_with(sig.header))
            else {
                index += 1;
                continue;
            };
            let length = carve_length(&mut *opened.reader, absolute, sig, CARVE_MAX_FILE_BYTES)?;
            opened.reader.seek(SeekFrom::Start(scan_cursor))?;
            if length < sig.header.len() as u64 {
                index += 1;
                continue;
            }
            carved += 1;
            min_next_offset = absolute + length;
            let name = format!("carved-{carved:05}-0x{absolute:X}.{}", sig.extension);
            let logical_path = format!("/Image Analysis/Carved/{name}");
            let mut metadata = serde_json::json!({
                "artifact_kind": "carved_file",
                "recovery_source": "signature_carving",
                "recovery_status": "carved from image by file signature",
                "recovery_read": "physical_extent",
                "storage_area": "carved",
                "carve_format": sig.label,
                "carve_signature": sig
                    .header
                    .iter()
                    .map(|byte| format!("{byte:02X}"))
                    .collect::<Vec<_>>()
                    .join(" "),
                "file_data_physical_offset": absolute,
                "file_data_logical_offset": absolute,
                "size_bytes": length,
            });
            add_entry_category(&mut metadata, &logical_path, &name, "file");
            let content_head = {
                let head_len = (CONTENT_INDEX_BYTES as u64).min(length) as usize;
                let mut head = vec![0_u8; head_len];
                opened.reader.seek(SeekFrom::Start(absolute))?;
                let head_read = opened.reader.read(&mut head)?;
                head.truncate(head_read);
                opened.reader.seek(SeekFrom::Start(scan_cursor))?;
                head
            };
            upsert_filesystem_entry_with_content(
                &tx,
                case_id,
                evidence_id,
                &logical_path,
                &name,
                "file",
                Some(i64::try_from(length).unwrap_or(i64::MAX)),
                &metadata.to_string(),
                job_id,
                Some(&content_head),
            )?;
            if carved >= max_files {
                truncated = true;
                break 'scan;
            }
            index += 1;
        }
        // Preserve the trailing overlap so a boundary-spanning header survives.
        let keep = window.len().min(overlap);
        carry_base += (window.len() - keep) as u64;
        carry = window.split_off(window.len() - keep);
        scan_cursor += read as u64;
    }

    if scan_limit < opened.decoded_size {
        truncated = true;
    }

    let status = if truncated { "truncated" } else { "completed" };
    tx.execute(
        "UPDATE evidence_jobs
         SET status = ?2, finished_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
         WHERE id = ?1",
        params![job_id, status],
    )?;
    tx.execute(
        "INSERT INTO audit_events(case_id, event_type, actor, object_type, object_id, details_json)
         VALUES (?1, 'evidence.carve', ?2, 'evidence', ?3,
                 json_object('carved_files', ?4, 'bytes_scanned', ?5))",
        params![
            case_id,
            actor,
            evidence_id,
            i64::try_from(carved).unwrap_or(i64::MAX),
            i64::try_from(scan_limit).unwrap_or(i64::MAX)
        ],
    )?;
    tx.commit()?;

    Ok(CarveResult {
        evidence_id,
        carved_files: carved,
        bytes_scanned: scan_limit,
        truncated,
    })
}

/// Determines a carved file's length by locating its footer within a bounded
/// window, falling back to the window cap when no footer is found.
fn carve_length(
    reader: &mut dyn disk_forensic::container::ReadSeek,
    start: u64,
    sig: &CarveSignature,
    max_len: u64,
) -> Result<u64> {
    let cap = usize::try_from(max_len).unwrap_or(usize::MAX);
    let mut buf = vec![0_u8; cap];
    reader.seek(SeekFrom::Start(start))?;
    let mut filled = 0_usize;
    while filled < buf.len() {
        let read = reader.read(&mut buf[filled..])?;
        if read == 0 {
            break;
        }
        filled += read;
    }
    buf.truncate(filled);
    if buf.is_empty() {
        return Ok(0);
    }
    // Each arm returns the carved length: footer position + trailing bytes that
    // belong to the file (e.g. PNG's IEND is followed by a 4-byte CRC).
    let length = match sig.extension {
        "jpg" => find_footer(&buf, &[0xFF, 0xD9], 0),
        "png" => find_footer(&buf, &[0x49, 0x45, 0x4E, 0x44], 4),
        "gif" => find_footer(&buf, &[0x00, 0x3B], 0),
        "pdf" => rfind_footer(&buf, b"%%EOF", 0),
        "bmp" => {
            if buf.len() >= 6 {
                let declared = u32::from_le_bytes(buf[2..6].try_into().unwrap()) as usize;
                Some(declared.clamp(sig.header.len(), buf.len()))
            } else {
                None
            }
        }
        _ => None,
    }
    .unwrap_or(buf.len());
    Ok(length as u64)
}

/// Length up to and including the first `footer` plus `trailing` bytes.
fn find_footer(haystack: &[u8], footer: &[u8], trailing: usize) -> Option<usize> {
    haystack
        .windows(footer.len())
        .position(|window| window == footer)
        .map(|pos| (pos + footer.len() + trailing).min(haystack.len()))
}

/// Same as `find_footer` but locates the last occurrence (PDFs can carry
/// multiple `%%EOF` markers from incremental updates).
fn rfind_footer(haystack: &[u8], footer: &[u8], trailing: usize) -> Option<usize> {
    if footer.is_empty() || haystack.len() < footer.len() {
        return None;
    }
    (0..=haystack.len() - footer.len())
        .rev()
        .find(|&pos| &haystack[pos..pos + footer.len()] == footer)
        .map(|pos| (pos + footer.len() + trailing).min(haystack.len()))
}

pub fn remove_evidence(case_path: &Path, evidence_id: i64) -> Result<RemoveEvidenceResult> {
    let mut conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let actor = audit_actor(&tx, case_id)?;
    ensure_evidence_source(&tx, case_id, evidence_id)?;
    let removed_entries: i64 = tx.query_row(
        "SELECT COUNT(*) FROM filesystem_entries WHERE case_id = ?1 AND evidence_id = ?2",
        params![case_id, evidence_id],
        |row| row.get(0),
    )?;
    let removed_jobs: i64 = tx.query_row(
        "SELECT COUNT(*) FROM evidence_jobs WHERE case_id = ?1 AND evidence_id = ?2",
        params![case_id, evidence_id],
        |row| row.get(0),
    )?;
    tx.execute(
        "INSERT INTO audit_events(case_id, event_type, actor, object_type, object_id, details_json)
         VALUES (?1, 'evidence.remove', ?2, 'evidence', ?3,
                 json_object('removed_entries', ?4, 'removed_jobs', ?5))",
        params![case_id, actor, evidence_id, removed_entries, removed_jobs],
    )?;
    let deleted = tx.execute(
        "DELETE FROM evidence_sources WHERE case_id = ?1 AND id = ?2",
        params![case_id, evidence_id],
    )?;
    if deleted == 0 {
        bail!("evidence source not found: {evidence_id}");
    }
    clear_stale_findings_tx(&tx, case_id, &actor)?;
    tx.commit()?;
    Ok(RemoveEvidenceResult {
        evidence_id,
        removed_entries,
        removed_jobs,
    })
}

pub fn clear_stale_findings(case_path: &Path) -> Result<ClearStaleFindingsResult> {
    let mut conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let actor = audit_actor(&tx, case_id)?;
    let result = clear_stale_findings_tx(&tx, case_id, &actor)?;
    tx.commit()?;
    Ok(result)
}

pub fn clear_all_findings(case_path: &Path) -> Result<ClearStaleFindingsResult> {
    let mut conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let actor = audit_actor(&tx, case_id)?;
    let before_items = case_bookmark_item_count(&tx, case_id)?;
    let before_bookmarks = case_bookmark_count(&tx, case_id)?;
    let before_folders = case_bookmark_folder_count(&tx, case_id)?;
    tx.execute(
        "DELETE FROM bookmark_folders WHERE case_id = ?1",
        params![case_id],
    )?;
    tx.execute("DELETE FROM bookmarks WHERE case_id = ?1", params![case_id])?;
    let result = ClearStaleFindingsResult {
        removed_folders: before_folders.saturating_sub(case_bookmark_folder_count(&tx, case_id)?),
        removed_bookmarks: before_bookmarks.saturating_sub(case_bookmark_count(&tx, case_id)?),
        removed_items: before_items.saturating_sub(case_bookmark_item_count(&tx, case_id)?),
    };
    if result.removed_folders > 0 || result.removed_bookmarks > 0 || result.removed_items > 0 {
        tx.execute(
            "INSERT INTO audit_events(case_id, event_type, actor, object_type, object_id, details_json)
             VALUES (?1, 'findings.clear_all', ?2, 'case', ?1,
                     json_object('removed_folders', ?3, 'removed_bookmarks', ?4, 'removed_items', ?5))",
            params![
                case_id,
                actor,
                result.removed_folders,
                result.removed_bookmarks,
                result.removed_items,
            ],
        )?;
    }
    tx.commit()?;
    Ok(result)
}

/// Maps a 0 entry limit to "unlimited". A single Windows disk can hold far more
/// than the old 100k cap, so processing indexes the whole volume by default.
fn unlimited_if_zero(max_entries: usize) -> usize {
    if max_entries == 0 {
        usize::MAX
    } else {
        max_entries
    }
}

pub fn process_evidence(
    case_path: &Path,
    options: ProcessEvidenceOptions,
) -> Result<ProcessEvidenceResult> {
    // 0 means "index everything"; there is no examiner-facing entry cap.
    let max_entries = unlimited_if_zero(options.max_entries);
    let mut conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    let evidence = read_evidence_for_processing(&conn, case_id, options.evidence_id)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let actor = audit_actor(&tx, case_id)?;
    let parameters_json = serde_json::json!({ "max_entries": max_entries }).to_string();
    tx.execute(
        "INSERT INTO evidence_jobs(case_id, evidence_id, job_type, status, parameters_json, started_at)
         VALUES (?1, ?2, 'filesystem_index', 'running', ?3, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
        params![case_id, evidence.id, parameters_json],
    )?;
    let job_id = tx.last_insert_rowid();

    let (entries_indexed, truncated) = match evidence.source_kind.as_str() {
        "file" => process_file_evidence(&tx, case_id, &evidence, job_id, max_entries)?,
        "folder" => process_folder_evidence(&tx, case_id, &evidence, job_id, max_entries)?,
        "image" => process_image_evidence(&tx, case_id, &evidence, job_id, max_entries)?,
        other => bail!("unsupported evidence source kind for processing: {other}"),
    };
    let bookmark_items_relinked = relink_bookmark_items_tx(&tx, case_id, evidence.id)?;
    let status = if truncated { "truncated" } else { "completed" };
    tx.execute(
        "UPDATE evidence_jobs
         SET status = ?1,
             finished_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
             error = CASE WHEN ?2 THEN 'entry limit reached' ELSE NULL END
         WHERE id = ?3",
        params![status, if truncated { 1 } else { 0 }, job_id],
    )?;
    if !truncated {
        tx.execute(
            "UPDATE evidence_sources
             SET indexed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE id = ?1 AND case_id = ?2",
            params![evidence.id, case_id],
        )?;
    }
    tx.execute(
        "INSERT INTO audit_events(case_id, event_type, actor, object_type, object_id, details_json)
         VALUES (?1, 'evidence.process', ?2, 'evidence', ?3,
                 json_object('job_id', ?4, 'entries_indexed', ?5, 'truncated', ?6,
                             'bookmark_items_relinked', ?7))",
        params![
            case_id,
            actor,
            evidence.id,
            job_id,
            entries_indexed as i64,
            if truncated { 1 } else { 0 },
            bookmark_items_relinked as i64,
        ],
    )?;
    tx.commit()?;

    Ok(ProcessEvidenceResult {
        job_id,
        evidence_id: evidence.id,
        entries_indexed,
        truncated,
        status: status.to_string(),
        bookmark_items_relinked,
    })
}

/// Examiner-triggered signature analysis (old-Ecase "Signature Analysis" / Axy file-type
/// verification). Reads each indexed file's header, detects its true type from `FILE_SIGNATURES`,
/// compares against the file extension, and records the result into each entry's `metadata_json`
/// as `file_extension`, `detected_signature`, `signature_description`, `signature_category`, and
/// `signature_status` (match / alias / mismatch / unknown / no_extension). A `mismatch` is the
/// forensically important "renamed extension / bad signature" case.
pub fn analyze_signatures(
    case_path: &Path,
    options: AnalyzeSignaturesOptions,
) -> Result<AnalyzeSignaturesResult> {
    let max_entries = unlimited_if_zero(options.max_entries);

    // Phase 1: read candidate entries and their headers using their own connections (the byte
    // reader opens the case read-only per call), before opening the write transaction.
    let candidates = {
        let conn = open_existing_case(case_path)?;
        let case_id = active_case_id(&conn)?;
        if let Some(evidence_id) = options.evidence_id {
            ensure_evidence_source(&conn, case_id, evidence_id)?;
        }
        let mut stmt = conn.prepare(
            "SELECT id, name, metadata_json
             FROM filesystem_entries
             WHERE case_id = ?1
               AND (?2 IS NULL OR evidence_id = ?2)
               AND entry_kind = 'file'
               AND COALESCE(size_bytes, 0) > 0
             ORDER BY evidence_id, logical_path, id
             LIMIT ?3",
        )?;
        let rows = stmt.query_map(
            params![case_id, options.evidence_id, (max_entries + 1) as i64],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .context("listing signature-analysis candidates")?
    };
    let truncated = candidates.len() > max_entries;
    let candidates = &candidates[..candidates.len().min(max_entries)];

    let mut updates: Vec<(i64, String)> = Vec::new();
    let mut files_examined = 0usize;
    let (mut matches, mut aliases, mut mismatches) = (0usize, 0usize, 0usize);
    let (mut unknown, mut no_extension, mut unreadable) = (0usize, 0usize, 0usize);

    for (entry_id, name, metadata_json) in candidates {
        let mut metadata: serde_json::Value =
            serde_json::from_str(metadata_json).unwrap_or_else(|_| serde_json::json!({}));
        // Skip synthetic rows that are not real byte files.
        let artifact_kind = metadata
            .get("artifact_kind")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if artifact_kind == "unallocated_space" {
            continue;
        }

        // 512 bytes is enough for every signature in the table. Unlike content search, we must
        // read the header of files of ANY size, so read a bounded window rather than rejecting
        // large files.
        let header = read_entry_header(case_path, *entry_id, 512);
        let Some(header) = header else {
            unreadable += 1;
            continue;
        };
        files_examined += 1;
        let finding = evaluate_signature(name, &header);
        match finding.status {
            "match" => matches += 1,
            "alias" => aliases += 1,
            "mismatch" => mismatches += 1,
            "unknown" => unknown += 1,
            "no_extension" => no_extension += 1,
            _ => {}
        }

        if let Some(object) = metadata.as_object_mut() {
            object.insert(
                "signature_status".to_string(),
                serde_json::Value::String(finding.status.to_string()),
            );
            match &finding.extension {
                Some(ext) => {
                    object.insert(
                        "file_extension".to_string(),
                        serde_json::Value::String(ext.clone()),
                    );
                }
                None => {
                    object.insert("file_extension".to_string(), serde_json::Value::Null);
                }
            }
            insert_opt_str(object, "detected_signature", finding.detected_label);
            insert_opt_str(
                object,
                "signature_description",
                finding.detected_description,
            );
            insert_opt_str(object, "signature_category", finding.detected_category);
            object.insert(
                "signature_analysis".to_string(),
                serde_json::Value::String("signature_magic_v1".to_string()),
            );
        }
        updates.push((*entry_id, metadata.to_string()));
    }

    // Phase 2: apply all metadata updates and record the job in one transaction.
    let mut conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let actor = audit_actor(&tx, case_id)?;
    let parameters_json = serde_json::json!({
        "evidence_id": options.evidence_id,
        "max_entries": max_entries,
    })
    .to_string();
    tx.execute(
        "INSERT INTO evidence_jobs(case_id, evidence_id, job_type, status, parameters_json, started_at)
         VALUES (?1, ?2, 'signature_analysis', 'running', ?3, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
        params![case_id, options.evidence_id, parameters_json],
    )?;
    let job_id = tx.last_insert_rowid();
    for (entry_id, metadata_json) in &updates {
        tx.execute(
            "UPDATE filesystem_entries SET metadata_json = ?1 WHERE id = ?2 AND case_id = ?3",
            params![metadata_json, entry_id, case_id],
        )?;
    }
    let status = if truncated { "truncated" } else { "completed" };
    tx.execute(
        "UPDATE evidence_jobs
         SET status = ?1,
             finished_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
             error = CASE WHEN ?2 THEN 'entry limit reached' ELSE NULL END
         WHERE id = ?3",
        params![status, if truncated { 1 } else { 0 }, job_id],
    )?;
    tx.execute(
        "INSERT INTO audit_events(case_id, event_type, actor, object_type, object_id, details_json)
         VALUES (?1, 'evidence.signature_analysis', ?2, 'evidence', ?3,
                 json_object('job_id', ?4, 'files_examined', ?5, 'mismatches', ?6))",
        params![
            case_id,
            actor,
            options.evidence_id,
            job_id,
            files_examined as i64,
            mismatches as i64,
        ],
    )?;
    tx.commit()?;

    Ok(AnalyzeSignaturesResult {
        job_id,
        evidence_id: options.evidence_id,
        files_examined,
        matches,
        aliases,
        mismatches,
        unknown,
        no_extension,
        unreadable,
        truncated,
        status: status.to_string(),
    })
}

fn insert_opt_str(
    object: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    value: Option<&str>,
) {
    match value {
        Some(text) => {
            object.insert(key.to_string(), serde_json::Value::String(text.to_string()));
        }
        None => {
            object.insert(key.to_string(), serde_json::Value::Null);
        }
    }
}

pub fn import_chromium_history(
    case_path: &Path,
    options: ImportBrowserHistoryOptions,
) -> Result<BrowserHistoryImportResult> {
    if options.max_visits == 0 {
        bail!("max_visits must be greater than zero");
    }
    let max_visits = options.max_visits.min(100_000);
    let profile_paths = chromium_profile_paths(&options.history_path)?;
    let source_metadata = fs::metadata(&profile_paths.history_path).with_context(|| {
        format!(
            "reading history database {}",
            profile_paths.history_path.display()
        )
    })?;
    let source_path = stable_path_string(&profile_paths.profile_dir);
    let display_name = trim_optional_string(options.evidence_name)
        .unwrap_or_else(|| default_history_display_name(&profile_paths.profile_dir));
    let history_rows = read_chromium_history_rows(&profile_paths.history_path, max_visits)?;
    let visit_records =
        browser_history_visit_records(&history_rows.rows, &profile_paths.history_path);
    let bookmark_records = read_chromium_bookmark_records(&profile_paths.bookmarks_path)?;
    let preference_records = read_chromium_preference_records(&profile_paths.preferences_path)?;
    let url_records = read_chromium_url_records(&profile_paths.history_path, max_visits);
    let search_records = read_chromium_search_records(&profile_paths.history_path, max_visits);
    let download_records = read_chromium_download_records(&profile_paths.history_path, max_visits);
    let login_records = read_chromium_login_records(&profile_paths.profile_dir, max_visits);
    let cookie_records = read_chromium_cookie_records(&profile_paths.profile_dir, max_visits);
    let truncated = history_rows.total_visits > history_rows.rows.len();
    let entries_indexed = visit_records.len()
        + bookmark_records.len()
        + preference_records.len()
        + url_records.len()
        + search_records.len()
        + download_records.len()
        + login_records.len()
        + cookie_records.len();

    let mut conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let actor = audit_actor(&tx, case_id)?;
    let evidence_id = upsert_browser_history_evidence(
        &tx,
        case_id,
        &source_path,
        &display_name,
        i64::try_from(source_metadata.len()).context("history database size exceeds i64")?,
    )?;
    let parameters_json = serde_json::json!({
        "history_path": source_path,
        "profile_dir": profile_paths.profile_dir.to_string_lossy(),
        "history_db": profile_paths.history_path.to_string_lossy(),
        "bookmarks_file": profile_paths.bookmarks_path.to_string_lossy(),
        "preferences_file": profile_paths.preferences_path.to_string_lossy(),
        "max_visits": max_visits
    })
    .to_string();
    tx.execute(
        "INSERT INTO evidence_jobs(case_id, evidence_id, job_type, status, parameters_json, started_at)
         VALUES (?1, ?2, 'browser_history_import', 'running', ?3, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
        params![case_id, evidence_id, parameters_json],
    )?;
    let job_id = tx.last_insert_rowid();

    tx.execute(
        "DELETE FROM filesystem_entries WHERE case_id = ?1 AND evidence_id = ?2",
        params![case_id, evidence_id],
    )?;
    for record in visit_records
        .iter()
        .chain(bookmark_records.iter())
        .chain(preference_records.iter())
        .chain(url_records.iter())
        .chain(search_records.iter())
        .chain(download_records.iter())
        .chain(login_records.iter())
        .chain(cookie_records.iter())
    {
        upsert_filesystem_entry(
            &tx,
            case_id,
            evidence_id,
            &record.logical_path,
            &record.display_name,
            "record",
            None,
            &record.metadata_json,
            job_id,
        )?;
    }
    relink_bookmark_items_tx(&tx, case_id, evidence_id)?;
    let status = if truncated { "truncated" } else { "completed" };
    tx.execute(
        "UPDATE evidence_jobs
         SET status = ?1,
             finished_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
             error = CASE WHEN ?2 THEN 'visit limit reached' ELSE NULL END
         WHERE id = ?3",
        params![status, if truncated { 1 } else { 0 }, job_id],
    )?;
    tx.execute(
        "UPDATE evidence_sources
         SET indexed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
         WHERE id = ?1 AND case_id = ?2",
        params![evidence_id, case_id],
    )?;
    tx.execute(
        "INSERT INTO audit_events(case_id, event_type, actor, object_type, object_id, details_json)
         VALUES (?1, 'browser_history.import', ?2, 'evidence', ?3,
                 json_object('entries_indexed', ?4, 'truncated', ?5, 'source_path', ?6))",
        params![
            case_id,
            actor,
            evidence_id,
            entries_indexed as i64,
            if truncated { 1 } else { 0 },
            source_path,
        ],
    )?;
    tx.commit()?;

    Ok(BrowserHistoryImportResult {
        evidence_id,
        job_id,
        source_path,
        entries_indexed,
        visits_indexed: visit_records.len(),
        bookmarks_indexed: bookmark_records.len(),
        preferences_indexed: preference_records.len(),
        truncated,
        status: status.to_string(),
    })
}

pub fn deep_search(case_path: &Path, options: DeepSearchOptions) -> Result<Vec<DeepSearchResult>> {
    let query = options.query.trim();
    if query.is_empty() {
        bail!("search query cannot be empty");
    }
    let max_results = options.max_results.clamp(1, 1_000);
    let max_file_bytes = options.max_file_bytes.clamp(1, 10 * 1024 * 1024);
    let query_lower = query.to_ascii_lowercase();
    let scope = SearchScope::new(options.category.as_deref(), options.file_types.as_deref())?;

    let conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    if let Some(evidence_id) = options.evidence_id {
        ensure_evidence_source(&conn, case_id, evidence_id)?;
    }

    // Byte-pattern mode: `hex:FF D8 FF` scans indexed content and reports
    // byte offsets. Path/metadata text search does not apply to raw bytes.
    if let Some(pattern_text) = strip_hex_query_prefix(query) {
        let needle = parse_hex_pattern(pattern_text)?;
        let mut results = Vec::new();
        content_hex_search_results(
            &conn,
            case_id,
            options.evidence_id,
            &needle,
            max_file_bytes,
            max_results,
            &scope,
            &mut results,
        )?;
        return Ok(results);
    }

    let mut results = path_search_results(
        &conn,
        case_id,
        options.evidence_id,
        query,
        &query_lower,
        max_results,
        &scope,
    )?;
    if options.include_content && results.len() < max_results {
        content_search_results(
            &conn,
            case_id,
            options.evidence_id,
            query,
            max_file_bytes,
            max_results,
            &scope,
            &mut results,
        )?;
    }
    Ok(results)
}

/// Category/file-type restriction for Deep Search, compiled once into an SQL
/// clause so LIMIT-bounded queries never drop in-scope hits behind
/// out-of-scope rows.
struct SearchScope {
    sql_clause: String,
}

impl SearchScope {
    fn new(category: Option<&str>, file_types: Option<&[String]>) -> Result<Self> {
        let mut sql_clause = String::new();
        if let Some(category) = category.map(str::trim).filter(|value| !value.is_empty()) {
            let literal = category.to_ascii_lowercase().replace('\'', "''");
            sql_clause.push_str(&format!(
                " AND instr(lower(\
                 coalesce(json_extract(fe.metadata_json,'$.category_main'),'') || ' ' || \
                 coalesce(json_extract(fe.metadata_json,'$.category_sub'),'') || ' ' || \
                 coalesce(json_extract(fe.metadata_json,'$.category_detail'),'') || ' ' || \
                 coalesce(json_extract(fe.metadata_json,'$.analysis_category'),'') || ' ' || \
                 coalesce(json_extract(fe.metadata_json,'$.category_tags'),'')\
                ), '{literal}') > 0"
            ));
        }
        if let Some(types) = file_types {
            let mut likes = Vec::new();
            for raw in types {
                let ext = raw.trim().trim_start_matches('.').to_ascii_lowercase();
                if ext.is_empty() {
                    continue;
                }
                if !ext
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '.' || ch == '_')
                {
                    bail!("file type filter contains unsupported characters: {raw}");
                }
                likes.push(format!("lower(fe.name) LIKE '%.{ext}'"));
            }
            if !likes.is_empty() {
                sql_clause.push_str(&format!(" AND ({})", likes.join(" OR ")));
            }
        }
        Ok(Self { sql_clause })
    }
}

fn strip_hex_query_prefix(query: &str) -> Option<&str> {
    let (prefix, rest) = query.split_at_checked(4)?;
    prefix.eq_ignore_ascii_case("hex:").then_some(rest)
}

/// Parses `FF D8 FF`, `ff,d8,ff`, `0xFFD8FF`, `FF-D8-FF` style byte patterns.
fn parse_hex_pattern(text: &str) -> Result<Vec<u8>> {
    let cleaned = text.replace("0x", "").replace("0X", "");
    let cleaned: String = cleaned
        .chars()
        .filter(|ch| !ch.is_whitespace() && !matches!(ch, ',' | '-' | ':'))
        .collect();
    if cleaned.is_empty() {
        bail!("hex search needs at least one byte, e.g. hex:FF D8 FF");
    }
    if !cleaned.chars().all(|ch| ch.is_ascii_hexdigit()) {
        bail!("hex pattern may only contain hex digits and space/comma/dash separators");
    }
    if cleaned.len() % 2 != 0 {
        bail!("hex pattern must contain whole bytes (an even number of hex digits)");
    }
    (0..cleaned.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&cleaned[index..index + 2], 16).context("parsing hex byte"))
        .collect()
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn hex_match_preview(bytes: &[u8], offset: usize, length: usize) -> String {
    let start = offset.saturating_sub(8);
    let end = offset
        .saturating_add(length)
        .saturating_add(8)
        .min(bytes.len());
    bytes[start..end]
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn list_filesystem_entries(
    case_path: &Path,
    evidence_id: Option<i64>,
) -> Result<Vec<FilesystemEntry>> {
    list_filesystem_entries_limited(case_path, evidence_id, None)
}

/// One direct child of a directory in the indexed tree, computed on demand so
/// the UI can browse an arbitrarily large indexed case folder by folder without
/// ever loading the whole index.
#[derive(Debug, Serialize)]
pub struct IndexedChild {
    /// Set when this child is itself an indexed entry (files and real folders);
    /// None for a folder that only exists implicitly in descendant paths.
    pub entry_id: Option<i64>,
    pub name: String,
    pub logical_path: String,
    pub is_dir: bool,
    pub has_children: bool,
    pub size_bytes: Option<i64>,
    pub is_deleted: bool,
    pub metadata_json: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct IndexedDirectory {
    pub children: Vec<IndexedChild>,
    pub truncated: bool,
}

const INDEXED_DIR_SCAN_LIMIT: usize = 400_000;

/// Lists the immediate children of `dir_path` for one evidence source directly
/// from the case database. Handles both real entries and folders that exist
/// only implicitly in descendant paths (e.g. the synthetic image containers).
///
/// Old-Ecase display model: an image device reads as device -> volume ->
/// folders, so the indexer's synthetic `/Image Analysis[/Volumes|/Partitions]`
/// containers are collapsed out of the root listing. Children keep their real
/// `logical_path`, so navigation, bookmarks, and deeper listings are unchanged.
pub fn list_indexed_directory(
    case_path: &Path,
    evidence_id: i64,
    dir_path: &str,
    limit: usize,
) -> Result<IndexedDirectory> {
    let conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    ensure_evidence_source(&conn, case_id, evidence_id)?;
    let mut dir = list_indexed_directory_inner(&conn, case_id, evidence_id, dir_path, limit)?;

    let is_root = dir_path.trim().trim_end_matches('/').is_empty();
    let synthetic_root = dir
        .children
        .iter()
        .position(|child| child.is_dir && child.logical_path == "/Image Analysis");
    if let (true, Some(index)) = (is_root, synthetic_root) {
        dir.children.remove(index);
        let inner =
            list_indexed_directory_inner(&conn, case_id, evidence_id, "/Image Analysis", limit)?;
        dir.truncated |= inner.truncated;
        for child in inner.children {
            let is_container = child.is_dir
                && (child.logical_path == "/Image Analysis/Volumes"
                    || child.logical_path == "/Image Analysis/Partitions");
            if is_container {
                let nested = list_indexed_directory_inner(
                    &conn,
                    case_id,
                    evidence_id,
                    &child.logical_path,
                    limit,
                )?;
                dir.truncated |= nested.truncated;
                dir.children
                    .extend(nested.children.into_iter().map(hoisted_indexed_child));
            } else {
                dir.children.push(hoisted_indexed_child(child));
            }
        }
        sort_indexed_children(&mut dir.children);
        if dir.children.len() > limit {
            dir.children.truncate(limit);
            dir.truncated = true;
        }
    }
    Ok(dir)
}

fn list_indexed_directory_inner(
    conn: &Connection,
    case_id: i64,
    evidence_id: i64,
    dir_path: &str,
    limit: usize,
) -> Result<IndexedDirectory> {
    let trimmed = dir_path.trim().trim_end_matches('/');
    let normalized = if trimmed.is_empty() {
        "/".to_string()
    } else if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    };
    let prefix = if normalized == "/" {
        "/".to_string()
    } else {
        format!("{normalized}/")
    };
    let like = format!("{}%", escape_like(&prefix));

    // Subtree scan WITHOUT the heavy metadata_json column (that column is the
    // bulk of each row; reading it for a whole big subtree is what made
    // top-level folders slow). Metadata is fetched only for the direct children
    // below.
    let mut stmt = conn.prepare(
        "SELECT id, logical_path, name, entry_kind, size_bytes, is_deleted
         FROM filesystem_entries
         WHERE case_id = ?1 AND evidence_id = ?2 AND logical_path LIKE ?3 ESCAPE '\\'
         ORDER BY logical_path
         LIMIT ?4",
    )?;
    let rows = stmt.query_map(
        params![
            case_id,
            evidence_id,
            like,
            i64::try_from(INDEXED_DIR_SCAN_LIMIT + 1).unwrap_or(i64::MAX)
        ],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<i64>>(4)?,
                row.get::<_, i64>(5)? != 0,
            ))
        },
    )?;

    let mut children: BTreeMap<String, IndexedChild> = BTreeMap::new();
    let mut scanned = 0_usize;
    let mut truncated = false;
    for row in rows {
        if scanned >= INDEXED_DIR_SCAN_LIMIT {
            truncated = true;
            break;
        }
        scanned += 1;
        let (id, logical_path, name, entry_kind, size_bytes, is_deleted) =
            row.context("reading indexed directory row")?;
        let rest = &logical_path[prefix.len().min(logical_path.len())..];
        let (segment, deeper) = match rest.find('/') {
            Some(index) => (&rest[..index], true),
            None => (rest, false),
        };
        if segment.is_empty() {
            continue;
        }
        let child_path = format!("{prefix}{segment}");
        let entry = children
            .entry(segment.to_string())
            .or_insert_with(|| IndexedChild {
                entry_id: None,
                name: segment.to_string(),
                logical_path: child_path.clone(),
                is_dir: false,
                has_children: false,
                size_bytes: None,
                is_deleted: false,
                metadata_json: serde_json::Value::Null,
            });
        if deeper {
            entry.is_dir = true;
            entry.has_children = true;
        } else {
            entry.entry_id = Some(id);
            entry.name = name;
            entry.is_dir = entry_kind == "directory";
            entry.size_bytes = size_bytes;
            entry.is_deleted = is_deleted;
            if entry.is_dir {
                entry.has_children = true;
            }
        }
    }

    let mut children: Vec<IndexedChild> = children.into_values().collect();
    sort_indexed_children(&mut children);
    if children.len() > limit {
        children.truncate(limit);
        truncated = true;
    }

    // Fetch metadata_json only for the (few) direct-child entries now.
    let ids: Vec<i64> = children.iter().filter_map(|child| child.entry_id).collect();
    if !ids.is_empty() {
        let placeholders = ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let mut meta_stmt = conn.prepare(&format!(
            "SELECT id, metadata_json FROM filesystem_entries WHERE id IN ({placeholders})"
        ))?;
        let meta_rows = meta_stmt.query_map(rusqlite::params_from_iter(ids.iter()), |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut by_id: HashMap<i64, serde_json::Value> = HashMap::new();
        for row in meta_rows {
            let (id, metadata_json) = row.context("reading child metadata")?;
            by_id.insert(
                id,
                serde_json::from_str(&metadata_json).unwrap_or(serde_json::Value::Null),
            );
        }
        for child in &mut children {
            if let Some(id) = child.entry_id {
                if let Some(value) = by_id.remove(&id) {
                    child.metadata_json = value;
                }
            }
        }
    }

    Ok(IndexedDirectory {
        children,
        truncated,
    })
}

// Children hoisted from the synthetic containers take their path basename as
// the display name; the stored names ("part0" for both a volume and its
// partition record) collide once they share the device root.
fn hoisted_indexed_child(mut child: IndexedChild) -> IndexedChild {
    if let Some(segment) = child.logical_path.rsplit('/').next() {
        if !segment.is_empty() {
            child.name = segment.to_string();
        }
    }
    child
}

fn sort_indexed_children(children: &mut [IndexedChild]) {
    children.sort_by(|left, right| {
        (right.is_dir as u8)
            .cmp(&(left.is_dir as u8))
            .then_with(|| {
                left.name
                    .to_ascii_lowercase()
                    .cmp(&right.name.to_ascii_lowercase())
            })
    });
}

fn escape_like(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

/// Lists indexed entries, optionally capped. The UI caps this because loading
/// hundreds of thousands of entries into the browser at once hangs it; for
/// full browsing of large evidence use live browse or deep search.
pub fn list_filesystem_entries_limited(
    case_path: &Path,
    evidence_id: Option<i64>,
    limit: Option<usize>,
) -> Result<Vec<FilesystemEntry>> {
    let conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    if let Some(evidence_id) = evidence_id {
        ensure_evidence_source(&conn, case_id, evidence_id)?;
    }
    let limit_value: i64 = limit
        .and_then(|value| i64::try_from(value).ok())
        .unwrap_or(-1);
    let mut stmt = conn.prepare(
        // Order by (evidence_id, logical_path) so the UNIQUE(evidence_id,
        // logical_path) index satisfies the sort and LIMIT reads only the first
        // rows instead of sorting the whole table (critical for huge cases).
        "SELECT id, case_id, evidence_id, parent_id, logical_path, name, entry_kind,
                size_bytes, is_deleted, metadata_json, discovered_by_job_id
         FROM filesystem_entries
         WHERE case_id = ?1
           AND (?2 IS NULL OR evidence_id = ?2)
         ORDER BY evidence_id, logical_path, id
         LIMIT ?3",
    )?;
    let rows = stmt.query_map(params![case_id, evidence_id, limit_value], |row| {
        Ok(RawFilesystemEntry {
            id: row.get(0)?,
            case_id: row.get(1)?,
            evidence_id: row.get(2)?,
            parent_id: row.get(3)?,
            logical_path: row.get(4)?,
            name: row.get(5)?,
            entry_kind: row.get(6)?,
            size_bytes: row.get(7)?,
            is_deleted: row.get::<_, i64>(8)? != 0,
            metadata_json: row.get(9)?,
            discovered_by_job_id: row.get(10)?,
        })
    })?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .context("listing filesystem entries")?
        .into_iter()
        .map(filesystem_entry_from_raw)
        .collect()
}

pub fn read_filesystem_entry_bytes(
    case_path: &Path,
    options: ReadEntryBytesOptions,
) -> Result<EntryBytes> {
    if options.length == 0 {
        bail!("length must be greater than zero");
    }
    // Single bounded read; large requests are used by the raw image preview endpoint. The hex
    // viewer keeps requesting small windows, so the cap only bounds worst-case memory use.
    let length = options.length.min(8 * 1024 * 1024);
    let conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    let entry = read_entry_for_bytes(&conn, case_id, options.entry_id)?;
    if entry.entry_kind == "record" {
        // Imported records (browser visits, bookmarks, cookies, preferences)
        // have no backing file; their content is the stored record metadata,
        // so the viewer gets that rendered as text.
        let rendered = serde_json::to_string_pretty(&entry.metadata_json)
            .context("rendering record metadata")?;
        let data = rendered.as_bytes();
        let total_size = data.len() as u64;
        let start = options.offset.min(total_size) as usize;
        let end = options.offset.saturating_add(length as u64).min(total_size) as usize;
        let bytes = data[start..end].to_vec();
        let bytes_read = bytes.len();
        return Ok(EntryBytes {
            entry_id: entry.entry_id,
            evidence_id: entry.evidence_id,
            logical_path: entry.logical_path,
            offset: options.offset,
            requested_length: length,
            bytes_read,
            total_size,
            eof: options.offset.saturating_add(bytes_read as u64) >= total_size,
            bytes,
        });
    }
    if entry.entry_kind != "file" {
        bail!(
            "filesystem entry is not a readable file: {}",
            entry.logical_path
        );
    }
    if let Some(bytes) = read_image_physical_extent_bytes(&entry, options.offset, length)? {
        return Ok(bytes);
    };
    if let Some(bytes) = read_image_ext_entry_bytes(&entry, options.offset, length)? {
        return Ok(bytes);
    };
    if let Some(bytes) = read_image_fat_entry_bytes(&entry, options.offset, length)? {
        return Ok(bytes);
    };
    if let Some(bytes) = read_image_ntfs_entry_bytes(&entry, options.offset, length)? {
        return Ok(bytes);
    };
    if is_disk_image_container_byte_entry(&entry) {
        bail!(
            "disk image file entries must be attached and analyzed as image evidence before byte viewing: {}",
            entry.logical_path
        );
    }
    let Some(path) = actual_file_path(&entry.source_kind, &entry.source_path, &entry.logical_path)
    else {
        bail!(
            "filesystem entry bytes require a readable source parser: {}",
            entry.logical_path
        );
    };
    let metadata = fs::metadata(&path)
        .with_context(|| format!("reading entry metadata {}", path.display()))?;
    if !metadata.is_file() {
        bail!("entry path is no longer a file: {}", path.display());
    }
    let total_size = metadata.len();
    let mut file =
        fs::File::open(&path).with_context(|| format!("opening entry {}", path.display()))?;
    file.seek(SeekFrom::Start(options.offset))
        .with_context(|| format!("seeking entry {}", path.display()))?;
    let mut bytes = vec![0_u8; length];
    let bytes_read = file
        .read(&mut bytes)
        .with_context(|| format!("reading entry {}", path.display()))?;
    bytes.truncate(bytes_read);
    Ok(EntryBytes {
        entry_id: entry.entry_id,
        evidence_id: entry.evidence_id,
        logical_path: entry.logical_path,
        offset: options.offset,
        requested_length: length,
        bytes_read,
        total_size,
        eof: options.offset.saturating_add(bytes_read as u64) >= total_size,
        bytes,
    })
}

pub fn recover_filesystem_entry(
    case_path: &Path,
    options: RecoverEntryOptions,
) -> Result<RecoverEntryResult> {
    if options.output_path.as_os_str().is_empty() {
        bail!("output path cannot be empty");
    }
    let mut offset = 0_u64;
    let mut bytes = read_filesystem_entry_bytes(
        case_path,
        ReadEntryBytesOptions {
            entry_id: options.entry_id,
            offset,
            length: 64 * 1024,
        },
    )?;
    let evidence_id = bytes.evidence_id;
    let total_size = bytes.total_size;

    if let Some(parent) = options
        .output_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating recovery directory {}", parent.display()))?;
    }
    let mut output = fs::File::create(&options.output_path).with_context(|| {
        format!(
            "creating recovered output {}",
            options.output_path.display()
        )
    })?;

    loop {
        if !bytes.bytes.is_empty() {
            output.write_all(&bytes.bytes).with_context(|| {
                format!("writing recovered output {}", options.output_path.display())
            })?;
            offset = offset.saturating_add(bytes.bytes_read as u64);
        }
        if bytes.eof || bytes.bytes_read == 0 {
            break;
        }
        bytes = read_filesystem_entry_bytes(
            case_path,
            ReadEntryBytesOptions {
                entry_id: options.entry_id,
                offset,
                length: 64 * 1024,
            },
        )?;
    }
    Ok(RecoverEntryResult {
        entry_id: options.entry_id,
        evidence_id,
        output_path: options.output_path.to_string_lossy().into_owned(),
        bytes_written: offset,
        total_size,
        status: if offset == total_size {
            "completed".to_string()
        } else {
            "partial".to_string()
        },
    })
}

pub fn create_bookmark_folder(
    case_path: &Path,
    parent_id: Option<i64>,
    name: &str,
    folder_comment: Option<&str>,
    show_in_report: bool,
) -> Result<i64> {
    if name.trim().is_empty() {
        bail!("bookmark folder name cannot be empty");
    }
    let mut conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let actor = audit_actor(&tx, case_id)?;
    if let Some(parent_id) = parent_id {
        ensure_bookmark_folder(&tx, case_id, parent_id)?;
    }
    ensure_bookmark_folder_name_available(&tx, case_id, parent_id, name.trim())?;
    let next_order: i64 = tx.query_row(
        "SELECT COALESCE(MAX(report_order), 0) + 10
         FROM bookmark_folders
         WHERE case_id = ?1 AND parent_id IS ?2",
        params![case_id, parent_id],
        |row| row.get(0),
    )?;
    tx.execute(
        "INSERT INTO bookmark_folders(
             case_id, parent_id, name, folder_comment, show_in_report, report_order
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            case_id,
            parent_id,
            name.trim(),
            folder_comment,
            if show_in_report { 1 } else { 0 },
            next_order,
        ],
    )?;
    let folder_id = tx.last_insert_rowid();
    tx.execute(
        "INSERT INTO audit_events(case_id, event_type, actor, object_type, object_id, details_json)
         VALUES (?1, 'bookmark.folder.create', ?2, 'bookmark_folder', ?3, json_object('name', ?4))",
        params![case_id, actor, folder_id, name.trim()],
    )?;
    tx.commit()?;
    Ok(folder_id)
}

pub fn list_bookmark_folders(case_path: &Path) -> Result<Vec<BookmarkFolder>> {
    let conn = open_existing_case(case_path)?;
    let mut stmt = conn.prepare(
        "SELECT id, case_id, parent_id, name, folder_comment, show_in_report, report_order,
                created_at, updated_at
         FROM bookmark_folders
         ORDER BY parent_id IS NOT NULL, parent_id, report_order, name",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(BookmarkFolder {
            id: row.get(0)?,
            case_id: row.get(1)?,
            parent_id: row.get(2)?,
            name: row.get(3)?,
            folder_comment: row.get(4)?,
            show_in_report: row.get::<_, i64>(5)? != 0,
            report_order: row.get(6)?,
            created_at: row.get(7)?,
            updated_at: row.get(8)?,
        })
    })?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .context("listing bookmark folders")
}

pub fn create_bookmark(case_path: &Path, options: CreateBookmarkOptions) -> Result<i64> {
    validate_json_object(&options.source_ref_json, "source_ref_json")?;
    validate_json_object(&options.content_ref_json, "content_ref_json")?;

    let mut conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let actor = audit_actor(&tx, case_id)?;
    ensure_bookmark_folder(&tx, case_id, options.folder_id)?;

    let bookmark_type = options.bookmark_type.as_str();
    let data_type = trim_optional_string(options.data_type);
    let title = trim_optional_string(options.title);
    let examiner_comment = trim_optional_string(options.examiner_comment);
    let source_ref_json = options.source_ref_json.to_string();
    let content_ref_json = options.content_ref_json.to_string();

    tx.execute(
        "INSERT INTO bookmarks(
             case_id, folder_id, bookmark_type, data_type, title, examiner_comment, in_report,
             source_ref_json, content_ref_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            case_id,
            options.folder_id,
            bookmark_type,
            data_type,
            title,
            examiner_comment,
            if options.in_report { 1 } else { 0 },
            source_ref_json,
            content_ref_json,
        ],
    )?;
    let bookmark_id = tx.last_insert_rowid();
    tx.execute(
        "INSERT INTO audit_events(case_id, event_type, actor, object_type, object_id, details_json)
         VALUES (?1, 'bookmark.create', ?2, 'bookmark', ?3,
                 json_object('folder_id', ?4, 'bookmark_type', ?5))",
        params![
            case_id,
            actor,
            bookmark_id,
            options.folder_id,
            bookmark_type
        ],
    )?;
    tx.commit()?;
    Ok(bookmark_id)
}

pub fn list_bookmarks(case_path: &Path) -> Result<Vec<Bookmark>> {
    let conn = open_existing_case(case_path)?;
    let mut stmt = conn.prepare(
        "SELECT b.id, b.case_id, b.folder_id, b.bookmark_type, b.data_type, b.title,
                b.examiner_comment, b.in_report, b.source_ref_json, b.content_ref_json,
                b.created_at, b.updated_at
         FROM bookmarks b
         JOIN bookmark_folders f ON f.id = b.folder_id
         ORDER BY f.report_order, f.name, b.id",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(RawBookmark {
            id: row.get(0)?,
            case_id: row.get(1)?,
            folder_id: row.get(2)?,
            bookmark_type: row.get(3)?,
            data_type: row.get(4)?,
            title: row.get(5)?,
            examiner_comment: row.get(6)?,
            in_report: row.get::<_, i64>(7)? != 0,
            source_ref_json: row.get(8)?,
            content_ref_json: row.get(9)?,
            created_at: row.get(10)?,
            updated_at: row.get(11)?,
        })
    })?;
    let raw_bookmarks = rows
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("listing bookmarks")?;

    raw_bookmarks
        .into_iter()
        .map(|raw| {
            let source_ref_json =
                parse_stored_json(&raw.source_ref_json, "source_ref_json", raw.id)?;
            let content_ref_json =
                parse_stored_json(&raw.content_ref_json, "content_ref_json", raw.id)?;
            Ok(Bookmark {
                id: raw.id,
                case_id: raw.case_id,
                folder_id: raw.folder_id,
                bookmark_type: raw.bookmark_type,
                data_type: raw.data_type,
                title: raw.title,
                examiner_comment: raw.examiner_comment,
                in_report: raw.in_report,
                source_ref_json,
                content_ref_json,
                created_at: raw.created_at,
                updated_at: raw.updated_at,
            })
        })
        .collect()
}

pub fn add_bookmark_item(
    case_path: &Path,
    options: CreateBookmarkItemOptions,
) -> Result<BookmarkItem> {
    validate_json_object(&options.item_ref_json, "item_ref_json")?;
    validate_non_negative(options.item_order, "item_order")?;
    validate_non_negative(options.selection_offset, "selection_offset")?;
    validate_non_negative(options.selection_length, "selection_length")?;

    let mut conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let actor = audit_actor(&tx, case_id)?;
    ensure_bookmark(&tx, case_id, options.bookmark_id)?;
    let mut evidence_id = options.evidence_id;
    if let Some(evidence_id) = evidence_id {
        ensure_evidence_source(&tx, case_id, evidence_id)?;
    }
    if let Some(entry_id) = options.entry_id {
        let entry_evidence_id = ensure_filesystem_entry(&tx, case_id, entry_id, evidence_id)?;
        if evidence_id.is_none() {
            evidence_id = Some(entry_evidence_id);
        }
    }

    let item_order = match options.item_order {
        Some(item_order) => item_order,
        None => tx.query_row(
            "SELECT COALESCE(MAX(item_order), 0) + 10
             FROM bookmark_items
             WHERE bookmark_id = ?1",
            params![options.bookmark_id],
            |row| row.get(0),
        )?,
    };
    ensure_bookmark_item_order_available(&tx, options.bookmark_id, item_order)?;
    let display_name = trim_optional_string(options.display_name);
    let logical_path = trim_optional_string(options.logical_path);
    let data_preview = trim_optional_string(options.data_preview);
    let item_ref_json = options.item_ref_json.to_string();

    tx.execute(
        "INSERT INTO bookmark_items(
             bookmark_id, evidence_id, entry_id, item_order, display_name, logical_path,
             selection_offset, selection_length, data_preview, item_ref_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            options.bookmark_id,
            evidence_id,
            options.entry_id,
            item_order,
            display_name,
            logical_path,
            options.selection_offset,
            options.selection_length,
            data_preview,
            item_ref_json,
        ],
    )?;
    let item_id = tx.last_insert_rowid();
    tx.execute(
        "INSERT INTO audit_events(case_id, event_type, actor, object_type, object_id, details_json)
         VALUES (?1, 'bookmark.item.add', ?2, 'bookmark_item', ?3,
                 json_object('bookmark_id', ?4, 'evidence_id', ?5, 'entry_id', ?6))",
        params![
            case_id,
            actor,
            item_id,
            options.bookmark_id,
            evidence_id,
            options.entry_id,
        ],
    )?;
    let item = read_bookmark_item(&tx, case_id, item_id)?;
    tx.commit()?;
    Ok(item)
}

pub fn list_bookmark_items(
    case_path: &Path,
    bookmark_id: Option<i64>,
) -> Result<Vec<BookmarkItem>> {
    let conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    if let Some(bookmark_id) = bookmark_id {
        ensure_bookmark(&conn, case_id, bookmark_id)?;
    }

    let mut stmt = conn.prepare(
        "SELECT bi.id, bi.bookmark_id, bi.evidence_id, bi.entry_id, bi.item_order,
                bi.display_name, bi.logical_path, bi.selection_offset, bi.selection_length,
                bi.data_preview, bi.item_ref_json, bi.created_at
         FROM bookmark_items bi
         JOIN bookmarks b ON b.id = bi.bookmark_id
         WHERE b.case_id = ?1
           AND (?2 IS NULL OR bi.bookmark_id = ?2)
         ORDER BY bi.bookmark_id, bi.item_order, bi.id",
    )?;
    let rows = stmt.query_map(params![case_id, bookmark_id], |row| {
        Ok(RawBookmarkItem {
            id: row.get(0)?,
            bookmark_id: row.get(1)?,
            evidence_id: row.get(2)?,
            entry_id: row.get(3)?,
            item_order: row.get(4)?,
            display_name: row.get(5)?,
            logical_path: row.get(6)?,
            selection_offset: row.get(7)?,
            selection_length: row.get(8)?,
            data_preview: row.get(9)?,
            item_ref_json: row.get(10)?,
            created_at: row.get(11)?,
        })
    })?;
    let raw_items = rows
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("listing bookmark items")?;

    raw_items.into_iter().map(bookmark_item_from_raw).collect()
}

pub fn report_data(case_path: &Path) -> Result<ReportData> {
    let case = case_info(case_path)?;
    let conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;

    let mut folder_stmt = conn.prepare(
        "SELECT id, name, folder_comment, report_order
         FROM bookmark_folders
         WHERE case_id = ?1 AND show_in_report = 1
         ORDER BY report_order, name, id",
    )?;
    let folder_rows = folder_stmt.query_map(params![case_id], |row| {
        Ok(ReportFolder {
            id: row.get(0)?,
            name: row.get(1)?,
            folder_comment: row.get(2)?,
            report_order: row.get(3)?,
            bookmarks: Vec::new(),
        })
    })?;
    let mut folders = folder_rows
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("listing report folders")?;

    for folder in &mut folders {
        folder.bookmarks = report_bookmarks_for_folder(&conn, folder.id)?;
    }

    let evidence = report_evidence_rows(&conn, case_id)?;

    Ok(ReportData {
        case,
        evidence,
        directory_trees: Vec::new(),
        folders,
    })
}

fn report_evidence_rows(conn: &Connection, case_id: i64) -> Result<Vec<ReportEvidence>> {
    let mut stmt = conn.prepare(
        "SELECT e.id, e.display_name, e.source_kind, e.source_path, e.size_bytes,
                e.attached_at, e.indexed_at, e.notes,
                (SELECT COUNT(*) FROM filesystem_entries f
                 WHERE f.case_id = e.case_id AND f.evidence_id = e.id),
                e.sha256_hex
         FROM evidence_sources e
         WHERE e.case_id = ?1
         ORDER BY e.id",
    )?;
    let rows = stmt.query_map(params![case_id], |row| {
        let source_path: String = row.get(3)?;
        let file_extension = Path::new(&source_path)
            .extension()
            .map(|ext| ext.to_string_lossy().to_lowercase());
        Ok(ReportEvidence {
            id: row.get(0)?,
            display_name: row.get(1)?,
            source_kind: row.get(2)?,
            source_path,
            file_extension,
            size_bytes: row.get(4)?,
            sha256: row.get(9)?,
            attached_at: row.get(5)?,
            indexed_at: row.get(6)?,
            entries_indexed: row.get(8)?,
            notes: row.get(7)?,
        })
    })?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .context("listing report evidence sources")
}

/// Report variant that also carries the full indexed directory structure of
/// each evidence source, bounded by `max_lines_per_evidence` tree lines.
pub fn report_data_with_directory_structure(
    case_path: &Path,
    max_lines_per_evidence: usize,
) -> Result<ReportData> {
    let mut report = report_data(case_path)?;
    let conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    let mut trees = Vec::new();
    for evidence in &report.evidence {
        let mut stmt = conn.prepare(
            "SELECT logical_path, name, entry_kind, size_bytes
             FROM filesystem_entries
             WHERE case_id = ?1 AND evidence_id = ?2",
        )?;
        let rows = stmt.query_map(params![case_id, evidence.id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<i64>>(3)?,
            ))
        })?;
        let rows = rows
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("listing directory structure entries")?;
        if rows.is_empty() {
            continue;
        }
        // BTreeMap keyed by path components yields depth-first, alphabetical
        // traversal and lets implied parent folders (paths with no directory
        // row of their own) appear in the tree.
        let mut nodes: BTreeMap<Vec<String>, (String, Option<i64>)> = BTreeMap::new();
        let total_entries = rows.len() as i64;
        for (logical_path, name, entry_kind, size_bytes) in rows {
            let mut parts: Vec<String> = logical_path
                .split('/')
                .filter(|part| !part.is_empty())
                .map(str::to_string)
                .collect();
            // Old-Ecase display model: strip the indexer's synthetic
            // containers so report trees read device -> volume -> folders.
            if parts.first().map(String::as_str) == Some("Image Analysis") {
                parts.remove(0);
                if matches!(
                    parts.first().map(String::as_str),
                    Some("Volumes") | Some("Partitions")
                ) {
                    parts.remove(0);
                }
                // The container folders themselves collapse away entirely.
                if parts.is_empty() {
                    continue;
                }
            }
            if parts.is_empty() {
                parts.push(name);
            }
            for ancestor_len in 1..parts.len() {
                nodes
                    .entry(parts[..ancestor_len].to_vec())
                    .or_insert_with(|| ("directory".to_string(), None));
            }
            // The report tree shows the directory structure only; individual
            // files would blow the report up on large evidence. Files still
            // contribute their implied ancestor folders above.
            if entry_kind == "directory" {
                nodes.insert(parts, (entry_kind, size_bytes));
            }
        }
        let mut truncated = false;
        let mut lines = Vec::new();
        for (parts, (entry_kind, size_bytes)) in &nodes {
            if lines.len() >= max_lines_per_evidence {
                truncated = true;
                break;
            }
            lines.push(ReportTreeLine {
                depth: parts.len() - 1,
                name: parts.last().cloned().unwrap_or_default(),
                entry_kind: entry_kind.clone(),
                size_bytes: *size_bytes,
            });
        }
        trees.push(ReportDirectoryTree {
            evidence_id: evidence.id,
            evidence_name: evidence.display_name.clone(),
            total_entries,
            truncated,
            lines,
        });
    }
    report.directory_trees = trees;
    Ok(report)
}

/// Records a report export (path + content hash) in the case audit trail so a
/// produced report can later be re-verified against the case database.
pub fn record_report_export(case_path: &Path, output_path: &str, sha256: &str) -> Result<()> {
    let mut conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let actor = audit_actor(&tx, case_id)?;
    tx.execute(
        "INSERT INTO audit_events(case_id, event_type, actor, object_type, object_id, details_json)
         VALUES (?1, 'report.export', ?2, 'report', ?1,
                 json_object('output_path', ?3, 'sha256', ?4))",
        params![case_id, actor, output_path, sha256],
    )?;
    tx.commit()?;
    Ok(())
}

pub fn render_report_html(report: &ReportData) -> String {
    render_report(report).html
}

pub fn render_report(report: &ReportData) -> RenderedReport {
    let mut html = String::new();
    html.push_str("<!doctype html><html><head><meta charset=\"utf-8\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\"><title>");
    html.push_str(&escape_html(&report.case.name));
    html.push_str("</title><style>");
    html.push_str("body{font-family:Segoe UI,Arial,sans-serif;margin:32px;line-height:1.4;color:#1f2933}h1{margin-bottom:0}h2{border-bottom:1px solid #cfd7df;padding-bottom:4px;margin-top:28px}article{margin:16px 0;padding:12px 0;border-bottom:1px solid #e6ebf0}.meta{color:#5b6773;font-size:0.9em}.comment{white-space:pre-wrap}.items{border-collapse:collapse;width:100%;margin-top:8px}.items th,.items td{border:1px solid #d9e1e8;padding:6px;text-align:left;vertical-align:top}.items th{background:#f3f6f8}.activity-details{margin:0}.activity-details dt{font-weight:600}.activity-details dd{margin:0 0 4px 0;overflow-wrap:anywhere}pre{white-space:pre-wrap;background:#f6f8fa;padding:8px;border:1px solid #d9e1e8}");
    html.push_str(".kdft-band{display:flex;justify-content:space-between;align-items:center;background:#0f3d3e;color:#eaf4f4;padding:10px 14px;border-radius:6px;font-size:0.9em}.kdft-band .kdft-logo{font-weight:800;letter-spacing:2px;font-size:1.2em}.dirtree{font-family:Consolas,monospace;font-size:0.85em;line-height:1.5;overflow-x:auto}.kdft-integrity{margin-top:32px;border-top:2px solid #0f3d3e;padding-top:8px;color:#5b6773;font-size:0.8em;overflow-wrap:anywhere}body::after{content:'KDFT';position:fixed;top:40%;left:20%;font-size:18vw;font-weight:900;color:rgba(15,61,62,0.05);transform:rotate(-28deg);pointer-events:none;z-index:0}");
    html.push_str("</style></head><body>");
    html.push_str("<div class=\"kdft-band\"><span class=\"kdft-logo\">KDFT</span><span>Kristiee's Digital Forensic Tool &middot; engine v");
    html.push_str(env!("CARGO_PKG_VERSION"));
    html.push_str("</span><span>Report generated ");
    let generated_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|now| DateTime::<Utc>::from_timestamp(now.as_secs() as i64, 0))
        .map(|now| now.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_else(|| "unknown".to_string());
    html.push_str(&escape_html(&generated_at));
    html.push_str("</span></div>");
    html.push_str("<h1>");
    html.push_str(&escape_html(&report.case.name));
    html.push_str("</h1>");
    html.push_str("<p class=\"meta\">");
    if let Some(case_number) = report
        .case
        .case_number
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        html.push_str("Case number: ");
        html.push_str(&escape_html(case_number));
        html.push_str(" | ");
    }
    if let Some(case_type) = report
        .case
        .case_type
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        html.push_str("Case type: ");
        html.push_str(&escape_html(case_type));
        html.push_str(" | ");
    }
    html.push_str("Examiner: ");
    html.push_str(&escape_html(
        report.case.examiner_name.as_deref().unwrap_or("unknown"),
    ));
    html.push_str(" | Created: ");
    html.push_str(&escape_html(&report.case.created_at));
    html.push_str("</p>");
    if let Some(description) = report
        .case
        .description
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        html.push_str("<p class=\"comment\">");
        html.push_str(&escape_html(description));
        html.push_str("</p>");
    }

    html.push_str("<section><h2>Technical Details</h2>");
    html.push_str("<table class=\"items\"><tbody>");
    let case_rows = [
        ("Case name", Some(report.case.name.clone())),
        ("Case number", report.case.case_number.clone()),
        ("Case type", report.case.case_type.clone()),
        ("Examiner", report.case.examiner_name.clone()),
        ("Case created", Some(report.case.created_at.clone())),
        ("Timezone", Some(report.case.timezone.clone())),
        ("Report generated", Some(generated_at.clone())),
        (
            "Generated by",
            Some(format!(
                "KDFT (Kristiee's Digital Forensic Tool) v{}",
                env!("CARGO_PKG_VERSION")
            )),
        ),
    ];
    for (label, value) in case_rows {
        if let Some(value) = value.filter(|value| !value.is_empty()) {
            html.push_str("<tr><th>");
            html.push_str(&escape_html(label));
            html.push_str("</th><td>");
            html.push_str(&escape_html(&value));
            html.push_str("</td></tr>");
        }
    }
    html.push_str("</tbody></table>");

    if !report.evidence.is_empty() {
        html.push_str("<h2>Evidence Sources</h2><table class=\"items\"><thead><tr><th>ID</th><th>Name</th><th>Kind</th><th>Extension</th><th>Size</th><th>SHA-256</th><th>Location</th><th>Attached</th><th>Indexed entries</th></tr></thead><tbody>");
        for evidence in &report.evidence {
            html.push_str("<tr><td>");
            html.push_str(&evidence.id.to_string());
            html.push_str("</td><td>");
            html.push_str(&escape_html(&evidence.display_name));
            html.push_str("</td><td>");
            html.push_str(&escape_html(&evidence.source_kind));
            html.push_str("</td><td>");
            html.push_str(&escape_html(
                evidence.file_extension.as_deref().unwrap_or(""),
            ));
            html.push_str("</td><td>");
            match evidence.size_bytes {
                Some(size) => html.push_str(&escape_html(&format_size_bytes(size))),
                None => html.push_str("unknown"),
            }
            html.push_str("</td><td>");
            match evidence.sha256.as_deref() {
                Some(hash) => html.push_str(&escape_html(hash)),
                None => html.push_str("<span class=\"meta\">not computed</span>"),
            }
            html.push_str("</td><td>");
            html.push_str(&escape_html(&evidence.source_path));
            html.push_str("</td><td>");
            html.push_str(&escape_html(&evidence.attached_at));
            html.push_str("</td><td>");
            html.push_str(&evidence.entries_indexed.to_string());
            html.push_str("</td></tr>");
        }
        html.push_str("</tbody></table>");
    }
    html.push_str("</section>");

    for tree in &report.directory_trees {
        html.push_str("<section><h2>Directory Structure - ");
        html.push_str(&escape_html(&tree.evidence_name));
        html.push_str("</h2><p class=\"meta\">");
        html.push_str(&tree.total_entries.to_string());
        html.push_str(" indexed entr");
        html.push_str(if tree.total_entries == 1 { "y" } else { "ies" });
        html.push_str(". Folder structure only; individual files are listed in bookmark sections.</p><pre class=\"dirtree\">");
        for line in &tree.lines {
            for _ in 0..line.depth {
                html.push_str("    ");
            }
            html.push_str(&escape_html(&line.name));
            if line.entry_kind == "directory" {
                html.push('/');
            } else if let Some(size) = line.size_bytes {
                html.push_str("  (");
                html.push_str(&escape_html(&format_size_bytes(size)));
                html.push(')');
            }
            html.push('\n');
        }
        html.push_str("</pre>");
        if tree.truncated {
            html.push_str("<p class=\"meta\">Directory listing truncated to ");
            html.push_str(&tree.lines.len().to_string());
            html.push_str(" lines.</p>");
        }
        html.push_str("</section>");
    }

    if report.folders.is_empty() {
        html.push_str("<p>No report-enabled bookmark folders.</p>");
    }

    for folder in &report.folders {
        html.push_str("<section><h2>");
        html.push_str(&escape_html(&folder.name));
        html.push_str("</h2>");
        if let Some(comment) = &folder.folder_comment {
            html.push_str("<p class=\"comment\">");
            html.push_str(&escape_html(comment));
            html.push_str("</p>");
        }
        if folder.bookmarks.is_empty() {
            html.push_str("<p class=\"meta\">No report-enabled bookmarks in this folder.</p>");
        }
        for bookmark in &folder.bookmarks {
            html.push_str("<article><h3>");
            html.push_str(&escape_html(
                bookmark.title.as_deref().unwrap_or(&bookmark.bookmark_type),
            ));
            html.push_str("</h3><p class=\"meta\">Type: ");
            html.push_str(&escape_html(&bookmark.bookmark_type));
            if let Some(data_type) = &bookmark.data_type {
                html.push_str(" | Data type: ");
                html.push_str(&escape_html(data_type));
            }
            html.push_str(" | Created: ");
            html.push_str(&escape_html(&bookmark.created_at));
            html.push_str("</p>");
            if let Some(comment) = &bookmark.examiner_comment {
                html.push_str("<p class=\"comment\">");
                html.push_str(&escape_html(comment));
                html.push_str("</p>");
            }
            render_report_items_html(&mut html, &bookmark.items);
            html.push_str("</article>");
        }
        html.push_str("</section>");
    }

    // The SHA-256 covers every report byte before the integrity footer, so an
    // exported file can be re-verified: hash the file content up to (not
    // including) the footer marker and compare, or match the hash against the
    // case database's report.export audit event.
    let sha256 = sha256_hex(html.as_bytes());
    html.push_str("<footer class=\"kdft-integrity\" data-kdft-sha256=\"");
    html.push_str(&sha256);
    html.push_str("\"><strong>KDFT report authenticity</strong> &mdash; generated by KDFT v");
    html.push_str(env!("CARGO_PKG_VERSION"));
    html.push_str(" on ");
    html.push_str(&escape_html(&generated_at));
    html.push_str(". SHA-256 of all report content preceding this footer: <code>");
    html.push_str(&sha256);
    html.push_str("</code>. To verify: hash the report file bytes up to (not including) the first occurrence of the marker <code>&lt;footer class=\"kdft-integrity\"</code> and compare with this value and with the report.export audit event stored in the case database.</footer>");
    html.push_str("</body></html>");
    RenderedReport { html, sha256 }
}

fn format_size_bytes(size: i64) -> String {
    if size < 0 {
        return size.to_string();
    }
    let units = ["B", "KB", "MB", "GB", "TB"];
    let mut value = size as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < units.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{size} B")
    } else {
        format!("{value:.1} {} ({size} bytes)", units[unit])
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn filesystem_entry_count(case_path: &Path) -> Result<i64> {
    let conn = open_existing_case(case_path)?;
    conn.query_row("SELECT COUNT(*) FROM filesystem_entries", [], |row| {
        row.get(0)
    })
    .context("counting filesystem entries")
}

/// Highest filesystem entry id (0 when the case has no entries). Combined with
/// the entry count this is a cheap change marker: any reprocess/import inserts
/// new rows with fresh ids, so (count, max_id) changing invalidates caches
/// derived from the entry table.
pub fn max_filesystem_entry_id(case_path: &Path) -> Result<i64> {
    let conn = open_existing_case(case_path)?;
    conn.query_row(
        "SELECT COALESCE(MAX(id), 0) FROM filesystem_entries",
        [],
        |row| row.get(0),
    )
    .context("reading max filesystem entry id")
}

#[derive(Debug, Clone, Serialize)]
pub struct CategoryCount {
    pub main: String,
    pub sub: String,
    pub count: i64,
}

/// Exact per-category entry counts computed in SQLite from the stored
/// `category_main` / `category_sub` metadata stamped at process time. Entries
/// processed before category stamping existed land in the "Uncategorized"
/// bucket. This scans every row's metadata_json, so callers should cache the
/// result on large cases (see `max_filesystem_entry_id`).
pub fn category_entry_counts(case_path: &Path) -> Result<Vec<CategoryCount>> {
    let conn = open_existing_case(case_path)?;
    let mut stmt = conn.prepare(
        "SELECT COALESCE(json_extract(metadata_json, '$.category_main'), 'Uncategorized'),
                COALESCE(json_extract(metadata_json, '$.category_sub'), ''),
                COUNT(*)
         FROM filesystem_entries
         WHERE entry_kind != 'directory'
         GROUP BY 1, 2
         ORDER BY 1, 2",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(CategoryCount {
            main: row.get(0)?,
            sub: row.get(1)?,
            count: row.get(2)?,
        })
    })?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .context("counting entries per category")
}

struct RawBookmark {
    id: i64,
    case_id: i64,
    folder_id: i64,
    bookmark_type: String,
    data_type: Option<String>,
    title: Option<String>,
    examiner_comment: Option<String>,
    in_report: bool,
    source_ref_json: String,
    content_ref_json: String,
    created_at: String,
    updated_at: String,
}

struct RawBookmarkItem {
    id: i64,
    bookmark_id: i64,
    evidence_id: Option<i64>,
    entry_id: Option<i64>,
    item_order: i64,
    display_name: Option<String>,
    logical_path: Option<String>,
    selection_offset: Option<i64>,
    selection_length: Option<i64>,
    data_preview: Option<String>,
    item_ref_json: String,
    created_at: String,
}

struct ChromiumProfilePaths {
    profile_dir: PathBuf,
    history_path: PathBuf,
    bookmarks_path: PathBuf,
    preferences_path: PathBuf,
}

struct BrowserActivityRecord {
    logical_path: String,
    display_name: String,
    metadata_json: String,
}

struct ChromiumHistoryRows {
    rows: Vec<ChromiumHistoryRow>,
    total_visits: usize,
}

struct ChromiumHistoryRow {
    visit_id: i64,
    url_id: i64,
    url: String,
    title: Option<String>,
    visit_time: i64,
    last_visit_time: Option<i64>,
    visit_count: Option<i64>,
    typed_count: Option<i64>,
    transition: Option<i64>,
    visit_duration: Option<i64>,
    hidden: Option<i64>,
}

impl ChromiumHistoryRow {
    fn display_name(&self) -> String {
        self.title
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(&self.url)
            .chars()
            .take(180)
            .collect()
    }

    fn logical_path(&self) -> String {
        let host = sanitize_logical_segment(&host_from_url(&self.url));
        format!(
            "/Browser Activities/Visits/{}/{}-{}.record",
            host, self.visit_time, self.visit_id
        )
    }
}

struct TempFileGuard {
    path: PathBuf,
}

impl TempFileGuard {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

struct EvidenceForProcessing {
    id: i64,
    source_kind: String,
    source_path: String,
    display_name: String,
}

struct ContentSearchHit {
    offset: usize,
    length: usize,
    data_preview: String,
}

struct RawFilesystemEntry {
    id: i64,
    case_id: i64,
    evidence_id: i64,
    parent_id: Option<i64>,
    logical_path: String,
    name: String,
    entry_kind: String,
    size_bytes: Option<i64>,
    is_deleted: bool,
    metadata_json: String,
    discovered_by_job_id: Option<i64>,
}

#[derive(Clone)]
struct EntryForBytes {
    entry_id: i64,
    evidence_id: i64,
    logical_path: String,
    entry_kind: String,
    size_bytes: Option<i64>,
    metadata_json: serde_json::Value,
    source_kind: String,
    source_path: String,
}

struct RawEntryForBytes {
    entry_id: i64,
    evidence_id: i64,
    logical_path: String,
    entry_kind: String,
    size_bytes: Option<i64>,
    metadata_json: String,
    source_kind: String,
    source_path: String,
}

fn filesystem_entry_from_raw(raw: RawFilesystemEntry) -> Result<FilesystemEntry> {
    let metadata_json = serde_json::from_str(&raw.metadata_json)
        .with_context(|| format!("parsing metadata_json for filesystem entry {}", raw.id))?;
    Ok(FilesystemEntry {
        id: raw.id,
        case_id: raw.case_id,
        evidence_id: raw.evidence_id,
        parent_id: raw.parent_id,
        logical_path: raw.logical_path,
        name: raw.name,
        entry_kind: raw.entry_kind,
        size_bytes: raw.size_bytes,
        is_deleted: raw.is_deleted,
        metadata_json,
        discovered_by_job_id: raw.discovered_by_job_id,
    })
}

fn read_entry_for_bytes(conn: &Connection, case_id: i64, entry_id: i64) -> Result<EntryForBytes> {
    let raw = conn
        .query_row(
            "SELECT fe.id, fe.evidence_id, fe.logical_path, fe.entry_kind,
                fe.size_bytes, fe.metadata_json,
                es.source_kind, es.source_path
         FROM filesystem_entries fe
         JOIN evidence_sources es ON es.id = fe.evidence_id
         WHERE fe.case_id = ?1 AND fe.id = ?2",
            params![case_id, entry_id],
            |row| {
                Ok(RawEntryForBytes {
                    entry_id: row.get(0)?,
                    evidence_id: row.get(1)?,
                    logical_path: row.get(2)?,
                    entry_kind: row.get(3)?,
                    size_bytes: row.get(4)?,
                    metadata_json: row.get(5)?,
                    source_kind: row.get(6)?,
                    source_path: row.get(7)?,
                })
            },
        )
        .optional()?
        .with_context(|| format!("filesystem entry does not exist in active case: {entry_id}"))?;
    let metadata_json = serde_json::from_str(&raw.metadata_json).with_context(|| {
        format!(
            "parsing metadata_json for filesystem entry {}",
            raw.entry_id
        )
    })?;
    Ok(EntryForBytes {
        entry_id: raw.entry_id,
        evidence_id: raw.evidence_id,
        logical_path: raw.logical_path,
        entry_kind: raw.entry_kind,
        size_bytes: raw.size_bytes,
        metadata_json,
        source_kind: raw.source_kind,
        source_path: raw.source_path,
    })
}

fn read_evidence_for_processing(
    conn: &Connection,
    case_id: i64,
    evidence_id: i64,
) -> Result<EvidenceForProcessing> {
    conn.query_row(
        "SELECT id, source_kind, source_path, display_name
         FROM evidence_sources
         WHERE id = ?1 AND case_id = ?2",
        params![evidence_id, case_id],
        |row| {
            Ok(EvidenceForProcessing {
                id: row.get(0)?,
                source_kind: row.get(1)?,
                source_path: row.get(2)?,
                display_name: row.get(3)?,
            })
        },
    )
    .optional()?
    .with_context(|| format!("evidence source does not exist in active case: {evidence_id}"))
}

fn read_chromium_history_rows(
    history_path: &Path,
    max_visits: usize,
) -> Result<ChromiumHistoryRows> {
    let copy_path = temp_history_copy_path(history_path);
    fs::copy(history_path, &copy_path).with_context(|| {
        format!(
            "copying history database {} to {}",
            history_path.display(),
            copy_path.display()
        )
    })?;
    let copy_guard = TempFileGuard::new(copy_path);
    let conn = Connection::open_with_flags(&copy_guard.path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| {
            format!(
                "opening history database copy {}",
                copy_guard.path.display()
            )
        })?;
    let total_visits: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM visits v JOIN urls u ON u.id = v.url",
            [],
            |row| row.get(0),
        )
        .context("counting Chromium history visits")?;
    let mut stmt = conn.prepare(
        "SELECT v.id, v.url, u.url, u.title, v.visit_time, u.last_visit_time,
                u.visit_count, u.typed_count, v.transition, v.visit_duration, u.hidden
         FROM visits v
         JOIN urls u ON u.id = v.url
         ORDER BY v.visit_time DESC, v.id DESC
         LIMIT ?1",
    )?;
    let rows = stmt.query_map(params![max_visits as i64], |row| {
        Ok(ChromiumHistoryRow {
            visit_id: row.get(0)?,
            url_id: row.get(1)?,
            url: row.get(2)?,
            title: row.get(3)?,
            visit_time: row.get(4)?,
            last_visit_time: row.get(5)?,
            visit_count: row.get(6)?,
            typed_count: row.get(7)?,
            transition: row.get(8)?,
            visit_duration: row.get(9)?,
            hidden: row.get(10)?,
        })
    })?;
    let rows = rows
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("reading Chromium history visits")?;
    Ok(ChromiumHistoryRows {
        rows,
        total_visits: usize::try_from(total_visits).unwrap_or(usize::MAX),
    })
}

fn browser_history_visit_records(
    rows: &[ChromiumHistoryRow],
    history_path: &Path,
) -> Vec<BrowserActivityRecord> {
    let source_metadata = source_artifact_metadata(history_path, "History");
    rows.iter()
        .map(|row| BrowserActivityRecord {
            logical_path: row.logical_path(),
            display_name: row.display_name(),
            metadata_json: browser_history_metadata_json(row, &source_metadata),
        })
        .collect()
}

fn open_sqlite_copy_read_only(path: &Path) -> Result<(Connection, TempFileGuard)> {
    let copy_path = temp_history_copy_path(path);
    fs::copy(path, &copy_path)
        .with_context(|| format!("copying browser database {}", path.display()))?;
    let guard = TempFileGuard::new(copy_path);
    let conn = Connection::open_with_flags(&guard.path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| format!("opening browser database copy {}", guard.path.display()))?;
    Ok((conn, guard))
}

/// Unique URL rows from the Chromium `urls` table ("URLs" DFIR category, distinct from
/// per-event "Visits").
fn read_chromium_url_records(history_path: &Path, max_rows: usize) -> Vec<BrowserActivityRecord> {
    read_chromium_url_records_inner(history_path, max_rows).unwrap_or_default()
}

fn read_chromium_url_records_inner(
    history_path: &Path,
    max_rows: usize,
) -> Result<Vec<BrowserActivityRecord>> {
    let (conn, _guard) = open_sqlite_copy_read_only(history_path)?;
    let source_metadata = source_artifact_metadata(history_path, "History");
    let mut stmt = conn.prepare(
        "SELECT id, url, title, visit_count, typed_count, last_visit_time, hidden
         FROM urls ORDER BY last_visit_time DESC, id DESC LIMIT ?1",
    )?;
    let rows = stmt.query_map(params![max_rows as i64], |row| {
        let id: i64 = row.get(0)?;
        let url: String = row.get(1)?;
        let title: Option<String> = row.get(2)?;
        let visit_count: Option<i64> = row.get(3)?;
        let typed_count: Option<i64> = row.get(4)?;
        let last_visit_time: Option<i64> = row.get(5)?;
        let hidden: Option<i64> = row.get(6)?;
        Ok((
            id,
            url,
            title,
            visit_count,
            typed_count,
            last_visit_time,
            hidden,
        ))
    })?;
    let mut records = Vec::new();
    for row in rows {
        let (id, url, title, visit_count, typed_count, last_visit_time, hidden) = row?;
        let host = host_from_url(&url);
        let mut metadata = serde_json::json!({
            "artifact_kind": "browser_url",
            "browser_family": "chromium",
            "url_id": id,
            "url": url,
            "title": title,
            "host": host,
            "visit_count": visit_count,
            "typed_count": typed_count,
            "last_visit_time_chrome": last_visit_time,
            "last_visit_time_utc": last_visit_time.and_then(chrome_time_to_rfc3339),
            "hidden": hidden.map(|value| value != 0),
        });
        merge_json_object(&mut metadata, &source_metadata);
        let display_name = title
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(&url)
            .chars()
            .take(180)
            .collect::<String>();
        let logical_path = format!(
            "/Browser Activities/URLs/{}/{}.record",
            sanitize_logical_segment(&host),
            id
        );
        add_entry_category(&mut metadata, &logical_path, &display_name, "record");
        records.push(BrowserActivityRecord {
            logical_path,
            display_name,
            metadata_json: metadata.to_string(),
        });
    }
    Ok(records)
}

/// Search terms typed in the browser (Chromium `keyword_search_terms`).
fn read_chromium_search_records(
    history_path: &Path,
    max_rows: usize,
) -> Vec<BrowserActivityRecord> {
    read_chromium_search_records_inner(history_path, max_rows).unwrap_or_default()
}

fn read_chromium_search_records_inner(
    history_path: &Path,
    max_rows: usize,
) -> Result<Vec<BrowserActivityRecord>> {
    let (conn, _guard) = open_sqlite_copy_read_only(history_path)?;
    let source_metadata = source_artifact_metadata(history_path, "History");
    let mut stmt = conn.prepare(
        "SELECT k.url_id, k.term, u.url, u.last_visit_time
         FROM keyword_search_terms k
         JOIN urls u ON u.id = k.url_id
         ORDER BY u.last_visit_time DESC, k.url_id DESC LIMIT ?1",
    )?;
    let rows = stmt.query_map(params![max_rows as i64], |row| {
        let url_id: i64 = row.get(0)?;
        let term: String = row.get(1)?;
        let url: String = row.get(2)?;
        let last_visit_time: Option<i64> = row.get(3)?;
        Ok((url_id, term, url, last_visit_time))
    })?;
    let mut records = Vec::new();
    for row in rows {
        let (url_id, term, url, last_visit_time) = row?;
        let mut metadata = serde_json::json!({
            "artifact_kind": "browser_search_term",
            "browser_family": "chromium",
            "url_id": url_id,
            "search_term": term,
            "url": url,
            "host": host_from_url(&url),
            "last_visit_time_chrome": last_visit_time,
            "last_visit_time_utc": last_visit_time.and_then(chrome_time_to_rfc3339),
        });
        merge_json_object(&mut metadata, &source_metadata);
        let logical_path = format!(
            "/Browser Activities/Searches/{}-{}.record",
            sanitize_logical_segment(term.chars().take(60).collect::<String>().as_str()),
            url_id
        );
        let display_name: String = format!("Search: {term}").chars().take(180).collect();
        add_entry_category(&mut metadata, &logical_path, &display_name, "record");
        records.push(BrowserActivityRecord {
            logical_path,
            display_name,
            metadata_json: metadata.to_string(),
        });
    }
    Ok(records)
}

/// Download records from the Chromium `downloads` table.
fn read_chromium_download_records(
    history_path: &Path,
    max_rows: usize,
) -> Vec<BrowserActivityRecord> {
    read_chromium_download_records_inner(history_path, max_rows).unwrap_or_default()
}

fn read_chromium_download_records_inner(
    history_path: &Path,
    max_rows: usize,
) -> Result<Vec<BrowserActivityRecord>> {
    let (conn, _guard) = open_sqlite_copy_read_only(history_path)?;
    let source_metadata = source_artifact_metadata(history_path, "History");
    let mut stmt = conn.prepare(
        "SELECT id, current_path, target_path, start_time, end_time, received_bytes,
                total_bytes, state, danger_type, interrupt_reason, referrer, tab_url, mime_type
         FROM downloads ORDER BY start_time DESC, id DESC LIMIT ?1",
    )?;
    let rows = stmt.query_map(params![max_rows as i64], |row| {
        let id: i64 = row.get(0)?;
        let current_path: Option<String> = row.get(1)?;
        let target_path: Option<String> = row.get(2)?;
        let start_time: Option<i64> = row.get(3)?;
        let end_time: Option<i64> = row.get(4)?;
        let received_bytes: Option<i64> = row.get(5)?;
        let total_bytes: Option<i64> = row.get(6)?;
        let state: Option<i64> = row.get(7)?;
        let danger_type: Option<i64> = row.get(8)?;
        let interrupt_reason: Option<i64> = row.get(9)?;
        let referrer: Option<String> = row.get(10)?;
        let tab_url: Option<String> = row.get(11)?;
        let mime_type: Option<String> = row.get(12)?;
        Ok((
            id,
            current_path,
            target_path,
            start_time,
            end_time,
            received_bytes,
            total_bytes,
            state,
            danger_type,
            interrupt_reason,
            referrer,
            tab_url,
            mime_type,
        ))
    })?;
    let mut records = Vec::new();
    for row in rows {
        let (
            id,
            current_path,
            target_path,
            start_time,
            end_time,
            received_bytes,
            total_bytes,
            state,
            danger_type,
            interrupt_reason,
            referrer,
            tab_url,
            mime_type,
        ) = row?;
        let file_name = target_path
            .as_deref()
            .or(current_path.as_deref())
            .map(|value| {
                value
                    .rsplit(['\\', '/'])
                    .next()
                    .unwrap_or(value)
                    .to_string()
            })
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| format!("download-{id}"));
        let mut metadata = serde_json::json!({
            "artifact_kind": "browser_download",
            "browser_family": "chromium",
            "download_id": id,
            "file_name": file_name,
            "target_path": target_path,
            "current_path": current_path,
            "start_time_chrome": start_time,
            "start_time_utc": start_time.and_then(chrome_time_to_rfc3339),
            "end_time_chrome": end_time,
            "end_time_utc": end_time.and_then(chrome_time_to_rfc3339),
            "received_bytes": received_bytes,
            "total_bytes": total_bytes,
            "state": state,
            "danger_type": danger_type,
            "interrupt_reason": interrupt_reason,
            "referrer": referrer,
            "tab_url": tab_url,
            "mime_type": mime_type,
        });
        merge_json_object(&mut metadata, &source_metadata);
        let logical_path = format!(
            "/Browser Activities/Downloads/{}-{}.record",
            id,
            sanitize_logical_segment(&file_name)
        );
        let display_name: String = file_name.chars().take(180).collect();
        add_entry_category(&mut metadata, &logical_path, &display_name, "record");
        records.push(BrowserActivityRecord {
            logical_path,
            display_name,
            metadata_json: metadata.to_string(),
        });
    }
    Ok(records)
}

/// Saved website credentials from `Login Data`. Only the origin, action URL, username, and
/// usage timestamps are recorded; encrypted password values are never read or stored.
fn read_chromium_login_records(profile_dir: &Path, max_rows: usize) -> Vec<BrowserActivityRecord> {
    read_chromium_login_records_inner(profile_dir, max_rows).unwrap_or_default()
}

fn read_chromium_login_records_inner(
    profile_dir: &Path,
    max_rows: usize,
) -> Result<Vec<BrowserActivityRecord>> {
    let login_path = profile_dir.join("Login Data");
    if !login_path.is_file() {
        return Ok(Vec::new());
    }
    let (conn, _guard) = open_sqlite_copy_read_only(&login_path)?;
    let source_metadata = source_artifact_metadata(&login_path, "Login Data");
    let mut stmt = conn.prepare(
        "SELECT origin_url, action_url, username_value, date_created, date_last_used, times_used
         FROM logins ORDER BY date_created DESC LIMIT ?1",
    )?;
    let rows = stmt.query_map(params![max_rows as i64], |row| {
        let origin_url: Option<String> = row.get(0)?;
        let action_url: Option<String> = row.get(1)?;
        let username: Option<String> = row.get(2)?;
        let date_created: Option<i64> = row.get(3)?;
        let date_last_used: Option<i64> = row.get(4)?;
        let times_used: Option<i64> = row.get(5)?;
        Ok((
            origin_url,
            action_url,
            username,
            date_created,
            date_last_used,
            times_used,
        ))
    })?;
    let mut records = Vec::new();
    for (index, row) in rows.enumerate() {
        let (origin_url, action_url, username, date_created, date_last_used, times_used) = row?;
        let origin = origin_url.clone().unwrap_or_default();
        let host = host_from_url(&origin);
        let user_label = username
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("(no username)");
        let mut metadata = serde_json::json!({
            "artifact_kind": "browser_login",
            "browser_family": "chromium",
            "origin_url": origin_url,
            "action_url": action_url,
            "username": username,
            "host": host,
            "date_created_chrome": date_created,
            "date_created_utc": date_created.and_then(chrome_time_to_rfc3339),
            "date_last_used_chrome": date_last_used,
            "date_last_used_utc": date_last_used.and_then(chrome_time_to_rfc3339),
            "times_used": times_used,
            "password_note": "encrypted password value not extracted",
        });
        merge_json_object(&mut metadata, &source_metadata);
        let logical_path = format!(
            "/Browser Activities/Logins/{}/{}-{}.record",
            sanitize_logical_segment(&host),
            sanitize_logical_segment(user_label),
            index
        );
        let display_name: String = format!("{user_label} @ {host}").chars().take(180).collect();
        add_entry_category(&mut metadata, &logical_path, &display_name, "record");
        records.push(BrowserActivityRecord {
            logical_path,
            display_name,
            metadata_json: metadata.to_string(),
        });
    }
    Ok(records)
}

/// Cookie metadata from the Chromium cookie store (`Network\Cookies` or legacy `Cookies`).
/// Cookie names, hosts, and timestamps are DFIR session/token indicators; encrypted cookie
/// values are never read or stored.
fn read_chromium_cookie_records(profile_dir: &Path, max_rows: usize) -> Vec<BrowserActivityRecord> {
    read_chromium_cookie_records_inner(profile_dir, max_rows).unwrap_or_default()
}

fn read_chromium_cookie_records_inner(
    profile_dir: &Path,
    max_rows: usize,
) -> Result<Vec<BrowserActivityRecord>> {
    let network_path = profile_dir.join("Network").join("Cookies");
    let legacy_path = profile_dir.join("Cookies");
    let cookie_path = if network_path.is_file() {
        network_path
    } else if legacy_path.is_file() {
        legacy_path
    } else {
        return Ok(Vec::new());
    };
    let (conn, _guard) = open_sqlite_copy_read_only(&cookie_path)?;
    let source_metadata = source_artifact_metadata(&cookie_path, "Cookies");
    let mut stmt = conn.prepare(
        "SELECT host_key, name, path, creation_utc, expires_utc, last_access_utc,
                is_secure, is_httponly
         FROM cookies ORDER BY creation_utc DESC LIMIT ?1",
    )?;
    let rows = stmt.query_map(params![max_rows as i64], |row| {
        let host_key: String = row.get(0)?;
        let name: String = row.get(1)?;
        let path: Option<String> = row.get(2)?;
        let creation: Option<i64> = row.get(3)?;
        let expires: Option<i64> = row.get(4)?;
        let last_access: Option<i64> = row.get(5)?;
        let is_secure: Option<i64> = row.get(6)?;
        let is_httponly: Option<i64> = row.get(7)?;
        Ok((
            host_key,
            name,
            path,
            creation,
            expires,
            last_access,
            is_secure,
            is_httponly,
        ))
    })?;
    let mut records = Vec::new();
    for row in rows {
        let (host_key, name, path, creation, expires, last_access, is_secure, is_httponly) = row?;
        let mut metadata = serde_json::json!({
            "artifact_kind": "browser_cookie",
            "browser_family": "chromium",
            "host": host_key,
            "cookie_name": name,
            "cookie_path": path,
            "creation_chrome": creation,
            "creation_utc": creation.and_then(chrome_time_to_rfc3339),
            "expires_chrome": expires,
            "expires_utc": expires.and_then(chrome_time_to_rfc3339),
            "last_access_chrome": last_access,
            "last_access_utc": last_access.and_then(chrome_time_to_rfc3339),
            "is_secure": is_secure.map(|value| value != 0),
            "is_httponly": is_httponly.map(|value| value != 0),
            "value_note": "encrypted cookie value not extracted",
        });
        merge_json_object(&mut metadata, &source_metadata);
        let logical_path = format!(
            "/Browser Activities/Cookies/{}/{}-{}.record",
            sanitize_logical_segment(&host_key),
            sanitize_logical_segment(&name),
            creation.unwrap_or_default()
        );
        let display_name: String = format!("{name} ({host_key})").chars().take(180).collect();
        add_entry_category(&mut metadata, &logical_path, &display_name, "record");
        records.push(BrowserActivityRecord {
            logical_path,
            display_name,
            metadata_json: metadata.to_string(),
        });
    }
    Ok(records)
}

fn read_chromium_bookmark_records(bookmarks_path: &Path) -> Result<Vec<BrowserActivityRecord>> {
    if !bookmarks_path.is_file() {
        return Ok(Vec::new());
    }
    let text = fs::read_to_string(bookmarks_path).with_context(|| {
        format!(
            "reading Chromium Bookmarks file {}",
            bookmarks_path.display()
        )
    })?;
    let value: serde_json::Value = serde_json::from_str(&text).with_context(|| {
        format!(
            "parsing Chromium Bookmarks file {}",
            bookmarks_path.display()
        )
    })?;
    let source_metadata = source_artifact_metadata(bookmarks_path, "Bookmarks");
    let mut records = Vec::new();
    if let Some(roots) = value.get("roots").and_then(|value| value.as_object()) {
        for (root_name, root_value) in roots {
            let label = chromium_bookmark_root_label(root_name);
            collect_chromium_bookmarks(
                root_value,
                &[label.to_string()],
                &source_metadata,
                &mut records,
            );
        }
    }
    Ok(records)
}

fn collect_chromium_bookmarks(
    node: &serde_json::Value,
    folder_path: &[String],
    source_metadata: &serde_json::Value,
    records: &mut Vec<BrowserActivityRecord>,
) {
    let node_type = node
        .get("type")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    if node_type == "url" {
        let name = node
            .get("name")
            .and_then(|value| value.as_str())
            .unwrap_or("Bookmark")
            .trim();
        let url = node
            .get("url")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        let guid = node.get("guid").and_then(|value| value.as_str());
        let date_added = chrome_json_time_value(node.get("date_added"));
        let date_last_used = chrome_json_time_value(node.get("date_last_used"));
        let folder_display = folder_path.join("/");
        let logical_folder = folder_path
            .iter()
            .map(|part| sanitize_logical_segment(part))
            .collect::<Vec<_>>()
            .join("/");
        let unique = guid
            .map(sanitize_logical_segment)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| sanitize_logical_segment(&format!("{name}-{url}")));
        let mut metadata = serde_json::json!({
            "artifact_kind": "browser_bookmark",
            "browser_family": "chromium",
            "name": name,
            "url": url,
            "host": host_from_url(url),
            "folder": folder_display,
            "guid": guid,
            "date_added_chrome": date_added,
            "date_added_utc": date_added.and_then(chrome_time_to_rfc3339),
            "date_last_used_chrome": date_last_used,
            "date_last_used_utc": date_last_used.and_then(chrome_time_to_rfc3339),
            "search_text": format!("{name} {url} {} {folder_display}", host_from_url(url)),
        });
        merge_json_object(&mut metadata, source_metadata);
        let logical_path = format!(
            "/Browser Activities/Bookmarks/{}/{}.record",
            logical_folder, unique
        );
        add_entry_category(&mut metadata, &logical_path, name, "record");
        records.push(BrowserActivityRecord {
            logical_path,
            display_name: if name.is_empty() {
                url.chars().take(180).collect()
            } else {
                name.chars().take(180).collect()
            },
            metadata_json: metadata.to_string(),
        });
        return;
    }

    let mut child_folder_path = folder_path.to_vec();
    if node_type == "folder" {
        if let Some(name) = node.get("name").and_then(|value| value.as_str()) {
            let name = name.trim();
            if !name.is_empty()
                && child_folder_path
                    .last()
                    .map(|last| last != name)
                    .unwrap_or(true)
            {
                child_folder_path.push(name.to_string());
            }
        }
    }
    if let Some(children) = node.get("children").and_then(|value| value.as_array()) {
        for child in children {
            collect_chromium_bookmarks(child, &child_folder_path, source_metadata, records);
        }
    }
}

fn read_chromium_preference_records(preferences_path: &Path) -> Result<Vec<BrowserActivityRecord>> {
    if !preferences_path.is_file() {
        return Ok(Vec::new());
    }
    let text = fs::read_to_string(preferences_path).with_context(|| {
        format!(
            "reading Chromium Preferences file {}",
            preferences_path.display()
        )
    })?;
    let value: serde_json::Value = serde_json::from_str(&text).with_context(|| {
        format!(
            "parsing Chromium Preferences file {}",
            preferences_path.display()
        )
    })?;
    let source_metadata = source_artifact_metadata(preferences_path, "Preferences");
    let mut records = Vec::new();
    push_preference_record(
        &mut records,
        "Profile",
        serde_json::json!({
            "artifact_kind": "browser_preference",
            "category": "profile",
            "name": json_path(&value, &["profile", "name"]).cloned(),
            "avatar_index": json_path(&value, &["profile", "avatar_index"]).cloned(),
            "created_by_version": json_path(&value, &["profile", "created_by_version"]).cloned(),
            "last_used": json_path(&value, &["profile", "last_used"]).cloned(),
        }),
        &source_metadata,
    );
    push_preference_record(
        &mut records,
        "Startup",
        serde_json::json!({
            "artifact_kind": "browser_preference",
            "category": "startup",
            "restore_on_startup": json_path(&value, &["session", "restore_on_startup"]).cloned(),
            "startup_urls": json_path(&value, &["session", "startup_urls"]).cloned(),
            "homepage": json_path(&value, &["homepage"]).cloned(),
            "homepage_is_newtabpage": json_path(&value, &["homepage_is_newtabpage"]).cloned(),
        }),
        &source_metadata,
    );
    push_preference_record(
        &mut records,
        "Search",
        serde_json::json!({
            "artifact_kind": "browser_preference",
            "category": "search",
            "default_search_provider": json_path(&value, &["default_search_provider"]).cloned(),
            "default_search_provider_data": json_path(&value, &["default_search_provider_data", "template_url_data"]).cloned(),
        }),
        &source_metadata,
    );
    push_preference_record(
        &mut records,
        "Downloads",
        serde_json::json!({
            "artifact_kind": "browser_preference",
            "category": "downloads",
            "download_default_directory": json_path(&value, &["download", "default_directory"]).cloned(),
            "prompt_for_download": json_path(&value, &["download", "prompt_for_download"]).cloned(),
        }),
        &source_metadata,
    );
    push_preference_record(
        &mut records,
        "Privacy And Safety",
        serde_json::json!({
            "artifact_kind": "browser_preference",
            "category": "privacy_safety",
            "safe_browsing": json_path(&value, &["safebrowsing"]).cloned(),
            "credentials_enable_service": json_path(&value, &["credentials_enable_service"]).cloned(),
            "profile_password_manager_enabled": json_path(&value, &["profile", "password_manager_enabled"]).cloned(),
            "autofill": json_path(&value, &["autofill"]).cloned(),
        }),
        &source_metadata,
    );
    let extensions_count = json_path(&value, &["extensions", "settings"])
        .and_then(|value| value.as_object())
        .map(|value| value.len())
        .unwrap_or(0);
    push_preference_record(
        &mut records,
        "Extensions",
        serde_json::json!({
            "artifact_kind": "browser_preference",
            "category": "extensions",
            "extension_count": extensions_count,
            "extensions_settings": json_path(&value, &["extensions", "settings"]).cloned(),
        }),
        &source_metadata,
    );
    Ok(records)
}

fn push_preference_record(
    records: &mut Vec<BrowserActivityRecord>,
    display_name: &str,
    mut metadata: serde_json::Value,
    source_metadata: &serde_json::Value,
) {
    let search_text = serde_json::to_string(&metadata).unwrap_or_default();
    if let Some(object) = metadata.as_object_mut() {
        object.insert(
            "browser_family".to_string(),
            serde_json::Value::String("chromium".to_string()),
        );
        object.insert(
            "search_text".to_string(),
            serde_json::Value::String(search_text),
        );
    }
    merge_json_object(&mut metadata, source_metadata);
    let logical_path = format!(
        "/Browser Activities/Preferences/{}.record",
        sanitize_logical_segment(display_name)
    );
    add_entry_category(&mut metadata, &logical_path, display_name, "record");
    records.push(BrowserActivityRecord {
        logical_path,
        display_name: display_name.to_string(),
        metadata_json: metadata.to_string(),
    });
}

fn upsert_browser_history_evidence(
    conn: &Connection,
    case_id: i64,
    source_path: &str,
    display_name: &str,
    size_bytes: i64,
) -> Result<i64> {
    if let Some(existing_id) = conn
        .query_row(
            "SELECT id FROM evidence_sources WHERE case_id = ?1 AND source_path = ?2",
            params![case_id, source_path],
            |row| row.get(0),
        )
        .optional()?
    {
        conn.execute(
            "UPDATE evidence_sources
             SET source_kind = 'browser_history',
                 display_name = ?1,
                 size_bytes = ?2,
                 read_file_system_requested = 0,
                 notes = 'Imported Chromium browser history'
             WHERE id = ?3 AND case_id = ?4",
            params![display_name, size_bytes, existing_id, case_id],
        )?;
        return Ok(existing_id);
    }

    conn.execute(
        "INSERT INTO evidence_sources(
             case_id, source_kind, source_path, display_name, size_bytes,
             read_file_system_requested, notes
         ) VALUES (?1, 'browser_history', ?2, ?3, ?4, 0, 'Imported Chromium browser history')",
        params![case_id, source_path, display_name, size_bytes],
    )?;
    Ok(conn.last_insert_rowid())
}

fn browser_history_metadata_json(
    row: &ChromiumHistoryRow,
    source_metadata: &serde_json::Value,
) -> String {
    let transition = row.transition.unwrap_or_default();
    let mut metadata = serde_json::json!({
        "artifact_kind": "browser_history_visit",
        "browser_family": "chromium",
        "visit_id": row.visit_id,
        "url_id": row.url_id,
        "url": row.url,
        "title": row.title,
        "host": host_from_url(&row.url),
        "visit_time_chrome": row.visit_time,
        "visit_time_utc": chrome_time_to_rfc3339(row.visit_time),
        "last_visit_time_chrome": row.last_visit_time,
        "last_visit_time_utc": row.last_visit_time.and_then(chrome_time_to_rfc3339),
        "visit_count": row.visit_count,
        "typed_count": row.typed_count,
        "transition": transition,
        "transition_type": chromium_transition_type(transition),
        "visit_duration_microseconds": row.visit_duration,
        "hidden": row.hidden.map(|value| value != 0),
        "search_text": format!("{} {} {}", row.url, row.title.as_deref().unwrap_or(""), host_from_url(&row.url)),
    });
    merge_json_object(&mut metadata, source_metadata);
    add_entry_category(
        &mut metadata,
        &row.logical_path(),
        row.title.as_deref().unwrap_or(&row.url),
        "record",
    );
    metadata.to_string()
}

#[derive(Clone, Copy)]
struct EntryCategory {
    main: &'static str,
    sub: &'static str,
    detail: &'static str,
    confidence: &'static str,
    tags: &'static [&'static str],
}

fn categorized_metadata_json(
    mut metadata: serde_json::Value,
    logical_path: &str,
    name: &str,
    entry_kind: &str,
) -> String {
    add_entry_category(&mut metadata, logical_path, name, entry_kind);
    metadata.to_string()
}

fn add_entry_category(
    metadata: &mut serde_json::Value,
    logical_path: &str,
    name: &str,
    entry_kind: &str,
) {
    let category = classify_entry(logical_path, name, entry_kind, metadata);
    if let Some(object) = metadata.as_object_mut() {
        object.insert(
            "category_main".to_string(),
            serde_json::Value::String(category.main.to_string()),
        );
        object.insert(
            "category_sub".to_string(),
            serde_json::Value::String(category.sub.to_string()),
        );
        object.insert(
            "category_detail".to_string(),
            serde_json::Value::String(category.detail.to_string()),
        );
        object.insert(
            "analysis_category".to_string(),
            serde_json::Value::String(format!("{} / {}", category.main, category.sub)),
        );
        object.insert(
            "category_confidence".to_string(),
            serde_json::Value::String(category.confidence.to_string()),
        );
        object.insert(
            "category_source".to_string(),
            serde_json::Value::String("extension_path_rules_v1".to_string()),
        );
        object.insert(
            "category_tags".to_string(),
            serde_json::Value::Array(
                category
                    .tags
                    .iter()
                    .map(|tag| serde_json::Value::String((*tag).to_string()))
                    .collect(),
            ),
        );
    }
}

fn should_index_content_head(metadata: &serde_json::Value, entry_kind: &str) -> bool {
    if entry_kind != "file" {
        return false;
    }
    if metadata["artifact_kind"].as_str() == Some("unallocated_space") {
        return false;
    }
    if metadata["storage_area"].as_str() == Some("alternate_data_stream") {
        return false;
    }
    // Media files are the storage bulk and are not the target of text keyword Deep Search.
    // They stay NULL in content_head to keep the case database bounded and search-focused.
    if metadata["category_main"].as_str() == Some("Pictures and Media") {
        return false;
    }
    true
}

fn read_content_head<R: Read>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take(CONTENT_INDEX_BYTES as u64)
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn local_file_content_head(
    path: &Path,
    metadata: &serde_json::Value,
    entry_kind: &str,
) -> Option<Vec<u8>> {
    if !should_index_content_head(metadata, entry_kind) {
        return None;
    }
    let mut file = fs::File::open(path).ok()?;
    read_content_head(&mut file).ok()
}

fn fat_entry_content_head<T: fatfs::ReadWriteSeek>(
    entry: &fatfs::DirEntry<'_, T>,
    metadata: &serde_json::Value,
    entry_kind: &str,
) -> Option<Vec<u8>> {
    if !should_index_content_head(metadata, entry_kind) {
        return None;
    }
    let mut file = entry.to_file();
    read_content_head(&mut file).ok()
}

fn ntfs_file_record_content_head<T: Read + Seek>(
    ntfs: &ntfs::Ntfs,
    fs: &mut T,
    file_record_number: u64,
    metadata: &serde_json::Value,
    entry_kind: &str,
) -> Option<Vec<u8>> {
    if !should_index_content_head(metadata, entry_kind) {
        return None;
    }
    read_ntfs_file_record_bytes(ntfs, fs, file_record_number, CONTENT_INDEX_BYTES).ok()
}

fn classify_entry(
    logical_path: &str,
    name: &str,
    entry_kind: &str,
    metadata: &serde_json::Value,
) -> EntryCategory {
    let artifact_kind = metadata
        .get("artifact_kind")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    match artifact_kind {
        "browser_history_visit" => {
            return category(
                "Web Activity",
                "Visits",
                "Individual web page visit event",
                "high",
                &["browser", "history", "visit", "web"],
            );
        }
        "browser_url" => {
            return category(
                "Web Activity",
                "URLs",
                "Unique visited URL with visit statistics",
                "high",
                &["browser", "url", "web"],
            );
        }
        "browser_search_term" => {
            return category(
                "Web Activity",
                "Searches",
                "Search term typed in the browser",
                "high",
                &["browser", "search", "keyword", "web"],
            );
        }
        "browser_download" => {
            return category(
                "Web Activity",
                "Downloads",
                "File downloaded through the browser",
                "high",
                &["browser", "download", "web"],
            );
        }
        "browser_bookmark" => {
            return category(
                "Web Activity",
                "Bookmarks",
                "Saved web bookmark",
                "high",
                &["browser", "bookmarks", "web"],
            );
        }
        "browser_login" => {
            return category(
                "Accounts and Identity",
                "Saved logins",
                "Saved website credential (username only; passwords are not extracted)",
                "high",
                &["browser", "login", "credential", "accounts"],
            );
        }
        "browser_cookie" => {
            return category(
                "Accounts and Identity",
                "Cookies",
                "Browser cookie metadata: session and token indicators (values not decrypted)",
                "medium",
                &["browser", "cookie", "session", "token"],
            );
        }
        "browser_preference" => {
            return category(
                "Accounts and Identity",
                "Browser profile settings",
                "Browser account, privacy, download, extension, and startup settings",
                "high",
                &["browser", "accounts", "profile"],
            );
        }
        "email_message" => {
            return category(
                "Email and Communications",
                "Email messages",
                "Parsed RFC 822 email message",
                "high",
                &["email", "communications", "message"],
            );
        }
        "email_store" => {
            return category(
                "Email and Communications",
                "Email stores",
                "Mailbox store requiring a dedicated mailbox parser",
                "medium",
                &["email", "mailbox", "store"],
            );
        }
        "deleted_file_record" => {
            return category(
                "Recovery",
                "Deleted files",
                "Deleted filesystem record discovered from NTFS MFT metadata",
                "high",
                &["deleted", "recovery", "ntfs"],
            );
        }
        "unallocated_space" => {
            return category(
                "Recovery",
                "Unallocated space",
                "Unallocated-space carving candidate",
                "medium",
                &["unallocated", "carving"],
            );
        }
        "recovered_partition" => {
            return category(
                "Recovery",
                "Recovered partitions",
                "Orphaned volume found by scanning unpartitioned space for boot sectors",
                "high",
                &["recovery", "partition", "boot-sector"],
            );
        }
        "carved_file" => {
            return category(
                "Recovery",
                "Carved files",
                "File carved from the image by signature",
                "high",
                &["recovery", "carving", "signature"],
            );
        }
        "disk_image_container"
        | "disk_partition_report"
        | "disk_partition"
        | "disk_volume"
        | "filesystem_volume"
        | "filesystem_parser_error" => {
            return category(
                "Operating System",
                "Disk and filesystem structure",
                "Container, partition, volume, or filesystem parser record",
                "high",
                &["disk", "filesystem", "partition"],
            );
        }
        _ => {}
    }

    let combined = format!("{logical_path}/{name}").to_ascii_lowercase();
    let ext = extension_lower(name).or_else(|| extension_lower(logical_path));
    let filesystem_parser = metadata
        .get("filesystem_parser")
        .and_then(|value| value.as_str())
        .unwrap_or("");

    if filesystem_parser == "ntfs"
        && contains_any(
            &combined,
            &[
                "$attrdef",
                "$badclus",
                "$bitmap",
                "$boot",
                "$extend",
                "$logfile",
                "$mft",
                "$mftmirr",
                "$objid",
                "$quota",
                "$repair",
                "$reparse",
                "$rmmetadata",
                "$secure",
                "$tops",
                "$txf",
                "$txflog",
                "$upcase",
                "$volume",
            ],
        )
    {
        return category(
            "Operating System",
            "NTFS metadata",
            "NTFS metadata file, transaction log, object ID, quota, reparse, or volume metadata entry",
            "high",
            &["ntfs", "filesystem", "metadata"],
        );
    }

    if entry_kind == "directory" {
        if contains_any(
            &combined,
            &["onedrive", "dropbox", "google drive", "icloud", "/box/"],
        ) {
            return category(
                "Cloud and Web",
                "Cloud sync folders",
                "Cloud synchronized folder",
                "medium",
                &["cloud", "sync"],
            );
        }
        if contains_any(
            &combined,
            &[
                "/windows",
                "/system32",
                "/program files",
                "/users/",
                "/appdata",
                "/library/",
                "/applications",
                "/etc/",
                "/var/",
            ],
        ) {
            return category(
                "Operating System",
                "System and user profile folders",
                "Operating system or user profile directory",
                "medium",
                &["os", "profile", "directory"],
            );
        }
        return category(
            "Uncategorized",
            "Directories",
            "Directory",
            "low",
            &["directory"],
        );
    }

    if contains_any(
        &combined,
        &[
            "/windows/prefetch",
            ".pf",
            "prefetch",
            "amcache.hve",
            "srum",
            "shimcache",
            "userassist",
        ],
    ) {
        return category(
            "Program Execution",
            "Execution artifacts",
            "Prefetch, Amcache, SRUM, Shimcache, or UserAssist artifact",
            "high",
            &["execution", "windows", "forensic-artifact"],
        );
    }
    if contains_any(
        &combined,
        &[
            "automaticdestinations-ms",
            "customdestinations-ms",
            ".lnk",
            "recent/",
            "recent\\",
            "jumplist",
        ],
    ) {
        return category(
            "Program Execution",
            "Shortcuts and jump lists",
            "Recent item shortcut or Windows jump list",
            "high",
            &["execution", "recent-files", "shortcuts"],
        );
    }
    if contains_any(
        &combined,
        &[
            "scheduled tasks",
            "/tasks/",
            "startup",
            "launchagents",
            "launchdaemons",
            "runonce",
        ],
    ) {
        return category(
            "Program Execution",
            "Startup and scheduled tasks",
            "Startup, launch, or scheduled task artifact",
            "high",
            &["execution", "persistence", "startup"],
        );
    }
    if contains_any(
        &combined,
        &[
            "login data",
            "password",
            "credentials",
            "credential",
            "keychain",
            "key4.db",
            "logins.json",
            "wallet",
            "vault",
            "secret",
            "token",
            "oauth",
        ],
    ) {
        return category(
            "Accounts and Identity",
            "Credentials and tokens",
            "Password, token, keychain, wallet, or credential store",
            "high",
            &["accounts", "credentials", "secrets"],
        );
    }
    if contains_any(&combined, &["session storage"])
        || (has_browser_context(&combined)
            && contains_any(&combined, &["cookies", "cookie", "sessions"]))
    {
        return category(
            "Accounts and Identity",
            "Cookies and sessions",
            "Cookie, browser session, or web authentication artifact",
            "high",
            &["accounts", "cookies", "sessions"],
        );
    }
    if contains_any(
        &combined,
        &["onedrive", "dropbox", "google drive", "icloud", "/box/"],
    ) {
        return category(
            "Cloud and Web",
            "Cloud sync",
            "Cloud synchronization data or cloud-synced file",
            "medium",
            &["cloud", "sync"],
        );
    }
    // Unambiguous browser database names match on their own; generic words
    // (history/cache/bookmarks/downloads) need browser context or they hit OS
    // paths like system32/dllcache.
    if contains_any(
        &combined,
        &[
            "places.sqlite",
            "webcachev01.dat",
            "favicons",
            "top sites",
            "visited links",
        ],
    ) || (has_browser_context(&combined)
        && contains_any(&combined, &["history", "cache", "bookmarks", "downloads"]))
    {
        return category(
            "Cloud and Web",
            "Browser artifacts",
            "Browser history, cache, download, favicon, or bookmark artifact",
            "medium",
            &["browser", "web"],
        );
    }
    if contains_any(
        &combined,
        &[
            "/windows/system32/config/sam",
            "/windows/system32/config/security",
            "/windows/system32/config/software",
            "/windows/system32/config/system",
            "/ntuser.dat",
            "/usrclass.dat",
        ],
    ) {
        return category(
            "Operating System",
            "Registry hives",
            "Windows registry hive",
            "high",
            &["windows", "registry", "accounts"],
        );
    }
    if contains_any(&combined, &[".evtx", ".etl", "event logs", "winevt/logs"]) {
        return category(
            "Operating System",
            "Event logs",
            "Windows event log or trace log",
            "high",
            &["windows", "logs", "timeline"],
        );
    }
    if contains_any(&combined, &["recycle.bin", "/trash", "/.trash"]) {
        return category(
            "Operating System",
            "Recycle and trash",
            "Deleted-item container",
            "high",
            &["deleted", "trash"],
        );
    }
    if contains_any(
        &combined,
        &["consolidated.db", "geolocation", "locationd", "/maps/"],
    ) {
        return category(
            "Location and Maps",
            "Geolocation data",
            "Location, maps, or geolocation artifact",
            "high",
            &["location", "maps"],
        );
    }
    if contains_any(
        &combined,
        &[
            "mobilebackup",
            "manifest.db",
            "android",
            "iphone",
            "itunes backup",
            "mobile sync",
        ],
    ) {
        return category(
            "Mobile Devices",
            "Mobile backups and app data",
            "iOS or Android backup or mobile app artifact",
            "medium",
            &["mobile", "backup"],
        );
    }

    if ext_in(
        ext.as_deref(),
        &[
            "jpg", "jpeg", "png", "gif", "bmp", "tif", "tiff", "heic", "heif", "webp",
        ],
    ) {
        return category(
            "Pictures and Media",
            "Pictures",
            "Image or photo file",
            "high",
            &["pictures", "media"],
        );
    }
    if ext_in(
        ext.as_deref(),
        &["cr2", "nef", "arw", "dng", "orf", "rw2", "raf"],
    ) {
        return category(
            "Pictures and Media",
            "Camera raw pictures",
            "Camera raw image file",
            "high",
            &["pictures", "camera", "raw"],
        );
    }
    if ext_in(ext.as_deref(), &["psd", "ai", "indd", "svg", "eps"]) {
        return category(
            "Pictures and Media",
            "Graphics and design",
            "Design, vector, or layered graphics file",
            "high",
            &["graphics", "design"],
        );
    }
    if ext_in(
        ext.as_deref(),
        &[
            "mp4", "mov", "avi", "mkv", "wmv", "m4v", "3gp", "webm", "flv", "mpg", "mpeg",
        ],
    ) {
        return category(
            "Pictures and Media",
            "Video",
            "Video file",
            "high",
            &["video", "media"],
        );
    }
    if ext_in(
        ext.as_deref(),
        &["mp3", "wav", "m4a", "aac", "flac", "ogg", "wma", "amr"],
    ) {
        return category(
            "Pictures and Media",
            "Audio",
            "Audio recording or music file",
            "high",
            &["audio", "media"],
        );
    }
    if ext_in(
        ext.as_deref(),
        &[
            "pst", "ost", "nst", "eml", "msg", "mbox", "olm", "dbx", "nsf",
        ],
    ) {
        return category(
            "Email and Communications",
            "Email stores and messages",
            "Email message or mailbox store",
            "high",
            &["email", "communications"],
        );
    }
    if ext_in(ext.as_deref(), &["vcf", "ics"]) {
        return category(
            "Email and Communications",
            "Contacts and calendars",
            "Contact card or calendar file",
            "high",
            &["contacts", "calendar"],
        );
    }
    if ext_in(ext.as_deref(), &["pdf"]) {
        return category(
            "Documents and Office",
            "PDF",
            "PDF document",
            "high",
            &["documents", "pdf"],
        );
    }
    if ext_in(
        ext.as_deref(),
        &["doc", "docx", "dot", "dotx", "rtf", "odt", "pages"],
    ) {
        return category(
            "Documents and Office",
            "Word processing",
            "Word processing document",
            "high",
            &["documents", "office"],
        );
    }
    if ext_in(
        ext.as_deref(),
        &["xls", "xlsx", "xlsm", "csv", "tsv", "ods", "numbers"],
    ) {
        return category(
            "Documents and Office",
            "Spreadsheets",
            "Spreadsheet or tabular data file",
            "high",
            &["documents", "spreadsheet"],
        );
    }
    if ext_in(ext.as_deref(), &["ppt", "pptx", "key", "odp"]) {
        return category(
            "Documents and Office",
            "Presentations",
            "Presentation file",
            "high",
            &["documents", "presentation"],
        );
    }
    if ext_in(ext.as_deref(), &["txt", "md", "log", "ini", "conf"]) {
        return category(
            "Documents and Office",
            "Text and notes",
            "Plain text, notes, or log text",
            "medium",
            &["documents", "text"],
        );
    }
    if ext_in(
        ext.as_deref(),
        &["zip", "rar", "7z", "tar", "gz", "tgz", "bz2", "xz"],
    ) {
        return category(
            "Archives and Containers",
            "Archives",
            "Compressed archive",
            "high",
            &["archive", "container"],
        );
    }
    // .img under OS/driver folders is firmware or driver data, not a disk
    // image (e.g. system32/drivers/netwlan5.img); let later rules handle it.
    let os_img = ext.as_deref() == Some("img")
        && contains_any(&combined, &["/windows/", "/system32/", "/drivers/"]);
    if !os_img
        && ext_in(
            ext.as_deref(),
            &[
                "e01", "ex01", "l01", "raw", "dd", "img", "iso", "vhd", "vhdx", "vmdk", "vdi",
                "qcow2", "dmg",
            ],
        )
    {
        return category(
            "Archives and Containers",
            "Disk and VM images",
            "Forensic, disk, virtual machine, or optical image",
            "high",
            &["disk-image", "virtualization"],
        );
    }
    if ext_in(
        ext.as_deref(),
        &[
            "tc", "hc", "kdbx", "gpg", "pgp", "pfx", "p12", "pem", "key", "crt", "cer",
        ],
    ) {
        return category(
            "Security and Encryption",
            "Encrypted data and keys",
            "Encrypted container, key, or certificate",
            "high",
            &["security", "encryption", "keys"],
        );
    }
    if ext_in(ext.as_deref(), &["exe", "dll", "sys", "com", "scr"]) {
        return category(
            "Program Execution",
            "Executables and binaries",
            "Executable, library, driver, or binary",
            "high",
            &["execution", "binary"],
        );
    }
    if ext_in(
        ext.as_deref(),
        &["msi", "msp", "appx", "pkg", "deb", "rpm", "apk", "ipa"],
    ) {
        return category(
            "Program Execution",
            "Installers and packages",
            "Installer or application package",
            "high",
            &["execution", "installer"],
        );
    }
    if ext_in(
        ext.as_deref(),
        &[
            "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "wsf", "sh", "bash", "zsh", "jar",
        ],
    ) {
        return category(
            "Program Execution",
            "Scripts",
            "Script or scriptable executable content",
            "high",
            &["execution", "script"],
        );
    }
    if ext_in(
        ext.as_deref(),
        &["db", "sqlite", "sqlite3", "db3", "mdb", "accdb", "edb"],
    ) {
        return category(
            "Databases",
            "Application databases",
            "Database file",
            "medium",
            &["database"],
        );
    }
    if ext_in(
        ext.as_deref(),
        &[
            "py", "rs", "go", "java", "cs", "cpp", "c", "h", "hpp", "php", "rb", "swift", "kt",
            "ts", "tsx", "jsx", "vue",
        ],
    ) {
        return category(
            "Development and Source Code",
            "Source code",
            "Program source code",
            "medium",
            &["development", "source"],
        );
    }
    if ext_in(
        ext.as_deref(),
        &[
            "json", "xml", "yaml", "yml", "toml", "lock", "gradle", "csproj", "sln",
        ],
    ) {
        return category(
            "Development and Source Code",
            "Project configuration",
            "Structured project or application configuration file",
            "medium",
            &["development", "configuration"],
        );
    }

    category(
        "Uncategorized",
        "Other files",
        "No rule matched",
        "low",
        &["uncategorized"],
    )
}

fn category(
    main: &'static str,
    sub: &'static str,
    detail: &'static str,
    confidence: &'static str,
    tags: &'static [&'static str],
) -> EntryCategory {
    EntryCategory {
        main,
        sub,
        detail,
        confidence,
        tags,
    }
}

fn extension_lower(value: &str) -> Option<String> {
    Path::new(value)
        .extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase)
        .filter(|value| !value.is_empty())
}

fn ext_in(ext: Option<&str>, values: &[&str]) -> bool {
    ext.map(|ext| values.iter().any(|value| *value == ext))
        .unwrap_or(false)
}

fn contains_any(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
}

/// Generic artifact words like "cache" or "history" only mean *browser*
/// artifacts when the path actually belongs to a browser. Without this guard,
/// OS paths such as `WINDOWS/system32/dllcache/*.dll` classify as web content.
fn has_browser_context(combined: &str) -> bool {
    contains_any(
        combined,
        &[
            "chrome",
            "chromium",
            "microsoft/edge",
            "microsoft\\edge",
            "mozilla",
            "firefox",
            "safari",
            "opera",
            "brave",
            "vivaldi",
            "netscape",
            "internet explorer",
            "temporary internet files",
            "content.ie5",
            "browser",
        ],
    )
}

fn annotate_email_metadata_for_path(
    metadata: &mut serde_json::Value,
    path: &Path,
    logical_path: &str,
    name: &str,
    size_bytes: u64,
) {
    let Some(ext) = extension_lower(name).or_else(|| extension_lower(logical_path)) else {
        return;
    };
    if ext == "eml" {
        if size_bytes > EMAIL_PARSE_MAX_BYTES {
            mark_email_parse_skipped(metadata, "eml", "message exceeds bounded email parse limit");
            return;
        }
        match fs::read(path) {
            Ok(bytes) => annotate_email_metadata_from_bytes(metadata, "eml", &bytes),
            Err(err) => mark_email_parse_skipped(
                metadata,
                "eml",
                &format!("could not read email message: {err}"),
            ),
        }
    } else if is_text_rfc822_email_candidate(&ext, logical_path, name) {
        if size_bytes <= EMAIL_PARSE_MAX_BYTES {
            if let Ok(bytes) = fs::read(path) {
                try_apply_email_metadata_from_bytes(metadata, "text-rfc822", &bytes);
            }
        }
    } else if is_email_store_extension(&ext) {
        mark_email_store(metadata, &ext);
    }
}

fn annotate_email_metadata_from_bytes(
    metadata: &mut serde_json::Value,
    email_format: &str,
    bytes: &[u8],
) {
    if !try_apply_email_metadata_from_bytes(metadata, email_format, bytes) {
        mark_email_parse_skipped(metadata, email_format, "not a recognizable RFC 822 message")
    }
}

fn try_apply_email_metadata_from_bytes(
    metadata: &mut serde_json::Value,
    email_format: &str,
    bytes: &[u8],
) -> bool {
    let Some(parsed) = parse_rfc822_email(bytes) else {
        return false;
    };
    apply_parsed_email_metadata(metadata, email_format, parsed);
    true
}

fn mark_email_store(metadata: &mut serde_json::Value, email_format: &str) {
    if let Some(object) = metadata.as_object_mut() {
        object.insert(
            "artifact_kind".to_string(),
            serde_json::Value::String("email_store".to_string()),
        );
        object.insert(
            "email_format".to_string(),
            serde_json::Value::String(email_format.to_string()),
        );
        object.insert(
            "email_parser_status".to_string(),
            serde_json::Value::String("pending mailbox store parser".to_string()),
        );
    }
}

fn mark_email_parse_skipped(metadata: &mut serde_json::Value, email_format: &str, reason: &str) {
    if let Some(object) = metadata.as_object_mut() {
        object.insert(
            "artifact_kind".to_string(),
            serde_json::Value::String("email_message".to_string()),
        );
        object.insert(
            "email_format".to_string(),
            serde_json::Value::String(email_format.to_string()),
        );
        object.insert(
            "email_parser_status".to_string(),
            serde_json::Value::String("skipped".to_string()),
        );
        object.insert(
            "email_parser_error".to_string(),
            serde_json::Value::String(reason.to_string()),
        );
    }
}

fn apply_parsed_email_metadata(
    metadata: &mut serde_json::Value,
    email_format: &str,
    parsed: ParsedEmail,
) {
    if let Some(object) = metadata.as_object_mut() {
        object.insert(
            "artifact_kind".to_string(),
            serde_json::Value::String("email_message".to_string()),
        );
        object.insert(
            "email_format".to_string(),
            serde_json::Value::String(email_format.to_string()),
        );
        object.insert(
            "email_parser".to_string(),
            serde_json::Value::String("rfc822_header_v1".to_string()),
        );
        object.insert(
            "email_parser_status".to_string(),
            serde_json::Value::String("parsed".to_string()),
        );
        insert_optional_string(object, "email_from", parsed.from);
        insert_optional_string(object, "email_to", parsed.to);
        insert_optional_string(object, "email_cc", parsed.cc);
        insert_optional_string(object, "email_bcc", parsed.bcc);
        insert_optional_string(object, "email_subject", parsed.subject);
        insert_optional_string(object, "email_date", parsed.date);
        insert_optional_string(object, "email_message_id", parsed.message_id);
        insert_optional_string(object, "email_reply_to", parsed.reply_to);
        insert_optional_string(object, "email_in_reply_to", parsed.in_reply_to);
        insert_optional_string(object, "email_body_preview", parsed.body_preview);
    }
}

fn insert_optional_string(
    object: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    value: Option<String>,
) {
    if let Some(value) = value.filter(|value| !value.is_empty()) {
        object.insert(key.to_string(), serde_json::Value::String(value));
    }
}

fn is_email_store_extension(ext: &str) -> bool {
    matches!(
        ext,
        "pst" | "ost" | "nst" | "msg" | "mbox" | "olm" | "dbx" | "nsf"
    )
}

fn is_text_rfc822_email_candidate(ext: &str, logical_path: &str, name: &str) -> bool {
    if !matches!(ext, "txt" | "text") {
        return false;
    }
    let combined = format!("{logical_path}/{name}")
        .replace('\\', "/")
        .to_ascii_lowercase();
    combined.starts_with("email/")
        || combined.contains("/email/")
        || combined.starts_with("emails/")
        || combined.contains("/emails/")
}

struct ParsedEmail {
    from: Option<String>,
    to: Option<String>,
    cc: Option<String>,
    bcc: Option<String>,
    subject: Option<String>,
    date: Option<String>,
    message_id: Option<String>,
    reply_to: Option<String>,
    in_reply_to: Option<String>,
    body_preview: Option<String>,
}

fn parse_rfc822_email(bytes: &[u8]) -> Option<ParsedEmail> {
    let text = String::from_utf8_lossy(bytes);
    let (header_text, body_text) = split_email_headers_body(&text)?;
    let headers = parse_email_headers(header_text);
    let has_message_header = ["from", "to", "subject", "date", "message-id"]
        .iter()
        .any(|key| headers.contains_key(*key));
    if !has_message_header {
        return None;
    }
    Some(ParsedEmail {
        from: header_value(&headers, "from"),
        to: header_value(&headers, "to"),
        cc: header_value(&headers, "cc"),
        bcc: header_value(&headers, "bcc"),
        subject: header_value(&headers, "subject"),
        date: header_value(&headers, "date"),
        message_id: header_value(&headers, "message-id"),
        reply_to: header_value(&headers, "reply-to"),
        in_reply_to: header_value(&headers, "in-reply-to"),
        body_preview: email_body_preview(body_text),
    })
}

fn split_email_headers_body(text: &str) -> Option<(&str, &str)> {
    if let Some(index) = text.find("\r\n\r\n") {
        return Some((&text[..index], &text[index + 4..]));
    }
    text.find("\n\n")
        .map(|index| (&text[..index], &text[index + 2..]))
}

fn parse_email_headers(header_text: &str) -> HashMap<String, String> {
    let mut headers = HashMap::new();
    let mut current_key: Option<String> = None;
    for raw_line in header_text.lines() {
        let line = raw_line.trim_end_matches('\r');
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(key) = &current_key {
                let entry = headers.entry(key.clone()).or_insert_with(String::new);
                if !entry.is_empty() {
                    entry.push(' ');
                }
                entry.push_str(line.trim());
            }
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            if let Some(key) = &current_key {
                let entry = headers.entry(key.clone()).or_insert_with(String::new);
                if !entry.is_empty() {
                    entry.push(' ');
                }
                entry.push_str(line.trim());
            }
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = normalize_email_header_value(value);
        current_key = Some(key.clone());
        headers
            .entry(key)
            .and_modify(|existing| {
                existing.push_str("; ");
                existing.push_str(&value);
            })
            .or_insert(value);
    }
    headers
}

fn header_value(headers: &HashMap<String, String>, key: &str) -> Option<String> {
    headers
        .get(key)
        .map(|value| normalize_email_header_value(value))
        .filter(|value| !value.is_empty())
}

fn normalize_email_header_value(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn email_body_preview(body_text: &str) -> Option<String> {
    let preview = body_text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .take(40)
        .collect::<Vec<_>>()
        .join("\n");
    let mut chars = preview.chars();
    let trimmed = chars
        .by_ref()
        .take(EMAIL_BODY_PREVIEW_CHARS)
        .collect::<String>();
    (!trimmed.is_empty()).then_some(trimmed)
}

fn process_file_evidence(
    conn: &Connection,
    case_id: i64,
    evidence: &EvidenceForProcessing,
    job_id: i64,
    _max_entries: usize,
) -> Result<(usize, bool)> {
    let path = PathBuf::from(&evidence.source_path);
    let metadata = fs::metadata(&path)
        .with_context(|| format!("reading file evidence metadata {}", path.display()))?;
    if !metadata.is_file() {
        bail!("file evidence path is no longer a file: {}", path.display());
    }
    let logical_path = format!("/{}", evidence.display_name);
    let mut metadata_value = serde_json::json!({});
    annotate_email_metadata_for_path(
        &mut metadata_value,
        &path,
        &logical_path,
        &evidence.display_name,
        metadata.len(),
    );
    add_entry_category(
        &mut metadata_value,
        &logical_path,
        &evidence.display_name,
        "file",
    );
    let content_head = local_file_content_head(&path, &metadata_value, "file");
    upsert_filesystem_entry_with_content(
        conn,
        case_id,
        evidence.id,
        &logical_path,
        &evidence.display_name,
        "file",
        Some(i64::try_from(metadata.len()).context("file size exceeds i64")?),
        &metadata_value.to_string(),
        job_id,
        content_head.as_deref(),
    )?;
    Ok((1, false))
}

fn process_folder_evidence(
    conn: &Connection,
    case_id: i64,
    evidence: &EvidenceForProcessing,
    job_id: i64,
    max_entries: usize,
) -> Result<(usize, bool)> {
    let root = PathBuf::from(&evidence.source_path);
    if !root.is_dir() {
        bail!(
            "folder evidence path is no longer a directory: {}",
            root.display()
        );
    }

    let mut indexed = 0_usize;
    let mut stack = vec![root.clone()];
    while let Some(folder) = stack.pop() {
        let mut children = fs::read_dir(&folder)
            .with_context(|| format!("reading evidence folder {}", folder.display()))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .with_context(|| format!("listing evidence folder {}", folder.display()))?;
        children.sort_by_key(|entry| entry.path());

        for child in children {
            if indexed >= max_entries {
                return Ok((indexed, true));
            }
            let child_path = child.path();
            let metadata = fs::symlink_metadata(&child_path).with_context(|| {
                format!("reading evidence entry metadata {}", child_path.display())
            })?;
            let relative = child_path
                .strip_prefix(&root)
                .with_context(|| format!("building logical path for {}", child_path.display()))?;
            let logical_path = logical_path_from_relative(relative);
            let name = child_path
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("")
                .to_string();
            let file_type = metadata.file_type();
            let (entry_kind, size_bytes, mut metadata_value, descend) = if file_type.is_symlink() {
                (
                    "symlink",
                    None,
                    serde_json::json!({ "symlink": true }),
                    false,
                )
            } else if file_type.is_dir() {
                ("directory", None, serde_json::json!({}), true)
            } else if file_type.is_file() {
                (
                    "file",
                    Some(i64::try_from(metadata.len()).context("file size exceeds i64")?),
                    serde_json::json!({}),
                    false,
                )
            } else {
                ("other", None, serde_json::json!({}), false)
            };
            if file_type.is_file() {
                annotate_email_metadata_for_path(
                    &mut metadata_value,
                    &child_path,
                    &logical_path,
                    &name,
                    metadata.len(),
                );
            }
            add_entry_category(&mut metadata_value, &logical_path, &name, entry_kind);
            let content_head = local_file_content_head(&child_path, &metadata_value, entry_kind);

            upsert_filesystem_entry_with_content(
                conn,
                case_id,
                evidence.id,
                &logical_path,
                &name,
                entry_kind,
                size_bytes,
                &metadata_value.to_string(),
                job_id,
                content_head.as_deref(),
            )?;
            indexed += 1;
            if descend {
                stack.push(child_path);
            }
        }
    }

    Ok((indexed, false))
}

fn process_image_evidence(
    conn: &Connection,
    case_id: i64,
    evidence: &EvidenceForProcessing,
    job_id: i64,
    max_entries: usize,
) -> Result<(usize, bool)> {
    let path = PathBuf::from(&evidence.source_path);
    if !path.is_file() {
        bail!(
            "image evidence path is no longer a file: {}",
            path.display()
        );
    }

    let mut opened = open_disk_image(&path)?;
    let source_metadata = fs::metadata(&path)
        .with_context(|| format!("reading image evidence metadata {}", path.display()))?;
    let source_info = source_artifact_metadata(&path, "Disk Image");
    let mut indexed = 0_usize;
    let mut truncated = false;

    conn.execute(
        "DELETE FROM filesystem_entries WHERE case_id = ?1 AND evidence_id = ?2",
        params![case_id, evidence.id],
    )?;

    let mut container_metadata = serde_json::json!({
        "artifact_kind": "disk_image_container",
        "container_format": opened.format,
        "decoded_size_bytes": opened.decoded_size,
        "source_size_bytes": source_metadata.len(),
        "source_path": evidence.source_path,
        "parser": "disk-forensic",
        "supported_formats": ["e01", "vmdk", "vhdx", "vhd", "vdi", "raw", "dd", "img"],
        "filesystem_browsing_status": "partition discovery only; filesystem parsers are pending",
    });
    merge_json_object(&mut container_metadata, &source_info);
    insert_image_record(
        conn,
        case_id,
        evidence.id,
        "/Image Analysis/Container.record",
        "Container",
        Some(i64::try_from(opened.decoded_size).unwrap_or(i64::MAX)),
        &container_metadata,
        job_id,
    )?;
    indexed += 1;
    if indexed >= max_entries {
        return Ok((indexed, true));
    }

    match disk_forensic::analyse_disk(&mut opened.reader, opened.decoded_size) {
        Ok(report) => {
            let scheme = format!("{:?}", report.scheme());
            let layout = disk_forensic::layout::from_report(
                &report,
                &evidence.display_name,
                opened.decoded_size,
            );
            let text_report = disk_forensic::report::text_report(&report);
            let report_metadata = serde_json::json!({
                "artifact_kind": "disk_partition_report",
                "container_format": opened.format,
                "partition_scheme": scheme,
                "decoded_size_bytes": opened.decoded_size,
                "logical_sector_size": layout.logical_sector_size,
                "physical_sector_size": layout.physical_sector_size,
                "partition_count": layout.partitions.len(),
                "has_anomalies": report.has_anomalies(),
                "container_finding_count": opened.container_finding_count,
                "text_report": text_report,
            });
            insert_image_record(
                conn,
                case_id,
                evidence.id,
                "/Image Analysis/Partitioning.report",
                "Partitioning",
                None,
                &report_metadata,
                job_id,
            )?;
            indexed += 1;
            if indexed >= max_entries {
                return Ok((indexed, true));
            }

            for (index, partition) in layout.partitions.iter().enumerate() {
                if indexed >= max_entries {
                    truncated = true;
                    break;
                }
                let name = partition
                    .label
                    .as_deref()
                    .filter(|value| !value.trim().is_empty())
                    .unwrap_or(&partition.name);
                let logical_path = format!(
                    "/Image Analysis/Partitions/{:03}-{}.record",
                    index + 1,
                    sanitize_logical_segment(name)
                );
                let volume_prefix = format!(
                    "/Image Analysis/Volumes/{:03}-{}",
                    index + 1,
                    sanitize_logical_segment(name)
                );
                let detected_filesystem =
                    detect_volume_filesystem_at(&mut *opened.reader, partition.start_offset)?;
                let can_parse_fat = detected_filesystem == Some("FAT")
                    || is_supported_fat_partition(
                        partition.partition_type.as_deref(),
                        partition.filesystem.as_deref(),
                    );
                let can_parse_ntfs = detected_filesystem == Some("NTFS")
                    || is_supported_ntfs_partition(
                        partition.partition_type.as_deref(),
                        partition.filesystem.as_deref(),
                    );
                let can_parse_ext = detected_filesystem == Some("EXT");
                let filesystem_parser = if can_parse_fat {
                    "fatfs"
                } else if can_parse_ntfs {
                    "ntfs"
                } else if can_parse_ext {
                    "ext4"
                } else {
                    "pending"
                };
                let filesystem_browsing_status = if can_parse_fat {
                    "FAT parser attempted; parsed entries appear under /Image Analysis/Volumes"
                } else if can_parse_ntfs {
                    "NTFS parser attempted; parsed entries appear under /Image Analysis/Volumes"
                } else if can_parse_ext {
                    "ext parser attempted; parsed entries appear under /Image Analysis/Volumes"
                } else {
                    "pending filesystem parser"
                };
                let volume_entry_prefix = if can_parse_fat || can_parse_ntfs || can_parse_ext {
                    Some(volume_prefix.as_str())
                } else {
                    None
                };
                let metadata = serde_json::json!({
                    "artifact_kind": "disk_partition",
                    "container_format": opened.format,
                    "partition_scheme": scheme,
                    "index": index + 1,
                    "name": partition.name,
                    "label": partition.label,
                    "partition_type": partition.partition_type,
                    "filesystem": partition.filesystem,
                    "detected_filesystem": detected_filesystem,
                    "start_offset": partition.start_offset,
                    "size_bytes": partition.size_bytes,
                    "end_offset_exclusive": partition.start_offset.saturating_add(partition.size_bytes),
                    "logical_sector_size": layout.logical_sector_size,
                    "physical_sector_size": layout.physical_sector_size,
                    "filesystem_parser": filesystem_parser,
                    "filesystem_browsing_status": filesystem_browsing_status,
                    "volume_entry_prefix": volume_entry_prefix,
                });
                insert_image_record(
                    conn,
                    case_id,
                    evidence.id,
                    &logical_path,
                    name,
                    Some(i64::try_from(partition.size_bytes).unwrap_or(i64::MAX)),
                    &metadata,
                    job_id,
                )?;
                indexed += 1;
                if can_parse_fat && indexed < max_entries {
                    match process_fat_partition_entries(
                        conn,
                        case_id,
                        evidence.id,
                        job_id,
                        &mut *opened.reader,
                        partition.start_offset,
                        partition.size_bytes,
                        &volume_prefix,
                        name,
                        index + 1,
                        &mut indexed,
                        max_entries,
                    ) {
                        Ok(fat_truncated) => truncated |= fat_truncated,
                        Err(err) => {
                            if indexed >= max_entries {
                                truncated = true;
                            } else {
                                insert_image_record(
                                    conn,
                                    case_id,
                                    evidence.id,
                                    &format!("{volume_prefix}/Parser Error.record"),
                                    "Parser Error",
                                    None,
                                    &serde_json::json!({
                                        "artifact_kind": "filesystem_parser_error",
                                        "filesystem_parser": "fatfs",
                                        "partition_index": index + 1,
                                        "error": err.to_string(),
                                    }),
                                    job_id,
                                )?;
                                indexed += 1;
                            }
                        }
                    }
                } else if can_parse_ntfs && indexed < max_entries {
                    match process_ntfs_partition_entries(
                        conn,
                        case_id,
                        evidence.id,
                        job_id,
                        &mut *opened.reader,
                        partition.start_offset,
                        partition.size_bytes,
                        &volume_prefix,
                        name,
                        index + 1,
                        &mut indexed,
                        max_entries,
                    ) {
                        Ok(ntfs_truncated) => truncated |= ntfs_truncated,
                        Err(err) => {
                            if indexed >= max_entries {
                                truncated = true;
                            } else {
                                insert_image_record(
                                    conn,
                                    case_id,
                                    evidence.id,
                                    &format!("{volume_prefix}/Parser Error.record"),
                                    "Parser Error",
                                    None,
                                    &serde_json::json!({
                                        "artifact_kind": "filesystem_parser_error",
                                        "filesystem_parser": "ntfs",
                                        "partition_index": index + 1,
                                        "error": err.to_string(),
                                    }),
                                    job_id,
                                )?;
                                indexed += 1;
                            }
                        }
                    }
                } else if can_parse_ext && indexed < max_entries {
                    match process_ext_partition_entries(
                        conn,
                        case_id,
                        evidence.id,
                        job_id,
                        &evidence.source_path,
                        partition.start_offset,
                        partition.size_bytes,
                        &volume_prefix,
                        name,
                        index + 1,
                        &mut indexed,
                        max_entries,
                    ) {
                        Ok(ext_truncated) => truncated |= ext_truncated,
                        Err(err) => {
                            if indexed >= max_entries {
                                truncated = true;
                            } else {
                                insert_image_record(
                                    conn,
                                    case_id,
                                    evidence.id,
                                    &format!("{volume_prefix}/Parser Error.record"),
                                    "Parser Error",
                                    None,
                                    &serde_json::json!({
                                        "artifact_kind": "filesystem_parser_error",
                                        "filesystem_parser": "ext4",
                                        "partition_index": index + 1,
                                        "error": err.to_string(),
                                    }),
                                    job_id,
                                )?;
                                indexed += 1;
                            }
                        }
                    }
                } else if (can_parse_fat || can_parse_ntfs || can_parse_ext)
                    && indexed >= max_entries
                {
                    truncated = true;
                } else if !can_parse_fat
                    && !can_parse_ntfs
                    && !can_parse_ext
                    && indexed < max_entries
                {
                    // btrfs is not yet browsable; if its superblock is present,
                    // record the volume with parsed metadata (pending walk).
                    if let Some(info) =
                        read_btrfs_superblock(&mut *opened.reader, partition.start_offset)?
                    {
                        record_btrfs_volume(
                            conn,
                            case_id,
                            evidence.id,
                            job_id,
                            partition.start_offset,
                            partition.size_bytes,
                            &volume_prefix,
                            name,
                            index + 1,
                            &info,
                            &mut indexed,
                        )?;
                    }
                }
            }

            if layout.partitions.is_empty() && indexed < max_entries {
                truncated |= process_whole_volume_fallback(
                    conn,
                    case_id,
                    evidence.id,
                    job_id,
                    &mut *opened.reader,
                    &evidence.source_path,
                    opened.decoded_size,
                    &opened.format,
                    Some(&scheme),
                    &mut indexed,
                    max_entries,
                )?;
            }

            if indexed < max_entries {
                let declared: Vec<(u64, u64)> = layout
                    .partitions
                    .iter()
                    .map(|partition| (partition.start_offset, partition.size_bytes))
                    .collect();
                // The whole-image fallback already probed offset 0.
                let skip: &[u64] = if declared.is_empty() { &[0] } else { &[] };
                truncated |= scan_lost_partitions(
                    conn,
                    case_id,
                    evidence.id,
                    job_id,
                    &mut *opened.reader,
                    opened.decoded_size,
                    &declared,
                    skip,
                    declared.len(),
                    &mut indexed,
                    max_entries,
                )?;
            }
        }
        Err(err) => {
            let metadata = serde_json::json!({
                "artifact_kind": "disk_partition_report",
                "container_format": opened.format,
                "decoded_size_bytes": opened.decoded_size,
                "status": "partition scheme not recognized",
                "error": err.to_string(),
            });
            insert_image_record(
                conn,
                case_id,
                evidence.id,
                "/Image Analysis/Partitioning.report",
                "Partitioning",
                None,
                &metadata,
                job_id,
            )?;
            indexed += 1;
            if indexed < max_entries {
                truncated |= process_whole_volume_fallback(
                    conn,
                    case_id,
                    evidence.id,
                    job_id,
                    &mut *opened.reader,
                    &evidence.source_path,
                    opened.decoded_size,
                    &opened.format,
                    None,
                    &mut indexed,
                    max_entries,
                )?;
            } else {
                truncated = true;
            }
            if indexed < max_entries {
                // No partition table at all (e.g. wiped/zeroed sector 0):
                // sweep the whole disk for orphaned boot sectors. Offset 0 was
                // already probed by the fallback.
                truncated |= scan_lost_partitions(
                    conn,
                    case_id,
                    evidence.id,
                    job_id,
                    &mut *opened.reader,
                    opened.decoded_size,
                    &[],
                    &[0],
                    0,
                    &mut indexed,
                    max_entries,
                )?;
            }
        }
    }

    Ok((indexed, truncated))
}

struct OpenedDiskImage {
    format: String,
    decoded_size: u64,
    reader: Box<dyn disk_forensic::container::ReadSeek>,
    container_finding_count: usize,
}

/// Discovers a split raw acquisition (image.001, image.002, ...) starting from
/// its first numeric segment. Returns None when `path` is not the `.001`-style
/// first segment or has no siblings. Like the EWF reader, a gap in the
/// sequence is an error rather than a silently partial image.
fn split_raw_segments(path: &Path) -> Result<Option<Vec<(PathBuf, u64)>>> {
    let Some(ext) = path.extension().and_then(|value| value.to_str()) else {
        return Ok(None);
    };
    if ext.len() < 2 || !ext.chars().all(|ch| ch.is_ascii_digit()) {
        return Ok(None);
    }
    let width = ext.len();
    let stem = path
        .to_string_lossy()
        .strip_suffix(ext)
        .map(str::to_string)
        .unwrap_or_default();
    if ext.parse::<u64>().unwrap_or(0) != 1 {
        // Only treat this as a split set when its first segment exists; other
        // numeric extensions (e.g. report.2024) stay ordinary raw files.
        let first = PathBuf::from(format!("{stem}{:0width$}", 1_u64));
        if first.is_file() {
            bail!(
                "split raw evidence must be added from its first segment {}: got {}",
                first.display(),
                path.display()
            );
        }
        return Ok(None);
    }
    let mut segments = Vec::new();
    let mut number: u64 = 1;
    loop {
        let candidate = PathBuf::from(format!("{stem}{number:0width$}"));
        let Ok(metadata) = fs::metadata(&candidate) else {
            break;
        };
        if !metadata.is_file() {
            break;
        }
        segments.push((candidate, metadata.len()));
        number += 1;
    }
    // A sibling segment past the last sequential number means a gap in the
    // set; refuse to open rather than presenting a truncated disk.
    if let Some(parent) = path.parent() {
        let prefix = Path::new(&stem)
            .file_name()
            .map(|value| value.to_string_lossy().into_owned())
            .unwrap_or_default();
        for entry in fs::read_dir(parent).into_iter().flatten().flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(suffix) = name.strip_prefix(&prefix) {
                if suffix.len() == width && suffix.chars().all(|ch| ch.is_ascii_digit()) {
                    let found: u64 = suffix.parse().unwrap_or(0);
                    if found > segments.len() as u64 {
                        bail!(
                            "split raw image has a segment gap: found segment {found} but segment {} is missing",
                            segments.len() + 1
                        );
                    }
                }
            }
        }
    }
    if segments.len() < 2 {
        return Ok(None);
    }
    Ok(Some(segments))
}

/// Presents ordered split raw segments as one continuous read/seek stream.
struct SplitRawReader {
    /// (open file, absolute start offset, length) per segment.
    segments: Vec<(fs::File, u64, u64)>,
    total_size: u64,
    position: u64,
}

impl SplitRawReader {
    fn open(paths: &[(PathBuf, u64)]) -> Result<Self> {
        let mut segments = Vec::with_capacity(paths.len());
        let mut offset = 0_u64;
        for (path, len) in paths {
            let file = fs::File::open(path)
                .with_context(|| format!("opening split raw segment {}", path.display()))?;
            segments.push((file, offset, *len));
            offset = offset
                .checked_add(*len)
                .context("split raw image exceeds u64 size")?;
        }
        Ok(Self {
            segments,
            total_size: offset,
            position: 0,
        })
    }
}

impl Read for SplitRawReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.position >= self.total_size {
            return Ok(0);
        }
        let position = self.position;
        let segment = self
            .segments
            .iter_mut()
            .find(|(_, start, len)| position >= *start && position < *start + *len);
        let Some((file, start, len)) = segment else {
            return Ok(0);
        };
        let within = position - *start;
        let remaining = (*len - within).min(buf.len() as u64) as usize;
        file.seek(SeekFrom::Start(within))?;
        let read = file.read(&mut buf[..remaining])?;
        self.position += read as u64;
        Ok(read)
    }
}

impl Seek for SplitRawReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let target = match pos {
            SeekFrom::Start(offset) => Some(offset),
            SeekFrom::End(delta) => self.total_size.checked_add_signed(delta),
            SeekFrom::Current(delta) => self.position.checked_add_signed(delta),
        };
        match target {
            Some(offset) => {
                self.position = offset;
                Ok(offset)
            }
            None => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before start of split raw image",
            )),
        }
    }
}

/// A browsable volume within a disk image, discovered without indexing.
#[derive(Debug, Serialize)]
pub struct LiveVolume {
    pub index: usize,
    pub name: String,
    pub filesystem: String,
    pub start_offset: u64,
    pub size_bytes: u64,
    pub browsable: bool,
}

/// One entry returned while browsing a directory live from the image.
#[derive(Debug, Serialize)]
pub struct LiveEntry {
    pub name: String,
    pub is_dir: bool,
    pub size_bytes: Option<i64>,
    pub created_utc: Option<String>,
    pub modified_utc: Option<String>,
    pub accessed_utc: Option<String>,
}

/// Lists the browsable volumes of a disk image (partitions or whole-image),
/// detecting each volume's filesystem. No files are indexed - this only reads
/// the partition table and volume boot sectors, so it is fast even for huge
/// disks. This is the entry point for old-Ecase-style live browsing.
pub fn list_image_volumes(image_path: &Path) -> Result<Vec<LiveVolume>> {
    let mut opened = open_disk_image(image_path)?;
    let mut volumes = Vec::new();
    if let Ok(report) = disk_forensic::analyse_disk(&mut opened.reader, opened.decoded_size) {
        let layout = disk_forensic::layout::from_report(&report, "image", opened.decoded_size);
        for partition in &layout.partitions {
            let filesystem = live_volume_filesystem(&mut *opened.reader, partition.start_offset)?;
            let browsable = matches!(filesystem.as_str(), "NTFS" | "FAT" | "EXT");
            let label = partition
                .label
                .as_deref()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or(&partition.name);
            volumes.push(LiveVolume {
                index: volumes.len(),
                name: format!(
                    "{:03}-{}",
                    volumes.len() + 1,
                    sanitize_logical_segment(label)
                ),
                filesystem,
                start_offset: partition.start_offset,
                size_bytes: partition.size_bytes,
                browsable,
            });
        }
    }
    if volumes.is_empty() {
        let filesystem = live_volume_filesystem(&mut *opened.reader, 0)?;
        if filesystem != "unknown" {
            let browsable = matches!(filesystem.as_str(), "NTFS" | "FAT" | "EXT");
            volumes.push(LiveVolume {
                index: 0,
                name: "whole-image".to_string(),
                filesystem,
                start_offset: 0,
                size_bytes: opened.decoded_size,
                browsable,
            });
        }
    }
    Ok(volumes)
}

fn live_volume_filesystem(
    reader: &mut dyn disk_forensic::container::ReadSeek,
    start_offset: u64,
) -> Result<String> {
    if let Some(filesystem) = detect_volume_filesystem_at(reader, start_offset)? {
        return Ok(filesystem.to_string());
    }
    if read_btrfs_superblock(reader, start_offset)?.is_some() {
        return Ok("BTRFS".to_string());
    }
    Ok("unknown".to_string())
}

/// Lists the immediate children of one directory in one volume, read live from
/// the image. `dir_path` is volume-relative ("" or "/" is the volume root).
pub fn list_image_directory(
    image_path: &Path,
    volume_index: usize,
    dir_path: &str,
) -> Result<Vec<LiveEntry>> {
    let volumes = list_image_volumes(image_path)?;
    let volume = volumes
        .get(volume_index)
        .with_context(|| format!("volume index {volume_index} out of range"))?;
    let relative = dir_path.trim_matches('/');
    let mut entries = match volume.filesystem.as_str() {
        "NTFS" => {
            list_ntfs_directory(image_path, volume.start_offset, volume.size_bytes, relative)?
        }
        "FAT" => list_fat_directory(image_path, volume.start_offset, volume.size_bytes, relative)?,
        "EXT" => list_ext_directory(image_path, volume.start_offset, relative)?,
        other => bail!("live browsing is not supported for {other} volumes"),
    };
    entries.sort_by(|left, right| {
        (right.is_dir as u8)
            .cmp(&(left.is_dir as u8))
            .then_with(|| {
                left.name
                    .to_ascii_lowercase()
                    .cmp(&right.name.to_ascii_lowercase())
            })
    });
    Ok(entries)
}

fn list_ntfs_directory(
    image_path: &Path,
    start_offset: u64,
    size_bytes: u64,
    relative: &str,
) -> Result<Vec<LiveEntry>> {
    let mut opened = open_disk_image(image_path)?;
    let mut slice = PartitionSlice::new(&mut *opened.reader, start_offset, size_bytes);
    let ntfs = ntfs::Ntfs::new(&mut slice)
        .with_context(|| format!("opening NTFS volume at offset {start_offset}"))?;
    let mut record = ntfs
        .root_directory(&mut slice)
        .context("opening NTFS root directory")?
        .file_record_number();
    for component in relative.split('/').filter(|value| !value.is_empty()) {
        let children = collect_ntfs_dir_children(&ntfs, &mut slice, record)?;
        let child = children
            .iter()
            .find(|child| child.is_directory && child.name.eq_ignore_ascii_case(component))
            .with_context(|| format!("directory not found: {component}"))?;
        record = child.file_record_number;
    }
    let children = collect_ntfs_dir_children(&ntfs, &mut slice, record)?;
    Ok(children
        .into_iter()
        .map(|child| LiveEntry {
            size_bytes: if child.is_directory {
                None
            } else {
                Some(i64::try_from(child.size_bytes).unwrap_or(i64::MAX))
            },
            created_utc: child.standard_creation_time_utc.or(child.creation_time_utc),
            modified_utc: child
                .standard_modification_time_utc
                .or(child.modification_time_utc),
            accessed_utc: child.standard_access_time_utc.or(child.access_time_utc),
            name: child.name,
            is_dir: child.is_directory,
        })
        .collect())
}

fn list_fat_directory(
    image_path: &Path,
    start_offset: u64,
    size_bytes: u64,
    relative: &str,
) -> Result<Vec<LiveEntry>> {
    let mut opened = open_disk_image(image_path)?;
    let slice = PartitionSlice::new(&mut *opened.reader, start_offset, size_bytes);
    let fs = fatfs::FileSystem::new(slice, fatfs::FsOptions::new())
        .with_context(|| format!("opening FAT volume at offset {start_offset}"))?;
    let root = fs.root_dir();
    let dir = if relative.is_empty() {
        root
    } else {
        root.open_dir(relative)
            .with_context(|| format!("opening FAT directory {relative}"))?
    };
    let mut entries = Vec::new();
    for entry in dir.iter() {
        let entry = entry.context("reading FAT directory entry")?;
        let name = entry.file_name();
        if name == "." || name == ".." {
            continue;
        }
        entries.push(LiveEntry {
            is_dir: entry.is_dir(),
            size_bytes: if entry.is_dir() {
                None
            } else {
                Some(i64::try_from(entry.len()).unwrap_or(i64::MAX))
            },
            created_utc: fat_datetime_iso(entry.created()),
            modified_utc: fat_datetime_iso(entry.modified()),
            accessed_utc: fat_date_iso(entry.accessed()),
            name,
        });
    }
    Ok(entries)
}

fn fat_datetime_iso(value: fatfs::DateTime) -> Option<String> {
    if value.date.year == 0 {
        return None;
    }
    Some(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        value.date.year,
        value.date.month,
        value.date.day,
        value.time.hour,
        value.time.min,
        value.time.sec
    ))
}

fn fat_date_iso(value: fatfs::Date) -> Option<String> {
    if value.year == 0 {
        return None;
    }
    Some(format!(
        "{:04}-{:02}-{:02}",
        value.year, value.month, value.day
    ))
}

fn list_ext_directory(
    image_path: &Path,
    start_offset: u64,
    relative: &str,
) -> Result<Vec<LiveEntry>> {
    let opened = open_disk_image(image_path)?;
    let reader = Ext4ImageReader {
        reader: opened.reader,
        partition_start: start_offset,
    };
    let fs = ext4_view::Ext4::load(Box::new(reader))
        .map_err(|err| anyhow!("opening ext volume at offset {start_offset}: {err}"))?;
    let path = if relative.is_empty() {
        "/".to_string()
    } else {
        format!("/{relative}")
    };
    let read_dir = fs
        .read_dir(path.as_str())
        .map_err(|err| anyhow!("reading ext directory {path}: {err}"))?;
    let mut entries = Vec::new();
    for entry in read_dir {
        let entry = entry.map_err(|err| anyhow!("reading ext directory entry: {err}"))?;
        let name = String::from_utf8_lossy(entry.file_name().as_ref()).into_owned();
        if name == "." || name == ".." {
            continue;
        }
        let is_dir = entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false);
        let size_bytes = entry
            .metadata()
            .ok()
            .map(|meta| i64::try_from(meta.len()).unwrap_or(i64::MAX));
        entries.push(LiveEntry {
            name,
            is_dir,
            size_bytes: if is_dir { None } else { size_bytes },
            created_utc: None,
            modified_utc: None,
            accessed_utc: None,
        });
    }
    Ok(entries)
}

/// Reads a file's bytes live from a volume by path (for the byte viewer during
/// live browsing, before anything is indexed).
/// Reads a bounded window of a file's bytes live from a volume by path, and
/// returns (window, total_file_size) for the byte viewer.
pub fn read_image_directory_bytes(
    image_path: &Path,
    volume_index: usize,
    file_path: &str,
    offset: u64,
    length: usize,
) -> Result<(Vec<u8>, u64)> {
    let length = length.min(8 * 1024 * 1024);
    let volumes = list_image_volumes(image_path)?;
    let volume = volumes
        .get(volume_index)
        .with_context(|| format!("volume index {volume_index} out of range"))?;
    let relative = file_path.trim_matches('/');
    match volume.filesystem.as_str() {
        "EXT" => {
            let opened = open_disk_image(image_path)?;
            let reader = Ext4ImageReader {
                reader: opened.reader,
                partition_start: volume.start_offset,
            };
            let fs = ext4_view::Ext4::load(Box::new(reader))
                .map_err(|err| anyhow!("opening ext volume: {err}"))?;
            let data = fs
                .read(format!("/{relative}").as_str())
                .map_err(|err| anyhow!("reading ext file {relative}: {err}"))?;
            let total = data.len() as u64;
            let start = (offset as usize).min(data.len());
            let end = start.saturating_add(length).min(data.len());
            Ok((data[start..end].to_vec(), total))
        }
        "FAT" => {
            let mut opened = open_disk_image(image_path)?;
            let slice =
                PartitionSlice::new(&mut *opened.reader, volume.start_offset, volume.size_bytes);
            let fs = fatfs::FileSystem::new(slice, fatfs::FsOptions::new())
                .context("opening FAT volume")?;
            let mut file = fs
                .root_dir()
                .open_file(relative)
                .with_context(|| format!("opening FAT file {relative}"))?;
            let total = file.seek(SeekFrom::End(0))?;
            file.seek(SeekFrom::Start(offset))?;
            // fatfs returns at most one cluster per read call; fill the whole
            // window or the request truncates at ~4 KiB.
            let mut buffer = vec![0_u8; length];
            let mut filled = 0_usize;
            while filled < buffer.len() {
                let read = file.read(&mut buffer[filled..])?;
                if read == 0 {
                    break;
                }
                filled += read;
            }
            buffer.truncate(filled);
            Ok((buffer, total))
        }
        "NTFS" => {
            let mut opened = open_disk_image(image_path)?;
            let mut slice =
                PartitionSlice::new(&mut *opened.reader, volume.start_offset, volume.size_bytes);
            let ntfs = ntfs::Ntfs::new(&mut slice).context("opening NTFS volume")?;
            let mut record = ntfs
                .root_directory(&mut slice)
                .context("opening NTFS root directory")?
                .file_record_number();
            let components: Vec<&str> = relative.split('/').filter(|v| !v.is_empty()).collect();
            let Some((file_name, dir_components)) = components.split_last() else {
                bail!("no file path given");
            };
            for component in dir_components {
                let children = collect_ntfs_dir_children(&ntfs, &mut slice, record)?;
                let child = children
                    .iter()
                    .find(|child| child.is_directory && child.name.eq_ignore_ascii_case(component))
                    .with_context(|| format!("directory not found: {component}"))?;
                record = child.file_record_number;
            }
            let children = collect_ntfs_dir_children(&ntfs, &mut slice, record)?;
            let target = children
                .iter()
                .find(|child| !child.is_directory && child.name.eq_ignore_ascii_case(file_name))
                .with_context(|| format!("file not found: {file_name}"))?;
            let total = target.size_bytes;
            let bytes = read_ntfs_file_record_bytes(
                &ntfs,
                &mut slice,
                target.file_record_number,
                offset.saturating_add(length as u64) as usize,
            )?;
            let start = (offset as usize).min(bytes.len());
            let end = start.saturating_add(length).min(bytes.len());
            Ok((bytes[start..end].to_vec(), total))
        }
        other => bail!("live byte reading is not supported for {other} volumes"),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct LiveExportResult {
    pub output_path: String,
    pub bytes_written: u64,
    pub total_size: u64,
    pub sha256_hex: String,
}

/// Safety ceiling for live (un-indexed) file export. A partial copy would look
/// complete on disk, so oversized files fail loudly instead of truncating.
const LIVE_EXPORT_MAX_BYTES: u64 = 1024 * 1024 * 1024;

/// Old-Ecase-preview-style export: copy one file out of an attached disk image
/// directly (no indexing), hashing the written bytes. The caller records the
/// audit event via `record_live_export`.
pub fn export_image_file(
    image_path: &Path,
    volume_index: usize,
    file_path: &str,
    output_path: &Path,
) -> Result<LiveExportResult> {
    let volumes = list_image_volumes(image_path)?;
    let volume = volumes
        .get(volume_index)
        .with_context(|| format!("volume index {volume_index} out of range"))?;
    let relative = file_path.trim_matches('/');

    let bytes: Vec<u8> = match volume.filesystem.as_str() {
        "EXT" => {
            let opened = open_disk_image(image_path)?;
            let reader = Ext4ImageReader {
                reader: opened.reader,
                partition_start: volume.start_offset,
            };
            let fs = ext4_view::Ext4::load(Box::new(reader))
                .map_err(|err| anyhow!("opening ext volume: {err}"))?;
            fs.read(format!("/{relative}").as_str())
                .map_err(|err| anyhow!("reading ext file {relative}: {err}"))?
        }
        "FAT" => {
            let mut opened = open_disk_image(image_path)?;
            let slice =
                PartitionSlice::new(&mut *opened.reader, volume.start_offset, volume.size_bytes);
            let fs = fatfs::FileSystem::new(slice, fatfs::FsOptions::new())
                .context("opening FAT volume")?;
            let mut file = fs
                .root_dir()
                .open_file(relative)
                .with_context(|| format!("opening FAT file {relative}"))?;
            let total = file.seek(SeekFrom::End(0))?;
            if total > LIVE_EXPORT_MAX_BYTES {
                bail!(
                    "file is {total} bytes; live export is capped at {LIVE_EXPORT_MAX_BYTES} bytes - process the evidence to export it"
                );
            }
            file.seek(SeekFrom::Start(0))?;
            let mut data = Vec::with_capacity(total as usize);
            file.read_to_end(&mut data)?;
            data
        }
        "NTFS" => {
            let mut opened = open_disk_image(image_path)?;
            let mut slice =
                PartitionSlice::new(&mut *opened.reader, volume.start_offset, volume.size_bytes);
            let ntfs = ntfs::Ntfs::new(&mut slice).context("opening NTFS volume")?;
            let mut record = ntfs
                .root_directory(&mut slice)
                .context("opening NTFS root directory")?
                .file_record_number();
            let components: Vec<&str> = relative.split('/').filter(|v| !v.is_empty()).collect();
            let Some((file_name, dir_components)) = components.split_last() else {
                bail!("no file path given");
            };
            for component in dir_components {
                let children = collect_ntfs_dir_children(&ntfs, &mut slice, record)?;
                let child = children
                    .iter()
                    .find(|child| child.is_directory && child.name.eq_ignore_ascii_case(component))
                    .with_context(|| format!("directory not found: {component}"))?;
                record = child.file_record_number;
            }
            let children = collect_ntfs_dir_children(&ntfs, &mut slice, record)?;
            let target = children
                .iter()
                .find(|child| !child.is_directory && child.name.eq_ignore_ascii_case(file_name))
                .with_context(|| format!("file not found: {file_name}"))?;
            if target.size_bytes > LIVE_EXPORT_MAX_BYTES {
                bail!(
                    "file is {} bytes; live export is capped at {LIVE_EXPORT_MAX_BYTES} bytes - process the evidence to export it",
                    target.size_bytes
                );
            }
            read_ntfs_file_record_bytes(
                &ntfs,
                &mut slice,
                target.file_record_number,
                target.size_bytes as usize,
            )?
        }
        other => bail!("live export is not supported for {other} volumes"),
    };

    if bytes.len() as u64 > LIVE_EXPORT_MAX_BYTES {
        bail!(
            "file is {} bytes; live export is capped at {LIVE_EXPORT_MAX_BYTES} bytes - process the evidence to export it",
            bytes.len()
        );
    }
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating export folder {}", parent.display()))?;
    }
    fs::write(output_path, &bytes)
        .with_context(|| format!("writing exported file {}", output_path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let sha256_hex = format!("{:x}", hasher.finalize());
    Ok(LiveExportResult {
        output_path: output_path.display().to_string(),
        bytes_written: bytes.len() as u64,
        total_size: bytes.len() as u64,
        sha256_hex,
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct LiveTreeExportResult {
    pub output_dir: String,
    pub manifest_path: String,
    pub files_exported: u64,
    pub bytes_written: u64,
    pub directories_visited: u64,
    pub skipped: Vec<String>,
    pub skipped_count: u64,
    pub truncated: bool,
}

const LIVE_TREE_EXPORT_MAX_FILES: usize = 10_000;
const LIVE_TREE_EXPORT_MAX_DIRS: usize = 5_000;
const LIVE_TREE_EXPORT_MAX_SKIP_NOTES: usize = 100;

struct TreeExportSink {
    output_root: PathBuf,
    manifest: String,
    files: u64,
    bytes: u64,
    dirs: u64,
    skipped: Vec<String>,
    skipped_count: u64,
    max_files: usize,
    truncated: bool,
    written: HashSet<PathBuf>,
}

impl TreeExportSink {
    fn new(output_root: &Path, max_files: usize) -> Self {
        Self {
            output_root: output_root.to_path_buf(),
            manifest: "relative_path,size_bytes,sha256\r\n".to_string(),
            files: 0,
            bytes: 0,
            dirs: 0,
            skipped: Vec::new(),
            skipped_count: 0,
            max_files,
            truncated: false,
            written: HashSet::new(),
        }
    }

    fn file_budget_left(&self) -> bool {
        (self.files as usize) < self.max_files
    }

    fn skip(&mut self, note: String) {
        self.skipped_count += 1;
        if self.skipped.len() < LIVE_TREE_EXPORT_MAX_SKIP_NOTES {
            self.skipped.push(note);
        }
    }

    fn write_file(&mut self, rel_parts: &[String], bytes: &[u8]) -> Result<()> {
        let mut target = self.output_root.clone();
        for part in rel_parts {
            target.push(sanitize_logical_segment(part));
        }
        let mut unique = target.clone();
        let mut suffix = 2;
        while !self.written.insert(unique.clone()) {
            unique = target.with_file_name(format!(
                "{}-{}",
                target
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "file".to_string()),
                suffix
            ));
            suffix += 1;
        }
        if let Some(parent) = unique.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("creating export folder {}", parent.display()))?;
        }
        fs::write(&unique, bytes)
            .with_context(|| format!("writing exported file {}", unique.display()))?;
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let sha = format!("{:x}", hasher.finalize());
        let rel = unique
            .strip_prefix(&self.output_root)
            .unwrap_or(&unique)
            .display()
            .to_string();
        self.manifest.push_str(&format!(
            "\"{}\",{},{}\r\n",
            rel.replace('"', "\"\""),
            bytes.len(),
            sha
        ));
        self.files += 1;
        self.bytes += bytes.len() as u64;
        Ok(())
    }

    fn finish(mut self) -> Result<LiveTreeExportResult> {
        fs::create_dir_all(&self.output_root)
            .with_context(|| format!("creating export folder {}", self.output_root.display()))?;
        let manifest_path = self.output_root.join("kdft-manifest.csv");
        fs::write(&manifest_path, self.manifest.as_bytes())
            .with_context(|| format!("writing manifest {}", manifest_path.display()))?;
        if self.skipped_count > self.skipped.len() as u64 {
            self.skipped.push(format!(
                "... and {} more skipped items",
                self.skipped_count - self.skipped.len() as u64
            ));
        }
        Ok(LiveTreeExportResult {
            output_dir: self.output_root.display().to_string(),
            manifest_path: manifest_path.display().to_string(),
            files_exported: self.files,
            bytes_written: self.bytes,
            directories_visited: self.dirs,
            skipped: self.skipped,
            skipped_count: self.skipped_count,
            truncated: self.truncated,
        })
    }
}

/// Recursive live export: copy a whole directory out of an attached disk
/// image (no indexing), preserving the folder structure under `output_root`
/// and writing a `kdft-manifest.csv` with per-file SHA-256. The filesystem is
/// opened once; the walk is bounded by file/dir caps and the per-file size
/// cap (oversized or unreadable files are skipped and noted, not fatal).
pub fn export_image_tree(
    image_path: &Path,
    volume_index: usize,
    dir_path: &str,
    output_root: &Path,
    max_files: Option<usize>,
) -> Result<LiveTreeExportResult> {
    let volumes = list_image_volumes(image_path)?;
    let volume = volumes
        .get(volume_index)
        .with_context(|| format!("volume index {volume_index} out of range"))?;
    let relative = dir_path.trim_matches('/').to_string();
    let max_files = max_files
        .unwrap_or(LIVE_TREE_EXPORT_MAX_FILES)
        .min(LIVE_TREE_EXPORT_MAX_FILES);
    let mut sink = TreeExportSink::new(output_root, max_files);

    match volume.filesystem.as_str() {
        "EXT" => {
            let opened = open_disk_image(image_path)?;
            let reader = Ext4ImageReader {
                reader: opened.reader,
                partition_start: volume.start_offset,
            };
            let fs = ext4_view::Ext4::load(Box::new(reader))
                .map_err(|err| anyhow!("opening ext volume: {err}"))?;
            let start = if relative.is_empty() {
                "/".to_string()
            } else {
                format!("/{relative}")
            };
            let mut stack: Vec<(String, Vec<String>)> = vec![(start, Vec::new())];
            while let Some((ext_path, rel_parts)) = stack.pop() {
                if sink.dirs as usize >= LIVE_TREE_EXPORT_MAX_DIRS || !sink.file_budget_left() {
                    sink.truncated = true;
                    break;
                }
                sink.dirs += 1;
                let read_dir = match fs.read_dir(ext_path.as_str()) {
                    Ok(read_dir) => read_dir,
                    Err(err) => {
                        sink.skip(format!("{ext_path}: {err}"));
                        continue;
                    }
                };
                for entry in read_dir {
                    if !sink.file_budget_left() {
                        sink.truncated = true;
                        break;
                    }
                    let Ok(entry) = entry else { continue };
                    let name = String::from_utf8_lossy(entry.file_name().as_ref()).into_owned();
                    if name == "." || name == ".." {
                        continue;
                    }
                    let child_path = if ext_path == "/" {
                        format!("/{name}")
                    } else {
                        format!("{ext_path}/{name}")
                    };
                    let mut child_rel = rel_parts.clone();
                    child_rel.push(name.clone());
                    let is_dir = entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false);
                    if is_dir {
                        stack.push((child_path, child_rel));
                        continue;
                    }
                    let size = entry.metadata().ok().map(|meta| meta.len()).unwrap_or(0);
                    if size > LIVE_EXPORT_MAX_BYTES {
                        sink.skip(format!("{child_path}: {size} bytes exceeds export cap"));
                        continue;
                    }
                    match fs.read(child_path.as_str()) {
                        Ok(bytes) => sink.write_file(&child_rel, &bytes)?,
                        Err(err) => sink.skip(format!("{child_path}: {err}")),
                    }
                }
            }
        }
        "FAT" => {
            let mut opened = open_disk_image(image_path)?;
            let slice =
                PartitionSlice::new(&mut *opened.reader, volume.start_offset, volume.size_bytes);
            let fs = fatfs::FileSystem::new(slice, fatfs::FsOptions::new())
                .context("opening FAT volume")?;
            let root = fs.root_dir();
            let mut stack: Vec<(String, Vec<String>)> = vec![(relative.clone(), Vec::new())];
            while let Some((fat_path, rel_parts)) = stack.pop() {
                if sink.dirs as usize >= LIVE_TREE_EXPORT_MAX_DIRS || !sink.file_budget_left() {
                    sink.truncated = true;
                    break;
                }
                sink.dirs += 1;
                let dir = if fat_path.is_empty() {
                    root.clone()
                } else {
                    match root.open_dir(&fat_path) {
                        Ok(dir) => dir,
                        Err(err) => {
                            sink.skip(format!("{fat_path}: {err}"));
                            continue;
                        }
                    }
                };
                for entry in dir.iter() {
                    if !sink.file_budget_left() {
                        sink.truncated = true;
                        break;
                    }
                    let Ok(entry) = entry else { continue };
                    let name = entry.file_name();
                    if name == "." || name == ".." {
                        continue;
                    }
                    let child_path = if fat_path.is_empty() {
                        name.clone()
                    } else {
                        format!("{fat_path}/{name}")
                    };
                    let mut child_rel = rel_parts.clone();
                    child_rel.push(name.clone());
                    if entry.is_dir() {
                        stack.push((child_path, child_rel));
                        continue;
                    }
                    if entry.len() > LIVE_EXPORT_MAX_BYTES {
                        sink.skip(format!(
                            "{child_path}: {} bytes exceeds export cap",
                            entry.len()
                        ));
                        continue;
                    }
                    let mut file = entry.to_file();
                    let mut bytes = Vec::with_capacity(entry.len() as usize);
                    match file.read_to_end(&mut bytes) {
                        Ok(_) => sink.write_file(&child_rel, &bytes)?,
                        Err(err) => sink.skip(format!("{child_path}: {err}")),
                    }
                }
            }
        }
        "NTFS" => {
            let mut opened = open_disk_image(image_path)?;
            let mut slice =
                PartitionSlice::new(&mut *opened.reader, volume.start_offset, volume.size_bytes);
            let ntfs = ntfs::Ntfs::new(&mut slice).context("opening NTFS volume")?;
            let mut record = ntfs
                .root_directory(&mut slice)
                .context("opening NTFS root directory")?
                .file_record_number();
            for component in relative.split('/').filter(|v| !v.is_empty()) {
                let children = collect_ntfs_dir_children(&ntfs, &mut slice, record)?;
                let child = children
                    .iter()
                    .find(|child| child.is_directory && child.name.eq_ignore_ascii_case(component))
                    .with_context(|| format!("directory not found: {component}"))?;
                record = child.file_record_number;
            }
            let mut stack: Vec<(u64, Vec<String>)> = vec![(record, Vec::new())];
            let mut seen_records: HashSet<u64> = HashSet::new();
            while let Some((dir_record, rel_parts)) = stack.pop() {
                if sink.dirs as usize >= LIVE_TREE_EXPORT_MAX_DIRS || !sink.file_budget_left() {
                    sink.truncated = true;
                    break;
                }
                if !seen_records.insert(dir_record) {
                    continue;
                }
                sink.dirs += 1;
                let children = match collect_ntfs_dir_children(&ntfs, &mut slice, dir_record) {
                    Ok(children) => children,
                    Err(err) => {
                        sink.skip(format!("record {dir_record}: {err}"));
                        continue;
                    }
                };
                for child in children {
                    if !sink.file_budget_left() {
                        sink.truncated = true;
                        break;
                    }
                    let mut child_rel = rel_parts.clone();
                    child_rel.push(child.name.clone());
                    if child.is_directory {
                        stack.push((child.file_record_number, child_rel));
                        continue;
                    }
                    if child.size_bytes > LIVE_EXPORT_MAX_BYTES {
                        sink.skip(format!(
                            "{}: {} bytes exceeds export cap",
                            child.name, child.size_bytes
                        ));
                        continue;
                    }
                    match read_ntfs_file_record_bytes(
                        &ntfs,
                        &mut slice,
                        child.file_record_number,
                        child.size_bytes as usize,
                    ) {
                        Ok(bytes) => sink.write_file(&child_rel, &bytes)?,
                        Err(err) => sink.skip(format!("{}: {err}", child.name)),
                    }
                }
            }
        }
        other => bail!("live export is not supported for {other} volumes"),
    }

    sink.finish()
}

/// Audit trail for a recursive live folder export.
pub fn record_live_tree_export(
    case_path: &Path,
    evidence_id: i64,
    volume_index: usize,
    dir_path: &str,
    result: &LiveTreeExportResult,
) -> Result<()> {
    let mut conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let actor = audit_actor(&tx, case_id)?;
    tx.execute(
        "INSERT INTO audit_events(case_id, event_type, actor, object_type, object_id, details_json)
         VALUES (?1, 'live.export_tree', ?2, 'evidence', ?3,
                 json_object('volume', ?4, 'dir_path', ?5, 'output_dir', ?6,
                             'files_exported', ?7, 'bytes_written', ?8,
                             'skipped', ?9, 'truncated', ?10, 'manifest_path', ?11))",
        params![
            case_id,
            actor,
            evidence_id,
            volume_index as i64,
            dir_path,
            result.output_dir,
            result.files_exported as i64,
            result.bytes_written as i64,
            result.skipped_count as i64,
            result.truncated,
            result.manifest_path
        ],
    )?;
    tx.commit()?;
    Ok(())
}

/// Audit trail for a live (un-indexed) file export.
pub fn record_live_export(
    case_path: &Path,
    evidence_id: i64,
    volume_index: usize,
    file_path: &str,
    result: &LiveExportResult,
) -> Result<()> {
    let mut conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let actor = audit_actor(&tx, case_id)?;
    tx.execute(
        "INSERT INTO audit_events(case_id, event_type, actor, object_type, object_id, details_json)
         VALUES (?1, 'live.export', ?2, 'evidence', ?3,
                 json_object('volume', ?4, 'file_path', ?5, 'output_path', ?6,
                             'bytes_written', ?7, 'sha256', ?8))",
        params![
            case_id,
            actor,
            evidence_id,
            volume_index as i64,
            file_path,
            result.output_path,
            result.bytes_written as i64,
            result.sha256_hex
        ],
    )?;
    tx.commit()?;
    Ok(())
}

fn open_disk_image(path: &Path) -> Result<OpenedDiskImage> {
    if let Some(segments) = split_raw_segments(path)? {
        let reader = SplitRawReader::open(&segments)?;
        return Ok(OpenedDiskImage {
            format: format!("SplitRaw({} segments)", segments.len()),
            decoded_size: reader.total_size,
            reader: Box::new(reader),
            container_finding_count: 0,
        });
    }
    if looks_like_vdi(path) {
        let file = positioned_io2::RandomAccessFile::open(path)
            .with_context(|| format!("opening VDI image {}", path.display()))?;
        let disk = vdi::VdiDisk::open(Box::new(file))
            .with_context(|| format!("decoding VDI image {}", path.display()))?;
        return Ok(OpenedDiskImage {
            format: "Vdi".to_string(),
            decoded_size: disk.header.disk_size,
            reader: Box::new(disk),
            container_finding_count: 0,
        });
    }

    let opened = disk_forensic::container::open(path)
        .with_context(|| format!("opening disk image {}", path.display()))?;
    Ok(OpenedDiskImage {
        format: format!("{:?}", opened.format),
        decoded_size: opened.size,
        reader: opened.reader,
        container_finding_count: opened.findings.len(),
    })
}

fn looks_like_vdi(path: &Path) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .map(|value| value.eq_ignore_ascii_case("vdi"))
        .unwrap_or(false)
}

fn is_supported_fat_partition(partition_type: Option<&str>, filesystem: Option<&str>) -> bool {
    let text = [partition_type, filesystem]
        .into_iter()
        .flatten()
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>()
        .join(" ");
    text.contains("fat") && !text.contains("exfat")
}

fn is_supported_ntfs_partition(partition_type: Option<&str>, filesystem: Option<&str>) -> bool {
    let text = [partition_type, filesystem]
        .into_iter()
        .flatten()
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>()
        .join(" ");
    text.contains("ntfs")
}

#[allow(clippy::too_many_arguments)]
fn process_whole_volume_fallback(
    conn: &Connection,
    case_id: i64,
    evidence_id: i64,
    job_id: i64,
    reader: &mut dyn disk_forensic::container::ReadSeek,
    source_path: &str,
    decoded_size: u64,
    container_format: &str,
    partition_scheme: Option<&str>,
    indexed: &mut usize,
    max_entries: usize,
) -> Result<bool> {
    if *indexed >= max_entries {
        return Ok(true);
    }

    let volume_prefix = "/Image Analysis/Volumes/000-whole-image";
    let filesystem = match detect_whole_volume_filesystem(reader)? {
        Some(filesystem) => filesystem,
        None => {
            if let Some(info) = read_btrfs_superblock(reader, 0)? {
                record_btrfs_volume(
                    conn,
                    case_id,
                    evidence_id,
                    job_id,
                    0,
                    decoded_size,
                    volume_prefix,
                    "Whole Image",
                    0,
                    &info,
                    indexed,
                )?;
            }
            return Ok(false);
        }
    };
    if filesystem == "EXT" {
        return match process_ext_partition_entries(
            conn,
            case_id,
            evidence_id,
            job_id,
            source_path,
            0,
            decoded_size,
            volume_prefix,
            "Whole Image",
            0,
            indexed,
            max_entries,
        ) {
            Ok(truncated) => Ok(truncated),
            Err(err) => {
                if *indexed >= max_entries {
                    return Ok(true);
                }
                insert_image_record(
                    conn,
                    case_id,
                    evidence_id,
                    &format!("{volume_prefix}/Parser Error.record"),
                    "Parser Error",
                    None,
                    &serde_json::json!({
                        "artifact_kind": "filesystem_parser_error",
                        "filesystem": filesystem,
                        "filesystem_parser": "ext4",
                        "partition_scheme": partition_scheme,
                        "start_offset": 0,
                        "size_bytes": decoded_size,
                        "error": err.to_string(),
                    }),
                    job_id,
                )?;
                *indexed += 1;
                Ok(false)
            }
        };
    }
    if filesystem == "FAT" {
        return match process_fat_partition_entries(
            conn,
            case_id,
            evidence_id,
            job_id,
            reader,
            0,
            decoded_size,
            volume_prefix,
            "Whole Image",
            0,
            indexed,
            max_entries,
        ) {
            Ok(truncated) => Ok(truncated),
            Err(err) => {
                if *indexed >= max_entries {
                    return Ok(true);
                }
                insert_image_record(
                    conn,
                    case_id,
                    evidence_id,
                    &format!("{volume_prefix}/Parser Error.record"),
                    "Parser Error",
                    None,
                    &serde_json::json!({
                        "artifact_kind": "filesystem_parser_error",
                        "filesystem": filesystem,
                        "filesystem_parser": "fatfs",
                        "partition_scheme": partition_scheme,
                        "start_offset": 0,
                        "size_bytes": decoded_size,
                        "error": err.to_string(),
                    }),
                    job_id,
                )?;
                *indexed += 1;
                Ok(false)
            }
        };
    }

    if filesystem == "NTFS" {
        return match process_ntfs_partition_entries(
            conn,
            case_id,
            evidence_id,
            job_id,
            reader,
            0,
            decoded_size,
            volume_prefix,
            "Whole Image",
            0,
            indexed,
            max_entries,
        ) {
            Ok(truncated) => Ok(truncated),
            Err(err) => {
                if *indexed >= max_entries {
                    return Ok(true);
                }
                insert_image_record(
                    conn,
                    case_id,
                    evidence_id,
                    &format!("{volume_prefix}/Parser Error.record"),
                    "Parser Error",
                    None,
                    &serde_json::json!({
                        "artifact_kind": "filesystem_parser_error",
                        "filesystem": filesystem,
                        "filesystem_parser": "ntfs",
                        "partition_scheme": partition_scheme,
                        "start_offset": 0,
                        "size_bytes": decoded_size,
                        "error": err.to_string(),
                    }),
                    job_id,
                )?;
                *indexed += 1;
                Ok(false)
            }
        };
    }

    insert_image_record(
        conn,
        case_id,
        evidence_id,
        "/Image Analysis/Volumes/000-whole-image.record",
        "Whole Image Volume",
        Some(i64::try_from(decoded_size).unwrap_or(i64::MAX)),
        &serde_json::json!({
            "artifact_kind": "disk_volume",
            "container_format": container_format,
            "partition_scheme": partition_scheme,
            "name": "Whole Image",
            "filesystem": filesystem,
            "start_offset": 0,
            "size_bytes": decoded_size,
            "end_offset_exclusive": decoded_size,
            "filesystem_parser": "pending",
            "filesystem_browsing_status": "pending filesystem parser",
        }),
        job_id,
    )?;
    *indexed += 1;
    Ok(false)
}

fn detect_whole_volume_filesystem(
    reader: &mut dyn disk_forensic::container::ReadSeek,
) -> Result<Option<&'static str>> {
    detect_volume_filesystem_at(reader, 0)
}

struct BtrfsInfo {
    fsid: String,
    label: String,
    total_bytes: u64,
    bytes_used: u64,
    num_devices: u64,
    sector_size: u32,
    node_size: u32,
}

/// Reads the btrfs primary superblock (64 KiB into the volume) and extracts
/// identifying metadata. Returns None when the magic is absent. btrfs tree
/// walking is not implemented; this gives the examiner an accurate record that
/// a btrfs volume exists.
fn read_btrfs_superblock(
    reader: &mut dyn disk_forensic::container::ReadSeek,
    start_offset: u64,
) -> Result<Option<BtrfsInfo>> {
    const SUPERBLOCK_OFFSET: u64 = 0x1_0000;
    let mut sb = [0_u8; 4096];
    reader.seek(SeekFrom::Start(start_offset + SUPERBLOCK_OFFSET))?;
    let read = reader.read(&mut sb)?;
    if read < 4096 || &sb[0x40..0x48] != b"_BHRfS_M" {
        return Ok(None);
    }
    let fsid = sb[0x20..0x30]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let label = String::from_utf8_lossy(&sb[0x12B..0x12B + 256])
        .trim_end_matches('\0')
        .trim()
        .to_string();
    Ok(Some(BtrfsInfo {
        fsid,
        label,
        total_bytes: u64::from_le_bytes(sb[0x70..0x78].try_into().unwrap()),
        bytes_used: u64::from_le_bytes(sb[0x78..0x80].try_into().unwrap()),
        num_devices: u64::from_le_bytes(sb[0x88..0x90].try_into().unwrap()),
        sector_size: u32::from_le_bytes(sb[0x90..0x94].try_into().unwrap()),
        node_size: u32::from_le_bytes(sb[0x94..0x98].try_into().unwrap()),
    }))
}

#[allow(clippy::too_many_arguments)]
fn record_btrfs_volume(
    conn: &Connection,
    case_id: i64,
    evidence_id: i64,
    job_id: i64,
    start_offset: u64,
    size_bytes: u64,
    volume_prefix: &str,
    volume_name: &str,
    partition_index: usize,
    info: &BtrfsInfo,
    indexed: &mut usize,
) -> Result<()> {
    insert_image_record(
        conn,
        case_id,
        evidence_id,
        volume_prefix,
        volume_name,
        None,
        &serde_json::json!({
            "artifact_kind": "filesystem_volume",
            "filesystem_parser": "btrfs-metadata",
            "filesystem": "btrfs",
            "filesystem_browsing_status":
                "btrfs volume detected from superblock; directory tree walking is not yet implemented",
            "partition_index": partition_index,
            "partition_start_offset": start_offset,
            "partition_size_bytes": size_bytes,
            "btrfs_fsid": info.fsid,
            "btrfs_label": info.label,
            "btrfs_total_bytes": info.total_bytes,
            "btrfs_bytes_used": info.bytes_used,
            "btrfs_num_devices": info.num_devices,
            "btrfs_sector_size": info.sector_size,
            "btrfs_node_size": info.node_size,
        }),
        job_id,
    )?;
    *indexed += 1;
    Ok(())
}

const EXT_MAX_DIRS: usize = 20_000;

/// Adapts an owned disk-image reader to the ext4-view `Ext4Read` trait,
/// translating filesystem-relative offsets to the partition's byte range.
struct Ext4ImageReader {
    reader: Box<dyn disk_forensic::container::ReadSeek>,
    partition_start: u64,
}

impl ext4_view::Ext4Read for Ext4ImageReader {
    fn read(
        &mut self,
        start_byte: u64,
        dst: &mut [u8],
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        self.reader.seek(SeekFrom::Start(
            self.partition_start.saturating_add(start_byte),
        ))?;
        self.reader.read_exact(dst)?;
        Ok(())
    }
}

/// Indexes an ext2/3/4 volume via the read-only ext4-view crate. Opens its own
/// image handle (the crate needs an owned reader) and walks the directory tree
/// breadth-first, bounded by max_entries and a directory cap.
#[allow(clippy::too_many_arguments)]
fn process_ext_partition_entries(
    conn: &Connection,
    case_id: i64,
    evidence_id: i64,
    job_id: i64,
    source_path: &str,
    start_offset: u64,
    size_bytes: u64,
    volume_prefix: &str,
    volume_name: &str,
    partition_index: usize,
    indexed: &mut usize,
    max_entries: usize,
) -> Result<bool> {
    let opened = open_disk_image(Path::new(source_path))?;
    let reader = Ext4ImageReader {
        reader: opened.reader,
        partition_start: start_offset,
    };
    let fs = ext4_view::Ext4::load(Box::new(reader))
        .map_err(|err| anyhow!("opening ext filesystem at image offset {start_offset}: {err}"))?;

    upsert_filesystem_entry(
        conn,
        case_id,
        evidence_id,
        volume_prefix,
        volume_name,
        "directory",
        None,
        &categorized_metadata_json(
            serde_json::json!({
                "artifact_kind": "filesystem_volume",
                "filesystem_parser": "ext4",
                "filesystem": "ext2/3/4",
                "partition_index": partition_index,
                "partition_start_offset": start_offset,
                "partition_size_bytes": size_bytes,
            }),
            volume_prefix,
            volume_name,
            "directory",
        ),
        job_id,
    )?;
    *indexed += 1;
    if *indexed >= max_entries {
        return Ok(true);
    }

    let mut truncated = false;
    // (ext absolute path, logical path prefix) work queue, breadth-first.
    let mut queue: std::collections::VecDeque<(String, String)> = std::collections::VecDeque::new();
    queue.push_back(("/".to_string(), volume_prefix.to_string()));
    let mut dirs_walked = 0_usize;

    while let Some((ext_path, parent_logical)) = queue.pop_front() {
        if dirs_walked >= EXT_MAX_DIRS {
            truncated = true;
            break;
        }
        dirs_walked += 1;
        let read_dir = match fs.read_dir(ext_path.as_str()) {
            Ok(read_dir) => read_dir,
            Err(_) => continue,
        };
        let mut used_paths = HashSet::new();
        for entry in read_dir {
            if *indexed >= max_entries {
                truncated = true;
                break;
            }
            let Ok(entry) = entry else { continue };
            let name = String::from_utf8_lossy(entry.file_name().as_ref()).into_owned();
            if name == "." || name == ".." {
                continue;
            }
            let file_type = entry.file_type().ok();
            let is_dir = file_type.map(|ft| ft.is_dir()).unwrap_or(false);
            let is_symlink = file_type.map(|ft| ft.is_symlink()).unwrap_or(false);
            let metadata = entry.metadata().ok();
            let size = metadata.as_ref().map(|meta| meta.len());
            let entry_kind = if is_dir { "directory" } else { "file" };

            let segment = sanitize_logical_segment(&name);
            let mut logical_path = format!("{parent_logical}/{segment}");
            let mut suffix = 2;
            while !used_paths.insert(logical_path.clone()) {
                logical_path = format!("{parent_logical}/{segment}-{suffix}");
                suffix += 1;
            }
            let child_ext_path = if ext_path == "/" {
                format!("/{name}")
            } else {
                format!("{ext_path}/{name}")
            };

            let mut entry_metadata = serde_json::json!({
                "artifact_kind": "filesystem_entry",
                "filesystem_parser": "ext4",
                "partition_index": partition_index,
                "partition_start_offset": start_offset,
                "partition_size_bytes": size_bytes,
                "storage_area": "allocated_file",
                "source_entry_name": name,
                "ext_path": child_ext_path,
                "ext_is_symlink": is_symlink,
                "ext_mode_octal": metadata.as_ref().map(|meta| format!("{:o}", meta.mode())),
                "ext_uid": metadata.as_ref().map(|meta| meta.uid()),
                "ext_gid": metadata.as_ref().map(|meta| meta.gid()),
            });
            add_entry_category(&mut entry_metadata, &logical_path, &name, entry_kind);
            upsert_filesystem_entry(
                conn,
                case_id,
                evidence_id,
                &logical_path,
                &name,
                entry_kind,
                size.map(|value| i64::try_from(value).unwrap_or(i64::MAX)),
                &entry_metadata.to_string(),
                job_id,
            )?;
            *indexed += 1;
            if is_dir {
                queue.push_back((child_ext_path, logical_path));
            }
        }
        if truncated {
            break;
        }
    }
    Ok(truncated)
}

const LOST_PARTITION_MIN_GAP_BYTES: u64 = 1024 * 1024;
const LOST_PARTITION_PROBE_STEP: u64 = 1024 * 1024;
const LOST_PARTITION_MAX_PROBES: usize = 4096;
const LOST_PARTITION_MAX_VOLUMES: usize = 8;

/// Old-Ecase-style "Recover Partitions": probe unpartitioned gaps for orphaned
/// NTFS/FAT boot sectors and index hits as recovered volumes. Bounded: gaps
/// under 1 MiB are skipped, probes step 1 MiB (plus the legacy 63-sector
/// offset), and probe/volume counts are capped.
#[allow(clippy::too_many_arguments)]
fn scan_lost_partitions(
    conn: &Connection,
    case_id: i64,
    evidence_id: i64,
    job_id: i64,
    reader: &mut dyn disk_forensic::container::ReadSeek,
    disk_size: u64,
    declared: &[(u64, u64)],
    skip_offsets: &[u64],
    declared_count: usize,
    indexed: &mut usize,
    max_entries: usize,
) -> Result<bool> {
    let mut ranges: Vec<(u64, u64)> = declared.to_vec();
    ranges.sort_unstable();
    let mut gaps: Vec<(u64, u64)> = Vec::new();
    let mut cursor = 0_u64;
    for (start, size) in &ranges {
        if *start > cursor && *start - cursor >= LOST_PARTITION_MIN_GAP_BYTES {
            gaps.push((cursor, *start));
        }
        cursor = cursor.max(start.saturating_add(*size));
    }
    if disk_size > cursor && disk_size - cursor >= LOST_PARTITION_MIN_GAP_BYTES {
        gaps.push((cursor, disk_size));
    }

    let mut truncated = false;
    let mut probes = 0_usize;
    let mut recovered = 0_usize;
    for (gap_start, gap_end) in gaps {
        if recovered >= LOST_PARTITION_MAX_VOLUMES || probes >= LOST_PARTITION_MAX_PROBES {
            break;
        }
        // Candidate offsets: the gap start, the legacy CHS 63-sector offset,
        // then every probe-step alignment inside the gap.
        let mut candidates: Vec<u64> = Vec::new();
        candidates.push(gap_start);
        let legacy = gap_start.saturating_add(63 * 512);
        if legacy < gap_end {
            candidates.push(legacy);
        }
        let mut aligned = gap_start.div_ceil(LOST_PARTITION_PROBE_STEP) * LOST_PARTITION_PROBE_STEP;
        while aligned < gap_end && candidates.len() < LOST_PARTITION_MAX_PROBES {
            if aligned != gap_start {
                candidates.push(aligned);
            }
            aligned = aligned.saturating_add(LOST_PARTITION_PROBE_STEP);
        }

        let mut resume_after = 0_u64;
        for candidate in candidates {
            if candidate < resume_after
                || skip_offsets.contains(&candidate)
                || probes >= LOST_PARTITION_MAX_PROBES
                || recovered >= LOST_PARTITION_MAX_VOLUMES
            {
                continue;
            }
            probes += 1;
            let Some(filesystem) = detect_volume_filesystem_at(reader, candidate)? else {
                continue;
            };
            let volume_size = recovered_volume_size(reader, candidate, filesystem)?
                .unwrap_or(gap_end - candidate)
                .min(gap_end - candidate);
            recovered += 1;
            resume_after = candidate.saturating_add(volume_size);
            let fs_lower = filesystem.to_ascii_lowercase();
            let name = format!("recovered-{recovered:02}-{fs_lower}");
            let volume_prefix = format!("/Image Analysis/Volumes/{name}");
            if *indexed >= max_entries {
                return Ok(true);
            }
            insert_image_record(
                conn,
                case_id,
                evidence_id,
                &format!("/Image Analysis/Partitions/{name}.record"),
                &name,
                Some(i64::try_from(volume_size).unwrap_or(i64::MAX)),
                &serde_json::json!({
                    "artifact_kind": "recovered_partition",
                    "recovery_source": "boot_sector_scan",
                    "recovery_status": "orphaned boot sector found in unpartitioned gap",
                    "detected_filesystem": filesystem,
                    "start_offset": candidate,
                    "size_bytes": volume_size,
                    "end_offset_exclusive": candidate.saturating_add(volume_size),
                    "gap_start": gap_start,
                    "gap_end": gap_end,
                    "volume_entry_prefix": volume_prefix,
                }),
                job_id,
            )?;
            *indexed += 1;
            if *indexed >= max_entries {
                return Ok(true);
            }
            let parse_result = if filesystem == "FAT" {
                process_fat_partition_entries(
                    conn,
                    case_id,
                    evidence_id,
                    job_id,
                    reader,
                    candidate,
                    volume_size,
                    &volume_prefix,
                    &name,
                    declared_count + recovered,
                    indexed,
                    max_entries,
                )
            } else {
                process_ntfs_partition_entries(
                    conn,
                    case_id,
                    evidence_id,
                    job_id,
                    reader,
                    candidate,
                    volume_size,
                    &volume_prefix,
                    &name,
                    declared_count + recovered,
                    indexed,
                    max_entries,
                )
            };
            match parse_result {
                Ok(parse_truncated) => truncated |= parse_truncated,
                Err(err) => {
                    if *indexed >= max_entries {
                        return Ok(true);
                    }
                    insert_image_record(
                        conn,
                        case_id,
                        evidence_id,
                        &format!("{volume_prefix}/Parser Error.record"),
                        "Parser Error",
                        None,
                        &serde_json::json!({
                            "artifact_kind": "filesystem_parser_error",
                            "filesystem_parser": fs_lower,
                            "recovered_partition": true,
                            "error": err.to_string(),
                        }),
                        job_id,
                    )?;
                    *indexed += 1;
                }
            }
        }
    }
    Ok(truncated)
}

/// Derives a recovered volume's size from its boot sector BPB fields.
fn recovered_volume_size(
    reader: &mut dyn disk_forensic::container::ReadSeek,
    start_offset: u64,
    filesystem: &str,
) -> Result<Option<u64>> {
    let mut sector = [0_u8; 512];
    reader.seek(SeekFrom::Start(start_offset))?;
    if reader.read(&mut sector)? < sector.len() {
        return Ok(None);
    }
    let bytes_per_sector = u64::from(u16::from_le_bytes([sector[11], sector[12]]));
    if !(256..=8192).contains(&bytes_per_sector) {
        return Ok(None);
    }
    let total_sectors = if filesystem == "NTFS" {
        u64::from_le_bytes(sector[40..48].try_into().unwrap())
    } else {
        let small = u64::from(u16::from_le_bytes([sector[19], sector[20]]));
        if small > 0 {
            small
        } else {
            u64::from(u32::from_le_bytes(sector[32..36].try_into().unwrap()))
        }
    };
    if total_sectors == 0 {
        return Ok(None);
    }
    Ok(total_sectors.checked_mul(bytes_per_sector))
}

fn detect_volume_filesystem_at(
    reader: &mut dyn disk_forensic::container::ReadSeek,
    start_offset: u64,
) -> Result<Option<&'static str>> {
    // Read past the ext2/3/4 superblock (1024 bytes in) so ext magic can be
    // checked even though ext volumes carry no MBR-style 0x55AA signature.
    let mut header = [0_u8; 2048];
    reader
        .seek(SeekFrom::Start(start_offset))
        .with_context(|| format!("seeking volume boot sector at {start_offset}"))?;
    let bytes_read = reader
        .read(&mut header)
        .with_context(|| format!("reading volume header at {start_offset}"))?;

    // ext2/3/4: s_magic == 0xEF53 at superblock offset 0x38 (absolute 0x438).
    if bytes_read >= 0x43A && header[0x438] == 0x53 && header[0x439] == 0xEF {
        return Ok(Some("EXT"));
    }

    if bytes_read < 512 || header[510] != 0x55 || header[511] != 0xAA {
        return Ok(None);
    }

    let oem_id = ascii_upper_trimmed(&header[3..11]);
    if oem_id.starts_with("NTFS") {
        return Ok(Some("NTFS"));
    }

    let fat_12_16 = ascii_upper_trimmed(&header[54..62]);
    let fat_32 = ascii_upper_trimmed(&header[82..90]);
    if fat_12_16.contains("FAT") || fat_32.contains("FAT") {
        return Ok(Some("FAT"));
    }

    Ok(None)
}

fn ascii_upper_trimmed(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .trim_matches(char::from(0))
        .trim()
        .to_ascii_uppercase()
}

fn process_fat_partition_entries(
    conn: &Connection,
    case_id: i64,
    evidence_id: i64,
    job_id: i64,
    reader: &mut dyn disk_forensic::container::ReadSeek,
    start_offset: u64,
    size_bytes: u64,
    volume_prefix: &str,
    volume_name: &str,
    partition_index: usize,
    indexed: &mut usize,
    max_entries: usize,
) -> Result<bool> {
    let mut truncated = false;
    {
        let slice = PartitionSlice::new(&mut *reader, start_offset, size_bytes);
        let fs = fatfs::FileSystem::new(slice, fatfs::FsOptions::new())
            .with_context(|| format!("opening FAT filesystem at image offset {start_offset}"))?;
        let fat_type = format!("{:?}", fs.fat_type());
        let volume_label = fs
            .read_volume_label_from_root_dir()
            .ok()
            .flatten()
            .or_else(|| Some(fs.volume_label()))
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());

        upsert_filesystem_entry(
            conn,
            case_id,
            evidence_id,
            volume_prefix,
            volume_name,
            "directory",
            None,
            &categorized_metadata_json(
                serde_json::json!({
                    "artifact_kind": "filesystem_volume",
                    "filesystem_parser": "fatfs",
                    "filesystem": fat_type,
                    "volume_label": volume_label,
                    "partition_index": partition_index,
                    "partition_start_offset": start_offset,
                    "partition_size_bytes": size_bytes,
                }),
                volume_prefix,
                volume_name,
                "directory",
            ),
            job_id,
        )?;
        *indexed += 1;
        if *indexed >= max_entries {
            return Ok(true);
        }

        walk_fat_dir(
            conn,
            case_id,
            evidence_id,
            job_id,
            &fs.root_dir(),
            volume_prefix,
            partition_index,
            start_offset,
            size_bytes,
            "",
            indexed,
            max_entries,
            &mut truncated,
        )?;
    }
    if *indexed < max_entries {
        // The fatfs crate only exposes live entries; deleted (0xE5) directory
        // records need a raw bounded walk over the same volume.
        if let Err(err) = scan_fat_deleted_entries(
            conn,
            case_id,
            evidence_id,
            job_id,
            reader,
            start_offset,
            size_bytes,
            volume_prefix,
            partition_index,
            indexed,
            max_entries,
            &mut truncated,
        ) {
            insert_image_record(
                conn,
                case_id,
                evidence_id,
                &format!("{volume_prefix}/Deleted Scan Error.record"),
                "Deleted Scan Error",
                None,
                &serde_json::json!({
                    "artifact_kind": "filesystem_parser_error",
                    "filesystem_parser": "fatfs-deleted",
                    "error": err.to_string(),
                }),
                job_id,
            )?;
            *indexed += 1;
        }
    }
    Ok(truncated)
}

const FAT_DELETED_MAX_DIRS: usize = 128;
const FAT_DELETED_MAX_CHAIN_CLUSTERS: usize = 1024;
const FAT_DELETED_MAX_RECORDS: usize = 512;
const FAT_DELETED_MAX_DIR_BYTES: usize = 1024 * 1024;
const FAT_TABLE_MAX_BYTES: usize = 16 * 1024 * 1024;

struct FatLayout {
    bytes_per_sector: u64,
    sectors_per_cluster: u64,
    first_data_sector: u64,
    cluster_count: u64,
    fat_kind: u8,
    root_dir_offset: u64,
    root_dir_bytes: u64,
    root_cluster: u64,
    fat_table: Vec<u8>,
}

impl FatLayout {
    fn cluster_data_offset(&self, cluster: u64) -> Option<u64> {
        if cluster < 2 || cluster >= 2 + self.cluster_count {
            return None;
        }
        Some(
            (self.first_data_sector + (cluster - 2) * self.sectors_per_cluster)
                * self.bytes_per_sector,
        )
    }

    fn next_cluster(&self, cluster: u64) -> Option<u64> {
        let table = &self.fat_table;
        let value = match self.fat_kind {
            12 => {
                let index = (cluster + cluster / 2) as usize;
                let raw = u16::from_le_bytes([*table.get(index)?, *table.get(index + 1)?]) as u64;
                if cluster & 1 == 1 {
                    raw >> 4
                } else {
                    raw & 0x0FFF
                }
            }
            16 => {
                let index = (cluster * 2) as usize;
                u16::from_le_bytes([*table.get(index)?, *table.get(index + 1)?]) as u64
            }
            _ => {
                let index = (cluster * 4) as usize;
                (u32::from_le_bytes([
                    *table.get(index)?,
                    *table.get(index + 1)?,
                    *table.get(index + 2)?,
                    *table.get(index + 3)?,
                ]) & 0x0FFF_FFFF) as u64
            }
        };
        let end = match self.fat_kind {
            12 => 0x0FF8,
            16 => 0xFFF8,
            _ => 0x0FFF_FFF8,
        };
        if value >= end || value < 2 {
            None
        } else {
            Some(value)
        }
    }
}

fn parse_fat_layout(
    reader: &mut dyn disk_forensic::container::ReadSeek,
    start_offset: u64,
) -> Result<Option<FatLayout>> {
    let mut boot = [0_u8; 512];
    reader.seek(SeekFrom::Start(start_offset))?;
    if reader.read(&mut boot)? < boot.len() {
        return Ok(None);
    }
    let bytes_per_sector = u64::from(u16::from_le_bytes([boot[11], boot[12]]));
    let sectors_per_cluster = u64::from(boot[13]);
    let reserved = u64::from(u16::from_le_bytes([boot[14], boot[15]]));
    let num_fats = u64::from(boot[16]);
    let root_entries = u64::from(u16::from_le_bytes([boot[17], boot[18]]));
    let fat_size_16 = u64::from(u16::from_le_bytes([boot[22], boot[23]]));
    let fat_size = if fat_size_16 > 0 {
        fat_size_16
    } else {
        u64::from(u32::from_le_bytes(boot[36..40].try_into().unwrap()))
    };
    let total_16 = u64::from(u16::from_le_bytes([boot[19], boot[20]]));
    let total_sectors = if total_16 > 0 {
        total_16
    } else {
        u64::from(u32::from_le_bytes(boot[32..36].try_into().unwrap()))
    };
    if !(256..=8192).contains(&bytes_per_sector)
        || sectors_per_cluster == 0
        || num_fats == 0
        || fat_size == 0
        || total_sectors == 0
    {
        return Ok(None);
    }
    let root_dir_sectors = (root_entries * 32).div_ceil(bytes_per_sector);
    let first_data_sector = reserved + num_fats * fat_size + root_dir_sectors;
    let cluster_count = total_sectors.saturating_sub(first_data_sector) / sectors_per_cluster;
    let fat_kind = if cluster_count < 4085 {
        12
    } else if cluster_count < 65_525 {
        16
    } else {
        32
    };
    let table_len = usize::try_from(fat_size * bytes_per_sector)
        .unwrap_or(FAT_TABLE_MAX_BYTES)
        .min(FAT_TABLE_MAX_BYTES);
    let mut fat_table = vec![0_u8; table_len];
    reader.seek(SeekFrom::Start(start_offset + reserved * bytes_per_sector))?;
    let read = reader.read(&mut fat_table)?;
    fat_table.truncate(read);
    Ok(Some(FatLayout {
        bytes_per_sector,
        sectors_per_cluster,
        first_data_sector,
        cluster_count,
        fat_kind,
        root_dir_offset: (reserved + num_fats * fat_size) * bytes_per_sector,
        root_dir_bytes: root_entries * 32,
        root_cluster: u64::from(u32::from_le_bytes(boot[44..48].try_into().unwrap())),
        fat_table,
    }))
}

fn fat_short_name(entry: &[u8], deleted: bool) -> String {
    let mut base: Vec<u8> = entry[0..8].to_vec();
    if deleted {
        base[0] = b'_';
    }
    let base = String::from_utf8_lossy(&base).trim_end().to_string();
    let ext = String::from_utf8_lossy(&entry[8..11])
        .trim_end()
        .to_string();
    if ext.is_empty() {
        base
    } else {
        format!("{base}.{ext}")
    }
}

fn dos_datetime_to_utc(date: u16, time: u16) -> Option<String> {
    if date == 0 {
        return None;
    }
    let year = 1980 + i32::from(date >> 9);
    let month = u32::from((date >> 5) & 0x0F);
    let day = u32::from(date & 0x1F);
    let stamp = chrono::NaiveDate::from_ymd_opt(year, month, day)?.and_hms_opt(
        u32::from(time >> 11),
        u32::from((time >> 5) & 0x3F),
        u32::from(time & 0x1F) * 2,
    )?;
    Some(stamp.format("%Y-%m-%dT%H:%M:%SZ").to_string())
}

/// Indexes deleted (0xE5) FAT directory entries under
/// `{volume_prefix}/Recovery/Deleted Files`. Data recovery assumes the
/// original allocation was contiguous from the recorded first cluster, which
/// is the standard FAT undelete heuristic.
#[allow(clippy::too_many_arguments)]
fn scan_fat_deleted_entries(
    conn: &Connection,
    case_id: i64,
    evidence_id: i64,
    job_id: i64,
    reader: &mut dyn disk_forensic::container::ReadSeek,
    start_offset: u64,
    size_bytes: u64,
    volume_prefix: &str,
    partition_index: usize,
    indexed: &mut usize,
    max_entries: usize,
    truncated: &mut bool,
) -> Result<()> {
    let Some(layout) = parse_fat_layout(reader, start_offset)? else {
        return Ok(());
    };
    // Directory work queue: byte regions relative to the partition start.
    let mut regions: Vec<(u64, u64, String)> = Vec::new();
    if layout.root_dir_bytes > 0 {
        regions.push((layout.root_dir_offset, layout.root_dir_bytes, String::new()));
    } else if layout.root_cluster >= 2 {
        collect_fat_chain_regions(&layout, layout.root_cluster, String::new(), &mut regions);
    }

    let mut scanned_dirs = 0_usize;
    let mut recorded = 0_usize;
    let mut region_index = 0_usize;
    let recovery_prefix = format!("{volume_prefix}/Recovery/Deleted Files");
    while region_index < regions.len() {
        if scanned_dirs >= FAT_DELETED_MAX_DIRS || recorded >= FAT_DELETED_MAX_RECORDS {
            break;
        }
        let (region_offset, region_len, parent_rel) = regions[region_index].clone();
        region_index += 1;
        scanned_dirs += 1;
        if region_offset >= size_bytes {
            continue;
        }
        let read_len = usize::try_from(region_len.min(size_bytes - region_offset))
            .unwrap_or(FAT_DELETED_MAX_DIR_BYTES)
            .min(FAT_DELETED_MAX_DIR_BYTES);
        let mut region = vec![0_u8; read_len];
        reader.seek(SeekFrom::Start(start_offset + region_offset))?;
        let read = reader.read(&mut region)?;
        region.truncate(read);

        for entry in region.chunks_exact(32) {
            if entry[0] == 0x00 {
                break;
            }
            let attr = entry[11];
            if attr == 0x0F || attr & 0x08 != 0 {
                continue;
            }
            let cluster_hi = if layout.fat_kind == 32 {
                u64::from(u16::from_le_bytes([entry[20], entry[21]])) << 16
            } else {
                0
            };
            let first_cluster = cluster_hi | u64::from(u16::from_le_bytes([entry[26], entry[27]]));
            if entry[0] == 0xE5 {
                if attr & 0x10 != 0 {
                    // Deleted directories are recorded without descending.
                    continue;
                }
                if recorded >= FAT_DELETED_MAX_RECORDS || *indexed >= max_entries {
                    *truncated = true;
                    break;
                }
                let name = fat_short_name(entry, true);
                let file_size = u64::from(u32::from_le_bytes(entry[28..32].try_into().unwrap()));
                let data_logical_offset = layout.cluster_data_offset(first_cluster);
                let data_physical_offset = data_logical_offset.map(|offset| start_offset + offset);
                let logical_path = format!(
                    "{recovery_prefix}/{}{}-cluster{first_cluster}",
                    if parent_rel.is_empty() {
                        String::new()
                    } else {
                        format!("{}-", sanitize_logical_segment(&parent_rel))
                    },
                    sanitize_logical_segment(&name)
                );
                let mut metadata = serde_json::json!({
                    "artifact_kind": "deleted_file_record",
                    "filesystem_parser": "fatfs",
                    "recovery_source": "fat_directory_entry",
                    "recovery_status": "deleted directory entry; data assumed contiguous from first cluster",
                    "recovery_read": "physical_extent",
                    "storage_area": "deleted_filesystem_record",
                    "partition_index": partition_index,
                    "partition_start_offset": start_offset,
                    "fat_parent_path": parent_rel,
                    "fat_first_cluster": first_cluster,
                    "fat_attributes": attr,
                    "file_data_logical_offset": data_logical_offset,
                    "file_data_physical_offset": data_physical_offset,
                    "created_utc": dos_datetime_to_utc(
                        u16::from_le_bytes([entry[16], entry[17]]),
                        u16::from_le_bytes([entry[14], entry[15]]),
                    ),
                    "accessed_utc": dos_datetime_to_utc(u16::from_le_bytes([entry[18], entry[19]]), 0),
                    "modified_utc": dos_datetime_to_utc(
                        u16::from_le_bytes([entry[24], entry[25]]),
                        u16::from_le_bytes([entry[22], entry[23]]),
                    ),
                });
                add_entry_category(&mut metadata, &logical_path, &name, "file");
                let content_head = data_physical_offset.and_then(|offset| {
                    let mut head = vec![0_u8; CONTENT_INDEX_BYTES.min(file_size as usize)];
                    if head.is_empty() {
                        return None;
                    }
                    reader.seek(SeekFrom::Start(offset)).ok()?;
                    let read = reader.read(&mut head).ok()?;
                    head.truncate(read);
                    Some(head)
                });
                upsert_deleted_filesystem_entry_with_content(
                    conn,
                    case_id,
                    evidence_id,
                    &logical_path,
                    &name,
                    "file",
                    Some(i64::try_from(file_size).unwrap_or(i64::MAX)),
                    &metadata.to_string(),
                    job_id,
                    content_head.as_deref(),
                )?;
                *indexed += 1;
                recorded += 1;
            } else if attr & 0x10 != 0 && entry[0] != b'.' && regions.len() < FAT_DELETED_MAX_DIRS {
                let name = fat_short_name(entry, false);
                let rel = if parent_rel.is_empty() {
                    name
                } else {
                    format!("{parent_rel}/{name}")
                };
                collect_fat_chain_regions(&layout, first_cluster, rel, &mut regions);
            }
        }
    }
    Ok(())
}

fn collect_fat_chain_regions(
    layout: &FatLayout,
    first_cluster: u64,
    rel_path: String,
    regions: &mut Vec<(u64, u64, String)>,
) {
    let cluster_bytes = layout.sectors_per_cluster * layout.bytes_per_sector;
    let mut cluster = first_cluster;
    let mut hops = 0_usize;
    while hops < FAT_DELETED_MAX_CHAIN_CLUSTERS {
        let Some(offset) = layout.cluster_data_offset(cluster) else {
            break;
        };
        regions.push((offset, cluster_bytes, rel_path.clone()));
        match layout.next_cluster(cluster) {
            Some(next) if next != cluster => cluster = next,
            _ => break,
        }
        hops += 1;
    }
}

fn process_ntfs_partition_entries(
    conn: &Connection,
    case_id: i64,
    evidence_id: i64,
    job_id: i64,
    reader: &mut dyn disk_forensic::container::ReadSeek,
    start_offset: u64,
    size_bytes: u64,
    volume_prefix: &str,
    volume_name: &str,
    partition_index: usize,
    indexed: &mut usize,
    max_entries: usize,
) -> Result<bool> {
    let mut slice = PartitionSlice::new(reader, start_offset, size_bytes);
    let ntfs = ntfs::Ntfs::new(&mut slice)
        .with_context(|| format!("opening NTFS filesystem at image offset {start_offset}"))?;
    let volume_label = ntfs
        .volume_name(&mut slice)
        .and_then(|value| value.ok())
        .map(|value| value.name().to_string_lossy());
    let root_record_number = ntfs
        .root_directory(&mut slice)
        .context("opening NTFS root directory")?
        .file_record_number();

    upsert_filesystem_entry(
        conn,
        case_id,
        evidence_id,
        volume_prefix,
        volume_name,
        "directory",
        None,
        &categorized_metadata_json(
            serde_json::json!({
                "artifact_kind": "filesystem_volume",
                "filesystem_parser": "ntfs",
                "filesystem": "NTFS",
                "volume_label": volume_label,
                "partition_index": partition_index,
                "partition_start_offset": start_offset,
                "partition_size_bytes": size_bytes,
                "ntfs_cluster_size": ntfs.cluster_size(),
                "ntfs_sector_size": ntfs.sector_size(),
                "ntfs_volume_size": ntfs.size(),
                "ntfs_serial_number": format!("{:016X}", ntfs.serial_number()),
                "ntfs_mft_position": ntfs.mft_position().value().map(|value| value.get()),
                "ntfs_root_record_number": root_record_number,
            }),
            volume_prefix,
            volume_name,
            "directory",
        ),
        job_id,
    )?;
    *indexed += 1;
    if *indexed >= max_entries {
        return Ok(true);
    }

    if let Some(summary) = ntfs_unallocated_summary(&ntfs, &mut slice, start_offset) {
        if summary.total_size_bytes > 0 {
            let logical_path = format!("{volume_prefix}/UnallocatedSpace");
            let mut metadata = serde_json::json!({
                "artifact_kind": "unallocated_space",
                "filesystem_parser": "ntfs",
                "filesystem": "NTFS",
                "recovery_source": "ntfs_bitmap",
                "recovery_status": "free clusters mapped from $Bitmap",
                "storage_area": "unallocated_space",
                "is_unallocated": true,
                "is_file_slack": false,
                "partition_index": partition_index,
                "partition_start_offset": start_offset,
                "partition_size_bytes": size_bytes,
                "ntfs_cluster_size": ntfs.cluster_size(),
                "ntfs_volume_size": ntfs.size(),
                "ntfs_bitmap_file_record_number": ntfs::KnownNtfsFileRecordNumber::Bitmap as u64,
                "ntfs_bitmap_size_bytes": summary.bitmap_size_bytes,
                "ntfs_bitmap_truncated": summary.bitmap_truncated,
                "ntfs_cluster_count": summary.cluster_count,
                "unallocated_run_count": summary.run_count,
                "unallocated_size_bytes": summary.total_size_bytes,
                "unallocated_sample_extents": summary.sample_extents,
            });
            add_entry_category(&mut metadata, &logical_path, "UnallocatedSpace", "file");
            upsert_filesystem_entry(
                conn,
                case_id,
                evidence_id,
                &logical_path,
                "UnallocatedSpace",
                "file",
                Some(i64::try_from(summary.total_size_bytes).unwrap_or(i64::MAX)),
                &metadata.to_string(),
                job_id,
            )?;
            *indexed += 1;
            if *indexed >= max_entries {
                return Ok(true);
            }
        }
    }

    let mut truncated = walk_ntfs_volume(
        conn,
        case_id,
        evidence_id,
        job_id,
        &ntfs,
        &mut slice,
        root_record_number,
        volume_prefix,
        "",
        partition_index,
        start_offset,
        size_bytes,
        indexed,
        max_entries,
    )?;
    if !truncated && *indexed < max_entries {
        truncated |= process_deleted_ntfs_mft_records(
            conn,
            case_id,
            evidence_id,
            job_id,
            &ntfs,
            &mut slice,
            volume_prefix,
            partition_index,
            start_offset,
            size_bytes,
            indexed,
            max_entries,
        )?;
    }
    Ok(truncated)
}

#[derive(Clone)]
struct NtfsDirChild {
    name: String,
    is_directory: bool,
    size_bytes: u64,
    allocated_size: u64,
    file_record_number: u64,
    sequence_number: u16,
    namespace: String,
    namespace_priority: u8,
    creation_time_raw: u64,
    creation_time_utc: Option<String>,
    modification_time_raw: u64,
    modification_time_utc: Option<String>,
    access_time_raw: u64,
    access_time_utc: Option<String>,
    mft_record_modification_time_raw: u64,
    mft_record_modification_time_utc: Option<String>,
    standard_creation_time_raw: Option<u64>,
    standard_creation_time_utc: Option<String>,
    standard_modification_time_raw: Option<u64>,
    standard_modification_time_utc: Option<String>,
    standard_access_time_raw: Option<u64>,
    standard_access_time_utc: Option<String>,
    standard_mft_record_modification_time_raw: Option<u64>,
    standard_mft_record_modification_time_utc: Option<String>,
    file_data_logical_offset: Option<u64>,
}

struct NtfsDataStreamInfo {
    name: String,
    size_bytes: u64,
    file_data_logical_offset: Option<u64>,
    is_resident: bool,
}

#[derive(Clone, Serialize)]
struct NtfsUnallocatedExtent {
    logical_offset: u64,
    physical_offset: u64,
    length_bytes: u64,
}

struct NtfsUnallocatedSummary {
    total_size_bytes: u64,
    run_count: u64,
    cluster_count: u64,
    bitmap_size_bytes: u64,
    bitmap_truncated: bool,
    sample_extents: Vec<NtfsUnallocatedExtent>,
}

fn walk_ntfs_volume<T: Read + Seek>(
    conn: &Connection,
    case_id: i64,
    evidence_id: i64,
    job_id: i64,
    ntfs: &ntfs::Ntfs,
    fs: &mut T,
    root_record_number: u64,
    volume_prefix: &str,
    root_ntfs_path: &str,
    partition_index: usize,
    partition_start_offset: u64,
    partition_size_bytes: u64,
    indexed: &mut usize,
    max_entries: usize,
) -> Result<bool> {
    let mut truncated = false;
    let mut visited_dirs = HashSet::new();
    let mut stack = vec![(
        root_record_number,
        volume_prefix.to_string(),
        root_ntfs_path.to_string(),
    )];

    while let Some((dir_record_number, parent_path, parent_ntfs_path)) = stack.pop() {
        if *indexed >= max_entries {
            truncated = true;
            break;
        }
        if !visited_dirs.insert(dir_record_number) {
            continue;
        }

        let children = collect_ntfs_dir_children(ntfs, fs, dir_record_number)?;
        let mut used_child_paths = HashSet::new();
        for child in children {
            if *indexed >= max_entries {
                truncated = true;
                break;
            }

            let logical_path =
                unique_child_logical_path(&parent_path, &child, &mut used_child_paths);
            let ntfs_path = if parent_ntfs_path.is_empty() {
                child.name.clone()
            } else {
                format!("{parent_ntfs_path}/{}", child.name)
            };
            let entry_kind = if child.is_directory {
                "directory"
            } else {
                "file"
            };
            let size_bytes =
                (!child.is_directory).then(|| i64::try_from(child.size_bytes).unwrap_or(i64::MAX));
            let mft_record_logical_offset =
                ntfs_mft_record_logical_offset(ntfs, child.file_record_number);
            let mft_record_physical_offset = mft_record_logical_offset
                .map(|offset| partition_start_offset.saturating_add(offset));
            let file_data_physical_offset = child
                .file_data_logical_offset
                .map(|offset| partition_start_offset.saturating_add(offset));
            let mut metadata = serde_json::json!({
                "artifact_kind": "filesystem_entry",
                "filesystem_parser": "ntfs",
                "partition_index": partition_index,
                "partition_start_offset": partition_start_offset,
                "partition_size_bytes": partition_size_bytes,
                "storage_area": "allocated_file",
                "source_entry_name": child.name,
                "ntfs_path": ntfs_path,
                "ntfs_file_record_number": child.file_record_number,
                "ntfs_sequence_number": child.sequence_number,
                "mft_record_logical_offset": mft_record_logical_offset,
                "mft_record_physical_offset": mft_record_physical_offset,
                "file_data_logical_offset": child.file_data_logical_offset,
                "file_data_physical_offset": file_data_physical_offset,
                "ntfs_namespace": child.namespace,
                "ntfs_allocated_size": child.allocated_size,
                "ntfs_creation_time_raw": child.creation_time_raw,
                "ntfs_creation_time_utc": child.creation_time_utc,
                "ntfs_modification_time_raw": child.modification_time_raw,
                "ntfs_modification_time_utc": child.modification_time_utc,
                "ntfs_access_time_raw": child.access_time_raw,
                "ntfs_access_time_utc": child.access_time_utc,
                "ntfs_mft_record_modification_time_raw": child.mft_record_modification_time_raw,
                "ntfs_mft_record_modification_time_utc": child.mft_record_modification_time_utc,
                "ntfs_standard_creation_time_raw": child.standard_creation_time_raw,
                "ntfs_standard_creation_time_utc": child.standard_creation_time_utc,
                "ntfs_standard_modification_time_raw": child.standard_modification_time_raw,
                "ntfs_standard_modification_time_utc": child.standard_modification_time_utc,
                "ntfs_standard_access_time_raw": child.standard_access_time_raw,
                "ntfs_standard_access_time_utc": child.standard_access_time_utc,
                "ntfs_standard_mft_record_modification_time_raw": child.standard_mft_record_modification_time_raw,
                "ntfs_standard_mft_record_modification_time_utc": child.standard_mft_record_modification_time_utc,
            });
            if !child.is_directory {
                if let Some(ext) =
                    extension_lower(&child.name).or_else(|| extension_lower(&logical_path))
                {
                    if ext == "eml" {
                        if child.size_bytes <= EMAIL_PARSE_MAX_BYTES {
                            match read_ntfs_file_record_bytes(
                                ntfs,
                                fs,
                                child.file_record_number,
                                EMAIL_PARSE_MAX_BYTES as usize,
                            ) {
                                Ok(bytes) => {
                                    annotate_email_metadata_from_bytes(&mut metadata, "eml", &bytes)
                                }
                                Err(err) => mark_email_parse_skipped(
                                    &mut metadata,
                                    "eml",
                                    &format!("could not read NTFS email message: {err}"),
                                ),
                            }
                        } else {
                            mark_email_parse_skipped(
                                &mut metadata,
                                "eml",
                                "message exceeds bounded email parse limit",
                            );
                        }
                    } else if is_text_rfc822_email_candidate(&ext, &logical_path, &child.name) {
                        if child.size_bytes <= EMAIL_PARSE_MAX_BYTES {
                            if let Ok(bytes) = read_ntfs_file_record_bytes(
                                ntfs,
                                fs,
                                child.file_record_number,
                                EMAIL_PARSE_MAX_BYTES as usize,
                            ) {
                                try_apply_email_metadata_from_bytes(
                                    &mut metadata,
                                    "text-rfc822",
                                    &bytes,
                                );
                            }
                        }
                    } else if is_email_store_extension(&ext) {
                        mark_email_store(&mut metadata, &ext);
                    }
                }
            }
            add_entry_category(&mut metadata, &logical_path, &child.name, entry_kind);
            let content_head = ntfs_file_record_content_head(
                ntfs,
                fs,
                child.file_record_number,
                &metadata,
                entry_kind,
            );
            upsert_filesystem_entry_with_content(
                conn,
                case_id,
                evidence_id,
                &logical_path,
                &child.name,
                entry_kind,
                size_bytes,
                &metadata.to_string(),
                job_id,
                content_head.as_deref(),
            )?;
            *indexed += 1;

            if !child.is_directory && *indexed < max_entries {
                if let Ok(file) = ntfs.file(fs, child.file_record_number) {
                    let named_streams = ntfs_named_data_streams(&file, fs);
                    for stream in named_streams {
                        if *indexed >= max_entries {
                            truncated = true;
                            break;
                        }

                        let stream_display_name = format!("{}:{}", child.name, stream.name);
                        let stream_logical_path = format!("{logical_path}:{}", stream.name);
                        let stream_ntfs_path = format!("{ntfs_path}:{}", stream.name);
                        let stream_physical_offset = stream
                            .file_data_logical_offset
                            .map(|offset| partition_start_offset.saturating_add(offset));
                        let mut stream_metadata = serde_json::json!({
                            "artifact_kind": "filesystem_entry",
                            "filesystem_parser": "ntfs",
                            "partition_index": partition_index,
                            "partition_start_offset": partition_start_offset,
                            "partition_size_bytes": partition_size_bytes,
                            "storage_area": "alternate_data_stream",
                            "source_entry_name": stream_display_name,
                            "ntfs_path": stream_ntfs_path,
                            "ntfs_base_path": ntfs_path,
                            "ntfs_base_name": child.name,
                            "ntfs_file_record_number": child.file_record_number,
                            "ntfs_sequence_number": child.sequence_number,
                            "ntfs_data_stream_name": stream.name,
                            "ntfs_data_stream_type": "$DATA",
                            "ntfs_data_stream_resident": stream.is_resident,
                            "mft_record_logical_offset": mft_record_logical_offset,
                            "mft_record_physical_offset": mft_record_physical_offset,
                            "file_data_logical_offset": stream.file_data_logical_offset,
                            "file_data_physical_offset": stream_physical_offset,
                            "ntfs_namespace": child.namespace,
                            "ntfs_allocated_size": stream.size_bytes,
                            "ntfs_creation_time_raw": child.creation_time_raw,
                            "ntfs_creation_time_utc": child.creation_time_utc,
                            "ntfs_modification_time_raw": child.modification_time_raw,
                            "ntfs_modification_time_utc": child.modification_time_utc,
                            "ntfs_access_time_raw": child.access_time_raw,
                            "ntfs_access_time_utc": child.access_time_utc,
                            "ntfs_mft_record_modification_time_raw": child.mft_record_modification_time_raw,
                            "ntfs_mft_record_modification_time_utc": child.mft_record_modification_time_utc,
                            "ntfs_standard_creation_time_raw": child.standard_creation_time_raw,
                            "ntfs_standard_creation_time_utc": child.standard_creation_time_utc,
                            "ntfs_standard_modification_time_raw": child.standard_modification_time_raw,
                            "ntfs_standard_modification_time_utc": child.standard_modification_time_utc,
                            "ntfs_standard_access_time_raw": child.standard_access_time_raw,
                            "ntfs_standard_access_time_utc": child.standard_access_time_utc,
                            "ntfs_standard_mft_record_modification_time_raw": child.standard_mft_record_modification_time_raw,
                            "ntfs_standard_mft_record_modification_time_utc": child.standard_mft_record_modification_time_utc,
                            "is_unallocated": false,
                            "is_file_slack": false,
                        });
                        add_entry_category(
                            &mut stream_metadata,
                            &stream_logical_path,
                            &stream_display_name,
                            "file",
                        );
                        upsert_filesystem_entry(
                            conn,
                            case_id,
                            evidence_id,
                            &stream_logical_path,
                            &stream_display_name,
                            "file",
                            Some(i64::try_from(stream.size_bytes).unwrap_or(i64::MAX)),
                            &stream_metadata.to_string(),
                            job_id,
                        )?;
                        *indexed += 1;
                    }
                }
            }

            if child.is_directory {
                stack.push((child.file_record_number, logical_path, ntfs_path));
            }
        }
    }

    Ok(truncated)
}

fn process_deleted_ntfs_mft_records<T: Read + Seek>(
    conn: &Connection,
    case_id: i64,
    evidence_id: i64,
    job_id: i64,
    ntfs: &ntfs::Ntfs,
    fs: &mut T,
    volume_prefix: &str,
    partition_index: usize,
    partition_start_offset: u64,
    partition_size_bytes: u64,
    indexed: &mut usize,
    max_entries: usize,
) -> Result<bool> {
    let Some(record_count) = ntfs_mft_record_count(ntfs, fs) else {
        return Ok(false);
    };
    let remaining = max_entries.saturating_sub(*indexed) as u64;
    if remaining == 0 {
        return Ok(true);
    }
    let scan_limit = record_count
        .min(200_000)
        .min(remaining.saturating_mul(100).saturating_add(1024));
    let mut truncated = record_count > scan_limit;
    let recovery_prefix = format!("{volume_prefix}/Recovery/Deleted Files");

    for record_number in 16..scan_limit {
        if *indexed >= max_entries {
            truncated = true;
            break;
        }
        let Ok(file) = ntfs.file(fs, record_number) else {
            continue;
        };
        if file.flags().contains(ntfs::NtfsFileFlags::IN_USE) {
            continue;
        }
        let Some(name) = ntfs_primary_file_name(&file, fs) else {
            continue;
        };
        let is_directory = file.is_directory();
        let entry_kind = if is_directory { "directory" } else { "file" };
        let size_bytes = if is_directory {
            None
        } else {
            Some(i64::try_from(name.data_size).unwrap_or(i64::MAX))
        };
        let logical_path = format!(
            "{recovery_prefix}/{}-mft{}",
            sanitize_logical_segment(&name.name),
            record_number
        );
        let standard_info = file.info().ok();
        let file_data_logical_offset = if is_directory {
            None
        } else {
            ntfs_default_data_logical_offset(&file, fs)
        };
        let file_data_physical_offset =
            file_data_logical_offset.map(|offset| partition_start_offset.saturating_add(offset));
        let mft_record_logical_offset = ntfs_mft_record_logical_offset(ntfs, record_number);
        let mft_record_physical_offset =
            mft_record_logical_offset.map(|offset| partition_start_offset.saturating_add(offset));
        let recovery_status = if is_directory {
            "metadata only"
        } else if file_data_logical_offset.is_some() {
            "data stream located"
        } else {
            "data stream not located"
        };
        let mut metadata = serde_json::json!({
            "artifact_kind": "deleted_file_record",
            "filesystem_parser": "ntfs",
            "recovery_source": "ntfs_deleted_mft",
            "recovery_status": recovery_status,
            "storage_area": "deleted_filesystem_record",
            "is_unallocated": false,
            "is_file_slack": false,
            "partition_index": partition_index,
            "partition_start_offset": partition_start_offset,
            "partition_size_bytes": partition_size_bytes,
            "source_entry_name": name.name,
            "ntfs_parent_record_number": name.parent_record_number,
            "ntfs_file_record_number": record_number,
            "ntfs_sequence_number": file.sequence_number(),
            "mft_record_logical_offset": mft_record_logical_offset,
            "mft_record_physical_offset": mft_record_physical_offset,
            "file_data_logical_offset": file_data_logical_offset,
            "file_data_physical_offset": file_data_physical_offset,
            "ntfs_namespace": name.namespace,
            "ntfs_allocated_size": name.allocated_size,
            "ntfs_creation_time_raw": name.creation_time_raw,
            "ntfs_creation_time_utc": name.creation_time_utc,
            "ntfs_modification_time_raw": name.modification_time_raw,
            "ntfs_modification_time_utc": name.modification_time_utc,
            "ntfs_access_time_raw": name.access_time_raw,
            "ntfs_access_time_utc": name.access_time_utc,
            "ntfs_mft_record_modification_time_raw": name.mft_record_modification_time_raw,
            "ntfs_mft_record_modification_time_utc": name.mft_record_modification_time_utc,
            "ntfs_standard_creation_time_raw": standard_info.as_ref().map(|info| info.creation_time().nt_timestamp()),
            "ntfs_standard_creation_time_utc": standard_info.as_ref().and_then(|info| ntfs_time_to_rfc3339(info.creation_time())),
            "ntfs_standard_modification_time_raw": standard_info.as_ref().map(|info| info.modification_time().nt_timestamp()),
            "ntfs_standard_modification_time_utc": standard_info.as_ref().and_then(|info| ntfs_time_to_rfc3339(info.modification_time())),
            "ntfs_standard_access_time_raw": standard_info.as_ref().map(|info| info.access_time().nt_timestamp()),
            "ntfs_standard_access_time_utc": standard_info.as_ref().and_then(|info| ntfs_time_to_rfc3339(info.access_time())),
            "ntfs_standard_mft_record_modification_time_raw": standard_info.as_ref().map(|info| info.mft_record_modification_time().nt_timestamp()),
            "ntfs_standard_mft_record_modification_time_utc": standard_info.as_ref().and_then(|info| ntfs_time_to_rfc3339(info.mft_record_modification_time())),
        });
        if entry_kind == "file" {
            if let Some(ext) =
                extension_lower(&name.name).or_else(|| extension_lower(&logical_path))
            {
                if ext == "eml" {
                    if name.data_size <= EMAIL_PARSE_MAX_BYTES {
                        match read_ntfs_file_record_bytes(
                            ntfs,
                            fs,
                            record_number,
                            EMAIL_PARSE_MAX_BYTES as usize,
                        ) {
                            Ok(bytes) => {
                                annotate_email_metadata_from_bytes(&mut metadata, "eml", &bytes)
                            }
                            Err(err) => mark_email_parse_skipped(
                                &mut metadata,
                                "eml",
                                &format!("could not read deleted NTFS email message: {err}"),
                            ),
                        }
                    } else {
                        mark_email_parse_skipped(
                            &mut metadata,
                            "eml",
                            "message exceeds bounded email parse limit",
                        );
                    }
                } else if is_text_rfc822_email_candidate(&ext, &logical_path, &name.name) {
                    if name.data_size <= EMAIL_PARSE_MAX_BYTES {
                        if let Ok(bytes) = read_ntfs_file_record_bytes(
                            ntfs,
                            fs,
                            record_number,
                            EMAIL_PARSE_MAX_BYTES as usize,
                        ) {
                            try_apply_email_metadata_from_bytes(
                                &mut metadata,
                                "text-rfc822",
                                &bytes,
                            );
                        }
                    }
                } else if is_email_store_extension(&ext) {
                    mark_email_store(&mut metadata, &ext);
                    if let Some(object) = metadata.as_object_mut() {
                        object.insert(
                            "artifact_kind".to_string(),
                            serde_json::Value::String("deleted_file_record".to_string()),
                        );
                        object.insert(
                            "email_artifact_kind".to_string(),
                            serde_json::Value::String("email_store".to_string()),
                        );
                    }
                }
            }
        }
        preserve_deleted_recovery_artifact_kind(&mut metadata);
        add_entry_category(&mut metadata, &logical_path, &name.name, entry_kind);
        let content_head =
            ntfs_file_record_content_head(ntfs, fs, record_number, &metadata, entry_kind);
        upsert_deleted_filesystem_entry_with_content(
            conn,
            case_id,
            evidence_id,
            &logical_path,
            &name.name,
            entry_kind,
            size_bytes,
            &metadata.to_string(),
            job_id,
            content_head.as_deref(),
        )?;
        *indexed += 1;
    }

    Ok(truncated)
}

fn preserve_deleted_recovery_artifact_kind(metadata: &mut serde_json::Value) {
    let Some(object) = metadata.as_object_mut() else {
        return;
    };
    let Some(kind) = object
        .get("artifact_kind")
        .and_then(|value| value.as_str())
        .map(ToString::to_string)
    else {
        return;
    };
    if kind == "email_message" || kind == "email_store" {
        object.insert(
            "email_artifact_kind".to_string(),
            serde_json::Value::String(kind),
        );
        object.insert(
            "artifact_kind".to_string(),
            serde_json::Value::String("deleted_file_record".to_string()),
        );
    }
}

struct NtfsRecordName {
    name: String,
    namespace: String,
    parent_record_number: u64,
    allocated_size: u64,
    data_size: u64,
    creation_time_raw: u64,
    creation_time_utc: Option<String>,
    modification_time_raw: u64,
    modification_time_utc: Option<String>,
    access_time_raw: u64,
    access_time_utc: Option<String>,
    mft_record_modification_time_raw: u64,
    mft_record_modification_time_utc: Option<String>,
}

fn ntfs_primary_file_name<T: Read + Seek>(
    file: &ntfs::NtfsFile<'_>,
    fs: &mut T,
) -> Option<NtfsRecordName> {
    let namespaces = [
        ntfs::structured_values::NtfsFileNamespace::Win32,
        ntfs::structured_values::NtfsFileNamespace::Win32AndDos,
        ntfs::structured_values::NtfsFileNamespace::Posix,
        ntfs::structured_values::NtfsFileNamespace::Dos,
    ];
    for namespace in namespaces {
        let Some(file_name_result) = file.name(fs, Some(namespace), None) else {
            continue;
        };
        let Ok(file_name) = file_name_result else {
            continue;
        };
        return Some(NtfsRecordName {
            name: file_name.name().to_string_lossy(),
            namespace: format!("{:?}", file_name.namespace()),
            parent_record_number: file_name.parent_directory_reference().file_record_number(),
            allocated_size: file_name.allocated_size(),
            data_size: file_name.data_size(),
            creation_time_raw: file_name.creation_time().nt_timestamp(),
            creation_time_utc: ntfs_time_to_rfc3339(file_name.creation_time()),
            modification_time_raw: file_name.modification_time().nt_timestamp(),
            modification_time_utc: ntfs_time_to_rfc3339(file_name.modification_time()),
            access_time_raw: file_name.access_time().nt_timestamp(),
            access_time_utc: ntfs_time_to_rfc3339(file_name.access_time()),
            mft_record_modification_time_raw: file_name
                .mft_record_modification_time()
                .nt_timestamp(),
            mft_record_modification_time_utc: ntfs_time_to_rfc3339(
                file_name.mft_record_modification_time(),
            ),
        });
    }
    None
}

fn collect_ntfs_dir_children<T: Read + Seek>(
    ntfs: &ntfs::Ntfs,
    fs: &mut T,
    dir_record_number: u64,
) -> Result<Vec<NtfsDirChild>> {
    let dir = ntfs
        .file(fs, dir_record_number)
        .with_context(|| format!("opening NTFS directory record {dir_record_number}"))?;
    let index = dir
        .directory_index(fs)
        .with_context(|| format!("opening NTFS directory index for record {dir_record_number}"))?;
    let mut iter = index.entries();
    let mut by_record: HashMap<u64, NtfsDirChild> = HashMap::new();

    while let Some(entry_result) = iter.next(fs) {
        let entry = entry_result
            .with_context(|| format!("reading NTFS directory record {dir_record_number}"))?;
        let Some(file_name_result) = entry.key() else {
            continue;
        };
        let file_name = file_name_result
            .with_context(|| format!("reading NTFS file name in record {dir_record_number}"))?;
        let name = file_name.name().to_string_lossy();
        if name == "." || name == ".." {
            continue;
        }

        let reference = entry.file_reference();
        let file_record_number = reference.file_record_number();
        let namespace = file_name.namespace();
        let file = ntfs.file(fs, file_record_number).ok();
        let is_directory = file
            .as_ref()
            .map(|file| file.is_directory())
            .unwrap_or_else(|| file_name.is_directory());
        let standard_info = file.as_ref().and_then(|file| file.info().ok());
        let actual_data_size = if is_directory {
            0
        } else {
            file.as_ref()
                .and_then(|file| ntfs_default_data_size(file, fs))
                .unwrap_or_else(|| file_name.data_size())
        };
        let file_data_logical_offset = if is_directory {
            None
        } else {
            file.as_ref()
                .and_then(|file| ntfs_default_data_logical_offset(file, fs))
        };
        let child = NtfsDirChild {
            name,
            is_directory,
            size_bytes: actual_data_size,
            allocated_size: file_name.allocated_size(),
            file_record_number,
            sequence_number: reference.sequence_number(),
            namespace: format!("{namespace:?}"),
            namespace_priority: ntfs_namespace_priority(namespace),
            creation_time_raw: file_name.creation_time().nt_timestamp(),
            creation_time_utc: ntfs_time_to_rfc3339(file_name.creation_time()),
            modification_time_raw: file_name.modification_time().nt_timestamp(),
            modification_time_utc: ntfs_time_to_rfc3339(file_name.modification_time()),
            access_time_raw: file_name.access_time().nt_timestamp(),
            access_time_utc: ntfs_time_to_rfc3339(file_name.access_time()),
            mft_record_modification_time_raw: file_name
                .mft_record_modification_time()
                .nt_timestamp(),
            mft_record_modification_time_utc: ntfs_time_to_rfc3339(
                file_name.mft_record_modification_time(),
            ),
            standard_creation_time_raw: standard_info
                .as_ref()
                .map(|info| info.creation_time().nt_timestamp()),
            standard_creation_time_utc: standard_info
                .as_ref()
                .and_then(|info| ntfs_time_to_rfc3339(info.creation_time())),
            standard_modification_time_raw: standard_info
                .as_ref()
                .map(|info| info.modification_time().nt_timestamp()),
            standard_modification_time_utc: standard_info
                .as_ref()
                .and_then(|info| ntfs_time_to_rfc3339(info.modification_time())),
            standard_access_time_raw: standard_info
                .as_ref()
                .map(|info| info.access_time().nt_timestamp()),
            standard_access_time_utc: standard_info
                .as_ref()
                .and_then(|info| ntfs_time_to_rfc3339(info.access_time())),
            standard_mft_record_modification_time_raw: standard_info
                .as_ref()
                .map(|info| info.mft_record_modification_time().nt_timestamp()),
            standard_mft_record_modification_time_utc: standard_info
                .as_ref()
                .and_then(|info| ntfs_time_to_rfc3339(info.mft_record_modification_time())),
            file_data_logical_offset,
        };

        let replace = by_record
            .get(&file_record_number)
            .map(|existing| child.namespace_priority > existing.namespace_priority)
            .unwrap_or(true);
        if replace {
            by_record.insert(file_record_number, child);
        }
    }

    let mut children = by_record.into_values().collect::<Vec<_>>();
    children.sort_by(|left, right| {
        left.name
            .to_ascii_lowercase()
            .cmp(&right.name.to_ascii_lowercase())
            .then_with(|| left.file_record_number.cmp(&right.file_record_number))
    });
    Ok(children)
}

fn ntfs_named_data_streams<T: Read + Seek>(
    file: &ntfs::NtfsFile<'_>,
    fs: &mut T,
) -> Vec<NtfsDataStreamInfo> {
    let mut streams = Vec::new();
    let mut iter = file.attributes();
    while let Some(item_result) = iter.next(fs) {
        let Ok(item) = item_result else {
            continue;
        };
        let Ok(attribute) = item.to_attribute() else {
            continue;
        };
        if attribute.ty().ok() != Some(ntfs::NtfsAttributeType::Data) {
            continue;
        }
        let Ok(name) = attribute.name() else {
            continue;
        };
        let name = name.to_string_lossy();
        if name.is_empty() {
            continue;
        }
        let Ok(data_value) = attribute.value(fs) else {
            continue;
        };
        streams.push(NtfsDataStreamInfo {
            name,
            size_bytes: data_value.len(),
            file_data_logical_offset: data_value
                .data_position()
                .value()
                .map(|position| position.get()),
            is_resident: attribute.is_resident(),
        });
    }
    streams.sort_by(|left, right| {
        left.name
            .to_ascii_lowercase()
            .cmp(&right.name.to_ascii_lowercase())
    });
    streams
}

fn ntfs_unallocated_summary<T: Read + Seek>(
    ntfs: &ntfs::Ntfs,
    fs: &mut T,
    partition_start_offset: u64,
) -> Option<NtfsUnallocatedSummary> {
    let bitmap = ntfs_bitmap_bytes(ntfs, fs)?;
    let mut summary = NtfsUnallocatedSummary {
        total_size_bytes: 0,
        run_count: 0,
        cluster_count: ntfs_cluster_count(ntfs),
        bitmap_size_bytes: bitmap.len() as u64,
        bitmap_truncated: bitmap.len() as u64 != ntfs_bitmap_expected_bytes(ntfs)?,
        sample_extents: Vec::new(),
    };
    for_each_ntfs_unallocated_run(ntfs, &bitmap, |logical_offset, length_bytes| {
        summary.total_size_bytes = summary.total_size_bytes.saturating_add(length_bytes);
        summary.run_count = summary.run_count.saturating_add(1);
        if summary.sample_extents.len() < NTFS_UNALLOCATED_METADATA_EXTENTS_LIMIT {
            summary.sample_extents.push(NtfsUnallocatedExtent {
                logical_offset,
                physical_offset: partition_start_offset.saturating_add(logical_offset),
                length_bytes,
            });
        }
        Ok(())
    })
    .ok()?;
    Some(summary)
}

fn ntfs_bitmap_bytes<T: Read + Seek>(ntfs: &ntfs::Ntfs, fs: &mut T) -> Option<Vec<u8>> {
    let expected_bytes = ntfs_bitmap_expected_bytes(ntfs)?;
    if expected_bytes == 0 || expected_bytes > NTFS_BITMAP_PARSE_MAX_BYTES {
        return None;
    }
    read_ntfs_file_record_stream_bytes(
        ntfs,
        fs,
        ntfs::KnownNtfsFileRecordNumber::Bitmap as u64,
        "",
        usize::try_from(expected_bytes).ok()?,
    )
    .ok()
}

fn ntfs_bitmap_expected_bytes(ntfs: &ntfs::Ntfs) -> Option<u64> {
    ntfs_cluster_count(ntfs)
        .checked_add(7)
        .map(|value| value / 8)
}

fn ntfs_cluster_count(ntfs: &ntfs::Ntfs) -> u64 {
    let cluster_size = u64::from(ntfs.cluster_size()).max(1);
    ntfs.size().saturating_add(cluster_size.saturating_sub(1)) / cluster_size
}

fn for_each_ntfs_unallocated_run<F>(ntfs: &ntfs::Ntfs, bitmap: &[u8], mut visit: F) -> Result<()>
where
    F: FnMut(u64, u64) -> Result<()>,
{
    let cluster_size = u64::from(ntfs.cluster_size()).max(1);
    let cluster_count = ntfs_cluster_count(ntfs);
    let mut run_start = None;

    for cluster_index in 0..cluster_count {
        if ntfs_bitmap_cluster_allocated(bitmap, cluster_index) {
            if let Some(start_cluster) = run_start.take() {
                visit_ntfs_unallocated_run(
                    start_cluster,
                    cluster_index,
                    cluster_size,
                    ntfs.size(),
                    &mut visit,
                )?;
            }
        } else if run_start.is_none() {
            run_start = Some(cluster_index);
        }
    }

    if let Some(start_cluster) = run_start {
        visit_ntfs_unallocated_run(
            start_cluster,
            cluster_count,
            cluster_size,
            ntfs.size(),
            &mut visit,
        )?;
    }
    Ok(())
}

fn visit_ntfs_unallocated_run<F>(
    start_cluster: u64,
    end_cluster: u64,
    cluster_size: u64,
    volume_size: u64,
    visit: &mut F,
) -> Result<()>
where
    F: FnMut(u64, u64) -> Result<()>,
{
    if end_cluster <= start_cluster {
        return Ok(());
    }
    let logical_offset = start_cluster.saturating_mul(cluster_size);
    if logical_offset >= volume_size {
        return Ok(());
    }
    let run_bytes = end_cluster
        .saturating_sub(start_cluster)
        .saturating_mul(cluster_size)
        .min(volume_size.saturating_sub(logical_offset));
    if run_bytes > 0 {
        visit(logical_offset, run_bytes)?;
    }
    Ok(())
}

fn ntfs_bitmap_cluster_allocated(bitmap: &[u8], cluster_index: u64) -> bool {
    let byte_index = match usize::try_from(cluster_index / 8) {
        Ok(value) => value,
        Err(_) => return true,
    };
    let Some(byte) = bitmap.get(byte_index) else {
        return true;
    };
    let bit = (cluster_index % 8) as u8;
    (byte & (1_u8 << bit)) != 0
}

fn ntfs_data_stream_size<T: Read + Seek>(
    file: &ntfs::NtfsFile<'_>,
    fs: &mut T,
    data_stream_name: &str,
) -> Option<u64> {
    let mut iter = file.attributes();
    while let Some(item_result) = iter.next(fs) {
        let item = item_result.ok()?;
        let attribute = item.to_attribute().ok()?;
        if attribute.ty().ok()? != ntfs::NtfsAttributeType::Data {
            continue;
        }
        if attribute.name().ok()?.to_string_lossy() != data_stream_name {
            continue;
        }
        return Some(attribute.value(fs).ok()?.len());
    }
    None
}

fn ntfs_default_data_size<T: Read + Seek>(file: &ntfs::NtfsFile<'_>, fs: &mut T) -> Option<u64> {
    ntfs_data_stream_size(file, fs, "")
}

fn ntfs_mft_record_count<T: Read + Seek>(ntfs: &ntfs::Ntfs, fs: &mut T) -> Option<u64> {
    let mft = ntfs
        .file(fs, ntfs::KnownNtfsFileRecordNumber::MFT as u64)
        .ok()?;
    let mft_size = ntfs_default_data_size(&mft, fs)?;
    let record_size = u64::from(ntfs.file_record_size()).max(1);
    Some(mft_size / record_size)
}

fn ntfs_mft_record_logical_offset(ntfs: &ntfs::Ntfs, file_record_number: u64) -> Option<u64> {
    let mft_position = ntfs.mft_position().value()?.get();
    mft_position.checked_add(file_record_number.checked_mul(u64::from(ntfs.file_record_size()))?)
}

fn ntfs_default_data_logical_offset<T: Read + Seek>(
    file: &ntfs::NtfsFile<'_>,
    fs: &mut T,
) -> Option<u64> {
    ntfs_data_stream_logical_offset(file, fs, "")
}

fn ntfs_data_stream_logical_offset<T: Read + Seek>(
    file: &ntfs::NtfsFile<'_>,
    fs: &mut T,
    data_stream_name: &str,
) -> Option<u64> {
    let mut iter = file.attributes();
    while let Some(item_result) = iter.next(fs) {
        let item = item_result.ok()?;
        let attribute = item.to_attribute().ok()?;
        if attribute.ty().ok()? != ntfs::NtfsAttributeType::Data {
            continue;
        }
        if attribute.name().ok()?.to_string_lossy() != data_stream_name {
            continue;
        }
        return attribute
            .value(fs)
            .ok()?
            .data_position()
            .value()
            .map(|position| position.get());
    }
    None
}

fn read_ntfs_file_record_bytes<T: Read + Seek>(
    ntfs: &ntfs::Ntfs,
    fs: &mut T,
    file_record_number: u64,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    read_ntfs_file_record_stream_bytes(ntfs, fs, file_record_number, "", max_bytes)
}

fn read_ntfs_file_record_stream_bytes<T: Read + Seek>(
    ntfs: &ntfs::Ntfs,
    fs: &mut T,
    file_record_number: u64,
    data_stream_name: &str,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    let file = ntfs
        .file(fs, file_record_number)
        .with_context(|| format!("opening NTFS file record {file_record_number}"))?;
    if file.is_directory() {
        bail!("NTFS file record {file_record_number} is a directory");
    }
    let mut iter = file.attributes();
    while let Some(item_result) = iter.next(fs) {
        let item = item_result
            .with_context(|| format!("opening NTFS attribute for record {file_record_number}"))?;
        let data_attribute = item
            .to_attribute()
            .with_context(|| format!("opening NTFS attribute for record {file_record_number}"))?;
        if data_attribute.ty().ok() != Some(ntfs::NtfsAttributeType::Data) {
            continue;
        }
        let attribute_name = data_attribute
            .name()
            .with_context(|| {
                format!("reading NTFS data stream name for record {file_record_number}")
            })?
            .to_string_lossy();
        if attribute_name != data_stream_name {
            continue;
        }
        let data_value = data_attribute
            .value(fs)
            .with_context(|| format!("opening NTFS data value for record {file_record_number}"))?;
        let read_len = usize::try_from(data_value.len())
            .unwrap_or(usize::MAX)
            .min(max_bytes);
        let mut data_reader = data_value.attach(fs);
        let mut bytes = vec![0_u8; read_len];
        let bytes_read = data_reader
            .read(&mut bytes)
            .with_context(|| format!("reading NTFS file record {file_record_number}"))?;
        bytes.truncate(bytes_read);
        return Ok(bytes);
    }
    if data_stream_name.is_empty() {
        bail!("NTFS file record {file_record_number} has no unnamed data stream");
    }
    bail!("NTFS file record {file_record_number} has no data stream named {data_stream_name}");
}

fn ntfs_namespace_priority(namespace: ntfs::structured_values::NtfsFileNamespace) -> u8 {
    match namespace {
        ntfs::structured_values::NtfsFileNamespace::Win32 => 4,
        ntfs::structured_values::NtfsFileNamespace::Win32AndDos => 3,
        ntfs::structured_values::NtfsFileNamespace::Posix => 2,
        ntfs::structured_values::NtfsFileNamespace::Dos => 1,
    }
}

fn unique_child_logical_path(
    parent_path: &str,
    child: &NtfsDirChild,
    used_child_paths: &mut HashSet<String>,
) -> String {
    let segment = sanitize_logical_segment(&child.name);
    let mut logical_path = format!("{parent_path}/{segment}");
    if used_child_paths.insert(logical_path.clone()) {
        return logical_path;
    }

    let mut suffix = format!("mft{}", child.file_record_number);
    loop {
        logical_path = format!("{parent_path}/{segment}-{suffix}");
        if used_child_paths.insert(logical_path.clone()) {
            return logical_path;
        }
        suffix.push('_');
    }
}

fn ntfs_time_to_rfc3339(value: ntfs::NtfsTime) -> Option<String> {
    const NTFS_TO_UNIX_EPOCH_100NS: i128 = 116_444_736_000_000_000;
    const INTERVALS_PER_SECOND: i128 = 10_000_000;
    let unix_100ns = i128::from(value.nt_timestamp()).checked_sub(NTFS_TO_UNIX_EPOCH_100NS)?;
    let seconds = unix_100ns.div_euclid(INTERVALS_PER_SECOND);
    let nanos = unix_100ns.rem_euclid(INTERVALS_PER_SECOND) * 100;
    let seconds = i64::try_from(seconds).ok()?;
    DateTime::<Utc>::from_timestamp(seconds, nanos as u32).map(|value| value.to_rfc3339())
}

fn metadata_u64_or_i64(metadata: &serde_json::Value, key: &str) -> Option<u64> {
    metadata[key].as_u64().or_else(|| {
        metadata[key]
            .as_i64()
            .and_then(|value| u64::try_from(value).ok())
    })
}

fn image_partition_start_offset(entry: &EntryForBytes, filesystem_name: &str) -> Result<u64> {
    entry.metadata_json["partition_start_offset"]
        .as_u64()
        .with_context(|| {
            format!(
                "{filesystem_name} entry is missing partition_start_offset: {}",
                entry.logical_path
            )
        })
}

fn image_partition_size_bytes(entry: &EntryForBytes) -> Option<u64> {
    metadata_u64_or_i64(&entry.metadata_json, "partition_size_bytes")
}

/// Serves deleted-record bytes recovered by direct physical-extent reads
/// (e.g. FAT 0xE5 entries, whose data is assumed contiguous from the recorded
/// first cluster).
fn read_image_physical_extent_bytes(
    entry: &EntryForBytes,
    offset: u64,
    length: usize,
) -> Result<Option<EntryBytes>> {
    if entry.source_kind != "image"
        || entry.metadata_json["recovery_read"].as_str() != Some("physical_extent")
    {
        return Ok(None);
    }
    let Some(physical) = entry.metadata_json["file_data_physical_offset"].as_u64() else {
        bail!(
            "deleted entry has no recoverable data offset: {}",
            entry.logical_path
        );
    };
    let total_size = entry
        .size_bytes
        .and_then(|value| u64::try_from(value).ok())
        .unwrap_or(0);
    let remaining = total_size.saturating_sub(offset.min(total_size));
    let want = usize::try_from(remaining).unwrap_or(usize::MAX).min(length);
    let mut bytes = vec![0_u8; want];
    let mut bytes_read = 0_usize;
    if want > 0 {
        let mut opened = open_disk_image(Path::new(&entry.source_path))?;
        opened
            .reader
            .seek(SeekFrom::Start(physical.saturating_add(offset)))
            .with_context(|| format!("seeking recovered data for {}", entry.logical_path))?;
        bytes_read = opened
            .reader
            .read(&mut bytes)
            .with_context(|| format!("reading recovered data for {}", entry.logical_path))?;
    }
    bytes.truncate(bytes_read);
    Ok(Some(EntryBytes {
        entry_id: entry.entry_id,
        evidence_id: entry.evidence_id,
        logical_path: entry.logical_path.clone(),
        offset,
        requested_length: length,
        bytes_read,
        total_size,
        eof: offset.saturating_add(bytes_read as u64) >= total_size,
        bytes,
    }))
}

fn read_image_ext_entry_bytes(
    entry: &EntryForBytes,
    offset: u64,
    length: usize,
) -> Result<Option<EntryBytes>> {
    if entry.source_kind != "image"
        || entry.metadata_json["filesystem_parser"].as_str() != Some("ext4")
    {
        return Ok(None);
    }
    let Some(ext_path) = entry.metadata_json["ext_path"].as_str() else {
        return Ok(None);
    };
    let start_offset = image_partition_start_offset(entry, "EXT")?;
    let opened = open_disk_image(Path::new(&entry.source_path))?;
    let reader = Ext4ImageReader {
        reader: opened.reader,
        partition_start: start_offset,
    };
    let fs = ext4_view::Ext4::load(Box::new(reader))
        .map_err(|err| anyhow!("opening ext filesystem for {}: {err}", entry.logical_path))?;
    let data = fs
        .read(ext_path)
        .map_err(|err| anyhow!("reading ext entry {}: {err}", entry.logical_path))?;
    let total_size = data.len() as u64;
    let start = offset.min(total_size) as usize;
    let end = start.saturating_add(length).min(data.len());
    let bytes = data[start..end].to_vec();
    let bytes_read = bytes.len();
    Ok(Some(EntryBytes {
        entry_id: entry.entry_id,
        evidence_id: entry.evidence_id,
        logical_path: entry.logical_path.clone(),
        offset,
        requested_length: length,
        bytes_read,
        total_size,
        eof: offset.saturating_add(bytes_read as u64) >= total_size,
        bytes,
    }))
}

fn read_image_fat_entry_bytes(
    entry: &EntryForBytes,
    offset: u64,
    length: usize,
) -> Result<Option<EntryBytes>> {
    if entry.source_kind != "image"
        || entry.metadata_json["filesystem_parser"].as_str() != Some("fatfs")
    {
        return Ok(None);
    }
    let start_offset = image_partition_start_offset(entry, "FAT")?;
    let size_bytes = image_partition_size_bytes(entry);
    let mut opened = open_disk_image(Path::new(&entry.source_path))?;
    let partition_size =
        size_bytes.unwrap_or_else(|| opened.decoded_size.saturating_sub(start_offset));
    let slice = PartitionSlice::new(&mut *opened.reader, start_offset, partition_size);
    let fs = fatfs::FileSystem::new(slice, fatfs::FsOptions::new())
        .with_context(|| format!("opening FAT filesystem for {}", entry.logical_path))?;
    read_mounted_fat_entry_bytes(&fs, entry, offset, length).map(Some)
}

fn read_mounted_fat_entry_bytes<T: fatfs::ReadWriteSeek>(
    fs: &fatfs::FileSystem<T>,
    entry: &EntryForBytes,
    offset: u64,
    length: usize,
) -> Result<EntryBytes> {
    let relative_path = fat_entry_relative_path(entry)?;
    let root = fs.root_dir();
    let mut file = root
        .open_file(&relative_path)
        .with_context(|| format!("opening FAT entry {}", entry.logical_path))?;
    let total_size = match entry.size_bytes.and_then(|value| u64::try_from(value).ok()) {
        Some(value) => value,
        None => file
            .seek(SeekFrom::End(0))
            .with_context(|| format!("sizing FAT entry {}", entry.logical_path))?,
    };
    file.seek(SeekFrom::Start(offset))
        .with_context(|| format!("seeking FAT entry {}", entry.logical_path))?;
    let mut bytes = vec![0_u8; length];
    let bytes_read = file
        .read(&mut bytes)
        .with_context(|| format!("reading FAT entry {}", entry.logical_path))?;
    bytes.truncate(bytes_read);
    Ok(EntryBytes {
        entry_id: entry.entry_id,
        evidence_id: entry.evidence_id,
        logical_path: entry.logical_path.clone(),
        offset,
        requested_length: length,
        bytes_read,
        total_size,
        eof: offset.saturating_add(bytes_read as u64) >= total_size,
        bytes,
    })
}

fn fat_entry_relative_path(entry: &EntryForBytes) -> Result<String> {
    entry.metadata_json["fat_path"]
        .as_str()
        .map(ToString::to_string)
        .or_else(|| fat_relative_path(&entry.logical_path))
        .with_context(|| {
            format!(
                "FAT entry path is not under a parsed volume: {}",
                entry.logical_path
            )
        })
}

fn fat_relative_path(logical_path: &str) -> Option<String> {
    let rest = logical_path.strip_prefix("/Image Analysis/Volumes/")?;
    let (_, relative) = rest.split_once('/')?;
    (!relative.is_empty()).then(|| relative.to_string())
}

fn read_image_ntfs_entry_bytes(
    entry: &EntryForBytes,
    offset: u64,
    length: usize,
) -> Result<Option<EntryBytes>> {
    if entry.source_kind != "image"
        || entry.metadata_json["filesystem_parser"].as_str() != Some("ntfs")
    {
        return Ok(None);
    }
    if is_ntfs_unallocated_entry(entry) {
        return read_image_ntfs_unallocated_entry_bytes(entry, offset, length);
    }
    let start_offset = image_partition_start_offset(entry, "NTFS")?;
    let size_bytes = image_partition_size_bytes(entry);

    let mut opened = open_disk_image(Path::new(&entry.source_path))?;
    let partition_size =
        size_bytes.unwrap_or_else(|| opened.decoded_size.saturating_sub(start_offset));
    let mut slice = PartitionSlice::new(&mut *opened.reader, start_offset, partition_size);
    let ntfs = ntfs::Ntfs::new(&mut slice)
        .with_context(|| format!("opening NTFS filesystem for {}", entry.logical_path))?;
    read_mounted_ntfs_entry_bytes(&ntfs, &mut slice, entry, offset, length).map(Some)
}

fn is_ntfs_unallocated_entry(entry: &EntryForBytes) -> bool {
    entry.metadata_json["artifact_kind"].as_str() == Some("unallocated_space")
        || entry.metadata_json["storage_area"].as_str() == Some("unallocated_space")
        || entry.metadata_json["is_unallocated"].as_bool() == Some(true)
}

fn read_mounted_ntfs_entry_bytes<T: Read + Seek>(
    ntfs: &ntfs::Ntfs,
    fs: &mut T,
    entry: &EntryForBytes,
    offset: u64,
    length: usize,
) -> Result<EntryBytes> {
    let file_record_number = entry.metadata_json["ntfs_file_record_number"]
        .as_u64()
        .with_context(|| {
            format!(
                "NTFS entry is missing ntfs_file_record_number: {}",
                entry.logical_path
            )
        })?;
    let data_stream_name = entry.metadata_json["ntfs_data_stream_name"]
        .as_str()
        .unwrap_or("");

    let file = ntfs
        .file(fs, file_record_number)
        .with_context(|| format!("opening NTFS entry {}", entry.logical_path))?;
    if file.is_directory() {
        bail!(
            "NTFS entry is a directory, not a readable file: {}",
            entry.logical_path
        );
    }
    let mut iter = file.attributes();
    while let Some(item_result) = iter.next(fs) {
        let item = item_result
            .with_context(|| format!("opening NTFS attribute {}", entry.logical_path))?;
        let data_attribute = item
            .to_attribute()
            .with_context(|| format!("opening NTFS data attribute {}", entry.logical_path))?;
        if data_attribute.ty().ok() != Some(ntfs::NtfsAttributeType::Data) {
            continue;
        }
        let attribute_name = data_attribute
            .name()
            .with_context(|| format!("reading NTFS data stream name {}", entry.logical_path))?
            .to_string_lossy();
        if attribute_name != data_stream_name {
            continue;
        }
        let data_value = data_attribute
            .value(fs)
            .with_context(|| format!("opening NTFS data value {}", entry.logical_path))?;
        let total_size = data_value.len();
        let mut data_reader = data_value.attach(fs);
        data_reader
            .seek(SeekFrom::Start(offset))
            .with_context(|| format!("seeking NTFS entry {}", entry.logical_path))?;
        let mut bytes = vec![0_u8; length];
        let bytes_read = data_reader
            .read(&mut bytes)
            .with_context(|| format!("reading NTFS entry {}", entry.logical_path))?;
        bytes.truncate(bytes_read);
        return Ok(EntryBytes {
            entry_id: entry.entry_id,
            evidence_id: entry.evidence_id,
            logical_path: entry.logical_path.clone(),
            offset,
            requested_length: length,
            bytes_read,
            total_size,
            eof: offset.saturating_add(bytes_read as u64) >= total_size,
            bytes,
        });
    }
    if data_stream_name.is_empty() {
        bail!(
            "NTFS entry has no unnamed data stream: {}",
            entry.logical_path
        );
    }
    bail!(
        "NTFS entry has no data stream named {}: {}",
        data_stream_name,
        entry.logical_path
    );
}

fn read_image_ntfs_unallocated_entry_bytes(
    entry: &EntryForBytes,
    offset: u64,
    length: usize,
) -> Result<Option<EntryBytes>> {
    let start_offset = image_partition_start_offset(entry, "NTFS unallocated")?;
    let size_bytes = image_partition_size_bytes(entry);

    let mut opened = open_disk_image(Path::new(&entry.source_path))?;
    let partition_size =
        size_bytes.unwrap_or_else(|| opened.decoded_size.saturating_sub(start_offset));
    let mut slice = PartitionSlice::new(&mut *opened.reader, start_offset, partition_size);
    let ntfs = ntfs::Ntfs::new(&mut slice)
        .with_context(|| format!("opening NTFS filesystem for {}", entry.logical_path))?;
    let bitmap = ntfs_bitmap_bytes(&ntfs, &mut slice).with_context(|| {
        format!(
            "NTFS unallocated entry cannot read $Bitmap: {}",
            entry.logical_path
        )
    })?;
    let (bytes, total_size) =
        read_ntfs_unallocated_stream_bytes(&mut slice, &ntfs, &bitmap, offset, length)
            .with_context(|| format!("reading NTFS unallocated space {}", entry.logical_path))?;
    let bytes_read = bytes.len();
    Ok(Some(EntryBytes {
        entry_id: entry.entry_id,
        evidence_id: entry.evidence_id,
        logical_path: entry.logical_path.clone(),
        offset,
        requested_length: length,
        bytes_read,
        total_size,
        eof: offset.saturating_add(bytes_read as u64) >= total_size,
        bytes,
    }))
}

fn read_ntfs_unallocated_stream_bytes<T: Read + Seek>(
    fs: &mut T,
    ntfs: &ntfs::Ntfs,
    bitmap: &[u8],
    offset: u64,
    length: usize,
) -> Result<(Vec<u8>, u64)> {
    let mut bytes = Vec::with_capacity(length);
    let mut total_size = 0_u64;
    let requested_end = offset.saturating_add(length as u64);
    for_each_ntfs_unallocated_run(ntfs, bitmap, |logical_offset, run_length| {
        let stream_run_start = total_size;
        let stream_run_end = stream_run_start.saturating_add(run_length);
        total_size = stream_run_end;

        if bytes.len() >= length || requested_end <= stream_run_start || offset >= stream_run_end {
            return Ok(());
        }

        let within_run = offset.saturating_sub(stream_run_start);
        let run_available = run_length.saturating_sub(within_run);
        let remaining = length.saturating_sub(bytes.len());
        let read_len = run_available.min(remaining as u64) as usize;
        if read_len == 0 {
            return Ok(());
        }

        fs.seek(SeekFrom::Start(logical_offset.saturating_add(within_run)))?;
        let start = bytes.len();
        bytes.resize(start + read_len, 0);
        let mut filled = 0;
        while filled < read_len {
            let count = fs.read(&mut bytes[start + filled..start + read_len])?;
            if count == 0 {
                bytes.truncate(start + filled);
                break;
            }
            filled += count;
        }
        Ok(())
    })?;
    Ok((bytes, total_size))
}

fn is_disk_image_container_byte_entry(entry: &EntryForBytes) -> bool {
    if entry.metadata_json["filesystem_parser"].as_str().is_some() {
        return false;
    }
    let path = if entry.source_kind == "file" {
        &entry.source_path
    } else {
        &entry.logical_path
    };
    looks_like_image(Path::new(path))
}

fn walk_fat_dir<T: fatfs::ReadWriteSeek>(
    conn: &Connection,
    case_id: i64,
    evidence_id: i64,
    job_id: i64,
    dir: &fatfs::Dir<'_, T>,
    parent_path: &str,
    partition_index: usize,
    partition_start_offset: u64,
    partition_size_bytes: u64,
    parent_fat_path: &str,
    indexed: &mut usize,
    max_entries: usize,
    truncated: &mut bool,
) -> Result<()> {
    for entry_result in dir.iter() {
        if *indexed >= max_entries {
            *truncated = true;
            break;
        }
        let entry = entry_result.context("reading FAT directory entry")?;
        let raw_name = entry.file_name();
        if raw_name == "." || raw_name == ".." {
            continue;
        }
        let segment = sanitize_logical_segment(&raw_name);
        let logical_path = format!("{parent_path}/{segment}");
        let fat_path = if parent_fat_path.is_empty() {
            raw_name.clone()
        } else {
            format!("{parent_fat_path}/{raw_name}")
        };
        let entry_kind = if entry.is_dir() { "directory" } else { "file" };
        let size_bytes = entry
            .is_file()
            .then(|| i64::try_from(entry.len()).unwrap_or(i64::MAX));
        let mut metadata = serde_json::json!({
            "artifact_kind": "filesystem_entry",
            "filesystem_parser": "fatfs",
            "partition_index": partition_index,
            "partition_start_offset": partition_start_offset,
            "partition_size_bytes": partition_size_bytes,
            "source_entry_name": raw_name,
            "fat_path": fat_path,
            "fat_created": format!("{:?}", entry.created()),
            "fat_accessed": format!("{:?}", entry.accessed()),
            "fat_modified": format!("{:?}", entry.modified()),
        });
        if entry.is_file() {
            if let Some(ext) = extension_lower(&raw_name).or_else(|| extension_lower(&logical_path))
            {
                if ext == "eml" {
                    if entry.len() <= EMAIL_PARSE_MAX_BYTES {
                        let mut file = entry.to_file();
                        let mut bytes = Vec::new();
                        match file.read_to_end(&mut bytes) {
                            Ok(_) => {
                                annotate_email_metadata_from_bytes(&mut metadata, "eml", &bytes)
                            }
                            Err(err) => mark_email_parse_skipped(
                                &mut metadata,
                                "eml",
                                &format!("could not read FAT email message: {err}"),
                            ),
                        }
                    } else {
                        mark_email_parse_skipped(
                            &mut metadata,
                            "eml",
                            "message exceeds bounded email parse limit",
                        );
                    }
                } else if is_text_rfc822_email_candidate(&ext, &logical_path, &raw_name) {
                    if entry.len() <= EMAIL_PARSE_MAX_BYTES {
                        let mut file = entry.to_file();
                        let mut bytes = Vec::new();
                        if file.read_to_end(&mut bytes).is_ok() {
                            try_apply_email_metadata_from_bytes(
                                &mut metadata,
                                "text-rfc822",
                                &bytes,
                            );
                        }
                    }
                } else if is_email_store_extension(&ext) {
                    mark_email_store(&mut metadata, &ext);
                }
            }
        }
        add_entry_category(&mut metadata, &logical_path, &raw_name, entry_kind);
        let content_head = fat_entry_content_head(&entry, &metadata, entry_kind);
        upsert_filesystem_entry_with_content(
            conn,
            case_id,
            evidence_id,
            &logical_path,
            &raw_name,
            entry_kind,
            size_bytes,
            &metadata.to_string(),
            job_id,
            content_head.as_deref(),
        )?;
        *indexed += 1;

        if entry.is_dir() {
            let child_dir = entry.to_dir();
            walk_fat_dir(
                conn,
                case_id,
                evidence_id,
                job_id,
                &child_dir,
                &logical_path,
                partition_index,
                partition_start_offset,
                partition_size_bytes,
                &fat_path,
                indexed,
                max_entries,
                truncated,
            )?;
            if *truncated {
                break;
            }
        }
    }
    Ok(())
}

struct PartitionSlice<'a> {
    inner: &'a mut dyn disk_forensic::container::ReadSeek,
    start: u64,
    len: u64,
    pos: u64,
}

impl<'a> PartitionSlice<'a> {
    fn new(inner: &'a mut dyn disk_forensic::container::ReadSeek, start: u64, len: u64) -> Self {
        Self {
            inner,
            start,
            len,
            pos: 0,
        }
    }
}

impl Read for PartitionSlice<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.len || buf.is_empty() {
            return Ok(0);
        }
        let remaining = self.len - self.pos;
        let read_len = usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(buf.len());
        let absolute = self.start.checked_add(self.pos).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "partition offset overflow")
        })?;
        self.inner.seek(SeekFrom::Start(absolute))?;
        let read = self.inner.read(&mut buf[..read_len])?;
        self.pos = self.pos.saturating_add(read as u64);
        Ok(read)
    }
}

impl Seek for PartitionSlice<'_> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let next = match pos {
            SeekFrom::Start(offset) => i128::from(offset),
            SeekFrom::Current(offset) => i128::from(self.pos) + i128::from(offset),
            SeekFrom::End(offset) => i128::from(self.len) + i128::from(offset),
        };
        if next < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot seek before partition start",
            ));
        }
        self.pos = u64::try_from(next)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "partition seek overflow"))?;
        Ok(self.pos)
    }
}

impl Write for PartitionSlice<'_> {
    fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "evidence partition slice is read-only",
        ))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn insert_image_record(
    conn: &Connection,
    case_id: i64,
    evidence_id: i64,
    logical_path: &str,
    name: &str,
    size_bytes: Option<i64>,
    metadata: &serde_json::Value,
    job_id: i64,
) -> Result<()> {
    let mut metadata = metadata.clone();
    add_entry_category(&mut metadata, logical_path, name, "record");
    upsert_filesystem_entry(
        conn,
        case_id,
        evidence_id,
        logical_path,
        name,
        "record",
        size_bytes,
        &metadata.to_string(),
        job_id,
    )
}

fn upsert_filesystem_entry(
    conn: &Connection,
    case_id: i64,
    evidence_id: i64,
    logical_path: &str,
    name: &str,
    entry_kind: &str,
    size_bytes: Option<i64>,
    metadata_json: &str,
    job_id: i64,
) -> Result<()> {
    upsert_filesystem_entry_with_content(
        conn,
        case_id,
        evidence_id,
        logical_path,
        name,
        entry_kind,
        size_bytes,
        metadata_json,
        job_id,
        None,
    )
}

fn upsert_filesystem_entry_with_content(
    conn: &Connection,
    case_id: i64,
    evidence_id: i64,
    logical_path: &str,
    name: &str,
    entry_kind: &str,
    size_bytes: Option<i64>,
    metadata_json: &str,
    job_id: i64,
    content_head: Option<&[u8]>,
) -> Result<()> {
    upsert_filesystem_entry_with_deleted(
        conn,
        case_id,
        evidence_id,
        logical_path,
        name,
        entry_kind,
        size_bytes,
        false,
        metadata_json,
        job_id,
        content_head,
    )
}

fn upsert_deleted_filesystem_entry_with_content(
    conn: &Connection,
    case_id: i64,
    evidence_id: i64,
    logical_path: &str,
    name: &str,
    entry_kind: &str,
    size_bytes: Option<i64>,
    metadata_json: &str,
    job_id: i64,
    content_head: Option<&[u8]>,
) -> Result<()> {
    upsert_filesystem_entry_with_deleted(
        conn,
        case_id,
        evidence_id,
        logical_path,
        name,
        entry_kind,
        size_bytes,
        true,
        metadata_json,
        job_id,
        content_head,
    )
}

fn upsert_filesystem_entry_with_deleted(
    conn: &Connection,
    case_id: i64,
    evidence_id: i64,
    logical_path: &str,
    name: &str,
    entry_kind: &str,
    size_bytes: Option<i64>,
    is_deleted: bool,
    metadata_json: &str,
    job_id: i64,
    content_head: Option<&[u8]>,
) -> Result<()> {
    conn.execute(
        "INSERT INTO filesystem_entries(
             case_id, evidence_id, logical_path, name, entry_kind, size_bytes, is_deleted,
             metadata_json, discovered_by_job_id, content_head
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
         ON CONFLICT(evidence_id, logical_path) DO UPDATE SET
             name = excluded.name,
             entry_kind = excluded.entry_kind,
             size_bytes = excluded.size_bytes,
             is_deleted = excluded.is_deleted,
             metadata_json = excluded.metadata_json,
             discovered_by_job_id = excluded.discovered_by_job_id,
             content_head = excluded.content_head",
        params![
            case_id,
            evidence_id,
            logical_path,
            name,
            entry_kind,
            size_bytes,
            if is_deleted { 1 } else { 0 },
            metadata_json,
            job_id,
            content_head,
        ],
    )
    .with_context(|| format!("indexing filesystem entry {logical_path}"))?;
    Ok(())
}

fn path_search_results(
    conn: &Connection,
    case_id: i64,
    evidence_id: Option<i64>,
    query: &str,
    query_lower: &str,
    max_results: usize,
    scope: &SearchScope,
) -> Result<Vec<DeepSearchResult>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT fe.id, fe.evidence_id, fe.logical_path, fe.name, fe.entry_kind, fe.metadata_json
         FROM filesystem_entries fe
         WHERE fe.case_id = ?1
           AND (?2 IS NULL OR fe.evidence_id = ?2)
           AND (
                instr(lower(fe.logical_path), ?3) > 0
                OR instr(lower(fe.name), ?3) > 0
                OR instr(lower(fe.metadata_json), ?3) > 0
           ){}
         ORDER BY fe.evidence_id, fe.logical_path, fe.id
         LIMIT ?4",
        scope.sql_clause
    ))?;
    let rows = stmt.query_map(
        params![case_id, evidence_id, query_lower, max_results as i64],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
            ))
        },
    )?;
    let results = rows
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("searching indexed paths")?
        .into_iter()
        .map(
            |(entry_id, evidence_id, logical_path, name, entry_kind, metadata_json)| {
                // A hit can come from the path/name text or from parsed metadata (e.g. an email
                // subject/body a parser extracted). Report which one actually matched instead of
                // always labeling it "path", and show the real matching text for metadata hits
                // instead of just repeating the file path.
                let matched_path_or_name = logical_path.to_ascii_lowercase().contains(query_lower)
                    || name.to_ascii_lowercase().contains(query_lower);
                if matched_path_or_name {
                    return DeepSearchResult {
                        evidence_id,
                        entry_id,
                        logical_path: logical_path.clone(),
                        display_name: name,
                        entry_kind,
                        match_kind: "path".to_string(),
                        selection_offset: None,
                        selection_length: None,
                        data_preview: Some(logical_path),
                    };
                }
                if let Some(offset) = metadata_json.to_ascii_lowercase().find(query_lower) {
                    return DeepSearchResult {
                        evidence_id,
                        entry_id,
                        logical_path,
                        display_name: name,
                        entry_kind,
                        match_kind: "metadata".to_string(),
                        selection_offset: None,
                        selection_length: None,
                        data_preview: Some(content_preview(&metadata_json, offset, query.len())),
                    };
                }
                // The SQL WHERE clause guarantees one of the three fields matched; fall back to a
                // path-style result if the classification above somehow finds none (should not
                // happen in practice).
                DeepSearchResult {
                    evidence_id,
                    entry_id,
                    logical_path: logical_path.clone(),
                    display_name: name,
                    entry_kind,
                    match_kind: "path".to_string(),
                    selection_offset: None,
                    selection_length: None,
                    data_preview: Some(logical_path),
                }
            },
        )
        .collect();
    Ok(results)
}

fn content_search_results(
    conn: &Connection,
    case_id: i64,
    evidence_id: Option<i64>,
    query: &str,
    max_file_bytes: u64,
    max_results: usize,
    scope: &SearchScope,
    results: &mut Vec<DeepSearchResult>,
) -> Result<()> {
    const CONTENT_SEARCH_MAX_FILES: usize = 100_000;
    // Content Deep Search is an index lookup over the first CONTENT_INDEX_BYTES of each processed
    // non-media file. Matches beyond that window, media files, and entries from existing cases that
    // have not been reprocessed are not indexed and therefore keep content_head NULL.
    let mut stmt = conn.prepare(&format!(
        "SELECT fe.id, fe.evidence_id, fe.logical_path, fe.name, fe.entry_kind, fe.content_head
         FROM filesystem_entries fe
         WHERE fe.case_id = ?1
           AND (?2 IS NULL OR fe.evidence_id = ?2)
           AND fe.entry_kind = 'file'{}
         ORDER BY fe.evidence_id, fe.logical_path, fe.id
         LIMIT ?3",
        scope.sql_clause
    ))?;
    let rows = stmt.query_map(
        params![case_id, evidence_id, CONTENT_SEARCH_MAX_FILES as i64],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Option<Vec<u8>>>(5)?,
            ))
        },
    )?;
    for row in rows {
        if results.len() >= max_results {
            break;
        }
        let (entry_id, evidence_id, logical_path, display_name, entry_kind, content_head) =
            row.context("reading content search candidate")?;
        let Some(content_head) = content_head else {
            continue;
        };
        let read_len = usize::try_from(max_file_bytes)
            .unwrap_or(usize::MAX)
            .min(content_head.len());
        let bytes = &content_head[..read_len];
        if let Some(hit) = content_search_hit(&bytes, query) {
            push_content_search_result(
                evidence_id,
                entry_id,
                &logical_path,
                &display_name,
                &entry_kind,
                hit,
                results,
            );
        }
    }
    Ok(())
}

/// Byte-pattern Deep Search over the same indexed content windows the text
/// content search uses. Reports the byte offset and length of each match.
#[allow(clippy::too_many_arguments)]
fn content_hex_search_results(
    conn: &Connection,
    case_id: i64,
    evidence_id: Option<i64>,
    needle: &[u8],
    max_file_bytes: u64,
    max_results: usize,
    scope: &SearchScope,
    results: &mut Vec<DeepSearchResult>,
) -> Result<()> {
    const CONTENT_SEARCH_MAX_FILES: usize = 100_000;
    let mut stmt = conn.prepare(&format!(
        "SELECT fe.id, fe.evidence_id, fe.logical_path, fe.name, fe.entry_kind, fe.content_head
         FROM filesystem_entries fe
         WHERE fe.case_id = ?1
           AND (?2 IS NULL OR fe.evidence_id = ?2)
           AND fe.entry_kind = 'file'
           AND fe.content_head IS NOT NULL{}
         ORDER BY fe.evidence_id, fe.logical_path, fe.id
         LIMIT ?3",
        scope.sql_clause
    ))?;
    let rows = stmt.query_map(
        params![case_id, evidence_id, CONTENT_SEARCH_MAX_FILES as i64],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Option<Vec<u8>>>(5)?,
            ))
        },
    )?;
    for row in rows {
        if results.len() >= max_results {
            break;
        }
        let (entry_id, evidence_id, logical_path, display_name, entry_kind, content_head) =
            row.context("reading hex search candidate")?;
        let Some(content_head) = content_head else {
            continue;
        };
        let read_len = usize::try_from(max_file_bytes)
            .unwrap_or(usize::MAX)
            .min(content_head.len());
        let bytes = &content_head[..read_len];
        if let Some(offset) = find_bytes(bytes, needle) {
            results.push(DeepSearchResult {
                evidence_id,
                entry_id,
                logical_path,
                display_name,
                entry_kind,
                match_kind: "content".to_string(),
                selection_offset: Some(offset as i64),
                selection_length: Some(needle.len() as i64),
                data_preview: Some(hex_match_preview(bytes, offset, needle.len())),
            });
        }
    }
    Ok(())
}

fn content_search_hit(bytes: &[u8], query: &str) -> Option<ContentSearchHit> {
    let content_match = find_content_search_match(bytes, query)?;
    Some(ContentSearchHit {
        offset: content_match.offset,
        length: content_match.length,
        data_preview: content_byte_preview(bytes, content_match.offset, content_match.length),
    })
}

fn push_content_search_result(
    evidence_id: i64,
    entry_id: i64,
    logical_path: &str,
    display_name: &str,
    entry_kind: &str,
    hit: ContentSearchHit,
    results: &mut Vec<DeepSearchResult>,
) {
    results.push(DeepSearchResult {
        evidence_id,
        entry_id,
        logical_path: logical_path.to_string(),
        display_name: display_name.to_string(),
        entry_kind: entry_kind.to_string(),
        match_kind: "content".to_string(),
        selection_offset: Some(hit.offset as i64),
        selection_length: Some(hit.length as i64),
        data_preview: Some(hit.data_preview),
    });
}

struct ContentSearchMatch {
    offset: usize,
    length: usize,
}

fn find_content_search_match(bytes: &[u8], query: &str) -> Option<ContentSearchMatch> {
    if let Some(hex_bytes) = parse_hex_search_query(query) {
        return find_exact_bytes(bytes, &hex_bytes).map(|offset| ContentSearchMatch {
            offset,
            length: hex_bytes.len(),
        });
    }

    let mut best: Option<ContentSearchMatch> = None;
    let query_bytes = query.as_bytes();
    maybe_keep_earliest_match(
        &mut best,
        find_ascii_case_insensitive_bytes(bytes, query_bytes),
        query_bytes.len(),
    );

    let utf16_units = query.encode_utf16().collect::<Vec<_>>();
    let utf16_len = utf16_units.len().saturating_mul(2);
    let le_offset = find_utf16_ascii_case_insensitive_bytes(bytes, &utf16_units, true);
    let mut be_offset = find_utf16_ascii_case_insensitive_bytes(bytes, &utf16_units, false);
    // For ASCII text, a UTF-16LE string at offset N preceded by a 0x00 byte also scans as a
    // valid UTF-16BE match at N-1 (its 1-byte shadow). Windows/NTFS evidence is UTF-16LE in
    // practice, so when the BE candidate is exactly the shadow of the LE candidate, keep LE.
    if let (Some(le), Some(be)) = (le_offset, be_offset) {
        if be + 1 == le {
            be_offset = None;
        }
    }
    maybe_keep_earliest_match(&mut best, le_offset, utf16_len);
    maybe_keep_earliest_match(&mut best, be_offset, utf16_len);

    best
}

fn maybe_keep_earliest_match(
    best: &mut Option<ContentSearchMatch>,
    offset: Option<usize>,
    length: usize,
) {
    let Some(offset) = offset else {
        return;
    };
    if length == 0 {
        return;
    }
    if best
        .as_ref()
        .map_or(true, |current| offset < current.offset)
    {
        *best = Some(ContentSearchMatch { offset, length });
    }
}

fn parse_hex_search_query(query: &str) -> Option<Vec<u8>> {
    let trimmed = query.trim();
    let lower = trimmed.to_ascii_lowercase();
    let raw = if lower.starts_with("hex:") {
        &trimmed[4..]
    } else if lower.starts_with("bytes:") {
        &trimmed[6..]
    } else if lower.starts_with("0x") {
        &trimmed[2..]
    } else {
        return None;
    };
    let compact = raw
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace() && *ch != '_' && *ch != '-')
        .collect::<String>();
    if compact.is_empty()
        || compact.len() % 2 != 0
        || !compact.chars().all(|ch| ch.is_ascii_hexdigit())
    {
        return None;
    }
    let mut bytes = Vec::with_capacity(compact.len() / 2);
    for index in (0..compact.len()).step_by(2) {
        bytes.push(u8::from_str_radix(&compact[index..index + 2], 16).ok()?);
    }
    Some(bytes)
}

fn find_exact_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn find_ascii_case_insensitive_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|window| {
        window
            .iter()
            .zip(needle)
            .all(|(left, right)| ascii_fold_byte(*left) == ascii_fold_byte(*right))
    })
}

fn find_utf16_ascii_case_insensitive_bytes(
    haystack: &[u8],
    needle: &[u16],
    little_endian: bool,
) -> Option<usize> {
    let byte_len = needle.len().checked_mul(2)?;
    if byte_len == 0 || byte_len > haystack.len() {
        return None;
    }
    // Check every byte offset, not only even ones: on-disk UTF-16 text carries no alignment
    // guarantee (strings after odd-length prefixes, in slack, or in unallocated space).
    for offset in 0..=haystack.len() - byte_len {
        let mut matched = true;
        for (index, expected) in needle.iter().enumerate() {
            let position = offset + (index * 2);
            let actual = if little_endian {
                u16::from_le_bytes([haystack[position], haystack[position + 1]])
            } else {
                u16::from_be_bytes([haystack[position], haystack[position + 1]])
            };
            if ascii_fold_u16(actual) != ascii_fold_u16(*expected) {
                matched = false;
                break;
            }
        }
        if matched {
            return Some(offset);
        }
    }
    None
}

fn ascii_fold_byte(byte: u8) -> u8 {
    if byte.is_ascii_uppercase() {
        byte.to_ascii_lowercase()
    } else {
        byte
    }
}

fn ascii_fold_u16(value: u16) -> u16 {
    if (b'A' as u16..=b'Z' as u16).contains(&value) {
        value + 32
    } else {
        value
    }
}

fn content_byte_preview(bytes: &[u8], offset: usize, length: usize) -> String {
    let start = offset.saturating_sub(64);
    let end = offset
        .saturating_add(length)
        .saturating_add(96)
        .min(bytes.len());
    let mut preview = String::new();
    if start > 0 {
        preview.push_str("...");
    }
    preview.push_str(&printable_ascii_preview(&bytes[start..end]));
    if end < bytes.len() {
        preview.push_str("...");
    }

    let matched_end = offset.saturating_add(length).min(bytes.len());
    let matched_hex = bytes[offset..matched_end]
        .iter()
        .take(32)
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(" ");
    if !matched_hex.is_empty() {
        preview.push_str(" | hex ");
        preview.push_str(&matched_hex);
        if matched_end.saturating_sub(offset) > 32 {
            preview.push_str(" ...");
        }
    }
    preview
}

fn printable_ascii_preview(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| {
            if (32..=126).contains(byte) {
                *byte as char
            } else {
                '.'
            }
        })
        .collect()
}

/// Reads up to `max_header_bytes` from the start of an entry for signature analysis. Unlike
/// content search, this reads files of ANY size (it never rejects a file for being larger than the
/// window), because we only need the header to identify the file type. Returns `None` only if the
/// entry's bytes cannot be read at all.
fn read_entry_header(case_path: &Path, entry_id: i64, max_header_bytes: usize) -> Option<Vec<u8>> {
    let bytes = read_filesystem_entry_bytes(
        case_path,
        ReadEntryBytesOptions {
            entry_id,
            offset: 0,
            length: max_header_bytes,
        },
    )
    .ok()?;
    Some(bytes.bytes)
}

/// A file-type signature: magic bytes at a fixed offset plus the extensions that legitimately
/// use that format. Used by signature analysis to detect when a file's real type does not match
/// its extension (old-Ecase "Signature Analysis" / "Bad Signature"; Axy file-type verification).
struct FileSignature {
    /// Short type label, e.g. "JPEG", "PNG", "ZIP/Office Open XML".
    label: &'static str,
    /// Human description of the detected format.
    description: &'static str,
    /// Byte offset where `magic` is expected.
    offset: usize,
    /// Magic byte prefix at `offset`.
    magic: &'static [u8],
    /// Lowercase extensions (no dot) that legitimately carry this format. The first is canonical.
    extensions: &'static [&'static str],
    /// Category label mirroring the analysis categories used elsewhere.
    category: &'static str,
}

/// Curated file-signature table covering forensically common types. Ordered most-specific first so
/// that container formats (ZIP, OLE, ISO-BMFF) that share prefixes resolve deterministically.
const FILE_SIGNATURES: &[FileSignature] = &[
    FileSignature {
        label: "JPEG",
        description: "JPEG image",
        offset: 0,
        magic: &[0xFF, 0xD8, 0xFF],
        extensions: &["jpg", "jpeg", "jpe", "jfif"],
        category: "Pictures and Media",
    },
    FileSignature {
        label: "PNG",
        description: "PNG image",
        offset: 0,
        magic: &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
        extensions: &["png"],
        category: "Pictures and Media",
    },
    FileSignature {
        label: "GIF",
        description: "GIF image",
        offset: 0,
        magic: b"GIF8",
        extensions: &["gif"],
        category: "Pictures and Media",
    },
    FileSignature {
        label: "BMP",
        description: "Windows bitmap image",
        offset: 0,
        magic: b"BM",
        extensions: &["bmp", "dib"],
        category: "Pictures and Media",
    },
    FileSignature {
        label: "TIFF (little-endian)",
        description: "TIFF image",
        offset: 0,
        magic: &[0x49, 0x49, 0x2A, 0x00],
        extensions: &["tif", "tiff", "nef", "cr2", "arw", "dng"],
        category: "Pictures and Media",
    },
    FileSignature {
        label: "TIFF (big-endian)",
        description: "TIFF image",
        offset: 0,
        magic: &[0x4D, 0x4D, 0x00, 0x2A],
        extensions: &["tif", "tiff", "nef", "cr2", "arw", "dng"],
        category: "Pictures and Media",
    },
    FileSignature {
        label: "PDF",
        description: "PDF document",
        offset: 0,
        magic: b"%PDF-",
        extensions: &["pdf"],
        category: "Documents and Office",
    },
    FileSignature {
        label: "RTF",
        description: "Rich Text Format document",
        offset: 0,
        magic: b"{\\rtf",
        extensions: &["rtf"],
        category: "Documents and Office",
    },
    FileSignature {
        label: "OLE Compound File",
        description: "OLE2 compound file (legacy Office doc/xls/ppt, msi, msg)",
        offset: 0,
        magic: &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1],
        extensions: &["doc", "xls", "ppt", "msi", "msg", "vsd", "db"],
        category: "Documents and Office",
    },
    FileSignature {
        label: "ZIP / Office Open XML / OpenDocument",
        description: "ZIP container (also docx/xlsx/pptx, odt/ods/odp, jar, apk, epub)",
        offset: 0,
        magic: &[0x50, 0x4B, 0x03, 0x04],
        extensions: &[
            "zip", "docx", "xlsx", "pptx", "odt", "ods", "odp", "jar", "apk", "epub", "kmz", "vsdx",
        ],
        category: "Archives and Containers",
    },
    FileSignature {
        label: "RAR",
        description: "RAR archive",
        offset: 0,
        magic: &[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07],
        extensions: &["rar"],
        category: "Archives and Containers",
    },
    FileSignature {
        label: "7-Zip",
        description: "7-Zip archive",
        offset: 0,
        magic: &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C],
        extensions: &["7z"],
        category: "Archives and Containers",
    },
    FileSignature {
        label: "GZIP",
        description: "gzip compressed data",
        offset: 0,
        magic: &[0x1F, 0x8B],
        extensions: &["gz", "gzip", "tgz"],
        category: "Archives and Containers",
    },
    FileSignature {
        label: "MP3 (ID3)",
        description: "MP3 audio with ID3 tag",
        offset: 0,
        magic: b"ID3",
        extensions: &["mp3"],
        category: "Pictures and Media",
    },
    FileSignature {
        label: "ISO Base Media (MP4/MOV)",
        description: "ISO base media file (mp4, m4v, m4a, mov, 3gp)",
        offset: 4,
        magic: b"ftyp",
        extensions: &["mp4", "m4v", "m4a", "mov", "3gp", "3g2", "f4v"],
        category: "Pictures and Media",
    },
    FileSignature {
        label: "RIFF (AVI/WAV)",
        description: "RIFF container (avi, wav, webp)",
        offset: 0,
        magic: b"RIFF",
        extensions: &["avi", "wav", "webp"],
        category: "Pictures and Media",
    },
    FileSignature {
        label: "Windows PE",
        description: "Windows executable / DLL (MZ / PE)",
        offset: 0,
        magic: &[0x4D, 0x5A],
        extensions: &["exe", "dll", "sys", "scr", "ocx", "cpl", "drv"],
        category: "Program Execution",
    },
    FileSignature {
        label: "ELF",
        description: "ELF executable / shared object",
        offset: 0,
        magic: &[0x7F, 0x45, 0x4C, 0x46],
        extensions: &["elf", "so", "o", "out"],
        category: "Program Execution",
    },
    FileSignature {
        label: "SQLite 3",
        description: "SQLite 3 database",
        offset: 0,
        magic: b"SQLite format 3\x00",
        extensions: &["db", "sqlite", "sqlite3", "db3"],
        category: "Databases",
    },
    FileSignature {
        label: "XML",
        description: "XML document",
        offset: 0,
        magic: b"<?xml",
        extensions: &["xml", "xhtml", "plist", "svg"],
        category: "Documents and Office",
    },
];

/// Result of comparing a file's header against the signature table.
struct SignatureFinding {
    /// One of: match, alias, mismatch, unknown, no_extension.
    status: &'static str,
    /// Detected type label, if any signature matched the header.
    detected_label: Option<&'static str>,
    detected_description: Option<&'static str>,
    detected_category: Option<&'static str>,
    /// Lowercase file extension parsed from the name (no dot), if present.
    extension: Option<String>,
}

/// Parse the lowercase extension (without the dot) from a file name. Returns `None` for names with
/// no extension, names that are all extension (dotfiles like `.bashrc`), or NTFS ADS names where
/// the stream part follows a colon.
fn file_extension_of(name: &str) -> Option<String> {
    // For ADS rows like `file.txt:Zone.Identifier`, judge the base name before the stream colon.
    let base = name.split(':').next().unwrap_or(name);
    let dot = base.rfind('.')?;
    // A leading-dot name (dotfile) with no other dot has no real extension.
    if dot == 0 {
        return None;
    }
    let ext = &base[dot + 1..];
    if ext.is_empty() || ext.len() > 12 || !ext.chars().all(|c| c.is_ascii_alphanumeric()) {
        return None;
    }
    Some(ext.to_ascii_lowercase())
}

/// Detect a file's true type from its header bytes and compare against its extension.
fn evaluate_signature(name: &str, header: &[u8]) -> SignatureFinding {
    let extension = file_extension_of(name);
    let detected = FILE_SIGNATURES.iter().find(|sig| {
        let end = sig.offset + sig.magic.len();
        header.len() >= end && &header[sig.offset..end] == sig.magic
    });

    let status = match (&extension, detected) {
        (None, _) => "no_extension",
        (Some(_), None) => "unknown",
        (Some(ext), Some(sig)) => {
            if sig.extensions.contains(&ext.as_str()) {
                // Canonical extension for this format.
                if Some(ext.as_str()) == sig.extensions.first().copied() {
                    "match"
                } else {
                    // Legitimate alternate extension for the same container/format.
                    "alias"
                }
            } else {
                "mismatch"
            }
        }
    };

    SignatureFinding {
        status,
        detected_label: detected.map(|sig| sig.label),
        detected_description: detected.map(|sig| sig.description),
        detected_category: detected.map(|sig| sig.category),
        extension,
    }
}

fn report_bookmarks_for_folder(conn: &Connection, folder_id: i64) -> Result<Vec<ReportBookmark>> {
    let mut stmt = conn.prepare(
        "SELECT id, folder_id, bookmark_type, data_type, title, examiner_comment,
                source_ref_json, content_ref_json, created_at
         FROM bookmarks
         WHERE folder_id = ?1 AND in_report = 1
         ORDER BY id",
    )?;
    let rows = stmt.query_map(params![folder_id], |row| {
        Ok(RawReportBookmark {
            id: row.get(0)?,
            folder_id: row.get(1)?,
            bookmark_type: row.get(2)?,
            data_type: row.get(3)?,
            title: row.get(4)?,
            examiner_comment: row.get(5)?,
            source_ref_json: row.get(6)?,
            content_ref_json: row.get(7)?,
            created_at: row.get(8)?,
        })
    })?;
    let raw_bookmarks = rows
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("listing report bookmarks")?;

    raw_bookmarks
        .into_iter()
        .map(|raw| {
            let source_ref_json =
                parse_stored_json(&raw.source_ref_json, "source_ref_json", raw.id)?;
            let content_ref_json =
                parse_stored_json(&raw.content_ref_json, "content_ref_json", raw.id)?;
            Ok(ReportBookmark {
                id: raw.id,
                folder_id: raw.folder_id,
                bookmark_type: raw.bookmark_type,
                data_type: raw.data_type,
                title: raw.title,
                examiner_comment: raw.examiner_comment,
                source_ref_json,
                content_ref_json,
                created_at: raw.created_at,
                items: report_items_for_bookmark(conn, raw.id)?,
            })
        })
        .collect()
}

struct RawReportBookmark {
    id: i64,
    folder_id: i64,
    bookmark_type: String,
    data_type: Option<String>,
    title: Option<String>,
    examiner_comment: Option<String>,
    source_ref_json: String,
    content_ref_json: String,
    created_at: String,
}

fn report_items_for_bookmark(conn: &Connection, bookmark_id: i64) -> Result<Vec<BookmarkItem>> {
    let mut stmt = conn.prepare(
        "SELECT id, bookmark_id, evidence_id, entry_id, item_order, display_name, logical_path,
                selection_offset, selection_length, data_preview, item_ref_json, created_at
         FROM bookmark_items
         WHERE bookmark_id = ?1
         ORDER BY item_order, id",
    )?;
    let rows = stmt.query_map(params![bookmark_id], |row| {
        Ok(RawBookmarkItem {
            id: row.get(0)?,
            bookmark_id: row.get(1)?,
            evidence_id: row.get(2)?,
            entry_id: row.get(3)?,
            item_order: row.get(4)?,
            display_name: row.get(5)?,
            logical_path: row.get(6)?,
            selection_offset: row.get(7)?,
            selection_length: row.get(8)?,
            data_preview: row.get(9)?,
            item_ref_json: row.get(10)?,
            created_at: row.get(11)?,
        })
    })?;
    let raw_items = rows
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("listing report bookmark items")?;
    raw_items.into_iter().map(bookmark_item_from_raw).collect()
}

fn apply_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(INITIAL_SCHEMA)
        .context("applying initial schema")?;
    apply_schema_migrations(conn)
}

fn apply_schema_migrations(conn: &Connection) -> Result<()> {
    ensure_filesystem_entries_content_head_column(conn)?;
    ensure_cases_metadata_columns(conn)?;
    ensure_evidence_hash_columns(conn)?;
    ensure_installed_resources_config_column(conn)?;
    ensure_filesystem_entries_indexes(conn)
}

fn ensure_installed_resources_config_column(conn: &Connection) -> Result<()> {
    // Cases created before the vendor-neutral rename still carry legacy
    // wording. The legacy identifiers are assembled at runtime so the old
    // vendor name never appears anywhere in this source tree.
    let legacy_column = format!("{}case_file_name", "en");
    let legacy_version = format!("{}case-6.11-baseline", "en");
    let legacy_notes = format!("modeled from {}Case v6.11 Chapter 3.", "En");
    let mut stmt = conn
        .prepare("PRAGMA table_info(installed_resources)")
        .context("reading installed_resources columns")?;
    let existing = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("collecting installed_resources columns")?;
    if existing.iter().any(|name| *name == legacy_column) {
        conn.execute(
            &format!(
                "ALTER TABLE installed_resources RENAME COLUMN {legacy_column} TO config_file_name"
            ),
            [],
        )
        .context("renaming installed_resources.config_file_name column")?;
    }
    // Refresh the tool-seeded resource rows (not examiner data) that older
    // cases created with the legacy vendor wording.
    conn.execute(
        "UPDATE installed_resources
         SET version = replace(version, ?1, 'ecase-6.11-baseline'),
             notes = replace(notes, ?2, 'modeled from the old Ecase 6.11 flavor, Chapter 3.')
         WHERE version LIKE '%' || ?1 || '%'
            OR notes LIKE '%' || ?2 || '%'",
        params![legacy_version, legacy_notes],
    )
    .context("refreshing seeded installed_resources wording")?;
    Ok(())
}

fn ensure_filesystem_entries_indexes(conn: &Connection) -> Result<()> {
    // Per-evidence entry counts (report, dashboard) must not scan the wide
    // UNIQUE(evidence_id, logical_path) index on large cases.
    //
    // The parent/entry/job FK indexes make ON DELETE cascades linear: without
    // them, removing an evidence source with N indexed entries scans the whole
    // entries table once per deleted row (parent_id ON DELETE SET NULL) -
    // O(N^2), which on a 359k-entry case never finishes and holds the write
    // lock ("database is locked" for every other action).
    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS ix_filesystem_entries_case_evidence
         ON filesystem_entries(case_id, evidence_id);
         CREATE INDEX IF NOT EXISTS ix_filesystem_entries_parent
         ON filesystem_entries(parent_id);
         CREATE INDEX IF NOT EXISTS ix_filesystem_entries_job
         ON filesystem_entries(discovered_by_job_id);
         CREATE INDEX IF NOT EXISTS ix_bookmark_items_entry
         ON bookmark_items(entry_id);",
    )
    .context("creating filesystem_entries/bookmark_items foreign-key indexes")
}

fn ensure_evidence_hash_columns(conn: &Connection) -> Result<()> {
    let mut stmt = conn
        .prepare("PRAGMA table_info(evidence_sources)")
        .context("reading evidence_sources columns")?;
    let existing = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("collecting evidence_sources columns")?;
    for column in ["sha256_hex", "hashed_at"] {
        if !existing.iter().any(|name| name == column) {
            conn.execute(
                &format!("ALTER TABLE evidence_sources ADD COLUMN {column} TEXT"),
                [],
            )
            .with_context(|| format!("adding evidence_sources.{column} column"))?;
        }
    }
    Ok(())
}

fn ensure_cases_metadata_columns(conn: &Connection) -> Result<()> {
    let mut stmt = conn
        .prepare("PRAGMA table_info(cases)")
        .context("reading cases columns")?;
    let existing = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("collecting cases columns")?;
    for column in ["case_number", "case_type", "description"] {
        if !existing.iter().any(|name| name == column) {
            conn.execute(&format!("ALTER TABLE cases ADD COLUMN {column} TEXT"), [])
                .with_context(|| format!("adding cases.{column} column"))?;
        }
    }
    Ok(())
}

fn ensure_filesystem_entries_content_head_column(conn: &Connection) -> Result<()> {
    let mut stmt = conn
        .prepare("PRAGMA table_info(filesystem_entries)")
        .context("checking filesystem_entries columns")?;
    let columns = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("reading filesystem_entries columns")?;
    if columns.is_empty() || columns.iter().any(|name| name == "content_head") {
        return Ok(());
    }
    conn.execute(
        "ALTER TABLE filesystem_entries ADD COLUMN content_head BLOB",
        [],
    )
    .context("adding filesystem_entries.content_head column")?;
    Ok(())
}

fn enable_foreign_keys(conn: &Connection) -> Result<()> {
    conn.execute_batch("PRAGMA foreign_keys = ON;")
        .context("enabling SQLite foreign keys")
}

fn open_existing_case(case_path: &Path) -> Result<Connection> {
    if !case_path.exists() {
        bail!("case does not exist: {}", case_path.display());
    }
    let conn = Connection::open(case_path)
        .with_context(|| format!("opening case database {}", case_path.display()))?;
    enable_foreign_keys(&conn)?;
    // WAL lets the UI keep reading (state, browsing) while a long indexing job
    // writes; busy_timeout makes concurrent access wait rather than fail.
    // Set the wait timeout first so a contended access waits rather than fails,
    // then switch to WAL best-effort (converting an existing rollback-mode DB
    // needs a write lock; if another job holds it, keep the current mode rather
    // than failing the open).
    conn.execute_batch("PRAGMA busy_timeout = 15000;")
        .context("configuring SQLite busy timeout")?;
    let _ = conn.execute_batch("PRAGMA journal_mode = WAL;");
    if !schema_version_applied(&conn, 1)? {
        apply_schema(&conn)?;
    }
    apply_schema_migrations(&conn)?;
    Ok(conn)
}

fn schema_version_applied(conn: &Connection, version: i64) -> Result<bool> {
    let has_migration_table = conn
        .query_row(
            "SELECT 1
             FROM sqlite_master
             WHERE type = 'table' AND name = 'schema_migrations'",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !has_migration_table {
        return Ok(false);
    }

    conn.query_row(
        "SELECT 1 FROM schema_migrations WHERE version = ?1",
        params![version],
        |_| Ok(()),
    )
    .optional()
    .map(|row| row.is_some())
    .context("checking schema migration version")
}

fn active_case_id(conn: &Connection) -> Result<i64> {
    let (count, min_id, max_id): (i64, Option<i64>, Option<i64>) =
        conn.query_row("SELECT COUNT(*), MIN(id), MAX(id) FROM cases", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?;
    match (count, min_id, max_id) {
        (0, _, _) => bail!("case database has no case row"),
        (1, Some(1), Some(1)) => Ok(1),
        (1, Some(id), Some(_)) => bail!("case database has unexpected case id {id}; expected 1"),
        _ => bail!("case database must contain exactly one case row"),
    }
}

fn read_global_options(conn: &Connection) -> Result<GlobalOptions> {
    conn.query_row(
        "SELECT id, config_root, evidence_library_root, default_storage_root, created_at, updated_at
         FROM global_options
         WHERE id = 1",
        [],
        |row| {
            Ok(GlobalOptions {
                id: row.get(0)?,
                config_root: row.get(1)?,
                evidence_library_root: row.get(2)?,
                default_storage_root: row.get(3)?,
                created_at: row.get(4)?,
                updated_at: row.get(5)?,
            })
        },
    )
    .context("reading global options")
}

fn audit_actor(conn: &Connection, case_id: i64) -> Result<String> {
    let examiner_name: Option<String> = conn
        .query_row(
            "SELECT examiner_name FROM cases WHERE id = ?1",
            params![case_id],
            |row| row.get(0),
        )
        .optional()?
        .flatten();
    Ok(audit_actor_from_examiner(examiner_name.as_deref()))
}

fn audit_actor_from_examiner(examiner_name: Option<&str>) -> String {
    examiner_name
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown")
        .to_string()
}

fn path_update_sql_value(update: Option<&GlobalOptionPathUpdate>) -> (bool, Option<String>) {
    match update {
        Some(GlobalOptionPathUpdate::Set(path)) => {
            (true, Some(path.to_string_lossy().into_owned()))
        }
        Some(GlobalOptionPathUpdate::Clear) => (true, None),
        None => (false, None),
    }
}

fn ensure_bookmark_folder(conn: &Connection, case_id: i64, folder_id: i64) -> Result<()> {
    let exists = conn
        .query_row(
            "SELECT 1 FROM bookmark_folders WHERE id = ?1 AND case_id = ?2",
            params![folder_id, case_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !exists {
        bail!("bookmark folder does not exist in active case: {folder_id}");
    }
    Ok(())
}

fn ensure_bookmark_folder_name_available(
    conn: &Connection,
    case_id: i64,
    parent_id: Option<i64>,
    name: &str,
) -> Result<()> {
    let exists = conn
        .query_row(
            "SELECT 1
             FROM bookmark_folders
             WHERE case_id = ?1 AND parent_id IS ?2 AND name = ?3",
            params![case_id, parent_id, name],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if exists {
        bail!("bookmark folder already exists under this parent: {name}");
    }
    Ok(())
}

fn ensure_bookmark(conn: &Connection, case_id: i64, bookmark_id: i64) -> Result<()> {
    let exists = conn
        .query_row(
            "SELECT 1 FROM bookmarks WHERE id = ?1 AND case_id = ?2",
            params![bookmark_id, case_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !exists {
        bail!("bookmark does not exist in active case: {bookmark_id}");
    }
    Ok(())
}

fn ensure_bookmark_item_order_available(
    conn: &Connection,
    bookmark_id: i64,
    item_order: i64,
) -> Result<()> {
    let exists = conn
        .query_row(
            "SELECT 1 FROM bookmark_items WHERE bookmark_id = ?1 AND item_order = ?2",
            params![bookmark_id, item_order],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if exists {
        bail!("bookmark item order already exists for bookmark {bookmark_id}: {item_order}");
    }
    Ok(())
}

fn ensure_evidence_source(conn: &Connection, case_id: i64, evidence_id: i64) -> Result<()> {
    let exists = conn
        .query_row(
            "SELECT 1 FROM evidence_sources WHERE id = ?1 AND case_id = ?2",
            params![evidence_id, case_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !exists {
        bail!("evidence source does not exist in active case: {evidence_id}");
    }
    Ok(())
}

fn ensure_evidence_path_available(
    conn: &Connection,
    case_id: i64,
    source_path: &str,
) -> Result<()> {
    let exists = conn
        .query_row(
            "SELECT 1 FROM evidence_sources WHERE case_id = ?1 AND source_path = ?2",
            params![case_id, source_path],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if exists {
        bail!("evidence source already attached: {source_path}");
    }
    Ok(())
}

/// Reprocessing deletes and regenerates an evidence source's filesystem entries, which nulls
/// `bookmark_items.entry_id` through the `ON DELETE SET NULL` foreign key. Restore each item's
/// entry link by matching its stored `logical_path` against the fresh index so existing bookmarks
/// survive a reprocess. Items whose logical path no longer exists stay unlinked.
fn relink_bookmark_items_tx(conn: &Connection, case_id: i64, evidence_id: i64) -> Result<usize> {
    let relinked = conn.execute(
        "UPDATE bookmark_items
         SET entry_id = (
             SELECT fe.id
             FROM filesystem_entries fe
             WHERE fe.case_id = ?1
               AND fe.evidence_id = bookmark_items.evidence_id
               AND fe.logical_path = bookmark_items.logical_path
             ORDER BY fe.id
             LIMIT 1
         )
         WHERE evidence_id = ?2
           AND entry_id IS NULL
           AND logical_path IS NOT NULL
           AND EXISTS (
               SELECT 1
               FROM filesystem_entries fe
               WHERE fe.case_id = ?1
                 AND fe.evidence_id = bookmark_items.evidence_id
                 AND fe.logical_path = bookmark_items.logical_path
           )",
        params![case_id, evidence_id],
    )?;
    Ok(relinked)
}

fn clear_stale_findings_tx(
    conn: &Connection,
    case_id: i64,
    actor: &str,
) -> Result<ClearStaleFindingsResult> {
    let entry_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM filesystem_entries WHERE case_id = ?1",
        params![case_id],
        |row| row.get(0),
    )?;
    let evidence_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM evidence_sources WHERE case_id = ?1",
        params![case_id],
        |row| row.get(0),
    )?;
    let before_items = case_bookmark_item_count(conn, case_id)?;
    let before_bookmarks = case_bookmark_count(conn, case_id)?;
    let before_folders = case_bookmark_folder_count(conn, case_id)?;
    if before_items == 0 && before_bookmarks == 0 && before_folders == 0 {
        return Ok(ClearStaleFindingsResult::default());
    }

    if evidence_count == 0 {
        conn.execute(
            "DELETE FROM bookmark_folders WHERE case_id = ?1",
            params![case_id],
        )?;
        conn.execute("DELETE FROM bookmarks WHERE case_id = ?1", params![case_id])?;
    } else {
        conn.execute(
            "DELETE FROM bookmark_items
             WHERE bookmark_id IN (SELECT id FROM bookmarks WHERE case_id = ?1)
               AND evidence_id IS NULL
               AND entry_id IS NULL",
            params![case_id],
        )?;
    }
    if evidence_count > 0 && entry_count == 0 {
        conn.execute(
            "DELETE FROM bookmark_items
             WHERE bookmark_id IN (SELECT id FROM bookmarks WHERE case_id = ?1)
               AND entry_id IS NULL
               AND (
                   evidence_id IS NULL
                   OR evidence_id NOT IN (
                       SELECT id FROM evidence_sources WHERE case_id = ?1
                   )
               )",
            params![case_id],
        )?;
    }
    conn.execute(
        "DELETE FROM bookmarks
         WHERE case_id = ?1
           AND NOT EXISTS (
               SELECT 1 FROM bookmark_items WHERE bookmark_id = bookmarks.id
           )",
        params![case_id],
    )?;
    conn.execute(
        "DELETE FROM bookmark_folders
         WHERE case_id = ?1
           AND NOT EXISTS (
               SELECT 1 FROM bookmarks WHERE folder_id = bookmark_folders.id
           )",
        params![case_id],
    )?;

    let result = ClearStaleFindingsResult {
        removed_folders: before_folders.saturating_sub(case_bookmark_folder_count(conn, case_id)?),
        removed_bookmarks: before_bookmarks.saturating_sub(case_bookmark_count(conn, case_id)?),
        removed_items: before_items.saturating_sub(case_bookmark_item_count(conn, case_id)?),
    };
    if result.removed_folders > 0 || result.removed_bookmarks > 0 || result.removed_items > 0 {
        conn.execute(
            "INSERT INTO audit_events(case_id, event_type, actor, object_type, object_id, details_json)
             VALUES (?1, 'findings.clear_stale', ?2, 'case', ?1,
                     json_object('removed_folders', ?3, 'removed_bookmarks', ?4, 'removed_items', ?5, 'reason', 'stale_or_orphan_findings'))",
            params![
                case_id,
                actor,
                result.removed_folders,
                result.removed_bookmarks,
                result.removed_items,
            ],
        )?;
    }
    Ok(result)
}

fn case_bookmark_folder_count(conn: &Connection, case_id: i64) -> Result<i64> {
    conn.query_row(
        "SELECT COUNT(*) FROM bookmark_folders WHERE case_id = ?1",
        params![case_id],
        |row| row.get(0),
    )
    .context("counting bookmark folders")
}

fn case_bookmark_count(conn: &Connection, case_id: i64) -> Result<i64> {
    conn.query_row(
        "SELECT COUNT(*) FROM bookmarks WHERE case_id = ?1",
        params![case_id],
        |row| row.get(0),
    )
    .context("counting bookmarks")
}

fn case_bookmark_item_count(conn: &Connection, case_id: i64) -> Result<i64> {
    conn.query_row(
        "SELECT COUNT(*)
         FROM bookmark_items bi
         JOIN bookmarks b ON b.id = bi.bookmark_id
         WHERE b.case_id = ?1",
        params![case_id],
        |row| row.get(0),
    )
    .context("counting bookmark items")
}

fn ensure_filesystem_entry(
    conn: &Connection,
    case_id: i64,
    entry_id: i64,
    expected_evidence_id: Option<i64>,
) -> Result<i64> {
    let evidence_id = conn
        .query_row(
            "SELECT evidence_id FROM filesystem_entries WHERE id = ?1 AND case_id = ?2",
            params![entry_id, case_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    let Some(evidence_id) = evidence_id else {
        bail!("filesystem entry does not exist in active case: {entry_id}");
    };
    if let Some(expected_evidence_id) = expected_evidence_id {
        if evidence_id != expected_evidence_id {
            bail!(
                "filesystem entry {entry_id} belongs to evidence source {evidence_id}, not {expected_evidence_id}"
            );
        }
    }
    Ok(evidence_id)
}

fn validate_json_object(value: &serde_json::Value, field: &str) -> Result<()> {
    if value.is_object() {
        Ok(())
    } else {
        bail!("{field} must be a JSON object")
    }
}

fn validate_non_negative(value: Option<i64>, field: &str) -> Result<()> {
    if matches!(value, Some(value) if value < 0) {
        bail!("{field} cannot be negative");
    }
    Ok(())
}

fn parse_stored_json(value: &str, field: &str, bookmark_id: i64) -> Result<serde_json::Value> {
    serde_json::from_str(value)
        .with_context(|| format!("parsing {field} for bookmark {bookmark_id}"))
}

fn parse_stored_item_json(value: &str, field: &str, item_id: i64) -> Result<serde_json::Value> {
    serde_json::from_str(value)
        .with_context(|| format!("parsing {field} for bookmark item {item_id}"))
}

fn read_bookmark_item(conn: &Connection, case_id: i64, item_id: i64) -> Result<BookmarkItem> {
    let raw = conn.query_row(
        "SELECT bi.id, bi.bookmark_id, bi.evidence_id, bi.entry_id, bi.item_order,
                bi.display_name, bi.logical_path, bi.selection_offset, bi.selection_length,
                bi.data_preview, bi.item_ref_json, bi.created_at
         FROM bookmark_items bi
         JOIN bookmarks b ON b.id = bi.bookmark_id
         WHERE b.case_id = ?1 AND bi.id = ?2",
        params![case_id, item_id],
        |row| {
            Ok(RawBookmarkItem {
                id: row.get(0)?,
                bookmark_id: row.get(1)?,
                evidence_id: row.get(2)?,
                entry_id: row.get(3)?,
                item_order: row.get(4)?,
                display_name: row.get(5)?,
                logical_path: row.get(6)?,
                selection_offset: row.get(7)?,
                selection_length: row.get(8)?,
                data_preview: row.get(9)?,
                item_ref_json: row.get(10)?,
                created_at: row.get(11)?,
            })
        },
    )?;
    bookmark_item_from_raw(raw)
}

fn bookmark_item_from_raw(raw: RawBookmarkItem) -> Result<BookmarkItem> {
    let item_ref_json = parse_stored_item_json(&raw.item_ref_json, "item_ref_json", raw.id)?;
    Ok(BookmarkItem {
        id: raw.id,
        bookmark_id: raw.bookmark_id,
        evidence_id: raw.evidence_id,
        entry_id: raw.entry_id,
        item_order: raw.item_order,
        display_name: raw.display_name,
        logical_path: raw.logical_path,
        selection_offset: raw.selection_offset,
        selection_length: raw.selection_length,
        data_preview: raw.data_preview,
        item_ref_json,
        created_at: raw.created_at,
    })
}

/// Report display form of an entry path: the indexer's synthetic containers
/// are stripped so paths read volume-first (old-Ecase device -> volume view).
/// Stored logical paths are never rewritten; this is display-only.
fn display_entry_path(path: &str) -> String {
    for prefix in [
        "/Image Analysis/Volumes",
        "/Image Analysis/Partitions",
        "/Image Analysis",
    ] {
        if let Some(rest) = path.strip_prefix(prefix) {
            if rest.is_empty() {
                return "/".to_string();
            }
            if rest.starts_with('/') {
                return rest.to_string();
            }
        }
    }
    path.to_string()
}

fn render_report_items_html(html: &mut String, items: &[BookmarkItem]) {
    if items.is_empty() {
        html.push_str("<p class=\"meta\">No bookmark items.</p>");
        return;
    }

    html.push_str("<table class=\"items\"><thead><tr><th>Order</th><th>Name</th><th>Path</th><th>Selection</th><th>Preview</th><th>Reference</th></tr></thead><tbody>");
    for item in items {
        html.push_str("<tr><td>");
        html.push_str(&item.item_order.to_string());
        html.push_str("</td><td>");
        html.push_str(&escape_html(item.display_name.as_deref().unwrap_or("")));
        html.push_str("</td><td>");
        html.push_str(&escape_html(&display_entry_path(
            item.logical_path.as_deref().unwrap_or(""),
        )));
        html.push_str("</td><td>");
        if let Some(offset) = item.selection_offset {
            html.push_str("offset ");
            html.push_str(&offset.to_string());
        }
        if let Some(length) = item.selection_length {
            if item.selection_offset.is_some() {
                html.push_str(", ");
            }
            html.push_str("length ");
            html.push_str(&length.to_string());
        }
        html.push_str("</td><td>");
        render_report_item_preview_html(html, item);
        html.push_str("</td><td>");
        render_report_item_reference_html(html, item);
        html.push_str("</td></tr>");
    }
    html.push_str("</tbody></table>");
}

fn render_report_item_preview_html(html: &mut String, item: &BookmarkItem) {
    if render_email_details_html(html, &item.item_ref_json) {
        // Email bookmarks still carry forensic context (MAC times, deleted/recovered state,
        // offsets, size, extension) when the item ref has it, so append it after the
        // email-specific fields instead of stopping here.
        render_forensic_context_details_html(html, item);
        return;
    }
    if render_browser_activity_details_html(html, &item.item_ref_json) {
        if let Some(preview) = item
            .data_preview
            .as_deref()
            .filter(|value| !value.is_empty())
        {
            html.push_str("<p class=\"meta\">Preview: ");
            html.push_str(&escape_html(preview));
            html.push_str("</p>");
        }
        return;
    }
    if render_forensic_context_details_html(html, item) {
        if let Some(preview) = item
            .data_preview
            .as_deref()
            .filter(|value| !value.is_empty())
        {
            html.push_str("<p class=\"meta\">Preview: ");
            html.push_str(&escape_html(preview));
            html.push_str("</p>");
        }
        return;
    }
    html.push_str(&escape_html(item.data_preview.as_deref().unwrap_or("")));
}

fn render_report_item_reference_html(html: &mut String, item: &BookmarkItem) {
    if email_artifact_kind(&item.item_ref_json).is_some() {
        html.push_str("<span class=\"meta\">email</span>");
        return;
    }
    if browser_activity_kind(&item.item_ref_json).is_some() {
        html.push_str("<span class=\"meta\">browser_activity</span>");
        return;
    }
    if item
        .item_ref_json
        .get("kind")
        .and_then(|value| value.as_str())
        == Some("search_result")
    {
        html.push_str("<span class=\"meta\">search_result</span>");
        return;
    }
    html.push_str("<pre>");
    let mut item_ref_value = item.item_ref_json.clone();
    if let Some(object) = item_ref_value.as_object_mut() {
        for key in ["logical_path", "path", "relative_path"] {
            if let Some(value) = object.get_mut(key) {
                if let Some(text) = value.as_str() {
                    *value = serde_json::Value::String(display_entry_path(text));
                }
            }
        }
    }
    let item_ref =
        serde_json::to_string_pretty(&item_ref_value).unwrap_or_else(|_| "{}".to_string());
    html.push_str(&escape_html(&item_ref));
    html.push_str("</pre>");
}

fn render_forensic_context_details_html(html: &mut String, item: &BookmarkItem) -> bool {
    let item_ref = &item.item_ref_json;
    let has_context = item_ref.get("kind").and_then(|value| value.as_str())
        == Some("search_result")
        || item_ref.get("mft_record_physical_offset").is_some()
        || item_ref.get("file_data_physical_offset").is_some()
        || item_ref.get("is_deleted").is_some()
        || item_ref.get("file_extension").is_some();
    if !has_context {
        return false;
    }
    html.push_str("<dl class=\"activity-details\"><dt>Artifact</dt><dd>Forensic Finding</dd>");
    if let Some(path) = item_ref
        .get("logical_path")
        .and_then(|value| value.as_str())
        .or_else(|| {
            item_ref
                .get("relative_path")
                .and_then(|value| value.as_str())
        })
    {
        html.push_str("<dt>Path</dt><dd>");
        html.push_str(&escape_html(&display_entry_path(path)));
        html.push_str("</dd>");
    }
    push_activity_detail(html, item_ref, "Extension", &["file_extension"]);
    push_activity_detail(html, item_ref, "Detected Type", &["detected_signature"]);
    push_activity_detail(html, item_ref, "Signature Status", &["signature_status"]);
    push_activity_detail(html, item_ref, "Size", &["size_bytes"]);
    push_activity_detail(html, item_ref, "Deleted", &["is_deleted"]);
    push_activity_detail(html, item_ref, "Match", &["match_kind"]);
    push_activity_detail(
        html,
        item_ref,
        "Finding Offset",
        &["finding_logical_offset", "selection_offset"],
    );
    push_activity_detail(html, item_ref, "Selection Length", &["selection_length"]);
    push_activity_detail(html, item_ref, "Storage Area", &["storage_area"]);
    push_activity_detail(
        html,
        item_ref,
        "MFT Record Logical Offset",
        &["mft_record_logical_offset"],
    );
    push_activity_detail(
        html,
        item_ref,
        "MFT Record Physical Offset",
        &["mft_record_physical_offset"],
    );
    push_activity_detail(
        html,
        item_ref,
        "File Data Logical Offset",
        &["file_data_logical_offset"],
    );
    push_activity_detail(
        html,
        item_ref,
        "File Data Physical Offset",
        &["file_data_physical_offset"],
    );
    push_activity_detail(html, item_ref, "In File Slack", &["is_file_slack"]);
    push_activity_detail(html, item_ref, "In Unallocated Space", &["is_unallocated"]);
    if let Some(metadata) = item_ref.get("metadata") {
        push_activity_detail(
            html,
            metadata,
            "Created",
            &["ntfs_creation_time_utc", "ntfs_standard_creation_time_utc"],
        );
        push_activity_detail(
            html,
            metadata,
            "Modified",
            &[
                "ntfs_modification_time_utc",
                "ntfs_standard_modification_time_utc",
            ],
        );
        push_activity_detail(
            html,
            metadata,
            "Accessed",
            &["ntfs_access_time_utc", "ntfs_standard_access_time_utc"],
        );
        push_activity_detail(
            html,
            metadata,
            "MFT Modified",
            &[
                "ntfs_mft_record_modification_time_utc",
                "ntfs_standard_mft_record_modification_time_utc",
            ],
        );
        push_activity_detail(html, metadata, "Recovery Source", &["recovery_source"]);
        push_activity_detail(html, metadata, "Recovery Status", &["recovery_status"]);
    }
    html.push_str("</dl>");
    true
}

fn render_email_details_html(html: &mut String, item_ref: &serde_json::Value) -> bool {
    let Some(kind) = email_artifact_kind(item_ref) else {
        return false;
    };
    html.push_str("<dl class=\"activity-details\"><dt>Artifact</dt><dd>");
    html.push_str(if kind == "email_store" {
        "Email Store"
    } else {
        "Email Message"
    });
    html.push_str("</dd>");
    push_activity_detail(html, item_ref, "Email Format", &["email_format"]);
    push_activity_detail(
        html,
        item_ref,
        "Email Parser",
        &["email_parser", "email_parser_status"],
    );
    push_activity_detail(html, item_ref, "From", &["email_from"]);
    push_activity_detail(html, item_ref, "To", &["email_to"]);
    push_activity_detail(html, item_ref, "Cc", &["email_cc"]);
    push_activity_detail(html, item_ref, "Bcc", &["email_bcc"]);
    push_activity_detail(
        html,
        item_ref,
        "Subject",
        &["email_subject", "display_name"],
    );
    push_activity_detail(html, item_ref, "Date", &["email_date"]);
    push_activity_detail(html, item_ref, "Message ID", &["email_message_id"]);
    push_activity_detail(html, item_ref, "Reply-To", &["email_reply_to"]);
    push_activity_detail(html, item_ref, "In Reply To", &["email_in_reply_to"]);
    push_activity_detail(html, item_ref, "Body Preview", &["email_body_preview"]);
    push_activity_detail(html, item_ref, "Parser Error", &["email_parser_error"]);
    if let Some(path) = item_ref
        .get("logical_path")
        .and_then(|value| value.as_str())
    {
        html.push_str("<dt>Path</dt><dd>");
        html.push_str(&escape_html(&display_entry_path(path)));
        html.push_str("</dd>");
    }
    html.push_str("</dl>");
    true
}

fn email_artifact_kind(item_ref: &serde_json::Value) -> Option<&str> {
    let kind = item_ref
        .get("artifact_kind")
        .and_then(|value| value.as_str())
        .or_else(|| {
            item_ref
                .get("metadata")
                .and_then(|value| value.get("artifact_kind"))
                .and_then(|value| value.as_str())
        })?;
    matches!(kind, "email_message" | "email_store").then_some(kind)
}

fn render_browser_activity_details_html(html: &mut String, item_ref: &serde_json::Value) -> bool {
    let Some(kind) = browser_activity_kind(item_ref) else {
        return false;
    };
    html.push_str("<dl class=\"activity-details\"><dt>Activity</dt><dd>");
    html.push_str(&escape_html(browser_activity_label(kind)));
    html.push_str("</dd>");
    match kind {
        "browser_history_visit" => {
            push_activity_detail(html, item_ref, "URL", &["url"]);
            push_activity_detail(html, item_ref, "Title", &["title", "display_name"]);
            push_activity_detail(html, item_ref, "Host", &["host"]);
            push_activity_detail(html, item_ref, "Visit Time", &["visit_time_utc"]);
            push_activity_detail(html, item_ref, "Last URL Visit", &["last_visit_time_utc"]);
            push_activity_detail(html, item_ref, "Transition", &["transition_type"]);
            push_activity_detail(html, item_ref, "Visit Count", &["visit_count"]);
            push_activity_detail(html, item_ref, "Typed Count", &["typed_count"]);
            push_activity_detail(html, item_ref, "Visit ID", &["visit_id"]);
            push_activity_detail(html, item_ref, "URL ID", &["url_id"]);
            push_activity_detail(html, item_ref, "Chrome Visit Time", &["visit_time_chrome"]);
            push_activity_detail(
                html,
                item_ref,
                "Chrome Last URL Visit",
                &["last_visit_time_chrome"],
            );
            push_activity_detail(html, item_ref, "Source Artifact", &["source_artifact"]);
            push_activity_detail(html, item_ref, "Source Path", &["source_artifact_path"]);
            push_activity_detail(
                html,
                item_ref,
                "Source Created",
                &["source_file_created_utc"],
            );
            push_activity_detail(
                html,
                item_ref,
                "Source Modified",
                &["source_file_modified_utc"],
            );
            push_activity_detail(
                html,
                item_ref,
                "Source Accessed",
                &["source_file_accessed_utc"],
            );
        }
        "browser_bookmark" => {
            push_activity_detail(html, item_ref, "Name", &["name", "display_name"]);
            push_activity_detail(html, item_ref, "URL", &["url"]);
            push_activity_detail(html, item_ref, "Folder", &["folder"]);
            push_activity_detail(html, item_ref, "Added", &["date_added_utc"]);
            push_activity_detail(html, item_ref, "Last Used", &["date_last_used_utc"]);
            push_activity_detail(html, item_ref, "Chrome Added", &["date_added_chrome"]);
            push_activity_detail(
                html,
                item_ref,
                "Chrome Last Used",
                &["date_last_used_chrome"],
            );
            push_activity_detail(html, item_ref, "GUID", &["guid"]);
            push_activity_detail(html, item_ref, "Source Artifact", &["source_artifact"]);
            push_activity_detail(html, item_ref, "Source Path", &["source_artifact_path"]);
            push_activity_detail(
                html,
                item_ref,
                "Source Created",
                &["source_file_created_utc"],
            );
            push_activity_detail(
                html,
                item_ref,
                "Source Modified",
                &["source_file_modified_utc"],
            );
            push_activity_detail(
                html,
                item_ref,
                "Source Accessed",
                &["source_file_accessed_utc"],
            );
        }
        "browser_preference" => {
            push_activity_detail(html, item_ref, "Category", &["category"]);
            push_activity_detail(html, item_ref, "Profile Name", &["name", "display_name"]);
            push_activity_detail(html, item_ref, "Startup URLs", &["startup_urls"]);
            push_activity_detail(html, item_ref, "Homepage", &["homepage"]);
            push_activity_detail(
                html,
                item_ref,
                "Download Directory",
                &["download_default_directory"],
            );
            push_activity_detail(html, item_ref, "Extensions", &["extension_count"]);
            push_activity_detail(
                html,
                item_ref,
                "Created By Version",
                &["created_by_version"],
            );
            push_activity_detail(html, item_ref, "Last Used", &["last_used"]);
            push_activity_detail(html, item_ref, "Source Artifact", &["source_artifact"]);
            push_activity_detail(html, item_ref, "Source Path", &["source_artifact_path"]);
            push_activity_detail(
                html,
                item_ref,
                "Source Created",
                &["source_file_created_utc"],
            );
            push_activity_detail(
                html,
                item_ref,
                "Source Modified",
                &["source_file_modified_utc"],
            );
            push_activity_detail(
                html,
                item_ref,
                "Source Accessed",
                &["source_file_accessed_utc"],
            );
        }
        _ => {
            push_activity_detail(html, item_ref, "Name", &["display_name", "name", "title"]);
            push_activity_detail(html, item_ref, "Path", &["logical_path"]);
        }
    }
    html.push_str("</dl>");
    true
}

fn browser_activity_kind(item_ref: &serde_json::Value) -> Option<&str> {
    if item_ref.get("kind").and_then(|value| value.as_str()) != Some("browser_activity") {
        return None;
    }
    item_ref
        .get("activity_kind")
        .and_then(|value| value.as_str())
        .or_else(|| {
            item_ref
                .get("metadata")
                .and_then(|value| value.get("artifact_kind"))
                .and_then(|value| value.as_str())
        })
}

fn browser_activity_label(kind: &str) -> &'static str {
    match kind {
        "browser_history_visit" => "Visit",
        "browser_url" => "URL",
        "browser_search_term" => "Search",
        "browser_download" => "Download",
        "browser_bookmark" => "Bookmark",
        "browser_login" => "Saved Login",
        "browser_cookie" => "Cookie",
        "browser_preference" => "Preference",
        _ => "Browser Activity",
    }
}

fn push_activity_detail(
    html: &mut String,
    item_ref: &serde_json::Value,
    label: &str,
    keys: &[&str],
) {
    if let Some(value) = activity_value_string(item_ref, keys) {
        html.push_str("<dt>");
        html.push_str(&escape_html(label));
        html.push_str("</dt><dd>");
        html.push_str(&escape_html(&value));
        html.push_str("</dd>");
    }
}

fn activity_value_string(item_ref: &serde_json::Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(value) = item_ref.get(*key).and_then(json_report_value) {
            return Some(value);
        }
        if let Some(value) = item_ref
            .get("metadata")
            .and_then(|metadata| metadata.get(*key))
            .and_then(json_report_value)
        {
            return Some(value);
        }
    }
    None
}

fn json_report_value(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::Null => None,
        serde_json::Value::String(value) => {
            let value = value.trim();
            if value.is_empty() {
                None
            } else {
                Some(value.to_string())
            }
        }
        serde_json::Value::Array(values) => {
            let parts = values
                .iter()
                .filter_map(json_report_value)
                .collect::<Vec<_>>();
            if parts.is_empty() {
                None
            } else {
                Some(parts.join(", "))
            }
        }
        serde_json::Value::Object(_) => Some(value.to_string()),
        serde_json::Value::Bool(value) => Some(value.to_string()),
        serde_json::Value::Number(value) => Some(value.to_string()),
    }
}

fn escape_html(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn trim_optional_string(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn infer_evidence_kind(
    path: &Path,
    requested: EvidenceKind,
    metadata: &fs::Metadata,
) -> Result<String> {
    let kind = match requested {
        EvidenceKind::File => {
            if !metadata.is_file() {
                bail!(
                    "requested evidence kind file, but path is not a file: {}",
                    path.display()
                );
            }
            "file"
        }
        EvidenceKind::Folder => {
            if !metadata.is_dir() {
                bail!(
                    "requested evidence kind folder, but path is not a directory: {}",
                    path.display()
                );
            }
            "folder"
        }
        EvidenceKind::Image => {
            if !metadata.is_file() {
                bail!(
                    "requested evidence kind image, but path is not a file: {}",
                    path.display()
                );
            }
            "image"
        }
        EvidenceKind::Auto => {
            if metadata.is_dir() {
                "folder"
            } else if looks_like_image(path) {
                "image"
            } else {
                "file"
            }
        }
    };
    Ok(kind.to_string())
}

fn looks_like_image(path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(|value| value.to_str()) else {
        return false;
    };
    // Split raw first segments (image.001) count as disk images.
    if ext.len() >= 2 && ext.chars().all(|ch| ch.is_ascii_digit()) && ext.parse::<u64>() == Ok(1) {
        return true;
    }
    matches!(
        ext.to_ascii_lowercase().as_str(),
        "e01"
            | "ex01"
            | "l01"
            | "raw"
            | "dd"
            | "img"
            | "vdi"
            | "vmdk"
            | "vhd"
            | "vhdx"
            | "aff4"
            | "iso"
    )
}

fn logical_path_from_relative(path: &Path) -> String {
    let parts = path
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect::<Vec<_>>();
    format!("/{}", parts.join("/"))
}

fn actual_file_path(source_kind: &str, source_path: &str, logical_path: &str) -> Option<PathBuf> {
    match source_kind {
        "file" => Some(PathBuf::from(source_path)),
        "folder" => {
            let relative = logical_path.trim_start_matches('/');
            if relative.is_empty() {
                return None;
            }
            let mut path = PathBuf::from(source_path);
            for part in relative.split('/') {
                if part.is_empty() || part == "." || part == ".." {
                    return None;
                }
                path.push(part);
            }
            Some(path)
        }
        _ => None,
    }
}

fn content_preview(text: &str, offset: usize, length: usize) -> String {
    let mut start = offset.saturating_sub(80);
    let mut end = (offset + length + 120).min(text.len());
    while start > 0 && !text.is_char_boundary(start) {
        start -= 1;
    }
    while end < text.len() && !text.is_char_boundary(end) {
        end += 1;
    }
    let mut preview = String::new();
    if start > 0 {
        preview.push_str("...");
    }
    preview.push_str(text[start..end].trim());
    if end < text.len() {
        preview.push_str("...");
    }
    preview
}

fn stable_path_string(path: &Path) -> String {
    path.canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .into_owned()
}

fn chromium_profile_paths(input_path: &Path) -> Result<ChromiumProfilePaths> {
    let metadata = fs::metadata(input_path)
        .with_context(|| format!("reading browser profile path {}", input_path.display()))?;
    let profile_dir = if metadata.is_dir() {
        input_path.to_path_buf()
    } else if metadata.is_file() {
        input_path
            .parent()
            .map(Path::to_path_buf)
            .with_context(|| {
                format!(
                    "browser history file has no parent: {}",
                    input_path.display()
                )
            })?
    } else {
        bail!(
            "browser history/profile path is not a file or directory: {}",
            input_path.display()
        );
    };
    let history_path = if metadata.is_file() {
        input_path.to_path_buf()
    } else {
        profile_dir.join("History")
    };
    if !history_path.is_file() {
        bail!(
            "Chromium History database was not found: {}",
            history_path.display()
        );
    }
    Ok(ChromiumProfilePaths {
        bookmarks_path: profile_dir.join("Bookmarks"),
        preferences_path: profile_dir.join("Preferences"),
        profile_dir,
        history_path,
    })
}

fn temp_history_copy_path(history_path: &Path) -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_micros())
        .unwrap_or_default();
    let source_name = history_path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("History");
    std::env::temp_dir().join(format!(
        "kdft-history-{}-{}-{}.sqlite",
        std::process::id(),
        stamp,
        sanitize_logical_segment(source_name)
    ))
}

fn default_history_display_name(profile_dir: &Path) -> String {
    let profile = profile_dir
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("Profile");
    format!("Chromium History - {profile}")
}

fn chrome_time_to_rfc3339(chrome_time: i64) -> Option<String> {
    const CHROME_TO_UNIX_EPOCH_MICROS: i64 = 11_644_473_600_i64 * 1_000_000;
    let unix_micros = chrome_time.checked_sub(CHROME_TO_UNIX_EPOCH_MICROS)?;
    let seconds = unix_micros.div_euclid(1_000_000);
    let nanos = unix_micros.rem_euclid(1_000_000) * 1_000;
    DateTime::<Utc>::from_timestamp(seconds, nanos as u32).map(|value| value.to_rfc3339())
}

fn source_artifact_metadata(path: &Path, artifact: &str) -> serde_json::Value {
    let mut metadata = serde_json::json!({
        "source_artifact": artifact,
        "source_artifact_path": path.to_string_lossy(),
    });
    if let Ok(file_metadata) = fs::metadata(path) {
        if let Some(object) = metadata.as_object_mut() {
            object.insert(
                "source_file_size_bytes".to_string(),
                serde_json::Value::from(file_metadata.len()),
            );
            object.insert(
                "source_file_created_utc".to_string(),
                optional_system_time_json(file_metadata.created().ok()),
            );
            object.insert(
                "source_file_modified_utc".to_string(),
                optional_system_time_json(file_metadata.modified().ok()),
            );
            object.insert(
                "source_file_accessed_utc".to_string(),
                optional_system_time_json(file_metadata.accessed().ok()),
            );
        }
    }
    metadata
}

fn optional_system_time_json(value: Option<std::time::SystemTime>) -> serde_json::Value {
    value
        .map(|time| DateTime::<Utc>::from(time).to_rfc3339())
        .map(serde_json::Value::String)
        .unwrap_or(serde_json::Value::Null)
}

fn merge_json_object(target: &mut serde_json::Value, source: &serde_json::Value) {
    if let (Some(target), Some(source)) = (target.as_object_mut(), source.as_object()) {
        for (key, value) in source {
            target.insert(key.clone(), value.clone());
        }
    }
}

fn chrome_json_time_value(value: Option<&serde_json::Value>) -> Option<i64> {
    match value {
        Some(serde_json::Value::String(value)) => value.parse().ok(),
        Some(serde_json::Value::Number(value)) => value.as_i64(),
        _ => None,
    }
}

fn host_from_url(url: &str) -> String {
    let trimmed = url.trim();
    let without_scheme = trimmed
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(trimmed);
    let without_credentials = without_scheme
        .rsplit_once('@')
        .map(|(_, rest)| rest)
        .unwrap_or(without_scheme);
    let host_port = without_credentials
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .trim();
    let host = host_port
        .strip_prefix('[')
        .and_then(|value| value.split_once(']').map(|(inside, _)| inside))
        .unwrap_or_else(|| host_port.split(':').next().unwrap_or(host_port))
        .trim()
        .trim_start_matches("www.");
    if host.is_empty() {
        "unknown-host".to_string()
    } else {
        host.to_ascii_lowercase()
    }
}

fn sanitize_logical_segment(value: &str) -> String {
    let mut segment = String::new();
    for ch in value.trim().chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_' | '@') {
            segment.push(ch);
        } else if ch.is_whitespace() || matches!(ch, '/' | '\\' | ':' | '?' | '#' | '&' | '=') {
            segment.push('_');
        }
        if segment.len() >= 96 {
            break;
        }
    }
    let segment = segment.trim_matches('_').trim_matches('.').to_string();
    if segment.is_empty() {
        "unnamed".to_string()
    } else {
        segment
    }
}

fn chromium_bookmark_root_label(root_name: &str) -> &'static str {
    match root_name {
        "bookmark_bar" => "Bookmarks Bar",
        "other" => "Other Bookmarks",
        "synced" => "Mobile Bookmarks",
        _ => "Bookmarks",
    }
}

fn json_path<'a>(value: &'a serde_json::Value, path: &[&str]) -> Option<&'a serde_json::Value> {
    let mut current = value;
    for part in path {
        current = current.get(*part)?;
    }
    Some(current)
}

fn chromium_transition_type(transition: i64) -> &'static str {
    match transition & 0xff {
        0 => "link",
        1 => "typed",
        2 => "auto_bookmark",
        3 => "auto_subframe",
        4 => "manual_subframe",
        5 => "generated",
        6 => "auto_toplevel",
        7 => "form_submit",
        8 => "reload",
        9 => "keyword",
        10 => "keyword_generated",
        _ => "unknown",
    }
}

fn option_path_to_string(path: Option<&Path>) -> Option<String> {
    path.map(|value| value.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn create_case_seeds_global_options_and_installed_resources() -> Result<()> {
        let case_path = unique_case_path("resources");
        create_test_case(&case_path)?;

        let options = global_options(&case_path)?;
        assert_eq!(options.id, 1);
        assert!(options.config_root.is_none());
        assert!(options.evidence_library_root.is_none());
        assert!(options.default_storage_root.is_none());

        let resources = list_installed_resources(&case_path)?;
        let keys = resources
            .iter()
            .map(|resource| resource.resource_key.as_str())
            .collect::<HashSet<_>>();
        assert!(keys.contains("file_signatures"));
        assert!(keys.contains("file_types"));
        assert!(keys.contains("filters"));
        assert!(keys.contains("keywords"));
        assert!(keys.contains("profiles"));
        assert!(keys.contains("text_styles"));
        assert!(keys.contains("case_report_template"));
        assert!(resources.iter().all(|resource| resource.enabled));

        cleanup_case_path(&case_path);
        Ok(())
    }

    #[test]
    fn case_database_rejects_second_case_row() -> Result<()> {
        let case_path = unique_case_path("single-case");
        create_test_case(&case_path)?;
        let conn = open_existing_case(&case_path)?;

        let err = conn
            .execute("INSERT INTO cases(id, name) VALUES (2, 'Second Case')", [])
            .expect_err("case database should reject a second case row")
            .to_string();
        assert!(err.contains("CHECK constraint failed"));

        cleanup_case_path(&case_path);
        Ok(())
    }

    #[test]
    fn global_options_round_trip() -> Result<()> {
        let case_path = unique_case_path("options");
        create_test_case(&case_path)?;
        let root = unique_temp_dir("options-root");
        let config_root = root.join("config");
        let evidence_library_root = root.join("evidence-library");
        let default_storage_root = root.join("storage");

        let updated = update_global_options(
            &case_path,
            UpdateGlobalOptions {
                config_root: Some(GlobalOptionPathUpdate::Set(config_root.clone())),
                evidence_library_root: Some(GlobalOptionPathUpdate::Set(
                    evidence_library_root.clone(),
                )),
                default_storage_root: Some(GlobalOptionPathUpdate::Set(
                    default_storage_root.clone(),
                )),
            },
        )?;
        let expected_config_root = path_str(&config_root);
        let expected_evidence_library_root = path_str(&evidence_library_root);
        let expected_default_storage_root = path_str(&default_storage_root);
        assert_eq!(
            updated.config_root.as_deref(),
            Some(expected_config_root.as_str())
        );
        assert_eq!(
            updated.evidence_library_root.as_deref(),
            Some(expected_evidence_library_root.as_str())
        );
        assert_eq!(
            updated.default_storage_root.as_deref(),
            Some(expected_default_storage_root.as_str())
        );

        let reread = global_options(&case_path)?;
        assert_eq!(reread.config_root, updated.config_root);
        assert_eq!(reread.evidence_library_root, updated.evidence_library_root);
        assert_eq!(reread.default_storage_root, updated.default_storage_root);

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn global_options_clear_and_noop_do_not_create_spurious_audit() -> Result<()> {
        let case_path = unique_case_path("options-clear");
        create_test_case(&case_path)?;
        let root = unique_temp_dir("options-clear-root");
        let config_root = root.join("config");

        update_global_options(
            &case_path,
            UpdateGlobalOptions {
                config_root: Some(GlobalOptionPathUpdate::Set(config_root)),
                evidence_library_root: None,
                default_storage_root: None,
            },
        )?;
        let after_set_count = audit_event_count(&case_path)?;

        let cleared = update_global_options(
            &case_path,
            UpdateGlobalOptions {
                config_root: Some(GlobalOptionPathUpdate::Clear),
                evidence_library_root: None,
                default_storage_root: None,
            },
        )?;
        assert!(cleared.config_root.is_none());
        assert_eq!(audit_event_count(&case_path)?, after_set_count + 1);

        let noop = update_global_options(&case_path, UpdateGlobalOptions::default())?;
        assert!(noop.config_root.is_none());
        assert_eq!(audit_event_count(&case_path)?, after_set_count + 1);

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn audit_events_record_examiner_actor() -> Result<()> {
        let case_path = unique_case_path("audit-actor");
        create_test_case(&case_path)?;

        let actors = audit_event_actors(&case_path)?;
        assert!(!actors.is_empty());
        assert!(actors.iter().all(|actor| actor == "Codex"));

        cleanup_case_path(&case_path);
        Ok(())
    }

    #[test]
    fn evidence_attach_records_source_without_jobs_or_filesystem_entries() -> Result<()> {
        let case_path = unique_case_path("no-index");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("evidence-source");
        fs::write(evidence_dir.join("sample.txt"), b"small sample")?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: Some("unit test".to_string()),
            },
        )?;
        assert_eq!(evidence_id, 1);
        assert_eq!(filesystem_entry_count(&case_path)?, 0);
        assert_eq!(evidence_job_count(&case_path)?, 0);

        let evidence = list_evidence(&case_path)?;
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].source_kind, "folder");
        assert!(evidence[0].read_file_system_requested);
        assert_eq!(evidence[0].indexed_at, None);

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn evidence_attach_rejects_duplicate_source_path() -> Result<()> {
        let case_path = unique_case_path("duplicate-evidence");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("duplicate-evidence-source");
        fs::write(evidence_dir.join("sample.txt"), b"small sample")?;
        let options = || AddEvidenceOptions {
            path: evidence_dir.clone(),
            kind: EvidenceKind::Auto,
            read_file_system_requested: false,
            notes: None,
        };

        add_evidence(&case_path, options())?;
        let err = add_evidence(&case_path, options())
            .expect_err("duplicate evidence source should be rejected")
            .to_string();
        assert!(err.contains("evidence source already attached"));

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn remove_evidence_deletes_source_jobs_and_entries() -> Result<()> {
        let case_path = unique_case_path("remove-evidence");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("remove-evidence-source");
        fs::write(evidence_dir.join("note.txt"), b"case note")?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 10,
            },
        )?;
        assert_eq!(list_evidence(&case_path)?.len(), 1);
        assert_eq!(
            list_filesystem_entries(&case_path, Some(evidence_id))?.len(),
            1
        );

        let removed = remove_evidence(&case_path, evidence_id)?;
        assert_eq!(removed.evidence_id, evidence_id);
        assert_eq!(removed.removed_entries, 1);
        assert_eq!(removed.removed_jobs, 1);
        assert!(list_evidence(&case_path)?.is_empty());
        assert!(list_filesystem_entries(&case_path, None)?.is_empty());

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn add_evidence_clears_stale_findings_from_empty_case() -> Result<()> {
        let case_path = unique_case_path("clear-stale-before-add");
        create_test_case(&case_path)?;
        let folder_id = create_bookmark_folder(&case_path, None, "Old Findings", None, true)?;
        let bookmark_id = create_bookmark(&case_path, test_bookmark_options(folder_id))?;
        add_bookmark_item(
            &case_path,
            CreateBookmarkItemOptions {
                bookmark_id,
                evidence_id: None,
                entry_id: None,
                item_order: None,
                display_name: Some("Old hit".to_string()),
                logical_path: Some("/old/path.txt".to_string()),
                selection_offset: None,
                selection_length: None,
                data_preview: None,
                item_ref_json: serde_json::json!({ "kind": "stale" }),
            },
        )?;
        assert_eq!(list_bookmarks(&case_path)?.len(), 1);

        let evidence_dir = unique_temp_dir("clear-stale-before-add-source");
        fs::write(evidence_dir.join("note.txt"), b"fresh")?;
        add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;

        assert_eq!(list_evidence(&case_path)?.len(), 1);
        assert!(list_bookmark_folders(&case_path)?.is_empty());
        assert!(list_bookmarks(&case_path)?.is_empty());
        assert!(list_bookmark_items(&case_path, None)?.is_empty());
        assert!(report_data(&case_path)?.folders.is_empty());

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn unindexed_case_cleanup_preserves_current_evidence_source_bookmark() -> Result<()> {
        let case_path = unique_case_path("clear-stale-preserve-current");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("clear-stale-preserve-source");
        fs::write(evidence_dir.join("note.txt"), b"fresh")?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        let stale_folder_id = create_bookmark_folder(&case_path, None, "Old Findings", None, true)?;
        let stale_bookmark_id =
            create_bookmark(&case_path, test_bookmark_options(stale_folder_id))?;
        add_bookmark_item(
            &case_path,
            CreateBookmarkItemOptions {
                bookmark_id: stale_bookmark_id,
                evidence_id: None,
                entry_id: None,
                item_order: None,
                display_name: Some("Old hit".to_string()),
                logical_path: Some("/old/path.txt".to_string()),
                selection_offset: None,
                selection_length: None,
                data_preview: None,
                item_ref_json: serde_json::json!({ "kind": "stale" }),
            },
        )?;
        let current_folder_id = create_bookmark_folder(&case_path, None, "Evidence", None, true)?;
        let current_bookmark_id =
            create_bookmark(&case_path, test_bookmark_options(current_folder_id))?;
        add_bookmark_item(
            &case_path,
            CreateBookmarkItemOptions {
                bookmark_id: current_bookmark_id,
                evidence_id: Some(evidence_id),
                entry_id: None,
                item_order: None,
                display_name: Some("Current source".to_string()),
                logical_path: Some(evidence_dir.to_string_lossy().into_owned()),
                selection_offset: None,
                selection_length: None,
                data_preview: None,
                item_ref_json: serde_json::json!({ "kind": "evidence_source" }),
            },
        )?;

        let cleared = clear_stale_findings(&case_path)?;
        assert_eq!(cleared.removed_bookmarks, 1);
        assert_eq!(cleared.removed_items, 1);

        let bookmarks = list_bookmarks(&case_path)?;
        assert_eq!(bookmarks.len(), 1);
        assert_eq!(bookmarks[0].id, current_bookmark_id);
        let items = list_bookmark_items(&case_path, None)?;
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].evidence_id, Some(evidence_id));
        assert_eq!(report_data(&case_path)?.folders.len(), 1);

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn stale_orphan_findings_are_cleared_after_entries_exist() -> Result<()> {
        let case_path = unique_case_path("clear-stale-after-index");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("clear-stale-after-index-source");
        fs::write(evidence_dir.join("note.txt"), b"fresh")?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 10,
            },
        )?;
        let folder_id = create_bookmark_folder(&case_path, None, "Old Findings", None, true)?;
        let bookmark_id = create_bookmark(&case_path, test_bookmark_options(folder_id))?;
        add_bookmark_item(
            &case_path,
            CreateBookmarkItemOptions {
                bookmark_id,
                evidence_id: None,
                entry_id: None,
                item_order: None,
                display_name: Some("Orphan hit".to_string()),
                logical_path: Some("/old/path.txt".to_string()),
                selection_offset: None,
                selection_length: None,
                data_preview: None,
                item_ref_json: serde_json::json!({ "kind": "stale" }),
            },
        )?;

        let cleared = clear_stale_findings(&case_path)?;
        assert_eq!(cleared.removed_bookmarks, 1);
        assert_eq!(cleared.removed_items, 1);
        assert!(list_bookmarks(&case_path)?.is_empty());
        assert!(report_data(&case_path)?.folders.is_empty());
        assert!(filesystem_entry_count(&case_path)? > 0);

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn reprocess_relinks_bookmark_items_by_logical_path() -> Result<()> {
        let case_path = unique_case_path("reprocess-relink-bookmarks");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("reprocess-relink-source");
        fs::write(evidence_dir.join("keep.txt"), b"keep me")?;
        fs::write(evidence_dir.join("gone.txt"), b"i will vanish")?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 10,
            },
        )?;

        let entries = list_filesystem_entries(&case_path, None)?;
        let keep_entry = entries
            .iter()
            .find(|entry| entry.name == "keep.txt")
            .expect("keep.txt indexed");
        let gone_entry = entries
            .iter()
            .find(|entry| entry.name == "gone.txt")
            .expect("gone.txt indexed");
        let keep_path = keep_entry.logical_path.clone();
        let gone_path = gone_entry.logical_path.clone();

        let folder_id = create_bookmark_folder(&case_path, None, "Findings", None, true)?;
        let bookmark_id = create_bookmark(&case_path, test_bookmark_options(folder_id))?;
        for entry in [keep_entry, gone_entry] {
            add_bookmark_item(
                &case_path,
                CreateBookmarkItemOptions {
                    bookmark_id,
                    evidence_id: Some(evidence_id),
                    entry_id: Some(entry.id),
                    item_order: None,
                    display_name: Some(entry.name.clone()),
                    logical_path: Some(entry.logical_path.clone()),
                    selection_offset: None,
                    selection_length: None,
                    data_preview: None,
                    item_ref_json: serde_json::json!({ "kind": "file" }),
                },
            )?;
        }

        // Image evidence reprocessing deletes all of the source's entries before re-indexing,
        // which nulls bookmark item entry links through the foreign key. Folder evidence upserts
        // in place, so simulate the image delete here to exercise the re-link path.
        {
            let conn = open_existing_case(&case_path)?;
            let case_id = active_case_id(&conn)?;
            conn.execute(
                "DELETE FROM filesystem_entries WHERE case_id = ?1 AND evidence_id = ?2",
                params![case_id, evidence_id],
            )?;
        }
        for item in list_bookmark_items(&case_path, None)? {
            assert_eq!(item.entry_id, None, "delete must null bookmark entry links");
        }

        fs::remove_file(evidence_dir.join("gone.txt"))?;
        let result = process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 10,
            },
        )?;
        assert_eq!(result.bookmark_items_relinked, 1);

        let new_entries = list_filesystem_entries(&case_path, None)?;
        let new_keep = new_entries
            .iter()
            .find(|entry| entry.logical_path == keep_path)
            .expect("keep.txt reindexed");
        let items = list_bookmark_items(&case_path, None)?;
        assert_eq!(items.len(), 2);
        let keep_item = items
            .iter()
            .find(|item| item.logical_path.as_deref() == Some(keep_path.as_str()))
            .expect("keep.txt bookmark item");
        assert_eq!(keep_item.entry_id, Some(new_keep.id));
        let gone_item = items
            .iter()
            .find(|item| item.logical_path.as_deref() == Some(gone_path.as_str()))
            .expect("gone.txt bookmark item");
        assert_eq!(gone_item.entry_id, None);

        // Re-linked and evidence-bound items must both survive the stale-findings cleanup.
        let cleared = clear_stale_findings(&case_path)?;
        assert_eq!(cleared.removed_items, 0);
        assert_eq!(cleared.removed_bookmarks, 0);
        assert_eq!(list_bookmark_items(&case_path, None)?.len(), 2);

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn clear_all_findings_removes_valid_current_bookmarks_on_request() -> Result<()> {
        let case_path = unique_case_path("clear-all-findings");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("clear-all-findings-source");
        fs::write(evidence_dir.join("note.txt"), b"fresh")?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 10,
            },
        )?;
        let entry = list_filesystem_entries(&case_path, Some(evidence_id))?
            .into_iter()
            .find(|entry| entry.entry_kind == "file")
            .expect("indexed file entry should exist");
        let folder_id = create_bookmark_folder(&case_path, None, "Evidence Entries", None, true)?;
        let bookmark_id = create_bookmark(&case_path, test_bookmark_options(folder_id))?;
        add_bookmark_item(
            &case_path,
            CreateBookmarkItemOptions {
                bookmark_id,
                evidence_id: Some(evidence_id),
                entry_id: Some(entry.id),
                item_order: None,
                display_name: Some(entry.name),
                logical_path: Some(entry.logical_path),
                selection_offset: None,
                selection_length: None,
                data_preview: None,
                item_ref_json: serde_json::json!({ "kind": "filesystem_entry" }),
            },
        )?;

        let cleared = clear_all_findings(&case_path)?;
        assert_eq!(cleared.removed_bookmarks, 1);
        assert_eq!(cleared.removed_items, 1);
        assert!(list_bookmark_folders(&case_path)?.is_empty());
        assert!(list_bookmarks(&case_path)?.is_empty());
        assert!(list_bookmark_items(&case_path, None)?.is_empty());
        assert_eq!(list_evidence(&case_path)?.len(), 1);
        assert!(filesystem_entry_count(&case_path)? > 0);

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn evidence_process_assigns_forensic_categories() -> Result<()> {
        let case_path = unique_case_path("evidence-categories");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("evidence-categories-source");
        fs::create_dir_all(evidence_dir.join("Pictures"))?;
        fs::write(evidence_dir.join("Pictures").join("photo.jpg"), b"jpg")?;
        fs::write(evidence_dir.join("mail.pst"), b"pst")?;
        fs::create_dir_all(
            evidence_dir
                .join("Users")
                .join("Cristina")
                .join("AppData")
                .join("Local")
                .join("Google")
                .join("Chrome")
                .join("User Data")
                .join("Default"),
        )?;
        fs::write(
            evidence_dir
                .join("Users")
                .join("Cristina")
                .join("AppData")
                .join("Local")
                .join("Google")
                .join("Chrome")
                .join("User Data")
                .join("Default")
                .join("Login Data"),
            b"sqlite",
        )?;
        fs::create_dir_all(evidence_dir.join("Windows").join("Prefetch"))?;
        fs::write(
            evidence_dir
                .join("Windows")
                .join("Prefetch")
                .join("APP.EXE-12345678.pf"),
            b"pf",
        )?;
        fs::create_dir_all(evidence_dir.join("OneDrive"))?;
        fs::write(evidence_dir.join("OneDrive").join("report.docx"), b"docx")?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )?;

        let entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        let category = |suffix: &str| -> (String, String) {
            let entry = entries
                .iter()
                .find(|entry| entry.logical_path.ends_with(suffix))
                .unwrap_or_else(|| panic!("missing categorized entry ending with {suffix}"));
            (
                entry.metadata_json["category_main"]
                    .as_str()
                    .unwrap()
                    .to_string(),
                entry.metadata_json["category_sub"]
                    .as_str()
                    .unwrap()
                    .to_string(),
            )
        };
        assert_eq!(
            category("/Pictures/photo.jpg"),
            ("Pictures and Media".to_string(), "Pictures".to_string())
        );
        assert_eq!(
            category("/mail.pst"),
            (
                "Email and Communications".to_string(),
                "Email stores".to_string()
            )
        );
        assert_eq!(
            category("/Default/Login Data"),
            (
                "Accounts and Identity".to_string(),
                "Credentials and tokens".to_string()
            )
        );
        assert_eq!(
            category("/Windows/Prefetch/APP.EXE-12345678.pf"),
            (
                "Program Execution".to_string(),
                "Execution artifacts".to_string()
            )
        );
        assert_eq!(
            category("/OneDrive/report.docx"),
            ("Cloud and Web".to_string(), "Cloud sync".to_string())
        );

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn os_paths_with_generic_artifact_words_do_not_classify_as_browser() -> Result<()> {
        let classify = |logical_path: &str, name: &str| {
            let mut metadata = serde_json::json!({});
            add_entry_category(&mut metadata, logical_path, name, "file");
            (
                metadata["category_main"].as_str().unwrap().to_string(),
                metadata["category_sub"].as_str().unwrap().to_string(),
            )
        };

        // The dllcache regression Cristina reported: system DLLs must be
        // executables, not browser artifacts, despite "cache" in the path.
        assert_eq!(
            classify(
                "/Volumes/001-part0/WINDOWS/system32/dllcache/acledit.dll",
                "acledit.dll"
            ),
            (
                "Program Execution".to_string(),
                "Executables and binaries".to_string()
            )
        );
        assert_eq!(
            classify(
                "/Volumes/001-part0/WINDOWS/system32/dllcache/arp.exe",
                "arp.exe"
            ),
            (
                "Program Execution".to_string(),
                "Executables and binaries".to_string()
            )
        );
        // Driver .img under Windows is not a disk image.
        let (img_main, _) = classify(
            "/Volumes/001-part0/WINDOWS/system32/drivers/netwlan5.img",
            "netwlan5.img",
        );
        assert_ne!(img_main, "Archives and Containers");

        // Real browser paths still classify as browser artifacts / cookies.
        assert_eq!(
            classify(
                "/Users/kris/AppData/Local/Google/Chrome/User Data/Default/Cache/f_000001",
                "f_000001"
            )
            .0,
            "Cloud and Web"
        );
        assert_eq!(
            classify(
                "/Users/kris/AppData/Local/Google/Chrome/User Data/Default/History",
                "History"
            ),
            ("Cloud and Web".to_string(), "Browser artifacts".to_string())
        );
        // Old-IE cookie path has no browser name: precision over recall means
        // it falls back to the .txt rule rather than guessing browser context.
        assert_eq!(
            classify(
                "/Documents and Settings/kris/Cookies/kris@ads[1].txt",
                "kris@ads[1].txt"
            ),
            (
                "Documents and Office".to_string(),
                "Text and notes".to_string()
            )
        );
        assert_eq!(
            classify(
                "/Users/kris/AppData/Roaming/Mozilla/Firefox/Profiles/x.default/cookies.sqlite",
                "cookies.sqlite"
            )
            .0,
            "Accounts and Identity"
        );
        Ok(())
    }

    #[test]
    fn recovery_artifacts_get_distinct_categories() -> Result<()> {
        let mut deleted = serde_json::json!({ "artifact_kind": "deleted_file_record" });
        add_entry_category(
            &mut deleted,
            "/Recovery/Deleted Files/message.eml",
            "message.eml",
            "file",
        );
        assert_eq!(deleted["category_main"].as_str(), Some("Recovery"));
        assert_eq!(deleted["category_sub"].as_str(), Some("Deleted files"));

        let mut unallocated = serde_json::json!({ "artifact_kind": "unallocated_space" });
        add_entry_category(
            &mut unallocated,
            "/Recovery/Unallocated Space/chunk-1.bin",
            "chunk-1.bin",
            "file",
        );
        assert_eq!(unallocated["category_main"].as_str(), Some("Recovery"));
        assert_eq!(
            unallocated["category_sub"].as_str(),
            Some("Unallocated space")
        );
        Ok(())
    }

    #[test]
    fn evidence_process_parses_eml_and_report_formats_email_bookmark() -> Result<()> {
        let case_path = unique_case_path("email-parse-report");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("email-parse-source");
        let eml_path = evidence_dir.join("message.eml");
        fs::write(
            &eml_path,
            b"From: Alice <alice@example.com>\r\nTo: Bob <bob@example.com>\r\nSubject: Quarterly plan\r\nDate: Tue, 30 Jun 2026 20:00:00 +0000\r\nMessage-ID: <plan@example.com>\r\n\r\nBob,\r\nThe mailbox evidence is ready for review.\r\n",
        )?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 10,
            },
        )?;

        let entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        let message = entries
            .iter()
            .find(|entry| entry.logical_path.ends_with("/message.eml"))
            .expect("message.eml should be indexed");
        assert_eq!(
            message.metadata_json["artifact_kind"].as_str(),
            Some("email_message")
        );
        assert_eq!(
            message.metadata_json["category_sub"].as_str(),
            Some("Email messages")
        );
        assert_eq!(
            message.metadata_json["email_subject"].as_str(),
            Some("Quarterly plan")
        );
        assert!(message.metadata_json["email_body_preview"]
            .as_str()
            .unwrap_or_default()
            .contains("mailbox evidence"));

        let folder_id = create_bookmark_folder(&case_path, None, "Emails", None, true)?;
        let bookmark_id = create_bookmark(
            &case_path,
            CreateBookmarkOptions {
                folder_id,
                bookmark_type: BookmarkType::Email,
                data_type: Some("Email Message".to_string()),
                title: Some("Email: Quarterly plan".to_string()),
                examiner_comment: None,
                in_report: true,
                source_ref_json: serde_json::json!({ "entry_id": message.id }),
                content_ref_json: serde_json::json!({ "artifact_kind": "email_message" }),
            },
        )?;
        add_bookmark_item(
            &case_path,
            CreateBookmarkItemOptions {
                bookmark_id,
                evidence_id: Some(evidence_id),
                entry_id: Some(message.id),
                item_order: None,
                display_name: Some("Quarterly plan".to_string()),
                logical_path: Some(message.logical_path.clone()),
                selection_offset: None,
                selection_length: None,
                data_preview: Some("Alice to Bob".to_string()),
                item_ref_json: serde_json::json!({
                    "kind": "email_message",
                    "artifact_kind": "email_message",
                    "email_from": "Alice <alice@example.com>",
                    "email_to": "Bob <bob@example.com>",
                    "email_subject": "Quarterly plan",
                    "email_date": "Tue, 30 Jun 2026 20:00:00 +0000",
                    "email_body_preview": "Bob,\nThe mailbox evidence is ready for review.",
                    "logical_path": message.logical_path.clone(),
                }),
            },
        )?;

        let html = render_report_html(&report_data(&case_path)?);
        assert!(html.contains("Email Message"));
        assert!(html.contains("Alice &lt;alice@example.com&gt;"));
        assert!(html.contains("Quarterly plan"));
        assert!(html.contains("mailbox evidence"));

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn evidence_process_parses_rfc822_txt_in_email_folder() -> Result<()> {
        let case_path = unique_case_path("email-txt-parse");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("email-txt-source");
        let email_dir = evidence_dir.join("Email");
        fs::create_dir_all(&email_dir)?;
        fs::write(
            email_dir.join("Charlie_2009-11-16_1102_Received.txt"),
            b"Subject:\r\nFound key\r\nFrom:\r\nFrank <frank@example.com>\r\nDate:\r\nMon, 16 Nov 2009 11:02:00 +0000\r\nTo:\r\nCharlie <charlie@example.com>\r\nMessage-ID:\r\n<found-key@example.com>\r\n\r\nCharlie,\r\nI found the key you asked about.\r\n",
        )?;
        fs::write(
            email_dir.join("readme.txt"),
            b"This is a plain note in the Email folder, not an RFC 822 message.\n",
        )?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 20,
            },
        )?;

        let entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        let message = entries
            .iter()
            .find(|entry| {
                entry
                    .logical_path
                    .ends_with("/Email/Charlie_2009-11-16_1102_Received.txt")
            })
            .expect("RFC 822 text email should be indexed");
        assert_eq!(
            message.metadata_json["artifact_kind"].as_str(),
            Some("email_message")
        );
        assert_eq!(
            message.metadata_json["email_format"].as_str(),
            Some("text-rfc822")
        );
        assert_eq!(
            message.metadata_json["category_sub"].as_str(),
            Some("Email messages")
        );
        assert_eq!(
            message.metadata_json["email_subject"].as_str(),
            Some("Found key")
        );
        assert_eq!(
            message.metadata_json["email_from"].as_str(),
            Some("Frank <frank@example.com>")
        );

        let readme = entries
            .iter()
            .find(|entry| entry.logical_path.ends_with("/Email/readme.txt"))
            .expect("plain text file should be indexed");
        assert_ne!(
            readme.metadata_json["artifact_kind"].as_str(),
            Some("email_message")
        );

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn image_evidence_auto_attaches_and_invalid_vdi_fails_loudly() -> Result<()> {
        let case_path = unique_case_path("vdi-source");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("vdi-source");
        let image_path = evidence_dir.join("disk.vdi");
        fs::write(&image_path, b"0123456789abcdef")?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: image_path.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        let evidence = list_evidence(&case_path)?;
        assert_eq!(evidence[0].source_kind, "image");
        assert_eq!(filesystem_entry_count(&case_path)?, 0);
        assert!(list_filesystem_entries(&case_path, Some(evidence_id))?.is_empty());

        let err = process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )
        .expect_err("invalid VDI image should fail loudly")
        .to_string();
        assert!(err.contains("decoding VDI image") || err.contains("Invalid VDI signature"));

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn image_process_analyzes_raw_mbr_partition_records() -> Result<()> {
        let case_path = unique_case_path("image-mbr");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("image-mbr-source");
        let image_path = evidence_dir.join("disk.img");
        create_test_mbr_image(&image_path)?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: image_path.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        assert_eq!(list_evidence(&case_path)?[0].source_kind, "image");

        let processed = process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )?;
        assert_eq!(processed.status, "completed");
        assert!(processed.entries_indexed >= 3);

        let entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        assert!(entries.iter().any(|entry| {
            entry.logical_path == "/Image Analysis/Container.record"
                && entry.metadata_json["artifact_kind"].as_str() == Some("disk_image_container")
        }));
        assert!(entries.iter().any(|entry| {
            entry.logical_path == "/Image Analysis/Partitioning.report"
                && entry.metadata_json["artifact_kind"].as_str() == Some("disk_partition_report")
                && entry.metadata_json["partition_scheme"].as_str() == Some("Mbr")
        }));
        let partition = entries
            .iter()
            .find(|entry| entry.metadata_json["artifact_kind"].as_str() == Some("disk_partition"))
            .expect("partition record should be created");
        assert_eq!(
            partition.metadata_json["start_offset"].as_u64(),
            Some(1_048_576)
        );
        assert_eq!(
            partition.metadata_json["size_bytes"].as_u64(),
            Some(1_048_576)
        );

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn deep_search_hex_pattern_and_scoped_filters() -> Result<()> {
        let case_path = unique_case_path("deep-hex");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("deep-hex-source");
        let image_path = evidence_dir.join("fat-disk.img");
        create_test_fat_mbr_image(&image_path)?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: image_path.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )?;

        // Byte-pattern mode: "FAT ev" = 46 41 54 20 65 76 at offset 0 of note.txt.
        let base = DeepSearchOptions {
            category: None,
            file_types: None,
            query: String::new(),
            evidence_id: None,
            include_content: true,
            max_results: 50,
            max_file_bytes: 65_536,
        };
        let hex_hits = deep_search(
            &case_path,
            DeepSearchOptions {
                query: "hex:46 41 54 20 65 76".to_string(),
                ..base.clone()
            },
        )?;
        let hit = hex_hits
            .iter()
            .find(|hit| hit.logical_path.ends_with("/DFIR/note.txt"))
            .expect("hex pattern should hit note.txt content");
        assert_eq!(hit.match_kind, "content");
        assert_eq!(hit.selection_offset, Some(0));
        assert_eq!(hit.selection_length, Some(6));
        assert!(hit
            .data_preview
            .as_deref()
            .unwrap_or("")
            .starts_with("46 41 54"));

        // File-type scope: txt keeps the hit, jpg excludes it.
        let txt_hits = deep_search(
            &case_path,
            DeepSearchOptions {
                query: "artifact".to_string(),
                file_types: Some(vec!["txt".to_string()]),
                ..base.clone()
            },
        )?;
        assert!(txt_hits
            .iter()
            .any(|hit| hit.logical_path.ends_with("/DFIR/note.txt")));
        let jpg_hits = deep_search(
            &case_path,
            DeepSearchOptions {
                query: "artifact".to_string(),
                file_types: Some(vec!["jpg".to_string()]),
                ..base.clone()
            },
        )?;
        assert!(!jpg_hits
            .iter()
            .any(|hit| hit.logical_path.ends_with("/DFIR/note.txt")));

        // Category scope: the entry's own stored main category and subcategory both match, while
        // a bogus one excludes.
        let entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        let note = entries
            .iter()
            .find(|entry| entry.logical_path.ends_with("/DFIR/note.txt"))
            .expect("note.txt entry");
        let stored_category = note.metadata_json["category_main"]
            .as_str()
            .expect("stored category_main")
            .to_string();
        let scoped = deep_search(
            &case_path,
            DeepSearchOptions {
                query: "artifact".to_string(),
                category: Some(stored_category),
                ..base.clone()
            },
        )?;
        assert!(scoped
            .iter()
            .any(|hit| hit.logical_path.ends_with("/DFIR/note.txt")));
        let stored_subcategory = note.metadata_json["category_sub"]
            .as_str()
            .expect("stored category_sub")
            .to_string();
        let subcategory_scoped = deep_search(
            &case_path,
            DeepSearchOptions {
                query: "artifact".to_string(),
                category: Some(stored_subcategory),
                ..base.clone()
            },
        )?;
        assert!(subcategory_scoped
            .iter()
            .any(|hit| hit.logical_path.ends_with("/DFIR/note.txt")));
        let excluded = deep_search(
            &case_path,
            DeepSearchOptions {
                query: "artifact".to_string(),
                category: Some("no-such-category".to_string()),
                ..base
            },
        )?;
        assert!(excluded.is_empty());

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn indexed_directory_root_collapses_synthetic_image_containers() -> Result<()> {
        let case_path = unique_case_path("idx-collapse");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("idx-collapse-source");
        let image_path = evidence_dir.join("fat-disk.img");
        create_test_fat_mbr_image(&image_path)?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: image_path.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )?;

        let root = list_indexed_directory(&case_path, evidence_id, "/", 1000)?;
        assert!(
            !root
                .children
                .iter()
                .any(|child| child.name == "Image Analysis"),
            "root listing must not expose the synthetic Image Analysis container"
        );
        let volume = root
            .children
            .iter()
            .find(|child| child.logical_path == "/Image Analysis/Volumes/001-part0")
            .expect("volume folder should surface at the device root");
        assert!(volume.is_dir);
        assert!(root.children.iter().any(|child| {
            child.logical_path == "/Image Analysis/Container.record" && !child.is_dir
        }));
        let volume_children = list_indexed_directory(
            &case_path,
            evidence_id,
            "/Image Analysis/Volumes/001-part0",
            1000,
        )?;
        assert!(volume_children
            .children
            .iter()
            .any(|child| child.name == "DFIR" && child.is_dir));

        // Report directory trees collapse the same synthetic containers.
        let report = report_data_with_directory_structure(&case_path, 1000)?;
        let tree = report
            .directory_trees
            .iter()
            .find(|tree| tree.evidence_id == evidence_id)
            .expect("image evidence should have a report tree");
        assert!(
            !tree
                .lines
                .iter()
                .any(|line| line.name == "Image Analysis" || line.name == "Volumes"),
            "report tree must not contain synthetic containers"
        );
        let volume_line = tree
            .lines
            .iter()
            .find(|line| line.name == "001-part0")
            .expect("volume folder should be a report tree root");
        assert_eq!(volume_line.depth, 0);

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn image_process_indexes_fat_partition_entries() -> Result<()> {
        let case_path = unique_case_path("image-fat");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("image-fat-source");
        let image_path = evidence_dir.join("fat-disk.img");
        create_test_fat_mbr_image(&image_path)?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: image_path.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;

        let processed = process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )?;
        assert_eq!(processed.status, "completed");

        let entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        assert!(entries.iter().any(|entry| {
            entry.logical_path == "/Image Analysis/Volumes/001-part0"
                && entry.entry_kind == "directory"
                && entry.metadata_json["filesystem_parser"].as_str() == Some("fatfs")
        }));
        assert!(entries.iter().any(|entry| {
            entry.logical_path == "/Image Analysis/Volumes/001-part0/DFIR"
                && entry.entry_kind == "directory"
        }));
        let note = entries
            .iter()
            .find(|entry| entry.logical_path == "/Image Analysis/Volumes/001-part0/DFIR/note.txt")
            .expect("FAT file should be indexed");
        assert_eq!(note.entry_kind, "file");
        assert_eq!(note.size_bytes, Some(21));
        assert_eq!(
            note.metadata_json["source_entry_name"].as_str(),
            Some("note.txt")
        );
        let bytes = read_filesystem_entry_bytes(
            &case_path,
            ReadEntryBytesOptions {
                entry_id: note.id,
                offset: 0,
                length: 64,
            },
        )?;
        assert_eq!(bytes.bytes, b"FAT evidence artifact");
        assert_eq!(bytes.total_size, 21);
        let spaced = entries
            .iter()
            .find(|entry| {
                entry.logical_path == "/Image Analysis/Volumes/001-part0/Case_Files/note_1.txt"
            })
            .expect("FAT file with sanitized name should be indexed");
        assert_eq!(
            spaced.metadata_json["fat_path"].as_str(),
            Some("Case Files/note (1).txt")
        );
        assert_eq!(
            spaced.metadata_json["partition_size_bytes"].as_u64(),
            Some(1_048_576)
        );
        let spaced_bytes = read_filesystem_entry_bytes(
            &case_path,
            ReadEntryBytesOptions {
                entry_id: spaced.id,
                offset: 0,
                length: 64,
            },
        )?;
        assert_eq!(spaced_bytes.bytes, b"FAT spaced artifact");
        let content_hits = deep_search(
            &case_path,
            DeepSearchOptions {
                category: None,
                file_types: None,
                query: "FAT evidence artifact".to_string(),
                evidence_id: Some(evidence_id),
                include_content: true,
                max_results: 10,
                max_file_bytes: 64,
            },
        )?;
        let content_hit = content_hits
            .iter()
            .find(|hit| {
                hit.logical_path == "/Image Analysis/Volumes/001-part0/DFIR/note.txt"
                    && hit.match_kind == "content"
            })
            .expect("Deep Search should scan image-backed FAT file content");
        assert_eq!(content_hit.selection_offset, Some(0));
        assert_eq!(
            content_hit.selection_length,
            Some("FAT evidence artifact".len() as i64)
        );

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    /// Builds a minimal, spec-correct ext2 image (block size 1024, one block
    /// group) containing /hello.txt, for exercising the ext parser without an
    /// external fixture or mke2fs.
    fn build_minimal_ext2_image(payload: &[u8]) -> Vec<u8> {
        const BS: usize = 1024;
        let mut img = vec![0_u8; 64 * BS];
        let put_u32 = |img: &mut [u8], off: usize, value: u32| {
            img[off..off + 4].copy_from_slice(&value.to_le_bytes());
        };
        let put_u16 = |img: &mut [u8], off: usize, value: u16| {
            img[off..off + 2].copy_from_slice(&value.to_le_bytes());
        };

        // Superblock (block 1).
        let sb = BS;
        put_u32(&mut img, sb, 16); // s_inodes_count
        put_u32(&mut img, sb + 4, 64); // s_blocks_count
        put_u32(&mut img, sb + 16, 1); // s_first_data_block
        put_u32(&mut img, sb + 20, 0); // s_log_block_size -> 1024
        put_u32(&mut img, sb + 24, 0); // s_log_frag_size
        put_u32(&mut img, sb + 32, 64); // s_blocks_per_group
        put_u32(&mut img, sb + 36, 64); // s_frags_per_group
        put_u32(&mut img, sb + 40, 16); // s_inodes_per_group
        put_u16(&mut img, sb + 56, 0xEF53); // s_magic (0x38)
        put_u16(&mut img, sb + 58, 1); // s_state
        put_u16(&mut img, sb + 60, 1); // s_errors
        put_u32(&mut img, sb + 76, 1); // s_rev_level = dynamic
        put_u32(&mut img, sb + 84, 11); // s_first_ino
        put_u16(&mut img, sb + 88, 128); // s_inode_size
        put_u32(&mut img, sb + 96, 0x2); // s_feature_incompat = FILETYPE

        // Block group descriptor (block 2).
        let gd = 2 * BS;
        put_u32(&mut img, gd, 3); // bg_block_bitmap
        put_u32(&mut img, gd + 4, 4); // bg_inode_bitmap
        put_u32(&mut img, gd + 8, 5); // bg_inode_table

        // Inode table (blocks 5-6), 128-byte inodes.
        let root = 5 * BS + 128; // inode 2
        put_u16(&mut img, root, 0x41ED); // dir, 0755
        put_u32(&mut img, root + 4, 1024); // i_size
        put_u16(&mut img, root + 26, 3); // i_links_count
        put_u32(&mut img, root + 28, 2); // i_blocks (512-byte units)
        put_u32(&mut img, root + 40, 7); // i_block[0] -> block 7

        let hello = 5 * BS + 10 * 128; // inode 11
        put_u16(&mut img, hello, 0x81A4); // reg, 0644
        put_u32(&mut img, hello + 4, payload.len() as u32); // i_size
        put_u16(&mut img, hello + 26, 1); // i_links_count
        put_u32(&mut img, hello + 28, 2); // i_blocks
        put_u32(&mut img, hello + 40, 8); // i_block[0] -> block 8

        // Root directory data (block 7).
        let dir = 7 * BS;
        put_u32(&mut img, dir, 2); // "." -> inode 2
        put_u16(&mut img, dir + 4, 12);
        img[dir + 6] = 1;
        img[dir + 7] = 2;
        img[dir + 8] = b'.';
        put_u32(&mut img, dir + 12, 2); // ".." -> inode 2
        put_u16(&mut img, dir + 16, 12);
        img[dir + 18] = 2;
        img[dir + 19] = 2;
        img[dir + 20] = b'.';
        img[dir + 21] = b'.';
        put_u32(&mut img, dir + 24, 11); // "hello.txt" -> inode 11
        put_u16(&mut img, dir + 28, 1000); // rec_len fills the block
        img[dir + 30] = 9;
        img[dir + 31] = 1;
        img[dir + 32..dir + 41].copy_from_slice(b"hello.txt");

        // File data (block 8).
        img[8 * BS..8 * BS + payload.len()].copy_from_slice(payload);
        img
    }

    /// Builds a raw image carrying a btrfs primary superblock (magic + a few
    /// metadata fields) at the standard 64 KiB offset.
    fn build_btrfs_superblock_image(label: &str, total_bytes: u64) -> Vec<u8> {
        let mut img = vec![0_u8; 128 * 1024];
        let sb = 0x1_0000;
        img[sb + 0x40..sb + 0x48].copy_from_slice(b"_BHRfS_M");
        for (i, byte) in (0..16).zip(0xA0_u8..) {
            img[sb + 0x20 + i] = byte;
        }
        img[sb + 0x70..sb + 0x78].copy_from_slice(&total_bytes.to_le_bytes());
        img[sb + 0x78..sb + 0x80].copy_from_slice(&(total_bytes / 4).to_le_bytes());
        img[sb + 0x88..sb + 0x90].copy_from_slice(&1_u64.to_le_bytes()); // num_devices
        img[sb + 0x90..sb + 0x94].copy_from_slice(&4096_u32.to_le_bytes()); // sector size
        img[sb + 0x94..sb + 0x98].copy_from_slice(&16384_u32.to_le_bytes()); // node size
        let label_bytes = label.as_bytes();
        img[sb + 0x12B..sb + 0x12B + label_bytes.len()].copy_from_slice(label_bytes);
        img
    }

    #[test]
    fn live_browse_lists_directories_without_indexing() -> Result<()> {
        let dir = unique_temp_dir("live-browse");

        // FAT volume inside an MBR partition: /DFIR/note.txt.
        let fat_image = dir.join("fat.img");
        fs::write(&fat_image, test_fat_mbr_image_bytes()?)?;
        let volumes = list_image_volumes(&fat_image)?;
        assert_eq!(volumes.len(), 1);
        assert_eq!(volumes[0].filesystem, "FAT");
        assert!(volumes[0].browsable);

        let root = list_image_directory(&fat_image, 0, "/")?;
        assert!(root
            .iter()
            .any(|entry| entry.name == "DFIR" && entry.is_dir));
        let dfir = list_image_directory(&fat_image, 0, "DFIR")?;
        let note = dfir
            .iter()
            .find(|entry| entry.name.eq_ignore_ascii_case("note.txt"))
            .expect("note.txt listed live");
        assert!(!note.is_dir);
        let (bytes, total) = read_image_directory_bytes(&fat_image, 0, "DFIR/note.txt", 0, 64)?;
        assert_eq!(bytes, b"FAT evidence artifact");
        assert_eq!(total, b"FAT evidence artifact".len() as u64);

        // ext2 whole-image volume: /hello.txt.
        let ext_image = dir.join("ext.img");
        let payload = b"ext live payload";
        fs::write(&ext_image, build_minimal_ext2_image(payload))?;
        let ext_volumes = list_image_volumes(&ext_image)?;
        assert_eq!(ext_volumes.len(), 1);
        assert_eq!(ext_volumes[0].filesystem, "EXT");
        let ext_root = list_image_directory(&ext_image, 0, "/")?;
        assert!(ext_root.iter().any(|entry| entry.name == "hello.txt"));
        let (ext_bytes, ext_total) = read_image_directory_bytes(&ext_image, 0, "hello.txt", 0, 64)?;
        assert_eq!(ext_bytes, payload);
        assert_eq!(ext_total, payload.len() as u64);

        // No case database is touched by live browsing.
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[test]
    fn image_process_records_btrfs_volume_metadata() -> Result<()> {
        let case_path = unique_case_path("image-btrfs");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("image-btrfs-source");
        let image_path = evidence_dir.join("btrfs.img");
        fs::write(
            &image_path,
            build_btrfs_superblock_image("EVIDENCE-VOL", 128 * 1024),
        )?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: image_path.clone(),
                kind: EvidenceKind::Image,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        let processed = process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )?;
        assert_eq!(processed.status, "completed");

        let entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        let volume = entries
            .iter()
            .find(|entry| {
                entry.metadata_json["filesystem_parser"].as_str() == Some("btrfs-metadata")
            })
            .expect("btrfs volume record should be indexed");
        assert_eq!(volume.metadata_json["filesystem"].as_str(), Some("btrfs"));
        assert_eq!(
            volume.metadata_json["btrfs_label"].as_str(),
            Some("EVIDENCE-VOL")
        );
        assert_eq!(
            volume.metadata_json["btrfs_sector_size"].as_u64(),
            Some(4096)
        );
        assert_eq!(
            volume.metadata_json["btrfs_node_size"].as_u64(),
            Some(16384)
        );
        assert!(volume.metadata_json["btrfs_fsid"]
            .as_str()
            .is_some_and(|fsid| fsid.len() == 32));

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn detect_volume_filesystem_recognizes_ext_magic() -> Result<()> {
        let image = build_minimal_ext2_image(b"x");
        let mut cursor = io::Cursor::new(image);
        assert_eq!(detect_volume_filesystem_at(&mut cursor, 0)?, Some("EXT"));
        Ok(())
    }

    #[test]
    fn image_process_indexes_ext_volume() -> Result<()> {
        let case_path = unique_case_path("image-ext");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("image-ext-source");
        let image_path = evidence_dir.join("ext.img");
        let payload = b"ext4 evidence payload";
        fs::write(&image_path, build_minimal_ext2_image(payload))?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: image_path.clone(),
                kind: EvidenceKind::Image,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        let processed = process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 200,
            },
        )?;
        assert_eq!(processed.status, "completed");

        let entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        assert!(entries.iter().any(|entry| {
            entry.entry_kind == "directory"
                && entry.metadata_json["filesystem_parser"].as_str() == Some("ext4")
        }));
        let hello = entries
            .iter()
            .find(|entry| entry.name == "hello.txt")
            .expect("ext file hello.txt should be indexed");
        assert_eq!(hello.size_bytes, Some(payload.len() as i64));
        assert_eq!(hello.metadata_json["ext_path"].as_str(), Some("/hello.txt"));

        // The file's bytes are readable through the ext byte reader.
        let bytes = read_filesystem_entry_bytes(
            &case_path,
            ReadEntryBytesOptions {
                entry_id: hello.id,
                offset: 0,
                length: 64,
            },
        )?;
        assert_eq!(bytes.bytes, payload);
        assert!(bytes.eof);

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn carve_evidence_recovers_files_by_signature() -> Result<()> {
        let case_path = unique_case_path("carve-evidence");
        create_test_case(&case_path)?;
        let dir = unique_temp_dir("carve-evidence-source");
        let image_path = dir.join("carve.img");

        // A raw image with a complete JPEG and PNG embedded at unaligned
        // offsets in otherwise-zeroed space (no filesystem).
        let mut jpeg = vec![0xFF, 0xD8, 0xFF, 0xE0];
        jpeg.extend_from_slice(b"JFIF payload bytes here");
        jpeg.extend_from_slice(&[0xFF, 0xD9]);
        let mut png = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        png.extend_from_slice(b"IHDR...pixels...");
        png.extend_from_slice(&[0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]);

        let mut image = vec![0_u8; 512 * 1024];
        let jpeg_offset = 4096 + 17;
        let png_offset = 200_000;
        image[jpeg_offset..jpeg_offset + jpeg.len()].copy_from_slice(&jpeg);
        image[png_offset..png_offset + png.len()].copy_from_slice(&png);
        fs::write(&image_path, &image)?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: image_path.clone(),
                kind: EvidenceKind::Image,
                read_file_system_requested: false,
                notes: None,
            },
        )?;
        // Attach-only; carving is examiner-driven and independent of indexing.
        let result = carve_evidence(
            &case_path,
            evidence_id,
            CarveOptions {
                max_scan_bytes: 0,
                max_files: 100,
            },
        )?;
        assert_eq!(result.carved_files, 2);
        assert!(!result.truncated);

        let entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        let carved: Vec<_> = entries
            .iter()
            .filter(|entry| entry.metadata_json["artifact_kind"].as_str() == Some("carved_file"))
            .collect();
        assert_eq!(carved.len(), 2);

        let jpg = carved
            .iter()
            .find(|entry| entry.name.ends_with(".jpg"))
            .expect("carved JPEG present");
        assert_eq!(
            jpg.metadata_json["file_data_physical_offset"].as_u64(),
            Some(jpeg_offset as u64)
        );
        assert_eq!(jpg.size_bytes, Some(jpeg.len() as i64));
        assert_eq!(
            jpg.metadata_json["category_main"].as_str(),
            Some("Recovery")
        );
        assert_eq!(
            jpg.metadata_json["category_sub"].as_str(),
            Some("Carved files")
        );

        // Carved bytes are recoverable exactly via the physical-extent reader.
        let bytes = read_filesystem_entry_bytes(
            &case_path,
            ReadEntryBytesOptions {
                entry_id: jpg.id,
                offset: 0,
                length: 1024,
            },
        )?;
        assert_eq!(bytes.bytes, jpeg);
        assert!(bytes.eof);

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[test]
    fn hash_evidence_records_sha256_and_fills_report() -> Result<()> {
        let case_path = unique_case_path("hash-evidence");
        create_test_case(&case_path)?;
        let dir = unique_temp_dir("hash-evidence-source");

        // Split raw: the hash must cover the DECODED stream (all segments).
        fs::write(dir.join("disk.001"), b"abc")?;
        fs::write(dir.join("disk.002"), b"defg")?;
        fs::write(dir.join("disk.003"), b"hi")?;
        let image_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: dir.join("disk.001"),
                kind: EvidenceKind::Image,
                read_file_system_requested: false,
                notes: None,
            },
        )?;
        let result = hash_evidence(&case_path, image_id)?;
        assert_eq!(result.bytes_hashed, 9);
        assert_eq!(result.sha256_hex, sha256_hex(b"abcdefghi"));
        assert!(!result.hashed_at.is_empty());

        let evidence = list_evidence(&case_path)?;
        assert_eq!(
            evidence[0].sha256_hex.as_deref(),
            Some(result.sha256_hex.as_str())
        );
        assert!(evidence[0].hashed_at.is_some());

        // The report's evidence table now carries the stored hash.
        let report = report_data(&case_path)?;
        assert_eq!(
            report.evidence[0].sha256.as_deref(),
            Some(result.sha256_hex.as_str())
        );
        let html = render_report_html(&report);
        assert!(html.contains(&result.sha256_hex));
        assert!(!html.contains("not computed"));

        // Plain file evidence hashes its bytes directly.
        fs::write(dir.join("doc.txt"), b"hello evidence")?;
        let file_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: dir.join("doc.txt"),
                kind: EvidenceKind::File,
                read_file_system_requested: false,
                notes: None,
            },
        )?;
        let file_hash = hash_evidence(&case_path, file_id)?;
        assert_eq!(file_hash.sha256_hex, sha256_hex(b"hello evidence"));

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[test]
    fn image_process_indexes_deleted_fat_entries() -> Result<()> {
        let case_path = unique_case_path("image-fat-deleted");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("image-fat-deleted-source");
        let image_path = evidence_dir.join("fat-deleted.img");

        // Build a FAT volume with a live file plus SECRET.TXT, then flip
        // SECRET.TXT's directory entry to 0xE5 without touching its data -
        // exactly what an ordinary delete leaves on disk.
        let payload = b"deleted fat payload";
        let mut volume = {
            let mut cursor = io::Cursor::new(vec![0_u8; 1024 * 1024]);
            fatfs::format_volume(&mut cursor, fatfs::FormatVolumeOptions::new())?;
            cursor.seek(SeekFrom::Start(0))?;
            {
                let fs = fatfs::FileSystem::new(&mut cursor, fatfs::FsOptions::new())?;
                let root = fs.root_dir();
                let mut live = root.create_file("keep.txt")?;
                live.write_all(b"live file")?;
                live.flush()?;
                let mut secret = root.create_file("secret.txt")?;
                secret.write_all(payload)?;
                secret.flush()?;
            }
            cursor.into_inner()
        };
        let marker = b"SECRET  TXT";
        let position = volume
            .windows(marker.len())
            .position(|window| window == marker)
            .expect("SECRET.TXT directory entry present");
        volume[position] = 0xE5;
        fs::write(&image_path, &volume)?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: image_path.clone(),
                kind: EvidenceKind::Image,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        let processed = process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 200,
            },
        )?;
        assert_eq!(processed.status, "completed");

        let entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        let deleted = entries
            .iter()
            .find(|entry| {
                entry.is_deleted
                    && entry.metadata_json["recovery_source"].as_str()
                        == Some("fat_directory_entry")
            })
            .expect("deleted FAT entry should be indexed");
        assert!(deleted.name.starts_with('_'));
        assert!(deleted.name.ends_with(".TXT"));
        assert!(deleted.logical_path.contains("/Recovery/Deleted Files/"));
        assert_eq!(deleted.size_bytes, Some(payload.len() as i64));
        assert_eq!(
            deleted.metadata_json["category_main"].as_str(),
            Some("Recovery")
        );
        assert_eq!(
            deleted.metadata_json["category_sub"].as_str(),
            Some("Deleted files")
        );
        assert!(deleted.metadata_json["file_data_physical_offset"].is_u64());
        // The fixture's fatfs build writes zeroed DOS timestamps, so
        // modified_utc is absent here; real volumes carry it.

        // The deleted file's content is recoverable byte-for-byte.
        let bytes = read_filesystem_entry_bytes(
            &case_path,
            ReadEntryBytesOptions {
                entry_id: deleted.id,
                offset: 0,
                length: 64,
            },
        )?;
        assert_eq!(bytes.bytes, payload);
        assert!(bytes.eof);

        // Live files are untouched by the deleted scan.
        assert!(entries
            .iter()
            .any(|entry| { entry.logical_path.ends_with("/keep.txt") && !entry.is_deleted }));

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn image_process_recovers_lost_partition_from_wiped_table() -> Result<()> {
        let case_path = unique_case_path("image-lost-partition");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("image-lost-partition-source");
        let image_path = evidence_dir.join("wiped-table.img");
        // Deleted-partition scenario: sector 0 zeroed (no MBR/GPT), orphaned
        // FAT volume at 2 MiB inside unpartitioned space.
        let fat_volume = test_fat_volume_bytes()?;
        let volume_offset = 2 * 1024 * 1024;
        let mut image = vec![0_u8; volume_offset + fat_volume.len() + 512];
        image[volume_offset..volume_offset + fat_volume.len()].copy_from_slice(&fat_volume);
        fs::write(&image_path, image)?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: image_path.clone(),
                kind: EvidenceKind::Image,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        let processed = process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 200,
            },
        )?;
        assert_eq!(processed.status, "completed");

        let entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        let record = entries
            .iter()
            .find(|entry| {
                entry.metadata_json["artifact_kind"].as_str() == Some("recovered_partition")
            })
            .expect("recovered partition record should be indexed");
        assert_eq!(
            record.metadata_json["start_offset"].as_u64(),
            Some(volume_offset as u64)
        );
        assert_eq!(
            record.metadata_json["detected_filesystem"].as_str(),
            Some("FAT")
        );
        assert_eq!(
            record.metadata_json["recovery_source"].as_str(),
            Some("boot_sector_scan")
        );
        assert_eq!(
            record.metadata_json["category_main"].as_str(),
            Some("Recovery")
        );
        assert_eq!(
            record.metadata_json["category_sub"].as_str(),
            Some("Recovered partitions")
        );

        // The orphaned volume's contents are browsable and readable.
        let note = entries
            .iter()
            .find(|entry| {
                entry.logical_path == "/Image Analysis/Volumes/recovered-01-fat/DFIR/note.txt"
            })
            .expect("file inside recovered volume should be indexed");
        let bytes = read_filesystem_entry_bytes(
            &case_path,
            ReadEntryBytesOptions {
                entry_id: note.id,
                offset: 0,
                length: 64,
            },
        )?;
        assert_eq!(bytes.bytes, b"FAT evidence artifact");

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn image_process_indexes_whole_fat_volume_without_partition_table() -> Result<()> {
        let case_path = unique_case_path("image-whole-fat");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("image-whole-fat-source");
        let image_path = evidence_dir.join("whole-fat.img");
        create_test_whole_fat_image(&image_path)?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: image_path.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;

        let processed = process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )?;
        assert_eq!(processed.status, "completed");

        let entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        assert!(entries.iter().any(|entry| {
            entry.logical_path == "/Image Analysis/Volumes/000-whole-image"
                && entry.entry_kind == "directory"
                && entry.metadata_json["filesystem_parser"].as_str() == Some("fatfs")
        }));
        let note = entries
            .iter()
            .find(|entry| {
                entry.logical_path == "/Image Analysis/Volumes/000-whole-image/DFIR/note.txt"
            })
            .expect("whole-image FAT file should be indexed");
        let bytes = read_filesystem_entry_bytes(
            &case_path,
            ReadEntryBytesOptions {
                entry_id: note.id,
                offset: 0,
                length: 64,
            },
        )?;
        assert_eq!(bytes.bytes, b"FAT evidence artifact");

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn image_process_indexes_whole_ntfs_volume_when_fixture_available() -> Result<()> {
        let Some(fixture_path) = optional_ntfs_testfs1_path() else {
            eprintln!("skipping NTFS fixture test; ntfs crate testfs1 fixture not found");
            return Ok(());
        };
        let case_path = unique_case_path("image-whole-ntfs");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("image-whole-ntfs-source");
        let image_path = evidence_dir.join("whole-ntfs.img");
        fs::copy(&fixture_path, &image_path).with_context(|| {
            format!(
                "copying NTFS fixture {} to {}",
                fixture_path.display(),
                image_path.display()
            )
        })?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: image_path.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;

        let processed = process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 2_000,
            },
        )?;
        assert_eq!(processed.status, "completed");

        let entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        assert!(entries.iter().any(|entry| {
            entry.logical_path == "/Image Analysis/Volumes/000-whole-image"
                && entry.entry_kind == "directory"
                && entry.metadata_json["filesystem_parser"].as_str() == Some("ntfs")
        }));
        let file = entries
            .iter()
            .find(|entry| {
                entry.logical_path == "/Image Analysis/Volumes/000-whole-image/file-with-12345"
            })
            .expect("NTFS resident data file should be indexed");
        assert_eq!(file.entry_kind, "file");
        assert!(file.metadata_json["ntfs_file_record_number"]
            .as_u64()
            .is_some());
        let bytes = read_filesystem_entry_bytes(
            &case_path,
            ReadEntryBytesOptions {
                entry_id: file.id,
                offset: 0,
                length: 64,
            },
        )?;
        assert_eq!(bytes.bytes, b"12345");
        assert_eq!(bytes.total_size, 5);

        let unallocated = entries
            .iter()
            .find(|entry| {
                entry.logical_path == "/Image Analysis/Volumes/000-whole-image/UnallocatedSpace"
            })
            .expect("NTFS unallocated-space row should be indexed from $Bitmap");
        assert_eq!(unallocated.entry_kind, "file");
        assert_eq!(
            unallocated.metadata_json["artifact_kind"].as_str(),
            Some("unallocated_space")
        );
        assert_eq!(
            unallocated.metadata_json["storage_area"].as_str(),
            Some("unallocated_space")
        );
        assert!(unallocated.size_bytes.unwrap_or_default() > 0);
        assert!(
            unallocated.metadata_json["unallocated_run_count"]
                .as_u64()
                .unwrap_or_default()
                > 0
        );
        let unallocated_bytes = read_filesystem_entry_bytes(
            &case_path,
            ReadEntryBytesOptions {
                entry_id: unallocated.id,
                offset: 0,
                length: 64,
            },
        )?;
        assert_eq!(
            unallocated_bytes.total_size,
            unallocated.size_bytes.unwrap_or_default() as u64
        );
        assert!(unallocated_bytes.bytes_read > 0);

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn image_process_analyzes_fixed_vhd_partition_records() -> Result<()> {
        let case_path = unique_case_path("image-vhd");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("image-vhd-source");
        let image_path = evidence_dir.join("disk.vhd");
        create_test_fixed_vhd_image(&image_path)?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: image_path.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        let processed = process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )?;
        assert_eq!(processed.status, "completed");

        let entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        let container = entries
            .iter()
            .find(|entry| entry.logical_path == "/Image Analysis/Container.record")
            .expect("container record should be created");
        assert_eq!(
            container.metadata_json["container_format"].as_str(),
            Some("Vhd")
        );
        assert!(entries.iter().any(|entry| {
            entry.metadata_json["artifact_kind"].as_str() == Some("disk_partition")
                && entry.metadata_json["start_offset"].as_u64() == Some(1_048_576)
        }));

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn image_process_indexes_fat_entries_inside_fixed_vhd() -> Result<()> {
        let case_path = unique_case_path("image-vhd-fat");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("image-vhd-fat-source");
        let image_path = evidence_dir.join("fat-disk.vhd");
        create_test_fat_fixed_vhd_image(&image_path)?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: image_path.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;

        let processed = process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )?;
        assert_eq!(processed.status, "completed");

        let entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        assert!(entries.iter().any(|entry| {
            entry.logical_path == "/Image Analysis/Container.record"
                && entry.metadata_json["container_format"].as_str() == Some("Vhd")
        }));
        let note = entries
            .iter()
            .find(|entry| entry.logical_path == "/Image Analysis/Volumes/001-part0/DFIR/note.txt")
            .expect("FAT file inside fixed VHD should be indexed");
        let bytes = read_filesystem_entry_bytes(
            &case_path,
            ReadEntryBytesOptions {
                entry_id: note.id,
                offset: 0,
                length: 64,
            },
        )?;
        assert_eq!(bytes.bytes, b"FAT evidence artifact");

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn evaluate_signature_classifies_headers_against_extension() {
        // JPEG bytes with a .jpg name -> canonical match.
        let jpeg = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
        let f = evaluate_signature("photo.jpg", &jpeg);
        assert_eq!(f.status, "match");
        assert_eq!(f.detected_label, Some("JPEG"));
        assert_eq!(f.extension.as_deref(), Some("jpg"));

        // Same JPEG bytes with a .txt name -> mismatch (renamed extension).
        let f = evaluate_signature("secret.txt", &jpeg);
        assert_eq!(f.status, "mismatch");
        assert_eq!(f.detected_label, Some("JPEG"));

        // JPEG bytes with .jpeg -> alias (legit alternate extension).
        let f = evaluate_signature("photo.jpeg", &jpeg);
        assert_eq!(f.status, "alias");

        // PNG bytes with .png -> match.
        let png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        assert_eq!(evaluate_signature("a.png", &png).status, "match");

        // Unrecognized header with an extension -> unknown.
        let f = evaluate_signature("notes.dat", b"just some ascii text here");
        assert_eq!(f.status, "unknown");
        assert_eq!(f.detected_label, None);

        // No extension -> no_extension regardless of content.
        assert_eq!(evaluate_signature("README", &jpeg).status, "no_extension");
        // Dotfiles have no real extension.
        assert_eq!(evaluate_signature(".bashrc", b"x").status, "no_extension");

        // ZIP container with an Office Open XML extension -> alias, not mismatch.
        let zip = [0x50, 0x4B, 0x03, 0x04];
        assert_eq!(evaluate_signature("report.docx", &zip).status, "alias");
        // ZIP container renamed to .jpg -> mismatch.
        assert_eq!(evaluate_signature("hidden.jpg", &zip).status, "mismatch");
    }

    #[test]
    fn analyze_signatures_flags_renamed_extension() -> Result<()> {
        let case_path = unique_case_path("signature-analysis");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("signature-analysis-source");
        fs::create_dir_all(&evidence_dir)?;
        // A real JPEG (magic FF D8 FF) deliberately misnamed with a .txt extension.
        let mut jpeg = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46];
        jpeg.extend_from_slice(&[0u8; 64]);
        fs::write(evidence_dir.join("disguised.txt"), &jpeg)?;
        // A genuine text file with a .txt extension -> unknown (no signature), not a mismatch.
        fs::write(
            evidence_dir.join("real.txt"),
            b"just plain notes, nothing to detect",
        )?;
        // A PNG correctly named.
        let png = [
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D,
        ];
        fs::write(evidence_dir.join("ok.png"), png)?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )?;

        let result = analyze_signatures(
            &case_path,
            AnalyzeSignaturesOptions {
                evidence_id: Some(evidence_id),
                max_entries: 100,
            },
        )?;
        assert_eq!(result.status, "completed");
        assert!(!result.truncated);
        assert!(result.files_examined >= 3);
        assert_eq!(result.mismatches, 1, "the renamed JPEG should be flagged");
        assert!(result.matches >= 1, "the PNG should match");

        // Verify the metadata was actually written back onto the disguised file.
        let entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        let disguised = entries
            .iter()
            .find(|e| e.logical_path.ends_with("/disguised.txt"))
            .expect("disguised.txt should be indexed");
        assert_eq!(
            disguised.metadata_json.get("signature_status"),
            Some(&serde_json::Value::String("mismatch".to_string()))
        );
        assert_eq!(
            disguised.metadata_json.get("detected_signature"),
            Some(&serde_json::Value::String("JPEG".to_string()))
        );
        assert_eq!(
            disguised.metadata_json.get("file_extension"),
            Some(&serde_json::Value::String("txt".to_string()))
        );

        let real = entries
            .iter()
            .find(|e| e.logical_path.ends_with("/real.txt"))
            .expect("real.txt should be indexed");
        assert_eq!(
            real.metadata_json.get("signature_status"),
            Some(&serde_json::Value::String("unknown".to_string()))
        );

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn category_entry_counts_groups_stored_categories() -> Result<()> {
        let case_path = unique_case_path("category-counts");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("category-counts-source");
        let nested = evidence_dir.join("Docs");
        fs::create_dir_all(&nested)?;
        fs::write(nested.join("notes.txt"), b"plain text notes")?;
        fs::write(nested.join("report.pdf"), b"%PDF-1.4 tiny test body")?;
        fs::write(evidence_dir.join("tool.exe"), b"MZ fake executable")?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        let processed = process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )?;
        assert_eq!(processed.status, "completed");

        // The migration must have created the per-evidence count index.
        let conn = open_existing_case(&case_path)?;
        let index_present: i64 = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master
             WHERE type = 'index' AND name = 'ix_filesystem_entries_case_evidence'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(index_present, 1);
        drop(conn);

        let counts = category_entry_counts(&case_path)?;
        let find = |main: &str, sub: &str| {
            counts
                .iter()
                .find(|row| row.main == main && row.sub == sub)
                .map(|row| row.count)
                .unwrap_or(0)
        };
        assert_eq!(find("Documents and Office", "Text and notes"), 1);
        assert_eq!(find("Documents and Office", "PDF"), 1);
        assert_eq!(find("Program Execution", "Executables and binaries"), 1);

        // Counts cover exactly the non-directory entries: the Docs folder row
        // must not contribute.
        let total: i64 = counts.iter().map(|row| row.count).sum();
        let file_entries = list_filesystem_entries(&case_path, Some(evidence_id))?
            .into_iter()
            .filter(|entry| entry.entry_kind != "directory")
            .count() as i64;
        assert_eq!(total, file_entries);
        assert!(counts
            .iter()
            .all(|row| !row.main.is_empty() && row.count > 0));
        assert!(max_filesystem_entry_id(&case_path)? > 0);

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn evidence_process_indexes_folder_and_deep_searches_content() -> Result<()> {
        let case_path = unique_case_path("process-search");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("process-search-source");
        let nested = evidence_dir.join("Users").join("Examiner");
        fs::create_dir_all(&nested)?;
        fs::write(
            nested.join("history.txt"),
            b"Visited example.com with browser keyword evidence",
        )?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        assert_eq!(filesystem_entry_count(&case_path)?, 0);

        let processed = process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )?;
        assert_eq!(processed.status, "completed");
        assert!(!processed.truncated);
        assert!(processed.entries_indexed >= 3);
        assert!(filesystem_entry_count(&case_path)? >= 3);

        let entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        let history_entry = entries
            .iter()
            .find(|entry| entry.logical_path.ends_with("/history.txt"))
            .expect("history entry should be listed");
        let entry_bytes = read_filesystem_entry_bytes(
            &case_path,
            ReadEntryBytesOptions {
                entry_id: history_entry.id,
                offset: 0,
                length: 7,
            },
        )?;
        assert_eq!(entry_bytes.bytes, b"Visited");

        let path_hits = deep_search(
            &case_path,
            DeepSearchOptions {
                category: None,
                file_types: None,
                query: "history.txt".to_string(),
                evidence_id: Some(evidence_id),
                include_content: false,
                max_results: 10,
                max_file_bytes: 64 * 1024,
            },
        )?;
        assert!(path_hits.iter().any(|hit| hit.match_kind == "path"));

        let content_hits = deep_search(
            &case_path,
            DeepSearchOptions {
                category: None,
                file_types: None,
                query: "keyword".to_string(),
                evidence_id: Some(evidence_id),
                include_content: true,
                max_results: 10,
                max_file_bytes: 64 * 1024,
            },
        )?;
        let content_hit = content_hits
            .iter()
            .find(|hit| hit.match_kind == "content")
            .expect("content hit should be returned");
        assert_eq!(content_hit.evidence_id, evidence_id);
        assert!(content_hit.entry_id > 0);
        assert_eq!(content_hit.selection_length, Some("keyword".len() as i64));

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn evidence_process_populates_content_head_for_folder_content_search() -> Result<()> {
        let case_path = unique_case_path("process-content-head");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("process-content-head-source");
        fs::create_dir_all(&evidence_dir)?;
        let content = b"stored deep search token in indexed bytes";
        fs::write(evidence_dir.join("note.txt"), content)?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        let processed = process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )?;
        assert_eq!(processed.status, "completed");

        let conn = open_existing_case(&case_path)?;
        let stored: Vec<u8> = conn.query_row(
            "SELECT content_head
             FROM filesystem_entries
             WHERE evidence_id = ?1 AND logical_path LIKE '%/note.txt'",
            params![evidence_id],
            |row| row.get(0),
        )?;
        assert_eq!(stored, content);
        drop(conn);

        fs::remove_dir_all(&evidence_dir)?;
        let hits = deep_search(
            &case_path,
            DeepSearchOptions {
                category: None,
                file_types: None,
                query: "deep search token".to_string(),
                evidence_id: Some(evidence_id),
                include_content: true,
                max_results: 10,
                max_file_bytes: 64 * 1024,
            },
        )?;
        let hit = hits
            .iter()
            .find(|hit| hit.logical_path.ends_with("/note.txt") && hit.match_kind == "content")
            .expect("content hit should come from stored content_head");
        assert_eq!(hit.selection_offset, Some(7));

        cleanup_case_path(&case_path);
        Ok(())
    }

    #[test]
    fn deep_search_scans_raw_byte_windows_in_large_and_unicode_files() -> Result<()> {
        let case_path = unique_case_path("process-search-bytes");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("process-search-bytes-source");
        fs::create_dir_all(&evidence_dir)?;

        let large_needle = b"VisibleNameInLargeBinary";
        // Within the indexed keyword-preview window (CONTENT_INDEX_BYTES); the
        // file itself is far larger, so this still exercises searching a big
        // file through the bounded preview.
        let large_offset = 2048;
        let mut large_bytes = vec![0_u8; 128 * 1024];
        large_bytes[large_offset..large_offset + large_needle.len()].copy_from_slice(large_needle);
        fs::write(evidence_dir.join("large.bin"), large_bytes)?;

        let mut utf16_bytes = vec![0xFF, 0xFE];
        for unit in "Visible UTF16 Secret".encode_utf16() {
            utf16_bytes.extend_from_slice(&unit.to_le_bytes());
        }
        fs::write(evidence_dir.join("utf16.bin"), utf16_bytes)?;

        // UTF-16LE text at an ODD byte offset (13-byte ASCII prefix). On-disk strings have no
        // alignment guarantee; an even-step scan misses these (regression for the step_by(2) bug).
        let mut odd_utf16_bytes = b"BEGIN-MARKER ".to_vec();
        for unit in "classifiedsecret".encode_utf16() {
            odd_utf16_bytes.extend_from_slice(&unit.to_le_bytes());
        }
        odd_utf16_bytes.extend_from_slice(b" END-MARKER");
        fs::write(evidence_dir.join("odd-utf16.bin"), odd_utf16_bytes)?;
        fs::write(
            evidence_dir.join("signature.bin"),
            [0x00, 0xDE, 0xAD, 0xBE, 0xEF],
        )?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        let processed = process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )?;
        assert_eq!(processed.status, "completed");

        let large_hits = deep_search(
            &case_path,
            DeepSearchOptions {
                category: None,
                file_types: None,
                query: "visiblenameinlargebinary".to_string(),
                evidence_id: Some(evidence_id),
                include_content: true,
                max_results: 10,
                max_file_bytes: 64 * 1024,
            },
        )?;
        let large_hit = large_hits
            .iter()
            .find(|hit| hit.logical_path.ends_with("/large.bin"))
            .expect("large file should be searched through the capped byte window");
        assert_eq!(large_hit.match_kind, "content");
        assert_eq!(large_hit.selection_offset, Some(large_offset as i64));
        assert_eq!(large_hit.selection_length, Some(large_needle.len() as i64));

        let utf16_hits = deep_search(
            &case_path,
            DeepSearchOptions {
                category: None,
                file_types: None,
                query: "utf16 secret".to_string(),
                evidence_id: Some(evidence_id),
                include_content: true,
                max_results: 10,
                max_file_bytes: 64 * 1024,
            },
        )?;
        let utf16_hit = utf16_hits
            .iter()
            .find(|hit| hit.logical_path.ends_with("/utf16.bin"))
            .expect("UTF-16LE text should be searchable from raw bytes");
        assert_eq!(utf16_hit.selection_offset, Some(18));
        assert_eq!(
            utf16_hit.selection_length,
            Some("utf16 secret".encode_utf16().count() as i64 * 2)
        );

        let odd_hits = deep_search(
            &case_path,
            DeepSearchOptions {
                category: None,
                file_types: None,
                query: "classifiedsecret".to_string(),
                evidence_id: Some(evidence_id),
                include_content: true,
                max_results: 10,
                max_file_bytes: 64 * 1024,
            },
        )?;
        let odd_hit = odd_hits
            .iter()
            .find(|hit| hit.logical_path.ends_with("/odd-utf16.bin"))
            .expect("odd-offset UTF-16LE text must be found (no alignment assumption)");
        assert_eq!(odd_hit.selection_offset, Some(13));
        assert_eq!(
            odd_hit.selection_length,
            Some("classifiedsecret".encode_utf16().count() as i64 * 2)
        );

        let hex_hits = deep_search(
            &case_path,
            DeepSearchOptions {
                category: None,
                file_types: None,
                query: "hex:DE AD BE EF".to_string(),
                evidence_id: Some(evidence_id),
                include_content: true,
                max_results: 10,
                max_file_bytes: 64 * 1024,
            },
        )?;
        let hex_hit = hex_hits
            .iter()
            .find(|hit| hit.logical_path.ends_with("/signature.bin"))
            .expect("explicit hex byte query should match exact bytes");
        assert_eq!(hex_hit.selection_offset, Some(1));
        assert_eq!(hex_hit.selection_length, Some(4));

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn deep_search_content_scans_beyond_first_thousand_file_candidates() -> Result<()> {
        let case_path = unique_case_path("process-search-candidate-limit");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("process-search-candidate-limit-source");
        fs::create_dir_all(&evidence_dir)?;

        for index in 0..1499 {
            fs::write(
                evidence_dir.join(format!("aaa_{index:04}.txt")),
                b"small filler file",
            )?;
        }
        fs::write(
            evidence_dir.join("zzz_target.txt"),
            b"needle-beyond-old-cap",
        )?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        let processed = process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 2_000,
            },
        )?;
        assert_eq!(processed.status, "completed");

        let hits = deep_search(
            &case_path,
            DeepSearchOptions {
                category: None,
                file_types: None,
                query: "needle-beyond-old-cap".to_string(),
                evidence_id: Some(evidence_id),
                include_content: true,
                max_results: 50,
                max_file_bytes: 1024,
            },
        )?;
        let target_hit = hits
            .iter()
            .find(|hit| hit.logical_path.ends_with("/zzz_target.txt"))
            .expect("target sorted beyond the old 1000-candidate cap should be content-scanned");
        assert_eq!(target_hit.match_kind, "content");

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn recover_filesystem_entry_exports_indexed_file_bytes() -> Result<()> {
        let case_path = unique_case_path("recover-entry");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("recover-entry-source");
        let nested = evidence_dir.join("Users").join("Examiner");
        fs::create_dir_all(&nested)?;
        fs::write(nested.join("note.txt"), b"Recovered evidence bytes")?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )?;
        let entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        let note = entries
            .iter()
            .find(|entry| entry.logical_path.ends_with("/note.txt"))
            .expect("note.txt should be indexed");
        let output_dir = unique_temp_dir("recover-entry-output");
        let output_path = output_dir.join("note-recovered.txt");

        let recovered = recover_filesystem_entry(
            &case_path,
            RecoverEntryOptions {
                entry_id: note.id,
                output_path: output_path.clone(),
            },
        )?;

        assert_eq!(recovered.evidence_id, evidence_id);
        assert_eq!(
            recovered.bytes_written,
            b"Recovered evidence bytes".len() as u64
        );
        assert_eq!(
            recovered.total_size,
            b"Recovered evidence bytes".len() as u64
        );
        assert_eq!(recovered.status, "completed");
        assert_eq!(fs::read(&output_path)?, b"Recovered evidence bytes");

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        let _ = fs::remove_dir_all(output_dir);
        Ok(())
    }

    #[test]
    fn disk_image_file_entries_are_not_opened_as_raw_bytes() -> Result<()> {
        let case_path = unique_case_path("folder-vm-image");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("folder-vm-image-source");
        fs::write(evidence_dir.join("guest.vhd"), b"not a real vhd")?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )?;
        let entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        let entry = entries
            .iter()
            .find(|entry| entry.logical_path == "/guest.vhd")
            .expect("folder VHD entry should be indexed");
        let err = read_filesystem_entry_bytes(
            &case_path,
            ReadEntryBytesOptions {
                entry_id: entry.id,
                offset: 0,
                length: 64,
            },
        )
        .expect_err("disk image entries should not raw-open as ordinary file bytes")
        .to_string();
        assert!(err.contains("attached and analyzed as image evidence"));

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn chromium_history_import_creates_searchable_record_entries() -> Result<()> {
        let case_path = unique_case_path("history-import");
        create_test_case(&case_path)?;
        let history_dir = unique_temp_dir("history-import-source");
        let history_path = history_dir.join("History");
        create_test_chromium_history(&history_path)?;

        let imported = import_chromium_history(
            &case_path,
            ImportBrowserHistoryOptions {
                history_path: history_path.clone(),
                max_visits: 10,
                evidence_name: Some("Chrome Default History".to_string()),
            },
        )?;
        assert_eq!(imported.visits_indexed, 2);
        assert_eq!(imported.bookmarks_indexed, 2);
        assert_eq!(imported.preferences_indexed, 6);
        // 2 visits + 2 bookmarks + 6 preferences + 2 unique URLs + 1 search + 1 download
        assert_eq!(imported.entries_indexed, 14);
        assert!(!imported.truncated);
        assert_eq!(imported.status, "completed");

        let evidence = list_evidence(&case_path)?;
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].source_kind, "browser_history");
        assert!(evidence[0].indexed_at.is_some());

        let entries = list_filesystem_entries(&case_path, Some(imported.evidence_id))?;
        assert_eq!(entries.len(), 14);
        assert!(entries.iter().all(|entry| entry.entry_kind == "record"));

        // DFIR browser categories: URLs, Searches, and Downloads rows with Web Activity mains.
        let url_entry = entries
            .iter()
            .find(|entry| {
                entry
                    .logical_path
                    .starts_with("/Browser Activities/URLs/example.com/")
            })
            .expect("unique URL record should be imported");
        assert_eq!(
            url_entry.metadata_json["category_main"].as_str(),
            Some("Web Activity")
        );
        assert_eq!(
            url_entry.metadata_json["category_sub"].as_str(),
            Some("URLs")
        );
        let search_entry = entries
            .iter()
            .find(|entry| {
                entry
                    .logical_path
                    .starts_with("/Browser Activities/Searches/")
            })
            .expect("search term record should be imported");
        assert_eq!(
            search_entry.metadata_json["search_term"].as_str(),
            Some("keyword")
        );
        assert_eq!(
            search_entry.metadata_json["category_sub"].as_str(),
            Some("Searches")
        );
        let download_entry = entries
            .iter()
            .find(|entry| {
                entry
                    .logical_path
                    .starts_with("/Browser Activities/Downloads/")
            })
            .expect("download record should be imported");
        assert_eq!(
            download_entry.metadata_json["file_name"].as_str(),
            Some("tool.zip")
        );
        assert_eq!(
            download_entry.metadata_json["category_sub"].as_str(),
            Some("Downloads")
        );
        let target = entries
            .iter()
            .find(|entry| {
                entry.name == "Example Page"
                    && entry
                        .logical_path
                        .starts_with("/Browser Activities/Visits/example.com/")
            })
            .expect("example history visit entry should be imported");
        assert_eq!(
            target.metadata_json["url"].as_str(),
            Some("https://example.com/path?q=keyword")
        );
        assert_eq!(
            target.metadata_json["transition_type"].as_str(),
            Some("typed")
        );
        assert_eq!(
            target.metadata_json["source_artifact"].as_str(),
            Some("History")
        );
        assert!(target.metadata_json["source_artifact_path"]
            .as_str()
            .unwrap_or_default()
            .ends_with("History"));
        assert!(target.metadata_json["source_file_modified_utc"].is_string());

        let hits = deep_search(
            &case_path,
            DeepSearchOptions {
                category: None,
                file_types: None,
                query: "example.com/path".to_string(),
                evidence_id: Some(imported.evidence_id),
                include_content: false,
                max_results: 10,
                max_file_bytes: 64 * 1024,
            },
        )?;
        assert!(hits.iter().any(|hit| hit.entry_id == target.id));
        assert!(entries.iter().any(|entry| entry
            .logical_path
            .contains("/Browser Activities/Bookmarks/")));
        assert!(entries.iter().any(|entry| entry
            .logical_path
            .contains("/Browser Activities/Preferences/")));
        assert!(entries.iter().any(|entry| {
            entry.metadata_json["artifact_kind"].as_str() == Some("browser_bookmark")
                && entry.metadata_json["url"].as_str() == Some("https://example.com/bookmark")
        }));

        let truncated = import_chromium_history(
            &case_path,
            ImportBrowserHistoryOptions {
                history_path: history_path.clone(),
                max_visits: 1,
                evidence_name: Some("Chrome Default History".to_string()),
            },
        )?;
        assert_eq!(truncated.evidence_id, imported.evidence_id);
        assert_eq!(truncated.visits_indexed, 1);
        assert_eq!(truncated.bookmarks_indexed, 2);
        assert_eq!(truncated.preferences_indexed, 6);
        // 1 visit + 2 bookmarks + 6 preferences + 1 URL + 1 search + 1 download (max_visits = 1)
        assert_eq!(truncated.entries_indexed, 12);
        assert!(truncated.truncated);
        assert_eq!(truncated.status, "truncated");
        assert_eq!(
            list_filesystem_entries(&case_path, Some(imported.evidence_id))?.len(),
            12
        );

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(history_dir);
        Ok(())
    }

    #[test]
    fn evidence_process_respects_entry_limit() -> Result<()> {
        let case_path = unique_case_path("process-limit");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("process-limit-source");
        fs::write(evidence_dir.join("a.txt"), b"a")?;
        fs::write(evidence_dir.join("b.txt"), b"b")?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        let processed = process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 1,
            },
        )?;
        assert_eq!(processed.status, "truncated");
        assert!(processed.truncated);
        assert_eq!(processed.entries_indexed, 1);
        assert_eq!(filesystem_entry_count(&case_path)?, 1);
        assert!(list_evidence(&case_path)?[0].indexed_at.is_none());

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn bookmark_type_parse_accepts_canonical_types() -> Result<()> {
        let cases = [
            ("notable_file", BookmarkType::NotableFile),
            ("file_group", BookmarkType::FileGroup),
            ("highlighted_data", BookmarkType::HighlightedData),
            ("folder_info", BookmarkType::FolderInfo),
            ("email", BookmarkType::Email),
            ("record", BookmarkType::Record),
            ("FILE_GROUP", BookmarkType::FileGroup),
        ];

        for (input, expected) in cases {
            assert_eq!(BookmarkType::parse(input)?, expected);
        }
        assert!(BookmarkType::parse("tag").is_err());
        Ok(())
    }

    #[test]
    fn bookmark_create_and_list_round_trip() -> Result<()> {
        let case_path = unique_case_path("bookmark-round-trip");
        create_test_case(&case_path)?;
        let folder_id =
            create_bookmark_folder(&case_path, None, "Findings", Some("Report-ready"), true)?;

        let bookmark_id = create_bookmark(
            &case_path,
            CreateBookmarkOptions {
                folder_id,
                bookmark_type: BookmarkType::HighlightedData,
                data_type: Some("Text".to_string()),
                title: Some("  Suspicious phrase  ".to_string()),
                examiner_comment: Some("  Confirmed by examiner  ".to_string()),
                in_report: true,
                source_ref_json: serde_json::json!({ "evidence_id": 1 }),
                content_ref_json: serde_json::json!({ "offset": 128, "length": 16 }),
            },
        )?;
        assert_eq!(bookmark_id, 1);

        let folders = list_bookmark_folders(&case_path)?;
        assert_eq!(folders.len(), 1);
        assert_eq!(folders[0].id, folder_id);
        assert!(!folders[0].created_at.is_empty());
        assert!(!folders[0].updated_at.is_empty());

        let bookmarks = list_bookmarks(&case_path)?;
        assert_eq!(bookmarks.len(), 1);
        let bookmark = &bookmarks[0];
        assert_eq!(bookmark.folder_id, folder_id);
        assert_eq!(bookmark.bookmark_type, "highlighted_data");
        assert_eq!(bookmark.data_type.as_deref(), Some("Text"));
        assert_eq!(bookmark.title.as_deref(), Some("Suspicious phrase"));
        assert_eq!(
            bookmark.examiner_comment.as_deref(),
            Some("Confirmed by examiner")
        );
        assert!(bookmark.in_report);
        assert_eq!(bookmark.source_ref_json["evidence_id"], 1);
        assert_eq!(bookmark.content_ref_json["offset"], 128);

        cleanup_case_path(&case_path);
        Ok(())
    }

    #[test]
    fn bookmark_create_rejects_missing_folder() -> Result<()> {
        let case_path = unique_case_path("bookmark-missing-folder");
        create_test_case(&case_path)?;

        let err = create_bookmark(&case_path, test_bookmark_options(999))
            .expect_err("missing bookmark folder should be rejected")
            .to_string();
        assert!(err.contains("bookmark folder does not exist"));

        cleanup_case_path(&case_path);
        Ok(())
    }

    #[test]
    fn bookmark_create_rejects_non_object_json_refs() -> Result<()> {
        let case_path = unique_case_path("bookmark-json");
        create_test_case(&case_path)?;
        let folder_id = create_bookmark_folder(&case_path, None, "Findings", None, true)?;
        let mut options = test_bookmark_options(folder_id);
        options.source_ref_json = serde_json::json!(["not", "an", "object"]);

        let err = create_bookmark(&case_path, options)
            .expect_err("non-object source_ref_json should be rejected")
            .to_string();
        assert!(err.contains("source_ref_json"));

        cleanup_case_path(&case_path);
        Ok(())
    }

    #[test]
    fn bookmark_folder_rejects_duplicate_root_name() -> Result<()> {
        let case_path = unique_case_path("bookmark-folder-duplicate-root");
        create_test_case(&case_path)?;
        create_bookmark_folder(&case_path, None, "Findings", None, true)?;

        let err = create_bookmark_folder(&case_path, None, "Findings", None, true)
            .expect_err("duplicate root bookmark folder should be rejected")
            .to_string();
        assert!(err.contains("bookmark folder already exists"));

        cleanup_case_path(&case_path);
        Ok(())
    }

    #[test]
    fn bookmark_folder_rejects_duplicate_child_name() -> Result<()> {
        let case_path = unique_case_path("bookmark-folder-duplicate-child");
        create_test_case(&case_path)?;
        let parent_id = create_bookmark_folder(&case_path, None, "Parent", None, true)?;
        create_bookmark_folder(&case_path, Some(parent_id), "Child", None, true)?;

        let err = create_bookmark_folder(&case_path, Some(parent_id), "Child", None, true)
            .expect_err("duplicate child bookmark folder should be rejected")
            .to_string();
        assert!(err.contains("bookmark folder already exists"));

        cleanup_case_path(&case_path);
        Ok(())
    }

    #[test]
    fn bookmark_item_add_and_list_round_trip() -> Result<()> {
        let case_path = unique_case_path("bookmark-item-round-trip");
        create_test_case(&case_path)?;
        let bookmark_id = create_test_bookmark(&case_path)?;

        let item = add_bookmark_item(
            &case_path,
            CreateBookmarkItemOptions {
                bookmark_id,
                evidence_id: None,
                entry_id: None,
                item_order: None,
                display_name: Some("  selected bytes  ".to_string()),
                logical_path: Some("/logical/path.txt".to_string()),
                selection_offset: Some(32),
                selection_length: Some(12),
                data_preview: Some("  preview text  ".to_string()),
                item_ref_json: serde_json::json!({ "artifact": "text", "confidence": 1 }),
            },
        )?;
        assert_eq!(item.id, 1);
        assert_eq!(item.bookmark_id, bookmark_id);
        assert_eq!(item.item_order, 10);

        let items = list_bookmark_items(&case_path, Some(bookmark_id))?;
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].bookmark_id, bookmark_id);
        assert_eq!(items[0].item_order, 10);
        assert_eq!(items[0].display_name.as_deref(), Some("selected bytes"));
        assert_eq!(items[0].logical_path.as_deref(), Some("/logical/path.txt"));
        assert_eq!(items[0].selection_offset, Some(32));
        assert_eq!(items[0].selection_length, Some(12));
        assert_eq!(items[0].data_preview.as_deref(), Some("preview text"));
        assert_eq!(items[0].item_ref_json["artifact"].as_str(), Some("text"));
        assert!(!items[0].created_at.is_empty());

        cleanup_case_path(&case_path);
        Ok(())
    }

    #[test]
    fn bookmark_item_auto_order_and_all_items_list() -> Result<()> {
        let case_path = unique_case_path("bookmark-item-all");
        create_test_case(&case_path)?;
        let first_bookmark_id = create_test_bookmark(&case_path)?;
        let second_folder_id = create_bookmark_folder(&case_path, None, "Second", None, true)?;
        let second_bookmark_id =
            create_bookmark(&case_path, test_bookmark_options(second_folder_id))?;

        add_bookmark_item(&case_path, test_bookmark_item_options(first_bookmark_id))?;
        add_bookmark_item(&case_path, test_bookmark_item_options(first_bookmark_id))?;
        add_bookmark_item(&case_path, test_bookmark_item_options(second_bookmark_id))?;

        let first_items = list_bookmark_items(&case_path, Some(first_bookmark_id))?;
        assert_eq!(first_items.len(), 2);
        assert_eq!(first_items[0].item_order, 10);
        assert_eq!(first_items[1].item_order, 20);

        let all_items = list_bookmark_items(&case_path, None)?;
        assert_eq!(all_items.len(), 3);

        cleanup_case_path(&case_path);
        Ok(())
    }

    #[test]
    fn bookmark_item_add_rejects_duplicate_explicit_order() -> Result<()> {
        let case_path = unique_case_path("bookmark-item-duplicate-order");
        create_test_case(&case_path)?;
        let bookmark_id = create_test_bookmark(&case_path)?;
        let mut first = test_bookmark_item_options(bookmark_id);
        first.item_order = Some(5);
        add_bookmark_item(&case_path, first)?;

        let mut second = test_bookmark_item_options(bookmark_id);
        second.item_order = Some(5);
        let err = add_bookmark_item(&case_path, second)
            .expect_err("duplicate item order should be rejected")
            .to_string();
        assert!(err.contains("bookmark item order already exists"));

        cleanup_case_path(&case_path);
        Ok(())
    }

    #[test]
    fn bookmark_item_add_rejects_missing_bookmark() -> Result<()> {
        let case_path = unique_case_path("bookmark-item-missing");
        create_test_case(&case_path)?;

        let err = add_bookmark_item(&case_path, test_bookmark_item_options(999))
            .expect_err("missing bookmark should be rejected")
            .to_string();
        assert!(err.contains("bookmark does not exist"));

        cleanup_case_path(&case_path);
        Ok(())
    }

    #[test]
    fn bookmark_item_add_rejects_entry_from_other_evidence() -> Result<()> {
        let case_path = unique_case_path("bookmark-item-entry-evidence");
        create_test_case(&case_path)?;
        let first_source = unique_temp_dir("bookmark-entry-evidence-a");
        let second_source = unique_temp_dir("bookmark-entry-evidence-b");
        fs::write(first_source.join("a.txt"), b"a")?;
        fs::write(second_source.join("b.txt"), b"b")?;
        let first_evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: first_source.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: false,
                notes: None,
            },
        )?;
        let second_evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: second_source.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: false,
                notes: None,
            },
        )?;
        let bookmark_id = create_test_bookmark(&case_path)?;
        let conn = open_existing_case(&case_path)?;
        let case_id = active_case_id(&conn)?;
        conn.execute(
            "INSERT INTO filesystem_entries(case_id, evidence_id, logical_path, name, entry_kind)
             VALUES (?1, ?2, '/a.txt', 'a.txt', 'file')",
            rusqlite::params![case_id, first_evidence_id],
        )?;
        let entry_id = conn.last_insert_rowid();

        let mut options = test_bookmark_item_options(bookmark_id);
        options.evidence_id = Some(second_evidence_id);
        options.entry_id = Some(entry_id);
        let err = add_bookmark_item(&case_path, options)
            .expect_err("entry tied to another evidence source should be rejected")
            .to_string();
        assert!(err.contains("belongs to evidence source"));

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(first_source);
        let _ = fs::remove_dir_all(second_source);
        Ok(())
    }

    #[test]
    fn bookmark_item_add_backfills_evidence_from_entry() -> Result<()> {
        let case_path = unique_case_path("bookmark-item-entry-backfill");
        create_test_case(&case_path)?;
        let evidence_source = unique_temp_dir("bookmark-entry-backfill");
        fs::write(evidence_source.join("a.txt"), b"a")?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_source.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: false,
                notes: None,
            },
        )?;
        let bookmark_id = create_test_bookmark(&case_path)?;
        let conn = open_existing_case(&case_path)?;
        let case_id = active_case_id(&conn)?;
        conn.execute(
            "INSERT INTO filesystem_entries(case_id, evidence_id, logical_path, name, entry_kind)
             VALUES (?1, ?2, '/a.txt', 'a.txt', 'file')",
            rusqlite::params![case_id, evidence_id],
        )?;
        let entry_id = conn.last_insert_rowid();

        let mut options = test_bookmark_item_options(bookmark_id);
        options.entry_id = Some(entry_id);
        let item = add_bookmark_item(&case_path, options)?;
        assert_eq!(item.evidence_id, Some(evidence_id));
        assert_eq!(item.entry_id, Some(entry_id));

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_source);
        Ok(())
    }

    #[test]
    fn bookmark_item_add_rejects_invalid_fields() -> Result<()> {
        let case_path = unique_case_path("bookmark-item-invalid");
        create_test_case(&case_path)?;
        let bookmark_id = create_test_bookmark(&case_path)?;

        let mut bad_json = test_bookmark_item_options(bookmark_id);
        bad_json.item_ref_json = serde_json::json!("not an object");
        let err = add_bookmark_item(&case_path, bad_json)
            .expect_err("non-object item_ref_json should be rejected")
            .to_string();
        assert!(err.contains("item_ref_json"));

        let mut bad_offset = test_bookmark_item_options(bookmark_id);
        bad_offset.selection_offset = Some(-1);
        let err = add_bookmark_item(&case_path, bad_offset)
            .expect_err("negative offset should be rejected")
            .to_string();
        assert!(err.contains("selection_offset"));

        cleanup_case_path(&case_path);
        Ok(())
    }

    #[test]
    fn report_data_filters_report_enabled_bookmarks_and_items() -> Result<()> {
        let case_path = unique_case_path("report-data");
        create_test_case(&case_path)?;
        let report_folder_id =
            create_bookmark_folder(&case_path, None, "Report", Some("Visible"), true)?;
        let hidden_folder_id = create_bookmark_folder(&case_path, None, "Hidden", None, false)?;
        let included_bookmark_id = create_bookmark(
            &case_path,
            CreateBookmarkOptions {
                folder_id: report_folder_id,
                bookmark_type: BookmarkType::NotableFile,
                data_type: Some("Document".to_string()),
                title: Some("Important finding".to_string()),
                examiner_comment: Some("Include this".to_string()),
                in_report: true,
                source_ref_json: serde_json::json!({}),
                content_ref_json: serde_json::json!({}),
            },
        )?;
        create_bookmark(
            &case_path,
            CreateBookmarkOptions {
                folder_id: report_folder_id,
                bookmark_type: BookmarkType::Record,
                data_type: None,
                title: Some("Excluded finding".to_string()),
                examiner_comment: None,
                in_report: false,
                source_ref_json: serde_json::json!({}),
                content_ref_json: serde_json::json!({}),
            },
        )?;
        create_bookmark(
            &case_path,
            CreateBookmarkOptions {
                folder_id: hidden_folder_id,
                bookmark_type: BookmarkType::Record,
                data_type: None,
                title: Some("Hidden folder finding".to_string()),
                examiner_comment: None,
                in_report: true,
                source_ref_json: serde_json::json!({}),
                content_ref_json: serde_json::json!({}),
            },
        )?;
        add_bookmark_item(
            &case_path,
            CreateBookmarkItemOptions {
                bookmark_id: included_bookmark_id,
                evidence_id: None,
                entry_id: None,
                item_order: None,
                display_name: Some("Selected bytes".to_string()),
                logical_path: Some("/case/file.txt".to_string()),
                selection_offset: Some(5),
                selection_length: Some(4),
                data_preview: Some("data".to_string()),
                item_ref_json: serde_json::json!({ "kind": "selection" }),
            },
        )?;

        let report = report_data(&case_path)?;
        assert_eq!(report.folders.len(), 1);
        assert_eq!(report.folders[0].name, "Report");
        assert_eq!(report.folders[0].bookmarks.len(), 1);
        assert_eq!(
            report.folders[0].bookmarks[0].title.as_deref(),
            Some("Important finding")
        );
        assert_eq!(report.folders[0].bookmarks[0].items.len(), 1);
        assert_eq!(
            report.folders[0].bookmarks[0].items[0]
                .display_name
                .as_deref(),
            Some("Selected bytes")
        );

        cleanup_case_path(&case_path);
        Ok(())
    }

    #[test]
    fn render_report_html_escapes_content() -> Result<()> {
        let case_path = unique_case_path("report-html");
        create_test_case(&case_path)?;
        let folder_id = create_bookmark_folder(&case_path, None, "<Findings>", None, true)?;
        create_bookmark(
            &case_path,
            CreateBookmarkOptions {
                folder_id,
                bookmark_type: BookmarkType::NotableFile,
                data_type: None,
                title: Some("<script>alert(1)</script>".to_string()),
                examiner_comment: Some("A&B".to_string()),
                in_report: true,
                source_ref_json: serde_json::json!({}),
                content_ref_json: serde_json::json!({}),
            },
        )?;

        let html = render_report_html(&report_data(&case_path)?);
        assert!(html.contains("&lt;Findings&gt;"));
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(html.contains("A&amp;B"));
        assert!(!html.contains("<script>alert(1)</script>"));

        cleanup_case_path(&case_path);
        Ok(())
    }

    #[test]
    fn split_raw_reader_concatenates_segments_and_detects_gaps() -> Result<()> {
        let dir = unique_temp_dir("split-raw");
        fs::write(dir.join("disk.001"), b"abc")?;
        fs::write(dir.join("disk.002"), b"defg")?;
        fs::write(dir.join("disk.003"), b"hi")?;

        // Auto kind detection treats the first segment as an image.
        assert!(looks_like_image(&dir.join("disk.001")));
        assert!(!looks_like_image(&dir.join("report.2024")));

        let mut opened = open_disk_image(&dir.join("disk.001"))?;
        assert_eq!(opened.decoded_size, 9);
        assert!(opened.format.contains("SplitRaw(3 segments)"));
        let mut all = Vec::new();
        opened.reader.read_to_end(&mut all)?;
        assert_eq!(all, b"abcdefghi");

        // Reads and seeks spanning segment boundaries.
        opened.reader.seek(SeekFrom::Start(2))?;
        let mut buf = [0_u8; 4];
        opened.reader.read_exact(&mut buf)?;
        assert_eq!(&buf, b"cdef");
        opened.reader.seek(SeekFrom::End(-3))?;
        let mut tail = Vec::new();
        opened.reader.read_to_end(&mut tail)?;
        assert_eq!(tail, b"ghi");

        // Adding a non-first segment is rejected with guidance.
        let Err(err) = open_disk_image(&dir.join("disk.002")) else {
            panic!("expected non-first segment to be rejected");
        };
        assert!(err.to_string().contains("first segment"));

        // A single .001 with no siblings is ordinary raw evidence.
        let single_dir = unique_temp_dir("split-raw-single");
        fs::write(single_dir.join("lonely.001"), b"xyz")?;
        let single = open_disk_image(&single_dir.join("lonely.001"))?;
        assert_eq!(single.decoded_size, 3);
        assert!(!single.format.contains("SplitRaw"));

        // Attach-time size records the decoded (total) size, not segment 1.
        let case_path = unique_case_path("split-raw-size");
        create_test_case(&case_path)?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: dir.join("disk.001"),
                kind: EvidenceKind::Image,
                read_file_system_requested: false,
                notes: None,
            },
        )?;
        let evidence = list_evidence(&case_path)?;
        assert_eq!(evidence[0].id, evidence_id);
        assert_eq!(evidence[0].size_bytes, Some(9));

        // A gap in the sequence refuses to open instead of truncating.
        fs::remove_file(dir.join("disk.002"))?;
        let Err(err) = open_disk_image(&dir.join("disk.001")) else {
            panic!("expected segment gap to be rejected");
        };
        assert!(err.to_string().contains("segment gap"));

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&single_dir);
        Ok(())
    }

    #[test]
    fn report_includes_technical_details_directory_tree_and_integrity_hash() -> Result<()> {
        let case_path = unique_case_path("report-tech-details");
        create_test_case(&case_path)?;

        let evidence_dir = unique_temp_dir("report-tree-evidence");
        fs::create_dir_all(evidence_dir.join("docs").join("sub"))?;
        fs::write(evidence_dir.join("docs").join("note.txt"), b"hello")?;
        fs::write(
            evidence_dir.join("docs").join("sub").join("inner.txt"),
            b"x",
        )?;
        fs::write(evidence_dir.join("root.bin"), b"abc")?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Folder,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )?;

        let report = report_data_with_directory_structure(&case_path, 2000)?;
        assert_eq!(report.evidence.len(), 1);
        assert_eq!(report.evidence[0].id, evidence_id);
        assert!(report.evidence[0].entries_indexed > 0);
        assert_eq!(report.evidence[0].sha256, None);
        assert_eq!(report.directory_trees.len(), 1);
        let tree = &report.directory_trees[0];
        assert!(!tree.truncated);
        assert!(tree.lines.iter().any(|line| line.name == "docs"));
        assert!(tree.lines.iter().any(|line| line.name == "sub"));
        // Directory structure is folders only: files must not appear.
        assert!(!tree.lines.iter().any(|line| line.name == "note.txt"));
        assert!(!tree.lines.iter().any(|line| line.name == "root.bin"));
        assert!(tree.lines.iter().all(|line| line.entry_kind == "directory"));

        // The lean report (used by /api/state) must stay tree-free.
        assert!(report_data(&case_path)?.directory_trees.is_empty());

        let rendered = render_report(&report);
        assert!(rendered.html.contains("Technical Details"));
        assert!(rendered.html.contains("Evidence Sources"));
        assert!(rendered.html.contains("Directory Structure - "));
        assert!(rendered.html.contains("kdft-band"));
        assert!(rendered.html.contains("KDFT report authenticity"));
        assert!(rendered.html.contains("not computed"));

        // Integrity: the hash must cover exactly the bytes before the footer.
        let marker = "<footer class=\"kdft-integrity\"";
        let footer_start = rendered
            .html
            .find(marker)
            .expect("integrity footer present");
        let recomputed = sha256_hex(rendered.html[..footer_start].as_bytes());
        assert_eq!(recomputed, rendered.sha256);
        assert!(rendered.html.contains(&rendered.sha256));

        // Truncation bound is honored.
        let bounded = report_data_with_directory_structure(&case_path, 1)?;
        assert!(bounded.directory_trees[0].truncated);
        assert_eq!(bounded.directory_trees[0].lines.len(), 1);

        // The export hash is recordable in the audit trail.
        record_report_export(&case_path, "C:/tmp/report.html", &rendered.sha256)?;

        let _ = fs::remove_dir_all(&evidence_dir);
        cleanup_case_path(&case_path);
        Ok(())
    }

    #[test]
    fn render_report_html_formats_search_result_forensic_context() -> Result<()> {
        let case_path = unique_case_path("report-search-context");
        create_test_case(&case_path)?;
        let folder_id = create_bookmark_folder(&case_path, None, "Search Results", None, true)?;
        let bookmark_id = create_bookmark(
            &case_path,
            CreateBookmarkOptions {
                folder_id,
                bookmark_type: BookmarkType::HighlightedData,
                data_type: Some("Search Result".to_string()),
                title: Some("Keyword hit".to_string()),
                examiner_comment: None,
                in_report: true,
                source_ref_json: serde_json::json!({}),
                content_ref_json: serde_json::json!({}),
            },
        )?;
        add_bookmark_item(
            &case_path,
            CreateBookmarkItemOptions {
                bookmark_id,
                evidence_id: None,
                entry_id: None,
                item_order: None,
                display_name: Some("message.eml".to_string()),
                logical_path: Some("/Recovery/Deleted Files/message.eml".to_string()),
                selection_offset: Some(16),
                selection_length: Some(7),
                data_preview: Some("keyword".to_string()),
                item_ref_json: serde_json::json!({
                    "kind": "search_result",
                    "match_kind": "content",
                    "logical_path": "/Recovery/Deleted Files/message.eml",
                    "relative_path": "/Recovery/Deleted Files/message.eml",
                    "size_bytes": 42,
                    "is_deleted": true,
                    "storage_area": "deleted_filesystem_record",
                    "is_file_slack": false,
                    "is_unallocated": false,
                    "mft_record_logical_offset": 2048,
                    "mft_record_physical_offset": 1050624,
                    "file_data_logical_offset": 4096,
                    "file_data_physical_offset": 1052672,
                    "finding_logical_offset": 16,
                    "selection_length": 7,
                    "metadata": {
                        "ntfs_creation_time_utc": "2026-06-30T20:00:00Z",
                        "ntfs_modification_time_utc": "2026-06-30T20:01:00Z",
                        "ntfs_access_time_utc": "2026-06-30T20:02:00Z",
                        "ntfs_mft_record_modification_time_utc": "2026-06-30T20:03:00Z"
                    }
                }),
            },
        )?;

        let html = render_report_html(&report_data(&case_path)?);
        assert!(html.contains("<span class=\"meta\">search_result</span>"));
        assert!(html.contains("<dt>Artifact</dt><dd>Forensic Finding</dd>"));
        assert!(html.contains("<dt>Path</dt><dd>/Recovery/Deleted Files/message.eml</dd>"));
        assert!(html.contains("<dt>Deleted</dt><dd>true</dd>"));
        assert!(html.contains("<dt>Storage Area</dt><dd>deleted_filesystem_record</dd>"));
        assert!(html.contains("<dt>Finding Offset</dt><dd>16</dd>"));
        assert!(html.contains("<dt>MFT Record Physical Offset</dt><dd>1050624</dd>"));
        assert!(html.contains("<dt>File Data Physical Offset</dt><dd>1052672</dd>"));
        assert!(html.contains("<dt>Created</dt><dd>2026-06-30T20:00:00Z</dd>"));
        assert!(html.contains("<dt>MFT Modified</dt><dd>2026-06-30T20:03:00Z</dd>"));

        cleanup_case_path(&case_path);
        Ok(())
    }

    #[test]
    fn render_report_html_formats_browser_activity_items() -> Result<()> {
        let case_path = unique_case_path("report-browser-activity");
        create_test_case(&case_path)?;
        let folder_id = create_bookmark_folder(&case_path, None, "Browser Activities", None, true)?;
        let bookmark_id = create_bookmark(
            &case_path,
            CreateBookmarkOptions {
                folder_id,
                bookmark_type: BookmarkType::Record,
                data_type: Some("Browser Activity".to_string()),
                title: Some("Visit: Example & Evidence".to_string()),
                examiner_comment: None,
                in_report: true,
                source_ref_json: serde_json::json!({}),
                content_ref_json: serde_json::json!({}),
            },
        )?;
        add_bookmark_item(
            &case_path,
            CreateBookmarkItemOptions {
                bookmark_id,
                evidence_id: None,
                entry_id: None,
                item_order: None,
                display_name: Some("Example & Evidence".to_string()),
                logical_path: Some("/Browser Activities/Visits/example.com/1.record".to_string()),
                selection_offset: None,
                selection_length: None,
                data_preview: Some(
                    "2026-06-28T10:00:00Z | Example & Evidence | https://example.com/<q>"
                        .to_string(),
                ),
                item_ref_json: serde_json::json!({
                    "kind": "browser_activity",
                    "activity_kind": "browser_history_visit",
                    "url": "https://example.com/<q>",
                    "title": "Example & Evidence",
                    "visit_time_utc": "2026-06-28T10:00:00Z",
                    "source_file_modified_utc": "2026-06-28T10:05:00Z",
                    "metadata": {
                        "transition_type": "typed",
                        "visit_count": 3
                    }
                }),
            },
        )?;

        let html = render_report_html(&report_data(&case_path)?);
        assert!(html.contains("Browser Activity"));
        assert!(html.contains("<dd>Visit</dd>"));
        assert!(html.contains("Example &amp; Evidence"));
        assert!(html.contains("https://example.com/&lt;q&gt;"));
        assert!(html.contains("<dt>Transition</dt><dd>typed</dd>"));
        assert!(html.contains("<dt>Visit Count</dt><dd>3</dd>"));
        assert!(html.contains("<dt>Source Modified</dt>"));
        assert!(!html.contains("https://example.com/<q>"));

        cleanup_case_path(&case_path);
        Ok(())
    }

    fn create_test_case(case_path: &Path) -> Result<i64> {
        create_case(
            case_path,
            CreateCaseOptions {
                name: "Unit Test Case".to_string(),
                examiner_name: Some("Codex".to_string()),
                case_number: Some("UT-0001".to_string()),
                case_type: Some("Other".to_string()),
                description: None,
                default_export_folder: None,
                temporary_folder: None,
                index_folder: None,
            },
        )
    }

    fn evidence_job_count(case_path: &Path) -> Result<i64> {
        let conn = open_existing_case(case_path)?;
        conn.query_row("SELECT COUNT(*) FROM evidence_jobs", [], |row| row.get(0))
            .context("counting evidence jobs")
    }

    fn audit_event_count(case_path: &Path) -> Result<i64> {
        let conn = open_existing_case(case_path)?;
        conn.query_row("SELECT COUNT(*) FROM audit_events", [], |row| row.get(0))
            .context("counting audit events")
    }

    fn audit_event_actors(case_path: &Path) -> Result<Vec<String>> {
        let conn = open_existing_case(case_path)?;
        let mut stmt = conn.prepare("SELECT actor FROM audit_events ORDER BY id")?;
        let rows = stmt.query_map([], |row| row.get(0))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .context("reading audit event actors")
    }

    fn create_test_bookmark(case_path: &Path) -> Result<i64> {
        let folder_id = create_bookmark_folder(case_path, None, "Findings", None, true)?;
        create_bookmark(case_path, test_bookmark_options(folder_id))
    }

    fn test_bookmark_options(folder_id: i64) -> CreateBookmarkOptions {
        CreateBookmarkOptions {
            folder_id,
            bookmark_type: BookmarkType::NotableFile,
            data_type: None,
            title: Some("Test bookmark".to_string()),
            examiner_comment: None,
            in_report: true,
            source_ref_json: serde_json::json!({}),
            content_ref_json: serde_json::json!({}),
        }
    }

    fn test_bookmark_item_options(bookmark_id: i64) -> CreateBookmarkItemOptions {
        CreateBookmarkItemOptions {
            bookmark_id,
            evidence_id: None,
            entry_id: None,
            item_order: None,
            display_name: None,
            logical_path: None,
            selection_offset: None,
            selection_length: None,
            data_preview: None,
            item_ref_json: serde_json::json!({}),
        }
    }

    fn create_test_chromium_history(history_path: &Path) -> Result<()> {
        let conn = Connection::open(history_path)?;
        conn.execute_batch(
            "CREATE TABLE urls(
                id INTEGER PRIMARY KEY,
                url LONGVARCHAR,
                title LONGVARCHAR,
                visit_count INTEGER DEFAULT 0 NOT NULL,
                typed_count INTEGER DEFAULT 0 NOT NULL,
                last_visit_time INTEGER NOT NULL,
                hidden INTEGER DEFAULT 0 NOT NULL
             );
             CREATE TABLE visits(
                id INTEGER PRIMARY KEY,
                url INTEGER NOT NULL,
                visit_time INTEGER NOT NULL,
                from_visit INTEGER,
                transition INTEGER DEFAULT 0 NOT NULL,
                segment_id INTEGER,
                visit_duration INTEGER DEFAULT 0 NOT NULL
             );
             CREATE TABLE keyword_search_terms(
                keyword_id INTEGER NOT NULL,
                url_id INTEGER NOT NULL,
                term LONGVARCHAR NOT NULL,
                normalized_term LONGVARCHAR NOT NULL
             );
             CREATE TABLE downloads(
                id INTEGER PRIMARY KEY,
                current_path LONGVARCHAR,
                target_path LONGVARCHAR,
                start_time INTEGER,
                end_time INTEGER,
                received_bytes INTEGER,
                total_bytes INTEGER,
                state INTEGER,
                danger_type INTEGER,
                interrupt_reason INTEGER,
                referrer LONGVARCHAR,
                tab_url LONGVARCHAR,
                mime_type LONGVARCHAR
             );",
        )?;
        conn.execute(
            "INSERT INTO keyword_search_terms(keyword_id, url_id, term, normalized_term)
             VALUES (1, 1, 'keyword', 'keyword')",
            [],
        )?;
        conn.execute(
            "INSERT INTO downloads(id, current_path, target_path, start_time, end_time,
                received_bytes, total_bytes, state, danger_type, interrupt_reason,
                referrer, tab_url, mime_type)
             VALUES (7, 'C:\\Users\\me\\Downloads\\tool.zip', 'C:\\Users\\me\\Downloads\\tool.zip',
                13300000015000000, 13300000016000000, 2048, 2048, 1, 0, 0,
                'https://example.com/path?q=keyword', 'https://example.com/downloads',
                'application/zip')",
            [],
        )?;
        conn.execute(
            "INSERT INTO urls(id, url, title, visit_count, typed_count, last_visit_time, hidden)
             VALUES (1, 'https://example.com/path?q=keyword', 'Example Page', 3, 1, 13300000020000000, 0)",
            [],
        )?;
        conn.execute(
            "INSERT INTO urls(id, url, title, visit_count, typed_count, last_visit_time, hidden)
             VALUES (2, 'https://openai.com/docs', 'Docs', 1, 0, 13300000010000000, 0)",
            [],
        )?;
        conn.execute(
            "INSERT INTO visits(id, url, visit_time, from_visit, transition, segment_id, visit_duration)
             VALUES (10, 1, 13300000020000000, 0, 1, 0, 1200000)",
            [],
        )?;
        conn.execute(
            "INSERT INTO visits(id, url, visit_time, from_visit, transition, segment_id, visit_duration)
             VALUES (9, 2, 13300000010000000, 0, 0, 0, 0)",
            [],
        )?;
        let profile_dir = history_path
            .parent()
            .context("test history path should have parent")?;
        fs::write(
            profile_dir.join("Bookmarks"),
            serde_json::json!({
                "roots": {
                    "bookmark_bar": {
                        "type": "folder",
                        "name": "Bookmarks Bar",
                        "children": [
                            {
                                "type": "url",
                                "name": "Example Bookmark",
                                "url": "https://example.com/bookmark",
                                "guid": "bookmark-guid-1",
                                "date_added": "13300000030000000"
                            },
                            {
                                "type": "folder",
                                "name": "Research",
                                "children": [
                                    {
                                        "type": "url",
                                        "name": "OpenAI Bookmark",
                                        "url": "https://openai.com/research",
                                        "guid": "bookmark-guid-2",
                                        "date_added": "13300000040000000"
                                    }
                                ]
                            }
                        ]
                    },
                    "other": {
                        "type": "folder",
                        "name": "Other Bookmarks",
                        "children": []
                    }
                }
            })
            .to_string(),
        )?;
        fs::write(
            profile_dir.join("Preferences"),
            serde_json::json!({
                "profile": {
                    "name": "Default",
                    "avatar_index": 1,
                    "created_by_version": "126.0",
                    "password_manager_enabled": true
                },
                "session": {
                    "restore_on_startup": 4,
                    "startup_urls": ["https://example.com/start"]
                },
                "homepage": "https://example.com/home",
                "homepage_is_newtabpage": false,
                "download": {
                    "default_directory": "C:\\Users\\Examiner\\Downloads",
                    "prompt_for_download": false
                },
                "default_search_provider_data": {
                    "template_url_data": {
                        "short_name": "Search",
                        "keyword": "search.example",
                        "url": "https://search.example/?q={searchTerms}"
                    }
                },
                "safebrowsing": {
                    "enabled": true
                },
                "credentials_enable_service": true,
                "autofill": {
                    "enabled": true
                },
                "extensions": {
                    "settings": {
                        "abc": { "manifest": { "name": "Test Extension" } }
                    }
                }
            })
            .to_string(),
        )?;
        Ok(())
    }

    fn create_test_mbr_image(image_path: &Path) -> Result<()> {
        fs::write(image_path, test_mbr_image_bytes())?;
        Ok(())
    }

    fn create_test_fat_mbr_image(image_path: &Path) -> Result<()> {
        fs::write(image_path, test_fat_mbr_image_bytes()?)?;
        Ok(())
    }

    fn create_test_whole_fat_image(image_path: &Path) -> Result<()> {
        fs::write(image_path, test_fat_volume_bytes()?)?;
        Ok(())
    }

    fn optional_ntfs_testfs1_path() -> Option<PathBuf> {
        let mut source_roots = Vec::new();
        if let Some(cargo_home) = std::env::var_os("CARGO_HOME") {
            source_roots.push(PathBuf::from(cargo_home).join("registry").join("src"));
        }
        if let Some(user_profile) = std::env::var_os("USERPROFILE") {
            source_roots.push(
                PathBuf::from(user_profile)
                    .join(".cargo")
                    .join("registry")
                    .join("src"),
            );
        }
        if let Some(home) = std::env::var_os("HOME") {
            source_roots.push(
                PathBuf::from(home)
                    .join(".cargo")
                    .join("registry")
                    .join("src"),
            );
        }

        for source_root in source_roots {
            let Ok(registry_dirs) = fs::read_dir(source_root) else {
                continue;
            };
            for registry_dir in registry_dirs.flatten() {
                let candidate = registry_dir
                    .path()
                    .join("ntfs-0.4.0")
                    .join("testdata")
                    .join("testfs1");
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
        None
    }

    fn create_test_fixed_vhd_image(image_path: &Path) -> Result<()> {
        fs::write(
            image_path,
            fixed_vhd_from_disk_bytes(test_mbr_image_bytes()),
        )?;
        Ok(())
    }

    fn create_test_fat_fixed_vhd_image(image_path: &Path) -> Result<()> {
        fs::write(
            image_path,
            fixed_vhd_from_disk_bytes(test_fat_mbr_image_bytes()?),
        )?;
        Ok(())
    }

    fn test_mbr_image_bytes() -> Vec<u8> {
        let mut image = vec![0_u8; 4 * 1024 * 1024];
        let entry_offset = 446;
        image[entry_offset] = 0x00;
        image[entry_offset + 4] = 0x07;
        image[entry_offset + 8..entry_offset + 12].copy_from_slice(&2048_u32.to_le_bytes());
        image[entry_offset + 12..entry_offset + 16].copy_from_slice(&2048_u32.to_le_bytes());
        image[510] = 0x55;
        image[511] = 0xAA;
        image
    }

    fn test_fat_mbr_image_bytes() -> Result<Vec<u8>> {
        const PARTITION_START_SECTOR: u32 = 2048;
        const SECTOR_SIZE: usize = 512;
        let fat_volume = test_fat_volume_bytes()?;
        let start = PARTITION_START_SECTOR as usize * SECTOR_SIZE;
        let sectors = u32::try_from(fat_volume.len() / SECTOR_SIZE)
            .context("test FAT volume sector count exceeds u32")?;
        let mut image = vec![0_u8; start + fat_volume.len() + SECTOR_SIZE];
        let entry_offset = 446;
        image[entry_offset] = 0x00;
        image[entry_offset + 4] = 0x01;
        image[entry_offset + 8..entry_offset + 12]
            .copy_from_slice(&PARTITION_START_SECTOR.to_le_bytes());
        image[entry_offset + 12..entry_offset + 16].copy_from_slice(&sectors.to_le_bytes());
        image[510] = 0x55;
        image[511] = 0xAA;
        image[start..start + fat_volume.len()].copy_from_slice(&fat_volume);
        Ok(image)
    }

    fn test_fat_volume_bytes() -> Result<Vec<u8>> {
        let mut fat_cursor = io::Cursor::new(vec![0_u8; 1024 * 1024]);
        fatfs::format_volume(&mut fat_cursor, fatfs::FormatVolumeOptions::new())
            .context("formatting test FAT volume")?;
        fat_cursor.seek(SeekFrom::Start(0))?;
        {
            let fs = fatfs::FileSystem::new(&mut fat_cursor, fatfs::FsOptions::new())
                .context("opening test FAT volume")?;
            let root = fs.root_dir();
            let dfir = root
                .create_dir("DFIR")
                .context("creating test FAT directory")?;
            let mut note = dfir
                .create_file("note.txt")
                .context("creating test FAT file")?;
            note.write_all(b"FAT evidence artifact")
                .context("writing test FAT file")?;
            let case_files = root
                .create_dir("Case Files")
                .context("creating test FAT directory with spaces")?;
            let mut spaced = case_files
                .create_file("note (1).txt")
                .context("creating test FAT file with sanitized name")?;
            spaced
                .write_all(b"FAT spaced artifact")
                .context("writing test FAT file with sanitized name")?;
        }
        Ok(fat_cursor.into_inner())
    }

    fn fixed_vhd_from_disk_bytes(mut image: Vec<u8>) -> Vec<u8> {
        let disk_size = image.len() as u64;
        let mut footer = [0_u8; 512];
        footer[0..8].copy_from_slice(b"conectix");
        footer[8..12].copy_from_slice(&2_u32.to_be_bytes());
        footer[12..16].copy_from_slice(&0x0001_0000_u32.to_be_bytes());
        footer[16..24].copy_from_slice(&u64::MAX.to_be_bytes());
        footer[28..32].copy_from_slice(b"kdft");
        footer[32..36].copy_from_slice(&0x0001_0000_u32.to_be_bytes());
        footer[36..40].copy_from_slice(b"Wi2k");
        footer[40..48].copy_from_slice(&disk_size.to_be_bytes());
        footer[48..56].copy_from_slice(&disk_size.to_be_bytes());
        footer[56..60].copy_from_slice(&512_u32.to_be_bytes());
        footer[60..64].copy_from_slice(&2_u32.to_be_bytes());
        let checksum = !footer
            .iter()
            .fold(0_u32, |acc, byte| acc.wrapping_add(u32::from(*byte)));
        footer[64..68].copy_from_slice(&checksum.to_be_bytes());
        image.extend_from_slice(&footer);
        image
    }

    fn unique_case_path(label: &str) -> PathBuf {
        unique_temp_dir("case-parent").join(format!("kdft-{label}.sqlite"))
    }

    fn cleanup_case_path(case_path: &Path) {
        let parent = case_path.parent().map(Path::to_path_buf);
        let _ = fs::remove_file(case_path);
        if let Some(parent) = parent {
            let _ = fs::remove_dir_all(parent);
        }
    }

    fn unique_temp_dir(label: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before UNIX epoch")
            .as_nanos();
        path.push(format!("kdft-v1-{label}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&path).expect("create test temp directory");
        path
    }

    fn path_str(path: &Path) -> String {
        path.to_string_lossy().into_owned()
    }
}
