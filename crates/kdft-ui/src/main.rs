use anyhow::{bail, Context, Result};
use kdft_case::{
    add_bookmark_item, add_evidence, analyze_signatures, carve_evidence, case_info,
    category_entry_counts, clear_all_findings, create_bookmark, create_bookmark_folder,
    create_case, deep_search, export_image_file, export_image_tree, filesystem_entry_count,
    hash_evidence, import_chromium_history, list_bookmark_folders, list_bookmark_items,
    list_bookmarks, list_evidence, list_filesystem_entries_limited, max_filesystem_entry_id,
    process_evidence, read_filesystem_entry_bytes, record_live_export, record_live_tree_export,
    record_report_export, recover_filesystem_entry, remove_evidence, render_report, report_data,
    report_data_with_directory_structure, AddEvidenceOptions, AnalyzeSignaturesOptions,
    BookmarkType, CarveOptions, CreateBookmarkItemOptions, CreateBookmarkOptions,
    CreateCaseOptions, DeepSearchOptions, EvidenceKind, ImportBrowserHistoryOptions,
    ProcessEvidenceOptions, ReadEntryBytesOptions, RecoverEntryOptions,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() -> Result<()> {
    let args = ServerArgs::parse();
    let config = std::sync::Arc::new(ServerConfig::new()?);
    let (listener, port) = bind_listener(&args.host, args.port)?;
    let url = format!("http://{}:{}/", args.host, port);
    println!("KDFT UI listening at {url}");
    if args.open {
        let _ = open_target(&url);
    }

    // One thread per connection so a long-running job (e.g. indexing a
    // multi-terabyte disk) never blocks the rest of the UI.
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let config = std::sync::Arc::clone(&config);
                std::thread::spawn(move || {
                    if let Err(err) = handle_connection(stream, &config) {
                        eprintln!("request failed: {err:#}");
                    }
                });
            }
            Err(err) => eprintln!("connection failed: {err}"),
        }
    }
    Ok(())
}

struct ServerArgs {
    host: String,
    port: u16,
    open: bool,
}

impl ServerArgs {
    fn parse() -> Self {
        let mut host = "127.0.0.1".to_string();
        let mut port = 8777_u16;
        let mut open = false;
        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--host" => {
                    if let Some(value) = args.next() {
                        host = value;
                    }
                }
                "--port" => {
                    if let Some(value) = args.next().and_then(|value| value.parse().ok()) {
                        port = value;
                    }
                }
                "--open" => open = true,
                _ => {}
            }
        }
        Self { host, port, open }
    }
}

struct ServerConfig {
    default_case_path: String,
    default_evidence_path: String,
    default_vhd_sample_path: String,
    default_history_path: String,
    default_report_path: String,
    workspace_root: String,
}

impl ServerConfig {
    fn new() -> Result<Self> {
        let cwd = std::env::current_dir().context("reading current directory")?;
        let output = cwd.join("ui-output");
        Ok(Self {
            default_case_path: output
                .join("workbench.kdft.sqlite")
                .to_string_lossy()
                .into_owned(),
            default_evidence_path: cwd
                .join("testdata")
                .join("smoke-evidence")
                .to_string_lossy()
                .into_owned(),
            default_vhd_sample_path: output
                .join("fat-partition-smoke.vhd")
                .to_string_lossy()
                .into_owned(),
            default_history_path: default_history_path(),
            default_report_path: output
                .join("quick-report.html")
                .to_string_lossy()
                .into_owned(),
            workspace_root: cwd.to_string_lossy().into_owned(),
        })
    }
}

#[derive(Deserialize)]
struct CreateCaseRequest {
    case_path: String,
    name: String,
    examiner: Option<String>,
    case_number: Option<String>,
    case_type: Option<String>,
    description: Option<String>,
}

#[derive(Deserialize)]
struct AddEvidenceRequest {
    case_path: String,
    path: String,
    kind: Option<String>,
    read_file_system: Option<bool>,
    notes: Option<String>,
}

#[derive(Deserialize)]
struct ProcessEvidenceRequest {
    case_path: String,
    evidence_id: i64,
    max_entries: Option<usize>,
}

#[derive(Deserialize)]
struct AnalyzeSignaturesRequest {
    case_path: String,
    evidence_id: Option<i64>,
    max_entries: Option<usize>,
}

#[derive(Deserialize)]
struct RemoveEvidenceRequest {
    case_path: String,
    evidence_id: i64,
}

#[derive(Deserialize)]
struct CarveEvidenceRequest {
    case_path: String,
    evidence_id: i64,
    max_scan_bytes: Option<u64>,
    max_files: Option<usize>,
}

#[derive(Deserialize)]
struct RecoverEntryRequest {
    case_path: String,
    entry_id: i64,
    output_path: String,
}

#[derive(Deserialize)]
struct DeepSearchRequest {
    case_path: String,
    query: String,
    evidence_id: Option<i64>,
    include_content: Option<bool>,
    max_results: Option<usize>,
    max_file_bytes: Option<u64>,
    category: Option<String>,
    /// Comma-separated extensions, e.g. "jpg,png,zip".
    file_types: Option<String>,
}

#[derive(Deserialize)]
struct ImportHistoryRequest {
    case_path: String,
    history_path: String,
    max_visits: Option<usize>,
    evidence_name: Option<String>,
}

#[derive(Deserialize)]
struct QuickBookmarkRequest {
    case_path: String,
    folder_name: Option<String>,
    title: Option<String>,
    comment: Option<String>,
    bookmark_type: Option<String>,
    data_type: Option<String>,
    evidence_id: Option<i64>,
    entry_id: Option<i64>,
    display_name: Option<String>,
    logical_path: Option<String>,
    selection_offset: Option<i64>,
    selection_length: Option<i64>,
    data_preview: Option<String>,
    item_ref_json: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct ClearFindingsRequest {
    case_path: String,
}

#[derive(Deserialize)]
struct ExportReportRequest {
    case_path: String,
    output_path: String,
}

#[derive(Serialize)]
struct UiState {
    case: kdft_case::CaseInfo,
    evidence: Vec<kdft_case::EvidenceSource>,
    entries: Vec<kdft_case::FilesystemEntry>,
    entries_truncated: bool,
    entries_limit: usize,
    /// Exact per-category counts from SQL. Populated only when `entries` is
    /// truncated; otherwise the UI derives counts from the full entry list.
    category_counts: Vec<kdft_case::CategoryCount>,
    folders: Vec<kdft_case::BookmarkFolder>,
    bookmarks: Vec<kdft_case::Bookmark>,
    items: Vec<kdft_case::BookmarkItem>,
    entry_count: i64,
    report: kdft_case::ReportData,
}

#[derive(Serialize)]
struct FsListing {
    path: String,
    parent: Option<String>,
    roots: Vec<String>,
    entries: Vec<FsEntry>,
}

#[derive(Serialize)]
struct FsEntry {
    name: String,
    path: String,
    kind: String,
    size_bytes: Option<u64>,
}

#[derive(Serialize)]
struct PickResult {
    path: Option<String>,
}

#[derive(Serialize)]
struct QuickBookmarkResponse {
    folder_id: i64,
    bookmark_id: i64,
    item: kdft_case::BookmarkItem,
}

struct HttpRequest {
    method: String,
    target: String,
    body: Vec<u8>,
}

struct HttpResponse {
    status: u16,
    reason: &'static str,
    content_type: &'static str,
    body: Vec<u8>,
}

fn bind_listener(host: &str, port: u16) -> Result<(TcpListener, u16)> {
    for offset in 0..25_u16 {
        let candidate = port.saturating_add(offset);
        let addr = format!("{host}:{candidate}");
        if let Ok(listener) = TcpListener::bind(&addr) {
            return Ok((listener, candidate));
        }
    }
    bail!("could not bind local UI server starting at {host}:{port}");
}

fn handle_connection(mut stream: TcpStream, config: &ServerConfig) -> Result<()> {
    let request = read_http_request(&mut stream)?;
    let (path, query) = split_target(&request.target);
    if request.method == "GET" && path == "/api/pick" {
        // The native picker blocks until the examiner closes the dialog, so it
        // must not stall the single-threaded accept loop.
        std::thread::spawn(move || {
            let response = api_response(api_pick_path(&query));
            let _ = write_http_response(&mut stream, response);
        });
        return Ok(());
    }
    let response = route_request(&request, config);
    write_http_response(&mut stream, response)
}

fn read_http_request(stream: &mut TcpStream) -> Result<HttpRequest> {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    reader
        .read_line(&mut request_line)
        .context("reading HTTP request line")?;
    if request_line.trim().is_empty() {
        bail!("empty HTTP request");
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();
    let mut content_length = 0_usize;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).context("reading HTTP header")?;
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().unwrap_or(0);
            }
        }
    }
    let mut body = vec![0_u8; content_length];
    if content_length > 0 {
        reader
            .read_exact(&mut body)
            .context("reading HTTP request body")?;
    }
    Ok(HttpRequest {
        method,
        target,
        body,
    })
}

fn route_request(request: &HttpRequest, config: &ServerConfig) -> HttpResponse {
    let (path, query) = split_target(&request.target);
    match (request.method.as_str(), path.as_str()) {
        ("GET", "/") => html_response(index_html(config)),
        ("GET", "/api/health") => json_ok(json!({ "status": "ok" })),
        ("GET", "/api/fs/list") => api_response(api_fs_list(&query)),
        ("GET", "/api/image/volumes") => api_response(api_image_volumes(&query)),
        ("GET", "/api/image/dir") => api_response(api_image_dir(&query)),
        ("GET", "/api/image/bytes") => api_response(api_image_bytes(&query)),
        ("POST", "/api/image/export") => api_response(api_image_export(&request.body)),
        ("POST", "/api/image/export-tree") => api_response(api_image_export_tree(&request.body)),
        ("GET", "/api/entries/dir") => api_response(api_entries_dir(&query)),
        ("GET", "/api/state") => api_response(api_state(&query)),
        ("GET", "/api/entry/bytes") => api_response(api_entry_bytes(&query)),
        ("GET", "/api/entry/raw") => match api_entry_raw(&query) {
            Ok((content_type, body)) => HttpResponse {
                status: 200,
                reason: "OK",
                content_type,
                body,
            },
            Err(err) => json_error(400, &format!("{err:#}")),
        },
        ("GET", "/api/image/raw") => match api_image_raw(&query) {
            Ok((content_type, body)) => HttpResponse {
                status: 200,
                reason: "OK",
                content_type,
                body,
            },
            Err(err) => json_error(400, &format!("{err:#}")),
        },
        ("POST", "/api/case/create") => api_response(api_create_case(&request.body)),
        ("POST", "/api/evidence/add") => api_response(api_add_evidence(&request.body)),
        ("POST", "/api/evidence/remove") => api_response(api_remove_evidence(&request.body)),
        ("POST", "/api/evidence/hash") => api_response(api_hash_evidence(&request.body)),
        ("POST", "/api/evidence/carve") => api_response(api_carve_evidence(&request.body)),
        ("POST", "/api/evidence/process") => api_response(api_process_evidence(&request.body)),
        ("POST", "/api/evidence/analyze-signatures") => {
            api_response(api_analyze_signatures(&request.body))
        }
        ("POST", "/api/entry/recover") => api_response(api_recover_entry(&request.body)),
        ("POST", "/api/history/import") => api_response(api_import_history(&request.body)),
        ("POST", "/api/search/deep") => api_response(api_deep_search(&request.body)),
        ("POST", "/api/bookmark/quick") => api_response(api_quick_bookmark(&request.body)),
        ("POST", "/api/findings/clear") => api_response(api_clear_findings(&request.body)),
        ("POST", "/api/report/export") => api_response(api_export_report(&request.body)),
        ("POST", "/api/report/open") => api_response(api_open_report(&request.body)),
        ("GET", "/favicon.ico") => HttpResponse {
            status: 204,
            reason: "No Content",
            content_type: "text/plain; charset=utf-8",
            body: Vec::new(),
        },
        _ => json_error(404, "not found"),
    }
}

fn api_state(query: &HashMap<String, String>) -> Result<UiState> {
    let case_path = query
        .get("case_path")
        .map(String::as_str)
        .context("case_path query parameter is required")
        .and_then(|value| request_path(value, "case_path"))?;
    // Loading state is a pure read: no stale-finding cleanup here (it writes and
    // ran on every refresh); cleanup happens on bookmark/process actions.
    // Cap entries shipped to the browser. Loading hundreds of thousands of
    // entries into one page hangs it; beyond the cap the examiner uses Live
    // browse (reads the image directly) or Deep Search.
    const STATE_ENTRY_LIMIT: usize = 5000;
    let entry_count = filesystem_entry_count(&case_path)?;
    let entries = list_filesystem_entries_limited(&case_path, None, Some(STATE_ENTRY_LIMIT))?;
    let entries_truncated = entry_count as usize > entries.len();
    let category_counts = if entries_truncated {
        cached_category_counts(&case_path, entry_count)?
    } else {
        Vec::new()
    };
    Ok(UiState {
        case: case_info(&case_path)?,
        evidence: list_evidence(&case_path)?,
        entries,
        entries_truncated,
        entries_limit: STATE_ENTRY_LIMIT,
        category_counts,
        folders: list_bookmark_folders(&case_path)?,
        bookmarks: list_bookmarks(&case_path)?,
        items: list_bookmark_items(&case_path, None)?,
        entry_count,
        report: report_data(&case_path)?,
    })
}

/// Cached exact category counts for large (truncated) cases. The SQL GROUP BY
/// scans every row's metadata_json (~2s on a 360k-entry case), so the result is
/// cached per case path and invalidated when (entry_count, max_id) changes -
/// entries only change through process/import/carve jobs, which always insert
/// fresh ids.
fn cached_category_counts(
    case_path: &Path,
    entry_count: i64,
) -> Result<Vec<kdft_case::CategoryCount>> {
    struct CacheEntry {
        entry_count: i64,
        max_entry_id: i64,
        counts: Vec<kdft_case::CategoryCount>,
    }
    static CACHE: std::sync::OnceLock<std::sync::Mutex<HashMap<PathBuf, CacheEntry>>> =
        std::sync::OnceLock::new();
    let cache = CACHE.get_or_init(|| std::sync::Mutex::new(HashMap::new()));
    let max_entry_id = max_filesystem_entry_id(case_path)?;
    if let Ok(guard) = cache.lock() {
        if let Some(entry) = guard.get(case_path) {
            if entry.entry_count == entry_count && entry.max_entry_id == max_entry_id {
                return Ok(entry.counts.clone());
            }
        }
    }
    let counts = category_entry_counts(case_path)?;
    if let Ok(mut guard) = cache.lock() {
        guard.insert(
            case_path.to_path_buf(),
            CacheEntry {
                entry_count,
                max_entry_id,
                counts: counts.clone(),
            },
        );
    }
    Ok(counts)
}

fn api_entry_bytes(query: &HashMap<String, String>) -> Result<kdft_case::EntryBytes> {
    let case_path = query
        .get("case_path")
        .map(String::as_str)
        .context("case_path query parameter is required")
        .and_then(|value| request_path(value, "case_path"))?;
    let entry_id = query_i64(query, "entry_id")?;
    let offset = query_u64(query, "offset")?.unwrap_or(0);
    let length = query_usize(query, "length")?.unwrap_or(512);
    read_filesystem_entry_bytes(
        &case_path,
        ReadEntryBytesOptions {
            entry_id,
            offset,
            length,
        },
    )
}

/// Bounded raw preview used by the picture thumbnail grid. Serves the entry's leading bytes
/// with a sniffed image content type; refuses entries that do not start with a known image
/// signature so this endpoint cannot be used to dump arbitrary evidence bytes to the browser.
const RAW_PREVIEW_DEFAULT_BYTES: usize = 2 * 1024 * 1024;
const RAW_PREVIEW_MAX_BYTES: usize = 8 * 1024 * 1024;

fn api_entry_raw(query: &HashMap<String, String>) -> Result<(&'static str, Vec<u8>)> {
    let case_path = query
        .get("case_path")
        .map(String::as_str)
        .context("case_path query parameter is required")
        .and_then(|value| request_path(value, "case_path"))?;
    let entry_id = query_i64(query, "entry_id")?;
    let length = query_usize(query, "length")?
        .unwrap_or(RAW_PREVIEW_DEFAULT_BYTES)
        .min(RAW_PREVIEW_MAX_BYTES);
    let data = read_filesystem_entry_bytes(
        &case_path,
        ReadEntryBytesOptions {
            entry_id,
            offset: 0,
            length,
        },
    )?;
    let content_type = detect_image_content_type(&data.bytes)
        .context("entry does not start with a supported image signature")?;
    Ok((content_type, data.bytes))
}

/// Live-browse variant of /api/entry/raw: decode one file straight from an
/// attached disk image volume and serve it as an image. Same signature
/// sniffing as the indexed endpoint, so it cannot dump arbitrary bytes.
fn api_image_raw(query: &HashMap<String, String>) -> Result<(&'static str, Vec<u8>)> {
    let image_path = evidence_image_path(query)?;
    let volume_index: usize = query
        .get("volume")
        .context("volume query parameter is required")?
        .parse()
        .context("volume must be an integer")?;
    let path = query
        .get("path")
        .context("path query parameter is required")?;
    let length = query_usize(query, "length")?
        .unwrap_or(RAW_PREVIEW_MAX_BYTES)
        .min(RAW_PREVIEW_MAX_BYTES);
    let (bytes, _total_size) =
        kdft_case::read_image_directory_bytes(&image_path, volume_index, path, 0, length)?;
    let content_type = detect_image_content_type(&bytes)
        .context("live file does not start with a supported image signature")?;
    Ok((content_type, bytes))
}

fn detect_image_content_type(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some("image/jpeg")
    } else if bytes.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]) {
        Some("image/png")
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        Some("image/gif")
    } else if bytes.starts_with(b"BM") {
        Some("image/bmp")
    } else if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP" {
        Some("image/webp")
    } else if bytes.starts_with(&[0x00, 0x00, 0x01, 0x00]) {
        Some("image/x-icon")
    } else {
        None
    }
}

fn evidence_image_path(query: &HashMap<String, String>) -> Result<PathBuf> {
    let case_path = query
        .get("case_path")
        .map(String::as_str)
        .context("case_path query parameter is required")
        .and_then(|value| request_path(value, "case_path"))?;
    let evidence_id: i64 = query
        .get("evidence_id")
        .context("evidence_id query parameter is required")?
        .parse()
        .context("evidence_id must be an integer")?;
    let evidence = list_evidence(&case_path)?;
    let source = evidence
        .iter()
        .find(|item| item.id == evidence_id)
        .with_context(|| format!("evidence {evidence_id} not found"))?;
    if source.source_kind != "image" {
        bail!("live browsing is only available for disk-image evidence");
    }
    Ok(PathBuf::from(&source.source_path))
}

fn api_image_volumes(query: &HashMap<String, String>) -> Result<serde_json::Value> {
    let image_path = evidence_image_path(query)?;
    let volumes = kdft_case::list_image_volumes(&image_path)?;
    Ok(json!({ "volumes": volumes }))
}

fn api_image_dir(query: &HashMap<String, String>) -> Result<serde_json::Value> {
    let image_path = evidence_image_path(query)?;
    let volume_index: usize = query
        .get("volume")
        .context("volume query parameter is required")?
        .parse()
        .context("volume must be an integer")?;
    let path = query.get("path").map(String::as_str).unwrap_or("/");
    let entries = kdft_case::list_image_directory(&image_path, volume_index, path)?;
    Ok(json!({ "entries": entries }))
}

#[derive(Deserialize)]
struct LiveExportRequest {
    case_path: String,
    evidence_id: i64,
    volume: usize,
    path: String,
    output_path: String,
}

fn api_image_export(body: &[u8]) -> Result<kdft_case::LiveExportResult> {
    let request: LiveExportRequest = parse_json_body(body)?;
    let case_path = request_path(&request.case_path, "case_path")?;
    let output_path = request_path(&request.output_path, "output_path")?;
    let mut query = HashMap::new();
    query.insert("case_path".to_string(), request.case_path.clone());
    query.insert("evidence_id".to_string(), request.evidence_id.to_string());
    let image_path = evidence_image_path(&query)?;
    let result = export_image_file(&image_path, request.volume, &request.path, &output_path)?;
    record_live_export(
        &case_path,
        request.evidence_id,
        request.volume,
        &request.path,
        &result,
    )?;
    Ok(result)
}

#[derive(Deserialize)]
struct LiveTreeExportRequest {
    case_path: String,
    evidence_id: i64,
    volume: usize,
    path: String,
    output_dir: String,
    max_files: Option<usize>,
}

fn api_image_export_tree(body: &[u8]) -> Result<kdft_case::LiveTreeExportResult> {
    let request: LiveTreeExportRequest = parse_json_body(body)?;
    let case_path = request_path(&request.case_path, "case_path")?;
    let output_dir = request_path(&request.output_dir, "output_dir")?;
    let mut query = HashMap::new();
    query.insert("case_path".to_string(), request.case_path.clone());
    query.insert("evidence_id".to_string(), request.evidence_id.to_string());
    let image_path = evidence_image_path(&query)?;
    let result = export_image_tree(
        &image_path,
        request.volume,
        &request.path,
        &output_dir,
        request.max_files,
    )?;
    record_live_tree_export(
        &case_path,
        request.evidence_id,
        request.volume,
        &request.path,
        &result,
    )?;
    Ok(result)
}

fn api_image_bytes(query: &HashMap<String, String>) -> Result<serde_json::Value> {
    let image_path = evidence_image_path(query)?;
    let volume_index: usize = query
        .get("volume")
        .context("volume query parameter is required")?
        .parse()
        .context("volume must be an integer")?;
    let path = query
        .get("path")
        .context("path query parameter is required")?;
    let offset = query_u64(query, "offset")?.unwrap_or(0);
    let length = query
        .get("length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(512);
    let (bytes, total_size) =
        kdft_case::read_image_directory_bytes(&image_path, volume_index, path, offset, length)?;
    let bytes_read = bytes.len();
    Ok(json!({
        "logical_path": path,
        "offset": offset,
        "requested_length": length,
        "bytes_read": bytes_read,
        "total_size": total_size,
        "eof": offset.saturating_add(bytes_read as u64) >= total_size,
        "bytes": bytes,
    }))
}

fn api_entries_dir(query: &HashMap<String, String>) -> Result<kdft_case::IndexedDirectory> {
    let case_path = query
        .get("case_path")
        .map(String::as_str)
        .context("case_path query parameter is required")
        .and_then(|value| request_path(value, "case_path"))?;
    let evidence_id: i64 = query
        .get("evidence_id")
        .context("evidence_id query parameter is required")?
        .parse()
        .context("evidence_id must be an integer")?;
    let path = query.get("path").map(String::as_str).unwrap_or("/");
    let limit = query
        .get("limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(10_000);
    kdft_case::list_indexed_directory(&case_path, evidence_id, path, limit)
}

fn api_fs_list(query: &HashMap<String, String>) -> Result<FsListing> {
    let requested = match query.get("path").map(String::as_str) {
        Some(value) if !value.trim().is_empty() => request_path(value, "path")?,
        _ => std::env::current_dir().context("reading current directory")?,
    };
    let mut path = requested.clone();
    if path.is_file() {
        path = path
            .parent()
            .map(Path::to_path_buf)
            .with_context(|| format!("path has no parent: {}", requested.display()))?;
    }
    if !path.exists() {
        bail!("path does not exist: {}", path.display());
    }
    if !path.is_dir() {
        bail!("path is not a directory: {}", path.display());
    }

    let display_path = path.to_string_lossy().into_owned();
    let parent = path
        .parent()
        .map(|parent| parent.to_string_lossy().into_owned());
    let mut entries = Vec::new();
    for entry in
        fs::read_dir(&path).with_context(|| format!("reading directory {}", path.display()))?
    {
        let entry = entry.with_context(|| format!("reading entry in {}", path.display()))?;
        let entry_path = entry.path();
        let metadata = match fs::symlink_metadata(&entry_path) {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        let file_type = metadata.file_type();
        let kind = if file_type.is_dir() {
            "directory"
        } else if file_type.is_file() {
            "file"
        } else if file_type.is_symlink() {
            "symlink"
        } else {
            "other"
        };
        let name = entry.file_name().to_string_lossy().trim().to_string();
        entries.push(FsEntry {
            name: if name.is_empty() {
                "(unnamed)".to_string()
            } else {
                name
            },
            path: entry_path.to_string_lossy().into_owned(),
            kind: kind.to_string(),
            size_bytes: if file_type.is_file() {
                Some(metadata.len())
            } else {
                None
            },
        });
    }
    entries.sort_by(|left, right| {
        let left_rank = if left.kind == "directory" { 0 } else { 1 };
        let right_rank = if right.kind == "directory" { 0 } else { 1 };
        left_rank
            .cmp(&right_rank)
            .then_with(|| left.name.to_lowercase().cmp(&right.name.to_lowercase()))
    });

    Ok(FsListing {
        path: display_path,
        parent,
        roots: filesystem_roots(),
        entries,
    })
}

static PICK_DIALOG_OPEN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn api_pick_path(query: &HashMap<String, String>) -> Result<PickResult> {
    let mode = query.get("mode").map(String::as_str).unwrap_or("file");
    if mode != "file" && mode != "folder" {
        bail!("mode must be file or folder");
    }
    let filter = query.get("filter").map(String::as_str).unwrap_or("any");
    let start = query.get("start").map(String::as_str).unwrap_or("");
    if PICK_DIALOG_OPEN.swap(true, std::sync::atomic::Ordering::SeqCst) {
        bail!("a browse dialog is already open; finish or cancel it first");
    }
    let result = run_native_pick_dialog(mode, filter, start);
    PICK_DIALOG_OPEN.store(false, std::sync::atomic::Ordering::SeqCst);
    result.map(|path| PickResult { path })
}

#[cfg(windows)]
fn run_native_pick_dialog(mode: &str, filter: &str, start: &str) -> Result<Option<String>> {
    use std::os::windows::process::CommandExt;

    let ps_filter = match filter {
        "image" => {
            let patterns =
                "*.E01;*.EX01;*.L01;*.dd;*.raw;*.img;*.001;*.vhd;*.vhdx;*.vmdk;*.vdi;*.iso";
            format!("Disk images ({patterns})|{patterns}|All files (*.*)|*.*")
        }
        _ => "All files (*.*)|*.*".to_string(),
    };
    // Single-quoted PowerShell strings only terminate on a quote; doubling
    // embedded quotes and dropping control characters keeps the value inert.
    let ps_start = start
        .chars()
        .filter(|ch| !ch.is_control())
        .collect::<String>()
        .replace('\'', "''");
    let dialog_body = if mode == "folder" {
        // OpenFileDialog with a placeholder file name doubles as a modern
        // Explorer folder picker; FolderBrowserDialog on .NET Framework is the
        // legacy tree control.
        r#"$dialog.Title = 'Select folder - open the folder, then press Open'
$dialog.ValidateNames = $false
$dialog.CheckFileExists = $false
$dialog.CheckPathExists = $true
$dialog.FileName = 'Select this folder'
$dialog.AddExtension = $false
$dialog.Filter = 'Folders|*.kdft-folder-picker'"#
            .to_string()
    } else {
        format!(
            "$dialog.Title = 'Select evidence file'\n$dialog.CheckFileExists = $true\n$dialog.Filter = '{ps_filter}'"
        )
    };
    let script = format!(
        r#"[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Add-Type -AssemblyName System.Windows.Forms | Out-Null
$dialog = New-Object System.Windows.Forms.OpenFileDialog
$dialog.RestoreDirectory = $true
{dialog_body}
$start = '{ps_start}'
if ($start) {{
  if (Test-Path -LiteralPath $start -PathType Container) {{ $dialog.InitialDirectory = $start }}
  else {{
    $parent = $null
    try {{ $parent = Split-Path -Path $start -Parent }} catch {{}}
    if ($parent -and (Test-Path -LiteralPath $parent -PathType Container)) {{ $dialog.InitialDirectory = $parent }}
  }}
}}
$owner = New-Object System.Windows.Forms.Form
$owner.TopMost = $true
$owner.ShowInTaskbar = $false
$owner.StartPosition = 'CenterScreen'
$owner.Size = New-Object System.Drawing.Size(1, 1)
$owner.Add_Shown({{ $owner.Activate(); $owner.BringToFront() }})
$owner.Show()
$result = $dialog.ShowDialog($owner)
$owner.Dispose()
if ($result -eq [System.Windows.Forms.DialogResult]::OK) {{
  $picked = $dialog.FileName
  if ('{mode}' -eq 'folder') {{ $picked = [System.IO.Path]::GetDirectoryName($picked) }}
  [Console]::Out.Write($picked)
}}
"#
    );
    let script_path = std::env::temp_dir().join(format!("kdft-pick-{}.ps1", std::process::id()));
    fs::write(&script_path, script).context("writing picker script")?;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let output = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-STA",
            "-WindowStyle",
            "Hidden",
            "-File",
        ])
        .arg(&script_path)
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    let _ = fs::remove_file(&script_path);
    let output = output.context("launching Windows file dialog")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("file dialog failed: {}", stderr.trim());
    }
    let picked = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if picked.is_empty() {
        Ok(None)
    } else {
        Ok(Some(picked))
    }
}

#[cfg(not(windows))]
fn run_native_pick_dialog(_mode: &str, _filter: &str, _start: &str) -> Result<Option<String>> {
    bail!("native browse is only available on Windows in this build; type the path manually")
}

fn filesystem_roots() -> Vec<String> {
    #[cfg(target_os = "windows")]
    {
        ('A'..='Z')
            .filter_map(|letter| {
                let root = format!("{letter}:\\");
                if Path::new(&root).exists() {
                    Some(root)
                } else {
                    None
                }
            })
            .collect()
    }
    #[cfg(not(target_os = "windows"))]
    {
        vec!["/".to_string()]
    }
}

fn default_history_path() -> String {
    let mut candidates = Vec::new();
    if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
        let local_app_data = PathBuf::from(local_app_data);
        candidates.push(
            local_app_data
                .join("Google")
                .join("Chrome")
                .join("User Data")
                .join("Default")
                .join("History"),
        );
        candidates.push(
            local_app_data
                .join("Microsoft")
                .join("Edge")
                .join("User Data")
                .join("Default")
                .join("History"),
        );
    }
    candidates
        .into_iter()
        .find(|path| path.is_file())
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn api_create_case(body: &[u8]) -> Result<serde_json::Value> {
    let request: CreateCaseRequest = parse_json_body(body)?;
    let case_path = request_path(&request.case_path, "case_path")?;
    let case_id = create_case(
        &case_path,
        CreateCaseOptions {
            name: non_empty(request.name, "name")?,
            examiner_name: request.examiner,
            case_number: request.case_number,
            case_type: request.case_type,
            description: request.description,
            default_export_folder: None,
            temporary_folder: None,
            index_folder: None,
        },
    )?;
    Ok(json!({ "case_id": case_id, "case": case_path }))
}

fn api_add_evidence(body: &[u8]) -> Result<serde_json::Value> {
    let request: AddEvidenceRequest = parse_json_body(body)?;
    let case_path = request_path(&request.case_path, "case_path")?;
    let evidence_path = request_path(&request.path, "path")?;
    let kind = EvidenceKind::parse(request.kind.as_deref().unwrap_or("auto"))?;
    let evidence_id = add_evidence(
        &case_path,
        AddEvidenceOptions {
            path: evidence_path,
            kind,
            read_file_system_requested: request.read_file_system.unwrap_or(true),
            notes: request.notes,
        },
    )?;
    Ok(json!({
        "evidence_id": evidence_id,
        // Add-evidence only inserts an evidence_sources row; it never creates filesystem_entries
        // for the new source (that happens in a later explicit process step), so this is always 0.
        // Previously reported the case-wide entry count, which was misleading once a case has more
        // than one evidence source.
        "filesystem_entries": 0,
        "indexed": false
    }))
}

fn api_process_evidence(body: &[u8]) -> Result<kdft_case::ProcessEvidenceResult> {
    let request: ProcessEvidenceRequest = parse_json_body(body)?;
    let case_path = request_path(&request.case_path, "case_path")?;
    process_evidence(
        &case_path,
        ProcessEvidenceOptions {
            evidence_id: request.evidence_id,
            // 0 = index everything (kdft-case treats it as unlimited).
            max_entries: request.max_entries.unwrap_or(0),
        },
    )
}

fn api_analyze_signatures(body: &[u8]) -> Result<kdft_case::AnalyzeSignaturesResult> {
    let request: AnalyzeSignaturesRequest = parse_json_body(body)?;
    let case_path = request_path(&request.case_path, "case_path")?;
    analyze_signatures(
        &case_path,
        AnalyzeSignaturesOptions {
            evidence_id: request.evidence_id,
            max_entries: request.max_entries.unwrap_or(100_000),
        },
    )
}

fn api_remove_evidence(body: &[u8]) -> Result<kdft_case::RemoveEvidenceResult> {
    let request: RemoveEvidenceRequest = parse_json_body(body)?;
    let case_path = request_path(&request.case_path, "case_path")?;
    remove_evidence(&case_path, request.evidence_id)
}

fn api_hash_evidence(body: &[u8]) -> Result<kdft_case::HashEvidenceResult> {
    let request: RemoveEvidenceRequest = parse_json_body(body)?;
    let case_path = request_path(&request.case_path, "case_path")?;
    hash_evidence(&case_path, request.evidence_id)
}

fn api_carve_evidence(body: &[u8]) -> Result<kdft_case::CarveResult> {
    let request: CarveEvidenceRequest = parse_json_body(body)?;
    let case_path = request_path(&request.case_path, "case_path")?;
    carve_evidence(
        &case_path,
        request.evidence_id,
        CarveOptions {
            max_scan_bytes: request.max_scan_bytes.unwrap_or(0),
            max_files: request.max_files.unwrap_or(1000),
        },
    )
}

fn api_recover_entry(body: &[u8]) -> Result<kdft_case::RecoverEntryResult> {
    let request: RecoverEntryRequest = parse_json_body(body)?;
    let case_path = request_path(&request.case_path, "case_path")?;
    let output_path = request_path(&request.output_path, "output_path")?;
    recover_filesystem_entry(
        &case_path,
        RecoverEntryOptions {
            entry_id: request.entry_id,
            output_path,
        },
    )
}

fn api_import_history(body: &[u8]) -> Result<kdft_case::BrowserHistoryImportResult> {
    let request: ImportHistoryRequest = parse_json_body(body)?;
    let case_path = request_path(&request.case_path, "case_path")?;
    let history_path = request_path(&request.history_path, "history_path")?;
    import_chromium_history(
        &case_path,
        ImportBrowserHistoryOptions {
            history_path,
            max_visits: request.max_visits.unwrap_or(5000),
            evidence_name: request.evidence_name,
        },
    )
}

fn api_deep_search(body: &[u8]) -> Result<Vec<kdft_case::DeepSearchResult>> {
    let request: DeepSearchRequest = parse_json_body(body)?;
    let case_path = request_path(&request.case_path, "case_path")?;
    deep_search(
        &case_path,
        DeepSearchOptions {
            query: request.query,
            evidence_id: request.evidence_id,
            include_content: request.include_content.unwrap_or(true),
            max_results: request.max_results.unwrap_or(50),
            max_file_bytes: request.max_file_bytes.unwrap_or(64 * 1024),
            category: request.category.filter(|value| !value.trim().is_empty()),
            file_types: request
                .file_types
                .map(|value| {
                    value
                        .split(',')
                        .map(str::trim)
                        .filter(|part| !part.is_empty())
                        .map(str::to_string)
                        .collect::<Vec<_>>()
                })
                .filter(|list| !list.is_empty()),
        },
    )
}

fn api_quick_bookmark(body: &[u8]) -> Result<QuickBookmarkResponse> {
    let request: QuickBookmarkRequest = parse_json_body(body)?;
    let case_path = request_path(&request.case_path, "case_path")?;
    let folder_name = request
        .folder_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("Findings");
    let folder_id = ensure_report_folder(&case_path, folder_name)?;
    let item_ref_json = request.item_ref_json.unwrap_or_else(|| json!({}));
    if !item_ref_json.is_object() {
        bail!("item_ref_json must be a JSON object");
    }
    let title = request
        .title
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("Bookmarked evidence")
        .to_string();
    let bookmark_type = BookmarkType::parse(
        request
            .bookmark_type
            .as_deref()
            .unwrap_or("highlighted_data"),
    )?;
    let data_type = request
        .data_type
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("Search Hit")
        .to_string();
    let source_ref_json = json!({
        "evidence_id": request.evidence_id,
        "entry_id": request.entry_id,
        "logical_path": request.logical_path,
    });
    let content_ref_json = json!({
        "selection_offset": request.selection_offset,
        "selection_length": request.selection_length,
        "preview": request.data_preview,
    });
    let bookmark_id = create_bookmark(
        &case_path,
        CreateBookmarkOptions {
            folder_id,
            bookmark_type,
            data_type: Some(data_type),
            title: Some(title),
            examiner_comment: request.comment,
            in_report: true,
            source_ref_json,
            content_ref_json,
        },
    )?;
    let item = add_bookmark_item(
        &case_path,
        CreateBookmarkItemOptions {
            bookmark_id,
            evidence_id: request.evidence_id,
            entry_id: request.entry_id,
            item_order: None,
            display_name: request.display_name,
            logical_path: request.logical_path,
            selection_offset: request.selection_offset,
            selection_length: request.selection_length,
            data_preview: request.data_preview,
            item_ref_json,
        },
    )?;
    Ok(QuickBookmarkResponse {
        folder_id,
        bookmark_id,
        item,
    })
}

fn api_clear_findings(body: &[u8]) -> Result<kdft_case::ClearStaleFindingsResult> {
    let request: ClearFindingsRequest = parse_json_body(body)?;
    let case_path = request_path(&request.case_path, "case_path")?;
    clear_all_findings(&case_path)
}

const REPORT_DIRECTORY_TREE_MAX_LINES: usize = 2000;

fn api_export_report(body: &[u8]) -> Result<serde_json::Value> {
    let request: ExportReportRequest = parse_json_body(body)?;
    let case_path = request_path(&request.case_path, "case_path")?;
    let output_path = request_path(&request.output_path, "output_path")?;
    let report = report_data_with_directory_structure(&case_path, REPORT_DIRECTORY_TREE_MAX_LINES)?;
    let rendered = render_report(&report);
    if let Some(parent) = output_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating report directory {}", parent.display()))?;
    }
    fs::write(&output_path, &rendered.html)
        .with_context(|| format!("writing report {}", output_path.display()))?;
    record_report_export(&case_path, &output_path.to_string_lossy(), &rendered.sha256)?;
    Ok(json!({
        "report": output_path,
        "folders": report.folders.len(),
        "sha256": rendered.sha256
    }))
}

fn api_open_report(body: &[u8]) -> Result<serde_json::Value> {
    let request: ExportReportRequest = parse_json_body(body)?;
    let output_path = request_path(&request.output_path, "output_path")?;
    open_target(&output_path.to_string_lossy())?;
    Ok(json!({ "opened": output_path }))
}

fn ensure_report_folder(case_path: &PathBuf, folder_name: &str) -> Result<i64> {
    let folders = list_bookmark_folders(case_path)?;
    if let Some(folder) = folders
        .iter()
        .find(|folder| folder.parent_id.is_none() && folder.name == folder_name)
    {
        return Ok(folder.id);
    }
    create_bookmark_folder(case_path, None, folder_name, None, true)
}

fn parse_json_body<T: DeserializeOwned>(body: &[u8]) -> Result<T> {
    if body.is_empty() {
        bail!("request body is required");
    }
    serde_json::from_slice(body).context("parsing request JSON")
}

fn request_path(value: &str, field: &str) -> Result<PathBuf> {
    let trimmed = trim_balanced_path_quotes(value);
    if trimmed.is_empty() {
        bail!("{field} is required");
    }
    Ok(PathBuf::from(trimmed))
}

fn trim_balanced_path_quotes(value: &str) -> String {
    let mut trimmed = value.trim();
    loop {
        let Some(first) = trimmed.chars().next() else {
            return String::new();
        };
        let Some(last) = trimmed.chars().next_back() else {
            return String::new();
        };
        let matching = matches!(
            (first, last),
            ('"', '"') | ('\'', '\'') | ('\u{201c}', '\u{201d}') | ('\u{2018}', '\u{2019}')
        );
        if !matching || trimmed.len() < first.len_utf8() + last.len_utf8() {
            break;
        }
        trimmed = trimmed[first.len_utf8()..trimmed.len() - last.len_utf8()].trim();
    }
    trimmed.to_string()
}

#[cfg(test)]
mod tests {
    use super::trim_balanced_path_quotes;

    #[test]
    fn path_quote_trimming_accepts_pasted_windows_paths() {
        assert_eq!(
            trim_balanced_path_quotes(r#"  "C:\Users\xt\Downloads\case file.E01"  "#),
            r#"C:\Users\xt\Downloads\case file.E01"#
        );
        assert_eq!(
            trim_balanced_path_quotes("'C:/Users/xt/Downloads/case file.E01'"),
            "C:/Users/xt/Downloads/case file.E01"
        );
        assert_eq!(
            trim_balanced_path_quotes(r#"C:\Users\xt\Downloads\case file.E01"#),
            r#"C:\Users\xt\Downloads\case file.E01"#
        );
    }
}

fn query_i64(query: &HashMap<String, String>, field: &str) -> Result<i64> {
    query
        .get(field)
        .with_context(|| format!("{field} query parameter is required"))?
        .parse::<i64>()
        .with_context(|| format!("parsing {field}"))
}

fn query_u64(query: &HashMap<String, String>, field: &str) -> Result<Option<u64>> {
    query
        .get(field)
        .map(|value| {
            value
                .parse::<u64>()
                .with_context(|| format!("parsing {field}"))
        })
        .transpose()
}

fn query_usize(query: &HashMap<String, String>, field: &str) -> Result<Option<usize>> {
    query
        .get(field)
        .map(|value| {
            value
                .parse::<usize>()
                .with_context(|| format!("parsing {field}"))
        })
        .transpose()
}

fn non_empty(value: String, field: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("{field} cannot be empty");
    }
    Ok(trimmed.to_string())
}

fn split_target(target: &str) -> (String, HashMap<String, String>) {
    let (path, query_string) = target.split_once('?').unwrap_or((target, ""));
    let mut query = HashMap::new();
    for pair in query_string.split('&').filter(|part| !part.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        query.insert(url_decode(key), url_decode(value));
    }
    (path.to_string(), query)
}

fn url_decode(value: &str) -> String {
    let mut bytes = Vec::with_capacity(value.len());
    let mut chars = value.as_bytes().iter().copied();
    while let Some(ch) = chars.next() {
        match ch {
            b'+' => bytes.push(b' '),
            b'%' => {
                let hi = chars.next();
                let lo = chars.next();
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    if let (Some(hi), Some(lo)) = (hex_value(hi), hex_value(lo)) {
                        bytes.push((hi << 4) | lo);
                    }
                }
            }
            _ => bytes.push(ch),
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn json_ok<T: Serialize>(value: T) -> HttpResponse {
    let body = serde_json::to_vec(&json!({ "ok": true, "data": value }))
        .unwrap_or_else(|_| b"{\"ok\":false,\"error\":\"serialization failed\"}".to_vec());
    HttpResponse {
        status: 200,
        reason: "OK",
        content_type: "application/json; charset=utf-8",
        body,
    }
}

fn api_response<T: Serialize>(result: Result<T>) -> HttpResponse {
    match result {
        Ok(value) => json_ok(value),
        Err(err) => json_error(400, &err.to_string()),
    }
}

fn json_error(status: u16, message: &str) -> HttpResponse {
    let reason = match status {
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "Error",
    };
    let body = serde_json::to_vec(&json!({ "ok": false, "error": message }))
        .unwrap_or_else(|_| b"{\"ok\":false,\"error\":\"serialization failed\"}".to_vec());
    HttpResponse {
        status,
        reason,
        content_type: "application/json; charset=utf-8",
        body,
    }
}

fn html_response(html: String) -> HttpResponse {
    HttpResponse {
        status: 200,
        reason: "OK",
        content_type: "text/html; charset=utf-8",
        body: html.into_bytes(),
    }
}

fn write_http_response(stream: &mut TcpStream, response: HttpResponse) -> Result<()> {
    write!(
        stream,
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.status,
        response.reason,
        response.content_type,
        response.body.len()
    )
    .context("writing HTTP response headers")?;
    stream
        .write_all(&response.body)
        .context("writing HTTP response body")
}

fn open_target(target: &str) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        Command::new("cmd")
            .args(["/C", "start", "", target])
            .spawn()
            .context("opening target")?;
    }
    #[cfg(target_os = "macos")]
    {
        Command::new("open")
            .arg(target)
            .spawn()
            .context("opening target")?;
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        Command::new("xdg-open")
            .arg(target)
            .spawn()
            .context("opening target")?;
    }
    Ok(())
}

fn index_html(config: &ServerConfig) -> String {
    let bootstrap = json!({
        "defaultCasePath": config.default_case_path,
        "defaultEvidencePath": config.default_evidence_path,
        "defaultVhdSamplePath": config.default_vhd_sample_path,
        "defaultHistoryPath": config.default_history_path,
        "defaultReportPath": config.default_report_path,
        "workspaceRoot": config.workspace_root,
    });
    INDEX_HTML.replace("__KDFT_BOOTSTRAP__", &bootstrap.to_string())
}

const INDEX_HTML: &str = r###"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>KDFT Workbench</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #eef2ee;
      --surface: #ffffff;
      --surface-2: #f7f9f8;
      --text: #1c2526;
      --muted: #657271;
      --line: #d6dfdc;
      --accent: #0b6f63;
      --accent-2: #8c3f21;
      --warn: #b7791f;
      --bad: #b42318;
      --shadow: 0 18px 48px rgba(27, 38, 38, 0.10);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      font-family: "Segoe UI", Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
    }
    body.analysis-fullscreen {
      background: #fff;
    }
    body.viewer-fullscreen {
      overflow: hidden;
    }
    button, input, select, textarea { font: inherit; }
    button {
      border: 0;
      border-radius: 6px;
      background: var(--accent);
      color: #fff;
      cursor: pointer;
      font-weight: 650;
      min-height: 36px;
      padding: 8px 12px;
    }
    button.secondary {
      background: #253230;
    }
    button.ghost {
      background: transparent;
      color: var(--accent);
      border: 1px solid var(--line);
    }
    button.ghost.danger {
      color: var(--bad);
      border-color: rgba(180,35,24,.35);
    }
    button:disabled {
      cursor: not-allowed;
      opacity: .45;
    }
    input, select, textarea {
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #fff;
      color: var(--text);
      min-height: 36px;
      padding: 8px 10px;
    }
    input[type="checkbox"] {
      width: 17px;
      height: 17px;
      min-height: 17px;
      padding: 0;
      margin: 0;
      vertical-align: middle;
    }
    textarea { min-height: 70px; resize: vertical; }
    label {
      display: grid;
      gap: 6px;
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
    }
    .app {
      display: grid;
      grid-template-columns: minmax(300px, 360px) 1fr;
      min-height: 100vh;
    }
    .app.sidebar-collapsed {
      grid-template-columns: 0 1fr;
    }
    .app.sidebar-collapsed .sidebar {
      display: none;
    }
    .sidebar {
      border-right: 1px solid var(--line);
      background: #fbfcfb;
      padding: 20px;
      display: grid;
      align-content: start;
      gap: 16px;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .mark {
      width: 38px;
      height: 38px;
      border-radius: 8px;
      background: var(--text);
      color: #fff;
      display: grid;
      place-items: center;
      font-weight: 800;
    }
    h1, h2, h3, p { margin: 0; }
    h1 { font-size: 20px; }
    h2 { font-size: 17px; }
    h3 { font-size: 14px; }
    .muted { color: var(--muted); }
    .tiny { font-size: 12px; }
    .panel {
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
    }
    .sidebar .panel {
      box-shadow: none;
      padding: 14px;
      display: grid;
      gap: 12px;
    }
    main {
      padding: 20px;
      display: grid;
      gap: 16px;
      align-content: start;
      min-width: 0;
    }
    .topbar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      padding: 6px 12px;
    }
    .topbar-case {
      display: flex;
      align-items: baseline;
      gap: 10px;
      min-width: 0;
    }
    .topbar-case h2 {
      font-size: 14px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    #caseMeta {
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      max-width: 42vw;
    }
    .sidebar-toggle {
      min-height: 26px;
      padding: 2px 9px;
      align-self: center;
      font-size: 15px;
      line-height: 1;
    }
    .stats {
      display: flex;
      gap: 16px;
      flex-shrink: 0;
    }
    .stat {
      display: flex;
      align-items: baseline;
      gap: 5px;
      border: 0;
      background: transparent;
      padding: 0;
    }
    .stat strong {
      font-size: 15px;
    }
    .tabs {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }
    .tab {
      background: #fff;
      color: var(--text);
      border: 1px solid var(--line);
    }
    .tab.active {
      background: var(--text);
      color: #fff;
      border-color: var(--text);
    }
    .tab-shortcut {
      margin-left: 6px;
      color: inherit;
      opacity: .62;
      font-size: 11px;
      font-weight: 800;
    }
    .tab.active .tab-shortcut {
      opacity: .85;
    }
    .view { display: none; }
    .view.active {
      display: grid;
      gap: 16px;
    }
    .view.analyze-view.active {
      min-height: calc(100vh - 172px);
    }
    .grid-2 {
      display: grid;
      grid-template-columns: minmax(300px, 420px) 1fr;
      gap: 16px;
      align-items: start;
    }
    .dashboard-grid {
      display: grid;
      grid-template-columns: minmax(280px, .9fr) minmax(340px, 1fr) minmax(360px, 1.1fr);
      gap: 16px;
      align-items: start;
    }
    .dashboard-grid .panel {
      min-width: 0;
    }
    .dashboard-facts {
      display: grid;
      gap: 1px;
      overflow: hidden;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--line);
    }
    .dashboard-fact {
      display: grid;
      grid-template-columns: minmax(120px, .8fr) minmax(0, 1fr);
      gap: 12px;
      align-items: start;
      background: #fff;
      padding: 8px 10px;
    }
    .dashboard-fact span {
      color: var(--muted);
      font-size: 11px;
      font-weight: 800;
      text-transform: uppercase;
    }
    .dashboard-fact strong {
      min-width: 0;
      overflow-wrap: anywhere;
      font-size: 13px;
    }
    .dashboard-table-wrap {
      overflow: auto;
    }
    .dashboard-category-list {
      display: grid;
      gap: 8px;
    }
    .dashboard-category-row {
      width: 100%;
      display: grid;
      grid-template-columns: minmax(130px, .9fr) minmax(0, 1.4fr) auto;
      gap: 10px;
      align-items: center;
      min-height: 38px;
      padding: 8px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #fff;
      color: var(--text);
      font-size: 13px;
      font-weight: 750;
      text-align: left;
    }
    .dashboard-category-row:hover {
      background: #e8f3f0;
      color: var(--accent);
      border-color: rgba(11,111,99,.35);
    }
    .dashboard-category-label {
      min-width: 0;
      overflow-wrap: anywhere;
    }
    .dashboard-category-bar {
      height: 10px;
      overflow: hidden;
      border-radius: 999px;
      background: var(--surface-2);
    }
    .dashboard-category-bar span {
      display: block;
      width: var(--bar-width);
      height: 100%;
      border-radius: inherit;
      background: #9ec9d5;
    }
    .dashboard-category-count {
      color: var(--muted);
      font-size: 12px;
      font-variant-numeric: tabular-nums;
    }
    .panel-head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      border-bottom: 1px solid var(--line);
      padding: 14px 16px;
    }
    .panel-body {
      padding: 16px;
      display: grid;
      gap: 12px;
    }
    .form-grid {
      display: grid;
      gap: 10px;
    }
    /* The hidden attribute must win over element display rules (e.g. .row is
       a grid), or toggled-off option rows keep showing. */
    [hidden] { display: none !important; }
    .row {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 10px;
    }
    .toolbar {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
    }
    .toolbar-select {
      width: auto;
      min-width: 160px;
      min-height: 30px;
      padding: 5px 8px;
      text-transform: none;
    }
    .analysis-notice {
      border-bottom: 1px solid var(--line);
      background: #edf8f5;
      color: var(--accent);
      padding: 6px 10px;
      font-size: 12px;
      font-weight: 750;
      line-height: 1.3;
      overflow-wrap: anywhere;
    }
    .analysis-notice.bad {
      background: #fff3f0;
      color: var(--bad);
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }
    th, td {
      border-bottom: 1px solid var(--line);
      padding: 10px 8px;
      text-align: left;
      vertical-align: top;
    }
    th {
      color: var(--muted);
      font-size: 11px;
      text-transform: uppercase;
      background: var(--surface-2);
    }
    td.actions {
      width: 190px;
    }
    .pill {
      display: inline-flex;
      align-items: center;
      border-radius: 999px;
      border: 1px solid var(--line);
      color: var(--muted);
      background: #fff;
      min-height: 26px;
      padding: 4px 8px;
      font-size: 12px;
      font-weight: 700;
    }
    .pill.good { color: var(--accent); border-color: rgba(11,111,99,.35); }
    .pill.warn { color: var(--warn); border-color: rgba(183,121,31,.35); }
    .pill.bad { color: var(--bad); border-color: rgba(180,35,24,.35); }
    .notice {
      border-left: 4px solid var(--accent);
      background: #edf8f5;
      padding: 10px 12px;
      border-radius: 6px;
      min-height: 40px;
    }
    .notice.bad {
      border-color: var(--bad);
      background: #fff3f0;
    }
    .empty {
      color: var(--muted);
      padding: 16px;
      border: 1px dashed var(--line);
      border-radius: 8px;
      background: var(--surface-2);
    }
    .path-pick-row {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 8px;
      align-items: end;
    }
    .path-pick-label {
      min-width: 0;
    }
    .browser-panel {
      grid-column: 1 / -1;
      min-height: calc(100vh - 180px);
    }
    .analyze-view .browser-panel {
      grid-column: 1;
    }
    .browser-panel .panel-body {
      height: calc(100vh - 252px);
      min-height: 560px;
      padding: 10px;
    }
    .browser-workspace {
      display: grid;
      --inspector-width: 520px;
      grid-template-columns: minmax(230px, 300px) minmax(520px, 1fr) 6px minmax(360px, var(--inspector-width));
      grid-template-rows: minmax(0, 1fr);
      gap: 10px;
      height: 100%;
      min-height: 0;
    }
    .browser-workspace.inspector-collapsed {
      grid-template-columns: minmax(230px, 300px) minmax(0, 1fr);
    }
    .browser-workspace.inspector-collapsed .pane-resizer,
    .browser-workspace.inspector-collapsed .browser-viewer {
      display: none;
    }
    .pane-resizer {
      min-width: 6px;
      border-radius: 999px;
      background: transparent;
      cursor: col-resize;
    }
    .pane-resizer:hover,
    .pane-resizer.dragging {
      background: #bed4cf;
    }
    .browser-tree,
    .browser-list,
    .browser-viewer {
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #fff;
      min-width: 0;
      overflow: hidden;
    }
    .browser-tree {
      display: grid;
      grid-template-rows: auto auto minmax(0, 1fr);
    }
    .browser-list,
    .browser-viewer {
      display: grid;
      grid-template-rows: auto minmax(0, 1fr);
    }
    .browser-list.has-notice {
      grid-template-rows: auto auto minmax(0, 1fr);
    }
    .pane-title {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      min-height: 40px;
      padding: 8px 10px;
      border-bottom: 1px solid var(--line);
      background: var(--surface-2);
      font-size: 12px;
      font-weight: 800;
      text-transform: uppercase;
      letter-spacing: 0;
      color: var(--muted);
    }
    .tree-list {
      overflow: auto;
      padding: 6px;
    }
    .tree-mode {
      display: flex;
      gap: 6px;
      padding: 6px;
      border-bottom: 1px solid var(--line);
      background: #fff;
    }
    .tree-mode button {
      flex: 1;
      min-height: 30px;
      padding: 5px 8px;
      background: transparent;
      color: var(--muted);
      border: 1px solid var(--line);
    }
    .tree-mode button.active {
      background: var(--text);
      color: #fff;
      border-color: var(--text);
    }
    .tree-row {
      width: 100%;
      display: grid;
      grid-template-columns: 18px minmax(0, 1fr) auto;
      gap: 6px;
      align-items: center;
      min-height: 30px;
      padding: 5px 8px 5px calc(8px + (var(--depth) * 14px));
      border: 0;
      border-radius: 6px;
      background: transparent;
      color: var(--text);
      font-size: 13px;
      font-weight: 650;
      text-align: left;
    }
    .tree-row:hover,
    .tree-row.active {
      background: #e8f3f0;
      color: var(--accent);
    }
    .tree-toggle {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 18px;
      min-height: 18px;
      border-radius: 4px;
      color: var(--muted);
      font-family: Consolas, "Cascadia Mono", monospace;
      font-size: 12px;
      font-weight: 900;
    }
    .tree-toggle.can-toggle:hover {
      background: rgba(11,111,99,.10);
      color: var(--accent);
    }
    .tree-label {
      min-width: 0;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .browser-table-wrap {
      min-height: 0;
      overflow: auto;
    }
    .browser-table-wrap table {
      font-size: 12px;
    }
    .browser-table-wrap .email-table {
      table-layout: fixed;
      min-width: 920px;
    }
    .browser-table-wrap .category-table {
      table-layout: fixed;
      min-width: 1300px;
    }
    .browser-table-wrap .folder-table {
      table-layout: fixed;
      min-width: 1220px;
    }
    /* Lazy indexed browse table (large cases): few columns, so it must fit
       the pane instead of forcing the wide folder-table horizontal scroll. */
    .browser-table-wrap .idx-table {
      table-layout: fixed;
      min-width: 100%;
    }
    .browser-table-wrap .idx-table th:nth-child(1),
    .browser-table-wrap .idx-table td:nth-child(1) {
      width: 34px;
    }
    .browser-table-wrap .idx-table th:nth-child(3),
    .browser-table-wrap .idx-table td:nth-child(3) {
      width: 72px;
    }
    .browser-table-wrap .idx-table th:nth-child(4),
    .browser-table-wrap .idx-table td:nth-child(4) {
      width: 96px;
    }
    .browser-table-wrap .idx-table th:nth-child(5),
    .browser-table-wrap .idx-table td:nth-child(5) {
      width: 176px;
    }
    /* Live browse table: checkbox / Name / Type / Size / Modified. Row click
       opens, right-click acts - no per-row buttons, so it fits the pane. */
    .browser-table-wrap .live-table {
      table-layout: fixed;
      min-width: 100%;
    }
    .browser-table-wrap .live-table th:nth-child(1),
    .browser-table-wrap .live-table td:nth-child(1) {
      width: 34px;
    }
    .browser-table-wrap .live-table th:nth-child(3),
    .browser-table-wrap .live-table td:nth-child(3) {
      width: 64px;
    }
    .browser-table-wrap .live-table th:nth-child(4),
    .browser-table-wrap .live-table td:nth-child(4) {
      width: 88px;
    }
    .browser-table-wrap .live-table th:nth-child(5),
    .browser-table-wrap .live-table td:nth-child(5) {
      width: 170px;
    }
    /* Right-click context menu (live browse rows) */
    .ctx-menu {
      position: fixed;
      z-index: 300;
      min-width: 230px;
      padding: 4px;
      background: var(--panel, #fff);
      border: 1px solid var(--border, #d7dee5);
      border-radius: 8px;
      box-shadow: 0 8px 28px rgba(15, 32, 39, .22);
    }
    .ctx-menu button {
      display: block;
      width: 100%;
      padding: 7px 12px;
      border: none;
      background: none;
      text-align: left;
      font: inherit;
      font-size: 13px;
      border-radius: 6px;
      cursor: pointer;
      color: inherit;
    }
    .ctx-menu button:hover {
      background: rgba(11, 111, 99, .10);
    }
    .ctx-menu .sep {
      height: 1px;
      margin: 4px 6px;
      background: var(--border, #d7dee5);
    }
    /* Draggable column resize: a grip on every header edge. Sticky headers in
       .browser-table-wrap are already positioned; plain tables need relative. */
    table th {
      position: relative;
    }
    .col-resizer {
      /* Kept fully inside its own header: a negative right offset would be
         painted over by the next sticky th and shrink the drag target. */
      position: absolute;
      top: 0;
      right: 0;
      bottom: 0;
      width: 9px;
      cursor: col-resize;
      z-index: 4;
      touch-action: none;
    }
    .col-resizer:hover,
    .col-resizer.dragging {
      background: rgba(11, 111, 99, .30);
    }
    .browser-table-wrap th {
      position: sticky;
      top: 0;
      z-index: 2;
    }
    .browser-table-wrap th,
    .browser-table-wrap td {
      padding: 4px 8px;
      line-height: 1.2;
    }
    .browser-table-wrap .category-table th:nth-child(1),
    .browser-table-wrap .category-table td:nth-child(1),
    .browser-table-wrap .email-table th:nth-child(1),
    .browser-table-wrap .email-table td:nth-child(1),
    .browser-table-wrap .folder-table th:nth-child(1),
    .browser-table-wrap .folder-table td:nth-child(1) {
      width: 34px;
    }
    .browser-table-wrap .category-table th:nth-child(2),
    .browser-table-wrap .category-table td:nth-child(2) {
      width: 320px;
    }
    .browser-table-wrap .category-table th:nth-child(3),
    .browser-table-wrap .category-table td:nth-child(3) {
      width: 180px;
    }
    .browser-table-wrap .folder-table th:nth-child(2),
    .browser-table-wrap .folder-table td:nth-child(2) {
      width: 300px;
    }
    .browser-table-wrap .email-table th:nth-child(2),
    .browser-table-wrap .email-table td:nth-child(2),
    .browser-table-wrap .email-table th:nth-child(3),
    .browser-table-wrap .email-table td:nth-child(3) {
      width: 220px;
    }
    .browser-table-wrap .email-table th:nth-child(4),
    .browser-table-wrap .email-table td:nth-child(4) {
      width: 150px;
    }
    .browser-table-wrap .email-table th:nth-child(5),
    .browser-table-wrap .email-table td:nth-child(5) {
      width: 260px;
    }
    .browser-table-wrap .email-table th:nth-child(7),
    .browser-table-wrap .email-table td:nth-child(7) {
      width: 78px;
    }
    .thumb-toolbar {
      display: flex;
      justify-content: flex-end;
      padding: 4px 8px;
    }
    .date-filter {
      display: inline-flex;
      gap: 4px;
      align-items: center;
    }
    .panel-summary {
      cursor: pointer;
      font-weight: 800;
      font-size: 15px;
      list-style: none;
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .panel-summary::before {
      content: "\25B8";
      font-size: 11px;
      transition: transform 0.15s;
    }
    details[open] > .panel-summary::before {
      transform: rotate(90deg);
    }
    details > .panel-summary + * {
      margin-top: 10px;
    }
    .evidence-type-row {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 6px;
    }
    .evidence-type {
      padding: 10px 6px;
      font-size: 12px;
      font-weight: 700;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--surface-2);
      color: var(--text);
      cursor: pointer;
    }
    .evidence-type.active {
      border-color: #0f766e;
      background: #0f766e;
      color: #ffffff;
    }
    .preview-card.image-preview {
      display: flex;
      justify-content: center;
      padding: 6px;
    }
    .preview-card.image-preview img {
      max-width: 100%;
      max-height: 260px;
      object-fit: contain;
      border-radius: 6px;
    }
    .preview-card.image-preview.thumb-broken::after {
      content: "no preview";
      font-size: 11px;
      color: #94a3b8;
    }
    .date-filter input[type="date"] {
      height: 26px;
      width: 128px;
      padding: 2px 4px;
      font-size: 11px;
    }
    .thumb-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
      gap: 8px;
      padding: 8px;
      overflow-y: auto;
    }
    .thumb-card {
      position: relative;
      border: 1px solid rgba(148, 163, 184, 0.25);
      border-radius: 8px;
      padding: 6px;
      cursor: pointer;
      background: rgba(15, 23, 42, 0.35);
    }
    .thumb-card.selected,
    .thumb-card.multi-selected {
      border-color: #38bdf8;
      background: rgba(56, 189, 248, 0.12);
    }
    .thumb-card > input[type="checkbox"] {
      position: absolute;
      top: 10px;
      left: 10px;
      z-index: 1;
    }
    .thumb-frame {
      height: 112px;
      display: flex;
      align-items: center;
      justify-content: center;
      overflow: hidden;
      border-radius: 6px;
      background: rgba(2, 6, 23, 0.6);
    }
    .thumb-frame img {
      max-width: 100%;
      max-height: 100%;
      object-fit: contain;
    }
    .thumb-frame.thumb-broken img {
      display: none;
    }
    .thumb-frame.thumb-broken::after {
      content: "no preview";
      font-size: 11px;
      color: #94a3b8;
    }
    .thumb-name {
      margin-top: 6px;
      font-size: 12px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .browser-table-wrap .category-table th:nth-child(4),
    .browser-table-wrap .category-table td:nth-child(4),
    .browser-table-wrap .folder-table th:nth-child(3),
    .browser-table-wrap .folder-table td:nth-child(3) {
      width: 82px;
    }
    .browser-table-wrap .category-table th:nth-child(5),
    .browser-table-wrap .category-table td:nth-child(5),
    .browser-table-wrap .folder-table th:nth-child(4),
    .browser-table-wrap .folder-table td:nth-child(4) {
      width: 72px;
    }
    .browser-table-wrap .category-table th:nth-child(6),
    .browser-table-wrap .category-table td:nth-child(6),
    .browser-table-wrap .folder-table th:nth-child(5),
    .browser-table-wrap .folder-table td:nth-child(5) {
      width: 94px;
    }
    .browser-table-wrap .category-table th:nth-child(7),
    .browser-table-wrap .category-table td:nth-child(7),
    .browser-table-wrap .folder-table th:nth-child(6),
    .browser-table-wrap .folder-table td:nth-child(6) {
      width: 150px;
    }
    .browser-table-wrap .category-table th:nth-child(8),
    .browser-table-wrap .category-table td:nth-child(8),
    .browser-table-wrap .folder-table th:nth-child(7),
    .browser-table-wrap .folder-table td:nth-child(7) {
      width: 150px;
    }
    .browser-table-wrap .category-table th:nth-child(9),
    .browser-table-wrap .category-table td:nth-child(9),
    .browser-table-wrap .folder-table th:nth-child(8),
    .browser-table-wrap .folder-table td:nth-child(8) {
      width: 150px;
    }
    .browser-table-wrap .folder-table th:nth-child(9),
    .browser-table-wrap .folder-table td:nth-child(9) {
      width: 150px;
    }
    .browser-table-wrap .toolbar {
      gap: 5px;
    }
    .browser-table-wrap button {
      min-height: 26px;
      padding: 3px 7px;
    }
    .category-table .toolbar,
    .email-table .toolbar,
    .folder-table .toolbar {
      flex-wrap: nowrap;
      justify-content: flex-end;
    }
    .entry-name {
      display: block;
      min-width: 0;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      font-weight: 750;
    }
    .entry-path {
      display: block;
      min-width: 0;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      color: var(--muted);
      font-size: 11px;
      line-height: 1.25;
    }
    .entry-kind,
    .entry-ext,
    .entry-size,
    .entry-offset,
    .entry-time,
    .email-cell {
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .email-body-cell {
      color: var(--muted);
    }
    .entry-flags {
      display: flex;
      flex-wrap: nowrap;
      gap: 4px;
      overflow: hidden;
      white-space: nowrap;
    }
    .entry-flags .pill {
      flex: 0 1 auto;
      min-width: 0;
      max-width: 100%;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      min-height: 22px;
      padding: 2px 6px;
      font-size: 11px;
    }
    .entry-flags .pill.more {
      flex: 0 0 auto;
    }
    .entry-category {
      display: block;
      min-width: 0;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .entry-row {
      cursor: pointer;
    }
    .entry-row.selected td {
      background: #e8f3f0;
    }
    .entry-row.multi-selected td {
      background: #f1f7f5;
    }
    .entry-row.selected.multi-selected td {
      background: #dcefe9;
    }
    .browser-viewer-head {
      display: grid;
      grid-template-columns: minmax(0, 1fr);
      gap: 10px;
      align-items: center;
      padding: 8px 10px;
      border-bottom: 1px solid var(--line);
      background: var(--surface-2);
    }
    .browser-viewer.viewer-idle .hex-meta {
      display: none;
    }
    .hex-meta {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
    }
    .hex-meta label {
      max-width: 130px;
    }
    .hex-meta select,
    .hex-meta input {
      min-height: 30px;
      padding: 5px 7px;
    }
    .viewer-notice {
      margin-top: 6px;
      color: var(--accent);
      font-size: 12px;
      font-weight: 750;
      line-height: 1.3;
      overflow-wrap: anywhere;
    }
    .viewer-notice.bad {
      color: var(--bad);
    }
    .hex-view {
      overflow: auto;
      background: #0f1716;
      color: #eef7f4;
      min-height: 0;
      font-family: Consolas, "Cascadia Mono", monospace;
      font-size: 13px;
    }
    .hex-current {
      position: sticky;
      top: 0;
      z-index: 2;
      display: flex;
      flex-wrap: wrap;
      gap: 8px 14px;
      align-items: center;
      min-width: max-content;
      padding: 8px 10px;
      border-bottom: 1px solid rgba(255,255,255,.12);
      background: #121f1d;
      color: #d8e8e4;
      user-select: none;
    }
    .hex-current strong {
      margin-right: 5px;
      color: #8fd5c8;
      font-size: 11px;
    }
    .hex-current-spacer {
      flex: 1 1 auto;
      min-width: 10px;
    }
    .hex-current button {
      min-height: 28px;
      padding: 4px 9px;
      font-size: 11px;
    }
    .hex-current button.ghost {
      border-color: rgba(143,213,200,.45);
      color: #8fd5c8;
    }
    .hex-grid {
      min-width: max-content;
    }
    .hex-row {
      display: grid;
      grid-template-columns: 100px max-content max-content;
      gap: 8px;
      min-width: max-content;
      padding: 5px 10px;
      border-bottom: 1px solid rgba(255,255,255,.06);
      white-space: pre;
    }
    .hex-row:nth-child(2n) {
      background: rgba(255,255,255,.025);
    }
    .hex-offset {
      color: #8fd5c8;
    }
    .hex-bytes {
      display: grid;
      grid-template-columns: repeat(var(--bytes-per-row, 16), 2ch);
      column-gap: 1ch;
      min-width: calc(var(--bytes-per-row, 16) * 3ch);
    }
    .hex-ascii {
      display: grid;
      grid-template-columns: repeat(var(--bytes-per-row, 16), 1ch);
      min-width: calc(var(--bytes-per-row, 16) * 1ch);
      color: #f0c38a;
    }
    .hex-cell {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 18px;
      border-radius: 3px;
      cursor: cell;
      user-select: none;
      touch-action: none;
    }
    .hex-cell:hover {
      background: rgba(255,255,255,.12);
    }
    .hex-cell.selected {
      background: #ffd166;
      color: #0f1716;
    }
    .hex-decode {
      display: grid;
      gap: 10px;
      min-width: max-content;
      padding: 10px;
      border-top: 1px solid rgba(255,255,255,.12);
      background: #121a19;
    }
    .hex-decode-head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      color: #8fd5c8;
      font-size: 12px;
      font-weight: 800;
      text-transform: uppercase;
    }
    .hex-decode-grid {
      display: grid;
      grid-template-columns: minmax(320px, 1fr) minmax(260px, .8fr);
      gap: 10px;
    }
    .hex-decode-group {
      overflow: hidden;
      border: 1px solid rgba(255,255,255,.12);
      border-radius: 6px;
      background: #0f1716;
    }
    .hex-decode-group h3 {
      padding: 7px 9px;
      border-bottom: 1px solid rgba(255,255,255,.1);
      color: #f0c38a;
      font-size: 11px;
      text-transform: uppercase;
    }
    .hex-decode-table {
      display: grid;
      grid-template-columns: 160px minmax(220px, 1fr);
    }
    .hex-decode-table dt,
    .hex-decode-table dd {
      min-width: 0;
      padding: 6px 8px;
      border-top: 1px solid rgba(255,255,255,.06);
    }
    .hex-decode-table dt:nth-of-type(1),
    .hex-decode-table dd:nth-of-type(1) {
      border-top: 0;
    }
    .hex-decode-table dt {
      color: #8fd5c8;
      font-weight: 750;
    }
    .hex-decode-table dd {
      margin: 0;
      color: #eef7f4;
      overflow-wrap: anywhere;
      white-space: pre-wrap;
    }
    body.viewer-fullscreen #browserViewer {
      position: fixed;
      inset: 0;
      z-index: 1000;
      border: 0;
      border-radius: 0;
      box-shadow: none;
      grid-template-rows: auto minmax(0, 1fr);
    }
    body.viewer-fullscreen #browserViewer .browser-viewer-head {
      border-bottom-color: #cfd9d6;
    }
    body.viewer-fullscreen #hexView {
      font-size: 14px;
    }
    body.viewer-fullscreen .browser-workspace.inspector-collapsed #browserViewer {
      display: grid;
    }
    .text-view {
      min-height: 0;
      overflow: auto;
      padding: 10px;
      background: #fff;
      color: var(--text);
      font-family: Consolas, "Cascadia Mono", monospace;
      font-size: 13px;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
    }
    .metadata-view {
      min-height: 0;
      overflow: auto;
      padding: 12px;
      background: #fff;
      color: var(--text);
      font-family: "Segoe UI", Arial, sans-serif;
      font-size: 13px;
      overflow-wrap: anywhere;
    }
    .inspector-summary {
      display: grid;
      gap: 8px;
      padding-bottom: 12px;
      margin-bottom: 12px;
      border-bottom: 1px solid var(--line);
    }
    .inspector-title {
      margin: 0;
      color: var(--text);
      font-size: 16px;
      line-height: 1.2;
      font-family: inherit;
    }
    .inspector-path {
      color: var(--muted);
      font-family: Consolas, "Cascadia Mono", monospace;
      font-size: 12px;
      overflow-wrap: anywhere;
    }
    .inspector-badges,
    .inspector-actions {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      align-items: center;
    }
    .inspector-actions button {
      min-height: 28px;
      padding: 4px 8px;
    }
    .preview-card {
      display: grid;
      gap: 8px;
      padding: 10px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--surface-2);
    }
    .preview-title {
      margin: 0;
      color: var(--text);
      font-family: inherit;
      font-size: 14px;
      line-height: 1.25;
    }
    .preview-meta {
      display: grid;
      gap: 4px;
      color: var(--muted);
      font-size: 12px;
    }
    .preview-body {
      max-height: 220px;
      overflow: auto;
      padding: 8px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #fff;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      font-size: 13px;
      line-height: 1.35;
    }
    .preview-url {
      color: var(--accent);
      overflow-wrap: anywhere;
    }
    .metadata-grid {
      display: grid;
      grid-template-columns: 160px minmax(0, 1fr);
      gap: 6px 12px;
    }
    .metadata-grid dt {
      color: var(--muted);
      font-weight: 800;
    }
    .metadata-grid dd {
      margin: 0;
      min-width: 0;
      overflow-wrap: anywhere;
    }
    .category-summary {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
      gap: 8px;
      padding: 8px;
      border-bottom: 1px solid var(--line);
      background: var(--surface-2);
    }
    .category-card {
      display: grid;
      gap: 4px;
      min-height: 72px;
      padding: 9px 10px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #fff;
      color: var(--text);
      text-align: left;
    }
    .category-card.active {
      border-color: rgba(11,111,99,.55);
      background: #e8f3f0;
    }
    .category-card strong {
      font-size: 17px;
      line-height: 1;
    }
    .category-card span {
      min-width: 0;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .category-row-meta {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      margin-top: 4px;
    }
    .metadata-section {
      display: grid;
      gap: 8px;
      padding-bottom: 12px;
      margin-bottom: 12px;
      border-bottom: 1px solid var(--line);
    }
    .metadata-section h3 {
      margin: 0;
      color: var(--text);
      font-family: inherit;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0;
    }
    .metadata-section summary {
      cursor: pointer;
      color: var(--text);
      font-weight: 800;
      text-transform: uppercase;
      font-size: 12px;
    }
    .metadata-section pre {
      max-height: 260px;
      overflow: auto;
      padding: 10px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--surface-2);
      color: var(--text);
      font-family: Consolas, "Cascadia Mono", monospace;
      font-size: 12px;
      white-space: pre-wrap;
    }
    .analysis-status {
      border-left: 4px solid var(--warn);
      background: #fff7ed;
      color: var(--text);
      padding: 10px 12px;
      font-size: 13px;
      line-height: 1.35;
    }
    body.analysis-fullscreen .app {
      grid-template-columns: 1fr;
      min-height: 100vh;
    }
    body.analysis-fullscreen .sidebar,
    body.analysis-fullscreen .topbar,
    body.analysis-fullscreen .tabs {
      display: none;
    }
    body.analysis-fullscreen main {
      padding: 8px;
      gap: 0;
      min-height: 100vh;
    }
    body.analysis-fullscreen .view.active {
      gap: 0;
    }
    body.analysis-fullscreen .view.analyze-view.active,
    body.analysis-fullscreen .browser-panel {
      min-height: calc(100vh - 16px);
    }
    body.analysis-fullscreen .browser-panel {
      border-radius: 0;
      box-shadow: none;
    }
    body.analysis-fullscreen .browser-panel .panel-body {
      height: calc(100vh - 72px);
      min-height: 560px;
      padding: 8px;
    }
    body.analysis-fullscreen .browser-workspace {
      --inspector-width: 540px;
      grid-template-columns: minmax(260px, 340px) minmax(620px, 1fr) 6px minmax(380px, var(--inspector-width));
      grid-template-rows: minmax(0, 1fr);
      height: 100%;
      min-height: 0;
    }
    body.analysis-fullscreen .browser-workspace.inspector-collapsed {
      grid-template-columns: minmax(260px, 340px) minmax(0, 1fr);
    }
    pre {
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      margin: 0;
      background: #111c1b;
      color: #edf8f5;
      border-radius: 8px;
      padding: 12px;
      max-height: 260px;
      overflow: auto;
    }
    @media (max-width: 980px) {
      .app { grid-template-columns: 1fr; }
      .sidebar { border-right: 0; border-bottom: 1px solid var(--line); }
      .topbar, .grid-2, .dashboard-grid { grid-template-columns: 1fr; }
      .stats { min-width: 0; grid-template-columns: repeat(2, 1fr); }
    }
    @media (max-width: 620px) {
      main, .sidebar { padding: 12px; }
      .row { grid-template-columns: 1fr; }
      .dashboard-category-row { grid-template-columns: 1fr auto; }
      .dashboard-category-bar { grid-column: 1 / -1; }
      .browser-panel .panel-body { height: auto; min-height: 0; }
      .browser-workspace { grid-template-columns: 1fr; grid-template-rows: auto minmax(260px, 40vh) minmax(340px, 1fr); }
      .pane-resizer { display: none; }
      .browser-tree { max-height: 260px; }
      .browser-viewer-head { grid-template-columns: 1fr; }
      td.actions { width: auto; }
      table, thead, tbody, tr, th, td { display: block; }
      thead { display: none; }
      tr { border-bottom: 1px solid var(--line); padding: 8px 0; }
      td { border: 0; padding: 6px 0; }
      .hex-decode-grid { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div class="app">
    <aside class="sidebar">
      <div class="brand">
        <div class="mark">K</div>
        <div>
          <h1>KDFT Workbench</h1>
          <p class="muted tiny">Local case interface</p>
        </div>
      </div>

      <section class="panel">
        <h2>Case</h2>
        <label>Case database<input id="casePath" spellcheck="false"></label>
        <div class="toolbar">
          <button id="refreshCase" class="secondary">Refresh</button>
        </div>
      </section>

      <section class="panel">
        <button id="caseOpenSetup" class="secondary">New / Open Case</button>
      </section>

      <div id="notice" class="notice">Ready.</div>
    </aside>

    <main>
      <section class="panel topbar">
        <div class="topbar-case">
          <button id="toggleSidebar" class="ghost sidebar-toggle" title="Show or hide the case sidebar">&#9776;</button>
          <h2 id="caseTitle">No case loaded</h2>
          <span id="caseMeta" class="muted tiny"></span>
        </div>
        <div class="stats">
          <span class="stat"><span class="muted tiny">Evidence</span><strong id="statEvidence">0</strong></span>
          <span class="stat"><span class="muted tiny">Entries</span><strong id="statEntries">0</strong></span>
          <span class="stat"><span class="muted tiny">Bookmarks</span><strong id="statBookmarks">0</strong></span>
          <span class="stat"><span class="muted tiny">Report</span><strong id="statReport">0</strong></span>
        </div>
      </section>

      <nav class="tabs">
        <button class="tab active" data-view="dashboardView" title="Case Dashboard (Alt+1)">Case Dashboard<span class="tab-shortcut">Alt+1</span></button>
        <button class="tab" data-view="evidenceView" title="Add and manage evidence (Alt+2)">Evidence<span class="tab-shortcut">Alt+2</span></button>
        <button class="tab" data-view="analyzeView" title="Analyze artifacts (Alt+3)">Analyze<span class="tab-shortcut">Alt+3</span></button>
        <button class="tab" data-view="searchView" title="Deep Search (Alt+4)">Deep Search<span class="tab-shortcut">Alt+4</span></button>
        <button class="tab" data-view="bookmarksView" title="Bookmarks (Alt+5)">Bookmarks<span class="tab-shortcut">Alt+5</span></button>
        <button class="tab" data-view="reportView" title="Quick Report (Alt+6)">Quick Report<span class="tab-shortcut">Alt+6</span></button>
      </nav>

      <section id="setupView" class="view">
        <div class="grid-2">
          <section class="panel">
            <div class="panel-head"><h2>Create New Case</h2><span class="pill good">Step 1</span></div>
            <div class="panel-body form-grid">
              <label>Case database file<input id="setupCasePath" spellcheck="false" placeholder="C:\Cases\my-case.kdft.sqlite"></label>
              <label>Name<input id="newCaseName" value="Workbench Case"></label>
              <label>Case number<input id="newCaseNumber" placeholder="e.g. 2026-0042"></label>
              <label>Case type<select id="newCaseType">
                <option value="">unspecified</option>
                <option>Administrative review</option>
                <option>Criminal</option>
                <option>Corporate compliance</option>
                <option>eDiscovery</option>
                <option>Fraud</option>
                <option>Human resources</option>
                <option>Intrusion / incident response</option>
                <option>Other</option>
              </select></label>
              <label>Examiner<input id="newCaseExaminer" value="Cristina"></label>
              <label>Description<textarea id="newCaseDescription" placeholder="Scan / case description"></textarea></label>
              <button id="createCase">Create Case</button>
              <p class="muted tiny">After the case is created you are taken to Evidence to add disk images, folders, files, or browser history (old Ecase 6.11 New Case wizard model, then Add Device).</p>
            </div>
          </section>
          <section class="panel">
            <div class="panel-head"><h2>Open Existing Case</h2><span class="pill">Resume</span></div>
            <div class="panel-body form-grid">
              <label>Case database<input id="caseOpenPath" spellcheck="false" placeholder="C:\Cases\my-case.kdft.sqlite"></label>
              <button id="caseOpenButton" class="secondary">Open Case</button>
              <p class="muted tiny">Opens the case and shows its dashboard.</p>
            </div>
          </section>
        </div>
      </section>

      <section id="dashboardView" class="view active">
        <div class="dashboard-grid">
          <section class="panel">
            <div class="panel-head"><h2>Case Overview</h2><span class="pill">Summary</span></div>
            <div id="dashboardCaseOverview" class="panel-body"></div>
          </section>

          <section class="panel">
            <div class="panel-head"><h2>Evidence Overview</h2><span class="pill">Sources</span></div>
            <div id="dashboardEvidenceOverview" class="panel-body"></div>
          </section>

          <section class="panel">
            <div class="panel-head"><h2>Artifact Categories</h2><span class="pill">Indexed</span></div>
            <div id="dashboardArtifactCategories" class="panel-body"></div>
          </section>
        </div>
      </section>

      <section id="evidenceView" class="view">
        <div class="grid-2">
          <section class="panel">
            <div class="panel-head"><h2>Add Evidence</h2><span class="pill good">Read File System</span></div>
            <div class="panel-body form-grid">
              <div class="evidence-type-row" id="evidenceTypeRow">
                <button class="evidence-type active" data-type="image" title="E01, dd/raw, VHD/VHDX, VMDK, VDI disk images">Disk image</button>
                <button class="evidence-type" data-type="folder" title="A local folder of files">Folder</button>
                <button class="evidence-type" data-type="file" title="A single local file">Single file</button>
                <button class="evidence-type" data-type="browser_history" title="Chrome/Edge/Chromium profile folder or History SQLite database">Browser history</button>
              </div>
              <p id="evidenceTypeHint" class="muted tiny">E01, dd/raw, VHD/VHDX, VMDK, VDI disk images</p>
              <div class="path-pick-row">
                <label id="evidencePathLabel" class="path-pick-label">Image path<input id="evidencePath" spellcheck="false" placeholder="C:\Evidence\image.E01"></label>
                <button id="browseEvidence" class="secondary">Browse&hellip;</button>
              </div>
              <div class="row" id="fsOptionsRow">
                <label>Read File System<select id="readFileSystem"><option value="true">yes &mdash; index now (bounded)</option><option value="false">no &mdash; attach only</option></select></label>
              </div>
              <div class="row" id="historyOptionsRow" hidden>
                <label>Max visits<input id="historyMaxVisits" type="number" min="1" value="5000"></label>
              </div>
              <label>Notes<textarea id="evidenceNotes"></textarea></label>
              <button id="addEvidence">Add Evidence</button>
            </div>
          </section>

          <section class="panel">
            <div class="panel-head">
              <h2>Evidence Sources</h2>
            </div>
            <div class="panel-body">
              <div id="evidenceTable"></div>
            </div>
          </section>

        </div>
      </section>

      <section id="analyzeView" class="view analyze-view">
          <section class="panel browser-panel">
            <div class="panel-head">
              <div>
                <h2>Analyze Evidence</h2>
                <p id="browserTitle" class="muted tiny">Select an evidence source</p>
              </div>
              <div class="toolbar">
                <button id="liveBrowse" class="ghost">Live browse</button>
                <button id="openAnalyzeWindow" class="ghost">Open full screen</button>
              </div>
            </div>
            <div class="panel-body">
              <div class="browser-workspace">
                <div class="browser-tree">
                  <div class="pane-title"><span id="treeTitle">Entries</span><span id="treeCount" class="tiny">0</span></div>
                  <div class="tree-mode">
                    <button id="treeModeFilesystem" class="active">Entries</button>
                    <button id="treeModeCategories">Categories</button>
                  </div>
                  <div id="filesystemTree" class="tree-list"></div>
                </div>
                <div class="browser-list">
                  <div class="pane-title">
                    <span>Folder Contents</span>
                    <span id="folderTitle" class="tiny">/</span>
                    <span class="toolbar">
                      <span class="tiny date-filter">
                        <input type="date" id="dateFilterFrom" title="Show only rows with a timestamp on or after this date">
                        <input type="date" id="dateFilterTo" title="Show only rows with a timestamp on or before this date">
                        <button id="dateFilterClear" class="ghost" title="Clear date filter">All dates</button>
                      </span>
                      <span id="selectedCount" class="tiny">0 selected</span>
                      <button id="selectVisibleRows" class="ghost">Select visible</button>
                      <select id="selectedAction" class="toolbar-select" title="Selected actions">
                        <option value="" disabled selected hidden>Selected actions</option>
                        <option value="bookmark">Bookmark selected</option>
                        <option value="bookmark_report">Bookmark + export report</option>
                        <option value="export_files">Export selected files</option>
                        <option value="export_csv">Export selected as CSV</option>
                        <option value="clear">Clear selection</option>
                      </select>
                      <button id="toggleInspector" class="ghost">Hide inspector</button>
                    </span>
                  </div>
                  <div id="analysisNotice" class="analysis-notice" hidden></div>
                  <div id="entryTable" class="browser-table-wrap"></div>
                </div>
                <div id="viewerResizer" class="pane-resizer" title="Drag to resize inspector"></div>
                <div id="browserViewer" class="browser-viewer viewer-idle">
                  <div class="browser-viewer-head">
                    <div>
                      <div class="pane-title" style="border:0;padding:0;background:transparent;min-height:0"><span>Inspector</span></div>
                      <div id="hexStatus" class="muted tiny">Select an item for preview, details, and bytes.</div>
                      <div id="viewerNotice" class="viewer-notice" hidden></div>
                    </div>
                    <div class="hex-meta">
                      <label>Display<select id="viewerMode"><option value="hex">Hex + ASCII</option><option value="text">Text</option><option value="metadata">Details</option></select></label>
                      <label>Bytes/row<select id="bytesPerRow"><option value="16">16</option><option value="8">8</option><option value="32">32</option></select></label>
                      <label>Offset base<select id="offsetBase"><option value="hex">hex</option><option value="decimal">decimal</option></select></label>
                      <label>Offset<input id="hexOffset" spellcheck="false" value="0"></label>
                      <label>Length<input id="hexLength" type="number" min="16" value="512"></label>
                      <button id="showEntryDetails" class="ghost">Details</button>
                      <button id="hexPrev" class="ghost">Prev</button>
                      <button id="hexGo" class="secondary">Go</button>
                      <button id="hexNext" class="ghost">Next</button>
                      <button id="bookmarkSelectedEntry" class="ghost">Bookmark</button>
                      <button id="toggleViewerFullscreen" class="ghost" aria-pressed="false">Full screen</button>
                    </div>
                  </div>
                  <div id="hexView" class="hex-view"></div>
                </div>
              </div>
            </div>
          </section>
      </section>

      <section id="searchView" class="view">
        <div class="grid-2">
          <section class="panel">
            <div class="panel-head"><h2>Deep Search</h2><span class="pill">Indexed evidence</span></div>
            <div class="panel-body form-grid">
              <label>Query<input id="searchQuery" placeholder="keyword, file name, URL, hex:50 4B"></label>
              <label>Evidence<select id="searchEvidence"><option value="">All evidence</option></select></label>
              <div class="row">
                <label>Include content<select id="includeContent"><option value="true">yes</option><option value="false">no</option></select></label>
                <label>Max results<input id="maxResults" type="number" min="1" value="50"></label>
              </div>
              <label>Max file bytes<input id="maxFileBytes" type="number" min="1" value="65536"></label>
              <div class="row">
                <label>Category scope<input id="searchCategory" placeholder="e.g. Email, Pictures, Recovery"></label>
                <label>File types<input id="searchFileTypes" placeholder="jpg,png,zip"></label>
              </div>
              <p class="muted tiny">Prefix the query with <strong>hex:</strong> for byte-pattern search (e.g. hex:FF D8 FF); hits report byte offsets. Scopes restrict hits to matching stored categories or file extensions.</p>
              <button id="runSearch">Run Search</button>
            </div>
          </section>

          <section class="panel">
            <div class="panel-head"><h2>Results</h2><span id="searchCount" class="pill">0</span></div>
            <div class="panel-body">
              <div class="toolbar">
                <button id="selectAllSearchResults" class="ghost">Select all</button>
                <button id="bookmarkSelectedSearchResults" class="ghost">Bookmark selected</button>
                <button id="clearSelectedSearchResults" class="ghost">Clear</button>
                <span id="searchSelectedCount" class="muted tiny">0 selected</span>
              </div>
              <div id="searchResults"></div>
            </div>
          </section>
        </div>
      </section>

      <section id="bookmarksView" class="view">
        <section class="panel">
          <div class="panel-head">
            <h2>Bookmarks</h2>
            <div class="toolbar">
              <span class="pill good">In report</span>
              <button id="clearFindings" class="ghost danger">Clear findings</button>
            </div>
          </div>
          <div class="panel-body">
            <div id="bookmarksTable"></div>
          </div>
        </section>
      </section>

      <section id="reportView" class="view">
        <div class="grid-2">
          <section class="panel">
            <div class="panel-head"><h2>Export</h2><span class="pill">HTML</span></div>
            <div class="panel-body form-grid">
              <label>Output path<input id="reportPath" spellcheck="false"></label>
              <div class="toolbar">
                <button id="exportReport">Export Report</button>
                <button id="openReport" class="ghost">Open</button>
              </div>
            </div>
          </section>
          <section class="panel">
            <div class="panel-head"><h2>Preview Data</h2><span id="reportCount" class="pill">0 folders</span></div>
            <div class="panel-body">
              <pre id="reportPreview">{}</pre>
            </div>
          </section>
        </div>
      </section>
    </main>
  </div>

  <div id="ctxMenu" class="ctx-menu" hidden></div>

  <script>
    const BOOTSTRAP = __KDFT_BOOTSTRAP__;
    const PAGE_PARAMS = new URLSearchParams(window.location.search);
    const ANALYSIS_MODE = PAGE_PARAMS.get("mode") === "analysis";
    const REQUESTED_EVIDENCE_ID = Number(PAGE_PARAMS.get("evidence_id") || "");
    if (ANALYSIS_MODE) {
      document.body.classList.add("analysis-fullscreen");
    }
    function makeHexState(entryId = null, offset = 0, length = 512, data = null) {
      return { entryId, offset, length, data, fetching: false, selStart: null, selEnd: null, live: null };
    }
    const state = {
      casePath: PAGE_PARAMS.get("case_path") || localStorage.getItem("kdft.casePath") || BOOTSTRAP.defaultCasePath,
      data: null,
      searchResults: [],
      selectedSearchIndexes: new Set(),
      browserState: { evidenceId: null, selectedPath: "/", treeMode: "filesystem", selectedCategory: "" },
      live: { active: false, evidenceId: null, volumes: [], dirCache: {}, expanded: new Set(), selKey: null, selected: new Map(), lastKey: null },
      idx: { evidenceId: null, dirCache: {}, expanded: new Set(), selPath: "/" },
      expandedTreePaths: new Map(),
      inspectorCollapsed: false,
      viewerFullscreen: false,
      selectedEntryIds: new Set(),
      lastSelectedEntryId: null,
      pictureViewMode: "grid",
      dateFilter: { from: "", to: "" },
      hex: makeHexState(),
      lastReportPath: BOOTSTRAP.defaultReportPath,
      pendingAnalysisSelection: ANALYSIS_MODE ? {
        evidenceId: Number.isFinite(REQUESTED_EVIDENCE_ID) && REQUESTED_EVIDENCE_ID > 0 ? REQUESTED_EVIDENCE_ID : null,
        selectedPath: PAGE_PARAMS.get("selected_path") || null,
        treeMode: PAGE_PARAMS.get("tree_mode") === "categories" || PAGE_PARAMS.has("selected_category") || PAGE_PARAMS.has("category") ? "categories" : "filesystem",
        selectedCategory: PAGE_PARAMS.get("selected_category") || PAGE_PARAMS.get("category") || "",
        applied: false
      } : null
    };
    const $ = (id) => document.getElementById(id);
    let hexSelecting = false;
    let hexSelectionAnchor = null;
    let hexPointerId = null;

    function setNotice(message, bad) {
      const notice = $("notice");
      if (notice) {
        notice.textContent = message;
        notice.classList.toggle("bad", Boolean(bad));
      }
      const viewerNotice = $("viewerNotice");
      if (viewerNotice) {
        viewerNotice.textContent = message || "";
        viewerNotice.hidden = !message;
        viewerNotice.classList.toggle("bad", Boolean(bad));
      }
      const analysisNotice = $("analysisNotice");
      if (analysisNotice) {
        analysisNotice.textContent = message || "";
        analysisNotice.hidden = !message;
        analysisNotice.classList.toggle("bad", Boolean(bad));
        const browserList = analysisNotice.closest(".browser-list");
        if (browserList) {
          browserList.classList.toggle("has-notice", Boolean(message));
        }
      }
    }

    async function apiGet(path, params) {
      const qs = new URLSearchParams(params || {});
      const response = await fetch(path + (qs.toString() ? "?" + qs.toString() : ""));
      return readApiResponse(response);
    }

    async function apiPost(path, body) {
      const response = await fetch(path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });
      return readApiResponse(response);
    }

    async function readApiResponse(response) {
      const payload = await response.json();
      if (!payload.ok) {
        throw new Error(payload.error || response.statusText);
      }
      return payload.data;
    }

    function currentCasePath() {
      const value = normalizePathInput($("casePath").value);
      $("casePath").value = value;
      state.casePath = value;
      localStorage.setItem("kdft.casePath", value);
      return value;
    }

    function currentEvidencePath() {
      const value = normalizePathInput($("evidencePath").value);
      $("evidencePath").value = value;
      localStorage.setItem("kdft.evidencePath", value);
      return value;
    }

    function currentReportPath() {
      const value = normalizePathInput($("reportPath").value);
      $("reportPath").value = value;
      return value;
    }

    function normalizePathInput(value) {
      let text = String(value ?? "").trim();
      while (text.length >= 2) {
        const first = text[0];
        const last = text[text.length - 1];
        const quoted = (first === '"' && last === '"')
          || (first === "'" && last === "'")
          || (first === "\u201c" && last === "\u201d")
          || (first === "\u2018" && last === "\u2019");
        if (!quoted) {
          break;
        }
        text = text.slice(1, -1).trim();
      }
      return text;
    }

    function analysisWindowUrl() {
      const params = new URLSearchParams();
      params.set("mode", "analysis");
      params.set("case_path", currentCasePath());
      if (state.browserState.evidenceId) {
        params.set("evidence_id", String(state.browserState.evidenceId));
      }
      if (state.browserState.selectedPath) {
        params.set("selected_path", state.browserState.selectedPath);
      }
      const treeMode = state.browserState.treeMode || "filesystem";
      params.set("tree_mode", treeMode);
      if (treeMode === "categories") {
        params.set("selected_category", state.browserState.selectedCategory || "");
      }
      return window.location.origin + window.location.pathname + "?" + params.toString();
    }

    function openAnalyzeWindow() {
      window.open(analysisWindowUrl(), "_blank", "noopener");
    }

    async function refresh() {
      const casePath = currentCasePath();
      if (!casePath) {
        setNotice("Case path is empty.", true);
        return;
      }
      try {
        state.data = await apiGet("/api/state", { case_path: casePath });
        renderState();
        applyPendingAnalysisSelection();
        // Once a case is open the sidebar is rarely needed - collapse it for
        // more workspace unless the examiner has expanded it explicitly.
        if (localStorage.getItem("kdft.sidebarCollapsed") !== "0") {
          document.querySelector(".app").classList.add("sidebar-collapsed");
        }
        setNotice("Loaded " + state.data.case.name + ".");
      } catch (err) {
        state.data = null;
        renderEmptyState();
        if (!ANALYSIS_MODE) {
          caseOpenSetupView();
        }
        setNotice(err.message, true);
      }
    }

    function suggestedNewCasePath() {
      const current = normalizePathInput($("casePath").value || "");
      const separator = current.includes("/") && !current.includes("\\") ? "/" : "\\";
      const folder = current.includes(separator)
        ? current.slice(0, current.lastIndexOf(separator))
        : "ui-output";
      const stamp = new Date().toISOString().replace(/[-:T]/g, "").slice(0, 14);
      return folder + separator + "case-" + stamp + ".kdft.sqlite";
    }

    function caseOpenSetupView() {
      if (!$("setupCasePath").value) {
        $("setupCasePath").value = suggestedNewCasePath();
      }
      if (!$("caseOpenPath").value) {
        $("caseOpenPath").value = normalizePathInput($("casePath").value || "");
      }
      switchView("setupView");
    }

    async function createCase() {
      try {
        const target = normalizePathInput($("setupCasePath").value);
        if (!target) {
          setNotice("Enter a case database file path first.", true);
          return;
        }
        $("casePath").value = target;
        state.casePath = target;
        localStorage.setItem("kdft.casePath", target);
        const data = await apiPost("/api/case/create", {
          case_path: target,
          name: $("newCaseName").value,
          examiner: $("newCaseExaminer").value,
          case_number: $("newCaseNumber").value,
          case_type: $("newCaseType").value,
          description: $("newCaseDescription").value
        });
        await refresh();
        switchView("evidenceView");
        setNotice("Created case " + data.case_id + ". Now add evidence.");
      } catch (err) {
        setNotice(err.message, true);
      }
    }

    async function openExistingCase() {
      const target = normalizePathInput($("caseOpenPath").value);
      if (!target) {
        setNotice("Enter the case database path to open.", true);
        return;
      }
      $("casePath").value = target;
      state.casePath = target;
      localStorage.setItem("kdft.casePath", target);
      await refresh();
      if (state.data) {
        switchView("dashboardView");
      }
    }

    function currentEvidenceType() {
      const active = document.querySelector("#evidenceTypeRow .evidence-type.active");
      return active ? active.dataset.type : "image";
    }

    const EVIDENCE_TYPE_LABELS = {
      image: { label: "Image path", placeholder: "C:\\Evidence\\image.E01", button: "Add Evidence", pick: "file", filter: "image", hint: "E01 (split segments auto-detected), dd/raw, split .001, VHD/VHDX, VMDK, VDI disk images" },
      folder: { label: "Folder path", placeholder: "C:\\Evidence\\source-folder", button: "Add Evidence", pick: "folder", filter: "any", hint: "A local folder of files" },
      file: { label: "File path", placeholder: "C:\\Evidence\\document.pdf", button: "Add Evidence", pick: "file", filter: "any", hint: "A single local file" },
      browser_history: { label: "Profile folder", placeholder: "C:\\Users\\me\\AppData\\Local\\Google\\Chrome\\User Data\\Default", button: "Import Browser History", pick: "folder", filter: "any", hint: "Chrome/Edge/Chromium profile folder (or paste a History database path)" }
    };

    function setEvidenceType(type) {
      document.querySelectorAll("#evidenceTypeRow .evidence-type").forEach((button) => {
        button.classList.toggle("active", button.dataset.type === type);
      });
      const spec = EVIDENCE_TYPE_LABELS[type] || EVIDENCE_TYPE_LABELS.image;
      const label = $("evidencePathLabel");
      label.childNodes[0].textContent = spec.label;
      $("evidencePath").placeholder = spec.placeholder;
      $("evidenceTypeHint").textContent = spec.hint;
      $("addEvidence").textContent = spec.button;
      $("fsOptionsRow").hidden = type === "browser_history";
      $("historyOptionsRow").hidden = type !== "browser_history";
    }

    async function addEvidence() {
      const type = currentEvidenceType();
      if (type === "browser_history") {
        await importHistory();
        return;
      }
      try {
        const processNow = $("readFileSystem").value === "true";
        const data = await apiPost("/api/evidence/add", {
          case_path: currentCasePath(),
          path: currentEvidencePath(),
          kind: type,
          read_file_system: processNow,
          notes: $("evidenceNotes").value
        });
        if (!processNow) {
          await refresh();
          selectEvidenceSource(data.evidence_id, "/");
          setNotice("Attached evidence " + data.evidence_id + ".");
          return;
        }
        try {
          const processed = await apiPost("/api/evidence/process", {
            case_path: currentCasePath(),
            evidence_id: data.evidence_id,
            max_entries: 0
          });
          await refresh();
          selectEvidenceSource(data.evidence_id, preferredAnalysisPath(data.evidence_id));
          setNotice("Attached and processed evidence " + data.evidence_id + " with " + processed.entries_indexed + " entries.");
        } catch (processErr) {
          await refresh();
          selectEvidenceSource(data.evidence_id, "/");
          setNotice("Attached evidence " + data.evidence_id + ", but processing failed: " + processErr.message, true);
        }
      } catch (err) {
        setNotice(err.message, true);
      }
    }

    async function pickEvidencePath() {
      const type = currentEvidenceType();
      const spec = EVIDENCE_TYPE_LABELS[type] || EVIDENCE_TYPE_LABELS.image;
      const browseButton = $("browseEvidence");
      browseButton.disabled = true;
      setNotice(spec.pick === "folder"
        ? "Choose the folder in the Windows dialog, then press Open."
        : "Choose the file in the Windows dialog.");
      try {
        const data = await apiGet("/api/pick", {
          mode: spec.pick,
          filter: spec.filter,
          start: currentEvidencePath()
        });
        if (data.path) {
          $("evidencePath").value = data.path;
          localStorage.setItem("kdft.evidencePath", data.path);
          setNotice("Selected " + data.path + ".");
        } else {
          setNotice("Browse cancelled.");
        }
      } catch (err) {
        setNotice(err.message, true);
      } finally {
        browseButton.disabled = false;
      }
    }

    async function processEvidence(id) {
      try {
        const data = await apiPost("/api/evidence/process", {
          case_path: currentCasePath(),
          evidence_id: id,
          max_entries: 0
        });
        let message = "Process job " + data.job_id + " " + data.status + " with " + data.entries_indexed + " entries.";
        if (data.bookmark_items_relinked > 0) {
          message += " Re-linked " + data.bookmark_items_relinked + " bookmark item(s) to the new index.";
        }
        await refresh();
        selectEvidenceSource(id, preferredAnalysisPath(id));
        setNotice(message);
      } catch (err) {
        setNotice(err.message, true);
      }
    }

    async function removeEvidence(id) {
      const evidence = state.data && state.data.evidence.find((item) => item.id === id);
      const name = evidence ? evidence.display_name : "evidence #" + id;
      if (!window.confirm("Remove " + name + " from this case? Indexed entries for this source will be removed.")) {
        return;
      }
      try {
        const data = await apiPost("/api/evidence/remove", {
          case_path: currentCasePath(),
          evidence_id: id
        });
        if (state.browserState.evidenceId === id) {
          state.browserState = { evidenceId: null, selectedPath: "/", treeMode: "filesystem", selectedCategory: "" };
          state.selectedEntryIds = new Set();
          state.hex = makeHexState();
        }
        const message = "Removed evidence " + data.evidence_id + " and " + data.removed_entries + " indexed entries.";
        await refresh();
        setNotice(message);
      } catch (err) {
        setNotice(err.message, true);
      }
    }

    async function recoverEntry(entryId) {
      const entry = state.data && state.data.entries.find((item) => item.id === entryId);
      if (!entry) {
        setNotice("Entry is not loaded.", true);
        return;
      }
      const labels = recoveryActionText(entry);
      const defaultPath = defaultRecoveryPath(entry);
      const outputPath = window.prompt(labels.prompt + " to:", defaultPath);
      if (!outputPath) {
        return;
      }
      try {
        setNotice(labels.button + " in progress...");
        const data = await apiPost("/api/entry/recover", {
          case_path: currentCasePath(),
          entry_id: entryId,
          output_path: normalizePathInput(outputPath)
        });
        setNotice(labels.past + " " + data.bytes_written + " bytes to " + data.output_path + ".");
      } catch (err) {
        setNotice(err.message, true);
      }
    }

    function showEntryDetails() {
      if (!state.hex.entryId) {
        setNotice("Select an entry before opening details.", true);
        return;
      }
      $("viewerMode").value = "metadata";
      renderHexViewer();
    }

    function bindInspectorResize() {
      const handle = $("viewerResizer");
      const workspace = document.querySelector(".browser-workspace");
      if (!handle || !workspace) {
        return;
      }
      handle.addEventListener("pointerdown", (event) => {
        if (window.matchMedia("(max-width: 980px)").matches) {
          return;
        }
        event.preventDefault();
        handle.setPointerCapture(event.pointerId);
        handle.classList.add("dragging");
        const onMove = (moveEvent) => {
          const rect = workspace.getBoundingClientRect();
          const maxWidth = Math.min(760, Math.max(380, rect.width - 760));
          const width = Math.max(360, Math.min(maxWidth, rect.right - moveEvent.clientX - 10));
          workspace.style.setProperty("--inspector-width", width + "px");
        };
        const onUp = () => {
          handle.classList.remove("dragging");
          handle.removeEventListener("pointermove", onMove);
          handle.removeEventListener("pointerup", onUp);
          handle.removeEventListener("pointercancel", onUp);
        };
        handle.addEventListener("pointermove", onMove);
        handle.addEventListener("pointerup", onUp);
        handle.addEventListener("pointercancel", onUp);
      });
    }

    function setInspectorCollapsed(collapsed) {
      state.inspectorCollapsed = Boolean(collapsed);
      const workspace = document.querySelector(".browser-workspace");
      if (workspace) {
        workspace.classList.toggle("inspector-collapsed", state.inspectorCollapsed);
      }
      const button = $("toggleInspector");
      if (button) {
        button.textContent = state.inspectorCollapsed ? "Show inspector" : "Hide inspector";
      }
    }

    function toggleInspectorPane() {
      setInspectorCollapsed(!state.inspectorCollapsed);
    }

    async function analyzeDiskImageEntry(entryId) {
      const entry = state.data && state.data.entries.find((item) => item.id === entryId);
      const evidence = selectedEvidenceSource();
      if (!entry || !evidence) {
        setNotice("Select a disk image entry first.", true);
        return;
      }
      const imagePath = evidenceEntryLocalPath(evidence, entry);
      if (!imagePath) {
        setNotice("This disk image entry cannot be analyzed directly from its current source.", true);
        return;
      }
      try {
        let imageEvidence = state.data.evidence.find((item) => sameLocalPath(item.source_path, imagePath));
        if (!imageEvidence) {
          const attached = await apiPost("/api/evidence/add", {
            case_path: currentCasePath(),
            path: imagePath,
            kind: "image",
            read_file_system: true,
            notes: "Promoted from " + evidence.display_name + " " + entry.logical_path
          });
          await refresh();
          imageEvidence = state.data.evidence.find((item) => item.id === attached.evidence_id);
        }
        if (!imageEvidence) {
          setNotice("Image evidence was attached but is not loaded yet.", true);
          return;
        }
        const processed = await apiPost("/api/evidence/process", {
          case_path: currentCasePath(),
          evidence_id: imageEvidence.id,
          max_entries: 0
        });
        const message = "Analyzed image " + imageEvidence.display_name + ": " + processed.entries_indexed + " entries (" + processed.status + ").";
        await refresh();
        selectEvidenceSource(imageEvidence.id, preferredAnalysisPath(imageEvidence.id));
        setNotice(message);
      } catch (err) {
        setNotice(err.message, true);
      }
    }

    async function importHistory() {
      try {
        const data = await apiPost("/api/history/import", {
          case_path: currentCasePath(),
          history_path: currentEvidencePath(),
          max_visits: numberValue("historyMaxVisits", 5000),
          evidence_name: "Browser Activities"
        });
        const message = "Imported browser activities: " + data.entries_indexed + " records (" + data.status + ").";
        await refresh();
        selectEvidenceSource(data.evidence_id, data.visits_indexed > 0 ? "/Browser Activities/Visits" : "/Browser Activities");
        setNotice(message);
      } catch (err) {
        setNotice(err.message, true);
      }
    }

    function selectEvidenceSource(id, selectedPath = "/") {
      state.browserState = {
        evidenceId: id,
        selectedPath: normalizeLogicalPath(selectedPath),
        treeMode: state.browserState.treeMode || "filesystem",
        selectedCategory: ""
      };
      expandTreePath(state.browserState.selectedPath);
      state.selectedEntryIds = new Set();
      state.hex = makeHexState(null, 0, numberValue("hexLength", 512));
      renderEvidenceBrowserEntries();
      renderHexViewer();
      switchView("analyzeView");
      const evidence = state.data.evidence.find((item) => item.id === id);
      setNotice(evidence ? "Selected evidence " + evidence.display_name + "." : "Selected evidence.");
    }

    function selectFolder(path) {
      state.browserState.treeMode = "filesystem";
      state.browserState.selectedPath = normalizeLogicalPath(path || "/");
      expandTreePath(state.browserState.selectedPath);
      state.hex = makeHexState(null, 0, numberValue("hexLength", 512));
      renderEvidenceBrowserEntries();
      renderHexViewer();
      setNotice("Selected folder " + displayPath(state.browserState.selectedPath) + ".");
    }

    function selectCategory(categoryKey) {
      state.browserState.treeMode = "categories";
      state.browserState.selectedCategory = categoryKey || "";
      state.hex = makeHexState(null, 0, numberValue("hexLength", 512));
      renderEvidenceBrowserEntries();
      renderHexViewer();
      setNotice("Selected category " + (categoryLabel(categoryKey) || "All Categories") + ".");
    }

    function setBrowserTreeMode(mode) {
      state.browserState.treeMode = mode === "categories" ? "categories" : "filesystem";
      if (state.browserState.treeMode === "categories") {
        state.browserState.selectedCategory = state.browserState.selectedCategory || "";
      }
      renderEvidenceBrowserEntries();
    }

    function toggleEntrySelection(entryId, checked, event) {
      if (event && event.shiftKey && state.lastSelectedEntryId) {
        selectEntryRange(state.lastSelectedEntryId, entryId, true);
        renderEvidenceBrowserEntries();
        setNotice("Selected " + state.selectedEntryIds.size + " entries.");
        return;
      }
      setEntrySelection(entryId, checked);
      state.lastSelectedEntryId = entryId;
      renderSelectionCount();
    }

    function setEntrySelection(entryId, selected) {
      if (selected) {
        state.selectedEntryIds.add(entryId);
      } else {
        state.selectedEntryIds.delete(entryId);
      }
    }

    function selectEntryRange(fromEntryId, toEntryId, selected) {
      const ids = visibleEntryIds();
      const fromIndex = ids.indexOf(fromEntryId);
      const toIndex = ids.indexOf(toEntryId);
      if (fromIndex < 0 || toIndex < 0) {
        setEntrySelection(toEntryId, selected);
        state.lastSelectedEntryId = toEntryId;
        return;
      }
      const start = Math.min(fromIndex, toIndex);
      const end = Math.max(fromIndex, toIndex);
      ids.slice(start, end + 1).forEach((id) => setEntrySelection(id, selected));
      state.lastSelectedEntryId = toEntryId;
    }

    function handleEntryRowClick(event, entryId) {
      if (event && event.shiftKey && state.lastSelectedEntryId) {
        selectEntryRange(state.lastSelectedEntryId, entryId, true);
        renderEvidenceBrowserEntries();
        setNotice("Selected " + state.selectedEntryIds.size + " entries.");
        return;
      }
      if (event && (event.ctrlKey || event.metaKey)) {
        setEntrySelection(entryId, !state.selectedEntryIds.has(entryId));
        state.lastSelectedEntryId = entryId;
        renderEvidenceBrowserEntries();
        renderSelectionCount();
        return;
      }
      state.lastSelectedEntryId = entryId;
      selectBrowserEntry(entryId);
    }

    function selectVisibleEntries() {
      if (state.live.active) {
        const visible = visibleLiveEntries();
        if (visible.length === 0) {
          setNotice("No visible live entries to select.", true);
          return;
        }
        visible.forEach((item) => setLiveSelection(item, true));
        renderLiveBrowse();
        setNotice("Selected " + visible.length + " visible live entries.");
        return;
      }
      const entries = visibleFolderEntries();
      if (entries.length === 0) {
        setNotice("No visible entries to select.", true);
        return;
      }
      entries.forEach((entry) => state.selectedEntryIds.add(entry.id));
      renderEvidenceBrowserEntries();
      setNotice("Selected " + entries.length + " visible entries.");
    }

    function clearEntrySelection() {
      state.selectedEntryIds = new Set();
      state.lastSelectedEntryId = null;
      renderEvidenceBrowserEntries();
      renderSelectionCount();
    }

    function restoreEntrySelection(ids) {
      if (!state.data) {
        state.selectedEntryIds = new Set();
        return;
      }
      const valid = new Set(state.data.entries.map((entry) => entry.id));
      for (const path in state.idx.dirCache) {
        state.idx.dirCache[path].forEach((child) => {
          if (child.entry_id != null) {
            valid.add(child.entry_id);
          }
        });
      }
      state.selectedEntryIds = new Set(ids.filter((id) => valid.has(id)));
    }

    async function bookmarkSelectedEntries() {
      const ids = Array.from(state.selectedEntryIds);
      if (ids.length === 0) {
        setNotice("Select one or more entries first.", true);
        return { succeeded: 0, failed: ids.length };
      }
      let succeeded = 0;
      const failed = [];
      let lastError = "";
      for (const entryId of ids) {
        try {
          await bookmarkEntry(entryId, false);
          succeeded += 1;
        } catch (err) {
          failed.push(entryId);
          lastError = err.message || String(err);
        }
      }
      await refresh();
      restoreEntrySelection(ids);
      renderEvidenceBrowserEntries();
      renderSelectionCount();
      if (failed.length) {
        setNotice("Bookmarked " + succeeded + " selected entries; " + failed.length + " failed" + (lastError ? ": " + lastError : "."), true);
        return { succeeded, failed: failed.length };
      }
      setNotice("Bookmarked " + succeeded + " selected entries.");
      return { succeeded, failed: 0 };
    }

    async function exportSelectedEntries() {
      const ids = Array.from(state.selectedEntryIds);
      if (ids.length === 0) {
        setNotice("Select one or more file entries first.", true);
        return { succeeded: 0, failed: ids.length };
      }
      let succeeded = 0;
      const failed = [];
      let lastError = "";
      for (const entryId of ids) {
        const entry = findLoadedEntry(entryId);
        if (!entry || entry.entry_kind !== "file") {
          failed.push(entryId);
          lastError = "Only file entries can be exported.";
          continue;
        }
        try {
          await apiPost("/api/entry/recover", {
            case_path: currentCasePath(),
            entry_id: entryId,
            output_path: defaultRecoveryPath(entry)
          });
          succeeded += 1;
        } catch (err) {
          failed.push(entryId);
          lastError = err.message || String(err);
        }
      }
      await refresh();
      restoreEntrySelection(ids);
      renderEvidenceBrowserEntries();
      renderSelectionCount();
      if (failed.length) {
        setNotice("Exported " + succeeded + " selected files; " + failed.length + " failed" + (lastError ? ": " + lastError : "."), true);
        return { succeeded, failed: failed.length };
      }
      setNotice("Exported " + succeeded + " selected file" + (succeeded === 1 ? "" : "s") + " to ui-output.");
      return { succeeded, failed: 0 };
    }

    async function handleSelectedAction() {
      const selectedAction = $("selectedAction");
      const action = selectedAction.value;
      selectedAction.selectedIndex = 0;
      if (!action) {
        return;
      }
      if (state.live.active) {
        if (action === "bookmark") {
          await bookmarkSelectedLive();
        } else if (action === "bookmark_report") {
          await bookmarkSelectedLive();
          await exportReport();
        } else if (action === "export_files") {
          await exportSelectedLive();
        } else if (action === "clear") {
          clearLiveSelection();
        } else {
          setNotice("That action is not available in live browse.", true);
        }
        return;
      }
      if (action === "bookmark") {
        await bookmarkSelectedEntries();
        return;
      }
      if (action === "bookmark_report") {
        const result = await bookmarkSelectedEntries();
        if (result && result.succeeded > 0) {
          await exportReport();
        }
        return;
      }
      if (action === "export_files") {
        await exportSelectedEntries();
        return;
      }
      if (action === "export_csv") {
        exportSelectedCsv();
        return;
      }
      if (action === "clear") {
        clearEntrySelection();
      }
    }

    function csvField(value) {
      const text = value == null ? "" : String(value);
      return /[",\r\n]/.test(text) ? '"' + text.replace(/"/g, '""') + '"' : text;
    }

    // Axy-style "Create export": write the selected artifacts to a CSV download with the
    // examiner-grade columns (identity, category, size, MAC times, deleted state, offsets).
    function exportSelectedCsv() {
      const entries = state.data
        ? state.data.entries.filter((entry) => state.selectedEntryIds.has(entry.id))
        : [];
      if (entries.length === 0) {
        setNotice("Select rows to export first.", true);
        return;
      }
      const header = ["Name", "Logical path", "Evidence", "Category", "Type", "Size (bytes)",
        "Created", "Accessed", "Modified", "Deleted", "Flags", "Offset"];
      const evidenceNames = new Map((state.data.evidence || []).map((item) => [item.id, item.display_name]));
      const lines = [header.join(",")];
      entries.forEach((entry) => {
        lines.push([
          csvField(entry.name || logicalName(entry.logical_path)),
          csvField(entry.logical_path),
          csvField(evidenceNames.get(entry.evidence_id) || entry.evidence_id),
          csvField(entryCategoryLabel(entry)),
          csvField(entry.entry_kind),
          csvField(entry.size_bytes == null ? "" : entry.size_bytes),
          csvField(filesystemCreatedTime(entry)),
          csvField(filesystemAccessedTime(entry)),
          csvField(filesystemModifiedTime(entry)),
          csvField(entry.is_deleted ? "yes" : "no"),
          csvField(entryFlagsText(entry)),
          csvField(entryPrimaryOffset(entry))
        ].join(","));
      });
      const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
      const blob = new Blob(["ï»¿" + lines.join("\r\n") + "\r\n"], { type: "text/csv;charset=utf-8" });
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = "kdft-export-" + stamp + ".csv";
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(link.href);
      setNotice("Exported " + entries.length + " selected item(s) to CSV.");
    }

    function selectBrowserEntry(entryId) {
      const entry = findLoadedEntry(entryId);
      if (!entry) {
        setNotice("Entry is not loaded.", true);
        return;
      }
      if (entry.entry_kind === "directory") {
        selectFolder(entry.logical_path);
        return;
      }
      state.hex = makeHexState(entry.id, 0, numberValue("hexLength", 512));
      $("viewerMode").value = "metadata";
      renderHexViewer();
      const evidence = selectedEvidenceSource();
      if (entry.entry_kind === "file" && isPromotableDiskImageEntry(entry, evidence)) {
        setNotice("Disk image file selected. Use Analyze image to decode the container.");
        return;
      }
      setNotice("Selected " + (entry.name || logicalName(entry.logical_path)) + ".");
    }

    async function openEntry(entryId) {
      state.hex = makeHexState(entryId, 0, numberValue("hexLength", 512));
      $("viewerMode").value = "hex";
      $("hexOffset").value = String(state.hex.offset);
      await fetchEntryBytes();
    }

    async function fetchEntryBytes() {
      if (!state.hex.entryId && !state.hex.live) {
        renderHexViewer();
        return;
      }
      if (state.hex.fetching) {
        return;
      }
      state.hex.fetching = true;
      try {
        const data = state.hex.live
          ? await apiGet("/api/image/bytes", {
              case_path: currentCasePath(),
              evidence_id: state.hex.live.evidenceId,
              volume: state.hex.live.volume,
              path: state.hex.live.path,
              offset: state.hex.offset,
              length: state.hex.length
            })
          : await apiGet("/api/entry/bytes", {
              case_path: currentCasePath(),
              entry_id: state.hex.entryId,
              offset: state.hex.offset,
              length: state.hex.length
            });
        clearHexSelection();
        state.hex.data = data;
        $("hexOffset").value = String(data.offset);
        $("hexLength").value = String(data.requested_length);
        state.hex.fetching = false;
        renderHexViewer();
        setNotice("Opened entry bytes at offset " + data.offset + ".");
      } catch (err) {
        clearHexSelection();
        state.hex.data = null;
        state.hex.fetching = false;
        renderHexViewer(err.message);
        setNotice(err.message, true);
      }
    }

    async function gotoHexOffset() {
      state.hex.offset = offsetValue();
      state.hex.length = numberValue("hexLength", 512);
      await fetchEntryBytes();
    }

    async function stepHex(delta) {
      const length = numberValue("hexLength", 512);
      const current = state.hex.data ? Number(state.hex.data.offset) : offsetValue();
      state.hex.length = length;
      state.hex.offset = Math.max(0, current + (delta * length));
      await fetchEntryBytes();
    }

    async function runSearch() {
      state.searchResults = [];
      state.selectedSearchIndexes = new Set();
      renderSearchResults();
      try {
        state.searchResults = await apiPost("/api/search/deep", {
          case_path: currentCasePath(),
          query: $("searchQuery").value,
          evidence_id: $("searchEvidence").value ? Number($("searchEvidence").value) : null,
          include_content: $("includeContent").value === "true",
          max_results: numberValue("maxResults", 50),
          max_file_bytes: numberValue("maxFileBytes", 65536),
          category: $("searchCategory").value || null,
          file_types: $("searchFileTypes").value || null
        });
        state.selectedSearchIndexes = new Set();
        renderSearchResults();
        setNotice("Search returned " + state.searchResults.length + " results.");
      } catch (err) {
        setNotice(err.message, true);
      }
    }

    function goToSearchResult(index) {
      const hit = state.searchResults[index];
      if (!hit) {
        setNotice("Search result is no longer loaded.", true);
        return;
      }
      const entry = state.data && state.data.entries.find((item) => item.id === hit.entry_id);
      if (!entry) {
        setNotice("Search result entry is not loaded in the current case state.", true);
        return;
      }
      const selectedPath = entry.entry_kind === "directory"
        ? normalizeLogicalPath(entry.logical_path)
        : parentLogicalPath(entry.logical_path);
      state.browserState = {
        evidenceId: entry.evidence_id,
        selectedPath,
        treeMode: "filesystem",
        selectedCategory: ""
      };
      expandTreePath(selectedPath);
      state.selectedEntryIds = new Set([entry.id]);
      state.hex = makeHexState(entry.id, 0, numberValue("hexLength", 512));
      $("viewerMode").value = "metadata";
      switchView("analyzeView");
      renderEvidenceBrowserEntries();
      const offset = entryPrimaryOffset(entry);
      const location = offset ? " File starts at " + offset + "." : "";
      setNotice("Opened source for " + (entry.name || logicalName(entry.logical_path)) + "." + location);
    }

    async function bookmarkEvidence(index) {
      const evidence = state.data.evidence[index];
      try {
        await apiPost("/api/bookmark/quick", {
          case_path: currentCasePath(),
          folder_name: "Evidence",
          title: "Evidence: " + evidence.display_name,
          comment: evidence.notes || "",
          bookmark_type: "notable_file",
          data_type: "Evidence Source",
          evidence_id: evidence.id,
          display_name: evidence.display_name,
          logical_path: evidence.source_path,
          item_ref_json: { kind: "evidence_source", source_kind: evidence.source_kind }
        });
        await refresh();
        setNotice("Bookmarked evidence " + evidence.id + ".");
      } catch (err) {
        setNotice(err.message, true);
      }
    }

    function idxChildToEntry(child) {
      return {
        id: child.entry_id,
        evidence_id: state.idx.evidenceId,
        logical_path: child.logical_path,
        name: child.name,
        entry_kind: child.is_dir ? "directory" : "file",
        size_bytes: child.size_bytes,
        is_deleted: child.is_deleted,
        metadata_json: child.metadata_json || {}
      };
    }

    function findLoadedEntry(entryId) {
      const inState = state.data.entries.find((item) => item.id === entryId);
      if (inState) {
        return inState;
      }
      // Entry may have come from the lazy indexed browse cache instead.
      for (const path in state.idx.dirCache) {
        const child = state.idx.dirCache[path].find((item) => item.entry_id === entryId);
        if (child) {
          return idxChildToEntry(child);
        }
      }
      return null;
    }

    async function bookmarkEntry(entryId, refreshAfter = true) {
      const entry = findLoadedEntry(entryId);
      if (!entry) {
        setNotice("Entry is not loaded.", true);
        return;
      }
      const bookmark = entryBookmarkPayload(entry);
      try {
        await apiPost("/api/bookmark/quick", {
          case_path: currentCasePath(),
          folder_name: bookmark.folderName,
          title: bookmark.title,
          comment: bookmark.comment,
          bookmark_type: bookmark.bookmarkType,
          data_type: bookmark.dataType,
          evidence_id: entry.evidence_id,
          entry_id: entry.id,
          display_name: bookmark.displayName,
          logical_path: entry.logical_path,
          data_preview: bookmark.dataPreview,
          item_ref_json: bookmark.itemRefJson
        });
        if (refreshAfter) {
          await refresh();
          setNotice("Bookmarked entry " + displayPath(entry.logical_path) + ".");
        }
      } catch (err) {
        setNotice(err.message, true);
        if (!refreshAfter) {
          throw err;
        }
      }
    }

    async function bookmarkSearchResult(index) {
      const hit = state.searchResults[index];
      await bookmarkSearchHit(hit, true);
    }

    async function bookmarkSearchHit(hit, refreshAfter = true) {
      try {
        await apiPost("/api/bookmark/quick", {
          case_path: currentCasePath(),
          folder_name: "Search Hits",
          title: "Search hit: " + hit.display_name,
          comment: "Match kind: " + hit.match_kind,
          bookmark_type: hit.match_kind === "content" ? "highlighted_data" : "notable_file",
          data_type: "Search Hit",
          evidence_id: hit.evidence_id,
          entry_id: hit.entry_id,
          display_name: hit.display_name,
          logical_path: hit.logical_path,
          selection_offset: hit.selection_offset,
          selection_length: hit.selection_length,
          data_preview: hit.data_preview,
          item_ref_json: searchResultItemRef(hit)
        });
        if (refreshAfter) {
          await refresh();
          setNotice("Bookmarked result " + hit.entry_id + ".");
        }
      } catch (err) {
        setNotice(err.message, true);
        if (!refreshAfter) {
          throw err;
        }
      }
    }

    async function bookmarkSelectedSearchResults() {
      const indexes = Array.from(state.selectedSearchIndexes || []).sort((left, right) => left - right);
      if (indexes.length === 0) {
        setNotice("No search results selected.", true);
        return;
      }
      let succeeded = 0;
      const failed = [];
      let lastError = "";
      for (const index of indexes) {
        const hit = state.searchResults[index];
        if (!hit) {
          failed.push(index);
          lastError = "Search result is no longer loaded.";
          continue;
        }
        try {
          await bookmarkSearchHit(hit, false);
          succeeded += 1;
        } catch (err) {
          failed.push(index);
          lastError = err.message || String(err);
        }
      }
      state.selectedSearchIndexes = new Set(failed);
      await refresh();
      renderSearchResults();
      if (failed.length) {
        setNotice("Bookmarked " + succeeded + " search result" + (succeeded === 1 ? "" : "s") + "; " + failed.length + " failed" + (lastError ? ": " + lastError : "."), true);
        return;
      }
      setNotice("Bookmarked " + succeeded + " search result" + (succeeded === 1 ? "" : "s") + ".");
    }

    async function clearFindings() {
      const bookmarkCount = state.data ? state.data.bookmarks.length : 0;
      const reportCount = state.data ? state.data.report.folders.length : 0;
      if (bookmarkCount === 0 && reportCount === 0) {
        setNotice("No findings to clear.");
        return;
      }
      if (!window.confirm("Clear all bookmarks and report findings for this case? Evidence and indexed entries stay attached.")) {
        return;
      }
      try {
        const cleared = await apiPost("/api/findings/clear", {
          case_path: currentCasePath()
        });
        await refresh();
        setNotice("Cleared " + cleared.removed_bookmarks + " bookmarks and " + cleared.removed_items + " bookmarked items.");
      } catch (err) {
        setNotice(err.message, true);
      }
    }

    function toggleSearchResultSelection(index, selected) {
      if (selected) {
        state.selectedSearchIndexes.add(index);
      } else {
        state.selectedSearchIndexes.delete(index);
      }
      renderSearchSelectionCount();
    }

    function selectAllSearchResults() {
      state.selectedSearchIndexes = new Set(state.searchResults.map((_hit, index) => index));
      renderSearchResults();
    }

    function clearSelectedSearchResults() {
      state.selectedSearchIndexes = new Set();
      renderSearchResults();
    }

    async function exportReport() {
      try {
        const data = await apiPost("/api/report/export", {
          case_path: currentCasePath(),
          output_path: currentReportPath()
        });
        state.lastReportPath = data.report;
        await refresh();
        setNotice("Wrote report " + data.report + ".");
      } catch (err) {
        setNotice(err.message, true);
      }
    }

    async function openReport() {
      try {
        await apiPost("/api/report/open", {
          case_path: currentCasePath(),
          output_path: currentReportPath()
        });
        setNotice("Opened report.");
      } catch (err) {
        setNotice(err.message, true);
      }
    }

    function renderState() {
      const data = state.data;
      $("caseTitle").textContent = data.case.name;
      $("caseMeta").textContent = "Examiner: " + (data.case.examiner_name || "unknown") + " | Created: " + data.case.created_at;
      $("statEvidence").textContent = data.evidence.length;
      $("statEntries").textContent = data.entry_count;
      $("statBookmarks").textContent = data.bookmarks.length;
      $("statReport").textContent = data.report.folders.length;
      if (!data.evidence.some((item) => item.id === state.browserState.evidenceId)) {
        const treeMode = state.browserState.treeMode || "filesystem";
        state.browserState = {
          evidenceId: data.evidence.length > 0 ? data.evidence[0].id : null,
          selectedPath: "/",
          treeMode,
          selectedCategory: ""
        };
      }
      pruneSelectedEntries();
      renderDashboard();
      renderEvidence();
      renderEvidenceBrowserEntries();
      renderSearchEvidence();
      renderBookmarks();
      renderReport();
    }

    function applyPendingAnalysisSelection() {
      const pending = state.pendingAnalysisSelection;
      if (!pending || pending.applied || !state.data) {
        return;
      }
      const requested = pending.evidenceId;
      const evidence = state.data.evidence.find((item) => item.id === requested)
        || state.data.evidence.find((item) => item.id === state.browserState.evidenceId)
        || state.data.evidence[0];
      pending.applied = true;
      if (evidence) {
        selectEvidenceSource(evidence.id, pending.selectedPath || preferredAnalysisPath(evidence.id));
        if (pending.treeMode === "categories") {
          selectCategory(pending.selectedCategory || "");
        }
      } else {
        switchView("analyzeView");
      }
    }

    function renderEmptyState() {
      $("caseTitle").textContent = "No case loaded";
      $("caseMeta").textContent = "";
      $("statEvidence").textContent = "0";
      $("statEntries").textContent = "0";
      $("statBookmarks").textContent = "0";
      $("statReport").textContent = "0";
      renderDashboard();
      $("evidenceTable").innerHTML = empty("No evidence.");
      $("filesystemTree").innerHTML = empty("No evidence selected.");
      $("entryTable").innerHTML = empty("No entries.");
      $("treeCount").textContent = "0";
      $("folderTitle").textContent = "/";
      $("selectedCount").textContent = "0 selected";
      state.browserState = { evidenceId: null, selectedPath: "/", treeMode: "filesystem", selectedCategory: "" };
      state.expandedTreePaths = new Map();
      state.selectedEntryIds = new Set();
      state.hex = makeHexState();
      renderHexViewer();
      $("bookmarksTable").innerHTML = empty("No bookmarks.");
      $("reportPreview").textContent = "{}";
      $("reportCount").textContent = "0 folders";
    }

    function renderDashboard() {
      if (!state.data) {
        $("dashboardCaseOverview").innerHTML = empty("Load or create a case to see dashboard details.");
        $("dashboardEvidenceOverview").innerHTML = empty("No evidence sources.");
        $("dashboardArtifactCategories").innerHTML = empty("No artifact categories.");
        return;
      }
      $("dashboardCaseOverview").innerHTML = renderDashboardCaseOverview(state.data);
      $("dashboardEvidenceOverview").innerHTML = renderDashboardEvidenceOverview(state.data);
      $("dashboardArtifactCategories").innerHTML = renderDashboardArtifactCategories(state.data);
    }

    function renderDashboardCaseOverview(data) {
      const facts = [
        ["Case name", data.case.name],
        ["Case number", data.case.case_number || "unspecified"],
        ["Case type", data.case.case_type || "unspecified"],
        ["Examiner", data.case.examiner_name || "unknown"],
        ["Created", data.case.created_at || "unknown"],
        ["Timezone", data.case.timezone || "unknown"],
        ["Evidence sources", data.evidence.length],
        ["Indexed entries", data.entry_count],
        ["Bookmarks", data.bookmarks.length]
      ];
      const description = data.case.description
        ? `<p class="muted tiny dashboard-description">${escapeHtml(data.case.description)}</p>`
        : "";
      return `<div class="dashboard-facts">${facts.map(([label, value]) => dashboardFact(label, value)).join("")}</div>${description}`;
    }

    function dashboardFact(label, value) {
      return `<div class="dashboard-fact"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`;
    }

    function renderDashboardEvidenceOverview(data) {
      if (data.evidence.length === 0) {
        return empty("No evidence sources attached.");
      }
      // Exact per-evidence counts come from the report rows (SQL COUNT);
      // the shipped entry list is capped on large cases.
      const reportCounts = new Map((data.report && data.report.evidence || [])
        .map((row) => [row.id, row.entries_indexed]));
      const sampleCounts = evidenceEntryCounts(data.entries);
      const rows = data.evidence.map((item) => {
        const entryCount = reportCounts.has(item.id)
          ? reportCounts.get(item.id)
          : (sampleCounts.get(item.id) || 0);
        const indexed = item.indexed_at
          ? escapeHtml(item.indexed_at)
          : evidenceProcessingStatusHtml(item, entryCount);
        return `
          <tr>
            <td><strong>${escapeHtml(item.display_name)}</strong><br><span class="muted tiny">${escapeHtml(item.source_path)}</span></td>
            <td><span class="pill">${escapeHtml(item.source_kind)}</span></td>
            <td>${item.size_bytes == null ? '<span class="muted tiny">unknown</span>' : escapeHtml(formatBytes(item.size_bytes))}</td>
            <td>${escapeHtml(Number(entryCount).toLocaleString())}</td>
            <td>${indexed}</td>
          </tr>`;
      }).join("");
      return `<div class="dashboard-table-wrap">${table(["Source", "Kind", "Size", "Entries", "Indexed"], rows)}</div>`;
    }

    function evidenceEntryCounts(entries) {
      const counts = new Map();
      entries.forEach((entry) => {
        counts.set(entry.evidence_id, (counts.get(entry.evidence_id) || 0) + 1);
      });
      return counts;
    }

    function evidenceIndexedEntryCount(evidenceId) {
      if (!state.data) {
        return 0;
      }
      const reportRow = (state.data.report && state.data.report.evidence || [])
        .find((row) => row.id === evidenceId);
      if (reportRow) {
        return Number(reportRow.entries_indexed) || 0;
      }
      return evidenceEntryCounts(state.data.entries).get(evidenceId) || 0;
    }

    function evidenceProcessingStatusHtml(item, entryCount = evidenceIndexedEntryCount(item.id)) {
      if (item.indexed_at) {
        return '<span class="pill good">indexed</span>';
      }
      if (item.read_file_system_requested && (Number(entryCount) > 0 || item.last_job_status === "truncated")) {
        return '<span class="pill warn">partially indexed</span>';
      }
      return '<span class="pill warn">attached</span>';
    }

    function renderDashboardArtifactCategories(data) {
      const categories = serverCategoryCountsAvailable()
        ? serverDashboardCategoryCounts(data.category_counts)
        : dashboardCategoryCounts(data.entries);
      if (categories.length === 0) {
        return empty("No indexed artifact categories.");
      }
      const maxCount = categories[0].count || 1;
      const rows = categories.map((category) => {
        const width = Math.max(4, Math.round((category.count / maxCount) * 100));
        return `<button class="dashboard-category-row" onclick="jumpToDashboardCategory('${escapeAttr(escapeJs(category.main))}')" title="Open ${escapeAttr(category.main)} in Analyze categories">
          <span class="dashboard-category-label">${escapeHtml(category.main)}</span>
          <span class="dashboard-category-bar" aria-hidden="true"><span style="--bar-width:${width}%"></span></span>
          <span class="dashboard-category-count">${category.count.toLocaleString()}</span>
        </button>`;
      }).join("");
      return `<div class="dashboard-category-list">${rows}</div>`;
    }

    // Exact SQL counts shipped by the server for large cases where the entry
    // list is truncated; the sampled 5000 entries would misrepresent bars.
    function serverCategoryCountsAvailable() {
      return Boolean(state.data && state.data.entries_truncated
        && Array.isArray(state.data.category_counts) && state.data.category_counts.length > 0);
    }

    function serverDashboardCategoryCounts(categoryCounts) {
      const counts = new Map();
      categoryCounts.forEach((row) => {
        counts.set(row.main, (counts.get(row.main) || 0) + row.count);
      });
      return Array.from(counts.entries())
        .map(([main, count]) => ({ main, count }))
        .sort((left, right) => right.count - left.count || left.main.localeCompare(right.main));
    }

    function dashboardCategoryCounts(entries) {
      const counts = new Map();
      entries.forEach((entry) => {
        const main = dashboardEntryMainCategory(entry);
        counts.set(main, (counts.get(main) || 0) + 1);
      });
      return Array.from(counts.entries())
        .map(([main, count]) => ({ main, count }))
        .sort((left, right) => right.count - left.count || left.main.localeCompare(right.main));
    }

    function dashboardEntryMainCategory(entry) {
      const metadata = entry.metadata_json || {};
      return metadata.category_main ? String(metadata.category_main) : entryCategory(entry).main;
    }

    function jumpToDashboardCategory(mainName) {
      if (!state.data) {
        switchView("analyzeView");
        return;
      }
      const evidenceId = dashboardEvidenceIdForCategory(mainName);
      if (evidenceId && state.browserState.evidenceId !== evidenceId) {
        state.browserState.evidenceId = evidenceId;
        state.browserState.selectedPath = preferredAnalysisPath(evidenceId);
        state.selectedEntryIds = new Set();
        state.lastSelectedEntryId = null;
      }
      selectCategory(categoryKey(mainName, ""));
      switchView("analyzeView");
    }

    function dashboardEvidenceIdForCategory(mainName) {
      const matchesCategory = (entry) => dashboardEntryMainCategory(entry) === mainName;
      const currentEvidenceId = state.browserState.evidenceId;
      if (currentEvidenceId && state.data.entries.some((entry) => entry.evidence_id === currentEvidenceId && matchesCategory(entry))) {
        return currentEvidenceId;
      }
      const match = state.data.entries.find(matchesCategory);
      if (match) {
        return match.evidence_id;
      }
      return currentEvidenceId || (state.data.evidence[0] && state.data.evidence[0].id) || null;
    }

    function renderEvidence() {
      const rows = state.data.evidence.map((item, index) => `
        <tr>
          <td><strong>${escapeHtml(item.display_name)}</strong><br><span class="muted tiny">${escapeHtml(item.source_path)}</span>${item.sha256_hex ? `<br><span class="muted tiny" title="SHA-256 computed ${escapeAttr(item.hashed_at || "")}">SHA-256: ${escapeHtml(item.sha256_hex)}</span>` : ""}</td>
          <td><span class="pill">${escapeHtml(item.source_kind)}</span></td>
          <td>${evidenceProcessingStatusHtml(item)}${item.sha256_hex ? ' <span class="pill good">hashed</span>' : ""}</td>
          <td class="actions">
            <div class="toolbar">
              <button class="secondary" onclick="selectEvidenceSource(${item.id}, preferredAnalysisPath(${item.id}))">Browse</button>
              ${item.source_kind === "image" ? `<button class="secondary" onclick="liveBrowseEvidence(${item.id})" title="Read the file system straight from the image - no indexing">Live browse</button>` : ""}
              ${processActionHtml(item)}
              ${item.source_kind === "folder" || item.source_kind === "browser_history" ? "" : `<button class="ghost" onclick="hashEvidence(${item.id})">${item.sha256_hex ? "Re-hash" : "Hash"}</button>`}
              ${item.source_kind === "image" ? `<button class="ghost" onclick="carveEvidence(${item.id})">Carve</button>` : ""}
              <button class="ghost" onclick="bookmarkEvidence(${index})">Bookmark</button>
              <button class="ghost danger" onclick="removeEvidence(${item.id})">Remove</button>
            </div>
          </td>
        </tr>`).join("");
      $("evidenceTable").innerHTML = rows ? table(["Source", "Kind", "Status", ""], rows) : empty("No evidence.");
    }

    async function carveEvidence(id) {
      const gib = window.prompt("Signature-carve unallocated/image data. Scan how many GiB from the start? (blank = up to 1 GiB)", "1");
      if (gib === null) {
        return;
      }
      const parsed = Number(gib);
      const maxScanBytes = Number.isFinite(parsed) && parsed > 0
        ? Math.round(parsed * 1024 * 1024 * 1024)
        : 0;
      setNotice("Carving evidence " + id + " (scanning image for file signatures)...");
      try {
        const data = await apiPost("/api/evidence/carve", {
          case_path: currentCasePath(),
          evidence_id: id,
          max_scan_bytes: maxScanBytes,
          max_files: 1000
        });
        await refresh();
        selectEvidenceSource(id, "/Image Analysis/Carved");
        setNotice("Carved " + data.carved_files + " file(s) from " + formatBytes(data.bytes_scanned) + (data.truncated ? " (limit reached; raise scan size to carve more)." : "."));
      } catch (err) {
        setNotice(err.message, true);
      }
    }

    async function hashEvidence(id) {
      setNotice("Hashing evidence " + id + " (reads the full source; large images take a while)...");
      try {
        const data = await apiPost("/api/evidence/hash", {
          case_path: currentCasePath(),
          evidence_id: id
        });
        await refresh();
        setNotice("Evidence " + id + " SHA-256: " + data.sha256_hex + " (" + formatBytes(data.bytes_hashed) + " hashed).");
      } catch (err) {
        setNotice(err.message, true);
      }
    }

    function processActionHtml(item) {
      if (item.source_kind === "browser_history") {
        return `<button disabled>Imported</button>`;
      }
      if (item.source_kind === "image" || looksLikeDiskImage(item.source_path)) {
        return `<button class="secondary" onclick="processEvidence(${item.id})">Analyze image</button>`;
      }
      return `<button class="ghost" onclick="processEvidence(${item.id})">Process</button>`;
    }

    function looksLikeDiskImage(path) {
      return /\.(e01|ex01|l01|raw|dd|img|vdi|vmdk|vhd|vhdx|aff4|iso)$/i.test(path || "");
    }

    function preferredAnalysisPath(evidenceId) {
      if (!state.data) {
        return "/";
      }
      const entries = state.data.entries
        .filter((entry) => entry.evidence_id === evidenceId)
        .map((entry) => ({ ...entry, logical_path: normalizeLogicalPath(entry.logical_path) }));
      const volume = entries.find((entry) =>
        entry.entry_kind === "directory"
        && entry.metadata_json
        && entry.metadata_json.artifact_kind === "filesystem_volume"
      );
      if (volume) {
        return volume.logical_path;
      }
      if (entries.some((entry) => entry.logical_path.startsWith("/Image Analysis/Volumes/"))) {
        return "/Image Analysis/Volumes";
      }
      if (entries.some((entry) => entry.logical_path.startsWith("/Image Analysis/Partitions/"))) {
        return "/Image Analysis/Partitions";
      }
      return "/";
    }

    function pruneSelectedEntries() {
      if (!state.data) {
        state.selectedEntryIds = new Set();
        return;
      }
      const valid = new Set(state.data.entries.map((entry) => entry.id));
      state.selectedEntryIds = new Set(Array.from(state.selectedEntryIds).filter((id) => valid.has(id)));
    }

    function liveKey(volume, path) {
      return volume + "|" + path;
    }

    // Evidence-row shortcut: jump straight into live browse for one image
    // source (attach-only evidence needs no indexing to be examined).
    async function liveBrowseEvidence(id) {
      if (state.live.active) {
        state.live = { active: false, evidenceId: null, volumes: [], dirCache: {}, expanded: new Set(), selKey: null, selected: new Map(), lastKey: null };
      }
      selectEvidenceSource(id);
      await toggleLiveBrowse();
    }

    async function toggleLiveBrowse() {
      const evidence = selectedEvidenceSource();
      if (state.live.active) {
        state.live = { active: false, evidenceId: null, volumes: [], dirCache: {}, expanded: new Set(), selKey: null, selected: new Map(), lastKey: null };
        renderEvidenceBrowserEntries();
        setNotice("Live browse off.");
        return;
      }
      if (!evidence || evidence.source_kind !== "image") {
        setNotice("Select a disk-image evidence source, then Live browse.", true);
        return;
      }
      setNotice("Reading volumes from " + evidence.display_name + "...");
      try {
        const data = await apiGet("/api/image/volumes", { case_path: currentCasePath(), evidence_id: evidence.id });
        state.live = { active: true, evidenceId: evidence.id, volumes: data.volumes || [], dirCache: {}, expanded: new Set(), selKey: null, selected: new Map(), lastKey: null };
        const first = state.live.volumes.find((volume) => volume.browsable);
        if (first) {
          await liveLoadDir(first.index, "/");
          state.live.expanded.add(liveKey(first.index, "/"));
          state.live.selKey = liveKey(first.index, "/");
        }
        renderEvidenceBrowserEntries();
        setNotice("Live browsing " + evidence.display_name + " directly from the image - no indexing.");
      } catch (err) {
        state.live.active = false;
        setNotice(err.message, true);
        // Fall back to the attached-source placeholder (matters when live
        // browse was auto-started for an un-indexed image).
        renderEvidenceBrowserEntries();
      }
    }

    async function liveLoadDir(volume, path) {
      const key = liveKey(volume, path);
      if (!state.live.dirCache[key]) {
        const data = await apiGet("/api/image/dir", { case_path: currentCasePath(), evidence_id: state.live.evidenceId, volume: volume, path: path });
        state.live.dirCache[key] = data.entries || [];
      }
      return state.live.dirCache[key];
    }

    async function liveToggleDir(volume, path) {
      const key = liveKey(volume, path);
      if (state.live.expanded.has(key)) {
        state.live.expanded.delete(key);
      } else {
        try { await liveLoadDir(volume, path); } catch (err) { setNotice(err.message, true); return; }
        state.live.expanded.add(key);
      }
      renderLiveBrowse();
    }

    async function liveSelectDir(volume, path) {
      try { await liveLoadDir(volume, path); } catch (err) { setNotice(err.message, true); return; }
      state.live.selKey = liveKey(volume, path);
      state.live.expanded.add(state.live.selKey);
      renderLiveBrowse();
    }

    function liveChildPath(path, name) {
      return path === "/" ? "/" + name : path + "/" + name;
    }

    async function openLiveFile(volume, path, name) {
      state.hex = makeHexState(null, 0, numberValue("hexLength", 512));
      state.hex.live = { evidenceId: state.live.evidenceId, volume: volume, path: path, name: name };
      // Pictures open straight into Details so the inspector shows the image;
      // everything else keeps the hex-first flow.
      const image = isImageEntry(currentHexEntry());
      $("viewerMode").value = image ? "metadata" : "hex";
      $("hexOffset").value = "0";
      await fetchEntryBytes();
      setInspectorCollapsed(false);
    }

    async function postLiveBookmark(volume, path, name, isDir) {
      await apiPost("/api/bookmark/quick", {
        case_path: currentCasePath(),
        folder_name: "Live Browse",
        title: name,
        bookmark_type: isDir ? "folder_info" : "notable_file",
        data_type: isDir ? "Live folder" : "Live file",
        evidence_id: state.live.evidenceId,
        logical_path: "[vol " + volume + "] " + path,
        display_name: name,
        item_ref_json: { kind: isDir ? "live_dir" : "live_file", volume: volume, path: path }
      });
    }

    async function bookmarkLiveItem(volume, path, name, isDir) {
      try {
        await postLiveBookmark(volume, path, name, isDir);
        await refresh();
        state.live.active = true;
        renderEvidenceBrowserEntries();
        setNotice("Bookmarked " + (isDir ? "folder " : "") + name + " from live browse.");
      } catch (err) {
        setNotice(err.message, true);
      }
    }

    // ---- Live selection (checkboxes, ranges) and bulk actions ----

    function visibleLiveEntries() {
      const selected = state.live.selKey;
      if (!selected) {
        return [];
      }
      const selPath = selected.split("|").slice(1).join("|");
      const selVolume = Number(selected.split("|")[0]);
      return (state.live.dirCache[selected] || []).map((entry) => ({
        volume: selVolume,
        path: liveChildPath(selPath, entry.name),
        name: entry.name,
        is_dir: entry.is_dir
      }));
    }

    function setLiveSelection(item, selected) {
      const key = liveKey(item.volume, item.path);
      if (selected) {
        state.live.selected.set(key, item);
      } else {
        state.live.selected.delete(key);
      }
    }

    function toggleLiveSelection(volume, path, name, isDir, checked, event) {
      const item = { volume: volume, path: path, name: name, is_dir: isDir };
      const key = liveKey(volume, path);
      if (event && event.shiftKey && state.live.lastKey) {
        selectLiveRange(state.live.lastKey, key, true);
      } else {
        setLiveSelection(item, checked);
      }
      state.live.lastKey = key;
      renderLiveBrowse();
    }

    function selectLiveRange(fromKey, toKey, selected) {
      const visible = visibleLiveEntries();
      const keys = visible.map((item) => liveKey(item.volume, item.path));
      const fromIndex = keys.indexOf(fromKey);
      const toIndex = keys.indexOf(toKey);
      if (fromIndex === -1 || toIndex === -1) {
        return;
      }
      const [start, end] = fromIndex <= toIndex ? [fromIndex, toIndex] : [toIndex, fromIndex];
      for (let index = start; index <= end; index += 1) {
        setLiveSelection(visible[index], selected);
      }
    }

    function clearLiveSelection() {
      state.live.selected = new Map();
      state.live.lastKey = null;
      renderLiveBrowse();
      setNotice("Selection cleared.");
    }

    function handleLiveRowClick(event, volume, path, name, isDir) {
      hideContextMenu();
      const key = liveKey(volume, path);
      if (event.ctrlKey || event.metaKey) {
        toggleLiveSelection(volume, path, name, isDir, !state.live.selected.has(key), null);
        state.live.lastKey = key;
        return;
      }
      if (event.shiftKey && state.live.lastKey) {
        selectLiveRange(state.live.lastKey, key, true);
        state.live.lastKey = key;
        renderLiveBrowse();
        return;
      }
      if (isDir) {
        liveSelectDir(volume, path);
      } else {
        openLiveFile(volume, path, name);
        renderLiveBrowse();
      }
    }

    const LIVE_BOOKMARK_BATCH_LIMIT = 300;

    async function bookmarkSelectedLive() {
      hideContextMenu();
      const items = Array.from(state.live.selected.values());
      if (items.length === 0) {
        setNotice("No live items selected.", true);
        return;
      }
      if (items.length > LIVE_BOOKMARK_BATCH_LIMIT) {
        setNotice("Too many items selected (" + items.length + "). Bookmark at most " + LIVE_BOOKMARK_BATCH_LIMIT + " at a time; bookmark the parent folder instead.", true);
        return;
      }
      let done = 0;
      let failed = 0;
      for (const item of items) {
        try {
          await postLiveBookmark(item.volume, item.path, item.name, item.is_dir);
          done += 1;
        } catch (err) {
          failed += 1;
        }
      }
      await refresh();
      state.live.active = true;
      renderEvidenceBrowserEntries();
      setNotice("Bookmarked " + done + " live item(s)" + (failed ? ", " + failed + " failed" : "") + ".");
    }

    async function exportSelectedLive() {
      hideContextMenu();
      const items = Array.from(state.live.selected.values());
      if (items.length === 0) {
        setNotice("No live items selected.", true);
        return;
      }
      const root = BOOTSTRAP.workspaceRoot || ".";
      let files = 0;
      let bytes = 0;
      let failures = [];
      let index = 0;
      for (const item of items) {
        index += 1;
        setNotice("Exporting " + index + "/" + items.length + ": " + item.name + "...");
        try {
          if (item.is_dir) {
            const outputDir = joinLocalPath(joinLocalPath(root, ["ui-output", "exported"]), [
              "live-tree-" + safeFileName(item.name)
            ]);
            const data = await apiPost("/api/image/export-tree", {
              case_path: currentCasePath(),
              evidence_id: state.live.evidenceId,
              volume: item.volume,
              path: item.path,
              output_dir: outputDir
            });
            files += data.files_exported;
            bytes += data.bytes_written;
            if (data.truncated || data.skipped_count > 0) {
              failures.push(item.name + ": " + data.skipped_count + " skipped" + (data.truncated ? ", truncated" : ""));
            }
          } else {
            const outputPath = joinLocalPath(joinLocalPath(root, ["ui-output", "exported"]), [
              "live-vol" + item.volume + "-" + safeFileName(item.name)
            ]);
            const data = await apiPost("/api/image/export", {
              case_path: currentCasePath(),
              evidence_id: state.live.evidenceId,
              volume: item.volume,
              path: item.path,
              output_path: outputPath
            });
            files += 1;
            bytes += data.bytes_written;
          }
        } catch (err) {
          failures.push(item.name + ": " + err.message);
        }
      }
      const problems = failures.length ? " Issues: " + failures.slice(0, 5).join(" | ") : "";
      setNotice("Exported " + files + " file(s), " + formatBytes(bytes) + " to ui-output\\exported." + problems, failures.length > 0);
    }

    async function exportLiveTree(volume, path, name) {
      hideContextMenu();
      const root = BOOTSTRAP.workspaceRoot || ".";
      const outputDir = joinLocalPath(joinLocalPath(root, ["ui-output", "exported"]), [
        "live-tree-" + safeFileName(name || "vol" + volume)
      ]);
      setNotice("Exporting folder " + (name || path) + " recursively...");
      try {
        const data = await apiPost("/api/image/export-tree", {
          case_path: currentCasePath(),
          evidence_id: state.live.evidenceId,
          volume: volume,
          path: path,
          output_dir: outputDir
        });
        const extras = [];
        if (data.skipped_count > 0) {
          extras.push(data.skipped_count + " skipped");
        }
        if (data.truncated) {
          extras.push("stopped at the export cap");
        }
        setNotice("Exported " + data.files_exported + " file(s), " + formatBytes(data.bytes_written) + " to " + data.output_dir + " (manifest with SHA-256 written)." + (extras.length ? " " + extras.join(", ") + "." : ""), data.truncated);
      } catch (err) {
        setNotice(err.message, true);
      }
    }

    // ---- Live context menu ----

    function hideContextMenu() {
      const menu = $("ctxMenu");
      if (menu) {
        menu.hidden = true;
      }
    }

    function ctxItem(label, call) {
      return `<button onclick="hideContextMenu(); ${call}">${escapeHtml(label)}</button>`;
    }

    function showLiveContextMenu(event, volume, path, name, isDir) {
      event.preventDefault();
      event.stopPropagation();
      const menu = $("ctxMenu");
      if (!menu) {
        return;
      }
      const escPath = escapeAttr(escapeJs(path));
      const escName = escapeAttr(escapeJs(name));
      const args = `${volume}, '${escPath}', '${escName}'`;
      const selCount = state.live.selected.size;
      const rows = [];
      if (isDir) {
        rows.push(ctxItem("Open folder", `liveSelectDir(${volume}, '${escPath}')`));
        rows.push(ctxItem("Bookmark folder", `bookmarkLiveItem(${args}, true)`));
        rows.push(ctxItem("Export folder (recursive)", `exportLiveTree(${args})`));
      } else {
        rows.push(ctxItem("View bytes", `openLiveFile(${args})`));
        rows.push(ctxItem("Bookmark file", `bookmarkLiveItem(${args}, false)`));
        rows.push(ctxItem("Export file", `exportLiveFile(${args})`));
      }
      if (selCount > 0) {
        rows.push('<div class="sep"></div>');
        rows.push(ctxItem("Bookmark selected (" + selCount + ")", "bookmarkSelectedLive()"));
        rows.push(ctxItem("Export selected (" + selCount + ")", "exportSelectedLive()"));
        rows.push(ctxItem("Clear selection", "clearLiveSelection()"));
      }
      menu.innerHTML = rows.join("");
      menu.hidden = false;
      const menuRect = menu.getBoundingClientRect();
      const x = Math.min(event.clientX, window.innerWidth - menuRect.width - 8);
      const y = Math.min(event.clientY, window.innerHeight - menuRect.height - 8);
      menu.style.left = Math.max(4, x) + "px";
      menu.style.top = Math.max(4, y) + "px";
    }

    async function exportLiveFile(volume, path, name) {
      const root = BOOTSTRAP.workspaceRoot || ".";
      const outputPath = joinLocalPath(joinLocalPath(root, ["ui-output", "exported"]), [
        "live-vol" + volume + "-" + safeFileName(name)
      ]);
      setNotice("Exporting " + name + " from the image...");
      try {
        const data = await apiPost("/api/image/export", {
          case_path: currentCasePath(),
          evidence_id: state.live.evidenceId,
          volume: volume,
          path: path,
          output_path: outputPath
        });
        setNotice("Exported " + name + " to " + data.output_path + " (" + formatBytes(data.bytes_written) + ", SHA-256 " + data.sha256_hex.slice(0, 16) + "...).");
      } catch (err) {
        setNotice(err.message, true);
      }
    }

    // Old-Ecase-preview model: an attached, un-indexed disk image opens straight
    // into live browsing so the examiner can see, bookmark, and export files
    // without processing. Attempted once per evidence source.
    function maybeAutoLiveBrowse(evidence) {
      if (!evidence || evidence.source_kind !== "image" || state.live.active) {
        return false;
      }
      state.liveAutoTried = state.liveAutoTried || new Set();
      if (state.liveAutoTried.has(evidence.id)) {
        return false;
      }
      state.liveAutoTried.add(evidence.id);
      $("filesystemTree").innerHTML = empty("Reading volumes from the image...");
      $("entryTable").innerHTML = empty("Reading the attached image directly (no indexing)...");
      toggleLiveBrowse();
      return true;
    }

    function renderLiveDirRows(volume, path, depth, rows) {
      const entries = state.live.dirCache[liveKey(volume, path)] || [];
      entries.filter((entry) => entry.is_dir).forEach((entry) => {
        const childPath = liveChildPath(path, entry.name);
        const key = liveKey(volume, childPath);
        const expanded = state.live.expanded.has(key);
        const active = state.live.selKey === key ? " active" : "";
        rows.push(`<button class="tree-row${active}" style="--depth:${depth}" onclick="liveSelectDir(${volume}, '${escapeAttr(escapeJs(childPath))}')" title="${escapeAttr(childPath)}">
          <span class="tree-toggle can-toggle" onclick="event.stopPropagation(); liveToggleDir(${volume}, '${escapeAttr(escapeJs(childPath))}')">${expanded ? "-" : "+"}</span>
          <span class="tree-label">${escapeHtml(entry.name)}</span>
          <span class="muted tiny"></span>
        </button>`);
        if (expanded) {
          renderLiveDirRows(volume, childPath, depth + 1, rows);
        }
      });
    }

    function renderLiveBrowse() {
      renderTreeModeControls();
      $("treeTitle").textContent = "Volumes (live)";
      const evidence = state.data && state.data.evidence.find((item) => item.id === state.live.evidenceId);
      $("browserTitle").textContent = (evidence ? evidence.display_name : "Image") + " | live browse";
      const rows = [];
      state.live.volumes.forEach((volume) => {
        const key = liveKey(volume.index, "/");
        const expanded = state.live.expanded.has(key);
        const active = state.live.selKey === key ? " active" : "";
        const toggle = volume.browsable
          ? `<span class="tree-toggle can-toggle" onclick="event.stopPropagation(); liveToggleDir(${volume.index}, '/')">${expanded ? "-" : "+"}</span>`
          : `<span class="tree-toggle"></span>`;
        const click = volume.browsable ? `onclick="liveSelectDir(${volume.index}, '/')"` : "";
        rows.push(`<button class="tree-row${active}" style="--depth:0" ${click} title="${escapeAttr(volume.filesystem + " " + formatBytes(volume.size_bytes))}">
          ${toggle}
          <span class="tree-label">${escapeHtml(volume.name)} <span class="muted tiny">${escapeHtml(volume.filesystem)}</span></span>
          <span class="muted tiny">${volume.browsable ? "" : "n/a"}</span>
        </button>`);
        if (volume.browsable && expanded) {
          renderLiveDirRows(volume.index, "/", 1, rows);
        }
      });
      $("treeCount").textContent = String(state.live.volumes.length);
      $("filesystemTree").innerHTML = rows.join("") || empty("No browsable volumes.");

      const selected = state.live.selKey;
      const entries = selected ? (state.live.dirCache[selected] || []) : [];
      const selPath = selected ? selected.split("|").slice(1).join("|") : "/";
      const selVolume = selected ? Number(selected.split("|")[0]) : 0;
      $("folderTitle").textContent = selected ? selPath : "Select a volume";
      if (!selected) {
        $("entryTable").innerHTML = empty("Select a volume or folder on the left to browse it live.");
        return;
      }
      const viewedPath = state.hex.live && state.hex.live.volume === selVolume ? state.hex.live.path : null;
      const contentRows = entries.map((entry) => {
        const childPath = liveChildPath(selPath, entry.name);
        const escChild = escapeAttr(escapeJs(childPath));
        const escName = escapeAttr(escapeJs(entry.name));
        const key = liveKey(selVolume, childPath);
        const isChecked = state.live.selected.has(key);
        const rowClasses = "entry-row" + (isChecked ? " multi-selected" : "") + (viewedPath === childPath ? " selected" : "");
        const rowArgs = `event, ${selVolume}, '${escChild}', '${escName}', ${entry.is_dir}`;
        return `<tr class="${rowClasses}" onclick="handleLiveRowClick(${rowArgs})" oncontextmenu="showLiveContextMenu(${rowArgs})">
          <td><input type="checkbox"${isChecked ? " checked" : ""} onclick="event.stopPropagation(); toggleLiveSelection(${selVolume}, '${escChild}', '${escName}', ${entry.is_dir}, this.checked, event)"></td>
          <td><span class="entry-name">${escapeHtml(entry.name)}</span></td>
          <td class="entry-kind">${entry.is_dir ? "Folder" : "File"}</td>
          <td class="entry-size">${entry.size_bytes == null ? "" : formatBytes(entry.size_bytes)}</td>
          <td class="entry-time">${escapeHtml(entry.modified_utc || entry.created_utc || "")}</td>
        </tr>`;
      }).join("");
      $("selectedCount").textContent = state.live.selected.size + " selected";
      const hint = `<div class="analysis-status">Live browse: click a file for hex/text, right-click a row for bookmark/export (folders export recursively), Ctrl/Shift-click or checkboxes to multi-select.</div>`;
      $("entryTable").innerHTML = contentRows
        ? hint + table(["", "Name", "Type", "Size", "Modified"], contentRows, "live-table")
        : empty("This folder is empty.");
    }

    // Lazy indexed browse: for cases too big to ship every entry, load folders
    // on demand from the case database (/api/entries/dir). Same data as the
    // normal indexed tree, but never loads more than one folder at a time.
    async function idxLoadDir(path) {
      if (!state.idx.dirCache[path]) {
        const data = await apiGet("/api/entries/dir", {
          case_path: currentCasePath(),
          evidence_id: state.idx.evidenceId,
          path: path
        });
        state.idx.dirCache[path] = data.children || [];
      }
      return state.idx.dirCache[path];
    }

    async function idxToggleDir(path) {
      if (state.idx.expanded.has(path)) {
        state.idx.expanded.delete(path);
      } else {
        try { await idxLoadDir(path); } catch (err) { setNotice(err.message, true); return; }
        state.idx.expanded.add(path);
      }
      renderIndexedBrowse();
    }

    async function idxSelectDir(path) {
      try { await idxLoadDir(path); } catch (err) { setNotice(err.message, true); return; }
      state.idx.selPath = path;
      state.idx.expanded.add(path);
      renderIndexedBrowse();
    }

    // Restores a stored selected_path (fullscreen/query restore) in lazy
    // indexed browse: loads and expands every ancestor folder so the tree
    // opens down to the selection. The synthetic containers are collapsed
    // out of the tree, so they are skipped rather than loaded.
    async function idxRestorePath(path) {
      await idxLoadDir("/");
      const target = normalizeLogicalPath(path || "/");
      if (target === "/") {
        return;
      }
      const synthetic = new Set(["/Image Analysis", "/Image Analysis/Volumes", "/Image Analysis/Partitions"]);
      const segments = target.split("/").filter(Boolean);
      let current = "";
      for (const segment of segments) {
        current += "/" + segment;
        if (synthetic.has(current)) {
          continue;
        }
        try {
          await idxLoadDir(current);
        } catch (err) {
          return;
        }
        state.idx.expanded.add(current);
        state.idx.selPath = current;
      }
    }

    function idxChildPath(parent, name) {
      return parent === "/" ? "/" + name : parent + "/" + name;
    }

    function renderIdxDirRows(path, depth, rows) {
      const children = state.idx.dirCache[path] || [];
      children.filter((child) => child.is_dir).forEach((child) => {
        const childPath = child.logical_path;
        const expanded = state.idx.expanded.has(childPath);
        const active = state.idx.selPath === childPath ? " active" : "";
        const toggle = child.has_children
          ? `<span class="tree-toggle can-toggle" onclick="event.stopPropagation(); idxToggleDir('${escapeAttr(escapeJs(childPath))}')">${expanded ? "-" : "+"}</span>`
          : `<span class="tree-toggle"></span>`;
        rows.push(`<button class="tree-row${active}" style="--depth:${depth}" onclick="idxSelectDir('${escapeAttr(escapeJs(childPath))}')" title="${escapeAttr(displayPath(childPath))}">
          ${toggle}
          <span class="tree-label">${escapeHtml(child.name)}</span>
          <span class="muted tiny"></span>
        </button>`);
        if (expanded) {
          renderIdxDirRows(childPath, depth + 1, rows);
        }
      });
    }

    function renderIndexedBrowse() {
      // Async dir loads can resolve after the examiner switched to Categories
      // or Live browse; never let a late load stomp those views.
      if (state.live.active || state.browserState.treeMode === "categories") {
        return;
      }
      renderTreeModeControls();
      const evidence = state.data && state.data.evidence.find((item) => item.id === state.idx.evidenceId);
      $("browserTitle").textContent = (evidence ? evidence.display_name : "Evidence") + " | indexed (lazy)";
      $("treeTitle").textContent = "Entries";
      const device = evidence ? evidence.display_name : "Entries";
      const rootActive = state.idx.selPath === "/" ? " active" : "";
      const rootExpanded = state.idx.expanded.has("/");
      const rows = [`<button class="tree-row${rootActive}" style="--depth:0" onclick="idxSelectDir('/')" title="/">
        <span class="tree-toggle can-toggle" onclick="event.stopPropagation(); idxToggleDir('/')">${rootExpanded ? "-" : "+"}</span>
        <span class="tree-label">${escapeHtml(device)}</span>
        <span class="muted tiny"></span>
      </button>`];
      if (rootExpanded) {
        renderIdxDirRows("/", 1, rows);
      }
      $("filesystemTree").innerHTML = rows.join("");
      $("treeCount").textContent = (state.data.entry_count || 0).toLocaleString();

      const selPath = state.idx.selPath || "/";
      const children = state.idx.dirCache[selPath] || [];
      $("folderTitle").textContent = displayPath(selPath);
      const contentRows = children.map((child) => {
        const selectable = !child.is_dir && child.entry_id != null;
        const isChecked = selectable && state.selectedEntryIds.has(child.entry_id);
        const checkbox = selectable
          ? `<input type="checkbox"${isChecked ? " checked" : ""} onclick="event.stopPropagation(); toggleEntrySelection(${child.entry_id}, this.checked, event)">`
          : "";
        const nameCell = `<span class="entry-name">${escapeHtml(child.name)}</span>`;
        const flags = child.is_deleted ? '<span class="pill bad">deleted</span>' : "";
        const actions = selectable
          ? `<div class="toolbar">
              <button class="secondary" onclick="event.stopPropagation(); openEntry(${child.entry_id})">View</button>
              <button class="ghost" onclick="event.stopPropagation(); bookmarkEntry(${child.entry_id})">Bookmark</button>
            </div>`
          : "";
        const rowClick = child.is_dir
          ? ` style="cursor:pointer" onclick="idxSelectDir('${escapeAttr(escapeJs(child.logical_path))}')"`
          : (selectable ? ` style="cursor:pointer" onclick="handleEntryRowClick(event, ${child.entry_id})"` : "");
        return `<tr class="entry-row${isChecked ? " multi-selected" : ""}"${rowClick}>
          <td>${checkbox}</td>
          <td>${nameCell} ${flags}</td>
          <td class="entry-kind">${child.is_dir ? "Folder" : "File"}</td>
          <td class="entry-size">${child.size_bytes == null ? "" : formatBytes(child.size_bytes)}</td>
          <td class="actions">${actions}</td>
        </tr>`;
      }).join("");
      const banner = `<div class="analysis-status">Large case (${(state.data.entry_count || 0).toLocaleString()} entries): browsing the full index folder by folder. Open folders on the left; use Deep Search to find files by name or content.</div>`;
      $("entryTable").innerHTML = banner + (contentRows
        ? table(["", "Name", "Type", "Size", ""], contentRows, "idx-table")
        : empty("This folder has no direct children."));
      renderSelectionCount();
    }

    function renderEvidenceBrowserEntries() {
      if (state.live.active) {
        renderLiveBrowse();
        renderHexViewer();
        return;
      }
      // Big case: browse the indexed tree lazily so we never load everything.
      if (state.data && state.data.entries_truncated && state.browserState.evidenceId
        && state.browserState.treeMode !== "categories") {
        if (state.idx.evidenceId !== state.browserState.evidenceId) {
          state.idx = { evidenceId: state.browserState.evidenceId, dirCache: {}, expanded: new Set(["/"]), selPath: "/" };
          $("filesystemTree").innerHTML = empty("Loading directory tree...");
          $("entryTable").innerHTML = empty("Loading...");
          renderTreeModeControls();
          idxRestorePath(state.browserState.selectedPath).then(renderIndexedBrowse).catch((err) => setNotice(err.message, true));
          renderHexViewer();
          return;
        }
        renderIndexedBrowse();
        renderHexViewer();
        return;
      }
      renderTreeModeControls();
      if (!state.data || !state.browserState.evidenceId) {
        $("browserTitle").textContent = "Select an evidence source";
        $("filesystemTree").innerHTML = empty("Select an evidence source.");
        $("entryTable").innerHTML = empty("Select an evidence source.");
        $("treeCount").textContent = "0";
        $("folderTitle").textContent = "/";
        renderHexViewer();
        return;
      }
      const evidence = state.data.evidence.find((item) => item.id === state.browserState.evidenceId);
      $("browserTitle").textContent = evidence ? evidence.display_name + " | " + evidence.source_kind : "Select an evidence source";
      const entries = selectedEvidenceEntries();
      if (entries.length === 0) {
        if (maybeAutoLiveBrowse(evidence)) {
          renderHexViewer();
          return;
        }
        renderAttachedEvidenceSource(evidence);
        renderHexViewer();
        return;
      }
      const knownFolders = directoryPathSet(entries);
      if (state.browserState.treeMode === "categories") {
        renderCategoryTree(entries);
        renderCategoryContents(entries);
        renderHexViewer();
        return;
      }
      const syntheticSelection = syntheticContainerSet(knownFolders);
      if (!knownFolders.has(normalizeLogicalPath(state.browserState.selectedPath))
        || syntheticSelection.has(normalizeLogicalPath(state.browserState.selectedPath))) {
        state.browserState.selectedPath = "/";
      }
      renderFilesystemTree(entries, knownFolders);
      renderFolderContents(entries, knownFolders);
      renderHexViewer();
    }

    function renderTreeModeControls() {
      const mode = state.browserState.treeMode || "filesystem";
      $("treeTitle").textContent = mode === "categories" ? "Categories" : "Entries";
      $("treeModeFilesystem").classList.toggle("active", mode === "filesystem");
      $("treeModeCategories").classList.toggle("active", state.browserState.treeMode === "categories");
    }

    function selectedEvidenceEntries() {
      if (!state.data || !state.browserState.evidenceId) {
        return [];
      }
      return state.data.entries
        .filter((entry) => entry.evidence_id === state.browserState.evidenceId)
        .map((entry) => ({ ...entry, logical_path: normalizeLogicalPath(entry.logical_path) }));
    }

    function renderAttachedEvidenceSource(evidence) {
      if (!evidence) {
        $("filesystemTree").innerHTML = empty("No evidence selected.");
        $("treeCount").textContent = "0";
        $("folderTitle").textContent = "/";
        $("entryTable").innerHTML = empty("No evidence selected.");
        return;
      }
      $("treeCount").textContent = "1";
      $("folderTitle").textContent = "Attached Evidence";
      $("filesystemTree").innerHTML = `<button class="tree-row active" style="--depth:0" title="${escapeAttr(evidence.source_path)}">
        <span class="tree-toggle"></span>
        <span class="tree-label">${escapeHtml(evidence.display_name)}</span>
        <span class="muted tiny">source</span>
      </button>`;
      const evidenceIndex = state.data.evidence.findIndex((item) => item.id === evidence.id);
      const bookmark = evidenceIndex >= 0
        ? `<button class="ghost" onclick="bookmarkEvidence(${evidenceIndex})">Bookmark</button>`
        : "";
      const status = evidenceProcessingStatusHtml(evidence);
      const rows = `
        <tr class="entry-row">
          <td><strong>${escapeHtml(evidence.display_name)}</strong><br><span class="muted tiny">${escapeHtml(evidence.source_path)}</span></td>
          <td><span class="pill">${escapeHtml(evidence.source_kind)}</span> ${status}</td>
          <td>${evidence.size_bytes == null ? "" : formatBytes(evidence.size_bytes)}</td>
          <td>${escapeHtml(evidence.attached_at || "")}</td>
          <td class="actions">
            <div class="toolbar">
              ${processActionHtml(evidence)}
              ${bookmark}
              <button class="ghost danger" onclick="removeEvidence(${evidence.id})">Remove</button>
            </div>
          </td>
        </tr>`;
      $("entryTable").innerHTML = table(["Attached Source", "Kind", "Size", "Attached", ""], rows);
      renderSelectionCount();
    }

    function renderFilesystemTree(entries, knownFolders) {
      const synthetic = syntheticContainerSet(knownFolders);
      const expanded = expandedTreeSet();
      ensureTreeAncestorsExpanded(state.browserState.selectedPath);
      const filterOn = dateFilterActive();
      const passing = filterOn ? applyDateFilter(entries) : null;
      const device = selectedEvidenceSource();
      const selected = normalizeLogicalPath(state.browserState.selectedPath);
      const rows = [];
      // Depth-first walk keeps children under their parent (old-Ecase-style
      // Windows-like hierarchy) instead of the old depth-sorted flat list.
      const walk = (path, depth) => {
        let childFolders = displayChildFolders(knownFolders, path, synthetic);
        if (filterOn) {
          childFolders = childFolders.filter((child) => matchingSubtreeCount(passing, child) > 0);
        }
        const count = filterOn
          ? matchingSubtreeCount(passing, path)
          : displayFolderChildCount(entries, knownFolders, path, synthetic);
        const active = selected === path ? " active" : "";
        const isExpanded = expanded.has(path);
        const toggle = childFolders.length > 0
          ? `<span class="tree-toggle can-toggle" onclick="event.stopPropagation(); toggleTreePath('${escapeAttr(escapeJs(path))}')" title="${isExpanded ? "Collapse" : "Expand"}">${isExpanded ? "-" : "+"}</span>`
          : `<span class="tree-toggle"></span>`;
        const label = path === "/"
          ? (device ? device.display_name : "Entries")
          : logicalName(path);
        rows.push(`<button class="tree-row${active}" style="--depth:${depth}" onclick="selectFolder('${escapeAttr(escapeJs(path))}')" title="${escapeAttr(path)}">
          ${toggle}
          <span class="tree-label">${escapeHtml(label)}</span>
          <span class="muted tiny">${count}</span>
        </button>`);
        if (isExpanded) {
          childFolders.forEach((child) => walk(child, depth + 1));
        }
      };
      walk("/", 0);
      $("treeCount").textContent = String(rows.length);
      $("filesystemTree").innerHTML = rows.join("") || empty("No folders.");
    }

    function renderCategoryTree(entries) {
      // Category counts follow the active date filter, like the contents pane.
      // On truncated (large) cases the exact SQL counts are used instead, but
      // only without a date filter - the server counts cannot be date-filtered.
      const useServerCounts = serverCategoryCountsAvailable() && !dateFilterActive();
      const categoryEntries = categorizedVisibleEntries(applyDateFilter(entries));
      const mains = new Map();
      let totalCount = 0;
      if (useServerCounts) {
        state.data.category_counts.forEach((row) => {
          if (!mains.has(row.main)) {
            mains.set(row.main, { count: 0, subs: new Map() });
          }
          const main = mains.get(row.main);
          main.count += row.count;
          totalCount += row.count;
          if (row.sub) {
            main.subs.set(row.sub, (main.subs.get(row.sub) || 0) + row.count);
          }
        });
      } else {
        categoryEntries.forEach((entry) => {
          const category = entryCategory(entry);
          if (!mains.has(category.main)) {
            mains.set(category.main, { count: 0, subs: new Map() });
          }
          const main = mains.get(category.main);
          main.count += 1;
          main.subs.set(category.sub, (main.subs.get(category.sub) || 0) + 1);
        });
        totalCount = categoryEntries.length;
      }
      ensureCategoryTreeSub(mains, "Recovery", "Deleted files");
      ensureCategoryTreeSub(mains, "Recovery", "Unallocated space");
      const selected = state.browserState.selectedCategory || "";
      const rows = [
        categoryTreeRow("", "All Categories", totalCount, 0, selected === "")
      ];
      Array.from(mains.entries())
        .sort((left, right) => left[0].localeCompare(right[0]))
        .forEach(([mainName, main]) => {
          const mainKey = categoryKey(mainName, "");
          rows.push(categoryTreeRow(mainKey, mainName, main.count, 1, selected === mainKey));
          Array.from(main.subs.entries())
            .sort((left, right) => left[0].localeCompare(right[0]))
            .forEach(([subName, count]) => {
              const subKey = categoryKey(mainName, subName);
              rows.push(categoryTreeRow(subKey, subName, count, 2, selected === subKey));
            });
        });
      $("treeCount").textContent = String(Array.from(mains.values()).filter((main) => main.count > 0).length);
      $("filesystemTree").innerHTML = rows.join("") || empty("No categories.");
    }

    function ensureCategoryTreeSub(mains, mainName, subName) {
      if (!mains.has(mainName)) {
        mains.set(mainName, { count: 0, subs: new Map() });
      }
      const main = mains.get(mainName);
      if (!main.subs.has(subName)) {
        main.subs.set(subName, 0);
      }
    }

    function categoryTreeRow(key, label, count, depth, active) {
      return `<button class="tree-row${active ? " active" : ""}" style="--depth:${depth}" onclick="selectCategory('${escapeAttr(escapeJs(key))}')" title="${escapeAttr(categoryLabel(key) || label)}">
        <span class="tree-toggle"></span>
        <span class="tree-label">${escapeHtml(label)}</span>
        <span class="muted tiny">${Number(count).toLocaleString()}</span>
      </button>`;
    }

    function renderCategoryContents(entries) {
      const selected = state.browserState.selectedCategory || "";
      const rows = applyDateFilter(categoryEntriesForSelection(entries, selected));
      const selectedLabel = categoryLabel(selected) || "All Categories";
      const filterNote = dateFilterActive() ? " (date filtered)" : "";
      $("folderTitle").textContent = selectedLabel + " | " + rows.length + " result" + (rows.length === 1 ? "" : "s") + filterNote;
      if (rows.length === 0) {
        $("entryTable").innerHTML = truncatedEntriesNoticeHtml() + empty("No entries in this category.");
        renderSelectionCount();
        return;
      }
      if (shouldRenderEmailCategory(rows)) {
        renderEmailCategoryContents(rows);
        return;
      }
      if (shouldRenderThumbnailCategory(rows)) {
        renderThumbnailCategoryContents(rows);
        return;
      }
      const entryRows = rows.map((entry) => {
        const selectedRow = state.hex.entryId === entry.id ? " selected" : "";
        const isChecked = state.selectedEntryIds.has(entry.id);
        const checked = isChecked ? " checked" : "";
        const multiSelected = isChecked ? " multi-selected" : "";
        const evidence = selectedEvidenceSource();
        const action = entry.entry_kind === "directory"
          ? `<button class="secondary" onclick="event.stopPropagation(); selectFolder('${escapeAttr(escapeJs(entry.logical_path))}')">Open</button>`
          : entry.entry_kind === "file" && isPromotableDiskImageEntry(entry, evidence)
            ? `<button class="secondary" onclick="event.stopPropagation(); analyzeDiskImageEntry(${entry.id})">Analyze image</button>`
            : "";
        const recover = entry.entry_kind === "file" && isRecoveryEntry(entry)
          ? `<button class="ghost" onclick="event.stopPropagation(); recoverEntry(${entry.id})">${escapeHtml(recoveryActionText(entry).button)}</button>`
          : "";
        return `
          <tr class="entry-row${selectedRow}${multiSelected}" data-entry-id="${entry.id}" onclick="handleEntryRowClick(event, ${entry.id})">
            <td><input type="checkbox"${checked} onclick="event.stopPropagation(); toggleEntrySelection(${entry.id}, this.checked, event)"></td>
            <td title="${escapeAttr(entry.logical_path)}"><span class="entry-name">${escapeHtml(entry.name || logicalName(entry.logical_path))}</span><span class="entry-path">${escapeHtml(displayPath(entry.logical_path))}</span></td>
            <td title="${escapeAttr(entryCategoryLabel(entry) + " | " + entryCategoryDetail(entry))}"><span class="entry-category">${escapeHtml(entryCategoryLabel(entry))}</span></td>
            <td class="entry-kind">${escapeHtml(activityLabel(entry))}</td>
            <td class="entry-size">${entry.size_bytes == null ? "" : formatBytes(entry.size_bytes)}</td>
            <td class="entry-flags" title="${escapeAttr(entryFlagsText(entry))}">${entryFlagsHtml(entry)}</td>
            <td class="entry-offset" title="${escapeAttr(entryPrimaryOffset(entry))}">${escapeHtml(entryPrimaryOffset(entry))}</td>
            <td class="entry-time" title="${escapeAttr(categoryTime(entry))}">${escapeHtml(categoryTime(entry))}</td>
            <td class="actions">
              <div class="toolbar">
                ${action}
                ${recover}
              </div>
            </td>
          </tr>`;
      });
      const gridToggle = rows.every((entry) => isImageEntry(entry))
        ? `<div class="thumb-toolbar"><button class="ghost" onclick="setPictureViewMode('grid')">Thumbnail view</button></div>`
        : "";
      $("entryTable").innerHTML = truncatedEntriesNoticeHtml() + gridToggle + table(["", "Name", "Category", "Type", "Size", "Flags", "Offset", "Time", ""], entryRows.join(""), "category-table");
      renderSelectionCount();
    }

    function shouldRenderEmailCategory(rows) {
      return rows.length > 0 && rows.every((entry) => isEmailEntry(entry));
    }

    function dateFilterActive() {
      return Boolean(state.dateFilter.from || state.dateFilter.to);
    }

    function entryTimestamps(entry) {
      return [categoryTime(entry), filesystemCreatedTime(entry), filesystemAccessedTime(entry),
        filesystemModifiedTime(entry), filesystemMftModifiedTime(entry)].filter(Boolean);
    }

    // Axy-style absolute date filter: keep rows with at least one timestamp inside the range.
    // Rows without any parseable timestamp are hidden while a filter is active.
    function applyDateFilter(rows) {
      if (!dateFilterActive()) {
        return rows;
      }
      const from = state.dateFilter.from ? Date.parse(state.dateFilter.from + "T00:00:00Z") : -Infinity;
      const to = state.dateFilter.to ? Date.parse(state.dateFilter.to + "T23:59:59.999Z") : Infinity;
      return rows.filter((entry) => entryTimestamps(entry).some((text) => {
        const value = Date.parse(text);
        return Number.isFinite(value) && value >= from && value <= to;
      }));
    }

    function isImageEntry(entry) {
      if (entry.entry_kind !== "file") {
        return false;
      }
      const name = (entry.name || entry.logical_path || "").toLowerCase();
      return [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".ico"]
        .some((ext) => name.endsWith(ext));
    }

    function shouldRenderThumbnailCategory(rows) {
      return state.pictureViewMode !== "list"
        && rows.length > 0
        && rows.every((entry) => isImageEntry(entry));
    }

    function setPictureViewMode(mode) {
      state.pictureViewMode = mode;
      renderEvidenceBrowserEntries();
    }

    function entryRawUrl(entry) {
      const meta = entry && entry.metadata_json;
      if (entry && entry.id == null && meta && meta.source === "live_browse") {
        return "/api/image/raw?case_path=" + encodeURIComponent(currentCasePath())
          + "&evidence_id=" + entry.evidence_id
          + "&volume=" + meta.volume
          + "&path=" + encodeURIComponent(meta.image_path);
      }
      return "/api/entry/raw?case_path=" + encodeURIComponent(currentCasePath()) + "&entry_id=" + entry.id;
    }

    function renderThumbnailCategoryContents(rows) {
      const cards = rows.map((entry) => {
        const selectedRow = state.hex.entryId === entry.id ? " selected" : "";
        const isChecked = state.selectedEntryIds.has(entry.id);
        return `
          <div class="thumb-card entry-row${selectedRow}${isChecked ? " multi-selected" : ""}" data-entry-id="${entry.id}" onclick="handleEntryRowClick(event, ${entry.id})" title="${escapeAttr(entry.logical_path)}">
            <input type="checkbox"${isChecked ? " checked" : ""} onclick="event.stopPropagation(); toggleEntrySelection(${entry.id}, this.checked, event)">
            <div class="thumb-frame"><img loading="lazy" src="${entryRawUrl(entry)}" alt="" onerror="this.parentElement.classList.add('thumb-broken')"></div>
            <div class="thumb-name">${escapeHtml(entry.name || logicalName(entry.logical_path))}</div>
            <div class="thumb-meta muted tiny">${entry.size_bytes == null ? "" : escapeHtml(formatBytes(entry.size_bytes))}</div>
          </div>`;
      });
      $("entryTable").innerHTML = `<div class="thumb-toolbar"><button class="ghost" onclick="setPictureViewMode('list')">List view</button></div><div class="thumb-grid">${cards.join("")}</div>`;
      renderSelectionCount();
    }

    function renderEmailCategoryContents(rows) {
      const entryRows = rows.map((entry) => {
        const metadata = entry.metadata_json || {};
        const selectedRow = state.hex.entryId === entry.id ? " selected" : "";
        const isChecked = state.selectedEntryIds.has(entry.id);
        const checked = isChecked ? " checked" : "";
        const multiSelected = isChecked ? " multi-selected" : "";
        const to = firstText(metadata.email_to, metadata.email_bcc);
        const from = firstText(metadata.email_from, metadata.email_reply_to);
        const date = firstText(metadata.email_date, categoryTime(entry));
        const subject = emailDisplayName(entry);
        const body = firstText(metadata.email_body_preview, metadata.email_parser_error, "");
        return `
          <tr class="entry-row${selectedRow}${multiSelected}" data-entry-id="${entry.id}" onclick="handleEntryRowClick(event, ${entry.id})">
            <td><input type="checkbox"${checked} onclick="event.stopPropagation(); toggleEntrySelection(${entry.id}, this.checked, event)"></td>
            <td class="email-cell" title="${escapeAttr(to)}">${escapeHtml(to)}</td>
            <td class="email-cell" title="${escapeAttr(from)}">${escapeHtml(from)}</td>
            <td class="email-cell" title="${escapeAttr(date)}">${escapeHtml(date)}</td>
            <td class="email-cell" title="${escapeAttr(subject)}">${escapeHtml(subject)}</td>
            <td class="email-cell email-body-cell" title="${escapeAttr(body)}">${escapeHtml(body)}</td>
            <td class="entry-size">${entry.size_bytes == null ? "" : formatBytes(entry.size_bytes)}</td>
          </tr>`;
      });
      $("entryTable").innerHTML = table(["", "To", "From", "Date/Time", "Subject", "Body", "Size"], entryRows.join(""), "email-table");
      renderSelectionCount();
    }

    function categorySummaryHtml(entries, selectedKey) {
      const categoryEntries = categorizedVisibleEntries(entries);
      const mains = new Map();
      categoryEntries.forEach((entry) => {
        const category = entryCategory(entry);
        if (!mains.has(category.main)) {
          mains.set(category.main, { count: 0, subs: new Map() });
        }
        const main = mains.get(category.main);
        main.count += 1;
        main.subs.set(category.sub, (main.subs.get(category.sub) || 0) + 1);
      });
      const allActive = !selectedKey;
      const cards = [
        categorySummaryCard("", "All Categories", categoryEntries.length, "Visible categorized results", allActive)
      ];
      Array.from(mains.entries())
        .sort((left, right) => right[1].count - left[1].count || left[0].localeCompare(right[0]))
        .slice(0, 5)
        .forEach(([mainName, main]) => {
          const topSubs = Array.from(main.subs.entries())
            .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
            .slice(0, 2)
            .map(([subName, count]) => subName + " " + count)
            .join(" | ");
          const key = categoryKey(mainName, "");
          cards.push(categorySummaryCard(key, mainName, main.count, topSubs || "No subcategories", selectedKey === key));
        });
      return `<div class="category-summary">${cards.join("")}</div>`;
    }

    function categorySummaryCard(key, label, count, detail, active) {
      return `<button class="category-card${active ? " active" : ""}" onclick="selectCategory('${escapeAttr(escapeJs(key))}')" title="${escapeAttr(label)}">
        <span class="muted tiny">${escapeHtml(label)}</span>
        <strong>${escapeHtml(count)}</strong>
        <span class="muted tiny">${escapeHtml(detail || "")}</span>
      </button>`;
    }

    function categoryRowBadges(entry) {
      const evidence = evidenceSourceForEntry(entry);
      const metadata = entry.metadata_json || {};
      const badges = [
        evidence ? "Source: " + evidence.display_name : "",
        metadata.filesystem_parser ? "Parser: " + metadata.filesystem_parser : "",
        metadata.category_confidence ? "Confidence: " + metadata.category_confidence : ""
      ].filter(Boolean);
      return badges.map((value) => `<span class="pill">${escapeHtml(value)}</span>`).join("");
    }

    function entryFlags(entry) {
      const metadata = entry.metadata_json || {};
      const flags = [];
      if (entry.is_deleted || metadata.recovery_source === "ntfs_deleted_mft" || metadata.artifact_kind === "deleted_file_record") {
        flags.push({ label: "deleted", tone: "bad" });
      }
      if (metadata.is_file_slack) {
        flags.push({ label: "slack", tone: "warn" });
      }
      if (metadata.is_unallocated || metadata.artifact_kind === "unallocated_space") {
        flags.push({ label: "unallocated", tone: "warn" });
      }
      if (flags.length === 0 && metadata.storage_area) {
        flags.push({ label: storageAreaLabel(metadata.storage_area), tone: "" });
      }
      return flags;
    }

    function entryFlagsHtml(entry) {
      const flags = entryFlags(entry);
      if (!flags.length) {
        return '<span class="muted tiny">-</span>';
      }
      const visible = flags.length > 2
        ? [flags[0], { label: "+" + (flags.length - 1), tone: "more" }]
        : flags;
      return visible.map((flag) => `<span class="pill ${flag.tone ? escapeAttr(flag.tone) : ""}">${escapeHtml(flag.label)}</span>`).join("");
    }

    function entryFlagsText(entry) {
      return entryFlags(entry).map((flag) => flag.label).join(", ");
    }

    function storageAreaLabel(value) {
      return String(value || "").replace(/_/g, " ");
    }

    function entryPrimaryOffset(entry) {
      const metadata = entry.metadata_json || {};
      const value = firstDefined(
        metadata.file_data_physical_offset,
        metadata.file_data_logical_offset,
        metadata.mft_record_physical_offset,
        metadata.mft_record_logical_offset,
        metadata.physical_offset,
        metadata.logical_offset,
        metadata.partition_start_offset,
        metadata.start_offset
      );
      return formatOffsetValue(value);
    }

    function filesystemTypeLabel(entry) {
      const metadata = entry && entry.metadata_json ? entry.metadata_json : {};
      if (!entry) {
        return "";
      }
      if (metadata.artifact_kind === "disk_partition") {
        return "Partition";
      }
      if (metadata.artifact_kind === "unallocated_space" || metadata.is_unallocated) {
        return "Unallocated Space";
      }
      if (entry.entry_kind === "directory") {
        return "Folder";
      }
      if (entry.entry_kind === "file") {
        return archiveOrImageExtension(entry) ? "Image" : "File";
      }
      return activityLabel(entry);
    }

    function archiveOrImageExtension(entry) {
      const ext = filesystemFileExtension(entry);
      return ["zip", "e01", "ex01", "raw", "dd", "img", "iso", "vhd", "vhdx", "vmdk", "vdi"].includes(ext);
    }

    function filesystemFileExtension(entry) {
      if (!entry) {
        return "";
      }
      const metadata = entry.metadata_json || {};
      return firstText(metadata.file_extension, fileExtension(entry.name || entry.logical_path));
    }

    function filesystemCreatedTime(entry) {
      const metadata = entry && entry.metadata_json ? entry.metadata_json : {};
      return firstText(metadata.ntfs_creation_time_utc, metadata.ntfs_standard_creation_time_utc, metadata.created_utc, metadata.source_file_created_utc);
    }

    function filesystemAccessedTime(entry) {
      const metadata = entry && entry.metadata_json ? entry.metadata_json : {};
      return firstText(metadata.ntfs_access_time_utc, metadata.ntfs_standard_access_time_utc, metadata.accessed_utc, metadata.source_file_accessed_utc);
    }

    function filesystemModifiedTime(entry) {
      const metadata = entry && entry.metadata_json ? entry.metadata_json : {};
      return firstText(metadata.ntfs_modification_time_utc, metadata.ntfs_standard_modification_time_utc, metadata.modified_utc, metadata.source_file_modified_utc);
    }

    function filesystemMftModifiedTime(entry) {
      const metadata = entry && entry.metadata_json ? entry.metadata_json : {};
      return firstText(metadata.ntfs_mft_record_modification_time_utc, metadata.ntfs_standard_mft_record_modification_time_utc);
    }

    function renderFolderContents(entries, knownFolders) {
      const synthetic = syntheticContainerSet(knownFolders);
      const folder = normalizeLogicalPath(state.browserState.selectedPath || "/");
      $("folderTitle").textContent = displayPath(folder) + (dateFilterActive() ? " (date filtered)" : "");
      const childFolders = displayChildFolders(knownFolders, folder, synthetic);
      const children = applyDateFilter(displayFolderChildren(entries, folder, synthetic));
      const status = truncatedEntriesNoticeHtml() + imageAnalysisStatusHtml(entries);
      // Folder rows follow the date filter too: keep a folder only when its own
      // timestamps match or its subtree still contains a matching entry, so
      // navigation always leads somewhere with results.
      let folderSpecs = childFolders.map((path) => ({
        path,
        count: displayFolderChildCount(entries, knownFolders, path, synthetic),
        countKind: "direct"
      }));
      if (dateFilterActive()) {
        const passing = applyDateFilter(entries);
        folderSpecs = folderSpecs
          .map((spec) => {
            const normalized = normalizeLogicalPath(spec.path);
            const prefix = normalized === "/" ? "/" : normalized + "/";
            const matches = passing.filter((entry) => {
              const entryPath = normalizeLogicalPath(entry.logical_path);
              return entryPath === normalized || entryPath.startsWith(prefix);
            }).length;
            return { path: spec.path, count: matches, countKind: "matching" };
          })
          .filter((spec) => spec.count > 0);
      }
      if (folderSpecs.length === 0 && children.length === 0) {
        $("entryTable").innerHTML = status + empty(dateFilterActive()
          ? "No entries in this folder match the date filter."
          : "No entries in this folder.");
        renderSelectionCount();
        return;
      }
      const folderRows = folderSpecs.map(({ path, count, countKind }) => {
        const folderEntry = entries.find((entry) =>
          entry.entry_kind === "directory" && normalizeLogicalPath(entry.logical_path) === normalizeLogicalPath(path)
        );
        return `
          <tr class="entry-row" onclick="selectFolder('${escapeAttr(escapeJs(path))}')">
            <td></td>
            <td title="${escapeAttr(path)}"><span class="entry-name">${escapeHtml(logicalName(path))}</span></td>
            <td class="entry-kind" title="${count} ${countKind} item${count === 1 ? "" : "s"}">Folder</td>
            <td class="entry-ext"></td>
            <td class="entry-size"></td>
            <td class="entry-time" title="${escapeAttr(filesystemCreatedTime(folderEntry))}">${escapeHtml(filesystemCreatedTime(folderEntry))}</td>
            <td class="entry-time" title="${escapeAttr(filesystemAccessedTime(folderEntry))}">${escapeHtml(filesystemAccessedTime(folderEntry))}</td>
            <td class="entry-time" title="${escapeAttr(filesystemModifiedTime(folderEntry))}">${escapeHtml(filesystemModifiedTime(folderEntry))}</td>
            <td class="entry-time" title="${escapeAttr(filesystemMftModifiedTime(folderEntry))}">${escapeHtml(filesystemMftModifiedTime(folderEntry))}</td>
          </tr>`;
      });
      const entryRows = children.map((entry) => {
        const selected = state.hex.entryId === entry.id ? " selected" : "";
        const isChecked = state.selectedEntryIds.has(entry.id);
        const checked = isChecked ? " checked" : "";
        const multiSelected = isChecked ? " multi-selected" : "";
        return `
          <tr class="entry-row${selected}${multiSelected}" data-entry-id="${entry.id}" onclick="handleEntryRowClick(event, ${entry.id})">
            <td><input type="checkbox"${checked} onclick="event.stopPropagation(); toggleEntrySelection(${entry.id}, this.checked, event)"></td>
            <td title="${escapeAttr(entry.logical_path)}"><span class="entry-name">${escapeHtml(entry.name || logicalName(entry.logical_path))}</span></td>
            <td class="entry-kind">${escapeHtml(filesystemTypeLabel(entry))}</td>
            <td class="entry-ext">${escapeHtml(filesystemFileExtension(entry))}</td>
            <td class="entry-size">${entry.size_bytes == null ? "" : formatBytes(entry.size_bytes)}</td>
            <td class="entry-time" title="${escapeAttr(filesystemCreatedTime(entry))}">${escapeHtml(filesystemCreatedTime(entry))}</td>
            <td class="entry-time" title="${escapeAttr(filesystemAccessedTime(entry))}">${escapeHtml(filesystemAccessedTime(entry))}</td>
            <td class="entry-time" title="${escapeAttr(filesystemModifiedTime(entry))}">${escapeHtml(filesystemModifiedTime(entry))}</td>
            <td class="entry-time" title="${escapeAttr(filesystemMftModifiedTime(entry))}">${escapeHtml(filesystemMftModifiedTime(entry))}</td>
          </tr>`;
      });
      $("entryTable").innerHTML = status + table(["", "Name", "Type", "File ext", "Size", "Created", "Accessed", "Modified", "MFT modified"], folderRows.concat(entryRows).join(""), "folder-table");
      renderSelectionCount();
    }

    function truncatedEntriesNoticeHtml() {
      if (!state.data || !state.data.entries_truncated) {
        return "";
      }
      const total = (state.data.entry_count || 0).toLocaleString();
      const shown = (state.data.entries_limit || state.data.entries.length).toLocaleString();
      return `<div class="analysis-status">This case has ${total} indexed entries; only the first ${shown} are loaded in this indexed view (loading all of them would hang the browser). Use <strong>Live browse</strong> to navigate the whole disk directly, or <strong>Deep Search</strong> to find specific files.</div>`;
    }

    function imageAnalysisStatusHtml(entries) {
      const evidence = selectedEvidenceSource();
      if (!evidence || !(evidence.source_kind === "image" || looksLikeDiskImage(evidence.source_path))) {
        return "";
      }
      const hasParsedVolume = entries.some((entry) =>
        entry.entry_kind === "directory"
        && entry.metadata_json
        && entry.metadata_json.artifact_kind === "filesystem_volume"
      );
      if (hasParsedVolume) {
        return "";
      }
      const wholeVolume = entries.find((entry) =>
        entry.metadata_json
        && entry.metadata_json.artifact_kind === "disk_volume"
        && entry.metadata_json.start_offset === 0
      );
      if (wholeVolume && wholeVolume.metadata_json.filesystem) {
        const fs = wholeVolume.metadata_json.filesystem;
        return `<div class="analysis-status">Detected a whole-image ${escapeHtml(fs)} volume at byte 0. Folder browsing for ${escapeHtml(fs)} is not indexed yet.</div>`;
      }
      const report = entries.find((entry) =>
        entry.metadata_json
        && entry.metadata_json.artifact_kind === "disk_partition_report"
      );
      if (report && report.metadata_json && report.metadata_json.error) {
        return `<div class="analysis-status">No browsable filesystem was indexed. Partition analysis reported: ${escapeHtml(report.metadata_json.error)}</div>`;
      }
      return "";
    }

    function renderSelectionCount() {
      const count = state.selectedEntryIds ? state.selectedEntryIds.size : 0;
      $("selectedCount").textContent = count + " selected";
    }

    function activityLabel(entry) {
      if (isEmailEntry(entry)) {
        return "Email";
      }
      if (entry.entry_kind !== "record") {
        return entry.entry_kind;
      }
      const kind = entry.metadata_json && entry.metadata_json.artifact_kind;
      if (kind === "browser_history_visit") return "Visit";
      if (kind === "browser_bookmark") return "Bookmark";
      if (kind === "browser_preference") return "Preference";
      return "Record";
    }

    function entrySummary(entry) {
      const metadata = entry.metadata_json || {};
      if (isEmailEntry(entry)) {
        return emailPreview(entry);
      }
      if (isBrowserActivityEntry(entry)) {
        return browserActivityPreview(entry);
      }
      if (metadata.url) {
        return metadata.visit_time_utc ? metadata.visit_time_utc + " | " + metadata.url : metadata.url;
      }
      if (metadata.analysis_category || metadata.category_main) {
        return compactParts([entryCategoryLabel(entry), entry.logical_path]);
      }
      if (metadata.category) {
        return compactParts([metadata.category, entry.logical_path]);
      }
      return entry.logical_path;
    }

    function idxBrowseActive() {
      return !!(state.data && state.data.entries_truncated
        && state.browserState.treeMode !== "categories"
        && state.idx.evidenceId
        && state.idx.evidenceId === state.browserState.evidenceId);
    }

    function visibleFolderEntries() {
      if (state.browserState.treeMode === "categories") {
        return categoryEntriesForSelection(selectedEvidenceEntries(), state.browserState.selectedCategory || "");
      }
      if (idxBrowseActive()) {
        return (state.idx.dirCache[state.idx.selPath || "/"] || [])
          .filter((child) => !child.is_dir && child.entry_id != null)
          .map(idxChildToEntry);
      }
      return folderChildren(selectedEvidenceEntries(), state.browserState.selectedPath || "/");
    }

    function visibleEntryIds() {
      return visibleFolderEntries()
        .filter((entry) => entry.entry_kind !== "directory")
        .map((entry) => entry.id);
    }

    function selectedEvidenceSource() {
      if (!state.data || !state.browserState.evidenceId) {
        return null;
      }
      return state.data.evidence.find((item) => item.id === state.browserState.evidenceId) || null;
    }

    function evidenceSourceForEntry(entry) {
      if (!state.data || !entry) {
        return null;
      }
      return state.data.evidence.find((item) => item.id === entry.evidence_id) || null;
    }

    function isPromotableDiskImageEntry(entry, evidence) {
      return !!entry
        && !!evidence
        && entry.entry_kind === "file"
        && (evidence.source_kind === "folder" || evidence.source_kind === "file")
        && looksLikeDiskImage(entry.name || entry.logical_path)
        && !!evidenceEntryLocalPath(evidence, entry);
    }

    function evidenceEntryLocalPath(evidence, entry) {
      if (!evidence || !entry) {
        return null;
      }
      if (evidence.source_kind === "file") {
        return evidence.source_path;
      }
      if (evidence.source_kind !== "folder") {
        return null;
      }
      const parts = normalizeLogicalPath(entry.logical_path).split("/").filter(Boolean);
      return joinLocalPath(evidence.source_path, parts);
    }

    function joinLocalPath(root, parts) {
      const baseValue = String(root || "");
      if (!baseValue || !parts || parts.length === 0) {
        return baseValue;
      }
      const windowsPath = /^[A-Za-z]:[\\/]/.test(baseValue) || baseValue.startsWith("\\\\") || baseValue.startsWith("//");
      const sep = windowsPath ? "\\" : "/";
      let base = baseValue;
      while (base.length > 3 && /[\\/]$/.test(base)) {
        base = base.slice(0, -1);
      }
      return (/[\\/]$/.test(base) ? base : base + sep) + parts.join(sep);
    }

    function sameLocalPath(left, right) {
      const normalize = (value) => String(value || "")
        .replace(/^\\\\\?\\/, "")
        .replace(/\\/g, "/")
        .replace(/\/+$/g, "")
        .toLowerCase();
      return normalize(left) === normalize(right);
    }

    function defaultRecoveryPath(entry) {
      const root = BOOTSTRAP.workspaceRoot || ".";
      const folder = recoveryActionText(entry).folder;
      return joinLocalPath(joinLocalPath(root, ["ui-output", folder]), [
        String(entry.id) + "-" + safeFileName(entry.name || logicalName(entry.logical_path) || "recovered.bin")
      ]);
    }

    function isDeletedRecoveryEntry(entry) {
      const metadata = entry && entry.metadata_json ? entry.metadata_json : {};
      return Boolean(entry && (
        entry.is_deleted
        || metadata.recovery_source === "ntfs_deleted_mft"
        || metadata.artifact_kind === "deleted_file_record"
      ));
    }

    function isRecoveryEntry(entry) {
      const metadata = entry && entry.metadata_json ? entry.metadata_json : {};
      return Boolean(entry && (
        isDeletedRecoveryEntry(entry)
        || metadata.artifact_kind === "unallocated_space"
        || metadata.is_unallocated
        || metadata.is_file_slack
      ));
    }

    function recoveryActionText(entry) {
      const metadata = entry && entry.metadata_json ? entry.metadata_json : {};
      if (metadata.artifact_kind === "unallocated_space" || metadata.is_unallocated) {
        return { button: "Export unallocated", prompt: "Export unallocated stream", past: "Exported", folder: "exported" };
      }
      if (metadata.is_file_slack) {
        return { button: "Export slack", prompt: "Export file slack", past: "Exported", folder: "exported" };
      }
      if (isDeletedRecoveryEntry(entry)) {
        return { button: "Recover", prompt: "Recover file", past: "Recovered", folder: "recovered" };
      }
      return { button: "Export file", prompt: "Export file", past: "Exported", folder: "exported" };
    }

    function safeFileName(value) {
      const cleaned = String(value || "recovered.bin")
        .replace(/[<>:"/\\|?*\x00-\x1F]/g, "_")
        .replace(/\s+/g, " ")
        .trim();
      return cleaned || "recovered.bin";
    }

    function categorizedVisibleEntries(entries) {
      return entries.filter((entry) => entry.entry_kind !== "directory");
    }

    function categoryEntriesForSelection(entries, key) {
      const selected = splitCategoryKey(key || "");
      return categorizedVisibleEntries(entries)
        .filter((entry) => {
          if (!selected.main) {
            return true;
          }
          const category = entryCategory(entry);
          if (category.main !== selected.main) {
            return false;
          }
          return !selected.sub || category.sub === selected.sub;
        })
        .sort((left, right) => {
          const leftCategory = entryCategoryLabel(left);
          const rightCategory = entryCategoryLabel(right);
          return leftCategory.localeCompare(rightCategory) || compareEntries(left, right);
        });
    }

    function entryCategoryLabel(entry) {
      const category = entryCategory(entry);
      return category.main + " / " + category.sub;
    }

    function entryCategoryDetail(entry) {
      const metadata = entry.metadata_json || {};
      return firstText(metadata.category_detail, metadata.analysis_category, entrySummary(entry));
    }

    function entryCategory(entry) {
      const metadata = entry.metadata_json || {};
      if (metadata.category_main && metadata.category_sub) {
        return { main: String(metadata.category_main), sub: String(metadata.category_sub) };
      }
      return inferEntryCategory(entry);
    }

    function inferEntryCategory(entry) {
      const metadata = entry.metadata_json || {};
      const artifact = metadata.artifact_kind || "";
      if (artifact === "browser_history_visit") return { main: "Cloud and Web", sub: "Browser history" };
      if (artifact === "browser_bookmark") return { main: "Cloud and Web", sub: "Browser bookmarks" };
      if (artifact === "browser_preference") return { main: "Accounts and Identity", sub: "Browser profile settings" };
      if (artifact === "email_message") return { main: "Email and Communications", sub: "Email messages" };
      if (artifact === "email_store") return { main: "Email and Communications", sub: "Email stores" };
      if (artifact === "deleted_file_record" || metadata.recovery_source === "ntfs_deleted_mft" || entry.is_deleted) return { main: "Recovery", sub: "Deleted files" };
      if (artifact === "unallocated_space" || metadata.is_unallocated) return { main: "Recovery", sub: "Unallocated space" };
      if (/disk_|filesystem_/.test(artifact)) return { main: "Operating System", sub: "Disk and filesystem structure" };

      const text = (String(entry.logical_path || "") + "/" + String(entry.name || "")).toLowerCase();
      const ext = fileExtension(entry.name || entry.logical_path);
      if (hasExt(ext, ["jpg", "jpeg", "png", "gif", "bmp", "tif", "tiff", "heic", "heif", "webp", "cr2", "nef", "arw", "dng", "svg", "ico", "psd", "ai", "emf", "wmf", "jfif", "raf", "orf"])) return { main: "Pictures and Media", sub: "Pictures" };
      if (hasExt(ext, ["mp4", "mov", "avi", "mkv", "wmv", "m4v", "3gp", "webm", "flv", "mpg", "mpeg", "ts", "m2ts", "vob", "ogv", "asf", "rm"])) return { main: "Pictures and Media", sub: "Video" };
      if (hasExt(ext, ["mp3", "wav", "m4a", "aac", "flac", "ogg", "wma", "amr", "mid", "midi", "aif", "aiff", "ape", "opus", "ra", "au"])) return { main: "Pictures and Media", sub: "Audio" };
      if (hasExt(ext, ["eml"])) return { main: "Email and Communications", sub: "Email messages" };
      if (hasExt(ext, ["pst", "ost", "msg", "mbox", "olm", "dbx", "nsf", "edb"]) && /mail|exchange|outlook/.test(text)) return { main: "Email and Communications", sub: "Email stores" };
      if (hasExt(ext, ["pst", "ost", "msg", "mbox", "olm", "dbx", "nsf"])) return { main: "Email and Communications", sub: "Email stores" };
      if (hasExt(ext, ["kdbx", "kdb", "psafe3"]) || /login data|password|credentials|keychain|cookies|token|wallet|vault|secret/.test(text)) return { main: "Accounts and Identity", sub: "Credentials and tokens" };
      if (hasExt(ext, ["pem", "cer", "crt", "der", "pfx", "p12", "p7b", "csr", "gpg", "asc", "sig"])) return { main: "Accounts and Identity", sub: "Certificates and keys" };
      if (/onedrive|dropbox|google drive|icloud|\/box\//.test(text)) return { main: "Cloud and Web", sub: "Cloud sync" };
      // Generic words (history/cache/...) only mean browser artifacts inside a
      // browser path; otherwise system32/dllcache etc. classify as web content.
      const browserContext = /chrome|chromium|microsoft[\/\\]edge|mozilla|firefox|safari|opera|brave|vivaldi|netscape|internet explorer|temporary internet files|content\.ie5|browser/.test(text);
      if (/places\.sqlite|webcachev01\.dat|favicons|top sites|visited links/.test(text) || (browserContext && /history|cache|bookmarks|downloads/.test(text))) return { main: "Cloud and Web", sub: "Browser artifacts" };
      if (hasExt(ext, ["html", "htm", "mht", "mhtml", "xhtml", "css", "url", "webloc"])) return { main: "Cloud and Web", sub: "Web pages and links" };
      if (hasExt(ext, ["torrent", "ica", "rdp", "ovpn", "pcap", "pcapng"])) return { main: "Cloud and Web", sub: "Network and remote access" };
      if (/prefetch|amcache|shimcache|userassist|automaticdestinations-ms|customdestinations-ms|\.lnk/.test(text) || hasExt(ext, ["lnk", "pf"])) return { main: "Program Execution", sub: "Execution artifacts" };
      if (hasExt(ext, ["exe", "dll", "sys", "com", "scr", "msi", "msp", "msu", "cpl", "ocx", "drv", "efi", "bin", "so", "dylib", "apk", "ipa", "app", "appx", "xap"])) return { main: "Program Execution", sub: "Executables and binaries" };
      if (hasExt(ext, ["bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "jar", "sh", "hta", "scpt", "applescript"])) return { main: "Program Execution", sub: "Scripts" };
      if (/\/windows\/system32\/config\/|\/ntuser\.dat|\/usrclass\.dat/.test(text) || hasExt(ext, ["hiv", "reg"])) return { main: "Operating System", sub: "Registry hives" };
      if (/\.evtx|\.etl|winevt\/logs/.test(text) || hasExt(ext, ["evtx", "evt", "etl", "log"])) return { main: "Operating System", sub: "Logs and events" };
      if (hasExt(ext, ["dmp", "mdmp", "hdmp", "chk"]) || /pagefile\.sys|hiberfil\.sys|swapfile\.sys|memory\.dmp/.test(text)) return { main: "Operating System", sub: "Memory and crash dumps" };
      if (hasExt(ext, ["ini", "inf", "cfg", "conf", "config", "plist", "pol", "admx", "adml", "manifest", "cat", "mum"])) return { main: "Operating System", sub: "Configuration files" };
      if (hasExt(ext, ["ttf", "otf", "ttc", "fon", "woff", "woff2", "eot"])) return { main: "Operating System", sub: "Fonts" };
      if (hasExt(ext, ["cur", "ani", "theme", "deskthemepack", "scf", "library-ms", "searchconnector-ms"])) return { main: "Operating System", sub: "Shell and appearance" };
      if (hasExt(ext, ["pdf", "xps", "oxps"])) return { main: "Documents and Office", sub: "PDF and fixed layout" };
      if (hasExt(ext, ["doc", "docx", "docm", "dot", "dotx", "rtf", "odt", "wpd", "pages", "one", "onetoc2"])) return { main: "Documents and Office", sub: "Word processing" };
      if (hasExt(ext, ["xls", "xlsx", "xlsm", "xlsb", "xlt", "csv", "tsv", "ods", "numbers"])) return { main: "Documents and Office", sub: "Spreadsheets" };
      if (hasExt(ext, ["ppt", "pptx", "pptm", "pps", "ppsx", "odp", "key"])) return { main: "Documents and Office", sub: "Presentations" };
      if (hasExt(ext, ["txt", "text", "md", "nfo", "readme"])) return { main: "Documents and Office", sub: "Plain text" };
      if (hasExt(ext, ["epub", "mobi", "azw", "azw3", "fb2", "chm", "hlp", "djvu"])) return { main: "Documents and Office", sub: "E-books and help" };
      if (hasExt(ext, ["zip", "rar", "7z", "tar", "gz", "tgz", "bz2", "xz", "zst", "lz", "lzh", "arj", "z", "cab", "wim", "swm", "deb", "rpm", "pkg", "dmg"])) return { main: "Archives and Containers", sub: "Archives" };
      if (hasExt(ext, ["e01", "ex01", "l01", "lx01", "aff4", "ad1", "raw", "dd", "img", "iso", "vhd", "vhdx", "vmdk", "vdi", "qcow2", "ova", "ovf", "vmem", "vmsn", "vmss", "nvram"])) return { main: "Archives and Containers", sub: "Disk images and VM files" };
      if (hasExt(ext, ["db", "sqlite", "sqlite3", "sqlitedb", "db3", "db-wal", "db-shm", "mdb", "accdb", "edb", "sdf", "frm", "ibd", "myd", "realm", "mdf", "ldf", "bak"])) return { main: "Databases", sub: "Application databases" };
      if (hasExt(ext, ["py", "rs", "go", "java", "cs", "cpp", "c", "h", "hpp", "php", "rb", "ts", "tsx", "jsx", "swift", "kt", "pl", "lua", "sql", "json", "xml", "yaml", "yml", "toml", "sln", "csproj", "gradle", "makefile"])) return { main: "Development and Source Code", sub: "Source and project files" };
      if (hasExt(ext, ["bup", "spf", "spi", "gho", "tib", "vbk", "vib"])) return { main: "Archives and Containers", sub: "Backups" };
      if (hasExt(ext, ["tmp", "temp", "crdownload", "partial", "part", "download"])) return { main: "Other Files", sub: "Temporary and partial files" };
      if (!ext) return { main: "Other Files", sub: "No extension" };
      return { main: "Other Files", sub: "Other extensions" };
    }

    function categoryTime(entry) {
      const metadata = entry.metadata_json || {};
      return firstText(
        metadata.email_date,
        metadata.visit_time_utc,
        metadata.date_added_utc,
        metadata.modified_utc,
        metadata.mft_modified_utc,
        metadata.file_name_modified_utc,
        metadata.standard_information_modified_utc,
        metadata.source_file_modified_utc,
        metadata.created_utc,
        metadata.file_name_created_utc,
        metadata.standard_information_created_utc
      );
    }

    function categoryKey(main, sub) {
      return sub ? main + "|||" + sub : main;
    }

    function splitCategoryKey(key) {
      if (!key) {
        return { main: "", sub: "" };
      }
      const parts = String(key).split("|||");
      return { main: parts[0] || "", sub: parts[1] || "" };
    }

    function categoryLabel(key) {
      const parts = splitCategoryKey(key);
      return parts.main && parts.sub ? parts.main + " / " + parts.sub : parts.main;
    }

    function fileExtension(value) {
      const name = String(value || "").split(/[\\/]/).pop() || "";
      const index = name.lastIndexOf(".");
      return index >= 0 && index < name.length - 1 ? name.slice(index + 1).toLowerCase() : "";
    }

    function hasExt(ext, values) {
      return values.includes(String(ext || "").toLowerCase());
    }

    function folderChildren(entries, folder) {
      const normalized = normalizeLogicalPath(folder || "/");
      return entries
        .filter((entry) => parentLogicalPath(entry.logical_path) === normalized)
        .sort(compareEntries);
    }

    function directChildFolders(knownFolders, folder) {
      const normalized = normalizeLogicalPath(folder || "/");
      return Array.from(knownFolders)
        .map(normalizeLogicalPath)
        .filter((path) => path !== normalized && parentLogicalPath(path) === normalized)
        .sort(compareLogicalPaths);
    }

    // Old Ecase 6.11 presents evidence as device -> volume -> folders (manual p.89
    // Figure 13; see docs/manual-notes/CH05-tree-pane-entries-view.md). The
    // indexer's synthetic "/Image Analysis[/Volumes|/Partitions]" containers are
    // collapsed at display time only; stored logical paths, bookmarks, and URLs
    // keep the real paths.
    function syntheticContainerSet(knownFolders) {
      const synthetic = new Set();
      if (knownFolders.has("/Image Analysis")) {
        synthetic.add("/Image Analysis");
        ["/Image Analysis/Volumes", "/Image Analysis/Partitions"].forEach((path) => {
          if (knownFolders.has(path)) {
            synthetic.add(path);
          }
        });
      }
      return synthetic;
    }

    function displayParentPath(path, synthetic) {
      let parent = parentLogicalPath(path);
      while (parent !== "/" && synthetic.has(parent)) {
        parent = parentLogicalPath(parent);
      }
      return parent;
    }

    function displayChildFolders(knownFolders, folder, synthetic) {
      const normalized = normalizeLogicalPath(folder || "/");
      return Array.from(knownFolders)
        .map(normalizeLogicalPath)
        .filter((path) => path !== normalized && !synthetic.has(path) && displayParentPath(path, synthetic) === normalized)
        .sort(compareLogicalPaths);
    }

    function displayFolderChildren(entries, folder, synthetic) {
      const normalized = normalizeLogicalPath(folder || "/");
      return entries
        .filter((entry) => {
          const path = normalizeLogicalPath(entry.logical_path);
          return !synthetic.has(path) && displayParentPath(path, synthetic) === normalized;
        })
        .sort(compareEntries);
    }

    function displayFolderChildCount(entries, knownFolders, folder, synthetic) {
      return displayFolderChildren(entries, folder, synthetic).length
        + displayChildFolders(knownFolders, folder, synthetic).length;
    }

    function matchingSubtreeCount(passingEntries, folder) {
      const normalized = normalizeLogicalPath(folder || "/");
      const prefix = normalized === "/" ? "/" : normalized + "/";
      return passingEntries.filter((entry) => {
        const entryPath = normalizeLogicalPath(entry.logical_path);
        return entryPath === normalized || entryPath.startsWith(prefix);
      }).length;
    }

    function expandedTreeSet() {
      const key = String(state.browserState.evidenceId || "none");
      if (!state.expandedTreePaths.has(key)) {
        state.expandedTreePaths.set(key, new Set(["/"]));
      }
      return state.expandedTreePaths.get(key);
    }

    function expandTreePath(path) {
      const normalized = normalizeLogicalPath(path || "/");
      const expanded = expandedTreeSet();
      expanded.add("/");
      treeAncestors(normalized).forEach((ancestor) => expanded.add(ancestor));
      expanded.add(normalized);
    }

    function ensureTreeAncestorsExpanded(path) {
      const expanded = expandedTreeSet();
      expanded.add("/");
      treeAncestors(path).forEach((ancestor) => expanded.add(ancestor));
    }

    function toggleTreePath(path) {
      const normalized = normalizeLogicalPath(path || "/");
      const expanded = expandedTreeSet();
      if (expanded.has(normalized)) {
        expanded.delete(normalized);
      } else {
        expanded.add(normalized);
      }
      renderEvidenceBrowserEntries();
    }

    function treeAncestors(path) {
      const parts = normalizeLogicalPath(path || "/").split("/").filter(Boolean);
      const ancestors = [];
      let current = "/";
      for (let index = 0; index < parts.length - 1; index += 1) {
        current = current === "/" ? "/" + parts[index] : current + "/" + parts[index];
        ancestors.push(current);
      }
      return ["/"].concat(ancestors.filter((ancestor) => ancestor !== "/"));
    }

    function folderChildCount(entries, knownFolders, folder) {
      const normalized = normalizeLogicalPath(folder || "/");
      const entryCount = entries.filter((entry) => parentLogicalPath(entry.logical_path) === normalized).length;
      const folderCount = Array.from(knownFolders)
        .map(normalizeLogicalPath)
        .filter((path) => path !== normalized && parentLogicalPath(path) === normalized)
        .length;
      return entryCount + folderCount;
    }

    function directoryPathSet(entries) {
      const paths = new Set(["/"]);
      entries.forEach((entry) => {
        const path = normalizeLogicalPath(entry.logical_path);
        let parent = parentLogicalPath(path);
        paths.add(parent);
        while (parent !== "/") {
          parent = parentLogicalPath(parent);
          paths.add(parent);
        }
        if (entry.entry_kind === "directory") {
          paths.add(path);
        }
      });
      return paths;
    }

    // Display form of a stored logical path: the synthetic image-analysis
    // containers are dropped so paths read device-relative like the Entries
    // tree. Tooltips and forensic records keep the full stored path.
    function displayPath(path) {
      return normalizeLogicalPath(path)
        .replace(/^\/Image Analysis\/(Volumes|Partitions)(\/|$)/, "/")
        .replace(/^\/Image Analysis(\/|$)/, "/");
    }

    function normalizeLogicalPath(path) {
      let value = String(path || "/").replace(/\\/g, "/");
      if (!value.startsWith("/")) {
        value = "/" + value;
      }
      value = value.replace(/\/+/g, "/");
      if (value.length > 1) {
        value = value.replace(/\/+$/g, "");
      }
      return value || "/";
    }

    function parentLogicalPath(path) {
      const normalized = normalizeLogicalPath(path);
      if (normalized === "/") {
        return "/";
      }
      const parts = normalized.split("/").filter(Boolean);
      parts.pop();
      return parts.length ? "/" + parts.join("/") : "/";
    }

    function logicalName(path) {
      const normalized = normalizeLogicalPath(path);
      if (normalized === "/") {
        return "/";
      }
      const parts = normalized.split("/").filter(Boolean);
      return parts[parts.length - 1] || normalized;
    }

    function pathDepth(path) {
      return normalizeLogicalPath(path).split("/").filter(Boolean).length;
    }

    function compareLogicalPaths(left, right) {
      const leftDepth = pathDepth(left);
      const rightDepth = pathDepth(right);
      return leftDepth - rightDepth || left.toLowerCase().localeCompare(right.toLowerCase());
    }

    function compareEntries(left, right) {
      const leftRank = left.entry_kind === "directory" ? 0 : left.entry_kind === "file" ? 1 : 2;
      const rightRank = right.entry_kind === "directory" ? 0 : right.entry_kind === "file" ? 1 : 2;
      return leftRank - rightRank || (left.name || left.logical_path).toLowerCase().localeCompare((right.name || right.logical_path).toLowerCase());
    }

    function isBrowserActivityEntry(entry) {
      const kind = entry && entry.metadata_json && entry.metadata_json.artifact_kind;
      return entry && entry.entry_kind === "record"
        && (kind === "browser_history_visit" || kind === "browser_bookmark" || kind === "browser_preference");
    }

    function isEmailEntry(entry) {
      const kind = entry && entry.metadata_json && entry.metadata_json.artifact_kind;
      return kind === "email_message" || kind === "email_store";
    }

    function entryBookmarkPayload(entry) {
      if (isEmailEntry(entry)) {
        const displayName = emailDisplayName(entry);
        return {
          folderName: "Emails",
          title: "Email: " + displayName,
          comment: emailPreview(entry),
          bookmarkType: "email",
          dataType: "Email Message",
          displayName,
          dataPreview: emailPreview(entry),
          itemRefJson: emailItemRef(entry)
        };
      }
      if (!isBrowserActivityEntry(entry)) {
        return {
          folderName: "Evidence Entries",
          title: "Entry: " + (entry.name || logicalName(entry.logical_path)),
          comment: "",
          bookmarkType: entry.entry_kind === "file" ? "notable_file" : "folder_info",
          dataType: "Evidence Entry",
          displayName: entry.name || logicalName(entry.logical_path),
          dataPreview: null,
          itemRefJson: filesystemEntryItemRef(entry)
        };
      }
      const label = activityLabel(entry);
      const displayName = browserActivityDisplayName(entry);
      return {
        folderName: "Browser Activities",
        title: label + ": " + displayName,
        comment: browserActivityPreview(entry),
        bookmarkType: "record",
        dataType: "Browser Activity",
        displayName,
        dataPreview: browserActivityPreview(entry),
        itemRefJson: browserActivityItemRef(entry)
      };
    }

    function emailDisplayName(entry) {
      const metadata = entry.metadata_json || {};
      return firstText(metadata.email_subject, metadata.email_message_id, entry.name, logicalName(entry.logical_path));
    }

    function emailPreview(entry) {
      const metadata = entry.metadata_json || {};
      if (metadata.artifact_kind === "email_store") {
        return compactParts([metadata.email_format ? String(metadata.email_format).toUpperCase() + " mailbox store" : "Mailbox store", metadata.email_parser_status]);
      }
      return compactParts([
        metadata.email_date,
        metadata.email_from ? "From: " + metadata.email_from : "",
        metadata.email_to ? "To: " + metadata.email_to : "",
        metadata.email_subject ? "Subject: " + metadata.email_subject : "",
        metadata.email_body_preview
      ]);
    }

    function emailItemRef(entry) {
      const metadata = entry.metadata_json || {};
      const ref = {
        kind: "email_message",
        artifact_kind: metadata.artifact_kind || "email_message",
        evidence_id: entry.evidence_id,
        entry_id: entry.id,
        entry_kind: entry.entry_kind,
        logical_path: entry.logical_path,
        display_name: emailDisplayName(entry),
        size_bytes: entry.size_bytes,
        is_deleted: Boolean(entry.is_deleted),
        storage_area: metadata.storage_area || "",
        is_file_slack: Boolean(metadata.is_file_slack),
        is_unallocated: Boolean(metadata.is_unallocated),
        mft_record_logical_offset: metadata.mft_record_logical_offset,
        mft_record_physical_offset: metadata.mft_record_physical_offset,
        file_data_logical_offset: metadata.file_data_logical_offset,
        file_data_physical_offset: metadata.file_data_physical_offset,
        file_extension: filesystemFileExtension(entry),
        signature_status: metadata.signature_status || "",
        detected_signature: metadata.detected_signature || "",
        metadata: reportMetadata(metadata)
      };
      [
        "email_format", "email_parser", "email_parser_status", "email_parser_error",
        "email_from", "email_to", "email_cc", "email_bcc", "email_subject",
        "email_date", "email_message_id", "email_reply_to", "email_in_reply_to",
        "email_body_preview", "source_entry_name", "filesystem_parser", "ntfs_path",
        "fat_path", "ntfs_standard_modification_time_utc", "ntfs_modification_time_utc"
      ].forEach((key) => {
        if (metadata[key] !== undefined && metadata[key] !== null && String(metadata[key]).length > 0) {
          ref[key] = metadata[key];
        }
      });
      return ref;
    }

    function browserActivityDisplayName(entry) {
      const metadata = entry.metadata_json || {};
      if (metadata.artifact_kind === "browser_history_visit") {
        return firstText(metadata.title, metadata.url, entry.name, logicalName(entry.logical_path));
      }
      if (metadata.artifact_kind === "browser_bookmark") {
        return firstText(metadata.name, metadata.title, metadata.url, entry.name, logicalName(entry.logical_path));
      }
      if (metadata.artifact_kind === "browser_preference") {
        return firstText(metadata.category, metadata.name, entry.name, logicalName(entry.logical_path));
      }
      return firstText(entry.name, logicalName(entry.logical_path));
    }

    function browserActivityPreview(entry) {
      const metadata = entry.metadata_json || {};
      if (metadata.artifact_kind === "browser_history_visit") {
        return compactParts([metadata.visit_time_utc, firstText(metadata.title), metadata.url]);
      }
      if (metadata.artifact_kind === "browser_bookmark") {
        return compactParts([firstText(metadata.name, metadata.title), metadata.url, metadata.folder]);
      }
      if (metadata.artifact_kind === "browser_preference") {
        return compactParts([metadata.category, preferenceSummary(metadata)]);
      }
      return entry.logical_path;
    }

    function preferenceSummary(metadata) {
      const values = [
        metadata.name ? "profile " + metadata.name : "",
        Array.isArray(metadata.startup_urls) && metadata.startup_urls.length ? "startup " + metadata.startup_urls.join(", ") : "",
        metadata.homepage ? "homepage " + metadata.homepage : "",
        metadata.download_default_directory ? "downloads " + metadata.download_default_directory : "",
        metadata.extension_count !== undefined && metadata.extension_count !== null ? metadata.extension_count + " extensions" : ""
      ];
      return compactParts(values) || compactJson(metadata);
    }

    function browserActivityItemRef(entry) {
      const metadata = entry.metadata_json || {};
      const ref = {
        kind: "browser_activity",
        activity_kind: metadata.artifact_kind || "record",
        browser_family: metadata.browser_family || "chromium",
        evidence_id: entry.evidence_id,
        entry_id: entry.id,
        entry_kind: entry.entry_kind,
        logical_path: entry.logical_path,
        display_name: browserActivityDisplayName(entry),
        metadata: reportMetadata(metadata)
      };
      [
        "url", "title", "host", "visit_time_utc", "transition_type", "visit_count",
        "typed_count", "visit_duration_microseconds", "visit_id", "url_id",
        "last_visit_time_utc", "visit_time_chrome", "last_visit_time_chrome",
        "transition", "hidden", "name", "folder", "date_added_utc",
        "date_last_used_utc", "date_added_chrome", "date_last_used_chrome",
        "guid", "category", "startup_urls", "homepage", "restore_on_startup",
        "homepage_is_newtabpage", "download_default_directory", "prompt_for_download",
        "created_by_version", "last_used", "avatar_index", "extension_count",
        "source_artifact", "source_artifact_path", "source_file_size_bytes",
        "source_file_created_utc", "source_file_modified_utc", "source_file_accessed_utc"
      ].forEach((key) => {
        if (metadata[key] !== undefined && metadata[key] !== null && String(metadata[key]).length > 0) {
          ref[key] = metadata[key];
        }
      });
      return ref;
    }

    function searchResultItemRef(hit) {
      const entry = state.data && state.data.entries.find((item) => item.id === hit.entry_id);
      const metadata = entry ? (entry.metadata_json || {}) : {};
      return {
        kind: "search_result",
        match_kind: hit.match_kind,
        evidence_id: hit.evidence_id,
        entry_id: hit.entry_id,
        logical_path: hit.logical_path,
        display_name: hit.display_name,
        selection_offset: hit.selection_offset,
        selection_length: hit.selection_length,
        data_preview: hit.data_preview,
        size_bytes: entry ? entry.size_bytes : null,
        is_deleted: entry ? Boolean(entry.is_deleted) : false,
        relative_path: hit.logical_path,
        storage_area: metadata.storage_area || "",
        is_file_slack: Boolean(metadata.is_file_slack),
        is_unallocated: Boolean(metadata.is_unallocated),
        mft_record_logical_offset: metadata.mft_record_logical_offset,
        mft_record_physical_offset: metadata.mft_record_physical_offset,
        file_data_logical_offset: metadata.file_data_logical_offset,
        file_data_physical_offset: metadata.file_data_physical_offset,
        finding_logical_offset: hit.selection_offset,
        file_extension: entry ? filesystemFileExtension(entry) : fileExtension(hit.logical_path),
        signature_status: metadata.signature_status || "",
        detected_signature: metadata.detected_signature || "",
        metadata: reportMetadata(metadata)
      };
    }

    function filesystemEntryItemRef(entry) {
      const metadata = entry.metadata_json || {};
      return {
        kind: "filesystem_entry",
        entry_kind: entry.entry_kind,
        evidence_id: entry.evidence_id,
        entry_id: entry.id,
        logical_path: entry.logical_path,
        relative_path: entry.logical_path,
        display_name: entry.name || logicalName(entry.logical_path),
        size_bytes: entry.size_bytes,
        is_deleted: Boolean(entry.is_deleted),
        storage_area: metadata.storage_area || "",
        is_file_slack: Boolean(metadata.is_file_slack),
        is_unallocated: Boolean(metadata.is_unallocated),
        mft_record_logical_offset: metadata.mft_record_logical_offset,
        mft_record_physical_offset: metadata.mft_record_physical_offset,
        file_data_logical_offset: metadata.file_data_logical_offset,
        file_data_physical_offset: metadata.file_data_physical_offset,
        file_extension: filesystemFileExtension(entry),
        signature_status: metadata.signature_status || "",
        detected_signature: metadata.detected_signature || "",
        metadata: reportMetadata(metadata)
      };
    }

    function reportMetadata(metadata) {
      const copy = {};
      Object.keys(metadata || {}).forEach((key) => {
        if (key !== "search_text") {
          copy[key] = metadata[key];
        }
      });
      return copy;
    }

    function firstText(...values) {
      for (const value of values) {
        const text = String(value ?? "").trim();
        if (text) {
          return text;
        }
      }
      return "";
    }

    function firstDefined(...values) {
      for (const value of values) {
        if (value !== undefined && value !== null && String(value).length > 0) {
          return value;
        }
      }
      return null;
    }

    function compactParts(values) {
      return values.map((value) => String(value ?? "").trim()).filter(Boolean).join(" | ");
    }

    function compactJson(value) {
      try {
        return JSON.stringify(value);
      } catch (_) {
        return "";
      }
    }

    function setInspectorState(stateName) {
      const pane = $("browserViewer");
      if (!pane) {
        return;
      }
      pane.classList.toggle("viewer-idle", stateName === "idle");
      pane.classList.toggle("viewer-detail", stateName === "detail");
      pane.classList.toggle("viewer-active", stateName === "active");
    }

    function currentHexEntry() {
      // Live-browse files have no indexed entry row; synthesize one so the
      // viewer renders instead of falling back to "No item selected".
      if (state.hex.live) {
        return {
          id: null,
          entry_kind: "file",
          evidence_id: state.hex.live.evidenceId,
          name: state.hex.live.name,
          logical_path: "[vol " + state.hex.live.volume + "] " + state.hex.live.path,
          metadata_json: { source: "live_browse", volume: state.hex.live.volume, image_path: state.hex.live.path }
        };
      }
      return state.data && state.hex.entryId ? findLoadedEntry(state.hex.entryId) : null;
    }

    function isReadableFileEntry(entry) {
      return !!entry && entry.entry_kind === "file";
    }

    function setViewerFullscreen(enabled) {
      state.viewerFullscreen = Boolean(enabled);
      document.body.classList.toggle("viewer-fullscreen", state.viewerFullscreen);
      const button = $("toggleViewerFullscreen");
      if (button) {
        button.textContent = state.viewerFullscreen ? "Exit full screen" : "Full screen";
        button.className = state.viewerFullscreen ? "secondary" : "ghost";
        button.setAttribute("aria-pressed", String(state.viewerFullscreen));
      }
      if (state.viewerFullscreen) {
        const entry = currentHexEntry();
        if (!isReadableFileEntry(entry)) {
          return;
        }
        if ($("viewerMode").value === "metadata") {
          $("viewerMode").value = "hex";
        }
        if (!state.hex.data && state.hex.entryId && !state.hex.fetching) {
          fetchEntryBytes();
        } else {
          renderHexViewer();
        }
      }
    }

    function toggleViewerFullscreen() {
      setViewerFullscreen(!state.viewerFullscreen);
    }

    function updateEntryRowHighlight() {
      const selectedId = state.hex && state.hex.entryId ? String(state.hex.entryId) : "";
      document.querySelectorAll("#entryTable .entry-row[data-entry-id]").forEach((row) => {
        row.classList.toggle("selected", row.dataset.entryId === selectedId);
      });
    }

    function clearHexSelection() {
      if (!state.hex) {
        return;
      }
      state.hex.selStart = null;
      state.hex.selEnd = null;
    }

    function isHexOffset(value) {
      return typeof value === "number" && Number.isFinite(value);
    }

    function normalizedHexSelection() {
      if (!state.hex || !isHexOffset(state.hex.selStart) || !isHexOffset(state.hex.selEnd)) {
        return null;
      }
      return {
        start: Math.min(state.hex.selStart, state.hex.selEnd),
        end: Math.max(state.hex.selStart, state.hex.selEnd)
      };
    }

    function selectedHexRangeForData(data) {
      const selection = normalizedHexSelection();
      const bytes = data && data.bytes ? data.bytes : [];
      if (!selection || bytes.length === 0) {
        return null;
      }
      const windowStart = Number(data.offset) || 0;
      const windowEnd = windowStart + bytes.length - 1;
      const start = Math.max(selection.start, windowStart);
      const end = Math.min(selection.end, windowEnd);
      return end >= start ? { start, end } : null;
    }

    function hexBytesForRange(data, range) {
      if (!data || !range || !data.bytes) {
        return [];
      }
      const baseOffset = Number(data.offset) || 0;
      const startIndex = Math.max(0, range.start - baseOffset);
      const endIndex = Math.min(data.bytes.length, range.end - baseOffset + 1);
      return Array.from(data.bytes).slice(startIndex, endIndex);
    }

    function currentHexDecode(data) {
      const bytes = data && data.bytes ? Array.from(data.bytes) : [];
      const selectedRange = selectedHexRangeForData(data);
      if (selectedRange) {
        return {
          selected: true,
          start: selectedRange.start,
          count: selectedRange.end - selectedRange.start + 1,
          bytes: hexBytesForRange(data, selectedRange)
        };
      }
      return {
        selected: false,
        start: Number(data && data.offset) || 0,
        count: bytes.length,
        bytes
      };
    }

    function renderHexViewer(error) {
      const data = state.hex.data;
      const entry = currentHexEntry();
      const mode = $("viewerMode").value;
      updateEntryRowHighlight();
      if (error) {
        setInspectorState("detail");
        $("hexStatus").textContent = error;
        $("hexView").innerHTML = "";
        $("hexView").className = "hex-view";
        return;
      }
      if (!entry) {
        setViewerFullscreen(false);
        setInspectorState("idle");
        $("hexStatus").textContent = "Select a file for bytes or a browser activity record for details.";
        $("hexView").className = "metadata-view";
        $("hexView").innerHTML = empty("No item selected.");
        return;
      }
      if (mode === "metadata") {
        setInspectorState("detail");
        $("hexStatus").textContent = entry.logical_path + " | metadata";
        $("hexView").className = "metadata-view";
        $("hexView").innerHTML = metadataView(entry);
        return;
      }
      if (!data) {
        setInspectorState("detail");
        $("hexStatus").textContent = state.hex.fetching
          ? entry.logical_path + " | reading bytes..."
          : entry.logical_path + " | choose View to read bytes.";
        $("hexView").className = "hex-view";
        $("hexView").innerHTML = "";
        return;
      }
      setInspectorState("active");
      $("hexStatus").textContent = `${entry ? entry.logical_path + " | " : ""}${formatBytes(data.total_size)} total | ${data.bytes_read} bytes read | offset ${data.offset}${data.eof ? " | EOF" : ""}`;
      if (mode === "text") {
        $("hexView").className = "text-view";
        $("hexView").textContent = decodeText(data.bytes);
      } else {
        $("hexView").className = "hex-view";
        $("hexView").style.setProperty("--bytes-per-row", String(numberValue("bytesPerRow", 16)));
        $("hexView").innerHTML = hexInspector(data);
      }
    }

    function hexInspector(data) {
      const decode = currentHexDecode(data);
      return [
        hexCurrentBar(decode),
        `<div class="hex-grid">${hexRows(data.bytes, data.offset)}</div>`,
        hexDecodePanel(decode)
      ].join("");
    }

    function hexCurrentBar(decode) {
      const byteLabel = decode.count === 1 ? "1 byte" : decode.count + " bytes";
      const disabled = decode.selected ? "" : " disabled";
      return `
        <div class="hex-current">
          <span class="hex-current-item"><strong>Current offset</strong>${escapeHtml(formatOffsetPair(decode.start))}</span>
          <span class="hex-current-item"><strong>Current selection</strong>${escapeHtml(byteLabel)}</span>
          <span class="hex-current-spacer"></span>
          <button id="copyHexSelection" class="ghost"${disabled}>COPY SELECTION</button>
          <button id="saveHexSelection" class="ghost"${disabled}>SAVE SELECTION</button>
        </div>
      `;
    }

    function hexRows(bytes, baseOffset) {
      if (!bytes || bytes.length === 0) {
        return `<div class="hex-row"><span class="hex-offset">${displayOffset(baseOffset)}</span><span></span><span class="hex-ascii">EOF</span></div>`;
      }
      const rows = [];
      const baseOffsetValue = Number(baseOffset) || 0;
      const bytesPerRow = numberValue("bytesPerRow", 16);
      const selection = selectedHexRangeForData({ bytes, offset: baseOffsetValue });
      for (let index = 0; index < bytes.length; index += bytesPerRow) {
        const chunk = bytes.slice(index, index + bytesPerRow);
        const hex = chunk.map((value, chunkIndex) => {
          const offset = baseOffsetValue + index + chunkIndex;
          return hexByteCell(value, offset, selection);
        }).join("");
        const ascii = chunk.map((value, chunkIndex) => {
          const offset = baseOffsetValue + index + chunkIndex;
          return hexAsciiCell(value, offset, selection);
        }).join("");
        rows.push(`<div class="hex-row"><span class="hex-offset">${displayOffset(baseOffsetValue + index)}</span><span class="hex-bytes">${hex}</span><span class="hex-ascii">${ascii}</span></div>`);
      }
      return rows.join("");
    }

    function hexByteCell(value, offset, selection) {
      const selected = selection && offset >= selection.start && offset <= selection.end;
      const className = selected ? "hex-cell hex-byte selected" : "hex-cell hex-byte";
      return `<span class="${className}" data-byte-offset="${offset}">${byteHex(value)}</span>`;
    }

    function hexAsciiCell(value, offset, selection) {
      const selected = selection && offset >= selection.start && offset <= selection.end;
      const className = selected ? "hex-cell hex-char selected" : "hex-cell hex-char";
      const text = value >= 32 && value <= 126 ? String.fromCharCode(value) : ".";
      return `<span class="${className}" data-byte-offset="${offset}">${escapeHtml(text)}</span>`;
    }

    function hexDecodePanel(decode) {
      const bytes = decode.bytes;
      const stringRows = [
        ["ASCII", decodeAscii(bytes)],
        ["Binary (Base 64)", encodeBase64(bytes)],
        ["UTF-7 (ASCII fallback)", decodeAscii(bytes)],
        ["UTF-8", decodeWithTextDecoder("utf-8", bytes)],
        ["UTF-16 LE (Unicode)", decodeWithTextDecoder("utf-16le", bytes)],
        ["UTF-32 LE", decodeUtf32Le(bytes)]
      ];
      const dateRows = [
        ["Chrome", decodeChromeTime(bytes)],
        ["FireFox", decodeFirefoxTime(bytes)],
        ["HFS+ 32-bit BE", decodeHfsTime(bytes)],
        ["Windows FILETIME", decodeFiletime(bytes)],
        ["Unix 32-bit LE", decodeUnixTime(bytes)]
      ];
      return `
        <section class="hex-decode">
          <div class="hex-decode-head"><span>DECODE</span></div>
          <div class="hex-decode-grid">
            <section class="hex-decode-group">
              <h3>STRING</h3>
              <dl class="hex-decode-table">${decodeRows(stringRows)}</dl>
            </section>
            <section class="hex-decode-group">
              <h3>DATE / TIME</h3>
              <dl class="hex-decode-table">${decodeRows(dateRows)}</dl>
            </section>
          </div>
        </section>
      `;
    }

    function decodeRows(rows) {
      return rows.map((row) => `<dt>${escapeHtml(row[0])}</dt><dd>${decodeValue(row[1])}</dd>`).join("");
    }

    function decodeValue(value) {
      if (value == null || value === "") {
        return "&mdash;";
      }
      return escapeHtml(visibleDecodedText(value));
    }

    function visibleDecodedText(value) {
      return String(value).replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, ".");
    }

    function decodeAscii(bytes) {
      return bytes.map((value) => value >= 32 && value <= 126 ? String.fromCharCode(value) : ".").join("");
    }

    function encodeBase64(bytes) {
      if (!bytes || bytes.length === 0) {
        return "";
      }
      let binary = "";
      const chunkSize = 0x8000;
      for (let index = 0; index < bytes.length; index += chunkSize) {
        binary += String.fromCharCode(...bytes.slice(index, index + chunkSize));
      }
      return btoa(binary);
    }

    function decodeWithTextDecoder(label, bytes) {
      if (!bytes || bytes.length === 0) {
        return "";
      }
      try {
        return new TextDecoder(label, { fatal: false }).decode(Uint8Array.from(bytes));
      } catch (_) {
        return decodeAscii(bytes);
      }
    }

    function decodeUtf32Le(bytes) {
      if (!bytes || bytes.length === 0) {
        return "";
      }
      const chars = [];
      for (let index = 0; index + 3 < bytes.length; index += 4) {
        const point =
          (bytes[index] & 255) +
          ((bytes[index + 1] & 255) * 0x100) +
          ((bytes[index + 2] & 255) * 0x10000) +
          ((bytes[index + 3] & 255) * 0x1000000);
        if (point <= 0x10FFFF && (point < 0xD800 || point > 0xDFFF)) {
          chars.push(String.fromCodePoint(point));
        } else {
          chars.push(String.fromCharCode(0xFFFD));
        }
      }
      if (bytes.length % 4 !== 0) {
        chars.push(String.fromCharCode(0xFFFD));
      }
      return chars.join("");
    }

    function decodeChromeTime(bytes) {
      if (!bytes || bytes.length !== 8) {
        return null;
      }
      const micros = readUint64Le(bytes);
      const millis = Number(micros / 1000n) - 11644473600000;
      return saneIsoDate(millis);
    }

    function decodeFirefoxTime(bytes) {
      if (!bytes || bytes.length !== 8) {
        return null;
      }
      const micros = readUint64Le(bytes);
      const millis = Number(micros / 1000n);
      return saneIsoDate(millis);
    }

    function decodeHfsTime(bytes) {
      if (!bytes || bytes.length !== 4) {
        return null;
      }
      const seconds =
        ((bytes[0] & 255) * 0x1000000) +
        ((bytes[1] & 255) * 0x10000) +
        ((bytes[2] & 255) * 0x100) +
        (bytes[3] & 255);
      return saneIsoDate(Date.UTC(1904, 0, 1) + (seconds * 1000));
    }

    function readUint64Le(bytes) {
      let value = 0n;
      for (let index = 7; index >= 0; index -= 1) {
        value = (value << 8n) + BigInt(bytes[index] & 255);
      }
      return value;
    }

    function saneIsoDate(millis) {
      if (!Number.isFinite(millis)) {
        return null;
      }
      const date = new Date(millis);
      if (!Number.isFinite(date.getTime())) {
        return null;
      }
      const year = date.getUTCFullYear();
      if (year < 1601 || year > 2200) {
        return null;
      }
      return date.toISOString();
    }

    function byteHex(value) {
      return (Number(value) & 255).toString(16).padStart(2, "0").toUpperCase();
    }

    function formatOffsetPair(value) {
      const offset = Number(value) || 0;
      return `${offset} (0x${offset.toString(16).toUpperCase().padStart(8, "0")})`;
    }

    function bindHexSelection() {
      const view = $("hexView");
      if (!view) {
        return;
      }
      view.addEventListener("pointerdown", startHexSelection);
      view.addEventListener("pointermove", moveHexSelection);
      view.addEventListener("pointerup", endHexSelection);
      view.addEventListener("pointercancel", endHexSelection);
      view.addEventListener("click", (event) => {
        if (!event.target || !event.target.closest) {
          return;
        }
        if (event.target.closest("#copyHexSelection")) {
          copyHexSelection();
        } else if (event.target.closest("#saveHexSelection")) {
          saveHexSelection();
        }
      });
    }

    function startHexSelection(event) {
      if (event.button !== 0) {
        return;
      }
      const offset = hexOffsetFromTarget(event.target);
      if (offset == null) {
        return;
      }
      const selection = normalizedHexSelection();
      const anchor = event.shiftKey && selection ? selection.start : offset;
      event.preventDefault();
      hexSelecting = true;
      hexSelectionAnchor = anchor;
      hexPointerId = event.pointerId;
      const view = $("hexView");
      if (view && view.setPointerCapture) {
        try {
          view.setPointerCapture(event.pointerId);
        } catch (_) {}
      }
      setHexSelection(anchor, offset);
    }

    function moveHexSelection(event) {
      if (!hexSelecting || event.pointerId !== hexPointerId) {
        return;
      }
      const offset = hexOffsetFromPoint(event.clientX, event.clientY);
      if (offset == null) {
        return;
      }
      event.preventDefault();
      setHexSelection(hexSelectionAnchor, offset);
    }

    function endHexSelection(event) {
      if (!hexSelecting || event.pointerId !== hexPointerId) {
        return;
      }
      const offset = hexOffsetFromPoint(event.clientX, event.clientY);
      if (offset != null) {
        setHexSelection(hexSelectionAnchor, offset);
      }
      hexSelecting = false;
      hexSelectionAnchor = null;
      const view = $("hexView");
      if (view && view.releasePointerCapture) {
        try {
          view.releasePointerCapture(event.pointerId);
        } catch (_) {}
      }
      hexPointerId = null;
    }

    function hexOffsetFromPoint(clientX, clientY) {
      const target = document.elementFromPoint(clientX, clientY);
      return hexOffsetFromTarget(target);
    }

    function hexOffsetFromTarget(target) {
      if (!target || !target.closest) {
        return null;
      }
      const cell = target.closest("[data-byte-offset]");
      if (!cell || !$("hexView").contains(cell)) {
        return null;
      }
      const offset = Number(cell.dataset.byteOffset);
      return Number.isFinite(offset) ? offset : null;
    }

    function setHexSelection(anchor, focus) {
      if (!state.hex || !state.hex.data || !Number.isFinite(anchor) || !Number.isFinite(focus)) {
        return;
      }
      const start = Math.min(Math.floor(anchor), Math.floor(focus));
      const end = Math.max(Math.floor(anchor), Math.floor(focus));
      if (state.hex.selStart === start && state.hex.selEnd === end) {
        return;
      }
      state.hex.selStart = start;
      state.hex.selEnd = end;
      renderHexViewer();
    }

    async function copyHexSelection() {
      const range = selectedHexRangeForData(state.hex.data);
      if (!range) {
        setNotice("Select bytes before copying.", true);
        return;
      }
      if (!navigator.clipboard || !navigator.clipboard.writeText) {
        setNotice("Clipboard copy is not available in this browser.", true);
        return;
      }
      const bytes = hexBytesForRange(state.hex.data, range);
      const text = bytes.map(byteHex).join(" ");
      try {
        await navigator.clipboard.writeText(text);
        setNotice("Copied " + bytes.length + " selected bytes.");
      } catch (err) {
        setNotice("Clipboard copy failed: " + err.message, true);
      }
    }

    // Axy "SAVE SELECTION": download the selected bytes as a .bin file.
    function saveHexSelection() {
      const range = selectedHexRangeForData(state.hex.data);
      if (!range) {
        setNotice("Select bytes before saving.", true);
        return;
      }
      const bytes = hexBytesForRange(state.hex.data, range);
      const entry = currentHexEntry();
      const baseName = entry ? (entry.name || logicalName(entry.logical_path)) : "entry-" + state.hex.entryId;
      const safeName = String(baseName).replace(/[^A-Za-z0-9._-]+/g, "_");
      const fileName = safeName + "-0x" + range.start.toString(16).toUpperCase() + "-" + bytes.length + "b.bin";
      const blob = new Blob([new Uint8Array(bytes)], { type: "application/octet-stream" });
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = fileName;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(link.href);
      setNotice("Saved " + bytes.length + " selected bytes to " + fileName + ".");
    }

    function decodeUnixTime(bytes) {
      if (!bytes || bytes.length < 4) {
        return "";
      }
      const seconds = ((bytes[0]) | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24)) >>> 0;
      if (seconds === 0) {
        return "";
      }
      const date = new Date(seconds * 1000);
      const year = date.getUTCFullYear();
      return Number.isFinite(date.getTime()) && year >= 1980 && year <= 2100 ? date.toISOString() : "";
    }

    function decodeFiletime(bytes) {
      if (!bytes || bytes.length < 8) {
        return "";
      }
      let value = 0n;
      for (let index = 7; index >= 0; index--) {
        value = (value << 8n) | BigInt(bytes[index] & 0xFF);
      }
      if (value === 0n) {
        return "";
      }
      const unixMs = Number((value - 116444736000000000n) / 10000n);
      const date = new Date(unixMs);
      const year = date.getUTCFullYear();
      return Number.isFinite(date.getTime()) && year >= 1700 && year <= 2200 ? date.toISOString() : "";
    }

    function displayOffset(value) {
      const offset = Number(value) || 0;
      if ($("offsetBase").value === "decimal") {
        return String(offset);
      }
      return "0x" + offset.toString(16).toUpperCase().padStart(8, "0");
    }

    function offsetValue() {
      const raw = String($("hexOffset").value || "0").trim();
      const value = raw.toLowerCase().startsWith("0x") ? Number.parseInt(raw, 16) : Number(raw);
      return Number.isFinite(value) && value >= 0 ? Math.floor(value) : 0;
    }

    function decodeText(bytes) {
      if (!bytes || bytes.length === 0) {
        return "";
      }
      try {
        return new TextDecoder("utf-8", { fatal: false }).decode(Uint8Array.from(bytes));
      } catch (_) {
        return bytes.map((value) => value >= 32 && value <= 126 ? String.fromCharCode(value) : ".").join("");
      }
    }

    function metadataView(entry) {
      const metadata = JSON.stringify(entry.metadata_json || {}, null, 2);
      const raw = entry.metadata_json || {};
      const evidence = evidenceSourceForEntry(entry);
      return [
        inspectorSummary(entry),
        previewSection(entry),
        detailSection("Overview", [
          ["ID", entry.id],
          ["Evidence", evidence ? evidence.display_name + " (#" + evidence.id + ")" : entry.evidence_id],
          ["Path", entry.logical_path],
          ["Relative Path", relativePathForEntry(entry)],
          ["Name", entry.name],
          ["Kind", entry.entry_kind],
          ["Size", entry.size_bytes == null ? "" : formatBytes(entry.size_bytes)],
          ["Deleted", entry.is_deleted ? "yes" : "no"],
          ["Category", entryCategoryLabel(entry)],
          ["Category Detail", entryCategoryDetail(entry)]
        ]),
        detailSection("Forensic Location", [
          ["Storage Area", raw.storage_area],
          ["Recovery Source", raw.recovery_source],
          ["Recovery Status", raw.recovery_status],
          ["Logical Offset", formatOffsetValue(raw.logical_offset || raw.finding_logical_offset || raw.start_offset)],
          ["Physical Offset", formatOffsetValue(raw.physical_offset)],
          ["MFT Record Logical Offset", formatOffsetValue(raw.mft_record_logical_offset)],
          ["MFT Record Physical Offset", formatOffsetValue(raw.mft_record_physical_offset)],
          ["File Data Logical Offset", formatOffsetValue(raw.file_data_logical_offset)],
          ["File Data Physical Offset", formatOffsetValue(raw.file_data_physical_offset)],
          ["Partition Start", formatOffsetValue(raw.partition_start_offset || raw.start_offset)],
          ["Partition Size", formatByteCountValue(raw.partition_size_bytes || raw.size_bytes)],
          ["In File Slack", raw.is_file_slack ? "yes" : ""],
          ["In Unallocated Space", raw.is_unallocated ? "yes" : ""]
        ]),
        detailSection("Category", [
          ["Main", raw.category_main],
          ["Subcategory", raw.category_sub],
          ["Detail", raw.category_detail],
          ["Analysis", raw.analysis_category],
          ["Confidence", raw.category_confidence],
          ["Rule Source", raw.category_source],
          ["Tags", Array.isArray(raw.category_tags) ? raw.category_tags.join(", ") : raw.category_tags]
        ]),
        recordDetails(entry),
        detailSection("MAC Times", [
          ["NTFS Created", raw.ntfs_creation_time_utc || raw.ntfs_standard_creation_time_utc],
          ["NTFS Modified", raw.ntfs_modification_time_utc || raw.ntfs_standard_modification_time_utc],
          ["NTFS Accessed", raw.ntfs_access_time_utc || raw.ntfs_standard_access_time_utc],
          ["NTFS MFT Modified", raw.ntfs_mft_record_modification_time_utc || raw.ntfs_standard_mft_record_modification_time_utc],
          ["FAT Created", raw.fat_created],
          ["FAT Modified", raw.fat_modified],
          ["FAT Accessed", raw.fat_accessed],
          ["Source Created", raw.source_file_created_utc],
          ["Source Modified", raw.source_file_modified_utc],
          ["Source Accessed", raw.source_file_accessed_utc]
        ]),
        detailSection("Parser And Source", [
          ["Artifact Kind", raw.artifact_kind],
          ["Filesystem Parser", raw.filesystem_parser],
          ["Filesystem", raw.filesystem],
          ["Partition Start", formatOffsetValue(raw.partition_start_offset || raw.start_offset)],
          ["Partition Size", formatByteCountValue(raw.partition_size_bytes || raw.size_bytes)],
          ["MFT Record", raw.mft_file_record_number || raw.ntfs_file_record_number],
          ["MFT Sequence", raw.mft_sequence_number],
          ["NTFS Path", raw.ntfs_path],
          ["FAT Path", raw.fat_path],
          ["Source Artifact", raw.source_artifact],
          ["Source Path", raw.source_artifact_path || raw.source_path],
          ["Source Modified", raw.source_file_modified_utc]
        ]),
        `<section class="metadata-section"><details><summary>Metadata JSON</summary><pre>${escapeHtml(metadata)}</pre></details></section>`
      ].filter(Boolean).join("");
    }

    function previewSection(entry) {
      const metadata = entry.metadata_json || {};
      if (metadata.artifact_kind === "email_message") {
        return emailPreviewSection(entry, metadata);
      }
      if (metadata.artifact_kind === "browser_history_visit" || metadata.artifact_kind === "browser_bookmark" || metadata.artifact_kind === "browser_preference") {
        return browserPreviewSection(entry, metadata);
      }
      if (entry.entry_kind === "record") {
        return genericRecordPreviewSection(entry, metadata);
      }
      if (isImageEntry(entry)) {
        return imagePreviewSection(entry);
      }
      return "";
    }

    function imagePreviewSection(entry) {
      return `<section class="metadata-section"><h3>Preview</h3><div class="preview-card image-preview">
        <img loading="lazy" src="${entryRawUrl(entry)}" alt="" onerror="this.parentElement.classList.add('thumb-broken'); this.remove();">
      </div></section>`;
    }

    function emailPreviewSection(entry, metadata) {
      const title = firstText(metadata.email_subject, entry.name, logicalName(entry.logical_path));
      const metaRows = [
        metadata.email_from ? "From: " + metadata.email_from : "",
        metadata.email_to ? "To: " + metadata.email_to : "",
        metadata.email_date ? "Date: " + metadata.email_date : "",
        metadata.email_message_id ? "Message ID: " + metadata.email_message_id : ""
      ].filter(Boolean).map((value) => `<span>${escapeHtml(value)}</span>`).join("");
      const body = firstText(metadata.email_body_preview, metadata.email_parser_error, "No message body preview.");
      return `<section class="metadata-section"><h3>Preview</h3><div class="preview-card">
        <h4 class="preview-title">${escapeHtml(title)}</h4>
        <div class="preview-meta">${metaRows || `<span>${escapeHtml(emailPreview(entry) || "Parsed email message")}</span>`}</div>
        <div class="preview-body">${escapeHtml(body)}</div>
      </div></section>`;
    }

    function browserPreviewSection(entry, metadata) {
      const title = firstText(metadata.title, metadata.name, metadata.category, entry.name, logicalName(entry.logical_path));
      const url = firstText(metadata.url, metadata.homepage);
      const metaRows = [
        metadata.visit_time_utc ? "Visited: " + metadata.visit_time_utc : "",
        metadata.date_added_utc ? "Added: " + metadata.date_added_utc : "",
        metadata.folder ? "Folder: " + metadata.folder : "",
        metadata.source_artifact_path ? "Source: " + metadata.source_artifact_path : ""
      ].filter(Boolean).map((value) => `<span>${escapeHtml(value)}</span>`).join("");
      const body = firstText(browserActivityPreview(entry), compactJson(metadata));
      return `<section class="metadata-section"><h3>Preview</h3><div class="preview-card">
        <h4 class="preview-title">${escapeHtml(title)}</h4>
        ${url ? `<div class="preview-url">${escapeHtml(url)}</div>` : ""}
        <div class="preview-meta">${metaRows}</div>
        <div class="preview-body">${escapeHtml(body)}</div>
      </div></section>`;
    }

    function genericRecordPreviewSection(entry, metadata) {
      const body = firstText(entrySummary(entry), compactJson(metadata));
      return `<section class="metadata-section"><h3>Preview</h3><div class="preview-card">
        <h4 class="preview-title">${escapeHtml(entry.name || logicalName(entry.logical_path))}</h4>
        <div class="preview-meta"><span>${escapeHtml(entry.logical_path)}</span></div>
        <div class="preview-body">${escapeHtml(body)}</div>
      </div></section>`;
    }

    function inspectorSummary(entry) {
      const raw = entry.metadata_json || {};
      const evidence = evidenceSourceForEntry(entry);
      const canAnalyze = entry.entry_kind === "file" && isPromotableDiskImageEntry(entry, evidence);
      const canViewBytes = entry.entry_kind === "file" && !canAnalyze;
      const badges = [
        inspectorBadge(entry.entry_kind),
        entry.size_bytes == null ? "" : inspectorBadge(formatBytes(entry.size_bytes)),
        entry.is_deleted ? inspectorBadge("deleted", "bad") : "",
        raw.is_file_slack ? inspectorBadge("file slack", "warn") : "",
        raw.is_unallocated ? inspectorBadge("unallocated", "warn") : "",
        raw.filesystem_parser ? inspectorBadge("parser: " + raw.filesystem_parser) : "",
        raw.category_confidence ? inspectorBadge("confidence: " + raw.category_confidence) : ""
      ].filter(Boolean).join("");
      const actions = [
        canViewBytes ? `<button class="secondary" onclick="openEntry(${entry.id})">View bytes</button>` : "",
        canAnalyze ? `<button class="secondary" onclick="analyzeDiskImageEntry(${entry.id})">Analyze image</button>` : "",
        entry.entry_kind === "file" ? `<button class="ghost" onclick="recoverEntry(${entry.id})">${escapeHtml(recoveryActionText(entry).button)}</button>` : "",
        `<button class="ghost" onclick="bookmarkEntry(${entry.id})">Bookmark</button>`
      ].filter(Boolean).join("");
      return `
        <section class="inspector-summary">
          <h2 class="inspector-title">${escapeHtml(entry.name || logicalName(entry.logical_path))}</h2>
          <div class="inspector-path">${escapeHtml(entry.logical_path)}</div>
          <div class="inspector-badges">${badges}</div>
          <div class="inspector-actions">${actions}</div>
        </section>`;
    }

    function inspectorBadge(text, tone = "") {
      return `<span class="pill ${tone ? escapeAttr(tone) : ""}">${escapeHtml(text)}</span>`;
    }

    function relativePathForEntry(entry) {
      const raw = entry.metadata_json || {};
      return firstText(raw.relative_path, raw.ntfs_path, raw.fat_path, entry.logical_path);
    }

    function formatOffsetValue(value) {
      if (value === undefined || value === null || String(value).length === 0) {
        return "";
      }
      const text = String(value);
      const number = typeof value === "number" ? value : (/^\d+$/.test(text) ? Number(text) : NaN);
      if (!Number.isFinite(number)) {
        return text;
      }
      return text + " (0x" + Math.trunc(number).toString(16).toUpperCase() + ")";
    }

    function formatByteCountValue(value) {
      if (value === undefined || value === null || String(value).length === 0) {
        return "";
      }
      const text = String(value);
      const number = typeof value === "number" ? value : (/^\d+$/.test(text) ? Number(text) : NaN);
      if (!Number.isFinite(number)) {
        return text;
      }
      return formatBytes(number) + " (" + text + " bytes)";
    }

    function recordDetails(entry) {
      const metadata = entry.metadata_json || {};
      if (metadata.artifact_kind === "email_message") {
        return detailSection("Email", [
          ["Format", metadata.email_format],
          ["Parser", metadata.email_parser || metadata.email_parser_status],
          ["From", metadata.email_from],
          ["To", metadata.email_to],
          ["Cc", metadata.email_cc],
          ["Bcc", metadata.email_bcc],
          ["Subject", metadata.email_subject],
          ["Date", metadata.email_date],
          ["Message ID", metadata.email_message_id],
          ["Reply-To", metadata.email_reply_to],
          ["In Reply To", metadata.email_in_reply_to],
          ["Body Preview", metadata.email_body_preview],
          ["Parser Error", metadata.email_parser_error]
        ]);
      }
      if (metadata.artifact_kind === "email_store") {
        return detailSection("Email Store", [
          ["Format", metadata.email_format],
          ["Parser Status", metadata.email_parser_status],
          ["Path", entry.logical_path],
          ["Size", entry.size_bytes == null ? "" : formatBytes(entry.size_bytes)]
        ]);
      }
      if (metadata.artifact_kind === "browser_history_visit") {
        return detailSection("Browser Activity", [
          ["Activity", "Visit"],
          ["URL", metadata.url],
          ["Title", metadata.title],
          ["Host", metadata.host],
          ["Visit Time", metadata.visit_time_utc],
          ["Last URL Visit", metadata.last_visit_time_utc],
          ["Transition", metadata.transition_type],
          ["Visit Count", metadata.visit_count],
          ["Typed Count", metadata.typed_count],
          ["Duration", metadata.visit_duration_microseconds ? metadata.visit_duration_microseconds + " microseconds" : ""],
          ["Visit ID", metadata.visit_id],
          ["URL ID", metadata.url_id],
          ["Chrome Visit Time", metadata.visit_time_chrome],
          ["Chrome Last URL Visit", metadata.last_visit_time_chrome],
          ["Transition Code", metadata.transition],
          ["Hidden", metadata.hidden],
          ["Source Artifact", metadata.source_artifact],
          ["Source Path", metadata.source_artifact_path],
          ["Source Created", metadata.source_file_created_utc],
          ["Source Modified", metadata.source_file_modified_utc],
          ["Source Accessed", metadata.source_file_accessed_utc],
          ["Source Size", metadata.source_file_size_bytes == null ? "" : formatBytes(metadata.source_file_size_bytes)]
        ]);
      }
      if (metadata.artifact_kind === "browser_bookmark") {
        return detailSection("Browser Activity", [
          ["Activity", "Bookmark"],
          ["URL", metadata.url],
          ["Name", metadata.name],
          ["Host", metadata.host],
          ["Folder", metadata.folder],
          ["Added", metadata.date_added_utc],
          ["Last Used", metadata.date_last_used_utc],
          ["Chrome Added", metadata.date_added_chrome],
          ["Chrome Last Used", metadata.date_last_used_chrome],
          ["GUID", metadata.guid],
          ["Source Artifact", metadata.source_artifact],
          ["Source Path", metadata.source_artifact_path],
          ["Source Created", metadata.source_file_created_utc],
          ["Source Modified", metadata.source_file_modified_utc],
          ["Source Accessed", metadata.source_file_accessed_utc],
          ["Source Size", metadata.source_file_size_bytes == null ? "" : formatBytes(metadata.source_file_size_bytes)]
        ]);
      }
      if (metadata.artifact_kind === "browser_preference") {
        return detailSection("Browser Activity", [
          ["Activity", "Preference"],
          ["Category", metadata.category],
          ["Profile Name", metadata.name],
          ["Startup URLs", Array.isArray(metadata.startup_urls) ? metadata.startup_urls.join(", ") : ""],
          ["Homepage", metadata.homepage],
          ["Download Directory", metadata.download_default_directory],
          ["Extensions", metadata.extension_count],
          ["Created By Version", metadata.created_by_version],
          ["Last Used", metadata.last_used],
          ["Restore On Startup", metadata.restore_on_startup],
          ["Homepage Is New Tab", metadata.homepage_is_newtabpage],
          ["Prompt For Download", metadata.prompt_for_download],
          ["Source Artifact", metadata.source_artifact],
          ["Source Path", metadata.source_artifact_path],
          ["Source Created", metadata.source_file_created_utc],
          ["Source Modified", metadata.source_file_modified_utc],
          ["Source Accessed", metadata.source_file_accessed_utc],
          ["Source Size", metadata.source_file_size_bytes == null ? "" : formatBytes(metadata.source_file_size_bytes)]
        ]);
      }
      return "";
    }

    function detailSection(title, rows) {
      const body = detailRows(rows);
      return body ? `<section class="metadata-section"><h3>${escapeHtml(title)}</h3><dl class="metadata-grid">${body}</dl></section>` : "";
    }

    function detailRows(rows) {
      return rows
        .filter((row) => row[1] !== undefined && row[1] !== null && String(row[1]).length > 0)
        .map((row) => `<dt>${escapeHtml(row[0])}</dt><dd>${escapeHtml(row[1])}</dd>`)
        .join("");
    }

    function renderSearchEvidence() {
      const current = $("searchEvidence").value;
      $("searchEvidence").innerHTML = '<option value="">All evidence</option>' + state.data.evidence.map((item) =>
        `<option value="${item.id}">${escapeHtml(item.id + " - " + item.display_name)}</option>`
      ).join("");
      $("searchEvidence").value = current;
    }

    function renderSearchResults() {
      $("searchCount").textContent = state.searchResults.length;
      const rows = state.searchResults.map((hit, index) => {
        const checked = state.selectedSearchIndexes.has(index) ? " checked" : "";
        const entry = state.data && state.data.entries.find((item) => item.id === hit.entry_id);
        const deleted = entry && entry.is_deleted ? ' <span class="pill bad">deleted</span>' : "";
        const offset = entry ? entryPrimaryOffset(entry) : "";
        return `
        <tr class="entry-row" onclick="goToSearchResult(${index})">
          <td><input type="checkbox"${checked} onclick="event.stopPropagation(); toggleSearchResultSelection(${index}, this.checked)"></td>
          <td><strong>${escapeHtml(hit.display_name)}</strong><br><span class="muted tiny">${escapeHtml(hit.logical_path)}</span></td>
          <td><span class="pill ${hit.match_kind === "content" ? "good" : ""}">${escapeHtml(hit.match_kind)}</span>${deleted}</td>
          <td class="entry-offset" title="${escapeAttr(offset)}">${escapeHtml(offset)}</td>
          <td>${escapeHtml(hit.data_preview || "")}</td>
          <td class="actions"><div class="toolbar">
            <button class="secondary" onclick="event.stopPropagation(); goToSearchResult(${index})">Source</button>
            <button class="ghost" onclick="event.stopPropagation(); bookmarkSearchResult(${index})">Bookmark</button>
          </div></td>
        </tr>`;
      }).join("");
      $("searchResults").innerHTML = rows ? table(["", "Entry", "Match", "Offset", "Preview", ""], rows) : empty("No results.");
      renderSearchSelectionCount();
    }

    function renderSearchSelectionCount() {
      $("searchSelectedCount").textContent = (state.selectedSearchIndexes ? state.selectedSearchIndexes.size : 0) + " selected";
    }

    function renderBookmarks() {
      const folderNames = new Map(state.data.folders.map((folder) => [folder.id, folder.name]));
      const rows = state.data.bookmarks.map((bookmark) => {
        const items = state.data.items.filter((item) => item.bookmark_id === bookmark.id);
        return `
          <tr>
            <td><strong>${escapeHtml(bookmark.title || bookmark.bookmark_type)}</strong><br><span class="muted tiny">${escapeHtml(folderNames.get(bookmark.folder_id) || "")}</span></td>
            <td><span class="pill">${escapeHtml(bookmark.bookmark_type)}</span></td>
            <td>${items.length}</td>
            <td>${escapeHtml(bookmark.examiner_comment || "")}</td>
          </tr>`;
      }).join("");
      $("bookmarksTable").innerHTML = rows ? table(["Bookmark", "Type", "Items", "Comment"], rows) : empty("No bookmarks.");
    }

    function renderReport() {
      $("reportCount").textContent = state.data.report.folders.length + " folders";
      $("reportPreview").textContent = JSON.stringify(state.data.report, null, 2);
    }

    function table(headers, rows, className = "") {
      const classAttr = className ? ` class="${escapeAttr(className)}"` : "";
      return `<table${classAttr}><thead><tr>${headers.map((header) => `<th>${escapeHtml(header)}</th>`).join("")}</tr></thead><tbody>${rows}</tbody></table>`;
    }

    function empty(text) {
      return `<div class="empty">${escapeHtml(text)}</div>`;
    }

    function numberValue(id, fallback) {
      const value = Number($(id).value);
      return Number.isFinite(value) && value > 0 ? value : fallback;
    }

    function escapeHtml(value) {
      return String(value ?? "").replace(/[&<>"']/g, (ch) => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;"
      }[ch]));
    }

    function escapeAttr(value) {
      return escapeHtml(value).replace(/`/g, "&#96;");
    }

    function escapeJs(value) {
      return String(value ?? "")
        .replace(/\\/g, "\\\\")
        .replace(/'/g, "\\'")
        .replace(/\r/g, "\\r")
        .replace(/\n/g, "\\n");
    }

    function formatBytes(value) {
      const units = ["B", "KB", "MB", "GB", "TB"];
      let size = Number(value) || 0;
      let unit = 0;
      while (size >= 1024 && unit < units.length - 1) {
        size = size / 1024;
        unit += 1;
      }
      return (unit === 0 ? String(size) : size.toFixed(1)) + " " + units[unit];
    }

    function bindTabs() {
      document.querySelectorAll(".tab").forEach((button) => {
        button.addEventListener("click", () => {
          switchView(button.dataset.view);
        });
      });
    }

    function isFormInputTarget(target) {
      return Boolean(target && target.closest && target.closest("input, textarea, select"));
    }

    function shortcutDigit(event) {
      if (/^[1-6]$/.test(event.key)) {
        return event.key;
      }
      const match = String(event.code || "").match(/^(Digit|Numpad)([1-6])$/);
      return match ? match[2] : "";
    }

    function shortcutViewForDigit(digit) {
      return {
        "1": "dashboardView",
        "2": "evidenceView",
        "3": "analyzeView",
        "4": "searchView",
        "5": "bookmarksView",
        "6": "reportView"
      }[digit] || "";
    }

    function handleGlobalKeydown(event) {
      if (event.key === "Escape" && state.viewerFullscreen) {
        setViewerFullscreen(false);
        return;
      }
      if (!event.altKey || event.ctrlKey || event.metaKey || isFormInputTarget(event.target)) {
        return;
      }
      const viewId = shortcutViewForDigit(shortcutDigit(event));
      if (!viewId) {
        return;
      }
      event.preventDefault();
      switchView(viewId);
    }

    function switchView(viewId) {
      document.querySelectorAll(".tab").forEach((tab) => {
        tab.classList.toggle("active", tab.dataset.view === viewId);
      });
      document.querySelectorAll(".view").forEach((view) => {
        view.classList.toggle("active", view.id === viewId);
      });
    }

    // Draggable column widths on every rendered table. Widths persist per
    // table kind (class + column count) so File System, Categories, Live
    // browse, Search, etc. each remember their own layout.
    function columnWidthKey(tableEl, columnCount) {
      const kind = (tableEl.className || "table").split(/\s+/)[0] || "table";
      return "kdft.colWidths." + kind + ":" + columnCount;
    }

    function loadColumnWidths(key) {
      try {
        return JSON.parse(localStorage.getItem(key)) || {};
      } catch (err) {
        return {};
      }
    }

    function makeTableColumnsResizable(tableEl) {
      if (!tableEl || tableEl.dataset.resizable === "1") {
        return;
      }
      tableEl.dataset.resizable = "1";
      const ths = Array.from(tableEl.querySelectorAll("thead th"));
      if (ths.length === 0) {
        return;
      }
      const storeKey = columnWidthKey(tableEl, ths.length);
      const saved = loadColumnWidths(storeKey);
      ths.forEach((th, index) => {
        if (saved[index]) {
          th.style.width = saved[index] + "px";
          tableEl.style.tableLayout = "fixed";
        }
        const grip = document.createElement("span");
        grip.className = "col-resizer";
        grip.title = "Drag to resize column";
        grip.addEventListener("pointerdown", (event) => {
          event.preventDefault();
          event.stopPropagation();
          grip.classList.add("dragging");
          const startX = event.clientX;
          const startWidth = th.getBoundingClientRect().width;
          // Fixed layout makes the header width authoritative for the column.
          tableEl.style.tableLayout = "fixed";
          const onMove = (moveEvent) => {
            th.style.width = Math.max(48, startWidth + moveEvent.clientX - startX) + "px";
          };
          const onUp = () => {
            document.removeEventListener("pointermove", onMove);
            document.removeEventListener("pointerup", onUp);
            grip.classList.remove("dragging");
            const widths = loadColumnWidths(storeKey);
            widths[index] = Math.round(th.getBoundingClientRect().width);
            localStorage.setItem(storeKey, JSON.stringify(widths));
          };
          document.addEventListener("pointermove", onMove);
          document.addEventListener("pointerup", onUp);
        });
        th.appendChild(grip);
      });
    }

    function enhanceRenderedTables() {
      document.querySelectorAll("table").forEach(makeTableColumnsResizable);
    }

    new MutationObserver(enhanceRenderedTables).observe(document.body, { childList: true, subtree: true });
    enhanceRenderedTables();

    // The live-browse context menu closes on any outside click, Escape, or scroll.
    document.addEventListener("click", hideContextMenu);
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        hideContextMenu();
      }
    });
    document.addEventListener("scroll", hideContextMenu, true);

    $("casePath").value = normalizePathInput(state.casePath);
    $("evidencePath").value = normalizePathInput(localStorage.getItem("kdft.evidencePath") || BOOTSTRAP.defaultEvidencePath);
    $("reportPath").value = normalizePathInput(BOOTSTRAP.defaultReportPath);
    $("refreshCase").addEventListener("click", refresh);
    $("toggleSidebar").addEventListener("click", () => {
      const collapsed = document.querySelector(".app").classList.toggle("sidebar-collapsed");
      localStorage.setItem("kdft.sidebarCollapsed", collapsed ? "1" : "0");
    });
    if (localStorage.getItem("kdft.sidebarCollapsed") === "1") {
      document.querySelector(".app").classList.add("sidebar-collapsed");
    }
    $("createCase").addEventListener("click", createCase);
    $("caseOpenSetup").addEventListener("click", caseOpenSetupView);
    $("caseOpenButton").addEventListener("click", openExistingCase);
    $("addEvidence").addEventListener("click", addEvidence);
    document.querySelectorAll("#evidenceTypeRow .evidence-type").forEach((button) => {
      button.addEventListener("click", () => setEvidenceType(button.dataset.type));
    });
    $("selectVisibleRows").addEventListener("click", selectVisibleEntries);
    $("selectedAction").addEventListener("change", handleSelectedAction);
    // "input" fires as soon as a complete date is typed or picked - no Enter
    // needed; the value stays "" until the date is complete.
    ["input", "change"].forEach((eventName) => {
      $("dateFilterFrom").addEventListener(eventName, () => {
        if (state.dateFilter.from !== $("dateFilterFrom").value) {
          state.dateFilter.from = $("dateFilterFrom").value;
          renderEvidenceBrowserEntries();
        }
      });
      $("dateFilterTo").addEventListener(eventName, () => {
        if (state.dateFilter.to !== $("dateFilterTo").value) {
          state.dateFilter.to = $("dateFilterTo").value;
          renderEvidenceBrowserEntries();
        }
      });
    });
    $("dateFilterClear").addEventListener("click", () => {
      state.dateFilter = { from: "", to: "" };
      $("dateFilterFrom").value = "";
      $("dateFilterTo").value = "";
      renderEvidenceBrowserEntries();
    });
    $("toggleInspector").addEventListener("click", toggleInspectorPane);
    $("openAnalyzeWindow").addEventListener("click", openAnalyzeWindow);
    $("liveBrowse").addEventListener("click", toggleLiveBrowse);
    $("treeModeFilesystem").addEventListener("click", () => setBrowserTreeMode("filesystem"));
    $("treeModeCategories").addEventListener("click", () => setBrowserTreeMode("categories"));
    $("browseEvidence").addEventListener("click", pickEvidencePath);
    $("runSearch").addEventListener("click", runSearch);
    $("selectAllSearchResults").addEventListener("click", selectAllSearchResults);
    $("bookmarkSelectedSearchResults").addEventListener("click", bookmarkSelectedSearchResults);
    $("clearSelectedSearchResults").addEventListener("click", clearSelectedSearchResults);
    $("clearFindings").addEventListener("click", clearFindings);
    $("exportReport").addEventListener("click", exportReport);
    $("openReport").addEventListener("click", openReport);
    $("hexPrev").addEventListener("click", () => stepHex(-1));
    $("hexGo").addEventListener("click", gotoHexOffset);
    $("hexNext").addEventListener("click", () => stepHex(1));
    $("showEntryDetails").addEventListener("click", showEntryDetails);
    $("toggleViewerFullscreen").addEventListener("click", toggleViewerFullscreen);
    $("bookmarkSelectedEntry").addEventListener("click", () => {
      if (state.hex.entryId) {
        bookmarkEntry(state.hex.entryId);
      } else {
        setNotice("Select an entry before bookmarking.", true);
      }
    });
    $("viewerMode").addEventListener("change", () => {
      if (state.hex.entryId && $("viewerMode").value !== "metadata" && !state.hex.data && !state.hex.fetching) {
        fetchEntryBytes();
      } else {
        renderHexViewer();
      }
    });
    $("bytesPerRow").addEventListener("change", renderHexViewer);
    $("offsetBase").addEventListener("change", renderHexViewer);
    $("hexOffset").addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        gotoHexOffset();
      }
    });
    document.addEventListener("keydown", handleGlobalKeydown);
    bindTabs();
    bindInspectorResize();
    bindHexSelection();
    setInspectorCollapsed(state.inspectorCollapsed);
    if (ANALYSIS_MODE) {
      switchView("analyzeView");
    }
    renderHexViewer();
    refresh();
  </script>
</body>
</html>
"###;
