use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use kdft_case::{
    add_bookmark_item, add_evidence, analyze_signatures, case_info, create_bookmark,
    create_bookmark_folder, create_case, deep_search, filesystem_entry_count, global_options,
    import_browser_history, list_bookmark_folders, list_bookmark_items, list_bookmarks,
    list_evidence, list_installed_resources, process_evidence, render_report_html, report_data,
    update_global_options, AddEvidenceOptions, AnalyzeSignaturesOptions, BookmarkType,
    CreateBookmarkItemOptions, CreateBookmarkOptions, CreateCaseOptions, DeepSearchOptions,
    EvidenceKind, GlobalOptionPathUpdate, ImportBrowserHistoryOptions, ProcessEvidenceOptions,
    UpdateGlobalOptions,
};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "kdft")]
#[command(about = "Kristiee's Digital Forensic Tool v1 command line")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Case {
        #[command(subcommand)]
        command: CaseCommand,
    },
    Evidence {
        #[command(subcommand)]
        command: EvidenceCommand,
    },
    Bookmark {
        #[command(subcommand)]
        command: BookmarkCommand,
    },
    Options {
        #[command(subcommand)]
        command: OptionsCommand,
    },
    Resources {
        #[command(subcommand)]
        command: ResourcesCommand,
    },
    Report {
        #[command(subcommand)]
        command: ReportCommand,
    },
    Search {
        #[command(subcommand)]
        command: SearchCommand,
    },
    History {
        #[command(subcommand)]
        command: HistoryCommand,
    },
}

#[derive(Debug, Subcommand)]
enum CaseCommand {
    Create(CreateCaseArgs),
    Info(CasePathArgs),
}

#[derive(Debug, Args)]
struct CreateCaseArgs {
    #[arg(long)]
    case: PathBuf,
    #[arg(long)]
    name: String,
    #[arg(long)]
    examiner: Option<String>,
    #[arg(long)]
    case_number: Option<String>,
    #[arg(long)]
    case_type: Option<String>,
    #[arg(long)]
    description: Option<String>,
    #[arg(long)]
    default_export_folder: Option<PathBuf>,
    #[arg(long)]
    temporary_folder: Option<PathBuf>,
    #[arg(long)]
    index_folder: Option<PathBuf>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct CasePathArgs {
    #[arg(long)]
    case: PathBuf,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Subcommand)]
enum EvidenceCommand {
    Add(AddEvidenceArgs),
    Process(ProcessEvidenceArgs),
    SignatureAnalysis(SignatureAnalysisArgs),
    List(CasePathArgs),
}

#[derive(Debug, Args)]
struct AddEvidenceArgs {
    #[arg(long)]
    case: PathBuf,
    #[arg(long)]
    path: PathBuf,
    #[arg(long, default_value = "auto")]
    kind: String,
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    read_file_system: Option<bool>,
    #[arg(long = "no-read-file-system", conflicts_with = "read_file_system")]
    no_read_file_system: bool,
    #[arg(long)]
    notes: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ProcessEvidenceArgs {
    #[arg(long)]
    case: PathBuf,
    #[arg(long)]
    evidence_id: i64,
    #[arg(long, default_value_t = 5000)]
    max_entries: usize,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct SignatureAnalysisArgs {
    #[arg(long)]
    case: PathBuf,
    #[arg(long)]
    evidence_id: Option<i64>,
    #[arg(long, default_value_t = 100000)]
    max_entries: usize,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Subcommand)]
enum BookmarkCommand {
    FolderCreate(CreateBookmarkFolderArgs),
    FolderList(CasePathArgs),
    Create(CreateBookmarkArgs),
    List(CasePathArgs),
    ItemAdd(AddBookmarkItemArgs),
    ItemList(ListBookmarkItemsArgs),
}

#[derive(Debug, Subcommand)]
enum OptionsCommand {
    Get(CasePathArgs),
    Set(SetGlobalOptionsArgs),
}

#[derive(Debug, Args)]
struct SetGlobalOptionsArgs {
    #[arg(long)]
    case: PathBuf,
    #[arg(long)]
    config_root: Option<PathBuf>,
    #[arg(long)]
    clear_config_root: bool,
    #[arg(long)]
    evidence_library_root: Option<PathBuf>,
    #[arg(long)]
    clear_evidence_library_root: bool,
    #[arg(long)]
    default_storage_root: Option<PathBuf>,
    #[arg(long)]
    clear_default_storage_root: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Subcommand)]
enum ResourcesCommand {
    List(CasePathArgs),
}

#[derive(Debug, Subcommand)]
enum ReportCommand {
    /// Fast report summary. Directory trees are only built on export, so
    /// `directory_trees` is always empty here.
    Preview(CasePathArgs),
    Export(ExportReportArgs),
}

#[derive(Debug, Subcommand)]
enum SearchCommand {
    Deep(DeepSearchArgs),
}

#[derive(Debug, Subcommand)]
enum HistoryCommand {
    Import(ImportHistoryArgs),
}

#[derive(Debug, Args)]
struct DeepSearchArgs {
    #[arg(long)]
    case: PathBuf,
    #[arg(long)]
    query: String,
    #[arg(long)]
    evidence_id: Option<i64>,
    #[arg(long, default_value_t = true)]
    include_content: bool,
    #[arg(long, default_value_t = 50)]
    max_results: usize,
    #[arg(long, default_value_t = 65536)]
    max_file_bytes: u64,
    /// Restrict hits to entries whose stored category contains this text.
    #[arg(long)]
    category: Option<String>,
    /// Restrict hits to these file extensions, comma separated (jpg,png,zip).
    #[arg(long, value_delimiter = ',')]
    file_types: Option<Vec<String>>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ImportHistoryArgs {
    #[arg(long)]
    case: PathBuf,
    #[arg(long)]
    path: PathBuf,
    #[arg(long, default_value_t = 5000)]
    max_visits: usize,
    #[arg(long)]
    name: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ExportReportArgs {
    #[arg(long)]
    case: PathBuf,
    #[arg(long)]
    output: PathBuf,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct CreateBookmarkFolderArgs {
    #[arg(long)]
    case: PathBuf,
    #[arg(long)]
    name: String,
    #[arg(long)]
    parent_id: Option<i64>,
    #[arg(long)]
    comment: Option<String>,
    #[arg(long, default_value_t = true)]
    show_in_report: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct CreateBookmarkArgs {
    #[arg(long)]
    case: PathBuf,
    #[arg(long)]
    folder_id: i64,
    #[arg(long = "type", default_value = "notable_file")]
    bookmark_type: String,
    #[arg(long)]
    data_type: Option<String>,
    #[arg(long)]
    title: Option<String>,
    #[arg(long)]
    comment: Option<String>,
    #[arg(long, default_value_t = true)]
    in_report: bool,
    #[arg(long)]
    source_ref_json: Option<String>,
    #[arg(long)]
    content_ref_json: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct AddBookmarkItemArgs {
    #[arg(long)]
    case: PathBuf,
    #[arg(long)]
    bookmark_id: i64,
    #[arg(long)]
    evidence_id: Option<i64>,
    #[arg(long)]
    entry_id: Option<i64>,
    #[arg(long)]
    item_order: Option<i64>,
    #[arg(long)]
    display_name: Option<String>,
    #[arg(long)]
    logical_path: Option<String>,
    #[arg(long)]
    selection_offset: Option<i64>,
    #[arg(long)]
    selection_length: Option<i64>,
    #[arg(long)]
    data_preview: Option<String>,
    #[arg(long)]
    item_ref_json: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ListBookmarkItemsArgs {
    #[arg(long)]
    case: PathBuf,
    #[arg(long)]
    bookmark_id: Option<i64>,
    #[arg(long)]
    json: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Case { command } => match command {
            CaseCommand::Create(args) => {
                let id = create_case(
                    &args.case,
                    CreateCaseOptions {
                        name: args.name,
                        examiner_name: args.examiner,
                        case_number: args.case_number,
                        case_type: args.case_type,
                        description: args.description,
                        default_export_folder: args.default_export_folder,
                        temporary_folder: args.temporary_folder,
                        index_folder: args.index_folder,
                    },
                )?;
                if args.json {
                    println!(
                        "{}",
                        serde_json::json!({ "case_id": id, "case": args.case })
                    );
                } else {
                    println!("Created case {} at {}", id, args.case.display());
                }
            }
            CaseCommand::Info(args) => {
                let info = case_info(&args.case)?;
                print_json_or_debug(args.json, &info)?;
            }
        },
        Command::Evidence { command } => match command {
            EvidenceCommand::Add(args) => {
                let id = add_evidence(
                    &args.case,
                    AddEvidenceOptions {
                        path: args.path,
                        kind: EvidenceKind::parse(&args.kind)?,
                        read_file_system_requested: args
                            .read_file_system
                            .unwrap_or(!args.no_read_file_system),
                        notes: args.notes,
                    },
                )?;
                let entry_count = filesystem_entry_count(&args.case)?;
                if args.json {
                    println!(
                        "{}",
                        serde_json::json!({
                            "evidence_id": id,
                            "filesystem_entries": entry_count,
                            "indexed": false
                        })
                    );
                } else {
                    println!("Attached evidence source {id}; no indexing was run.");
                }
            }
            EvidenceCommand::Process(args) => {
                let result = process_evidence(
                    &args.case,
                    ProcessEvidenceOptions {
                        evidence_id: args.evidence_id,
                        max_entries: args.max_entries,
                    },
                )?;
                print_json_or_debug(args.json, &result)?;
            }
            EvidenceCommand::SignatureAnalysis(args) => {
                let result = analyze_signatures(
                    &args.case,
                    AnalyzeSignaturesOptions {
                        evidence_id: args.evidence_id,
                        max_entries: args.max_entries,
                    },
                )?;
                print_json_or_debug(args.json, &result)?;
            }
            EvidenceCommand::List(args) => {
                let evidence = list_evidence(&args.case)?;
                print_json_or_debug(args.json, &evidence)?;
            }
        },
        Command::Bookmark { command } => match command {
            BookmarkCommand::FolderCreate(args) => {
                let id = create_bookmark_folder(
                    &args.case,
                    args.parent_id,
                    &args.name,
                    args.comment.as_deref(),
                    args.show_in_report,
                )?;
                if args.json {
                    println!("{}", serde_json::json!({ "folder_id": id }));
                } else {
                    println!("Created bookmark folder {id}");
                }
            }
            BookmarkCommand::FolderList(args) => {
                let folders = list_bookmark_folders(&args.case)?;
                print_json_or_debug(args.json, &folders)?;
            }
            BookmarkCommand::Create(args) => {
                let source_ref_json =
                    parse_optional_json_object(args.source_ref_json, "source-ref-json")?;
                let content_ref_json =
                    parse_optional_json_object(args.content_ref_json, "content-ref-json")?;
                let id = create_bookmark(
                    &args.case,
                    CreateBookmarkOptions {
                        folder_id: args.folder_id,
                        bookmark_type: BookmarkType::parse(&args.bookmark_type)?,
                        data_type: args.data_type,
                        title: args.title,
                        examiner_comment: args.comment,
                        in_report: args.in_report,
                        source_ref_json,
                        content_ref_json,
                    },
                )?;
                if args.json {
                    println!("{}", serde_json::json!({ "bookmark_id": id }));
                } else {
                    println!("Created bookmark {id}");
                }
            }
            BookmarkCommand::List(args) => {
                let bookmarks = list_bookmarks(&args.case)?;
                print_json_or_debug(args.json, &bookmarks)?;
            }
            BookmarkCommand::ItemAdd(args) => {
                let item_ref_json =
                    parse_optional_json_object(args.item_ref_json, "item-ref-json")?;
                let created_item = add_bookmark_item(
                    &args.case,
                    CreateBookmarkItemOptions {
                        bookmark_id: args.bookmark_id,
                        evidence_id: args.evidence_id,
                        entry_id: args.entry_id,
                        item_order: args.item_order,
                        display_name: args.display_name,
                        logical_path: args.logical_path,
                        selection_offset: args.selection_offset,
                        selection_length: args.selection_length,
                        data_preview: args.data_preview,
                        item_ref_json,
                    },
                )?;
                if args.json {
                    print_json_or_debug(true, &created_item)?;
                } else {
                    println!("Added bookmark item {}", created_item.id);
                }
            }
            BookmarkCommand::ItemList(args) => {
                let items = list_bookmark_items(&args.case, args.bookmark_id)?;
                print_json_or_debug(args.json, &items)?;
            }
        },
        Command::Options { command } => match command {
            OptionsCommand::Get(args) => {
                let options = global_options(&args.case)?;
                print_json_or_debug(args.json, &options)?;
            }
            OptionsCommand::Set(args) => {
                let options = update_global_options(
                    &args.case,
                    UpdateGlobalOptions {
                        config_root: path_update(
                            args.config_root,
                            args.clear_config_root,
                            "config-root",
                        )?,
                        evidence_library_root: path_update(
                            args.evidence_library_root,
                            args.clear_evidence_library_root,
                            "evidence-library-root",
                        )?,
                        default_storage_root: path_update(
                            args.default_storage_root,
                            args.clear_default_storage_root,
                            "default-storage-root",
                        )?,
                    },
                )?;
                print_json_or_debug(args.json, &options)?;
            }
        },
        Command::Resources { command } => match command {
            ResourcesCommand::List(args) => {
                let resources = list_installed_resources(&args.case)?;
                print_json_or_debug(args.json, &resources)?;
            }
        },
        Command::Report { command } => match command {
            ReportCommand::Preview(args) => {
                let report = report_data(&args.case)?;
                print_json_or_debug(args.json, &report)?;
            }
            ReportCommand::Export(args) => {
                let report = report_data(&args.case)?;
                let html = render_report_html(&report);
                if let Some(parent) = args
                    .output
                    .parent()
                    .filter(|path| !path.as_os_str().is_empty())
                {
                    fs::create_dir_all(parent).with_context(|| {
                        format!("creating report directory {}", parent.display())
                    })?;
                }
                fs::write(&args.output, html)
                    .with_context(|| format!("writing report {}", args.output.display()))?;
                if args.json {
                    println!(
                        "{}",
                        serde_json::json!({
                            "report": args.output,
                            "folders": report.folders.len()
                        })
                    );
                } else {
                    println!("Wrote report {}", args.output.display());
                }
            }
        },
        Command::Search { command } => match command {
            SearchCommand::Deep(args) => {
                let results = deep_search(
                    &args.case,
                    DeepSearchOptions {
                        query: args.query,
                        evidence_id: args.evidence_id,
                        include_content: args.include_content,
                        max_results: args.max_results,
                        max_file_bytes: args.max_file_bytes,
                        category: args.category,
                        file_types: args.file_types,
                    },
                )?;
                print_json_or_debug(args.json, &results)?;
            }
        },
        Command::History { command } => match command {
            HistoryCommand::Import(args) => {
                let result = import_browser_history(
                    &args.case,
                    ImportBrowserHistoryOptions {
                        history_path: args.path,
                        max_visits: args.max_visits,
                        evidence_name: args.name,
                    },
                )?;
                print_json_or_debug(args.json, &result)?;
            }
        },
    }
    Ok(())
}

fn parse_optional_json_object(value: Option<String>, field: &str) -> Result<serde_json::Value> {
    let value = match value {
        Some(value) => {
            serde_json::from_str(&value).with_context(|| format!("parsing --{field} as JSON"))?
        }
        None => serde_json::json!({}),
    };
    if value.is_object() {
        Ok(value)
    } else {
        anyhow::bail!("--{field} must be a JSON object");
    }
}

fn path_update(
    value: Option<PathBuf>,
    clear: bool,
    field: &str,
) -> Result<Option<GlobalOptionPathUpdate>> {
    match (value, clear) {
        (Some(_), true) => anyhow::bail!("--{field} conflicts with --clear-{field}"),
        (Some(value), false) => Ok(Some(GlobalOptionPathUpdate::Set(value))),
        (None, true) => Ok(Some(GlobalOptionPathUpdate::Clear)),
        (None, false) => Ok(None),
    }
}

fn print_json_or_debug<T>(json: bool, value: &T) -> Result<()>
where
    T: serde::Serialize + std::fmt::Debug,
{
    if json {
        println!("{}", serde_json::to_string_pretty(value)?);
    } else {
        println!("{value:#?}");
    }
    Ok(())
}
