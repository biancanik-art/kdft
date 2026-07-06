# Kristiee's Digital Forensic Tool v1

This is the professional rewrite base for Kristiee's Digital Forensic Tool (KDFT): a
**cross-platform** (Windows, macOS, Linux), local-only digital forensic workbench for
attaching evidence, browsing file systems inside disk images, deep searching (text and
hex byte patterns), bookmarking, and reporting. One small self-contained executable per
platform - no installer, no runtime dependencies.

A versioned user manual (with per-release changes and bug-fix notes) will follow in a later
release.

## Download And Run

Every [GitHub release](https://github.com/biancanik-art/kdft/releases) ships ready-made
builds for all three operating systems:

- **Windows x64** — `kdft-vX.Y.Z-windows-x64.zip` (or the standalone `kdft-ui.exe`)
- **macOS** — `kdft-vX.Y.Z-macos-arm64.tar.gz` (Apple Silicon) or `-macos-x64.tar.gz`
  (Intel)
- **Linux x64** — `kdft-vX.Y.Z-linux-x64.tar.gz`

On Windows, grab `kdft-ui.exe` and run it — no installer, no dependencies:

```powershell
.\kdft-ui.exe --port 8780 --open
```

It starts a local-only workbench server (bound to 127.0.0.1, nothing leaves the machine) and
opens your browser. From there: **New / Open Case** -> create the case database -> **Add
Evidence** (disk image / folder / single file / browser history, with a native Browse dialog)
-> Analyze, Deep Search, Bookmarks, Quick Report. Reports carry a KDFT integrity footer with a
SHA-256 that is also recorded in the case database's audit trail.

On macOS, unpack the matching tarball, then remove the download quarantine and run the
workbench:

```bash
xattr -d com.apple.quarantine kdft-ui kdft
./kdft-ui --port 8780 --open
```

The macOS binaries are ad-hoc signed, not notarized. Apple requires a paid Developer ID for
Gatekeeper-clean distribution, so downloaded unsigned command-line binaries can still need the
quarantine attribute removed before first run.

On Linux, unpack the tarball and run the workbench:

```bash
chmod +x kdft-ui kdft
./kdft-ui --port 8780 --open
```

The `chmod +x` step is only needed if the archive tool did not preserve executable bits.
Install `zenity` for the Browse dialog when available; KDFT also tries `kdialog` and otherwise
accepts manually typed paths.

`kdft.exe` is the equivalent command-line interface for scripted workflows (see
[Current Commands](#current-commands)).

## Install From Source (Windows, macOS, Linux)

1. Install Rust (stable) from <https://rustup.rs/>.
2. Clone this repository and build the two executables:

   ```powershell
   git clone https://github.com/biancanik-art/kdft.git
   cd kdft
   cargo build --release -p kdft-ui -p kdft-cli
   ```

3. The executables land in `target/release/`: `kdft-ui` (local browser workbench) and
   `kdft` (command-line interface). Both are self-contained — no runtime dependencies,
   no installer, nothing to register.
4. Run the workbench:

   ```powershell
   .\target\release\kdft-ui.exe --port 8780 --open
   ```

   On macOS/Linux the same binaries build and run with `./target/release/kdft-ui --port 8780 --open`.

V1 starts from a clean architecture and follows the classic examiner workflow of the old
Ecase 6.11 flavor.

## Language And Portability

The core is Rust:

- fast enough for evidence I/O, hashing, parsing, and search
- memory-safe for untrusted evidence data
- portable across Windows, macOS, and Linux
- suitable for CLI, service, local web UI, and desktop UI backends

The first UI surface is `kdft-ui`, a local browser workbench served by Rust. The forensic model
still lives in Rust crates and the command/API layer so the desktop UI can change later without
rewriting case logic.

## First Principles

- Adding evidence is lightweight. It records a source and bounded metadata only.
- Indexing, file-system traversal, hashing, carving, text extraction, and artifact parsing are
  examiner-driven jobs.
- Bookmarking follows the old Ecase 6.11 flavor: user-created folders, comments, data types,
  highlighted data, file/group bookmarks, and report inclusion flags.
- BitLocker support is planned as a read-only evidence-reader/decryption layer. Recovery keys are
  never stored in the case database.
- Routine tests use small local samples only.

## Current Commands

```powershell
cargo run -p kdft-cli -- case create --case C:\temp\case.kdft.sqlite --name Demo --examiner Examiner
cargo run -p kdft-cli -- options set --case C:\temp\case.kdft.sqlite --config-root C:\temp\kdft-config --json
cargo run -p kdft-cli -- options set --case C:\temp\case.kdft.sqlite --clear-config-root --json
cargo run -p kdft-cli -- evidence add --case C:\temp\case.kdft.sqlite --path ..\testdata\smoke-evidence --json
cargo run -p kdft-cli -- evidence add --case C:\temp\case.kdft.sqlite --path C:\temp\flat.bin --read-file-system=false --json
cargo run -p kdft-cli -- evidence process --case C:\temp\case.kdft.sqlite --evidence-id 1 --max-entries 5000 --json
cargo run -p kdft-cli -- evidence list --case C:\temp\case.kdft.sqlite --json
cargo run -p kdft-cli -- search deep --case C:\temp\case.kdft.sqlite --query forensic --json
cargo run -p kdft-cli -- bookmark folder-create --case C:\temp\case.kdft.sqlite --name Findings --json
cargo run -p kdft-cli -- bookmark create --case C:\temp\case.kdft.sqlite --folder-id 1 --title "Notable file" --in-report=false --json
cargo run -p kdft-cli -- bookmark list --case C:\temp\case.kdft.sqlite --json
cargo run -p kdft-cli -- bookmark item-add --case C:\temp\case.kdft.sqlite --bookmark-id 1 --display-name "Selected bytes" --selection-offset 128 --selection-length 16 --data-preview "keyword hit preview" --json
cargo run -p kdft-cli -- bookmark item-list --case C:\temp\case.kdft.sqlite --bookmark-id 1 --json
cargo run -p kdft-cli -- report preview --case C:\temp\case.kdft.sqlite --json
cargo run -p kdft-cli -- report export --case C:\temp\case.kdft.sqlite --output C:\temp\kdft-report.html --json
```

## See It Work

Run the durable demo from the workspace root:

```powershell
.\scripts\demo-report.ps1
```

It creates `demo-output\demo.kdft.sqlite` and `demo-output\report.html`.

Start the local browser UI from the workspace root:

```powershell
cargo run -p kdft-ui -- --open
```

By default it serves `http://127.0.0.1:8777/` and uses `ui-output\workbench.kdft.sqlite` plus
`ui-output\quick-report.html` as the prefilled paths.

In the UI, create or load a case first, then use **Add Evidence > Browse** to select a local file
or folder. Evidence attach is still metadata-only. The Evidence Browser shows indexed evidence
entries in a three-pane source tree, folder list, and entry viewer; file/folder evidence can be
indexed by the current bounded process job. Disk images such as `.e01`, `.vmdk`, `.vhdx`, `.vhd`,
`.vdi`, `.raw`, `.dd`, `.img`, and split raw (`.001`/`.002`/...) can be analyzed into container
and partition records; split E01 segment sets are discovered automatically. FAT12/16/32, NTFS,
and ext2/3/4 partitions are enumerated into browsable volume, folder, and file entries under
`/Image Analysis/Volumes`. NTFS support covers active entries, named streams (ADS), deleted MFT
record recovery, and `$Bitmap`-derived unallocated space; FAT covers deleted (0xE5) entry
recovery. Examiner-driven jobs add lost-partition recovery (orphaned boot sectors in
unpartitioned gaps), signature carving, and SHA-256 hashing. APFS, HFS, btrfs, and other
partition file-system parsers remain later evidence-reader jobs.

## Live Browse (Preview model)

You do not have to index a disk image to look inside it. Attach a disk image, open the **Analyze**
tab, and click **Live browse**: KDFT reads the partition table and each directory straight from the
image on demand (NTFS, FAT, ext2/3/4), so you can navigate a multi-terabyte disk immediately
without a full up-front index. Indexing, hashing, carving, and search remain separate
examiner-driven jobs for when you want the case database populated.

When a disk-image file is found inside folder evidence, use its **Analyze image** action so the file
is attached and processed as image evidence instead of opened as raw container bytes.

The `evidence add` command must report `"indexed": false` and leave `filesystem_entries` at zero.
The `read_file_system_requested` field records examiner intent for a later preview/index job; it
does not mean file-system traversal has already run.

The `evidence process` command is the first bounded indexing job. It handles file/folder evidence
and disk-image container/partition analysis, records entries in `filesystem_entries`, enumerates
FAT12/16/32 and NTFS partition entries when present, and stops at `--max-entries`. Physical-device
acquisition, deleted NTFS record recovery, and non-FAT/non-NTFS partition file-system parsing remain
later evidence-reader jobs.

Browser history import supports Chromium-style Chrome or Edge profile data:

```powershell
cargo run -p kdft-cli -- history import --case ui-output\workbench.kdft.sqlite --path "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History" --max-visits 5000 --json
```

The path may be a profile folder or its `History` database. The importer copies the History
database to a temp file, reads it locally, and also processes sibling `Bookmarks` and `Preferences`
files when present. Visits, bookmarks, and preference summaries are written as `browser_history`
evidence entries of kind `record`. Those entries appear under `Browser Activities` in the Evidence
Browser, deep search can match URL/title/host/preference metadata, and records can be selected in
bulk or bookmarked for reports.

Each `.kdft.sqlite` file is a single-case database. Bookmark item order is unique within each
bookmark so report/export output can be deterministic.

## Credits

KDFT is built by **Cristina** (examiner, product owner) together with her AI engineering
partners **Codex** (implementation) and **Claude** (testing, validation, and release
engineering).

## License

Apache License 2.0 — see [LICENSE](LICENSE).
