# SSE metadata virtual drive

This Windows-only helper exposes a **read-only, listing-only** WinFsp volume labelled
`FD Client`. After login, Java fetches `/api/folders/root` and recursively visits
`/api/folders/{id}`, then sends a metadata snapshot through the helper's private
stdin pipe. Files and folders, sizes, and available timestamps appear in Explorer.
No authentication tokens or file contents are sent to the helper. Content reads,
uploads, and mutations are not supported yet. Before login the drive is empty.
It is separate from the CSE native library so filesystem dependencies do not
affect the encryption build.

## Prerequisites

- Rust MSVC toolchain and Visual Studio C++ build tools / Windows SDK.
- [WinFsp 2.1 runtime](https://github.com/winfsp/winfsp/releases/tag/v2.1).
  The Rust dependency bundles SDK headers/libraries for building, so the
  WinFsp Developer installation is not required.
- LLVM (`libclang.dll`) for the Rust binding generator. If it is not detected,
  set `LIBCLANG_PATH` to the LLVM `bin` directory before building.

For example, in PowerShell with the standard LLVM installation:

```powershell
$env:LIBCLANG_PATH = 'C:\Program Files\LLVM\bin'
cargo build --manifest-path native-drive/Cargo.toml
cargo test --manifest-path native-drive/Cargo.toml
```

Only the WinFsp runtime/driver is needed on an end-user machine; LLVM and the
SDK are build-time prerequisites. Review WinFsp and winfsp-rs licensing before
distributing the application.

## Client integration

Run FD Client from the repository root. Application startup automatically
starts `native-drive/target/debug/fd-virtual-drive.exe` (or the release build if
no debug build exists), even while the login screen is displayed. The main page
reuses the existing mount; the **Open SSE drive** button opens it in Explorer.
Mount failure is displayed on the page and does not prevent normal CSE use.

The initial snapshot is loaded after login. Starting a fresh directory scan
(including Explorer F5 / Refresh) requests a backend refresh. Repeated
requests are combined, with a two-second cooldown after completion. The cached
listing is returned if the request fails or takes longer than 15 seconds;
otherwise the same directory scan returns the refreshed snapshot. Explorer is
also notified for changed folders. Pagination stays on a stable snapshot until the scan
restarts. This is refresh-on-browse, not continuous push synchronization.

Failed backend refreshes retain the previous snapshot and log the error; a later
directory refresh can retry. Initial listing errors are shown on the main page.
The backend is not modified. Windows-invalid
names and case-insensitive name collisions fail the snapshot rather than silently
hide or rename items. Deleted files are excluded. Limits are 10,000 folders and
100,000 total items per snapshot.

The helper prefers `F:` and otherwise selects an unused letter, never replacing
an existing drive. The selected letter appears on the main page. Logout or
application exit closes the helper's input pipe and unmounts the drive. A parent
process crash also closes the pipe. The client has a forced-termination fallback
if graceful shutdown does not complete within three seconds.

## Manual smoke test

```powershell
.\native-drive\target\debug\fd-virtual-drive.exe
```

Wait for `MOUNTED F:` (the letter may differ), then open that drive in Explorer.
The root is empty until a metadata snapshot is supplied, and writes are rejected. Press Enter in the
helper terminal to unmount. No disk is formatted and no local folder is mapped
or copied into this drive.

Run `./native-drive/smoke-test.ps1` from PowerShell for a real mount/unmount test
with synthetic nested folder metadata, refresh requests, added/deleted entries,
refresh failure cache preservation, sizes, and rejection of content reads.
