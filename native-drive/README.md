# SSE virtual drive

This Windows-only helper exposes a WinFsp volume labelled
`FD Client`. After login, Java fetches `/api/folders/root` and recursively visits
`/api/folders/{id}`, then sends a metadata snapshot through the helper's private
stdin pipe. Files and folders, sizes, and available timestamps appear in Explorer.
Explorer supports dragging/copying files and folders **into the drive to upload**
and **out of the drive to download**. Before login the drive is empty and uploads
are rejected. Java owns authenticated HTTP; no authentication tokens are sent to
the helper. Content is exchanged through a private per-mount temporary directory.
It is separate from the CSE native library so filesystem dependencies do not
affect the encryption build.

## Transfers

- Downloads use `GET /api/files/{id}` and stage the complete file on first read.
  Explorer then reads that local file at the requested offsets. Folder copies
  use normal Windows recursive copying.
- New files are staged locally as Windows writes them, then uploaded once using
  `POST /api/files` when the destination handle is cleaned up. Intermediate
  flushes only flush staging data. Empty files are uploaded too. New directories
  use `POST /api/folders` and are resolved to their backend IDs before returning.
- Explorer **New folder**, naming/renaming files and folders, and moving them
  between folders (including back to the drive root) are supported. Moving a
  folder retains its entire subtree and backend IDs. Moves use backend operations
  rather than downloading and uploading the contents again. Move and rename in
  separate steps when both the destination folder and filename need to change.
- The drive is presented to Windows as a network volume so Explorer bypasses
  the local Recycle Bin. **Delete** sends files and folders to the backend trash, where they can be
  restored; it does not call permanent deletion. Windows recursively deletes
  children before removing their folder. A server-side nonempty folder is rejected
  to protect children that were not present in the Explorer listing. A failed
  delete retains the cached entry and displays an error in Java; refresh to check
  the server state before retrying after a connection failure.
- Existing files cannot be overwritten or edited in place. Conflicting destination
  names, moving a folder into itself/its descendants, and moves of folders with
  unfinished uploads are rejected. The drive root cannot be renamed or deleted.
- The Explorer byte progress describes the local copy. The HTTP upload and server
  processing happen afterward. Windows cleanup cannot return upload errors, so
  Java displays an upload-failure dialog with the retained local recovery path.
  Failed transfers are never retried automatically, since a lost HTTP response
  can occur after a successful server commit. Check the remote folder before retrying.
- Completed download caches and successful upload staging files are removed.
  Failed/interrupted uploads remain under `%TEMP%\fd-drive-*\upload-*.part`,
  with a matching `.name.txt` file containing the original destination path.
  Cancelled delete-on-close staging files are discarded without uploading.
- Reported free space is local staging space; the backend separately enforces
  its limits. A download currently needs enough local space for the entire file.
  Individual HTTP requests have a 210-second timeout. Login/session changes
  invalidate pending work; requests already accepted by the server may complete.

Snapshot refreshes and HTTP transfers are serialized per mounted session so an
older listing cannot hide a newly uploaded file or created folder. Staged files
remain visible during refresh. Authentication failures require a refreshed
session before retrying.

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
also sent filesystem notifications for added/removed folders and files, including
new nested folders. Directory metadata caching is disabled so refreshed folders
can be opened without remounting. Pagination stays on a stable snapshot until the scan
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
The root is empty until a metadata snapshot is supplied. Without a Java parent,
transfer requests have no responder; use the smoke tests below. Press Enter in the
helper terminal to unmount. No disk is formatted and no local folder is mapped
or copied into this drive.

Run `./native-drive/smoke-test.ps1` from PowerShell for a real mount/unmount test
with synthetic nested folder metadata, refresh requests, added/deleted entries,
new nested folders without remounting, Windows folder-created notifications,
refresh failure cache preservation, sizes, and existing-file overwrite protection.

Run `./native-drive/transfer-smoke-test.ps1` for a real WinFsp mount with a mock
parent (no backend changes). It verifies recursive copies in both directions,
binary byte equality, nested upload parent IDs, empty files, intermediate flushes,
cancelled staging, overwrite protection, retained failed-upload data, folder
creation/renaming, file/folder moves, moves back to root, recursive deletion,
self-move rejection, and unchanged cached entries after rejected mutations.
