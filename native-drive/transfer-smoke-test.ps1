param([switch]$Trace)
$ErrorActionPreference = 'Stop'
$staging = Join-Path ([System.IO.Path]::GetTempPath()) ('fd-drive-test-' + [guid]::NewGuid())
[System.IO.Directory]::CreateDirectory($staging) | Out-Null
$start = [System.Diagnostics.ProcessStartInfo]::new((Join-Path $PSScriptRoot 'target\debug\fd-virtual-drive.exe'))
$start.UseShellExecute = $false
$start.CreateNoWindow = $true
$start.RedirectStandardInput = $true
$start.RedirectStandardOutput = $true
$start.RedirectStandardError = $true
$start.EnvironmentVariables['FD_DRIVE_STAGING'] = $staging
$process = [System.Diagnostics.Process]::Start($start)
$worker = $null
try {
    $ready = $process.StandardOutput.ReadLineAsync()
    if (-not $ready.Wait(15000) -or $ready.Result -notmatch '^MOUNTED ([D-Z]):$') { throw 'Mount failed.' }
    $root = $Matches[1] + ':\'
    if ([System.IO.DriveInfo]::new($root).DriveType -ne [System.IO.DriveType]::Network) {
        throw 'The cloud drive must be a network volume so Explorer bypasses the local Recycle Bin.'
    }
    $snapshot = @{entries=@(
        @{id=10; path='\Docs'; directory=$true; size=0},
        @{id=11; path='\Docs\hello.bin'; directory=$false; size=1048579}
    )} | ConvertTo-Json -Depth 5 -Compress
    $process.StandardInput.WriteLine($snapshot)
    $ack = $process.StandardOutput.ReadLineAsync()
    if (-not $ack.Wait(10000) -or $ack.Result -ne 'UPDATED 2') { throw 'Snapshot failed.' }
    $payload = [byte[]]::new(1048579)
    [Random]::new(42).NextBytes($payload)
    $source = Join-Path $staging 'source'
    [System.IO.Directory]::CreateDirectory((Join-Path $source 'Nested')) | Out-Null
    [System.IO.File]::WriteAllBytes((Join-Path $source 'Nested\upload.bin'), $payload)
    [System.IO.File]::WriteAllBytes((Join-Path $source 'empty.bin'), [byte[]]::new(0))
    $worker = [PowerShell]::Create()
    $null = $worker.AddScript({param($root, $staging, $source)
        $ErrorActionPreference = 'Stop'
        Copy-Item -LiteralPath (Join-Path $root 'Docs') -Destination (Join-Path $staging 'downloaded') -Recurse
        Copy-Item -LiteralPath $source -Destination $root -Recurse
        # Intermediate flushes must not publish partial files or prevent further writes.
        $stream = [System.IO.File]::Create((Join-Path $root 'flushed.bin'))
        try {
            $stream.WriteByte(1)
            $stream.Flush($true)
            $stream.WriteByte(2)
        } finally { $stream.Dispose() }
        $cancelled = [System.IO.FileStream]::new((Join-Path $root 'cancelled.bin'), [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None, 4096, [System.IO.FileOptions]::DeleteOnClose)
        try { $cancelled.WriteByte(3) } finally { $cancelled.Dispose() }
        $denied = $false
        try { [System.IO.File]::WriteAllText((Join-Path $root 'Docs\hello.bin'), 'overwrite') }
        catch { $denied = $true }
        if (-not $denied) { throw 'Existing cloud file was overwritten.' }
        [System.IO.File]::WriteAllBytes((Join-Path $root 'rejected.bin'), [byte[]]@(4,5,6))
        # Exercise the same mkdir/rename/move/delete callbacks used by Explorer.
        [System.IO.Directory]::CreateDirectory((Join-Path $root 'New folder')) | Out-Null
        [System.IO.Directory]::Move((Join-Path $root 'New folder'), (Join-Path $root 'Destination'))
        [System.IO.File]::Move((Join-Path $root 'Docs\hello.bin'), (Join-Path $root 'Destination\hello.bin'))
        [System.IO.Directory]::Move((Join-Path $root 'source'), (Join-Path $root 'Destination\source'))
        if (-not [System.IO.File]::Exists((Join-Path $root 'Destination\source\Nested\upload.bin'))) {
            throw 'Moving a folder lost its descendants.'
        }
        [System.IO.File]::Move((Join-Path $root 'Destination\hello.bin'), (Join-Path $root 'hello.bin'))
        [System.IO.Directory]::Move((Join-Path $root 'Docs'), (Join-Path $root 'Destination\Docs'))
        $denied = $false
        try { [System.IO.Directory]::Move((Join-Path $root 'Destination'), (Join-Path $root 'Destination\source\Nested\Bad')) }
        catch { $denied = $true }
        if (-not $denied) { throw 'Folder was moved into its descendant.' }
        $denied = $false
        try { [System.IO.File]::Move((Join-Path $root 'flushed.bin'), (Join-Path $root 'refused.bin')) }
        catch { $denied = $true }
        if (-not $denied -or -not [System.IO.File]::Exists((Join-Path $root 'flushed.bin'))) { throw 'Failed move changed the cached tree.' }
        # The root belongs to this newly mounted mock helper, never an existing drive.
        [System.IO.Directory]::Delete((Join-Path $root 'Destination'), $true)
        [System.IO.File]::Delete((Join-Path $root 'hello.bin'))
        [System.IO.File]::Delete((Join-Path $root 'flushed.bin')) # mock rejects this deletion
        if (-not [System.IO.File]::Exists((Join-Path $root 'flushed.bin'))) { throw 'Rejected deletion hid the original file.' }
        if ([System.IO.Directory]::Exists((Join-Path $root 'Destination'))) { throw 'Recursive folder deletion did not finish.' }
    }).AddArgument($root).AddArgument($staging).AddArgument($source)
    $running = $worker.BeginInvoke()
    $uploads = @{}
    $folders = @{}
    $nextId = 100
    $rejectedPath = $null
    $moves = [System.Collections.Generic.List[object]]::new()
    $deletions = [System.Collections.Generic.List[object]]::new()
    $read = $process.StandardOutput.ReadLineAsync()
    $deadline = [DateTime]::UtcNow.AddSeconds(90)
    while (-not $running.IsCompleted) {
        if ([DateTime]::UtcNow -gt $deadline) { throw 'Copy operations timed out.' }
        if (-not $read.Wait(100)) { continue }
        $line = $read.Result
        if ($null -eq $line) { throw 'Helper exited during transfers.' }
        if ($line -eq 'REFRESH') {
            $process.StandardInput.WriteLine('REFRESH_FAILED')
        } elseif ($line.StartsWith('TRANSFER ')) {
            $request = $line.Substring(9) | ConvertFrom-Json
            if ($Trace) { Write-Output "Mock request: $line" }
            $response = @{request=$request.request; ok=$true}
            switch ($request.op) {
                'ready' { }
                'download' {
                    if ($request.id -ne 11) { throw 'Unexpected download ID.' }
                    $file = 'download-' + [guid]::NewGuid() + '.part'
                    [System.IO.File]::WriteAllBytes((Join-Path $staging $file), $payload)
                    $response.file = $file
                }
                'mkdir' { $nextId++; $response.id=$nextId; $folders[$request.name]=$nextId }
                'relocate' {
                    if ($request.name -eq 'refused.bin') { $response.ok=$false }
                    else { $moves.Add($request) }
                }
                'delete' {
                    if ($request.path -eq '\flushed.bin') { $response.ok=$false }
                    else { $deletions.Add($request) }
                }
                'upload' {
                    if ($request.name -eq 'rejected.bin') {
                        $rejectedPath = Join-Path $staging $request.file
                        $response.ok = $false
                        break
                    }
                    $nextId++; $response.id=$nextId
                    $input = [System.IO.FileStream]::new((Join-Path $staging $request.file), [System.IO.FileMode]::Open,
                        [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete)
                    $memory = [System.IO.MemoryStream]::new()
                    try { $input.CopyTo($memory); $uploads[$request.name]=@{bytes=$memory.ToArray(); parent=$request.parent} }
                    finally { $input.Dispose(); $memory.Dispose() }
                }
                default { throw "Unexpected transfer operation: $($request.op)" }
            }
            $process.StandardInput.WriteLine('TRANSFER ' + ($response | ConvertTo-Json -Compress))
        } else { throw "Unexpected protocol line: $line" }
        $read = $process.StandardOutput.ReadLineAsync()
    }
    $null = $worker.EndInvoke($running)
    if ($worker.HadErrors) { throw ($worker.Streams.Error | Out-String) }
    $downloaded = [System.IO.File]::ReadAllBytes((Join-Path $staging 'downloaded\hello.bin'))
    $expected = [Convert]::ToBase64String($payload)
    if ([Convert]::ToBase64String($downloaded) -ne $expected) { throw 'Download bytes differ.' }
    if ($uploads.Count -ne 3) { throw "Expected 3 uploads, got $($uploads.Count)." }
    if ([Convert]::ToBase64String($uploads['upload.bin'].bytes) -ne $expected) { throw 'Upload bytes differ.' }
    if ($uploads['upload.bin'].parent -ne $folders['Nested']) { throw 'Nested upload parent differs.' }
    if ($uploads['empty.bin'].bytes.Length -ne 0) { throw 'Empty upload differs.' }
    if ([Convert]::ToBase64String($uploads['flushed.bin'].bytes) -ne 'AQI=') { throw 'Intermediate flush uploaded partial data.' }
    if (-not $rejectedPath -or [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($rejectedPath)) -ne 'BAUG') {
        throw 'Failed upload bytes were not retained.'
    }
    if ([System.IO.File]::Exists((Join-Path $root 'rejected.bin'))) { throw 'Failed upload left a phantom file.' }
    if ($moves.Count -ne 5) { throw "Expected 5 successful renames/moves, got $($moves.Count)." }
    if ($deletions.Count -ne 7) { throw "Expected 7 trash operations, got $($deletions.Count)." }
    if ($moves[1].id -ne 11 -or $moves[3].parent -ne 0) { throw 'Moving a file or moving back to root used the wrong ID.' }
    Write-Output 'PASS: mounted-drive recursive upload/download, binary bytes, empty file, intermediate flush, cancelled staging, overwrite protection, and failed-upload recovery.'
    Write-Output 'PASS: folder creation/naming, file/folder moves, recursive trash deletion, self-move rejection, and unchanged entries after rejected mutations.'
} finally {
    if (-not $process.HasExited) {
        $process.StandardInput.Close()
        if (-not $process.WaitForExit(5000)) { $process.Kill() }
    }
    if ($worker) { $worker.Dispose() }
    $process.Dispose()
    # Delete only the explicitly validated, unique test directory.
    $resolved = [System.IO.Path]::GetFullPath($staging)
    $tempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
    if ($resolved.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -and
        [System.IO.Path]::GetFileName($resolved).StartsWith('fd-drive-test-')) {
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
