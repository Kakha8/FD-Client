$ErrorActionPreference = 'Stop'
$helper = Join-Path $PSScriptRoot 'target\debug\fd-virtual-drive.exe'
$start = [System.Diagnostics.ProcessStartInfo]::new($helper)
$start.UseShellExecute = $false
$start.CreateNoWindow = $true
$start.RedirectStandardInput = $true
$start.RedirectStandardOutput = $true
$start.RedirectStandardError = $true
$process = [System.Diagnostics.Process]::Start($start)
try {
    $ready = $process.StandardOutput.ReadLineAsync()
    if (-not $ready.Wait(15000)) { throw 'Timed out waiting for the mount.' }
    $response = $ready.Result
    if ($response -notmatch '^MOUNTED ([D-Z]):$') {
        if ($process.HasExited) { throw $process.StandardError.ReadToEnd() }
        throw "Unexpected helper response: $response"
    }
    $root = $Matches[1] + ':\'
    $drive = [System.IO.DriveInfo]::new($root)
    if (-not $drive.IsReady) { throw 'Mounted drive is not ready.' }
    if ($drive.VolumeLabel -ne 'FD Client') { throw 'Unexpected volume label.' }
    if ($drive.DriveFormat -ne 'FD-SSE') { throw 'Unexpected filesystem type.' }
    if (@(Get-ChildItem -LiteralPath $root -Force).Count -ne 0) {
        throw 'The prototype drive should be empty.'
    }
    Write-Output "Verified empty mounted drive: $root ($($drive.VolumeLabel), $($drive.DriveFormat))"
    $snapshot = @{ entries = @(
        @{ path = '\Docs'; directory = $true; size = 0 },
        @{ path = '\Docs\hello.txt'; directory = $false; size = 123; created = 1788048000000; modified = 1788048000000 },
        @{ path = '\root.txt'; directory = $false; size = 45 }
    ) } | ConvertTo-Json -Depth 5 -Compress
    $process.StandardInput.WriteLine($snapshot)
    $process.StandardInput.Flush()
    $updated = $process.StandardOutput.ReadLineAsync()
    if (-not $updated.Wait(10000) -or $updated.Result -ne 'UPDATED 3') {
        throw 'Metadata snapshot was not acknowledged.'
    }
    # Let WinFsp's one-second metadata cache expire after the initial empty scan.
    Start-Sleep -Milliseconds 1200
    $items = @(Get-ChildItem -LiteralPath $root -Force)
    if ($items.Count -ne 2) { throw 'Root listing did not expose folder and file.' }
    $nested = @(Get-ChildItem -LiteralPath (Join-Path $root 'Docs'))
    if ($nested.Count -ne 1 -or $nested[0].Name -ne 'hello.txt' -or $nested[0].Length -ne 123) {
        throw 'Nested file metadata was incorrect.'
    }
    $readRejected = $false
    try { [System.IO.File]::ReadAllText((Join-Path $root 'Docs\hello.txt')) | Out-Null }
    catch [System.IO.IOException] { $readRejected = $true }
    if (-not $readRejected) { throw 'File-content reads must be unsupported in this milestone.' }
    Write-Output 'Verified nested directory listing, file sizes, and rejection of content reads.'
    Start-Sleep -Milliseconds 2100
    $scan = [PowerShell]::Create()
    $null = $scan.AddScript('param($path) Get-ChildItem -LiteralPath $path').AddArgument((Join-Path $root 'Docs'))
    $scanResult = $scan.BeginInvoke()
    $refresh = $process.StandardOutput.ReadLineAsync()
    if (-not $refresh.Wait(10000) -or $refresh.Result -ne 'REFRESH') {
        throw 'A new directory scan did not request a backend refresh.'
    }
    $replacement = @{ entries = @(
        @{ path = '\Docs'; directory = $true; size = 0 },
        @{ path = '\Docs\added-on-web.txt'; directory = $false; size = 456 }
    ) } | ConvertTo-Json -Depth 5 -Compress
    $process.StandardInput.WriteLine($replacement)
    $process.StandardInput.Flush()
    $ack = $process.StandardOutput.ReadLineAsync()
    if (-not $ack.Wait(10000) -or $ack.Result -ne 'UPDATED 2') { throw 'Refresh was not acknowledged.' }
    $firstRefresh = @($scan.EndInvoke($scanResult))
    $scan.Dispose()
    if ($firstRefresh.Count -ne 1 -or $firstRefresh[0].Name -ne 'added-on-web.txt') {
        throw 'The SAME directory refresh must return updated metadata, without a second F5.'
    }
    Start-Sleep -Milliseconds 1200
    $refreshed = @(Get-ChildItem -LiteralPath (Join-Path $root 'Docs'))
    if ($refreshed.Count -ne 1 -or $refreshed[0].Name -ne 'added-on-web.txt' -or $refreshed[0].Length -ne 456) {
        throw 'Refresh did not replace the old directory listing.'
    }
    if (@(Get-ChildItem -LiteralPath $root).Count -ne 1) { throw 'Deleted root entry remained visible.' }
    Start-Sleep -Milliseconds 2100
    $scan = [PowerShell]::Create()
    $null = $scan.AddScript('param($path) Get-ChildItem -LiteralPath $path').AddArgument($root)
    $scanResult = $scan.BeginInvoke()
    $refresh = $process.StandardOutput.ReadLineAsync()
    if (-not $refresh.Wait(10000) -or $refresh.Result -ne 'REFRESH') { throw 'Second refresh was not requested.' }
    $process.StandardInput.WriteLine('REFRESH_FAILED')
    $process.StandardInput.Flush()
    $null = $scan.EndInvoke($scanResult)
    $scan.Dispose()
    if (@(Get-ChildItem -LiteralPath (Join-Path $root 'Docs'))[0].Name -ne 'added-on-web.txt') {
        throw 'A failed refresh discarded cached metadata.'
    }
    Write-Output 'Verified same-scan refresh, added/deleted entries, and cache preservation on refresh failure.'
    $process.StandardInput.Close()
    if (-not $process.WaitForExit(10000)) { throw 'Timed out waiting for unmount.' }
    if ($process.ExitCode -ne 0) { throw $process.StandardError.ReadToEnd() }
    if ([System.IO.Directory]::Exists($root)) { throw 'Drive remained mounted after helper exit.' }
    Write-Output 'Verified clean unmount.'
} finally {
    if (-not $process.HasExited) {
        $process.StandardInput.Close()
        if (-not $process.WaitForExit(3000)) { $process.Kill() }
    }
    $process.Dispose()
}
