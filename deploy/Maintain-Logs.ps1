#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$LogDirectory = 'C:\2fa\logs',
    [switch]$LibraryOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-LogPath {
    param([string]$Path)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    while ($null -ne $item) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Log paths cannot contain reparse points or symbolic links.'
        }
        $item = if ($item -is [IO.DirectoryInfo]) { $item.Parent } else { $item.Directory }
    }
}

function Get-LogDate {
    param([string]$Name)
    if ($Name -cnotmatch '^agent-(\d{4}-\d{2}-\d{2})(?:\.part-[a-f0-9]{64})?\.jsonl$') { return $null }
    $parsed = [DateTime]::MinValue
    if (-not [DateTime]::TryParseExact($Matches[1], 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::None, [ref]$parsed)) { return $null }
    return [DateTime]::SpecifyKind($parsed, [DateTimeKind]::Utc)
}

function Get-LogMonth {
    param([string]$Name)
    if ($Name -cnotmatch '^agent-(\d{4}-\d{2})\.zip$') { return $null }
    $parsed = [DateTime]::MinValue
    if (-not [DateTime]::TryParseExact($Matches[1], 'yyyy-MM', [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::None, [ref]$parsed)) { return $null }
    return [DateTime]::SpecifyKind($parsed, [DateTimeKind]::Utc)
}

function Get-LogHash {
    param([IO.Stream]$Stream)
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($hash.ComputeHash($Stream))).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose() }
}

function Test-MonthArchive {
    param([string]$ArchivePath, [string]$Month, [hashtable]$Expected)
    $stream = [IO.File]::Open($ArchivePath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $zip = $null
    try {
        $zip = New-Object IO.Compression.ZipArchive($stream, [IO.Compression.ZipArchiveMode]::Read, $true)
        if ($zip.Entries.Count -ne $Expected.Count) { throw 'Archive entry count differs from its sources.' }
        $seen = @{}
        foreach ($entry in $zip.Entries) {
            $date = Get-LogDate $entry.FullName
            if ($null -eq $date -or $date.ToString('yyyy-MM') -cne $Month -or $seen.ContainsKey($entry.FullName) -or
                -not $Expected.ContainsKey($entry.FullName)) { throw 'Archive contains an unexpected entry.' }
            $seen[$entry.FullName] = $true
            $input = $entry.Open()
            try { $digest = Get-LogHash $input } finally { $input.Dispose() }
            if ($digest -cne $Expected[$entry.FullName].Hash -or $entry.Length -ne $Expected[$entry.FullName].Length) {
                throw 'Archive content verification failed.'
            }
        }
    }
    finally {
        if ($null -ne $zip) { $zip.Dispose() }
        $stream.Dispose()
    }
}

function Publish-LogMonth {
    param([string]$ArchiveDirectory, [string]$Month, [array]$Files)
    $destination = Join-Path $ArchiveDirectory ('agent-' + $Month + '.zip')
    $temporary = Join-Path $ArchiveDirectory ('.agent-' + $Month + '.' + [guid]::NewGuid().ToString('N') + '.tmp')
    $sources = @()
    $expected = @{}
    $oldStream = $null
    $oldZip = $null
    $newStream = $null
    $newZip = $null
    $published = $false
    $deleted = 0
    try {
        # Hold the source files open without write/delete sharing while composing
        # the archive. A late writer cannot change bytes that we are verifying.
        foreach ($file in $Files) {
            Assert-LogPath $file.FullName
            $input = [IO.File]::Open($file.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
            try {
                $digest = Get-LogHash $input
                $input.Position = 0
                $sources += [pscustomobject]@{ Path = $file.FullName; Name = $file.Name; Hash = $digest; Length = $input.Length; Stream = $input }
            }
            catch { $input.Dispose(); throw }
        }
        $newStream = [IO.File]::Open($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        $newZip = New-Object IO.Compression.ZipArchive($newStream, [IO.Compression.ZipArchiveMode]::Create, $true)
        if ([IO.File]::Exists($destination)) {
            Assert-LogPath $destination
            $oldStream = [IO.File]::Open($destination, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
            $oldZip = New-Object IO.Compression.ZipArchive($oldStream, [IO.Compression.ZipArchiveMode]::Read, $true)
            foreach ($entry in $oldZip.Entries) {
                $date = Get-LogDate $entry.FullName
                if ($null -eq $date -or $date.ToString('yyyy-MM') -cne $Month -or $expected.ContainsKey($entry.FullName)) {
                    throw 'Existing archive contains an unexpected or duplicate entry.'
                }
                $input = $entry.Open()
                try { $digest = Get-LogHash $input } finally { $input.Dispose() }
                $expected[$entry.FullName] = @{ Hash = $digest; Length = $entry.Length }
                $copy = $newZip.CreateEntry($entry.FullName, [IO.Compression.CompressionLevel]::Optimal)
                $input = $entry.Open(); $output = $copy.Open()
                try { $input.CopyTo($output) } finally { $output.Dispose(); $input.Dispose() }
            }
        }
        foreach ($source in $sources) {
            $entryName = $source.Name
            if ($expected.ContainsKey($entryName)) {
                if ($expected[$entryName].Hash -ceq $source.Hash -and $expected[$entryName].Length -eq $source.Length) { continue }
                # A recreated daily log after archival must not replace earlier
                # events. Preserve it as a distinct content-addressed fragment.
                $entryName = $source.Name.Substring(0, $source.Name.Length - 6) + '.part-' + $source.Hash + '.jsonl'
                if ($expected.ContainsKey($entryName)) {
                    if ($expected[$entryName].Hash -cne $source.Hash -or $expected[$entryName].Length -ne $source.Length) {
                        throw 'Conflicting content-addressed archive fragment.'
                    }
                    continue
                }
            }
            $entry = $newZip.CreateEntry($entryName, [IO.Compression.CompressionLevel]::Optimal)
            $output = $entry.Open()
            try { $source.Stream.CopyTo($output) } finally { $output.Dispose() }
            $expected[$entryName] = @{ Hash = $source.Hash; Length = $source.Length }
        }
        $newZip.Dispose(); $newZip = $null
        $newStream.Dispose(); $newStream = $null
        Test-MonthArchive $temporary $Month $expected
        if ($null -ne $oldZip) { $oldZip.Dispose(); $oldZip = $null }
        if ($null -ne $oldStream) { $oldStream.Dispose(); $oldStream = $null }
        if ([IO.File]::Exists($destination)) {
            # Same-directory replacement keeps the previous valid archive until
            # the fully written, verified replacement is ready.
            [IO.File]::Replace($temporary, $destination, [System.Management.Automation.Language.NullString]::Value)
        } else {
            [IO.File]::Move($temporary, $destination)
        }
        $published = $true
        foreach ($source in $sources) { $source.Stream.Dispose() }
        foreach ($source in $sources) {
            Assert-LogPath $source.Path
            # Reopen without write sharing, recheck, then delete with delete
            # sharing explicitly allowed (required by Windows for an open file).
            $input = [IO.File]::Open($source.Path, [IO.FileMode]::Open, [IO.FileAccess]::Read,
                ([IO.FileShare]::Read -bor [IO.FileShare]::Delete))
            try {
                if ($input.Length -ne $source.Length -or (Get-LogHash $input) -cne $source.Hash) {
                    throw 'Source changed after archive creation; original retained.'
                }
                [IO.File]::Delete($source.Path)
                $deleted++
            }
            finally { $input.Dispose() }
        }
        return $deleted
    }
    finally {
        if ($null -ne $newZip) { $newZip.Dispose() }
        if ($null -ne $newStream) { $newStream.Dispose() }
        if ($null -ne $oldZip) { $oldZip.Dispose() }
        if ($null -ne $oldStream) { $oldStream.Dispose() }
        foreach ($source in $sources) { $source.Stream.Dispose() }
        if (-not $published -and [IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
    }
}

function Invoke-LogMaintenance {
    param([Parameter(Mandatory = $true)][string]$LogDirectory, [DateTime]$NowUtc = [DateTime]::UtcNow)
    if ($NowUtc.Kind -eq [DateTimeKind]::Local) { $NowUtc = $NowUtc.ToUniversalTime() }
    elseif ($NowUtc.Kind -eq [DateTimeKind]::Unspecified) { $NowUtc = [DateTime]::SpecifyKind($NowUtc, [DateTimeKind]::Utc) }
    $directory = Get-Item -LiteralPath $LogDirectory -Force
    if (-not $directory.PSIsContainer -or $null -eq $directory.Parent) { throw 'A dedicated existing log directory is required.' }
    Assert-LogPath $directory.FullName
    $archiveDirectory = Join-Path $directory.FullName 'archive'
    $lockPath = Join-Path $directory.FullName '.maintenance.lock'
    if (Test-Path -LiteralPath $lockPath) { Assert-LogPath $lockPath }
    $lock = [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try {
        if (-not (Test-Path -LiteralPath $archiveDirectory)) { $null = New-Item -ItemType Directory -Path $archiveDirectory }
        Assert-LogPath $archiveDirectory
        if (-not (Get-Item -LiteralPath $archiveDirectory -Force).PSIsContainer) { throw 'The archive path must be a directory.' }
        foreach ($item in @(Get-ChildItem -LiteralPath $directory.FullName -Force) + @(Get-ChildItem -LiteralPath $archiveDirectory -Force)) {
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse point found inside the log directory.' }
        }
        Add-Type -AssemblyName System.IO.Compression
        $cutoff = $NowUtc.Date.AddYears(-3)
        $currentMonth = $NowUtc.ToString('yyyy-MM')
        $summary = @{ utc = $NowUtc.ToString('o'); archivedMonths = 0; archivedFiles = 0; removedRaw = 0; removedArchives = 0; removedTemporary = 0; failed = 0; errors = @() }
        # The exclusive maintenance lock proves no other instance is building a
        # candidate now. A previous interrupted candidate has never authorized
        # deletion of its raw sources, so it can safely be rebuilt from them.
        foreach ($file in @(Get-ChildItem -LiteralPath $archiveDirectory -File -Force)) {
            if ($file.Name -cnotmatch '^\.agent-(\d{4}-\d{2})\.[a-f0-9]{32}\.tmp$') { continue }
            $month = Get-LogMonth ('agent-' + $Matches[1] + '.zip')
            if ($null -eq $month) { continue }
            try { [IO.File]::Delete($file.FullName); $summary.removedTemporary++ }
            catch { $summary.failed++; if ($summary.errors.Count -lt 10) { $summary.errors += @{ code = 'temporary_cleanup_failed'; period = $month.ToString('yyyy-MM') } } }
        }
        $months = @{}
        foreach ($file in @(Get-ChildItem -LiteralPath $directory.FullName -File)) {
            if ($file.Name -cnotmatch '^agent-\d{4}-\d{2}-\d{2}\.jsonl$') { continue }
            $date = Get-LogDate $file.Name
            if ($null -eq $date) { continue }
            if ($date -lt $cutoff) {
                try { [IO.File]::Delete($file.FullName); $summary.removedRaw++ }
                catch { $summary.failed++; if ($summary.errors.Count -lt 10) { $summary.errors += @{ code = 'retention_raw_failed'; period = $date.ToString('yyyy-MM-dd') } } }
                continue
            }
            $month = $date.ToString('yyyy-MM')
            if ([string]::CompareOrdinal($month, $currentMonth) -ge 0) { continue }
            if (-not $months.ContainsKey($month)) { $months[$month] = @() }
            $months[$month] += $file
        }
        foreach ($month in @($months.Keys | Sort-Object)) {
            try {
                $summary.archivedFiles += Publish-LogMonth $archiveDirectory $month $months[$month]
                $summary.archivedMonths++
            }
            catch { $summary.failed++; if ($summary.errors.Count -lt 10) { $summary.errors += @{ code = 'archive_failed'; period = $month } } }
        }
        foreach ($file in @(Get-ChildItem -LiteralPath $archiveDirectory -File)) {
            $month = Get-LogMonth $file.Name
            if ($null -eq $month -or $month -ge $cutoff -or $month.AddMonths(1) -gt $cutoff) { continue }
            try { [IO.File]::Delete($file.FullName); $summary.removedArchives++ }
            catch { $summary.failed++; if ($summary.errors.Count -lt 10) { $summary.errors += @{ code = 'retention_archive_failed'; period = $month.ToString('yyyy-MM') } } }
        }
        return $summary
    }
    finally { $lock.Dispose() }
}

if (-not $LibraryOnly) {
    try {
        $result = Invoke-LogMaintenance -LogDirectory $LogDirectory
        $result | ConvertTo-Json -Depth 4 -Compress | Write-Output
        if ($result.failed -gt 0) { exit 1 }
    }
    catch {
        Write-Output '{"failed":1,"errors":[{"code":"maintenance_failed"}]}'
        exit 1
    }
}
