#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\..\deploy\Maintain-Logs.ps1') -LibraryOnly
Add-Type -AssemblyName System.IO.Compression
$script:count = 0
$script:root = Join-Path ([IO.Path]::GetTempPath()) ('2fa-log-tests-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $script:root
$script:now = [DateTime]::SpecifyKind([DateTime]'2026-11-05T10:00:00', [DateTimeKind]::Utc)

function Assert-Equal($Actual, $Expected) {
    if ($Actual -cne $Expected) { throw "Expected [$Expected], got [$Actual]" }
}
function New-Fixture {
    $path = Join-Path $script:root ([guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $path
    return $path
}
function Write-Raw([string]$Path, [string]$Name, [string]$Text) {
    [IO.File]::WriteAllText((Join-Path $Path $Name), $Text, (New-Object Text.UTF8Encoding($false)))
}
function Read-Zip([string]$Path) {
    $s = [IO.File]::OpenRead($Path)
    $z = New-Object IO.Compression.ZipArchive($s, [IO.Compression.ZipArchiveMode]::Read, $true)
    try {
        $result = @{}
        foreach ($entry in $z.Entries) {
            $input = $entry.Open(); $reader = New-Object IO.StreamReader($input)
            try { $result[$entry.FullName] = $reader.ReadToEnd() } finally { $reader.Dispose(); $input.Dispose() }
        }
        return $result
    } finally { $z.Dispose(); $s.Dispose() }
}
function Test-Case([string]$Name, [scriptblock]$Body) {
    & $Body
    $script:count++
    Write-Output ('PASS ' + $Name)
}

try {
    Test-Case 'completed UTC month is zipped and verified before originals disappear' {
        $p = New-Fixture
        Write-Raw $p 'agent-2026-10-01.jsonl' "first`n"
        Write-Raw $p 'agent-2026-10-31.jsonl' "last`n"
        $r = Invoke-LogMaintenance $p $script:now
        Assert-Equal $r.failed 0
        Assert-Equal $r.archivedFiles 2
        Assert-Equal (Test-Path (Join-Path $p 'agent-2026-10-01.jsonl')) $false
        $entries = Read-Zip (Join-Path $p 'archive/agent-2026-10.zip')
        Assert-Equal $entries.Count 2
        Assert-Equal $entries['agent-2026-10-31.jsonl'] "last`n"
    }
    Test-Case 'current and future months remain raw' {
        $p = New-Fixture
        Write-Raw $p 'agent-2026-11-01.jsonl' 'current'
        Write-Raw $p 'agent-2026-12-01.jsonl' 'future'
        $r = Invoke-LogMaintenance $p $script:now
        Assert-Equal $r.archivedFiles 0
        Assert-Equal (Test-Path (Join-Path $p 'agent-2026-11-01.jsonl')) $true
        Assert-Equal (Test-Path (Join-Path $p 'agent-2026-12-01.jsonl')) $true
    }
    Test-Case 'late daily file is merged without losing existing archived day' {
        $p = New-Fixture
        Write-Raw $p 'agent-2026-10-01.jsonl' 'one'
        $null = Invoke-LogMaintenance $p $script:now
        Write-Raw $p 'agent-2026-10-02.jsonl' 'two'
        $r = Invoke-LogMaintenance $p $script:now
        Assert-Equal $r.failed 0
        $entries = Read-Zip (Join-Path $p 'archive/agent-2026-10.zip')
        Assert-Equal $entries.Count 2
        Assert-Equal $entries['agent-2026-10-01.jsonl'] 'one'
        Assert-Equal $entries['agent-2026-10-02.jsonl'] 'two'
    }
    Test-Case 'retry after publication before source deletion does not duplicate data' {
        $p = New-Fixture
        Write-Raw $p 'agent-2026-10-01.jsonl' 'same'
        $null = Invoke-LogMaintenance $p $script:now
        Write-Raw $p 'agent-2026-10-01.jsonl' 'same'
        $r = Invoke-LogMaintenance $p $script:now
        Assert-Equal $r.failed 0
        Assert-Equal (Read-Zip (Join-Path $p 'archive/agent-2026-10.zip')).Count 1
        Assert-Equal (Test-Path (Join-Path $p 'agent-2026-10-01.jsonl')) $false
    }
    Test-Case 'different late contents with the same daily name are preserved separately' {
        $p = New-Fixture
        Write-Raw $p 'agent-2026-10-01.jsonl' 'original'
        $null = Invoke-LogMaintenance $p $script:now
        Write-Raw $p 'agent-2026-10-01.jsonl' 'late'
        $r = Invoke-LogMaintenance $p $script:now
        Assert-Equal $r.failed 0
        $entries = Read-Zip (Join-Path $p 'archive/agent-2026-10.zip')
        Assert-Equal $entries.Count 2
        Assert-Equal $entries['agent-2026-10-01.jsonl'] 'original'
        Assert-Equal @($entries.Values | Where-Object { $_ -ceq 'late' }).Count 1
        Write-Raw $p 'agent-2026-10-01.jsonl' 'late'
        $null = Invoke-LogMaintenance $p $script:now
        Assert-Equal (Read-Zip (Join-Path $p 'archive/agent-2026-10.zip')).Count 2
    }
    Test-Case 'corrupt existing archive is retained and raw files are not deleted' {
        $p = New-Fixture
        $null = New-Item -ItemType Directory -Path (Join-Path $p 'archive')
        Write-Raw (Join-Path $p 'archive') 'agent-2026-10.zip' 'broken-zip'
        Write-Raw $p 'agent-2026-10-01.jsonl' 'must-survive'
        $r = Invoke-LogMaintenance $p $script:now
        Assert-Equal $r.failed 1
        Assert-Equal ([IO.File]::ReadAllText((Join-Path $p 'archive/agent-2026-10.zip'))) 'broken-zip'
        Assert-Equal ([IO.File]::ReadAllText((Join-Path $p 'agent-2026-10-01.jsonl'))) 'must-survive'
        Assert-Equal @(Get-ChildItem (Join-Path $p 'archive') -Force -Filter '*.tmp').Count 0
    }
    Test-Case 'retention uses UTC period not refreshed file modification dates' {
        $p = New-Fixture
        $null = New-Item -ItemType Directory -Path (Join-Path $p 'archive')
        Write-Raw $p 'agent-2023-11-04.jsonl' 'expired'
        Write-Raw $p 'agent-2023-11-05.jsonl' 'boundary'
        Write-Raw (Join-Path $p 'archive') 'agent-2023-10.zip' 'expired archive placeholder'
        Write-Raw (Join-Path $p 'archive') 'agent-2023-12.zip' 'retained archive placeholder'
        $r = Invoke-LogMaintenance $p $script:now
        Assert-Equal $r.removedRaw 1
        Assert-Equal $r.removedArchives 1
        Assert-Equal (Test-Path (Join-Path $p 'archive/agent-2023-10.zip')) $false
        Assert-Equal (Test-Path (Join-Path $p 'archive/agent-2023-12.zip')) $true
        Assert-Equal (Read-Zip (Join-Path $p 'archive/agent-2023-11.zip'))['agent-2023-11-05.jsonl'] 'boundary'
    }
    Test-Case 'leap-year retention uses three calendar years' {
        $p = New-Fixture
        Write-Raw $p 'agent-2025-02-27.jsonl' 'expired'
        Write-Raw $p 'agent-2025-02-28.jsonl' 'boundary'
        $r = Invoke-LogMaintenance $p ([DateTime]'2028-02-29T12:00:00Z')
        Assert-Equal $r.removedRaw 1
        Assert-Equal (Read-Zip (Join-Path $p 'archive/agent-2025-02.zip'))['agent-2025-02-28.jsonl'] 'boundary'
    }
    Test-Case 'unrelated names and invalid dates are never deleted or archived' {
        $p = New-Fixture
        Write-Raw $p 'notes.txt' 'keep'
        Write-Raw $p 'agent-2020-99-99.jsonl' 'keep'
        Write-Raw $p 'other-2020-01-01.jsonl' 'keep'
        $null = New-Item -ItemType Directory -Path (Join-Path $p 'archive')
        Write-Raw (Join-Path $p 'archive') 'backup-2020-01.zip' 'keep'
        $r = Invoke-LogMaintenance $p $script:now
        Assert-Equal $r.archivedFiles 0
        Assert-Equal $r.removedRaw 0
        Assert-Equal $r.removedArchives 0
        Assert-Equal (Test-Path (Join-Path $p 'notes.txt')) $true
        Assert-Equal (Test-Path (Join-Path $p 'archive/backup-2020-01.zip')) $true
    }
    Test-Case 'exclusive maintenance lock prevents two concurrent runs' {
        $p = New-Fixture
        $lock = [IO.File]::Open((Join-Path $p '.maintenance.lock'), [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        try {
            $failed = $false
            try { $null = Invoke-LogMaintenance $p $script:now } catch { $failed = $true }
            Assert-Equal $failed $true
        } finally { $lock.Dispose() }
    }
    Test-Case 'archive path must be a directory' {
        $p = New-Fixture
        Write-Raw $p 'archive' 'not a directory'
        $failed = $false
        try { $null = Invoke-LogMaintenance $p $script:now } catch { $failed = $true }
        Assert-Equal $failed $true
        Assert-Equal ([IO.File]::ReadAllText((Join-Path $p 'archive'))) 'not a directory'
    }
    Test-Case 'interrupted own temporary archive is removed without touching unrelated files' {
        $p = New-Fixture
        $null = New-Item -ItemType Directory -Path (Join-Path $p 'archive')
        $name = '.agent-2026-10.' + [guid]::NewGuid().ToString('N') + '.tmp'
        Write-Raw (Join-Path $p 'archive') $name 'interrupted candidate'
        Write-Raw (Join-Path $p 'archive') 'unrelated.tmp' 'keep'
        Write-Raw (Join-Path $p 'archive') 'agent-9999-12.zip' 'future keep'
        $r = Invoke-LogMaintenance $p $script:now
        Assert-Equal $r.failed 0
        Assert-Equal $r.removedTemporary 1
        Assert-Equal (Test-Path (Join-Path $p ('archive/' + $name))) $false
        Assert-Equal (Test-Path (Join-Path $p 'archive/unrelated.tmp')) $true
        Assert-Equal (Test-Path (Join-Path $p 'archive/agent-9999-12.zip')) $true
    }
    Test-Case 'one damaged month does not prevent another month being archived' {
        $p = New-Fixture
        $null = New-Item -ItemType Directory -Path (Join-Path $p 'archive')
        Write-Raw (Join-Path $p 'archive') 'agent-2026-09.zip' 'broken'
        Write-Raw $p 'agent-2026-09-01.jsonl' 'preserve'
        Write-Raw $p 'agent-2026-10-01.jsonl' 'archive'
        $r = Invoke-LogMaintenance $p $script:now
        Assert-Equal $r.failed 1
        Assert-Equal $r.archivedMonths 1
        Assert-Equal (Read-Zip (Join-Path $p 'archive/agent-2026-10.zip'))['agent-2026-10-01.jsonl'] 'archive'
    }
    Test-Case 'root symlinks are rejected rather than followed' {
        if ($env:OS -eq 'Windows_NT') { return }
        $target = New-Fixture
        $link = Join-Path $script:root ('link-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType SymbolicLink -Path $link -Target $target
        $failed = $false
        try { $null = Invoke-LogMaintenance $link $script:now } catch { $failed = $true }
        Assert-Equal $failed $true
    }
    Write-Output ('Passed ' + $script:count + ' log-maintenance tests (temporary files only).')
}
finally {
    Remove-Item -LiteralPath $script:root -Recurse -Force
}
