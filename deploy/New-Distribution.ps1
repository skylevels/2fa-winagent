#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$CodePath = 'C:\2fa\agent',
    [string]$PhpPath = 'C:\Program Files\PHP\php.exe',
    [string]$DestinationPath = 'C:\2fa\distrib',
    [switch]$LibraryOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression

function Assert-DistributionPlainPath {
    param([string]$Path)
    $item = Get-Item -LiteralPath $Path -Force
    while ($null -ne $item) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Distribution input/output must not use links or reparse points.'
        }
        $item = if ($item -is [IO.DirectoryInfo]) { $item.Parent } else { $item.Directory }
    }
}

function Get-DistributionFiles {
    param([string]$Directory)
    Assert-DistributionPlainPath $Directory
    foreach ($item in Get-ChildItem -LiteralPath $Directory -Force) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'A link was found in the distribution source.'
        }
        if ($item.PSIsContainer) { Get-DistributionFiles $item.FullName }
        else { $item }
    }
}

function Get-DistributionPlan {
    param([string]$AgentDirectory, [string]$PhpDirectory)
    $agentRoot = (Get-Item -LiteralPath $AgentDirectory).FullName.TrimEnd([char[]]@('\', '/'))
    $phpRoot = (Get-Item -LiteralPath $PhpDirectory).FullName.TrimEnd([char[]]@('\', '/'))
    Assert-DistributionPlainPath $agentRoot
    Assert-DistributionPlainPath $phpRoot
    foreach ($relative in @('bin/agent.php', 'bin/agentctl.php', 'bin/export-certificate.php', 'src/LocalAdminServer.php', 'powershell/Directory.ps1', 'powershell/LocalAdmin.ps1', 'vendor/autoload.php', 'deploy/Install-Agent.ps1', 'deploy/Maintain-Logs.ps1', 'deploy/New-Distribution.ps1', 'deploy/Request-AgentCertificate.ps1', 'deploy/Validate-Config.php')) {
        if (-not (Test-Path -LiteralPath (Join-Path $agentRoot $relative) -PathType Leaf)) {
            throw ('Missing required agent distribution file: ' + $relative)
        }
    }
    $plan = New-Object 'System.Collections.Generic.List[object]'
    foreach ($name in @('README.md', 'composer.json', 'composer.lock', 'config.example.json', 'config.dosifey.example.json', 'config.pimen.example.json')) {
        $source = Join-Path $agentRoot $name
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw ('Missing distribution source: ' + $name) }
        Assert-DistributionPlainPath $source
        $plan.Add([pscustomobject]@{ Source = $source; EntryName = ('agent/' + $name) })
    }
    foreach ($name in @('bin', 'src', 'powershell', 'deploy', 'vendor', 'docs', 'tests')) {
        foreach ($file in @(Get-DistributionFiles (Join-Path $agentRoot $name))) {
            $relative = $file.FullName.Substring($agentRoot.Length + 1).Replace('\', '/')
            if ($file.Name -ieq 'config.json' -or $file.Name -match '\.local\.' -or $file.Name -like '.env*' -or
                $file.Extension -match '^\.(pem|pfx|p12|key|crt|cer|der|p7b|p7c|csr|req)$' -or
                $relative -match '(^|/)(tls|\.enrollment-[0-9a-f]+)(/|$)') {
                continue
            }
            $plan.Add([pscustomobject]@{ Source = $file.FullName; EntryName = ('agent/' + $relative) })
        }
    }
    foreach ($name in @('instruction.txt', 'api.txt', 'API.md', 'support-api.md', 'hmac-test-vector.json', 'WINDOWS-VALIDATION.md', 'VALIDATION-RESULTS.md', 'SECURITY-REVIEW.md')) {
        $source = Join-Path (Join-Path $agentRoot 'docs') $name
        if (-not (Test-Path -LiteralPath $source)) {
            if ($name -in @('instruction.txt', 'api.txt')) { throw ('Missing administrator documentation: ' + $name) }
            continue
        }
        Assert-DistributionPlainPath $source
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw ('Administrator documentation must be a file: ' + $name) }
        $plan.Add([pscustomobject]@{ Source = $source; EntryName = ('docs/' + $name) })
    }
    foreach ($name in @('php.exe', 'php.ini-production')) {
        $source = Join-Path $phpRoot $name
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw ('Missing PHP distribution file: ' + $name) }
        Assert-DistributionPlainPath $source
        $plan.Add([pscustomobject]@{ Source = $source; EntryName = ('php/' + $name) })
    }
    # Never export the live php.ini; use the vendor's clean production template.
    # The installation instructions enable OpenSSL in this clean production INI.
    $plan.Add([pscustomobject]@{ Source = (Join-Path $phpRoot 'php.ini-production'); EntryName = 'php/php.ini' })
    foreach ($file in Get-ChildItem -LiteralPath $phpRoot -File -Filter '*.dll') {
        Assert-DistributionPlainPath $file.FullName
        $plan.Add([pscustomobject]@{ Source = $file.FullName; EntryName = ('php/' + $file.Name) })
    }
    foreach ($name in @('LICENSE', 'NEWS', 'README.md', 'README.REDIST.BINS', 'license.txt')) {
        $source = Join-Path $phpRoot $name
        if (Test-Path -LiteralPath $source -PathType Leaf) {
            Assert-DistributionPlainPath $source
            $plan.Add([pscustomobject]@{ Source = $source; EntryName = ('php/' + $name) })
        }
    }
    $extensions = Join-Path $phpRoot 'ext'
    if (Test-Path -LiteralPath $extensions -PathType Container) {
        foreach ($file in @(Get-DistributionFiles $extensions)) {
            if ($file.Extension -ieq '.dll') {
                $plan.Add([pscustomobject]@{ Source = $file.FullName; EntryName = ('php/ext/' + $file.FullName.Substring($extensions.Length + 1).Replace('\', '/')) })
            }
        }
    }
    return $plan.ToArray()
}

function Get-DistributionStreamHash {
    param([IO.Stream]$Stream)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($algorithm.ComputeHash($Stream))).Replace('-', '').ToLowerInvariant() }
    finally { $algorithm.Dispose() }
}

function Assert-DistributionPrivateAcl {
    param($Acl, [string[]]$AllowedSids, [bool]$ParentDirectory = $false)
    # Owners retain implicit permission to change the DACL. A restrictive list
    # of allow rules alone is insufficient if an ordinary user owns the folder.
    $owner = $Acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($AllowedSids -notcontains $owner) {
        throw 'Distribution paths must be owned by administrators or SYSTEM. Reapply installer permissions first.'
    }
    foreach ($rule in $Acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and $AllowedSids -notcontains $rule.IdentityReference.Value) {
            $rights = [int]$rule.FileSystemRights
            # Only traversal is permitted to a technical account on the parent.
            $permitted = if ($ParentDirectory) { [int][Security.AccessControl.FileSystemRights]::Traverse -bor [int][Security.AccessControl.FileSystemRights]::Synchronize } else { 0 }
            if (($rights -band (-bnot $permitted)) -ne 0) { throw 'Distribution paths have broad access permissions. Reapply installer permissions first.' }
        }
    }
}

function New-AgentDistributionArchive {
    param([string]$AgentDirectory, [string]$PhpDirectory, [string]$OutputDirectory)
    Assert-DistributionPlainPath $OutputDirectory
    $plan = @(Get-DistributionPlan $AgentDirectory $PhpDirectory)
    $temporary = Join-Path $OutputDirectory ('.agent-dist-' + [guid]::NewGuid().ToString('N') + '.zip.tmp')
    $target = Join-Path $OutputDirectory 'windows-agent-full.zip'
    $checksum = $target + '.sha256'
    $lockPath = Join-Path $OutputDirectory '.distribution.lock'
    foreach ($path in @($target, $checksum, $lockPath)) {
        if (Test-Path -LiteralPath $path) { Assert-DistributionPlainPath $path }
    }
    $lock = [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try {
        $expected = @{}
        $stream = [IO.File]::Open($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        try {
            $archive = New-Object IO.Compression.ZipArchive($stream, [IO.Compression.ZipArchiveMode]::Create, $true)
            try {
                foreach ($file in $plan) {
                    if ($expected.ContainsKey($file.EntryName)) { throw 'Duplicate distribution archive entry.' }
                    $input = [IO.File]::Open($file.Source, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
                    try {
                        $expected[$file.EntryName] = Get-DistributionStreamHash $input
                        $input.Position = 0
                        $entry = $archive.CreateEntry($file.EntryName, [IO.Compression.CompressionLevel]::Optimal)
                        $output = $entry.Open()
                        try { $input.CopyTo($output) } finally { $output.Dispose() }
                    } finally { $input.Dispose() }
                }
            } finally { $archive.Dispose() }
        } finally { $stream.Dispose() }
        $stream = [IO.File]::OpenRead($temporary)
        try {
            $archive = New-Object IO.Compression.ZipArchive($stream, [IO.Compression.ZipArchiveMode]::Read, $true)
            try {
                if ($archive.Entries.Count -ne $expected.Count) { throw 'Distribution verification failed.' }
                foreach ($entry in $archive.Entries) {
                    $input = $entry.Open()
                    try { $actual = Get-DistributionStreamHash $input } finally { $input.Dispose() }
                    if ($actual -cne $expected[$entry.FullName]) { throw 'Distribution content verification failed.' }
                }
            } finally { $archive.Dispose() }
        } finally { $stream.Dispose() }
        if ([IO.File]::Exists($target)) { [IO.File]::Replace($temporary, $target, [System.Management.Automation.Language.NullString]::Value) }
        else { [IO.File]::Move($temporary, $target) }
        $stream = [IO.File]::OpenRead($target)
        try { $digest = Get-DistributionStreamHash $stream } finally { $stream.Dispose() }
        [IO.File]::WriteAllText($checksum, ($digest + '  windows-agent-full.zip' + [Environment]::NewLine), (New-Object Text.UTF8Encoding $false))
        return [pscustomobject]@{ Archive = $target; Sha256 = $digest; Files = $plan.Count }
    } finally {
        if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
        $lock.Dispose()
    }
}

if (-not $LibraryOnly) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run distribution export from an elevated administrator PowerShell console.' }
    $agentRoot = (Resolve-Path -LiteralPath $CodePath).ProviderPath.TrimEnd('\')
    $destination = (Resolve-Path -LiteralPath $DestinationPath).ProviderPath.TrimEnd('\')
    $phpExecutable = (Resolve-Path -LiteralPath $PhpPath).ProviderPath
    if ($agentRoot -ine 'C:\2fa\agent' -or $destination -ine 'C:\2fa\distrib' -or [IO.Path]::GetFileName($phpExecutable) -ine 'php.exe') {
        throw 'Use C:\2fa\agent, C:\2fa\distrib and an installed php.exe runtime.'
    }
    Assert-DistributionPlainPath $destination
    # The installer creates/protects these paths before export. Reject a broad ACL
    # when the export command is invoked separately after installation.
    Import-Module ActiveDirectory -ErrorAction Stop
    $domainSid = (Get-ADDomain).DomainSID.Value
    $allowed = @('S-1-5-18', 'S-1-5-32-544', ($domainSid + '-512'))
    foreach ($path in @('C:\2fa', $destination)) {
        $acl = Get-Acl -LiteralPath $path
        Assert-DistributionPrivateAcl -Acl $acl -AllowedSids $allowed -ParentDirectory ($path -ieq 'C:\2fa')
    }
    New-AgentDistributionArchive $agentRoot (Split-Path -Parent $phpExecutable) $destination
}
