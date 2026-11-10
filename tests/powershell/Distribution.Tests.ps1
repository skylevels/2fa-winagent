#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\..\deploy\New-Distribution.ps1') -LibraryOnly
$root = Join-Path ([IO.Path]::GetTempPath()) ('2fa-distribution-tests-' + [guid]::NewGuid().ToString('N'))
$count = 0
function Assert-Equal($Actual, $Expected) {
    if ($Actual -cne $Expected) { throw ('Expected [' + $Expected + '], got [' + $Actual + ']') }
}
function Write-Fixture([string]$Path, [string]$Value = 'public source') {
    $parent = Split-Path -Parent $Path
    if (-not [IO.Directory]::Exists($parent)) { $null = [IO.Directory]::CreateDirectory($parent) }
    [IO.File]::WriteAllText($Path, $Value, (New-Object Text.UTF8Encoding $false))
}
function Read-Distribution([string]$Path) {
    $stream = [IO.File]::OpenRead($Path)
    $archive = New-Object IO.Compression.ZipArchive($stream, [IO.Compression.ZipArchiveMode]::Read, $true)
    try {
        $entries = @{}
        foreach ($entry in $archive.Entries) {
            $reader = New-Object IO.StreamReader($entry.Open())
            try { $entries[$entry.FullName] = $reader.ReadToEnd() } finally { $reader.Dispose() }
        }
        return $entries
    } finally { $archive.Dispose(); $stream.Dispose() }
}

function New-AclFixture([string]$OwnerSid, [string]$AllowedSid, [Security.AccessControl.FileSystemRights]$Rights) {
    # Fake descriptors exercise validation on any OS. Effective NTFS access
    # and ownership still require the Windows deployment acceptance checks.
    $acl = [pscustomobject]@{ OwnerSid = $OwnerSid; Rules = @([pscustomobject]@{
        AccessControlType = [Security.AccessControl.AccessControlType]::Allow
        IdentityReference = [pscustomobject]@{ Value = $AllowedSid }
        FileSystemRights = $Rights
    }) }
    $acl | Add-Member -MemberType ScriptMethod -Name GetOwner -Value { param($Type) return [pscustomobject]@{ Value = $this.OwnerSid } }
    $acl | Add-Member -MemberType ScriptMethod -Name GetAccessRules -Value { param($Explicit, $Inherited, $Type) return $this.Rules }
    return $acl
}

try {
    $agent = Join-Path $root 'agent'; $php = Join-Path $root 'php'; $output = Join-Path $root 'distrib'
    $null = [IO.Directory]::CreateDirectory($output)
    foreach ($name in @('README.md', 'composer.json', 'composer.lock', 'config.example.json', 'config.dosifey.example.json', 'config.pimen.example.json')) {
        Write-Fixture (Join-Path $agent $name)
    }
    foreach ($name in @('bin', 'src', 'powershell', 'deploy', 'vendor', 'docs', 'tests')) {
        Write-Fixture (Join-Path (Join-Path $agent $name) 'public.txt')
    }
    foreach ($relative in @('bin/agent.php', 'bin/agentctl.php', 'bin/export-certificate.php', 'src/LocalAdminServer.php', 'powershell/Directory.ps1', 'powershell/LocalAdmin.ps1', 'vendor/autoload.php', 'deploy/Install-Agent.ps1', 'deploy/Maintain-Logs.ps1', 'deploy/New-Distribution.ps1', 'deploy/Request-AgentCertificate.ps1', 'deploy/Validate-Config.php')) {
        Write-Fixture (Join-Path $agent $relative)
    }
    Write-Fixture (Join-Path $agent 'docs/instruction.txt') 'DokuWiki instruction'
    Write-Fixture (Join-Path $agent 'docs/api.txt') 'DokuWiki API'
    Write-Fixture (Join-Path $agent 'config.json') 'SECRET_LIVE_AGENT_CONFIG'
    Write-Fixture (Join-Path $agent 'config.local.json') 'SECRET_LOCAL_CONFIG'
    Write-Fixture (Join-Path $agent 'logs/private.log') 'SECRET_LOG'
    Write-Fixture (Join-Path $agent '.env') 'SECRET_ENV'
    Write-Fixture (Join-Path $agent 'src/.env') 'SECRET_NESTED_ENV'
    Write-Fixture (Join-Path $agent 'tls/agent.key.pem') 'SECRET_SERVER_KEY'
    Write-Fixture (Join-Path $agent 'tls/agent.crt.pem') 'SECRET_SERVER_CERTIFICATE'
    Write-Fixture (Join-Path $agent 'docs/accidental-key.pem') 'SECRET_NESTED_KEY'
    Write-Fixture (Join-Path $agent 'docs/tls/copy.txt') 'SECRET_NESTED_TLS'
    Write-Fixture (Join-Path $php 'php.exe') 'runtime executable fixture'
    Write-Fixture (Join-Path $php 'php8.dll') 'runtime dll fixture'
    Write-Fixture (Join-Path $php 'ext/php_test.dll') 'extension fixture'
    Write-Fixture (Join-Path $php 'php.ini-production') 'clean production template'
    Write-Fixture (Join-Path $php 'php.ini') 'SECRET_CUSTOM_PHP_CONFIG'
    Write-Fixture (Join-Path $php 'php_errors.log') 'SECRET_PHP_LOG'
    $result = New-AgentDistributionArchive $agent $php $output
    $entries = Read-Distribution $result.Archive
    foreach ($name in @('agent/config.example.json', 'agent/vendor/autoload.php', 'agent/bin/agentctl.php', 'agent/src/LocalAdminServer.php', 'agent/powershell/LocalAdmin.ps1', 'php/php.exe', 'php/php8.dll', 'php/ext/php_test.dll', 'docs/instruction.txt', 'docs/api.txt')) {
        Assert-Equal $entries.ContainsKey($name) $true
    }
    Assert-Equal $entries['php/php.ini'] 'clean production template'
    $count++; Write-Output 'PASS distribution contains code dependencies runtime templates and DokuWiki docs'
    Assert-Equal (($entries.Values -join '') -match 'SECRET_') $false
    Assert-Equal $entries.ContainsKey('agent/config.json') $false
    Assert-Equal $entries.ContainsKey('php/php_errors.log') $false
    Assert-Equal $entries.ContainsKey('agent/tls/agent.key.pem') $false
    Assert-Equal $entries.ContainsKey('agent/docs/accidental-key.pem') $false
    Assert-Equal $entries.ContainsKey('agent/docs/tls/copy.txt') $false
    $count++; Write-Output 'PASS working secrets log files and live php.ini never enter the archive'
    $hash = (Get-FileHash -LiteralPath $result.Archive -Algorithm SHA256).Hash.ToLowerInvariant()
    Assert-Equal $result.Sha256 $hash
    Assert-Equal ([IO.File]::ReadAllText($result.Archive + '.sha256').Trim()) ($hash + '  windows-agent-full.zip')
    $count++; Write-Output 'PASS published checksum matches verified distribution bytes'
    $additionalDocs = @('API.md', 'hmac-test-vector.json', 'WINDOWS-VALIDATION.md', 'VALIDATION-RESULTS.md', 'SECURITY-REVIEW.md')
    foreach ($name in $additionalDocs) {
        Write-Fixture (Join-Path (Join-Path $agent 'docs') $name) ($name + ' public documentation')
    }
    $updatedDocs = Read-Distribution (New-AgentDistributionArchive $agent $php $output).Archive
    foreach ($name in $additionalDocs) {
        Assert-Equal $updatedDocs[('docs/' + $name)] ($name + ' public documentation')
        Assert-Equal $updatedDocs[('agent/docs/' + $name)] $updatedDocs[('docs/' + $name)]
    }
    $count++; Write-Output 'PASS optional API and validation documents are identical in root docs and agent docs'
    Write-Fixture (Join-Path $agent 'src/public.txt') 'new release'
    $result2 = New-AgentDistributionArchive $agent $php $output
    Assert-Equal (Read-Distribution $result2.Archive)['agent/src/public.txt'] 'new release'
    $count++; Write-Output 'PASS rebuilding replaces an existing distribution successfully'
    $previousHash = (Get-FileHash -LiteralPath $result2.Archive).Hash
    [IO.File]::Delete((Join-Path $php 'php.ini-production'))
    $failed = $false
    try { $null = New-AgentDistributionArchive $agent $php $output } catch { $failed = $true }
    Assert-Equal $failed $true
    Assert-Equal (Get-FileHash -LiteralPath $result2.Archive).Hash $previousHash
    $count++; Write-Output 'PASS missing runtime input fails without replacing the previous distribution'
    Write-Fixture (Join-Path $php 'php.ini-production') 'clean production template'
    [IO.File]::Delete((Join-Path $agent 'powershell/LocalAdmin.ps1'))
    $failed = $false
    try { $null = New-AgentDistributionArchive $agent $php $output } catch { $failed = $true }
    Assert-Equal $failed $true
    Assert-Equal (Get-FileHash -LiteralPath $result2.Archive).Hash $previousHash
    $count++; Write-Output 'PASS missing local console transport fails without replacing the previous distribution'
    $privateSids = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-21-1-2-3-512')
    $acl = New-AclFixture 'S-1-5-32-544' 'S-1-5-18' FullControl
    Assert-DistributionPrivateAcl $acl $privateSids
    $count++; Write-Output 'PASS administrator-owned restricted distribution directory is accepted'
    $acl = New-AclFixture 'S-1-5-21-1-2-3-1001' 'S-1-5-18' FullControl
    $failed = $false
    try { Assert-DistributionPrivateAcl $acl $privateSids } catch { $failed = $true }
    Assert-Equal $failed $true
    $count++; Write-Output 'PASS ordinary owner is rejected even with a restricted distribution DACL'
    $acl = New-AclFixture 'S-1-5-32-544' 'S-1-5-21-1-2-3-1002' Traverse
    Assert-DistributionPrivateAcl $acl $privateSids -ParentDirectory $true
    $failed = $false
    try { Assert-DistributionPrivateAcl $acl $privateSids } catch { $failed = $true }
    Assert-Equal $failed $true
    $acl = New-AclFixture 'S-1-5-32-544' 'S-1-5-21-1-2-3-1002' Read
    $failed = $false
    try { Assert-DistributionPrivateAcl $acl $privateSids -ParentDirectory $true } catch { $failed = $true }
    Assert-Equal $failed $true
    $count++; Write-Output 'PASS technical-account traversal is confined to the parent and cannot grant read access'
    Write-Output ('Passed ' + $count + ' distribution tests.')
} finally {
    if ([IO.Directory]::Exists($root)) { Remove-Item -LiteralPath $root -Recurse -Force }
}
