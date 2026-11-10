#Requires -Version 5.1
# Real NTFS ACL checks on an isolated temporary tree; never changes the domain.
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') {
    Write-Output 'SKIP actual NTFS ACL tests: Windows is required.'
    return
}
. (Join-Path $PSScriptRoot '..\..\deploy\Install-Agent.ps1') -LibraryOnly
Assert-AgentAdministrator

$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('2fa-acl-test-' + [guid]::NewGuid().ToString('N'))
$domainAdminsSid = New-Object Security.Principal.SecurityIdentifier 'S-1-5-21-111-222-333-512'
$serviceSid = New-Object Security.Principal.SecurityIdentifier 'S-1-5-21-111-222-333-1234'
$count = 0

function Assert-PrivateAcl {
    param([string]$Path, [bool]$ExpectService, [string]$Rights = 'ReadAndExecute')
    $acl = Get-Acl -LiteralPath $Path
    if (-not $acl.AreAccessRulesProtected) { throw 'Inheritance remains enabled.' }
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    $allowed = @('S-1-5-18', 'S-1-5-32-544', $domainAdminsSid.Value)
    if ($ExpectService) { $allowed += $serviceSid.Value }
    foreach ($rule in $rules) {
        if ($rule.IsInherited -or $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or $rule.IdentityReference.Value -notin $allowed) {
            throw 'Unexpected inherited, deny, or broad access rule remains.'
        }
        if ($rule.IdentityReference.Value -eq $serviceSid.Value) {
            $requested = [Security.AccessControl.FileSystemRights]$Rights
            if (($rule.FileSystemRights -band $requested) -ne $requested) { throw 'Service rights are missing.' }
            if ($Rights -ne 'Modify' -and ($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::WriteData) -ne 0) {
                throw 'Service unexpectedly has write access.'
            }
            if ($Rights -eq 'Traverse' -and $rule.InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]::None) {
                throw 'Parent traversal must not propagate to unrelated children.'
            }
        }
    }
    foreach ($sid in $allowed) {
        if (@($rules | Where-Object { $_.IdentityReference.Value -eq $sid }).Count -ne 1) { throw ('Missing or duplicate SID rule: ' + $sid) }
    }
}

try {
    $null = New-Item -Path $testRoot -ItemType Directory
    foreach ($name in @('agent', 'logs', 'docs')) {
        $path = Join-Path $testRoot $name
        $null = New-Item -Path $path -ItemType Directory
        Set-Content -LiteralPath (Join-Path $path 'sample.txt') -Value 'test'
        $acl = Get-Acl -LiteralPath $path
        $broad = New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier 'S-1-1-0'), 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($broad)
        Set-Acl -LiteralPath $path -AclObject $acl
    }
    Set-AgentPrivateAcl -Path $testRoot -DomainAdminsSid $domainAdminsSid -RunSid $serviceSid -ServiceRights Traverse -Recurse $false
    Assert-PrivateAcl $testRoot $true Traverse
    $count++; Write-Output 'PASS parent permits only admins/SYSTEM and non-inheriting service traversal'
    Set-AgentPrivateAcl -Path (Join-Path $testRoot 'agent') -DomainAdminsSid $domainAdminsSid -RunSid $serviceSid
    Assert-PrivateAcl (Join-Path $testRoot 'agent') $true
    Assert-PrivateAcl (Join-Path $testRoot 'agent\sample.txt') $true
    $count++; Write-Output 'PASS explicit and inherited broad code access is removed recursively'
    Set-AgentPrivateAcl -Path (Join-Path $testRoot 'logs') -DomainAdminsSid $domainAdminsSid -RunSid $serviceSid -ServiceRights Modify
    Assert-PrivateAcl (Join-Path $testRoot 'logs') $true Modify
    Assert-PrivateAcl (Join-Path $testRoot 'logs\sample.txt') $true Modify
    $count++; Write-Output 'PASS service can modify only the log tree'
    Set-AgentPrivateAcl -Path (Join-Path $testRoot 'docs') -DomainAdminsSid $domainAdminsSid -RunSid $serviceSid -ServiceRights None
    Assert-PrivateAcl (Join-Path $testRoot 'docs') $false
    Assert-PrivateAcl (Join-Path $testRoot 'docs\sample.txt') $false
    $count++; Write-Output 'PASS documentation admits only administrators and SYSTEM'
    $junction = Join-Path $testRoot 'agent\linked-docs'
    $null = New-Item -ItemType Junction -Path $junction -Target (Join-Path $testRoot 'docs')
    $failed = $false
    try { Set-AgentPrivateAcl -Path (Join-Path $testRoot 'agent') -DomainAdminsSid $domainAdminsSid -RunSid $serviceSid }
    catch { $failed = $true }
    if (-not $failed) { throw 'Junction was not rejected.' }
    $null = [IO.Directory]::Delete($junction)
    Assert-PrivateAcl (Join-Path $testRoot 'docs') $false
    $count++; Write-Output 'PASS junction traversal is refused before changing target ACL'
    Write-Output ('Passed ' + $count + ' Windows ACL tests.')
} finally {
    if (Test-Path -LiteralPath $testRoot) { Remove-Item -LiteralPath $testRoot -Recurse -Force }
}
