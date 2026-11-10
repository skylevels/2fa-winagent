[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/../../powershell/LocalAdmin.ps1" -LibraryOnly
$script:passed = 0
$script:failed = 0
function Test-LocalCase([string]$Name, [scriptblock]$Test) {
    try { & $Test; $script:passed++; Write-Output "PASS $Name" }
    catch { $script:failed++; Write-Output "FAIL ${Name}: $($_.Exception.Message)" }
}
function Assert-Equal($Actual, $Expected) {
    if ($Actual -cne $Expected) { throw "Expected $Expected, got $Actual" }
}
function Assert-Throws([scriptblock]$Action) {
    $didThrow = $false
    try { & $Action } catch { $didThrow = $true }
    if (-not $didThrow) { throw 'Expected rejection.' }
}
function New-TestRequest([string]$Action = 'submit') {
    $request = @{ action = $Action; id = ('a' * 64); nonce = ('b' * 64) }
    if ($Action -ceq 'submit') { $request.command = 'disable'; $request.dryRun = $false }
    return [pscustomobject]$request
}

Test-LocalCase 'local signature uses a separate context and verifies every character' {
    $signature = Get-LocalAdminSignature ('0123456789abcdef' * 4) ('a' * 64) 'e30='
    Assert-Equal $signature 'c9c2fe2b201e9f3e6b8709e6e3bf97c9e75f50bcc068da3c855de0e84b05a742'
    Assert-Equal (Test-LocalAdminSignature $signature $signature) $true
    Assert-Equal (Test-LocalAdminSignature $signature ('0' * 64)) $false
    Assert-Equal (Test-LocalAdminSignature $signature ($signature + '0')) $false
}
Test-LocalCase 'new local submission emits exactly one accepted command' {
    $decision = Get-LocalAdminReply (New-TestRequest) @()
    Assert-Equal $decision.reply.state 'pending'
    Assert-Equal $decision.event.event 'request'
    Assert-Equal $decision.event.command 'disable'
}
Test-LocalCase 'repeated submission returns previous result without another command' {
    $entry = [pscustomobject]@{ id = ('a' * 64); command = 'disable'; dryRun = $false; response = @{ ok = $true; result = @{ status = 'disabled' } } }
    $decision = Get-LocalAdminReply (New-TestRequest) @($entry)
    Assert-Equal $decision.reply.state 'complete'
    Assert-Equal $decision.event.event 'idle'
    Assert-Equal $decision.reply.response.result.status 'disabled'
}
Test-LocalCase 'a reused id with a different command is rejected' {
    $entry = [pscustomobject]@{ id = ('a' * 64); command = 'enable'; dryRun = $false; response = $null }
    Assert-Equal (Get-LocalAdminReply (New-TestRequest) @($entry)).reply.state 'conflict'
}
Test-LocalCase 'unknown polling after restart cannot become a new submission' {
    $decision = Get-LocalAdminReply (New-TestRequest 'get') @()
    Assert-Equal $decision.reply.state 'unknown'
    Assert-Equal $decision.event.event 'idle'
}
Test-LocalCase 'local commands and payload fields are strictly bounded' {
    $request = New-TestRequest
    $request.command = '/v1/admin/disable'
    Assert-Throws { Assert-LocalAdminRequest $request }
    $request = New-TestRequest
    $request.dryRun = 'false'
    Assert-Throws { Assert-LocalAdminRequest $request }
    $request = New-TestRequest
    $request | Add-Member host 'remote.example.test'
    Assert-Throws { Assert-LocalAdminRequest $request }
}
Test-LocalCase 'framed messages read complete UTF8 and reject over-limit input' {
    $stream = [IO.MemoryStream]::new([Text.Encoding]::UTF8.GetBytes("hello`n"))
    try { Assert-Equal (Read-LocalAdminFrame $stream 5) 'hello' } finally { $stream.Dispose() }
    $stream = [IO.MemoryStream]::new([Text.Encoding]::UTF8.GetBytes("too-long`n"))
    try { Assert-Throws { Read-LocalAdminFrame $stream 5 } } finally { $stream.Dispose() }
}
Test-LocalCase 'expired frame deadline rejects data even when already buffered' {
    $stream = [IO.MemoryStream]::new([Text.Encoding]::UTF8.GetBytes("hello`n"))
    try {
        $errorCode = ''
        try { $null = Read-LocalAdminFrame $stream 5 0 } catch { $errorCode = $_.Exception.Message }
        Assert-Equal $errorCode 'pipe_read_timeout'
    } finally { $stream.Dispose() }
}
Test-LocalCase 'client submits once then polls a command that remains running' {
    function Assert-LocalAdminElevated {}
    $script:actions = @()
    function Invoke-LocalAdminExchange($Name, $SecretHex, $Request) {
        $script:actions += $Request.action
        if ($script:actions.Count -eq 1) { return [pscustomobject]@{ state = 'pending' } }
        return [pscustomobject]@{ state = 'complete'; response = @{ ok = $true; result = @{ status = 'disabled' } } }
    }
    $result = Invoke-LocalAdminClient ('Elemer-2FA-' + ('0' * 64)) ([pscustomobject]@{ secretHex = ('0123456789abcdef' * 4); command = 'disable'; dryRun = $false }) 5
    Assert-Equal ($script:actions -join ',') 'submit,get'
    Assert-Equal $result.result.status 'disabled'
}
Test-LocalCase 'client never re-submits an uncertain command after a lost receipt' {
    function Assert-LocalAdminElevated {}
    $script:actions = @()
    function Invoke-LocalAdminExchange($Name, $SecretHex, $Request) {
        $script:actions += $Request.action
        if ($script:actions.Count -eq 1) { throw 'pipe_closed' }
        return [pscustomobject]@{ state = 'unknown' }
    }
    Assert-Throws { Invoke-LocalAdminClient ('Elemer-2FA-' + ('0' * 64)) ([pscustomobject]@{ secretHex = ('0123456789abcdef' * 4); command = 'disable'; dryRun = $false }) 5 }
    Assert-Equal ($script:actions -join ',') 'submit,get'
}
Test-LocalCase 'client may retry a connection that never transmitted a command' {
    function Assert-LocalAdminElevated {}
    $script:actions = @()
    function Invoke-LocalAdminExchange($Name, $SecretHex, $Request) {
        $script:actions += $Request.action
        if ($script:actions.Count -eq 1) { throw 'local_connect_unavailable' }
        return [pscustomobject]@{ state = 'complete'; response = @{ ok = $true; result = @{ status = 'disabled' } } }
    }
    $null = Invoke-LocalAdminClient ('Elemer-2FA-' + ('0' * 64)) ([pscustomobject]@{ secretHex = ('0123456789abcdef' * 4); command = 'disable'; dryRun = $false }) 5
    Assert-Equal ($script:actions -join ',') 'submit,submit'
}
Test-LocalCase 'pending command polling stops at the elapsed timeout without resubmitting' {
    function Assert-LocalAdminElevated {}
    $script:actions = @()
    function Invoke-LocalAdminExchange($Name, $SecretHex, $Request) {
        $script:actions += $Request.action
        return [pscustomobject]@{ state = 'pending' }
    }
    $elapsed = [Diagnostics.Stopwatch]::StartNew()
    $errorCode = ''
    try { $null = Invoke-LocalAdminClient ('Elemer-2FA-' + ('0' * 64)) ([pscustomobject]@{ secretHex = ('0123456789abcdef' * 4); command = 'disable'; dryRun = $false }) 1 }
    catch { $errorCode = $_.Exception.Message }
    Assert-Equal $errorCode 'local_command_timeout_operation_may_continue_check_status'
    Assert-Equal ($elapsed.Elapsed.TotalSeconds -lt 2.5) $true
    Assert-Equal @($script:actions | Where-Object { $_ -eq 'submit' }).Count 1
}
if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
    Test-LocalCase 'named pipe ACL rejects NETWORK and does not grant ordinary users' {
        $acl = New-LocalAdminPipeSecurity
        $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
        $network = @($rules | Where-Object { $_.IdentityReference.Value -eq 'S-1-5-2' -and $_.AccessControlType -eq 'Deny' })
        Assert-Equal $network.Count 1
        foreach ($broadSid in @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545')) {
            Assert-Equal @($rules | Where-Object { $_.IdentityReference.Value -eq $broadSid -and $_.AccessControlType -eq 'Allow' }).Count 0
        }
        Assert-Equal $acl.AreAccessRulesProtected $true
    }
} else { Write-Output 'SKIP Windows named-pipe ACL / actual elevated-client integration; run on the target Windows DC.' }
Write-Output "$script:passed tests passed, $script:failed failed."
if ($script:failed -gt 0) { exit 1 }
