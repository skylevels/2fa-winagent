#Requires -Version 5.1
param([string]$PhpPath = 'C:\Program Files\PHP\php.exe')
$ErrorActionPreference = 'Stop'
$testPhpPath = $PhpPath
. (Join-Path $PSScriptRoot '..\..\deploy\Install-Agent.ps1') -LibraryOnly
$PhpPath = $testPhpPath
$script:validatorPath = Join-Path $PSScriptRoot '..\..\deploy\Validate-Config.php'
$root = Join-Path ([IO.Path]::GetTempPath()) ('2fa-install-secret-tests-' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($root)
$configFile = Join-Path $root 'config.json'
$count = 0
$script:taskExists = $false
$script:firewallExists = $false
$script:secretGenerations = 0
$script:generateSecret = ${function:New-AgentApiSecret}
function New-AgentApiSecret { $script:secretGenerations++; & $script:generateSecret }
function Get-ScheduledTask {
    [CmdletBinding()]param([string]$TaskName, [string]$TaskPath)
    if ($script:taskExists) { [pscustomobject]@{ TaskName = $TaskName } }
}
function Get-NetFirewallRule {
    [CmdletBinding()]param([string]$Name)
    if ($script:firewallExists) { [pscustomobject]@{ Name = $Name } }
}
function Assert-True($Value, [string]$Message) { if (-not $Value) { throw $Message } }
function Assert-Rejected([scriptblock]$Operation) {
    $failed = $false
    try { & $Operation } catch { $failed = $true }
    Assert-True $failed 'Expected installation failure.'
}
function New-ConfigFixture {
    return [pscustomobject]@{ agentId = 'dosifey'; domainController = 'dosifey.elemer.org'; allowedIPs = @('192.0.2.10'); port = 8443; startEnabled = $true }
}
function Save-Fixture($Configuration) {
    [IO.File]::WriteAllText($configFile, ($Configuration | ConvertTo-Json -Depth 32), (New-Object Text.UTF8Encoding $false))
}
$script:events = New-Object 'System.Collections.Generic.List[string]'
$guard = { Assert-AgentInstallNotRegistered 'TwoFactorAgent' }
$protect = {
    param($Path)
    Assert-True ((Get-Item -LiteralPath $Path -Force).Length -eq 0) 'Secret bytes appeared before private ACL assignment.'
    $script:events.Add('private-acl')
}
$validate = {
    param($Path)
    $script:events.Add('php-validation')
    $validationOutput = @(& $PhpPath $script:validatorPath $Path 2>&1)
    if ($LASTEXITCODE -ne 0) { throw 'PHP configuration validation failed.' }
}

try {
    $keys = @{}
    1..64 | ForEach-Object {
        $secret = New-AgentApiSecret
        Assert-True ($secret -cmatch '^[0-9a-f]{64}$') 'Generated key does not contain 32 bytes as lowercase hexadecimal.'
        Assert-True (-not $keys.ContainsKey($secret)) 'Independent generation repeated a key.'
        $keys[$secret] = $true
    }
    $count++; Write-Output 'PASS independently generated keys contain 32 random bytes without collisions'

    $configuration = New-ConfigFixture
    Save-Fixture $configuration
    $captured = @(Write-AgentInstalledConfig -Path $configFile -Configuration $configuration -EnsureUnregistered $guard -ProtectFile $protect -ValidateFile $validate -Confirm:$false)
    $installed = Get-Content -LiteralPath $configFile -Raw | ConvertFrom-Json
    Assert-True ($installed.apiSecretHex -cmatch '^[0-9a-f]{64}$') 'Missing key was not generated.'
    Assert-True ($installed.agentId -ceq $configuration.agentId -and $installed.allowedIPs.Count -eq 1 -and $installed.allowedIPs[0] -ceq '192.0.2.10' -and $installed.startEnabled -eq $true -and $installed.port -eq 8443) 'Unrelated configuration fields changed.'
    Assert-True (($script:events -join ',') -ceq 'private-acl,php-validation') 'Configuration write bypassed private permissions or PHP validation.'
    Assert-True ($captured.Count -eq 0) 'Configuration installation printed output.'
    $count++; Write-Output 'PASS missing secret is generated after private ACL assignment and preserves settings'

    $configuration = New-ConfigFixture
    $configuration | Add-Member apiSecretHex 'GENERATED_BY_INSTALLER'
    Save-Fixture $configuration
    Write-AgentInstalledConfig -Path $configFile -Configuration $configuration -EnsureUnregistered $guard -ProtectFile $protect -ValidateFile $validate -Confirm:$false
    $installed = Get-Content -LiteralPath $configFile -Raw | ConvertFrom-Json
    Assert-True ($installed.apiSecretHex -cmatch '^[0-9a-f]{64}$') 'Placeholder was not replaced.'
    $count++; Write-Output 'PASS installer placeholder is replaced with a generated server key'

    $copied = $installed.apiSecretHex
    Write-AgentInstalledConfig -Path $configFile -Configuration $installed -EnsureUnregistered $guard -ProtectFile $protect -ValidateFile $validate -Confirm:$false
    $reinstalled = Get-Content -LiteralPath $configFile -Raw | ConvertFrom-Json
    Assert-True ($reinstalled.apiSecretHex -cne $copied) 'Fresh installation reused a copied key.'
    $count++; Write-Output 'PASS fresh installation rotates even an existing valid copied key'

    $configuration = New-ConfigFixture
    $configuration.allowedIPs = @('192.0.2.0/24')
    Save-Fixture $configuration
    $original = [IO.File]::ReadAllText($configFile)
    Assert-Rejected { Write-AgentInstalledConfig -Path $configFile -Configuration $configuration -EnsureUnregistered $guard -ProtectFile $protect -ValidateFile $validate -Confirm:$false }
    Assert-True ([IO.File]::ReadAllText($configFile) -ceq $original) 'Invalid configuration replaced the original.'
    Assert-True (@(Get-ChildItem -LiteralPath $root -Filter '.agent-config-*.tmp' -Force).Count -eq 0) 'Temporary secret configuration remained after validation failure.'
    $count++; Write-Output 'PASS actual PHP validation rejects non-exact IPs and preserves the original file'

    $configuration = New-ConfigFixture
    Save-Fixture $configuration
    $original = [IO.File]::ReadAllText($configFile)
    $before = $script:secretGenerations
    Assert-Rejected { Write-AgentInstalledConfig -Path $configFile -Configuration $configuration -EnsureUnregistered $guard -ProtectFile { throw 'Simulated private ACL failure.' } -ValidateFile $validate -Confirm:$false }
    Assert-True ([IO.File]::ReadAllText($configFile) -ceq $original -and $script:secretGenerations -eq $before) 'ACL failure generated or published a new key.'
    Assert-True (@(Get-ChildItem -LiteralPath $root -Filter '.agent-config-*.tmp' -Force).Count -eq 0) 'Temporary file remained after ACL failure.'
    $count++; Write-Output 'PASS private ACL failure occurs before key generation and preserves configuration'

    $script:taskExists = $true
    Assert-Rejected { Write-AgentInstalledConfig -Path $configFile -Configuration $configuration -EnsureUnregistered $guard -ProtectFile $protect -ValidateFile $validate -Confirm:$false }
    Assert-True ([IO.File]::ReadAllText($configFile) -ceq $original -and $script:secretGenerations -eq $before) 'Existing task did not prevent key rotation.'
    $script:taskExists = $false
    $count++; Write-Output 'PASS existing registered task rejects reinstall before changing the secret'

    $script:firewallExists = $true
    Assert-Rejected { Write-AgentInstalledConfig -Path $configFile -Configuration $configuration -EnsureUnregistered $guard -ProtectFile $protect -ValidateFile $validate -Confirm:$false }
    Assert-True ([IO.File]::ReadAllText($configFile) -ceq $original -and $script:secretGenerations -eq $before) 'Existing firewall rule did not prevent key rotation.'
    $script:firewallExists = $false
    $count++; Write-Output 'PASS existing firewall registration rejects reinstall before changing the secret'

    Write-AgentInstalledConfig -Path $configFile -Configuration $configuration -EnsureUnregistered $guard -ProtectFile $protect -ValidateFile $validate -WhatIf
    Assert-True ([IO.File]::ReadAllText($configFile) -ceq $original -and $script:secretGenerations -eq $before) 'WhatIf generated or published a new key.'
    Assert-True (@(Get-ChildItem -LiteralPath $root -Filter '.agent-config-*.tmp' -Force).Count -eq 0) 'WhatIf created a temporary file.'
    $count++; Write-Output 'PASS WhatIf does not generate a key or write any files'
    Write-Output ('Passed ' + $count + ' installer secret tests. Actual NTFS access checks are separate Windows tests.')
} finally {
    if ([IO.Directory]::Exists($root)) { Remove-Item -LiteralPath $root -Recurse -Force }
}
