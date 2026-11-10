#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$PhpPath = 'C:\Program Files\PHP\php.exe',
    [string]$CodePath = 'C:\2fa\agent',
    [string]$ConfigPath = 'C:\2fa\agent\config.json',
    [ValidatePattern('^[A-Za-z0-9_-]{1,64}$')][string]$TaskName = 'TwoFactorAgent',
    [string]$ServiceAccount = 'SYSTEM',
    [switch]$Start,
    [switch]$LibraryOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-AgentLocalPath {
    param([string]$Path)
    if ($Path -notmatch '^[A-Za-z]:\\' -or $Path -match '["\x00-\x1f]' -or $Path.StartsWith('\\')) {
        throw 'Use an absolute local drive path without quotes or control characters.'
    }
    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath
    if ($resolved -notmatch '^[A-Za-z]:\\') { throw 'Only local file-system paths are supported.' }
    return $resolved.TrimEnd('\')
}

function Assert-AgentNoReparse {
    param([string]$Path)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    while ($null -ne $item) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Reparse points are not supported in agent installation paths.'
        }
        $item = if ($item -is [IO.DirectoryInfo]) { $item.Parent } else { $item.Directory }
    }
}

function Get-AgentPrivateItems {
    param([string]$Path, [bool]$Recurse = $true)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Reparse points are not supported in private directories.'
    }
    $item
    if ($item.PSIsContainer -and $Recurse) {
        # Inspect each child before descending; never follow a junction to an
        # unrelated directory while hardening permissions recursively.
        foreach ($child in @(Get-ChildItem -LiteralPath $item.FullName -Force -ErrorAction Stop)) {
            Get-AgentPrivateItems -Path $child.FullName -Recurse $true
        }
    }
}

function Set-AgentPrivateAcl {
    param(
        [string]$Path,
        [Security.Principal.SecurityIdentifier]$DomainAdminsSid,
        [Security.Principal.SecurityIdentifier]$RunSid,
        [ValidateSet('None', 'ReadAndExecute', 'Modify', 'Traverse')][string]$ServiceRights = 'ReadAndExecute',
        [bool]$Recurse = $true
    )
    $items = @(Get-AgentPrivateItems -Path $Path -Recurse $Recurse)
    foreach ($item in $items) {
        $acl = if ($item.PSIsContainer) { New-Object Security.AccessControl.DirectorySecurity } else { New-Object Security.AccessControl.FileSecurity }
        # Replace inherited and explicit access with a small allow list. A Deny
        # for Domain Users would also deny administrators who belong to it.
        $acl.SetAccessRuleProtection($true, $false)
        $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-544'))
        $inherit = if ($item.PSIsContainer) { [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit' } else { [Security.AccessControl.InheritanceFlags]::None }
        foreach ($sidText in @('S-1-5-18', 'S-1-5-32-544', $DomainAdminsSid.Value) | Select-Object -Unique) {
            $sid = New-Object Security.Principal.SecurityIdentifier $sidText
            $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', $inherit, 'None', 'Allow')
            $acl.AddAccessRule($rule)
        }
        if ($RunSid.Value -ne 'S-1-5-18' -and $ServiceRights -ne 'None') {
            $serviceInherit = if ($ServiceRights -eq 'Traverse') { [Security.AccessControl.InheritanceFlags]::None } else { $inherit }
            $rule = New-Object Security.AccessControl.FileSystemAccessRule($RunSid, $ServiceRights, $serviceInherit, 'None', 'Allow')
            $acl.AddAccessRule($rule)
        }
        Set-Acl -LiteralPath $item.FullName -AclObject $acl -ErrorAction Stop
    }
}

function Assert-AgentAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal $identity
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this installer from an elevated PowerShell console.'
    }
}

function Assert-AgentInstallNotRegistered {
    param([string]$Name)
    foreach ($candidate in @($Name, ($Name + '-LogMaintenance'))) {
        if ($null -ne (Get-ScheduledTask -TaskName $candidate -TaskPath '\' -ErrorAction SilentlyContinue)) {
            throw 'An agent task already exists. Coordinate a stop/uninstall before registering new tasks; the existing API secret was not changed.'
        }
    }
    if ($null -ne (Get-NetFirewallRule -Name ('TwoFactorAgent-' + $Name) -ErrorAction SilentlyContinue)) {
        throw 'The agent firewall rule already exists. Review it before reinstalling; the existing API secret was not changed.'
    }
}

function Assert-AgentHttpsPort {
    param([psobject]$Configuration)
    if ($null -eq $Configuration.PSObject.Properties['port'] -or
        ($Configuration.port -isnot [int] -and $Configuration.port -isnot [long])) {
        throw 'Configuration port must be an integer.'
    }
    if ($Configuration.port -ne 8443) { throw 'The agent API must use HTTPS on port 8443.' }
    $httpsListeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object { $_.LocalPort -eq $Configuration.port })
    if ($httpsListeners.Count -gt 0) {
        throw ('Port ' + $Configuration.port + ' already has a listener. The agent cannot share this port with another service. Review the existing listener before installation; no service was stopped or changed.')
    }
    return [int]$Configuration.port
}

function New-AgentApiSecret {
    $bytes = New-Object byte[] 32
    $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $generator.GetBytes($bytes)
        return ([BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
    } finally {
        [Array]::Clear($bytes, 0, $bytes.Length)
        $generator.Dispose()
    }
}

function Write-AgentInstalledConfig {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][psobject]$Configuration,
        [Parameter(Mandatory = $true)][scriptblock]$EnsureUnregistered,
        [Parameter(Mandatory = $true)][scriptblock]$ProtectFile,
        [Parameter(Mandatory = $true)][scriptblock]$ValidateFile
    )
    # The caller has already protected the code/config directory. Recheck task
    # registration immediately before generation so an existing install is safe.
    $null = & $EnsureUnregistered
    if (-not $PSCmdlet.ShouldProcess($Path, 'Generate and save a new server-specific API secret')) { return }
    Assert-AgentNoReparse $Path
    $temporary = Join-Path (Split-Path -Parent $Path) ('.agent-config-' + [guid]::NewGuid().ToString('N') + '.tmp')
    $stream = $null
    try {
        # Create an empty file under the protected parent, then assign the same
        # explicit private ACL before any secret bytes are written.
        $stream = [IO.File]::Open($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $stream.Dispose()
        $stream = $null
        $null = & $ProtectFile $temporary
        $updated = $Configuration | ConvertTo-Json -Depth 32 | ConvertFrom-Json
        if ($updated -isnot [pscustomobject]) { throw 'Agent configuration must be a JSON object.' }
        $updated | Add-Member -MemberType NoteProperty -Name apiSecretHex -Value (New-AgentApiSecret) -Force
        $json = $updated | ConvertTo-Json -Depth 32
        $bytes = (New-Object Text.UTF8Encoding $false).GetBytes($json + [Environment]::NewLine)
        if ($bytes.Length -gt 65536) { throw 'Agent configuration is too large.' }
        $stream = [IO.File]::Open($temporary, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
        finally { $stream.Dispose(); $stream = $null; [Array]::Clear($bytes, 0, $bytes.Length) }
        # Validate through the actual PHP Config class before replacing config.json.
        # Neither the generated key nor the JSON document is sent to console output.
        $null = & $ValidateFile $temporary
        [IO.File]::Replace($temporary, $Path, [System.Management.Automation.Language.NullString]::Value)
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
        if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
    }
}

if ($LibraryOnly) { return }
Assert-AgentAdministrator

$installationRoot = 'C:\2fa'
$logsPath = 'C:\2fa\logs'
$docsPath = 'C:\2fa\docs'
$distribPath = 'C:\2fa\distrib'
$PhpPath = Resolve-AgentLocalPath $PhpPath
$CodePath = Resolve-AgentLocalPath $CodePath
$ConfigPath = Resolve-AgentLocalPath $ConfigPath
if ($CodePath -ine 'C:\2fa\agent' -or $ConfigPath -ine 'C:\2fa\agent\config.json') {
    throw 'This installation uses C:\2fa\agent and C:\2fa\agent\config.json.'
}
$installationRoot = Resolve-AgentLocalPath $installationRoot
$phpDirectory = Split-Path -Parent $PhpPath
$programFilesPrefix = (Resolve-AgentLocalPath $env:ProgramFiles) + '\'
if ($phpDirectory -ine 'C:\2fa\php' -and -not $phpDirectory.StartsWith($programFilesPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'PHP must be in its own directory under Program Files or in C:\2fa\php.'
}
if ([IO.Path]::GetFileName($PhpPath) -ine 'php.exe') { throw 'PhpPath must point to the PHP CLI executable php.exe.' }
foreach ($path in @($PhpPath, $CodePath, $ConfigPath, $installationRoot)) { Assert-AgentNoReparse $path }
foreach ($path in @($logsPath, $docsPath, $distribPath)) {
    if (Test-Path -LiteralPath $path) {
        if (-not (Test-Path -LiteralPath $path -PathType Container)) { throw 'The logs and docs paths must be directories.' }
        Assert-AgentNoReparse $path
    }
}
foreach ($relative in @('bin\agent.php', 'bin\agentctl.php', 'bin\export-certificate.php', 'src\LocalAdminServer.php', 'vendor\autoload.php', 'powershell\Directory.ps1', 'powershell\LocalAdmin.ps1', 'deploy\Maintain-Logs.ps1', 'deploy\New-Distribution.ps1', 'deploy\Request-AgentCertificate.ps1', 'deploy\Validate-Config.php', 'docs\instruction.txt', 'docs\api.txt', 'composer.json')) {
    if (-not (Test-Path -LiteralPath (Join-Path $CodePath $relative) -PathType Leaf)) { throw ('Missing agent file: ' + $relative) }
}
& $PhpPath (Join-Path $CodePath 'bin\export-certificate.php') --check
if ($LASTEXITCODE -ne 0) { throw 'Enable the OpenSSL extension in PHP 8.2 or newer before installing the HTTPS agent.' }
# Enumerate the protected trees before making any changes, rejecting junctions.
$null = @(Get-AgentPrivateItems -Path $CodePath)
$null = @(Get-AgentPrivateItems -Path $phpDirectory)
foreach ($path in @($logsPath, $docsPath, $distribPath)) {
    if (Test-Path -LiteralPath $path) { $null = @(Get-AgentPrivateItems -Path $path) }
}

try {
    if ((Get-Item -LiteralPath $ConfigPath).Length -gt 65536) { throw 'Too large.' }
    $config = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($config -isnot [pscustomobject]) { throw 'Not an object.' }
} catch { throw 'Agent configuration must be a valid JSON object no larger than 64 KiB.' }
$apiPort = Assert-AgentHttpsPort $config
foreach ($setting in @(@{ Name = 'tlsCertificateFile'; File = 'C:\2fa\agent\tls\agent.crt.pem' }, @{ Name = 'tlsPrivateKeyFile'; File = 'C:\2fa\agent\tls\agent.key.pem' })) {
    if ($null -ne $config.PSObject.Properties[$setting.Name] -and [string]$config.($setting.Name) -ine $setting.File) {
        throw ('Set ' + $setting.Name + ' to ' + $setting.File + '.')
    }
    if (-not (Test-Path -LiteralPath $setting.File -PathType Leaf)) {
        throw 'Agent TLS files are missing. Run deploy\Request-AgentCertificate.ps1 with the existing certificate template before installation.'
    }
    Assert-AgentNoReparse $setting.File
}
if ($null -ne $config.PSObject.Properties['logDirectory'] -and [string]$config.logDirectory -ine $logsPath) {
    throw 'Set logDirectory to C:\2fa\logs in the agent configuration.'
}
if ($null -eq $config.PSObject.Properties['powershellPath']) { throw 'Configuration powershellPath is required.' }
$powerShellPath = Resolve-AgentLocalPath ([string]$config.powershellPath)
$trustedPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
if ($powerShellPath -ine $trustedPowerShell) { throw 'Use the built-in Windows PowerShell 5.1 executable.' }
Assert-AgentNoReparse $powerShellPath
$remoteIps = @($config.allowedIPs)
if ($remoteIps.Count -eq 0 -or $remoteIps.Count -gt 64) { throw 'allowedIPs must contain between 1 and 64 exact mobile-server IP addresses.' }
foreach ($ip in $remoteIps) {
    $parsedIp = $null
    if ($ip -isnot [string] -or -not [Net.IPAddress]::TryParse($ip, [ref]$parsedIp)) { throw 'allowedIPs must contain exact IP addresses, not networks or host names.' }
}
# apiSecretHex may be missing or contain a placeholder. Every new installation
# replaces it after private permissions are applied, including copied valid keys.

Import-Module ActiveDirectory -ErrorAction Stop
$localMachine = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
if (-not [bool]$localMachine.PartOfDomain -or [int]$localMachine.DomainRole -notin @(4, 5)) {
    throw 'The agent must be installed on a domain controller.'
}
$localFqdn = [string]$localMachine.DNSHostName + '.' + [string]$localMachine.Domain
if ([string]$config.domainController -ine $localFqdn) { throw 'domainController must be the FQDN of this local server.' }
$domain = Get-ADDomain -Server $localFqdn -ErrorAction Stop
$domainAdminsSid = New-Object Security.Principal.SecurityIdentifier ($domain.DomainSID.Value + '-512')
if ($ServiceAccount -ieq 'SYSTEM') {
    $runSid = New-Object Security.Principal.SecurityIdentifier 'S-1-5-18'
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
} else {
    if ($ServiceAccount -notmatch '^[^\\]+\\[^\\]+\$$') { throw 'ServiceAccount must be SYSTEM or DOMAIN\gmsa$.' }
    $accountName = ($ServiceAccount -split '\\', 2)[1]
    if (-not (Test-ADServiceAccount -Identity $accountName)) { throw 'The gMSA is not installed or its password cannot be retrieved on this controller.' }
    $runSid = (New-Object Security.Principal.NTAccount $ServiceAccount).Translate([Security.Principal.SecurityIdentifier])
    $principal = New-ScheduledTaskPrincipal -UserId $ServiceAccount -LogonType Password -RunLevel Highest
}

$maintenanceTaskName = $TaskName + '-LogMaintenance'
Assert-AgentInstallNotRegistered $TaskName
$firewallName = 'TwoFactorAgent-' + $TaskName

$arguments = '"' + (Join-Path $CodePath 'bin\agent.php') + '" --config "' + $ConfigPath + '"'
$action = New-ScheduledTaskAction -Execute $PhpPath -Argument $arguments -WorkingDirectory $CodePath
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$maintenanceArguments = '-NoLogo -NoProfile -NonInteractive -File "' + (Join-Path $CodePath 'deploy\Maintain-Logs.ps1') + '" -LogDirectory "' + $logsPath + '"'
$maintenanceAction = New-ScheduledTaskAction -Execute $powerShellPath -Argument $maintenanceArguments -WorkingDirectory $CodePath
$maintenanceTriggers = @((New-ScheduledTaskTrigger -AtStartup), (New-ScheduledTaskTrigger -Daily -At ([DateTime]::Today.AddHours(3).AddMinutes(15))))
$maintenanceSettings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 4) -MultipleInstances IgnoreNew -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

if ($PSCmdlet.ShouldProcess($installationRoot, 'Protect agent folders; generate a server-specific API secret; copy documentation; register tasks; create a reusable distribution')) {
    # Protect the parent against replacement/deletion of its private children.
    # A gMSA needs only traversal here; it cannot list or modify the parent.
    Set-AgentPrivateAcl -Path $installationRoot -DomainAdminsSid $domainAdminsSid -RunSid $runSid -ServiceRights Traverse -Recurse $false
    Set-AgentPrivateAcl -Path $phpDirectory -DomainAdminsSid $domainAdminsSid -RunSid $runSid
    Set-AgentPrivateAcl -Path $CodePath -DomainAdminsSid $domainAdminsSid -RunSid $runSid
    Write-AgentInstalledConfig -Path $ConfigPath -Configuration $config -EnsureUnregistered {
        Assert-AgentInstallNotRegistered $TaskName
    } -ProtectFile {
        param($temporaryPath)
        Set-AgentPrivateAcl -Path $temporaryPath -DomainAdminsSid $domainAdminsSid -RunSid $runSid
    } -ValidateFile {
        param($temporaryPath)
        & $PhpPath (Join-Path $CodePath 'deploy\Validate-Config.php') $temporaryPath
        if ($LASTEXITCODE -ne 0) { throw 'Agent configuration validation failed; the original config.json was retained.' }
    } -Confirm:$false
    foreach ($path in @($logsPath, $docsPath, $distribPath)) {
        if (-not (Test-Path -LiteralPath $path)) { $null = New-Item -Path $path -ItemType Directory }
    }
    Set-AgentPrivateAcl -Path $logsPath -DomainAdminsSid $domainAdminsSid -RunSid $runSid -ServiceRights Modify
    foreach ($name in @('instruction.txt', 'api.txt', 'API.md', 'support-api.md', 'hmac-test-vector.json', 'WINDOWS-VALIDATION.md', 'VALIDATION-RESULTS.md', 'SECURITY-REVIEW.md')) {
        $source = Join-Path (Join-Path $CodePath 'docs') $name
        if (-not (Test-Path -LiteralPath $source)) {
            if ($name -in @('instruction.txt', 'api.txt')) { throw ('Missing administrator documentation: ' + $name) }
            continue
        }
        Assert-AgentNoReparse $source
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw ('Administrator documentation must be a file: ' + $name) }
        Copy-Item -LiteralPath $source -Destination (Join-Path $docsPath $name) -Force
    }
    Set-AgentPrivateAcl -Path $docsPath -DomainAdminsSid $domainAdminsSid -RunSid $runSid -ServiceRights None
    Set-AgentPrivateAcl -Path $distribPath -DomainAdminsSid $domainAdminsSid -RunSid $runSid -ServiceRights None
    $ruleCreated = $false
    $registeredTasks = @()
    try {
        New-NetFirewallRule -Name $firewallName -DisplayName ('TwoFactorAgent HTTPS (' + $TaskName + ')') -Direction Inbound -Action Allow -Enabled True -Profile Domain -Protocol TCP -LocalPort $apiPort -RemoteAddress $remoteIps -Program $PhpPath -EdgeTraversalPolicy Block | Out-Null
        $ruleCreated = $true
        Register-ScheduledTask -TaskName $TaskName -TaskPath '\' -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description 'Independent in-memory AD workstation authorization agent. No session termination.' | Out-Null
        $registeredTasks += $TaskName
        Register-ScheduledTask -TaskName $maintenanceTaskName -TaskPath '\' -Action $maintenanceAction -Trigger $maintenanceTriggers -Settings $maintenanceSettings -Principal $principal -Description 'Archive completed UTC log months and remove agent logs beyond three calendar years.' | Out-Null
        $registeredTasks += $maintenanceTaskName
    } catch {
        foreach ($name in $registeredTasks) { Unregister-ScheduledTask -TaskName $name -TaskPath '\' -Confirm:$false -ErrorAction SilentlyContinue }
        if ($ruleCreated) { Remove-NetFirewallRule -Name $firewallName -ErrorAction SilentlyContinue }
        throw
    }
    # Run maintenance once after installation, including an initial catch-up.
    Start-ScheduledTask -TaskName $maintenanceTaskName -TaskPath '\'
    if ($Start) { Start-ScheduledTask -TaskName $TaskName -TaskPath '\' }
    try {
        & (Join-Path $CodePath 'deploy\New-Distribution.ps1') -CodePath $CodePath -PhpPath $PhpPath -DestinationPath $distribPath
    } catch {
        throw 'Agent tasks are registered, but distribution creation failed. Correct the cause and rerun deploy\New-Distribution.ps1; the existing tasks and private permissions were retained.'
    }
    Write-Output ('Installed tasks ' + $TaskName + ' and ' + $maintenanceTaskName + '. Agent start requested: ' + $Start.IsPresent + '. No AD accounts or groups were modified.')
    Write-Output 'A new API HMAC secret was saved in C:\2fa\agent\config.json. Copy apiSecretHex to the mobile authorization server settings for this specific agent; reinstalling generates a new secret.'
    Write-Output 'Documentation: C:\2fa\docs\instruction.txt and C:\2fa\docs\api.txt. Logs: C:\2fa\logs. Reusable distribution: C:\2fa\distrib.'
}
