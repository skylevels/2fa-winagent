#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$AllowedIP = '',
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9.-]{1,252}$')][string]$CAHost = 'dosifey.elemer.org',
    [string]$CAConfig = '',
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$')][string]$CertificateTemplate = 'WebServer10y',
    [ValidatePattern('^[A-Za-z0-9_-]{1,64}$')][string]$TaskName = 'TwoFactorAgent',
    [string]$ServiceAccount = 'SYSTEM',
    [switch]$LibraryOnly
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-AgentOnlineUri {
    param([uri]$Uri, [string[]]$Hosts)
    if (-not $Uri.IsAbsoluteUri -or $Uri.Scheme -cne 'https' -or $Uri.Port -ne 443 -or
        $Uri.UserInfo -ne '' -or $Uri.Fragment -ne '' -or $Hosts -notcontains $Uri.DnsSafeHost.ToLowerInvariant()) {
        throw 'Download URL must use HTTPS on an explicitly trusted host.'
    }
}

function New-AgentOnlineHttpClient {
    param([long]$MaximumBytes, [int]$TimeoutSeconds)
    Add-Type -AssemblyName System.Net.Http
    $handler = New-Object Net.Http.HttpClientHandler
    $handler.AllowAutoRedirect = $false
    $handler.UseCookies = $false
    $handler.UseDefaultCredentials = $false
    try {
        $client = New-Object Net.Http.HttpClient($handler)
        $client.MaxResponseContentBufferSize = $MaximumBytes
        $client.Timeout = [TimeSpan]::FromSeconds($TimeoutSeconds)
        $client.DefaultRequestHeaders.UserAgent.ParseAdd('2fa-winagent-installer')
        return [pscustomobject]@{ Client = $client; Handler = $handler }
    } catch { $handler.Dispose(); throw }
}

function Save-AgentOnlineDownload {
    param([uri]$Uri, [string]$Destination, [string[]]$Hosts, [long]$MaximumBytes, [int]$TimeoutSeconds = 120)
    Assert-AgentOnlineUri $Uri $Hosts
    if (Test-Path -LiteralPath $Destination) { throw 'Download destination already exists.' }
    Add-Type -AssemblyName System.Net.Http
    $oldProtocol = [Net.ServicePointManager]::SecurityProtocol
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $elapsed = [Diagnostics.Stopwatch]::StartNew()
    $complete = $false
    $client = $null; $handler = $null
    try {
        $transport = New-AgentOnlineHttpClient $MaximumBytes $TimeoutSeconds
        $client = $transport.Client; $handler = $transport.Handler
        for ($redirects = 0; $redirects -le 8; $redirects++) {
            Assert-AgentOnlineUri $Uri $Hosts
            $remaining = $TimeoutSeconds - $elapsed.Elapsed.TotalSeconds
            if ($remaining -le 0) { throw 'Download timed out.' }
            $response = $null
            try {
                # ResponseContentRead buffers the complete size-bounded body in
                # the asynchronous task. The outer wait covers headers, chunk
                # framing and slow bodies, rather than resetting on each read.
                $task = $client.GetAsync($Uri, [Net.Http.HttpCompletionOption]::ResponseContentRead)
                if (-not $task.Wait([int][Math]::Max(1, [Math]::Min([int]::MaxValue, $remaining * 1000)))) {
                    $client.CancelPendingRequests()
                    throw 'Download timed out.'
                }
                $response = $task.Result
                $status = [int]$response.StatusCode
                if ($status -in @(301, 302, 303, 307, 308)) {
                    if ($redirects -eq 8 -or $null -eq $response.Headers.Location) { throw 'Too many or invalid download redirects.' }
                    $Uri = New-Object Uri($Uri, $response.Headers.Location)
                    Assert-AgentOnlineUri $Uri $Hosts
                    continue
                }
                if ($status -ne 200) {
                    $failure = New-Object InvalidOperationException('Unexpected download HTTP status.')
                    $failure.Data['HttpStatus'] = $status
                    throw $failure
                }
                $bytes = $response.Content.ReadAsByteArrayAsync().Result
                if ($bytes.Length -eq 0 -or $bytes.LongLength -gt $MaximumBytes -or $elapsed.Elapsed.TotalSeconds -ge $TimeoutSeconds) { throw 'Download was empty, oversized or timed out.' }
                $output = [IO.File]::Open($Destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
                try { $output.Write($bytes, 0, $bytes.Length); $output.Flush($true) } finally { $output.Dispose() }
                $complete = $true
                return
            } finally { if ($null -ne $response) { $response.Dispose() } }
        }
    } finally {
        if ($null -ne $client) { $client.CancelPendingRequests(); $client.Dispose() }
        if ($null -ne $handler) { $handler.Dispose() }
        [Net.ServicePointManager]::SecurityProtocol = $oldProtocol
        if (-not $complete -and [IO.File]::Exists($Destination)) { [IO.File]::Delete($Destination) }
    }
}

function Save-AgentOnlinePhp {
    param([string]$Destination)
    $name = 'php-8.4.27-1-nts-Win32-vs17-x64.zip'
    $hosts = @('downloads.php.net', 'windows.php.net')
    try { Save-AgentOnlineDownload ('https://downloads.php.net/~windows/releases/' + $name) $Destination $hosts 100000000 }
    catch {
        if ($_.Exception.Data['HttpStatus'] -ne 404) { throw }
        Save-AgentOnlineDownload ('https://downloads.php.net/~windows/releases/archives/' + $name) $Destination $hosts 100000000
    }
    Assert-AgentOnlineHash $Destination 'dbae154a0a89791f36c3d48e68bae797878333e7d6cb5721e74617de59b63ab7'
}

function Get-AgentOnlineRevision {
    param([string]$JsonPath)
    $value = [IO.File]::ReadAllText($JsonPath) | ConvertFrom-Json
    if ($null -eq $value -or $null -eq $value.PSObject.Properties['sha'] -or $value.sha -isnot [string] -or $value.sha -cnotmatch '^[0-9a-f]{40}$') {
        throw 'GitHub did not return a valid immutable revision.'
    }
    return $value.sha
}

function Get-AgentOnlineSourceHash {
    param([string]$Path)
    $value = [IO.File]::ReadAllText($Path).Trim()
    if ($value -cnotmatch '^([0-9a-f]{64})  windows-agent\.zip$') { throw 'Invalid source archive checksum file.' }
    return $Matches[1]
}

function Assert-AgentOnlineHash {
    param([string]$Path, [string]$Expected)
    if ($Expected -notmatch '^[0-9a-fA-F]{64}$' -or (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ine $Expected) {
        throw 'Downloaded file SHA-256 does not match the expected value.'
    }
}

function Get-AgentOnlineZipPlan {
    param($Archive, [ValidateSet('Source', 'Php')][string]$Kind)
    $seen = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $plan = New-Object 'Collections.Generic.List[object]'
    $files = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $total = 0L
    foreach ($entry in $Archive.Entries) {
        if ($plan.Count -ge 5000) { throw 'ZIP contains too many entries.' }
        $name = [string]$entry.FullName
        if ($name -match '[\\\x00-\x1f\x7f:*?"<>|]' -or $name.StartsWith('/')) { throw 'Unsafe ZIP entry name.' }
        $directory = $name.EndsWith('/')
        $clean = $name.TrimEnd('/')
        if ($clean.Length -eq 0) { throw 'Empty ZIP entry name.' }
        $parts = $clean.Split('/')
        foreach ($part in $parts) {
            if ($part -eq '' -or $part -in @('.', '..') -or $part.EndsWith('.') -or $part.EndsWith(' ') -or
                $part -match '^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$') { throw 'Unsafe Windows ZIP path.' }
        }
        if (-not $seen.Add($clean)) { throw 'ZIP contains duplicate paths.' }
        $unixKind = ($entry.ExternalAttributes -shr 16) -band 61440
        if ($unixKind -notin @(0, 16384, 32768) -or ($entry.ExternalAttributes -band 1024) -ne 0) { throw 'ZIP links and special files are prohibited.' }
        if ($entry.Length -lt 0 -or $entry.Length -gt 150000000) { throw 'ZIP entry is too large.' }
        $total += $entry.Length
        if ($total -gt 600000000) { throw 'ZIP expands beyond its size limit.' }
        if ($Kind -eq 'Source') {
            if ($parts[0] -notin @('agent', 'docs')) { throw 'Unexpected source ZIP root.' }
            if ($parts -icontains 'tls' -or $parts -icontains 'logs' -or $parts[-1] -ieq 'config.json' -or
                $parts[-1] -like '.env*' -or [IO.Path]::GetExtension($clean) -in @('.exe', '.dll', '.so', '.pfx', '.p12', '.key', '.pem')) { throw 'Source ZIP contains private or binary files.' }
        }
        if (-not $directory) { $null = $files.Add($clean) }
        $plan.Add([pscustomobject]@{ Entry = $entry; Relative = $clean; Directory = $directory })
    }
    # File/parent collisions must be rejected before any extraction begins.
    foreach ($item in $plan) {
        $parent = $item.Relative
        while ($parent.Contains('/')) {
            $parent = $parent.Substring(0, $parent.LastIndexOf('/'))
            if ($files.Contains($parent)) { throw 'ZIP file conflicts with a parent directory.' }
        }
    }
    $required = if ($Kind -eq 'Source') { @('agent/deploy/Install-Agent.ps1', 'agent/deploy/Request-AgentCertificate.ps1', 'agent/config.example.json', 'agent/vendor/autoload.php') } else { @('php.exe', 'php8.dll', 'ext/php_openssl.dll', 'php.ini-production') }
    foreach ($name in $required) {
        if (@($plan | Where-Object { -not $_.Directory -and $_.Relative -ceq $name }).Count -ne 1) { throw ('Required archive component missing: ' + $name) }
    }
    return $plan.ToArray()
}

function Copy-AgentOnlineZipEntry {
    param($InputStream, $OutputStream, [long]$DeclaredLength, [ref]$Total)
    $buffer = New-Object byte[] 65536
    $actual = 0L
    while ($true) {
        $read = $InputStream.Read($buffer, 0, $buffer.Length)
        if ($read -eq 0) { break }
        $actual += $read
        $Total.Value += $read
        if ($actual -gt $DeclaredLength -or $actual -gt 150000000 -or $Total.Value -gt 600000000) { throw 'Actual ZIP expansion exceeded its declared or allowed size.' }
        $OutputStream.Write($buffer, 0, $read)
    }
    if ($actual -ne $DeclaredLength) { throw 'ZIP entry did not match its declared length.' }
}

function Expand-AgentOnlineZip {
    param([string]$Path, [string]$Destination, [ValidateSet('Source', 'Php')][string]$Kind)
    if (Test-Path -LiteralPath $Destination) { throw 'Extraction destination already exists.' }
    Add-Type -AssemblyName System.IO.Compression
    $stream = [IO.File]::OpenRead($Path)
    $archive = New-Object IO.Compression.ZipArchive($stream, [IO.Compression.ZipArchiveMode]::Read, $true)
    try {
        $plan = @(Get-AgentOnlineZipPlan $archive $Kind)
        $null = [IO.Directory]::CreateDirectory($Destination)
        $actualTotal = 0L
        foreach ($item in $plan) {
            $target = Join-Path $Destination ($item.Relative.Replace('/', [IO.Path]::DirectorySeparatorChar))
            if ($item.Directory) { $null = [IO.Directory]::CreateDirectory($target); continue }
            $null = [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target))
            $inputStream = $item.Entry.Open()
            $outputStream = [IO.File]::Open($target, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            try { Copy-AgentOnlineZipEntry $inputStream $outputStream $item.Entry.Length ([ref]$actualTotal) } finally { $inputStream.Dispose(); $outputStream.Dispose() }
        }
    } finally { $archive.Dispose(); $stream.Dispose() }
}

function Assert-AgentOnlineMicrosoftSignature {
    param($Signature)
    if ([string]$Signature.Status -cne 'Valid' -or $null -eq $Signature.SignerCertificate -or
        [string]$Signature.SignerCertificate.Subject -notmatch '(?:^|,\s*)O=Microsoft Corporation(?:,|$)') {
        throw 'VC++ installer must have a valid Microsoft Corporation Authenticode signature.'
    }
}

function Get-AgentOnlineVcResult {
    param([int]$ExitCode)
    if ($ExitCode -in @(0, 1638)) { return 'ready' }
    if ($ExitCode -eq 3010) { return 'restart_required' }
    throw ('Microsoft VC++ installation failed with exit code ' + $ExitCode + '.')
}

function Invoke-AgentOnlineVcInstall {
    param([string]$Path)
    $process = Start-Process -FilePath $Path -ArgumentList @('/install', '/quiet', '/norestart') -PassThru
    try {
        if (-not $process.WaitForExit(300000)) {
            try { $process.Kill() } catch { }
            $null = $process.WaitForExit(10000)
            throw 'VC++ installation exceeded five minutes. Check Windows Installer state before retrying; the agent was not started.'
        }
        return Get-AgentOnlineVcResult $process.ExitCode
    } finally { $process.Dispose() }
}

function New-AgentOnlinePhpIni {
    param([string]$Production)
    $directoryMatches = [regex]::Matches($Production, '(?m)^;\s*extension_dir\s*=\s*"ext"\s*\r?$')
    $sslMatches = [regex]::Matches($Production, '(?m)^;\s*extension\s*=\s*openssl\s*\r?$')
    if ($directoryMatches.Count -ne 1 -or $sslMatches.Count -ne 1) { throw 'Unexpected official PHP production configuration.' }
    $result = [regex]::Replace($Production, '(?m)^;\s*extension_dir\s*=\s*"ext"\s*\r?$', 'extension_dir = "C:/2fa/php/ext"')
    return [regex]::Replace($result, '(?m)^;\s*extension\s*=\s*openssl\s*\r?$', 'extension=openssl')
}

function New-AgentOnlineConfig {
    param([string]$Template, [string]$Fqdn, [string]$Id, [string]$IP)
    $address = $null
    if (($IP -notmatch '^\d{1,3}(\.\d{1,3}){3}$' -and $IP -notmatch ':') -or $IP -match '[%/\s]' -or
        -not [Net.IPAddress]::TryParse($IP, [ref]$address)) { throw 'AllowedIP must be one exact IPv4 or IPv6 address.' }
    if ($Fqdn -notmatch '^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z][A-Za-z0-9-]{0,62}$' -or
        $Id -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$') { throw 'Invalid local domain-controller identity.' }
    if ($IP -match '^\d{1,3}(\.\d{1,3}){3}$' -and $address.ToString() -cne $IP) { throw 'IPv4 must use ordinary decimal dotted notation without leading zeroes.' }
    $config = $Template | ConvertFrom-Json
    $config.agentId = $Id.ToLowerInvariant()
    $config.domainController = $Fqdn.ToLowerInvariant()
    $config.allowedIPs = @($address.ToString())
    $config.apiSecretHex = 'GENERATED_BY_INSTALLER'
    $config.port = 8443
    return $config | ConvertTo-Json -Depth 32
}

function Assert-AgentOnlineNoReparse {
    param([string]$Path)
    $current = [IO.DirectoryInfo]$Path
    while ($null -ne $current) {
        if ($current.Exists -and ($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse points are prohibited in installation paths.' }
        $current = $current.Parent
    }
}

function Set-AgentOnlinePrivateDirectory {
    param([string]$Path, [string]$DomainAdminsSid)
    Assert-AgentOnlineNoReparse $Path
    if (Test-Path -LiteralPath $Path -PathType Leaf) { throw 'Installation path is not a directory.' }
    $allowed = @('S-1-5-18', 'S-1-5-32-544', $DomainAdminsSid)
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-544'))
    foreach ($sid in $allowed | Select-Object -Unique) {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier $sid), 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')))
    }
    if (-not [IO.Directory]::Exists($Path)) {
        # Windows PowerShell/.NET Framework creates the directory with its
        # private DACL in one call, without an inherited write-access window.
        $null = [IO.Directory]::CreateDirectory($Path, $acl)
        return
    }
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $existing = Get-Acl -LiteralPath $Path
    $owner = $existing.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin ($allowed + $currentUser)) { throw 'An installation directory is owned by an untrusted account.' }
    $writeMask = [Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles
    foreach ($rule in $existing.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
            $rule.IdentityReference.Value -notin ($allowed + $currentUser) -and ($rule.FileSystemRights -band $writeMask) -ne 0) {
            throw 'An installation directory grants write access to an untrusted account.'
        }
    }
    Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
}

if ($LibraryOnly) { return }
if ($env:OS -ne 'Windows_NT' -or $PSVersionTable.PSEdition -ne 'Desktop' -or -not [Environment]::Is64BitOperatingSystem -or -not [Environment]::Is64BitProcess) { throw 'Run this installer in 64-bit Windows PowerShell on the target domain controller.' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal $identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run PowerShell as administrator.' }
Import-Module ActiveDirectory -ErrorAction Stop
$computer = Get-CimInstance -ClassName Win32_ComputerSystem
if (-not $computer.PartOfDomain -or [int]$computer.DomainRole -notin @(4, 5)) { throw 'Installation must run on a writable domain controller.' }
$localFqdn = [string]$computer.DNSHostName + '.' + [string]$computer.Domain
$controller = Get-ADDomainController -Identity $localFqdn -Server $localFqdn -ErrorAction Stop
if ($controller.IsReadOnly -or [string]$controller.Name -ine [Environment]::MachineName) { throw 'This must be the local writable domain controller.' }
$domain = Get-ADDomain -ErrorAction Stop
$domainAdminsSid = [string]$domain.DomainSID + '-512'
$root = 'C:\2fa'
foreach ($path in @($root, 'C:\2fa\agent', 'C:\2fa\php')) { Assert-AgentOnlineNoReparse $path }
foreach ($path in @('C:\2fa\agent', 'C:\2fa\php')) {
    if ((Test-Path -LiteralPath $path) -and (@(Get-ChildItem -LiteralPath $path -Force).Count -gt 0 -or (Test-Path -LiteralPath $path -PathType Leaf))) { throw 'This online installer performs a fresh installation only. Existing agent/PHP files are preserved; use the installed offline scripts for recovery.' }
}
foreach ($name in @($TaskName, ($TaskName + '-LogMaintenance'))) {
    if ($null -ne (Get-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction SilentlyContinue)) { throw 'An agent task is already registered; existing installation was preserved.' }
}
if ($null -ne (Get-NetFirewallRule -Name ('TwoFactorAgent-' + $TaskName) -ErrorAction SilentlyContinue)) { throw 'An agent firewall rule is already registered.' }
if (@(Get-NetTCPConnection -State Listen | Where-Object { $_.LocalPort -eq 8443 }).Count -ne 0) { throw 'Port 8443 already has a listener.' }
if (-not $PSCmdlet.ShouldProcess($root, 'Download verified components and install the HTTPS domain agent')) { return }
if (-not $AllowedIP) { $AllowedIP = Read-Host 'Exact IP address of the mobile authorization server' }
$localFqdn = [string]$computer.DNSHostName + '.' + [string]$computer.Domain
Set-AgentOnlinePrivateDirectory $root $domainAdminsSid
$staging = Join-Path $root ('.install-' + [guid]::NewGuid().ToString('N'))
Set-AgentOnlinePrivateDirectory $staging $domainAdminsSid
$published = $false
try {
    $revisionFile = Join-Path $staging 'revision.json'
    Save-AgentOnlineDownload 'https://api.github.com/repos/skylevels/2fa-winagent/commits/main' $revisionFile @('api.github.com') 1000000
    $revision = Get-AgentOnlineRevision $revisionFile
    $origin = 'https://raw.githubusercontent.com/skylevels/2fa-winagent/' + $revision + '/dist/'
    $sourceZip = Join-Path $staging 'windows-agent.zip'; $sourceChecksum = $sourceZip + '.sha256'
    Save-AgentOnlineDownload ($origin + 'windows-agent.zip.sha256') $sourceChecksum @('raw.githubusercontent.com') 4096
    Save-AgentOnlineDownload ($origin + 'windows-agent.zip') $sourceZip @('raw.githubusercontent.com') 20000000
    Assert-AgentOnlineHash $sourceZip (Get-AgentOnlineSourceHash $sourceChecksum)
    $phpZip = Join-Path $staging 'php.zip'
    Save-AgentOnlinePhp $phpZip
    $vc = Join-Path $staging 'VC_redist.x64.exe'
    Save-AgentOnlineDownload 'https://aka.ms/vc14/vc_redist.x64.exe' $vc @('aka.ms', 'go.microsoft.com', 'download.visualstudio.microsoft.com', 'download.microsoft.com') 100000000
    Assert-AgentOnlineMicrosoftSignature (Get-AuthenticodeSignature -LiteralPath $vc)
    $sourcePath = Join-Path $staging 'source'; $phpPath = Join-Path $staging 'php'
    Expand-AgentOnlineZip $sourceZip $sourcePath Source
    Expand-AgentOnlineZip $phpZip $phpPath Php
    $ini = New-AgentOnlinePhpIni ([IO.File]::ReadAllText((Join-Path $phpPath 'php.ini-production')))
    [IO.File]::WriteAllText((Join-Path $phpPath 'php.ini'), $ini, (New-Object Text.UTF8Encoding $false))
    $configuration = New-AgentOnlineConfig ([IO.File]::ReadAllText((Join-Path $sourcePath 'agent\config.example.json'))) $localFqdn ([string]$computer.DNSHostName) $AllowedIP
    if ((Invoke-AgentOnlineVcInstall $vc) -eq 'restart_required') { throw 'VC++ Runtime requires a server restart. Restart Windows, then rerun this installer; agent/PHP have not been published or started.' }
    foreach ($path in @('C:\2fa\agent', 'C:\2fa\php')) {
        if (Test-Path -LiteralPath $path) { [IO.Directory]::Delete($path, $false) }
    }
    [IO.Directory]::Move((Join-Path $sourcePath 'agent'), 'C:\2fa\agent')
    $published = $true
    [IO.Directory]::Move($phpPath, 'C:\2fa\php')
    [IO.File]::WriteAllText('C:\2fa\agent\config.json', $configuration, (New-Object Text.UTF8Encoding $false))
    $certificateArguments = @{ PhpPath = 'C:\2fa\php\php.exe'; CAHost = $CAHost; Template = $CertificateTemplate }
    if ($CAConfig) { $certificateArguments.CAConfig = $CAConfig }
    & 'C:\2fa\agent\deploy\Request-AgentCertificate.ps1' @certificateArguments
    & 'C:\2fa\agent\deploy\Install-Agent.ps1' -PhpPath 'C:\2fa\php\php.exe' -CodePath 'C:\2fa\agent' -ConfigPath 'C:\2fa\agent\config.json' -TaskName $TaskName -ServiceAccount $ServiceAccount
    Start-ScheduledTask -TaskName $TaskName
    Write-Output 'Agent installed and started on HTTPS:8443. Config: C:\2fa\agent\config.json; instructions: C:\2fa\docs\instruction.txt.'
    Write-Output 'The server-specific API secret is generated by the offline installer and is not printed. Transfer it to the matching portal slot using the administrator instructions.'
    Write-Output 'If 2fabypass is missing, create it once using the documented local console command and wait for AD replication before granting access.'
} catch {
    if ($published) {
        Write-Warning 'Published agent/PHP files and configuration were preserved. Recover certificate enrollment with deploy\Request-AgentCertificate.ps1 (use -RequestId for a pending request), then run deploy\Install-Agent.ps1 with -PhpPath C:\2fa\php\php.exe; start the scheduled task only after successful installation.'
    }
    throw
} finally {
    if (Test-Path -LiteralPath $staging -PathType Container) { Remove-Item -LiteralPath $staging -Recurse -Force }
}
