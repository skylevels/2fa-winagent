#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\..\deploy\Install-AgentOnline.ps1') -LibraryOnly
Add-Type -AssemblyName System.IO.Compression
$root = Join-Path ([IO.Path]::GetTempPath()) ('2fa-online-test-' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($root)
$count = 0
function Assert-True($Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function Assert-Rejected([scriptblock]$Action) {
    $failed = $false; try { & $Action } catch { $failed = $true }
    Assert-True $failed 'Expected a fail-closed result.'
}
function New-TestZip([string]$Name, [string[]]$Extra = @(), [switch]$Php) {
    $path = Join-Path $root $Name
    $stream = [IO.File]::Open($path, [IO.FileMode]::CreateNew)
    $zip = New-Object IO.Compression.ZipArchive($stream, [IO.Compression.ZipArchiveMode]::Create, $true)
    try {
        $required = if ($Php) { @('php.exe', 'php8.dll', 'ext/php_openssl.dll', 'php.ini-production') } else { @('agent/deploy/Install-Agent.ps1', 'agent/deploy/Request-AgentCertificate.ps1', 'agent/config.example.json', 'agent/vendor/autoload.php') }
        foreach ($entryName in ($required + $Extra)) {
            $entry = $zip.CreateEntry($entryName)
            $writer = New-Object IO.StreamWriter($entry.Open())
            try { $writer.Write('public fixture') } finally { $writer.Dispose() }
        }
    } finally { $zip.Dispose(); $stream.Dispose() }
    return $path
}
try {
    foreach ($url in @('http://downloads.php.net/archive.zip', 'https://downloads.php.net.evil.test/x', 'https://user@downloads.php.net/x', 'https://downloads.php.net:8443/x', 'https://downloads.php.net/x#y')) {
        Assert-Rejected { Assert-AgentOnlineUri ([uri]$url) @('downloads.php.net') }
    }
    Assert-AgentOnlineUri ([uri]'https://downloads.php.net/~windows/releases/php.zip') @('downloads.php.net')
    $count++; Write-Output 'PASS downloader URL validation rejects downgrade, port, credentials and lookalike hosts'

    $file = Join-Path $root 'payload.bin'; [IO.File]::WriteAllText($file, 'public source')
    $digest = (Get-FileHash $file -Algorithm SHA256).Hash.ToLowerInvariant()
    Assert-AgentOnlineHash $file $digest
    Assert-Rejected { Assert-AgentOnlineHash $file ('0' * 64) }
    $checksum = Join-Path $root 'source.sha256'; [IO.File]::WriteAllText($checksum, ($digest + '  windows-agent.zip' + "`n"))
    Assert-True ((Get-AgentOnlineSourceHash $checksum) -ceq $digest) 'Checksum parsing changed digest.'
    [IO.File]::WriteAllText($checksum, ($digest + '  other.zip'))
    Assert-Rejected { Get-AgentOnlineSourceHash $checksum }
    $count++; Write-Output 'PASS source and PHP hash gates reject corruption and a checksum for another file'

    $revision = Join-Path $root 'revision.json'; [IO.File]::WriteAllText($revision, ('{"sha":"' + ('a' * 40) + '"}'))
    Assert-True ((Get-AgentOnlineRevision $revision) -ceq ('a' * 40)) 'Immutable revision parsing failed.'
    foreach ($value in @('{"sha":"main"}', '{"sha":1}', '{"sha":"../escape"}', '{}')) {
        [IO.File]::WriteAllText($revision, $value); Assert-Rejected { Get-AgentOnlineRevision $revision }
    }
    $count++; Write-Output 'PASS source URLs can be based only on a validated immutable Git commit'

    $zip = New-TestZip 'valid.zip'
    $destination = Join-Path $root 'valid'
    Expand-AgentOnlineZip $zip $destination Source
    Assert-True ([IO.File]::Exists((Join-Path $destination 'agent/vendor/autoload.php'))) 'Expected dependency was not extracted.'
    Assert-Rejected { Expand-AgentOnlineZip $zip $destination Source }
    $count++; Write-Output 'PASS a valid complete source ZIP extracts only into a fresh destination'

    $case = 0
    foreach ($extra in @('../escape', '/absolute', 'agent/../../escape', 'agent/a:b', 'agent/NUL.txt', 'agent/a./x', 'agent/a /x', 'agent/a\b', 'agent/CONFIG.json', 'other/file.txt', 'agent/tls/key.txt', 'agent/evil.exe', 'agent/.env')) {
        $case++; $bad = New-TestZip ('unsafe-' + $case + '.zip') @($extra)
        $target = Join-Path $root ('unsafe-' + $case)
        Assert-Rejected { Expand-AgentOnlineZip $bad $target Source }
        Assert-True (-not (Test-Path -LiteralPath $target)) 'Unsafe ZIP created an extraction directory.'
    }
    $count++; Write-Output 'PASS ZIP traversal, ADS, devices, Windows normalization, private files and unknown roots fail before extraction'

    foreach ($extras in @(@('agent/x', 'agent/X'), @('agent/file', 'agent/file/child'))) {
        $case++; $bad = New-TestZip ('collision-' + $case + '.zip') $extras
        Assert-Rejected { Expand-AgentOnlineZip $bad (Join-Path $root ('collision-' + $case)) Source }
    }
    $count++; Write-Output 'PASS ZIP case collisions and file-parent conflicts are rejected'

    foreach ($length in @(1, 9)) {
        $input = New-Object IO.MemoryStream(,[Text.Encoding]::UTF8.GetBytes('abcd'))
        $output = New-Object IO.MemoryStream
        $expanded = 0L
        try { Assert-Rejected { Copy-AgentOnlineZipEntry $input $output $length ([ref]$expanded) } }
        finally { $input.Dispose(); $output.Dispose() }
    }
    $input = New-Object IO.MemoryStream(,[Text.Encoding]::UTF8.GetBytes('abcd'))
    $output = New-Object IO.MemoryStream
    $expanded = 599999999L
    try { Assert-Rejected { Copy-AgentOnlineZipEntry $input $output 4 ([ref]$expanded) } }
    finally { $input.Dispose(); $output.Dispose() }
    $count++; Write-Output 'PASS actual ZIP byte counts reject false metadata and total expansion overflow'

    $php = New-TestZip 'php.zip' -Php
    Expand-AgentOnlineZip $php (Join-Path $root 'php') Php
    Assert-Rejected { Expand-AgentOnlineZip $zip (Join-Path $root 'not-php') Php }
    $count++; Write-Output 'PASS PHP extraction requires executable, runtime DLL, OpenSSL and production template'

    Assert-AgentOnlineMicrosoftSignature ([pscustomobject]@{ Status='Valid'; SignerCertificate=[pscustomobject]@{ Subject='CN=Microsoft Corporation, O=Microsoft Corporation, C=US' } })
    foreach ($signature in @(
        [pscustomobject]@{ Status='NotSigned'; SignerCertificate=$null },
        [pscustomobject]@{ Status='HashMismatch'; SignerCertificate=[pscustomobject]@{ Subject='O=Microsoft Corporation' } },
        [pscustomobject]@{ Status='Valid'; SignerCertificate=[pscustomobject]@{ Subject='CN=Microsoft Corporation, O=Microsoft Corporation Evil, C=US' } },
        [pscustomobject]@{ Status='Valid'; SignerCertificate=[pscustomobject]@{ Subject='CN=Other vendor' } }
    )) { Assert-Rejected { Assert-AgentOnlineMicrosoftSignature $signature } }
    $count++; Write-Output 'PASS Microsoft signer validation requires both valid Authenticode and exact company identity'

    Assert-True ((Get-AgentOnlineVcResult 0) -eq 'ready') 'Success was not recognized.'
    Assert-True ((Get-AgentOnlineVcResult 1638) -eq 'ready') 'Already installed result was not recognized.'
    Assert-True ((Get-AgentOnlineVcResult 3010) -eq 'restart_required') 'Restart requirement was lost.'
    Assert-Rejected { Get-AgentOnlineVcResult 1603 }
    $count++; Write-Output 'PASS VC++ exit handling distinguishes success, installed version, reboot and failure'

    function Start-Process {
        param($FilePath, $ArgumentList, [switch]$PassThru)
        return $script:vcProcess
    }
    $script:vcProcess = [pscustomobject]@{ ExitCode=0; Killed=$false; Disposed=$false; Waits=0 }
    $script:vcProcess | Add-Member ScriptMethod WaitForExit { param($Milliseconds) $this.Waits++; return $false }
    $script:vcProcess | Add-Member ScriptMethod Kill { $this.Killed=$true }
    $script:vcProcess | Add-Member ScriptMethod Dispose { $this.Disposed=$true }
    Assert-Rejected { Invoke-AgentOnlineVcInstall 'fixture.exe' }
    Assert-True ($script:vcProcess.Killed -and $script:vcProcess.Disposed -and $script:vcProcess.Waits -eq 2) 'A hung prerequisite installer was not terminated and disposed.'
    $count++; Write-Output 'PASS VC++ execution has a finite wait and no continuation after timeout'

    $production = '; extension_dir = "ext"' + "`r`n" + ';extension=openssl' + "`r`n"
    $ini = New-AgentOnlinePhpIni $production
    Assert-True ($ini.Contains('extension_dir = "C:/2fa/php/ext"') -and $ini.Contains('extension=openssl')) 'OpenSSL preparation failed.'
    Assert-Rejected { New-AgentOnlinePhpIni 'extension_dir="untrusted"' }
    $count++; Write-Output 'PASS PHP uses the official production template and its own enabled OpenSSL extension'

    $template = [IO.File]::ReadAllText((Join-Path $PSScriptRoot '..\..\config.example.json'))
    $config = New-AgentOnlineConfig $template 'DC1.example.test' 'DC1' '192.0.2.10' | ConvertFrom-Json
    Assert-True ($config.domainController -ceq 'dc1.example.test' -and $config.agentId -ceq 'dc1' -and $config.port -eq 8443 -and $config.allowedIPs[0] -ceq '192.0.2.10' -and $config.apiSecretHex -ceq 'GENERATED_BY_INSTALLER') 'Generated configuration was not safe or local.'
    foreach ($ip in @('mobile.example.test', '192.0.2.0/24', '127.1', '010.1.2.3', 'fe80::1%12', '')) {
        Assert-Rejected { New-AgentOnlineConfig $template 'dc1.example.test' 'dc1' $ip }
    }
    $count++; Write-Output 'PASS fresh configuration uses detected controller, exact IP, port8443 and installer-generated secret placeholder'

    $realDownload = ${function:Save-AgentOnlineDownload}
    $realHash = ${function:Assert-AgentOnlineHash}
    try {
        $script:downloadUris = New-Object 'Collections.Generic.List[string]'
        $script:failStatus = 404
        function Save-AgentOnlineDownload {
            param($Uri, $Destination, $Hosts, $MaximumBytes)
            $script:downloadUris.Add([string]$Uri)
            if ($script:downloadUris.Count -eq 1) {
                $error = New-Object InvalidOperationException('fixture')
                $error.Data['HttpStatus'] = $script:failStatus
                throw $error
            }
        }
        function Assert-AgentOnlineHash { param($Path, $Expected) Assert-True ($Expected -eq 'dbae154a0a89791f36c3d48e68bae797878333e7d6cb5721e74617de59b63ab7') 'PHP fallback changed its pinned digest.' }
        Save-AgentOnlinePhp (Join-Path $root 'download.zip')
        Assert-True ($script:downloadUris.Count -eq 2 -and $script:downloadUris[1].Contains('/archives/')) 'A removed release did not use the official archive fallback.'
        $script:downloadUris.Clear(); $script:failStatus = 503
        Assert-Rejected { Save-AgentOnlinePhp (Join-Path $root 'download.zip') }
        Assert-True ($script:downloadUris.Count -eq 1) 'An untrusted failure silently switched download sources.'
        $count++; Write-Output 'PASS PHP archive fallback occurs only on HTTP404 and retains the pinned SHA256'
    } finally {
        ${function:Save-AgentOnlineDownload} = $realDownload
        ${function:Assert-AgentOnlineHash} = $realHash
    }

    Add-Type -AssemblyName System.Net.Http
    $script:httpTasks = New-Object 'Collections.Generic.Queue[object]'
    $script:httpUris = New-Object 'Collections.Generic.List[string]'
    $script:cancelled = 0; $script:disposed = 0
    $realFactory = ${function:New-AgentOnlineHttpClient}
    function New-CompletedHttpTask([int]$Status, [string]$Location = '', [string]$Body = 'download') {
        $bytesTask = New-Object 'Threading.Tasks.TaskCompletionSource[byte[]]'
        $bytesTask.SetResult([Text.Encoding]::UTF8.GetBytes($Body))
        $content = [pscustomobject]@{ Bytes = $bytesTask.Task }
        $content | Add-Member ScriptMethod ReadAsByteArrayAsync { return $this.Bytes }
        $response = [pscustomobject]@{ StatusCode=$Status; Headers=[pscustomobject]@{ Location=if($Location){[uri]$Location}else{$null} }; Content=$content }
        $response | Add-Member ScriptMethod Dispose { }
        $completion = New-Object 'Threading.Tasks.TaskCompletionSource[object]'
        $completion.SetResult($response)
        return $completion.Task
    }
    function New-AgentOnlineHttpClient {
        param($MaximumBytes, $TimeoutSeconds)
        $client = [pscustomobject]@{}
        $client | Add-Member ScriptMethod GetAsync { param($Uri,$Option) $script:httpUris.Add($Uri.AbsoluteUri); return $script:httpTasks.Dequeue() }
        $client | Add-Member ScriptMethod CancelPendingRequests { $script:cancelled++ }
        $client | Add-Member ScriptMethod Dispose { $script:disposed++ }
        $handler = [pscustomobject]@{}
        $handler | Add-Member ScriptMethod Dispose { $script:disposed++ }
        return [pscustomobject]@{ Client=$client; Handler=$handler }
    }
    try {
        $script:httpTasks.Enqueue((New-CompletedHttpTask 302 'https://raw.githubusercontent.com/source.zip'))
        $script:httpTasks.Enqueue((New-CompletedHttpTask 200 -Body 'source'))
        $download = Join-Path $root 'bounded-download'
        Save-AgentOnlineDownload 'https://api.github.com/start' $download @('api.github.com','raw.githubusercontent.com') 64 2
        Assert-True ([IO.File]::ReadAllText($download) -ceq 'source' -and $script:httpUris.Count -eq 2 -and $script:disposed -eq 2) 'Successful download or cleanup failed.'
        $script:httpTasks.Enqueue((New-CompletedHttpTask 302 'http://raw.githubusercontent.com/insecure'))
        $before = $script:httpUris.Count
        Assert-Rejected { Save-AgentOnlineDownload 'https://api.github.com/start' (Join-Path $root 'downgrade') @('api.github.com','raw.githubusercontent.com') 64 2 }
        Assert-True ($script:httpUris.Count -eq $before + 1 -and -not (Test-Path (Join-Path $root 'downgrade'))) 'An insecure redirect reached the transport or wrote output.'
        $count++; Write-Output 'PASS complete downloader follows only allowlisted HTTPS redirects and cleans resources'

        $never = New-Object 'Threading.Tasks.TaskCompletionSource[object]'
        $script:httpTasks.Enqueue($never.Task)
        $started = [Diagnostics.Stopwatch]::StartNew()
        Assert-Rejected { Save-AgentOnlineDownload 'https://api.github.com/stalled' (Join-Path $root 'stalled') @('api.github.com') 64 1 }
        Assert-True ($started.Elapsed.TotalSeconds -lt 3 -and $script:cancelled -gt 0 -and -not (Test-Path (Join-Path $root 'stalled'))) 'A stalled whole-body task exceeded the finite download deadline.'
        $count++; Write-Output 'PASS total download deadline cancels a stalled response task and publishes no partial file'
    } finally { ${function:New-AgentOnlineHttpClient} = $realFactory }
} finally { Remove-Item -LiteralPath $root -Recurse -Force }
Write-Output ('Passed ' + $count + ' online installer tests. No downloads, Windows services, certificates or prerequisite installers were executed.')
