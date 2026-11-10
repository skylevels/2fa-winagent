#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$InputsDirectory = (Join-Path $PSScriptRoot '..\.build\inputs'),
    [string]$VendorDirectory = (Join-Path $PSScriptRoot '..\.build\vendor')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'Dependency preparation uses the pinned official Windows PHP and must run on Windows.'
}
$agent = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$inputs = [IO.Path]::GetFullPath($InputsDirectory)
$vendor = [IO.Path]::GetFullPath($VendorDirectory)

function Assert-PlainBuildPath([string]$Path) {
    $candidate = [IO.Path]::GetFullPath($Path)
    while ($candidate) {
        if (Test-Path -LiteralPath $candidate) {
            $item = Get-Item -LiteralPath $candidate -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'Build paths must not contain links or reparse points.'
            }
        }
        $candidate = [IO.Path]::GetDirectoryName($candidate)
    }
}

function Receive-PinnedComponent($Component) {
    if ([IO.Path]::GetFileName([string]$Component.filename) -cne [string]$Component.filename) {
        throw 'The component filename must be a basename.'
    }
    $destination = Join-Path $inputs ([string]$Component.filename)
    Assert-PlainBuildPath $destination
    if (Test-Path -LiteralPath $destination -PathType Leaf) {
        if ((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash -ine $Component.sha256) {
            throw ('Cached component checksum mismatch: ' + $Component.filename)
        }
        return $destination
    }
    $temporary = Join-Path $inputs ('.download-' + [guid]::NewGuid().ToString('N'))
    $uri = [uri]$Component.url
    try {
        for ($redirects = 0; $redirects -le 5; $redirects++) {
            if ($uri.Scheme -cne 'https') { throw 'Component downloads require HTTPS, including redirects.' }
            $request = [Net.HttpWebRequest]::Create($uri)
            $request.AllowAutoRedirect = $false
            $request.Timeout = 30000
            $request.ReadWriteTimeout = 30000
            $response = $request.GetResponse()
            try {
                if ([int]$response.StatusCode -in @(301, 302, 303, 307, 308)) {
                    $uri = New-Object uri $uri, ([string]$response.Headers['Location'])
                    continue
                }
                if ([int]$response.StatusCode -ne 200 -or $response.ContentLength -gt [long]$Component.maximum_bytes) {
                    throw 'Unexpected component response or size.'
                }
                $source = $response.GetResponseStream()
                $output = [IO.File]::Open($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
                try {
                    $buffer = New-Object byte[] 65536
                    $total = 0L
                    while (($count = $source.Read($buffer, 0, $buffer.Length)) -gt 0) {
                        $total += $count
                        if ($total -gt [long]$Component.maximum_bytes) { throw 'Component download exceeds its size limit.' }
                        $output.Write($buffer, 0, $count)
                    }
                } finally { $output.Dispose(); $source.Dispose() }
                break
            } finally { $response.Dispose() }
        }
        if (-not (Test-Path -LiteralPath $temporary -PathType Leaf)) { throw 'Too many component redirects.' }
        if ((Get-FileHash -LiteralPath $temporary -Algorithm SHA256).Hash -ine $Component.sha256) {
            throw ('Downloaded component checksum mismatch: ' + $Component.filename)
        }
        Move-Item -LiteralPath $temporary -Destination $destination
        return $destination
    } finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force }
    }
}

function Expand-PinnedPhp([string]$Archive, [string]$Destination) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $root = [IO.Path]::GetFullPath($Destination).TrimEnd('\') + '\'
    $zip = [IO.Compression.ZipFile]::OpenRead($Archive)
    try {
        if ($zip.Entries.Count -gt 1000) { throw 'PHP archive contains too many entries.' }
        $total = 0L
        $names = @{}
        foreach ($entry in $zip.Entries) {
            $relative = [string]$entry.FullName
            if ($relative.Contains('\') -or $relative.Contains(':') -or $relative.StartsWith('/') -or
                @($relative.Split('/') | Where-Object { $_ -eq '..' }).Count -gt 0 -or
                (($entry.ExternalAttributes -shr 16) -band 0xf000) -eq 0xa000) {
                throw 'Unsafe PHP archive member.'
            }
            $path = [IO.Path]::GetFullPath((Join-Path $Destination $relative.Replace('/', '\')))
            if (-not $path.StartsWith($root, [StringComparison]::OrdinalIgnoreCase) -or $names.ContainsKey($path)) {
                throw 'Duplicate or escaping PHP archive member.'
            }
            $names[$path] = $true
            $total += $entry.Length
            if ($entry.Length -gt 150MB -or $total -gt 400MB -or $entry.Length -gt [Math]::Max(1MB, $entry.CompressedLength * 200)) {
                throw 'PHP archive exceeds size/ratio limits.'
            }
            if ($relative.EndsWith('/')) { $null = New-Item -ItemType Directory -Path $path -Force; continue }
            $null = New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($path)) -Force
            $source = $entry.Open()
            $output = [IO.File]::Open($path, [IO.FileMode]::CreateNew)
            try { $source.CopyTo($output) } finally { $output.Dispose(); $source.Dispose() }
        }
    } finally { $zip.Dispose() }
}

Assert-PlainBuildPath $agent
Assert-PlainBuildPath $inputs
Assert-PlainBuildPath $vendor
if (Test-Path -LiteralPath $vendor) { throw 'Choose a new VendorDirectory; existing source/vendor trees are never replaced.' }
$null = New-Item -ItemType Directory -Path $inputs -Force
$pins = (Get-Content -LiteralPath (Join-Path $PSScriptRoot 'download-inputs.json') -Raw -Encoding UTF8 | ConvertFrom-Json).components
$originalProtocol = [Net.ServicePointManager]::SecurityProtocol
$originalComposerEnvironment = @{}
foreach ($name in @('COMPOSER', 'COMPOSER_HOME', 'COMPOSER_CACHE_DIR', 'COMPOSER_VENDOR_DIR', 'COMPOSER_AUTH')) {
    $originalComposerEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
$workspace = Join-Path $inputs ('.prepare-' + [guid]::NewGuid().ToString('N'))
try {
    [Net.ServicePointManager]::SecurityProtocol = $originalProtocol -bor [Net.SecurityProtocolType]::Tls12
    $phpArchive = Receive-PinnedComponent $pins.php
    $vc = Receive-PinnedComponent $pins.visual_cpp
    $composer = Receive-PinnedComponent $pins.composer
    $signature = Get-AuthenticodeSignature -LiteralPath $vc
    if ($signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate -or
        $signature.SignerCertificate.Subject -notmatch '(^|,)\s*O=Microsoft Corporation(,|$)') {
        throw 'The VC++ installer must have a valid Microsoft Corporation Authenticode signature.'
    }
    $null = New-Item -ItemType Directory -Path $workspace
    $runtime = Join-Path $workspace 'php'
    $null = New-Item -ItemType Directory -Path $runtime
    Expand-PinnedPhp $phpArchive $runtime
    $extensionDirectory = (Join-Path $runtime 'ext').Replace('\', '/')
    $php = Join-Path $runtime 'php.exe'
    # -n prevents machine/user PHP configuration from loading other binaries.
    # ZIP support allows Composer to install its locked archives without git/unzip.
    $phpOptions = @('-n', '-d', ('extension_dir=' + $extensionDirectory), '-d', 'extension=openssl', '-d', 'extension=zip')
    & $php @phpOptions --ri openssl | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Pinned PHP could not run with OpenSSL. Install the verified VC++ runtime on this build machine first.' }
    & $php @phpOptions --ri zip | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Pinned PHP could not load its official ZIP extension.' }
    $project = Join-Path $workspace 'project'
    $null = New-Item -ItemType Directory -Path $project
    foreach ($name in @('composer.json', 'composer.lock')) {
        Assert-PlainBuildPath (Join-Path $agent $name)
        Copy-Item -LiteralPath (Join-Path $agent $name) -Destination (Join-Path $project $name)
    }
    # Copying only metadata prevents Composer from touching the live source tree.
    $env:COMPOSER = Join-Path $project 'composer.json'
    $env:COMPOSER_HOME = Join-Path $workspace 'composer-home'
    $env:COMPOSER_CACHE_DIR = Join-Path $workspace 'composer-cache'
    $env:COMPOSER_VENDOR_DIR = Join-Path $project 'vendor'
    $env:COMPOSER_AUTH = '{}'
    & $php @phpOptions $composer install --working-dir $project --no-dev --prefer-dist --no-plugins --no-scripts --no-interaction --no-progress
    if ($LASTEXITCODE -ne 0) { throw 'Locked Composer installation failed.' }
    $null = New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($vendor)) -Force
    Assert-PlainBuildPath $vendor
    Move-Item -LiteralPath (Join-Path $project 'vendor') -Destination $vendor
    Write-Output ('Prepared hash-pinned runtime inputs: ' + $inputs)
    Write-Output ('Prepared locked PHP dependencies: ' + $vendor)
    Write-Output 'No service, firewall, domain or installed agent was changed.'
} finally {
    [Net.ServicePointManager]::SecurityProtocol = $originalProtocol
    foreach ($name in $originalComposerEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($name, $originalComposerEnvironment[$name], 'Process')
    }
    if (Test-Path -LiteralPath $workspace) { Remove-Item -LiteralPath $workspace -Recurse -Force }
}
