#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$PhpPath = 'C:\Program Files\PHP\php.exe',
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9.-]{1,252}$')][string]$CAHost = 'dosifey.elemer.org',
    [string]$CAConfig = '',
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$')][string]$Template = 'WebServer10y',
    [ValidateRange(0, 2147483647)][int]$RequestId = 0,
    [switch]$LibraryOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function New-AgentCertificateRequestText {
    param([string]$DnsName, [string]$TemplateName)
    if ($DnsName -notmatch '^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z][A-Za-z0-9-]{0,62}$' -or
        $TemplateName -notmatch '^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$') { throw 'Invalid certificate identity or template.' }
    return @(
        '[Version]', 'Signature="$Windows NT$"', '', '[NewRequest]',
        ('Subject="CN=' + $DnsName.ToLowerInvariant() + '"'),
        'Exportable=TRUE', 'MachineKeySet=TRUE', 'KeyAlgorithm=RSA', 'KeyLength=3072',
        'KeySpec=1', 'KeyUsage=0xa0', 'ProviderName="Microsoft RSA SChannel Cryptographic Provider"',
        'ProviderType=12', 'HashAlgorithm=sha256', 'RequestType=PKCS10', '',
        '[Extensions]', ('2.5.29.17="{text}DNS=' + $DnsName.ToLowerInvariant() + '"'), '',
        '[EnhancedKeyUsageExtension]', 'OID=1.3.6.1.5.5.7.3.1', '',
        '[RequestAttributes]', ('CertificateTemplate=' + $TemplateName), ''
    ) -join "`r`n"
}

function Get-AgentTemplateValiditySeconds {
    param([byte[]]$RawPeriod)
    if ($RawPeriod.Length -ne 8) { throw 'The template validity period must be an 8-byte interval.' }
    # AD certificate-template periods use a negative, little-endian FILETIME interval.
    $bytes = [byte[]]$RawPeriod.Clone()
    if (-not [BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes) }
    $ticks = [BitConverter]::ToInt64($bytes, 0)
    if ($ticks -ge 0 -or $ticks -eq [long]::MinValue) { throw 'The template validity interval is invalid.' }
    $seconds = [long](-$ticks / [TimeSpan]::TicksPerSecond)
    if ($seconds -lt (3650L * 86400) -or $seconds -gt (3653L * 86400)) {
        throw 'The selected existing template does not have a ten-year validity period.'
    }
    return $seconds
}

function Assert-AgentCertificateValidity {
    param([DateTime]$NotBefore, [DateTime]$NotAfter, [long]$ExpectedSeconds, [DateTime]$NowUtc = [DateTime]::UtcNow)
    if ($ExpectedSeconds -lt (3650L * 86400) -or $ExpectedSeconds -gt (3653L * 86400)) { throw 'An expected ten-year template interval is required.' }
    if ($NotBefore.ToUniversalTime() -gt $NowUtc.AddMinutes(5) -or $NotAfter.ToUniversalTime() -le $NowUtc -or
        ($NotAfter.ToUniversalTime() - $NotBefore.ToUniversalTime()).TotalSeconds -lt ($ExpectedSeconds - 86400)) {
        throw ('Certificate validity is insufficient: ' + $NotBefore.ToUniversalTime().ToString('o') + ' to ' + $NotAfter.ToUniversalTime().ToString('o') + '. Check the existing ten-year template and CA limits/remaining lifetime with the CA administrator.')
    }
}

function ConvertTo-AgentCertificatePem {
    param([byte[]]$RawData)
    return "-----BEGIN CERTIFICATE-----`n" + [Convert]::ToBase64String($RawData, [Base64FormattingOptions]::InsertLineBreaks).Replace("`r`n", "`n") + "`n-----END CERTIFICATE-----`n"
}

if ($LibraryOnly) { return }
if ($env:OS -ne 'Windows_NT') { throw 'Certificate enrollment requires Windows Server and an elevated local administrator console.' }

# Reuse the installer's SID-based ACL routines before creating any private key file.
$enrollmentPhpPath = $PhpPath
. (Join-Path $PSScriptRoot 'Install-Agent.ps1') -LibraryOnly
Assert-AgentAdministrator
$PhpPath = Resolve-AgentLocalPath $enrollmentPhpPath
if ([IO.Path]::GetFileName($PhpPath) -ine 'php.exe') { throw 'PhpPath must point to php.exe with the OpenSSL extension enabled.' }
Assert-AgentNoReparse $PhpPath
$codePath = Resolve-AgentLocalPath 'C:\2fa\agent'
$rootPath = Resolve-AgentLocalPath 'C:\2fa'
$tlsPath = Join-Path $codePath 'tls'
$exportScript = Join-Path $codePath 'bin\export-certificate.php'
if (-not (Test-Path -LiteralPath $exportScript -PathType Leaf)) { throw 'The certificate export helper is missing.' }
Assert-AgentNoReparse $rootPath
Assert-AgentNoReparse $codePath
& $PhpPath $exportScript --check
if ($LASTEXITCODE -ne 0) { throw 'Enable the OpenSSL extension in PHP 8.2 or newer before requesting a certificate.' }
if (Test-Path -LiteralPath $tlsPath) {
    if (-not (Test-Path -LiteralPath $tlsPath -PathType Container)) { throw 'The TLS path must be a directory.' }
    Assert-AgentNoReparse $tlsPath
}
foreach ($name in @('agent.crt.pem', 'agent.key.pem', 'ca-chain.pem')) {
    if (Test-Path -LiteralPath (Join-Path $tlsPath $name)) { throw 'TLS files already exist. This initial-enrollment command does not replace a running agent certificate or its permissions.' }
}
Import-Module ActiveDirectory -ErrorAction Stop
$machine = Get-CimInstance -ClassName Win32_ComputerSystem
if (-not [bool]$machine.PartOfDomain -or [int]$machine.DomainRole -notin @(4, 5)) { throw 'Run certificate enrollment on the target domain controller.' }
$dnsName = ([string]$machine.DNSHostName + '.' + [string]$machine.Domain).ToLowerInvariant()
$domainSid = (Get-ADDomain -Server $dnsName).DomainSID.Value
$domainAdminsSid = New-Object Security.Principal.SecurityIdentifier ($domainSid + '-512')
$systemSid = New-Object Security.Principal.SecurityIdentifier 'S-1-5-18'
Set-AgentPrivateAcl -Path $rootPath -DomainAdminsSid $domainAdminsSid -RunSid $systemSid -ServiceRights None -Recurse $false
Set-AgentPrivateAcl -Path $codePath -DomainAdminsSid $domainAdminsSid -RunSid $systemSid -ServiceRights None
if (-not (Test-Path -LiteralPath $tlsPath)) { $null = New-Item -Path $tlsPath -ItemType Directory }
Assert-AgentNoReparse $tlsPath
Set-AgentPrivateAcl -Path $tlsPath -DomainAdminsSid $domainAdminsSid -RunSid $systemSid -ServiceRights None

$configurationDn = (Get-ADRootDSE -Server $dnsName).configurationNamingContext
$services = @(Get-ADObject -Server $dnsName -SearchBase ('CN=Enrollment Services,CN=Public Key Services,CN=Services,' + $configurationDn) -LDAPFilter '(objectClass=pKIEnrollmentService)' -Properties dNSHostName, certificateTemplates | Where-Object { $_.dNSHostName -ieq $CAHost })
if ([string]::IsNullOrEmpty($CAConfig)) {
    if ($services.Count -ne 1) { throw 'CA discovery did not find exactly one enterprise CA on CAHost. Specify -CAConfig "dosifey.elemer.org\CA name".' }
    $CAConfig = $CAHost + '\' + $services[0].Name
}
if ($CAConfig -match '["\x00-\x1f]' -or $CAConfig -notmatch '^([^\\]+)\\([^\\]+)$' -or $Matches[1] -ine $CAHost) {
    throw 'CAConfig must contain the selected CAHost followed by a single CA name.'
}
$caName = $CAConfig.Substring($CAConfig.IndexOf('\') + 1)
$selected = @($services | Where-Object { $_.Name -ieq $caName })
if ($selected.Count -ne 1 -or @($selected[0].certificateTemplates) -notcontains $Template) {
    throw 'The requested existing certificate template is not published on the selected enterprise CA. Check -Template and -CAConfig with the CA administrator.'
}
$templateObject = Get-ADObject -Server $dnsName -Identity ('CN=' + $Template + ',CN=Certificate Templates,CN=Public Key Services,CN=Services,' + $configurationDn) -Properties pKIExpirationPeriod
$expectedValiditySeconds = Get-AgentTemplateValiditySeconds ([byte[]]$templateObject.pKIExpirationPeriod)
$workPath = Join-Path $tlsPath ('.enrollment-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -Path $workPath -ItemType Directory
Set-AgentPrivateAcl -Path $workPath -DomainAdminsSid $domainAdminsSid -RunSid $systemSid -ServiceRights None
$certreq = Join-Path $env:SystemRoot 'System32\certreq.exe'
$issuedPath = Join-Path $workPath 'issued.cer'
$pfxPath = Join-Path $workPath 'temporary.pfx'
$chain = $null
$process = $null
$published = @()
try {
    if ($RequestId -eq 0) {
        $infPath = Join-Path $workPath 'request.inf'
        $csrPath = Join-Path $workPath 'request.req'
        [IO.File]::WriteAllText($infPath, (New-AgentCertificateRequestText $dnsName $Template), [Text.Encoding]::ASCII)
        & $certreq -new -q -machine $infPath $csrPath
        if ($LASTEXITCODE -ne 0) { throw 'certreq could not create the machine certificate request.' }
        & $certreq -submit -q -config $CAConfig -attrib ('CertificateTemplate:' + $Template) $csrPath $issuedPath
    } else {
        & $certreq -retrieve -q -config $CAConfig $RequestId $issuedPath
    }
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $issuedPath -PathType Leaf)) {
        throw 'The CA did not issue a certificate. For a pending request, obtain CA approval and rerun this command with -RequestId using the ID printed by certreq.'
    }
    $issued = New-Object Security.Cryptography.X509Certificates.X509Certificate2 $issuedPath
    Assert-AgentCertificateValidity $issued.NotBefore $issued.NotAfter $expectedValiditySeconds
    & $certreq -accept -q -machine $issuedPath
    if ($LASTEXITCODE -ne 0) { throw 'certreq could not associate the issued certificate with its local machine private key.' }
    $certificate = Get-Item -LiteralPath ('Cert:\LocalMachine\My\' + $issued.Thumbprint)
    if (-not $certificate.HasPrivateKey) { throw 'The issued certificate has no private key on this machine.' }
    $chain = New-Object Security.Cryptography.X509Certificates.X509Chain
    $chain.ChainPolicy.RevocationMode = [Security.Cryptography.X509Certificates.X509RevocationMode]::Online
    $chain.ChainPolicy.RevocationFlag = [Security.Cryptography.X509Certificates.X509RevocationFlag]::ExcludeRoot
    $chain.ChainPolicy.UrlRetrievalTimeout = [TimeSpan]::FromSeconds(15)
    $null = $chain.ChainPolicy.ApplicationPolicy.Add((New-Object Security.Cryptography.Oid '1.3.6.1.5.5.7.3.1'))
    if (-not $chain.Build($certificate) -or $chain.ChainElements.Count -lt 2) {
        throw 'The issued certificate does not build a trusted, unrevoked server-authentication chain on this controller. Check CA trust and CRL availability.'
    }
    $randomBytes = New-Object byte[] 32
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($randomBytes) } finally { $rng.Dispose() }
    $password = ([BitConverter]::ToString($randomBytes)).Replace('-', '').ToLowerInvariant()
    $securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force
    try { $null = Export-PfxCertificate -Cert $certificate -FilePath $pfxPath -Password $securePassword -ChainOption EndEntityCertOnly -CryptoAlgorithmOption AES256_SHA256 -NoProperties -NoClobber }
    finally { $securePassword.Dispose() }
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $PhpPath
    $start.Arguments = '"' + $exportScript + '"'
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $start
    $null = $process.Start()
    $outputTask = $process.StandardOutput.ReadToEndAsync()
    $errorTask = $process.StandardError.ReadToEndAsync()
    # .NET Framework used by Windows PowerShell 5.1 has no StandardInputEncoding.
    # Write UTF-8 bytes directly to the pipe without a BOM.
    $requestJson = @{ pfxPath = $pfxPath; password = $password; outputDirectory = $workPath; dnsName = $dnsName; expectedValiditySeconds = $expectedValiditySeconds } | ConvertTo-Json -Compress
    $inputBytes = (New-Object Text.UTF8Encoding $false).GetBytes($requestJson + "`n")
    $process.StandardInput.BaseStream.Write($inputBytes, 0, $inputBytes.Length)
    $process.StandardInput.BaseStream.Flush()
    $process.StandardInput.Close()
    $password = $null
    $requestJson = $null
    [Array]::Clear($inputBytes, 0, $inputBytes.Length)
    if (-not $process.WaitForExit(30000)) { $process.Kill(); $null = $process.WaitForExit(5000); throw 'PHP certificate conversion timed out.' }
    if ($process.ExitCode -ne 0) { throw 'PHP certificate conversion rejected the certificate. Check PHP OpenSSL, SAN, ten-year validity, server EKU, and RSA key size.' }
    $result = $outputTask.Result | ConvertFrom-Json
    if ($result.ok -ne $true -or $result.thumbprint -ine $certificate.Thumbprint) { throw 'PHP certificate conversion did not confirm the expected certificate.' }
    $chainPem = ''
    $intermediates = ''
    for ($i = 1; $i -lt $chain.ChainElements.Count; $i++) {
        $pem = ConvertTo-AgentCertificatePem $chain.ChainElements[$i].Certificate.RawData
        $chainPem += $pem
        if ($i -lt $chain.ChainElements.Count - 1) { $intermediates += $pem }
    }
    [IO.File]::AppendAllText((Join-Path $workPath 'agent.crt.pem'), $intermediates, (New-Object Text.UTF8Encoding $false))
    [IO.File]::WriteAllText((Join-Path $workPath 'ca-chain.pem'), $chainPem, (New-Object Text.UTF8Encoding $false))
    foreach ($name in @('agent.crt.pem', 'agent.key.pem', 'ca-chain.pem')) {
        $target = Join-Path $tlsPath $name
        [IO.File]::Move((Join-Path $workPath $name), $target)
        $published += $target
    }
    Set-AgentPrivateAcl -Path $tlsPath -DomainAdminsSid $domainAdminsSid -RunSid $systemSid -ServiceRights None
    [pscustomobject]@{ DnsName = $dnsName; CA = $CAConfig; Template = $Template; TemplateValidityDays = ($expectedValiditySeconds / 86400); Thumbprint = $certificate.Thumbprint; NotBeforeUtc = $certificate.NotBefore.ToUniversalTime().ToString('o'); NotAfterUtc = $certificate.NotAfter.ToUniversalTime().ToString('o'); Certificate = (Join-Path $tlsPath 'agent.crt.pem'); PrivateKey = (Join-Path $tlsPath 'agent.key.pem'); PublicCAChain = (Join-Path $tlsPath 'ca-chain.pem') }
} catch {
    foreach ($path in $published) { if ([IO.File]::Exists($path)) { [IO.File]::Delete($path) } }
    throw
} finally {
    $password = $null
    if ($null -ne $process) { $process.Dispose() }
    if ($null -ne $chain) { $chain.Dispose() }
    if (Test-Path -LiteralPath $workPath) { Remove-Item -LiteralPath $workPath -Recurse -Force }
}
