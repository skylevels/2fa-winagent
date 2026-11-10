#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\..\deploy\Request-AgentCertificate.ps1') -LibraryOnly
$count = 0
function Assert-True($Value, [string]$Message) { if (-not $Value) { throw $Message } }
function Assert-Rejected([scriptblock]$Operation) {
    $failed = $false
    try { & $Operation } catch { $failed = $true }
    Assert-True $failed 'Unsafe certificate request was not rejected.'
}
$request = New-AgentCertificateRequestText 'DOSIFEY.elemer.org' 'WebServer10y'
Assert-True ($request.Contains('Subject="CN=dosifey.elemer.org"')) 'Incorrect certificate subject.'
Assert-True ($request.Contains('2.5.29.17="{text}DNS=dosifey.elemer.org"')) 'SAN is missing.'
Assert-True ($request.Contains('CertificateTemplate=WebServer10y')) 'Existing template was not selected.'
Assert-True ($request.Contains('MachineKeySet=TRUE') -and $request.Contains('Exportable=TRUE') -and $request.Contains('HashAlgorithm=sha256')) 'Incorrect machine key settings.'
$count++; Write-Output 'PASS machine certificate request uses local DNS SAN and the existing template'
Assert-Rejected { New-AgentCertificateRequestText "host.elemer.org`r`nExportable=FALSE" 'WebServer10y' }
Assert-Rejected { New-AgentCertificateRequestText 'host.elemer.org' 'bad"template' }
Assert-Rejected { New-AgentCertificateRequestText 'localhost' 'WebServer10y' }
$count++; Write-Output 'PASS request identity and template reject INF injection and non-FQDN identities'
$now = [DateTime]::Parse('2026-11-05T12:00:00Z').ToUniversalTime()
$seconds = 3650L * 86400
Assert-AgentCertificateValidity $now.AddHours(-1) $now.AddDays(3650) $seconds $now
Assert-Rejected { Assert-AgentCertificateValidity $now $now.AddYears(2) $seconds $now }
Assert-Rejected { Assert-AgentCertificateValidity $now.AddHours(1) $now.AddDays(3650) $seconds $now }
Assert-Rejected { Assert-AgentCertificateValidity $now.AddYears(-11) $now.AddYears(-1) $seconds $now }
$count++; Write-Output 'PASS actual validity accepts ten years and rejects short future or expired certificates'
$periodBytes = [BitConverter]::GetBytes(-[long]($seconds * [TimeSpan]::TicksPerSecond))
Assert-True ((Get-AgentTemplateValiditySeconds $periodBytes) -eq $seconds) 'Incorrect AD template interval conversion.'
Assert-Rejected { Get-AgentTemplateValiditySeconds ([BitConverter]::GetBytes(-[long](365L * 86400 * [TimeSpan]::TicksPerSecond))) }
Assert-Rejected { Get-AgentTemplateValiditySeconds ([byte[]](0, 1)) }
$count++; Write-Output 'PASS template FILETIME accepts 3650-day ten-year duration and rejects shorter or invalid periods'
$raw = [byte[]](0..255)
$pem = ConvertTo-AgentCertificatePem $raw
$decoded = [Convert]::FromBase64String(($pem -replace '-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s', ''))
Assert-True (([Convert]::ToBase64String($raw)) -ceq [Convert]::ToBase64String($decoded)) 'Certificate PEM conversion changed bytes.'
$count++; Write-Output 'PASS public chain PEM conversion preserves DER bytes'
Write-Output ('Passed ' + $count + ' certificate request tests. Actual AD CS enrollment requires Windows.')
