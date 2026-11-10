#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\..\deploy\Install-Agent.ps1') -LibraryOnly

$script:listeners = @()
$script:queryCount = 0
function Get-NetTCPConnection {
    [CmdletBinding()]param([string]$State)
    if ($State -ne 'Listen') { throw 'The preflight must inspect listening connections only.' }
    $script:queryCount++
    $script:listeners
}
function Assert-True($Value, [string]$Message) { if (-not $Value) { throw $Message } }
function Assert-Rejected([scriptblock]$Operation) {
    $failed = $false
    try { & $Operation } catch { $failed = $true }
    Assert-True $failed 'Expected installation preflight failure.'
}

$port = Assert-AgentHttpsPort ([pscustomobject]@{ port = 8443 })
Assert-True ($port -eq 8443 -and $port -is [int]) 'The API must return its checked TCP port for firewall setup.'
Write-Output 'PASS free HTTPS8443 is accepted and returned for firewall setup'

$script:listeners = @([pscustomobject]@{ LocalPort = 443; OwningProcess = 1234 })
Assert-True ((Assert-AgentHttpsPort ([pscustomobject]@{ port = 8443 })) -eq 8443) 'An unrelated HTTPS443 listener blocked installation.'
Write-Output 'PASS an existing HTTPS443 service does not block the agent preflight'

$script:listeners += [pscustomobject]@{ LocalPort = 8443; OwningProcess = 5678 }
Assert-Rejected { Assert-AgentHttpsPort ([pscustomobject]@{ port = 8443 }) }
Assert-True ($script:listeners.Count -eq 2 -and $script:listeners[0].OwningProcess -eq 1234 -and $script:listeners[1].OwningProcess -eq 5678) 'Preflight changed the existing listener list.'
Write-Output 'PASS occupied HTTPS8443 rejects installation without changing either listener'

$before = $script:queryCount
foreach ($invalid in @(443, 80, 0, 65536, '8443', 8443.0, $true, $null)) {
    Assert-Rejected { Assert-AgentHttpsPort ([pscustomobject]@{ port = $invalid }) }
}
Assert-Rejected { Assert-AgentHttpsPort ([pscustomobject]@{}) }
Assert-True ($script:queryCount -eq $before) 'Invalid configuration reached TCP-listener discovery.'
Write-Output 'PASS wrong ports and non-integer values fail before listener discovery'

$script:listeners = @()
Assert-True ((Assert-AgentHttpsPort ([pscustomobject]@{ port = [long]8443 })) -eq 8443) 'JSON integer represented as Int64 was rejected.'
Write-Output 'PASS JSON Int64 port8443 is accepted'
Write-Output 'Passed 5 installer port tests. Actual Windows listeners and Firewall are not changed.'
