#requires -Version 5.1
[CmdletBinding()]
param([switch]$LibraryOnly)

# The PHP process invokes this fixed script. Requests are data on stdin, never
# PowerShell source or command-line fragments. No access state is saved to disk.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'
$DebugPreference = 'SilentlyContinue'

function Stop-AgentOperation {
    param([string]$Code, [string]$Message)
    $exception = New-Object System.InvalidOperationException($Message)
    $exception.Data['AgentCode'] = $Code
    $exception.Data['AgentMessage'] = $Message
    throw $exception
}

function Get-AgentError {
    param($ErrorRecord)
    $exception = $ErrorRecord.Exception
    while ($null -ne $exception) {
        if ($exception.Data.Contains('AgentCode')) {
            return @{ code = [string]$exception.Data['AgentCode']; message = [string]$exception.Data['AgentMessage'] }
        }
        $exception = $exception.InnerException
    }
    # Do not expose distinguished names, paths, credentials, or raw AD exceptions.
    return @{ code = 'directory_error'; message = 'Active Directory operation failed; check directory availability and delegated permissions.' }
}

function Get-RequestString {
    param($Object, [string]$Name, [int]$MaximumLength = 256)
    if ($null -eq $Object -or $null -eq $Object.PSObject.Properties[$Name]) {
        Stop-AgentOperation 'invalid_request' ('Missing property: ' + $Name)
    }
    $value = $Object.PSObject.Properties[$Name].Value
    if ($value -isnot [string] -or $value.Length -lt 1 -or $value.Length -gt $MaximumLength -or $value -match '[\x00-\x1f\x7f]') {
        Stop-AgentOperation 'invalid_request' ('Invalid property: ' + $Name)
    }
    return $value
}

function ConvertTo-LdapFilterValue {
    param([string]$Value)
    return $Value.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29').Replace([string][char]0, '\00')
}

function Get-SidText {
    param($Value)
    if ($Value -is [string]) {
        if ($Value -notmatch '^S-1-[0-9]+(-[0-9]+)+$') {
            Stop-AgentOperation 'membership_unavailable' 'Unable to verify security group membership.'
        }
        return $Value
    }
    if ($Value -is [System.Security.Principal.SecurityIdentifier]) { return $Value.Value }
    if ($Value -is [byte[]]) {
        return (New-Object System.Security.Principal.SecurityIdentifier($Value, 0)).Value
    }
    Stop-AgentOperation 'membership_unavailable' 'Unable to verify security group membership.'
}

function Get-BypassGroup {
    param($Context, [switch]$AllowMissing)
    $escaped = ConvertTo-LdapFilterValue $Context.BypassName
    $groups = @(Get-ADGroup -LDAPFilter ('(sAMAccountName=' + $escaped + ')') -SearchBase $Context.SearchBase -Server $Context.Server -ResultSetSize 2 -Properties primaryGroupToken -ErrorAction Stop)
    if ($groups.Count -eq 0 -and $AllowMissing) { return $null }
    if ($groups.Count -ne 1) {
        Stop-AgentOperation 'bypass_group_missing' 'The configured bypass group must exist uniquely before processing users.'
    }
    if ([string]$groups[0].GroupCategory -ne 'Security') {
        Stop-AgentOperation 'bypass_group_invalid' 'The bypass group must be a security group.'
    }
    return $groups[0]
}

function Assert-StubAvailable {
    param($Context)
    $escaped = ConvertTo-LdapFilterValue $Context.Stub
    $filter = '(|(sAMAccountName=' + $escaped + '$)(name=' + $escaped + ')(dNSHostName=' + $escaped + ')(dNSHostName=' + $escaped + '.*))'
    $collisions = @(Get-ADComputer -LDAPFilter $filter -SearchBase $Context.SearchBase -Server $Context.Server -ResultSetSize 1 -ErrorAction Stop)
    if ($collisions.Count -ne 0) {
        Stop-AgentOperation 'stub_collision' 'The reserved stub matches an existing domain computer.'
    }
}

function Initialize-AgentDirectory {
    param($Config, [switch]$AllowMissingBypass)
    $server = Get-RequestString $Config 'domainController' 253
    $stub = (Get-RequestString $Config 'stub' 15).ToUpperInvariant()
    $bypassName = Get-RequestString $Config 'bypassGroup' 64
    if ($server -notmatch '^[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z0-9][a-zA-Z0-9.-]*$' -or $server -match '^\d+\.\d+\.\d+\.\d+$') {
        Stop-AgentOperation 'invalid_config' 'domainController must be the local domain controller FQDN, not an IP address.'
    }
    if ($stub -notmatch '^[A-Z0-9](?:[A-Z0-9-]{0,13}[A-Z0-9])?$' -or $stub -match '^\d+$') {
        Stop-AgentOperation 'invalid_config' 'The stub must be a reserved NetBIOS computer name of at most 15 characters.'
    }
    if ($bypassName -notmatch '^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$') {
        Stop-AgentOperation 'invalid_config' 'Invalid bypass group name.'
    }
    Import-Module ActiveDirectory -ErrorAction Stop
    $localComputer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $localFqdn = [string]$localComputer.DNSHostName + '.' + [string]$localComputer.Domain
    if (-not [bool]$localComputer.PartOfDomain -or [int]$localComputer.DomainRole -notin @(4, 5)) {
        Stop-AgentOperation 'wrong_domain_controller' 'This agent must run directly on a writable domain controller.'
    }
    $controller = Get-ADDomainController -Identity $server -Server $server -ErrorAction Stop
    if ([string]$controller.Name -ine [Environment]::MachineName -or [string]$controller.HostName -ine $localFqdn -or [bool]$controller.IsReadOnly) {
        Stop-AgentOperation 'wrong_domain_controller' 'The configured directory must be this machine and must be a writable domain controller.'
    }
    $domain = Get-ADDomain -Server $server -ErrorAction Stop
    $forest = Get-ADForest -Server $server -ErrorAction Stop
    if ([string]$forest.RootDomain -ine [string]$domain.DNSRoot) {
        Stop-AgentOperation 'unsupported_domain' 'This agent is configured for a single root-domain deployment.'
    }
    $domainSid = Get-SidText $domain.DomainSID
    $context = [pscustomobject]@{
        Server = [string]$controller.HostName
        Domain = [string]$domain.DNSRoot
        DomainSid = $domainSid
        SearchBase = [string]$domain.DistinguishedName
        UsersContainer = [string]$domain.UsersContainer
        Stub = $stub
        BypassName = $bypassName
        AdminSids = @(($domainSid + '-512'), ($domainSid + '-519'), 'S-1-5-32-544')
        AdministratorSid = $domainSid + '-500'
    }
    Assert-StubAvailable $context
    $null = Get-BypassGroup $context -AllowMissing:$AllowMissingBypass
    return $context
}

function Get-DirectoryUser {
    param($Context, $Request)
    if ($null -ne $Request.PSObject.Properties['userId']) {
        $text = Get-RequestString $Request 'userId' 36
        $id = [guid]::Empty
        if (-not [guid]::TryParseExact($text, 'D', [ref]$id)) {
            Stop-AgentOperation 'invalid_request' 'userId must be a canonical GUID.'
        }
        try { $identity = Get-ADUser -Identity $id -Server $Context.Server -ErrorAction Stop }
        catch {
            if ($_.Exception.GetType().Name -eq 'ADIdentityNotFoundException') {
                Stop-AgentOperation 'user_not_found' 'The domain user was not found.'
            }
            throw
        }
    }
    else {
        $login = Get-RequestString $Request 'login' 64
        if ($login -notmatch '^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$') {
            Stop-AgentOperation 'invalid_request' 'login must be a simple sAMAccountName.'
        }
        $escaped = ConvertTo-LdapFilterValue $login
        $users = @(Get-ADUser -LDAPFilter ('(&(objectCategory=person)(objectClass=user)(sAMAccountName=' + $escaped + '))') -SearchBase $Context.SearchBase -Server $Context.Server -ResultSetSize 2 -ErrorAction Stop)
        if ($users.Count -ne 1) {
            Stop-AgentOperation 'user_not_found' 'The domain user was not found uniquely.'
        }
        $identity = $users[0]
    }
    # tokenGroups requires a BASE lookup. It includes indirect and primary-group
    # membership; a search over all users cannot safely substitute this lookup.
    return Get-ADUser -Identity $identity.ObjectGUID -Server $Context.Server -Properties userWorkstations, memberOf, primaryGroupID, tokenGroups -ErrorAction Stop
}

function Get-UserExclusion {
    param($Context, $User, $BypassGroup)
    $sid = Get-SidText $User.SID
    if ($sid -eq $Context.AdministratorSid) { return 'builtin_administrator' }
    $primarySid = $Context.DomainSid + '-' + [string]$User.primaryGroupID
    if ($Context.AdminSids -contains $primarySid) { return 'administrator' }
    $rawGroups = @($User.tokenGroups)
    if ($rawGroups.Count -eq 0) {
        Stop-AgentOperation 'membership_unavailable' 'Security group membership could not be verified; no changes were made.'
    }
    foreach ($raw in $rawGroups) {
        if ($null -eq $raw) {
            Stop-AgentOperation 'membership_unavailable' 'Security group membership could not be verified; no changes were made.'
        }
        if ($Context.AdminSids -contains (Get-SidText $raw)) { return 'administrator' }
    }
    # Deliberately do NOT use tokenGroups for bypass: only direct membership is
    # exempt. Primary group membership is direct even though memberOf omits it.
    $bypassSid = Get-SidText $BypassGroup.SID
    if ($primarySid -eq $bypassSid -or @($User.memberOf) -icontains [string]$BypassGroup.DistinguishedName) {
        return 'bypass'
    }
    return $null
}

function Get-WorkstationList {
    param($User)
    $value = [string]$User.userWorkstations
    if ([string]::IsNullOrWhiteSpace($value)) { return @() }
    return @($value.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_.Length -gt 0 })
}

function Get-ComputerName {
    param($Request, $Context)
    $computer = (Get-RequestString $Request 'computer' 15).ToUpperInvariant()
    if ($computer -notmatch '^[A-Z0-9](?:[A-Z0-9-]{0,13}[A-Z0-9])?$' -or $computer -match '^\d+$' -or $computer -eq $Context.Stub) {
        Stop-AgentOperation 'invalid_request' 'computer must be a NetBIOS name of at most 15 characters and cannot be the stub.'
    }
    return $computer
}

function Invoke-UserChange {
    param($Context, $Request, [string]$Action, [bool]$DryRun = $false)
    $computer = $null
    if ($Action -in @('grant', 'revoke')) { $computer = Get-ComputerName $Request $Context }
    Assert-StubAvailable $Context
    # Refresh both membership inputs for every operation, including each user in
    # a bulk action. Never reuse an earlier resolve result as authorization.
    $bypass = Get-BypassGroup $Context
    $user = Get-DirectoryUser $Context $Request
    $reason = Get-UserExclusion $Context $user $bypass
    $result = @{
        userId = $user.ObjectGUID.ToString('D')
        login = [string]$user.SamAccountName
        excluded = $null -ne $reason
        reason = $reason
        changed = $false
    }
    if ($null -ne $reason -or $Action -eq 'resolve') { return $result }
    $before = [string]$user.userWorkstations
    $names = @(Get-WorkstationList $user)
    switch ($Action) {
        'grant' {
            # Preserve the existing list; this is an addition, not a reset.
            if ($names -inotcontains $computer) { $names += $computer }
        }
        'revoke' {
            $names = @($names | Where-Object { $_ -ine $computer })
            if ($names -inotcontains $Context.Stub) { $names += $Context.Stub }
        }
        'support-grant' { $names = @() }
        'support-revoke' { $names = @($Context.Stub) }
        'expire' { $names = @($Context.Stub) }
        'bulk-enable' {
            if ($names -inotcontains $Context.Stub) { $names += $Context.Stub }
        }
        'bulk-disable' { $names = @() }
        default { Stop-AgentOperation 'invalid_request' 'Unknown user operation.' }
    }
    $after = $names -join ','
    if ($after.Length -gt 1024) {
        Stop-AgentOperation 'workstations_limit' 'The workstation list exceeds the Active Directory attribute limit.'
    }
    $result.changed = $before -cne $after
    if ($result.changed -and -not $DryRun) {
        if ($after.Length -eq 0) {
            Set-ADUser -Identity $user.ObjectGUID -Server $Context.Server -Clear 'userWorkstations' -Confirm:$false -ErrorAction Stop
        }
        else {
            Set-ADUser -Identity $user.ObjectGUID -Server $Context.Server -Replace @{ userWorkstations = $after } -Confirm:$false -ErrorAction Stop
        }
        # A successful cmdlet call confirms the write request, but a concurrent
        # writer/replication can replace this single-valued attribute. Confirm the
        # resulting value on this DC before acknowledging success to the caller.
        $verified = Get-ADUser -Identity $user.ObjectGUID -Server $Context.Server -Properties userWorkstations -ErrorAction Stop
        if ([string]$verified.userWorkstations -cne $after) {
            Stop-AgentOperation 'write_not_verified' 'The workstation update could not be verified on this domain controller.'
        }
    }
    return $result
}

function Invoke-BulkChange {
    param($Context, [string]$Action, [bool]$DryRun, $Cursor = $null, [int]$BatchSize = 10)
    if ($BatchSize -lt 1 -or $BatchSize -gt 50) {
        Stop-AgentOperation 'invalid_request' 'batchSize must be an integer between 1 and 50.'
    }
    if ($null -ne $Cursor) {
        $cursorId = [guid]::Empty
        if ($Cursor -isnot [string] -or -not [guid]::TryParseExact($Cursor, 'D', [ref]$cursorId)) {
            Stop-AgentOperation 'invalid_request' 'cursor must be a canonical GUID or null.'
        }
        $Cursor = $cursorId.ToString('D')
    }
    $summary = @{ dryRun = $DryRun; found = 0; changed = 0; excluded = 0; failed = 0; errors = @(); nextCursor = $null; complete = $true }
    # Enumerate inexpensive identities, then process a bounded number of BASE
    # membership reads and writes. PHP can run due expiries between batches. The
    # cursor is a GUID in ordinal order, never a mutable login or array offset.
    # Each batch re-enumerates: this is deliberately not an atomic AD snapshot.
    [string[]]$allIds = @(Get-ADUser -LDAPFilter '(&(objectCategory=person)(objectClass=user))' -SearchBase $Context.SearchBase -Server $Context.Server -ResultPageSize 200 -ErrorAction Stop | ForEach-Object { $_.ObjectGUID.ToString('D') })
    [Array]::Sort($allIds, [StringComparer]::Ordinal)
    $batch = New-Object 'System.Collections.Generic.List[string]'
    foreach ($id in $allIds) {
        if ($null -ne $Cursor -and [StringComparer]::Ordinal.Compare($id, $Cursor) -le 0) { continue }
        if ($batch.Count -ge $BatchSize) {
            $summary.complete = $false
            $summary.nextCursor = $batch[$batch.Count - 1]
            break
        }
        $batch.Add($id)
    }
    # Exemptions/current attributes are fetched again by stable GUID immediately
    # before each write. Never trust stale data returned by the enumeration.
    foreach ($id in $batch) {
        $summary.found++
        try {
            $result = Invoke-UserChange $Context ([pscustomobject]@{ userId = $id }) $Action $DryRun
            if ($result.excluded) { $summary.excluded++ }
            elseif ($result.changed) { $summary.changed++ }
        }
        catch {
            $summary.failed++
            if ($summary.errors.Count -lt 5) { $summary.errors += (Get-AgentError $_) }
        }
    }
    return $summary
}

function Invoke-DirectoryRequest {
    param($Request)
    if ($null -eq $Request -or $Request -is [array] -or $null -eq $Request.PSObject.Properties['config']) {
        Stop-AgentOperation 'invalid_request' 'A JSON request object with config is required.'
    }
    $action = Get-RequestString $Request 'action' 32
    if ($action -notin @('resolve', 'grant', 'revoke', 'support-grant', 'support-revoke', 'expire', 'bulk-enable', 'bulk-disable', 'ensure-bypass', 'health')) {
        Stop-AgentOperation 'invalid_request' 'Unknown directory action.'
    }
    $context = Initialize-AgentDirectory $Request.config -AllowMissingBypass:($action -eq 'ensure-bypass')
    switch ($action) {
        'ensure-bypass' {
            $group = Get-BypassGroup $context -AllowMissing
            $created = $false
            if ($null -eq $group) {
                New-ADGroup -Name $context.BypassName -SamAccountName $context.BypassName -GroupCategory Security -GroupScope Global -Path $context.UsersContainer -Server $context.Server -Description 'Accounts excluded from the 2FA workstation agent.' -Confirm:$false -ErrorAction Stop
                $created = $true
                $group = Get-BypassGroup $context
            }
            return @{ created = $created; group = [string]$group.SamAccountName; groupId = $group.ObjectGUID.ToString('D') }
        }
        'health' {
            return @{ domainController = $context.Server; domain = $context.Domain; bypassGroup = $context.BypassName; stub = $context.Stub }
        }
        { $_ -in @('bulk-enable', 'bulk-disable') } {
            $dryRun = $false
            if ($null -ne $Request.PSObject.Properties['dryRun']) {
                if ($Request.dryRun -isnot [bool]) { Stop-AgentOperation 'invalid_request' 'dryRun must be a JSON boolean.' }
                $dryRun = $Request.dryRun
            }
            $cursor = $null
            if ($null -ne $Request.PSObject.Properties['cursor']) { $cursor = $Request.cursor }
            $batchSize = 10
            if ($null -ne $Request.PSObject.Properties['batchSize']) {
                if ($Request.batchSize -isnot [int] -and $Request.batchSize -isnot [long]) {
                    Stop-AgentOperation 'invalid_request' 'batchSize must be an integer between 1 and 50.'
                }
                if ($Request.batchSize -lt 1 -or $Request.batchSize -gt 50) {
                    Stop-AgentOperation 'invalid_request' 'batchSize must be an integer between 1 and 50.'
                }
                $batchSize = [int]$Request.batchSize
            }
            return Invoke-BulkChange $context $action $dryRun $cursor $batchSize
        }
        default { return Invoke-UserChange $context $Request $action }
    }
}

if (-not $LibraryOnly) {
    [Console]::InputEncoding = New-Object System.Text.UTF8Encoding($false)
    [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
    $response = $null
    $exitCode = 0
    try {
        $inputText = [Console]::In.ReadToEnd()
        if ($inputText.Length -gt 16384 -or [string]::IsNullOrWhiteSpace($inputText)) {
            Stop-AgentOperation 'invalid_request' 'Request length is invalid.'
        }
        try { $request = ConvertFrom-Json -InputObject $inputText -ErrorAction Stop }
        catch { Stop-AgentOperation 'invalid_request' 'Request must be valid JSON.' }
        $response = @{ ok = $true; result = Invoke-DirectoryRequest $request }
    }
    catch {
        $response = @{ ok = $false; error = Get-AgentError $_ }
        $exitCode = 1
    }
    $json = ConvertTo-Json -InputObject $response -Depth 8 -Compress
    if ([Text.Encoding]::UTF8.GetByteCount($json) -gt 3000) {
        $json = '{"ok":false,"error":{"code":"response_limit","message":"Directory response exceeded the permitted size."}}'
        $exitCode = 1
    }
    [Console]::Out.WriteLine($json)
    exit $exitCode
}
