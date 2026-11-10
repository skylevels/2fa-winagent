#requires -Version 5.1
# Run with: powershell.exe -NoProfile -File tests\powershell\Directory.Tests.ps1
# These tests mock every AD command; they never read or write a real domain.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\..\powershell\Directory.ps1') -LibraryOnly

$script:testCount = 0
$script:domainSid = 'S-1-5-21-1-2-3'
$script:context = [pscustomobject]@{
    Server = 'dc1.example.test'
    Domain = 'example.test'
    DomainSid = $script:domainSid
    SearchBase = 'DC=example,DC=test'
    UsersContainer = 'CN=Users,DC=example,DC=test'
    Stub = '2FA-BLOCK'
    BypassName = '2fabypass'
    AdminSids = @('S-1-5-21-1-2-3-512', 'S-1-5-21-1-2-3-519', 'S-1-5-32-544')
    AdministratorSid = 'S-1-5-21-1-2-3-500'
}

function Reset-Fixture {
    $script:user = [pscustomobject]@{
        ObjectGUID = [guid]'11111111-1111-1111-1111-111111111111'
        SamAccountName = 'ivanov-dd'
        SID = 'S-1-5-21-1-2-3-1100'
        primaryGroupID = 513
        tokenGroups = @('S-1-5-21-1-2-3-513')
        memberOf = @()
        userWorkstations = 'PC-A,PC-B'
    }
    $script:group = [pscustomobject]@{
        SID = 'S-1-5-21-1-2-3-1200'
        DistinguishedName = 'CN=2fabypass,CN=Users,DC=example,DC=test'
        GroupCategory = 'Security'
        SamAccountName = '2fabypass'
        ObjectGUID = [guid]'22222222-2222-2222-2222-222222222222'
    }
    $script:colliding = $false
    $script:loseWrite = $false
    $script:users = @($script:user)
    $script:localComputer = [pscustomobject]@{ DNSHostName = 'dc1'; Domain = 'example.test'; DomainRole = 5; PartOfDomain = $true }
    $script:controller = [pscustomobject]@{ Name = [Environment]::MachineName; HostName = 'dc1.example.test'; IsReadOnly = $false }
    $script:writes = @()
    $script:request = [pscustomobject]@{ login = 'ivanov-dd'; computer = 'PC-A' }
}

# Intentionally use plain functions with explicit parameters; no ActiveDirectory
# module is loaded and the production code still passes -Server on every call.
function Import-Module { param($Name, $ErrorAction) }
function Get-CimInstance {
    param($ClassName, $ErrorAction)
    if ($ClassName -cne 'Win32_ComputerSystem') { throw 'Unexpected local machine query' }
    return $script:localComputer
}
function Get-ADDomainController {
    param($Identity, $Server, $ErrorAction)
    return $script:controller
}
function Get-ADDomain {
    param($Server, $ErrorAction)
    return [pscustomobject]@{ DNSRoot = 'example.test'; DomainSID = $script:domainSid; DistinguishedName = $script:context.SearchBase; UsersContainer = $script:context.UsersContainer }
}
function Get-ADForest {
    param($Server, $ErrorAction)
    return [pscustomobject]@{ RootDomain = 'example.test' }
}
function Get-ADComputer {
    param($LDAPFilter, $SearchBase, $Server, $ResultSetSize, $ErrorAction)
    if ($Server -cne $script:context.Server) { throw 'Wrong directory server' }
    if ($script:colliding) { return [pscustomobject]@{ Name = '2FA-BLOCK' } }
}
function Get-ADGroup {
    param($LDAPFilter, $SearchBase, $Server, $ResultSetSize, $Properties, $ErrorAction)
    if ($Server -cne $script:context.Server) { throw 'Wrong directory server' }
    if ($null -ne $script:group) { return $script:group }
}
function Get-ADUser {
    param($Identity, $LDAPFilter, $SearchBase, $Server, $ResultSetSize, $ResultPageSize, $Properties, $ErrorAction)
    if ($Server -cne $script:context.Server) { throw 'Wrong directory server' }
    if ($null -ne $Identity) {
        $selected = @($script:users | Where-Object { $_.ObjectGUID -eq [guid]$Identity })
        if ($selected.Count -ne 1) { throw 'Requested test identity was not found uniquely' }
        return $selected[0]
    }
    if ($LDAPFilter -ceq '(&(objectCategory=person)(objectClass=user))') { return $script:users }
    return $script:user
}
function Set-ADUser {
    param($Identity, $Server, $Clear, $Replace, [switch]$Confirm, $ErrorAction)
    if ($Server -cne $script:context.Server) { throw 'Wrong directory server' }
    $selected = @($script:users | Where-Object { $_.ObjectGUID -eq [guid]$Identity })
    if ($selected.Count -ne 1) { throw 'Mutation must use stable GUID identity' }
    $targetUser = $selected[0]
    $script:writes += @{ Identity = $Identity; Clear = $Clear; Replace = $Replace }
    if (-not $script:loseWrite) {
        if ($null -ne $Clear) { $targetUser.userWorkstations = '' }
        else { $targetUser.userWorkstations = $Replace.userWorkstations }
    }
}

function Assert-Equal {
    param($Expected, $Actual, [string]$Message)
    if ($Expected -cne $Actual) { throw ($Message + ': expected [' + $Expected + '], got [' + $Actual + ']') }
}
function Assert-Fault {
    param([scriptblock]$Action, [string]$Code)
    $seen = $false
    try { $null = & $Action }
    catch {
        Assert-Equal $Code (Get-AgentError $_).code 'Fault code'
        $seen = $true
    }
    if (-not $seen) { throw ('Expected failure: ' + $Code) }
    Assert-Equal 0 $script:writes.Count 'Failure must not write'
}
function Test-Case {
    param([string]$Name, [scriptblock]$Action)
    Reset-Fixture
    & $Action
    $script:testCount++
    Write-Output ('PASS ' + $Name)
}

Test-Case 'grant preserves existing workstations and appends requested PC' {
    $script:request.computer = 'IVANOV-2121'
    $r = Invoke-UserChange $script:context $script:request 'grant'
    Assert-Equal 'PC-A,PC-B,IVANOV-2121' $script:user.userWorkstations 'Workstations'
    Assert-Equal $true $r.changed 'Changed'
}
Test-Case 'grant is case-insensitive and idempotent for existing PC' {
    $script:request.computer = 'pc-a'
    $r = Invoke-UserChange $script:context $script:request 'grant'
    Assert-Equal 'PC-A,PC-B' $script:user.userWorkstations 'Workstations'
    Assert-Equal $false $r.changed 'Changed'
    Assert-Equal 0 $script:writes.Count 'Write count'
}
Test-Case 'revoke removes only the pair and ensures stub' {
    $null = Invoke-UserChange $script:context $script:request 'revoke'
    Assert-Equal 'PC-B,2FA-BLOCK' $script:user.userWorkstations 'Workstations'
}
Test-Case 'expiry replaces every workstation with stub' {
    $null = Invoke-UserChange $script:context $script:request 'expire'
    Assert-Equal '2FA-BLOCK' $script:user.userWorkstations 'Workstations'
}
Test-Case 'bulk enable adds stub and preserves existing permissions' {
    $r = Invoke-BulkChange $script:context 'bulk-enable' $false
    Assert-Equal 'PC-A,PC-B,2FA-BLOCK' $script:user.userWorkstations 'Workstations'
    Assert-Equal 1 $r.changed 'Changed count'
}
Test-Case 'bulk disable clears the whole attribute' {
    $r = Invoke-BulkChange $script:context 'bulk-disable' $false
    Assert-Equal '' $script:user.userWorkstations 'Workstations'
    Assert-Equal 'userWorkstations' $script:writes[0].Clear 'Clear attribute'
    Assert-Equal 1 $r.changed 'Changed count'
}
Test-Case 'bulk dry run reports changes without applying them' {
    $r = Invoke-BulkChange $script:context 'bulk-disable' $true
    Assert-Equal 1 $r.changed 'Would change count'
    Assert-Equal 0 $script:writes.Count 'Write count'
    Assert-Equal 'PC-A,PC-B' $script:user.userWorkstations 'Workstations'
}
Test-Case 'renamed builtin administrator is always excluded by SID' {
    $script:user.SID = 'S-1-5-21-1-2-3-500'
    $script:user.SamAccountName = 'renamed-admin'
    foreach ($action in @('grant', 'revoke', 'support-grant', 'support-revoke', 'expire', 'bulk-enable', 'bulk-disable')) {
        $r = Invoke-UserChange $script:context $script:request $action
        Assert-Equal 'builtin_administrator' $r.reason 'Reason'
    }
    Assert-Equal 0 $script:writes.Count 'Write count'
}
Test-Case 'all protected group SIDs include indirect membership' {
    foreach ($sid in $script:context.AdminSids) {
        $script:user.tokenGroups = @('S-1-5-21-1-2-3-513', $sid)
        foreach ($action in @('grant', 'revoke', 'support-grant', 'support-revoke', 'expire', 'bulk-enable', 'bulk-disable')) {
            $r = Invoke-UserChange $script:context $script:request $action
            Assert-Equal 'administrator' $r.reason 'Reason'
        }
    }
    Assert-Equal 0 $script:writes.Count 'Write count'
}
Test-Case 'primary administrator group is excluded even without tokenGroups' {
    $script:user.primaryGroupID = 512
    $script:user.tokenGroups = @()
    $r = Invoke-UserChange $script:context $script:request 'expire'
    Assert-Equal 'administrator' $r.reason 'Reason'
    Assert-Equal 0 $script:writes.Count 'Write count'
}
Test-Case 'direct bypass preserves an existing stub for every operation' {
    $script:user.memberOf = @($script:group.DistinguishedName)
    $script:user.userWorkstations = 'PC-A,2FA-BLOCK'
    foreach ($action in @('grant', 'revoke', 'support-grant', 'support-revoke', 'expire', 'bulk-enable', 'bulk-disable')) {
        $r = Invoke-UserChange $script:context $script:request $action
        Assert-Equal 'bypass' $r.reason 'Reason'
    }
    Assert-Equal 0 $script:writes.Count 'Write count'
    Assert-Equal 'PC-A,2FA-BLOCK' $script:user.userWorkstations 'Workstations'
}
Test-Case 'nested bypass membership is intentionally not excluded' {
    $script:user.tokenGroups += $script:group.SID
    $r = Invoke-UserChange $script:context $script:request 'expire'
    Assert-Equal $false $r.excluded 'Excluded'
    Assert-Equal '2FA-BLOCK' $script:user.userWorkstations 'Workstations'
}
Test-Case 'bypass as primary group is direct membership' {
    $script:user.primaryGroupID = 1200
    $r = Invoke-UserChange $script:context $script:request 'expire'
    Assert-Equal 'bypass' $r.reason 'Reason'
    Assert-Equal 0 $script:writes.Count 'Write count'
}
Test-Case 'membership is checked again after resolve' {
    $first = Invoke-UserChange $script:context $script:request 'resolve'
    Assert-Equal $false $first.excluded 'Initial exclusion'
    $script:user.memberOf = @($script:group.DistinguishedName)
    $second = Invoke-UserChange $script:context $script:request 'expire'
    Assert-Equal 'bypass' $second.reason 'New exclusion'
    Assert-Equal 0 $script:writes.Count 'Write count'
}
Test-Case 'missing security memberships fail closed' {
    $script:user.tokenGroups = @()
    Assert-Fault { Invoke-UserChange $script:context $script:request 'expire' } 'membership_unavailable'
}
Test-Case 'missing bypass group fails closed' {
    $script:group = $null
    Assert-Fault { Invoke-UserChange $script:context $script:request 'expire' } 'bypass_group_missing'
}
Test-Case 'distribution bypass group fails closed' {
    $script:group.GroupCategory = 'Distribution'
    Assert-Fault { Invoke-UserChange $script:context $script:request 'expire' } 'bypass_group_invalid'
}
Test-Case 'real stub computer blocks mutations' {
    $script:colliding = $true
    Assert-Fault { Invoke-UserChange $script:context $script:request 'expire' } 'stub_collision'
}
Test-Case 'attribute limit prevents destructive truncation' {
    $script:user.userWorkstations = 'X' * 1024
    Assert-Fault { Invoke-UserChange $script:context $script:request 'grant' } 'workstations_limit'
}
Test-Case 'stub cannot be supplied as requested computer' {
    $script:request.computer = '2FA-BLOCK'
    Assert-Fault { Invoke-UserChange $script:context $script:request 'grant' } 'invalid_request'
}
Test-Case 'login rejects LDAP and command injection payloads' {
    foreach ($login in @('*)(objectClass=*)', 'DOMAIN\name', 'name@example.test', 'name;whoami', 'name`n')) {
        $script:request.login = $login
        Assert-Fault { Invoke-UserChange $script:context $script:request 'resolve' } 'invalid_request'
    }
}
Test-Case 'GUID request must be canonical' {
    $request = [pscustomobject]@{ userId = '*'; computer = 'PC-A' }
    Assert-Fault { Invoke-UserChange $script:context $request 'expire' } 'invalid_request'
}
Test-Case 'LDAP filter escaping is complete' {
    Assert-Equal '\5c\2a\28\29\00' (ConvertTo-LdapFilterValue ('\*()' + [char]0)) 'Escaped value'
}
Test-Case 'bulk reports bounded errors without raw exception details' {
    $script:user.tokenGroups = @()
    $r = Invoke-BulkChange $script:context 'bulk-enable' $false
    Assert-Equal 1 $r.failed 'Failed count'
    Assert-Equal 'membership_unavailable' $r.errors[0].code 'Failure code'
    Assert-Equal 0 $script:writes.Count 'Write count'
}
Test-Case 'a lost or overwritten write is not acknowledged as applied' {
    $script:loseWrite = $true
    $seen = $false
    try { $null = Invoke-UserChange $script:context $script:request 'expire' }
    catch {
        Assert-Equal 'write_not_verified' (Get-AgentError $_).code 'Failure code'
        $seen = $true
    }
    Assert-Equal $true $seen 'Verification failed'
    Assert-Equal 1 $script:writes.Count 'Attempted write count'
}
Test-Case 'bounded batches traverse unsorted GUIDs once in ordinal order' {
    $script:users = @(foreach ($prefix in @('99999999', '11111111', '88888888', '22222222', '77777777')) {
        $copy = $script:user.PSObject.Copy()
        $copy.ObjectGUID = [guid]($prefix + '-1111-1111-1111-111111111111')
        $copy
    })
    $cursor = $null
    $found = 0
    $calls = 0
    do {
        $r = Invoke-BulkChange $script:context 'bulk-enable' $false $cursor 2
        if ($r.found -gt 2) { throw 'Batch exceeded requested size' }
        if (-not $r.complete -and $null -eq $r.nextCursor) { throw 'Incomplete batch requires continuation' }
        if ($null -ne $cursor -and $null -ne $r.nextCursor -and [StringComparer]::Ordinal.Compare($cursor, $r.nextCursor) -ge 0) {
            throw 'Cursor failed to advance'
        }
        $found += $r.found
        $calls++
        $cursor = $r.nextCursor
    } while (-not $r.complete)
    Assert-Equal 5 $found 'Found across batches'
    Assert-Equal 3 $calls 'Batch count'
    Assert-Equal 5 $script:writes.Count 'Write count'
    Assert-Equal 5 @($script:writes.Identity | Sort-Object -Unique).Count 'Distinct writes'
    foreach ($user in $script:users) {
        Assert-Equal 'PC-A,PC-B,2FA-BLOCK' $user.userWorkstations 'Workstations'
    }
}
Test-Case 'cursor past the last user produces complete empty batch' {
    $r = Invoke-BulkChange $script:context 'bulk-enable' $false 'ffffffff-ffff-ffff-ffff-ffffffffffff' 10
    Assert-Equal 0 $r.found 'Found'
    Assert-Equal $true $r.complete 'Complete'
    Assert-Equal $null $r.nextCursor 'Continuation'
    Assert-Equal 0 $script:writes.Count 'Write count'
}
Test-Case 'invalid cursor is rejected before touching users' {
    Assert-Fault { Invoke-BulkChange $script:context 'bulk-enable' $false '*' 10 } 'invalid_request'
}
Test-Case 'bulk batch size is bounded' {
    Assert-Fault { Invoke-BulkChange $script:context 'bulk-enable' $false $null 0 } 'invalid_request'
    Assert-Fault { Invoke-BulkChange $script:context 'bulk-enable' $false $null 51 } 'invalid_request'
}
Test-Case 'local directory initialization derives protected SIDs correctly' {
    $r = Initialize-AgentDirectory ([pscustomobject]@{ domainController = 'dc1.example.test'; stub = '2FA-BLOCK'; bypassGroup = '2fabypass' })
    Assert-Equal 3 $r.AdminSids.Count 'Protected groups'
    Assert-Equal 'S-1-5-21-1-2-3-512' $r.AdminSids[0] 'Domain Admins SID'
    Assert-Equal 'S-1-5-21-1-2-3-519' $r.AdminSids[1] 'Enterprise Admins SID'
    Assert-Equal 'S-1-5-32-544' $r.AdminSids[2] 'Builtin Administrators SID'
}
Test-Case 'same short name in a different DNS domain cannot pass local DC check' {
    $script:controller.HostName = 'dc1.other.test'
    Assert-Fault { Initialize-AgentDirectory ([pscustomobject]@{ domainController = 'dc1.other.test'; stub = '2FA-BLOCK'; bypassGroup = '2fabypass' }) } 'wrong_domain_controller'
}
Test-Case 'member server cannot be used as the local DC' {
    $script:localComputer.DomainRole = 3
    Assert-Fault { Initialize-AgentDirectory ([pscustomobject]@{ domainController = 'dc1.example.test'; stub = '2FA-BLOCK'; bypassGroup = '2fabypass' }) } 'wrong_domain_controller'
}
Test-Case 'read-only domain controller is refused' {
    $script:controller.IsReadOnly = $true
    Assert-Fault { Initialize-AgentDirectory ([pscustomobject]@{ domainController = 'dc1.example.test'; stub = '2FA-BLOCK'; bypassGroup = '2fabypass' }) } 'wrong_domain_controller'
}

Test-Case 'support grant clears workstation restriction through the ordinary verified AD adapter' {
    $request = [pscustomobject]@{
        action = 'support-grant'
        userId = $script:user.ObjectGUID.ToString('D')
        config = [pscustomobject]@{ domainController = 'dc1.example.test'; stub = '2FA-BLOCK'; bypassGroup = '2fabypass' }
    }
    $r = Invoke-DirectoryRequest $request
    Assert-Equal $false $r.excluded 'Exclusion'
    Assert-Equal $true $r.changed 'Changed'
    Assert-Equal '' $script:user.userWorkstations 'All workstations allowed'
    Assert-Equal 'userWorkstations' $script:writes[0].Clear 'Attribute cleared'
    Assert-Equal $script:user.ObjectGUID $script:writes[0].Identity 'Stable identity'
}
Test-Case 'support revoke writes only the deny baseline without needing a computer' {
    $script:user.userWorkstations = ''
    $r = Invoke-UserChange $script:context ([pscustomobject]@{ login = 'ivanov-dd' }) 'support-revoke'
    Assert-Equal $true $r.changed 'Changed'
    Assert-Equal '2FA-BLOCK' $script:user.userWorkstations 'Deny baseline'
    Assert-Equal '2FA-BLOCK' $script:writes[0].Replace.userWorkstations 'Replacement'
}
Test-Case 'support operations do not write when the requested state was already confirmed on this DC' {
    $script:user.userWorkstations = ''
    $r = Invoke-UserChange $script:context $script:request 'support-grant'
    Assert-Equal $false $r.changed 'Unchanged allow'
    $script:user.userWorkstations = '2FA-BLOCK'
    $r = Invoke-UserChange $script:context $script:request 'support-revoke'
    Assert-Equal $false $r.changed 'Unchanged deny'
    Assert-Equal 0 $script:writes.Count 'No redundant writes'
}
Test-Case 'lost support allow and deny writes are never acknowledged' {
    foreach ($action in @('support-grant', 'support-revoke')) {
        Reset-Fixture
        $script:loseWrite = $true
        if ($action -eq 'support-revoke') { $script:user.userWorkstations = '' }
        $seen = $false
        try { $null = Invoke-UserChange $script:context $script:request $action }
        catch {
            Assert-Equal 'write_not_verified' (Get-AgentError $_).code 'Readback failure'
            $seen = $true
        }
        Assert-Equal $true $seen 'Failure reported'
        Assert-Equal 1 $script:writes.Count 'Attempted write'
    }
}
Test-Case 'support fails closed when protected membership cannot be verified' {
    $script:user.tokenGroups = @()
    Assert-Fault { Invoke-UserChange $script:context $script:request 'support-grant' } 'membership_unavailable'
    Assert-Fault { Invoke-UserChange $script:context $script:request 'support-revoke' } 'membership_unavailable'
}
Test-Case 'support honours a new bypass membership immediately before mutation' {
    $first = Invoke-UserChange $script:context $script:request 'resolve'
    Assert-Equal $false $first.excluded 'Initial membership'
    $script:user.memberOf = @($script:group.DistinguishedName)
    foreach ($action in @('support-grant', 'support-revoke')) {
        $r = Invoke-UserChange $script:context $script:request $action
        Assert-Equal 'bypass' $r.reason 'Refreshed membership'
    }
    Assert-Equal 'PC-A,PC-B' $script:user.userWorkstations 'Preserved restriction'
    Assert-Equal 0 $script:writes.Count 'No protected-user writes'
}
Test-Case 'support refuses a reserved deny stub collision' {
    $script:colliding = $true
    Assert-Fault { Invoke-UserChange $script:context $script:request 'support-grant' } 'stub_collision'
    Assert-Fault { Invoke-UserChange $script:context $script:request 'support-revoke' } 'stub_collision'
}

Write-Output ('Passed ' + $script:testCount + ' PowerShell adapter tests (mocked AD).')
