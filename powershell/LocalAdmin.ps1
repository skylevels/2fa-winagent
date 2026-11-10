[CmdletBinding()]
param(
    [ValidateSet('Server', 'Client')][string]$Mode = 'Client',
    [string]$PipeName,
    [ValidateRange(1, 86400)][int]$TimeoutSeconds = 3600,
    [switch]$LibraryOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-LocalAdminWindows {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'windows_required' }
}

function Assert-LocalAdminElevated {
    Assert-LocalAdminWindows
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'elevated_administrator_required' }
    } finally { $identity.Dispose() }
}

function Get-LocalAdminSignature([string]$SecretHex, [string]$Nonce, [string]$Body) {
    if ($SecretHex -cnotmatch '^[0-9a-f]{64}$' -or $Nonce -cnotmatch '^[0-9a-f]{64}$') { throw 'invalid_signature_input' }
    $key = New-Object byte[] 32
    for ($i = 0; $i -lt 32; $i++) { $key[$i] = [Convert]::ToByte($SecretHex.Substring(2 * $i, 2), 16) }
    $hmac = [Security.Cryptography.HMACSHA256]::new($key)
    try {
        $hash = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes("LOCAL-ADMIN-RESPONSE`n$Nonce`n$Body"))
        return [BitConverter]::ToString($hash).Replace('-', '').ToLowerInvariant()
    } finally { $hmac.Dispose(); [Array]::Clear($key, 0, $key.Length) }
}

function Test-LocalAdminSignature([string]$Expected, [string]$Actual) {
    if ($Actual -cnotmatch '^[0-9a-f]{64}$') { return $false }
    $difference = 0
    for ($i = 0; $i -lt 64; $i++) { $difference = $difference -bor ([int][char]$Expected[$i] -bxor [int][char]$Actual[$i]) }
    return $difference -eq 0
}

function New-LocalAdminNonce {
    $bytes = New-Object byte[] 32
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes); return [BitConverter]::ToString($bytes).Replace('-', '').ToLowerInvariant() }
    finally { $rng.Dispose() }
}

function Read-LocalAdminFrame([IO.Stream]$Stream, [int]$MaximumBytes = 8192, [int]$WaitMilliseconds = 5000) {
    $bytes = [IO.MemoryStream]::new()
    $one = New-Object byte[] 1
    $elapsed = [Diagnostics.Stopwatch]::StartNew()
    try {
        while ($bytes.Length -le $MaximumBytes) {
            $remaining = $WaitMilliseconds - $elapsed.Elapsed.TotalMilliseconds
            if ($remaining -le 0) { throw 'pipe_read_timeout' }
            $wait = [int][Math]::Ceiling($remaining)
            $read = $Stream.BeginRead($one, 0, 1, $null, $null)
            try {
                if (-not $read.AsyncWaitHandle.WaitOne($wait)) { throw 'pipe_read_timeout' }
                $count = $Stream.EndRead($read)
            } finally { $read.AsyncWaitHandle.Close() }
            if ($count -eq 0) { throw 'pipe_closed' }
            if ($one[0] -eq 10) {
                return [Text.UTF8Encoding]::new($false, $true).GetString($bytes.ToArray())
            }
            $bytes.WriteByte($one[0])
        }
        throw 'pipe_frame_limit'
    } finally { $bytes.Dispose() }
}

function Write-LocalAdminFrame([IO.Stream]$Stream, [string]$Text) {
    $bytes = [Text.Encoding]::UTF8.GetBytes($Text + "`n")
    if ($bytes.Length -gt 8192) { throw 'pipe_frame_limit' }
    $write = $Stream.BeginWrite($bytes, 0, $bytes.Length, $null, $null)
    try {
        if (-not $write.AsyncWaitHandle.WaitOne(5000)) { throw 'pipe_write_timeout' }
        $Stream.EndWrite($write)
    } finally { $write.AsyncWaitHandle.Close() }
}

function New-LocalAdminPipeSecurity {
    Assert-LocalAdminWindows
    $security = [IO.Pipes.PipeSecurity]::new()
    $security.SetAccessRuleProtection($true, $false)
    # NETWORK deny makes this local-only even if SMB is enabled on the DC.
    $network = [Security.Principal.SecurityIdentifier]::new('S-1-5-2')
    $security.AddAccessRule([IO.Pipes.PipeAccessRule]::new($network, [IO.Pipes.PipeAccessRights]::FullControl, [Security.AccessControl.AccessControlType]::Deny))
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $security.AddAccessRule([IO.Pipes.PipeAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),
            [IO.Pipes.PipeAccessRights]::ReadWrite, [Security.AccessControl.AccessControlType]::Allow))
    }
    # A dedicated service account may own/create the server. Only the console
    # client requires administrator elevation; domain admins belong to BUILTIN Administrators.
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $security.AddAccessRule([IO.Pipes.PipeAccessRule]::new($identity.User,
            [IO.Pipes.PipeAccessRights]::FullControl, [Security.AccessControl.AccessControlType]::Allow))
    } finally { $identity.Dispose() }
    return $security
}

function Assert-LocalAdminRequest($Request) {
    if ($Request -isnot [pscustomobject] -or $Request.id -isnot [string] -or $Request.id -cnotmatch '^[0-9a-f]{64}$' -or
        $Request.nonce -isnot [string] -or $Request.nonce -cnotmatch '^[0-9a-f]{64}$' -or
        $Request.action -isnot [string] -or $Request.action -cnotin @('submit', 'get')) { throw 'invalid_request' }
    $expected = if ($Request.action -ceq 'submit') { @('action', 'id', 'nonce', 'command', 'dryRun') } else { @('action', 'id', 'nonce') }
    if (@($Request.PSObject.Properties.Name | Where-Object { $_ -cnotin $expected }).Count -ne 0) { throw 'invalid_request' }
    if ($Request.action -ceq 'submit') {
        if ($Request.command -isnot [string] -or $Request.command -cnotin @('status', 'enable', 'disable', 'ensure-bypass') -or $Request.dryRun -isnot [bool]) { throw 'invalid_request' }
        if ($Request.command -ceq 'status' -and $Request.dryRun) { throw 'invalid_request' }
    }
}

function Get-LocalAdminReply($Request, $Entries) {
    Assert-LocalAdminRequest $Request
    $matches = @($Entries | Where-Object { $_.id -ceq $Request.id })
    if ($matches.Count -gt 1) { throw 'invalid_state' }
    if ($matches.Count -eq 1) {
        $entry = $matches[0]
        if ($Request.action -ceq 'submit' -and ($entry.command -cne $Request.command -or $entry.dryRun -ne $Request.dryRun)) {
            return @{ reply = @{ state = 'conflict' }; event = @{ event = 'idle' } }
        }
        if ($null -ne $entry.response) { return @{ reply = @{ state = 'complete'; response = $entry.response }; event = @{ event = 'idle' } } }
        return @{ reply = @{ state = 'pending' }; event = @{ event = 'idle' } }
    }
    if ($Request.action -ceq 'get') { return @{ reply = @{ state = 'unknown' }; event = @{ event = 'idle' } } }
    if (@($Entries).Count -ge 16) { return @{ reply = @{ state = 'busy' }; event = @{ event = 'idle' } } }
    return @{ reply = @{ state = 'pending' }; event = @{ event = 'request'; id = $Request.id; command = $Request.command; dryRun = $Request.dryRun } }
}

function Invoke-LocalAdminServer([string]$Name, $InputData) {
    Assert-LocalAdminWindows
    if ($Name -cnotmatch '^Elemer-2FA-[0-9a-f]{64}$' -or $InputData.secretHex -cnotmatch '^[0-9a-f]{64}$' -or
        @($InputData.entries).Count -gt 16) { throw 'invalid_state' }
    $security = New-LocalAdminPipeSecurity
    # max instances 1 also requests FILE_FLAG_FIRST_PIPE_INSTANCE in .NET Framework.
    $pipe = [IO.Pipes.NamedPipeServerStream]::new($Name, [IO.Pipes.PipeDirection]::InOut, 1,
        [IO.Pipes.PipeTransmissionMode]::Byte, [IO.Pipes.PipeOptions]::Asynchronous, 8192, 8192, $security)
    $event = @{ event = 'idle' }
    try {
        $connection = $pipe.BeginWaitForConnection($null, $null)
        try {
            if (-not $connection.AsyncWaitHandle.WaitOne(300000)) { return $event }
            $pipe.EndWaitForConnection($connection)
        } finally { $connection.AsyncWaitHandle.Close() }
        try {
            $request = (Read-LocalAdminFrame $pipe 1024) | ConvertFrom-Json
            $decision = Get-LocalAdminReply $request @($InputData.entries)
            # The request is retained even if the client disconnects before its receipt.
            $event = $decision.event
            $body = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($decision.reply | ConvertTo-Json -Depth 16 -Compress)))
            $wire = @{ body = $body; signature = Get-LocalAdminSignature $InputData.secretHex $request.nonce $body } | ConvertTo-Json -Compress
            Write-LocalAdminFrame $pipe $wire
        } catch {
            # A malformed or abandoned connection never emits its raw contents/errors.
        }
        return $event
    } finally { $pipe.Dispose() }
}

function Invoke-LocalAdminExchange([string]$Name, [string]$SecretHex, $Request) {
    $pipe = [IO.Pipes.NamedPipeClientStream]::new('.', $Name, [IO.Pipes.PipeDirection]::InOut,
        [IO.Pipes.PipeOptions]::Asynchronous, [Security.Principal.TokenImpersonationLevel]::Identification)
    try {
        try { $pipe.Connect(1500) } catch { throw 'local_connect_unavailable' }
        Write-LocalAdminFrame $pipe ($Request | ConvertTo-Json -Compress)
        $wire = (Read-LocalAdminFrame $pipe) | ConvertFrom-Json
        $expected = Get-LocalAdminSignature $SecretHex $Request.nonce $wire.body
        if (-not (Test-LocalAdminSignature $expected $wire.signature)) { throw 'response_authentication_failed' }
        return ([Text.UTF8Encoding]::new($false, $true).GetString([Convert]::FromBase64String($wire.body)) | ConvertFrom-Json)
    } finally { $pipe.Dispose() }
}

function Invoke-LocalAdminClient([string]$Name, $InputData, [int]$WaitSeconds) {
    Assert-LocalAdminElevated
    if ($Name -cnotmatch '^Elemer-2FA-[0-9a-f]{64}$' -or $InputData.secretHex -cnotmatch '^[0-9a-f]{64}$') { throw 'invalid_client_input' }
    $id = New-LocalAdminNonce
    $request = @{ action = 'submit'; id = $id; command = $InputData.command; dryRun = $InputData.dryRun; nonce = New-LocalAdminNonce }
    Assert-LocalAdminRequest ([pscustomobject]$request)
    $elapsed = [Diagnostics.Stopwatch]::StartNew()
    $acceptedOrUncertain = $false
    while ($elapsed.Elapsed.TotalSeconds -lt $WaitSeconds) {
        $request.nonce = New-LocalAdminNonce
        try {
            $reply = Invoke-LocalAdminExchange $Name $InputData.secretHex $request
        } catch {
            if ($_.Exception.Message -eq 'response_authentication_failed') { throw }
            if ($_.Exception.Message -eq 'local_connect_unavailable') {
                if (-not $acceptedOrUncertain -and $elapsed.Elapsed.TotalSeconds -ge 10) { throw 'local_agent_unavailable_check_running_task' }
                Start-Sleep -Milliseconds 250
                continue
            }
            # After any uncertain submission, query its id instead of resubmitting.
            # A restarted agent must never re-run an old administrative command.
            $acceptedOrUncertain = $true
            $request = @{ action = 'get'; id = $id; nonce = New-LocalAdminNonce }
            Start-Sleep -Milliseconds 250
            continue
        }
        if ($reply.state -ceq 'complete') { return $reply.response }
        if ($reply.state -ceq 'unknown') { throw 'outcome_unknown_check_status_do_not_blindly_repeat' }
        if ($reply.state -ceq 'conflict') { throw 'request_conflict' }
        if ($reply.state -ceq 'busy') { throw 'local_console_busy_retry_later' }
        if ($reply.state -cne 'pending') { throw 'invalid_local_response' }
        $acceptedOrUncertain = $true
        $request = @{ action = 'get'; id = $id; nonce = New-LocalAdminNonce }
        Start-Sleep -Milliseconds 250
    }
    throw 'local_command_timeout_operation_may_continue_check_status'
}

if ($LibraryOnly) { return }
try {
    [Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
    [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
    $inputText = [Console]::In.ReadToEnd()
    if ($inputText.Length -gt 65536) { throw 'input_limit' }
    $data = $inputText | ConvertFrom-Json
    $result = if ($Mode -ceq 'Server') { Invoke-LocalAdminServer $PipeName $data } else { Invoke-LocalAdminClient $PipeName $data $TimeoutSeconds }
    $outputText = $result | ConvertTo-Json -Depth 16 -Compress
    $limit = if ($Mode -ceq 'Server') { 2000 } else { 2800 }
    if ([Text.Encoding]::UTF8.GetByteCount($outputText) -gt $limit) { throw 'output_limit' }
    [Console]::Out.Write($outputText)
    exit 0
} catch {
    $safe = if ($_.Exception.Message -cmatch '^[a-z_]{1,100}$') { $_.Exception.Message } else { 'local_control_failed' }
    [Console]::Out.Write((@{ ok = $false; error = @{ code = $safe; message = 'Local console command failed. Check elevation, running agent and its status; an accepted operation may continue.' } } | ConvertTo-Json -Compress))
    exit 1
}
