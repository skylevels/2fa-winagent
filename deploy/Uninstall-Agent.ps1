#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [ValidatePattern('^[A-Za-z0-9_-]{1,64}$')][string]$TaskName = 'TwoFactorAgent'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Write-Warning 'Stopping removes this process''s in-memory timers. AD workstation lists remain unchanged. Drain grants or coordinate an explicit domain-wide disable before uninstalling.'
if ($PSCmdlet.ShouldProcess($TaskName, 'Stop and remove the agent and log-maintenance tasks and the firewall rule')) {
    foreach ($name in @($TaskName, ($TaskName + '-LogMaintenance'))) {
        $task = Get-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction SilentlyContinue
        if ($null -ne $task) {
            Stop-ScheduledTask -TaskName $name -TaskPath '\'
            Unregister-ScheduledTask -TaskName $name -TaskPath '\' -Confirm:$false
        }
    }
    $rule = Get-NetFirewallRule -Name "TwoFactorAgent-$TaskName" -ErrorAction SilentlyContinue
    if ($null -ne $rule) { $rule | Remove-NetFirewallRule }
    Write-Output 'Agent and log-maintenance tasks and firewall rule removed. Code, configuration, logs, archives, documentation, file permissions and AD attributes were retained. Automatic log archiving and retention are now stopped.'
}
