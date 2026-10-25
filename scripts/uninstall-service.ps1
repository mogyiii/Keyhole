<#
.SYNOPSIS
    Stops and removes the Keyhole Windows service.

.DESCRIPTION
    Must run elevated. Leaves %ProgramData%\Keyhole alone by default so flow history,
    rules and captures survive a reinstall. Pass -PurgeData to remove it too.

.PARAMETER PurgeData
    Also delete %ProgramData%\Keyhole, including the database, logs and captured traffic.
#>
[CmdletBinding()]
param(
    [switch]$PurgeData
)

$ErrorActionPreference = 'Stop'
$serviceName = 'Keyhole'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'This script must run elevated. Start PowerShell as administrator and retry.'
}

$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($service) {
    if ($service.Status -ne 'Stopped') {
        Write-Host 'Stopping service...' -ForegroundColor Cyan
        Stop-Service -Name $serviceName -Force
        $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }

    Write-Host 'Removing service registration...' -ForegroundColor Cyan
    sc.exe delete $serviceName | Out-Null
    Write-Host 'Service removed.' -ForegroundColor Green
} else {
    Write-Host "Service '$serviceName' is not registered; nothing to remove." -ForegroundColor Yellow
}

$dataRoot = Join-Path $env:ProgramData 'Keyhole'
if ($PurgeData) {
    if (Test-Path $dataRoot) {
        # Captured traffic and TLS keys live here, so deleting is opt-in and confirmed.
        Write-Host "About to delete $dataRoot (database, logs, captures, TLS keys)." -ForegroundColor Yellow
        $answer = Read-Host 'Type DELETE to confirm'
        if ($answer -ceq 'DELETE') {
            Remove-Item -Recurse -Force $dataRoot
            Write-Host 'Data removed.' -ForegroundColor Green
        } else {
            Write-Host 'Left data in place.' -ForegroundColor Yellow
        }
    }
} elseif (Test-Path $dataRoot) {
    Write-Host "Data kept at $dataRoot (use -PurgeData to remove)." -ForegroundColor Cyan
}
