<#
.SYNOPSIS
    Rebuilds the service and replaces the installed copy.

.DESCRIPTION
    Must run elevated. Stops the Keyhole service, publishes the current source over the
    installed binaries, and starts it again. Settings, rules and flow history are
    untouched -- they live in %ProgramData%, not next to the executable.

    Use this after changing service code. install-service.ps1 is for the first install.

.PARAMETER InstallPath
    Where the service is installed. Defaults to %ProgramFiles%\Keyhole.
#>
[CmdletBinding()]
param(
    [string]$InstallPath = (Join-Path $env:ProgramFiles 'Keyhole')
)

$ErrorActionPreference = 'Stop'
$serviceName = 'Keyhole'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'This script must run elevated. Start PowerShell as administrator and retry.'
}

$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if (-not $service) {
    throw "The Keyhole service is not installed. Run install-service.ps1 first."
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$project = Join-Path $repoRoot 'src\Keyhole.Service\Keyhole.Service.csproj'

$wasRunning = $service.Status -eq 'Running'
if ($wasRunning) {
    Write-Host 'Stopping service...' -ForegroundColor Cyan
    # A clean stop lets the service flush open flows' byte totals before exiting.
    Stop-Service -Name $serviceName
    $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
}

Write-Host 'Publishing...' -ForegroundColor Cyan
dotnet publish $project -c Release -r win-x64 --self-contained -o $InstallPath
if ($LASTEXITCODE -ne 0) {
    # Leave the service stopped rather than starting a half-replaced install.
    throw "Publish failed with exit code $LASTEXITCODE. The service is stopped."
}

if ($wasRunning) {
    Write-Host 'Starting service...' -ForegroundColor Cyan
    Start-Service -Name $serviceName
    (Get-Service -Name $serviceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
}

$status = (Get-Service -Name $serviceName).Status
Write-Host ''
Write-Host "Keyhole service updated and $status." -ForegroundColor Green
Write-Host "Logs: $env:ProgramData\Keyhole\logs"
