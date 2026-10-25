<#
.SYNOPSIS
    Publishes Keyhole.Service and registers it as a Windows service.

.DESCRIPTION
    Must run elevated. The service is installed as LocalSystem because from M2 on it needs
    ETW sessions, Windows Firewall rules and packet capture, none of which a normal account
    can do. The UI stays unelevated and reaches it over a named pipe.

.PARAMETER Configuration
    Build configuration to publish. Defaults to Release.

.PARAMETER InstallPath
    Where the service binaries land. Defaults to %ProgramFiles%\Keyhole.
#>
[CmdletBinding()]
param(
    [string]$Configuration = 'Release',
    [string]$InstallPath = (Join-Path $env:ProgramFiles 'Keyhole')
)

$ErrorActionPreference = 'Stop'
$serviceName = 'Keyhole'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'This script must run elevated. Start PowerShell as administrator and retry.'
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$project = Join-Path $repoRoot 'src\Keyhole.Service\Keyhole.Service.csproj'

Write-Host "Publishing $Configuration build..." -ForegroundColor Cyan
dotnet publish $project -c $Configuration -o $InstallPath
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed with exit code $LASTEXITCODE." }

$exe = Join-Path $InstallPath 'Keyhole.Service.exe'
if (-not (Test-Path $exe)) { throw "Expected $exe after publish, but it is missing." }

$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host 'Service already registered; stopping it to refresh the binary path.' -ForegroundColor Yellow
    if ($existing.Status -ne 'Stopped') {
        Stop-Service -Name $serviceName -Force
        $existing.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
    # binPath is the one property New-Service cannot update in place.
    sc.exe config $serviceName binPath= "`"$exe`"" | Out-Null
} else {
    Write-Host 'Registering service...' -ForegroundColor Cyan
    New-Service -Name $serviceName `
        -BinaryPathName "`"$exe`"" `
        -DisplayName 'Keyhole Network Monitor' `
        -Description 'Monitors per-application network activity and applies Keyhole block rules.' `
        -StartupType Automatic | Out-Null
}

# Restart on crash: without this a failed monitor leaves the UI permanently disconnected.
sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null

Write-Host 'Starting service...' -ForegroundColor Cyan
Start-Service -Name $serviceName
(Get-Service -Name $serviceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))

Write-Host ''
Write-Host "Keyhole service is running from $InstallPath" -ForegroundColor Green
Write-Host "Logs:  $env:ProgramData\Keyhole\logs"
Write-Host "Data:  $env:ProgramData\Keyhole"
