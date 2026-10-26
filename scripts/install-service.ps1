<#
.SYNOPSIS
    Installs Keyhole: the Windows service and the desktop UI.

.DESCRIPTION
    Must run elevated. The service is installed as LocalSystem because it needs ETW
    sessions and Windows Firewall rules, neither of which a normal account can do. The UI
    is installed alongside it but runs unelevated as the signed-in user, reaching the
    service over a named pipe.

    The UI goes to a stable location with a Start menu shortcut, so it does not have to be
    run out of a build folder -- which breaks on the next rebuild and makes the
    start-at-sign-in setting point at a path that may not survive.

.PARAMETER Configuration
    Build configuration to publish. Defaults to Release.

.PARAMETER InstallPath
    Where the binaries land. Defaults to %ProgramFiles%\Keyhole.

.PARAMETER SkipUi
    Install only the service. The UI then has to be run from a build folder.
#>
[CmdletBinding()]
param(
    [string]$Configuration = 'Release',
    [string]$InstallPath = (Join-Path $env:ProgramFiles 'Keyhole'),
    [switch]$SkipUi
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

# --- UI ---------------------------------------------------------------------

$uiPath = Join-Path $InstallPath 'app'
$uiExe = Join-Path $uiPath 'Keyhole.exe'

if (-not $SkipUi) {
    # Publishing over a running UI fails on locked files, and the message MSBuild gives
    # is about a dll rather than about Keyhole being open.
    $running = @(Get-Process -Name 'Keyhole' -ErrorAction SilentlyContinue |
        Where-Object {
            try { $_.Path -and $_.Path.StartsWith($uiPath, [StringComparison]::OrdinalIgnoreCase) }
            catch { $false }
        })

    if ($running.Count -gt 0) {
        Write-Host 'Closing the running Keyhole UI to replace it...' -ForegroundColor Yellow
        $running | Stop-Process -Force
        Start-Sleep -Milliseconds 800
    }

    Write-Host 'Publishing UI...' -ForegroundColor Cyan
    dotnet publish (Join-Path $repoRoot 'src\Keyhole.App\Keyhole.App.csproj') `
        -c $Configuration -o $uiPath
    if ($LASTEXITCODE -ne 0) { throw "UI publish failed with exit code $LASTEXITCODE." }

    if (-not (Test-Path $uiExe)) { throw "Expected $uiExe after publish, but it is missing." }

    # A Start menu entry so the UI can be found without knowing where it was installed.
    $shortcut = Join-Path ([Environment]::GetFolderPath('CommonStartMenu')) 'Programs\Keyhole.lnk'
    $shell = New-Object -ComObject WScript.Shell
    $link = $shell.CreateShortcut($shortcut)
    $link.TargetPath = $uiExe
    $link.WorkingDirectory = $uiPath
    $link.Description = 'Keyhole network monitor'
    $link.Save()

    Write-Host "  shortcut: $shortcut"
}

Write-Host ''
Write-Host "Keyhole service is running from $InstallPath" -ForegroundColor Green
if (-not $SkipUi) {
    Write-Host "UI:    $uiExe (also in the Start menu)" -ForegroundColor Green
}
Write-Host "Logs:  $env:ProgramData\Keyhole\logs"
Write-Host "Data:  $env:ProgramData\Keyhole"
