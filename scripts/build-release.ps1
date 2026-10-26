<#
.SYNOPSIS
    Builds a self-contained Keyhole release and packages it for distribution.

.DESCRIPTION
    Produces dist\Keyhole-<version>\ containing the UI, the service and the install
    scripts, plus a zip of the same.

    The output is NOT code signed. Windows SmartScreen will warn the first time anyone
    runs it, and Defender may hold it briefly — see RELEASE.md. Signing needs a code
    signing certificate; pass -CertificatePath to enable it once one exists.

.PARAMETER Version
    Version stamped into the assemblies and the folder name.

.PARAMETER SelfContained
    Bundle the .NET runtime so the target machine needs no separate install.
    Larger output, far fewer support questions.

.PARAMETER CertificatePath
    Optional .pfx to sign with. The password is read from the KEYHOLE_CERT_PASSWORD
    environment variable so it never lands in the repo or the shell history.
#>
[CmdletBinding()]
param(
    [string]$Version = '0.1.0',
    [switch]$SelfContained = $true,
    [string]$CertificatePath
)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$distRoot = Join-Path $repoRoot 'dist'
$stage = Join-Path $distRoot "Keyhole-$Version"

if (Test-Path $stage) {
    Remove-Item -Recurse -Force $stage
}
New-Item -ItemType Directory -Force $stage | Out-Null

$publishArgs = @(
    '-c', 'Release',
    '-r', 'win-x64',
    "-p:Version=$Version",
    "-p:InformationalVersion=$Version"
)

if ($SelfContained) {
    $publishArgs += '--self-contained'
    $publishArgs += '-p:IncludeNativeLibrariesForSelfExtract=true'
} else {
    $publishArgs += '--no-self-contained'
}

Write-Host "Publishing service..." -ForegroundColor Cyan
dotnet publish (Join-Path $repoRoot 'src\Keyhole.Service\Keyhole.Service.csproj') `
    @publishArgs -o (Join-Path $stage 'service')
if ($LASTEXITCODE -ne 0) { throw "Service publish failed ($LASTEXITCODE)." }

Write-Host "Publishing UI..." -ForegroundColor Cyan
dotnet publish (Join-Path $repoRoot 'src\Keyhole.App\Keyhole.App.csproj') `
    @publishArgs -o (Join-Path $stage 'app')
if ($LASTEXITCODE -ne 0) { throw "UI publish failed ($LASTEXITCODE)." }

Copy-Item (Join-Path $repoRoot 'scripts\install-service.ps1') $stage
Copy-Item (Join-Path $repoRoot 'scripts\uninstall-service.ps1') $stage
Copy-Item (Join-Path $repoRoot 'scripts\verify-elevated.ps1') $stage
Copy-Item (Join-Path $repoRoot 'README.md') $stage
if (Test-Path (Join-Path $repoRoot 'RELEASE.md')) {
    Copy-Item (Join-Path $repoRoot 'RELEASE.md') $stage
}

# One entry point, so nobody has to work out which exe starts what.
@"
@echo off
REM Installs the Keyhole service (needs administrator) and starts the UI.
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','%~dp0install-service.ps1'"
"@ | Set-Content (Join-Path $stage 'Install Keyhole.cmd') -Encoding ascii

if ($CertificatePath) {
    if (-not $env:KEYHOLE_CERT_PASSWORD) {
        throw 'Set KEYHOLE_CERT_PASSWORD before signing. It is deliberately not a parameter.'
    }

    Write-Host "Signing binaries..." -ForegroundColor Cyan
    $signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -like '*x64*' } | Select-Object -First 1
    if (-not $signtool) { throw 'signtool.exe not found. Install the Windows SDK.' }

    Get-ChildItem $stage -Recurse -Include 'Keyhole*.exe', 'Keyhole*.dll' | ForEach-Object {
        & $signtool.FullName sign /fd SHA256 /f $CertificatePath /p $env:KEYHOLE_CERT_PASSWORD `
            /tr http://timestamp.digicert.com /td SHA256 $_.FullName
        if ($LASTEXITCODE -ne 0) { throw "Signing failed for $($_.Name)." }
    }
} else {
    Write-Host ''
    Write-Host 'NOT SIGNED. SmartScreen will warn on first run; see RELEASE.md.' -ForegroundColor Yellow
}

$zip = Join-Path $distRoot "Keyhole-$Version.zip"
if (Test-Path $zip) { Remove-Item $zip }
Compress-Archive -Path "$stage\*" -DestinationPath $zip

$sizeMb = [math]::Round((Get-Item $zip).Length / 1MB, 1)
Write-Host ''
Write-Host "Built Keyhole $Version" -ForegroundColor Green
Write-Host "  folder: $stage"
Write-Host "  zip:    $zip ($sizeMb MB)"
