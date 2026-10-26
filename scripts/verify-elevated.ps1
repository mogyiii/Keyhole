<#
.SYNOPSIS
    Verifies the capabilities that need administrator rights: ETW byte counting and
    Windows Firewall blocking.

.DESCRIPTION
    Must run elevated, with the Keyhole service already running (also elevated).

    The blocking check creates a real firewall rule for a throwaway executable this
    script writes to the temp folder, confirms it in the Windows firewall, then removes
    it again. Nothing the machine depends on is touched, and the rule is cleaned up even
    if a step fails.

.PARAMETER KeepRule
    Leaves the test rule in place so it can be inspected in wf.msc. Remove it manually.
#>
[CmdletBinding()]
param(
    [switch]$KeepRule
)

$ErrorActionPreference = 'Stop'

function Write-Check($ok, $text) {
    if ($ok) { Write-Host "  [PASS] $text" -ForegroundColor Green }
    else     { Write-Host "  [FAIL] $text" -ForegroundColor Red }
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'This script must run elevated. Start PowerShell as administrator and retry.'
}

# --- IPC helper -------------------------------------------------------------

function Invoke-Keyhole([string]$Method, [string]$ParamsJson) {
    $pipe = New-Object System.IO.Pipes.NamedPipeClientStream(
        '.', 'keyhole.service', [System.IO.Pipes.PipeDirection]::InOut)
    try {
        $pipe.Connect(3000)
    } catch {
        throw "Could not reach the Keyhole service. Start it elevated first: dotnet run --project src\Keyhole.Service"
    }

    $id = [guid]::NewGuid().ToString('n')
    if ($ParamsJson) {
        $request = "{`"method`":`"$Method`",`"id`":`"$id`",`"params`":$ParamsJson}`n"
    } else {
        $request = "{`"method`":`"$Method`",`"id`":`"$id`"}`n"
    }

    $bytes = [Text.Encoding]::UTF8.GetBytes($request)
    $pipe.Write($bytes, 0, $bytes.Length)
    $pipe.Flush()

    $sb = New-Object Text.StringBuilder
    $buffer = New-Object byte[] 65536
    while ($true) {
        $read = $pipe.Read($buffer, 0, $buffer.Length)
        if ($read -le 0) { break }
        $chunk = [Text.Encoding]::UTF8.GetString($buffer, 0, $read)
        [void]$sb.Append($chunk)
        if ($chunk.Contains("`n")) { break }
    }
    $pipe.Dispose()

    $parsed = $sb.ToString().TrimEnd("`n") | ConvertFrom-Json
    if ($parsed.error) { throw "$($parsed.error.code): $($parsed.error.message)" }
    return $parsed.result
}

# --- 1. Service state -------------------------------------------------------

Write-Host "`nService status" -ForegroundColor Cyan
$status = Invoke-Keyhole -Method 'get-status'

Write-Check $status.isElevated "service is elevated"
Write-Check ($status.monitorState -eq 'running') "monitoring is running ($($status.activeConnections) connections)"

if (-not $status.isElevated) {
    throw 'The service itself is not elevated. Restart it from an elevated prompt.'
}

# --- 2. ETW byte counting ---------------------------------------------------

Write-Host "`nByte counting (ETW)" -ForegroundColor Cyan
Write-Check (-not $status.byteCountingUnavailableReason) "ETW session started"
if ($status.byteCountingUnavailableReason) {
    Write-Host "    reason: $($status.byteCountingUnavailableReason)" -ForegroundColor Yellow
} else {
    # Generate traffic, then look for a non-zero total somewhere in the app list.
    try { Invoke-WebRequest -Uri 'https://example.com' -UseBasicParsing -TimeoutSec 10 | Out-Null } catch {}
    Start-Sleep -Seconds 5

    $apps = Invoke-Keyhole -Method 'list-apps'
    $withTraffic = @($apps | Where-Object { $_.bytesSent -gt 0 -or $_.bytesReceived -gt 0 })

    Write-Check ($withTraffic.Count -gt 0) "byte totals are being recorded ($($withTraffic.Count) apps with traffic)"
    $withTraffic | Select-Object -First 5 | ForEach-Object {
        Write-Host ("    {0,-38} up {1,10}  down {2,10}" -f $_.displayName, $_.bytesSent, $_.bytesReceived)
    }
}

# --- 3. Blocking ------------------------------------------------------------

Write-Host "`nBlocking (Windows Firewall)" -ForegroundColor Cyan
Write-Check (-not $status.blockingUnavailableReason) "firewall is writable"
if ($status.blockingUnavailableReason) {
    Write-Host "    reason: $($status.blockingUnavailableReason)" -ForegroundColor Yellow
    exit 1
}

# A throwaway binary, so no real application's connectivity is affected.
$testExe = Join-Path $env:TEMP "keyhole-blocktest-$([guid]::NewGuid().ToString('n')).exe"
Copy-Item "$env:SystemRoot\System32\curl.exe" $testExe
$rule = $null

try {
    $rule = Invoke-Keyhole -Method 'block-app' -ParamsJson (@{
        executablePath = $testExe
        direction      = 'outbound'
        note           = 'verify-elevated.ps1 test rule'
    } | ConvertTo-Json -Compress)

    Write-Check ($null -ne $rule.id) "block-app returned rule id $($rule.id)"
    Write-Check ($rule.executableState -eq 'match') "executable hash was pinned ($($rule.executableState))"

    # Confirm in the firewall itself, not just in Keyhole's own record.
    $fwRules = @(Get-NetFirewallRule -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -like 'Keyhole - *' })

    $matching = @($fwRules | Where-Object {
        ($_ | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue).Program -eq $testExe
    })

    Write-Check ($matching.Count -gt 0) "Windows Firewall has the rule ($($matching.Count) entr(y/ies))"
    $matching | ForEach-Object {
        Write-Host "    $($_.DisplayName): $($_.Action) $($_.Direction), enabled=$($_.Enabled)"
        Write-Check ($_.Action -eq 'Block') "action is Block"
        Write-Check ($_.Direction -eq 'Outbound') "direction is Outbound"
    }

    $listed = @(Invoke-Keyhole -Method 'list-rules')
    Write-Check (@($listed | Where-Object { $_.id -eq $rule.id }).Count -eq 1) "rule appears in list-rules"
}
finally {
    if ($rule -and -not $KeepRule) {
        Write-Host "`nCleanup" -ForegroundColor Cyan
        try {
            Invoke-Keyhole -Method 'unblock-app' -ParamsJson (@{ ruleId = $rule.id } | ConvertTo-Json -Compress) | Out-Null

            $left = @(Get-NetFirewallRule -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName -like 'Keyhole - *' } |
                Where-Object { ($_ | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue).Program -eq $testExe })

            Write-Check ($left.Count -eq 0) "firewall rule removed"

            $stillListed = @(Invoke-Keyhole -Method 'list-rules' | Where-Object { $_.id -eq $rule.id })
            Write-Check ($stillListed.Count -eq 0) "rule removed from Keyhole"
        } catch {
            Write-Host "  [WARN] Cleanup failed: $_" -ForegroundColor Yellow
            Write-Host "         Remove any leftover 'Keyhole - ' rule in wf.msc." -ForegroundColor Yellow
        }
    } elseif ($KeepRule) {
        Write-Host "`nTest rule left in place for rule id $($rule.id); remove it with wf.msc." -ForegroundColor Yellow
    }

    Remove-Item $testExe -ErrorAction SilentlyContinue
}

Write-Host "`nDone.`n" -ForegroundColor Green
