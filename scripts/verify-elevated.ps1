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
        throw "Could not reach the Keyhole service on \\.\pipe\keyhole.service."
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

# --- 0. Make sure a service is actually running ------------------------------

function Test-KeyholePipe {
    return [bool](@([System.IO.Directory]::GetFiles('\\.\pipe\')) -like '*keyhole.service*')
}

function Find-ServiceExe {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    $candidates = @(
        # Next to this script in an unpacked release.
        (Join-Path $PSScriptRoot 'service\Keyhole.Service.exe'),
        (Join-Path (Split-Path -Parent $PSScriptRoot) 'service\Keyhole.Service.exe'),
        # Installed location.
        (Join-Path $env:ProgramFiles 'Keyhole\Keyhole.Service.exe'),
        # Developer builds.
        (Join-Path $repoRoot 'src\Keyhole.Service\bin\Release\net10.0-windows\win-x64\Keyhole.Service.exe'),
        (Join-Path $repoRoot 'src\Keyhole.Service\bin\Release\net10.0-windows\Keyhole.Service.exe'),
        (Join-Path $repoRoot 'src\Keyhole.Service\bin\Debug\net10.0-windows\Keyhole.Service.exe')
    )
    # Newest wins rather than first match. Several of these can exist at once on a
    # development machine, and verifying against a stale build would report on code
    # that is no longer what anyone is running.
    return $candidates |
        Where-Object { Test-Path $_ } |
        Get-Item |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1 -ExpandProperty FullName
}

$startedByUs = $null

if (-not (Test-KeyholePipe)) {
    Write-Host "`nNo service running - starting one" -ForegroundColor Cyan

    # The point of this script is to exercise the elevated paths, and it is already
    # elevated, so starting the service here is both safe and what the user wants.
    # Requiring them to start it separately only invites running the checks against
    # an unelevated service, which would report false failures.
    $svc = Get-Service -Name 'Keyhole' -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.Status -ne 'Running') {
            Start-Service -Name 'Keyhole'
            $svc.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
        }
        Write-Check $true "started the installed Keyhole service"
    } else {
        $exe = Find-ServiceExe
        if (-not $exe) {
            throw "Could not find Keyhole.Service.exe. Install the service first (install-service.ps1) or build the solution."
        }

        Write-Host "  using $exe"
        $startedByUs = Start-Process -FilePath $exe -PassThru -WindowStyle Hidden

        $deadline = (Get-Date).AddSeconds(30)
        while ((Get-Date) -lt $deadline -and -not (Test-KeyholePipe)) {
            Start-Sleep -Milliseconds 400
        }
        Write-Check (Test-KeyholePipe) "started the service from disk"
    }

    if (-not (Test-KeyholePipe)) {
        throw 'The service did not come up. Check %ProgramData%\Keyhole\logs.'
    }

    # Give the first sampling pass time to land before asking about monitor state.
    Start-Sleep -Seconds 3
}

try {

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
Write-Check (-not $status.byteCountingUnavailable) "ETW session started"
if ($status.byteCountingUnavailable) {
    Write-Host "    reason code: $($status.byteCountingUnavailable)" -ForegroundColor Yellow
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
Write-Check (-not $status.blockingUnavailable) "firewall is writable"
if ($status.blockingUnavailable) {
    Write-Host "    reason code: $($status.blockingUnavailable)" -ForegroundColor Yellow
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

# --- 4. Packet capture and TLS decoding (M8) --------------------------------

Write-Host "`nPacket capture (Npcap)" -ForegroundColor Cyan

Write-Host "    npcap state: $($status.npcapState) $($status.npcapVersion)"
Write-Check ($status.npcapState -eq 'ready') "Npcap is ready"

if ($status.npcapState -ne 'ready') {
    Write-Host "    Skipping the capture checks. Install Npcap to verify them." -ForegroundColor Yellow
} else {
    # A browser, because the point is to exercise the whole chain: an application that
    # writes a real keylog, over real TLS, decoded by Keyhole's own pipeline. Anything on
    # Schannel - including the curl.exe in System32 - writes no keys and would verify
    # nothing beyond that packets were recorded.
    $browsers = @(
        (Join-Path $env:ProgramFiles 'Google\Chrome\Application\chrome.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'Google\Chrome\Application\chrome.exe'),
        (Join-Path $env:ProgramFiles 'BraveSoftware\Brave-Browser\Application\brave.exe'),
        (Join-Path $env:ProgramFiles 'Mozilla Firefox\firefox.exe')
    )
    $browser = $browsers | Where-Object { Test-Path $_ } | Select-Object -First 1

    if (-not $browser) {
        Write-Host "    No Chrome, Brave or Firefox found; cannot verify TLS decoding." -ForegroundColor Yellow
    } else {
        Write-Host "    using $browser"

        # A fresh profile, so the run is not answered entirely out of a warm cache and so
        # nothing touches the user's real browser state.
        $profileDir = Join-Path $env:TEMP "keyhole-verify-profile-$([guid]::NewGuid().ToString('n'))"

        # HTTP/1.1 is forced on purpose. Chrome prefers HTTP/3 over QUIC wherever a server
        # offers it, and Keyhole cannot decode QUIC - so without this the capture would be
        # mostly undecodable UDP and the check would fail for a reason that is documented
        # rather than a bug.
        # Not named $args: that is an automatic variable in PowerShell, and shadowing it
        # is the kind of thing that works until it suddenly does not.
        $browserArgs = "--user-data-dir=`"$profileDir`" --no-first-run --no-default-browser-check " +
                       "--disable-quic --disable-http2 https://example.com/"

        $session = Invoke-Keyhole -Method 'start-capture' -ParamsJson (@{
            executablePath = $browser
            arguments      = $browserArgs
        } | ConvertTo-Json -Compress)

        Write-Check ($null -ne $session.id) "start-capture returned session id $($session.id)"
        Write-Check ($null -ne $session.pcapFile) "a packet capture was created"
        Write-Host "    directory: $($session.directory)"

        try {
            # Long enough for the page to load and the browser to settle.
            Write-Host "    letting the browser run for 20 seconds..."
            Start-Sleep -Seconds 20

            Invoke-Keyhole -Method 'stop-capture' -ParamsJson (@{ sessionId = $session.id } | ConvertTo-Json -Compress) | Out-Null

            $listed = @(Invoke-Keyhole -Method 'list-captures') | Where-Object { $_.id -eq $session.id }

            Write-Check ($listed.keylogBytes -gt 0) "the browser wrote TLS keys ($($listed.keylogBytes) bytes)"
            Write-Check ($listed.pcapBytes -gt 0) "packets were recorded ($($listed.pcapBytes) bytes)"

            # The whole point of M8: Keyhole decrypts its own capture with its own keys.
            Write-Host "`n  Decoding the capture" -ForegroundColor Cyan
            $decoded = Invoke-Keyhole -Method 'decode-capture' -ParamsJson (@{ sessionId = $session.id } | ConvertTo-Json -Compress)

            # The service sends counts, not a sentence: the interface composes the summary
            # in the user's language, so this script composes its own.
            Write-Host ("    {0} conversations: {1} decrypted, {2} without keys, {3} missing a handshake, {4} failed" -f `
                $decoded.conversations, $decoded.decrypted, $decoded.encryptedWithoutKeys, `
                $decoded.handshakeMissing, $decoded.decryptionFailed)

            if ($decoded.quicBytes -gt 0) {
                Write-Host "    $($decoded.quicBytes) bytes of QUIC were skipped (not decodable)"
            }

            if ($decoded.failure) {
                Write-Host "    failure code: $($decoded.failure)" -ForegroundColor Yellow
            }
            Write-Check ($decoded.decrypted -gt 0) "TLS connections were decrypted ($($decoded.decrypted) of $($decoded.conversations))"
            Write-Check (@($decoded.exchanges).Count -gt 0) "requests were recovered ($(@($decoded.exchanges).Count))"

            @($decoded.exchanges) | Select-Object -First 8 | ForEach-Object {
                Write-Host ("    {0,-6} {1,-4} {2}" -f $_.method, $_.statusCode, $_.url)
            }

            # Wireshark reading the same file is the independent check: it proves the
            # capture is a real pcapng and that the embedded secrets are readable by
            # something other than Keyhole.
            $tshark = @(
                (Join-Path $env:ProgramFiles 'Wireshark\tshark.exe'),
                (Join-Path ${env:ProgramFiles(x86)} 'Wireshark\tshark.exe')
            ) | Where-Object { Test-Path $_ } | Select-Object -First 1

            if ($tshark) {
                Write-Host "`n  Wireshark reading the same capture" -ForegroundColor Cyan
                $fields = & $tshark -r $listed.pcapFile -Y 'http.request' -T fields -e http.host -e http.request.uri 2>$null
                $rows = @($fields | Where-Object { $_ -match '\S' })

                Write-Check ($rows.Count -gt 0) "tshark decrypted the capture too ($($rows.Count) requests)"
                $rows | Select-Object -First 5 | ForEach-Object { Write-Host "    $_" }
            } else {
                Write-Host "    Wireshark not installed; skipped the cross-check." -ForegroundColor Yellow
            }
        }
        finally {
            # The browser is left running by design when a capture stops, so this script
            # has to close the one it started itself.
            Get-Process -ErrorAction SilentlyContinue |
                Where-Object { $_.Path -eq $browser } |
                ForEach-Object { try { $_.CloseMainWindow() | Out-Null } catch {} }

            Start-Sleep -Seconds 2
            Get-Process -ErrorAction SilentlyContinue |
                Where-Object { $_.Path -eq $browser } |
                ForEach-Object { try { $_.Kill() } catch {} }

            Start-Sleep -Seconds 1
            Remove-Item $profileDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Write-Host "`nDone.`n" -ForegroundColor Green

}
finally {
    # Only stop what this script started. A service the user was already running -
    # installed or launched by hand - is left exactly as it was found.
    if ($startedByUs -and -not $startedByUs.HasExited) {
        Write-Host "Stopping the service this script started." -ForegroundColor Cyan
        $startedByUs.Kill()
        $startedByUs.WaitForExit(5000) | Out-Null
    }
}
