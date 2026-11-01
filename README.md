# Keyhole

[![CI](https://github.com/mogyiii/Keyhole/actions/workflows/ci.yml/badge.svg)](https://github.com/mogyiii/Keyhole/actions/workflows/ci.yml)

A network traffic analyser and per-application blocker for Windows. GlassWire's clarity
and Wireshark's depth in one place, without setting `SSLKEYLOGFILE` by hand.

**Current state:** M1–M8 complete, verified against real traffic. Installation and known
limits: [`RELEASE.md`](RELEASE.md). The full plan and the measurements behind each
milestone: [`milestone.md`](milestone.md). Both are written in Hungarian — they are the
author's working documents.

The interface is available in English and Hungarian, following the system language by
default.

## What it does

- **Who is talking on the network** — per application, with its icon, publisher,
  Authenticode signature status and resolved hostnames; for svchost, the name of the
  service running inside it
- **What one application is doing** — a breakdown per connection with PID, state and volume
- **Live throughput graph** split by direction, machine-wide and per application
- **UDP and QUIC with their destinations** — the UDP socket table carries no remote
  endpoint at all, so these come from ETW (which needs administrator rights)
- **Blocking in one click** — a Windows Firewall rule that survives a reboot. The rule
  records the executable's SHA-256 when it is created and flags it if the binary later
  changes. Manual only: no deny-by-default, no stream of permission prompts
- **TLS visibility without the environment-variable dance** — Keyhole launches the
  application with `SSLKEYLOGFILE` set **in that process alone**, so nothing else on the
  machine starts writing secrets and there is nothing to remember to turn off
- **Packet capture scoped to the target process** — recorded for the session's duration
  into a single pcapng *together with the keys*, so Wireshark opens it already decrypted
  with no keylog path to configure
- **A request and response view in the app** — Keyhole decrypts its own capture with its
  own keys: method, URL, status, headers, size, timing. HTTP/1.1 and HTTP/2 with HPACK.
  QUIC/HTTP3 is recorded but cannot be decoded, and the interface says so rather than
  showing a mysteriously short list
- **Top hosts** — which *destination* receives the most traffic, independent of which
  application sent it. This is where something unexpected shows up: a host that three
  unrelated programs all talk to
- **Country and network operator** from offline MaxMind MMDB files — no network calls,
  because a tool that watches other programs' traffic must not start generating its own

## Layout

| Project | Role |
|---|---|
| `src/Keyhole.App` | Avalonia desktop UI. **Not** elevated — every privileged operation belongs to the service. |
| `src/Keyhole.Service` | Windows Service (LocalSystem). ETW, firewall rules, capture. |
| `src/Keyhole.Core` | Shared code: the IPC contract, SQLite storage, paths, capture and decoding. |
| `src/Keyhole.Native` | P/Invoke and COM interop for Windows APIs. |
| `tests/Keyhole.Tests` | Unit and integration tests. |

The two processes talk over a named pipe (`\\.\pipe\keyhole.service`) in newline-delimited
JSON frames. The pipe's ACL is restricted to the interactive user and administrators.

### Why the UI and the service are separate

Traffic monitoring, writing firewall rules and packet capture all need administrator
rights. If the UI itself ran elevated, every UI bug would run with those rights and every
launch would raise a UAC prompt. Instead the UI runs as the signed-in user and only sends
requests.

## Development

```powershell
dotnet build            # the whole solution
dotnet test             # the tests

# The service as a console app, for development -- no installation needed:
dotnet run --project src/Keyhole.Service

# The UI in another window:
dotnet run --project src/Keyhole.App
```

Run that way the service is not elevated, so it reports which capabilities are
unavailable and continues without them: connection monitoring works, while byte counting,
blocking and packet capture do not.

Some tests compare Keyhole's output against Wireshark's own tools and are skipped when
Wireshark is not installed. A skip there means "unverified", not "verified" — the
structural tests remain the floor.

## Installing as a service

From an elevated PowerShell:

```powershell
.\scripts\install-service.ps1              # service, UI and a Start menu entry
.\scripts\update-service.ps1               # replace the service with a new build
.\scripts\uninstall-service.ps1            # data is kept
.\scripts\uninstall-service.ps1 -PurgeData # data is removed too (asks first)
.\scripts\verify-elevated.ps1              # exercises every privileged capability
```

`verify-elevated.ps1` is worth knowing about: it runs the whole chain end to end —
including launching a browser, recording it, decoding the capture and cross-checking the
result with `tshark` — and it is what found most of the bugs recorded in `milestone.md`.

## Data on disk

Everything under `%ProgramData%\Keyhole`, because the service runs as LocalSystem and
cannot use a per-user folder:

- `keyhole.sqlite` — flow history, processes, rules, capture sessions
- `settings.json` — the Settings tab
- `logs/` — daily Serilog files, kept 14 days
- `geoip/` — where MaxMind `.mmdb` files go, if you want the country and operator columns
- `captures/` — one folder per session: `capture.pcapng` and `sslkeys.log`

> ⚠️ `capture.pcapng` holds **both the recorded traffic and the keys that decrypt it, in
> one file** — which is exactly why Wireshark reads it straight away. For the same reason
> that single file is enough for anyone to read everything the application sent:
> passwords, tokens, cookies. `.gitignore` excludes it, but sharing is a larger question
> than that.

## Two dependencies are not bundled

Neither is licensed for redistribution, so Keyhole detects them and explains what to do:

- **Npcap**, for packet capture. The Capture tab offers to download the vendor's installer
  and verifies that it really is signed by the Nmap Project before running it. Without
  Npcap a session still collects TLS keys.
- **MaxMind GeoLite2** `.mmdb` files, for the country and operator columns. A free account
  is needed; the files go in `%ProgramData%\Keyhole\geoip`.

## Licence

Not yet chosen. The BSD-licensed managed bindings it depends on (SharpPcap, PacketDotNet)
and the Apache-2.0 MaxMind reader ship with the release; no third-party database or driver
does.
