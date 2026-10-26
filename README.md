# Keyhole

[![CI](https://github.com/mogyiii/Keyhole/actions/workflows/ci.yml/badge.svg)](https://github.com/mogyiii/Keyhole/actions/workflows/ci.yml)

Hálózati forgalom-elemző és per-alkalmazás blokkoló Windowsra. A GlassWire átláthatóságát és a
Wireshark mélységét egy helyen, kézi `SSLKEYLOGFILE` kapcsolgatás nélkül.

A részletes terv és az aktuális állapot: [`milestone.md`](milestone.md).

**Jelenleg:** M2 kész — a monitorozás működik. Blokkolás (M4) és a kész UI (M3) még hátravan.

## Felépítés

| Projekt | Szerep |
|---|---|
| `src/Keyhole.App` | Avalonia desktop UI. **Nem** elevated — minden privilegizált művelet a service-é. |
| `src/Keyhole.Service` | Windows Service (LocalSystem). ETW, tűzfalszabályok, capture. |
| `src/Keyhole.Core` | Közös kód: IPC-kontraktus, SQLite tárolás, útvonalak. |
| `src/Keyhole.Native` | P/Invoke és COM interop réteg Windows API-khoz. |
| `tests/Keyhole.Tests` | Unit- és integrációs tesztek. |

A két folyamat egy named pipe-on (`\\.\pipe\keyhole.service`) beszél, újsor-határolt JSON
keretekkel. A pipe ACL-je az interaktív felhasználóra és adminokra korlátozott.

### Miért van szétválasztva a UI és a service?

A forgalom-monitorozás, a tűzfalszabály-írás és a packet capture mind adminjogot kér. Ha maga az UI
futna elevated módban, minden UI-bug admin-jogosultságú lenne, és minden indításnál UAC-prompt jönne.
Így az UI a bejelentkezett userként fut, és csak kéréseket küld.

## Fejlesztés

```powershell
dotnet build            # teljes solution
dotnet test             # tesztek

# Service konzol módban (fejlesztéshez, nem kell telepíteni):
dotnet run --project src/Keyhole.Service

# UI külön ablakban:
dotnet run --project src/Keyhole.App
```

Konzol módban a service nem elevated, ezért figyelmeztetést ír — M1-ben ez rendben van, mert még
nincs privilegizált funkció. Az M2-től viszont emelt jogosultság kell.

## Telepítés szolgáltatásként

Emelt jogú PowerShellből:

```powershell
.\scripts\install-service.ps1
.\scripts\uninstall-service.ps1            # adatok megmaradnak
.\scripts\uninstall-service.ps1 -PurgeData # adatok is törlődnek (megerősítést kér)
```

## Adatok a lemezen

Minden a `%ProgramData%\Keyhole` alatt, mert a service LocalSystemként fut és nem használhat
felhasználói mappát:

- `keyhole.sqlite` — forgalomtörténet, folyamatok, szabályok, capture-session-ök
- `logs/` — napi rotált Serilog fájlok, 14 nap
- `captures/` — session-önként egy mappa a pcap és a TLS keylog fájllal

> ⚠️ A `captures/` mappa visszafejtett forgalmat és TLS-kulcsokat tartalmaz. A `.gitignore` kizárja,
> de megosztás előtt is érdemes meggondolni, mi van benne.
