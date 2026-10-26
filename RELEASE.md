# Keyhole — telepítés és első indulás

## Amit telepítés előtt tudni érdemes

### A build nincs aláírva

Nincs kódaláíró tanúsítvány a projekthez, ezért a Windows **SmartScreen figyelmeztetni fog**
az első indításkor:

> *A Windows megvédte a számítógépet — Ismeretlen közzétevő*

Ez nem azt jelenti, hogy valami baj van a fájllal; azt jelenti, hogy a Windows nem tudja
ellenőrizni, ki készítette. Továbblépés: **További információ → Futtatás mindenképp**.

A Defender is visszatarthatja egy-két percre, amíg felhőben elemzi. Ez normális egy olyan
programnál, ami forgalmat figyel és tűzfalszabályokat ír — ezek önmagukban gyanús minták.

> Ha később lesz tanúsítvány: `scripts\build-release.ps1 -CertificatePath cert.pfx`, a
> jelszót a `KEYHOLE_CERT_PASSWORD` környezeti változóból olvassa, nem parancssori
> paraméterből.

### Mihez kell rendszergazda

| Funkció | Jogosultság | Enélkül |
|---|---|---|
| Kapcsolat-monitorozás | nem kell | működik |
| Process- és hostnév-feloldás | nem kell | működik (kevesebb elérési út látszik) |
| **Byte-számlálás (ETW)** | **admin** | a forgalom-oszlop `—` marad, a UI megindokolja |
| **UDP/QUIC célpontok (ETW)** | **admin** | a UDP-forgalom nem jelenik meg a listában |
| **Blokkolás (tűzfal)** | **admin** | a Block gombok le vannak tiltva, a UI megindokolja |
| TLS keylog capture | nem kell | működik |

A **service** fut rendszergazdaként (LocalSystem), a **UI nem**. Ez szándékos: így nincs
UAC-prompt minden indításnál, és egy UI-hiba sem fut emelt jogosultsággal.

---

## Telepítés

1. Csomagold ki a zipet egy tetszőleges mappába.
2. Futtasd az **`Install Keyhole.cmd`** fájlt. UAC-promptot fog kérni — ez a service
   telepítéséhez kell.
3. Indítsd a UI-t: `app\Keyhole.exe`.

Kézzel, emelt jogú PowerShellből ugyanez:

```powershell
.\install-service.ps1
```

### Ellenőrzés

Emelt jogú PowerShellből, futó service mellett:

```powershell
.\verify-elevated.ps1
```

Végigviszi a byte-számlálást és egy teljes blokkolás-kört (létrehoz egy szabályt egy
eldobható fájlra, ellenőrzi a Windows tűzfalban, majd eltakarítja).

---

## Eltávolítás

```powershell
.\uninstall-service.ps1              # az adatok megmaradnak
.\uninstall-service.ps1 -PurgeData   # az adatok is törlődnek (megerősítést kér)
```

A tűzfalszabályokat a Keyhole a service leállításakor **nem** törli — ez szándékos: amit
letiltottál, az letiltva marad. Ha mindet meg akarod szüntetni, előbb a UI „Blocked apps"
fülén oldd fel őket, és csak utána távolítsd el a service-t. Kézzel a `wf.msc`-ben a
`Keyhole - ` előtagú szabályokat kell törölni.

---

## Hol tárol adatot

Minden a `%ProgramData%\Keyhole` alatt:

| Mappa / fájl | Tartalom |
|---|---|
| `keyhole.sqlite` | forgalomtörténet, folyamatok, szabályok, capture-session-ök |
| `settings.json` | a Settings fül beállításai |
| `logs\` | napi rotált naplók, 14 nap |
| `captures\` | **TLS-kulcsok** session-önként |

> ⚠️ A `captures\` mappa valódi TLS-titkokat tartalmaz. Amíg egy keylog megvan, a hozzá
> tartozó rögzített forgalom visszafejthető. Ne oszd meg, és ha végeztél, töröld.

---

## Ismert korlátok

- **A capture nem működik minden appnál.** Csak NSS/BoringSSL/OpenSSL-alapú programok
  olvassák az `SSLKEYLOGFILE`-t: Chrome, Firefox, Brave, Edge, Electron, Node, curl
  (OpenSSL-es build). A Windows saját Schannel-ét használó programok — köztük a legtöbb
  natív .NET app és a Windows beépített `curl.exe`-je — figyelmen kívül hagyják. A Keyhole
  ezt indítás előtt jelzi.
- **A blokkolás útvonal alapján működik.** A Windows tűzfal így működik. A Keyhole a
  szabály létrehozásakor elmenti az `.exe` SHA-256 hash-ét, és jelzi, ha a fájl utóbb
  megváltozott — de a szabály akkor is az útvonalra vonatkozik.
- **UDP-célpontokhoz admin kell.** A UDP socket-tábla nem tartalmaz távoli végpontot, ezért
  a Keyhole az ETW-ből veszi őket — ami emelt jogot igényel. Enélkül a UDP (így a QUIC/HTTP3)
  forgalom nem jelenik meg a listában.
- **Antivírus-riasztás lehetséges.** Forgalom-figyelés, ETW-session és környezeti változó
  injektálás — aláíratlan buildnél ez együtt kiverheti a biztosítékot.
