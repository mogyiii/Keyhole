# Keyhole — Milestone terv

> Hálózati forgalom-elemző és -szabályozó .NET alkalmazás Windowsra.
> Cél: a GlassWire átláthatósága + a Wireshark mélysége, kézi env-var kapcsolgatás nélkül.

**Állapot:** M1–M7 kész ✅ + UDP-célpontok és per-app grafikon
**Utolsó frissítés:** 2026-10-26

---

## Termékcélok (a `plan.txt` alapján)

1. **Process-központú forgalomlista** — mely alkalmazások kommunikálnak, kivel, mennyit (GlassWire-stílus).
2. **Drill-down egy appra** — kapcsolatok, távoli hostok/IP-k, portok, protokoll, forgalommennyiség; és ha lehet: *mit* küld (payload).
3. **Blokkolás** — alkalmazás betallózása (`.exe`), és a hálózat letiltása neki. **Kizárólag manuális**: a felhasználó dönti el, melyik gyanús szoftvert tiltja le; nincs deny-by-default, nincs prompt-áradat.
4. **TLS-láthatóság kényelmesen** — ne kelljen kézzel `SSLKEYLOGFILE` env vart állítani, se Wiresharkot külön indítani.
5. **Modern UI** — nem Win32-retro; sötét téma, élő grafikonok, gyors lista.

---

## Architektúra-vázlat

```
┌─────────────────────────── Keyhole.App (UI, user-mode) ───────────────────────────┐
│  Modern UI: dashboard / app-lista / connection drill-down / rules / capture       │
└──────────────────────────────────┬────────────────────────────────────────────────┘
                                   │  IPC (named pipe, JSON-RPC)
┌──────────────────────────────────┴────────────────────────────────────────────────┐
│                 Keyhole.Service (Windows Service, elevated)                       │
│                                                                                   │
│  ┌───────────────┐ ┌───────────────┐ ┌──────────────┐ ┌────────────────────────┐ │
│  │ Flow monitor  │ │ Process map   │ │ Firewall     │ │ Capture / TLS          │ │
│  │ ETW kernel-   │ │ GetExtended   │ │ WFP / Net-   │ │ Npcap+SharpPcap        │ │
│  │ network       │ │ TcpTable, PID │ │ FwPolicy2    │ │ + keylog / MITM proxy  │ │
│  └───────────────┘ └───────────────┘ └──────────────┘ └────────────────────────┘ │
│                          ▼  SQLite (flow history, rules, sessions)               │
└───────────────────────────────────────────────────────────────────────────────────┘
```

**Miért kettéosztva:** a flow-monitorozás, a tűzfalszabály-írás és a packet capture adminjogot kér. Ha az UI is elevated, minden UI-bug admin-jogosultságú; a service-modell sokkal biztonságosabb és nem kell UAC-prompt minden indításnál.

---

## M0 — Döntések és spike-ok

**Cél:** a nyitott technológiai kérdések lezárása mérhető bizonyítékkal, mielőtt bármi épül.

| Teendő | Kimenet |
|---|---|
| ~~UI keretrendszer kiválasztása~~ | ✅ **Avalonia** (D1 lezárva) |
| ~~ETW spike~~ | ✅ `EtwByteCounter` megvalósítva (D2) |
| ~~WFP vs. `INetFwPolicy2`~~ | ✅ **INetFwPolicy2** — a szabályokat az OS birtokolja, túlélik az újraindítást (D3) |
| Npcap jelenlét/telepítés kezelése | silent install vagy "Npcap szükséges" onboarding flow |
| TLS-stratégia spike (keylog vs. MITM) | mérés: hány app fedhető le melyik úttal |

**Done, ha:** minden spike-ról van 1 bekezdés + működő kóddemó, és a *Nyitott döntések* szekcióban minden sor el van döntve.

---

## M1 — Csontváz és infrastruktúra ✅

- [x] .NET 10 solution: `Keyhole.App` (Avalonia), `Keyhole.Service`, `Keyhole.Core`, `Keyhole.Native`, `Keyhole.Tests`
- [x] Windows Service host + telepítő/eltávolító (`scripts/install-service.ps1`, `uninstall-service.ps1`)
- [x] Named pipe IPC, ACL-lel az interaktív userre; JSON-RPC-szerű kontraktus
- [x] SQLite séma + migrációk (`flows`, `processes`, `rules`, `sessions`)
- [x] Strukturált logolás (Serilog) fájlba és konzolra
- [x] CI: build + unit tesztek GitHub Actionsön (`windows-latest`)

**Done:** az UI elindul, a named pipe-on lekéri a service állapotát, és megjeleníti a verziót, uptime-ot
és az elevation-állapotot. 18 teszt zöld, a teljes solution 0 warninggal fordul.

> **Megtalált és javított hiba:** a kiszolgáló a válasz kiírása után azonnal `Disconnect()`-elt, ami
> eldobja a klienstől még el nem olvasott puffert. A rövid (payload nélküli) `ping`-válasz emiatt
> rendszertelenül elveszett — 25 hívásból a 15. Javítás: `WaitForPipeDrain()` időkorláttal, mielőtt
> a kapcsolat lebomlik. A `Repeated_pings_all_get_answers` teszt pont ezt őrzi.

---

## M2 — Monitorozás (olvasó funkciók) ✅

- [x] **Socket-pillanatkép:** `GetExtendedTcpTable` / `GetExtendedUdpTable` → PID szerinti aktív kapcsolatok (IPv4 + IPv6)
- [x] **Byte-számlálók:** ETW kernel-network szál (`EtwByteCounter`), emelt jog nélkül tisztán degradál
- [x] **Process-feloldás:** elérési út, terméknév, cég, Authenticode-állapot (`WinVerifyTrust`); svchost esetén service-nevek
- [x] **Hostnév-feloldás:** nem blokkoló reverse DNS, korlátozott párhuzamossággal és külön TTL-lel
- [x] Aggregáció: app → kapcsolat hierarchia, folyamatonkénti csoportosítás
- [x] Perzisztencia: SQLite forgalomtörténet + 30 napos retention
- [x] **UDP-célpontok ETW-ből** — a QUIC/HTTP3 forgalom már célponttal látszik
- [x] **Ikon-kinyerés** az `.exe`-kből (M3-ban)
- [x] **Élő sebesség** (byte/s) (M3-ban)
- [ ] **GeoIP** (opcionális, offline MMDB) — elhalasztva, nem blokkol semmit

**Done:** valódi forgalmon ellenőrizve — Brave, Claude Code, WinDefend, svchost-szolgáltatások és
`sunshine` is helyes névvel, kiadóval, aláírás-állapottal és feloldott hostnévvel jelenik meg.
A drill-down kattintásra megadja a kapcsolatokat PID-enként. 86 teszt zöld.

> **Nem ellenőrzött:** az ETW byte-számlálás **valódi** működése. A session emelt jogot kér, a
> fejlesztői környezet viszont nem az, így csak az hitelesített, hogy hiánya esetén a monitorozás
> fut tovább, és a UI meg is indokolja. Az élesítés előtt le kell futtatni emelt jogon — lásd lentebb.

### Megtalált és javított hibák

| Hiba | Hatás | Javítás |
|---|---|---|
| TIME_WAIT socketek PID 0-val | 57 kapcsolatból 56 „System Idle Process" alatt gyűlt, uralva a listát | Attribútálhatatlan kapcsolatot nem kezdünk követni; a már ismert gazdájú megmarad |
| SQLite `UNIQUE` + `NULL` | Minden mintavétel új process-sort írt (igazolva: 3 beszúrás = 3 sor) | `''` szentinel a „nincs hash" jelölésére |
| Elérési út nem olvasható emelt jog nélkül | 94 svchost és 40 rendszerfolyamat „PID 1792"-ként jelent meg | Szolgáltatásnév az SCM-ből, illetve process-név a folyamatlistából |
| Elárvult flow-k | Service-leállás után a futó kapcsolatok örökre „aktívak" maradtak (106 vs. 28 valós) | Induláskor lezárás, az utolsó észlelés idejére datálva |
| `InsertFlow` nem futtatta a parancsot | A flow-k egyáltalán nem íródtak ki | Hiányzó `ExecuteNonQuery()` |

---

## M3 — UI: dashboard és drill-down ✅

- [x] **App-lista:** élő sebesség, összesített forgalom, **ikon**, blokkolt-e; szabad szavas keresés
- [x] **App-nézet:** kapcsolat-tábla (távoli host, IP, port, proto, állapot, forgalom)
- [x] **Dashboard:** össz-throughput grafikon fel/le bontásban
- [x] Sötét/világos/automatikus téma, erőforrás-szótárakkal (nincs beégetett szín)
- [x] **Per-app grafikon a drill-downban** — a kiválasztott app saját throughputja
- [ ] Top appok / top hostok panel — a grafikon és a rendezhető lista már lefedi

**Done:** a fő workflow kattintható. Valódi forgalmon ellenőrizve, mindkét témában.

> A grafikon színei a dataviz-irányelv kategorikus 1–2. slotjai, **validátorral ellenőrizve**
> mindkét felületen: CVD ΔE 24.7 (világos) és 26.8 (sötét), a 8-as küszöb felett. A fel/le
> megkülönböztetése sosem csak színen múlik — a jelmagyarázat kiírja mindkettőt.

---

## M4 — Blokkolás és szabályok ✅

> **Hatókör:** csak manuális blokkolás. A tipikus munkamenet: feltűnik egy gyanús szoftver a listában → egy kattintással elveszti a hálózatot. Nincs deny-by-default, nincs engedélykérő prompt.

- [x] Alkalmazás betallózása (`.exe` picker) + szabály létrehozása
- [x] **Blokkolás egy kattintással** közvetlenül az app-listából
- [x] **Per-app blokk** kimenő/bejövő irányra külön
- [x] Szabály-perzisztencia, és egyezés *útvonalra + hash-re*
- [x] Szabálylista UI: feloldás, „executable changed" jelzés
- [x] Failsafe: a tűzfal írása előzi meg a tárolást, így sosem állítjuk tévesen blokkoltnak
- [ ] Szabályok importálása/exportálása — elhalasztva, nem blokkol semmit

**Kész:** a tűzfal-háttér (`WindowsFirewall`, INetFwPolicy2 COM), a szabálytár SHA-256 rögzítéssel,
az indulási egyeztetés és a teljes UI (Block gomb + betallózás + „Blocked apps" fül).

> **Nem ellenőrzött:** a tényleges szabályírás. Emelt jogot kér, a fejlesztői környezet nem az.
> Igazolva: a COM-réteg olvasásra működik, és jogosultság híján minden írás érthető indokkal
> utasít el. A teljes kör ellenőrzése egy paranccsal: `scripts\verify-elevated.ps1` (emelt jogon).

### Megtalált és javított hibák

| Hiba | Hatás | Javítás |
|---|---|---|
| `string.GetHashCode` a szabálynévben | A .NET futásonként randomizálja — a név minden service-indításnál más lett volna, az egyeztetés minden szabályt elárvított volna | Determinisztikus SHA-256 alapú név |
| Fájlnév megtartotta az írásmódot | `app.exe` és `App.exe` két külön szabálynevet adott ugyanarra a programra | A teljes név kisbetűsítve, nem csak a hash |

---

## M5 — TLS-láthatóság ✅

> **Hatókör (a te döntésed):** kizárólag per-process keylog. Nincs Npcap, nincs MITM proxy,
> nincs CA-telepítés a trust store-ba.

- [x] „Launch app with key logging" — a Keyhole indítja az appot, `SSLKEYLOGFILE` **csak annak
      a folyamatnak** a környezetében
- [x] Session-kezelés: minden capture külön mappa, saját keylog fájllal
- [x] Capture fül: futó és lezárt session-ök, keylog mérete, mappa megnyitása
- [x] Előzetes figyelmeztetés, ha az app Schannelt használ (nem fog kulcsot írni)
- [ ] Beépített pcap-rögzítés és TLS-dekódolás a UI-ban — Npcap kellene hozzá, kihagyva
- [ ] MITM proxy a Schannel-appokhoz — CA-telepítés kellene hozzá, kihagyva

**Done — valódi méréssel igazolva:** a Keyhole által indított Chrome **6330 byte valódi TLS-titkot**
írt a Wireshark által olvasott NSS formátumban (`CLIENT_HANDSHAKE_TRAFFIC_SECRET`…). Közben
igazolva, hogy a változó **sehol máshol** nem létezik: sem a service-ben, sem User/Machine
szinten, és egy párhuzamosan, normálisan indított folyamat sem látja.

**Használat Wiresharkkal:** a session mappájából a `sslkeys.log` megadható a
*Preferences → Protocols → TLS → (Pre)-Master-Secret log filename* mezőben. A kézi
env-var kapcsolgatás így teljesen megszűnik.

### Megtalált és javított hibák

| Hiba | Hatás | Javítás |
|---|---|---|
| Azonos másodpercben indított capture-ök | Közös mappa és közös keylog — két app titkai keverednek, egyik sem dekódolható | Ütközés esetén `-2`, `-3` utótag (igazolva: `cmd-2` … `cmd-7`) |
| A heurisztika „likely"-t mondott a System32-es `curl.exe`-re | A felhasználó hiába várt volna kulcsokra; `curl --version` szerint **Schannel** | A Windows-mappa alatti binárisok „unlikely" besorolást kapnak |
| A tesztek a valódi `ProgramData`-ba írtak | Minden futás szemetelt a gépi capture-mappába | A capture gyökér injektálható, a tesztek temp mappát használnak |

---

## M6 — Kiélesítés ✅

- [x] Tray-ikon, „bezárás a tray-be" (a monitorozás így nem tűnik el szem elől)
- [x] Automatikus indítás bejelentkezéskor (per-user Run kulcs, nem kell hozzá admin)
- [x] Settings fül: retention, tray-viselkedés, hostnév-feloldás, autostart
- [x] DB retention a beállításból, nem beégetve; 6 óránként prune
- [x] Hibatűrés: hiányzó jogosultság, elérhetetlen service, sérült settings — mind
      érthető állapotot ad, nem összeomlást
- [ ] 24h+ futás profilozása — nem futtattam le, lásd lentebb

---

## M7 — Kiadás ✅ (aláírás nélkül)

- [x] `scriptsuild-release.ps1` — önálló (self-contained) build, zip csomag
- [x] `RELEASE.md`: telepítés, eltávolítás, mihez kell admin, hol tárol adatot, korlátok
- [x] Aláírás **kihagyva** (a te döntésed) — a SmartScreen-figyelmeztetés dokumentálva;
      a szkript `-CertificatePath`-szal később bekapcsolható, a jelszó környezeti változóból
- [ ] MSI/MSIX installer — a zip + `Install Keyhole.cmd` egyelőre elég
- [ ] Automatikus frissítés — kihagyva

**Igazolva:** a `dist\Keyhole-0.1.0.zip` (118 MB) elkészült, és a **publikált** binárisok
futnak: a service felhozza a pipe-ot, a UI csatlakozik és megjeleníti az élő forgalmat —
nem `dotnet run`-ból, hanem a kiadott exe-kből.

---

## Emelt jogú ellenőrzés — lefutott ✅

`scriptserify-elevated.ps1`, 2026-10-26 14:41, **14/14 PASS**:

| Mi | Eredmény |
|---|---|
| Service elevated, monitorozás fut | ✅ 15 kapcsolat |
| **ETW byte-számlálás** | ✅ 5 app valódi forgalommal (pl. `nvcontainer.exe` up 7720 / down 772) |
| **Tűzfalszabály írása** | ✅ létrehozva, a Windows tűzfalban visszaellenőrizve (Block / Outbound / enabled) |
| SHA-256 rögzítés | ✅ `match` |
| Takarítás | ✅ a szabály a tűzfalból és a Keyhole-ból is eltűnt |

**UDP-célpontok** (ezt a szkript nem méri, az adatbázisból ellenőriztem): 31 UDP flow valódi
célponttal, köztük `Dnscache (svchost) → 8.8.8.8:53`. A javítás előtt ezek mind láthatatlanok voltak.

### Amit ez az ellenőrzés hozott elő

A zöld pipák mellett az adatbázis egy hibát árult el: **a 16 TCP flow mind nullával** szerepelt,
miközben a 31 UDP mind byte-számokkal. Ok: a byte-totálok csak *lezáráskor* íródtak ki, így
minden kapcsolat, ami nyitva volt a service leállásakor, elvesztette a forgalmát a történetből —
épp a hosszú életű, érdekes kapcsolatok. Javítva: 30 másodpercenként kiíródnak az aktív flow-k
számai (5 teszt fedi). **Élesben még nem igazolt** — a következő emelt jogú futásnál lesz látható.

### Továbbra is méretlen

**Hosszú terhelési teszt** (memória-szivárgás, WAL-növekedés napokon át). A retention és a prune
be van kötve és tesztelt, de valós hosszú futás alatt nem mértem.

---

## Mi maradt ki tudatosan

| Terület | Miért |
|---|---|
| Npcap csomagrögzítés, beépített TLS-dekódolás | a te döntésed: csak keylog, külső függőség nélkül |
| MITM proxy a Schannel-appokhoz | ugyanaz; CA-telepítés kellene a trust store-ba |
| Kódaláírás | nincs tanúsítvány; a build-szkript készen áll rá |
| MSI/MSIX installer | a zip + `Install Keyhole.cmd` egyelőre elég |
| GeoIP (ország/ASN) | nem blokkol semmit, bármikor pótolható |
| UDP távoli végpontok | a socket-tábla nem tartalmazza; ETW-ből kijönne, a felület (`GetUdpPeers`) megvan |
| Szabályok import/export | nem blokkol semmit |

---

## Utómunka (a mérföldkövek után)

| Mi | Állapot |
|---|---|
| **UDP-célpontok ETW-ből** | ✅ a UDP socketek peerenként külön flow-vá bomlanak |
| **Per-app grafikon** | ✅ a drill-downban, a kapcsolatlista fölött |
| `verify-elevated.ps1` lefuttatása | ⬜ rajtad a sor — emelt jog kell hozzá |

### Megtalált és javított hiba

| Hiba | Hatás | Javítás |
|---|---|---|
| A szűrt lista kétmásodpercenként újraépült | A kijelölés minden frissítéskor elveszett — rákattintottál egy appra, és 2 mp múlva üres lett a drill-down | Helyben szinkronizálás törlés-újratöltés helyett |

## Következő lépés

1. **`scriptserify-elevated.ps1`** emelt jogon — ez zárja le a két nyitott ellenőrzést,
   és egyúttal ez az első alkalom, hogy a UDP-célpontok valódi forgalmon látszanak
   (ETW nélkül nincs peer, így a UDP most is láthatatlan marad).
2. **GeoIP** — ország/ASN a távoli végpontokhoz, ha érdekel.
3. **Top hostok panel** — melyik *célpont* kapja a legtöbb forgalmat, appoktól függetlenül.
