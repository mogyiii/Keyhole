# Keyhole — Milestone terv

> Hálózati forgalom-elemző és -szabályozó .NET alkalmazás Windowsra.
> Cél: a GlassWire átláthatósága + a Wireshark mélysége, kézi env-var kapcsolgatás nélkül.

**Állapot:** M2 kész ✅ — következik M3 (UI) vagy M4 (blokkolás)
**Utolsó frissítés:** 2026-10-25

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
| ETW `Microsoft-Windows-Kernel-Network` spike | PID→kapcsolat eventek olvashatók-e stabilan, mekkora a drop rate |
| WFP vs. `INetFwPolicy2` spike blokkoláshoz | melyik tud per-exe denyt, túlélik-e a szabályok az újraindítást |
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
- [ ] CI: build + unit tesztek (nincs még repo/remote — az M2 elején)

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
- [ ] **Ikon-kinyerés** az `.exe`-kből — az M3 UI-hoz tartozik, ott logikusabb
- [ ] **GeoIP** (opcionális, offline MMDB) — elhalasztva, nem blokkol semmit
- [ ] **Élő sebesség** (byte/s) — byte-számok kellenek hozzá, M3-ban a grafikonnal együtt

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

## M3 — UI: dashboard és drill-down

- [ ] **App-lista:** élő sebesség, összesített forgalom, ikon, blokkolt-e; keresés/rendezés
- [ ] **App-nézet:** kapcsolat-tábla (távoli host, IP, port, proto, állapot, be/ki byte), időbeli grafikon
- [ ] **Dashboard:** össz-throughput grafikon, top appok, top hostok, friss események
- [ ] **Új app jelzése** passzívan a listában (badge/kiemelés, nem felugró prompt)
- [ ] Sötét/világos téma, DPI-helyes, virtualizált listák (ne akadjon 1000 sornál)

**Done, ha:** a fő workflow (gép figyelése → gyanús app kiszúrása → kapcsolatai megnézése) kattintható és gyors.

---

## M4 — Blokkolás és szabályok

> **Hatókör:** csak manuális blokkolás. A tipikus munkamenet: feltűnik egy gyanús szoftver a listában → egy kattintással elveszti a hálózatot. Nincs deny-by-default, nincs engedélykérő prompt.

- [ ] Alkalmazás betallózása (`.exe` picker) + szabály létrehozása
- [ ] **Blokkolás egy kattintással** közvetlenül az app-listából (a monitorozott appra, külön tallózás nélkül)
- [ ] **Per-app blokk** kimenő/bejövő irányra külön
- [ ] Szabály-perzisztencia, és egyezés *útvonalra + hash-re* (ne lehessen átnevezéssel kijátszani)
- [ ] Szabálylista UI: engedélyezés/tiltás, törlés, importálás/exportálás
- [ ] Failsafe: ha a service meghal, maradjon konzisztens állapot (ne zárjuk ki a gépet a netről)

**Done, ha:** egy betallózott app azonnal elveszti a netet, az újraindítás után is, és a blokk feloldása után újra működik — és ez tesztelve van store-appra is.

---

## M5 — Capture és TLS-láthatóság 🎯 a `plan.txt` fő fájdalompontja

Két út, **nem** egymás alternatívái — egymást kiegészítik:

### 5a. Per-process keylog (elsődleges út)

A mostani kényelmetlenség gyökere, hogy a `SSLKEYLOGFILE` **globálisan** van beállítva. Megoldás: a Keyhole indítsa a célalkalmazást, és csak annak a processznek injektálja az env vart (`CreateProcess` saját environment blokkal).

- [ ] "Launch with capture" funkció: app kiválasztása → Keyhole indítja, saját `SSLKEYLOGFILE`-lal egy session-mappába
- [ ] Session-kezelés: minden capture külön keylog + pcap fájlpár
- [ ] Npcap/SharpPcap capture a session idejére, PID-re szűkítve
- [ ] Dekódolás: keylog + pcap → TLS-visszafejtés, HTTP(S) kérések/válaszok listája az UI-ban
- [ ] "Open in Wireshark" gomb, ami átadja a pcap-ot és a keylogot is (a kézi beállítás teljesen eltűnik)

> **Előny:** nincs cert-telepítés, nincs cert-pinning probléma, nem módosul a forgalom, globális env var nem kell.
> **Korlát:** csak NSS/OpenSSL-alapú stackeknél működik (Chrome/Firefox/Electron/Node/curl) — Schannel-t használó .NET és natív Windows-appoknál nem.

### 5b. MITM proxy (másodlagos út, a Schannel-appokra)

- [ ] Beépített HTTP(S) proxy, saját CA-val (gépi trust store-ba telepítve, explicit user-engedéllyel)
- [ ] Szelektív átirányítás: **ne** rendszer-szintű proxy legyen, hanem per-app (proxy env var / WFP redirect csak a kiválasztott PID-re)
- [ ] Kérés/válasz böngésző UI-ban (header, body, timing)
- [ ] Cert-pinninget használó appoknál felismerés + érthető hibaüzenet ("ez az app pinninget használ, használd az 5a utat")
- [ ] CA-kulcs biztonságos tárolása (DPAPI) + egy kattintásos CA-eltávolítás

> **Döntés M0-ban:** saját proxy implementáció vs. külső (mitmproxy wrap). Lásd *Nyitott döntések*.

**Done, ha:** egy böngésző és egy .NET desktop app HTTPS-forgalma is olvashatóvá tehető az UI-ból, nulla kézi env-var vagy cert-művelet nélkül.

---

## M6 — Kiélesítés

- [ ] Teljesítmény-profilozás: memória-plafon, hosszú futás (24h+) leak-mentesen
- [ ] DB retention + tömörítés (ne nőjön a SQLite végtelenre)
- [ ] Hibatűrés: Npcap hiányzik, ETW session elveszett, service-összeomlás → érthető UI-állapot
- [ ] Automatikus indítás bejelentkezéskor, tray-ikon, "minimalizálás trayre"
- [ ] Beállítások: retention, értesítések, GeoIP ki/be, capture-mappa

---

## M7 — Kiadás

- [ ] Installer (MSIX vagy WiX), kódaláírás
- [ ] Onboarding: mire kell admin, mit telepítünk (Npcap, CA), mi hol tárolódik
- [ ] README + rövid használati doc, képernyőképek
- [ ] Auto-update vagy legalább verzióellenőrzés

---

## Nyitott döntések (M0-ban lezárni)

| # | Kérdés | Opciók | Döntés / hajlás |
|---|---|---|---|
| ~~D1~~ | UI keretrendszer | WinUI 3 / Avalonia / WPF + WPF-UI | ✅ **Avalonia 12** — lezárva 2026-10-25 |
| D2 | Flow-adat forrása | ETW / periodikus socket-poll / WinDivert | ETW + poll kiegészítésként; WinDivert csak ha kell |
| D3 | Blokkolás módja | `INetFwPolicy2` (Windows Firewall) / saját WFP filterek | Firewall API-val indulni (egyszerű, perzisztens), WFP-re váltani ha nem elég granuláris |
| D4 | Packet capture | Npcap+SharpPcap / WinDivert / ETW pktmon | Npcap, de a külső dependency kezelését meg kell oldani |
| D5 | **TLS-stratégia** | per-process keylog / MITM proxy / mindkettő | **Mindkettő**, keylog az elsődleges — ez szünteti meg a `plan.txt`-ben leírt kényelmetlenséget |
| D6 | MITM implementáció | saját (Kestrel-alapú) / mitmproxy wrap / Fiddler Core | M0 spike döntse el; Titanium Web Proxy már nem maintained |

---

## Kockázatok

- **Antivírus/EDR false positive** — a forgalom-elfogás és env-var injektálás gyanús minta. Mitigáció: kódaláírás, dokumentált viselkedés.
- **Avalonia natív integráció** — a tray-ikon, az `.exe`-ikon kinyerése és a fájl-picker Windows-specifikus; Avalonián ezekhez saját P/Invoke kell (`Keyhole.Native`), nem kapjuk ingyen mint WinUI-on.
- **Cert pinning** — a MITM út eleve nem fog működni appok egy részénél; ezt nem bugként, hanem korlátként kell kommunikálni az UI-ban.
- **Npcap licenc** — kereskedelmi terjesztésnél licencdíjas; ha ez cél, M0-ban tisztázni.
- **Admin-jogosultság** — elkerülhetetlen; a service-modell a kockázat minimalizálása.
- **ETW event-drop nagy forgalomnál** — pufferméret-tuning és számláló-alapú korrekció kell.

---

## Nyitott ellenőrzés: ETW emelt jogon

A byte-számlálás valódi működése még nincs igazolva. Emelt jogú PowerShellben:

```powershell
dotnet run --project src\Keyhole.Service
```

Amit látni kell: a `Byte counting needs administrator rights` figyelmeztetés **nem** jelenik meg,
helyette `ETW byte counting started`. A UI-ban a Traffic oszlop `—` helyett valódi értékeket mutat,
és a sárga figyelmeztető sáv eltűnik.

Ha hibázik, a `%ProgramData%\Keyhole\logs` naplóban lesz az ok.

## Következő lépés

**M3 (UI)** vagy **M4 (blokkolás)** — a sorrend szabadon választható, a kettő független.
M4 adja a `plan.txt` másik fő kívánságát (gyanús szoftver letiltása), M3 teszi használhatóvá
a meglévő adatot (grafikonok, keresés, ikonok).
