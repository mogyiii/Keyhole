# Keyhole — Milestone terv

> Hálózati forgalom-elemző és -szabályozó .NET alkalmazás Windowsra.
> Cél: a GlassWire átláthatósága + a Wireshark mélysége, kézi env-var kapcsolgatás nélkül.

**Állapot:** M1–M7 kész ✅ — telepítve, élesben ellenőrizve. Következik: M8.
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
| Npcap jelenlét/telepítés kezelése | ⏭ **M8-ba halasztva** — az M5 nem igényelte |
| ~~TLS-stratégia (keylog vs. MITM)~~ | ✅ **keylog** (D5) — mérve: Chrome 6330 byte kulcsot írt, a Schannel-appok semmit |

**Done:** minden döntés lezárva, mindegyik működő kóddal vagy méréssel alátámasztva.

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

> Az ETW byte-számlálás azóta **élesben is igazolt** — lásd az *Élesben ellenőrizve* szakaszt.

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

> **Hatókör:** kizárólag per-process keylog — ez szünteti meg a `plan.txt`-ben leírt
> kényelmetlenséget. A csomagrögzítés **M8-ba** került; a MITM proxy továbbra is kimarad
> (CA-telepítést kérne a trust store-ba).

- [x] „Launch app with key logging" — a Keyhole indítja az appot, `SSLKEYLOGFILE` **csak annak
      a folyamatnak** a környezetében
- [x] Session-kezelés: minden capture külön mappa, saját keylog fájllal
- [x] Capture fül: futó és lezárt session-ök, keylog mérete, mappa megnyitása
- [x] Előzetes figyelmeztetés, ha az app Schannelt használ (nem fog kulcsot írni)
- [ ] Beépített pcap-rögzítés és TLS-dekódolás a UI-ban — **átkerült M8-ba**
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

## M8 — Npcap csomagrögzítés és beépített TLS-dekódolás

> **Miért most:** az M5 megszüntette a kézi env-var kapcsolgatást, de a kört még mindig a
> Wireshark zárja be. Ezzel a Keyhole maga rögzíti a forgalmat, és a saját keylogjával
> azonnal vissza is fejti — egy helyen, külön eszköz nélkül.

### Amit hoz

A capture-session ma csak TLS-kulcsokat gyűjt. Ezzel mellé kerül a **pcap** is, és mivel a
Keyhole mindkettőt birtokolja, a dekódolást el tudja végezni helyben: a UI-ban látszana,
hogy a kiválasztott alkalmazás **mit** kért és mit kapott, nem csak kivel beszélt.

### Feladatok

- [ ] **Npcap-függőség kezelése** — jelenlét-ellenőrzés, érthető onboarding, ha hiányzik
      (`npcap.sys` / `npcap` service), nem néma hiba
- [ ] **SharpPcap/PacketDotNet** bekötés, adapter-választás
- [ ] **Rögzítés a session idejére**, a célfolyamat forgalmára szűkítve
- [ ] **pcapng írás** a session mappájába a keylog mellé
- [ ] **TLS-dekódolás** a session keylogjával: TCP-összefűzés → TLS-rekordok → HTTP(S)
- [ ] **Kérés/válasz nézet** a Capture fülön: metódus, URL, státusz, fejlécek, méret, idő
- [ ] **„Open in Wireshark"** gomb, ami a pcap-ot és a keylogot együtt adja át

### Amit előre tisztázni kell

| Kérdés | Miért számít |
|---|---|
| **Npcap licenc** | Saját használatra más feltételek vonatkoznak, mint a továbbterjesztésre. Ha a Keyhole valaha kikerül a gépedről, az **aktuális** Npcap-licencet előbb el kell olvasni — ne ebből a táblázatból dolgozz. |
| **Telepítés módja** | Néma telepítés a saját installerünkből, vagy „Npcap szükséges" üzenet és link? Az előbbi kényelmesebb, de harmadik fél driverét rakja fel a felhasználó gépére. |
| **Rögzítés hatóköre** | Csak a capture-session alatt, csak a célfolyamat forgalmára. Teljes interfész-rögzítés minden app forgalmát lemezre írná — ez adatvédelmi kérdés, nem csak helykérdés. |
| **Lemezigény** | Egy böngésző-session percek alatt több száz MB pcap. Kell felső korlát és rotáció. |

### Hatókörön kívül

A **MITM proxy** továbbra is kimarad, és ezzel a Schannelt használó alkalmazások sem
kerülnek közelebb: azok nem írnak keylogot, így a pcap **velük is csak titkosított
bájtokat** fog tartalmazni. Rájuk továbbra is csak a proxy-út működne — ahhoz viszont
saját CA-t kellene a gépi trust store-ba telepíteni.

**Done, ha:** egy böngésző-session után a Capture fülön látszanak a kérések és válaszok,
a session mappájában pedig ott a pcap és a keylog, amit a Wireshark is megnyit.

> ⚠️ A pcap a session teljes forgalmát tartalmazza, a keyloggal együtt visszafejthető
> formában. A `captures/` mappa ettől még érzékenyebb lesz, mint ma.

---

## Élesben ellenőrizve ✅

A service telepítve (`Program Files\Keyhole`, LocalSystem, automatikus indítás), és valódi
forgalmon mérve. Minden képesség igazolva:

| Mi | Bizonyíték |
|---|---|
| Elevation | `isElevated: true`, egyetlen figyelmeztetés sem a UI-ban |
| **ETW byte-számlálás** | TCP up 42,1 MB / down 22,2 MB, UDP up 1,3 MB / down 31,3 MB |
| **Tűzfal-blokkolás** | szabály létrehozva, a Windows tűzfalban visszaellenőrizve, majd eltakarítva |
| **UDP/QUIC célpontok** | 653 UDP flow valódi célponttal |
| **Byte-totálok perzisztálása** | nyitott flow-k számai is kiíródnak (30 mp-enként + leálláskor) |

### Amit az éles futtatás hozott elő

| Hiba | Hogyan derült ki | Javítás |
|---|---|---|
| **A TCP letöltés mindig 0 volt** | 16,4 MB küldés, 0 fogadás 37 flow-n. Az eseményszámlálók mutatták, hogy 11 267 fogadás-esemény **megérkezett** — a kernel viszont fordított sorrendben címkézi a végpontokat fogadásnál, így más kulcs alá került | Kanonikus (rendezett) végpont-pár kulcs |
| Nyitott flow-k byte-számai elvesztek | 16 TCP flow nullával, 31 UDP számokkal | 30 mp-enkénti + leállításkori kiírás |
| **Az IPC-tesztek a telepített service-t mérték** | A saját szerverük nem tudta megnyitni a foglalt pipe-ot, a kliens a valódihoz csatlakozott — átmentek, miközben a tesztelendő kódból semmit nem futtattak | Tesztenként egyedi pipe-név |
| A `verify-elevated.ps1` futó service-t várt | Az első futtatás semmit nem csinált | A szkript maga indítja, és csak azt állítja le, amit ő indított |
| Egy gondolatjel megtörte a PowerShell-szkriptet | PS 5.1 BOM nélkül CP1252-ként olvas; az UTF-8 `—` okos idézőjelre fordul, amit string-lezárónak vesz | A szkriptek csak ASCII-t tartalmaznak |

### Ismert korlát

Loopback-kapcsolatoknál (`127.0.0.1` mindkét végen) a fel- és letöltés megegyezik: a két
oldal ugyanarra a kulcsra esik. A PID-et nem tettem a kulcsba, mert a kernel a TCP
fogadás-eseményeket gyakran a megszakításkor futó folyamathoz rendeli, nem a socket
gazdájához — ez elronthatná a most bizonyítottan működő javítást. Valódi hálózati forgalmat
nem érint.

### Továbbra is méretlen

**Hosszú terhelési teszt** (memória-szivárgás, WAL-növekedés napokon át). A retention és a
prune be van kötve és tesztelt, de valós hosszú futás alatt nem mértem.

---

## Mi maradt ki tudatosan

| Terület | Miért |
|---|---|
| MITM proxy a Schannel-appokhoz | ugyanaz; CA-telepítés kellene a trust store-ba |
| Kódaláírás | nincs tanúsítvány; a build-szkript készen áll rá |
| MSI/MSIX installer | a zip + `Install Keyhole.cmd` egyelőre elég |
| GeoIP (ország/ASN) | nem blokkol semmit, bármikor pótolható |
| Szabályok import/export | nem blokkol semmit |

---

## Utómunka (a mérföldkövek után)

| Mi | Állapot |
|---|---|
| **UDP-célpontok ETW-ből** | ✅ a UDP socketek peerenként külön flow-vá bomlanak |
| **Per-app grafikon** | ✅ a drill-downban, a kapcsolatlista fölött |
| `verify-elevated.ps1` lefuttatása | ✅ 14/14 PASS |

### Megtalált és javított hiba

| Hiba | Hatás | Javítás |
|---|---|---|
| A szűrt lista kétmásodpercenként újraépült | A kijelölés minden frissítéskor elveszett — rákattintottál egy appra, és 2 mp múlva üres lett a drill-down | Helyben szinkronizálás törlés-újratöltés helyett |

## Következő lépés

M1–M7 kész és élesben ellenőrizve. A következő:

1. **M8 — Npcap csomagrögzítés és TLS-dekódolás.** Az Npcap licenc- és telepítés-kérdését
   érdemes előbb eldönteni, mert az befolyásolja a többit.
2. **Top hostok panel** — melyik *célpont* kapja a legtöbb forgalmat, appoktól függetlenül.
3. **GeoIP** — ország/ASN a távoli végpontokhoz (offline MMDB, nincs hálózati hívás).
4. **Hosszú terhelési teszt** — az egyetlen méretlen terület.
