# Keyhole — Milestone terv

> Hálózati forgalom-elemző és -szabályozó .NET alkalmazás Windowsra.
> Cél: a GlassWire átláthatósága + a Wireshark mélysége, kézi env-var kapcsolgatás nélkül.

**Állapot:** M1–M8 kész ✅ — telepítve, élesben ellenőrizve. Minden visszafejthető TLS
kapcsolat visszafejtve valódi böngésző-forgalmon (15-ből 14; a 15. Schannel, elvileg sem
fejthető).
**Utolsó frissítés:** 2026-11-01

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
| ~~Npcap jelenlét/telepítés kezelése~~ | ✅ **felismerés + letöltés-felajánlás** (M8) — nem terjesztjük, a licenc tiltja |
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
- [x] Beépített pcap-rögzítés és TLS-dekódolás a UI-ban — **M8-ban kész**
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

## M8 — Npcap csomagrögzítés és beépített TLS-dekódolás ✅

> **Miért most:** az M5 megszüntette a kézi env-var kapcsolgatást, de a kört még mindig a
> Wireshark zárta be. Ezzel a Keyhole maga rögzíti a forgalmat, és a saját keylogjával
> azonnal vissza is fejti — egy helyen, külön eszköz nélkül.

### Feladatok

- [x] **Npcap-függőség kezelése** — `NpcapProbe`: a driver-service állapota (SCM-ből,
      P/Invoke-kal), a `wpcap.dll` helye, a registry verzió és az „csak adminok"
      beállítás. Négy állapot, mert négy különböző tanács tartozik hozzájuk:
      `Ready` / `Missing` / `Stopped` / `Unusable`. Mindig van mondata a UI-nak.
- [x] **SharpPcap/PacketDotNet** bekötés — minden adapter megnyitva, nem heurisztikával
      kiválasztva egy; a hibázó adaptereket egyenként átlépi
- [x] **Rögzítés a session idejére**, a célfolyamat forgalmára szűkítve
- [x] **pcapng írás** a session mappájába — saját író, mert a **Decryption Secrets Block**
      miatt kellett (lásd lentebb)
- [x] **TLS-dekódolás** a session keylogjával: TCP-összefűzés → TLS-rekordok → HTTP(S).
      TLS 1.3 és 1.2, AES-GCM / ChaCha20-Poly1305 / AES-CCM
- [x] **Kérés/válasz nézet** a Capture fülön: idő, metódus, státusz, URL, típus, méret,
      időtartam, protokoll; a fejlécek tooltipben
- [x] **„Open in Wireshark"** gomb — **egy fájlt** ad át, nem kettőt: a pcapng maga
      tartalmazza a kulcsokat

### Amit eldöntöttünk

| Kérdés | Döntés |
|---|---|
| **Npcap licenc** | Az ingyenes licenc tiltja az újraterjesztést és a csomagolást (OEM-engedély kell hozzá), és 5 rendszerre korlátoz, ha nem csak Nmap/Wireshark/Defender mellett használják. **Ezért a Keyhole nem terjeszti.** Az aktuális feltételeket az `npcap.com`-on kell olvasni, nem innen. |
| **Telepítés módja** | **Felismerés + letöltés-felajánlás.** A „Get Npcap…" a gyártó telepítőjét hozza le, **Authenticode-aláírást ellenőriz** (érvényes *és* az Nmap Project aláírása — a kettő külön kérdés), és csak utána indítja, normál UAC-prompttal. Ami nem megy át, az törlődik, nem fut le. |
| **Rögzítés hatóköre** | Csak a session alatt, csak a célfolyamat (és leszármazottai) forgalma. Per csomag döntés, nem BPF-szűrő: a szűrő futás közben nem írható át, a böngésző pedig folyamatosan nyit kapcsolatokat gyerekfolyamatokban. |
| **Lemezigény** | **512 MB / session**, a Settings fülön állítható. A plafonnál a rögzítés leáll és kiírja; a session és a kulcsgyűjtés megy tovább. Nincs ring buffer: egy hosszú session elejének eldobása rosszabb, mint a végének. |

### Amit az éles futtatások kikényszerítettek: visszamenős puffer

A hatókör-szűrésnek van egy beépített versenye, amit három éles futtatás hozott elő
fokozatosan. Egy kapcsolat első csomagjai **előbb érkeznek, mint ahogy a hatókör tudhatná
a portját** — a socket-táblát nem lehet csomagonként végigjárni —, és TLS esetén épp
azokban van a ClientHello, ami a kulcshoz köti a kapcsolatot.

Két megoldás volt. A **frissítés sűrítése** egyszerűbb, de továbbra is időzítésen múlik:
a böngésző indulási burstje alatt sűrűbben nyílnak kapcsolatok, mint ahogy a frissítés
futhat. A **visszamenős puffer** nem versenyez: a nem illeszkedő csomag nem eldobásra
megy, hanem várakozik, és ha a portja hatókörbe kerül, visszamenőleg bekerül a felvételbe.

Egy szűkítés kellett hozzá, hogy ne legyen rosszabb, mint amit megold: **csak
kapcsolat-nyitásokat** puffereli, és csak olyanokat, amikre SYN-t látott. Egy általános,
2 másodperces gyűrűpuffer minden app forgalmának a közepét tartaná memóriában — egy olyan
folyamatban, ami TLS-kulcsokat ír lemezre. Így viszont néhány ezer kapcsolat eleje,
8 MB plafonnal.

Egy következmény: a visszamenőleg kiírt csomagok a fájlban **később** állnak, mint a
náluk frissebbek, tehát a felvétel időbélyegei nem szigorúan növekvőek. Ez szándékos és
ártalmatlan — a TCP-folyamok sorszám szerint állnak össze, nem beérkezés szerint, a
Keyhole dekóderében és a Wiresharkban is. A sorrend megőrzése az egész rögzítés
késleltetését jelentené egy kozmetikai problémáért.

### A nem várt tervezési döntés: saját pcapng-író

A capture-könyvtárak csak klasszikus pcap-ot írnak, abban pedig nincs hova tenni a
kulcsokat. A pcapng-ben **van**: a *Decryption Secrets Block*. Ezért lett saját író —
és ezzel a felvétel **önmagában olvasható**: a Wireshark beállítás nélkül, azonnal
visszafejtve nyitja meg. Nincs keylog-útvonalat beírni egy preferences-dialógusba, és
nem tud elcsúszni egymástól a két fél.

A titkok a session **végén** kerülnek be, a csomagok **elé** — mert egy olvasó menet
közben alkalmazza őket, így a fájl végén már késő. Az átírás egy soros másolás, és csak
akkor cseréli le az eredetit, ha végig sikerült.

### Hatókörön kívül

- A **MITM proxy** továbbra is kimarad, és ezzel a Schannelt használó alkalmazások sem
  kerülnek közelebb: nem írnak keylogot, így a pcap **velük is csak titkosított bájtokat**
  tartalmaz. A UI ezt külön írja ki attól, amikor a dekódolás hibázott.
- **QUIC / HTTP3 nincs dekódolva.** Rögzítve van, de a QUIC saját csomagvédelmet használ,
  ez nem a TLS-rekordok kérdése. A Chrome viszont előnyben részesíti, ahol kínálják —
  ezért a UI **kiírja, mennyi QUIC került a felvételbe**, hogy egy üresebb kéréslista
  magyarázatot kapjon, és ne hibának tűnjön.

> ⚠️ **A `captures/` mappa ettől érzékenyebb lett, mint volt.** Korábban kulcsok voltak
> benne, forgalom nélkül. Most a `capture.pcapng` mindkettőt tartalmazza, egy fájlban —
> aki ezt megkapja, mindent elolvas, amit az app küldött és kapott.

### Hogyan van igazolva

A kulcs-levezetést nem lehet körbe-teszteléssel igazolni: ugyanaz a kód titkosít és fejt
vissza, tehát egy önmagában következetes **félreértés** minden saját tesztet átenged. Ezért
a döntő ellenőrzés a **Wireshark** — független implementáció, ugyanazt a fájlt és ugyanazt
a beágyazott keylogot olvassa.

| Mi | Bizonyíték |
|---|---|
| **pcapng formátum** | `capinfos` és `tshark` beolvassa a Keyhole írta fájlt, és a TCP-fejléceket helyesen bontja (helyes link type és időbélyeg nélkül nem tudná) |
| **TLS 1.3 kulcs-levezetés** | a `tshark` **ugyanabból a fájlból** visszafejti a titkosított handshake-et *és* a HTTP-t, csak a beágyazott DSB-ből — tehát a HKDF-Expand-Label, a nonce (IV XOR seq) és az AAD mind egyezik az RFC 8446-tal |
| **Negatív kontroll** | titkok nélkül ugyanazt a fájlt a `tshark` sem fejti vissza — tehát az előző sor nem valami más olvasásából jött |
| **HPACK Huffman** | a Kraft-egyenlőség pontosan teljesül, az RFC 7541 **12 teszt-vektora** átmegy, és mind a 256 bájtérték körbejár |
| **HPACK állapotgép** | az RFC 7541 **C.3, C.4, C.5, C.6** teljes kérés- és válaszfolyamai, a 256 bájtos táblakorláttal és a kiürítésekkel együtt |
| **HTTP/2** | a `tshark` ugyanabból a felvételből ugyanazt a metódust, útvonalat és státuszt olvassa — ami a HPACK-ot is független úton ellenőrzi, mert saját dinamikus táblát épít |
| **Hatókör-szűrés** | szkriptelt csomagokkal: 4 csomagból 2 kerül be, és a kidobott többség a bizonyíték, hogy a szűrés egyáltalán megtörtént |

**270 teszt, mind zöld.** Az M8 tesztjei a Wireshark-ellenőrzéseket is beleértve zöldek;
a 86-ról 270-re nőtt szám nagyrészt a HPACK és a TLS teszt-vektorai.

### Élesben ellenőrizve (2026-11-01)

`verify-elevated.ps1` emelt jogon, telepített service-szel, friss Chrome-profillal. Négy
futtatás, mindegyik egy hibát hozott elő és a következő mérte a javítást.

| Mi | 1. | 2. | 3. | **4.** |
|---|---|---|---|---|
| Npcap | `ready`, 1.78 | ugyanaz | ugyanaz | ugyanaz |
| TLS-kulcsok | 12 752 B | 12 524 B | 12 524 B | 12 524 B |
| Csomagok | 40,1 MB | 41,3 MB | 41,1 MB | 41,1 MB |
| **Visszafejtve** | **5-ből 1** | **16-ból 10** | **14-ből 9** | **15-ből 14** |
| Elszámolva | 5-ből 2 | 16-ból 12 | 14-ből 14 | 15-ből 15 |
| „handshake nélkül" | — | 4 | 4 | **0** |
| „kulcs nem használható" | — | — | 1 | **0** |
| **Kérés** | **1** | **20** | **22** | **28** |
| A betöltött oldal (`example.com`) | — | — | megjelenik | megjelenik |
| `tshark` ugyanazon a fájlon | 1 | 23 | 29 | 30 |

**A negyedik futtatás zárja le M8-at.** A maradék egyetlen visszafejtetlen kapcsolat
helyesen „nincs kulcs" — Windows-komponens Schannellel, ami elvileg sem fejthető vissza.
Vagyis minden visszafejthető kapcsolat visszafejtve. A 28 kérés a `tshark` 30-ához képest
kis eltérés, és nem keresem tovább ok nélkül: a `tshark` keretekre szűr (`http.request`),
ami nem ugyanaz a számolási konvenció, mint a kérés–válasz párosítás.

A harmadik futtatás volt az első, ahol **a számok összeadtak**: 9 visszafejtve + 4 handshake
nélkül + 1 hibázott = 14. Innen derült ki a maradék két dolog:

- **A „4 handshake nélkül" magyarázatát tévesen fogalmaztam.** „Már nyitva volt, amikor a
  rögzítés indult" — de a rögzítés a Chrome *indítása előtt* kezdődik, szóval ez a Chrome
  saját kapcsolatainál valószínűtlen. A valószínűbb ok, hogy a SYN megjött, de a
  kényszerített frissítés 50 ms-os korlátja egy indulási burst alatt kihagyta. Az
  összegzés most **azt mondja meg, mi hiányzik, nem azt, hogy miért** — mindkét ok
  lehetséges, és egyiket kimondva a rossz helyre küldi az olvasót.
- **Az „1 hibázott" valódi hiba volt, és megvan:** TLS 1.3 **kulcs-frissítés**. Bármelyik
  fél rotálhatja a traffic secretjét menet közben, a keylogban viszont csak a `_0` van.
  A KeyUpdate üzenet maga is a régi kulccsal titkosított, szóval semmi nem jelzi — a
  származtatást meg kell próbálni, és az AEAD tag dönt. 41 MB forgalomnál ez bekövetkezik.
  Javítva: a dekóder legfeljebb 64 frissítést követ, a sorszám nullára áll.
  A kódommentem egyébként előre kimondta („*a key update Keyhole does not follow*") —
  csak nem gondoltam, hogy egy 20 másodperces futás eléri.

**A diagnózis, ami idevezetett:** a `tshark` egyetértése volt a döntő jelzés. Ha ő is csak
egy kérést lát ugyanabban a fájlban, akkor a dekóder jól dolgozik, és a baj **a
rögzítésben** van — ez terelte a vizsgálatot a hatókör-frissítésre a dekódoló helyett.

**Amit tévesen állítottam:** a 40 MB-ot először túl-rögzítésnek tulajdonítottam, és ezen
az alapon szűkítettem az exe-név szabályt. A második futtatás ezt megcáfolta: a méret
változatlan (41 MB), és a dekódolt kérések megmagyarázzák, miért — `update.googleapis.com`,
CRX-blobok, `redirector.gvt1.com/edgedl/diffgen-puffin`. A szkript **friss profillal**
indítja a Chrome-ot, ami minden futásnál újra lehúzza a teljes komponens-készletét. Ez a
Chrome **saját** forgalma. Az ETW-lista is ezt támasztja: egyik futásnál sem futott már
egy Chrome, tehát a szélesítésnek nem volt mit bevennie.

A szűkítés attól még helyes — a kockázat valós, ha tényleg nyitva van egy példány —, de
**nem a 41 MB-ról szól**, és nem lett volna szabad okként kimondani mérés nélkül.

### Megtalált és javított hibák

| Hiba | Hogyan derült ki | Javítás |
|---|---|---|
| **A HPACK Huffman-tábla egy hossza téves volt** | A Kraft-egyenlőség 2<sup>-28</sup>-cal nem jött ki. A 246-os szimbólum 27 bitet kapott 26 helyett — egyetlen szám egy 257 elemű táblában, amit semmilyen ASCII teszt-vektor nem érintett volna | A tábla csak **kódhosszakat** tárol, a kódokat kanonikusan számolja, és a teljességet **tesztben ellenőrzi** — így a hiba aritmetikailag kiderül, nem a felhasználónál |
| **A Huffman-akkumulátor 32 bites volt** | A hosszú bájtsorozat körbejárása elcsúszott. A leghosszabb kód 30 bites, így 29 bit maradhat, plusz a következő bájt = 37 — a 32 bites akkumulátor pont a leghosszabb (ritka, magas bájtértékű) kódok felső bitjeit dobta el | 64 bites akkumulátor |
| **A pcapng-olvasó felfalta a következő blokk típusát** | A dekóder nulla TLS-rekordot talált egy olyan felvételben, amit a `tshark` hibátlanul bontott. A `ReadAtLeast` a *puffer* méretéig olvas, nem a minimumig — a 4 bájtos záró hosszhoz 8 bájtos puffert adtam | Saját 4 bájtos puffer a záró hossznak |
| **A szerver SYN-ACK-ja elvette a kliens szerepét** | A komment azt mondta „SYN ACK nélkül", a kód viszont nem nézte az ACK flaget — így a második SYN átírta, melyik oldal a kliens, és a két irány kulcsa felcserélődött | `TransportSegment.IsAck` + `IsConnectionOpener` |
| **Azonnal kilépő folyamat elhasalt a capture-indításon** | `InvalidOperationException: No process is associated with this object`. A `process.Id`-t az exit-kezelő bekötése *után* olvastam, az pedig addigra eldobta a `Process`-t | A PID egyszer, a `Process.Start` után; plusz `HasExited`-ellenőrzés arra, ha az esemény már nem jön |
| **A „miért nincs rögzítés" magyarázat eltűnt a session végén** | Két teszt átment egyedül és elhasalt a teljes futásban. A `GetRecordingIssue` csak a futó rögzítésből olvasott — pedig a UI befejezett session-nél is mutatja a megjegyzést | Az ok session-önként megjegyezve, a rögzítést túlélve |
| **A dekódolt válasz átléphette az IPC 4 MB-os keretét** | Kódolvasás: egy böngésző-session több ezer kérést ad, fejlécekkel. A keretező réteg ezt kivétellel utasítja el, amit a felhasználó protokollhibaként látna | Max 1000 kérés, 64 fejléc/irány, 512 bájt/érték — a vágás kiírva az összegzésben |
| **A teszt-segéd holtpontra futott a `tshark`-kal** | A második teljes tesztfutás beragadt: a `testhost` élt, de nem haladt. A segéd a teljes stdout-ot olvasta, *aztán* a stderr-t — ha közben betelik a nem olvasott pipe, a gyerek blokkol, és egyik sem fejeződik be. A `tshark` beszédes a stderr-en | Mindkét stream egyszerre, `ReadToEndAsync`-kal; plusz időkorlát és `Kill`, ha mégis beragad |
| **Az első éles futtatás: elveszett a ClientHello** | 5 TLS kapcsolatból 1 fejtődött vissza, pedig a kulcsok megvoltak — 40 MB felvételből pont az a néhány bájt hiányzott, ami számít. A port-készlet másodpercenként frissült; a két frissítés között nyíló kapcsolat első csomagjai kimaradtak, azok közt a ClientHello. **Enélkül az egész kapcsolat visszafejthetetlen** — a kódban álló komment („néhány csomagba kerül") alábecslés volt | TCP SYN-re azonnali hatókör-frissítés (legfeljebb 50 ms-onként), aztán újraértékelés. A socket a SYN kiküldésekor már benne van az OS táblájában, így a handshake még megérkezése előtt hatókörbe kerül |
| **A hatókör bevette a már futó böngészőt is** | Nem mérésből, hanem a kód olvasásából: az azonos exe-nevű folyamatokat is bevettem — ez a szándékos szélesítés a gyerekek újra-szülőzése miatt volt, de így a felhasználó már nyitott böngészőjének egész session-je bekerülne a kulcsokat is tartalmazó fájlba | Az exe-név szabály a capture után **indult** folyamatokra szűkítve. Itt a kétség *kifelé* dönt, a fa-szabállyal ellentétben: ott a lyuk a cél forgalmából vesz el, itt a túl-bevétel egy kívülálló adatait viszi be |
| **A CONNECT kérés URL-je duplikálódott** | A második éles futtatás kiírta: `https://www.google.com:443www.google.com:443`. A HTTP/1.1-nek négy alakja van a kérés-célra, és csak az egyik útvonal; a CONNECT célja maga az authority, amihez a `Host`-ot hozzáfűzni értelmetlen | Mind a négy alak külön kezelve: absolute, authority (CONNECT), asterisk (`OPTIONS *`) és origin |
| **A kapcsolatok egy része elszámolatlan maradt** | A második futtatás „16-ból 10 visszafejtve"-t írt, és a maradék hatból négyről **semmit** nem mondott. Ez a `DecodeResult` saját alapelvének a megsértése volt („a kudarc is eredmény"), és pont ez az összemosás terelte az első vizsgálatot a dekóderre a rögzítés helyett | A `NoHandshake` és a `Failed` külön számol és külön mondatot kap; teszt őrzi, hogy a részek összeadnak. A kettő más okot jelent: az egyik a rögzítésre, a másik a Keyhole-ra mutat |
| **A TLS 1.3 kulcs-frissítés megállította a dekódolást** | A harmadik futtatás jelezte: „1 had a key that Keyhole could not use" — kulcs volt, mégsem nyílt. A traffic secret menet közben rotálódik, a keylog meg csak a `_0`-t tartalmazza; a KeyUpdate maga is a régi kulccsal titkosított, szóval semmi nem jelzi | A `traffic upd` címkével továbbszármaztatva, sorszám nullára, legfeljebb 64 frissítés. Minden lépés tippelés, amit az AEAD tag igazol, szóval egy téves tipp egyetlen rekordba kerül |
| **A SYN-re frissítés sem elég a handshake-hez** | A harmadik futtatás 14 kapcsolatából négynek nem volt handshake-je. A kényszerített frissítés 50 ms-onként fut, a böngésző indulási burstje alatt viszont ennél sűrűbben nyílnak kapcsolatok — és a socket-tábla sem feltétlenül jelenti már a SYN pillanatában | **Visszamenős puffer:** a hatókörbe nem illő kapcsolat-nyitások 2 másodpercig memóriában, és amikor egy port hatókörbe kerül, a korábbi csomagjai visszamenőleg bekerülnek. Nem időzítésen múlik, tehát nem versenyez |

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
prune be van kötve és tesztelt, de valós hosszú futás alatt nem mértem. M8 óta a
visszamenős puffer is új memóriahasználat, amit érdemes figyelni — bár a 8 MB-os plafon
korlátozza.

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
| `verify-elevated.ps1` lefuttatása | ✅ 14/14 PASS (M7 után); M8-cal kiegészítve 22/22 PASS |

### Megtalált és javított hibák

| Hiba | Hatás | Javítás |
|---|---|---|
| A szűrt lista kétmásodpercenként újraépült | A kijelölés minden frissítéskor elveszett — rákattintottál egy appra, és 2 mp múlva üres lett a drill-down | Helyben szinkronizálás törlés-újratöltés helyett |
| **A figyelő socketek állapota üresen jelent meg** | A drill-down State oszlopa semmit nem írt egy listenernél. A hiba M1 óta benne volt, és a `SocketTableReaderTests` folyamatosan jelezte, csak nem ott volt a baj, ahol a teszt neve sugallta | Lásd lentebb |

#### A TCP-állapot hibája — és amit nem a gyanú, hanem a mérés mutatott meg

A tünet alapján a `SocketTableReader` struct-layoutja tűnt hibásnak: a `MIB_TCP_STATE` 1-től
indul, szóval egy nulla rossz eltolásra vall. **Ez tévedés volt**, és három mérés kellett a
kizárásához:

1. Az `Established` kapcsolatok **helyesen** 5-öt adnak — ha az eltolás csúszna, minden sor
   romlana, nem csak a listenerek.
2. A dedikált listener-only táblában, ahol *minden* sor LISTEN, szintén 0-kat olvasunk —
   tehát nem a sorok válogatása a kérdés.
3. Végül egy hexdump a saját, frissen `listen()`-elt socketünk soráról, a szomszédaival
   együtt: a cím, a port és a PID mind helyesen dekódol, a következő sor state-je 5, és a
   mienk mezője **tényleg nulla**.

Vagyis a kernel ad vissza olyan értéket, amit a `MIB_TCP_STATE` nem tud kifejezni —
ugyanabban a táblában, ahol más listenerek 2-t adnak. A javítás ezért szűk: egy
**peer nélküli** sor definíció szerint figyelő socket, szóval ott az értelmezhetetlen
állapot `Listen` lesz. Peerrel rendelkező sornál `None` marad: ott nincs mit következtetni,
és egy kitalált állapot rosszabb, mint a bevallott tudatlanság.

Ezzel a `SocketTableReaderTests` terhelés-érzékeny második hibája is elment — ugyanaz volt
a gyökere. **270 teszt, mind zöld, háromszor egymás után.**

## Következő lépés

M1–M8 kész és élesben ellenőrizve. A következő:

1. **Top hostok panel** — melyik *célpont* kapja a legtöbb forgalmat, appoktól függetlenül.
2. **GeoIP** — ország/ASN a távoli végpontokhoz (offline MMDB, nincs hálózati hívás).
3. **Hosszú terhelési teszt** — az egyetlen méretlen terület.
