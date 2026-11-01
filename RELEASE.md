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
| **Csomagrögzítés (Npcap)** | **admin + Npcap** | a session csak TLS-kulcsokat gyűjt, a Capture fül megindokolja |
| **TLS-dekódolás (kérés/válasz nézet)** | ugyanaz | nincs mit dekódolni csomagok nélkül |
| Top hostok panel | nem kell | működik (forgalom-számok adminhoz kötöttek) |
| **Ország / üzemeltető (GeoIP)** | nem kell, de **MMDB-fájl** igen | a két oszlop üres marad, a Hosts fül megindokolja |

A **service** fut rendszergazdaként (LocalSystem), a **UI nem**. Ez szándékos: így nincs
UAC-prompt minden indításnál, és egy UI-hiba sem fut emelt jogosultsággal.

### Npcap: nincs a csomagban

A csomagrögzítés az **Npcap** drivert igényli, ami **nincs benne a Keyhole zipjében**. Ez
nem lustaság: az Npcap ingyenes licence kifejezetten megtiltja az újraterjesztést és a más
szoftverrel együtt csomagolást — ahhoz fizetős OEM-engedély kell. A Keyhole ezért csak
felismeri, és ha hiányzik, a Capture fülön felajánlja a letöltést.

A **„Get Npcap…"** gomb a gyártó saját telepítőjét hozza le az `npcap.com`-ról, ellenőrzi,
hogy valóban az Nmap Project aláírása van rajta, és csak utána indítja el — a szokásos
UAC-prompttal, nem csendben. Ami nem megy át az ellenőrzésen, az törlődik, nem fut le.

> Az Npcap ingyenes licence **5 rendszerre** korlátozza a használatot, kivéve ha csak
> Nmap/Wireshark/Defender for Identity mellett használod. Ha ez nem elég, a gyártónál van
> OEM-licenc. **Az aktuális feltételeket az `npcap.com`-on olvasd el, ne ebből a fájlból** —
> ez a bekezdés egy adott napon volt igaz.

Enélkül a Keyhole minden mása változatlanul működik, a TLS keylog is: pontosan annyit
tud, amennyit M8 előtt tudott.

### GeoIP: szintén nincs a csomagban

Az **ország** és **üzemeltető** oszlopok MaxMind MMDB-fájlokból olvasnak, amik **nincsenek
a zipben**: a MaxMind fiókot kér a letöltéshez, és a licence szabályozza a
továbbterjesztést. A Keyhole nem is töltheti le helyetted.

Ha kérsz egy ingyenes MaxMind-fiókot, töltsd le a **GeoLite2 Country** és a **GeoLite2 ASN**
adatbázist, és tedd a `.mmdb` fájlokat ide:

```
%ProgramData%\Keyhole\geoip
```

A Keyhole a következő indításkor felveszi őket. A `GeoLite2-City.mmdb` is megteszi a
Country helyett — az is tartalmaz országadatot. Enélkül a két oszlop üresen marad, és a
Hosts fül kiírja, mit hova kell tenni.

> A lekérdezés **teljesen offline**, és ez szándékos: egy eszköz, ami azt mutatja meg, mit
> küldenek más programok, nem kezdhet el magától kéréseket küldeni harmadik félnek.

---

## Telepítés

1. Csomagold ki a zipet egy tetszőleges mappába.
2. Futtasd az **`Install Keyhole.cmd`** fájlt. UAC-promptot fog kérni.
3. Indítsd a Keyhole-t a **Start menüből**.

A telepítő mindkét felet felrakja: a service-t `%ProgramFiles%\Keyhole`-ba
(LocalSystem, automatikus indítás), a UI-t pedig `%ProgramFiles%\Keyhole\app`-ba,
Start menü bejegyzéssel. A UI **nem** emelt jogon fut.

> Ne a build-mappából indítsd a UI-t: az a következő fordításnál zárolódik, és az
> „indulás bejelentkezéskor” beállítás is egy múlékony útvonalra mutatna.

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

Eltávolítja a service-t, a UI-t, a Start menü bejegyzést és az automatikus indítást is.

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
| `geoip\` | ide tedd a MaxMind `.mmdb` fájlokat; a Keyhole csak olvassa |
| `captures\` | **TLS-kulcsok és a rögzített forgalom** session-önként |

> ⚠️ **A `captures\` mappa M8 óta érzékenyebb, mint volt.** Korábban csak TLS-kulcsokat
> tartalmazott, amikhez a forgalom valahol máshol volt. Most a `capture.pcapng` **a
> forgalmat is tartalmazza, a kulcsokkal egy fájlban** — pont ezért nyitja meg a Wireshark
> azonnal visszafejtve. Ez azt is jelenti, hogy aki megkapja ezt az egy fájlt, az mindent
> elolvas, amit az adott alkalmazás küldött és kapott: jelszavakat, tokeneket, sütiket.
>
> Ne oszd meg, és ha végeztél egy session-nel, töröld az egész mappáját.

A pcap mérete session-önként korlátozva van (alapértelmezés **512 MB**, a Settings fülön
állítható). A plafonnál a rögzítés leáll és a Capture fül kiírja; a session és a
kulcsgyűjtés megy tovább.

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
- **Loopback-forgalomnál a fel/le szám megegyezik.** Ha egy kapcsolat mindkét vége ezen a
  gépen van (`127.0.0.1`), a két oldal ugyanazt a bejegyzést olvassa, így mindkettő azonos
  fel- és letöltést mutat. A valódi hálózati forgalmat ez nem érinti.
- **A QUIC/HTTP3 forgalom nem dekódolható.** A Keyhole rögzíti, de nem fejti vissza: a QUIC
  saját csomagvédelmet használ, a dekódolása nem a TLS-rekordok kérdése. A Chrome
  alapértelmezésben előnyben részesíti a HTTP/3-at, ahol a szerver kínálja — ezért a
  Capture fül kiírja, mennyi QUIC került a felvételbe, hogy egy üresebb kéréslista
  magyarázatot kapjon, és ne hibának tűnjön.
- **A Schannel-es appok forgalma a pcapban is titkosított marad.** Nem írnak keylogot, így
  nincs mivel visszafejteni. A Capture fül ezt is kiírja, külön attól, amikor a dekódolás
  hibázott.
- **Antivírus-riasztás lehetséges.** Forgalom-figyelés, ETW-session, környezeti változó
  injektálás és most csomagrögzítés is — aláíratlan buildnél ez együtt kiverheti a
  biztosítékot.
