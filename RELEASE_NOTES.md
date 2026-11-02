# Keyhole 0.1.0

Hálózati forgalom-elemző és per-alkalmazás blokkoló Windowsra. A GlassWire
átláthatóságát és a Wireshark mélységét egy helyen, kézi `SSLKEYLOGFILE`
kapcsolgatás nélkül.

**Első kiadás.** Minden képesség valódi forgalmon ellenőrizve — a részletes
mérésekkel és a közben megtalált hibákkal együtt a [`milestone.md`](milestone.md)
dokumentálja.

---

## Mit tud

**Ki beszél a hálózaton.** Alkalmazásonként, ikonnal, kiadóval, Authenticode-aláírás
állapottal és feloldott hostnevekkel; svchost esetén a benne futó szolgáltatás nevével.
Kapcsolatonkénti lebontás PID-del, állapottal, forgalommal. Élő throughput grafikon fel/le
bontásban, gépszinten és apponként is.

**UDP/QUIC célpontokkal.** A UDP socket-tábla nem tartalmaz távoli végpontot, ezért a
Keyhole ETW-ből veszi őket — enélkül egy modern böngésző forgalmának a nagy része
láthatatlan lenne.

**Top hostok.** Melyik *célpont* kapja a legtöbb forgalmat, appoktól függetlenül. Itt
bukkan elő, ha három egymással össze nem függő program ugyanazzal a hosttal beszél.
Ország és hálózat-üzemeltető oszloppal, offline adatbázisból.

**Blokkolás egy kattintással.** Windows tűzfalszabály, ami túléli az újraindítást. A
szabály elmenti a bináris SHA-256-át a létrehozáskor, és jelzi, ha a fájl utóbb
megváltozott. **Kizárólag manuális:** nincs deny-by-default, nincs engedélykérő prompt — te
döntöd el, melyik szoftver veszíti el a hálózatot.

**TLS-láthatóság kézi env-var nélkül.** A Keyhole indítja az appot `SSLKEYLOGFILE`-lal,
ami **csak annak a folyamatnak** a környezetében létezik. Nincs gépszintű változó, nincs
mit elfelejteni kikapcsolni.

**Csomagrögzítés és beépített visszafejtés.** A session alatt, a célfolyamat forgalmára
szűkítve, a kulcsokkal **egy pcapng fájlba**. A Wireshark így magától, visszafejtve nyitja
meg — nincs keylog-útvonalat beállítani. A Capture fülön pedig ott a kérés/válasz lista:
metódus, URL, státusz, fejlécek, méret, idő. HTTP/1.1 és HTTP/2 (HPACK-kal).

**Magyar és angol felület.** Alapértelmezésben a rendszer nyelvét követi, a Beállítások
fülön felülírható (Automatikus / English / Magyar), és a váltás azonnal érvényes —
újraindítás nélkül. A szolgáltatás nem küld kész mondatokat, hanem kódokat, amiket a
felület önt szavakba: így a magyarázó szöveg — a „miért nulla minden", a „miért nem
olvasható ez a kapcsolat" — is magyar, nem csak a feliratok.

---

## Telepítés

1. Csomagold ki a zipet.
2. Futtasd az **`Install Keyhole.cmd`**-t. UAC-promptot fog kérni.
3. Indítsd a Start menüből.

A service `%ProgramFiles%\Keyhole`-ba kerül (LocalSystem, automatikus indítás), a UI
ugyanoda, Start menü bejegyzéssel. **A UI nem fut emelt jogon** — ez szándékos: így nincs
UAC-prompt minden indításnál, és egy UI-hiba sem admin-jogosultságú.

Részletek, eltávolítás és korlátok: [`RELEASE.md`](RELEASE.md).

---

## Amit telepítés előtt tudni kell

### A build nincs aláírva

Nincs kódaláíró tanúsítvány a projekthez, ezért a **SmartScreen figyelmeztetni fog** az
első indításnál. Továbblépés: *További információ → Futtatás mindenképp*. A Defender is
visszatarthatja egy-két percre, amíg felhőben elemzi — ez normális egy olyan programnál,
ami forgalmat figyel és tűzfalszabályokat ír.

### Két függőség nincs a csomagban

Egyik sem licencelhető újraterjesztésre, szóval a Keyhole felismeri őket és megmondja,
mit hova kell tenni:

- **Npcap** a csomagrögzítéshez. A Capture fül „Get Npcap…" gombja letölti a gyártó
  telepítőjét, **ellenőrzi, hogy valóban az Nmap Project aláírása van rajta**, és csak
  utána indítja. Enélkül a session a TLS-kulcsokat ugyanúgy begyűjti.
- **MaxMind GeoLite2** `.mmdb` fájlok az ország/üzemeltető oszlopokhoz. Ingyenes fiók kell
  hozzá; a fájlok a `%ProgramData%\Keyhole\geoip` mappába mennek. A lekérdezés **teljesen
  offline** — egy forgalom-figyelő nem kezdhet el magától kéréseket küldeni.

### ⚠️ A capture-mappa érzékeny

A `capture.pcapng` **a rögzített forgalmat és a visszafejtéséhez szükséges kulcsokat is
tartalmazza, egy fájlban** — ez az, ami miatt a Wireshark azonnal olvassa. Ugyanezért elég
ez az egy fájl ahhoz, hogy valaki mindent elolvasson, amit az adott alkalmazás küldött:
jelszót, tokent, sütit. **Ne oszd meg, és ha végeztél egy session-nel, töröld az egész
mappáját.**

---

## Ismert korlátok

- **A TLS-capture nem működik minden appnál.** Csak NSS/BoringSSL/OpenSSL-alapú programok
  olvassák az `SSLKEYLOGFILE`-t: Chrome, Firefox, Brave, Edge, Electron, Node. A Windows
  saját Schannel-ét használó programok — köztük a legtöbb natív .NET app és a beépített
  `curl.exe` — figyelmen kívül hagyják. A Keyhole ezt **indítás előtt jelzi**, és a
  dekódolás után is külön kiírja, hány kapcsolathoz nem volt kulcs.
- **A QUIC/HTTP3 rögzítve van, de nem dekódolható.** A QUIC saját csomagvédelmet használ,
  ez nem a TLS-rekordok kérdése. A Chrome előnyben részesíti, ahol kínálják — ezért a UI
  **kiírja, mennyi QUIC került a felvételbe**, hogy egy üresebb kéréslista magyarázatot
  kapjon, és ne hibának tűnjön.
- **MITM proxy nincs.** Saját CA-t kellene a gépi trust store-ba telepíteni, ezért kimaradt
  — és ezzel a Schannel-es appok forgalma a pcapban is titkosított marad.
- **Loopback-forgalomnál a fel/le szám megegyezik.** A két oldal ugyanarra a bejegyzésre
  esik. Valódi hálózati forgalmat nem érint.
- **Hosszú terhelési teszt nincs lefuttatva.** A retention és a prune be van kötve és
  tesztelt, de napokig tartó futás alatt nem mértem.

---

## Követelmények

Windows 10/11 x64. A zip önálló (self-contained) — nem kell .NET telepítve lennie.
A monitorozás és a blokkolás rendszergazdai jogot kér; ezt a service kapja meg, nem a UI.

---

**298 teszt**, a Wireshark saját eszközeivel (`tshark`, `capinfos`) való
összehasonlításokkal együtt. A TLS-visszafejtés nem körbe-teszteléssel van igazolva —
ugyanaz a kód titkosít és fejt vissza, egy önmagában következetes félreértés minden saját
tesztet átengedne —, hanem azzal, hogy a `tshark` ugyanabból a fájlból ugyanazt olvassa.

`Keyhole-0.1.0.zip` SHA-256:

```
80ed8518ca1ea5e899801cef02bc52b5a307424a5d6e1e416e876ae7654c3da7
```
