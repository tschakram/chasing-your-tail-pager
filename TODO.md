# Chasing Your Tail NG - TODO

## Aktueller Stand: v4.5 ✅ abgeschlossen

### Erledigte Features
- [x] Native Pager Framework (keine externen Tools)
- [x] Scan-Modi 0-3 (WiFi, GPS, BT, Alle)
- [x] PCAP Capture + Channel Hopping
- [x] Persistence Scoring
- [x] OUI Vendor Lookup (offline, ~39k Einträge, auto-update)
- [x] MAC Spoofing Erkennung (lokal/global)
- [x] Probe Response SSID Parsing
- [x] WiGLE API Integration (MAC/BT/SSID Lookup)
- [x] Bluetooth Classic + BLE Scanner
- [x] GPS Integration (u-blox, gpsd)
- [x] Ignore-Listen (MAC + SSID)
- [x] Report auf Display anzeigen
- [x] NTP/RTC Zeitkorrektur beim Start
- [x] MIN_APPEARANCES dynamisch nach Scan-Dauer
- [x] PCAP_LIST nur vom aktuellen Lauf
- [x] Report-Pfad direkt aus Python-Output
- [x] SuspectsDB - persistente Verdächtige-Datenbank
- [x] WatchList - static/dynamic Tracking-Erkennung
- [x] BEKANNT/NEU Status im Report
- [x] OPSEC - alle sensiblen Dateien in .gitignore
- [x] README zweisprachig EN/DE

---

## v4.4 - BT Device Fingerprinting ✅

### bt_fingerprint.py (neu)
- [x] BLE Service UUIDs → Gerätetyp + Risiko
      - 0x111E Handsfree → Headset mit Mikrofon 🎤 (medium)
      - 0x110B Audio Sink → Kopfhörer ohne Mikrofon 🎧 (low)
      - 0x1108 Headset → Headset Classic (medium)
      - 0x180A Device Info → IoT Gerät (none)
      - 0xFE9F Google → Chromecast/Google Gerät (low)
      - 0xFE2C Apple → AirDrop/AirPods (low)
      - 0xFFE0/FFE1 → Kamera-Service (high)
- [x] Appearance Codes → Gerätekategorie + Risiko
- [x] Bekannte Gerätenamen → Mikrofon / Kamera erkannt
- [x] Risikobewertung: none/low/medium/high
- [x] Kamera-Hersteller OUI-Datenbank (intern)

### bt_scanner.py erweitert
- [x] BLE Advertisement Data via btmon (parallel)
- [x] Service UUIDs erfassen
- [x] Appearance Code auslesen
- [x] Gerätename aus Advertisement
- [x] OUI Lookup für BT MACs (IEEE Liste via oui_lookup.py)
- [x] Risikobewertung + Fingerprint pro Gerät

### Report BT Fingerprinting (analyze_pcap.py)
- [x] Kritische BT-Geräte separat hervorheben (🔴 Sektion)
- [x] Mikrofon-Flag 🎤 anzeigen
- [x] Kamera-Flag 📷 anzeigen
- [x] Risiko-Level in BT-Tabelle
- [x] Korrelation WiFi ↔ BT (gleicher OUI)

---

## v4.4 - Modus 4: Hotel-Scan ✅

### hotel_scan.py (neu)
- [x] WiFi Beacon Frame Analyse (pcap_engine.read_pcap_beacons)
- [x] SSID + BSSID + Kanal + RSSI erfassen
- [x] Bekannte Kamera-SSIDs erkennen (30+ Muster)
- [x] Versteckte SSIDs markieren
- [x] OUI-Abgleich mit Kamera-Herstellern

### Kamera OUI Datenbank (intern in hotel_scan.py + bt_fingerprint.py)
- [x] Hikvision, Dahua, Reolink, Wyze, Arlo, Ring, Nest
- [x] Espressif (ESP32) = häufig in DIY/Billig-Kameras
- [x] Realtek, MediaTek IoT Chips

### pcap_engine.py erweitert
- [x] read_pcap_beacons() → Beacon Frames (0x80) auswerten
- [x] RSSI via Radiotap-Header-Parser

### BLE Advertisement Scan (Hotel-Modus)
- [x] 60s BLE Scan (konfigurierbar via --bt-duration)
- [x] Advertisement Data via btmon
- [x] Kamera/IoT BLE UUIDs erkennen
- [x] Espressif, Realtek OUIs markieren

### Report Hotel-Scan
- [x] Separate Sektion "Verdächtige Kameras" (🔴 KRITISCH)
- [x] RSSI + Entfernungsschätzung
- [x] LED rot (5x) + Vibration bei Kamera-Verdacht

### Modus-Auswahl
- [x] Modus 4 = Hotel-Scan (Beacon + BLE Advertisement)
- [x] payload.sh: NUMBER_PICKER auf 0-4 erweitert

---

## v4.5 - Verbesserungen ✅

### BT Classic Fingerprinting (SDP) ✅
- [x] `sdptool browse <MAC>` für BT Classic Geräte (kein BLE)
- [x] SDP Profile-UUIDs → Fingerprinting (HFP 0x111E, HSP 0x1108, A2DP 0x110A)
- [x] Automatisch nach Classic-Scan aufrufen wenn btmon keine UUIDs liefert
- [x] Graceful Fallback: Timeout/nicht erreichbar → [], kein Crash
- [x] JBL Flip 5 in Ignore-Liste (Live-Test bestätigt: taucht nicht mehr auf)

### BT Ignore-Liste ✅
- [x] analyze_pcap.py: BT-Geräte gegen ignore_macs filtern
- [x] hotel_scan.py: Ignore-Liste laden + WiFi/BLE filtern
- [x] JBL Flip 5 `aa:bb:cc:dd:ee:01` in mac_list.json auf Pager eingetragen

### Watch-List Management vom Display ✅
- [x] python/watchlist_add.py: CLI-Wrapper für WatchList.add()
- [x] payload.sh: Watch-List-Block nach Report-Anzeige
- [x] Verdächtige MACs aus Report extrahieren (Emoji-Fix: gsub /[^0-9a-fA-F:]/)
- [x] NUMBER_PICKER Gerät (1-N oder 0=Überspringen)
- [x] NUMBER_PICKER Typ: 1=Dynamic, 2=Static
- [x] Zonenwahl: konfigurierte Zonen aus config.json + "Aktueller GPS-Standort"
- [x] CONFIRMATION_DIALOG vor Eintrag
- [x] VIBRATE 3 + LOG green bei Erfolg
- [x] Duplikat-Erkennung (ALREADY_EXISTS)
- [x] GPS-Koordinaten nur in config.json auf Pager (NIEMALS im Repo)
- [x] config.example.json: watch_list-Sektion mit Platzhalter-GPS (0.000000)

### WiGLE Nearby-Search ✅
- [x] search_nearby(lat, lon, radius_m=200) mit GPS-Koordinaten
- [x] nearby_cross_reference(): matched + unmatched Geräte
- [x] format_nearby_section(): Markdown-Sektion im Report
- [x] Wird am Ende von save_report() aufgerufen (GPS erforderlich)

### Cleanup beim Start ✅
- [x] python/cleanup.py: Löscht alte Reports/PCAPs/BT-Scans/Logs
- [x] config.json: cleanup-Sektion (keep_reports_days, keep_pcaps_days etc.)
- [x] payload.sh: cleanup beim Start, Ergebnis als LOG-Zeile
- [x] --dry-run und --verbose Flags

### Bugfixes ✅
- [x] CRLF-Problem: Windows→Pager Zeilenenden (payload.sh + Python)
- [x] PATH fix: /mmc/usr/bin nicht im non-login shell PATH (payload.sh)
- [x] MAC-Emoji-Bug: 🔴 blieb in MAC-Feld hängen bei awk-Extraktion
- [x] SSH-Config: ~/.ssh/config für einfacheren Zugriff als "pager"
- [x] .gitattributes: LF-Zeilenenden für alle Textdateien

### README / Dokumentation ✅
- [x] How to Use (EN + DE): Ignore-Listen, Watch-List, Scan-Empfehlungen
- [x] Beispiel 45-Minuten-Fahrt: Ablauf + Persistence-Score-Tabelle
- [x] Dateistruktur aktualisiert (alle v4.5-Dateien)
- [x] Modus 4 in Scan-Modi-Tabelle
- [x] Version v4.2 → v4.5 in Beschreibungen

---

## v4.6 - Mögliche nächste Features

### GPS Verbesserungen
- [ ] GPS-Track KML Export (Google Earth)
- [ ] Geschwindigkeit berechnen (stehend/fahrend erkennbar)
- [ ] Bei stehendem Scan: statische Umgebungsgeräte automatisch niedriger wichten

### Display Verbesserungen
- [ ] Live-Updates während Scan (Geräte-Counter pro Runde)
- [ ] Scan-Fortschritt in Prozent
- [ ] BT-Geräte Counter während BT-Scan

---

## Bekannte Bugs / Offene Punkte

- [ ] Systemzeit nach Neustart falsch (RTC ohne Batterie)
      → Workaround: NTP beim Start, hwclock -w nach manuellem Fix
- [ ] Bei 1 Scan-Runde alle Geräte Score 1.0
      → Workaround: min_appearances dynamisch, empfehle 2+ Runden
- [ ] WiGLE Section leer wenn keine Treffer
      → Zeigt "Keine Treffer (Wildcard Probes)"
- [x] BT OUI Lookup in bt_scanner.py → erledigt v4.4

---

## Hardware

- WiFi Pineapple Pager (OpenWrt 24.10.1, mipsel_24kc)
- Python 3.11.14
- u-blox GNSS Receiver (USB /dev/ttyACM0, gpsd 3.25)
- Bluetooth hci0 (USB, BlueZ 5.72)

## Loot-Struktur
```
/root/loot/chasing_your_tail/
├── pcap/                    ← PCAP-Dateien
├── surveillance_reports/    ← Markdown Reports
├── bt_scan_*.json           ← Bluetooth Scans
├── gps_track.csv            ← GPS Koordinaten
├── oui_cache.json           ← OUI Vendor Cache
├── wigle_cache.json         ← WiGLE Cache
├── suspects_db.json         ← Verdächtige-DB (nicht im Repo!)
├── watch_list.json          ← Watch-List (nicht im Repo!)
└── ignore_lists/
    ├── mac_list.json
    └── ssid_list.json
```

## Repo

https://github.com/tschakram/chasing-your-tail-pager
