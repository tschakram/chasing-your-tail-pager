# Chasing Your Tail NG - TODO

## Aktueller Stand: v4.3 ✅

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

## v4.4 - BT Device Fingerprinting

### bt_devices_db.json
- [ ] OUI → Hersteller + typische Geräte
- [ ] BLE Service UUIDs → Gerätetyp + Risiko
      - 0x111E Handsfree → Headset mit Mikrofon 🎤 (medium risk)
      - 0x110B Audio Sink → Kopfhörer ohne Mikrofon 🎧 (low risk)
      - 0x1108 Headset → Headset Classic (medium risk)
      - 0x180A Device Info → IoT Gerät (low risk)
      - 0xFE9F Google → Chromecast/Google Gerät
      - 0xFE2C Apple → AirDrop/AirPods
- [ ] Appearance Codes → Gerätekategorie
- [ ] Bekannte Gerätenamen → Mikrofon ja/nein
- [ ] Risikobewertung: low/medium/high

### bt_scanner.py erweitern
- [ ] BLE Advertisement Data auslesen
- [ ] Service UUIDs erfassen
- [ ] Appearance Code auslesen
- [ ] Gerätename aus Advertisement
- [ ] OUI Lookup für BT MACs (gleiche IEEE Liste)
- [ ] Risikobewertung pro Gerät

### Report BT Fingerprinting
- [ ] Hersteller + Gerätetyp anzeigen
- [ ] Mikrofon-Flag anzeigen
- [ ] Risiko-Level anzeigen
- [ ] Korrelation WiFi ↔ BT (gleicher OUI)

---

## v4.4 - Modus 4: Hotel-Scan

### Ziel: Versteckte Kameras + aktive Geräte erkennen

### WiFi Beacon Frame Analyse
- [ ] pcap_engine.py: Beacon Frames (0x80) auswerten
- [ ] SSID + BSSID + Kanal + Signalstärke (RSSI) erfassen
- [ ] Bekannte Kamera-SSIDs erkennen:
      IPCamera, ESP_, Hikvision, Dahua, Reolink, EZVIZ, Wyze...
- [ ] Versteckte SSIDs (leere SSID in Beacon) markieren
- [ ] OUI-Abgleich mit Kamera-Herstellern

### Kamera OUI Datenbank (camera_oui.json)
- [ ] Hikvision, Dahua, Reolink, Wyze, Arlo, Ring, Nest
- [ ] Espressif (ESP32) = häufig in DIY/Billig-Kameras
- [ ] Realtek, MediaTek IoT Chips

### BLE Advertisement Scan (Hotel-Modus)
- [ ] Längerer BLE Scan (60s)
- [ ] Advertisement Data auslesen
- [ ] Bekannte Kamera/IoT BLE UUIDs erkennen
- [ ] Espressif, Realtek, MediaTek OUIs markieren

### Report Hotel-Scan
- [ ] Separate Sektion "Verdächtige Kameras"
- [ ] RSSI anzeigen → Näherungsschätzung
- [ ] WiGLE: BSSID nachschlagen
- [ ] LED rot + Vibration bei Kamera-Verdacht

### Modus-Auswahl
- [ ] Modus 4 = Hotel-Scan (Beacon + BLE Advertisement)
- [ ] payload.sh: NUMBER_PICKER auf 0-4 erweitern

---

## v4.5 - Verbesserungen

### Watch-List Management
- [ ] Gerät direkt vom Display zur Watch-List hinzufügen
- [ ] Typ wählen: static/dynamic
- [ ] Bei static: aktuelle GPS-Position als Zone speichern
- [ ] Label eingeben via NUMBER_PICKER oder fixer Name

### Cleanup beim Start
- [ ] Alte Reports löschen (älter als X Tage, konfigurierbar)
- [ ] Alte PCAPe löschen (außer letzten N Scans)
- [ ] Konfigurierbar in config.json

### GPS Verbesserungen
- [ ] GPS-Track KML Export (Google Earth)
- [ ] Geschwindigkeit berechnen (stehend/fahrend)
- [ ] Bei stehendem Scan: statische Geräte ignorieren

### Display Verbesserungen  
- [ ] Live-Updates während Scan (Geräte-Counter)
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
- [ ] BT OUI Lookup noch nicht in bt_scanner.py
      → Kommt mit v4.4

---

## Hardware

- WiFi Pineapple Pager (OpenWrt 24.10.1, mipsel_24kc)
- Python 3.11.14
- u-blox GNSS Receiver (USB /dev/ttyACM0, gpsd 3.25)
- Bluetooth hci0 (USB, BlueZ 5.72) BD: 00:13:37:AD:61:C6

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
