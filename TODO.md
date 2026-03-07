# Chasing Your Tail NG - TODO

## v4.2 - Geplante Features
- [ ] GPS-Daten korrekt speichern (Test draußen mit GPS-Dongle)
- [ ] WiGLE Integration (SSID Geolocation)
- [ ] BT OUI im Report anzeigen (gleiche Liste, bt_scanner.py erweitern)

## Erledigt v4.0-v4.1
- [x] Ignore-Liste MAC + SSID
- [x] Bluetooth Scanner Classic + BLE  
- [x] BT-Korrelation im Report
- [x] Scan-Modus Auswahl WiFi/GPS/BT
- [x] Defaults 1 Runde / 30 Sekunden
- [x] Startbildschirm ASCII
- [x] Report JA/NEIN Anzeige
- [x] OUI Hersteller-Lookup offline + Auto-Update
- [x] Gespooffte MAC Erkennung

## v4.2 - WiGLE Integration

### Neue Daten im Report pro verdächtigem Gerät:
- [ ] Probe-SSIDs des Geräts sammeln und speichern
- [ ] WiGLE: MAC-Adresse suchen → Standort/Erstgesehen
- [ ] WiGLE: Gerätename (BT) suchen → Standort
- [ ] WiGLE: Probe-SSIDs suchen → wo ist das Heimnetz?
- [ ] Konfigurierbarer API-Key in config.json
- [ ] Offline-Modus wenn kein Internet

### Neue Datenstruktur pro Gerät:
- mac, vendor, type (spoofed/global)
- appearances, windows
- probe_ssids[]  ← NEU
- wigle_mac {}   ← NEU  
- wigle_bt {}    ← NEU
- wigle_ssids {} ← NEU

## v4.3 - Verdächtige Datenbank

### Workflow beim Start:
- [ ] suspects_db.json laden (falls vorhanden)
- [ ] Alte Reports + PCAPe löschen
- [ ] Nach Scan: Abgleich neue Verdächtige vs suspects_db.json
- [ ] Bekannte Verdächtige: "⚠ BEREITS BEKANNT!" im Report
- [ ] Neue Verdächtige: suspects_db.json aktualisieren

### suspects_db.json Struktur:
- mac, vendor, type (spoofed/global)
- first_seen (Datum/Uhrzeit)
- last_seen (Datum/Uhrzeit)  
- seen_count (wie oft gesehen)
- locations[] (GPS-Koordinaten)
- ssids[] (gesammelte Probe-SSIDs)
- wigle_results{} (gecachte WiGLE Ergebnisse)

### Fix gleichzeitig:
- [ ] PCAP_LIST nur vom aktuellen Lauf

## v4.3 - Verdächtige-Datenbank + Watch-List

### suspects_db.json
- [ ] Beim Start: alte Reports + PCAPe löschen
- [ ] Nach Scan: neue Verdächtige speichern
- [ ] Bekannte Verdächtige: "⚠ BEREITS BEKANNT!" im Report
- [ ] Felder: mac, vendor, type, first_seen, last_seen, seen_count, locations[], ssids[]

### watch_list.json - Drei Kategorien
- [ ] IGNORE    → eigene Geräte (bereits vorhanden als mac_list.json)
- [ ] STATIC    → Gerät nur an bekanntem Ort erwartet (Nachbar, Hotel, Arbeit)
- [ ] DYNAMIC   → Gerät folgt mir = Tracking!

### watch_list.json Struktur
- [ ] mac, label, type (static/dynamic)
- [ ] known_locations[]: name, lat, lon, radius_m (für static)
- [ ] seen_locations[]: lat, lon, timestamp (für dynamic - wird automatisch befüllt)
- [ ] first_seen, notes

### Logik beim Scan
- [ ] Gerät in watch_list STATIC + GPS in bekannter Zone → unauffällig
- [ ] Gerät in watch_list STATIC + GPS außerhalb Zone → ⚠ AUSSERHALB BEKANNTER ZONE!
- [ ] Gerät in watch_list DYNAMIC + 1 Ort → noch unauffällig
- [ ] Gerät in watch_list DYNAMIC + 2+ Orte → 🔴 TRACKING ERKANNT!
- [ ] Neues Gerät → suspects_db.json + Alarm

### Neue Python Module
- [ ] watch_list.py → WatchList Klasse, Zonen-Check (Haversine), Tracking-Erkennung
- [ ] suspects_db.py → SuspectsDB Klasse, CRUD, JSON persistence

### Integration in analyze_pcap.py
- [ ] watch_list laden
- [ ] suspects_db laden  
- [ ] Pro Gerät: Kategorie bestimmen → ignore/static/dynamic/new
- [ ] Report: neue Sektionen STATIC ALARM, DYNAMIC TRACKING, NEU VERDÄCHTIG
- [ ] suspects_db nach Scan aktualisieren

### Report Sektionen v4.3
- [ ] 🔴 TRACKING ERKANNT - Dynamische Geräte an mehreren Orten
- [ ] ⚠ AUSSERHALB BEKANNTER ZONE - Statische Geräte am falschen Ort  
- [ ] 🆕 NEUE VERDÄCHTIGE - Noch unbekannte Geräte
- [ ] 👁 BEOBACHTETE GERÄTE - Unauffällige watched devices
