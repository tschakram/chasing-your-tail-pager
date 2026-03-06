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
