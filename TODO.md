# Chasing Your Tail NG - TODO

## v4.1 - Geplante Features

### 1. Startbildschirm fixen
- [ ] Rahmen korrekt darstellen (Breite anpassen)
- [ ] Version v4.0 korrekt zentriert

### 2. Report-Anzeige am Ende
- [ ] JA/NEIN Frage nach Payload-Ende
- [ ] Bei JA: Report seitenweise auf Display anzeigen

### 3. OUI/MAC Hersteller-Lookup (offline)
- [ ] IEEE OUI Liste herunterladen (https://standards-oui.ieee.org/oui/oui.txt)
- [ ] Bei Internetverbindung automatisch updaten
- [ ] Hersteller in Report und Display anzeigen
- [ ] In analyze_pcap.py integrieren

### 4. Bluetooth OUI Lookup
- [ ] BT nutzt gleiche OUI wie WiFi (IEEE 802 Standard)
- [ ] Gleiche OUI-Liste verwendbar für BT-Geräte
- [ ] bt_scanner.py um Hersteller-Lookup erweitern

## Notizen
- BT MAC OUI = gleiche IEEE Liste wie WiFi ✅
- OUI Liste: ~6MB, gut für Offline-Nutzung
- Update-Intervall: wöchentlich bei Internetverbindung
