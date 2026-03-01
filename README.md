# Chasing Your Tail NG - Pineapple Pager Payload 🔍

**Pineapple Pager Payload** | Kategorie: Reconnaissance  
Basiert auf: [ArgeliusLabs/Chasing-Your-Tail-NG](https://github.com/ArgeliusLabs/Chasing-Your-Tail-NG) (MIT)

Erkennt ob du verfolgt wirst – durch Analyse wiederkehrender WiFi-Probe-Requests mit optionaler GPS-Standortaufzeichnung.

> **v3.0:** Komplette Neuentwicklung auf Basis des nativen Pineapple Pager Frameworks – kein manueller tcpdump, kein eigenes Channel-Hopping, kein Framebuffer-Hacking. Alles läuft nativ über die Pager-APIs.

---

## Wie es funktioniert

1. **Dependency-Check** – python3 wird automatisch via `opkg` installiert falls nicht vorhanden
2. **GPS-Check** – optionale Standortaufzeichnung via u-blox oder kompatiblem GNSS-Empfänger
3. **Konfiguration** – Anzahl Runden und Scan-Dauer per NUMBER_PICKER wählbar
4. **Channel-Hopping** – `PINEAPPLE_HOPPING_START` aktiviert das eingebaute Hopping
5. **PCAP-Capture** – `WIFI_PCAP_START` erfasst Probe-Requests nativ
6. **Python-Analyse** – Persistence-Scoring vergleicht alle Scan-Runden
7. **Report** – Ergebnis auf dem Display + Markdown-Report in `/root/loot/`

---

## Dateistruktur

```
chasing_your_tail/
├── payload.sh                    ← Haupt-Script – startet über Pager-Dashboard
├── config.json                   ← Lokale Konfiguration (nicht im Repo!)
├── config.example.json           ← Vorlage für config.json
├── .gitignore                    ← Schützt API-Keys und Loot
├── python/
│   ├── pcap_engine.py            ← PCAP-Parser + Persistence-Analyse (stdlib only)
│   ├── analyze_pcap.py           ← Haupt-Analyse + Report-Generator
│   ├── chasing_your_tail.py      ← Kern-Engine (optional, Kismet-kompatibel)
│   ├── surveillance_analyzer.py  ← GPS-Korrelation + KML-Export
│   └── probe_analyzer.py         ← WiGLE-Integration + Probe-Statistiken
└── README.md
```

**Loot** landet automatisch in:

```
/root/loot/chasing_your_tail/
├── pcap/                    ← PCAP-Dateien (via WIFI_PCAP_START)
├── surveillance_reports/    ← Markdown Reports
├── gps_track.csv            ← GPS-Koordinaten pro Scan-Runde (optional)
└── ignore_lists/            ← MAC/SSID Ignorier-Listen (JSON)
```

---

## Installation

**1. Repo klonen:**
```bash
cd /root/payloads/user/reconnaissance/
git clone https://github.com/tschakram/chasing-your-tail-pager.git chasing_your_tail
cd chasing_your_tail
```

**2. Konfiguration einrichten:**
```bash
cp config.example.json config.json
```

> ⚠️ `config.json` enthält optionale API-Keys und wird **nicht** in Git eingecheckt.

**3. Starten:**  
Payload über das **Pager-Dashboard** starten:  
`Payloads → User → Reconnaissance → Chasing Your Tail NG`

> ⚠️ Der Payload **muss** über das Dashboard gestartet werden – nicht über `bash payload.sh` in SSH. Die Pager-APIs (LOG, GPS_GET, WIFI_PCAP_START etc.) funktionieren nur im Dashboard-Kontext.

---

## Ablauf auf dem Display

```
1. Start
   └── Abhängigkeiten prüfen
   └── GPS prüfen (Fix oder weiter ohne GPS)

2. Konfiguration
   └── NUMBER_PICKER: Anzahl Runden (Standard: 2)
   └── NUMBER_PICKER: Dauer pro Runde in Sekunden (Standard: 120)

3. Scan (pro Runde)
   └── PINEAPPLE_HOPPING_START → Channel-Hopping aktiv
   └── WIFI_PCAP_START → Probe-Requests erfassen
   └── GPS_GET → Koordinaten speichern (wenn Fix vorhanden)
   └── WIFI_PCAP_STOP → Capture beenden

4. Analyse
   └── pcap_engine.py → MACs + SSIDs extrahieren
   └── analyze_pcap.py → Persistence-Score berechnen
   └── Report → surveillance_reports/cyt_report_*.md

5. Ergebnis
   └── ✅ Keine Auffälligkeiten → Green LED
   └── ⚠️ Verdächtige Geräte → Red LED + VIBRATE
```

---

## Persistence-Score

| Score | Bedeutung |
|-------|-----------|
| 1.00 | Gerät in allen Scan-Runden sichtbar 🔴 |
| 0.50 | Gerät in der Hälfte der Runden sichtbar 🟡 |
| < 0.6 | Unauffällig 🟢 |

Standard-Schwellenwert: **0.6** (in `config.json` anpassbar)

---

## LED-Anzeige

| LED | Bedeutung |
|-----|-----------|
| 🔵 Cyan Blink | Initialisierung / Channel-Hopping |
| 🔵 Blue Blink | Scanning läuft |
| 🟡 Amber | Analyse läuft |
| 🟢 Green | ✅ Keine Auffälligkeiten |
| 🔴 Red Blink | ⚠️ Verdächtige Geräte erkannt |

---

## GPS Integration

Der Payload unterstützt **u-blox GNSS Receiver** (USB) sowie andere gpsd-kompatible Geräte.

**Voraussetzungen:**
- GPS-Dongle per USB angeschlossen
- gpsd läuft (auf dem Pager standardmäßig aktiv)
- GPS-Fix vorhanden (ca. 2-5 Minuten im Freien beim Kaltstart)

**GPS konfigurieren:**
```bash
GPS_CONFIGURE /dev/ttyACM0 9600
```

**GPS-Daten werden gespeichert in:**
```
/root/loot/chasing_your_tail/gps_track.csv
```
Format: `timestamp,latitude,longitude,altitude`

Ohne GPS-Fix läuft der Payload normal weiter – GPS ist optional.

---

## Konfiguration

```bash
cp config.example.json config.json
```

```json
{
  "surveillance": {
    "persistence_threshold": 0.6,
    "min_appearances": 2
  },
  "wigle": {
    "enabled": false,
    "api_name": "",
    "api_token": ""
  }
}
```

### WiGLE API (optional)

1. Account auf [wigle.net](https://wigle.net) erstellen
2. **Account → API Token** generieren
3. `api_name` und `api_token` in `config.json` eintragen
4. `"enabled": true` setzen

---

## Pager Framework APIs

v3.0 nutzt ausschließlich native Pager-APIs:

| API | Zweck |
|-----|-------|
| `LOG` | Display-Ausgabe |
| `GPS_GET` | GPS-Koordinaten abfragen |
| `GPS_CONFIGURE` | GPS-Gerät konfigurieren |
| `PINEAPPLE_HOPPING_START/STOP` | Channel-Hopping |
| `WIFI_PCAP_START/STOP` | Probe-Request Capture |
| `NUMBER_PICKER` | Interaktive Zahleneingabe |
| `START_SPINNER / STOP_SPINNER` | Ladeanimation |
| `LED` | LED-Steuerung |
| `VIBRATE` | Vibration bei Alarm |

---

## OpenWrt-Kompatibilität

| Original CYT-NG | Pager v3.0 |
|-----------------|------------|
| Kismet | `WIFI_PCAP_START` (nativ) |
| Eigenes Channel-Hopping | `PINEAPPLE_HOPPING_START` (nativ) |
| `tkinter` GUI | `LOG` + Pager-Display (nativ) |
| `cryptography` | Entfernt |
| `numpy`/`scipy` | Reines Python (Haversine) |
| `requests` | `urllib` stdlib Fallback |
| Framebuffer-Direktzugriff | Entfernt |

---

## Ignore-Listen

Eigene Geräte ignorieren um False Positives zu vermeiden:

**`ignore_lists/mac_list.json`:**
```json
{"ignore_macs": ["AA:BB:CC:DD:EE:FF"]}
```

**`ignore_lists/ssid_list.json`:**
```json
{"ignore_ssids": ["MeinHeimnetzwerk"]}
```

---

## Geplante Features

- [ ] Bluetooth-Korrelation (stabilere Geräteerkennung trotz MAC-Spoofing)
- [ ] WiGLE API Integration (SSID-Geolocation)
- [ ] GPS-KML Export (Google Earth Visualisierung)
- [ ] Hardware-Button Start/Stop
- [ ] Live-Display mit Echtzeit-Updates

---

## Getestet auf

- WiFi Pineapple Pager (OpenWrt 24.10.1, mipsel_24kc)
- Python 3.11.14
- u-blox GNSS Receiver (USB, gpsd 3.25)

---

## Rechtliches

Analysiert ausschließlich **öffentlich gesendete Funksignale** (Probe Requests im offenen ISM-Band 2.4/5 GHz). Keine Verbindungen, keine abgefangenen Daten, keine aktive Kontaktierung von Geräten. Nutzung auf eigene Verantwortung im Rahmen der geltenden Gesetze.

---

## Credits

- Original: [azmatt/chasing_your_tail](https://github.com/azmatt/chasing_your_tail)
- NG-Version: [ArgeliusLabs/Chasing-Your-Tail-NG](https://github.com/ArgeliusLabs/Chasing-Your-Tail-NG) – MIT
- Pineapple Pager Port: [tschakram](https://github.com/tschakram)
