# Chasing Your Tail NG - Pineapple Pager Payload 🔍

**Pineapple Pager Payload** | Kategorie: Reconnaissance  
Basiert auf: [ArgeliusLabs/Chasing-Your-Tail-NG](https://github.com/ArgeliusLabs/Chasing-Your-Tail-NG) (MIT)

Erkennt ob du verfolgt wirst – durch Analyse wiederkehrender WiFi-Probe-Requests via **Kismet** + optionaler **WiGLE**-Geolocation.

---

## Wie es funktioniert

1. **Dependency-Check** – fehlende Pakete werden automatisch via `opkg` auf der MMC installiert
2. **Kismet startet** – passiver Scan aller WiFi-Probe-Requests auf dem konfigurierten Interface
3. **Datensammlung** – konfigurierbare Scanzeit (Standard: 5 Minuten)
4. **Python-Analyse** – Persistence-Scoring über vier Zeitfenster (5/10/15/20 Min.)
5. **Report** – Markdown + KML-Visualisierung (Google Earth) unter `/root/loot/chasing_your_tail/`

---

## Dateistruktur

```
chasing_your_tail/
├── payload.sh                    ← Haupt-Script (hier starten)
├── config.json                   ← Deine lokale Konfiguration (nicht im Repo!)
├── config.example.json           ← Vorlage für config.json
├── .gitignore                    ← Schützt API-Keys und Loot vor git push
├── python/
│   ├── chasing_your_tail.py      ← Kern-Engine (Kismet DB → Persistence-Analyse)
│   ├── surveillance_analyzer.py  ← GPS-Korrelation + KML-Export
│   └── probe_analyzer.py         ← WiGLE-Integration + Probe-Statistiken
└── README.md
```

**Loot** (Ergebnisse) landet automatisch in:

```
/root/loot/chasing_your_tail/
├── logs/                    ← Payload-Logs
├── kismet_data/             ← Kismet .kismet SQLite-DBs
├── surveillance_reports/    ← Markdown Reports
├── kml_files/               ← Google Earth KML
├── reports/                 ← Probe-Analyse Reports
└── ignore_lists/            ← MAC/SSID Ignorier-Listen (JSON)
```

---

## Installation auf dem Pineapple Pager

**1. Payload-Ordner auf den Pager laden:**
```
/root/payloads/user/reconnaissance/chasing_your_tail/
```

**2. Ausführbar machen:**
```bash
chmod +x payload.sh python/*.py
```

**3. Konfiguration einrichten:**
```bash
cp config.example.json config.json
```
Dann `config.json` öffnen und Interface + optionale WiGLE-Keys eintragen.  
> ⚠️ `config.json` enthält deine API-Keys und wird **nicht** in Git eingecheckt (`.gitignore`).

**4. Über das Pager-Dashboard** unter Payloads starten.

---

## Abhängigkeiten (automatisch installiert)

| Paket | Zweck | Installation |
|-------|-------|--------------|
| `kismet` | WiFi Monitor-Mode Capture | `opkg install -d mmc kismet` |
| `python3` | Script-Runtime | `opkg install -d mmc python3` |
| `python3-sqlite3` | Kismet DB lesen | `opkg install -d mmc python3-sqlite3` |
| `iw` | Interface-Konfiguration | meist vorinstalliert |

> ⚠️ **Wichtig:** Pakete werden immer mit `-d mmc` auf die 4GB MMC-Partition installiert – nicht auf den begrenzten internen Flash-Speicher.

> ⚠️ **Nie** `opkg upgrade` ausführen – das kann den Pager beschädigen!

---

## Konfiguration

Kopiere zuerst die Vorlage:
```bash
cp config.example.json config.json
```

Dann passe `config.json` an:

```json
{
  "kismet": {
    "interface": "wlan1",          ← WiFi-Interface für Monitor-Mode
    "scan_duration_seconds": 300   ← Scandauer in Sekunden (Standard: 5 Min.)
  },
  "surveillance": {
    "persistence_threshold": 0.6,  ← Score ab dem gewarnt wird (0.0–1.0)
    "min_appearances": 3           ← Mindestanzahl Appearances für Wertung
  },
  "wigle": {
    "enabled": false,    ← true = WiGLE API nutzen (verbraucht Credits!)
    "api_name": "",      ← WiGLE API Name (von wigle.net)
    "api_token": ""      ← WiGLE API Token
  }
}
```

### WiGLE API einrichten (optional)

1. Account auf [wigle.net](https://wigle.net) erstellen
2. Unter **Account → API Token** einen Token generieren
3. `api_name` und `api_token` in `config.json` eintragen
4. `"enabled": true` setzen

---

## LED-Anzeige

| LED | Bedeutung |
|-----|-----------|
| 🔵 Cyan Blink | Dependency-Check läuft |
| 🔵 Blue Blink | Kismet / Python aktiv |
| 🟡 Amber Solid | ⚠️ Verdächtige Signale erkannt |
| 🟢 Green Solid | ✅ Scan abgeschlossen – keine Auffälligkeiten |
| 🔴 Red Blink | ❌ Fehler (Log unter `/root/loot/chasing_your_tail/logs/` prüfen) |

---

## OpenWrt-Kompatibilität

Die Python-Scripts wurden vollständig für OpenWrt (MIPS-Architektur) angepasst:

| Original | Pager-Anpassung |
|----------|----------------|
| `tkinter` GUI | Entfernt – reine Kommandozeile |
| `cryptography`-Paket | Entfernt – Credentials in `config.json` |
| `pip` / `pip3` | Ersetzt durch `opkg` |
| `numpy` / `scipy` | Ersetzt durch reines Python (Haversine) |
| `requests` | `urllib` (stdlib) als Fallback |
| `sqlite3` (extern) | stdlib-Version (immer verfügbar) |

---

## Ignore-Listen

Bekannte eigene Geräte können ignoriert werden um False Positives zu vermeiden.  
Die Listen werden automatisch unter `/root/loot/chasing_your_tail/ignore_lists/` angelegt.

**MAC-Adressen ignorieren** (`mac_list.json`):
```json
{
  "ignore_macs": [
    "AA:BB:CC:DD:EE:FF",
    "11:22:33:44:55:66"
  ]
}
```

**SSIDs ignorieren** (`ssid_list.json`):
```json
{
  "ignore_ssids": [
    "MeinHeimnetzwerk",
    "Büro-WLAN"
  ]
}
```

---

## Rechtliches

Dieses Tool analysiert ausschließlich **öffentlich gesendete Funksignale** (Probe Requests im offenen ISM-Band 2.4/5 GHz). Es werden keine Verbindungen aufgebaut, keine Daten abgefangen und keine Geräte aktiv kontaktiert. Nutzung auf eigene Verantwortung im Rahmen der geltenden Gesetze.

---

## Credits

- Original: [azmatt/chasing_your_tail](https://github.com/azmatt/chasing_your_tail)
- NG-Version: [ArgeliusLabs/Chasing-Your-Tail-NG](https://github.com/ArgeliusLabs/Chasing-Your-Tail-NG) – MIT Lizenz
- Pineapple Pager Port: [tschakram](https://github.com/tschakram)
