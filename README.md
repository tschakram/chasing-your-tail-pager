# Chasing Your Tail NG - Pineapple Pager Payload 🔍

**Pineapple Pager Payload** | Kategorie: Reconnaissance  
Basiert auf: [ArgeliusLabs/Chasing-Your-Tail-NG](https://github.com/ArgeliusLabs/Chasing-Your-Tail-NG) (MIT)

Erkennt ob du verfolgt wirst – durch Analyse wiederkehrender WiFi-Probe-Requests via **tcpdump** + optionaler **WiGLE**-Geolocation.

> **v2.0:** Kismet wurde durch tcpdump ersetzt – leichter, stabiler, direkt auf dem Pager verfügbar.

---

## Wie es funktioniert

1. **Dependency-Check** – fehlende Pakete werden automatisch via `opkg` auf der MMC installiert
2. **Channel-Hopping** – `wlan1mon` springt automatisch durch alle 2.4GHz + 5GHz Kanäle
3. **Zwei Scan-Runden** – tcpdump erfasst passive Probe-Requests in PCAP-Dateien
4. **Python-Analyse** – Persistence-Scoring vergleicht beide Scans miteinander
5. **Report** – Markdown-Report unter `/root/loot/chasing_your_tail/`

### Warum tcpdump statt Kismet?

Kismet ist in den OpenWrt-Paketquellen des Pineapple Pagers nicht verfügbar. tcpdump ist vorinstalliert, leichtgewichtig und erfasst Probe-Requests genauso zuverlässig. Der eigene PCAP-Parser (`pcap_engine.py`) liest die Captures direkt – ohne externe Python-Bibliotheken.

---

## Dateistruktur

```
chasing_your_tail/
├── payload.sh                    ← Haupt-Script (hier starten)
├── config.json                   ← Deine lokale Konfiguration (nicht im Repo!)
├── config.example.json           ← Vorlage für config.json
├── .gitignore                    ← Schützt API-Keys und Loot vor git push
├── python/
│   ├── pcap_engine.py            ← PCAP-Parser + Persistence-Analyse (stdlib only)
│   ├── analyze_pcap.py           ← Haupt-Analyse + Report-Generator
│   ├── chasing_your_tail.py      ← Kern-Engine (Kismet-kompatibel, optional)
│   ├── surveillance_analyzer.py  ← GPS-Korrelation + KML-Export
│   └── probe_analyzer.py         ← WiGLE-Integration + Probe-Statistiken
└── README.md
```

**Loot** landet automatisch in:

```
/root/loot/chasing_your_tail/
├── logs/                    ← Payload-Logs
├── pcap/                    ← tcpdump PCAP-Dateien
├── surveillance_reports/    ← Markdown Reports
└── ignore_lists/            ← MAC/SSID Ignorier-Listen (JSON)
```

---

## Installation auf dem Pineapple Pager

**1. Repo klonen:**
```bash
cd /root/payloads/user/reconnaissance/
git clone https://github.com/tschakram/chasing-your-tail-pager.git chasing_your_tail
cd chasing_your_tail
```

**2. Konfiguration einrichten:**
```bash
cp config.example.json config.json
chmod +x payload.sh python/*.py
```

> ⚠️ `config.json` enthält deine API-Keys und wird **nicht** in Git eingecheckt (`.gitignore`).

**3. Starten:**
```bash
bash payload.sh
```

---

## Abhängigkeiten

| Paket | Zweck | Status |
|-------|-------|--------|
| `tcpdump` | Probe-Request Capture | ✅ Vorinstalliert |
| `python3` | Script-Runtime | Auto-Install via `opkg` |
| `iw` | Channel-Hopping | ✅ Vorinstalliert |

> ⚠️ Pakete werden mit `-d mmc` auf die 4GB MMC-Partition installiert – nicht auf den internen Flash.

> ⚠️ **Nie** `opkg upgrade` ausführen – das kann den Pager beschädigen!

---

## Konfiguration

```bash
cp config.example.json config.json
```

Dann `config.json` anpassen:

```json
{
  "kismet": {
    "interface": "wlan1mon",       ← Monitor-Mode Interface
    "scan_duration_seconds": 120   ← Scandauer pro Runde in Sekunden
  },
  "surveillance": {
    "persistence_threshold": 0.6,  ← Score ab dem gewarnt wird (0.0–1.0)
    "min_appearances": 2           ← Mindestanzahl Appearances
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

## Technischer Ablauf

```
payload.sh
    │
    ├── Dependency-Check (python3, tcpdump, iw)
    ├── Channel-Hopping starten (alle 0.3s, Kanäle 1-11 + 36,40,44,48)
    ├── Scan-Runde 1 → pcap/scan_*_round1.pcap
    ├── Scan-Runde 2 → pcap/scan_*_round2.pcap
    └── Python-Analyse
            ├── pcap_engine.py  → MACs + SSIDs extrahieren
            ├── analyze_pcap.py → Persistence-Score berechnen
            └── Report → surveillance_reports/cyt_report_*.md
```

### Persistence-Score

| Score | Bedeutung |
|-------|-----------|
| 1.00 | Gerät in allen Scan-Runden sichtbar 🔴 |
| 0.50 | Gerät in der Hälfte der Runden sichtbar 🟡 |
| < 0.6 | Unauffällig 🟢 |

---

## LED-Anzeige

| LED | Bedeutung |
|-----|-----------|
| 🔵 Cyan Blink | Initialisierung |
| 🔵 Blue Blink | Scanning läuft |
| 🟡 Amber Solid | ⚠️ Verdächtige Signale erkannt |
| 🟢 Green Solid | ✅ Keine Auffälligkeiten |
| 🔴 Red Blink | ❌ Fehler |

---

## OpenWrt-Kompatibilität

| Original CYT-NG | Pager-Anpassung |
|-----------------|----------------|
| Kismet | tcpdump + pcap_engine.py |
| `tkinter` GUI | Entfernt |
| `cryptography` | Entfernt – Credentials in config.json |
| `pip` | Ersetzt durch `opkg` |
| `numpy`/`scipy` | Reines Python (Haversine) |
| `requests` | `urllib` stdlib Fallback |

---

## Getestet auf

- WiFi Pineapple Pager (OpenWrt 24.10.1, mipsel_24kc)
- Python 3.11.14
- tcpdump 4.99.5

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

## Rechtliches

Analysiert ausschließlich **öffentlich gesendete Funksignale** (Probe Requests im offenen ISM-Band). Keine Verbindungen, keine abgefangenen Daten, keine aktive Kontaktierung von Geräten. Nutzung auf eigene Verantwortung.

---

## Credits

- Original: [azmatt/chasing_your_tail](https://github.com/azmatt/chasing_your_tail)
- NG-Version: [ArgeliusLabs/Chasing-Your-Tail-NG](https://github.com/ArgeliusLabs/Chasing-Your-Tail-NG) – MIT
- Pineapple Pager Port: [tschakram](https://github.com/tschakram)
