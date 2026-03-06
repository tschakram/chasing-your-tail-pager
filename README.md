# Chasing Your Tail NG - Pineapple Pager Payload 🔍

**Pineapple Pager Payload** | Category: Reconnaissance  
Based on: [ArgeliusLabs/Chasing-Your-Tail-NG](https://github.com/ArgeliusLabs/Chasing-Your-Tail-NG) (MIT)

> 🇩🇪 [Deutsche Version weiter unten](#deutsch)

---

## English

Detects whether you are being followed – by analysing recurring WiFi Probe Requests, optional Bluetooth scanning, GPS tracking, OUI vendor lookup and WiGLE geolocation.

> **v4.2:** Native Pineapple Pager Framework – no manual tcpdump, no custom channel hopping, no framebuffer hacking. Full Bluetooth + GPS + WiGLE integration.

---

### How it works

1. **Dependency check** – python3 installed automatically via `opkg` if missing
2. **Mode selection** – choose WiFi only, WiFi+GPS, WiFi+BT or all modules
3. **Configuration** – rounds and duration selectable via NUMBER_PICKER
4. **Channel hopping** – `PINEAPPLE_HOPPING_START` activates built-in hopping
5. **PCAP capture** – `WIFI_PCAP_START` captures Probe Requests natively
6. **BT scan** – parallel Bluetooth Classic + BLE scan (optional)
7. **GPS tracking** – coordinates saved per round (optional)
8. **Analysis** – persistence scoring, OUI vendor lookup, spoofed MAC detection
9. **WiGLE lookup** – MAC, BT address and probe SSIDs looked up in WiGLE
10. **Report** – result on display + Markdown report in `/root/loot/`

---

### Scan Modes

| Mode | Description |
|------|-------------|
| 0 | WiFi only |
| 1 | WiFi + GPS |
| 2 | WiFi + Bluetooth |
| 3 | All modules (WiFi + GPS + BT) |

---

### Installation

```bash
cd /root/payloads/user/reconnaissance/
git clone https://github.com/tschakram/chasing-your-tail-pager.git chasing_your_tail
cd chasing_your_tail
cp config.example.json config.json
```

> ⚠️ The payload **must** be launched from the **Pager Dashboard**:  
> `Payloads → User → Reconnaissance → Chasing Your Tail NG`  
> Do not run via `bash payload.sh` in SSH – Pager APIs only work in Dashboard context.

---

### File Structure

```
chasing_your_tail/
├── payload.sh              ← Main script
├── config.json             ← Local config (not in repo!)
├── config.example.json     ← Config template
├── ignore_lists/
│   ├── mac_list.json       ← MAC addresses to ignore
│   └── ssid_list.json      ← SSIDs to ignore
└── python/
    ├── pcap_engine.py      ← PCAP parser + persistence analysis
    ├── analyze_pcap.py     ← Main analysis + report generator
    ├── bt_scanner.py       ← Bluetooth Classic + BLE scanner
    ├── oui_lookup.py       ← Offline OUI vendor lookup (auto-update)
    └── wigle_lookup.py     ← WiGLE API integration
```

**Loot** is saved to:

```
/root/loot/chasing_your_tail/
├── pcap/                    ← PCAP files
├── surveillance_reports/    ← Markdown reports
├── gps_track.csv            ← GPS coordinates per round
├── bt_scan_*.json           ← Bluetooth scan results
├── oui_cache.json           ← OUI vendor cache
├── wigle_cache.json         ← WiGLE result cache
└── ignore_lists/            ← MAC/SSID ignore lists
```

---

### Report Contents

Each report includes per suspicious device:

- MAC address + **vendor** (OUI lookup)
- **MAC type** – global (real) or local/spoofed
- Persistence score + appearances
- **WiGLE results:**
  - WiFi MAC location (if found)
  - Bluetooth MAC location (if found)
  - Probe SSID locations (home network geolocation)

---

### Persistence Score

| Score | Meaning |
|-------|---------|
| 1.00 | Device seen in all scan rounds 🔴 |
| 0.50 | Device seen in half the rounds 🟡 |
| < 0.6 | Not suspicious 🟢 |

Default threshold: **0.6** (configurable in `config.json`)

---

### LED States

| LED | Meaning |
|-----|---------|
| 🔵 Cyan blink | Initialisation |
| 🔵 Blue blink | Scanning |
| 🟡 Amber | Analysis |
| 🟢 Green | ✅ Nothing suspicious |
| 🔴 Red blink | ⚠️ Suspicious devices detected |

---

### OUI Vendor Lookup

- Offline IEEE OUI database (~39,000 entries)
- Auto-update weekly when internet is available
- Works for both WiFi and Bluetooth MAC addresses

---

### WiGLE Integration (optional)

1. Create account at [wigle.net](https://wigle.net)
2. Go to **Account → API Token**
3. Add to `config.json`:

```json
{
  "wigle": {
    "enabled": true,
    "api_name": "YOUR_API_NAME",
    "api_token": "YOUR_API_TOKEN"
  }
}
```

---

### Ignore Lists

Add your own devices to avoid false positives:

**`ignore_lists/mac_list.json`:**
```json
{
  "ignore_macs": ["AA:BB:CC:DD:EE:FF"],
  "comments": {"AA:BB:CC:DD:EE:FF": "My Garmin GPS"}
}
```

---

### GPS Setup

- USB u-blox GNSS receiver or any gpsd-compatible device
- Cold start fix: ~2-5 minutes outdoors

```bash
GPS_CONFIGURE /dev/ttyACM0 9600
```

---

### Pager Framework APIs used

| API | Purpose |
|-----|---------|
| `LOG` | Display output |
| `GPS_GET` / `GPS_CONFIGURE` | GPS coordinates |
| `PINEAPPLE_HOPPING_START/STOP` | Channel hopping |
| `WIFI_PCAP_START/STOP` | Probe capture |
| `NUMBER_PICKER` | Interactive number input |
| `CONFIRMATION_DIALOG` | Yes/No prompt |
| `START_SPINNER / STOP_SPINNER` | Loading animation |
| `LED` | LED control |
| `VIBRATE` | Alert vibration |

---

### Legal

Analyses only **publicly broadcast radio signals** (Probe Requests on open ISM band 2.4/5 GHz). No connections established, no data intercepted, no active device contact. Use responsibly within applicable laws.

---

### Credits

- Original: [azmatt/chasing_your_tail](https://github.com/azmatt/chasing_your_tail)
- NG version: [ArgeliusLabs/Chasing-Your-Tail-NG](https://github.com/ArgeliusLabs/Chasing-Your-Tail-NG) – MIT
- Pineapple Pager port: [tschakram](https://github.com/tschakram)

---

---

<a name="deutsch"></a>
## 🇩🇪 Deutsch

Erkennt ob du verfolgt wirst – durch Analyse wiederkehrender WiFi-Probe-Requests, optionalen Bluetooth-Scan, GPS-Tracking, OUI-Herstellersuche und WiGLE-Geolokalisierung.

> **v4.2:** Natives Pineapple Pager Framework – kein manueller tcpdump, kein eigenes Channel-Hopping, kein Framebuffer-Hacking. Vollständige Bluetooth + GPS + WiGLE Integration.

---

### Wie es funktioniert

1. **Dependency-Check** – python3 wird automatisch via `opkg` installiert
2. **Modus-Auswahl** – nur WiFi, WiFi+GPS, WiFi+BT oder alle Module
3. **Konfiguration** – Runden und Dauer per NUMBER_PICKER wählbar
4. **Channel-Hopping** – `PINEAPPLE_HOPPING_START` aktiviert eingebautes Hopping
5. **PCAP-Capture** – `WIFI_PCAP_START` erfasst Probe-Requests nativ
6. **BT-Scan** – paralleler Bluetooth Classic + BLE Scan (optional)
7. **GPS-Tracking** – Koordinaten pro Runde gespeichert (optional)
8. **Analyse** – Persistence-Scoring, OUI-Herstellersuche, Spoofing-Erkennung
9. **WiGLE-Lookup** – MAC, BT-Adresse und Probe-SSIDs in WiGLE nachschlagen
10. **Report** – Ergebnis auf Display + Markdown-Report in `/root/loot/`

---

### Scan-Modi

| Modus | Beschreibung |
|-------|--------------|
| 0 | Nur WiFi |
| 1 | WiFi + GPS |
| 2 | WiFi + Bluetooth |
| 3 | Alle Module (WiFi + GPS + BT) |

---

### Installation

```bash
cd /root/payloads/user/reconnaissance/
git clone https://github.com/tschakram/chasing-your-tail-pager.git chasing_your_tail
cd chasing_your_tail
cp config.example.json config.json
```

> ⚠️ Der Payload **muss** über das **Pager-Dashboard** gestartet werden:  
> `Payloads → User → Reconnaissance → Chasing Your Tail NG`  
> Nicht über `bash payload.sh` in SSH – Pager-APIs funktionieren nur im Dashboard-Kontext.

---

### Report-Inhalt

Pro verdächtigem Gerät enthält der Report:

- MAC-Adresse + **Hersteller** (OUI-Lookup)
- **MAC-Typ** – global (echt) oder lokal/gespooft
- Persistence-Score + Erscheinungen
- **WiGLE-Ergebnisse:**
  - WiFi-MAC Standort (falls gefunden)
  - Bluetooth-MAC Standort (falls gefunden)
  - Probe-SSID Standorte (Heimnetz-Geolokalisierung)

---

### Geplante Features

- [ ] GPS-KML Export (Google Earth Visualisierung)
- [ ] WiGLE Upload eigener Scans
- [ ] Live-Display Echtzeit-Updates
- [ ] Mehrfach-Runden Zusammenfassung

---

### Getestet auf

- WiFi Pineapple Pager (OpenWrt 24.10.1, mipsel_24kc)
- Python 3.11.14
- u-blox GNSS Receiver (USB, gpsd 3.25)
- Bluetooth: hci0 (USB, BlueZ 5.72)
