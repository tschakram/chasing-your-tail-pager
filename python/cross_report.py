#!/usr/bin/env python3
"""
cross_report.py — Cross-Report MAC Persistenz-Analyse
v1.0: Findet MACs die über mehrere unabhängige Scans hinweg persistieren,
      gewichtet nach GPS-Ortswechsel (Haversine).

Ausgabe:
  CROSS_REPORT_PATH:/pfad/zur/datei  (für payload.sh)
  CROSS_SUMMARY:N_kritisch/N_gesamt  (für LOG)
"""

import argparse
import re
import math
import os
import sys
import json
from datetime import datetime, timedelta
from collections import defaultdict

RAT_HISTORY_FILE = "/root/loot/raypager/rat_history.json"


# ── Haversine ─────────────────────────────────────────────────────────────────
def haversine(lat1, lon1, lat2, lon2):
    R = 6371000
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


# ── GPS Track ─────────────────────────────────────────────────────────────────
def load_gps_track(path):
    """Lädt gps_track.csv → [(datetime, lat, lon)]"""
    entries = []
    if not path or not os.path.exists(path):
        return entries
    with open(path) as f:
        for line in f:
            parts = line.strip().split(',')
            if len(parts) < 3:
                continue
            try:
                ts = datetime.strptime(parts[0], '%Y%m%d_%H%M%S')
                lat, lon = float(parts[1]), float(parts[2])
                if lat == 0.0 and lon == 0.0:
                    continue
                entries.append((ts, lat, lon))
            except (ValueError, IndexError):
                continue
    return entries


def find_nearest_gps(report_ts, gps_track, max_delta_sec=900):
    """Nächster GPS-Fix zu einem Report-Timestamp (max 15 min Abstand)."""
    best, best_delta = None, float('inf')
    for gts, lat, lon in gps_track:
        delta = abs((report_ts - gts).total_seconds())
        if delta < best_delta:
            best_delta = delta
            best = (lat, lon)
    return best if best_delta <= max_delta_sec else None


# ── Report Parser ─────────────────────────────────────────────────────────────
def parse_report_ts(filename):
    m = re.search(r'(\d{8}_\d{6})', os.path.basename(filename))
    if not m:
        return None
    try:
        return datetime.strptime(m.group(1), '%Y%m%d_%H%M%S')
    except ValueError:
        return None


def parse_report_macs(filepath):
    """
    Extrahiert MACs aus Report-Markdown.
    Gibt dict: {mac: {'vendor': str, 'scan_type': 'wifi'|'ble', 'risk': 'high'|'low'}}
    """
    macs = {}
    try:
        with open(filepath) as f:
            content = f.read()
    except OSError:
        return macs

    # WiFi — "Alle Geräte" Tabelle: | 🔴/🟢 `mac` | vendor | ...
    for m in re.finditer(
        r'\|\s*(🔴|🟢)\s*`([0-9a-f:]{17})`\s*\|\s*([^|]*)\|',
        content
    ):
        flag, mac, vendor = m.group(1), m.group(2).lower(), m.group(3).strip()
        macs[mac] = {
            'vendor': vendor,
            'scan_type': 'wifi',
            'risk': 'high' if flag == '🔴' else 'low',
        }

    # BLE — "Bluetooth Geräte" Tabelle: | `mac` | name | typ | 🔴/🟢 risk | ...
    for m in re.finditer(
        r'\|\s*`([0-9a-f:]{17})`\s*\|[^|]*\|[^|]*\|\s*(🔴|🟢)\s*(high|medium|none|low)',
        content
    ):
        mac = m.group(1).lower()
        risk = m.group(3)
        if mac not in macs:
            macs[mac] = {
                'vendor': '',
                'scan_type': 'ble',
                'risk': 'high' if risk in ('high', 'medium') else 'low',
            }

    return macs


# ── Standort-Clustering ───────────────────────────────────────────────────────
def distinct_locations(coords, min_dist_m):
    """Anzahl Standort-Cluster (Haversine < min_dist_m = gleicher Ort)."""
    clusters = []
    for lat, lon in coords:
        if not any(haversine(lat, lon, c[0], c[1]) < min_dist_m for c in clusters):
            clusters.append((lat, lon))
    return len(clusters), clusters


# ── Cell-Anomalien aus RAT-History ───────────────────────────────────────────

def load_rat_anomalies(hours):
    """Lädt RAT-Downgrades und No-Encryption Events aus rat_history.json."""
    anomalies = []
    cutoff = datetime.utcnow().timestamp() - hours * 3600
    try:
        with open(RAT_HISTORY_FILE) as f:
            history = json.load(f)
    except (OSError, json.JSONDecodeError):
        return anomalies
    for entry in history:
        ts = entry.get("ts", 0)
        if ts < cutoff:
            continue
        if entry.get("downgrade"):
            anomalies.append({
                "ts":      datetime.utcfromtimestamp(ts),
                "type":    "RAT_DOWNGRADE",
                "detail":  f"{entry.get('prev_rat','?')} → {entry.get('rat','?')}",
                "rat":     entry.get("rat"),
                "cipher":  entry.get("ciphering"),
                "cipher_label": entry.get("ciphering_label", ""),
            })
        elif entry.get("rat") == "GSM":
            c = entry.get("ciphering")
            if c is not None and c <= 1:
                anomalies.append({
                    "ts":     datetime.utcfromtimestamp(ts),
                    "type":   "WEAK_ENCRYPTION" if c == 1 else "NO_ENCRYPTION",
                    "detail": entry.get("ciphering_label", f"A5/{c}"),
                    "rat":    "GSM",
                    "cipher": c,
                    "cipher_label": entry.get("ciphering_label", ""),
                })
        # Extended anomalies from imsi_monitor.py (raypager v1.2+)
        ta = entry.get("ta")
        rsrp = entry.get("rsrp")
        if ta == 0 and rsrp is not None and rsrp < -100:
            anomalies.append({
                "ts":     datetime.utcfromtimestamp(ts),
                "type":   "TA_ANOMALY",
                "detail": f"TA=0 with RSRP {rsrp} dBm (spoofed proximity)",
                "rat":    entry.get("rat"),
                "cipher": entry.get("ciphering"),
                "cipher_label": entry.get("ciphering_label", ""),
            })
        if entry.get("tac_change"):
            anomalies.append({
                "ts":     datetime.utcfromtimestamp(ts),
                "type":   "TAC_CHANGE",
                "detail": f"Same CID {entry.get('cell_id','?')} but TAC changed (cell clone?)",
                "rat":    entry.get("rat"),
                "cipher": entry.get("ciphering"),
                "cipher_label": entry.get("ciphering_label", ""),
            })
        if entry.get("neighbors_vanished"):
            anomalies.append({
                "ts":     datetime.utcfromtimestamp(ts),
                "type":   "NEIGHBORS_VANISHED",
                "detail": "Neighbor cells disappeared (fake BTS signature)",
                "rat":    entry.get("rat"),
                "cipher": entry.get("ciphering"),
                "cipher_label": entry.get("ciphering_label", ""),
            })
        if entry.get("cell_id_zero"):
            anomalies.append({
                "ts":     datetime.utcfromtimestamp(ts),
                "type":   "CELL_ID_ZERO",
                "detail": "Cell ID reported as 0 (spoofed identifier)",
                "rat":    entry.get("rat"),
                "cipher": entry.get("ciphering"),
                "cipher_label": entry.get("ciphering_label", ""),
            })
    return anomalies


# ── Silent SMS events ─────────────────────────────────────────────────────────
SILENT_SMS_FILE = "/root/loot/raypager/silent_sms.jsonl"


def load_silent_sms(hours):
    """Load flagged SMS from silent_sms.jsonl within the last `hours`."""
    out = []
    cutoff = datetime.utcnow().timestamp() - hours * 3600
    try:
        with open(SILENT_SMS_FILE) as f:
            for line in f:
                try:
                    e = json.loads(line)
                    ts_str = e.get("timestamp", "").rstrip("Z")
                    ts = datetime.fromisoformat(ts_str).timestamp()
                    if ts < cutoff:
                        continue
                    out.append({
                        "ts":     datetime.utcfromtimestamp(ts),
                        "flags":  e.get("flags", []),
                        "sender": e.get("sender"),
                        "tp_pid": e.get("tp_pid"),
                        "tp_dcs": e.get("tp_dcs"),
                    })
                except (ValueError, KeyError):
                    continue
    except (OSError, json.JSONDecodeError):
        pass
    return out


# ── Hauptanalyse ──────────────────────────────────────────────────────────────
def analyze(report_dir, gps_track_path, hours, min_reports, min_dist_m, output):
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    gps_track = load_gps_track(gps_track_path)

    # Reports im Zeitfenster laden
    patterns = ('argus_report_', 'cyt_report_', 'hotel_scan_')
    candidates = sorted([
        os.path.join(report_dir, f)
        for f in os.listdir(report_dir)
        if f.endswith('.md') and any(f.startswith(p) for p in patterns)
    ])

    reports = []
    for rf in candidates:
        ts = parse_report_ts(rf)
        if ts is None or ts < cutoff:
            continue
        macs = parse_report_macs(rf)
        gps = find_nearest_gps(ts, gps_track) if gps_track else None
        reports.append({'file': rf, 'ts': ts, 'macs': macs, 'gps': gps})

    n_reports = len(reports)
    rat_anomalies = load_rat_anomalies(hours)

    if n_reports < 2:
        msg = (
            f'# 🔍 Cross-Report Persistenz-Analyse\n\n'
            f'**Reports im Zeitfenster ({hours:.0f}h):** {n_reports}  \n'
            f'ℹ️ Mindestens 2 Reports für Analyse nötig — weiterer Scan erforderlich.\n'
        )
        _write(output, msg)
        print(f'CROSS_SUMMARY:0/{n_reports}')
        return

    # MAC-Sichtungen aggregieren
    mac_data = defaultdict(list)
    for r in reports:
        for mac, info in r['macs'].items():
            mac_data[mac].append({
                'ts': r['ts'],
                'gps': r['gps'],
                'risk': info['risk'],
                'scan_type': info['scan_type'],
                'vendor': info['vendor'],
                'report': os.path.basename(r['file']),
            })

    # Filtern und bewerten
    results = []
    for mac, sightings in mac_data.items():
        if len(sightings) < min_reports:
            continue

        coords = [(s['gps'][0], s['gps'][1]) for s in sightings if s['gps']]
        n_locs, loc_clusters = distinct_locations(coords, min_dist_m) if coords else (0, [])
        has_gps = len(coords) > 0

        risks = [s['risk'] for s in sightings]
        top_risk = 'high' if 'high' in risks else 'low'
        vendor = next((s['vendor'] for s in sightings if s['vendor']), 'Unbekannt')
        scan_type = sightings[0]['scan_type']

        results.append({
            'mac': mac,
            'vendor': vendor,
            'scan_type': scan_type,
            'top_risk': top_risk,
            'count': len(sightings),
            'n_locs': n_locs,
            'has_gps': has_gps,
            'sightings': sightings,
            'loc_clusters': loc_clusters,
        })

    # Sortieren: multi-Ort zuerst, dann count
    results.sort(key=lambda x: (x['n_locs'], x['count']), reverse=True)

    critical = [r for r in results if r['n_locs'] >= 2]
    persistent = [r for r in results if r['n_locs'] < 2]

    # Korrelation: Cell-Anomalie ± 5min mit verdächtigen MACs
    correlated = []
    for anom in rat_anomalies:
        anom_ts = anom["ts"]
        coincident_macs = []
        for r in reports:
            if abs((r["ts"] - anom_ts).total_seconds()) <= 300:
                high_macs = [m for m, d in r["macs"].items() if d["risk"] == "high"]
                coincident_macs.extend(high_macs)
        if coincident_macs:
            correlated.append({**anom, "macs": list(set(coincident_macs))})
        else:
            correlated.append({**anom, "macs": []})

    # Report generieren
    n_cell_critical = sum(1 for a in correlated if a["type"] in ("RAT_DOWNGRADE", "NO_ENCRYPTION"))
    now_str = datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')
    lines = [
        '# 🔍 Cross-Report Persistenz-Analyse',
        '',
        f'**Erstellt:** {now_str}  ',
        f'**Zeitfenster:** letzte {hours:.0f}h  ',
        f'**Analysierte Reports:** {n_reports}  ',
        f'**Geräte mit GPS-Ortswechsel:** {len(critical)}  ',
        f'**Cell-Anomalien:** {len(rat_anomalies)} '
        f'(davon {n_cell_critical} kritisch)  ',
        '',
    ]

    if not results:
        lines.append('## ✅ Keine persistenten Geräte im Zeitfenster')

    if critical:
        lines += [
            '## 🔴 KRITISCH — Geräte an mehreren Orten gesehen',
            '',
            '> Diese Geräte wurden an mindestens 2 verschiedenen GPS-Positionen '
            f'(>{min_dist_m:.0f}m Abstand) detektiert — starker Beschattungs-Indikator.',
            '',
        ]
        for r in critical:
            lines += [
                f"### `{r['mac']}` — {r['vendor']}",
                f"- **Typ:** {r['scan_type'].upper()} | **Risiko:** {r['top_risk']}",
                f"- **Sichtungen:** {r['count']}/{n_reports} Reports",
                f"- **Distinct Orte:** {r['n_locs']} (GPS-bestätigt)",
                f"- **Gesehen in:**",
            ]
            for s in r['sightings']:
                gps_str = f"{s['gps'][0]:.5f},{s['gps'][1]:.5f}" if s['gps'] else 'kein GPS'
                lines.append(
                    f"  - {s['ts'].strftime('%H:%M')} | {gps_str} | {s['report']}"
                )
            lines.append('')

    if persistent:
        lines += [
            '## ⚠️ Persistent — ein Ort oder kein GPS',
            '',
            '| MAC | Hersteller | Typ | Sichtungen | Orte |',
            '|-----|------------|-----|------------|------|',
        ]
        for r in persistent:
            loc_str = str(r['n_locs']) if r['has_gps'] else '? (kein GPS)'
            lines.append(
                f"| `{r['mac']}` | {r['vendor'] or '?'} | "
                f"{r['scan_type']} | {r['count']}/{n_reports} | {loc_str} |"
            )
        lines.append('')

    # ── Cell-Anomalien Sektion ────────────────────────────────────────────────
    if correlated:
        lines += ['', '## 📡 Cell-Anomalien', '']
        for anom in correlated:
            ts_str = anom["ts"].strftime('%H:%M')
            high_sev = anom["type"] in (
                "RAT_DOWNGRADE", "NO_ENCRYPTION",
                "NEIGHBORS_VANISHED", "TAC_CHANGE",
            )
            icon = "🔴" if high_sev else "🟡"
            lines.append(f"### {icon} {anom['type']} — {ts_str}")
            lines.append(f"- **Detail:** {anom['detail']}")
            if anom["type"] == "RAT_DOWNGRADE":
                lines.append(
                    "- **Bewertung:** Klassisches IMSI-Catcher-Muster — "
                    "Tower erzwingt Downgrade auf schwächeres Netz"
                )
            elif anom["type"] == "NO_ENCRYPTION":
                lines.append(
                    "- **Bewertung:** 🚨 KRITISCH — Verbindung vollständig unverschlüsselt, "
                    "Inhalt kann mitgeschnitten werden"
                )
            elif anom["type"] == "TA_ANOMALY":
                lines.append(
                    "- **Bewertung:** Timing Advance=0 trotz schwachem Signal — "
                    "Tower täuscht Nähe vor (typisch für stationäre Fake-BTS)"
                )
            elif anom["type"] == "NEIGHBORS_VANISHED":
                lines.append(
                    "- **Bewertung:** 🚨 Nachbarzellen verschwunden — "
                    "klassische Fake-BTS-Signatur (isolierte Zelle zwingt Registrierung)"
                )
            elif anom["type"] == "TAC_CHANGE":
                lines.append(
                    "- **Bewertung:** 🚨 Gleiche Cell-ID, neue TAC — "
                    "möglicher Cell-Clone-Angriff"
                )
            elif anom["type"] == "CELL_ID_ZERO":
                lines.append(
                    "- **Bewertung:** Cell-ID = 0 ist in echten Netzen unüblich — "
                    "oft von Fake-BTS ohne gültige Identität"
                )
            if anom["macs"]:
                lines.append(
                    f"- **⚠️ Gleichzeitig verdächtige MACs ({len(anom['macs'])}):** "
                    + ", ".join(f"`{m}`" for m in anom["macs"])
                )
                lines.append("- **→ STARKE KORRELATION: Downgrade + Tracker gleichzeitig!**")
            else:
                lines.append("- *Keine gleichzeitigen MAC-Sichtungen im Zeitfenster*")
            lines.append('')
    elif rat_anomalies:
        lines += [
            '', '## 📡 Cell-Anomalien',
            '',
            f'ℹ️ {len(rat_anomalies)} Anomalie(n) gefunden, '
            'aber keine gleichzeitigen verdächtigen MAC-Sichtungen.',
            '',
        ]

    # ── Silent / Binary / OTA SMS Sektion ─────────────────────────────────────
    silent_sms = load_silent_sms(hours)
    if silent_sms:
        lines += ['', '## 📨 Covert SMS', '']
        for e in silent_sms:
            flags = ", ".join(e["flags"]) or "?"
            ts_str = e["ts"].strftime('%H:%M')
            sender = e.get("sender") or "unknown"
            icon = "🔴" if "SILENT_SMS" in e["flags"] or "SIM_DATA_DOWNLOAD" in e["flags"] else "🟡"
            lines.append(f"### {icon} {flags} — {ts_str}")
            lines.append(f"- **Absender:** `{sender}`")
            lines.append(f"- **TP-PID:** {e.get('tp_pid','?')}   **TP-DCS:** {e.get('tp_dcs','?')}")
            if "SILENT_SMS" in e["flags"]:
                lines.append(
                    "- **Bewertung:** Type-0 SMS ohne User-Display — "
                    "klassisches Überwachungswerkzeug zur Standortbestimmung"
                )
            if "SIM_DATA_DOWNLOAD" in e["flags"]:
                lines.append(
                    "- **Bewertung:** 🚨 OTA-Kommando zur SIM-Karte — "
                    "Provider oder Angreifer konfiguriert SIM remote"
                )
            if "BINARY_SMS" in e["flags"]:
                lines.append(
                    "- **Bewertung:** Binäre SMS — häufig STK-Kommando oder Tracking-Payload"
                )
            lines.append('')

    content = '\n'.join(lines) + '\n'
    _write(output, content)
    print(f'CROSS_REPORT_PATH:{output}')
    print(f'CROSS_SUMMARY:{len(critical)}/{len(results)}')


def _write(path, content):
    if path:
        with open(path, 'w') as f:
            f.write(content)
    else:
        sys.stdout.write(content)


# ── CLI ───────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    ap = argparse.ArgumentParser(description='Cross-Report MAC Persistenz-Analyse')
    ap.add_argument('--report-dir', required=True, help='Reports-Verzeichnis')
    ap.add_argument('--gps-track', default=None, help='Pfad zur gps_track.csv')
    ap.add_argument('--hours', type=float, default=4.0, help='Zeitfenster in Stunden')
    ap.add_argument('--min-reports', type=int, default=2, help='Min. Sichtungen')
    ap.add_argument('--min-distance', type=float, default=200.0, help='Min. Ortsdistanz (m)')
    ap.add_argument('--output', default=None, help='Ausgabedatei (.md)')
    args = ap.parse_args()

    analyze(
        report_dir=args.report_dir,
        gps_track_path=args.gps_track,
        hours=args.hours,
        min_reports=args.min_reports,
        min_dist_m=args.min_distance,
        output=args.output,
    )
