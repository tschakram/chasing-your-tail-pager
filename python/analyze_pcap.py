#!/usr/bin/env python3
"""
analyze_pcap.py - Hauptanalyse auf Basis von PCAP-Dateien.
Nutzt pcap_engine.py für das Lesen, erstellt Reports.
"""
import os, sys, json, logging, argparse
from datetime import datetime
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pcap_engine import read_pcap_probes, analyze_persistence
from oui_lookup import load_oui_db, lookup

log = logging.getLogger('CYT-Analyze')

def load_ignore_lists(config):
    """Lädt MAC und SSID Ignore-Listen aus config."""
    ignore_macs  = set()
    ignore_ssids = set()

    # Aus config.json Pfade lesen
    mac_file  = config.get('paths', {}).get('ignore_lists', {}).get(
        'mac',  '/root/loot/chasing_your_tail/ignore_lists/mac_list.json')
    ssid_file = config.get('paths', {}).get('ignore_lists', {}).get(
        'ssid', '/root/loot/chasing_your_tail/ignore_lists/ssid_list.json')

    if os.path.exists(mac_file):
        with open(mac_file) as f:
            data = json.load(f)
        ignore_macs = set(m.lower() for m in data.get('ignore_macs', []))
        log.info(f'Ignore-MACs geladen: {len(ignore_macs)}')

    if os.path.exists(ssid_file):
        with open(ssid_file) as f:
            data = json.load(f)
        ignore_ssids = set(s.lower() for s in data.get('ignore_ssids', []))
        log.info(f'Ignore-SSIDs geladen: {len(ignore_ssids)}')

    return ignore_macs, ignore_ssids

def filter_scans(scans, ignore_macs, ignore_ssids):
    """Entfernt ignorierte MACs und SSIDs aus allen Scans."""
    filtered = []
    total_removed = 0

    for scan in scans:
        clean = {}
        for mac, data in scan.items():
            # MAC prüfen
            if mac.lower() in ignore_macs:
                total_removed += 1
                continue

            # SSIDs filtern
            clean_ssids = {
                s for s in data.get('ssids', set())
                if s.lower() not in ignore_ssids
            }

            clean[mac] = {**data, 'ssids': clean_ssids}

        filtered.append(clean)

    if total_removed:
        log.info(f'{total_removed} Einträge durch Ignore-Liste gefiltert')

    return filtered

def save_report(scored, suspicious, output_dir, ignore_macs, bt_devices=None, oui_db=None):
    os.makedirs(output_dir, exist_ok=True)
    ts   = datetime.now().strftime('%Y%m%d_%H%M%S')
    path = os.path.join(output_dir, f'cyt_report_{ts}.md')

    with open(path, 'w') as f:
        f.write('# Chasing Your Tail NG - Report\n\n')
        f.write(f'**Datum:** {datetime.now().strftime("%d.%m.%Y %H:%M:%S")}  \n')
        f.write(f'**Geräte gesamt:** {len(scored)}  \n')
        f.write(f'**Verdächtig:** {len(suspicious)}  \n')
        if ignore_macs:
            f.write(f'**Ignoriert:** {len(ignore_macs)} MACs  \n')
        f.write('\n')

        if suspicious:
            f.write('## ⚠️ WARNING - Verdächtige Geräte\n\n')
            f.write('| MAC | Hersteller | Score | Appearances |\n')
            f.write('|-----|------------|-------|-------------|\n')
            for mac, d in sorted(suspicious.items(),
                                 key=lambda x: x[1]['persistence_score'],
                                 reverse=True):
                vendor = lookup(mac, oui_db) if oui_db else '?'
                f.write(f'| `{mac}` | {vendor} | {d["persistence_score"]:.2f} | '
                        f'{d["appearances"]} |\n')
        else:
            f.write('## ✅ Keine verdächtigen Geräte erkannt\n\n')

        f.write('\n## Alle Geräte\n\n')
        f.write('| MAC | Hersteller | Score | Appearances | Fenster |\n')
        f.write('|-----|------------|-------|-------------|--------|\n')
        for mac, d in sorted(scored.items(),
                             key=lambda x: x[1]['persistence_score'],
                             reverse=True):
            flag = '🔴' if d['suspicious'] else '🟢'
            vendor = lookup(mac, oui_db) if oui_db else '?'
            f.write(f'| {flag} `{mac}` | {vendor} | {d["persistence_score"]:.2f} | '
                    f'{d["appearances"]} | '
                    f'{d["present_in_windows"]}/{d["total_windows"]} |\n')

        if ignore_macs:
            f.write('\n## Ignorierte Geräte\n\n')
            for mac in sorted(ignore_macs):
                f.write(f'- `{mac}`\n')

        if bt_devices:
            f.write('\n## Bluetooth Geräte\n\n')
            f.write('| MAC | Name | Typ | Korrelation WiFi |\n')
            f.write('|-----|------|-----|---------------------|\n')
            for mac, d in bt_devices.items():
                # OUI-Match mit verdächtigen WiFi-Geräten prüfen
                corr = '-'
                for wmac in suspicious:
                    if mac[:8].lower() == wmac[:8].lower():
                        corr = f'⚠️ OUI-Match: `{wmac}`'
                        break
                    if mac.lower() == wmac.lower():
                        corr = f'🔴 Exakt: `{wmac}`'
                        break
                f.write(f'| `{mac}` | {d.get("name","?")} | '
                        f'{d.get("type","?")} | {corr} |\n')

    log.info(f'Report: {path}')
    return path

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--pcaps', required=True)
    parser.add_argument('--config', default='config.json')
    parser.add_argument('--output-dir',
                        default='/root/loot/chasing_your_tail/surveillance_reports')
    parser.add_argument('--threshold', type=float, default=None)
    parser.add_argument('--min-appearances', type=int, default=None)
    parser.add_argument('--log-file')
    parser.add_argument('--bt-scans', default=None,
                        help='Kommagetrennte BT-Scan JSON-Dateien')
    args = parser.parse_args()

    handlers = [logging.StreamHandler()]
    if args.log_file:
        os.makedirs(os.path.dirname(args.log_file), exist_ok=True)
        handlers.append(logging.FileHandler(args.log_file))
    logging.basicConfig(level=logging.INFO,
                        format='[%(asctime)s] %(levelname)s %(message)s',
                        handlers=handlers)

    config = {}
    if os.path.exists(args.config):
        with open(args.config) as f:
            config = json.load(f)

    threshold = args.threshold or \
        config.get('surveillance', {}).get('persistence_threshold', 0.6)
    min_app = args.min_appearances or \
        config.get('surveillance', {}).get('min_appearances', 2)

    # OUI-Datenbank laden
    oui_db = load_oui_db()

    # BT-Scans laden
    bt_devices_all = {}
    if args.bt_scans:
        for bt_file in [f.strip() for f in args.bt_scans.split(',') if f.strip()]:
            if os.path.exists(bt_file):
                with open(bt_file) as f:
                    bt_data = json.load(f)
                bt_devices_all.update(bt_data.get('bt_devices', {}))
        log.info(f'BT-Geräte geladen: {len(bt_devices_all)}')

    # Ignore-Listen laden
    ignore_macs, ignore_ssids = load_ignore_lists(config)

    # PCAP-Dateien lesen
    pcap_files = [p.strip() for p in args.pcaps.split(',') if p.strip()]
    log.info(f'{len(pcap_files)} PCAP-Datei(en) werden analysiert')

    scans = [read_pcap_probes(p) for p in pcap_files]
    if not any(scans):
        log.warning('Keine Daten gefunden.')
        sys.exit(0)

    # Ignorierte Geräte herausfiltern
    scans = filter_scans(scans, ignore_macs, ignore_ssids)

    scored, suspicious = analyze_persistence(
        *scans, threshold=threshold, min_appearances=min_app
    )

    log.info(f'Geräte gesamt: {len(scored)} | Verdächtig: {len(suspicious)}')
    save_report(scored, suspicious, args.output_dir, ignore_macs, bt_devices_all, oui_db)
    sys.exit(2 if suspicious else 0)

if __name__ == '__main__':
    main()
