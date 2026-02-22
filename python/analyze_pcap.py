#!/usr/bin/env python3
"""
analyze_pcap.py - Hauptanalyse auf Basis von PCAP-Dateien.
Nutzt pcap_engine.py für das Lesen, erstellt Reports.
"""

import os, sys, json, logging, argparse
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pcap_engine import read_pcap_probes, analyze_persistence

log = logging.getLogger('CYT-Analyze')

def save_report(scored, suspicious, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    path = os.path.join(output_dir, f'cyt_report_{ts}.md')

    with open(path, 'w') as f:
        f.write('# Chasing Your Tail NG - Report\n\n')
        f.write(f'**Datum:** {datetime.now().strftime("%d.%m.%Y %H:%M:%S")}  \n')
        f.write(f'**Geräte gesamt:** {len(scored)}  \n')
        f.write(f'**Verdächtig:** {len(suspicious)}  \n\n')

        if suspicious:
            f.write('## ⚠️ WARNING - Verdächtige Geräte\n\n')
            f.write('| MAC | Score | Appearances | SSIDs |\n')
            f.write('|-----|-------|-------------|-------|\n')
            for mac, d in sorted(suspicious.items(),
                                 key=lambda x: x[1]['persistence_score'],
                                 reverse=True):
                ssids = ', '.join(d['ssids']) or '-'
                f.write(f'| `{mac}` | {d["persistence_score"]:.2f} | '
                        f'{d["appearances"]} | {ssids} |\n')
        else:
            f.write('## ✅ Keine verdächtigen Geräte erkannt\n\n')

        f.write('\n## Alle Geräte\n\n')
        f.write('| MAC | Score | Appearances | Fenster |\n')
        f.write('|-----|-------|-------------|--------|\n')
        for mac, d in sorted(scored.items(),
                             key=lambda x: x[1]['persistence_score'],
                             reverse=True):
            flag = '🔴' if d['suspicious'] else '🟢'
            f.write(f'| {flag} `{mac}` | {d["persistence_score"]:.2f} | '
                    f'{d["appearances"]} | '
                    f'{d["present_in_windows"]}/{d["total_windows"]} |\n')

    log.info(f'Report: {path}')
    return path

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--pcaps', required=True,
                        help='Kommagetrennte PCAP-Dateipfade')
    parser.add_argument('--config', default='config.json')
    parser.add_argument('--output-dir',
                        default='/root/loot/chasing_your_tail/surveillance_reports')
    parser.add_argument('--log-file')
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

    threshold = config.get('surveillance', {}).get('persistence_threshold', 0.6)
    min_app = config.get('surveillance', {}).get('min_appearances', 2)

    # PCAP-Dateien lesen
    pcap_files = [p.strip() for p in args.pcaps.split(',') if p.strip()]
    log.info(f'{len(pcap_files)} PCAP-Datei(en) werden analysiert')

    scans = [read_pcap_probes(p) for p in pcap_files]

    if not any(scans):
        log.warning('Keine Daten in PCAP-Dateien gefunden.')
        sys.exit(0)

    scored, suspicious = analyze_persistence(
        *scans, threshold=threshold, min_appearances=min_app
    )

    log.info(f'Geräte gesamt: {len(scored)} | Verdächtig: {len(suspicious)}')
    save_report(scored, suspicious, args.output_dir)

    sys.exit(2 if suspicious else 0)

if __name__ == '__main__':
    main()
