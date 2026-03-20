#!/usr/bin/env python3
"""
camera_activity.py — Camera Activity Detection für Hotel-Scan v4.8
Erkennt ob verdächtige Kameras während des Scans aktiv waren,
anhand von Data-Frame-Bandbreite (bytes/s) im PCAP.

Inspiriert von MonitoRing (bennjordan/MonitoRing) — portiert auf
stdlib-only PCAP-Parsing (kein pyshark/scapy).

Input:
  --pcap        Kommaliste PCAP-Dateien (dieselben wie hotel_scan.py)
  --suspects    JSON-Datei mit verdächtigen BSSIDs aus hotel_scan.py
  --threshold   KB/s Schwellwert für "aktiv" (default: 200)
  --output-dir  Loot-Verzeichnis

Output (stdout, parsebar von payload.sh):
  ACTIVITY:<bssid>:<spike_count>:<max_kbps>
  ACTIVITY_SUMMARY:<N> Kameras aktiv während Scan
"""

import struct
import os
import sys
import json
import argparse
import logging
from collections import defaultdict
from datetime import datetime

log = logging.getLogger('CYT-Activity')


def analyze_camera_activity(pcap_files, suspect_bssids, threshold_kbps=200):
    """
    Scannt PCAP-Dateien nach Data-Frames von verdächtigen BSSIDs.
    Berechnet bytes/s pro Sekunde und erkennt Aktivitätsspikes.

    Returns: {bssid: {spikes, max_kbps, total_bytes, active_seconds, seconds}}
    """
    # Normalisiere BSSIDs zu lowercase
    targets = set(b.lower() for b in suspect_bssids)
    if not targets:
        return {}

    # bytes pro Sekunde pro BSSID sammeln
    # {bssid: {ts_sec: total_bytes}}
    traffic = defaultdict(lambda: defaultdict(int))

    for filepath in pcap_files:
        if not os.path.exists(filepath):
            log.warning(f'PCAP nicht gefunden: {filepath}')
            continue

        try:
            _read_data_frames(filepath, targets, traffic)
        except Exception as e:
            log.warning(f'PCAP-Lesefehler: {filepath}: {e}')

    # Auswertung pro BSSID
    threshold_bytes = threshold_kbps * 1024
    results = {}

    for bssid in targets:
        per_sec = traffic.get(bssid, {})
        if not per_sec:
            results[bssid] = {
                'spikes': 0, 'max_kbps': 0, 'total_bytes': 0,
                'active_seconds': 0, 'seconds': 0, 'active': False,
            }
            continue

        total_bytes = sum(per_sec.values())
        max_bytes = max(per_sec.values())
        max_kbps = round(max_bytes / 1024, 1)
        spikes = sum(1 for b in per_sec.values() if b > threshold_bytes)
        seconds = len(per_sec)

        results[bssid] = {
            'spikes': spikes,
            'max_kbps': max_kbps,
            'total_bytes': total_bytes,
            'active_seconds': spikes,
            'seconds': seconds,
            'active': spikes > 0,
        }

    return results


def _read_data_frames(filepath, targets, traffic):
    """
    Liest Data-Frames aus PCAP und summiert bytes/s pro BSSID.
    Data Frames: FC type == 0x08 (bits 2-3 of FC byte 0)
    QoS Data:    FC subtype 0x88
    """
    with open(filepath, 'rb') as f:
        magic = f.read(4)
        if magic == b'\xd4\xc3\xb2\xa1':
            endian = '<'
        elif magic == b'\xa1\xb2\xc3\xd4':
            endian = '>'
        else:
            log.error(f'Ungültiges PCAP-Format: {filepath}')
            return

        f.read(20)  # Rest Global Header

        while True:
            hdr = f.read(16)
            if len(hdr) < 16:
                break

            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
                endian + 'IIII', hdr
            )
            if incl_len > 0x40000:
                break
            data = f.read(incl_len)
            if len(data) < incl_len:
                break

            # Radiotap Header
            if len(data) < 4:
                continue
            rt_len = struct.unpack('<H', data[2:4])[0]
            if rt_len > len(data):
                continue
            dot11 = data[rt_len:]

            if len(dot11) < 24:
                continue

            fc = dot11[0]
            # Data frame: type == 10 (bits 3:2 of FC byte 0)
            # FC byte: B7 B6 B5 B4 B3 B2 B1 B0
            #          subtype      type   ver
            # type == 10 → Data frames → (fc & 0x0C) == 0x08
            if (fc & 0x0C) != 0x08:
                continue

            # To DS / From DS bits (FC byte 1, bits 0-1)
            fc1 = dot11[1]
            to_ds = fc1 & 0x01
            from_ds = (fc1 >> 1) & 0x01

            # Extrahiere BSSID und Source aus 802.11 Header
            # abhängig von To DS / From DS:
            #   To=0 From=0: Addr1=DA, Addr2=SA, Addr3=BSSID
            #   To=1 From=0: Addr1=BSSID, Addr2=SA, Addr3=DA
            #   To=0 From=1: Addr1=DA, Addr2=BSSID, Addr3=SA
            #   To=1 From=1: Addr1=RA, Addr2=TA, Addr3=DA, Addr4=SA
            if to_ds == 0 and from_ds == 1:
                # From DS: Addr2 = BSSID (Sender = AP/Kamera)
                bssid = ':'.join(f'{b:02x}' for b in dot11[10:16])
            elif to_ds == 1 and from_ds == 0:
                # To DS: Addr1 = BSSID
                bssid = ':'.join(f'{b:02x}' for b in dot11[4:10])
            elif to_ds == 0 and from_ds == 0:
                # IBSS: Addr3 = BSSID
                bssid = ':'.join(f'{b:02x}' for b in dot11[16:22])
            else:
                # WDS (to=1, from=1): skip
                continue

            if bssid not in targets:
                continue

            # Bytes dieses Frames zählen (orig_len = tatsächliche Größe)
            traffic[bssid][ts_sec] += orig_len


def save_activity_report(results, suspects_info, output_dir):
    """Speichert Activity-Ergebnisse als JSON."""
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    path = os.path.join(output_dir, f'camera_activity_{ts}.json')

    report = {
        'timestamp': datetime.now().isoformat(),
        'results': {},
    }
    for bssid, data in results.items():
        info = suspects_info.get(bssid, {})
        report['results'][bssid] = {
            **data,
            'ssid': info.get('ssid', ''),
            'vendor': info.get('vendor', ''),
        }

    with open(path, 'w') as f:
        json.dump(report, f, indent=2)
    log.info(f'Activity-Report: {path}')
    return path


def main():
    parser = argparse.ArgumentParser(
        description='Camera Activity Detection für Hotel-Scan'
    )
    parser.add_argument('--pcap', required=True,
                        help='PCAP-Datei(en), kommagetrennt')
    parser.add_argument('--suspects', required=True,
                        help='JSON-Datei mit verdächtigen BSSIDs')
    parser.add_argument('--threshold', type=int, default=200,
                        help='KB/s Schwellwert (default: 200)')
    parser.add_argument('--output-dir',
                        default='/root/loot/chasing_your_tail/surveillance_reports')
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] %(levelname)s %(message)s',
    )

    # PCAP-Dateien
    pcap_files = [p.strip() for p in args.pcap.split(',')
                  if p.strip() and os.path.exists(p.strip())]
    if not pcap_files:
        log.error('Keine gültigen PCAP-Dateien')
        sys.exit(1)

    # Suspects laden
    try:
        with open(args.suspects) as f:
            suspects_list = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        log.error(f'Suspects-Datei nicht lesbar: {e}')
        sys.exit(1)

    suspect_bssids = [s['bssid'] for s in suspects_list if 'bssid' in s]
    suspects_info = {s['bssid'].lower(): s for s in suspects_list if 'bssid' in s}

    if not suspect_bssids:
        print('ACTIVITY_SUMMARY:Keine Verdächtigen zu prüfen')
        sys.exit(0)

    # Analyse
    results = analyze_camera_activity(pcap_files, suspect_bssids, args.threshold)

    # Output für payload.sh
    active_count = 0
    for bssid, data in results.items():
        if data['active']:
            active_count += 1
            print(f"ACTIVITY:{bssid}:{data['spikes']}:{data['max_kbps']}")

    if active_count > 0:
        print(f'ACTIVITY_SUMMARY:{active_count} Kamera(s) aktiv während Scan')
    else:
        print('ACTIVITY_SUMMARY:Keine Kamera-Aktivität erkannt')

    # JSON-Report
    report_path = save_activity_report(results, suspects_info, args.output_dir)
    print(f'ACTIVITY_REPORT:{report_path}')


if __name__ == '__main__':
    main()
