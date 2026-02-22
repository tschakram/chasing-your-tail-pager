#!/usr/bin/env python3
"""
pcap_engine.py - Pineapple Pager Edition
Ersetzt Kismet-DB durch direktes PCAP-Lesen.
Nur Python stdlib - kein scapy, kein pyshark.
"""

import struct
import os
import json
import logging
from collections import defaultdict
from datetime import datetime

log = logging.getLogger('CYT-PCAP')

def read_pcap_probes(filepath):
    """
    Liest Probe-Requests direkt aus PCAP-Datei.
    Gibt {mac: {count, first_seen, last_seen, ssids}} zurück.
    """
    devices = defaultdict(lambda: {
        'count': 0,
        'first_seen': None,
        'last_seen': None,
        'ssids': set()
    })

    if not os.path.exists(filepath):
        log.error(f"PCAP nicht gefunden: {filepath}")
        return {}

    try:
        with open(filepath, 'rb') as f:
            # Global Header
            magic = f.read(4)
            if magic == b'\xd4\xc3\xb2\xa1':
                endian = '<'
            elif magic == b'\xa1\xb2\xc3\xd4':
                endian = '>'
            else:
                log.error("Ungültiges PCAP-Format")
                return {}

            f.read(20)  # Rest Global Header

            while True:
                hdr = f.read(16)
                if len(hdr) < 16:
                    break

                ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
                    endian + 'IIII', hdr
                )
                data = f.read(incl_len)
                if len(data) < incl_len:
                    break

                # Radiotap Header überspringen
                if len(data) < 4:
                    continue
                rt_len = struct.unpack('<H', data[2:4])[0]
                dot11 = data[rt_len:]

                # Probe Request = Frame Control 0x40
                if len(dot11) < 16 or dot11[0] != 0x40:
                    continue

                # Source MAC (Bytes 10-15)
                mac = ':'.join(f'{b:02x}' for b in dot11[10:16])

                # SSID aus Tagged Parameters (nach Fixed Parameters)
                # Fixed Params bei Probe Request: 4 Bytes
                # Danach Tagged: Tag-ID(1) + Länge(1) + Wert
                ssid = ''
                if len(dot11) > 28:
                    tag_start = 28  # 4 Bytes Fixed nach MAC-Feldern (24B)
                    try:
                        tag_id = dot11[tag_start]
                        tag_len = dot11[tag_start + 1]
                        if tag_id == 0 and tag_len > 0:
                            ssid_bytes = dot11[tag_start+2:tag_start+2+tag_len]
                            ssid = ssid_bytes.decode('utf-8', errors='ignore').strip()
                    except (IndexError, UnicodeDecodeError):
                        pass

                # Gerät speichern
                devices[mac]['count'] += 1
                if devices[mac]['first_seen'] is None:
                    devices[mac]['first_seen'] = ts_sec
                devices[mac]['last_seen'] = ts_sec
                if ssid:
                    devices[mac]['ssids'].add(ssid)

    except Exception as e:
        log.error(f"PCAP-Lesefehler: {e}")

    # Sets zu Listen
    result = {}
    for mac, data in devices.items():
        result[mac] = {
            'count': data['count'],
            'first_seen': data['first_seen'],
            'last_seen': data['last_seen'],
            'ssids': list(data['ssids']),
            'appearances': data['count']
        }

    log.info(f"PCAP gelesen: {len(result)} Geräte gefunden")
    return result


def analyze_persistence(*scans, threshold=0.6, min_appearances=2):
    """
    Vergleicht mehrere Scans und berechnet Persistence-Score.
    Score = Anteil der Scans in dem das Gerät sichtbar war.
    """
    scans = [s for s in scans if s]
    all_macs = set()
    for scan in scans:
        all_macs.update(scan.keys())

    scored = {}
    for mac in all_macs:
        present = sum(1 for scan in scans if mac in scan)
        score = present / len(scans)
        total_appearances = sum(
            scan.get(mac, {}).get('count', 0) for scan in scans
        )
        all_ssids = set()
        for scan in scans:
            if mac in scan:
                all_ssids.update(scan[mac].get('ssids', []))

        if total_appearances >= min_appearances:
            scored[mac] = {
                'persistence_score': round(score, 3),
                'appearances': total_appearances,
                'present_in_windows': present,
                'total_windows': len(scans),
                'ssids': list(all_ssids),
                'suspicious': score >= threshold
            }

    suspicious = {m: d for m, d in scored.items() if d['suspicious']}
    return scored, suspicious
