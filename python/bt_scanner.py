#!/usr/bin/env python3
"""
bt_scanner.py - Bluetooth Scanner für Chasing Your Tail NG
Scannt BT Classic + BLE Geräte und korreliert mit WiFi-Probes
"""
import subprocess, threading, time, logging, os, json
from datetime import datetime

log = logging.getLogger('CYT-BT')

# ============================================================
# BLUETOOTH SCANNER
# ============================================================

def scan_bt_classic(duration=10):
    """Scannt BT Classic Geräte via hcitool scan."""
    devices = {}
    try:
        result = subprocess.run(
            ['hcitool', 'scan', '--flush'],
            capture_output=True, text=True, timeout=duration+5
        )
        for line in result.stdout.strip().split('\n'):
            line = line.strip()
            if not line or line == 'Scanning ...':
                continue
            parts = line.split('\t')
            if len(parts) >= 2:
                mac  = parts[0].strip().lower()
                name = parts[1].strip() if len(parts) > 1 else ''
                if len(mac) == 17:
                    devices[mac] = {
                        'name': name,
                        'type': 'classic',
                        'rssi': None,
                        'first_seen': datetime.now().isoformat(),
                    }
                    log.info(f'BT Classic: {mac} ({name})')
    except subprocess.TimeoutExpired:
        pass
    except Exception as e:
        log.error(f'BT Classic Fehler: {e}')
    return devices

def scan_ble(duration=15):
    """Scannt BLE Geräte via hcitool lescan."""
    devices = {}
    try:
        proc = subprocess.Popen(
            ['hcitool', 'lescan', '--duplicates'],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )
        start = time.time()
        while time.time() - start < duration:
            line = proc.stdout.readline()
            if not line:
                break
            line = line.strip()
            if not line or line == 'LE Scan ...':
                continue
            parts = line.split(' ', 1)
            if len(parts) >= 1:
                mac  = parts[0].strip().lower()
                name = parts[1].strip() if len(parts) > 1 else ''
                if len(mac) == 17 and mac not in devices:
                    devices[mac] = {
                        'name': name,
                        'type': 'ble',
                        'rssi': None,
                        'first_seen': datetime.now().isoformat(),
                    }
                    log.info(f'BLE: {mac} ({name})')
        proc.terminate()
        proc.wait()
    except Exception as e:
        log.error(f'BLE Fehler: {e}')
    return devices

def scan_bluetooth(duration=15):
    """Scannt BT Classic und BLE parallel."""
    log.info('Starte Bluetooth-Scan...')

    results = {'classic': {}, 'ble': {}}

    # BT Classic + BLE parallel
    def run_classic():
        results['classic'] = scan_bt_classic(duration)

    def run_ble():
        results['ble'] = scan_ble(duration)

    t_classic = threading.Thread(target=run_classic, daemon=True)
    t_ble     = threading.Thread(target=run_ble, daemon=True)

    t_classic.start()
    t_ble.start()
    t_classic.join(timeout=duration+5)
    t_ble.join(timeout=duration+5)

    # Zusammenführen
    all_devices = {}
    all_devices.update(results['classic'])
    for mac, data in results['ble'].items():
        if mac not in all_devices:
            all_devices[mac] = data
        else:
            all_devices[mac]['type'] = 'classic+ble'

    log.info(f'BT-Scan: {len(all_devices)} Geräte gefunden '
             f'({len(results["classic"])} Classic, {len(results["ble"])} BLE)')
    return all_devices

# ============================================================
# KORRELATION WiFi <-> Bluetooth
# ============================================================

def correlate_wifi_bt(wifi_devices, bt_devices):
    """
    Korreliert WiFi-Probes mit Bluetooth-Geräten.

    Strategie:
    - Direkte MAC-Übereinstimmung (selten, da WiFi oft randomisiert)
    - OUI-Übereinstimmung (erste 3 Bytes) – gleicher Hersteller
    - Zeitliche Nähe (beide im gleichen Scan-Fenster gesehen)

    Returns:
        correlated: {mac: {wifi_data, bt_data, correlation_type}}
    """
    correlated   = {}
    wifi_oui_map = {mac[:8]: mac for mac in wifi_devices}
    bt_oui_map   = {mac[:8]: mac for mac in bt_devices}

    for bt_mac, bt_data in bt_devices.items():
        # 1. Direkte MAC-Übereinstimmung
        if bt_mac in wifi_devices:
            correlated[bt_mac] = {
                'bt':               bt_data,
                'wifi':             wifi_devices[bt_mac],
                'correlation_type': 'exact_mac',
                'confidence':       1.0,
            }
            log.info(f'Exakte Korrelation: {bt_mac} ({bt_data.get("name","")})')
            continue

        # 2. OUI-Übereinstimmung (gleicher Hersteller)
        bt_oui = bt_mac[:8]
        if bt_oui in wifi_oui_map:
            wifi_mac = wifi_oui_map[bt_oui]
            correlated[bt_mac] = {
                'bt':               bt_data,
                'wifi':             wifi_devices[wifi_mac],
                'wifi_mac':         wifi_mac,
                'correlation_type': 'oui_match',
                'confidence':       0.6,
            }
            log.info(f'OUI-Korrelation: BT {bt_mac} ↔ WiFi {wifi_mac}')

    return correlated

# ============================================================
# GPS
# ============================================================

def get_gps_position():
    """Liest GPS-Position via GPS_GET Pager-API."""
    try:
        result = subprocess.run(
            ['GPS_GET'], capture_output=True, text=True, timeout=5
        )
        parts = result.stdout.strip().split()
        if len(parts) >= 2:
            lat = float(parts[0])
            lon = float(parts[1])
            alt = float(parts[2]) if len(parts) > 2 else 0.0
            spd = float(parts[3]) if len(parts) > 3 else 0.0
            if lat != 0.0 or lon != 0.0:
                return {
                    'lat': lat, 'lon': lon,
                    'alt': alt, 'speed': spd,
                    'time': datetime.now().isoformat(),
                    'fix': True
                }
    except Exception as e:
        log.debug(f'GPS Fehler: {e}')
    return {'lat': 0, 'lon': 0, 'alt': 0, 'speed': 0,
            'time': datetime.now().isoformat(), 'fix': False}

def save_gps_track(gps_data, loot_dir):
    """Speichert GPS-Track als CSV."""
    track_file = os.path.join(loot_dir, 'gps_track.csv')
    write_header = not os.path.exists(track_file)

    with open(track_file, 'a') as f:
        if write_header:
            f.write('timestamp,latitude,longitude,altitude,speed,fix\n')
        f.write(f'{gps_data["time"]},'
                f'{gps_data["lat"]},'
                f'{gps_data["lon"]},'
                f'{gps_data["alt"]},'
                f'{gps_data["speed"]},'
                f'{gps_data["fix"]}\n')

def save_bt_scan(bt_devices, correlated, gps_data, output_path):
    """Speichert BT-Scan-Ergebnisse als JSON."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    path = output_path

    with open(path, 'w') as f:
        json.dump({
            'timestamp':   datetime.now().isoformat(),
            'gps':         gps_data,
            'bt_devices':  bt_devices,
            'correlated':  correlated,
        }, f, indent=2, default=str)

    log.info(f'BT-Scan gespeichert: {path}')
    return path

# ============================================================
# MAIN (Test)
# ============================================================
if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--duration', type=int, default=15)
    parser.add_argument('--output',   default=None)
    parser.add_argument('--loot-dir', default='/root/loot/chasing_your_tail')
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] %(levelname)s %(message)s'
    )

    # GPS
    gps = get_gps_position()
    if gps['fix']:
        log.info(f'GPS: {gps["lat"]}, {gps["lon"]}')
        save_gps_track(gps, args.loot_dir)
    else:
        log.info('Kein GPS-Fix')

    # BT scannen
    bt_devices = scan_bluetooth(duration=args.duration)

    # Korrelation
    correlated = correlate_wifi_bt({}, bt_devices)

    # Speichern
    if args.output:
        out = args.output  # direkt als Dateipfad verwenden
    else:
        os.makedirs(args.loot_dir, exist_ok=True)
        out = os.path.join(args.loot_dir,
            f'bt_scan_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json')
    save_bt_scan(bt_devices, correlated, gps, out)

    print(f'\nGefunden: {len(bt_devices)} BT-Geräte')
    for mac, data in bt_devices.items():
        print(f'  {mac} | {data["type"]:10} | {data["name"]}')
