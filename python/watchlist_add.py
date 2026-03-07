#!/usr/bin/env python3
"""
watchlist_add.py - CLI-Wrapper für WatchList.add()
Wird von payload.sh aufgerufen um Geräte zur Watch-List hinzuzufügen.
v4.5
"""
import os
import sys
import argparse
import logging

# Eigenes Modul-Verzeichnis in den Suchpfad
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from watch_list import WatchList


def main():
    parser = argparse.ArgumentParser(description='Gerät zur Watch-List hinzufügen')
    parser.add_argument('--mac',
                        required=True,
                        help='MAC-Adresse des Geräts')
    parser.add_argument('--label',
                        default='',
                        help='Bezeichnung / Hersteller')
    parser.add_argument('--type',
                        default='dynamic',
                        choices=['dynamic', 'static'],
                        help='dynamic=Tracking-Erkennung, static=Nur an bekanntem Ort')
    parser.add_argument('--notes',
                        default='',
                        help='Optionale Notizen')
    parser.add_argument('--lat',
                        type=float,
                        default=None,
                        help='GPS Latitude (für static-Typ)')
    parser.add_argument('--lon',
                        type=float,
                        default=None,
                        help='GPS Longitude (für static-Typ)')
    parser.add_argument('--zone',
                        default='Aktueller Standort',
                        help='Zonenname (für static-Typ)')
    parser.add_argument('--radius',
                        type=int,
                        default=100,
                        help='Zonen-Radius in Metern')
    parser.add_argument('--path',
                        default='/root/loot/chasing_your_tail/watch_list.json',
                        help='Pfad zur watch_list.json')
    args = parser.parse_args()

    logging.basicConfig(level=logging.WARNING)

    try:
        wl = WatchList(path=args.path)

        # Schon in der Liste?
        if wl.is_watched(args.mac):
            existing = wl.get(args.mac)
            label = existing.get('label', args.mac)
            wtype = existing.get('type', '?')
            print(f'WATCHLIST:ALREADY_EXISTS:{label} ({wtype})')
            sys.exit(0)

        wl.add(
            mac       = args.mac,
            label     = args.label or args.mac,
            watch_type= args.type,
            notes     = args.notes,
            lat       = args.lat,
            lon       = args.lon,
            zone_name = args.zone,
            radius_m  = args.radius,
        )
        print(f'WATCHLIST:OK:{args.type}')

    except Exception as e:
        print(f'WATCHLIST:ERROR:{e}', file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
