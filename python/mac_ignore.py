#!/usr/bin/env python3
"""mac_ignore.py - MAC-Ignore-Liste mit Pattern-Wildcards.

Drop-in fuer ein klassisches set[str] von MAC-Adressen, plus Wildcards
fuer BLE-Privacy-Rotation (Samsung TVs / iPhones / Watches rotieren
ihre BLE-Adresse ~alle 15 Min - jede Rotation wird sonst als neuer
Verdaechtiger geflaggt).

Syntax (fnmatch):
    "aa:bb:cc:dd:ee:??"   - alle 256 Variants im letzten Byte
    "aa:bb:cc:dd:??:??"   - alle 65536 Variants in den letzten 2 Bytes
    "aa:bb:cc:*"          - alles mit diesem Prefix
    "aa:bb:cc:dd:ee:ff"   - exakte MAC (kompatibel zu altem Format)

Performance:
    Exact-MACs in O(1) ueber ein set.
    Patterns linear (bei typisch < 20 Patterns vernachlaessigbar).

Case-insensitive: intern alles lowercase, eingehende MACs ebenfalls.

Verwendung:
    from mac_ignore import MacIgnoreSet
    ig = MacIgnoreSet(["aa:bb:cc:dd:ee:01", "70:b1:3d:ab:74:??"])
    "70:B1:3D:AB:74:05" in ig   # True (Pattern + case-insensitive)
    "11:22:33:44:55:66" in ig   # False
    len(ig)                      # 2 (raw entries, nicht expanded)
"""

import fnmatch


class MacIgnoreSet:
    """Set-like container fuer MAC-Adressen mit ?/*-Wildcard-Support."""

    __slots__ = ('_exact', '_patterns', '_raw')

    def __init__(self, entries=None):
        self._exact = set()
        self._patterns = []
        self._raw = []
        if entries:
            self.update(entries)

    def add(self, entry):
        if entry is None:
            return
        s = str(entry).lower().strip()
        if not s:
            return
        self._raw.append(s)
        if '?' in s or '*' in s or '[' in s:
            self._patterns.append(s)
        else:
            self._exact.add(s)

    def update(self, entries):
        for e in entries:
            self.add(e)

    def __contains__(self, mac):
        if not isinstance(mac, str):
            return False
        m = mac.lower()
        if m in self._exact:
            return True
        for p in self._patterns:
            if fnmatch.fnmatchcase(m, p):
                return True
        return False

    def __len__(self):
        return len(self._raw)

    def __iter__(self):
        return iter(self._raw)

    def __bool__(self):
        return bool(self._raw)

    @property
    def num_patterns(self):
        return len(self._patterns)

    @property
    def num_exact(self):
        return len(self._exact)


if __name__ == '__main__':
    ig = MacIgnoreSet([
        "AA:BB:CC:DD:EE:01",
        "70:b1:3d:ab:74:??",
        "11:22:33:44:??:??",
        "  ",
        "",
        None,
    ])
    assert "aa:bb:cc:dd:ee:01" in ig
    assert "AA:BB:CC:DD:EE:01" in ig
    assert "70:b1:3d:ab:74:00" in ig
    assert "70:b1:3d:ab:74:ff" in ig
    assert "70:b1:3d:ab:74:FF" in ig
    assert "70:b1:3d:ab:75:00" not in ig
    assert "11:22:33:44:55:66" in ig
    assert "11:22:33:44:ff:ff" in ig
    assert "11:22:33:45:55:66" not in ig
    assert "ff:ff:ff:ff:ff:ff" not in ig
    assert len(ig) == 3
    assert ig.num_patterns == 2
    assert ig.num_exact == 1
    assert bool(ig) is True
    assert bool(MacIgnoreSet()) is False
    print("mac_ignore self-test: OK")
