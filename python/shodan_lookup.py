#!/usr/bin/env python3
"""
shodan_lookup.py — Shodan + Fingerbank API Integration
Chasing Your Tail NG / Argus Pager v4.8

APIs:
  - InternetDB  (kostenlos, kein Key)  → IP → Ports/Tags/CVEs
  - CVEDB       (kostenlos, kein Key)  → Produkt → CVE-Liste
  - Shodan Host (Key, $49 einmalig)    → IP → Org/ASN/Banner
  - Fingerbank  (Key, kostenlos)       → MAC → Gerätekategorie

Nur stdlib — urllib.request + json.
"""

import json
import logging
import time
import urllib.request
import urllib.error
import urllib.parse

log = logging.getLogger('CYT-Shodan')

# ── In-Memory Cache (Laufzeit des Scripts) ────────────────────────────────────
_cache = {}


# ── Private IP Check ─────────────────────────────────────────────────────────

def is_private_ip(ip):
    """RFC1918 + Loopback + Link-Local Check."""
    try:
        parts = [int(p) for p in ip.split('.')]
        if len(parts) != 4:
            return True
        a, b = parts[0], parts[1]
        if a == 10:
            return True
        if a == 172 and 16 <= b <= 31:
            return True
        if a == 192 and b == 168:
            return True
        if a == 127:
            return True
        if a == 169 and b == 254:
            return True
        if a == 0 or a >= 224:
            return True
        return False
    except (ValueError, IndexError):
        return True


# ── HTTP Helper ──────────────────────────────────────────────────────────────

def _http_get(url, timeout=5, headers=None):
    """GET request, returns parsed JSON or None."""
    try:
        req = urllib.request.Request(url, headers=headers or {})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        log.debug(f'HTTP {e.code}: {url}')
        return None
    except Exception as e:
        log.debug(f'HTTP error: {url}: {e}')
        return None


# ── InternetDB (kostenlos) ───────────────────────────────────────────────────

def internetdb_lookup(ip, timeout=5):
    """
    Kostenlos, kein Key.
    Returns: {ports, hostnames, cpes, tags, vulns} or None
    """
    if is_private_ip(ip):
        return None

    cache_key = f'idb:{ip}'
    if cache_key in _cache:
        return _cache[cache_key]

    data = _http_get(f'https://internetdb.shodan.io/{ip}', timeout=timeout)
    if data and 'ip' in data:
        result = {
            'ports': data.get('ports', []),
            'hostnames': data.get('hostnames', []),
            'cpes': data.get('cpes', []),
            'tags': data.get('tags', []),
            'vulns': data.get('vulns', []),
        }
        _cache[cache_key] = result
        return result

    _cache[cache_key] = None
    return None


# ── CVEDB (kostenlos) ────────────────────────────────────────────────────────

def cvedb_by_product(product, limit=5):
    """
    Kostenlos, kein Key. Sucht CVEs nach Produktname.
    Returns: [{cve, cvss, kev, epss, propose_action}]
    """
    if not product:
        return []

    cache_key = f'cve:{product}'
    if cache_key in _cache:
        return _cache[cache_key]

    # Erst KEV (Known Exploited Vulnerabilities)
    params = urllib.parse.urlencode({
        'product': product, 'is_kev': 'true', 'limit': limit
    })
    data = _http_get(f'https://cvedb.shodan.io/cves?{params}', timeout=8)
    results = []
    if data and data.get('cves'):
        for c in data['cves'][:limit]:
            results.append({
                'cve': c.get('cve_id', c.get('cve', '?')),
                'cvss': c.get('cvss', c.get('cvss_v3', 0)),
                'kev': True,
                'epss': c.get('epss', 0),
                'propose_action': c.get('propose_action', ''),
            })

    # Falls keine KEVs: nach EPSS sortiert
    if not results:
        params = urllib.parse.urlencode({
            'product': product, 'sort_by_epss': 'true', 'limit': limit
        })
        data = _http_get(f'https://cvedb.shodan.io/cves?{params}', timeout=8)
        if data and data.get('cves'):
            for c in data['cves'][:limit]:
                results.append({
                    'cve': c.get('cve_id', c.get('cve', '?')),
                    'cvss': c.get('cvss', c.get('cvss_v3', 0)),
                    'kev': c.get('kev', False),
                    'epss': c.get('epss', 0),
                    'propose_action': c.get('propose_action', ''),
                })

    _cache[cache_key] = results
    return results


# ── Shodan Full Host API (Key erforderlich) ──────────────────────────────────

def shodan_host_lookup(ip, api_key, timeout=8):
    """
    Erfordert API-Key. Returns extended host info or None.
    """
    if is_private_ip(ip) or not api_key:
        return None

    cache_key = f'host:{ip}'
    if cache_key in _cache:
        return _cache[cache_key]

    params = urllib.parse.urlencode({'key': api_key})
    data = _http_get(
        f'https://api.shodan.io/shodan/host/{ip}?{params}',
        timeout=timeout
    )
    if not data:
        _cache[cache_key] = None
        return None

    result = {
        'org': data.get('org', ''),
        'isp': data.get('isp', ''),
        'asn': data.get('asn', ''),
        'ports': data.get('ports', []),
        'vulns': data.get('vulns', []),
        'tags': data.get('tags', []),
        'cpes': [],
        'hostnames': data.get('hostnames', []),
        'product': '',
        'version': '',
        'location': data.get('location', {}),
    }
    # Produkt/Version aus erstem Service-Banner
    for svc in data.get('data', []):
        if svc.get('product'):
            result['product'] = svc['product']
            result['version'] = svc.get('version', '')
            break
        if svc.get('cpe'):
            result['cpes'].extend(
                svc['cpe'] if isinstance(svc['cpe'], list) else [svc['cpe']]
            )

    _cache[cache_key] = result
    return result


# ── Kombinierter IP-Lookup ───────────────────────────────────────────────────

def enrich_ip(ip, api_key=None, timeout=5):
    """
    InternetDB immer, Full API wenn key vorhanden.
    Returns: {source, ports, tags, cpes, vulns, org, asn, ...}
    """
    if is_private_ip(ip):
        return {'source': 'private', 'ip': ip}

    # InternetDB
    idb = internetdb_lookup(ip, timeout=timeout)
    if idb:
        result = {'source': 'internetdb', 'ip': ip, **idb}
    else:
        result = {'source': 'error', 'ip': ip, 'ports': [], 'tags': [],
                  'cpes': [], 'vulns': [], 'hostnames': []}

    # Full API wenn Key vorhanden
    if api_key:
        full = shodan_host_lookup(ip, api_key, timeout=timeout)
        if full:
            result['source'] = 'shodan_api'
            result.update({k: v for k, v in full.items() if v})

    return result


# ── Vendor → CVEDB Produkt-Mapping ───────────────────────────────────────────

VENDOR_TO_CVEDB = {
    'Hikvision':        'hikvision',
    'EZVIZ/Hikvision':  'hikvision',
    'Dahua':            'dahua',
    'IMOU/Dahua':       'dahua',
    'Axis Communications': 'axis',
    'Foscam':           'foscam',
    'Reolink':          'reolink',
    'D-Link Camera':    'dlink',
    'TP-Link Camera':   'tp-link',
    'Amcrest':          'amcrest',
    'Ring':             'ring',
    'Wyze':             'wyze',
    'Nest/Google':      'nest',
    'Eufy':             'eufy',
    'Arlo':             'arlo',
    'Espressif (IoT)':  'espressif',
}


def cvedb_for_vendor(vendor):
    """Vendor-String → CVEDB-Lookup. Leere Liste wenn nicht im Mapping."""
    product = VENDOR_TO_CVEDB.get(vendor)
    return cvedb_by_product(product) if product else []


# ── Fingerbank ───────────────────────────────────────────────────────────────

FINGERBANK_HIGH_RISK = {
    'IP Camera', 'Video Surveillance', 'Network Video Recorder',
    'Security Camera', 'CCTV',
}
FINGERBANK_MEDIUM_RISK = {
    'IoT Device', 'Smart Home Device', 'Embedded Device', 'Network Device',
}


def fingerbank_lookup(mac, api_key, dhcp_fingerprint=None, timeout=5):
    """
    MAC → Gerätekategorie via Fingerbank.
    Returns: {device_name, category, score, risk} or None
    """
    if not api_key:
        return None

    cache_key = f'fb:{mac.lower()}'
    if cache_key in _cache:
        return _cache[cache_key]

    params = {'key': api_key, 'mac': mac}
    if dhcp_fingerprint:
        params['dhcp_fingerprint'] = dhcp_fingerprint

    url = f'https://api.fingerbank.org/api/v2/combinations/interrogate?{urllib.parse.urlencode(params)}'
    data = _http_get(url, timeout=timeout)

    if not data or 'device' not in data:
        _cache[cache_key] = None
        return None

    score = data.get('score', 0)
    if score < 60:
        _cache[cache_key] = None
        return None

    device = data['device']
    category = device.get('name', '')

    # Kategorie aus parents extrahieren (oft genauer)
    parents = device.get('parents', [])
    if parents:
        category = parents[0].get('name', category)

    risk = 'none'
    if category in FINGERBANK_HIGH_RISK:
        risk = 'high'
    elif category in FINGERBANK_MEDIUM_RISK:
        risk = 'medium'

    result = {
        'device_name': device.get('name', '?'),
        'category': category,
        'score': score,
        'risk': risk,
    }
    _cache[cache_key] = result
    return result
