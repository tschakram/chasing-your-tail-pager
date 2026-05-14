#!/usr/bin/env python3
"""
bt_fingerprint.py - BT/BLE Device Fingerprinting für Chasing Your Tail NG v4.4
Mappt Service UUIDs, Appearance Codes und Gerätenamen → Risikobewertung.
Keine externen Abhängigkeiten.
"""

# Risiko-Level
RISK_NONE   = 'none'
RISK_LOW    = 'low'
RISK_MEDIUM = 'medium'
RISK_HIGH   = 'high'

_RISK_ORDER = [RISK_NONE, RISK_LOW, RISK_MEDIUM, RISK_HIGH]

def _max_risk(a, b):
    return b if _RISK_ORDER.index(b) > _RISK_ORDER.index(a) else a

def risk_emoji(risk):
    return {'none': '🟢', 'low': '🔵', 'medium': '🟡', 'high': '🔴'}.get(risk, '⚪')

# ============================================================
# SERVICE UUID DATENBANK
# UUID (4 hex, lowercase) → (label, has_mic, risk_level)
# ============================================================

SERVICE_UUID_DB = {
    # === BT Classic Profile UUIDs ===
    '1101': ('Serial Port (SPP)',              False, RISK_LOW),
    '1105': ('OPP File Transfer',              False, RISK_LOW),
    '1106': ('OBEX File Transfer',             False, RISK_LOW),
    '1108': ('Headset HSP',                    True,  RISK_MEDIUM),  # 🎤 Mikrofon
    '110a': ('A2DP Audio Source',              False, RISK_LOW),
    '110b': ('A2DP Audio Sink (Kopfhörer)',    False, RISK_LOW),
    '110c': ('A2DP Remote Control Target',     False, RISK_LOW),
    '110e': ('A2DP Remote Control',            False, RISK_LOW),
    '1112': ('Headset Audio Gateway',          True,  RISK_MEDIUM),  # 🎤 Mikrofon
    '1115': ('PAN Network (PANU)',             False, RISK_LOW),
    '1116': ('PAN Network (NAP)',              False, RISK_LOW),
    '1124': ('HID Device',                     False, RISK_LOW),
    '111e': ('Handsfree HFP',                  True,  RISK_MEDIUM),  # 🎤 Mikrofon
    '111f': ('Handsfree Audio Gateway',        True,  RISK_MEDIUM),  # 🎤 Mikrofon
    '112d': ('SIM Access Profile',             False, RISK_MEDIUM),
    '112f': ('Phonebook Access (PBAP)',        False, RISK_MEDIUM),
    '1132': ('Message Access (MAP)',           False, RISK_MEDIUM),

    # === BLE GATT Services ===
    '1800': ('Generic Access',                 False, RISK_NONE),
    '1801': ('Generic Attribute',              False, RISK_NONE),
    '1802': ('Immediate Alert',                False, RISK_LOW),
    '1803': ('Link Loss',                      False, RISK_LOW),
    '1804': ('TX Power',                       False, RISK_NONE),
    '1805': ('Current Time',                   False, RISK_NONE),
    '180a': ('Device Information',             False, RISK_NONE),
    '180d': ('Heart Rate Monitor',             False, RISK_LOW),
    '180e': ('Phone Alert / Mic-capable',      True,  RISK_MEDIUM),
    '180f': ('Battery Service',                False, RISK_NONE),
    '1812': ('HID / Input Device',             False, RISK_LOW),
    '1819': ('Location & Navigation',          False, RISK_MEDIUM),  # Tracker
    '181a': ('Environmental Sensing',          False, RISK_LOW),
    '181c': ('User Data',                      False, RISK_LOW),
    '181e': ('Bond Management',                False, RISK_LOW),
    '1820': ('IP Support (IoT)',               False, RISK_MEDIUM),
    '1821': ('Indoor Positioning',             False, RISK_MEDIUM),  # Tracker
    '1823': ('HTTP Proxy (IoT Gateway)',        False, RISK_MEDIUM),
    '1826': ('Fitness Machine',                False, RISK_LOW),
    '1827': ('BT Mesh Provisioning',           False, RISK_MEDIUM),  # IoT-Netz
    '1828': ('BT Mesh Proxy',                  False, RISK_MEDIUM),  # IoT-Netz
    '1843': ('Audio Input Control',            True,  RISK_MEDIUM),  # 🎤 Mikrofon
    '184e': ('Audio Stream',                   True,  RISK_MEDIUM),  # 🎤 Mikrofon

    # === Proprietary / Vendor UUIDs ===
    'fd6f': ('COVID Contact Tracing',          False, RISK_NONE),
    'fd87': ('Apple MagSafe',                  False, RISK_NONE),
    'fe2c': ('Apple AirDrop / AirPods',        False, RISK_LOW),
    'fe59': ('Nordic UART / Audio',            True,  RISK_MEDIUM),  # 🎤 Mikrofon möglich
    'fe8b': ('Apple iPhone Service',           False, RISK_LOW),
    'febe': ('Apple Proprietary',              False, RISK_LOW),
    'fe9f': ('Google Nearby / Chromecast',     False, RISK_LOW),
    'feaa': ('Eddystone Beacon',               False, RISK_MEDIUM),  # Tracker
    'ffe0': ('Camera Control Service',         False, RISK_HIGH),    # 📷 Kamera!
    'ffe1': ('Camera Data Stream',             False, RISK_HIGH),    # 📷 Kamera!
    'fff0': ('IoT Proprietary Control',        False, RISK_MEDIUM),
    'fff1': ('IoT Data Service',               False, RISK_LOW),
    'ff00': ('Unknown Proprietary',            False, RISK_MEDIUM),
    # === Tracker-spezifische UUIDs ===
    'feed': ('Tile Tracker',                   False, RISK_HIGH),
    'feea': ('Tile Tracker (Legacy)',           False, RISK_HIGH),
    'fe9a': ('Chipolo Tracker',                False, RISK_HIGH),
    'fd44': ('Samsung SmartThings Find',       False, RISK_HIGH),
    'fabe': ('Tracker Beacon',                 False, RISK_HIGH),
}

# ============================================================
# APPEARANCE CODE DATENBANK
# Code → (label, is_suspicious)
# ============================================================

APPEARANCE_DB = {
    0x0000: ('Unbekannt',               False),
    0x0040: ('Handy',                   False),
    0x0041: ('Smartphone',              False),
    0x0080: ('PC',                      False),
    0x0081: ('Desktop-PC',              False),
    0x0082: ('Laptop',                  False),
    0x0083: ('Handheld-PC',             False),
    0x0084: ('Palmtop',                 False),
    0x0085: ('Tablet',                  False),
    0x00C0: ('Uhr',                     False),
    0x00C1: ('Sport-Uhr',               False),
    0x00C2: ('Smartwatch',              False),
    0x0100: ('Wecker',                  False),
    0x0140: ('Display',                 False),
    0x0180: ('Fernbedienung',           False),
    0x01C0: ('Smart Glasses',           True),   # Kamera möglich
    0x0200: ('Tag / Tracker',           True),
    0x0240: ('Schlüsselanhänger',       True),
    0x0280: ('Mediaplayer',             False),
    0x02C0: ('Barcode-Scanner',         False),
    0x0300: ('Thermometer',             False),
    0x0340: ('Herzfrequenzsensor',      False),
    0x03C0: ('HID-Gerät',               False),
    0x03C1: ('Tastatur',                False),
    0x03C2: ('Maus',                    False),
    0x03C4: ('Gamepad',                 False),
    0x03C9: ('Kartenleser',             False),
    0x0440: ('Digitaler Stift',         False),
    0x07C0: ('Smart-Lampe',             False),
    0x07C1: ('Smart-Steckdose',         True),   # IoT
    0x07C6: ('Zugangskontrolle',        True),   # Überwachung
    0x07C9: ('Netzwerkgerät',           True),   # IoT
    0x07CA: ('Lichtsensor',             False),
    0x07CB: ('Bewegungsmelder (BLE)',   True),   # Überwachung!
    0x07CC: ('PIR Sensor',              True),   # Überwachung!
    0x07D4: ('IP-Kamera',              True),   # 📷 KAMERA!
    0x07D5: ('Videokamera',             True),   # 📷 KAMERA!
    0x07D6: ('Audio-Sensor',            True),   # 🎤 Mikrofon!
    0x07D7: ('Präsenzsensor',           True),   # Überwachung
    0x07D8: ('Umgebungssensor',         False),
    0x0C40: ('Mediaplayer',             False),
    0x0C41: ('Set-Top-Box',             False),
    0x0C42: ('DVR',                     False),
    0x0C44: ('AV-Receiver',             False),
    0x0C46: ('Videokamera',             True),   # 📷 KAMERA!
    0x0C48: ('Videomonitor',            False),
    0x0C49: ('Fernseher',               False),
    0x0C4A: ('Videokonferenz',          True),   # Kamera + Mikrofon
    0x0C4B: ('Digitalkamera',           True),   # 📷 KAMERA!
    0x0C4C: ('Digitale Videokamera',    True),   # 📷 KAMERA!
}

# Appearance Codes die eindeutig auf Kamera hinweisen
_CAMERA_APPEARANCE_CODES = {0x07D4, 0x07D5, 0x0C46, 0x0C4B, 0x0C4C}
# Appearance Code für Audio-Sensor (Mikrofon)
_AUDIO_APPEARANCE_CODES  = {0x07D6, 0x0C4A}

# ============================================================
# TRACKER COMPANY IDs (BT SIG Assigned Numbers)
# company_id (int) → Tracker-Bezeichnung
# ============================================================

TRACKER_COMPANY_IDS = {
    76:  'Apple (AirTag/FindMy)',      # 0x004C Apple Inc.
    117: 'Samsung (SmartTag)',          # 0x0075 Samsung Electronics
    224: 'Google (Find My Device)',     # 0x00E0 Google LLC
    155: 'Tile, Inc.',                  # 0x009B Tile
}


# ============================================================
# APPLE CONTINUITY MSD-SUBTYPES
# (Public reverse-engineering von Apple-Manufacturer-Data)
# Erstes Byte nach Company-ID = Type
# Quelle: https://github.com/furiousMAC/continuity
#
# Nur 0x12 ist FindMy/AirTag-Beacon. Alle anderen sind Continuity-
# Protokolle (Handoff, AirDrop, Hey-Siri etc.) - normales Apple-
# Geraete-Verhalten, KEIN Tracker.
# ============================================================
APPLE_MSD_SUBTYPES = {
    0x01: ('iBeacon',                   False, 'ibeacon'),
    0x02: ('AirPrint',                  False, 'apple_device'),
    0x03: ('AirDrop',                   False, 'apple_device'),
    0x05: ('AirPlay',                   False, 'apple_device'),
    0x07: ('AirPods/Magic-Pair',        False, 'airpods'),
    0x08: ('HomeKit Hey-Siri',          False, 'apple_device'),
    0x09: ('Apple TV Remote Setup',     False, 'apple_tv'),
    0x0A: ('WiFi Settings',             False, 'apple_device'),
    0x0B: ('Watch Continuity',          False, 'apple_watch'),
    0x0C: ('Handoff',                   False, 'apple_device'),
    0x0D: ('WiFi Network Joining',      False, 'apple_device'),
    0x0E: ('Hotspot',                   False, 'apple_device'),
    0x0F: ('WiFi Join V2',              False, 'apple_device'),
    0x10: ('Nearby (Continuity)',       False, 'apple_device'),
    0x11: ('U1 Ranging',                False, 'apple_device'),
    0x12: ('FindMy / AirTag',           True,  'airtag'),        # !!! TRACKER
    0x14: ('Find My Network',           True,  'findmy_network'),# !!! TRACKER
    0x16: ('AirTag (alt format)',       True,  'airtag'),        # !!! TRACKER
}


def _parse_apple_msd(msd_hex):
    """Liest erstes Byte (subtype) aus Apple-MSD payload.
    Returns (label, is_tracker, device_kind) oder None bei unparsbar.

    msd_hex ist die hex-string ohne spaces, z.B. '1019000000...'.
    Bei Apple ist Byte 0 = subtype, Byte 1 = subtype-payload-laenge.
    """
    if not msd_hex or len(msd_hex) < 2:
        return None
    try:
        subtype = int(msd_hex[0:2], 16)
    except ValueError:
        return None
    return APPLE_MSD_SUBTYPES.get(subtype,
                                  (f'Apple type 0x{subtype:02x}',
                                   False, 'apple_device_unknown'))


# ============================================================
# SAMSUNG MSD-PATTERN
# Samsung-MSD ist firmware-abhaengig und nicht offen dokumentiert.
# Bekannte Patterns aus Reverse-Engineering:
#   - SmartTag (BLE):    haeufig '01000200...' oder '0200xxxxxx...'
#   - Galaxy Phone:      '4204xxxxxx...' (Quick-Share / Nearby-Share)
#   - SmartThings/TV:    '4202' / '4243' (verschiedene Subtypes)
#   - Galaxy Buds:       '0104' / '01001b...'
#
# Konservativ: wir markieren NUR SmartTag-Pattern als Tracker; alles
# andere = Samsung-Geraet (nicht Tracker, medium-risk wenn RPA, sonst low).
# ============================================================
SAMSUNG_SMARTTAG_PREFIXES = (
    '01000200',   # SmartTag manuf. specific (häufig)
    '02000100',   # SmartTag alternative
    '0200',       # vorsichtig: kann andere Subtypes treffen,
                  # nur in Kombination mit RPA als Tracker werten
)
SAMSUNG_PHONE_PREFIXES = (
    '4204', '4242', '4243', '4202',  # Quick-Share / Nearby-Share / SmartThings
)
SAMSUNG_BUDS_PREFIXES = (
    '0104', '01001b',                # Galaxy Buds
)


def _parse_samsung_msd(msd_hex):
    """Returns (label, is_tracker, device_kind) oder None bei unparsbar.

    Konservativ: 'wahrscheinlich SmartTag' nur bei exakten Prefixes.
    Wenn keine Prefix matcht: Samsung-Geraet (nicht Tracker).
    """
    if not msd_hex or len(msd_hex) < 4:
        return None
    msd = msd_hex.lower()
    if any(msd.startswith(p) for p in SAMSUNG_SMARTTAG_PREFIXES[:2]):
        return ('Samsung SmartTag', True, 'samsung_smarttag')
    if msd.startswith(SAMSUNG_SMARTTAG_PREFIXES[2]):
        # weak signal: Pattern '0200' allein, koennte SmartTag ODER was
        # anderes sein. Konservativ: nicht als Tracker werten.
        return ('Samsung BLE (unklarer Subtype)', False, 'samsung_device_unknown')
    if any(msd.startswith(p) for p in SAMSUNG_PHONE_PREFIXES):
        return ('Samsung Galaxy Phone/TV', False, 'samsung_device')
    if any(msd.startswith(p) for p in SAMSUNG_BUDS_PREFIXES):
        return ('Samsung Galaxy Buds', False, 'samsung_buds')
    return ('Samsung-Geraet (unbekannter Subtype)', False, 'samsung_device_unknown')

# ============================================================
# GERÄTENAMEN MUSTER
# ============================================================

_TRACKER_NAME_PATTERNS = [
    'airtag', 'air tag', 'smarttag', 'smart tag', 'galaxy smarttag',
    'tile', 'chipolo', 'orbit', 'pebblebee', 'nut find',
    'invoxia', 'tracki', 'spytec', 'optimus',
    'find my', 'findmy', 'location tracker',
]

# Gerätenamen die TROTZ Tracker-Company-ID kein Tracker sind (False-Positive-Filter)
# Company-ID 117 = Samsung trifft z.B. auch TVs, Soundbars, Drucker etc.
_TRACKER_NAME_EXCLUDES = [
    # Samsung TVs
    'tv', ' qled', ' oled', ' neo', 'samsung bu', 'samsung cu', 'samsung au',
    'samsung qn', 'samsung un', 'the frame', 'the serif', 'the sero',
    # Soundbars / Speaker
    'soundbar', 'hw-', 'sound tower', 'shape m',
    # Monitore / Displays
    'monitor', 'display', 'smart monitor',
    # Drucker / Scan
    'printer', 'xpress', 'scx-', 'clp-', 'ml-',
    # Haushaltsgeräte
    'washer', 'dryer', 'fridge', 'refrigerator', 'vacuum', 'robotic',
    'bespoke', 'jet bot', 'powerbot',
    # Wearables (kein Tracker)
    'galaxy watch', 'gear s', 'gear fit', 'galaxy fit',
    # PC / Tablet
    'galaxy book', 'galaxy tab', 'galaxy s ', 'galaxy a ', 'galaxy m ',
    # Apple Non-Tracker (Company ID 76 = Apple, aber nicht alle sind AirTags)
    'macbook', 'imac', 'mac pro', 'mac mini', 'ipad', 'apple tv',
    'apple watch', 'homepod', 'airpods', 'beats',
]

_MIC_NAME_PATTERNS = [
    'headset', 'earbuds', 'airpods', 'galaxy buds', 'jabra', 'plantronics',
    'poly ', 'bose', 'sony wh', 'sony wf', 'beats', 'sennheiser',
    'echo ', 'alexa', 'google home', 'nest mini', 'homepod',
    'macbook', 'surface pro', 'thinkpad',
]

_CAMERA_NAME_PATTERNS = [
    'ipcam', 'ip cam', 'ip-cam', 'camera', 'cam_', 'cam-',
    'hikvision', 'dahua', 'reolink', 'wyze', 'arlo', 'ring',
    'foscam', 'eufy', 'ezviz', 'amcrest', 'annke',
    'esp32-cam', 'esp32cam', 'esp8266', 'espcam',
]

# ============================================================
# KAMERA-HERSTELLER OUI (BT MAC Lookup)
# ============================================================

CAMERA_OUI_PREFIXES = {
    '9c:b8:b5': 'Hikvision',
    'ac:cc:8e': 'Hikvision',
    'c8:02:10': 'Hikvision',
    'f0:9e:4a': 'Hikvision',
    'b4:a3:82': 'Hikvision',
    'd0:75:a7': 'Hikvision',
    '54:c4:15': 'Hikvision',
    'a0:e4:cb': 'Dahua',
    '70:6a:eb': 'Dahua',
    '7c:c2:c6': 'Reolink',
    'ec:71:db': 'Wyze',
    'a8:5b:4f': 'Wyze',
    '2c:aa:8e': 'Arlo',
    'e0:9a:d9': 'Arlo',
    '30:8c:fb': 'Eufy',
    '64:a2:f9': 'Ring',
    'b0:09:da': 'Ring',
    'c4:de:e2': 'Nest/Google',
    '18:b4:30': 'Nest/Google',
    # Espressif (ESP32/ESP8266) - häufig in DIY/Billig-Kameras
    '68:02:b8': 'Espressif (IoT)',
    '10:52:1c': 'Espressif (IoT)',
    'a4:cf:12': 'Espressif (IoT)',
    '24:0a:c4': 'Espressif (IoT)',
    'cc:50:e3': 'Espressif (IoT)',
    '84:f3:eb': 'Espressif (IoT)',
    'ec:fa:bc': 'Espressif (IoT)',
    '30:ae:a4': 'Espressif (IoT)',
    '24:6f:28': 'Espressif (IoT)',
    'c4:4f:33': 'Espressif (IoT)',
    '7c:df:a1': 'Espressif (IoT)',
    'b4:e6:2d': 'Espressif (IoT)',
    '08:3a:f2': 'Espressif (IoT)',
    'e8:68:e7': 'Espressif (IoT)',
    # Realtek
    '00:00:6c': 'Realtek (IoT)',
    '00:e0:4c': 'Realtek (IoT)',
    # Hikvision (weitere OUI-Blöcke)
    '44:19:b6': 'Hikvision',
    '40:59:c0': 'Hikvision',
    'bc:ad:28': 'Hikvision',
    'c0:56:e3': 'Hikvision',
    # EZVIZ (Hikvision-Marke)
    'c4:2f:90': 'EZVIZ/Hikvision',
    '8c:e7:48': 'EZVIZ/Hikvision',
    # Dahua (weitere OUI-Blöcke)
    '3c:ef:8c': 'Dahua',
    'e0:50:8b': 'Dahua',
    '60:ed:e0': 'Dahua',
    # IMOU (Dahua-Marke)
    'f8:36:9b': 'IMOU/Dahua',
    # Reolink (weitere OUI-Blöcke)
    'e0:62:90': 'Reolink',
    # Axis Communications (Profi-IP-Kameras)
    '00:40:8c': 'Axis Communications',
    # Tuya IoT (BK7231-Chip)
    'd8:f1:5b': 'Tuya IoT',
    'a4:50:46': 'Tuya IoT',
    # Amazon Echo / Alexa (Mikrofon — BLE-Advertisement sichtbar)
    'fc:65:de': 'Amazon Echo',
    '40:b4:cd': 'Amazon Echo',
    '74:c2:46': 'Amazon Echo',
    '68:37:e9': 'Amazon Echo',
    'f0:81:73': 'Amazon Echo',
    # Raspberry Pi (DIY-Kamera / Surveillance-Plattform)
    'b8:27:eb': 'Raspberry Pi',
    'dc:a6:32': 'Raspberry Pi',
    'e4:5f:01': 'Raspberry Pi',
}

# ============================================================
# FINGERPRINT FUNKTION
# ============================================================

def fingerprint_device(mac, name='', uuids=None, appearance_code=None,
                       oui_vendor='', company_id=None,
                       addr_type=None, addr_subtype=None,
                       msd_hex=None):
    """
    Bewertet ein BT/BLE-Gerät anhand von UUIDs, Appearance, Name, OUI, Company ID.

    Args:
        mac:             MAC-Adresse (lowercase, colon-separated)
        name:            Gerätename (aus Advertisement oder Scan)
        uuids:           Liste von 4-stelligen hex UUID-Strings
        appearance_code: BLE Appearance Code (int) oder None
        oui_vendor:      Herstellername aus IEEE OUI-Lookup
        company_id:      BT SIG Company ID (int) aus Manufacturer Data
        addr_type:       'public' / 'random' / 'unknown' (BLE Address Type)
        addr_subtype:    'resolvable' / 'non_resolvable' / 'static' (nur bei random)

    Returns:
        dict mit: risk, has_mic, has_camera, has_tracker, device_type, flags
    """
    uuids = [u.lower().strip() for u in (uuids or [])]
    name_lower = (name or '').lower()

    risk        = RISK_NONE
    has_mic     = False
    has_camera  = False
    has_tracker = False
    device_types = []
    flags        = []

    # 1. Service UUIDs auswerten
    for uuid in uuids:
        uuid_short = uuid[-4:] if len(uuid) > 4 else uuid
        if uuid_short in SERVICE_UUID_DB:
            label, mic, uuid_risk = SERVICE_UUID_DB[uuid_short]
            if label not in device_types:
                device_types.append(label)
            if mic:
                has_mic = True
                flags.append(f'🎤 Mikrofon via {label} ({uuid_short})')
            if uuid_short in ('ffe0', 'ffe1'):
                has_camera = True
                flags.append(f'📷 Kamera-Service UUID: {uuid_short}')
            risk = _max_risk(risk, uuid_risk)

    # 2. Appearance Code auswerten
    if appearance_code is not None:
        app_label, suspicious = APPEARANCE_DB.get(
            appearance_code, (f'0x{appearance_code:04x}', False)
        )
        if app_label not in device_types:
            device_types.insert(0, app_label)
        if appearance_code in _CAMERA_APPEARANCE_CODES:
            has_camera = True
            risk = RISK_HIGH
            flags.append(f'📷 KAMERA (Appearance 0x{appearance_code:04x}: {app_label})')
        elif appearance_code in _AUDIO_APPEARANCE_CODES:
            has_mic = True
            risk = _max_risk(risk, RISK_MEDIUM)
            flags.append(f'🎤 Audio-Sensor (Appearance 0x{appearance_code:04x})')
        elif suspicious:
            risk = _max_risk(risk, RISK_MEDIUM)
            flags.append(f'⚠ Verdächtiger Typ: {app_label}')

    # 3. Gerätename auswerten
    for pattern in _CAMERA_NAME_PATTERNS:
        if pattern in name_lower:
            has_camera = True
            risk = RISK_HIGH
            flags.append(f'📷 Kamera-Name: "{name}"')
            break

    if not has_camera:
        for pattern in _MIC_NAME_PATTERNS:
            if pattern in name_lower:
                has_mic = True
                risk = _max_risk(risk, RISK_MEDIUM)
                flags.append(f'🎤 Headset/Speaker: "{name}"')
                break

    # 4. OUI check (Kamera-Hersteller via eigene DB)
    mac_oui = mac.lower()[:8] if mac else ''
    cam_vendor = CAMERA_OUI_PREFIXES.get(mac_oui)
    if cam_vendor:
        risk = _max_risk(risk, RISK_MEDIUM)
        flags.append(f'⚠ OUI Kamera-Hersteller: {cam_vendor}')
        if 'Espressif' in cam_vendor or 'Realtek' in cam_vendor:
            flags.append('⚠ IoT-Chip (DIY-Kamera möglich)')

    # 5. IEEE OUI-Vendor (Espressif, Realtek, MediaTek = IoT-Hinweis)
    if oui_vendor and any(v in oui_vendor for v in ['Espressif', 'Realtek', 'MediaTek']):
        risk = _max_risk(risk, RISK_MEDIUM)
        if not any('IoT' in f for f in flags):
            flags.append(f'⚠ IoT-Chip-Hersteller: {oui_vendor}')

    # 6. Tracker-Erkennung — Reihenfolge nach Vertrauensgrad:
    #
    # HARTE Indikatoren (eindeutig Tracker):
    #   a) Appearance Code 0x0200 (Tag/Tracker) oder 0x0240 (Schluesselanhaenger)
    #   b) Tracker-Name im Advertisement
    #   c) Tracker-spezifische Service-UUID
    #
    # WEICHE Indikatoren (nur wenn keine harten Gegen-Beweise):
    #   d) Company ID (Apple/Samsung/Google/Tile)  +  Address-Type-Heuristik

    # a) Appearance Code = HARTER Tracker-Marker (BLE-Standard, eindeutig)
    if appearance_code in (0x0200, 0x0240):
        has_tracker = True
        risk = _max_risk(risk, RISK_HIGH)
        app_label = APPEARANCE_DB.get(appearance_code, ('Tracker', False))[0]
        flags.append(f'🔍 TRACKER (Appearance 0x{appearance_code:04x}: {app_label})')

    # b) Tracker-Name (eindeutig - "AirTag", "SmartTag", "Tile" etc.)
    if not has_tracker:
        for pattern in _TRACKER_NAME_PATTERNS:
            if pattern in name_lower:
                has_tracker = True
                risk = RISK_HIGH
                flags.append(f'🔍 TRACKER Name: "{name}"')
                break

    # c) Tracker-Service-UUID (Tile, Chipolo, Samsung SmartThings Find)
    tracker_uuids = {'feed', 'feea', 'fe9a', 'fd44', 'fabe'}
    for uuid in uuids:
        uuid_short = uuid[-4:] if len(uuid) > 4 else uuid
        if uuid_short in tracker_uuids:
            has_tracker = True
            # risk schon durch SERVICE_UUID_DB gesetzt
            break

    # d) Company ID + MSD-Subtype + Address-Type-Heuristik
    #
    # Erweiterte Logik nach Drive-Test 13.05.: pure Company-ID-Check
    # markiert jedes iPhone/Galaxy-Phone in Reichweite als Tracker
    # (alle nutzen RPA + CompanyID 76/117). Lösung: MSD-Subtype-Bytes
    # auswerten:
    #   - Apple Continuity Subtype 0x12/0x14/0x16 -> echter AirTag/FindMy
    #   - Apple 0x10/0x0F/0x0C/0x07 etc. -> normales Apple-Geraet
    #   - Samsung MSD '01000200...'/'02000100...' -> SmartTag
    #   - Samsung '4204...'/'0104...' -> Phone/Buds/TV
    if company_id is not None and not has_tracker:
        tracker_brand = TRACKER_COMPANY_IDS.get(company_id)
        if tracker_brand:
            is_excluded = any(ex in name_lower for ex in _TRACKER_NAME_EXCLUDES)
            msd_info = None
            if company_id == 76:        # Apple
                msd_info = _parse_apple_msd(msd_hex)
            elif company_id == 117:     # Samsung
                msd_info = _parse_samsung_msd(msd_hex)

            if is_excluded:
                flags.append(f'ℹ️ Company ID {company_id} ({tracker_brand}) — kein Tracker (bekanntes Geraet: "{name}")')
            elif addr_type == 'public':
                # Public OUI = stationaeres Hausgeraet, MSD-Subtype optional
                flags.append(f'ℹ️ Company ID {company_id} ({tracker_brand}) — Public-Address-OUI, Hausgeraet (TV/Soundbar/IoT)')
                if msd_info:
                    flags.append(f'ℹ️ MSD: {msd_info[0]}')
                if not device_types:
                    device_types.append('Hausgeraet (BLE)')
            elif msd_info and msd_info[1]:
                # MSD-Subtype identifiziert explizit als Tracker
                has_tracker = True
                risk = RISK_HIGH
                flags.append(f'🔍 TRACKER MSD-Subtype: {msd_info[0]} '
                             f'({tracker_brand})')
                if msd_info[2] and msd_info[2] not in device_types:
                    device_types.insert(0, msd_info[2])
            elif msd_info and not msd_info[1]:
                # MSD-Subtype identifiziert als nicht-Tracker-Apple/Samsung-
                # Geraet (z.B. iPhone Continuity, Galaxy Phone, Buds, TV)
                flags.append(f'ℹ️ {msd_info[0]} (Company ID {company_id}) — '
                             f'kein Tracker laut MSD-Subtype')
                if msd_info[2] and msd_info[2] not in device_types:
                    device_types.insert(0, msd_info[2])
                # Low risk fuer Wachs-Wissen, kein high-Alarm
                risk = _max_risk(risk, RISK_LOW)
            elif addr_type == 'random' and addr_subtype == 'resolvable':
                # RPA + Tracker-CompanyID OHNE MSD-Info = unklar
                # Konservativer: Medium statt High wenn wir MSD nicht kennen
                # (alpha10-Fix: vorher war das immer high, gab False-Positives
                # bei jedem iPhone)
                risk = _max_risk(risk, RISK_MEDIUM)
                flags.append(f'⚠ Company ID {company_id} ({tracker_brand}) + RPA — moeglicher Tracker, MSD-Subtype nicht erfasst')
            elif addr_type == 'random' and addr_subtype == 'static':
                risk = _max_risk(risk, RISK_MEDIUM)
                flags.append(f'⚠ Company ID {company_id} ({tracker_brand}) + Random-Static-Address (unklar)')
            else:
                # addr_type unknown - sehr konservativ medium
                risk = _max_risk(risk, RISK_LOW)
                flags.append(f'⚠ Company ID {company_id} ({tracker_brand}) — Address-Type unbekannt')

    device_type = device_types[0] if device_types else 'Unbekannt'

    return {
        'risk':        risk,
        'has_mic':     has_mic,
        'has_camera':  has_camera,
        'has_tracker': has_tracker,
        'device_type': device_type,
        'all_types':   device_types,
        'flags':       flags,
        'uuids':       uuids,
    }


# ============================================================
# MAIN (Test)
# ============================================================
if __name__ == '__main__':
    tests = [
        ('aa:bb:cc:dd:ee:01', 'JBL Earbuds',     ['111e', '110b'],  0x0040,  ''),
        ('aa:bb:cc:dd:ee:02', 'ESP32-CAM',        ['ffe0', 'ffe1'],  None,    'Espressif'),
        ('68:02:b8:11:22:33', '',                  ['180a'],         None,    'Espressif Inc.'),
        ('aa:bb:cc:dd:ee:04', 'Apple Watch',       ['180d', '180f'], 0x00C2,  'Apple'),
        ('aa:bb:cc:dd:ee:05', 'IP-Camera-Hikvision', [],            0x07D4,  ''),
    ]

    for mac, name, uuids, app, vendor in tests:
        fp = fingerprint_device(mac, name, uuids, app, vendor)
        emoji = risk_emoji(fp['risk'])
        print(f'{emoji} {mac} | {name or "?":20} | {fp["risk"]:6} | '
              f'mic={fp["has_mic"]} cam={fp["has_camera"]} | {fp["device_type"]}')
        for flag in fp['flags']:
            print(f'     {flag}')
