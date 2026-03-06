#!/bin/bash
# Title: Chasing Your Tail NG
# Description: Surveillance detection via WiFi probe request persistence analysis
# Author: tschakram
# Category: reconnaissance
# Version: 3.0
# Based on: ArgeliusLabs/Chasing-Your-Tail-NG (MIT)

# ============================================================
# CONFIGURATION
# ============================================================
SCAN_ROUNDS=1
SCAN_DURATION=30
PERSISTENCE_THRESHOLD=0.6
MIN_APPEARANCES=2

LOOT_DIR="/root/loot/chasing_your_tail"
PCAP_DIR="$LOOT_DIR/pcap"
REPORT_DIR="$LOOT_DIR/surveillance_reports"
PYTHON_DIR="/root/payloads/user/reconnaissance/chasing_your_tail/python"
CONFIG_FILE="/root/payloads/user/reconnaissance/chasing_your_tail/config.json"

# ============================================================
# SETUP
# ============================================================
mkdir -p "$PCAP_DIR" "$REPORT_DIR"

LOG "╔══════════════════════════╗"
LOG "║  Chasing Your Tail NG    ║"
LOG "║      v3.0                ║"
LOG "╚══════════════════════════╝"
LOG ""
LOG "Surveillance Detection"
LOG "via WiFi Probe Analysis"
LOG ""
sleep 2

# ============================================================
# DEPENDENCY CHECK
# ============================================================
SPINNER_ID=$(START_SPINNER "Checking dependencies...")

if ! command -v python3 >/dev/null 2>&1; then
    STOP_SPINNER "$SPINNER_ID"
    LOG red "Python3 nicht gefunden!"
    LOG yellow "Installiere python3..."
    opkg install -d mmc python3 2>/dev/null
fi

STOP_SPINNER "$SPINNER_ID"
LOG green "✓ Abhängigkeiten OK"
sleep 1

# ============================================================
# SCAN-MODUS AUSWÄHLEN
# ============================================================
LOG ""
LOG blue "━━━━━━━━━━━━━━━━━━━━━━━━━━"
LOG blue "     Scan-Module"
LOG blue "━━━━━━━━━━━━━━━━━━━━━━━━━━"
LOG ""
LOG "0 = Nur WiFi"
LOG "1 = WiFi + GPS"
LOG "2 = WiFi + Bluetooth"
LOG "3 = Alle Module"
LOG ""
sleep 5
SCAN_MODE=$(NUMBER_PICKER "Scan-Modus (0-3):" 0)
case $? in
    $DUCKYSCRIPT_CANCELLED|$DUCKYSCRIPT_REJECTED|$DUCKYSCRIPT_ERROR)
        SCAN_MODE=0
        ;;
esac

# Module aktivieren
USE_GPS=false
USE_BT=false
case "$SCAN_MODE" in
    1) USE_GPS=true ;;
    2) USE_BT=true ;;
    3) USE_GPS=true; USE_BT=true ;;
esac

LOG ""
LOG "Module:"
[ "$USE_GPS" = true ] && LOG green "  ✓ GPS aktiv" || LOG "  ✗ GPS deaktiviert"
[ "$USE_BT"  = true ] && LOG green "  ✓ Bluetooth aktiv" || LOG "  ✗ Bluetooth deaktiviert"
LOG green "  ✓ WiFi aktiv"
sleep 2

# ============================================================
# GPS CHECK
# ============================================================
GPS_AVAILABLE=false
if [ "$USE_GPS" = true ]; then
    LOG ""
    LOG "Prüfe GPS..."
    GPS_RAW=$(GPS_GET)
    GPS_LAT=$(echo "$GPS_RAW" | awk '{print $1}')
    GPS_LON=$(echo "$GPS_RAW" | awk '{print $2}')

    if [ "$GPS_LAT" = "0" ] || [ -z "$GPS_LAT" ]; then
        LOG yellow "⚠ Kein GPS-Fix"
        LOG "Weiter ohne GPS..."
    else
        LOG green "✓ GPS-Fix: $GPS_LAT, $GPS_LON"
        GPS_AVAILABLE=true
    fi
    sleep 1
fi

# ============================================================
# SCAN KONFIGURATION
# ============================================================
LOG ""
LOG "Scan-Konfiguration:"
LOG ""

# Anzahl Runden wählen
SCAN_ROUNDS=$(NUMBER_PICKER "Scan-Runden:" 1)
case $? in
    $DUCKYSCRIPT_CANCELLED|$DUCKYSCRIPT_REJECTED|$DUCKYSCRIPT_ERROR)
        SCAN_ROUNDS=2
        ;;
esac
LOG "Runden: $SCAN_ROUNDS"

# Scan-Dauer wählen
SCAN_DURATION=$(NUMBER_PICKER "Dauer pro Runde (Sek):" 30)
case $? in
    $DUCKYSCRIPT_CANCELLED|$DUCKYSCRIPT_REJECTED|$DUCKYSCRIPT_ERROR)
        SCAN_DURATION=120
        ;;
esac
LOG "Dauer: ${SCAN_DURATION}s"

LOG ""
LOG ""

# ============================================================
# COUNTDOWN VOR START
# ============================================================
LOG ""
LOG "Scan startet in 5s..."
LOG "ROT = Abbrechen"
sleep 5
LOG green "▶ Scan gestartet!"

# ============================================================
# CLEANUP HANDLER
# ============================================================
PCAP_FILES=()
BT_SCAN_FILES=()

cleanup() {
    PINEAPPLE_HOPPING_STOP 2>/dev/null
    WIFI_PCAP_STOP 2>/dev/null
    LED off
}
trap cleanup EXIT INT TERM

# ============================================================
# SCAN RUNDEN
# ============================================================
LED cyan blink

# Channel Hopping starten
SPINNER_ID=$(START_SPINNER "Starte Channel-Hopping...")
PINEAPPLE_HOPPING_START
sleep 2
STOP_SPINNER "$SPINNER_ID"
LOG green "✓ Channel-Hopping aktiv"

for ROUND in $(seq 1 "$SCAN_ROUNDS"); do
    LOG ""
    LOG blue "━━━━━━━━━━━━━━━━━━━━━━━━━━"
    LOG blue "  Runde $ROUND / $SCAN_ROUNDS"
    LOG blue "━━━━━━━━━━━━━━━━━━━━━━━━━━"
    LOG ""

    TS=$(date +%Y%m%d_%H%M%S)
    PCAP_FILE="$PCAP_DIR/scan_${TS}_round${ROUND}.pcap"

    # GPS Koordinaten speichern
    if [ "$GPS_AVAILABLE" = true ]; then
        GPS_RAW=$(GPS_GET)
        GPS_LAT=$(echo "$GPS_RAW" | awk '{print $1}')
        GPS_LON=$(echo "$GPS_RAW" | awk '{print $2}')
        GPS_ALT=$(echo "$GPS_RAW" | awk '{print $3}')
        LOG "📍 GPS: $GPS_LAT, $GPS_LON"
        echo "$TS,$GPS_LAT,$GPS_LON,$GPS_ALT" >> "$LOOT_DIR/gps_track.csv"
    fi

    # Zeitstempel vor Capture merken
    PCAP_START_TIME=$(date +%s)

    # PCAP Capture + BT-Scan parallel starten
    LED blue blink
    WIFI_PCAP_START

    # BT-Scan im Hintergrund (wenn aktiviert)
    BT_PID=""
    BT_FILE=""
    if [ "$USE_BT" = true ]; then
        BT_FILE="$LOOT_DIR/bt_scan_${TS}_round${ROUND}.json"
        python3 "$PYTHON_DIR/bt_scanner.py"             --duration "$SCAN_DURATION"             --output "$BT_FILE" &
        BT_PID=$!
    fi

    if [ "$USE_BT" = true ]; then
        LOG "🔍 WiFi + BT Capture läuft..."
    else
        LOG "🔍 WiFi Capture läuft..."
    fi
    LOG "   Dauer: ${SCAN_DURATION}s"
    LOG ""

    # Countdown mit Status-Updates
    LOG "   ⏱ Scan läuft ${SCAN_DURATION}s..."
    ELAPSED=0
    STEP=15
    while [ "$ELAPSED" -lt "$SCAN_DURATION" ]; do
        sleep $STEP
        ELAPSED=$((ELAPSED + STEP))
        REMAINING=$((SCAN_DURATION - ELAPSED))
        if [ "$REMAINING" -gt 0 ]; then
            LOG "   ⏱ Noch ${REMAINING}s..."
        fi
    done

    # PCAP stoppen und sichern
    WIFI_PCAP_STOP
    # BT-Scan abwarten
    if [ -n "$BT_PID" ]; then
        wait $BT_PID 2>/dev/null
        [ -f "$BT_FILE" ] && BT_SCAN_FILES+=("$BT_FILE") &&             LOG green "✓ BT-Scan: $(python3 -c "import json; d=json.load(open('$BT_FILE')); print(len(d.get('bt_devices',{})))" 2>/dev/null || echo '?') Geräte"
    fi
    # Warten bis WIFI_PCAP_STOP die Datei fertig geschrieben hat
    sleep 5
    # Nur PCAP nehmen die während diesem Scan erstellt wurde
    LATEST_PCAP=""
    for f in $(ls -t /root/loot/pcap/*.pcap 2>/dev/null); do
        FILE_TIME=$(date -r "$f" +%s 2>/dev/null)
        if [ "$FILE_TIME" -ge "$PCAP_START_TIME" ]; then
            LATEST_PCAP="$f"
            break
        fi
    done

    if [ -n "$LATEST_PCAP" ]; then
        cp "$LATEST_PCAP" "$PCAP_FILE"
        PCAP_FILES+=("$PCAP_FILE")
        PROBE_COUNT=$(tcpdump -r "$PCAP_FILE" 2>/dev/null | wc -l)
        LOG green "✓ Runde $ROUND: $PROBE_COUNT Probes"
    else
        LOG yellow "⚠ Keine neue PCAP gefunden"
    fi

    # GPS nach Runde aktualisieren
    if [ "$GPS_AVAILABLE" = true ]; then
        GPS_RAW=$(GPS_GET)
        GPS_LAT=$(echo "$GPS_RAW" | awk '{print $1}')
        GPS_LON=$(echo "$GPS_RAW" | awk '{print $2}')
    fi

    # Pause zwischen Runden
    if [ "$ROUND" -lt "$SCAN_ROUNDS" ]; then
        LOG ""
        LOG yellow "⏸ Pause 10s..."
        sleep 10
    fi
done

# Hopping stoppen
PINEAPPLE_HOPPING_STOP
LOG ""
LOG green "✓ Alle Scans abgeschlossen"

# ============================================================
# PYTHON ANALYSE
# ============================================================
if [ ${#PCAP_FILES[@]} -eq 0 ]; then
    LOG red "Keine PCAP-Dateien gefunden!"
    LED red
    sleep 3
    exit 1
fi

LED amber solid
SPINNER_ID=$(START_SPINNER "Analysiere Daten...")

PCAP_LIST=$(IFS=','; echo "${PCAP_FILES[*]}")

BT_LIST=$(IFS=','; echo "${BT_SCAN_FILES[*]}")
python3 "$PYTHON_DIR/analyze_pcap.py" \
    --pcaps "$PCAP_LIST" \
    --config "$CONFIG_FILE" \
    --output-dir "$REPORT_DIR" \
    --threshold "$PERSISTENCE_THRESHOLD" \
    --min-appearances "$MIN_APPEARANCES" \
    ${BT_LIST:+--bt-scans "$BT_LIST"}

RESULT=$?
STOP_SPINNER "$SPINNER_ID"
sleep 2

# ============================================================
# ERGEBNIS ANZEIGEN
# ============================================================
LATEST_REPORT=$(ls -t "$REPORT_DIR"/*.md 2>/dev/null | head -1)
LOG "Debug: $LATEST_REPORT"

LOG ""
LOG blue "━━━━━━━━━━━━━━━━━━━━━━━━━━"
LOG blue "       ERGEBNIS"
LOG blue "━━━━━━━━━━━━━━━━━━━━━━━━━━"
LOG ""

if [ -f "$LATEST_REPORT" ]; then
    # Statistiken aus Report lesen
    TOTAL=$(grep "Geräte gesamt" "$LATEST_REPORT" | grep -o '[0-9]*' | head -1)
    SUSPICIOUS=$(grep "Verdächtig" "$LATEST_REPORT" | grep -o '[0-9]*' | head -1)

    LOG "📊 Geräte gesamt:  ${TOTAL:-0}"
    LOG "🔍 Verdächtig:     ${SUSPICIOUS:-0}"
    LOG ""

    if [ "$RESULT" -eq 2 ] || [ "${SUSPICIOUS:-0}" -gt 0 ]; then
        LED red blink
        LOG red "⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠"
        LOG red "  WARNUNG!"
        LOG red "  Verdächtige Geräte"
        LOG red "  erkannt!"
        LOG red "⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠"
        LOG ""
        # Verdächtige MACs anzeigen
        grep "🔴\|⚠" "$LATEST_REPORT" 2>/dev/null | while read -r line; do
            LOG red "$line"
        done
        VIBRATE 3
    else
        LED green solid
        LOG green "✅ Keine Auffälligkeiten"
        LOG green "   Alles unauffällig!"
    fi
else
    LOG yellow "⚠ Kein Report generiert"
    LED yellow
fi

LOG ""
LOG "Report: $LATEST_REPORT"
LOG ""

if [ "$GPS_AVAILABLE" = true ]; then
    LOG "📍 GPS-Track gespeichert"
    LOG "   $LOOT_DIR/gps_track.csv"
fi

LOG ""
LOG "Loot: $LOOT_DIR"
LOG ""

# ============================================================
# WARTEN AUF BEENDEN
# ============================================================
LOG "Drücke ROT zum Beenden"
WAIT_FOR_BUTTON_PRESS "red"
LED off
exit 0
