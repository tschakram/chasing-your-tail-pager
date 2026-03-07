#!/bin/bash
# Title: Chasing Your Tail NG
# Description: Surveillance detection via WiFi probe request persistence analysis
# Author: tschakram
# Category: reconnaissance
# Version: 3.0
# Based on: ArgeliusLabs/Chasing-Your-Tail-NG (MIT)

# OpenWrt: mmc-Pakete nicht im Standard-PATH (Pager Framework = non-login shell)
export PATH="/mmc/usr/bin:/mmc/usr/sbin:/mmc/bin:/mmc/sbin:$PATH"
export LD_LIBRARY_PATH="/mmc/usr/lib:/mmc/lib:${LD_LIBRARY_PATH:-}"

# ============================================================
# CONFIGURATION
# ============================================================
SCAN_ROUNDS=1
SCAN_DURATION=30
PERSISTENCE_THRESHOLD=0.6
# MIN_APPEARANCES wird dynamisch nach SCAN_DURATION berechnet

LOOT_DIR="/root/loot/chasing_your_tail"
PCAP_DIR="$LOOT_DIR/pcap"
REPORT_DIR="$LOOT_DIR/surveillance_reports"
PYTHON_DIR="/root/payloads/user/reconnaissance/chasing_your_tail/python"
CONFIG_FILE="/root/payloads/user/reconnaissance/chasing_your_tail/config.json"

# ============================================================
# SETUP
# ============================================================
mkdir -p "$PCAP_DIR" "$REPORT_DIR"

LOG "=============================="
LOG "  Chasing Your Tail NG v4.4"
LOG "=============================="
LOG ""
LOG "Surveillance Detection"
LOG "via WiFi Probe Analysis"
LOG ""
sleep 2

# ============================================================
# DEPENDENCY CHECK
# ============================================================
SPINNER_ID=$(START_SPINNER "Checking dependencies...")

# Systemzeit prüfen und synchronisieren
CURRENT_YEAR=$(date +%Y)
if ntpd -q -p pool.ntp.org 2>/dev/null; then
    LOG green "✓ Zeit via NTP: $(date '+%d.%m.%Y %H:%M')"
elif [ "$CURRENT_YEAR" -lt 2026 ]; then
    # Systemzeit falsch - aus Hardware Clock laden
    hwclock -s 2>/dev/null
    CURRENT_YEAR=$(date +%Y)
    if [ "$CURRENT_YEAR" -lt 2026 ]; then
        LOG yellow "⚠ Systemzeit ungültig: $(date '+%d.%m.%Y %H:%M')"
        LOG yellow "  Report-Timestamps werden falsch sein!"
    else
        LOG green "✓ Zeit aus RTC: $(date '+%d.%m.%Y %H:%M')"
    fi
else
    LOG green "✓ Systemzeit OK: $(date '+%d.%m.%Y %H:%M')"
fi

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
# CLEANUP ALTER SCAN-DATEN
# ============================================================
CLEANUP_OUT=$(python3 "$PYTHON_DIR/cleanup.py" --config "$CONFIG_FILE" 2>/dev/null)
CLEANUP_MSG=$(echo "$CLEANUP_OUT" | grep "^CLEANUP:" | cut -d: -f2-)
[ -n "$CLEANUP_MSG" ] && LOG green "🗑 Cleanup: $CLEANUP_MSG"

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
LOG "4 = Hotel-Scan (Kamera)"
LOG ""
sleep 5
SCAN_MODE=$(NUMBER_PICKER "Scan-Modus (0-4):" 0)
case $? in
    $DUCKYSCRIPT_CANCELLED|$DUCKYSCRIPT_REJECTED|$DUCKYSCRIPT_ERROR)
        SCAN_MODE=0
        ;;
esac

# Module aktivieren
USE_GPS=false
USE_BT=false
HOTEL_SCAN=false
case "$SCAN_MODE" in
    1) USE_GPS=true ;;
    2) USE_BT=true ;;
    3) USE_GPS=true; USE_BT=true ;;
    4) HOTEL_SCAN=true; USE_BT=true ;;
esac

LOG ""
LOG "Module:"
[ "$USE_GPS"      = true ] && LOG green "  ✓ GPS aktiv"             || LOG "  ✗ GPS deaktiviert"
[ "$USE_BT"       = true ] && LOG green "  ✓ Bluetooth aktiv"       || LOG "  ✗ Bluetooth deaktiviert"
[ "$HOTEL_SCAN"   = true ] && LOG green "  ✓ Hotel-Scan aktiv"      || LOG "  ✗ Hotel-Scan deaktiviert"
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

# min_appearances dynamisch: ~1 pro 60s, min 3, max 15
MIN_APPEARANCES=$(( SCAN_DURATION / 60 + 2 ))
[ "$MIN_APPEARANCES" -lt 3 ] && MIN_APPEARANCES=3
[ "$MIN_APPEARANCES" -gt 15 ] && MIN_APPEARANCES=15
LOG "Min. Appearances: ${MIN_APPEARANCES}"

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
SCAN_START_TIME=$(date +%s)

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

LED amber solid
SPINNER_ID=$(START_SPINNER "Analysiere Daten...")

# Nur PCAPe vom aktuellen Lauf (nach SCAN_START_TIME)
PCAP_LIST=""
for f in $(ls -t "$PCAP_DIR"/scan_*.pcap 2>/dev/null); do
    FILE_TIME=$(date -r "$f" +%s 2>/dev/null)
    if [ "$FILE_TIME" -ge "$SCAN_START_TIME" ]; then
        PCAP_LIST="${PCAP_LIST:+$PCAP_LIST,}$f"
    fi
done

BT_LIST=$(ls -t "$LOOT_DIR"/bt_scan_*.json 2>/dev/null | grep -v "test" | tr "\n" "," | sed "s/,$//"  )

if [ "$HOTEL_SCAN" = true ]; then
    # ── Modus 4: Hotel-Scan ────────────────────────────────
    # Letztes PCAP für Beacon-Analyse verwenden
    HOTEL_PCAP=$(echo "$PCAP_LIST" | tr ',' '\n' | tail -1)
    HOTEL_BT=""
    if [ -n "$BT_LIST" ]; then
        HOTEL_BT=$(echo "$BT_LIST" | tr ',' '\n' | head -1)
    fi

    ANALYSIS_OUTPUT=$(python3 "$PYTHON_DIR/hotel_scan.py" \
        --pcap "$HOTEL_PCAP" \
        ${HOTEL_BT:+--bt-scan "$HOTEL_BT"} \
        --output-dir "$REPORT_DIR" 2>&1)

    RESULT=$?
    LATEST_REPORT=$(echo "$ANALYSIS_OUTPUT" | grep "REPORT_PATH:" | cut -d: -f2-)
    if [ -z "$LATEST_REPORT" ]; then
        LATEST_REPORT=$(ls "$REPORT_DIR"/hotel_scan_*.md 2>/dev/null | sort | tail -1)
    fi
    echo "$ANALYSIS_OUTPUT" | grep -v "REPORT_PATH:" >&2
else
    # ── Modi 0-3: Normale Probe-Request-Analyse ────────────
    ANALYSIS_OUTPUT=$(python3 "$PYTHON_DIR/analyze_pcap.py" \
        --pcaps "$PCAP_LIST" \
        --config "$CONFIG_FILE" \
        --output-dir "$REPORT_DIR" \
        --threshold "$PERSISTENCE_THRESHOLD" \
        --min-appearances "$MIN_APPEARANCES" \
        ${BT_LIST:+--bt-scans "$BT_LIST"} 2>&1)

    RESULT=$?
    LATEST_REPORT=$(echo "$ANALYSIS_OUTPUT" | grep "REPORT_PATH:" | cut -d: -f2-)
    if [ -z "$LATEST_REPORT" ]; then
        LATEST_REPORT=$(ls "$REPORT_DIR"/cyt_report_*.md 2>/dev/null | sort | tail -1)
    fi
    echo "$ANALYSIS_OUTPUT" | grep -v "REPORT_PATH:" >&2
fi

STOP_SPINNER "$SPINNER_ID"
sleep 2

# ============================================================

LOG ""
LOG blue "━━━━━━━━━━━━━━━━━━━━━━━━━━"
LOG blue "       ERGEBNIS"
LOG blue "━━━━━━━━━━━━━━━━━━━━━━━━━━"
LOG ""

if [ -f "$LATEST_REPORT" ]; then
    if [ "$HOTEL_SCAN" = true ]; then
        # Hotel-Scan Ergebnis
        WIFI_CAM=$(grep "WiFi Kamera-Verdächtige:" "$LATEST_REPORT" | grep -o '[0-9]*' | head -1)
        BLE_CAM=$(grep "BLE Kamera/IoT-Verdächtige:" "$LATEST_REPORT" | grep -o '[0-9]*' | head -1)
        SUSPICIOUS=$(( ${WIFI_CAM:-0} + ${BLE_CAM:-0} ))

        LOG "📷 WiFi Kameras: ${WIFI_CAM:-0}"
        LOG "📡 BLE Verdächt: ${BLE_CAM:-0}"
        LOG ""

        if [ "$RESULT" -eq 2 ] || [ "${SUSPICIOUS:-0}" -gt 0 ]; then
            LED red blink
            LOG red "🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨"
            LOG red "  KAMERA VERDACHT!"
            LOG red "  Raum prüfen!"
            LOG red "🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨"
            LOG ""
            grep "KRITISCH\|📷\|🔴" "$LATEST_REPORT" 2>/dev/null | head -10 | while read -r line; do
                LOG red "$line"
            done
            VIBRATE 5
        else
            LED green solid
            LOG green "✅ Keine Kameras erkannt"
            LOG green "   Zimmer unauffällig!"
        fi
    else
        # Normaler Scan
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
            grep "🔴\|⚠" "$LATEST_REPORT" 2>/dev/null | while read -r line; do
                LOG red "$line"
            done
            VIBRATE 3
        else
            LED green solid
            LOG green "✅ Keine Auffälligkeiten"
            LOG green "   Alles unauffällig!"
        fi
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
# Report anzeigen?
CONFIRMATION_DIALOG "Report anzeigen?"
case $? in
    $DUCKYSCRIPT_CANCELLED|$DUCKYSCRIPT_REJECTED|$DUCKYSCRIPT_ERROR)
        SHOW_REPORT=false ;;
    *)
        SHOW_REPORT=true ;;
esac
if [ "$SHOW_REPORT" = true ]; then
    if [ -f "$LATEST_REPORT" ]; then
        LOG ""
        LOG "=============================="
        LOG "         REPORT"
        LOG "=============================="
        # Nur relevante Zeilen anzeigen - keine Tabellen
        grep "Datum:\|Geräte gesamt:\|Verdächtig:\|Ignoriert:\|WARNING\|Keine verdäch"             "$LATEST_REPORT" | while IFS= read -r line; do
            line=$(echo "$line" | sed "s/\*\*//g")
            LOG "$line"
        done
        LOG ""
        LOG "Verdächtige MACs:"
        grep "^| 🔴" "$LATEST_REPORT" | while IFS= read -r line; do
            # Format: MAC | Hersteller | Score | Appearances
            MAC=$(echo "$line" | awk -F"|" "{print \$2}" | tr -d " \`")
            VENDOR=$(echo "$line" | awk -F"|" "{print \$3}" | tr -d " ")
            MTYPE=$(echo "$line" | awk -F"|" "{print \$4}" | tr -d " ")
            SCORE=$(echo "$line" | awk -F"|" "{print \$5}" | tr -d " ")
            APP=$(echo "$line" | awk -F"|" "{print \$6}" | tr -d " ")
            LOG "  $MAC"
            LOG "  $VENDOR ($MTYPE)"
            LOG "  Score:$SCORE Seen:$APP"
            LOG "  --------------------"
        done
        LOG "=============================="
    fi
fi

# ============================================================
# WATCH-LIST Management
# ============================================================
if [ -f "$LATEST_REPORT" ]; then
    WATCH_TMP=$(mktemp /tmp/cyt_watch_XXXXXX 2>/dev/null || echo "/tmp/cyt_watch_$$")

    # Verdächtige MACs aus Report extrahieren → "MAC|Hersteller" pro Zeile
    grep "^| 🔴" "$LATEST_REPORT" | awk -F'|' '{
        mac=$2; gsub(/[[:space:]`]/, "", mac)
        vendor=$3; gsub(/^[[:space:]]+|[[:space:]]+$/, "", vendor)
        if (mac != "") print mac "|" vendor
    }' > "$WATCH_TMP"

    MAC_COUNT=$(awk 'END{print NR}' "$WATCH_TMP")

    if [ "$MAC_COUNT" -gt 0 ]; then
        LOG ""
        LOG blue "━━━━━━━━━━━━━━━━━━━━━━━━━━"
        LOG blue "   Watch-List Management"
        LOG blue "━━━━━━━━━━━━━━━━━━━━━━━━━━"
        LOG ""

        # Nummerierte Liste anzeigen
        i=1
        while IFS='|' read -r wl_mac wl_vendor; do
            [ -z "$wl_mac" ] && continue
            LOG "  $i = $wl_mac"
            LOG "      $wl_vendor"
            i=$((i+1))
        done < "$WATCH_TMP"
        LOG "  0 = Überspringen"
        LOG ""

        WATCH_PICK=$(NUMBER_PICKER "Gerät zur Watch-List:" 0)

        if [ -n "$WATCH_PICK" ] && [ "$WATCH_PICK" -gt 0 ] 2>/dev/null && \
           [ "$WATCH_PICK" -le "$MAC_COUNT" ] 2>/dev/null; then

            SELECTED_LINE=$(sed -n "${WATCH_PICK}p" "$WATCH_TMP")
            SELECTED_MAC=$(echo "$SELECTED_LINE" | cut -d'|' -f1)
            SELECTED_VENDOR=$(echo "$SELECTED_LINE" | cut -d'|' -f2-)

            if [ -n "$SELECTED_MAC" ]; then
                LOG ""
                LOG "Gerät:  $SELECTED_MAC"
                LOG "        $SELECTED_VENDOR"
                LOG ""
                LOG "  1 = Dynamic  (Tracking-Erkennung)"
                LOG "  2 = Static   (Nur an bekanntem Ort)"
                LOG ""
                WATCH_TYPE_NUM=$(NUMBER_PICKER "Überwachungstyp:" 1)

                if [ "$WATCH_TYPE_NUM" -eq 2 ] 2>/dev/null; then
                    WATCH_TYPE="static"
                else
                    WATCH_TYPE="dynamic"
                fi

                # Zonenwahl für Static-Typ (Zonen aus config.json - nur auf dem Pager)
                ZONE_IDX=""
                if [ "$WATCH_TYPE" = "static" ]; then
                    ZONE_TMP=$(mktemp /tmp/cyt_zones_XXXXXX 2>/dev/null || echo "/tmp/cyt_zones_$$")
                    python3 "$PYTHON_DIR/watchlist_add.py" \
                        --list-zones --config "$CONFIG_FILE" 2>/dev/null \
                        | grep "^ZONE:" | cut -d: -f2- > "$ZONE_TMP"

                    LOG ""
                    LOG "Zone wählen:"
                    zi=1
                    while IFS= read -r zname; do
                        [ -z "$zname" ] && continue
                        LOG "  $zi = $zname"
                        zi=$((zi+1))
                    done < "$ZONE_TMP"
                    LOG "  0 = Ohne Zone"
                    LOG ""
                    rm -f "$ZONE_TMP"

                    ZONE_IDX=$(NUMBER_PICKER "Zone:" 1)
                fi

                LOG ""
                LOG "Hinzufügen:"
                LOG "  MAC:  $SELECTED_MAC"
                LOG "  Typ:  $WATCH_TYPE"
                LOG ""

                CONFIRMATION_DIALOG "Watch-List: $SELECTED_MAC ($WATCH_TYPE)?"
                case $? in
                    $DUCKYSCRIPT_CANCELLED|$DUCKYSCRIPT_REJECTED|$DUCKYSCRIPT_ERROR)
                        LOG yellow "⚠ Abgebrochen."
                        ;;
                    *)
                        if [ "$WATCH_TYPE" = "static" ]; then
                            WL_OUT=$(python3 "$PYTHON_DIR/watchlist_add.py" \
                                --mac "$SELECTED_MAC" \
                                --label "$SELECTED_VENDOR" \
                                --type "$WATCH_TYPE" \
                                --zone-idx "$ZONE_IDX" \
                                --lat "${GPS_LAT:-0}" --lon "${GPS_LON:-0}" \
                                --config "$CONFIG_FILE" 2>/dev/null)
                        else
                            WL_OUT=$(python3 "$PYTHON_DIR/watchlist_add.py" \
                                --mac "$SELECTED_MAC" \
                                --label "$SELECTED_VENDOR" \
                                --type "$WATCH_TYPE" \
                                --config "$CONFIG_FILE" 2>/dev/null)
                        fi

                        WL_STATUS=$(echo "$WL_OUT" | grep "^WATCHLIST:" | cut -d: -f2)
                        WL_ZONE=$(echo "$WL_OUT" | grep "^WATCHLIST:" | cut -d: -f4-)
                        case "$WL_STATUS" in
                            OK)
                                VIBRATE 3
                                LOG green "✓ Watch-List: $SELECTED_MAC"
                                LOG green "  Typ: $WATCH_TYPE"
                                [ -n "$WL_ZONE" ] && LOG green "  Zone: $WL_ZONE"
                                ;;
                            ALREADY_EXISTS)
                                WL_LABEL=$(echo "$WL_OUT" | grep "^WATCHLIST:" | cut -d: -f3-)
                                LOG yellow "⚠ Bereits in Watch-List:"
                                LOG yellow "  $WL_LABEL"
                                ;;
                            *)
                                LOG red "✗ Watch-List Fehler"
                                ;;
                        esac
                        ;;
                esac
            fi
        fi
    fi

    rm -f "$WATCH_TMP"
fi

LOG "Drücke ROT zum Beenden"
WAIT_FOR_BUTTON_PRESS "red"
LED off
exit 0
