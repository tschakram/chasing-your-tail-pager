#!/bin/bash
# ============================================================
# Title:        Chasing Your Tail - NG
# Description:  Counter-surveillance via passive WiFi Probe
#               Request analysis. Kein Kismet nötig - nutzt
#               tcpdump + Python PCAP-Parser.
# Author:       tschakram
# Version:      2.0
# Category:     Reconnaissance
# ============================================================
# LED:
#   Cyan Blink    - Initialisierung
#   Blue Blink    - Scanning läuft
#   Amber Solid   - Warnung: Verdächtige Signale
#   Green Solid   - Abgeschlossen, keine Auffälligkeiten
#   Red Blink     - Fehler

PAYLOAD_DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON_DIR="$PAYLOAD_DIR/python"
LOOT_DIR="/root/loot/chasing_your_tail"
REPORT_DIR="$LOOT_DIR/surveillance_reports"
LOG_DIR="$LOOT_DIR/logs"
CONFIG="$PAYLOAD_DIR/config.json"
IFACE="wlan1mon"
SCAN_DURATION=120      # Sekunden pro Scan
SCAN_ROUNDS=2          # Anzahl Scans für Persistence-Vergleich
HOP_INTERVAL=0.3       # Sekunden pro Kanal beim Channel-Hopping

# ============================================================
# SETUP
# ============================================================
LED CYAN BLINK
mkdir -p "$LOOT_DIR" "$REPORT_DIR" "$LOG_DIR"
MAIN_LOG="$LOG_DIR/payload_$(date +%Y%m%d_%H%M%S).log"
PCAP_DIR="$LOOT_DIR/pcap"
mkdir -p "$PCAP_DIR"

log() {
    echo "[$(date '+%H:%M:%S')] $1" | tee -a "$MAIN_LOG"
}

log "========================================"
log " Chasing Your Tail NG v2.0"
log " Interface: $IFACE"
log " Scan-Dauer: ${SCAN_DURATION}s x ${SCAN_ROUNDS} Runden"
log "========================================"

# ============================================================
# ABHÄNGIGKEITEN PRÜFEN
# ============================================================
log "Prüfe Abhängigkeiten..."

# Python3 PATH sicherstellen (MMC-Installation)
export PATH="/opt/usr/bin:/opt/usr/sbin:$PATH"

if ! command -v python3 &>/dev/null; then
    log "FEHLER: python3 nicht gefunden!"
    LED RED BLINK
    exit 1
fi

if ! command -v tcpdump &>/dev/null; then
    log "tcpdump fehlt - installiere..."
    opkg install -d mmc tcpdump >> "$MAIN_LOG" 2>&1
    if ! command -v tcpdump &>/dev/null; then
        log "FEHLER: tcpdump Installation fehlgeschlagen!"
        LED RED BLINK
        exit 1
    fi
fi

if ! command -v iw &>/dev/null; then
    log "FEHLER: iw nicht gefunden!"
    LED RED BLINK
    exit 1
fi

log "Alle Abhängigkeiten OK"

# ============================================================
# INTERFACE PRÜFEN
# ============================================================
if ! ip link show "$IFACE" &>/dev/null; then
    log "FEHLER: Interface $IFACE nicht gefunden!"
    log "Verfügbare Interfaces:"
    ip link show | grep -E "^[0-9]" | tee -a "$MAIN_LOG"
    LED RED BLINK
    exit 1
fi

log "Interface $IFACE OK"

# ============================================================
# CHANNEL HOPPING STARTEN
# ============================================================
log "Starte Channel-Hopping..."

cat > /tmp/cyt_hop.sh << 'HOPEOF'
#!/bin/sh
IFACE="wlan1mon"
while true; do
    for ch in 1 2 3 4 5 6 7 8 9 10 11 36 40 44 48; do
        iw dev "$IFACE" set channel $ch 2>/dev/null
        sleep 0.3
    done
done
HOPEOF
chmod +x /tmp/cyt_hop.sh
/tmp/cyt_hop.sh &
HOP_PID=$!
log "Channel-Hopping PID: $HOP_PID"
sleep 2

# ============================================================
# SCANS DURCHFÜHREN
# ============================================================
LED BLUE BLINK
PCAP_FILES=()

for round in $(seq 1 $SCAN_ROUNDS); do
    PCAP="$PCAP_DIR/scan_$(date +%Y%m%d_%H%M%S)_round${round}.pcap"
    log "Starte Scan $round/$SCAN_ROUNDS → $PCAP"

    tcpdump -i "$IFACE" \
        -w "$PCAP" \
        type mgt subtype probe-req \
        >> "$MAIN_LOG" 2>&1 &
    TCP_PID=$!

    sleep "$SCAN_DURATION"
    kill "$TCP_PID" 2>/dev/null
    wait "$TCP_PID" 2>/dev/null

    # Pakete zählen
    COUNT=$(tcpdump -r "$PCAP" 2>/dev/null | wc -l)
    log "Scan $round abgeschlossen: $COUNT Probe-Requests erfasst"
    PCAP_FILES+=("$PCAP")

    # Zwischen Scans kurz warten (außer nach letztem)
    if [ "$round" -lt "$SCAN_ROUNDS" ]; then
        log "Warte 10s vor nächstem Scan..."
        sleep 10
    fi
done

# Channel-Hopping stoppen
kill "$HOP_PID" 2>/dev/null
log "Channel-Hopping gestoppt"

# ============================================================
# PYTHON ANALYSE
# ============================================================
log "Starte Python-Analyse..."
export PYTHONPATH="$PYTHON_DIR:$PYTHONPATH"

# PCAP-Dateien als kommagetrennte Liste übergeben
PCAP_LIST=$(IFS=','; echo "${PCAP_FILES[*]}")

python3 "$PYTHON_DIR/analyze_pcap.py" \
    --pcaps "$PCAP_LIST" \
    --config "$CONFIG" \
    --output-dir "$REPORT_DIR" \
    --log-file "$LOG_DIR/analysis.log"

RESULT=$?

# ============================================================
# ERGEBNIS
# ============================================================
LATEST=$(ls -t "$REPORT_DIR"/*.md 2>/dev/null | head -1)

if [ "$RESULT" -eq 2 ]; then
    log "WARNUNG: Verdächtige Geräte erkannt!"
    LED AMBER SOLID
    NOTIFY "CYT: Verdächtige Signale erkannt! Report: $LATEST"
else
    log "Keine Auffälligkeiten."
    LED GREEN SOLID
    NOTIFY "CYT: Scan abgeschlossen. Loot: $LOOT_DIR"
fi

log "Fertig. Alle Ergebnisse unter: $LOOT_DIR"
