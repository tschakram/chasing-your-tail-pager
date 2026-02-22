#!/bin/bash
# ============================================================
# Title:        Chasing Your Tail - NG
# Description:  Counter-surveillance tool. Detects if you are
#               being followed by analyzing recurring WiFi probe
#               requests via Kismet + WiGLE correlation.
#               Based on ArgeliusLabs/Chasing-Your-Tail-NG (MIT)
# Author:       tschakram
# Version:      1.0
# Category:     Reconnaissance
# ============================================================
# LED:
#   Cyan Blink    - Initialisierung / Dependency-Check
#   Blue Blink    - Kismet startet / Python läuft
#   Amber Solid   - Warnung: Verdächtige Signale erkannt
#   Green Solid   - Abgeschlossen, keine Auffälligkeiten
#   Red Blink     - Fehler

# ============================================================
# PFADE & KONFIGURATION
# ============================================================
PAYLOAD_DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON_DIR="$PAYLOAD_DIR/python"
LOOT_DIR="/root/loot/chasing_your_tail"
LOG_DIR="$LOOT_DIR/logs"
REPORT_DIR="$LOOT_DIR/surveillance_reports"
KML_DIR="$LOOT_DIR/kml_files"
ANALYSIS_LOG="$LOOT_DIR/analysis_logs/cyt.log"
CONFIG="$PAYLOAD_DIR/config.json"
KISMET_DB_PATTERN="$LOOT_DIR/kismet_data/*.kismet"
KISMET_IFACE="wlan1"       # Monitor-Mode Interface
SCAN_DURATION=300          # Sekunden Kismet läuft bevor Analyse startet (5 Min)

# ============================================================
# SETUP
# ============================================================
LED CYAN BLINK

mkdir -p "$LOOT_DIR" "$LOG_DIR" "$REPORT_DIR" "$KML_DIR" \
         "$LOOT_DIR/analysis_logs" "$LOOT_DIR/kismet_data" \
         "$LOOT_DIR/ignore_lists"

MAIN_LOG="$LOG_DIR/payload_$(date +%Y%m%d_%H%M%S).log"

log() {
    local level="$1"
    local msg="$2"
    echo "[$(date '+%H:%M:%S')] [$level] $msg" | tee -a "$MAIN_LOG"
}

log "INFO" "========================================"
log "INFO" " Chasing Your Tail NG - Pineapple Pager"
log "INFO" "========================================"
log "INFO" "Payload-Dir: $PAYLOAD_DIR"
log "INFO" "Loot-Dir:    $LOOT_DIR"

# ============================================================
# SCHRITT 1: ABHÄNGIGKEITEN PRÜFEN & INSTALLIEREN
# ============================================================
log "INFO" "Prüfe Abhängigkeiten..."

MISSING_PKGS=()
MISSING_PY=()
NEED_OPKG_UPDATE=false

# --- System-Pakete prüfen ---
check_pkg() {
    local cmd="$1"
    local pkg="$2"
    if ! command -v "$cmd" &>/dev/null; then
        log "WARN" "Nicht gefunden: $cmd (Paket: $pkg)"
        MISSING_PKGS+=("$pkg")
        NEED_OPKG_UPDATE=true
    else
        log "INFO" "OK: $cmd"
    fi
}

check_pkg "kismet"    "kismet"
check_pkg "python3"   "python3"
check_pkg "iw"        "iw"

# --- Python3-Module prüfen (über opkg, kein pip!) ---
check_python_mod() {
    local mod="$1"
    local pkg="$2"
    if ! python3 -c "import $mod" 2>/dev/null; then
        log "WARN" "Python-Modul fehlt: $mod (opkg: $pkg)"
        MISSING_PY+=("$pkg")
        NEED_OPKG_UPDATE=true
    else
        log "INFO" "OK: python3 $mod"
    fi
}

check_python_mod "sqlite3"  "python3-sqlite3"
check_python_mod "json"     "python3-json"        # meist eingebaut
check_python_mod "requests" "python3-urllib3"
check_python_mod "datetime" ""                    # stdlib
check_python_mod "logging"  ""                    # stdlib

# --- Fehlende Pakete installieren? ---
ALL_MISSING=("${MISSING_PKGS[@]}" "${MISSING_PY[@]}")

if [ ${#ALL_MISSING[@]} -gt 0 ]; then
    log "WARN" "Fehlende Pakete: ${ALL_MISSING[*]}"

    # Auf Pineapple Pager: Payload kann per CONFIRM_DIALOG fragen
    # Fallback: direkt installieren wenn root
    if [ "$(id -u)" -eq 0 ]; then
        log "INFO" "Starte Installation fehlender Pakete auf MMC..."

        if $NEED_OPKG_UPDATE; then
            log "INFO" "Aktualisiere opkg-Paketliste..."
            opkg update >> "$MAIN_LOG" 2>&1
            if [ $? -ne 0 ]; then
                log "ERROR" "opkg update fehlgeschlagen. Internetverbindung prüfen!"
                LED RED BLINK
                exit 1
            fi
        fi

        for pkg in "${ALL_MISSING[@]}"; do
            [ -z "$pkg" ] && continue
            log "INFO" "Installiere: $pkg auf MMC..."
            opkg install -d mmc "$pkg" >> "$MAIN_LOG" 2>&1
            if [ $? -ne 0 ]; then
                log "WARN" "Installation fehlgeschlagen: $pkg (möglicherweise nicht verfügbar)"
            else
                log "INFO" "Installiert: $pkg"
            fi
        done

        # Nach Installation nochmal python3 prüfen
        if ! command -v python3 &>/dev/null; then
            # Python könnte in /opt/usr/bin landen (MMC-Installation)
            export PATH="/opt/usr/bin:/opt/usr/sbin:$PATH"
        fi

    else
        log "ERROR" "Root-Rechte benötigt für Installation. Bitte als root ausführen."
        LED RED BLINK
        exit 1
    fi
fi

# --- Finale Prüfung: Kismet & Python3 verfügbar? ---
if ! command -v kismet &>/dev/null; then
    # Nochmal mit erweitertem PATH
    export PATH="/opt/usr/bin:/opt/usr/sbin:/usr/bin:/usr/sbin:$PATH"
    if ! command -v kismet &>/dev/null; then
        log "ERROR" "Kismet konnte nicht gefunden oder installiert werden!"
        LED RED BLINK
        exit 1
    fi
fi

if ! command -v python3 &>/dev/null; then
    log "ERROR" "Python3 konnte nicht gefunden oder installiert werden!"
    LED RED BLINK
    exit 1
fi

log "INFO" "Alle Abhängigkeiten vorhanden."

# ============================================================
# SCHRITT 2: CONFIG ERSTELLEN (falls nicht vorhanden)
# ============================================================
if [ ! -f "$CONFIG" ]; then
    log "INFO" "Erstelle Standard-config.json..."
    cat > "$CONFIG" << EOF
{
  "paths": {
    "base_dir": "$LOOT_DIR",
    "log_dir": "$LOG_DIR",
    "kismet_logs": "$KISMET_DB_PATTERN",
    "ignore_lists": {
      "mac": "$LOOT_DIR/ignore_lists/mac_list.json",
      "ssid": "$LOOT_DIR/ignore_lists/ssid_list.json"
    }
  },
  "timing": {
    "check_interval": 60,
    "list_update_interval": 5,
    "time_windows": {
      "recent": 5,
      "medium": 10,
      "old": 15,
      "oldest": 20
    }
  },
  "search": {
    "lat_min": -90.0,
    "lat_max": 90.0,
    "lon_min": -180.0,
    "lon_max": 180.0
  },
  "wigle": {
    "enabled": false,
    "api_name": "",
    "api_token": ""
  },
  "surveillance": {
    "persistence_threshold": 0.6,
    "min_appearances": 3,
    "stalking_min_persistence": 0.8
  }
}
EOF
    log "INFO" "config.json erstellt."
fi

# Ignore-Listen anlegen falls nicht vorhanden
if [ ! -f "$LOOT_DIR/ignore_lists/mac_list.json" ]; then
    echo '{"ignore_macs": [], "description": "MAC-Adressen die ignoriert werden sollen"}' \
        > "$LOOT_DIR/ignore_lists/mac_list.json"
fi
if [ ! -f "$LOOT_DIR/ignore_lists/ssid_list.json" ]; then
    echo '{"ignore_ssids": [], "description": "SSIDs die ignoriert werden sollen"}' \
        > "$LOOT_DIR/ignore_lists/ssid_list.json"
fi

# ============================================================
# SCHRITT 3: KISMET STARTEN
# ============================================================
log "INFO" "Starte Kismet auf Interface: $KISMET_IFACE"
LED BLUE BLINK

# Laufendes Kismet stoppen
if pgrep kismet > /dev/null 2>&1; then
    log "INFO" "Vorhandene Kismet-Instanz wird beendet..."
    for pid in $(pgrep kismet); do kill -9 "$pid" 2>/dev/null; done
    sleep 2
fi

# Interface in Monitor Mode versetzen
log "INFO" "Versetze $KISMET_IFACE in Monitor-Mode..."
iw dev "$KISMET_IFACE" set type monitor 2>/dev/null || \
    ip link set "$KISMET_IFACE" down 2>/dev/null && \
    iw dev "$KISMET_IFACE" set type monitor 2>/dev/null && \
    ip link set "$KISMET_IFACE" up 2>/dev/null

# Kismet im Hintergrund starten
kismet \
    --no-ncurses \
    --log-prefix "$LOOT_DIR/kismet_data/kismet" \
    --log-types kismet \
    -c "$KISMET_IFACE" \
    >> "$MAIN_LOG" 2>&1 &

KISMET_PID=$!
log "INFO" "Kismet PID: $KISMET_PID"

# Warten bis Kismet läuft und erste Daten sammelt
log "INFO" "Kismet sammelt Daten für ${SCAN_DURATION}s..."
sleep 5

# Prüfen ob Kismet noch läuft
if ! kill -0 "$KISMET_PID" 2>/dev/null; then
    log "ERROR" "Kismet ist unerwartet beendet! Log prüfen: $MAIN_LOG"
    LED RED BLINK
    exit 1
fi

log "INFO" "Kismet läuft. Warte $SCAN_DURATION Sekunden für Datensammlung..."
sleep "$SCAN_DURATION"

# ============================================================
# SCHRITT 4: PYTHON ANALYSE STARTEN
# ============================================================
log "INFO" "Starte Python-Analyse..."

# Python-Suchpfad für die Modulsammlung setzen
export PYTHONPATH="$PYTHON_DIR:$PYTHONPATH"

# Neueste Kismet-Datenbank finden
KISMET_DB=$(ls -t "$LOOT_DIR/kismet_data/"*.kismet 2>/dev/null | head -1)

if [ -z "$KISMET_DB" ]; then
    log "WARN" "Keine Kismet-Datenbank gefunden. Kismet hat möglicherweise noch keine Daten gespeichert."
    log "INFO" "Versuche direkten Probe-Analyse-Modus..."
    python3 "$PYTHON_DIR/probe_analyzer.py" \
        --days 1 \
        --config "$CONFIG" \
        --output-dir "$REPORT_DIR" \
        >> "$MAIN_LOG" 2>&1
else
    log "INFO" "Kismet-DB gefunden: $KISMET_DB"

    # Haupt-Surveillance-Analyse
    log "INFO" "Starte Surveillance-Analyse..."
    python3 "$PYTHON_DIR/surveillance_analyzer.py" \
        --kismet-db "$KISMET_DB" \
        --config "$CONFIG" \
        --output-dir "$REPORT_DIR" \
        --kml-dir "$KML_DIR" \
        --log-file "$ANALYSIS_LOG" \
        >> "$MAIN_LOG" 2>&1

    ANALYZE_EXIT=$?

    # Probe-Analyse zusätzlich
    log "INFO" "Starte Probe-Analyse..."
    python3 "$PYTHON_DIR/probe_analyzer.py" \
        --days 1 \
        --config "$CONFIG" \
        --output-dir "$REPORT_DIR" \
        >> "$MAIN_LOG" 2>&1
fi

# ============================================================
# SCHRITT 5: ERGEBNIS AUSWERTEN
# ============================================================
log "INFO" "Kismet beenden..."
if kill -0 "$KISMET_PID" 2>/dev/null; then
    kill -TERM "$KISMET_PID" 2>/dev/null
    sleep 2
    kill -9 "$KISMET_PID" 2>/dev/null
fi

# Interface zurücksetzen
iw dev "$KISMET_IFACE" set type managed 2>/dev/null

# Neuesten Report lesen und auswerten
LATEST_REPORT=$(ls -t "$REPORT_DIR/"*.md 2>/dev/null | head -1)
ALERT=false

if [ -n "$LATEST_REPORT" ]; then
    # Nach Warnungen in Report suchen
    if grep -qiE "WARNING|ALERT|HIGH PERSISTENCE|STALKING|verdächt" "$LATEST_REPORT" 2>/dev/null; then
        ALERT=true
    fi
    log "INFO" "Report: $LATEST_REPORT"
fi

if $ALERT; then
    log "WARN" "WARNUNG: Verdächtige Aktivität erkannt! Report prüfen."
    LED AMBER SOLID
    NOTIFY "CYT: Verdächtige Signale erkannt! Report in $REPORT_DIR"
else
    log "INFO" "Analyse abgeschlossen. Keine Auffälligkeiten."
    LED GREEN SOLID
    NOTIFY "CYT: Scan abgeschlossen. Keine Auffälligkeiten. Loot: $LOOT_DIR"
fi

log "INFO" "Alle Ergebnisse unter: $LOOT_DIR"
log "INFO" "========================================"
log "INFO" " Chasing Your Tail NG - beendet"
log "INFO" "========================================"
