#!/usr/bin/env bash
# ==============================================================================
# AIPENT — Vulnify CVE Catalog Setup & Verification Script
# ==============================================================================
# This script sets up and verifies the offline `vulnify.db` SQLite database
# used by AIPENT for grounded, zero-hallucination CVE intelligence.
#
# Upstream Project: https://github.com/mez-0/vulnify (by mez-0)
#
# Usage:
#   ./setup_vulnify.sh            # Verify existing DB or decompress local archive
#   ./setup_vulnify.sh --download # Download release DB asset (requires internet)
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

DB_FILE="vulnify.db"
ARCHIVE_ZST="vulnify.db.zst"
ARCHIVE_ZIP="vulnify.db.zip"

echo "=================================================================="
echo "          AIPENT — Vulnify CVE Catalog Setup & Verification       "
echo "=================================================================="

verify_db() {
    local target="$1"
    echo -n "[*] Verifying integrity of $target... "
    if command -v sqlite3 >/dev/null 2>&1; then
        local cve_count
        cve_count=$(sqlite3 "$target" "SELECT count(*) FROM cve;" 2>/dev/null || echo "0")
        if [[ "$cve_count" -gt 100000 ]]; then
            echo "OK"
            local kev_count
            kev_count=$(sqlite3 "$target" "SELECT count(*) FROM kev WHERE listed = 1;" 2>/dev/null || echo "0")
            local size
            size=$(du -h "$target" | cut -f1)
            echo "------------------------------------------------------------------"
            echo "[SUCCESS] Vulnify catalog is ready and verified!"
            echo "  - File:       $target ($size)"
            echo "  - Total CVEs: $cve_count"
            echo "  - CISA KEV:   $kev_count"
            echo "------------------------------------------------------------------"
            return 0
        else
            echo "FAILED (Unexpected schema or row count: $cve_count)"
            return 1
        fi
    elif command -v python3 >/dev/null 2>&1; then
        python3 -c "
import sqlite3, sys
conn = sqlite3.connect('$target')
c = conn.execute('SELECT count(*) FROM cve').fetchone()[0]
if c > 100000:
    print(f'OK ({c:,} CVEs)')
    sys.exit(0)
sys.exit(1)
" && return 0 || return 1
    else
        echo "OK (sqlite3 not installed to inspect contents, file exists)"
        return 0
    fi
}

# 1. Check if vulnify.db already exists
if [[ -f "$DB_FILE" && -s "$DB_FILE" ]]; then
    echo "[+] Found existing $DB_FILE."
    if verify_db "$DB_FILE"; then
        exit 0
    fi
    echo "[!] Existing $DB_FILE is corrupted or incomplete."
fi

# 2. Check for local archives (e.g. user downloaded manually)
if [[ -f "$ARCHIVE_ZST" ]]; then
    echo "[+] Found local compressed archive: $ARCHIVE_ZST"
    echo "[*] Decompressing with zstd..."
    if command -v zstd >/dev/null 2>&1; then
        zstd -d "$ARCHIVE_ZST" -o "$DB_FILE" --force
    elif command -v unzstd >/dev/null 2>&1; then
        unzstd -c "$ARCHIVE_ZST" > "$DB_FILE"
    elif python3 -c "import zstandard" >/dev/null 2>&1; then
        python3 -c "
import zstandard as zstd
dctx = zstd.ZstdDecompressor()
with open('$ARCHIVE_ZST', 'rb') as ifh, open('$DB_FILE', 'wb') as ofh:
    dctx.copy_stream(ifh, ofh)
"
    else
        echo "[ERROR] zstd is required to decompress $ARCHIVE_ZST."
        echo "Install it with: sudo apt install zstd (or brew install zstd)"
        exit 1
    fi
    verify_db "$DB_FILE"
    exit 0
fi

if [[ -f "$ARCHIVE_ZIP" ]]; then
    echo "[+] Found local zip archive: $ARCHIVE_ZIP"
    echo "[*] Extracting..."
    if command -v unzip >/dev/null 2>&1; then
        unzip -o "$ARCHIVE_ZIP"
    else
        python3 -m zipfile -e "$ARCHIVE_ZIP" .
    fi
    # If the zip extracted to a subfolder or different name, ensure vulnify.db exists
    if [[ ! -f "$DB_FILE" ]]; then
        found=$(find . -maxdepth 2 -name "vulnify*.db" | head -n 1)
        if [[ -n "$found" && "$found" != "./$DB_FILE" ]]; then
            cp "$found" "$DB_FILE"
        fi
    fi
    verify_db "$DB_FILE"
    exit 0
fi

# 3. Handle Download (only if explicitly requested via --download)
DO_DOWNLOAD=false
for arg in "$@"; do
    if [[ "$arg" == "--download" ]]; then
        DO_DOWNLOAD=true
        break
    fi
done

if [[ "$DO_DOWNLOAD" == "true" ]]; then
    echo "[*] Starting download of vulnify.db.zst from GitHub release (mez-0/vulnify)..."
    if command -v gh >/dev/null 2>&1; then
        echo "[*] Using GitHub CLI (gh)..."
        gh release download -R mez-0/vulnify --pattern "vulnify.db.zst"
    else
        echo "[*] Using curl..."
        RELEASE_URL="https://github.com/mez-0/vulnify/releases/latest/download/vulnify.db.zst"
        curl -fSL "$RELEASE_URL" -o "$ARCHIVE_ZST"
    fi

    if [[ -f "$ARCHIVE_ZST" ]]; then
        echo "[*] Decompressing..."
        zstd -d "$ARCHIVE_ZST" -o "$DB_FILE" --force
        verify_db "$DB_FILE"
        exit 0
    fi
fi

# 4. Instructions if neither DB nor archive is present
echo ""
echo "[INFO] vulnify.db is not present in the workspace."
echo ""
echo "To obtain the pre-built 2.5GB CVE database:"
echo "------------------------------------------------------------------"
echo "Option A: Use GitHub CLI (Fastest):"
echo "  gh release download -R mez-0/vulnify --pattern vulnify.db.zst"
echo "  zstd -d vulnify.db.zst -o vulnify.db"
echo ""
echo "Option B: Run this script with --download:"
echo "  ./setup_vulnify.sh --download"
echo ""
echo "Option C: Direct Browser Download:"
echo "  Download vulnify.db.zst from:"
echo "  https://github.com/mez-0/vulnify/releases/latest"
echo "  Place it in this directory and re-run: ./setup_vulnify.sh"
echo "------------------------------------------------------------------"
exit 1
