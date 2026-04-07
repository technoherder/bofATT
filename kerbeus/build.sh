#!/bin/bash
# Build script for Kerbeus BOF suite using MinGW cross-compiler
# Full Rubeus Feature Set

echo "========================================"
echo "Building Kerbeus BOF Suite"
echo "Full Rubeus Feature Set"
echo "========================================"
echo

CC_x64="x86_64-w64-mingw32-gcc"
CC_x86="i686-w64-mingw32-gcc"
CFLAGS="-c -I. -I../"

# Check for cross-compiler
if [ ! $(command -v ${CC_x64}) ]; then
    echo "No cross-compiler detected. Try: apt-get install mingw-w64"
    exit 1
fi

mkdir -p bin

# Original BOFs from Kerbeus-BOF
BOFS_ORIGINAL="krb_asktgt krb_asktgs krb_kerberoasting krb_asreproasting krb_klist krb_ptt krb_purge krb_describe krb_tgtdeleg krb_hash krb_dump krb_triage krb_s4u krb_renew krb_changepw"

# New BOFs matching Rubeus features
BOFS_NEW="krb_currentluid krb_logonsession krb_createnetonly krb_monitor krb_harvest krb_brute krb_golden krb_silver krb_diamond"

echo "[Phase 1] Building original Kerbeus BOFs..."
echo

for bof in ${BOFS_ORIGINAL}; do
    echo "Building ${bof}..."

    # Build 64-bit
    ${CC_x64} ${CFLAGS} ${bof}.c -o bin/${bof}.x64.o 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "  [OK] ${bof}.x64.o"
    else
        echo "  [FAILED] ${bof}.x64.o"
    fi

    # Build 32-bit
    ${CC_x86} ${CFLAGS} ${bof}.c -o bin/${bof}.x86.o 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "  [OK] ${bof}.x86.o"
    else
        echo "  [FAILED] ${bof}.x86.o"
    fi
done

echo
echo "[Phase 2] Building new Rubeus-equivalent BOFs..."
echo

for bof in ${BOFS_NEW}; do
    echo "Building ${bof}..."

    # Build 64-bit
    ${CC_x64} ${CFLAGS} ${bof}.c -o bin/${bof}.x64.o 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "  [OK] ${bof}.x64.o"
    else
        echo "  [FAILED] ${bof}.x64.o"
    fi

    # Build 32-bit
    ${CC_x86} ${CFLAGS} ${bof}.c -o bin/${bof}.x86.o 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "  [OK] ${bof}.x86.o"
    else
        echo "  [FAILED] ${bof}.x86.o"
    fi
done

echo
echo "========================================"
echo "Build complete!"
echo "Output files in: bin/"
echo
echo "Total BOFs: 24"
echo "========================================"
echo
echo "Ticket Requests:    krb_asktgt, krb_asktgs, krb_renew"
echo "Roasting:           krb_kerberoasting, krb_asreproasting"
echo "Ticket Management:  krb_klist, krb_ptt, krb_purge, krb_describe"
echo "Ticket Extraction:  krb_dump, krb_triage, krb_tgtdeleg, krb_harvest, krb_monitor"
echo "Delegation:         krb_s4u"
echo "Ticket Forging:     krb_golden, krb_silver, krb_diamond"
echo "Utilities:          krb_hash, krb_changepw, krb_currentluid, krb_logonsession"
echo "                    krb_createnetonly, krb_brute"
echo
