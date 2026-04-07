#!/bin/bash
# Build credprompt BOF using MinGW-w64

mkdir -p bin

echo "[*] Building credprompt (x64)..."
x86_64-w64-mingw32-gcc -c -masm=intel -Wall -o bin/credprompt.x64.o credprompt.c
echo "[+] bin/credprompt.x64.o"

echo "[*] Building credprompt (x86)..."
i686-w64-mingw32-gcc -c -masm=intel -Wall -o bin/credprompt.x86.o credprompt.c
echo "[+] bin/credprompt.x86.o"

echo "[+] Build complete."
