#!/bin/bash
# Build script for Kerberos TGS BOF using MinGW cross-compiler

CC_x64="x86_64-w64-mingw32-gcc"
CC_x86="i686-w64-mingw32-gcc"

echo "Building Kerberos TGS BOF..."

# Check for cross-compiler
if [ ! $(command -v ${CC_x64}) ]; then
    echo "No cross-compiler detected. Try: apt-get install mingw-w64"
    exit 1
fi

# Build 64-bit version
echo "Compiling x64..."
${CC_x64} -c kerberos_tgs.c -o kerberos_tgs.x64.o -Wall -I../../
if [ $? -ne 0 ]; then
    echo "Failed to build x64 version"
    exit 1
fi
echo "Built: kerberos_tgs.x64.o"

# Build 32-bit version
echo "Compiling x86..."
${CC_x86} -c kerberos_tgs.c -o kerberos_tgs.x86.o -Wall -I../../
if [ $? -ne 0 ]; then
    echo "Failed to build x86 version"
    exit 1
fi
echo "Built: kerberos_tgs.x86.o"

echo "Build complete!"
