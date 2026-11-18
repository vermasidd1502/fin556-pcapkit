#!/bin/bash
# build.sh - compile the scanner and the parser engine. Run once in the pcapkit folder. No sudo, no network.
set -e
cd "$(dirname "$0")"
FLAGS="-O3 -std=c++17 -pthread"
[ "$(uname)" = "Darwin" ] && FLAGS="$FLAGS -I/opt/homebrew/include -L/opt/homebrew/lib" || FLAGS="$FLAGS -march=native"
ZSTD=""; ZLIB=""
for z in "-l:libzstd.so.1" "-lzstd"; do echo 'int main(){}' | g++ -x c++ - -o /tmp/.zt_$$ $FLAGS $z 2>/dev/null && { ZSTD=$z; break; }; done
for z in "-l:libz.so.1" "-lz"; do echo 'int main(){}' | g++ -x c++ - -o /tmp/.zt_$$ $FLAGS $z 2>/dev/null && { ZLIB=$z; break; }; done
rm -f /tmp/.zt_$$
DEFS=""; [ -z "$ZSTD" ] && DEFS="$DEFS -DNO_ZSTD"; [ -z "$ZLIB" ] && DEFS="$DEFS -DNO_ZLIB"
g++ $FLAGS $DEFS -o pcap_scan pcap_scan.cpp $ZSTD $ZLIB
echo "pcap_scan: built (zstd: ${ZSTD:-no}, gzip: ${ZLIB:-no})"
if [ "$1" != "--scan-only" ]; then
  bash engine/build.sh
fi
echo "BUILD OK"
