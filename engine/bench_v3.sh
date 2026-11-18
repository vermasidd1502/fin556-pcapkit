#!/bin/bash
# bench_v3.sh - unit test + benchmark on the VM: v1 vs v2 vs v3 on real captures, outputs must be identical.
#   ./bench_v3.sh [YYYYMMDD] [threads]        default 20250402, 16 threads for v3
# ITCH: 6 consecutive 10-min files (14:00-15:00 UTC).  CME: 3 files (14:00-14:30 UTC), NQM5 only.
# Prints one line per feed:  <feed> | v1 Ns | v2 Ns | v3 Ns | bbo X | trades X.  Cleans up after itself.
set -e
cd "$(dirname "$0")"
source ~/letf_env/bin/activate 2>/dev/null || true
D=${1:-20250402}; T=${2:-16}
W=$(mktemp -d ~/v3bench.XXXX)
trap 'rm -rf "$W"' EXIT
XF=$(ls /db_pcaps/xnas_pcaps/$D/*T14[0-5]0*.pcap.zst | head -6)
GF=$(ls /db_pcaps/glbx_pcaps/$D/*T14[0-2]0*.pcap.zst | head -3)
secs() { local s=$(date +%s.%N); "$@" 2>/dev/null; python3 -c "print(f'{$(date +%s.%N)-$s:.1f}')"; }
cmpall() { for f in bbo trades; do cmp -s "$1_$f.csv" "$2_$f.csv" && printf " | $f IDENTICAL" || printf " | $f DIFFER"; done; }

echo "date $D, v3 threads $T, $(echo $XF | wc -w) ITCH files, $(echo $GF | wc -w) CME files, free disk $(df -h / | awk 'NR==2{print $4}')"
a=$(secs python3 fast_feed.py ./itch_fast --symbols QQQ,TQQQ,SQQQ --out $W/i1 -- $XF)
b=$(secs ./itch_fast2 --symbols QQQ,TQQQ,SQQQ --out $W/i2 -- $XF)
c=$(secs ./itch_fast3 --symbols QQQ,TQQQ,SQQQ --threads $T --out $W/i3 -- $XF)
printf "ITCH | v1 ${a}s | v2 ${b}s | v3 ${c}s"; cmpall $W/i1 $W/i3; echo
a=$(secs python3 fast_feed.py ./mdp3_fast --secids NQM5=42005804 --display-factor 0.01 --depth 1 --out $W/c1 -- $GF)
b=$(secs ./mdp3_fast2 --secids NQM5=42005804 --display-factor 0.01 --depth 1 --out $W/c2 -- $GF)
c=$(secs ./mdp3_fast3 --secids NQM5=42005804 --display-factor 0.01 --depth 1 --threads $T --out $W/c3 -- $GF)
printf "CME  | v1 ${a}s | v2 ${b}s | v3 ${c}s"; cmpall $W/c1 $W/c3; echo
echo "cleaned: $W"
