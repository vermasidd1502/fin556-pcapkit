#!/usr/bin/env python3
"""find_cme_port.py - which CME UDP port (channel) carries a SecurityID? Reads ONE capture file, prints counts only.
  ~/letf_env/bin/python find_cme_port.py --secid 42005804 /db_pcaps/glbx_pcaps/20250402/<one file>.pcap.zst
Counts packets per UDP destination port and how many contain the SecurityID (as a little-endian int32)."""
import argparse, collections, struct, sys
import zstandard


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--secid", type=int, required=True)
    ap.add_argument("--max-packets", type=int, default=3_000_000); ap.add_argument("file")
    a = ap.parse_args()
    needle = struct.pack("<i", a.secid)
    tot, hit = collections.Counter(), collections.Counter()
    with open(a.file, "rb") as fh:
        f = zstandard.ZstdDecompressor().stream_reader(fh, read_across_frames=True) if a.file.endswith(".zst") else fh
        def rd(n):
            b = f.read(n)
            while len(b) < n:
                c = f.read(n - len(b))
                if not c: break
                b += c
            return b
        magic = rd(24)[:4]
        if magic not in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            sys.exit("not a little-endian pcap")
        n = 0
        while n < a.max_packets:
            h = rd(16)
            if len(h) < 16: break
            cap = struct.unpack_from("<I", h, 8)[0]; p = rd(cap); n += 1
            off, et = 14, struct.unpack_from(">H", p, 12)[0] if len(p) > 14 else 0
            while et in (0x8100, 0x88A8):
                et = struct.unpack_from(">H", p, off + 2)[0]; off += 4
            if et != 0x0800 or len(p) < off + 28 or p[off + 9] != 17: continue
            ihl = (p[off] & 15) * 4; dport = struct.unpack_from(">H", p, off + ihl + 2)[0]
            tot[dport] += 1
            if needle in p[off + ihl + 8:]: hit[dport] += 1
    print(f"packets read: {n}")
    for port, c in hit.most_common(6):
        print(f"port {port} (channel {port % 1000}): {c} packets with secid {a.secid}, {tot[port]} packets total")
    if not hit: print("secid not found in this file; try a busier time (e.g. a 14:30 UTC file)")


if __name__ == "__main__":
    main()
