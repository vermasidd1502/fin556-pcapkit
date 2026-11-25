#!/usr/bin/env python3
"""find_cme_secids.py - which CME SecurityIDs trade on one channel? Reads ONE capture file, prints counts only.
  ~/letf_env/bin/python find_cme_secids.py --port 14318 /db_pcaps/glbx_pcaps/20250402/<one file>.pcap.zst
Prints the busiest SecurityIDs (trade entries, total size, a typical price) so they can be added with --extra-secids.
Same-price groups: NQ and MNQ trade at the same price (~20,000); ES and MES at ~5,600; next-quarter months a bit apart."""
import argparse, collections, statistics, struct, sys
import zstandard


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--max-packets", type=int, default=5_000_000); ap.add_argument("--top", type=int, default=15)
    ap.add_argument("file"); a = ap.parse_args()
    n_tr, sz, px = collections.Counter(), collections.Counter(), collections.defaultdict(list)
    with open(a.file, "rb") as fh:
        f = zstandard.ZstdDecompressor().stream_reader(fh, read_across_frames=True) if a.file.endswith(".zst") else fh
        def rd(k):
            b = f.read(k)
            while len(b) < k:
                c = f.read(k - len(b))
                if not c: break
                b += c
            return b
        if rd(24)[:4] not in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"): sys.exit("not a little-endian pcap")
        n = 0
        while n < a.max_packets:
            h = rd(16)
            if len(h) < 16: break
            p = rd(struct.unpack_from("<I", h, 8)[0]); n += 1
            off, et = 14, struct.unpack_from(">H", p, 12)[0] if len(p) > 14 else 0
            while et in (0x8100, 0x88A8):
                et = struct.unpack_from(">H", p, off + 2)[0]; off += 4
            if et != 0x0800 or len(p) < off + 28 or p[off + 9] != 17: continue
            ihl = (p[off] & 15) * 4
            if struct.unpack_from(">H", p, off + ihl + 2)[0] % 1000 != a.port % 1000: continue
            pl = p[off + ihl + 8:]; m = 12
            while m + 10 <= len(pl):
                ml = struct.unpack_from("<H", pl, m)[0]
                if ml < 10 or m + ml > len(pl): break
                bl, tid = struct.unpack_from("<HH", pl, m + 2)
                body = m + 10; g = body + bl
                if tid == 48 and g + 3 <= m + ml:
                    gbl, ne = struct.unpack_from("<H", pl, g)[0], pl[g + 2]; e = g + 3
                    for _ in range(ne):
                        if e + 16 > m + ml: break
                        price, size, sid = struct.unpack_from("<qii", pl, e)
                        n_tr[sid] += 1; sz[sid] += max(size, 0)
                        if len(px[sid]) < 500: px[sid].append(price * 1e-9)
                        e += gbl
                m += ml
    print(f"packets read: {n}; SecurityIDs with trades: {len(n_tr)}")
    for sid, c in n_tr.most_common(a.top):
        print(f"secid {sid}: {c} trade entries, size {sz[sid]}, typical price {statistics.median(px[sid]):.2f}")


if __name__ == "__main__":
    main()
