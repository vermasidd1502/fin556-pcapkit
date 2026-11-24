#!/usr/bin/env python3
"""iex_parse.py - IEX TOPS 1.6 / DEEP 1.0 parser (IEX-TP v1 over UDP, in pcap or pcapng).

Writes, for the requested symbols only:
  <out>_bbo.csv     ts_event_ns,symbol,bid_px,bid_sz,ask_px,ask_sz        (TOPS Quote Update 'Q')
  <out>_levels.csv  ts_event_ns,symbol,side,price,size,flags               (DEEP Price Level Update '8' buy / '5' sell)
  <out>_trades.csv  ts_event_ns,symbol,price,size,trade_id,sale_flags      (Trade Report 'T', both feeds)
  <out>_auction.csv ts_event_ns,symbol,auction_type,paired,ref_px,ind_clear_px,imbalance,imb_side,
                    extension,sched_time,book_clear_px,collar_ref,lower_collar,upper_collar  (Auction Information 'A')
IEX timestamps are ns since the UNIX epoch (UTC). Prices are int64 / 1e4.
Input: .pcap / .pcapng, optionally .gz or .zst (detected from magic bytes). Prints counts only.

  python3 iex_parse.py --symbols QQQ,TQQQ,SQQQ --out out/raw/iex_20250402 -- file1.pcap.gz file2 ...
  python3 iex_parse.py --start-ns X --end-ns Y ...     # optional time filter
"""
import argparse, csv, gzip, struct, sys

ZST, GZ = b"\x28\xb5\x2f\xfd", b"\x1f\x8b"
U16, U32, U64, I64 = struct.Struct("<H"), struct.Struct("<I"), struct.Struct("<Q"), struct.Struct("<q")
TP_HDR = 40


def open_any(path):
    with open(path, "rb") as f:
        head = f.read(4)
    if head == ZST:
        import zstandard
        return zstandard.ZstdDecompressor().stream_reader(open(path, "rb"), read_across_frames=True)
    return gzip.open(path, "rb") if head[:2] == GZ else open(path, "rb")


def read_exact(f, n):
    b = f.read(n)
    while len(b) < n:
        c = f.read(n - len(b))
        if not c:
            break
        b += c
    return b


def frames(f):
    """yield link-layer frames from pcap or pcapng; also yields linktype"""
    magic = read_exact(f, 4)
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):          # pcap LE (us / ns)
        hdr = read_exact(f, 20); link = U32.unpack_from(hdr, 16)[0]
        while True:
            rh = read_exact(f, 16)
            if len(rh) < 16:
                return
            caplen = U32.unpack_from(rh, 8)[0]
            yield link, read_exact(f, caplen)
    elif magic == b"\x0a\x0d\x0d\x0a":                                # pcapng (little-endian assumed)
        blen = U32.unpack(read_exact(f, 4))[0]; read_exact(f, blen - 8)
        links = []
        while True:
            h = read_exact(f, 8)
            if len(h) < 8:
                return
            btype, blen = struct.unpack("<II", h)
            body = read_exact(f, blen - 8)
            if btype == 1:                                            # IDB
                links.append(U16.unpack_from(body, 0)[0])
            elif btype == 6:                                          # EPB
                iface, caplen = U32.unpack_from(body, 0)[0], U32.unpack_from(body, 12)[0]
                yield (links[iface] if iface < len(links) else 1), body[20:20 + caplen]
            elif btype == 3:                                          # SPB
                yield (links[0] if links else 1), body[4:]
    else:
        raise SystemExit(f"not a pcap/pcapng file (magic {magic.hex()})")


def udp_payload(link, fr):
    if link == 1:                                                     # Ethernet (+ VLAN tags)
        off, et = 14, struct.unpack_from(">H", fr, 12)[0]
        while et in (0x8100, 0x88A8):
            et = struct.unpack_from(">H", fr, off + 2)[0]; off += 4
        if et != 0x0800:
            return None
    elif link == 101:                                                 # raw IPv4
        off = 0
    elif link == 113:                                                 # Linux SLL
        off = 16
    else:
        return None
    if len(fr) < off + 28 or fr[off] >> 4 != 4 or fr[off + 9] != 17:
        return None
    ihl = (fr[off] & 0xF) * 4
    return fr[off + ihl + 8:]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--symbols", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--start-ns", type=int, default=0)
    ap.add_argument("--end-ns", type=int, default=2**63 - 1)
    ap.add_argument("files", nargs="+")
    a = ap.parse_args()
    want = {s.strip().encode().ljust(8) for s in a.symbols.split(",") if s.strip()}
    W = {}
    for k, cols in [("bbo", "ts_event_ns,symbol,bid_px,bid_sz,ask_px,ask_sz"),
                    ("levels", "ts_event_ns,symbol,side,price,size,flags"),
                    ("trades", "ts_event_ns,symbol,price,size,trade_id,sale_flags"),
                    ("auction", "ts_event_ns,symbol,auction_type,paired,ref_px,ind_clear_px,imbalance,imb_side,"
                                "extension,sched_time,book_clear_px,collar_ref,lower_collar,upper_collar")]:
        fh = open(f"{a.out}_{k}.csv", "w", newline=""); fh.write(cols + "\n"); W[k] = csv.writer(fh)
    n = dict(packets=0, msgs=0, bbo=0, levels=0, trades=0, auction=0, other=0)
    px = lambda b, o: I64.unpack_from(b, o)[0] / 1e4
    for path in a.files:
        with open_any(path) as f:
            for link, fr in frames(f):
                p = udp_payload(link, fr)
                if p is None or len(p) < TP_HDR or p[0] != 1:
                    continue
                n["packets"] += 1
                end, off = TP_HDR + U16.unpack_from(p, 12)[0], TP_HDR
                while off + 2 <= end and off + 2 <= len(p):
                    ml = U16.unpack_from(p, off)[0]; m = p[off + 2:off + 2 + ml]; off += 2 + ml
                    n["msgs"] += 1
                    if len(m) < 18:
                        continue
                    t, ts, sym = m[0], I64.unpack_from(m, 2)[0], m[10:18]
                    if sym not in want or not (a.start_ns <= ts < a.end_ns):
                        continue
                    s = sym.decode().rstrip()
                    if t == 0x51 and ml >= 42:                        # Q quote update
                        W["bbo"].writerow([ts, s, px(m, 22), U32.unpack_from(m, 18)[0], px(m, 30), U32.unpack_from(m, 38)[0]]); n["bbo"] += 1
                    elif t in (0x38, 0x35) and ml >= 30:              # 8 buy / 5 sell price level
                        W["levels"].writerow([ts, s, "B" if t == 0x38 else "S", px(m, 22), U32.unpack_from(m, 18)[0], m[1]]); n["levels"] += 1
                    elif t == 0x54 and ml >= 38:                      # T trade report
                        W["trades"].writerow([ts, s, px(m, 22), U32.unpack_from(m, 18)[0], U64.unpack_from(m, 30)[0], m[1]]); n["trades"] += 1
                    elif t == 0x41 and ml >= 80:                      # A auction information
                        W["auction"].writerow([ts, s, chr(m[1]), U32.unpack_from(m, 18)[0], px(m, 22), px(m, 30),
                                               U32.unpack_from(m, 38)[0], chr(m[42]), m[43], U32.unpack_from(m, 44)[0],
                                               px(m, 48), px(m, 56), px(m, 64), px(m, 72)]); n["auction"] += 1
                    else:
                        n["other"] += 1
    print("iex_parse counts:", n, flush=True)


if __name__ == "__main__":
    main()
