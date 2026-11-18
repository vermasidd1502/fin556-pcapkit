#!/usr/bin/env python3
"""
itch_zst_parse.py - stream-parse compressed Nasdaq TotalView-ITCH 5.0 captures
(.pcap.zst, .pcapng.zst, or raw 2-byte-length-framed ITCH, zstd-compressed or not)
WITHOUT ever writing the decompressed data to disk.

What it does
  * decompresses on the fly (needs `pip install zstandard`; pyarrow optional)
  * auto-detects the container: classic pcap (us/ns, either endian), pcapng, or raw ITCH
  * strips Ethernet / VLAN / IPv4 / IPv6 / UDP, trims by the UDP length field (so FCS/padding is ignored)
  * unwraps MoldUDP64, de-duplicates A/B feed copies and re-orders by sequence number
  * rebuilds the full order book (MBO) for ONLY the symbols you ask for
  * writes two files per input:  <stem>_bbo.parquet   top-of-book change events
                                 <stem>_trades.parquet executions / hidden trades / crosses
    (falls back to .csv if pyarrow is missing)

Usage
  python itch_zst_parse.py --inspect  one_file.pcap.zst            # look first: what is in the file?
  python itch_zst_parse.py --out-dir out  /db_pcaps/xnas_pcaps/20250203/*.pcap.zst   # ONE day = one continuous stream
  python itch_zst_parse.py --by-dir --jobs 4 --out-dir out  /db_pcaps/xnas_pcaps/2025020*/*.pcap.zst  # days in parallel
  (files given together are sorted by name and processed as one stream so the order book carries over)
  python itch_zst_parse.py --preset spx ...                           # S&P cluster instead of QQQ/TQQQ/SQQQ
  python itch_zst_parse.py --symbols QQQ,TQQQ,SQQQ,QQQM ...           # any tickers you like
  some_streamer ... | python itch_zst_parse.py --name 2026-03-02 --out-dir out -   # stdin, nothing on disk

Nothing in this script touches the network.
"""
import argparse
import csv
import io
import os
import struct
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor
from heapq import heapify, heappop, heappush

PRESETS = {
    "ndx": "QQQ,TQQQ,SQQQ",                          # Nasdaq-100 ETF + 3x bull / 3x bear
    "spx": "SPY,SSO,UPRO,SDS,SPXU,SPXL,SPXS",        # S&P 500 cluster from the class blueprint
}
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
ITCH_TYPES = b"SRHYLVWKJhAFECXDUBPQINO"

U16 = struct.Struct(">H").unpack_from
U32 = struct.Struct(">I").unpack_from
U64 = struct.Struct(">Q").unpack_from
NS_PER_S = 1_000_000_000


# --------------------------------------------------------------------------- input
def open_stream(path):
    """Return a buffered binary reader over the (possibly zstd-compressed) data."""
    raw = sys.stdin.buffer if path == "-" else open(path, "rb", buffering=1 << 20)
    buf = raw if hasattr(raw, "peek") else io.BufferedReader(raw, 1 << 20)
    if buf.peek(4)[:4] == ZSTD_MAGIC:
        try:
            import zstandard
        except ImportError:
            sys.exit("This file is zstd-compressed: run  pip install zstandard")
        reader = zstandard.ZstdDecompressor().stream_reader(buf, read_across_frames=True)
        buf = io.BufferedReader(reader, 1 << 22)
    return buf


def detect_container(f):
    head = f.peek(8)[:8]
    if head[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        return "pcap"
    if head[:4] == b"\x0a\x0d\x0d\x0a":
        return "pcapng"
    if len(head) >= 3 and head[2] in ITCH_TYPES and 0 < ((head[0] << 8) | head[1]) < 1000:
        return "itch"
    raise SystemExit("Unrecognised container; first bytes: " + head.hex())


def iter_pcap(f, info):
    hdr = f.read(24)
    magic = hdr[:4]
    end, nano = {
        b"\xd4\xc3\xb2\xa1": ("<", False), b"\xa1\xb2\xc3\xd4": (">", False),
        b"\x4d\x3c\xb2\xa1": ("<", True), b"\xa1\xb2\x3c\x4d": (">", True),
    }[magic]
    network = struct.unpack(end + "I", hdr[20:24])[0] & 0x0FFFFFFF
    info["pcap_nanosecond"] = nano
    info["pcap_snaplen"] = struct.unpack(end + "I", hdr[16:20])[0]
    rec = struct.Struct(end + "IIII").unpack
    while True:
        h = f.read(16)
        if len(h) < 16:
            break
        sec, frac, incl, orig = rec(h)
        data = f.read(incl)
        if len(data) < incl:
            info["truncated_file"] = 1
            break
        if incl < orig:
            info["snaplen_truncated_pkts"] += 1
        yield sec * NS_PER_S + (frac if nano else frac * 1000), network, data


def iter_pcapng(f, info):
    end = "<"
    ifaces = []  # (linktype, ts multiplier num, den)
    while True:
        h = f.read(8)
        if len(h) < 8:
            break
        btype = struct.unpack("<I", h[:4])[0] if end == "<" else struct.unpack(">I", h[:4])[0]
        if h[:4] == b"\x0a\x0d\x0d\x0a":  # section header: byte-order magic decides endianness
            blen_le = struct.unpack("<I", h[4:])[0]
            body = f.read(blen_le - 8)
            end = "<" if body[:4] == b"\x4d\x3c\x2b\x1a" else ">"
            ifaces = []
            continue
        btype, blen = struct.unpack(end + "II", h)
        body = f.read(blen - 8)
        if len(body) < blen - 8:
            info["truncated_file"] = 1
            break
        body = body[:-4]  # trailing total length
        if btype == 1:  # interface description
            link = struct.unpack(end + "H", body[:2])[0]
            tsresol = 6
            p = 8
            while p + 4 <= len(body):
                code, ln = struct.unpack(end + "HH", body[p:p + 4])
                if code == 0:
                    break
                if code == 9:
                    tsresol = body[p + 4]
                p += 4 + ((ln + 3) & ~3)
            ifaces.append((link, tsresol))
        elif btype == 6:  # enhanced packet block
            iid, hi, lo, cap, orig = struct.unpack(end + "IIIII", body[:20])
            link, res = ifaces[iid]
            units = (hi << 32) | lo
            if res & 0x80:
                ns = units * NS_PER_S >> (res & 0x7F)
            elif res <= 9:
                ns = units * 10 ** (9 - res)
            else:
                ns = units // 10 ** (res - 9)
            if cap < orig:
                info["snaplen_truncated_pkts"] += 1
            yield ns, link, body[20:20 + cap]


def udp_payload(link, d, info):
    """Return (src_port, dst_port, payload) for a UDP packet, else None."""
    n = len(d)
    if link == 1:  # Ethernet
        if n < 14:
            return None
        et = (d[12] << 8) | d[13]
        off = 14
        while et in (0x8100, 0x88A8, 0x9100) and n >= off + 4:  # VLAN / QinQ
            et = (d[off + 2] << 8) | d[off + 3]
            off += 4
    elif link == 113 and n >= 16:  # Linux cooked v1
        et, off = (d[14] << 8) | d[15], 16
    elif link == 276 and n >= 20:  # Linux cooked v2
        et, off = (d[0] << 8) | d[1], 20
    elif link in (101, 12) and n >= 1:  # raw IP
        et, off = (0x0800 if d[0] >> 4 == 4 else 0x86DD), 0
    else:
        info["unsupported_link"] = link
        return None
    if et == 0x0800:
        if n < off + 20:
            return None
        if d[off + 9] != 17:
            return None
        if ((d[off + 6] & 0x3F) << 8) | d[off + 7]:  # fragment
            info["ip_fragments"] += 1
            return None
        udp = off + (d[off] & 0x0F) * 4
    elif et == 0x86DD:
        if n < off + 40 or d[off + 6] != 17:
            return None
        udp = off + 40
    else:
        return None
    if n < udp + 8:
        return None
    sport, dport, ulen = struct.unpack_from(">HHH", d, udp)
    return sport, dport, d[udp + 8:udp + ulen]  # trim by UDP length: drops Ethernet padding / FCS


class Sequencer:
    """MoldUDP64 sequence handling: drop duplicate (A/B feed) packets, re-order, count gaps."""

    def __init__(self, info, window):
        self.info, self.window = info, window
        self.next, self.pend = {}, {}

    def push(self, sess, seq, count, ts, msgs):
        out = []
        nxt = self.next.setdefault(sess, seq)
        if seq + count <= nxt:
            self.info["dup_packets"] += 1
            return out
        if seq > nxt:
            p = self.pend.setdefault(sess, {})
            if seq in p:
                self.info["dup_packets"] += 1
                return out
            p[seq] = (count, ts, msgs)
            self.info["held_out_of_order"] += 1
            if len(p) > self.window:  # give up waiting for the missing packets
                k = min(p)
                self.info["gap_msgs"] += k - self.next[sess]
                self.next[sess] = k
                self._drain(sess, out)
            return out
        self._emit(sess, seq, count, ts, msgs, out)
        self._drain(sess, out)
        return out

    def _emit(self, sess, seq, count, ts, msgs, out):
        nxt = self.next[sess]
        if seq + count <= nxt:
            self.info["dup_packets"] += 1
            return
        if nxt > seq:
            self.info["overlap_msgs"] += nxt - seq
            msgs = msgs[nxt - seq:]
        out.append((ts, msgs))
        self.next[sess] = seq + count

    def _drain(self, sess, out):
        p = self.pend.get(sess)
        while p:
            k = min(p)
            if k > self.next[sess]:
                break
            c, ts, msgs = p.pop(k)
            self._emit(sess, k, c, ts, msgs, out)

    def flush(self):
        out = []
        for sess, p in self.pend.items():
            while p:
                k = min(p)
                if k > self.next[sess]:
                    self.info["gap_msgs"] += k - self.next[sess]
                    self.next[sess] = k
                c, ts, msgs = p.pop(k)
                self._emit(sess, k, c, ts, msgs, out)
        return out


def iter_blocks(f, info, opts, state=None, last=True):
    """Yield (recv_ts_ns, [itch message bytes ...]) in sequence order."""
    kind = detect_container(f)
    info["container"] = kind
    if kind == "itch":  # raw: 2-byte big-endian length + message
        batch = []
        while True:
            h = f.read(2)
            if len(h) < 2:
                break
            m = f.read((h[0] << 8) | h[1])
            batch.append(m)
            if len(batch) >= 4096:
                yield 0, batch
                batch = []
        if batch:
            yield 0, batch
        return
    state = state if state is not None else {}
    seqr = state.setdefault("seqr", Sequencer(info, opts.reorder_window))
    ports = info["_ports"]
    npk = 0
    for ts, link, data in (iter_pcap(f, info) if kind == "pcap" else iter_pcapng(f, info)):
        npk += 1
        if opts.max_packets and npk > opts.max_packets:
            break
        info["packets"] = npk
        if "first_pcap_ts" not in info:
            info["first_pcap_ts"] = ts
        info["last_pcap_ts"] = ts
        r = udp_payload(link, data, info)
        if r is None:
            info["non_udp_packets"] += 1
            continue
        _, dport, pl = r
        ports[dport] += 1
        if opts.port and dport != opts.port:
            continue
        if len(pl) < 20:
            info["short_udp"] += 1
            continue
        count = (pl[18] << 8) | pl[19]
        if count == 0 or count == 0xFFFF:  # heartbeat / end of session
            info["mold_heartbeat_or_eos"] += 1
            continue
        sess, seq = bytes(pl[:10]), U64(pl, 10)[0]
        msgs, pos, n = [], 20, len(pl)
        for _ in range(count):
            if pos + 2 > n:
                info["truncated_pkts"] += 1
                break
            ln = (pl[pos] << 8) | pl[pos + 1]
            pos += 2
            if pos + ln > n:
                info["truncated_pkts"] += 1
                break
            msgs.append(pl[pos:pos + ln])
            pos += ln
        else:
            if pos != n:
                info["mold_trailing_bytes_pkts"] += 1
        info["_sessions"].setdefault(sess, [seq, seq + count])
        s = info["_sessions"][sess]
        s[0], s[1] = min(s[0], seq), max(s[1], seq + count)
        yield from seqr.push(sess, seq, count, ts, msgs)
    if last:
        yield from seqr.flush()


# --------------------------------------------------------------------------- order book
class Book:
    __slots__ = ("sym", "bid", "ask", "bh", "ah", "last")

    def __init__(self, sym):
        self.sym, self.bid, self.ask, self.bh, self.ah, self.last = sym, {}, {}, [], [], None

    def add(self, is_bid, px, sz):
        if is_bid:
            d, h, key = self.bid, self.bh, -px
        else:
            d, h, key = self.ask, self.ah, px
        cur = d.get(px)
        if cur is None:
            d[px] = sz
            heappush(h, key)
            if len(h) > 4 * len(d) + 256:  # drop stale heap entries
                h[:] = [-p if is_bid else p for p in d]
                heapify(h)
        else:
            d[px] = cur + sz

    def remove(self, is_bid, px, sz):
        d = self.bid if is_bid else self.ask
        cur = d.get(px)
        if cur is None:
            return
        cur -= sz
        if cur > 0:
            d[px] = cur
        else:
            del d[px]

    def top(self):
        bh, bid, ah, ask = self.bh, self.bid, self.ah, self.ask
        while bh and -bh[0] not in bid:
            heappop(bh)
        while ah and ah[0] not in ask:
            heappop(ah)
        bp = -bh[0] if bh else 0
        ap = ah[0] if ah else 0
        return (bp, bid[bp] if bp else 0, ap, ask[ap] if ap else 0)


class Sink:
    BBO = ["ts_recv_ns", "ts_itch_ns", "symbol", "bid_px", "bid_sz", "ask_px", "ask_sz"]
    TRD = ["ts_recv_ns", "ts_itch_ns", "symbol", "price", "size", "kind", "aggressor", "match_no", "cross_type"]

    def __init__(self, base, fmt):
        self.fmt, self.base = fmt, base
        self.b = [[] for _ in self.BBO]
        self.t = [[] for _ in self.TRD]
        self.nb = self.nt = 0
        self.w = {}
        if fmt == "parquet":
            import pyarrow as pa
            import pyarrow.parquet as pq
            self.pa, self.pq = pa, pq
            self.schema = {
                "bbo": pa.schema([("ts_recv_ns", pa.int64()), ("ts_itch_ns", pa.int64()), ("symbol", pa.string()),
                                  ("bid_px", pa.float64()), ("bid_sz", pa.int64()),
                                  ("ask_px", pa.float64()), ("ask_sz", pa.int64())]),
                "trades": pa.schema([("ts_recv_ns", pa.int64()), ("ts_itch_ns", pa.int64()), ("symbol", pa.string()),
                                     ("price", pa.float64()), ("size", pa.int64()), ("kind", pa.string()),
                                     ("aggressor", pa.string()), ("match_no", pa.int64()),
                                     ("cross_type", pa.string())]),
            }

    def bbo(self, ts_recv, ts, sym, tup):
        b = self.b
        b[0].append(ts_recv); b[1].append(ts); b[2].append(sym)
        b[3].append(tup[0]); b[4].append(tup[1]); b[5].append(tup[2]); b[6].append(tup[3])
        self.nb += 1
        if len(b[0]) >= 1_000_000:
            self.flush()

    def trade(self, ts_recv, ts, sym, px, sz, kind, aggr, match, cross):
        t = self.t
        t[0].append(ts_recv); t[1].append(ts); t[2].append(sym); t[3].append(px); t[4].append(sz)
        t[5].append(kind); t[6].append(aggr); t[7].append(match); t[8].append(cross)
        self.nt += 1
        if len(t[0]) >= 1_000_000:
            self.flush()

    @staticmethod
    def _px(lst):
        return [p / 10000.0 if p else float("nan") for p in lst]

    def _write(self, name, cols, names):
        if not cols[0]:
            return
        path = f"{self.base}_{name}.{'parquet' if self.fmt == 'parquet' else 'csv'}"
        px_cols = {"bbo": (3, 5), "trades": (3,)}[name]
        orig = cols
        cols = [self._px(c) if i in px_cols else c for i, c in enumerate(orig)]
        if self.fmt == "parquet":
            w = self.w.get(name)
            if w is None:
                w = self.w[name] = self.pq.ParquetWriter(path, self.schema[name], compression="zstd")
            w.write_table(self.pa.table(dict(zip(names, cols)), schema=self.schema[name]))
        else:
            w = self.w.get(name)
            if w is None:
                fh = open(path, "w", newline="")
                w = self.w[name] = (fh, csv.writer(fh))
                w[1].writerow(names)
            w[1].writerows(zip(*cols))
        for c in orig:  # clear the ORIGINAL buffers (the price columns were converted into new lists above)
            c.clear()

    def flush(self):
        self._write("bbo", self.b, self.BBO)
        self._write("trades", self.t, self.TRD)

    def close(self):
        self.flush()
        for name, w in self.w.items():
            (w[0].close() if self.fmt == "csv" else w.close())
        # make sure both files exist even when empty
        if self.fmt == "parquet":
            for name, names in (("bbo", self.BBO), ("trades", self.TRD)):
                if name not in self.w:
                    self.pq.write_table(self.schema[name].empty_table(), f"{self.base}_{name}.parquet")


class Books:
    def __init__(self, symbols, sink, start_ns, end_ns):
        self.sink, self.start_ns, self.end_ns = sink, start_ns, end_ns
        self.books = {s: Book(s) for s in symbols}
        self.by8 = {s.encode().ljust(8): self.books[s] for s in symbols}
        self.orders = {}
        self.tc = [0] * 256
        self.opened = False
        self.done = False
        self.bad_msgs = 0
        self.sym_info = {}
        self.sys_events = []
        self.n_dir = 0
        self.first_ts = self.last_ts = None
        self.adds = Counter()

    # ---- helpers
    def _open(self, ts_recv):
        self.opened = True
        for b in self.books.values():
            tup = b.top()
            if tup[0] or tup[2]:
                b.last = tup
                if self.sink:
                    self.sink.bbo(ts_recv, self.start_ns, b.sym, tup)

    def _post(self, b, ts_recv, ts):
        tup = b.top()
        if tup != b.last:
            b.last = tup
            if self.sink:
                self.sink.bbo(ts_recv, ts, b.sym, tup)

    def _pre(self, ts_recv, ts):
        """Called before a tracked event mutates a book. Returns False when past the end of the window."""
        if ts > self.end_ns:
            self.done = True
            return False
        if not self.opened and ts >= self.start_ns:
            self._open(ts_recv)
        return True

    # ---- main loop body
    def feed(self, ts_recv, msgs):
        orders, tc, by8, sink = self.orders, self.tc, self.by8, self.sink
        for m in msgs:
            if len(m) < 12:
                continue
            t = m[0]
            tc[t] += 1
            try:
                if t == 65 or t == 70:  # A add / F add with MPID
                    b = by8.get(m[24:32])
                    if b is None:
                        continue
                    ts = int.from_bytes(m[5:11], "big")
                    if not self._pre(ts_recv, ts):
                        return
                    is_bid = m[19] == 66
                    px, sh = U32(m, 32)[0], U32(m, 20)[0]
                    orders[U64(m, 11)[0]] = [b, is_bid, px, sh]
                    b.add(is_bid, px, sh)
                    self.adds[b.sym] += 1
                    if self.opened:
                        self._post(b, ts_recv, ts)
                elif t == 68:  # D delete
                    o = orders.pop(U64(m, 11)[0], None)
                    if o is None:
                        continue
                    ts = int.from_bytes(m[5:11], "big")
                    if not self._pre(ts_recv, ts):
                        return
                    o[0].remove(o[1], o[2], o[3])
                    if self.opened:
                        self._post(o[0], ts_recv, ts)
                elif t == 85:  # U replace
                    o = orders.pop(U64(m, 11)[0], None)
                    if o is None:
                        continue
                    ts = int.from_bytes(m[5:11], "big")
                    if not self._pre(ts_recv, ts):
                        return
                    b = o[0]
                    b.remove(o[1], o[2], o[3])
                    px, sh = U32(m, 31)[0], U32(m, 27)[0]
                    orders[U64(m, 19)[0]] = [b, o[1], px, sh]
                    b.add(o[1], px, sh)
                    if self.opened:
                        self._post(b, ts_recv, ts)
                elif t == 88:  # X cancel (partial)
                    o = orders.get(U64(m, 11)[0])
                    if o is None:
                        continue
                    ts = int.from_bytes(m[5:11], "big")
                    if not self._pre(ts_recv, ts):
                        return
                    sh = min(U32(m, 19)[0], o[3])
                    o[0].remove(o[1], o[2], sh)
                    o[3] -= sh
                    if o[3] <= 0:
                        del orders[U64(m, 11)[0]]
                    if self.opened:
                        self._post(o[0], ts_recv, ts)
                elif t == 69 or t == 67:  # E executed / C executed with price
                    ref = U64(m, 11)[0]
                    o = orders.get(ref)
                    if o is None:
                        continue
                    ts = int.from_bytes(m[5:11], "big")
                    if not self._pre(ts_recv, ts):
                        return
                    sh = min(U32(m, 19)[0], o[3])
                    b = o[0]
                    b.remove(o[1], o[2], sh)
                    o[3] -= sh
                    if o[3] <= 0:
                        del orders[ref]
                    printable, px = True, o[2]
                    if t == 67:
                        printable, px = m[31] == 89, U32(m, 32)[0]
                    if sink and printable and ts >= self.start_ns:
                        sink.trade(ts_recv, ts, b.sym, px, sh, "C" if t == 67 else "E",
                                   "S" if o[1] else "B", U64(m, 23)[0], "")
                    if self.opened:
                        self._post(b, ts_recv, ts)
                elif t == 80:  # P non-cross trade (hidden liquidity)
                    b = by8.get(m[24:32])
                    if b is None:
                        continue
                    ts = int.from_bytes(m[5:11], "big")
                    if not self._pre(ts_recv, ts):
                        return
                    if sink and ts >= self.start_ns:
                        sink.trade(ts_recv, ts, b.sym, U32(m, 32)[0], U32(m, 20)[0], "P",
                                   "S" if m[19] == 66 else "B", U64(m, 36)[0], "")
                elif t == 81:  # Q cross trade
                    b = by8.get(m[19:27])
                    if b is None:
                        continue
                    ts = int.from_bytes(m[5:11], "big")
                    if not self._pre(ts_recv, ts):
                        return
                    if sink and ts >= self.start_ns:
                        sink.trade(ts_recv, ts, b.sym, U32(m, 27)[0], U64(m, 11)[0], "Q", "X",
                                   U64(m, 31)[0], chr(m[39]))
                elif t == 82:  # R stock directory (symbol info, ETP leverage factor)
                    self.n_dir += 1
                    b = by8.get(m[11:19])
                    if b is not None:
                        self.sym_info[b.sym] = {"locate": U16(m, 1)[0], "market_category": chr(m[19]),
                                                "etp_flag": chr(m[33]), "etp_leverage": U32(m, 34)[0],
                                                "inverse": chr(m[38])}
                elif t == 83:  # S system event
                    self.sys_events.append((int.from_bytes(m[5:11], "big"), chr(m[11])))
            except (IndexError, struct.error):
                self.bad_msgs += 1


# --------------------------------------------------------------------------- driver
def hhmm_to_ns(s):
    parts = [int(x) for x in s.split(":")] + [0, 0]
    return (parts[0] * 3600 + parts[1] * 60 + parts[2]) * NS_PER_S


def fmt_ns(ns):
    s, r = divmod(ns, NS_PER_S)
    return f"{s // 3600:02d}:{s % 3600 // 60:02d}:{s % 60:02d}.{r:09d}"


def stem_of(path, name):
    if name:
        return name
    s = os.path.basename(path)
    for suf in (".zst", ".pcapng", ".pcap", ".itch", ".dbn", ".bin"):
        if s.lower().endswith(suf):
            s = s[: -len(suf)]
    return s or "stdin"


def process_file(paths, opts):
    """Process one or more files as ONE continuous stream (order book carried across files)."""
    if isinstance(paths, str):
        paths = [paths]
    if len(paths) > 1 or opts.by_dir:
        paths = sorted(paths)
    path = paths[0]
    t0 = time.time()
    info = defaultdict(int)
    info["_ports"], info["_sessions"] = Counter(), {}
    symbols = [s.strip().upper() for s in (opts.symbols or PRESETS[opts.preset]).split(",") if s.strip()]
    start_ns = hhmm_to_ns(opts.start) if opts.rth else 0
    end_ns = hhmm_to_ns(opts.end) if opts.rth else 1 << 62
    sink = None
    if not opts.inspect:
        os.makedirs(opts.out_dir, exist_ok=True)
        fmt = opts.format
        if fmt == "auto":
            try:
                import pyarrow  # noqa: F401
                fmt = "parquet"
            except ImportError:
                fmt = "csv"
        name = opts.name or (os.path.basename(os.path.dirname(os.path.abspath(path))) if len(paths) > 1
                             else stem_of(path, ""))
        sink = Sink(os.path.join(opts.out_dir, name), fmt)
    bk = Books(symbols, sink, start_ns, end_ns)
    state, nblk, tlast = {}, 0, time.time()
    for fi, p in enumerate(paths, 1):
        f = open_stream(p)
        for ts_recv, msgs in iter_blocks(f, info, opts, state, last=(p == paths[-1])):
            bk.feed(ts_recv, msgs)
            nblk += 1
            if nblk % 5000 == 0 and time.time() - tlast > 20:
                tlast = time.time()
                print(f"  ... file {fi}/{len(paths)}  {sum(bk.tc):,} messages  {tlast - t0:.0f}s elapsed",
                      file=sys.stderr, flush=True)
            if bk.done:
                info["stopped_early_after_window"] = 1
                break
        if bk.done:
            break
    if sink:
        sink.close()
    return summarize(path if len(paths) == 1 else f"{path} (+{len(paths) - 1} more files, one continuous stream)",
                     opts, info, bk, sink, time.time() - t0)


def summarize(path, opts, info, bk, sink, secs):
    L = [f"=== {path}  ({secs:.1f}s)"]
    L.append(f"container: {info.get('container')}  link-layer unsupported: {info.get('unsupported_link', '-')}")
    if "first_pcap_ts" in info:
        try:
            from datetime import datetime, timezone
            from zoneinfo import ZoneInfo
            a = datetime.fromtimestamp(info["first_pcap_ts"] / 1e9, timezone.utc)
            b = datetime.fromtimestamp(info["last_pcap_ts"] / 1e9, timezone.utc)
            et = ZoneInfo("America/New_York")
            L.append(f"capture time: {a.astimezone(et):%Y-%m-%d %H:%M:%S} -> {b.astimezone(et):%Y-%m-%d %H:%M:%S} ET")
        except Exception:
            L.append(f"capture ts (ns): {info['first_pcap_ts']} -> {info['last_pcap_ts']}")
    keys = ["packets", "non_udp_packets", "short_udp", "mold_heartbeat_or_eos", "dup_packets", "held_out_of_order",
            "gap_msgs", "overlap_msgs", "truncated_pkts", "mold_trailing_bytes_pkts", "snaplen_truncated_pkts",
            "ip_fragments", "truncated_file"]
    L.append("  ".join(f"{k}={info[k]}" for k in keys if info.get(k)) or "no packet-level anomalies")
    if info["_ports"]:
        L.append("udp dest ports: " + ", ".join(f"{p}:{n}" for p, n in info["_ports"].most_common(5)))
    for s, (lo, hi) in list(info["_sessions"].items())[:3]:
        L.append(f"mold session {s!r}: seq {lo} .. {hi}")
    total = sum(bk.tc)
    hist = ", ".join(f"{chr(i)}={n:,}" for i, n in sorted(enumerate(bk.tc), key=lambda x: -x[1]) if n)
    L.append(f"itch messages: {total:,}   bad={bk.bad_msgs}   [{hist}]")
    if opts.inspect:
        L.append(f"stock-directory (R) messages: {bk.n_dir:,}")
        for s in bk.books:
            i = bk.sym_info.get(s)
            L.append(f"  {s:5s} adds seen={bk.adds[s]:<9,} " + (
                f"locate={i['locate']} listing_market={i['market_category']} etp={i['etp_flag']} "
                f"leverage={i['etp_leverage']} inverse={i['inverse']}"
                if i else "no R message seen (capture may start after the directory, or symbol absent)"))
        if bk.sys_events:
            L.append("system events: " + ", ".join(f"{c}@{fmt_ns(t)}" for t, c in bk.sys_events[:12]))
        L.append("next step: run without --inspect (add --rth for 09:30-16:00 ET only)")
    elif sink:
        L.append(f"wrote {sink.nb:,} bbo rows, {sink.nt:,} trade rows -> {sink.base}_bbo/_trades.{sink.fmt}")
        if info.get("stopped_early_after_window"):
            L.append(f"stopped reading after {opts.end} ET (--rth)")
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="+", help="input files, or - for stdin")
    ap.add_argument("--inspect", action="store_true", help="report what is in the file, write nothing")
    ap.add_argument("--preset", choices=sorted(PRESETS), default="ndx",
                    help="symbol group: ndx=QQQ,TQQQ,SQQQ (default)  spx=SPY,SSO,UPRO,SDS,SPXU,SPXL,SPXS")
    ap.add_argument("--symbols", default="", help="comma list, overrides --preset (e.g. QQQ,TQQQ,SQQQ,QQQM)")
    ap.add_argument("--rth", action="store_true", help="keep only --start..--end (ET) in the output")
    ap.add_argument("--start", default="09:30")
    ap.add_argument("--end", default="16:00")
    ap.add_argument("--out-dir", default="out")
    ap.add_argument("--format", choices=["auto", "parquet", "csv"], default="auto")
    ap.add_argument("--jobs", type=int, default=1, help="capture days to process in parallel (needs --by-dir)")
    ap.add_argument("--by-dir", action="store_true",
                    help="each parent folder (one day) is its own continuous stream, output named after the folder")
    ap.add_argument("--separate", action="store_true", help="treat every file as its own stream (no book carry-over)")
    ap.add_argument("--max-packets", type=int, default=0, help="stop after N packets (0 = all)")
    ap.add_argument("--port", type=int, default=0, help="only UDP packets to this destination port")
    ap.add_argument("--name", default="", help="output stem (required-ish for stdin)")
    ap.add_argument("--reorder-window", type=int, default=2048)
    opts = ap.parse_args()
    if opts.inspect and not opts.max_packets:
        opts.max_packets = 300_000
    if opts.separate:
        groups = [[p] for p in opts.files]
    elif opts.by_dir:
        g = defaultdict(list)
        for p in opts.files:
            g[os.path.dirname(os.path.abspath(p))].append(p)
        groups = list(g.values())
    else:
        groups = [opts.files]
    if opts.jobs > 1 and len(groups) > 1:
        with ProcessPoolExecutor(opts.jobs) as ex:
            for r in ex.map(process_file, groups, [opts] * len(groups)):
                print(r, flush=True)
    else:
        for g in groups:
            print(process_file(g, opts), flush=True)


if __name__ == "__main__":
    main()
