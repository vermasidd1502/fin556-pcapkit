#!/usr/bin/env python3
"""
mdp3_parse.py - stream-parse CME Globex MDP 3.0 (SBE) packet captures
(Databento "glbx" files such as dc3-glbx-a-20250201T000000.pcap.zst) and keep only the
instruments you care about (default: Nasdaq-100 futures NQ and MNQ, all expiries).
Nothing is written to disk except the filtered output, and nothing touches the network.

Output (one pair of files per run; files are processed in name order and the order book
is carried across files, so 10-minute chunks join seamlessly):
  <name>_bbo.parquet     every change of the top --depth book levels (default 1 = top of book)
  <name>_trades.parquet  trade summary prints (price, size, aggressor side)
(.csv if pyarrow is not installed)

Quick start
  pip install zstandard pyarrow
  python mdp3_parse.py --inspect  /db_pcaps/glbx_pcaps/20250201/dc3-glbx-a-20250201T000000.pcap.zst
  python mdp3_parse.py --defs defs.json --scan-defs  /db_pcaps/glbx_pcaps/20250201/dc3-glbx-a-20250201T000000.pcap.zst
  python mdp3_parse.py --defs defs.json --out-dir out  /db_pcaps/glbx_pcaps/20250201/*.pcap.zst

Notes
  * Prices are PRICE9 (mantissa x 1e-9). SecurityIDs are mapped to symbols through the
    instrument definitions (template 54) that CME repeats on the definition channel;
    --scan-defs reads them once and saves them to --defs for later runs.
  * Book updates are applied as CME specifies (New / Change / Delete / DeleteThru / DeleteFrom /
    Overlay on price levels 1..10, explicit book only: implied entries E/F are ignored).
  * Per-instrument RptSeq is used to drop duplicate copies (A/B feeds, retransmissions).
  * A capture that starts mid-session has no snapshot: levels fill in as they update, so treat the
    first minute of the first file as warm-up.
"""
import argparse
import csv
import io
import json
import os
import re
import struct
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor

ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
NS = 1_000_000_000
U16 = struct.Struct("<H").unpack_from
U32 = struct.Struct("<I").unpack_from
I32 = struct.Struct("<i").unpack_from
U64 = struct.Struct("<Q").unpack_from
I64 = struct.Struct("<q").unpack_from
NULL_I32, NULL_PX = 2147483647, 9223372036854775807
MAXD = 10  # CME futures book depth
MONTHS = "FGHJKMNQUVXZ"
TEMPLATES = {4: "ChannelReset4", 12: "AdminHeartbeat12", 27: "MDInstrumentDefinitionFuture27", 30: "SecurityStatus30",
             32: "MDIncrementalRefreshBook32", 33: "MDIncrementalRefreshDailyStatistics33",
             34: "MDIncrementalRefreshLimitsBanding34", 35: "MDIncrementalRefreshSessionStatistics35",
             36: "MDIncrementalRefreshTrade36", 37: "MDIncrementalRefreshVolume37", 38: "SnapshotFullRefresh38",
             42: "MDIncrementalRefreshTradeSummary42", 43: "MDIncrementalRefreshBook43",
             46: "MDIncrementalRefreshBook46", 47: "MDIncrementalRefreshOrderBook47",
             48: "MDIncrementalRefreshTradeSummary48", 49: "MDIncrementalRefreshDailyStatistics49",
             50: "MDIncrementalRefreshLimitsBanding50", 51: "MDIncrementalRefreshSessionStatistics51",
             52: "SnapshotFullRefresh52", 53: "SnapshotFullRefreshOrderBook53",
             54: "MDInstrumentDefinitionFuture54", 55: "MDInstrumentDefinitionOption55",
             56: "MDInstrumentDefinitionSpread56"}


# --------------------------------------------------------------------------- capture reading
def open_stream(path):
    raw = open(path, "rb", buffering=1 << 20)
    buf = raw if hasattr(raw, "peek") else io.BufferedReader(raw, 1 << 20)
    if buf.peek(4)[:4] == ZSTD_MAGIC:
        try:
            import zstandard
        except ImportError:
            sys.exit("This file is zstd-compressed: run  pip install zstandard")
        rd = zstandard.ZstdDecompressor().stream_reader(buf, read_across_frames=True)
        buf = io.BufferedReader(rd, 1 << 22)
    return buf


def iter_pcap(f, info):
    hdr = f.read(24)
    end, nano = {b"\xd4\xc3\xb2\xa1": ("<", False), b"\xa1\xb2\xc3\xd4": (">", False),
                 b"\x4d\x3c\xb2\xa1": ("<", True), b"\xa1\xb2\x3c\x4d": (">", True)}[hdr[:4]]
    link = struct.unpack(end + "I", hdr[20:24])[0] & 0x0FFFFFFF
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
        yield sec * NS + (frac if nano else frac * 1000), link, data


def iter_pcapng(f, info):
    end, ifaces = "<", []
    while True:
        h = f.read(8)
        if len(h) < 8:
            break
        if h[:4] == b"\x0a\x0d\x0d\x0a":
            body = f.read(struct.unpack("<I", h[4:])[0] - 8)
            end = "<" if body[:4] == b"\x4d\x3c\x2b\x1a" else ">"
            ifaces = []
            continue
        btype, blen = struct.unpack(end + "II", h)
        body = f.read(blen - 8)
        if len(body) < blen - 8:
            info["truncated_file"] = 1
            break
        body = body[:-4]
        if btype == 1:
            link, tsres, p = struct.unpack(end + "H", body[:2])[0], 6, 8
            while p + 4 <= len(body):
                code, ln = struct.unpack(end + "HH", body[p:p + 4])
                if code == 0:
                    break
                if code == 9:
                    tsres = body[p + 4]
                p += 4 + ((ln + 3) & ~3)
            ifaces.append((link, tsres))
        elif btype == 6:
            iid, hi, lo, cap, orig = struct.unpack(end + "IIIII", body[:20])
            link, res = ifaces[iid]
            u = (hi << 32) | lo
            ns = (u * NS >> (res & 0x7F)) if res & 0x80 else (u * 10 ** (9 - res) if res <= 9 else u // 10 ** (res - 9))
            yield ns, link, body[20:20 + cap]


def udp_payload(link, d, info):
    """-> (dst_ip_bytes, dst_port, udp_payload) or None"""
    n = len(d)
    if link == 1:
        if n < 14:
            return None
        et, off = (d[12] << 8) | d[13], 14
        while et in (0x8100, 0x88A8, 0x9100) and n >= off + 4:
            et, off = (d[off + 2] << 8) | d[off + 3], off + 4
    elif link == 113 and n >= 16:
        et, off = (d[14] << 8) | d[15], 16
    elif link == 276 and n >= 20:
        et, off = (d[0] << 8) | d[1], 20
    elif link in (101, 12) and n >= 1:
        et, off = (0x0800 if d[0] >> 4 == 4 else 0x86DD), 0
    else:
        info["unsupported_link"] = link
        return None
    if et == 0x0800:
        if n < off + 20 or d[off + 9] != 17:
            return None
        if ((d[off + 6] & 0x3F) << 8) | d[off + 7]:
            info["ip_fragments"] += 1
            return None
        dip, udp = bytes(d[off + 16:off + 20]), off + (d[off] & 0x0F) * 4
    elif et == 0x86DD:
        if n < off + 40 or d[off + 6] != 17:
            return None
        dip, udp = bytes(d[off + 24:off + 40]), off + 40
    else:
        return None
    if n < udp + 8:
        return None
    _, dport, ulen = struct.unpack_from(">HHH", d, udp)
    return dip, dport, d[udp + 8:udp + ulen]


def iter_packets(f, info):
    head = f.peek(4)[:4]
    if head in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        info["container"] = "pcap"
        return iter_pcap(f, info)
    if head == b"\x0a\x0d\x0d\x0a":
        info["container"] = "pcapng"
        return iter_pcapng(f, info)
    raise SystemExit("Not a pcap/pcapng stream; first bytes: " + f.peek(16)[:16].hex())


# --------------------------------------------------------------------------- output
class Table:
    def __init__(self, base, name, cols, fmt, scale=1.0):
        self.name, self.cols, self.fmt, self.scale = name, cols, fmt, scale
        self.path = f"{base}_{name}.{'parquet' if fmt == 'parquet' else 'csv'}"
        self.rows, self.n, self.w = [], 0, None
        if fmt == "parquet":
            import pyarrow as pa
            import pyarrow.parquet as pq
            self.pa, self.pq = pa, pq
            t = {"i": pa.int64(), "p": pa.float64(), "s": pa.string()}
            self.schema = pa.schema([(c, t[k]) for c, k in cols])

    def add(self, row):
        self.rows.append(row)
        self.n += 1
        if len(self.rows) >= 250_000:
            self.flush()

    def flush(self):
        if not self.rows:
            return
        cols = list(zip(*self.rows))
        cols = [[round(v / 1e9 * self.scale, 8) if v else float("nan") for v in c] if k == "p" else list(c)
                for c, (_, k) in zip(cols, self.cols)]
        if self.fmt == "parquet":
            if self.w is None:
                self.w = self.pq.ParquetWriter(self.path, self.schema, compression="zstd")
            self.w.write_table(self.pa.table({c: v for (c, _), v in zip(self.cols, cols)}, schema=self.schema))
        else:
            if self.w is None:
                fh = open(self.path, "w", newline="")
                self.w = (fh, csv.writer(fh))
                self.w[1].writerow([c for c, _ in self.cols])
            self.w[1].writerows(zip(*cols))
        self.rows = []

    def close(self):
        self.flush()
        if self.w is not None:
            (self.w[0].close() if self.fmt == "csv" else self.w.close())
        elif self.fmt == "parquet":
            self.pq.write_table(self.schema.empty_table(), self.path)
        else:
            with open(self.path, "w", newline="") as fh:
                csv.writer(fh).writerow([c for c, _ in self.cols])


# --------------------------------------------------------------------------- order book
class Bk:
    __slots__ = ("sym", "bid", "ask", "last")

    def __init__(self, sym):
        self.sym, self.bid, self.ask, self.last = sym, [], [], None


Z = (0, 0, 0)


def book_key(bk, depth):
    bid, ask = bk.bid, bk.ask
    if depth == 1:
        b = bid[0] if bid else Z
        a = ask[0] if ask else Z
        return (b[0], b[1], b[2], a[0], a[1], a[2])
    out = []
    for i in range(depth):
        b = bid[i] if i < len(bid) else Z
        a = ask[i] if i < len(ask) else Z
        out += (b[0], b[1], b[2], a[0], a[1], a[2])
    return tuple(out)


def apply_level(side, act, lvl, px, sz, ct):
    i = lvl - 1
    if act == 0:  # New: insert at level, deeper levels shift down
        if i > len(side):
            i = len(side)
        side.insert(i, (px, sz, ct))
        del side[MAXD:]
    elif act == 1 or act == 5:  # Change / Overlay
        if i < len(side):
            side[i] = (px, sz, ct)
        elif i == len(side):
            side.append((px, sz, ct))
    elif act == 2:  # Delete: deeper levels shift up
        if i < len(side):
            del side[i]
    elif act == 3:  # DeleteThru: whole side
        side.clear()
    elif act == 4:  # DeleteFrom: levels 1..lvl
        del side[:lvl]


class Mdp3:
    def __init__(self, opts, bbo, trd, defs):
        self.o, self.bbo, self.trd = opts, bbo, trd
        self.depth = opts.depth
        self.defs = dict(defs)  # secid -> symbol (all futures definitions seen)
        self.regex = re.compile(r"^(%s)[%s]\d$" % ("|".join(re.escape(p.strip().upper()) for p in opts.products.split(",")), MONTHS))
        self.explicit = {s.strip().upper() for s in opts.symbols.split(",") if s.strip()}
        self.books, self.pats = {}, []
        self.last_rpt = {}
        self.tc = Counter()
        self.schemas = Counter()
        self.other = Counter()
        self.info = None
        self.samples = defaultdict(list)
        self.ts_min = self.ts_max = None
        self.n_defs = 0
        self.stat = {}
        self.cur_dst = ""
        for sid, sym in self.defs.items():
            self._maybe_track(sid, sym)

    def _maybe_track(self, sid, sym):
        if sid in self.books:
            return
        if (sym in self.explicit) if self.explicit else self.regex.match(sym):
            self.books[sid] = Bk(sym)
            self.pats = [struct.pack("<i", s) for s in self.books]

    @property
    def need_defs(self):
        return self.o.scan_defs or self.o.discover or not self.books

    # ---- packet
    def feed(self, ts_recv, pl, info):
        n = len(pl)
        if n < 12:
            info["short_udp"] += 1
            return
        if n >= 22 and U16(pl, 18)[0] != 1:  # first message's SchemaID: 1 = MDP 3.0 core; anything else is not ours
            info["other_schema_packets"] += 1
            if self.o.inspect:
                self.other[(U16(pl, 18)[0], U16(pl, 20)[0], U16(pl, 16)[0])] += 1
            return
        sending = U64(pl, 4)[0]
        if self.ts_min is None or sending < self.ts_min:
            self.ts_min = sending
        if self.ts_max is None or sending > self.ts_max:
            self.ts_max = sending
        pos, tc = 12, self.tc
        while pos + 10 <= n:
            sz = U16(pl, pos)[0]
            if sz < 10 or pos + sz > n:
                info["bad_frame"] += 1
                break
            bl, tid = U16(pl, pos + 2)[0], U16(pl, pos + 4)[0]
            body, end = pos + 10, pos + sz
            if self.o.inspect:
                self.schemas[(U16(pl, pos + 6)[0], U16(pl, pos + 8)[0])] += 1
                if len(self.samples[tid]) < 2:
                    self.samples[tid].append((bl, bytes(pl[pos:min(end, pos + 100)])))
            pos = end
            tc[tid] += 1
            if self.o.discover:
                if tid == 46 or tid == 48:
                    self._disc(pl, body, bl, end, tid)
            elif tid == 46:
                if not self.o.scan_defs:
                    self._book(ts_recv, pl, body, bl, end, info)
            elif tid == 48:
                if not self.o.scan_defs:
                    self._trades(ts_recv, pl, body, bl, end, info)
            elif tid == 54:
                self._def(pl, body, end)

    def _disc(self, pl, body, bl, end, tid):
        # no definitions in the capture: collect per-SecurityID price/size statistics so NQ/MNQ can be told apart by price
        g = body + bl
        if g + 3 > end:
            return
        gbl, ne = U16(pl, g)[0], pl[g + 2]
        off = g + 3
        if gbl < 26 or off + ne * gbl > end:
            return
        st = self.stat
        lo, hi = self.o.px_min * 1_000_000_000, self.o.px_max * 1_000_000_000
        for _ in range(ne):
            px = I64(pl, off)[0]
            if lo <= px <= hi:
                sid = I32(pl, off + 12)[0]
                r = st.get(sid)
                if r is None:
                    r = st[sid] = [0, 0, 0, px, px, 0, 0, 0, 0, self.cur_dst]  # nbook, ntrade, volume, pmin, pmax, last, bid_sz_sum, bid_n, maxsz
                sz = I32(pl, off + 8)[0]
                if tid == 48:
                    r[1] += 1
                    r[2] += sz
                    r[5] = px
                    if px < r[3]:
                        r[3] = px
                    if px > r[4]:
                        r[4] = px
                else:
                    r[0] += 1
                    if pl[off + 26] == 48 and pl[off + 24] == 1:  # best bid size
                        r[6] += sz
                        r[7] += 1
                    if sz > r[8]:
                        r[8] = sz
            off += gbl

    def _def(self, pl, body, end):
        if body + 59 > end:
            return
        sym = bytes(pl[body + 35:body + 55]).split(b"\0", 1)[0].decode("ascii", "replace").strip()
        sid = I32(pl, body + 55)[0]
        if sid not in self.defs:
            self.n_defs += 1
        self.defs[sid] = sym
        self._maybe_track(sid, sym)

    def _book(self, ts_recv, pl, body, bl, end, info):
        ts_ev, flags = U64(pl, body)[0], pl[body + 8]
        g = body + bl
        if g + 3 > end:
            info["bad_book"] += 1
            return
        gbl, ne = U16(pl, g)[0], pl[g + 2]
        off = g + 3
        if gbl < 27 or off + ne * gbl > end:
            info["bad_book"] += 1
            return
        books, last_rpt = self.books, self.last_rpt
        inspect = self.o.inspect
        touched = []
        for _ in range(ne):
            sid = I32(pl, off + 12)[0]
            if inspect and len(self.samples["book_entries"]) < 6:
                self.samples["book_entries"].append(
                    (sid, I64(pl, off)[0], I32(pl, off + 8)[0], U32(pl, off + 16)[0], I32(pl, off + 20)[0],
                     pl[off + 24], pl[off + 25], chr(pl[off + 26])))
            bk = books.get(sid)
            if bk is not None:
                rpt = U32(pl, off + 16)[0]
                lr = last_rpt.get(sid, -1)
                if rpt <= lr and lr - rpt < 1_000_000:
                    info["dup_entries"] += 1
                else:
                    last_rpt[sid] = rpt
                    typ = pl[off + 26]
                    if typ == 48 or typ == 49:  # '0' bid, '1' offer
                        px, sz, ct = I64(pl, off)[0], I32(pl, off + 8)[0], I32(pl, off + 20)[0]
                        apply_level(bk.bid if typ == 48 else bk.ask, pl[off + 25], pl[off + 24],
                                    0 if px == NULL_PX else px, 0 if sz == NULL_I32 else sz,
                                    0 if ct == NULL_I32 else ct)
                        if bk not in touched:
                            touched.append(bk)
                    elif typ == 74:  # 'J' empty book
                        bk.bid.clear()
                        bk.ask.clear()
                        if bk not in touched:
                            touched.append(bk)
            off += gbl
        if touched and self.bbo is not None:
            d = self.depth
            for bk in touched:
                k = book_key(bk, d)
                if k != bk.last:
                    bk.last = k
                    self.bbo.add((ts_recv, ts_ev, flags, bk.sym) + k)

    def _trades(self, ts_recv, pl, body, bl, end, info):
        ts_ev, flags = U64(pl, body)[0], pl[body + 8]
        g = body + bl
        if g + 3 > end:
            info["bad_trade"] += 1
            return
        gbl, ne = U16(pl, g)[0], pl[g + 2]
        off = g + 3
        if gbl < 26 or off + ne * gbl > end:
            info["bad_trade"] += 1
            return
        books, last_rpt = self.books, self.last_rpt
        for _ in range(ne):
            sid = I32(pl, off + 12)[0]
            if self.o.inspect and len(self.samples["trade_entries"]) < 6:
                self.samples["trade_entries"].append(
                    (sid, I64(pl, off)[0], I32(pl, off + 8)[0], U32(pl, off + 16)[0], I32(pl, off + 20)[0],
                     pl[off + 24], pl[off + 25]))
            bk = books.get(sid)
            if bk is not None:
                rpt = U32(pl, off + 16)[0]
                lr = last_rpt.get(sid, -1)
                if rpt <= lr and lr - rpt < 1_000_000:
                    info["dup_entries"] += 1
                else:
                    last_rpt[sid] = rpt
                    if self.trd is not None:
                        ag = pl[off + 24]
                        self.trd.add((ts_recv, ts_ev, flags, bk.sym, I64(pl, off)[0], I32(pl, off + 8)[0],
                                      "B" if ag == 1 else "S" if ag == 2 else "", I32(pl, off + 20)[0], rpt,
                                      pl[off + 25]))
            off += gbl


# --------------------------------------------------------------------------- driver
def fmt_ns(ns):
    try:
        from datetime import datetime, timezone
        from zoneinfo import ZoneInfo
        t = datetime.fromtimestamp(ns / 1e9, timezone.utc)
        return f"{t:%Y-%m-%d %H:%M:%S} UTC = {t.astimezone(ZoneInfo('America/New_York')):%Y-%m-%d %H:%M:%S} ET"
    except Exception:
        return str(ns)


def load_defs(path, opts=None):
    if path and os.path.exists(path):
        with open(path) as fh:
            d = {int(k): v for k, v in json.load(fh).items()}
    else:
        d = {}
    for item in (getattr(opts, "secids", "") or "").split(","):
        if "=" in item:
            sym, sid = item.split("=", 1)
            d[int(sid)] = sym.strip().upper()
    return d


def run_group(paths, opts):
    t0 = time.time()
    paths = sorted(paths)
    info = defaultdict(int)
    info["_dst"] = Counter()
    fmt = opts.format
    if fmt == "auto":
        try:
            import pyarrow  # noqa: F401
            fmt = "parquet"
        except ImportError:
            fmt = "csv"
    bbo = trd = None
    if not (opts.inspect or opts.scan_defs or opts.discover):
        os.makedirs(opts.out_dir, exist_ok=True)
        name = opts.name or os.path.basename(os.path.dirname(os.path.abspath(paths[0]))) or "mdp3"
        base = os.path.join(opts.out_dir, name)
        cols = [("ts_recv_ns", "i"), ("ts_event_ns", "i"), ("flags", "i"), ("symbol", "s")]
        for i in range(opts.depth):
            cols += [(f"bid_px_{i:02d}", "p"), (f"bid_sz_{i:02d}", "i"), (f"bid_ct_{i:02d}", "i"),
                     (f"ask_px_{i:02d}", "p"), (f"ask_sz_{i:02d}", "i"), (f"ask_ct_{i:02d}", "i")]
        bbo = Table(base, "bbo", cols, fmt, opts.display_factor)
        trd = Table(base, "trades", [("ts_recv_ns", "i"), ("ts_event_ns", "i"), ("flags", "i"), ("symbol", "s"),
                                      ("price", "p"), ("size", "i"), ("aggressor", "s"), ("num_orders", "i"),
                                      ("rpt_seq", "i"), ("action", "i")], fmt, opts.display_factor)
    m = Mdp3(opts, bbo, trd, load_defs(opts.defs, opts))
    npk, stop, tlast = 0, False, time.time()
    for fi, path in enumerate(paths, 1):
        f = open_stream(path)
        for ts, link, data in iter_packets(f, info):
            npk += 1
            if npk % 20000 == 0 and time.time() - tlast > 20:
                tlast = time.time()
                print(f"  ... file {fi}/{len(paths)}  {npk:,} packets  {tlast - t0:.0f}s elapsed", file=sys.stderr, flush=True)
            if opts.max_packets and npk > opts.max_packets:
                stop = True
                break
            r = udp_payload(link, data, info)
            if r is None:
                info["non_udp_packets"] += 1
                continue
            dip, dport, pl = r
            info["_dst"][(dip, dport)] += 1
            if opts.port and dport != opts.port:
                continue
            if not m.need_defs and not opts.inspect:
                if not any(p in pl for p in m.pats):  # cheap pre-filter: packet cannot hold our SecurityIDs
                    continue
            m.cur_dst = f"{'.'.join(map(str, dip))}:{dport}" if len(dip) == 4 else str(dport)
            m.feed(ts, pl, info)
        if stop:
            break
    info["packets"] = npk
    if opts.defs and (opts.scan_defs or m.n_defs):
        with open(opts.defs, "w") as fh:
            json.dump({str(k): v for k, v in sorted(m.defs.items())}, fh)
    if bbo:
        bbo.close()
        trd.close()
    return report(paths, opts, info, m, bbo, trd, time.time() - t0)


def report(paths, opts, info, m, bbo, trd, secs):
    L = [f"=== {len(paths)} file(s), first: {paths[0]}  ({secs:.1f}s)"]
    L.append(f"container={info.get('container')}  packets={info['packets']:,}  "
             + "  ".join(f"{k}={info[k]:,}" for k in ("non_udp_packets", "short_udp", "other_schema_packets", "bad_frame", "bad_book", "bad_trade",
                                                     "dup_entries", "ip_fragments", "truncated_file") if info.get(k)))
    if m.ts_min:
        L.append(f"sending time: {fmt_ns(m.ts_min)}  ->  {fmt_ns(m.ts_max)}")
    L.append("instrument definitions: %d known, %d tracked: %s" % (
        len(m.defs), len(m.books), ", ".join(f"{b.sym}={sid}" for sid, b in sorted(m.books.items(), key=lambda x: x[1].sym))
        or "none yet"))
    if opts.discover:
        rows = sorted(m.stat.items(), key=lambda kv: -kv[1][1])
        L.append(f"candidates with price in [{opts.px_min:,.0f}, {opts.px_max:,.0f}] (futures like NQ/MNQ), most trades first:")
        L.append("  secid        trades     volume    book_upd   px_min     px_max     last       avg_best_bid_sz  max_sz  udp_dest")
        for sid, r in rows[:25]:
            L.append(f"  {sid:<11d} {r[1]:>8,} {r[2]:>10,} {r[0]:>11,} {r[3] / 1e9:>10,.2f} {r[4] / 1e9:>10,.2f} {r[5] / 1e9:>10,.2f} "
                     f"{(r[6] / r[7] if r[7] else 0):>12.1f} {r[8]:>9,}  {r[9]}")
        L.append("pick the front month: most trades, price ~ the NQ level. The micro (MNQ) trades at the same price with a bigger "
                 "avg_best_bid_sz. Then run with:  --secids NQH5=<secid>,MNQH5=<secid>")
    elif opts.inspect:
        L.append("udp destinations (ip:port -> packets): " + ", ".join(
            f"{'.'.join(map(str, k[0])) if len(k[0]) == 4 else k[0].hex()}:{k[1]}={n:,}"
            for k, n in info["_dst"].most_common(8)))
        L.append("schema (id,version) -> messages: " + ", ".join(f"{k}={n:,}" for k, n in m.schemas.most_common(4)))
        if m.other:
            L.append("ignored (not MDP 3.0 core schema 1): " + ", ".join(
                f"schema {a} v{b} template {c} x{n:,}" for (a, b, c), n in m.other.most_common(4)))
        L.append("templates: " + ", ".join(f"{t}:{TEMPLATES.get(t, '?')}={n:,}" for t, n in m.tc.most_common(12)))
        L.append(f"bad frames: {info['bad_frame']}  (0 means every message size chained exactly to the end of its packet)")
        if m.defs:
            L.append("sample definitions: " + ", ".join(f"{v}={k}" for k, v in list(m.defs.items())[:8]))
        for key, title in (("book_entries", "first book entries (secid, px_mantissa, size, rptseq, orders, level, action, type)"),
                           ("trade_entries", "first trade entries (secid, px_mantissa, size, rptseq, orders, aggressor, action)")):
            for e in m.samples[key][:4]:
                sym = m.defs.get(e[0], "?")
                L.append(f"  {title.split(' (')[0]} {sym}: {e}  px={e[1] / 1e9:.2f}")
        for t in (46, 48, 54):
            for bl, hx in m.samples[t][:1]:
                L.append(f"  raw {TEMPLATES.get(t)} blockLength={bl}: {hx.hex()}")
        L.append("next: if the prices above look right, run --scan-defs once, then the full run")
    elif opts.scan_defs:
        L.append(f"definitions saved to {opts.defs}")
    else:
        L.append(f"wrote {bbo.n:,} bbo rows, {trd.n:,} trade rows -> {bbo.path} / {trd.path}")
        if not m.books:
            L.append("WARNING: no tracked instruments - run --scan-defs on a file that contains the definition channel, "
                     "or pass --symbols / --defs")
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="+", help="*.pcap.zst files of one continuous capture (sorted by name)")
    ap.add_argument("--inspect", action="store_true", help="report what is in the file, write nothing")
    ap.add_argument("--scan-defs", action="store_true", help="only read instrument definitions and save them to --defs")
    ap.add_argument("--defs", default="", help="JSON file with secid->symbol (read, and updated when new ones appear)")
    ap.add_argument("--products", default="NQ,MNQ", help="futures product codes to keep (default NQ,MNQ = Nasdaq-100)")
    ap.add_argument("--symbols", default="", help="exact symbols instead of products, e.g. NQH5,NQM5")
    ap.add_argument("--depth", type=int, default=1, choices=range(1, 11), help="book levels in the bbo output (1 = top of book)")
    ap.add_argument("--out-dir", default="out")
    ap.add_argument("--name", default="", help="output name (default: parent folder name, e.g. 20250201)")
    ap.add_argument("--format", choices=["auto", "parquet", "csv"], default="auto")
    ap.add_argument("--by-dir", action="store_true", help="treat each parent folder as a separate capture (parallel with --jobs)")
    ap.add_argument("--jobs", type=int, default=1)
    ap.add_argument("--max-packets", type=int, default=0)
    ap.add_argument("--discover", action="store_true", help="no definitions in the capture: list SecurityIDs whose prices look like NQ/MNQ")
    ap.add_argument("--px-min", type=float, default=15000.0)
    ap.add_argument("--px-max", type=float, default=30000.0)
    ap.add_argument("--display-factor", type=float, default=1.0, help="multiply prices by this; NQ/MNQ/ES are sent 100x too large, use 0.01")
    ap.add_argument("--secids", default="", help="manual map, e.g. NQH5=42002868,MNQH5=42005412 (use after --discover)")
    ap.add_argument("--port", type=int, default=0, help="only UDP packets to this destination port")
    opts = ap.parse_args()
    if opts.inspect and not opts.max_packets:
        opts.max_packets = 300_000
    groups = [opts.files]
    if opts.by_dir:
        g = defaultdict(list)
        for p in opts.files:
            g[os.path.dirname(os.path.abspath(p))].append(p)
        groups = list(g.values())
    if opts.jobs > 1 and len(groups) > 1:
        with ProcessPoolExecutor(opts.jobs) as ex:
            for r in ex.map(run_group, groups, [opts] * len(groups)):
                print(r, flush=True)
    else:
        for g in groups:
            print(run_group(g, opts), flush=True)


if __name__ == "__main__":
    main()
