#!/usr/bin/env python3
"""day_pull.py - one-pass pull of everything the FIN556 team-8 study needs, per trading day. Runs ON THE LAB VM.

Read-only on the capture folders; writes only --out-dir; deletes raw parser output after each day; stops if free
disk < --min-free-gb. Prints counts only, never data rows. Output is Parquet (zstd), one file per table per day:

  ticks_<date>.parquet      Nasdaq + CME (+ IEX) L1 quotes and all trades, --start..--end ET (default 04:00-20:00)
                            ts_recv_ns, ts_event_ns (UTC epoch ns), venue XNAS/GLBX/IEXG, symbol (NQ contract for GLBX),
                            type Q/T, bid_px, bid_sz, ask_px, ask_sz, price, size, aggressor B/S, trade_id,
                            kind (XNAS: E=lit exec, P=hidden/non-displayed, C=exec w/ price; IEX: sale-condition flags)
  cme_depth_<date>.parquet  NQ book levels 2-10 (bid/ask px, sz, order count) at every CME book update
  noii_<date>.parquet       every Nasdaq Net Order Imbalance message (open, close, halt crosses)
  crosses_<date>.parquet    official Nasdaq opening/closing/halt cross prints
  iex_levels_<date>.parquet IEX DEEP price-level updates (full IEX depth)        [if --iex-glob given]
  iex_auction_<date>.parquet IEX auction information (IEX's own imbalance feed) [if --iex-glob given]

Columns in the study windows can be selected later by time; no window is hard-coded, so nothing needs re-parsing.
Symbols: QQQ/TQQQ/SQQQ, the 12 stocks and their 44 leveraged single-stock ETFs (59 total), plus the front NQ contract.

  python3 day_pull.py --from 20250203 --to 20250430 --dry-run
  python3 day_pull.py --from 20250402 --to 20250402
  python3 day_pull.py --from 20250203 --to 20250314 --out-dir ~/myproject/pull_c1 --iex-glob '/path/{date}/*.pcap*'
"""
import argparse, glob, os, shutil, subprocess, sys, threading, time

import pyarrow as pa, pyarrow.compute as pc, pyarrow.csv as pacsv, pyarrow.parquet as pq

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from datetime import timedelta
from ndx_combine import NS, daterange, et_ns, select_files  # noqa: E402

STOCKS = "NVDA,TSLA,AAPL,AMD,AMZN,AVGO,COIN,GOOGL,META,MSFT,MSTR,PLTR"
INDEX = "QQQ,TQQQ,SQQQ"
LEV = ("AAPB,AAPD,AAPU,AMDG,AMDL,AMDD,AMUU,AMZD,AMZU,AMZZ,AVGX,AVL,AVS,CONI,CONL,COIG,FBL,METD,METU,GGLL,GGLS,"
       "MSFD,MSFL,MSFU,MSTX,SMST,NVD,NVDD,NVDG,NVDL,NVDS,NVDU,PLTD,PLTU,PTIR,PLTG,TSDD,TSL,TSLG,TSLL,TSLQ,TSLR,TSLS")
SYMS = ",".join([INDEX, STOCKS, LEV])
NQ_IDS = [("20250317", "NQM5=42005804"), ("00000000", "NQH5=42288528")]   # NQH5 until 2025-03-14
DEPTH = 10
TICK_SCHEMA = pa.schema([("ts_recv_ns", pa.int64()), ("ts_event_ns", pa.int64()), ("venue", pa.string()),
                         ("symbol", pa.string()), ("type", pa.string()), ("bid_px", pa.float64()), ("bid_sz", pa.int64()),
                         ("ask_px", pa.float64()), ("ask_sz", pa.int64()), ("price", pa.float64()), ("size", pa.int64()),
                         ("aggressor", pa.string()), ("trade_id", pa.int64()), ("kind", pa.string())])
STR = pacsv.ConvertOptions(strings_can_be_null=True, column_types={
    "symbol": pa.string(), "kind": pa.string(), "aggressor": pa.string(), "cross_type": pa.string(),
    "direction": pa.string(), "pvi": pa.string(), "side": pa.string(), "auction_type": pa.string(), "imb_side": pa.string()})


def free_gb(p):
    return shutil.disk_usage(p).free / 1e9


def nq_for(tag):
    return next(v for d, v in NQ_IDS if tag >= d)


def rd(path):
    return pacsv.read_csv(path, convert_options=STR)


def write(tbl, path):
    pq.write_table(tbl, path, compression="zstd", compression_level=9, use_dictionary=["venue", "symbol", "type",
                   "aggressor", "kind", "cross_type", "direction", "pvi", "side", "auction_type", "imb_side"],
                   row_group_size=1 << 20)


def conform(tbl, consts):
    cols = []
    for f in TICK_SCHEMA:
        if f.name in consts:
            cols.append(pa.array([consts[f.name]] * tbl.num_rows, f.type))
        elif f.name in tbl.column_names:
            cols.append(pc.cast(tbl[f.name], f.type))
        else:
            cols.append(pa.nulls(tbl.num_rows, f.type))
    return pa.Table.from_arrays(cols, schema=TICK_SCHEMA)


def in_win(tbl, col, t0, t1):
    c = tbl[col]
    return tbl.filter(pc.and_(pc.greater_equal(c, t0), pc.less(c, t1)))


def shift(tbl, col, new, base):
    i = tbl.column_names.index(col)
    return tbl.set_column(i, new, pc.add(tbl[col], base))


STRCOLS = {"symbol", "kind", "aggressor", "cross_type", "direction", "pvi", "side", "auction_type", "imb_side", "action"}
NAMES = (["ts_recv_ns", "ts_itch_ns", "ts_event_ns", "flags", "symbol", "bid_px", "bid_sz", "ask_px", "ask_sz", "price", "size",
          "kind", "aggressor", "match_no", "cross_type", "paired", "imbalance", "direction", "far_px", "near_px", "ref_px", "pvi",
          "num_orders", "rpt_seq", "action", "side", "trade_id", "sale_flags", "auction_type", "ind_clear_px", "imb_side",
          "extension", "sched_time", "book_clear_px", "collar_ref", "lower_collar", "upper_collar"]
         + [f"{s}_{k}_{i:02d}" for i in range(10) for s in ("bid", "ask") for k in ("px", "sz", "ct")])
CONV = pacsv.ConvertOptions(strings_can_be_null=True, column_types={
    n: pa.string() if n in STRCOLS else pa.float64() if ("px" in n or n in ("price", "collar_ref", "lower_collar", "upper_collar"))
    else pa.int64() for n in NAMES})


class Sink(threading.Thread):
    """Reads one parser output through a named pipe (no CSV on disk). on_batch may transform/stream each
    record batch and return what to keep in memory (or None)."""
    def __init__(self, path, on_batch=None):
        super().__init__(daemon=True)
        self.path, self.on_batch, self.batches, self.err = path, on_batch, [], None
        if os.path.exists(path):
            os.remove(path)
        os.mkfifo(path)
        self.start()

    def run(self):
        f = open(self.path, "rb", buffering=1 << 20)
        try:
            for b in pacsv.open_csv(pa.PythonFile(f, mode="r"), read_options=pacsv.ReadOptions(block_size=1 << 25),
                                    convert_options=CONV):
                b = self.on_batch(b) if self.on_batch else b
                if b is not None and b.num_rows:
                    self.batches.append(b)
        except Exception as e:                       # empty output or parse error: keep draining so the writer never blocks
            self.err = e
            while f.read(1 << 20):
                pass
        finally:
            f.close()

    def finish(self):
        for _ in range(40):                          # parser exited without opening this pipe: unblock our open()
            if not self.is_alive():
                break
            try:
                os.close(os.open(self.path, os.O_WRONLY | os.O_NONBLOCK))
            except OSError:
                pass
            self.join(0.25)
        self.join()
        os.remove(self.path)
        return pa.Table.from_batches(self.batches) if self.batches else None


class StreamParquet:
    """Writes record batches to one Parquet file as they arrive (for the big tables: CME depth, IEX levels)."""
    def __init__(self, path):
        self.path, self.w, self.rows = path, None, 0

    def add(self, b):
        if b.num_rows:
            if self.w is None:
                self.w = pq.ParquetWriter(self.path, b.schema, compression="zstd", compression_level=9)
            self.w.write_batch(b); self.rows += b.num_rows

    def close(self):
        if self.w is not None:
            self.w.close()


def bwin(b, col, t0, t1, shift_from=None, base=0):
    t = pa.Table.from_batches([b])
    if shift_from:
        t = shift(t, shift_from, col, base)
    return in_win(t, col, t0, t1).combine_chunks()


def do_nq_night(day, a, raw):
    """NQ only, overnight: 20:00 ET the previous evening -> 04:00 ET on `day`. The CME session opens at 18:00 ET, so
    files are read from 18:00 (book built from the session start) but only 20:00-04:00 is written.
    Output: nq_night_<day>.parquet (L1 quotes + trades, same columns as ticks) and nq_night_depth_<day>.parquet."""
    tag = day.strftime("%Y%m%d"); prev = day - timedelta(days=1)
    w0, t0, t1 = et_ns(prev, "18:00"), et_ns(prev, "20:00"), et_ns(day, "04:00")
    cme = select_files(a.glbx_root, day, w0, t1)
    print(f"{tag}: night glbx {len(cme)} files {sum(map(os.path.getsize, cme))/1e9:.1f} GB, NQ {nq_for(tag)}", flush=True)
    if a.dry_run:
        return None
    if not cme:
        print(f"INCOMPLETE {tag} | glbx-night | missing files", flush=True)
        return None
    gb = os.path.join(raw, f"glbx_{tag}")
    out = lambda n: os.path.join(a.out_dir, f"{n}_{tag}.parquet")
    log = os.path.join(a.out_dir, f"log_{tag}.txt")
    cme_bin = next(os.path.join(HERE, b) for b in ("mdp3_fast3", "mdp3_fast2", "mdp3_fast") if os.access(os.path.join(HERE, b), os.X_OK))
    depth_w = StreamParquet(out("nq_night_depth"))

    def cme_bbo(b):
        t = bwin(b, "ts_event_ns", t0, t1)
        if t.num_rows:
            depth_w.add(t.select(["ts_recv_ns", "ts_event_ns", "flags"] + [c for c in t.column_names if c[-2:].isdigit() and c[-2:] != "00"]).to_batches()[0])
            t = t.select(["ts_recv_ns", "ts_event_ns", "symbol", "bid_px_00", "bid_sz_00", "ask_px_00", "ask_sz_00"]) \
                 .rename_columns(["ts_recv_ns", "ts_event_ns", "symbol", "bid_px", "bid_sz", "ask_px", "ask_sz"])
        return t.to_batches()[0] if t.num_rows else None

    sinks = {"gq": Sink(gb + "_bbo.csv", cme_bbo),
             "gt": Sink(gb + "_trades.csv", lambda b: (lambda t: t.to_batches()[0] if t.num_rows else None)(bwin(b, "ts_event_ns", t0, t1)))}
    lf = open(log, "a")
    p = subprocess.Popen([sys.executable, os.path.join(HERE, "fast_feed.py"), cme_bin, "--secids", ",".join([nq_for(tag)] + ([a.extra_secids] if a.extra_secids else [])), "--display-factor", "0.01",
                          "--depth", str(DEPTH), "--out", gb] + (["--port", str(a.cme_port)] if a.cme_port else []) + ["--"] + cme,
                         stdout=lf, stderr=subprocess.STDOUT)
    while p.poll() is None:
        if free_gb(a.out_dir) < a.min_free_gb:
            p.kill(); raise SystemExit(f"{tag}: free disk below {a.min_free_gb} GB - stopped")
        time.sleep(5)
    T = {k: s.finish() for k, s in sinks.items()}
    depth_w.close()
    if p.returncode or T["gq"] is None:
        print(f"INCOMPLETE {tag} | glbx-night | {'parser exit ' + str(p.returncode) if p.returncode else 'no rows'} (see {log})", flush=True)
        return None
    parts = [conform(T["gq"], {"venue": "GLBX", "type": "Q"})]
    if T["gt"] is not None:
        parts.append(conform(T["gt"].rename_columns(["trade_id" if c == "rpt_seq" else c for c in T["gt"].column_names]), {"venue": "GLBX", "type": "T"}))
    nt = pa.concat_tables(parts); nt = nt.take(pc.sort_indices(nt, [("ts_event_ns", "ascending")]))
    write(nt, out("nq_night"))
    print(f"{tag}: night NQ quotes {T['gq'].num_rows}, trades {0 if T['gt'] is None else T['gt'].num_rows}; "
          f"{(os.path.getsize(out('nq_night')) + os.path.getsize(out('nq_night_depth'))) / 1e6:.0f} MB", flush=True)
    return 1


def do_day(day, a, raw):
    tag = day.strftime("%Y%m%d")
    t0, t1, mid = et_ns(day, a.start), et_ns(day, a.end), et_ns(day, "00:00")
    itch = select_files(a.xnas_root, day, t0, t1)
    cme = select_files(a.glbx_root, day, t0, t1)
    iex = sorted(glob.glob(a.iex_glob.format(date=tag))) if a.iex_glob else []
    print(f"{tag}: xnas {len(itch)} files {sum(map(os.path.getsize, itch))/1e9:.1f} GB, glbx {len(cme)} files "
          f"{sum(map(os.path.getsize, cme))/1e9:.1f} GB, iex {len(iex)} files "
          f"{sum(map(os.path.getsize, iex))/1e9:.1f} GB, NQ {nq_for(tag)}", flush=True)
    if a.dry_run:
        return None
    if not itch or not cme:
        print(f"INCOMPLETE {tag} | {'xnas' if not itch else 'glbx'} | missing files", flush=True)
        return None
    xb, gb, ib = (os.path.join(raw, f"{v}_{tag}") for v in ("xnas", "glbx", "iex"))
    out = lambda n: os.path.join(a.out_dir, f"{n}_{tag}.parquet")
    log = os.path.join(a.out_dir, f"log_{tag}.txt")
    feed = os.path.join(HERE, "fast_feed.py")
    cme_bin = next(os.path.join(HERE, b) for b in ("mdp3_fast3", "mdp3_fast2", "mdp3_fast") if os.access(os.path.join(HERE, b), os.X_OK))
    depth_w, lev_w = StreamParquet(out("cme_depth")), StreamParquet(out("iex_levels"))

    def cme_bbo(b):                                  # stream levels 2-10 to disk, keep L1 in memory
        t = bwin(b, "ts_event_ns", t0, t1)
        if t.num_rows:
            depth_w.add(t.select(["ts_recv_ns", "ts_event_ns", "flags"] + [c for c in t.column_names if c[-2:].isdigit() and c[-2:] != "00"]).to_batches()[0])
            t = t.select(["ts_recv_ns", "ts_event_ns", "symbol", "bid_px_00", "bid_sz_00", "ask_px_00", "ask_sz_00"]) \
                 .rename_columns(["ts_recv_ns", "ts_event_ns", "symbol", "bid_px", "bid_sz", "ask_px", "ask_sz"])
        return t.to_batches()[0] if t.num_rows else None

    def xw(b):                                       # ITCH time = ns since New York midnight
        t = bwin(b, "ts_event_ns", t0, t1, "ts_itch_ns", mid)
        return t.to_batches()[0] if t.num_rows else None

    def xtr(b):                                      # keep cross prints (kind Q) whatever their time
        t = shift(pa.Table.from_batches([b]), "ts_itch_ns", "ts_event_ns", mid)
        t = t.filter(pc.or_(pc.equal(t["kind"], "Q"), pc.and_(pc.greater_equal(t["ts_event_ns"], t0), pc.less(t["ts_event_ns"], t1))))
        t = t.combine_chunks()
        return t.to_batches()[0] if t.num_rows else None

    sinks = {"xq": Sink(xb + "_bbo.csv", xw), "xt": Sink(xb + "_trades.csv", xtr), "xn": Sink(xb + "_noii.csv", xw),
             "gq": Sink(gb + "_bbo.csv", cme_bbo), "gt": Sink(gb + "_trades.csv", lambda b: (lambda t: t.to_batches()[0] if t.num_rows else None)(bwin(b, "ts_event_ns", t0, t1)))}
    if iex:
        sinks.update({"iq": Sink(ib + "_bbo.csv"), "it": Sink(ib + "_trades.csv"), "ia": Sink(ib + "_auction.csv"),
                      "il": Sink(ib + "_levels.csv", lambda b: lev_w.add(b))})
    lf = open(log, "a")
    procs = {"xnas": subprocess.Popen([sys.executable, feed, os.path.join(HERE, "itch_noii"), "--symbols", SYMS, "--out", xb, "--"] + itch, stdout=lf, stderr=subprocess.STDOUT),
             "glbx": subprocess.Popen([sys.executable, feed, cme_bin, "--secids", ",".join([nq_for(tag)] + ([a.extra_secids] if a.extra_secids else [])), "--display-factor", "0.01", "--depth", str(DEPTH), "--threads", str(a.cme_threads),
                                       "--out", gb] + (["--port", str(a.cme_port)] if a.cme_port else []) + ["--"] + cme, stdout=lf, stderr=subprocess.STDOUT)}
    if iex:
        procs["iex"] = subprocess.Popen([sys.executable, os.path.join(HERE, "iex_parse.py"), "--symbols", SYMS, "--out", ib,
                                         "--start-ns", str(t0), "--end-ns", str(t1)] + iex, stdout=lf, stderr=subprocess.STDOUT)
    while any(p.poll() is None for p in procs.values()):
        if free_gb(a.out_dir) < a.min_free_gb:
            for p in procs.values(): p.kill()
            raise SystemExit(f"{tag}: free disk below {a.min_free_gb} GB - stopped")
        time.sleep(5)
    T = {k: s.finish() for k, s in sinks.items()}
    depth_w.close(); lev_w.close()
    bad = [k for k, p in procs.items() if p.returncode]
    for k in bad:
        print(f"INCOMPLETE {tag} | {k} | parser exit {procs[k].returncode} (see {log})", flush=True)
    if "xnas" in bad or "glbx" in bad or T["xq"] is None or T["gq"] is None:
        if not bad:
            print(f"INCOMPLETE {tag} | xnas/glbx | no rows parsed (see {log})", flush=True)
        return None

    parts = [conform(T["xq"], {"venue": "XNAS", "type": "Q"})]
    t = T["xt"]
    isq = pc.equal(t["kind"], "Q")
    cr = t.filter(isq)
    t = t.filter(pc.invert(isq)).rename_columns(["trade_id" if c == "match_no" else c for c in t.column_names])
    parts.append(conform(t, {"venue": "XNAS", "type": "T"}))
    write(cr.select(["ts_recv_ns", "ts_event_ns", "symbol", "price", "size", "cross_type", "match_no"]), out("crosses"))
    n = T["xn"] if T["xn"] is not None else pa.table({"ts_event_ns": pa.array([], pa.int64())})
    write(n, out("noii"))
    parts.append(conform(T["gq"], {"venue": "GLBX", "type": "Q"}))
    if T["gt"] is not None:
        parts.append(conform(T["gt"].rename_columns(["trade_id" if c == "rpt_seq" else c for c in T["gt"].column_names]), {"venue": "GLBX", "type": "T"}))
    if iex and "iex" not in bad:
        if T["iq"] is not None:
            parts.append(conform(T["iq"], {"venue": "IEXG", "type": "Q"}))
        if T["it"] is not None:
            it = T["it"]
            parts.append(conform(it.set_column(it.column_names.index("sale_flags"), "kind", pc.cast(it["sale_flags"], pa.string())), {"venue": "IEXG", "type": "T"}))
        if T["ia"] is not None:
            write(T["ia"], out("iex_auction"))
    ticks = pa.concat_tables(parts)
    ticks = ticks.take(pc.sort_indices(ticks, [("ts_event_ns", "ascending")]))
    write(ticks, out("ticks"))

    cnt = {f"{v}/{ty}": int(pc.sum(pc.and_(pc.equal(ticks["venue"], v), pc.equal(ticks["type"], ty))).as_py() or 0)
           for v in ("XNAS", "GLBX", "IEXG") for ty in "QT"}
    hidden = int(pc.sum(pc.equal(t["kind"], "P")).as_py() or 0)
    ccs = set(cr.filter(pc.equal(cr["cross_type"], "C"))["symbol"].to_pylist())
    miss = [s for s in STOCKS.split(",") + INDEX.split(",") if s not in ccs]
    mb = sum(os.path.getsize(out(x)) for x in ("ticks", "cme_depth", "noii", "crosses")) / 1e6
    print(f"{tag}: {cnt}; hidden execs {hidden}; noii {n.num_rows}; cross prints {cr.num_rows}; "
          f"closing cross {len(ccs)} syms; {mb:.0f} MB", flush=True)
    if miss:
        print(f"INCOMPLETE {tag} | xnas | closing cross missing for {','.join(miss)}", flush=True)
    return 1


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--from", dest="d0", required=True)
    ap.add_argument("--to", dest="d1", required=True)
    ap.add_argument("--start", default="04:00", help="ET, default 04:00 (pre-market)")
    ap.add_argument("--end", default="20:00", help="ET, default 20:00 (end of after-hours)")
    ap.add_argument("--xnas-root", default="/db_pcaps/xnas_pcaps")
    ap.add_argument("--glbx-root", default="/db_pcaps/glbx_pcaps")
    ap.add_argument("--iex-glob", default="", help="IEX capture files per day, with {date}=YYYYMMDD, e.g. '/x/{date}/*.pcap*'")
    ap.add_argument("--out-dir", default=os.path.expanduser("~/myproject/pull_out"))
    ap.add_argument("--min-free-gb", type=float, default=5.0)
    ap.add_argument("--cme-port", type=int, default=0, help="UDP port of NQ's CME channel: skip all other channels before decoding")
    ap.add_argument("--extra-secids", default="", help="more CME contracts on the same channel, e.g. MNQM5=123,ESM5=456 (label=SecurityID)")
    ap.add_argument("--cme-threads", type=int, default=16)
    ap.add_argument("--nq-night", action="store_true", help="NQ only, 20:00 ET previous evening -> 04:00 ET (book built from 18:00)")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    if not a.dry_run and not a.nq_night and not os.access(os.path.join(HERE, "itch_noii"), os.X_OK):
        raise SystemExit("build first: g++ -O3 -std=c++17 -o itch_noii itch_noii.cpp")
    os.makedirs(a.out_dir, exist_ok=True)
    raw = os.path.join(a.out_dir, "raw"); os.makedirs(raw, exist_ok=True)
    print(f"free disk {free_gb(a.out_dir):.1f} GB (stop below {a.min_free_gb}); window {a.start}-{a.end} ET")
    T0, ok, tot = time.time(), 0, 0
    for day in daterange(a.d0, a.d1):
        if day.weekday() >= 5:
            continue
        tot += 1
        if free_gb(a.out_dir) < a.min_free_gb:
            raise SystemExit(f"free disk below {a.min_free_gb} GB - stopped before {day:%Y%m%d}")
        try:
            ok += bool((do_nq_night if a.nq_night else do_day)(day, a, raw))
        except Exception as e:                       # keep going; report the day as incomplete
            print(f"INCOMPLETE {day:%Y%m%d} | all | {type(e).__name__}: {e}", flush=True)
    shutil.rmtree(raw, ignore_errors=True)
    print(f"done: {ok}/{tot} days in {time.time() - T0:.0f}s; free disk {free_gb(a.out_dir):.1f} GB")


if __name__ == "__main__":
    main()
