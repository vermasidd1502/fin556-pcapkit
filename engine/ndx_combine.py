#!/usr/bin/env python3
"""
ndx_combine.py - one file per trading day with NQ futures (CME) + QQQ/TQQQ/SQQQ (Nasdaq) on ONE nanosecond clock.

For every trading date in --from..--to it
  1. finds that date's files in  <xnas-root>/<YYYYMMDD>/  and  <glbx-root>/<YYYYMMDD>/  (plus the neighbouring UTC date
     folders when the window crosses midnight UTC) and keeps only the 10-minute files that cover the window,
  2. runs itch_zst_parse.py (QQQ,TQQQ,SQQQ) and mdp3_parse.py (NQ only) on them - both at the same time,
  3. merges the results:
        <out>/ndx_long_<date>.parquet   LONG : one row per update, all symbols mixed, sorted by exchange time (ns)
        <out>/ndx_wide_<date>.parquet   WIDE : one row per time step, columns side by side per symbol (last known value)

Dates are ET trading dates (so 20250203 = Monday 3 Feb 2025). Weekends and dates without both folders are skipped.
Window default 09:30-16:00 ET.  Nothing in this script touches the network.

Examples (run from the folder that holds this file and the two parsers):
  python3 ndx_combine.py --from 20250203 --to 20250203 --dry-run          # list what would be read, parse nothing
  python3 ndx_combine.py --from 20250203 --to 20250203                    # one day
  python3 ndx_combine.py --from 20250202 --to 20250205                    # the 5-day test (Sun is skipped)
  python3 ndx_combine.py --from 20250203 --to 20250203 --merge-only       # redo only the merge (raw parse already done)
  python3 ndx_combine.py --from 20250203 --to 20250203 --grid-ms 1        # finer WIDE grid (bigger file)
"""
import argparse
import glob
import os
import re
import subprocess
import sys
import time
from datetime import date, datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

ET = ZoneInfo("America/New_York")
HERE = os.path.dirname(os.path.abspath(__file__))
FN = re.compile(r"(\d{8})T(\d{6})")
NS = 1_000_000_000
LONG_COLS = ["ts_event_ns", "ts_recv_ns", "source", "symbol", "kind", "bid_px", "bid_sz", "ask_px", "ask_sz",
             "price", "size", "aggressor", "trade_type", "trade_id"]


# --------------------------------------------------------------------------- time + file selection
def et_ns(d, hhmm):
    h, m = (int(x) for x in hhmm.split(":"))
    return int(datetime(d.year, d.month, d.day, h, m, tzinfo=ET).timestamp()) * NS


def select_files(root, day, t0, t1):
    """10-minute files (named by UTC start time) that overlap [t0, t1) in epoch ns, oldest first."""
    out = []
    for dd in (day - timedelta(days=1), day, day + timedelta(days=1)):
        for p in glob.glob(os.path.join(root, dd.strftime("%Y%m%d"), "*.pcap.zst")):
            m = FN.search(os.path.basename(p))
            if not m:
                continue
            s = int(datetime.strptime(m.group(1) + m.group(2), "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc).timestamp()) * NS
            if s + 600 * NS > t0 and s < t1:
                out.append((s, p))
    return [p for _, p in sorted(out)]


def daterange(a, b):
    d = datetime.strptime(a, "%Y%m%d").date()
    z = datetime.strptime(b, "%Y%m%d").date()
    while d <= z:
        yield d
        d += timedelta(days=1)


# --------------------------------------------------------------------------- parse step (the two existing parsers)
def raw_paths(rawdir, tag):
    """base path (no extension) of each raw output; the parsers write .parquet, the C++ ones write .csv"""
    return {(src, t): os.path.join(rawdir, f"{src}_{tag}_{t}") for src in ("xnas", "glbx") for t in ("bbo", "trades")}


def raw_exists(base):
    return os.path.exists(base + ".parquet") or os.path.exists(base + ".csv")


def fast_bin(name):
    p = os.path.join(HERE, name)
    return p if os.path.isfile(p) and os.access(p, os.X_OK) else None


def run_parsers(tag, itch_files, cme_files, args, rawdir):
    os.makedirs(rawdir, exist_ok=True)
    feed = os.path.join(HERE, "fast_feed.py")
    # prefer v3 (many threads), then v2 (3 threads), then v1
    itch_bin = (fast_bin("itch_fast3") or fast_bin("itch_fast2") or fast_bin("itch_fast")) if args.fast != "off" else None
    cme_bin = (fast_bin("mdp3_fast3") or fast_bin("mdp3_fast2") or fast_bin("mdp3_fast")) if args.fast != "off" else None
    if args.fast == "on" and not (itch_bin and cme_bin):
        raise SystemExit("--fast on but itch_fast / mdp3_fast are not compiled in " + HERE +
                         "  (g++ -O3 -std=c++17 -o itch_fast itch_fast.cpp ; g++ -O3 -std=c++17 -o mdp3_fast mdp3_fast.cpp)")
    xbase, gbase = os.path.join(rawdir, f"xnas_{tag}"), os.path.join(rawdir, f"glbx_{tag}")
    if itch_bin:
        c1 = [sys.executable, feed, itch_bin, "--symbols", args.etf, "--out", xbase, "--"] + itch_files
    else:
        c1 = [sys.executable, os.path.join(HERE, "itch_zst_parse.py"), "--symbols", args.etf, "--format", "parquet",
              "--out-dir", rawdir, "--name", f"xnas_{tag}"] + itch_files
    if cme_bin:
        c2 = [sys.executable, feed, cme_bin, "--secids", args.nq_secids, "--display-factor", str(args.display_factor),
              "--depth", "1", "--out", gbase, "--"] + cme_files
    else:
        c2 = [sys.executable, os.path.join(HERE, "mdp3_parse.py"), "--secids", args.nq_secids, "--display-factor",
              str(args.display_factor), "--depth", "1", "--format", "parquet", "--out-dir", rawdir, "--name", f"glbx_{tag}"] + cme_files
    print(f"{tag}: Nasdaq side: {'C++ (itch_fast)' if itch_bin else 'Python'};  CME side: {'C++ (mdp3_fast)' if cme_bin else 'Python'}", flush=True)
    for script, flag in (("mdp3_parse.py", "--display-factor"), ("itch_zst_parse.py", "--symbols")):
        h = subprocess.run([sys.executable, os.path.join(HERE, script), "--help"], capture_output=True, text=True).stdout
        if flag not in h:
            raise SystemExit(f"{script} in {HERE} is an old version (no {flag}). Copy the newest {script} over it and run again.")
    procs = [subprocess.Popen(c) for c in (c1, c2)]  # both feeds in parallel; their progress lines print to this screen
    try:
        while True:
            codes = [p.poll() for p in procs]
            if any(c not in (None, 0) for c in codes):  # one failed: stop the other instead of letting it run for hours
                break
            if all(c == 0 for c in codes):
                break
            time.sleep(2)
    except KeyboardInterrupt:
        for p in procs:
            p.terminate()
        raise SystemExit("stopped")
    if any(c not in (None, 0) for c in codes):
        for p in procs:
            if p.poll() is None:
                p.terminate()
        raise SystemExit(f"a parser failed (exit codes {codes}) - see the messages above")


# --------------------------------------------------------------------------- merge step
def load(base):
    if os.path.exists(base + ".parquet"):
        return pd.read_parquet(base + ".parquet")
    if os.path.exists(base + ".csv"):  # written by the C++ parsers
        import pyarrow.csv as pacsv
        strs = {c: pa.string() for c in ("symbol", "kind", "aggressor", "cross_type")}
        return pacsv.read_csv(base + ".csv", convert_options=pacsv.ConvertOptions(column_types=strs)).to_pandas()
    return pd.DataFrame()


def unified(raw, midnight_ns):
    xb, xt, gb, gt = (load(raw[k]) for k in (("xnas", "bbo"), ("xnas", "trades"), ("glbx", "bbo"), ("glbx", "trades")))
    parts = []
    if len(xb):
        d = xb[["ts_recv_ns", "symbol", "bid_px", "bid_sz", "ask_px", "ask_sz"]].copy()
        d["ts_event_ns"] = xb["ts_itch_ns"] + midnight_ns  # ITCH time = ns since midnight ET
        d["source"], d["kind"] = "xnas", "bbo"
        parts.append(d)
    if len(xt):
        d = xt[["ts_recv_ns", "symbol", "price", "size", "aggressor"]].copy()
        d["ts_event_ns"] = xt["ts_itch_ns"] + midnight_ns
        d["trade_type"], d["trade_id"] = xt["kind"], xt["match_no"]
        d["source"], d["kind"] = "xnas", "trade"
        parts.append(d)
    if len(gb):
        d = gb[["ts_recv_ns", "ts_event_ns", "symbol"]].copy()
        for a, b in (("bid_px", "bid_px_00"), ("bid_sz", "bid_sz_00"), ("ask_px", "ask_px_00"), ("ask_sz", "ask_sz_00")):
            d[a] = gb[b]  # CME event time is already UTC epoch ns
        d["source"], d["kind"] = "glbx", "bbo"
        parts.append(d)
    if len(gt):
        d = gt[["ts_recv_ns", "ts_event_ns", "symbol", "price", "size", "aggressor"]].copy()
        d["trade_type"], d["trade_id"] = gt["action"].astype(str), gt["rpt_seq"]
        d["source"], d["kind"] = "glbx", "trade"
        parts.append(d)
    if not parts:
        return pd.DataFrame(columns=LONG_COLS)
    df = pd.concat(parts, ignore_index=True).reindex(columns=LONG_COLS)
    for c in ("ts_event_ns", "ts_recv_ns"):
        df[c] = df[c].astype("int64")
    for c in ("bid_sz", "ask_sz", "size", "trade_id"):
        df[c] = df[c].astype("Int64")
    return df.sort_values(["ts_event_ns", "ts_recv_ns"], kind="stable").reset_index(drop=True)


def add_et(df, col="ts_event_ns"):
    df.insert(1, "time_et", pd.to_datetime(df[col], unit="ns", utc=True).dt.tz_convert("America/New_York"))
    return df


def make_long(df, start_ns, end_ns):
    """Window rows, plus one 'snapshot' row per symbol (its last quote before the window, stamped at the window start)."""
    pre = df[(df["kind"] == "bbo") & (df["ts_event_ns"] < start_ns)]
    snap = pre.groupby("symbol").tail(1).copy()
    snap["kind"], snap["ts_event_ns"] = "snapshot", start_ns
    win = df[(df["ts_event_ns"] >= start_ns) & (df["ts_event_ns"] <= end_ns)]
    out = pd.concat([snap, win], ignore_index=True).sort_values(["ts_event_ns", "ts_recv_ns"], kind="stable")
    return add_et(out.reset_index(drop=True))


def make_wide(df, symbols, start_ns, end_ns, step_ns, path, chunk=1_000_000):
    """One row per grid time T = start+step, start+2*step ... <= end.
       *_bid_px/_bid_sz/_ask_px/_ask_sz : last quote at or before T      (NaN until the first quote of the day)
       *_last_px                        : last trade price at or before T
       *_vol, *_trades                  : shares/contracts and number of trades in (T-step, T]"""
    n = (end_ns - start_ns) // step_ns
    data = {}
    for s in symbols:
        q = df[(df["symbol"] == s) & (df["kind"] == "bbo")].sort_values("ts_event_ns", kind="stable")
        t = df[(df["symbol"] == s) & (df["kind"] == "trade")].sort_values("ts_event_ns", kind="stable")
        f = lambda c: q[c].to_numpy(dtype="float64", na_value=np.nan)
        data[s] = dict(qts=q["ts_event_ns"].to_numpy(), bid_px=f("bid_px"), bid_sz=f("bid_sz"), ask_px=f("ask_px"),
                       ask_sz=f("ask_sz"), tts=t["ts_event_ns"].to_numpy(),
                       tpx=t["price"].to_numpy(dtype="float64", na_value=np.nan),
                       cum=np.concatenate([[0.0], np.cumsum(t["size"].to_numpy(dtype="float64", na_value=0.0))]))
    writer = None
    for k0 in range(0, n, chunk):
        k1 = min(n, k0 + chunk)
        T = start_ns + step_ns * np.arange(k0 + 1, k1 + 1, dtype=np.int64)
        cols = {"ts_ns": T, "time_et": pd.to_datetime(T, unit="ns", utc=True).tz_convert("America/New_York")}
        for s, d in data.items():
            qi = np.searchsorted(d["qts"], T, side="right") - 1
            ok = qi >= 0
            for c in ("bid_px", "bid_sz", "ask_px", "ask_sz"):
                a = np.full(len(T), np.nan)
                a[ok] = d[c][qi[ok]]
                cols[f"{s}_{c}"] = a
            j1 = np.searchsorted(d["tts"], T, side="right")
            j0 = np.searchsorted(d["tts"], T - step_ns, side="right")
            last = np.full(len(T), np.nan)
            has = j1 > 0
            last[has] = d["tpx"][j1[has] - 1]
            cols[f"{s}_last_px"] = last
            cols[f"{s}_vol"] = d["cum"][j1] - d["cum"][j0]
            cols[f"{s}_trades"] = (j1 - j0).astype("int64")
        tbl = pa.Table.from_pandas(pd.DataFrame(cols), preserve_index=False)
        if writer is None:
            writer = pq.ParquetWriter(path, tbl.schema, compression="zstd")
        writer.write_table(tbl)
    if writer is None:  # empty window
        writer = pq.ParquetWriter(path, pa.schema([("ts_ns", pa.int64())]))
    writer.close()
    return n


def checks(df, symbols):
    L = []
    for s in symbols:
        q = df[(df["symbol"] == s) & (df["kind"] == "bbo")]
        t = df[(df["symbol"] == s) & (df["kind"] == "trade")]
        both = q.dropna(subset=["bid_px", "ask_px"])
        both = both[(both["bid_px"] > 0) & (both["ask_px"] > 0)]
        crossed = int((both["bid_px"] > both["ask_px"]).sum())
        L.append(f"    {s:<7} quotes {len(q):>10,}  trades {len(t):>9,}  crossed quotes {crossed:,}"
                 + (f"  price {both['bid_px'].median():,.2f}" if len(both) else "  (no two-sided quotes!)"))
    return L


# --------------------------------------------------------------------------- driver
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--from", dest="d0", required=True, help="first ET trading date, YYYYMMDD")
    ap.add_argument("--to", dest="d1", required=True, help="last ET trading date, YYYYMMDD (inclusive)")
    ap.add_argument("--start", default="09:30", help="window start, ET (default 09:30)")
    ap.add_argument("--end", default="16:00", help="window end, ET (default 16:00)")
    ap.add_argument("--xnas-root", default="/db_pcaps/xnas_pcaps")
    ap.add_argument("--glbx-root", default="/db_pcaps/glbx_pcaps")
    ap.add_argument("--etf", default="QQQ,TQQQ,SQQQ", help="Nasdaq symbols to keep")
    ap.add_argument("--nq-secids", default="NQH5=42288528",
                    help="NQ symbol=SecurityID (the captures carry no definitions; find the id with mdp3_parse.py --discover; "
                         "it changes at the quarterly roll)")
    ap.add_argument("--display-factor", type=float, default=0.01, help="CME prices are sent 100x too large; 0.01 fixes that")
    ap.add_argument("--itch-from", default="04:00", help="ET time to start reading Nasdaq files so the order book is complete")
    ap.add_argument("--nq-warmup-min", type=int, default=30, help="minutes of NQ before --start used to build the book")
    ap.add_argument("--fast", choices=["auto", "on", "off"], default="auto",
                    help="use the compiled C++ parsers itch_fast / mdp3_fast when they exist next to this script (default auto)")
    ap.add_argument("--layout", choices=["both", "long", "wide"], default="both")
    ap.add_argument("--grid-ms", type=float, default=100.0, help="WIDE time step in milliseconds (default 100; 1 = very large)")
    ap.add_argument("--out-dir", default="out")
    ap.add_argument("--merge-only", action="store_true", help="skip parsing, reuse out/raw")
    ap.add_argument("--force", action="store_true", help="parse again even if out/raw already has the day")
    ap.add_argument("--dry-run", action="store_true", help="only list the files that would be read")
    args = ap.parse_args()

    nq_syms = [x.split("=")[0].strip().upper() for x in args.nq_secids.split(",") if "=" in x]
    etf = [s.strip().upper() for s in args.etf.split(",") if s.strip()]
    symbols = nq_syms + etf
    step_ns = int(round(args.grid_ms * 1e6))
    rawdir = os.path.join(args.out_dir, "raw")
    os.makedirs(args.out_dir, exist_ok=True)
    T0 = time.time()
    done = []
    for day in daterange(args.d0, args.d1):
        tag = day.strftime("%Y%m%d")
        if day.weekday() >= 5:
            print(f"{tag}: weekend - skipped")
            continue
        start_ns, end_ns = et_ns(day, args.start), et_ns(day, args.end)
        itch_files = select_files(args.xnas_root, day, et_ns(day, args.itch_from), end_ns)
        cme_files = select_files(args.glbx_root, day, start_ns - args.nq_warmup_min * 60 * NS, end_ns)
        print(f"{tag}: {len(itch_files)} xnas files, {len(cme_files)} glbx files")
        if not args.merge_only and (not itch_files or not cme_files):
            print(f"{tag}: missing folder/files for one of the feeds - skipped")
            continue
        if args.dry_run:
            for nm, fl in (("xnas", itch_files), ("glbx", cme_files)):
                if fl:
                    print(f"   {nm}: {os.path.basename(fl[0])} ... {os.path.basename(fl[-1])}")
            continue
        raw = raw_paths(rawdir, tag)
        if not args.merge_only and (args.force or not all(raw_exists(p) for p in raw.values())):
            t = time.time()
            print(f"{tag}: parsing (both feeds at once) ...", flush=True)
            run_parsers(tag, itch_files, cme_files, args, rawdir)
            print(f"{tag}: parsing took {(time.time() - t) / 60:.1f} min", flush=True)
        elif not args.merge_only:
            print(f"{tag}: raw files already exist - reusing (use --force to parse again)")
        t = time.time()
        df = unified(raw, et_ns(day, "00:00"))
        if df.empty:
            print(f"{tag}: nothing parsed - skipped")
            continue
        print(f"{tag}: merged {len(df):,} raw rows in {time.time() - t:.0f}s; checks:")
        print("\n".join(checks(df, symbols)))
        if args.layout in ("both", "long"):
            lg = make_long(df, start_ns, end_ns)
            p = os.path.join(args.out_dir, f"ndx_long_{tag}.parquet")
            lg.to_parquet(p, compression="zstd", index=False)
            print(f"{tag}: LONG  {len(lg):>12,} rows -> {p}")
        if args.layout in ("both", "wide"):
            p = os.path.join(args.out_dir, f"ndx_wide_{tag}.parquet")
            n = make_wide(df, symbols, start_ns, end_ns, step_ns, p)
            print(f"{tag}: WIDE  {n:>12,} rows ({args.grid_ms:g} ms grid) -> {p}")
        done.append(tag)
    print(f"finished {len(done)} day(s) in {(time.time() - T0) / 60:.1f} min")


if __name__ == "__main__":
    main()
