#!/usr/bin/env python3
"""make_bars.py - bars (and, with --ticks, every quote and trade) for many Nasdaq names + NQ, as pipe-separated text

Run on the VM from the ndx_parse_c folder (itch_fast built, letf_env switched on):
  python3 make_bars.py --date 20250402 --bar-min 5
  python3 make_bars.py --date 20250402 --bar-min 1 --start 18:00 --end 20:00 --ticks --symbols QQQ,TQQQ,...
Output (in out/):
  bars_<N>min_<date>[_HHMM-HHMM].txt  Date|Time|Symbol|Open|High|Low|Close|Volume|Trades|VWAP|Bid|Ask|Mid
  ticks_<date>_HHMM-HHMM.txt.gz       every quote change and trade inside the window (only with --ticks)
Times are New York time:  5-7 pm Chicago  =  --start 18:00 --end 20:00.
Disk: the parser's output streams through pipes; only per-minute summaries and the window's ticks are
written. NQ comes from the CME parse ndx_combine.py already made (out/raw/glbx_<date>_*.csv).
"""
import argparse
import glob
import os
import re
import subprocess
import sys
import threading
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
ET = ZoneInfo("America/New_York")
NS = 1_000_000_000
MINUTE = 60 * NS
FN = re.compile(r"(\d{8})T(\d{6})")
DEFAULT = ("QQQ,TQQQ,SQQQ,NVDA,NVDL,NVDU,TSLA,TSLL,TSLQ,MSTR,MSTX,"
           "COIN,CONL,AAPL,AAPU,AMZN,AMZU,META,METU,PLTR")


def et_ns(day, hhmm):
    h, m = map(int, hhmm.split(":"))
    return int(datetime(day.year, day.month, day.day, h, m, tzinfo=ET).timestamp()) * NS


def select_files(root, day, t0, t1):
    """10-minute capture files (named by UTC start) that overlap [t0, t1), oldest first."""
    out = []
    for dd in (day - timedelta(days=1), day, day + timedelta(days=1)):
        for p in glob.glob(os.path.join(root, dd.strftime("%Y%m%d"), "*.pcap.zst")):
            m = FN.search(os.path.basename(p))
            if m:
                s = int(datetime.strptime(m.group(1) + m.group(2), "%Y%m%d%H%M%S")
                        .replace(tzinfo=timezone.utc).timestamp()) * NS
                if s + 600 * NS > t0 and s < t1:
                    out.append((s, p))
    return [p for _, p in sorted(out)]


# ----------------------------------------------------------------------------- streaming the parser output
def stream_quotes(src, dst, win, w0, w1):
    """Every quote change in -> last quote per symbol per minute out (+ the window's quotes, if asked)."""
    last = {}
    with open(src) as f, open(dst, "w") as o:
        hdr = f.readline()
        o.write(hdr)
        wf = open(win, "w") if win else None
        if wf:
            wf.write(hdr)
        for line in f:
            p = line.split(",", 3)
            if len(p) < 4:
                continue
            ts = int(p[1])
            if wf and w0 <= ts < w1:
                wf.write(line)
            m = ts // MINUTE
            prev = last.get(p[2])
            if prev is not None and prev[0] != m:
                o.write(prev[1])
            last[p[2]] = (m, line)
        for _, line in last.values():
            o.write(line)
        if wf:
            wf.close()


def stream_trades(src, dst, win, w0, w1):
    """Every trade in -> per-symbol per-minute open/high/low/close/volume/count out (+ the window's trades)."""
    cur = {}
    with open(src) as f, open(dst, "w") as o:
        hdr = f.readline()
        o.write("symbol,minute,open,high,low,close,volume,trades,pv\n")
        wf = open(win, "w") if win else None
        if wf:
            wf.write(hdr)

        def flush(s, a):
            o.write(f"{s},{a[0]},{a[1]!r},{a[2]!r},{a[3]!r},{a[4]!r},{a[5]},{a[6]},{a[7]!r}\n")

        for line in f:
            p = line.split(",", 5)
            if len(p) < 6 or not p[3]:
                continue
            size = int(p[4])
            if size <= 0:
                continue
            ts = int(p[1])
            if wf and w0 <= ts < w1:
                wf.write(line)
            px, m, s = float(p[3]), ts // MINUTE, p[2]
            a = cur.get(s)
            if a is None or a[0] != m:
                if a is not None:
                    flush(s, a)
                cur[s] = [m, px, px, px, px, size, 1, px * size]
            else:
                if px > a[2]:
                    a[2] = px
                if px < a[3]:
                    a[3] = px
                a[4] = px
                a[5] += size
                a[6] += 1
                a[7] += px * size
        for s, a in cur.items():
            flush(s, a)
        if wf:
            wf.close()


def parse_nasdaq(args, day, base, files_out, ticks, w0, w1):
    # always read from 04:00 ET so every order book is complete
    if args.files:  # explicit list (one path per line), e.g. picked by pcapkit from its catalog
        files = [l.strip() for l in open(args.files) if l.strip()]
    else:
        files = select_files(args.xnas_root, day, et_ns(day, "04:00"), et_ns(day, "20:00"))
    if not files:
        sys.exit(f"no Nasdaq files found for {args.date} under {args.files or args.xnas_root}")
    exe = next((os.path.join(HERE, b) for b in ("itch_fast3", "itch_fast2", "itch_fast")
                if os.access(os.path.join(HERE, b), os.X_OK)), "")
    if not os.access(exe, os.X_OK):
        sys.exit("parsers are not built. Run:  ./build.sh")
    os.makedirs(os.path.dirname(base), exist_ok=True)
    q_pipe, t_pipe = base + "_bbo.csv", base + "_trades.csv"
    for p in [q_pipe, t_pipe] + list(files_out.values()):
        if os.path.lexists(p):
            os.remove(p)
    os.mkfifo(q_pipe)
    os.mkfifo(t_pipe)
    th = [threading.Thread(target=stream_quotes, daemon=True,
                           args=(q_pipe, files_out["q1m"], files_out.get("qwin") if ticks else None, w0, w1)),
          threading.Thread(target=stream_trades, daemon=True,
                           args=(t_pipe, files_out["t1m"], files_out.get("twin") if ticks else None, w0, w1))]
    for t in th:
        t.start()
    print(f"parsing {len(files)} Nasdaq files for {len(args.symbols.split(','))} symbols (takes ~1 hour) ...",
          flush=True)
    cmd = [sys.executable, os.path.join(HERE, "fast_feed.py"), exe,
           "--symbols", args.symbols, "--out", base, "--"] + files
    rc = subprocess.call(cmd)
    if rc == 0:
        for t in th:
            t.join(timeout=900)
    os.remove(q_pipe)
    os.remove(t_pipe)
    if rc != 0:
        for p in files_out.values():
            if os.path.exists(p):
                os.remove(p)
        sys.exit("Nasdaq parse failed - see messages above")
    with open(files_out["syms"], "w") as f:
        f.write(args.symbols)


# ----------------------------------------------------------------------------- bars
def trade_bars_min(path, bar_min):
    """bars from the per-minute trade summary (Nasdaq)"""
    t = pd.read_csv(path, dtype={"symbol": str}).sort_values(["symbol", "minute"], kind="stable")
    t["bar"] = t["minute"] // bar_min
    b = t.groupby(["symbol", "bar"], sort=False).agg(
        open=("open", "first"), high=("high", "max"), low=("low", "min"), close=("close", "last"),
        volume=("volume", "sum"), trades=("trades", "sum"), pv=("pv", "sum"))
    b["vwap"] = b["pv"] / b["volume"]
    return b.drop(columns="pv")


def trade_bars_raw(path, tcol, shift, bar_ns):
    """bars from every trade (CME raw file)"""
    t = pd.read_csv(path, usecols=[tcol, "symbol", "price", "size"], dtype={"symbol": str})
    t = t[(t["size"] > 0) & t["price"].notna()].copy()
    t["bar"] = (t[tcol] - shift) // bar_ns
    t["pv"] = t["price"] * t["size"]
    g = t.groupby(["symbol", "bar"], sort=False)
    b = g["price"].agg(["first", "max", "min", "last", "count"])
    b.columns = ["open", "high", "low", "close", "trades"]
    b["volume"] = g["size"].sum()
    b["vwap"] = g["pv"].sum() / b["volume"]
    return b


def quote_bars(path, tcol, bidc, askc, shift, bar_ns):
    parts = []
    for ch in pd.read_csv(path, usecols=[tcol, "symbol", bidc, askc], dtype={"symbol": str},
                          chunksize=5_000_000):
        ch["bar"] = (ch[tcol] - shift) // bar_ns
        parts.append(ch.groupby(["symbol", "bar"], sort=False)[[bidc, askc]].last())
    q = pd.concat(parts).groupby(level=[0, 1], sort=False).last()
    q.columns = ["bid", "ask"]
    return q


# ----------------------------------------------------------------------------- ticks
def build_ticks(args, fo, glbx, mid, w0, w1, path):
    """Every quote and trade in [w0, w1) (New York ns since midnight), plus each symbol's last quote before
    the window as type S, on one UTC-epoch nanosecond clock."""
    parts = []
    q = pd.read_csv(fo["qwin"], dtype={"symbol": str})
    pre = pd.read_csv(fo["q1m"], dtype={"symbol": str})
    pre = pre[pre["ts_itch_ns"] < w0].sort_values("ts_itch_ns", kind="stable").groupby("symbol").tail(1)
    for df, typ in ((pre, "S"), (q, "Q")):
        parts.append(pd.DataFrame({"ts_event_ns": df["ts_itch_ns"] + mid, "venue": "XNAS", "symbol": df["symbol"],
                                   "type": typ, "bid_px": df["bid_px"], "bid_sz": df["bid_sz"],
                                   "ask_px": df["ask_px"], "ask_sz": df["ask_sz"]}))
    t = pd.read_csv(fo["twin"], dtype={"symbol": str, "aggressor": str})
    parts.append(pd.DataFrame({"ts_event_ns": t["ts_itch_ns"] + mid, "venue": "XNAS", "symbol": t["symbol"],
                               "type": "T", "price": t["price"], "size": t["size"], "aggressor": t["aggressor"]}))
    if glbx:
        a0, a1 = w0 + mid, w1 + mid
        win, pre = [], []
        for ch in pd.read_csv(glbx + "_bbo.csv", dtype={"symbol": str}, chunksize=5_000_000,
                              usecols=["ts_event_ns", "symbol", "bid_px_00", "bid_sz_00", "ask_px_00", "ask_sz_00"]):
            win.append(ch[(ch["ts_event_ns"] >= a0) & (ch["ts_event_ns"] < a1)])
            pre.append(ch[ch["ts_event_ns"] < a0].groupby("symbol").tail(1))
        pre = pd.concat(pre).groupby("symbol").tail(1)
        for df, typ in ((pre, "S"), (pd.concat(win), "Q")):
            parts.append(pd.DataFrame({"ts_event_ns": df["ts_event_ns"], "venue": "GLBX", "symbol": df["symbol"],
                                       "type": typ, "bid_px": df["bid_px_00"], "bid_sz": df["bid_sz_00"],
                                       "ask_px": df["ask_px_00"], "ask_sz": df["ask_sz_00"]}))
        t = pd.read_csv(glbx + "_trades.csv", usecols=["ts_event_ns", "symbol", "price", "size", "aggressor"],
                        dtype={"symbol": str, "aggressor": str})
        t = t[(t["ts_event_ns"] >= a0) & (t["ts_event_ns"] < a1)]
        parts.append(pd.DataFrame({"ts_event_ns": t["ts_event_ns"], "venue": "GLBX", "symbol": t["symbol"],
                                   "type": "T", "price": t["price"], "size": t["size"],
                                   "aggressor": t["aggressor"]}))
    df = pd.concat(parts, ignore_index=True).sort_values(["ts_event_ns", "venue"], kind="stable")
    hms = pd.to_datetime(df["ts_event_ns"], unit="ns", utc=True).dt.tz_convert("America/New_York").dt.strftime("%H:%M:%S")
    df.insert(1, "time_et", hms + "." + (df["ts_event_ns"] % NS).astype(str).str.zfill(9))
    cols = ["ts_event_ns", "time_et", "venue", "symbol", "type", "bid_px", "bid_sz", "ask_px", "ask_sz",
            "price", "size", "aggressor"]
    df = df.reindex(columns=cols)
    for c in ("bid_sz", "ask_sz", "size"):
        df[c] = df[c].astype("Int64")
    df.to_csv(path, sep="|", index=False, compression="gzip")
    c = df.groupby(["symbol", "type"]).size().unstack(fill_value=0)
    print("ticks in the window (Q = quote changes, T = trades):")
    print(c.reindex(columns=["Q", "T"], fill_value=0).to_string())
    print(f"wrote {len(df):,} rows -> {path}")


# ----------------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--date", required=True, help="trading date YYYYMMDD")
    ap.add_argument("--bar-min", type=int, default=5, help="bar length in whole minutes (1, 5, 10, 60 ...)")
    ap.add_argument("--symbols", default=DEFAULT, help="comma-separated Nasdaq symbols")
    ap.add_argument("--start", default="04:00", help="window start, New York time")
    ap.add_argument("--end", default="20:00", help="window end, New York time")
    ap.add_argument("--ticks", action="store_true", help="also write every quote and trade in the window")
    ap.add_argument("--xnas-root", default="/db_pcaps/xnas_pcaps")
    ap.add_argument("--files", help="text file listing the Nasdaq capture files to read, in time order (overrides --xnas-root)")
    ap.add_argument("--out-dir", default="out")
    ap.add_argument("--no-nq", action="store_true", help="leave NQ out")
    ap.add_argument("--force", action="store_true", help="parse the Nasdaq files again")
    args = ap.parse_args()
    args.symbols = ",".join(dict.fromkeys(s.strip().upper() for s in args.symbols.split(",") if s.strip()))

    day = datetime.strptime(args.date, "%Y%m%d").date()
    mid = et_ns(day, "00:00")
    w0, w1 = et_ns(day, args.start) - mid, et_ns(day, args.end) - mid
    bar_ns = args.bar_min * MINUTE
    b0, b1 = w0 // bar_ns, -(-w1 // bar_ns)
    tag = args.start.replace(":", "") + "-" + args.end.replace(":", "")
    raw = os.path.join(args.out_dir, "raw")
    base = os.path.join(raw, f"xnas_bars_{args.date}")
    fo = {"q1m": base + "_q1m.csv", "t1m": base + "_t1m.csv", "syms": base + "_symbols.txt",
          "qwin": base + f"_qwin_{tag}.csv", "twin": base + f"_twin_{tag}.csv"}
    glbx = os.path.join(raw, f"glbx_{args.date}")
    if args.no_nq or not os.path.exists(glbx + "_trades.csv"):
        if not args.no_nq:
            print(f"note: no NQ parse found ({glbx}_trades.csv) - NQ left out")
        glbx = None

    same_syms = os.path.exists(fo["syms"]) and open(fo["syms"]).read().strip() == args.symbols
    need = (args.force or not same_syms or not os.path.exists(fo["q1m"]) or not os.path.exists(fo["t1m"])
            or (args.ticks and not os.path.exists(fo["qwin"])))
    if need:
        if not args.force and os.path.exists(fo["q1m"]):
            print("symbol list or tick window changed since the last parse - parsing again")
        parse_nasdaq(args, day, base, fo, args.ticks, w0, w1)
    else:
        print(f"reusing earlier parse in {raw}/ (same symbols)")

    print("building bars ...", flush=True)
    frames = [trade_bars_min(fo["t1m"], args.bar_min)
              .join(quote_bars(fo["q1m"], "ts_itch_ns", "bid_px", "ask_px", 0, bar_ns), how="outer")]
    order = args.symbols.split(",")
    if glbx:
        nq = trade_bars_raw(glbx + "_trades.csv", "ts_event_ns", mid, bar_ns).join(
            quote_bars(glbx + "_bbo.csv", "ts_event_ns", "bid_px_00", "ask_px_00", mid, bar_ns), how="outer")
        frames.append(nq)
        order = list(nq.index.get_level_values(0).unique()) + order
    allb = pd.concat(frames)
    have = set(allb.index.get_level_values(0))

    rows = []
    for s in order:
        if s not in have:
            print(f"WARNING: {s}: no data that day (wrong ticker, or not listed yet)")
            continue
        d = allb.loc[s].sort_index()
        d = d.reindex(range(min(int(d.index.min()), b0), b1))
        d[["bid", "ask"]] = d[["bid", "ask"]].ffill()          # quote carries over until it changes
        d = d.loc[b0:b1 - 1].copy()
        d["volume"] = d["volume"].fillna(0).astype("int64")
        d["trades"] = d["trades"].fillna(0).astype("int64")
        d["mid"] = (d["bid"] + d["ask"]) / 2
        mins = d.index.to_numpy() * args.bar_min
        d.insert(0, "Time", [f"{m // 60:02d}:{m % 60:02d}" for m in mins])
        d.insert(0, "Date", day.isoformat())
        d.insert(2, "Symbol", s)
        rows.append(d)
        traded = d[d["trades"] > 0]
        px = traded["close"].median() if len(traded) else float("nan")
        print(f"  {s:<6} {len(d):>4} bars, {len(traded):>4} with trades, volume {d['volume'].sum():>12,}, "
              f"median price {px:,.2f}")

    out = pd.concat(rows)[["Date", "Time", "Symbol", "open", "high", "low", "close", "volume",
                           "trades", "vwap", "bid", "ask", "mid"]]
    out.columns = ["Date", "Time", "Symbol", "Open", "High", "Low", "Close", "Volume",
                   "Trades", "VWAP", "Bid", "Ask", "Mid"]
    suffix = "" if (args.start, args.end) == ("04:00", "20:00") else f"_{tag}"
    path = os.path.join(args.out_dir, f"bars_{args.bar_min}min_{args.date}{suffix}.txt")
    out.to_csv(path, sep="|", index=False, float_format="%.4f")
    print(f"wrote {len(out):,} rows -> {path}")

    if args.ticks:
        build_ticks(args, fo, glbx, mid, w0, w1, os.path.join(args.out_dir, f"ticks_{args.date}_{tag}.txt.gz"))


if __name__ == "__main__":
    main()
