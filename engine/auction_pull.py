#!/usr/bin/env python3
"""auction_pull.py - pull open/close auction windows + NOII + cross prints for the FIN556 auction study.

Runs ON THE LAB VM. Read-only on /db_pcaps; writes only --out-dir; deletes raw files after each day;
stops if free disk < --min-free-gb. Prints counts only, never data rows.

Per trading day it writes (pipe-separated, same column order as the evening tick files plus a `window` column):
  auction_ticks_<date>.txt.gz  ts_recv_ns|ts_event_ns|time_et|venue|symbol|type|bid_px|bid_sz|ask_px|ask_sz|price|size|aggressor|trade_id|window
                               windows: OPEN = 09:20-09:45 ET, CLOSE = 15:45-16:15 ET; NQ + Nasdaq symbols; type Q/T
  noii_<date>.txt.gz           ts_recv_ns|ts_event_ns|time_et|symbol|paired|imbalance|direction|far_px|near_px|ref_px|cross_type|pvi
                               every Net Order Imbalance message 09:00-16:15 for the symbols (cross_type O=open, C=close, H=halt/IPO)
  crosses_<date>.txt           ts_event_ns|time_et|symbol|price|size|cross_type|match_no   (official opening/closing cross prints)

Build once:  g++ -O3 -std=c++17 -o itch_noii itch_noii.cpp   (and the usual mdp3_fast* via build.sh)
Run:
  python3 auction_pull.py --from 20250203 --to 20250430 --dry-run
  python3 auction_pull.py --from 20250402 --to 20250402            # one test day first
  python3 auction_pull.py --from 20250203 --to 20250430
"""
import argparse, gzip, os, shutil, subprocess, sys, time
from datetime import timedelta

import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from ndx_combine import ET, NS, daterange, et_ns, select_files  # noqa: E402

STOCKS = "NVDA,TSLA,AAPL,AMD,AMZN,AVGO,COIN,GOOGL,META,MSFT,MSTR,PLTR"
INDEX = "QQQ,TQQQ,SQQQ"
LEV = ("AAPB,AAPD,AAPU,AMDG,AMDL,AMDD,AMUU,AMZD,AMZU,AMZZ,AVGX,AVL,AVS,CONI,CONL,COIG,FBL,METD,METU,GGLL,GGLS,"
       "MSFD,MSFL,MSFU,MSTX,SMST,NVD,NVDD,NVDG,NVDL,NVDS,NVDU,PLTD,PLTU,PTIR,PLTG,TSDD,TSL,TSLG,TSLL,TSLQ,TSLR,TSLS")
# CME SecurityIDs from DATA_NOTES / pcapkit prefs: NQH5 until 2025-03-14, NQM5 from 2025-03-17
NQ_IDS = [("20250317", "NQM5=42005804"), ("00000000", "NQH5=42288528")]
WINDOWS = {"OPEN": ("09:20", "09:45"), "CLOSE": ("15:45", "16:15")}
COLS = ["ts_recv_ns", "ts_event_ns", "time_et", "venue", "symbol", "type", "bid_px", "bid_sz", "ask_px", "ask_sz",
        "price", "size", "aggressor", "trade_id", "window"]


def free_gb(path):
    return shutil.disk_usage(path).free / 1e9


def nq_for(tag):
    return next(v for d, v in NQ_IDS if tag >= d)


def run(cmd, log):
    with open(log, "a") as fh:
        r = subprocess.run(cmd, stdout=fh, stderr=fh)
    if r.returncode:
        raise RuntimeError(f"{os.path.basename(cmd[2])} failed (exit {r.returncode}); see {log}")


def to_et(ns):
    return pd.to_datetime(ns, utc=True).dt.tz_convert(ET).dt.strftime("%H:%M:%S.%f")


def window_mask(ts, day):
    lab = pd.Series("", index=ts.index)
    for w, (a, b) in WINDOWS.items():
        lab[(ts >= et_ns(day, a)) & (ts < et_ns(day, b))] = w
    return lab


def do_day(day, a, raw):
    tag = day.strftime("%Y%m%d")
    midnight = et_ns(day, "00:00")
    itch = select_files(a.xnas_root, day, et_ns(day, "04:00"), et_ns(day, "16:15"))
    cme = [f for w in WINDOWS.values() for f in
           select_files(a.glbx_root, day, et_ns(day, w[0]) - 30 * 60 * NS, et_ns(day, w[1]))]
    cme = sorted(set(cme), key=os.path.basename)
    print(f"{tag}: {len(itch)} xnas files, {len(cme)} glbx files, NQ {nq_for(tag)}", flush=True)
    if a.dry_run or not itch or not cme:
        if not itch or not cme:
            print(f"{tag}: missing files for one feed - skipped")
        return None
    syms = ",".join([INDEX, STOCKS, LEV])
    xb, gb, log = os.path.join(raw, f"xnas_{tag}"), os.path.join(raw, f"glbx_{tag}"), os.path.join(a.out_dir, f"log_{tag}.txt")
    feed = os.path.join(HERE, "fast_feed.py")
    cme_bin = next(os.path.join(HERE, b) for b in ("mdp3_fast3", "mdp3_fast2", "mdp3_fast") if os.access(os.path.join(HERE, b), os.X_OK))
    p1 = subprocess.Popen([sys.executable, feed, os.path.join(HERE, "itch_noii"), "--symbols", syms, "--out", xb, "--"] + itch,
                          stdout=open(log, "a"), stderr=subprocess.STDOUT)
    p2 = subprocess.Popen([sys.executable, feed, cme_bin, "--secids", nq_for(tag), "--display-factor", "0.01", "--depth", "1",
                           "--out", gb, "--"] + cme, stdout=open(log, "a"), stderr=subprocess.STDOUT)
    while p1.poll() is None or p2.poll() is None:
        if free_gb(a.out_dir) < a.min_free_gb:
            p1.kill(); p2.kill()
            raise SystemExit(f"{tag}: free disk below {a.min_free_gb} GB - stopped (raw files left in {raw}, delete them)")
        time.sleep(5)
    if p1.returncode or p2.returncode:
        raise RuntimeError(f"{tag}: parser failed (itch {p1.returncode}, cme {p2.returncode}); see {log}")

    # ---- Nasdaq quotes + trades (ITCH time = ns since New York midnight)
    q = pd.read_csv(xb + "_bbo.csv"); q["ts_event_ns"] = q.pop("ts_itch_ns") + midnight
    t = pd.read_csv(xb + "_trades.csv", dtype={"cross_type": str}); t["ts_event_ns"] = t.pop("ts_itch_ns") + midnight
    crosses = t[t.kind == "Q"].copy()
    t = t[t.kind != "Q"]
    q = q.assign(venue="XNAS", type="Q", price=None, size=None, aggressor=None, trade_id=None)
    t = t.rename(columns={"match_no": "trade_id"}).assign(venue="XNAS", type="T", bid_px=None, bid_sz=None, ask_px=None, ask_sz=None)
    # ---- CME
    gq = pd.read_csv(gb + "_bbo.csv").rename(columns={"bid_px_00": "bid_px", "bid_sz_00": "bid_sz", "ask_px_00": "ask_px", "ask_sz_00": "ask_sz"})
    gq = gq.assign(venue="GLBX", type="Q", price=None, size=None, aggressor=None, trade_id=None)
    gt = pd.read_csv(gb + "_trades.csv").rename(columns={"rpt_seq": "trade_id"})
    gt = gt.assign(venue="GLBX", type="T", bid_px=None, bid_sz=None, ask_px=None, ask_sz=None)
    allr = pd.concat([x.reindex(columns=COLS[:-1]) for x in (q, t, gq, gt)], ignore_index=True)
    allr["window"] = window_mask(allr.ts_event_ns, day)
    allr = allr[allr.window != ""].sort_values("ts_event_ns", kind="stable")
    allr["time_et"] = to_et(allr.ts_event_ns)
    allr[COLS].to_csv(os.path.join(a.out_dir, f"auction_ticks_{tag}.txt.gz"), sep="|", index=False, compression="gzip")

    # ---- NOII + crosses
    n = pd.read_csv(xb + "_noii.csv", dtype={"direction": str, "cross_type": str, "pvi": str})
    n["ts_event_ns"] = n.pop("ts_itch_ns") + midnight
    n = n[n.ts_event_ns >= et_ns(day, "09:00")]
    n["time_et"] = to_et(n.ts_event_ns)
    n[["ts_recv_ns", "ts_event_ns", "time_et", "symbol", "paired", "imbalance", "direction", "far_px", "near_px", "ref_px",
       "cross_type", "pvi"]].to_csv(os.path.join(a.out_dir, f"noii_{tag}.txt.gz"), sep="|", index=False, compression="gzip")
    crosses["time_et"] = to_et(crosses.ts_event_ns)
    crosses.rename(columns={"match_no": "match_no"})[["ts_event_ns", "time_et", "symbol", "price", "size", "cross_type", "match_no"]] \
        .to_csv(os.path.join(a.out_dir, f"crosses_{tag}.txt"), sep="|", index=False)

    # counts only
    cnt = allr.groupby(["window", "venue", "type"]).size().to_dict()
    nct = n.cross_type.value_counts().to_dict()
    cct = crosses.cross_type.value_counts().to_dict()
    nsym = crosses[crosses.cross_type == "C"].symbol.nunique()
    print(f"{tag}: ticks {cnt}; noii by cross_type {nct}; cross prints {cct}; symbols with a closing cross {nsym}", flush=True)
    for f in os.listdir(raw):
        if f.startswith((f"xnas_{tag}", f"glbx_{tag}")):
            os.remove(os.path.join(raw, f))
    return nsym


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--from", dest="d0", required=True)
    ap.add_argument("--to", dest="d1", required=True)
    ap.add_argument("--xnas-root", default="/db_pcaps/xnas_pcaps")
    ap.add_argument("--glbx-root", default="/db_pcaps/glbx_pcaps")
    ap.add_argument("--out-dir", default=os.path.expanduser("~/myproject/auction_out"))
    ap.add_argument("--min-free-gb", type=float, default=5.0)
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    if not a.dry_run and not os.access(os.path.join(HERE, "itch_noii"), os.X_OK):
        raise SystemExit("build first: g++ -O3 -std=c++17 -o itch_noii itch_noii.cpp")
    os.makedirs(a.out_dir, exist_ok=True)
    raw = os.path.join(a.out_dir, "raw"); os.makedirs(raw, exist_ok=True)
    print(f"free disk {free_gb(a.out_dir):.1f} GB (stop below {a.min_free_gb})")
    T0, ok = time.time(), 0
    for day in daterange(a.d0, a.d1):
        if day.weekday() >= 5:
            continue
        if free_gb(a.out_dir) < a.min_free_gb:
            raise SystemExit(f"free disk below {a.min_free_gb} GB - stopped before {day:%Y%m%d}")
        try:
            r = do_day(day, a, raw)
            ok += r is not None
        except RuntimeError as e:
            print(e, flush=True)
    shutil.rmtree(raw, ignore_errors=True)
    print(f"done: {ok} days in {time.time() - T0:.0f}s; free disk {free_gb(a.out_dir):.1f} GB")


if __name__ == "__main__":
    main()
