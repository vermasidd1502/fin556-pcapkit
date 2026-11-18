#!/usr/bin/env python3
"""kit.py - find the market data captures on this machine, pick what you want, pull it. Fast and disk-safe.

THIS IS HFT! NOT SHEEPLE CODING!!!  The heavy work is C++ (pcap_scan, itch_fast3, mdp3_fast3). This script reads
prefs.ini, plans, checks the disk, and runs the C++ tools through a job queue capped at 32 threads.

Nothing is tied to one folder layout. `scan` looks inside every capture it can find (read-only) and records the
exchange, protocol and start time of each file in catalog.tsv; every later step picks files from that catalog.
So new data the professor puts on the VM, in any folder, with any file names, works the same way.

  python3 kit.py scan            find captures under [data] roots (auto = the usual data folders) -> catalog.tsv
  python3 kit.py ask             answer a few questions -> prefs.ini   (or edit it, or let your AI agent fill it)
  python3 kit.py plan            per day: files found, gaps, disk estimate, exact commands
  python3 kit.py run             pull it (asks first; --yes to skip the question)
  python3 kit.py discover-cme --date YYYYMMDD   busy CME SecurityIDs and their prices (no definitions in captures)
  python3 kit.py clean           delete this kit's temporary files
Options: --prefs FILE (default prefs.ini next to this script)
"""
import argparse
import configparser
import csv
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta, timezone

try:
    from zoneinfo import ZoneInfo
except ImportError:
    sys.exit("needs python 3.9 or newer")

HERE = os.path.dirname(os.path.abspath(__file__))
ENGINE = os.path.join(HERE, "engine")
CATALOG = os.path.join(HERE, "catalog.tsv")
ET = ZoneInfo("America/New_York")
NS = 1_000_000_000
DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
# where course data usually lives on a lab machine; `roots = auto` scans the ones that exist (read-only)
AUTO_ROOTS = ["/db_pcaps", "/md", "/data", "/datasets", "/shared", "/course", "/class", "/mnt", "/srv", "/scratch",
              "/opt/data", "~/data", "~/pcaps"]
VENUE_OF = {"nasdaq": "NASDAQ", "cme": "CME", "iex": "IEX"}
# rough output sizes measured on the course data (58 symbols, 18:00-20:00, 40 days); disk estimate only
MB_TICKS_PER_SYM_HOUR, MB_BARS_PER_SYM_HOUR = 0.04, 0.004


# --------------------------------------------------------------------------- prefs
def load_prefs(path):
    if not os.path.exists(path):
        sys.exit(f"no {path} - run: python3 kit.py ask")
    cp = configparser.ConfigParser(inline_comment_prefixes=("#",))
    cp.read(path)
    g = lambda s, k, d="": cp.get(s, k, fallback=d).strip()
    lst = lambda s: [x.strip() for x in s.split(",") if x.strip()]
    p = {
        "roots": lst(g("data", "roots", "auto")),
        "venues": [v.lower() for v in lst(g("request", "venues", "nasdaq"))],
        "symbols": g("request", "symbols", "QQQ"),
        "cme": lst(g("request", "cme_instruments", "")),
        "cme_factor": float(g("request", "cme_price_factor", "0.01") or 0.01),
        "from": g("request", "from"), "to": g("request", "to"),
        "weekdays": [d.lower()[:3] for d in lst(g("request", "weekdays", "mon,tue,wed,thu,fri"))],
        "skip": set(lst(g("request", "skip_dates", ""))),
        "start": g("request", "start", "09:30"), "end": g("request", "end", "16:00"),
        "book_from": g("request", "book_from", "04:00"),
        "bars": [int(x) for x in lst(g("output", "bars", "1"))],
        "ticks": g("output", "ticks", "no").lower() in ("yes", "y", "true", "1"),
        "out_dir": os.path.expanduser(g("output", "out_dir", "out")),
        "max_threads": min(32, int(g("limits", "max_threads", "32") or 32)),
        "min_free_gb": float(g("limits", "min_free_gb", "5") or 5),
        "max_out_gb": float(g("limits", "max_out_gb", "10") or 10),
    }
    syms = p["symbols"]
    if syms and os.path.exists(os.path.join(HERE, syms)):
        syms = ",".join(l.strip() for l in open(os.path.join(HERE, syms)) if l.strip() and not l.startswith("#"))
    p["symbols"] = ",".join(dict.fromkeys(s.strip().upper() for s in syms.split(",") if s.strip()))
    if not os.path.isabs(p["out_dir"]):
        p["out_dir"] = os.path.join(HERE, p["out_dir"])
    for k in ("from", "to"):
        if not re.fullmatch(r"\d{8}", p[k]):
            sys.exit(f"prefs: [request] {k} must be YYYYMMDD (got '{p[k]}')")
    for k in ("start", "end", "book_from"):
        if not re.fullmatch(r"\d{2}:\d{2}", p[k]):
            sys.exit(f"prefs: [request] {k} must be HH:MM New York time (got '{p[k]}')")
    bad = set(p["venues"]) - set(VENUE_OF)
    if bad:
        sys.exit(f"prefs: unknown venue(s) {sorted(bad)}; use nasdaq, cme, iex")
    return p


def resolve_roots(p):
    roots = []
    for r in p["roots"]:
        if r.lower() == "auto":
            roots += [os.path.expanduser(x) for x in AUTO_ROOTS]
        else:
            roots.append(os.path.expanduser(r))
    return [r for r in dict.fromkeys(roots) if os.path.isdir(r)]


def days_of(p):
    d = datetime.strptime(p["from"], "%Y%m%d").date()
    z = datetime.strptime(p["to"], "%Y%m%d").date()
    while d <= z:
        if DAYS[d.weekday()] in p["weekdays"] and d.strftime("%Y%m%d") not in p["skip"]:
            yield d
        d += timedelta(days=1)


def cme_for_day(p, day):
    """active CME instruments for a day: NAME=ID[@YYYYMMDD]; per root (name minus month+year) the newest start wins"""
    best, tag = {}, day.strftime("%Y%m%d")
    for item in p["cme"]:
        m = re.fullmatch(r"([A-Za-z0-9]+)=(\d+)(?:@(\d{8}))?", item.replace(" ", ""))
        if not m:
            sys.exit(f"prefs: bad cme_instruments entry '{item}' (want NAME=SecurityID or NAME=SecurityID@YYYYMMDD)")
        name, sid, first = m.group(1).upper(), m.group(2), m.group(3) or "00000000"
        root = name[:-2] if len(name) > 2 and name[-1].isdigit() else name
        if first <= tag and (root not in best or first >= best[root][2]):
            best[root] = (name, sid, first)
    return ",".join(f"{n}={s}" for n, s, _ in best.values())


def et_ns(day, hhmm):
    h, m = map(int, hhmm.split(":"))
    return int(datetime(day.year, day.month, day.day, h, m, tzinfo=ET).timestamp()) * NS


# --------------------------------------------------------------------------- catalog: the only source of file paths
def run_scan(p, peek=1, quiet=False):
    exe = os.path.join(HERE, "pcap_scan")
    if not os.access(exe, os.X_OK):
        sys.exit("pcap_scan is not built - run: bash build.sh")
    roots = resolve_roots(p)
    if not roots:
        sys.exit("no data folders found. Set [data] roots in prefs.ini to the folder(s) holding the captures.")
    c = [exe, "--peek", str(peek), "--threads", str(p["max_threads"]), "--out", CATALOG] + roots
    if not quiet:
        print("scanning (read-only):", ", ".join(roots), flush=True)
    rc = subprocess.call(c, stdout=subprocess.DEVNULL if quiet else None)
    if rc:
        sys.exit(f"pcap_scan failed (exit {rc})")
    with open(CATALOG + ".roots", "w") as f:
        f.write("\n".join(roots))


def file_start_ns(row):
    """start time of a capture file: first packet time if the scan opened it, else a YYYYMMDDTHHMMSS (UTC) name"""
    fp = row.get("first_packet_utc", "-")
    if fp and fp != "-":
        s, frac = fp.rstrip("Z").split(".") if "." in fp else (fp.rstrip("Z"), "0")
        t = datetime.strptime(s, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
        return int(t.timestamp()) * NS + int(frac.ljust(9, "0")[:9])
    d, t = row.get("date", "-"), row.get("file_time", "-")
    if d != "-" and t != "-":
        return int(datetime.strptime(d + t, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc).timestamp()) * NS
    if d != "-":  # a whole-day file named only by date: treat it as starting at New York midnight
        dd = datetime.strptime(d, "%Y%m%d").date()
        return et_ns(dd, "00:00")
    return None


def load_catalog(p):
    roots = resolve_roots(p)
    stale = not os.path.exists(CATALOG) or not os.path.exists(CATALOG + ".roots") or \
        open(CATALOG + ".roots").read().split("\n") != roots
    if stale:
        print("catalog missing or made for other folders - scanning first", flush=True)
        run_scan(p, peek=1, quiet=True)
    with open(CATALOG) as f:
        rows = list(csv.DictReader(f, delimiter="\t"))
    groups = {}
    for r in rows:
        if r.get("protocol", "-") in ("-",):  # names-only scan: venue from the path is all we know
            pass
        s = file_start_ns(r)
        if s is None:
            continue
        r["start_ns"] = s
        groups.setdefault((r["venue"], os.path.dirname(r["path"])), []).append(r)
    # each file ends where the next file of the same feed starts; the last one gets the feed's usual length
    by_venue = {}
    for (venue, _), fs in groups.items():
        fs.sort(key=lambda r: r["start_ns"])
        gaps = sorted(b["start_ns"] - a["start_ns"] for a, b in zip(fs, fs[1:]) if b["start_ns"] > a["start_ns"])
        typical = gaps[len(gaps) // 2] if gaps else 24 * 3600 * NS
        for a, b in zip(fs, fs[1:] + [None]):  # a file never runs past the next one, nor much past the usual length
            nxt = b["start_ns"] if b and b["start_ns"] > a["start_ns"] else None
            a["end_ns"] = min(nxt, a["start_ns"] + typical) if nxt else a["start_ns"] + typical
        by_venue.setdefault(venue, []).extend(fs)
    # merge feeds split across folders (e.g. one folder per day) into one timeline per venue
    for v in by_venue:
        by_venue[v].sort(key=lambda r: r["start_ns"])
    return by_venue


def ny_date(ns):
    return datetime.fromtimestamp(ns / NS, tz=ET).strftime("%Y%m%d")


def pick(cat, venue, t0, t1, day=None):
    """capture files of a venue that overlap [t0, t1) in UTC epoch ns, oldest first.
    Nasdaq ITCH times count from New York midnight with no date, so a Nasdaq file must also start on `day`."""
    out = [r for r in cat.get(VENUE_OF[venue], []) if r["start_ns"] < t1 and r["end_ns"] > t0]
    if venue == "nasdaq" and day is not None:
        out = [r for r in out if ny_date(r["start_ns"]) == day.strftime("%Y%m%d")]
    return [r["path"] for r in out]


def free_gb(path):
    d = path
    while not os.path.exists(d):
        d = os.path.dirname(d) or "."
    return shutil.disk_usage(d).free / 1e9


def dir_gb(path):
    tot = 0
    for dp, _, fs in os.walk(path):
        for n in fs:
            try:
                tot += os.path.getsize(os.path.join(dp, n))
            except OSError:
                pass
    return tot / 1e9


def binary(name):
    p = os.path.join(ENGINE, name)
    return p if os.access(p, os.X_OK) else None


# --------------------------------------------------------------------------- commands
def cmd_scan(p, args):
    run_scan(p, peek=args.peek)
    print(f"catalog -> {CATALOG}")


def ask(q, default):
    a = input(f"{q} [{default}]: ").strip()
    return a or default


def cmd_ask(p_path, args):
    print("Answer each question, or press Enter to keep the value in [brackets]. Times are New York time.")
    cp = configparser.ConfigParser(inline_comment_prefixes=("#",))
    if os.path.exists(p_path):
        cp.read(p_path)
    for s in ("data", "request", "output", "limits"):
        if not cp.has_section(s):
            cp.add_section(s)
    g = lambda s, k, d: cp.get(s, k, fallback=d)
    cp["data"]["roots"] = ask("Data folders to search (auto = the usual ones)", g("data", "roots", "auto"))
    cp["request"]["venues"] = ask("Venues (nasdaq, cme, iex)", g("request", "venues", "nasdaq, cme"))
    cp["request"]["symbols"] = ask("Nasdaq symbols (comma list or a file name)", g("request", "symbols", "QQQ, TQQQ, SQQQ"))
    cp["request"]["cme_instruments"] = ask("CME instruments NAME=SecurityID[@first_date]",
                                           g("request", "cme_instruments", "NQH5=42288528, NQM5=42005804@20250317"))
    cp["request"]["from"] = ask("First date YYYYMMDD", g("request", "from", "20250203"))
    cp["request"]["to"] = ask("Last date YYYYMMDD", g("request", "to", "20250207"))
    cp["request"]["weekdays"] = ask("Weekdays", g("request", "weekdays", "mon, tue, wed, thu, fri"))
    cp["request"]["skip_dates"] = ask("Dates to skip", g("request", "skip_dates", ""))
    cp["request"]["start"] = ask("Window start HH:MM", g("request", "start", "18:00"))
    cp["request"]["end"] = ask("Window end HH:MM", g("request", "end", "20:00"))
    cp["output"]["bars"] = ask("Bar sizes in minutes (comma list, empty = none)", g("output", "bars", "1"))
    cp["output"]["ticks"] = ask("Every quote and trade too? yes/no", g("output", "ticks", "yes"))
    cp["output"]["out_dir"] = ask("Output folder", g("output", "out_dir", "out"))
    with open(p_path, "w") as f:
        cp.write(f)
    print(f"saved {p_path}. Next: python3 kit.py plan")


def plan(p, cat, quiet=False):
    days = list(days_of(p))
    if not days:
        sys.exit("no days match from/to/weekdays/skip_dates")
    nsym = len(p["symbols"].split(",")) if "nasdaq" in p["venues"] else 0
    hours = max(0.0, (int(p["end"][:2]) * 60 + int(p["end"][3:]) - int(p["start"][:2]) * 60 - int(p["start"][3:])) / 60)
    rows, ok_days = [], []
    for d in days:
        t0, t1 = et_ns(d, p["start"]), et_ns(d, p["end"])
        nx = len(pick(cat, "nasdaq", et_ns(d, p["book_from"]), t1, d)) if "nasdaq" in p["venues"] else None
        ids = cme_for_day(p, d) if "cme" in p["venues"] else ""
        ng = len(pick(cat, "cme", t0 - 30 * 60 * NS, t1)) if "cme" in p["venues"] else None
        ni = len(pick(cat, "iex", t0, t1)) if "iex" in p["venues"] else None
        notes = []
        if nx == 0:
            notes.append("no Nasdaq files")
        if ng == 0:
            notes.append("no CME files")
        if "cme" in p["venues"] and not ids:
            notes.append("no CME instrument for this date")
        if ni is not None:
            notes.append(f"IEX: {ni} file(s), extraction not built yet" if ni else "no IEX files")
        go = (nx is None or nx > 0) and (ng is None or (ng > 0 and ids)) and (nx is not None or ng is not None)
        if go:
            ok_days.append(d)
        rows.append((d.strftime("%Y%m%d"), DAYS[d.weekday()], nx, ng, ids or "-", "pull" if go else "skip", "; ".join(notes)))
    sym_hours = (nsym + (1 if "cme" in p["venues"] else 0)) * hours * len(ok_days)
    est_mb = sym_hours * ((MB_TICKS_PER_SYM_HOUR if p["ticks"] else 0) + MB_BARS_PER_SYM_HOUR * len(p["bars"]))
    fgb = free_gb(p["out_dir"])
    if not quiet:
        print(f"{'date':<9} {'day':<4} {'nasdaq':>6} {'cme':>4}  {'cme ids':<22} action  notes")
        for r in rows:
            print(f"{r[0]:<9} {r[1]:<4} {'' if r[2] is None else r[2]:>6} {'' if r[3] is None else r[3]:>4}  {r[4]:<22} {r[5]:<7} {r[6]}")
        print(f"\n{len(ok_days)}/{len(days)} day(s) to pull | venues {', '.join(p['venues'])} | "
              f"{nsym} Nasdaq symbol(s) | {p['start']}-{p['end']} New York | bars {p['bars'] or 'none'} min | ticks {'yes' if p['ticks'] else 'no'}")
        print(f"output -> {p['out_dir']}  (estimate ~{est_mb:,.0f} MB kept; temporary files deleted after each day)")
        print(f"disk free {fgb:,.1f} GB, floor {p['min_free_gb']:g} GB" +
              ("  -> OK" if fgb - est_mb / 1e3 > p["min_free_gb"] else "  -> NOT ENOUGH: shrink the request"))
    return ok_days, est_mb, fgb


def cmd_plan(p, args):
    cat = load_catalog(p)
    ok_days, _, _ = plan(p, cat)
    if ok_days:
        print("\nfirst day would run:")
        for c in day_commands(p, cat, ok_days[0], write_lists=False):
            if "--" in c:
                k = c.index("--") + 1
                files = c[k:]
                c = c[:k] + (files[:2] + [f"... ({len(files)} files)"] if len(files) > 2 else files)
            print("  " + " ".join(c))


def day_commands(p, cat, day, write_lists=True):
    tag = day.strftime("%Y%m%d")
    raw = os.path.join(p["out_dir"], "raw")
    cmds = []
    ids = cme_for_day(p, day) if "cme" in p["venues"] else ""
    if ids:
        cme = binary("mdp3_fast3") or binary("mdp3_fast2") or binary("mdp3_fast") or "mdp3_fast3(not built)"
        files = pick(cat, "cme", et_ns(day, p["start"]) - 30 * 60 * NS, et_ns(day, p["end"]))
        cmds.append([sys.executable, os.path.join(ENGINE, "fast_feed.py"), cme, "--secids", ids, "--display-factor",
                     str(p["cme_factor"]), "--depth", "1", "--out", os.path.join(raw, f"glbx_{tag}"), "--"] + files)
    if "nasdaq" in p["venues"]:
        lst = os.path.join(raw, f"xnas_files_{tag}.txt")
        if write_lists:
            os.makedirs(raw, exist_ok=True)
            with open(lst, "w") as f:
                f.write("\n".join(pick(cat, "nasdaq", et_ns(day, p["book_from"]), et_ns(day, p["end"]), day)))
        for i, b in enumerate(p["bars"] or [1]):
            c = [sys.executable, os.path.join(ENGINE, "make_bars.py"), "--date", tag, "--bar-min", str(b),
                 "--start", p["start"], "--end", p["end"], "--symbols", p["symbols"], "--files", lst,
                 "--out-dir", p["out_dir"]]
            if p["ticks"] and i == 0:
                c.append("--ticks")
            if not ids:
                c.append("--no-nq")
            cmds.append(c)
    return cmds


def cme_only_outputs(p, day, log):
    """CME without Nasdaq: bars + ticks straight from the CME parse, same formats as make_bars."""
    import pandas as pd
    sys.path.insert(0, ENGINE)
    from make_bars import quote_bars, trade_bars_raw
    tag = day.strftime("%Y%m%d")
    base = os.path.join(p["out_dir"], "raw", f"glbx_{tag}")
    mid = et_ns(day, "00:00")
    a0, a1 = et_ns(day, p["start"]), et_ns(day, p["end"])
    wtag = p["start"].replace(":", "") + "-" + p["end"].replace(":", "")
    for b in p["bars"]:
        bar_ns = b * 60 * NS
        df = trade_bars_raw(base + "_trades.csv", "ts_event_ns", mid, bar_ns).join(
            quote_bars(base + "_bbo.csv", "ts_event_ns", "bid_px_00", "ask_px_00", mid, bar_ns), how="outer").reset_index()
        df = df[(df["bar"] >= (a0 - mid) // bar_ns) & (df["bar"] < -(-(a1 - mid) // bar_ns))]
        mins = df["bar"] * b
        out = pd.DataFrame({"Date": day.isoformat(), "Time": [f"{m // 60:02d}:{m % 60:02d}" for m in mins], "Symbol": df["symbol"],
                            "Open": df["open"], "High": df["high"], "Low": df["low"], "Close": df["close"],
                            "Volume": df["volume"].fillna(0).astype("int64"), "Trades": df["trades"].fillna(0).astype("int64"),
                            "VWAP": df["vwap"], "Bid": df["bid"], "Ask": df["ask"], "Mid": (df["bid"] + df["ask"]) / 2})
        path = os.path.join(p["out_dir"], f"bars_{b}min_{tag}_{wtag}.txt")
        out.to_csv(path, sep="|", index=False, float_format="%.4f")
        print(f"  wrote {len(out):,} rows -> {path}", file=log)
    if p["ticks"]:
        q = pd.read_csv(base + "_bbo.csv", usecols=["ts_event_ns", "symbol", "bid_px_00", "bid_sz_00", "ask_px_00", "ask_sz_00"],
                        dtype={"symbol": str})
        t = pd.read_csv(base + "_trades.csv", dtype={"symbol": str, "aggressor": str})
        q = q[(q["ts_event_ns"] >= a0) & (q["ts_event_ns"] < a1)]
        t = t[(t["ts_event_ns"] >= a0) & (t["ts_event_ns"] < a1)]
        qq = pd.DataFrame({"ts_event_ns": q["ts_event_ns"], "venue": "GLBX", "symbol": q["symbol"], "type": "Q",
                           "bid_px": q["bid_px_00"], "bid_sz": q["bid_sz_00"], "ask_px": q["ask_px_00"], "ask_sz": q["ask_sz_00"]})
        tt = pd.DataFrame({"ts_event_ns": t["ts_event_ns"], "venue": "GLBX", "symbol": t["symbol"], "type": "T",
                           "price": t["price"], "size": t["size"], "aggressor": t.get("aggressor")})
        df = pd.concat([qq, tt], ignore_index=True).sort_values("ts_event_ns", kind="stable")
        hms = pd.to_datetime(df["ts_event_ns"], unit="ns", utc=True).dt.tz_convert("America/New_York").dt.strftime("%H:%M:%S")
        df.insert(1, "time_et", hms + "." + (df["ts_event_ns"] % NS).astype(str).str.zfill(9))
        df = df.reindex(columns=["ts_event_ns", "time_et", "venue", "symbol", "type", "bid_px", "bid_sz", "ask_px", "ask_sz",
                                 "price", "size", "aggressor"])
        for c in ("bid_sz", "ask_sz", "size"):
            df[c] = df[c].astype("Int64")
        path = os.path.join(p["out_dir"], f"ticks_{tag}_{wtag}.txt.gz")
        df.to_csv(path, sep="|", index=False, compression="gzip")
        print(f"  wrote {len(df):,} rows -> {path}", file=log)


def cmd_run(p, args):
    cat = load_catalog(p)
    ok_days, est_mb, fgb = plan(p, cat)
    if not ok_days:
        sys.exit("nothing to pull")
    if fgb - est_mb / 1e3 <= p["min_free_gb"]:
        sys.exit("not enough free disk for this request - shrink it (fewer days, symbols or a shorter window)")
    if "nasdaq" in p["venues"] and not (binary("itch_fast3") or binary("itch_fast2") or binary("itch_fast")):
        sys.exit("Nasdaq parser not built - run: bash build.sh")
    if "cme" in p["venues"] and not (binary("mdp3_fast3") or binary("mdp3_fast2") or binary("mdp3_fast")):
        sys.exit("CME parser not built - run: bash build.sh")
    if not args.yes and input("start? yes/no: ").strip().lower() not in ("y", "yes"):
        sys.exit("not started")
    os.makedirs(os.path.join(p["out_dir"], "logs"), exist_ok=True)
    os.makedirs(os.path.join(p["out_dir"], "raw"), exist_ok=True)
    per_job = 32 if (binary("itch_fast3") or binary("mdp3_fast3")) else 6
    workers = max(1, min(32, p["max_threads"], os.cpu_count() or 1) // per_job)
    print(f"{len(ok_days)} day(s) queued; {workers} worker(s) x {per_job} threads (cap 32)", flush=True)
    q, lock, res, stop = queue.Queue(), threading.Lock(), {}, threading.Event()
    for d in ok_days:
        q.put(d)

    def worker():
        while not stop.is_set():
            try:
                d = q.get_nowait()
            except queue.Empty:
                return
            tag, t = d.strftime("%Y%m%d"), time.time()
            log = os.path.join(p["out_dir"], "logs", f"kit_{tag}.log")
            rc = 0
            with open(log, "w") as lg:
                for c in day_commands(p, cat, d):
                    rc = subprocess.call(c, stdout=lg, stderr=subprocess.STDOUT, cwd=ENGINE)
                    if rc:
                        break
                if rc == 0 and "cme" in p["venues"] and "nasdaq" not in p["venues"]:
                    try:
                        cme_only_outputs(p, d, lg)
                    except Exception as e:  # report, keep going with the other days
                        print(f"CME-only output failed: {e}", file=lg)
                        rc = 1
            raw = os.path.join(p["out_dir"], "raw")
            removed = 0
            if os.path.isdir(raw):  # temporary parser output for this day: delete it
                for n in os.listdir(raw):
                    if tag in n:
                        os.remove(os.path.join(raw, n))
                        removed += 1
            used = dir_gb(p["out_dir"])
            with lock:
                res[tag] = rc
                print(f"  {tag}: {'ok' if rc == 0 else 'FAILED (see ' + log + ')'} in {(time.time() - t) / 60:.1f} min, "
                      f"{removed} temp file(s) deleted, output folder {used:.2f} GB ({len(res)}/{len(ok_days)})", flush=True)
                if used > p["max_out_gb"]:
                    print(f"STOP: output folder passed {p['max_out_gb']:g} GB - move results off the VM, then run again")
                    stop.set()
                if free_gb(p["out_dir"]) < p["min_free_gb"]:
                    print(f"STOP: disk free under {p['min_free_gb']:g} GB")
                    stop.set()

    th = [threading.Thread(target=worker, daemon=True) for _ in range(workers)]
    for x in th:
        x.start()
    for x in th:
        x.join()
    bad = [d for d, rc in res.items() if rc]
    print(f"done: {len(res) - len(bad)} ok, {len(bad)} failed{' ' + str(bad) if bad else ''}; output in {p['out_dir']}")
    raw = os.path.join(p["out_dir"], "raw")
    if os.path.isdir(raw) and not os.listdir(raw):
        os.rmdir(raw)
    print("cleaned: temporary parser files for every finished day (out_dir/raw)")


def cmd_discover(p, args):
    if not args.date:
        sys.exit("give --date YYYYMMDD")
    d = datetime.strptime(args.date, "%Y%m%d").date()
    cat = load_catalog(p)
    files = pick(cat, "cme", et_ns(d, p["start"]), et_ns(d, p["start"]) + 20 * 60 * NS)
    if not files:
        sys.exit("no CME files near the window start that day")
    c = [sys.executable, os.path.join(ENGINE, "mdp3_parse.py"), "--discover", "--max-packets", "3000000"] + args.rest + [files[0]]
    print("reading", os.path.basename(files[0]), "(read-only) ...")
    sys.exit(subprocess.call(c))


def cmd_clean(p, args):
    raw = os.path.join(p["out_dir"], "raw")
    gone = []
    if os.path.isdir(raw):
        gone.append(f"{raw} ({len(os.listdir(raw))} file(s))")
        shutil.rmtree(raw)
    for f in (CATALOG, CATALOG + ".roots"):
        if os.path.exists(f):
            os.remove(f)
            gone.append(os.path.basename(f))
    print("cleaned: " + (", ".join(gone) if gone else "nothing to remove"))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["scan", "ask", "plan", "run", "discover-cme", "clean"])
    ap.add_argument("--prefs", default=os.path.join(HERE, "prefs.ini"))
    ap.add_argument("--peek", type=int, default=4, help="scan: MB to open per file to identify it (0 = names only)")
    ap.add_argument("--date", help="discover-cme: day to look at")
    ap.add_argument("--yes", action="store_true", help="run: don't ask before starting")
    args, args.rest = ap.parse_known_args()
    if args.command == "ask":
        return cmd_ask(args.prefs, args)
    p = load_prefs(args.prefs)
    {"scan": cmd_scan, "plan": cmd_plan, "run": cmd_run, "discover-cme": cmd_discover, "clean": cmd_clean}[args.command](p, args)


if __name__ == "__main__":
    main()
