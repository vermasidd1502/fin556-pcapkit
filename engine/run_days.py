#!/usr/bin/env python3
"""run_days.py - many trading days through ndx_combine.py: a job queue drained by a capped worker pool.

THIS IS HFT! NOT SHEEPLE CODING!!!  Each day is one job; a fixed pool of workers takes the next day off the
queue. Each job runs two v2 parsers (3 threads each = 6 threads), so the number of days in flight is
max_threads // 6, with max_threads capped at 32 (professor's rule) and at the machine's core count.

  python3 run_days.py --from 20250401 --to 20250430 --nq-secids NQM5=42005804 --start 04:00 --end 20:00 --clean-raw
Every option not listed below is passed straight to ndx_combine.py. One log per day in <out-dir>/logs/.
"""
import argparse
import os
import queue
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--from", dest="d0", required=True)
    ap.add_argument("--to", dest="d1", required=True)
    ap.add_argument("--max-threads", type=int, default=32, help="hard cap on threads in use (default 32)")
    ap.add_argument("--threads-per-job", type=int, default=0,
                    help="threads one day uses (default: 32 with v3 parsers, 6 with v2)")
    ap.add_argument("--out-dir", default="out")
    ap.add_argument("--clean-raw", action="store_true", help="delete that day's out/raw CSVs once its parquet is written")
    args, rest = ap.parse_known_args()

    if not args.threads_per_job:
        args.threads_per_job = 32 if os.access(os.path.join(HERE, "itch_fast3"), os.X_OK) else 6
    cap = min(32, args.max_threads, os.cpu_count() or 1)
    workers = max(1, cap // args.threads_per_job)
    days = []
    d, z = datetime.strptime(args.d0, "%Y%m%d").date(), datetime.strptime(args.d1, "%Y%m%d").date()
    while d <= z:
        if d.weekday() < 5:
            days.append(d.strftime("%Y%m%d"))
        d += timedelta(days=1)
    if not days:
        sys.exit("no weekdays in that range")
    logs = os.path.join(args.out_dir, "logs")
    os.makedirs(logs, exist_ok=True)
    print(f"{len(days)} day(s) queued; {workers} worker(s) x {args.threads_per_job} threads (cap {cap})", flush=True)

    q = queue.Queue()
    for day in days:
        q.put(day)
    results, lock = {}, threading.Lock()

    def worker():
        while True:
            try:
                day = q.get_nowait()
            except queue.Empty:
                return
            t = time.time()
            cmd = [sys.executable, os.path.join(HERE, "ndx_combine.py"), "--from", day, "--to", day,
                   "--out-dir", args.out_dir] + rest
            with open(os.path.join(logs, f"run_{day}.log"), "w") as lg:
                rc = subprocess.call(cmd, stdout=lg, stderr=subprocess.STDOUT)
            if rc == 0 and args.clean_raw and os.path.exists(os.path.join(args.out_dir, f"ndx_long_{day}.parquet")):
                raw = os.path.join(args.out_dir, "raw")
                for src in ("xnas", "glbx"):
                    for kind in ("bbo", "trades"):
                        p = os.path.join(raw, f"{src}_{day}_{kind}.csv")
                        if os.path.exists(p):
                            os.remove(p)
            with lock:
                results[day] = (rc, time.time() - t)
                print(f"  {day}: {'ok' if rc == 0 else 'FAILED rc=%d' % rc} in {(time.time() - t) / 60:.1f} min "
                      f"({len(results)}/{len(days)} done)", flush=True)
            q.task_done()

    T = time.time()
    threads = [threading.Thread(target=worker, daemon=True) for _ in range(workers)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    bad = [d for d, (rc, _) in results.items() if rc != 0]
    print(f"finished {len(days) - len(bad)}/{len(days)} day(s) in {(time.time() - T) / 60:.1f} min"
          + (f"; failed: {', '.join(sorted(bad))} (see {logs}/)" if bad else ""))


if __name__ == "__main__":
    main()
