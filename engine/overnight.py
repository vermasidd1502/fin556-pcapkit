#!/usr/bin/env python3
"""overnight.py - unattended multi-day pull on the FIN556 lab VM (team 8 defaults built in).

Parses trading days with day_pull.py, several at once, into a staging folder. When staging is full (or the disk is
near the floor) it packs everything into ONE file, <work>/ready/batch_NN.tar, and waits until that file has been
downloaded and deleted, then continues. Resumable: re-running the same command skips finished days.

Typical use (all defaults are the team-8 settings; override any flag on the command line):
  nohup ~/letf_env/bin/python overnight.py >> ~/myproject/overnight.log 2>&1 &
  grep -E 'start:|ok |READY|SHIPPED|INCOMPLETE|WAIT|STOP|ALL DONE' ~/myproject/overnight.log | tail

Day order: --center 20250402 pulls the tariff date first, then +1, -1, +2, -2 ... trading days.
State file: finished days, permanently skipped days (no data on the VM) and batch records. Days whose parser failed
are NOT recorded, so the next run retries them.
Prints counts, sizes and timings only - never data rows.
"""
import argparse
import os
import shutil
import subprocess
import sys
import tarfile
import time
from datetime import datetime, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
HOME = os.path.expanduser("~")

# ----------------------------------------------------------------------------- team-8 defaults (one place)
DEFAULTS = dict(
    d0="20250203", d1="20250430", center="20250402",
    work=f"{HOME}/myproject/overnight", state=f"{HOME}/myproject/overnight_done.txt",
    remote="hold", batch_gb=100.0, min_free_gb=1.0, day_gb=2.5,
    jobs=8, cme_threads=32, cme_port=14318,
    iex_glob="/md/iex_pcaps/data_feeds_{date}_{date}_IEXTP1_DEEP1.0.pcap.gz",
    iex_python=f"{HOME}/pypy/bin/pypy3",                    # used only if it exists
    secids_file=f"{HOME}/myproject/cme_secids.txt",         # one LABEL=SecurityID per line (extra CME contracts)
    rclone=f"{HOME}/bin/rclone", retries=5,
    wait_poll_s=60, wait_note_s=1800,                       # hold/low-disk waits: check every minute, note every 30 min
)
SKIP_MARK = "skip "                                         # state-file prefix for days with no data on the VM


def log(msg):
    print(f"{datetime.now():%m-%d %H:%M:%S} {msg}", flush=True)


def free_gb(path):
    return shutil.disk_usage(path).free / 1e9


def du_gb(path):
    return sum(os.path.getsize(os.path.join(r, f)) for r, _, fs in os.walk(path) for f in fs) / 1e9


def weekdays(d0, d1):
    d, z = datetime.strptime(d0, "%Y%m%d"), datetime.strptime(d1, "%Y%m%d")
    out = []
    while d <= z:
        if d.weekday() < 5:
            out.append(d.strftime("%Y%m%d"))
        d += timedelta(days=1)
    return out


def center_out(days, center):
    """center, +1, -1, +2, -2 ... in trading-day steps (ties: later day first)."""
    if not center or not days:
        return list(days)
    c = min(range(len(days)), key=lambda i: abs(int(days[i]) - int(center)))
    return sorted(days, key=lambda d: (abs(days.index(d) - c), days.index(d) < c))


# ----------------------------------------------------------------------------- state file
class State:
    """Plain-text, append-only: '<day>' = finished, 'skip <day> <reason>' = no data, 'batch N <days...>'."""

    def __init__(self, path):
        self.path, self.done, self.skipped, self.last_batch = path, set(), set(), 0
        if os.path.exists(path):
            for line in open(path):
                w = line.split()
                if not w:
                    continue
                if w[0] == "batch":
                    self.last_batch = max(self.last_batch, int(w[1]))
                elif w[0] == "skip":
                    self.skipped.add(w[1])
                else:
                    self.done.add(w[0])

    def _append(self, text):
        with open(self.path, "a") as fh:
            fh.write(text)

    def mark_batch(self, n, days):
        self._append(f"batch {n} {' '.join(days)}\n" + "".join(f"{d}\n" for d in days))
        self.done.update(days); self.last_batch = n

    def mark_skip(self, day, reason):
        self._append(f"{SKIP_MARK}{day} {reason}\n"); self.skipped.add(day)


# ----------------------------------------------------------------------------- shipping a batch
def wait_until(cond, what, a):
    """Sleep-poll (no busy loop) until cond() is true; a short note every wait_note_s seconds."""
    t0 = last = time.time()
    while not cond():
        time.sleep(a.wait_poll_s)
        if time.time() - last >= a.wait_note_s:
            log(f"WAIT {what} ({(time.time() - t0) / 3600:.1f} h so far)"); last = time.time()


def ship(a, stage, n):
    """Pack staged files into one tar (adding then deleting each file, so the disk peak is one file) and hand it off."""
    files = sorted(f for f in os.listdir(stage) if os.path.isfile(os.path.join(stage, f)))
    if a.remote == "keep":                                   # local run: finished days simply stay in the stage folder
        return True
    if a.remote == "hold":
        ready = os.path.join(a.work, "ready"); os.makedirs(ready, exist_ok=True)
        tar = os.path.join(ready, f"batch_{n:02d}.tar")
        with tarfile.open(tar + ".part", "w") as tf:
            for f in files:
                tf.add(os.path.join(stage, f), arcname=f"batch_{n:02d}/{f}")
                os.remove(os.path.join(stage, f))
        os.rename(tar + ".part", tar)
        log(f"READY {tar} ({os.path.getsize(tar) / 1e9:.2f} GB) - download it, then: rm {tar}")
        wait_until(lambda: not os.path.exists(tar), f"for {os.path.basename(tar)} to be downloaded and deleted", a)
        return True
    dest = f"{a.remote}/batch_{n:02d}"                        # rclone route (if the remote is reachable)
    for attempt in range(1, a.retries + 1):
        r = subprocess.run([a.rclone, "copy", stage, dest, "--transfers", "4", "--stats", "0", "--log-level", "ERROR"],
                           capture_output=True, text=True)
        c = subprocess.run([a.rclone, "check", stage, dest, "--one-way", "--size-only", "--log-level", "ERROR"],
                           capture_output=True, text=True)
        if r.returncode == 0 and c.returncode == 0:
            for f in files:
                os.remove(os.path.join(stage, f))
            return True
        log(f"upload batch_{n:02d} attempt {attempt} failed: {(r.stderr or c.stderr).strip()[-300:]}")
        time.sleep(60 * attempt)
    return False


# ----------------------------------------------------------------------------- main loop
def main():
    D = DEFAULTS
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--from", dest="d0", default=D["d0"])
    ap.add_argument("--to", dest="d1", default=D["d1"])
    ap.add_argument("--center", default=D["center"], help="pull outward from this day; '' = calendar order")
    ap.add_argument("--work", default=D["work"])
    ap.add_argument("--state", default=D["state"])
    ap.add_argument("--remote", default=D["remote"], help="'hold' (download by hand), 'keep' (local run) or an rclone remote:path")
    ap.add_argument("--batch-gb", type=float, default=D["batch_gb"], help="ship when staging reaches this (or disk is low)")
    ap.add_argument("--min-free-gb", type=float, default=D["min_free_gb"], help="hard disk floor")
    ap.add_argument("--day-gb", type=float, default=D["day_gb"], help="disk reserved per day running in parallel")
    ap.add_argument("--jobs", type=int, default=D["jobs"], help="max days parsed at once")
    ap.add_argument("--cme-threads", type=int, default=D["cme_threads"])
    ap.add_argument("--cme-port", type=int, default=D["cme_port"], help="CME channel port; 0 = all channels")
    ap.add_argument("--iex-glob", default=D["iex_glob"], help="'' = no IEX")
    ap.add_argument("--iex-python", default=D["iex_python"], help="PyPy for iex_parse.py (used if it exists)")
    ap.add_argument("--secids-file", default=D["secids_file"], help="extra CME contracts, LABEL=SecurityID per line")
    ap.add_argument("--extra-secids", default="", help="extra CME contracts inline (added to --secids-file)")
    ap.add_argument("--venues", default="xnas,glbx,iex", help="feeds to parse; e.g. xnas for a Nasdaq-only local run")
    ap.add_argument("--xnas-remote", default="", help="Nasdaq captures from an rclone remote, e.g. box:db/xnas_pcaps")
    ap.add_argument("--skip-days-file", default="", help="extra list of days already done (one YYYYMMDD per line); never re-pulled")
    ap.add_argument("--start-batch", type=int, default=0, help="next batch number to use (if the state file was lost)")
    ap.add_argument("--nq-night", action="store_true", help="NQ-only overnight pass; use its own --work and --state")
    ap.add_argument("--rclone", default=D["rclone"])
    ap.add_argument("--retries", type=int, default=D["retries"])
    ap.add_argument("--wait-poll-s", type=int, default=D["wait_poll_s"])
    ap.add_argument("--wait-note-s", type=int, default=D["wait_note_s"])
    ap.add_argument("--puller", default=os.path.join(HERE, "day_pull.py"), help=argparse.SUPPRESS)
    a = ap.parse_args()
    if a.remote not in ("hold", "keep") and not os.access(a.rclone, os.X_OK):
        sys.exit(f"rclone not found at {a.rclone}")

    secids = [s.strip() for s in a.extra_secids.split(",") if s.strip()]
    if os.path.exists(a.secids_file):
        secids += [l.strip() for l in open(a.secids_file) if "=" in l and not l.lstrip().startswith("#")]
    secids = ",".join(dict.fromkeys(secids))
    iex_python = a.iex_python if a.iex_python and os.access(a.iex_python, os.X_OK) else ""
    key = "nq_night_" if a.nq_night else "ticks_"            # a day is complete once this file exists (written last)

    stage = os.path.join(a.work, "stage"); os.makedirs(stage, exist_ok=True)
    shutil.rmtree(os.path.join(stage, "raw"), ignore_errors=True)
    staged = {f[len(key):len(key) + 8] for f in os.listdir(stage) if f.startswith(key)}
    for f in os.listdir(stage):                               # leftovers of half-finished days
        p = os.path.join(stage, f)
        if os.path.isfile(p) and not any(d in f for d in staged):
            os.remove(p)

    st = State(a.state)
    if a.skip_days_file and os.path.exists(a.skip_days_file):  # days already pulled elsewhere / before a cleanup
        st.done |= {w for l in open(a.skip_days_file) for w in l.split() if w.isdigit() and len(w) == 8}
    if a.start_batch:
        st.last_batch = max(st.last_batch, a.start_batch - 1)
    todo = center_out([d for d in weekdays(a.d0, a.d1) if d not in st.done | st.skipped | staged], a.center)
    log(f"start: {len(todo)} days to pull, {len(staged)} staged, {len(st.done)} done, {len(st.skipped)} skipped; "
        f"free {free_gb(a.work):.1f} GB; jobs {a.jobs}; cme port {a.cme_port}; extra contracts {secids.count('=')}; "
        f"iex {'pypy' if iex_python else 'python'}; order {'center ' + a.center if a.center else 'calendar'}")

    def flush(force):
        nonlocal staged
        if not os.listdir(stage):
            return
        gb = du_gb(stage)
        if not force and gb < a.batch_gb:
            return
        days = sorted(staged - st.done)
        if not days:
            return
        n = st.last_batch + 1
        if not ship(a, stage, n):
            log(f"STOP: batch_{n:02d} could not be shipped; data kept in {stage}; re-run to resume"); sys.exit(2)
        st.mark_batch(n, days)
        if a.remote != "keep":
            staged = set()
        log(f"{'SAVED' if a.remote == 'keep' else 'SHIPPED'} batch_{n:02d}: {len(days)} days ({', '.join(days)}), "
            f"{gb:.2f} GB; free {free_gb(a.work):.1f} GB")

    sizes = []                                                # GB written per finished day (learned as we go)

    def day_need():
        """disk to reserve per parallel day: the --day-gb floor, or 1.3x the median finished day, whichever is larger"""
        if not sizes:
            return a.day_gb
        return max(a.day_gb, 1.3 * sorted(sizes)[len(sizes) // 2])

    def room():
        return int((free_gb(a.work) - a.min_free_gb - 2) // day_need())

    attempts, i = {}, 0
    while i < len(todo):
        if room() < 1:
            flush(force=True)                                 # ship only when not even one more day fits
        if room() < 1:
            wait_until(lambda: room() >= 1, f"for disk (free {free_gb(a.work):.1f} GB; another user may be using it)", a)
        group = todo[i:i + max(1, min(a.jobs, room(), len(todo) - i))]
        t0 = time.time(); procs = {}
        for d in group:
            cmd = [sys.executable, a.puller, "--from", d, "--to", d, "--out-dir", stage,
                   "--min-free-gb", str(a.min_free_gb), "--cme-threads", str(a.cme_threads)]
            cmd += ["--cme-port", str(a.cme_port)] if a.cme_port else []
            cmd += ["--iex-glob", a.iex_glob] if a.iex_glob else []
            cmd += ["--iex-python", iex_python] if iex_python else []
            cmd += ["--extra-secids", secids] if secids else []
            cmd += ["--nq-night"] if a.nq_night else []
            cmd += ["--venues", a.venues, "--rclone", a.rclone]
            cmd += ["--xnas-remote", a.xnas_remote] if a.xnas_remote else []
            procs[d] = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        outs = {d: p.communicate() for d, p in procs.items()}  # blocks until the whole group is done
        secs = time.time() - t0
        for f in os.listdir(stage):                           # per-day parser logs are not kept
            if f.startswith("log_"):
                os.remove(os.path.join(stage, f))
        for d in group:
            out, err = outs[d]
            for line in out.splitlines():
                if line.startswith("INCOMPLETE"):
                    log(line)
            if os.path.exists(os.path.join(stage, f"{key}{d}.parquet")):
                staged.add(d)
                day_gb = sum(os.path.getsize(os.path.join(stage, f)) for f in os.listdir(stage) if d in f) / 1e9
                sizes.append(day_gb)
                log(f"{d}: ok in {secs:.0f}s ({len(group)} in parallel); day {day_gb:.2f} GB; staged {du_gb(stage):.2f} GB; "
                    f"reserving {day_need():.1f} GB/day ({i + 1}/{len(todo)})")
            else:
                for f in os.listdir(stage):                   # drop partial files of this day
                    if d in f and os.path.isfile(os.path.join(stage, f)):
                        os.remove(os.path.join(stage, f))
                if "| all | missing files" in out:
                    st.mark_skip(d, "no-data-on-vm")          # holiday or capture gap: never retried
                    log(f"{d}: skipped (no data on the VM) ({i + 1}/{len(todo)})")
                elif attempts.get(d, 0) < 1:                  # retry once later in this run (often a disk squeeze)
                    attempts[d] = attempts.get(d, 0) + 1
                    todo.append(d)
                    log(f"INCOMPLETE {d} | parse failed (exit {procs[d].returncode}); requeued: {(err or out).strip()[-160:]}")
                else:
                    log(f"INCOMPLETE {d} | parse failed twice; left for the next run: {(err or out).strip()[-160:]}")
            i += 1
        flush(force=False)
    flush(force=True)
    log("ALL DONE")


if __name__ == "__main__":
    main()
