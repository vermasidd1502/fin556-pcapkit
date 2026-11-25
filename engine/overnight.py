#!/usr/bin/env python3
"""overnight.py - unattended loop on the lab VM: parse a day -> when the staging folder reaches --batch-gb,
upload it to cloud storage with rclone -> verify -> delete -> continue. Resumable: re-run the same command and
finished days are skipped (state in --state). No AI agent needed while it runs. Prints counts/sizes only.

  nohup ~/letf_env/bin/python overnight.py --remote univ_onedrive:FIN556/team8_pull \
      --iex-glob '/md/iex_pcaps/data_feeds_{date}_{date}_IEXTP1_DEEP1.0.pcap.gz' > ~/myproject/overnight.log 2>&1 &
  grep -E 'UPLOADED|INCOMPLETE|STOP|ALL DONE' ~/myproject/overnight.log      # check in the morning
"""
import argparse, os, shutil, subprocess, sys, time
from datetime import datetime, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))


def log(msg):
    print(f"{datetime.now():%m-%d %H:%M:%S} {msg}", flush=True)


def du_gb(p):
    return sum(os.path.getsize(os.path.join(r, f)) for r, _, fs in os.walk(p) for f in fs) / 1e9


def free_gb(p):
    return shutil.disk_usage(p).free / 1e9


def weekdays(a, b):
    d, z = datetime.strptime(a, "%Y%m%d"), datetime.strptime(b, "%Y%m%d")
    while d <= z:
        if d.weekday() < 5:
            yield d.strftime("%Y%m%d")
        d += timedelta(days=1)


def upload(a, stage, n):
    """rclone copy + one-way check, with retries; True only if every file is verified remote.
    --remote hold: move the batch to <work>/ready/batch_NN and wait until something else (the Mac's
    pull_batches.sh) has copied it away and deleted that folder."""
    if a.remote == "hold":
        ready = os.path.join(a.work, "ready"); os.makedirs(ready, exist_ok=True)
        tar = os.path.join(ready, f"batch_{n:02d}.tar")
        files = sorted(os.listdir(stage))
        import tarfile
        with tarfile.open(tar + ".part", "w") as tf:          # add then delete each file: disk peak = 1 file
            for f in files:
                tf.add(os.path.join(stage, f), arcname=f"batch_{n:02d}/{f}"); os.remove(os.path.join(stage, f))
        os.rename(tar + ".part", tar)                      # one file: download it, then delete it
        log(f"READY {tar} ({os.path.getsize(tar)/1e9:.2f} GB) - download it, then: rm {tar}")
        while os.path.exists(tar):
            time.sleep(30)
        return True
    dest = f"{a.remote}/batch_{n:02d}"
    for attempt in range(1, a.retries + 1):
        r = subprocess.run([a.rclone, "copy", stage, dest, "--transfers", "4", "--retries", "3", "--low-level-retries", "10",
                            "--stats", "0", "--log-level", "ERROR"], capture_output=True, text=True)
        c = subprocess.run([a.rclone, "check", stage, dest, "--one-way", "--size-only", "--log-level", "ERROR"],
                           capture_output=True, text=True)
        if r.returncode == 0 and c.returncode == 0:
            return True
        log(f"upload batch_{n:02d} attempt {attempt} failed: {(r.stderr or c.stderr).strip()[-300:]}")
        time.sleep(60 * attempt)
    return False


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--from", dest="d0", default="20250203")
    ap.add_argument("--to", dest="d1", default="20250430")
    ap.add_argument("--remote", required=True, help="rclone remote:path, or 'hold' to wait for pull_batches.sh on the Mac")
    ap.add_argument("--iex-glob", default="")
    ap.add_argument("--work", default=os.path.expanduser("~/myproject/overnight"))
    ap.add_argument("--state", default=os.path.expanduser("~/myproject/overnight_done.txt"))
    ap.add_argument("--batch-gb", type=float, default=7.5)
    ap.add_argument("--min-free-gb", type=float, default=5.0)
    ap.add_argument("--cme-port", type=int, default=0)
    ap.add_argument("--jobs", type=int, default=8, help="days parsed in parallel")
    ap.add_argument("--day-gb", type=float, default=1.0, help="disk room reserved per parallel day")
    ap.add_argument("--cme-threads", type=int, default=32)
    ap.add_argument("--extra-secids", default="")
    ap.add_argument("--iex-python", default="")
    ap.add_argument("--nq-night", action="store_true", help="NQ-only overnight pass (20:00 prev -> 04:00); use its own --work/--state")
    ap.add_argument("--rclone", default=os.path.expanduser("~/bin/rclone"))
    ap.add_argument("--retries", type=int, default=5)
    ap.add_argument("--puller", default=os.path.join(HERE, "day_pull.py"), help=argparse.SUPPRESS)
    a = ap.parse_args()
    if a.remote != "hold" and not os.access(a.rclone, os.X_OK):
        sys.exit(f"rclone not found at {a.rclone}")
    stage = os.path.join(a.work, "stage"); os.makedirs(stage, exist_ok=True)
    done = {l.strip() for l in open(a.state) if l.strip() and not l.startswith("batch ")} if os.path.exists(a.state) else set()
    # a day counts as staged only if its ticks file exists (written last); remove leftovers of half-finished days
    key = "nq_night_" if a.nq_night else "ticks_"
    staged = sorted({f[len(key):len(key) + 8] for f in os.listdir(stage) if f.startswith(key) and f[len(key):len(key) + 8].isdigit()})
    for f in os.listdir(stage):
        p = os.path.join(stage, f)
        if os.path.isfile(p) and not any(d in f for d in staged):
            os.remove(p)
    shutil.rmtree(os.path.join(stage, "raw"), ignore_errors=True)
    n = 1 + max([int(l.split()[1]) for l in open(a.state) if l.startswith("batch ")] or [0]) if os.path.exists(a.state) else 1
    todo = [d for d in weekdays(a.d0, a.d1) if d not in done and d not in staged]
    log(f"start: {len(todo)} days to pull, {len(staged)} staged, {len(done)} done; free {free_gb(a.work):.1f} GB; batch {a.batch_gb} GB")

    def flush(final=False):
        nonlocal n, staged
        if not os.listdir(stage):
            return
        gb = du_gb(stage)
        if not final and gb < a.batch_gb:
            return
        days = sorted({f.split("_")[-1].split(".")[0] for f in os.listdir(stage) if f.endswith(".parquet")} | set(staged))
        if not upload(a, stage, n):
            log(f"STOP: upload of batch_{n:02d} failed after {a.retries} tries; data kept in {stage}; re-run to resume")
            sys.exit(2)
        for f in os.listdir(stage):
            os.remove(os.path.join(stage, f))
        with open(a.state, "a") as fh:
            fh.write(f"batch {n} {' '.join(days)}\n" + "".join(d + "\n" for d in days))
        log(f"UPLOADED batch_{n:02d}: {len(days)} days {days[0]}..{days[-1]}, {gb:.2f} GB; free {free_gb(a.work):.1f} GB")
        n += 1; staged = []

    done_n, J = 0, max(1, a.jobs)
    while done_n < len(todo):
        # each parallel day needs ~day_gb of room; ship what's staged first if the disk can't hold a full group
        if free_gb(a.work) < a.min_free_gb + 2 + a.day_gb * J:
            flush(final=True)
        room = int((free_gb(a.work) - a.min_free_gb - 2) // a.day_gb)
        k = min(J, max(room, 0), len(todo) - done_n)
        if k < 1:
            log(f"STOP: free disk {free_gb(a.work):.1f} GB too low before {todo[done_n]}"); sys.exit(3)
        group = todo[done_n:done_n + k]
        t = time.time(); procs = {}
        for d in group:
            cmd = [sys.executable, a.puller, "--from", d, "--to", d, "--out-dir", stage, "--min-free-gb", str(a.min_free_gb),
                   "--cme-threads", str(a.cme_threads)]
            if a.iex_glob:
                cmd += ["--iex-glob", a.iex_glob]
            if a.cme_port:
                cmd += ["--cme-port", str(a.cme_port)]
            if a.extra_secids:
                cmd += ["--extra-secids", a.extra_secids]
            if a.iex_python:
                cmd += ["--iex-python", a.iex_python]
            if a.nq_night:
                cmd += ["--nq-night"]
            procs[d] = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        outs = {d: p.communicate() for d, p in procs.items()}
        for f in os.listdir(stage):                     # parser logs are not data we keep
            if f.startswith("log_"):
                os.remove(os.path.join(stage, f))
        for d in group:
            so, se = outs[d]; done_n += 1
            for line in so.splitlines():
                if line.startswith(("INCOMPLETE", "free disk below")):
                    log(line)
            got = os.path.exists(os.path.join(stage, f"{'nq_night' if a.nq_night else 'ticks'}_{d}.parquet"))
            if not got:                                 # drop partial files of a failed day
                for f in os.listdir(stage):
                    if d in f and os.path.isfile(os.path.join(stage, f)):
                        os.remove(os.path.join(stage, f))
                with open(a.state, "a") as fh:
                    fh.write(d + "\n")                   # holiday / missing feed: don't retry every run
                if "INCOMPLETE" not in so:
                    log(f"INCOMPLETE {d} | all | no output (exit {procs[d].returncode}) {se.strip()[-200:]}")
            log(f"{d}: {'ok' if got else 'NO OUTPUT'} in {time.time()-t:.0f}s ({k} days in parallel); stage {du_gb(stage):.2f} GB ({done_n}/{len(todo)})")
        flush()
    flush(final=True)
    shutil.rmtree(stage, ignore_errors=True)
    log("ALL DONE")


if __name__ == "__main__":
    main()
