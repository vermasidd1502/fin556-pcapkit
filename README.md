# pcapkit · find and pull market data from the FIN556 lab VM captures

A small C++ toolkit for the course VM. It **finds** every packet capture on the machine, tells you what is inside
(exchange, protocol, dates, sizes), then **pulls** exactly the data you ask for (venues, symbols, dates, time window)
into small text files: 1-minute (or any size) bars and every quote and trade. Disk-safe and fast.

**Not tied to one folder.** The kit never assumes where data lives or how files are named. `scan` opens each capture
and reads the packets themselves to learn the exchange, protocol and start time. So when the professor adds a new
data folder, point `roots` at it (or leave `roots = auto`) and the same steps work. Files may be `.pcap.zst`,
`.pcap.gz` or plain `.pcap`.

Works on its own, and works even better with an AI agent (Claude Code, Gemini, Copilot, Codex): the agent asks
you what you want, fills in `prefs.ini`, shows you the plan, and runs it. See
[fin556-claude-vm-guide](https://github.com/vermasidd1502/fin556-claude-vm-guide) to set up an agent on the VM.

> **Status:** tested end to end on made-up captures (`test/make_fake_pcaps.py`); testing on the real course data is in progress.

> **Disclaimer:** shared by a student as a starting point. Use at your own risk. You are responsible for following
> the course and data rules. The exchange data is licensed for coursework: this repo holds **code only**, never data.

## What it does
| Step | Command | What happens |
|---|---|---|
| Find | `python3 kit.py scan` | C++ `pcap_scan` walks the data folders (read-only; `roots = auto` tries the usual ones), opens the first MB of each capture and writes `catalog.tsv`: venue, protocol (Nasdaq ITCH, CME MDP3, IEX-TP), date, first packet time, size, UDP ports. Every later step picks files from this catalog. |
| Choose | `python3 kit.py ask` | A few questions → `prefs.ini`. Or edit the file, or let your agent fill it. |
| Plan | `python3 kit.py plan` | Day by day: which files exist, which days are missing, a disk estimate against free space, and the exact commands. |
| Pull | `python3 kit.py run` | C++ parsers through a job queue (max 32 threads). Temporary files are deleted after each day; it stops if the disk gets low. |

Supported now: **Nasdaq TotalView-ITCH** (stocks, ETFs) and **CME MDP3** (futures, by SecurityID).
IEX files are found and listed by `scan` and `plan`; extracting them is not built yet.

## Quick start (on the VM, in a terminal)
1. Upload `pcapkit.zip` through Guacamole (Ctrl+Alt+Shift → Devices → Upload), then:
```bash
mkdir -p ~/myproject && cd ~/myproject && unzip -o ~/pcapkit.zip && rm ~/pcapkit.zip && cd pcapkit && bash build.sh
```
2. See what data exists:
```bash
python3 kit.py scan
```
3. Say what you want, check the plan, pull it:
```bash
python3 kit.py ask
```
```bash
python3 kit.py plan
```
```bash
python3 kit.py run
```
Needs `g++` and Python 3.9+ with `pandas` (in your own virtual environment). No sudo, no network.

## prefs.ini (the important lines)
```ini
[data]
roots = auto                              # or: /db_pcaps, /path/to/a/new/drop
[request]
venues = nasdaq, cme
symbols = QQQ, TQQQ, SQQQ                 # or a file: symbols.txt
cme_instruments = NQH5=42288528, NQM5=42005804@20250317
from = 20250203
to = 20250207
weekdays = mon, tue, wed, thu, fri
start = 18:00                             # New York time
end = 20:00
[output]
bars = 1, 5                               # minutes
ticks = yes
```
The course CME captures carry no instrument definitions, so futures are picked by SecurityID, and the id changes at
each quarterly roll (`@first_date`). Find ids with `python3 kit.py discover-cme --date YYYYMMDD`.

## Output
- `bars_<N>min_<date>_<HHMM-HHMM>.txt`: `Date|Time|Symbol|Open|High|Low|Close|Volume|Trades|VWAP|Bid|Ask|Mid`
- `ticks_<date>_<HHMM-HHMM>.txt.gz`: every quote change and trade, nanosecond timestamps, venue, aggressor side.
  Nasdaq trades include executions against hidden orders.

## How it is built (HFT rules)
- C++ for all heavy work. No thread does both reading and writing: readers → queues → one writer.
- A simple single-threaded parser stays in the kit as the reference; the fast ones must match it byte for byte
  (`engine/bench_v3.sh`).
- Job queue capped at 32 threads. Disk checked before and during every run.
- Read-only on the data folders. Only your output folder is written.

## Files
| File | What it is |
|---|---|
| `kit.py` | scan / ask / plan / run / discover-cme / clean |
| `pcap_scan.cpp` | multithreaded capture finder (zstd, gzip, plain pcap) |
| `prefs.ini` | your request |
| `AGENTS.md`, `CLAUDE.md` | rules for an AI agent driving the kit |
| `engine/` | the C++ parsers (ITCH, MDP3: v1 reference, v2, v3) and helpers |
| `test/make_fake_pcaps.py` | builds made-up captures to test the kit without real data |
