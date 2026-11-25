# pcapkit: fast, disk-safe market-data extraction for the FIN 556 lab VM

C++ parsers and Python orchestration that turn raw exchange packet captures (**Nasdaq TotalView-ITCH 5.0**,
**CME MDP 3.0**, **IEX DEEP 1.0**) into compact, analysis-ready Parquet: order-book-derived quotes, trades, CME
depth, Nasdaq auction imbalance, cross prints and attributed orders, with nanosecond timestamps kept separate by source.

Built for FIN 556 (Algorithmic Market Microstructure, UIUC) by team 8. **Code only, no market data.** The exchange
data is licensed for coursework and never leaves approved storage.

---

## Contents
- [What it produces](#what-it-produces)
- [How it works](#how-it-works)
- [Quick start](#quick-start-on-the-lab-vm)
- [Running the full pull](#running-the-full-pull-unattended)
- [Output tables](#output-tables)
- [Timestamps](#timestamps)
- [Performance](#performance)
- [Design notes](#design-notes)
- [Limitations and known gaps](#limitations-and-known-gaps)
- [Repository layout](#repository-layout)
- [Data and usage rules](#data-and-usage-rules)

---

## What it produces
For each trading day (default window 04:00-20:00 ET), one Parquet file per table, zstd-compressed:

| Venue | What is extracted |
|---|---|
| **Nasdaq ITCH** | Best bid/offer rebuilt from the full market-by-order book (from the start of the day), all trades with the hidden-execution flag, Net Order Imbalance (NOII) messages, opening/closing/halt cross prints, and every **attributed add order with its market participant ID (MPID)** |
| **CME MDP3** | Top of book + **10 price levels** for every requested contract, all trades (aggressor side, number of orders), **TransactTime and packet SendingTime** |
| **IEX DEEP** | Quotes, trades, full price-level depth and IEX auction information |

Default universe: **148 Nasdaq symbols** (the 101 Nasdaq-100 securities as of Q1 2025, QQQ/TQQQ/SQQQ and leveraged
single-stock ETFs) plus NQ futures and any other contract on NQ's CME channel (e.g. MNQ, ES, MES, other months).

## How it works
```
 raw captures (.pcap.zst / .pcap.gz)
        |
        |  per venue, per day, in parallel
        v
 +------------------------ C++ parser (one process per feed) ------------------------+
 |  K reader threads        dispatcher            book shards        merger   writer |
 |  (mmap / large blocks,   (UDP/channel filter,  (rebuild books,    (restore  (big  |
 |   in-process zstd)  -->   symbol filter)   -->  emit BBO/trades) -> order) -> I/O) |
 |            lock-free single-producer/single-consumer rings between stages          |
 +------------------------------------------------------------------------------------+
        |  CSV rows through a named pipe (never written to disk)
        v
 Python (pyarrow): window filter, type conversion, streaming write --> Parquet (zstd)
```

**Filtering happens as early as possible:**
- **CME:** each product group is published on its own multicast channel. `--cme-port` drops every packet not on the
  requested channel **before any decoding** (both A and B feeds of that channel are kept). NQ is on channel 318.
- **Nasdaq:** TotalView publishes all symbols on one channel, so filtering is by the 2-byte *stock locate* in each
  message header (mapped to symbols from the stock directory). Messages for other symbols are dropped undecoded.

**Reading, decoding and writing never share a thread** (system calls stay off the hot path), and the merger
restores exchange order so multi-threaded output is byte-identical to the single-threaded reference parsers
(`itch_fast`, `mdp3_fast`), which serve as the unit test (`engine/bench_v3.sh`).

## Quick start (on the lab VM)
Requirements: `g++` (C++17), Python 3.9+ with `pyarrow` and `zstandard` in your own virtual environment, and
optionally PyPy for the IEX parser. No sudo, no network access needed for parsing.

```bash
cd ~/myproject && git clone https://github.com/vermasidd1502/fin556-pcapkit.git pcapkit && cd pcapkit/engine
bash build.sh && g++ -O3 -std=c++17 -o itch_noii itch_noii.cpp
```

Find the CME channel and the busy contracts on it once (counts and prices only):
```bash
python find_cme_port.py   --secid 42005804 /db_pcaps/glbx_pcaps/20250402/<one regular-hours file>
python find_cme_secids.py --port 14318     /db_pcaps/glbx_pcaps/20250402/<one regular-hours file>
```

Pull one day (dry run first):
```bash
python day_pull.py --from 20250402 --to 20250402 --dry-run
python day_pull.py --from 20250402 --to 20250402 --cme-port 14318 \
    --iex-glob '/md/iex_pcaps/data_feeds_{date}_{date}_IEXTP1_DEEP1.0.pcap.gz' --out-dir ~/myproject/pull_test
```

## Running the full pull (unattended)
`overnight.py` loops over days, runs several in parallel, packs finished days into batches and keeps the shared
disk safe. It is resumable: re-running the same command skips every finished day.

```bash
nohup python overnight.py --from 20250326 --to 20250417 \
    --jobs 8 --cme-threads 32 --cme-port 14318 --extra-secids C111=111,C222=222 \
    --iex-python ~/pypy/bin/pypy3 --iex-glob '/md/iex_pcaps/data_feeds_{date}_{date}_IEXTP1_DEEP1.0.pcap.gz' \
    --remote hold --batch-gb 100 --min-free-gb 1 --work ~/myproject/overnight >> ~/myproject/overnight.log 2>&1 &
```

| Option | Meaning |
|---|---|
| `--jobs N` | days parsed at the same time (default 8; capped by free disk, `--day-gb` = 1.0 GB reserved per day) |
| `--cme-threads` | threads per CME parser (default 32: 8 readers/decompressors + 12 book shards) |
| `--remote hold` | when staging fills, pack it into `ready/batch_NN.tar` and wait until it has been copied off and deleted |
| `--remote <rclone remote>` | alternatively upload each batch with rclone and verify it |
| `--batch-gb` | batch size; with a large value, batches are sized by free disk instead |
| `--min-free-gb` | hard floor: parsers are stopped if free space drops below it |
| `--nq-night` | NQ-only overnight pass (20:00 ET previous evening to 04:00 ET; book built from the 18:00 session open) |

Progress lines only (no data): `grep -E 'start:|ok in|READY|INCOMPLETE|STOP|ALL DONE' ~/myproject/overnight.log`

## Output tables
| File | Rows | Key columns |
|---|---|---|
| `ticks_<day>.parquet` | L1 quote changes and trades, all venues, time-sorted | `ts_recv_ns, ts_event_ns, ts_send_ns, venue (XNAS/GLBX/IEXG), symbol, type (Q/T), bid_px, bid_sz, ask_px, ask_sz, price, size, aggressor, trade_id, kind` (`kind = P`: execution against a hidden order) |
| `cme_depth_<day>.parquet` | every CME book update | levels 2-10: `bid/ask_px_NN, bid/ask_sz_NN, bid/ask_ct_NN` |
| `noii_<day>.parquet` | Nasdaq Net Order Imbalance | `paired, imbalance, direction, far_px, near_px, ref_px, cross_type, pvi` |
| `crosses_<day>.parquet` | official cross prints | `symbol, price, size, cross_type (O/C/H)` |
| `mpid_<day>.parquet` | attributed Nasdaq add orders | `symbol, side, shares, price, mpid, order_ref` |
| `iex_levels_<day>.parquet` | IEX price-level updates | `side, price, size` |
| `iex_auction_<day>.parquet` | IEX auction information | `paired, imbalance, ref/clearing prices, collars` |
| `nq_night_<day>.parquet`, `nq_night_depth_<day>.parquet` | NQ overnight pass | same columns as ticks / cme_depth |

## Timestamps
All times are integer nanoseconds, UTC epoch; **sources are never mixed**:
- `ts_event_ns`: exchange time. Nasdaq ITCH (nanoseconds since New York midnight, converted to UTC), CME
  **TransactTime** (matching engine; identical across all messages of one event), IEX message timestamp.
- `ts_send_ns`: CME packet **SendingTime** (when market data left CME). `ts_send_ns - ts_event_ns` measures
  matching-engine-to-wire delay, which grows with the work an event caused.
- `ts_recv_ns`: capture time at our recording point.

Grouping CME trades by `ts_event_ns` and counting distinct prices identifies single aggressive orders that swept
several price levels.

## Performance
Measured so far:
- `itch_fast3` / `itch_noii`: one busy 10-minute Nasdaq file (1.3 GB compressed, 58 symbols) in **4.4 s**
  (~290 MB/s compressed input) on an Apple M5 laptop; output byte-identical between the two.
- CSV to Parquet (zstd 9): **5.6x** smaller.
- First full day on the VM (before the channel filter and parallel days): ~40 min. Re-measurement with the channel
  filter, parallel days and PyPy is in progress.

Core usage (defaults): each day runs ~27 threads (CME: 8 readers/decompressors + dispatcher + 12 book shards +
merger + writer; Nasdaq parser + decompressor; IEX parser; Parquet writer), and up to 8 days run at once (~215
threads). The earlier version kept ~3 cores busy; the number of parallel days is currently capped by free disk.

Where the time goes: CME captures carry every CME product, so even with the channel filter the files must be read
and decompressed in full; the IEX capture is one file per day. Parallelism is across days and feeds; a single day's
CME is never split, because the order book must run continuously.

## Design notes
- **No temporary CSV on disk.** Parser output goes through named pipes straight into Parquet, so a day's peak disk
  use is its final Parquet size. An earlier version that wrote full CSVs filled the shared disk.
- **Disk safety.** One up-front reservation decides how many days run in parallel (avoids several processes each
  deciding there is room), plus a hard free-space floor checked every few seconds while parsing.
- **Resumable.** A day counts as done only when its `ticks_` file exists; half-finished days are removed on restart.
- **Correctness first.** Single-threaded reference parsers are the unit test; faster versions must match them byte
  for byte on real data before they replace them.

## Limitations and known gaps
- CME books in the main pull start at 04:00 ET rather than the 18:00 session open: top-of-book levels correct within
  seconds, deep levels can be briefly stale (the `--nq-night` pass starts at 18:00).
- Nasdaq output is the best bid/offer derived from the full book, not every price level.
- Volumes are Nasdaq and IEX only (no NYSE/Arca or consolidated tape).
- Some leveraged ETFs are listed outside Nasdaq, so they have no Nasdaq NOII or crosses.
- IEX parser is Python (PyPy recommended); a C++ port is planned if it remains the bottleneck.
- Tested end to end with synthetic captures; the real-data run is in progress.

## Repository layout
```
engine/
  day_pull.py          one day, all feeds -> Parquet (streaming, filters, options above)
  overnight.py         unattended multi-day loop: parallel days, batches, disk safety, resume
  itch_noii.cpp        Nasdaq ITCH parser + NOII + MPID output
  itch_fast3.cpp       multithreaded Nasdaq parser (reference: itch_fast.cpp)
  mdp3_fast3.cpp       multithreaded CME parser with channel filter (reference: mdp3_fast.cpp)
  pipeline*.hpp        lock-free rings, readers, sharder, merger, writer
  iex_parse.py         IEX TOPS 1.6 / DEEP 1.0 parser (pcap/pcapng, .gz/.zst)
  find_cme_port.py     which CME channel carries a SecurityID
  find_cme_secids.py   busiest SecurityIDs on a channel
  fast_feed.py, ndx_combine.py, build.sh, bench_v3.sh
kit.py, pcap_scan.cpp  earlier capture finder / prefs-driven runner (scan, plan, run)
CLAUDE.md, CLAUDE_team8.md   rules for AI agents operating this kit on the shared VM
test/make_fake_pcaps.py      synthetic captures for testing without licensed data
```

## Data and usage rules
- This repository contains **code only**. Never commit captures, Parquet, CSV or logs (`.gitignore` blocks them).
- The exchange data is licensed for coursework: keep it on the VM or in approved university storage.
- On the shared VM: work in your own folder, no sudo, keep free disk above the floor, clean up after each run.
- Shared as a starting point by FIN 556 students. Use at your own risk; you are responsible for following the
  course and data rules. Credit appreciated if you reuse it.
