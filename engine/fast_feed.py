#!/usr/bin/env python3
"""fast_feed.py - feed capture files (in the order given) into itch_fast* / mdp3_fast*.

  python3 fast_feed.py ./itch_fast3 --symbols QQQ,TQQQ,SQQQ --out out/raw/xnas_20250203 -- file1 file2 ...
  python3 fast_feed.py ./mdp3_fast3 --secids NQH5=42288528 --display-factor 0.01 --out out/raw/glbx_20250203 -- files...

Everything before `--` is the C++ program's command line, everything after is the input files.
Files may be .pcap.zst, .pcap.gz or plain .pcap (detected from their first bytes, not their names).
  - v3 programs read zstd and plain pcap themselves (mmap, own reader threads): handed the files directly.
  - v2 programs read zstd themselves: handed the files directly when every file is zstd.
  - anything else (gzip, mixed): decompressed here on a reader thread and piped into the v1 program, which
    reads stdin; the pipe keeps the reading and the writing on different threads/processes.
Nothing is written to disk except the program's own output, and nothing touches the network.
"""
import gzip
import os
import subprocess
import sys

ZSTD_MAGIC, GZ_MAGIC = b"\x28\xb5\x2f\xfd", b"\x1f\x8b"


def kind(path):
    with open(path, "rb") as f:
        head = f.read(4)
    return "zst" if head == ZSTD_MAGIC else "gz" if head[:2] == GZ_MAGIC else "plain"


def chunks(path, k):
    if k == "zst":
        import zstandard
        with open(path, "rb", buffering=1 << 20) as fh:
            r = zstandard.ZstdDecompressor().stream_reader(fh, read_across_frames=True)
            while True:
                c = r.read(1 << 23)
                if not c:
                    return
                yield c
    else:
        op = gzip.open if k == "gz" else open
        with op(path, "rb") as fh:
            while True:
                c = fh.read(1 << 23)
                if not c:
                    return
                yield c


def main():
    if "--" not in sys.argv:
        sys.exit(__doc__)
    i = sys.argv.index("--")
    cmd, files = sys.argv[1:i], sys.argv[i + 1:]
    kinds = [kind(f) for f in files]
    exe = cmd[0]
    ver = os.path.basename(exe)[-1:]
    if (ver == "3" and all(k in ("zst", "plain") for k in kinds)) or (ver == "2" and all(k == "zst" for k in kinds)):
        os.execv(exe, cmd + ["--"] + files)  # the program decompresses on its own reader thread(s)
    if ver in ("2", "3"):  # fall back to the v1 program that reads a pcap stream on stdin
        v1 = exe[:-1]
        if not os.access(v1, os.X_OK):
            sys.exit(f"{os.path.basename(exe)} can't read {sorted(set(kinds))} files and {os.path.basename(v1)} is not built")
        print(f"  fast_feed: {sorted(set(kinds))} input -> using {os.path.basename(v1)} through a pipe", file=sys.stderr, flush=True)
        cmd = [v1] + cmd[1:]
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE)
    try:
        for fi, (path, k) in enumerate(zip(files, kinds), 1):
            for c in chunks(path, k):
                p.stdin.write(c)
            print(f"  fast_feed: fed file {fi}/{len(files)}", file=sys.stderr, flush=True)
        p.stdin.close()
    except BrokenPipeError:
        pass  # the program exited early; its exit code below says why
    sys.exit(p.wait())


if __name__ == "__main__":
    main()
