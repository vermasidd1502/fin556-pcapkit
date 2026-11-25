#!/usr/bin/env python3
"""box_feed.py - stream capture files from a cloud remote (rclone) straight into a parser, nothing saved to disk.

  python3 box_feed.py --rclone ~/rclone --files box:db/xnas_pcaps/20250402/a.pcap.zst,box:... -- ./itch_noii --symbols QQQ --out o

Pipeline (three processes/threads in parallel): `rclone cat` (network) -> zstd decompression (this process) -> the
parser's stdin (C++). Files are fed in the given order as one continuous pcap stream; the parser handles the pcap
header at each file boundary. Exit code = the parser's exit code (non-zero if any download failed).
"""
import argparse
import subprocess
import sys

import zstandard

CHUNK = 1 << 23


def main():
    if "--" not in sys.argv:
        sys.exit(__doc__)
    i = sys.argv.index("--")
    ap = argparse.ArgumentParser()
    ap.add_argument("--rclone", required=True)
    ap.add_argument("--files", required=True, help="comma-separated remote paths, in time order")
    a = ap.parse_args(sys.argv[1:i])
    cmd = sys.argv[i + 1:]
    files = [f for f in a.files.split(",") if f]
    parser = subprocess.Popen(cmd, stdin=subprocess.PIPE)
    failed = False
    try:
        for n, path in enumerate(files, 1):
            # read through the parent folder + exact-name filter: opening a file path directly makes rclone run an
            # upload-permission check, which read-only (viewer) shares refuse with 403
            folder, name = path.rsplit("/", 1)
            dl = subprocess.Popen([a.rclone, "cat", "--retries", "5", "--low-level-retries", "20", folder, "--include", name],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            src = dl.stdout
            if path.endswith(".zst"):
                src = zstandard.ZstdDecompressor().stream_reader(dl.stdout, read_across_frames=True)
            while True:
                c = src.read(CHUNK)
                if not c:
                    break
                parser.stdin.write(c)
            if dl.wait() != 0:
                failed = True
                print(f"  box_feed: download failed for file {n}/{len(files)}: "
                      f"{dl.stderr.read().decode(errors='replace').strip()[-200:]}", file=sys.stderr, flush=True)
                break
            print(f"  box_feed: fed file {n}/{len(files)}", file=sys.stderr, flush=True)
        parser.stdin.close()
    except BrokenPipeError:
        pass                                            # parser exited early; its exit code says why
    rc = parser.wait()
    sys.exit(rc or (3 if failed else 0))


if __name__ == "__main__":
    main()
