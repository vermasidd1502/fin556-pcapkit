#!/usr/bin/env python3
"""fast_feed.py - decompress .pcap.zst files and pipe them (in the order given) into itch_fast / mdp3_fast.

  python3 fast_feed.py ./itch_fast --symbols QQQ,TQQQ,SQQQ --out out/raw/xnas_20250203 -- file1.pcap.zst file2.pcap.zst ...
  python3 fast_feed.py ./mdp3_fast --secids NQH5=42288528 --display-factor 0.01 --out out/raw/glbx_20250203 -- files...

Everything before `--` is the command line of the C++ program, everything after is the input files.
Nothing is written to disk except the program's own output, and nothing touches the network.
"""
import os
import subprocess
import sys


def main():
    if "--" not in sys.argv:
        sys.exit(__doc__)
    i = sys.argv.index("--")
    cmd, files = sys.argv[1:i], sys.argv[i + 1:]
    if os.path.basename(cmd[0])[-1:] in ("2", "3"):
        # v2/v3 parsers (itch_fast2/3, mdp3_fast2/3) mmap + decompress the files themselves on their own reader thread
        os.execv(cmd[0], cmd + ["--"] + files)
    import zstandard
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE)
    try:
        for fi, path in enumerate(files, 1):
            with open(path, "rb", buffering=1 << 20) as fh:
                r = zstandard.ZstdDecompressor().stream_reader(fh, read_across_frames=True)
                while True:
                    chunk = r.read(1 << 23)
                    if not chunk:
                        break
                    p.stdin.write(chunk)
            print(f"  fast_feed: fed file {fi}/{len(files)}", file=sys.stderr, flush=True)
        p.stdin.close()
    except BrokenPipeError:
        pass  # the program exited early; its exit code below says why
    sys.exit(p.wait())


if __name__ == "__main__":
    main()
