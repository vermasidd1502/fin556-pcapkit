#!/usr/bin/env python3
"""make_fake_pcaps.py - build a tiny fake capture tree (Nasdaq ITCH, CME MDP3, IEX-TP) to test pcap_scan.

No real market data: every packet is made up. Usage:  python3 make_fake_pcaps.py <out_dir>
"""
import gzip
import os
import struct
import subprocess
import sys

out = sys.argv[1] if len(sys.argv) > 1 else "fake"


def eth_ip_udp(payload, dport):
    udp = struct.pack(">HHHH", 40000, dport, 8 + len(payload), 0) + payload
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0, bytes([10, 0, 0, 1]), bytes([233, 54, 12, 1]))
    return b"\x01\x00\x5e\x00\x00\x01" + b"\x00\x11\x22\x33\x44\x55" + b"\x08\x00" + ip + udp


def pcap(packets, t0, nano=True):
    g = struct.pack("<IHHiIII", 0xA1B23C4D if nano else 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1)
    body = b""
    for i, p in enumerate(packets):
        ts = t0 + i * 1000
        body += struct.pack("<IIII", ts // 10**9, ts % 10**9, len(p), len(p)) + p
    return g + body


ET_MIDNIGHT_UTC = 5 * 3600  # New York midnight is 05:00 UTC in February (EST)


def itch_packets(n, day_t0):
    """stock directory + adds + executions + a hidden trade, for QQQ and TQQQ, 18:00-19:00 New York."""
    msgs, seq = [], 1
    since_mid = lambda k: (18 * 3600 + k * 3) * 10**9          # ns since New York midnight, one event every 3 s
    for loc, sym in ((1, b"QQQ     "), (2, b"TQQQ    ")):
        r = b"R" + struct.pack(">HH", loc, 0) + (since_mid(0)).to_bytes(6, "big") + sym + b"Q" + b"N" + struct.pack(">I", 100) + b"N" + b"C" + b"  " + b"P" + b"N" + b"N" + b"1" + b"Y" + struct.pack(">I", 1) + b"N"
        msgs.append(r)
    ref = 1000
    for k in range(1, n):
        loc, sym, px = (1, b"QQQ     ", 5000000) if k % 2 else (2, b"TQQQ    ", 800000)
        ts = since_mid(k).to_bytes(6, "big")
        bid = b"A" + struct.pack(">HH", loc, 0) + ts + struct.pack(">Q", ref) + b"B" + struct.pack(">I", 300) + sym + struct.pack(">I", px - 100 + k)
        ask = b"A" + struct.pack(">HH", loc, 0) + ts + struct.pack(">Q", ref + 1) + b"S" + struct.pack(">I", 200) + sym + struct.pack(">I", px + 100 + k)
        exe = b"E" + struct.pack(">HH", loc, 0) + ts + struct.pack(">Q", ref) + struct.pack(">I", 100) + struct.pack(">Q", 900000 + k)
        msgs += [bid, ask, exe]
        if k % 10 == 0:
            msgs.append(b"P" + struct.pack(">HH", loc, 0) + ts + struct.pack(">Q", 0) + b"B" + struct.pack(">I", 50) + sym + struct.pack(">I", px + k) + struct.pack(">Q", 950000 + k))
        ref += 2
    out = []
    for i in range(0, len(msgs), 4):
        chunk = msgs[i:i + 4]
        body = b"".join(struct.pack(">H", len(m)) + m for m in chunk)
        out.append(eth_ip_udp(b"NASDAQ0001" + struct.pack(">QH", seq, len(chunk)) + body, 26477))
        seq += len(chunk)
    return out


def cme_packets(n, t0):
    """MDP3 book updates (template 46) and trades (template 48) for one SecurityID, NQ near 20000.00."""
    out = []
    sid = 42288528
    for i in range(n):
        ts = t0 + 5 * 60 * 10**9 + i * 2 * 10**9
        px = (2000000 + (i % 20)) * 10**9                        # sent 100x too large, like the real feed
        if i % 3 == 2:
            ent = struct.pack("<qiiIiBB", px, 1, sid, 12 + 3 * i, 1, 1, 0) + b"\x00" * 6
            body = struct.pack("<QB2x", ts, 1) + struct.pack("<HB", 32, 1) + ent
            tid = 48
        else:
            b = struct.pack("<qiiIiBBc5x", px - 25 * 10**9, 3, sid, 10 + 3 * i, 2, 1, 1, b"0")
            a = struct.pack("<qiiIiBBc5x", px + 25 * 10**9, 4, sid, 11 + 3 * i, 2, 1, 1, b"1")
            body = struct.pack("<QB2x", ts, 1) + struct.pack("<HB", 32, 2) + b + a
            tid = 46
        msg = struct.pack("<HHHHH", 10 + len(body), 11, tid, 1, 13) + body
        out.append(eth_ip_udp(struct.pack("<IQ", 5000 + i, ts) + msg, 14310))
    return out


def iex_packets(n, t0):
    out = []
    for i in range(n):
        msgs = struct.pack("<H", 10) + b"Q" + b"\x00" * 9
        hdr = struct.pack("<BBHIIHHQQq", 1, 0, 0x8004, 1, 42, len(msgs), 1, i * len(msgs), 1 + i, t0 + i * 1000)
        out.append(eth_ip_udp(hdr + msgs, 10378))
    return out


def write(path, data, comp):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if comp == "zst":
        raw = path[:-4]
        open(raw, "wb").write(data)
        subprocess.run(["zstd", "-q", "-f", "--rm", raw, "-o", path], check=True)
    elif comp == "gz":
        with gzip.open(path, "wb") as f:
            f.write(data)
    else:
        open(path, "wb").write(data)


t0 = 1738623600 * 10**9  # 2025-02-03 23:00 UTC = 18:00 New York
for day, t in (("20250203", t0), ("20250204", t0 + 86400 * 10**9)):
    write(f"{out}/db_pcaps/xnas_pcaps/{day}/xnas-itch-{day}T230000.pcap.zst", pcap(itch_packets(600, t), t), "zst")
    write(f"{out}/db_pcaps/glbx_pcaps/{day}/glbx-mdp3-{day}T230000.pcap.zst", pcap(cme_packets(500, t), t), "zst")
    write(f"{out}/md/iex_pcaps/data_feeds_{day}_{day}_IEXTP1_DEEP1.0.pcap.gz", pcap(iex_packets(500, t), t, nano=False), "gz")
write(f"{out}/db_pcaps/xnas_pcaps/20250205/xnas-itch-20250205T230000.pcap", pcap(itch_packets(50, t0), t0 + 2 * 86400 * 10**9), "none")
write(f"{out}/db_pcaps/readme.txt", b"not a capture", "none")
print("fake capture tree written to", out)
