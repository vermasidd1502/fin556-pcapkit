// mdp3_fast3.cpp - THIS IS HFT! NOT SHEEPLE CODING!!!
// CME MDP 3.0 (Globex), v3: same output as mdp3_fast (v1), byte for byte, multi-channel and many threads:
//   K readers (parallel decompression) -> dispatcher (pcap/UDP, routes each packet by CME channel)
//   -> S channel shards (SBE decode + books, channels split across shards) -> merger -> writer.
// Channel key = UDP port % 1000, so a channel's A feed (14xxx) and B feed (15xxx) land on the same shard and
// RptSeq de-duplication still works.
//
// Build: g++ -O3 -march=native -std=c++17 -pthread -o mdp3_fast3 mdp3_fast3.cpp -l:libzstd.so.1
// Run  : ./mdp3_fast3 --secids NQM5=42005804 --display-factor 0.01 --depth 1 --out out/raw/glbx_20250402 [--threads 16] -- files...
#include <chrono>
#include <unordered_map>

#include "pipeline3.hpp"

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int32_t i32;
typedef int64_t i64;

static inline u16 be16(const u8 *p) { return (u16)(p[0] << 8 | p[1]); }
static inline u32 le16(const u8 *p) { return (u32)(p[0] | p[1] << 8); }
static inline u32 le32(const u8 *p) { return (u32)p[0] | (u32)p[1] << 8 | (u32)p[2] << 16 | (u32)p[3] << 24; }
static inline u64 le64(const u8 *p) { return (u64)le32(p) | (u64)le32(p + 4) << 32; }

static const i32 NULL_I32 = 2147483647;
static const i64 NULL_PX = 9223372036854775807LL;
static const size_t MAXD = 10;

static std::vector<std::string> g_syms;
static std::unordered_map<i32, int> g_by_id;
static int g_depth = 1;
static double g_scale = 1.0;

struct Lvl { i64 px; i32 sz, ct; };
struct Bk {
    std::vector<Lvl> bid, ask;
    bool has_last = false;
    std::vector<Lvl> lastb, lasta;
};

static void apply_level(std::vector<Lvl> &side, int act, int lvl, i64 px, i32 sz, i32 ct) {
    long i = lvl - 1;
    long n = (long)side.size();
    if (act == 0) {
        if (i < 0) i = 0;
        if (i > n) i = n;
        side.insert(side.begin() + i, Lvl{px, sz, ct});
        if (side.size() > MAXD) side.resize(MAXD);
    } else if (act == 1 || act == 5) {
        if (i >= 0 && i < n) side[i] = Lvl{px, sz, ct};
        else if (i == n) side.push_back(Lvl{px, sz, ct});
    } else if (act == 2) {
        if (i >= 0 && i < n) side.erase(side.begin() + i);
    } else if (act == 3) {
        side.clear();
    } else if (act == 4) {
        long k = std::min<long>(lvl, n);
        if (k > 0) side.erase(side.begin(), side.begin() + k);
    }
}

// ------------------------------------------------------------------ shard: v1 decode + book logic for its channels
struct CmeShard {
    hft3::ShardOut out[2];   // 0 = bbo, 1 = trades
    std::vector<Bk> books;
    std::unordered_map<i32, u32> last_rpt;
    std::vector<Lvl> kb, ka;
    u64 n_msgs = 0, bad_frame = 0, bad_book = 0, bad_trade = 0, dup_entries = 0, other_schema = 0, tc46 = 0, tc48 = 0;
    CmeShard() : books(g_syms.size()) {}

    void price(hft3::ShardOut &o, i64 v) {
        if (!v) return;
        char t[48];
        int n = snprintf(t, sizeof t, "%.8f", (double)v / 1e9 * g_scale);
        o.add(t, (size_t)n);
    }
    void key(const Bk &b) {
        kb.assign(g_depth, Lvl{0, 0, 0});
        ka.assign(g_depth, Lvl{0, 0, 0});
        for (int i = 0; i < g_depth; i++) {
            if (i < (int)b.bid.size()) kb[i] = b.bid[i];
            if (i < (int)b.ask.size()) ka[i] = b.ask[i];
        }
    }
    static bool same(const std::vector<Lvl> &a, const std::vector<Lvl> &b) {
        for (size_t i = 0; i < a.size(); i++)
            if (a[i].px != b[i].px || a[i].sz != b[i].sz || a[i].ct != b[i].ct) return false;
        return true;
    }
    void emit_bbo(int bi, u64 ts_recv, u64 ts_ev, u8 flags) {
        Bk &b = books[bi];
        key(b);
        if (b.has_last && same(kb, b.lastb) && same(ka, b.lasta)) return;
        b.has_last = true;
        b.lastb = kb;
        b.lasta = ka;
        hft3::ShardOut &o = out[0];
        o.begin_row();
        o.u(ts_recv); o.push_back(','); o.u(ts_ev); o.push_back(','); o.u(flags); o.push_back(','); o.str(g_syms[bi]);
        for (int i = 0; i < g_depth; i++) {
            o.push_back(','); price(o, kb[i].px); o.push_back(','); o.i(kb[i].sz); o.push_back(','); o.i(kb[i].ct);
            o.push_back(','); price(o, ka[i].px); o.push_back(','); o.i(ka[i].sz); o.push_back(','); o.i(ka[i].ct);
        }
        o.push_back('\n');
        o.end_row();
    }
    void book(u64 ts_recv, const u8 *pl, size_t body, size_t bl, size_t end) {
        u64 ts_ev = le64(pl + body);
        u8 flags = pl[body + 8];
        size_t g = body + bl;
        if (g + 3 > end) { bad_book++; return; }
        size_t gbl = le16(pl + g), ne = pl[g + 2], off = g + 3;
        if (gbl < 27 || off + ne * gbl > end) { bad_book++; return; }
        int touched[64];
        int nt = 0;
        for (size_t k = 0; k < ne; k++, off += gbl) {
            i32 sid = (i32)le32(pl + off + 12);
            auto it = g_by_id.find(sid);
            if (it == g_by_id.end()) continue;
            u32 rpt = le32(pl + off + 16);
            auto lr = last_rpt.find(sid);
            if (lr != last_rpt.end() && rpt <= lr->second && lr->second - rpt < 1000000u) { dup_entries++; continue; }
            last_rpt[sid] = rpt;
            Bk &b = books[it->second];
            u8 typ = pl[off + 26];
            bool hit = false;
            if (typ == 48 || typ == 49) {
                i64 px = (i64)le64(pl + off);
                i32 sz = (i32)le32(pl + off + 8), ct = (i32)le32(pl + off + 20);
                apply_level(typ == 48 ? b.bid : b.ask, pl[off + 25], pl[off + 24], px == NULL_PX ? 0 : px, sz == NULL_I32 ? 0 : sz,
                            ct == NULL_I32 ? 0 : ct);
                hit = true;
            } else if (typ == 74) {
                b.bid.clear();
                b.ask.clear();
                hit = true;
            }
            if (hit) {
                bool have = false;
                for (int j = 0; j < nt; j++) if (touched[j] == it->second) have = true;
                if (!have && nt < 64) touched[nt++] = it->second;
            }
        }
        for (int j = 0; j < nt; j++) emit_bbo(touched[j], ts_recv, ts_ev, flags);
    }
    void trades(u64 ts_recv, const u8 *pl, size_t body, size_t bl, size_t end) {
        u64 ts_ev = le64(pl + body);
        u8 flags = pl[body + 8];
        size_t g = body + bl;
        if (g + 3 > end) { bad_trade++; return; }
        size_t gbl = le16(pl + g), ne = pl[g + 2], off = g + 3;
        if (gbl < 26 || off + ne * gbl > end) { bad_trade++; return; }
        for (size_t k = 0; k < ne; k++, off += gbl) {
            i32 sid = (i32)le32(pl + off + 12);
            auto it = g_by_id.find(sid);
            if (it == g_by_id.end()) continue;
            u32 rpt = le32(pl + off + 16);
            auto lr = last_rpt.find(sid);
            if (lr != last_rpt.end() && rpt <= lr->second && lr->second - rpt < 1000000u) { dup_entries++; continue; }
            last_rpt[sid] = rpt;
            u8 ag = pl[off + 24];
            hft3::ShardOut &o = out[1];
            o.begin_row();
            o.u(ts_recv); o.push_back(','); o.u(ts_ev); o.push_back(','); o.u(flags); o.push_back(','); o.str(g_syms[it->second]); o.push_back(',');
            price(o, (i64)le64(pl + off)); o.push_back(','); o.i((i32)le32(pl + off + 8)); o.push_back(',');
            if (ag == 1) o.push_back('B'); else if (ag == 2) o.push_back('S');
            o.push_back(','); o.i((i32)le32(pl + off + 20)); o.push_back(','); o.u(rpt); o.push_back(','); o.u(pl[off + 25]); o.push_back('\n');
            o.end_row();
        }
    }
    void handle(u64 ts_recv, const u8 *pl, u32 n) {   // one UDP payload (one MDP3 packet)
        if (n < 12) return;
        if (n >= 22 && le16(pl + 18) != 1) { other_schema++; return; }
        size_t pos = 12;
        while (pos + 10 <= n) {
            size_t sz = le16(pl + pos);
            if (sz < 10 || pos + sz > n) { bad_frame++; break; }
            size_t bl = le16(pl + pos + 2), tid = le16(pl + pos + 4), body = pos + 10, end = pos + sz;
            pos = end;
            n_msgs++;
            if (tid == 46) { tc46++; book(ts_recv, pl, body, bl, end); }
            else if (tid == 48) { tc48++; trades(ts_recv, pl, body, bl, end); }
        }
    }
};

static bool is_magic(const u8 *p, bool &le, bool &nano) {
    static const u8 M[4][4] = {{0xd4, 0xc3, 0xb2, 0xa1}, {0xa1, 0xb2, 0xc3, 0xd4}, {0x4d, 0x3c, 0xb2, 0xa1}, {0xa1, 0xb2, 0x3c, 0x4d}};
    for (int i = 0; i < 4; i++)
        if (!memcmp(p, M[i], 4)) { le = (i == 0 || i == 2); nano = (i >= 2); return true; }
    return false;
}

int main(int argc, char **argv) {
    std::string secids, out = "out";
    int port = 0, threads = 16;
    std::vector<std::string> files;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--secids" && i + 1 < argc) secids = argv[++i];
        else if (a == "--out" && i + 1 < argc) out = argv[++i];
        else if (a == "--depth" && i + 1 < argc) g_depth = atoi(argv[++i]);
        else if (a == "--display-factor" && i + 1 < argc) g_scale = atof(argv[++i]);
        else if (a == "--port" && i + 1 < argc) port = atoi(argv[++i]);
        else if (a == "--threads" && i + 1 < argc) threads = atoi(argv[++i]);
        else if (a == "--pin" && i + 1 < argc) ++i;
        else if (a == "--") { for (int j = i + 1; j < argc; j++) files.push_back(argv[j]); break; }
        else { fprintf(stderr, "usage: mdp3_fast3 --secids NQM5=42005804 --display-factor 0.01 --depth 1 --out base [--port N] [--threads 16] -- files...\n"); return 1; }
    }
    if (files.empty()) { fprintf(stderr, "mdp3_fast3 reads files only: pass them after --\n"); return 1; }
    if (g_depth < 1 || g_depth > 10) { fprintf(stderr, "--depth must be 1..10\n"); return 1; }
    {
        size_t s = 0;
        while (s < secids.size()) {
            size_t e = secids.find(',', s);
            if (e == std::string::npos) e = secids.size();
            std::string item = secids.substr(s, e - s);
            size_t q = item.find('=');
            if (q != std::string::npos) {
                std::string sym = item.substr(0, q);
                for (auto &c : sym) c = (char)toupper(c);
                g_by_id[(i32)atoi(item.c_str() + q + 1)] = (int)g_syms.size();
                g_syms.push_back(sym);
            }
            s = e + 1;
        }
    }
    if (g_syms.empty()) { fprintf(stderr, "need --secids SYMBOL=id\n"); return 1; }
    threads = std::max(6, std::min(32, threads));
    int K = std::max(2, std::min(8, threads / 4));
    int S = std::max(1, std::min(threads - K - 3, 12));

    std::string hb = "ts_recv_ns,ts_event_ns,flags,symbol";
    for (int i = 0; i < g_depth; i++) {
        char t[128];
        snprintf(t, sizeof t, ",bid_px_%02d,bid_sz_%02d,bid_ct_%02d,ask_px_%02d,ask_sz_%02d,ask_ct_%02d", i, i, i, i, i, i);
        hb += t;
    }
    hft::Writer wr(-1);
    hft::Out bbo, trd;
    bbo.open(wr, out + "_bbo.csv", hb + "\n");
    trd.open(wr, out + "_trades.csv", "ts_recv_ns,ts_event_ns,flags,symbol,price,size,aggressor,num_orders,rpt_seq,action\n");

    hft3::Sharder sharder(S, 4u << 20, 16384);
    std::vector<std::unique_ptr<hft3::Shard<CmeShard>>> shards;
    hft3::Merger merger;
    merger.final_[0] = &bbo;
    merger.final_[1] = &trd;
    for (int s = 0; s < S; s++) {
        shards.emplace_back(new hft3::Shard<CmeShard>());
        merger.outs.push_back(&shards.back()->out_ch);
    }
    hft3::ReaderPool rp(files, K);
    wr.start();
    merger.start();
    for (int s = 0; s < S; s++) shards[s]->start(sharder.lanes[s].get());
    rp.start();
    fprintf(stderr, "mdp3_fast3: %zu files, threads: %d readers + 1 dispatcher + %d channel shards + 1 merger + 1 writer\n", files.size(), rp.K, S);

    hft3::MultiStream in(rp);
    int chan_shard[1000];
    for (int &c : chan_shard) c = -1;
    int next_shard = 0, nchan = 0;
    u64 pseq = 0;
    bool le = true, nano = false, have_hdr = false;
    u32 network = 1;
    u64 npk = 0, nfiles = 0, non_udp = 0, unsupported = 0, trunc = 0;
    auto t0 = std::chrono::steady_clock::now(), tl = t0;
    auto rd32 = [&](const u8 *p) -> u32 { return le ? le32(p) : (u32)p[0] << 24 | (u32)p[1] << 16 | (u32)p[2] << 8 | p[3]; };
    for (;;) {
        const u8 *m4 = in.peek(4);
        if (!m4) break;
        bool l2, n2;
        if (is_magic(m4, l2, n2)) {
            const u8 *fh = in.peek(24);
            if (!fh) break;
            le = l2; nano = n2;
            network = rd32(fh + 20) & 0x0FFFFFFF;
            in.consume(24);
            have_hdr = true;
            nfiles++;
            continue;
        }
        if (!have_hdr) { fprintf(stderr, "input is not a classic pcap stream\n"); _exit(3); }
        const u8 *h = in.peek(16);
        if (!h) break;
        u32 sec = rd32(h), frac = rd32(h + 4), incl = rd32(h + 8);
        if (incl > (1u << 20)) { fprintf(stderr, "corrupt record length %u\n", incl); _exit(4); }
        h = in.peek(16 + (size_t)incl);
        if (!h) { trunc = 1; break; }
        const u8 *d = h + 16;
        in.consume(16 + (size_t)incl);
        u64 ts = (u64)sec * 1000000000ull + (nano ? frac : (u64)frac * 1000);
        npk++;
        if ((npk & 0xFFFFF) == 0) {
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration<double>(now - tl).count() > 20) {
                tl = now;
                fprintf(stderr, "  ... mdp3_fast3: %llu packets, %zu/%zu files done, %d channels, %.0fs elapsed\n", (unsigned long long)npk,
                        in.files_done(), files.size(), nchan, std::chrono::duration<double>(now - t0).count());
            }
        }
        size_t n = incl, off, udp;
        u32 et;
        if (network == 1) {
            if (n < 14) { non_udp++; continue; }
            et = be16(d + 12);
            off = 14;
            while ((et == 0x8100 || et == 0x88A8 || et == 0x9100) && n >= off + 4) { et = be16(d + off + 2); off += 4; }
        } else if (network == 113 && n >= 16) { et = be16(d + 14); off = 16; }
        else if (network == 276 && n >= 20) { et = be16(d); off = 20; }
        else if ((network == 101 || network == 12) && n >= 1) { et = (d[0] >> 4 == 4) ? 0x0800 : 0x86DD; off = 0; }
        else { unsupported++; continue; }
        if (et == 0x0800) {
            if (n < off + 20 || d[off + 9] != 17) { non_udp++; continue; }
            if (((d[off + 6] & 0x3F) << 8) | d[off + 7]) { non_udp++; continue; }
            udp = off + (d[off] & 0x0F) * 4;
        } else if (et == 0x86DD) {
            if (n < off + 40 || d[off + 6] != 17) { non_udp++; continue; }
            udp = off + 40;
        } else { non_udp++; continue; }
        if (n < udp + 8) { non_udp++; continue; }
        u16 dport = be16(d + udp + 2);
        if (port && dport % 1000 != port % 1000) continue;   // keep both A and B feeds of the channel
        size_t ulen = be16(d + udp + 4);
        size_t plen = ulen >= 8 ? std::min(ulen - 8, n - udp - 8) : 0;
        int key = dport % 1000;
        if (chan_shard[key] < 0) { chan_shard[key] = next_shard++ % S; nchan++; }
        sharder.put(chan_shard[key], pseq++, ts, d + udp + 8, (u32)plen);
    }
    in.drain();
    sharder.finish();
    for (auto &s : shards) s->th.join();
    merger.th.join();
    bbo.close();
    trd.close();
    wr.finish();
    rp.join();
    u64 msgs = 0, b46 = 0, t48 = 0, osch = 0, bf = 0, bb = 0, bt = 0, dup = 0;
    for (auto &s : shards) {
        CmeShard &p = s->proc;
        msgs += p.n_msgs; b46 += p.tc46; t48 += p.tc48; osch += p.other_schema; bf += p.bad_frame; bb += p.bad_book; bt += p.bad_trade; dup += p.dup_entries;
    }
    double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    fprintf(stderr, "mdp3_fast3: %llu files, %llu packets on %d channels in %.1fs; messages=%llu (book46=%llu trade48=%llu)\n", (unsigned long long)nfiles,
            (unsigned long long)npk, nchan, secs, (unsigned long long)msgs, (unsigned long long)b46, (unsigned long long)t48);
    fprintf(stderr, "  other_schema_packets=%llu bad_frame=%llu bad_book=%llu bad_trade=%llu dup_entries=%llu non_udp=%llu unsupported_link=%llu truncated=%llu\n",
            (unsigned long long)osch, (unsigned long long)bf, (unsigned long long)bb, (unsigned long long)bt, (unsigned long long)dup,
            (unsigned long long)non_udp, (unsigned long long)unsupported, (unsigned long long)trunc);
    fprintf(stderr, "wrote %llu bbo rows, %llu trade rows -> %s_bbo.csv / %s_trades.csv\n", (unsigned long long)merger.rows[0],
            (unsigned long long)merger.rows[1], out.c_str(), out.c_str());
    return 0;
}
