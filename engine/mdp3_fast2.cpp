// mdp3_fast2.cpp - THIS IS HFT! NOT SHEEPLE CODING!!!
// CME MDP 3.0 (Globex) parser, v2: same logic and byte-identical output as mdp3_fast (v1), on the
// 3-thread pipeline in pipeline.hpp: reader (mmap + in-process zstd) -> parser -> writer.
//
// Build: g++ -O3 -march=native -std=c++17 -pthread -o mdp3_fast2 mdp3_fast2.cpp -l:libzstd.so.1
// Run  : ./mdp3_fast2 --secids NQM5=42005804 --display-factor 0.01 --depth 1 --out out/raw/glbx_20250402 [--pin r,p,w] -- files...
#include <algorithm>
#include <charconv>
#include <chrono>
#include <unordered_map>

#include "pipeline.hpp"

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

struct Out : hft::Out {
    void i(i64 v) { char t[24]; auto r = std::to_chars(t, t + 24, v); add(t, (size_t)(r.ptr - t)); }
    void u(u64 v) { char t[24]; auto r = std::to_chars(t, t + 24, v); add(t, (size_t)(r.ptr - t)); }
    void ch(char c) { push_back(c); }
    void str(const std::string &s) { add(s.data(), s.size()); }
};

struct Lvl { i64 px; i32 sz, ct; };
struct Bk {
    std::string sym;
    std::vector<Lvl> bid, ask;
    bool has_last = false;
    std::vector<Lvl> lastb, lasta;
};

static void apply_level(std::vector<Lvl> &side, int act, int lvl, i64 px, i32 sz, i32 ct) {
    long i = lvl - 1;
    long n = (long)side.size();
    if (act == 0) {  // New: insert at level, deeper levels shift down
        if (i < 0) i = 0;
        if (i > n) i = n;
        side.insert(side.begin() + i, Lvl{px, sz, ct});
        if (side.size() > MAXD) side.resize(MAXD);
    } else if (act == 1 || act == 5) {  // Change / Overlay
        if (i >= 0 && i < n) side[i] = Lvl{px, sz, ct};
        else if (i == n) side.push_back(Lvl{px, sz, ct});
    } else if (act == 2) {  // Delete: deeper levels shift up
        if (i >= 0 && i < n) side.erase(side.begin() + i);
    } else if (act == 3) {
        side.clear();
    } else if (act == 4) {  // DeleteFrom: levels 1..lvl
        long k = std::min<long>(lvl, n);
        if (k > 0) side.erase(side.begin(), side.begin() + k);
    }
}

struct Parser {
    std::vector<Bk> books;
    std::unordered_map<i32, int> by_id;
    std::unordered_map<i32, u32> last_rpt;
    Out bbo, trd;
    int depth = 1;
    double scale = 1.0;
    u64 n_msgs = 0, bad_frame = 0, bad_book = 0, bad_trade = 0, dup_entries = 0, other_schema = 0, tc46 = 0, tc48 = 0;
    std::vector<Lvl> kb, ka;   // scratch, reused (no allocation per update)

    void price(Out &o, i64 v) {  // PRICE9 mantissa * 1e-9 * display factor, 8 decimals; empty when 0
        if (!v) return;
        char t[48];
        int n = snprintf(t, sizeof t, "%.8f", (double)v / 1e9 * scale);
        o.add(t, (size_t)n);
    }

    static void key(const Bk &b, int depth, std::vector<Lvl> &kb, std::vector<Lvl> &ka) {
        kb.assign(depth, Lvl{0, 0, 0});
        ka.assign(depth, Lvl{0, 0, 0});
        for (int i = 0; i < depth; i++) {
            if (i < (int)b.bid.size()) kb[i] = b.bid[i];
            if (i < (int)b.ask.size()) ka[i] = b.ask[i];
        }
    }
    static bool same(const std::vector<Lvl> &a, const std::vector<Lvl> &b) {
        for (size_t i = 0; i < a.size(); i++)
            if (a[i].px != b[i].px || a[i].sz != b[i].sz || a[i].ct != b[i].ct) return false;
        return true;
    }

    void emit_bbo(Bk &b, u64 ts_recv, u64 ts_ev, u8 flags) {
        key(b, depth, kb, ka);
        if (b.has_last && same(kb, b.lastb) && same(ka, b.lasta)) return;
        b.has_last = true;
        b.lastb = kb;
        b.lasta = ka;
        bbo.u(ts_recv); bbo.ch(','); bbo.u(ts_ev); bbo.ch(','); bbo.u(flags); bbo.ch(','); bbo.str(b.sym);
        for (int i = 0; i < depth; i++) {
            bbo.ch(','); price(bbo, kb[i].px); bbo.ch(','); bbo.i(kb[i].sz); bbo.ch(','); bbo.i(kb[i].ct);
            bbo.ch(','); price(bbo, ka[i].px); bbo.ch(','); bbo.i(ka[i].sz); bbo.ch(','); bbo.i(ka[i].ct);
        }
        bbo.ch('\n');
        bbo.rows++;
        bbo.check();
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
            auto it = by_id.find(sid);
            if (it == by_id.end()) continue;
            u32 rpt = le32(pl + off + 16);
            auto lr = last_rpt.find(sid);
            if (lr != last_rpt.end() && rpt <= lr->second && lr->second - rpt < 1000000u) { dup_entries++; continue; }
            last_rpt[sid] = rpt;
            Bk &b = books[it->second];
            u8 typ = pl[off + 26];
            bool hit = false;
            if (typ == 48 || typ == 49) {  // '0' bid, '1' offer
                i64 px = (i64)le64(pl + off);
                i32 sz = (i32)le32(pl + off + 8), ct = (i32)le32(pl + off + 20);
                apply_level(typ == 48 ? b.bid : b.ask, pl[off + 25], pl[off + 24], px == NULL_PX ? 0 : px, sz == NULL_I32 ? 0 : sz,
                            ct == NULL_I32 ? 0 : ct);
                hit = true;
            } else if (typ == 74) {  // 'J' empty book
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
        for (int j = 0; j < nt; j++) emit_bbo(books[touched[j]], ts_recv, ts_ev, flags);
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
            auto it = by_id.find(sid);
            if (it == by_id.end()) continue;
            u32 rpt = le32(pl + off + 16);
            auto lr = last_rpt.find(sid);
            if (lr != last_rpt.end() && rpt <= lr->second && lr->second - rpt < 1000000u) { dup_entries++; continue; }
            last_rpt[sid] = rpt;
            u8 ag = pl[off + 24];
            trd.u(ts_recv); trd.ch(','); trd.u(ts_ev); trd.ch(','); trd.u(flags); trd.ch(','); trd.str(books[it->second].sym); trd.ch(',');
            price(trd, (i64)le64(pl + off)); trd.ch(','); trd.i((i32)le32(pl + off + 8)); trd.ch(',');
            if (ag == 1) trd.ch('B'); else if (ag == 2) trd.ch('S');
            trd.ch(','); trd.i((i32)le32(pl + off + 20)); trd.ch(','); trd.u(rpt); trd.ch(','); trd.u(pl[off + 25]); trd.ch('\n');
            trd.rows++;
            trd.check();
        }
    }

    void packet(u64 ts_recv, const u8 *pl, size_t n) {
        if (n < 12) return;
        if (n >= 22 && le16(pl + 18) != 1) { other_schema++; return; }  // first message's SchemaID: 1 = MDP 3.0 core
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
    int port = 0, pin_r = -1, pin_p = -1, pin_w = -1;
    std::vector<std::string> files;
    static Parser P;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--secids" && i + 1 < argc) secids = argv[++i];
        else if (a == "--out" && i + 1 < argc) out = argv[++i];
        else if (a == "--depth" && i + 1 < argc) P.depth = atoi(argv[++i]);
        else if (a == "--display-factor" && i + 1 < argc) P.scale = atof(argv[++i]);
        else if (a == "--port" && i + 1 < argc) port = atoi(argv[++i]);
        else if (a == "--pin" && i + 1 < argc) hft::parse_pin(argv[++i], pin_r, pin_p, pin_w);
        else if (a == "--") { for (int j = i + 1; j < argc; j++) files.push_back(argv[j]); break; }
        else { fprintf(stderr, "usage: mdp3_fast2 --secids NQM5=42005804[,SYM=id] --display-factor 0.01 --depth 1 --out base [--port N] [--pin r,p,w] [-- files...]\n"); return 1; }
    }
    if (P.depth < 1 || P.depth > 10) { fprintf(stderr, "--depth must be 1..10\n"); return 1; }
    {
        size_t s = 0;
        while (s < secids.size()) {
            size_t e = secids.find(',', s);
            if (e == std::string::npos) e = secids.size();
            std::string item = secids.substr(s, e - s);
            size_t q = item.find('=');
            if (q != std::string::npos) {
                Bk b;
                b.sym = item.substr(0, q);
                for (auto &c : b.sym) c = (char)toupper(c);
                P.by_id[(i32)atoi(item.c_str() + q + 1)] = (int)P.books.size();
                P.books.push_back(b);
            }
            s = e + 1;
        }
    }
    if (P.books.empty()) { fprintf(stderr, "need --secids SYMBOL=id\n"); return 1; }
    std::string hb = "ts_recv_ns,ts_event_ns,flags,symbol";
    for (int i = 0; i < P.depth; i++) {
        char t[128];
        snprintf(t, sizeof t, ",bid_px_%02d,bid_sz_%02d,bid_ct_%02d,ask_px_%02d,ask_sz_%02d,ask_ct_%02d", i, i, i, i, i, i);
        hb += t;
    }
    hft::Writer wr(pin_w);
    P.bbo.open(wr, out + "_bbo.csv", hb + "\n");
    P.trd.open(wr, out + "_trades.csv", "ts_recv_ns,ts_event_ns,flags,symbol,price,size,aggressor,num_orders,rpt_seq,action\n");
    hft::Reader rd(files, pin_r);
    wr.start();
    rd.start();
    hft::pin_this_thread(pin_p);
    hft::Stream in(rd.ch);

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
        if (!have_hdr) { fprintf(stderr, "input is not a classic pcap stream (use mdp3_parse.py for pcapng)\n"); _exit(3); }
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
                fprintf(stderr, "  ... mdp3_fast2: %llu packets, file %llu, %.0fs elapsed\n", (unsigned long long)npk, (unsigned long long)nfiles,
                        std::chrono::duration<double>(now - t0).count());
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
        if (port && be16(d + udp + 2) != port) continue;
        size_t ulen = be16(d + udp + 4);
        size_t plen = ulen >= 8 ? std::min(ulen - 8, n - udp - 8) : 0;
        P.packet(ts, d + udp + 8, plen);
    }
    in.drain();
    P.bbo.close();
    P.trd.close();
    wr.finish();
    rd.join();
    double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    fprintf(stderr, "mdp3_fast2: %llu files, %llu packets in %.1fs; messages=%llu (book46=%llu trade48=%llu)\n", (unsigned long long)nfiles,
            (unsigned long long)npk, secs, (unsigned long long)P.n_msgs, (unsigned long long)P.tc46, (unsigned long long)P.tc48);
    fprintf(stderr, "  other_schema_packets=%llu bad_frame=%llu bad_book=%llu bad_trade=%llu dup_entries=%llu non_udp=%llu unsupported_link=%llu truncated=%llu\n",
            (unsigned long long)P.other_schema, (unsigned long long)P.bad_frame, (unsigned long long)P.bad_book, (unsigned long long)P.bad_trade,
            (unsigned long long)P.dup_entries, (unsigned long long)non_udp, (unsigned long long)unsupported, (unsigned long long)trunc);
    fprintf(stderr, "wrote %llu bbo rows, %llu trade rows -> %s_bbo.csv / %s_trades.csv\n", (unsigned long long)P.bbo.rows,
            (unsigned long long)P.trd.rows, out.c_str(), out.c_str());
    return 0;
}
