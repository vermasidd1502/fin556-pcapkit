// itch_fast3.cpp - THIS IS HFT! NOT SHEEPLE CODING!!!
// Nasdaq TotalView-ITCH 5.0, v3: same output as itch_fast (v1), byte for byte, on many threads:
//   K readers (parallel decompression) -> dispatcher (pcap/UDP/MoldUDP64 A/B de-dup, filters to tracked
//   symbols) -> S book shards (symbols split across shards) -> merger (restores v1 row order) -> writer.
//
// Build: g++ -O3 -march=native -std=c++17 -pthread -o itch_fast3 itch_fast3.cpp -l:libzstd.so.1
// Run  : ./itch_fast3 --symbols QQQ,TQQQ,SQQQ --out out/raw/xnas_20250402 [--threads 16] -- files...
//        --threads = total budget (readers + dispatcher + shards + merger + writer), default 16, max 32.
#include <chrono>
#include <map>
#include <unordered_map>

#include "pipeline3.hpp"

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int64_t i64;

static inline u16 be16(const u8 *p) { return (u16)(p[0] << 8 | p[1]); }
static inline u32 be32(const u8 *p) { return (u32)p[0] << 24 | (u32)p[1] << 16 | (u32)p[2] << 8 | p[3]; }
static inline u64 be64(const u8 *p) { return (u64)be32(p) << 32 | be32(p + 4); }
static inline u64 be48(const u8 *p) { return (u64)be16(p) << 32 | be32(p + 2); }

static std::vector<std::string> g_syms;                 // tracked symbols, index = book id
static std::unordered_map<u64, int> g_by8;              // 8-byte space-padded symbol -> book id

static int find_sym(const u8 *p) {
    u64 k;
    memcpy(&k, p, 8);
    auto it = g_by8.find(k);
    return it == g_by8.end() ? -1 : it->second;
}

// ------------------------------------------------------------------ shard: v1 book logic for its symbols
struct Book {
    std::map<u32, i64> bid, ask;
    bool has_last = false;
    u32 lbp = 0, lap = 0;
    i64 lbs = 0, las = 0;
    void add(bool is_bid, u32 px, i64 sz) { (is_bid ? bid : ask)[px] += sz; }
    void remove(bool is_bid, u32 px, i64 sz) {
        auto &d = is_bid ? bid : ask;
        auto it = d.find(px);
        if (it == d.end()) return;
        it->second -= sz;
        if (it->second <= 0) d.erase(it);
    }
    void top(u32 &bp, i64 &bs, u32 &ap, i64 &as) const {
        bp = bid.empty() ? 0 : bid.rbegin()->first;
        bs = bp ? bid.rbegin()->second : 0;
        ap = ask.empty() ? 0 : ask.begin()->first;
        as = ap ? ask.begin()->second : 0;
    }
};
struct Order { int book; bool is_bid; u32 px; i64 sh; };

struct ItchShard {
    hft3::ShardOut out[2];   // 0 = bbo, 1 = trades
    std::vector<Book> books;
    std::unordered_map<u64, Order> orders;
    std::vector<int> bidx;   // per locate: book id (-1 = not tracked), learned from the symbol field
    ItchShard() : books(g_syms.size()), bidx(65536, -2) { orders.reserve(1 << 18); }

    int sym_of(u16 loc, const u8 *sym) {
        if (bidx[loc] != -2) return bidx[loc];
        return bidx[loc] = find_sym(sym);
    }
    void px(hft3::ShardOut &o, u32 p) {
        if (!p) return;
        o.u(p / 10000);
        o.push_back('.');
        u32 fr = p % 10000;
        char t[4] = {(char)('0' + fr / 1000), (char)('0' + fr / 100 % 10), (char)('0' + fr / 10 % 10), (char)('0' + fr % 10)};
        o.add(t, 4);
    }
    void post(int bi, u64 ts_recv, u64 ts) {
        Book &b = books[bi];
        u32 bp, ap;
        i64 bs, as;
        b.top(bp, bs, ap, as);
        if (b.has_last && bp == b.lbp && bs == b.lbs && ap == b.lap && as == b.las) return;
        b.has_last = true; b.lbp = bp; b.lbs = bs; b.lap = ap; b.las = as;
        hft3::ShardOut &o = out[0];
        o.begin_row();
        o.u(ts_recv); o.push_back(','); o.u(ts); o.push_back(',');
        o.str(g_syms[bi]); o.push_back(',');
        px(o, bp); o.push_back(','); o.u((u64)bs); o.push_back(',');
        px(o, ap); o.push_back(','); o.u((u64)as); o.push_back('\n');
        o.end_row();
    }
    void trade(u64 ts_recv, u64 ts, int bi, u32 p, u64 sz, char kind, char aggr, u64 match, char cross) {
        hft3::ShardOut &o = out[1];
        o.begin_row();
        o.u(ts_recv); o.push_back(','); o.u(ts); o.push_back(',');
        o.str(g_syms[bi]); o.push_back(',');
        px(o, p); o.push_back(','); o.u(sz); o.push_back(',');
        o.push_back(kind); o.push_back(','); o.push_back(aggr); o.push_back(',');
        o.u(match); o.push_back(',');
        if (cross) o.push_back(cross);
        o.push_back('\n');
        o.end_row();
    }
    // one ITCH message that the dispatcher already knows belongs to a tracked symbol
    void handle(u64 ts_recv, const u8 *m, u32 n) {
        u8 t = m[0];
        switch (t) {
        case 'A':
        case 'F': {
            int bi = sym_of(be16(m + 1), m + 24);
            if (bi < 0) break;
            bool is_bid = m[19] == 'B';
            u32 p = be32(m + 32);
            i64 sh = be32(m + 20);
            orders[be64(m + 11)] = Order{bi, is_bid, p, sh};
            books[bi].add(is_bid, p, sh);
            post(bi, ts_recv, be48(m + 5));
            break;
        }
        case 'D': {
            auto it = orders.find(be64(m + 11));
            if (it == orders.end()) break;
            Order o = it->second;
            orders.erase(it);
            books[o.book].remove(o.is_bid, o.px, o.sh);
            post(o.book, ts_recv, be48(m + 5));
            break;
        }
        case 'U': {
            auto it = orders.find(be64(m + 11));
            if (it == orders.end()) break;
            Order o = it->second;
            orders.erase(it);
            Book &b = books[o.book];
            b.remove(o.is_bid, o.px, o.sh);
            u32 p = be32(m + 31);
            i64 sh = be32(m + 27);
            orders[be64(m + 19)] = Order{o.book, o.is_bid, p, sh};
            b.add(o.is_bid, p, sh);
            post(o.book, ts_recv, be48(m + 5));
            break;
        }
        case 'X': {
            auto it = orders.find(be64(m + 11));
            if (it == orders.end()) break;
            Order &o = it->second;
            i64 sh = std::min<i64>(be32(m + 19), o.sh);
            books[o.book].remove(o.is_bid, o.px, sh);
            o.sh -= sh;
            int bi = o.book;
            if (o.sh <= 0) orders.erase(it);
            post(bi, ts_recv, be48(m + 5));
            break;
        }
        case 'E':
        case 'C': {
            auto it = orders.find(be64(m + 11));
            if (it == orders.end()) break;
            Order &o = it->second;
            u64 ts = be48(m + 5);
            i64 sh = std::min<i64>(be32(m + 19), o.sh);
            books[o.book].remove(o.is_bid, o.px, sh);
            o.sh -= sh;
            bool printable = true;
            u32 p = o.px;
            if (t == 'C') { printable = m[31] == 'Y'; p = be32(m + 32); }
            if (printable) trade(ts_recv, ts, o.book, p, (u64)sh, (char)t, o.is_bid ? 'S' : 'B', be64(m + 23), 0);
            int bi = o.book;
            if (o.sh <= 0) orders.erase(it);
            post(bi, ts_recv, ts);
            break;
        }
        case 'P': {
            int bi = sym_of(be16(m + 1), m + 24);
            if (bi < 0) break;
            trade(ts_recv, be48(m + 5), bi, be32(m + 32), be32(m + 20), 'P', m[19] == 'B' ? 'S' : 'B', be64(m + 36), 0);
            break;
        }
        case 'Q': {
            int bi = sym_of(be16(m + 1), m + 19);
            if (bi < 0) break;
            trade(ts_recv, be48(m + 5), bi, be32(m + 27), be64(m + 11), 'Q', 'X', be64(m + 31), (char)m[39]);
            break;
        }
        default: break;
        }
        (void)n;
    }
};

// ------------------------------------------------------------------ dispatcher-side classification + routing
struct Span { u32 off, len; };

struct Router {
    hft3::Sharder &sh;
    int S;
    u8 cls[65536];      // per locate: 0 unknown, 1 tracked, 2 other  (v1's rule)
    int bidx[65536];
    u64 seq = 0, n_msgs = 0, bad_msgs = 0, routed = 0;
    Router(hft3::Sharder &s, int nshards) : sh(s), S(nshards) { memset(cls, 0, sizeof cls); }
    int sym_of(u16 loc, const u8 *sym) {
        if (cls[loc] == 1) return bidx[loc];
        if (cls[loc] == 2) return -1;
        int bi = find_sym(sym);
        cls[loc] = bi < 0 ? 2 : 1;
        bidx[loc] = bi;
        return bi;
    }
    void send(int bi, u64 ts, const u8 *m, u32 n) {
        sh.put(bi % S, seq++, ts, m, n);
        routed++;
    }
    // same filtering as v1's feed(): only messages v1 would act on are forwarded
    void feed(u64 ts, const u8 *base, const Span *sp, size_t nsp, size_t skip) {
        for (size_t k = skip; k < nsp; k++) {
            const u8 *m = base + sp[k].off;
            u32 n = sp[k].len;
            if (n < 12) continue;
            u8 t = m[0];
            n_msgs++;
            switch (t) {
            case 'A':
            case 'F': {
                if (n < 36) { bad_msgs++; break; }
                int bi = sym_of(be16(m + 1), m + 24);
                if (bi >= 0) send(bi, ts, m, n);
                break;
            }
            case 'D':
                if (n < 19) { bad_msgs++; break; }
                if (cls[be16(m + 1)] == 1) send(bidx[be16(m + 1)], ts, m, n);
                break;
            case 'U':
                if (n < 35) { bad_msgs++; break; }
                if (cls[be16(m + 1)] == 1) send(bidx[be16(m + 1)], ts, m, n);
                break;
            case 'X':
                if (n < 23) { bad_msgs++; break; }
                if (cls[be16(m + 1)] == 1) send(bidx[be16(m + 1)], ts, m, n);
                break;
            case 'E':
            case 'C':
                if (n < (t == 'C' ? 36u : 31u)) { bad_msgs++; break; }
                if (cls[be16(m + 1)] == 1) send(bidx[be16(m + 1)], ts, m, n);
                break;
            case 'P': {
                if (n < 44) { bad_msgs++; break; }
                int bi = sym_of(be16(m + 1), m + 24);
                if (bi >= 0) send(bi, ts, m, n);
                break;
            }
            case 'Q': {
                if (n < 40) { bad_msgs++; break; }
                int bi = sym_of(be16(m + 1), m + 19);
                if (bi >= 0) send(bi, ts, m, n);
                break;
            }
            case 'R':
                if (n >= 19) sym_of(be16(m + 1), m + 11);
                break;
            default: break;
            }
        }
    }
};

// ------------------------------------------------------------------ MoldUDP64 sequencing (identical to v1)
struct Pend { u64 count, ts; std::vector<u8> pl; std::vector<Span> sp; };
struct Sess { bool init = false; u64 next = 0; std::map<u64, Pend> pend; };

struct Sequencer {
    Router &P;
    size_t window;
    std::unordered_map<std::string, Sess> sessions;
    u64 dup = 0, held = 0, gap = 0, overlap = 0;
    Sequencer(Router &p, size_t w) : P(p), window(w) {}
    void emit(Sess &S, u64 seq, u64 count, u64 ts, const u8 *pl, const std::vector<Span> &sp) {
        if (seq + count <= S.next) { dup++; return; }
        size_t skip = 0;
        if (S.next > seq) { overlap += S.next - seq; skip = S.next - seq; }
        if (skip < sp.size()) P.feed(ts, pl, sp.data(), sp.size(), skip);
        S.next = seq + count;
    }
    void drain(Sess &S) {
        while (!S.pend.empty()) {
            auto it = S.pend.begin();
            if (it->first > S.next) break;
            u64 k = it->first;
            Pend p = std::move(it->second);
            S.pend.erase(it);
            emit(S, k, p.count, p.ts, p.pl.data(), p.sp);
        }
    }
    void push(const std::string &key, u64 seq, u64 count, u64 ts, const u8 *pl, size_t n, const std::vector<Span> &sp) {
        Sess &S = sessions[key];
        if (!S.init) { S.init = true; S.next = seq; }
        if (seq + count <= S.next) { dup++; return; }
        if (seq > S.next) {
            if (S.pend.count(seq)) { dup++; return; }
            Pend p;
            p.count = count; p.ts = ts; p.pl.assign(pl, pl + n); p.sp = sp;
            S.pend.emplace(seq, std::move(p));
            held++;
            if (S.pend.size() > window) {
                u64 k = S.pend.begin()->first;
                gap += k - S.next;
                S.next = k;
                drain(S);
            }
            return;
        }
        emit(S, seq, count, ts, pl, sp);
        drain(S);
    }
    void flush() {
        for (auto &kv : sessions) {
            Sess &S = kv.second;
            while (!S.pend.empty()) {
                auto it = S.pend.begin();
                u64 k = it->first;
                if (k > S.next) { gap += k - S.next; S.next = k; }
                Pend p = std::move(it->second);
                S.pend.erase(it);
                emit(S, k, p.count, p.ts, p.pl.data(), p.sp);
            }
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
    std::string symbols = "QQQ,TQQQ,SQQQ", out = "out";
    size_t window = 2048;
    int threads = 16;
    std::vector<std::string> files;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--symbols" && i + 1 < argc) symbols = argv[++i];
        else if (a == "--out" && i + 1 < argc) out = argv[++i];
        else if (a == "--reorder-window" && i + 1 < argc) window = strtoul(argv[++i], nullptr, 10);
        else if (a == "--threads" && i + 1 < argc) threads = atoi(argv[++i]);
        else if (a == "--pin" && i + 1 < argc) ++i;   // accepted for compatibility with v2; v3 does not pin
        else if (a == "--") { for (int j = i + 1; j < argc; j++) files.push_back(argv[j]); break; }
        else { fprintf(stderr, "usage: itch_fast3 --symbols A,B,C --out base [--threads 16] -- files.pcap.zst ...\n"); return 1; }
    }
    if (files.empty()) { fprintf(stderr, "itch_fast3 reads files only: pass them after --\n"); return 1; }
    {
        size_t s = 0;
        while (s <= symbols.size()) {
            size_t e = symbols.find(',', s);
            if (e == std::string::npos) e = symbols.size();
            std::string sym = symbols.substr(s, e - s);
            for (auto &c : sym) c = (char)toupper(c);
            if (!sym.empty()) {
                char k8[8];
                memset(k8, ' ', 8);
                memcpy(k8, sym.data(), std::min<size_t>(8, sym.size()));
                u64 k;
                memcpy(&k, k8, 8);
                g_by8[k] = (int)g_syms.size();
                g_syms.push_back(sym);
            }
            s = e + 1;
        }
    }
    threads = std::max(6, std::min(32, threads));
    int K = std::max(2, std::min(8, threads / 4));
    int S = std::max(1, std::min<int>({threads - K - 3, 8, (int)g_syms.size()}));

    hft::Writer wr(-1);
    hft::Out bbo, trd;
    bbo.open(wr, out + "_bbo.csv", "ts_recv_ns,ts_itch_ns,symbol,bid_px,bid_sz,ask_px,ask_sz\n");
    trd.open(wr, out + "_trades.csv", "ts_recv_ns,ts_itch_ns,symbol,price,size,kind,aggressor,match_no,cross_type\n");

    hft3::Sharder sharder(S, 4u << 20, 131072);
    std::vector<std::unique_ptr<hft3::Shard<ItchShard>>> shards;
    hft3::Merger merger;
    merger.final_[0] = &bbo;
    merger.final_[1] = &trd;
    for (int s = 0; s < S; s++) {
        shards.emplace_back(new hft3::Shard<ItchShard>());
        merger.outs.push_back(&shards.back()->out_ch);
    }
    hft3::ReaderPool rp(files, K);
    wr.start();
    merger.start();
    for (int s = 0; s < S; s++) shards[s]->start(sharder.lanes[s].get());
    rp.start();
    fprintf(stderr, "itch_fast3: %zu files, threads: %d readers + 1 dispatcher + %d shards + 1 merger + 1 writer\n", files.size(), rp.K, S);

    hft3::MultiStream in(rp);
    Router R(sharder, S);
    Sequencer Q(R, window);
    bool le = true, nano = false, have_hdr = false;
    u32 network = 1;
    u64 npk = 0, non_udp = 0, short_udp = 0, hb = 0, trunc = 0, nfiles = 0, unsupported = 0;
    auto t0 = std::chrono::steady_clock::now(), tl = t0;
    std::vector<Span> sp;
    sp.reserve(512);
    auto rd32 = [&](const u8 *p) -> u32 { return le ? (u32)p[0] | (u32)p[1] << 8 | (u32)p[2] << 16 | (u32)p[3] << 24 : be32(p); };
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
        if ((npk & 0x3FFFF) == 0) {
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration<double>(now - tl).count() > 20) {
                tl = now;
                fprintf(stderr, "  ... itch_fast3: %llu packets, %llu messages, %zu/%zu files done, %.0fs elapsed\n", (unsigned long long)npk,
                        (unsigned long long)R.n_msgs, in.files_done(), files.size(), std::chrono::duration<double>(now - t0).count());
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
        size_t ulen = be16(d + udp + 4);
        size_t plen = ulen >= 8 ? std::min(ulen - 8, n - udp - 8) : 0;
        const u8 *pl = d + udp + 8;
        if (plen < 20) { short_udp++; continue; }
        u64 count = be16(pl + 18);
        if (count == 0 || count == 0xFFFF) { hb++; continue; }
        u64 seq = be64(pl + 10);
        sp.clear();
        size_t pos = 20;
        for (u64 i = 0; i < count; i++) {
            if (pos + 2 > plen) break;
            size_t ln = be16(pl + pos);
            pos += 2;
            if (pos + ln > plen) break;
            sp.push_back(Span{(u32)pos, (u32)ln});
            pos += ln;
        }
        Q.push(std::string((const char *)pl, 10), seq, count, ts, pl, plen, sp);
    }
    in.drain();
    Q.flush();
    sharder.finish();
    for (auto &s : shards) s->th.join();
    merger.th.join();
    bbo.close();
    trd.close();
    wr.finish();
    rp.join();
    double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    fprintf(stderr, "itch_fast3: %llu files, %llu packets, %llu itch messages (%llu routed to shards) in %.1fs\n", (unsigned long long)nfiles,
            (unsigned long long)npk, (unsigned long long)R.n_msgs, (unsigned long long)R.routed, secs);
    fprintf(stderr, "  dup_packets=%llu held_out_of_order=%llu gap_msgs=%llu overlap_msgs=%llu heartbeats=%llu non_udp=%llu short_udp=%llu bad_msgs=%llu truncated=%llu unsupported_link=%llu\n",
            (unsigned long long)Q.dup, (unsigned long long)Q.held, (unsigned long long)Q.gap, (unsigned long long)Q.overlap,
            (unsigned long long)hb, (unsigned long long)non_udp, (unsigned long long)short_udp, (unsigned long long)R.bad_msgs,
            (unsigned long long)trunc, (unsigned long long)unsupported);
    fprintf(stderr, "wrote %llu bbo rows, %llu trade rows -> %s_bbo.csv / %s_trades.csv\n", (unsigned long long)merger.rows[0],
            (unsigned long long)merger.rows[1], out.c_str(), out.c_str());
    return 0;
}
