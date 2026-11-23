// itch_noii.cpp - itch_fast (v1 reference) + Net Order Imbalance Indicator ('I') output for auction studies.
// Generated from itch_fast.cpp; bbo/trades output is unchanged. Extra output:
//   <out>_noii.csv  ts_recv_ns,ts_itch_ns,symbol,paired,imbalance,direction,far_px,near_px,ref_px,cross_type,pvi
// Build: g++ -O3 -std=c++17 -o itch_noii itch_noii.cpp
//
//
// Same logic and same output columns as itch_zst_parse.py, in C++ (about 30-100x faster).
// Input : DECOMPRESSED classic pcap data on stdin (one or several files back to back, in time order).
//         itch_fast_feed.py does the zstd decompression and pipes the files in.
// Output: <out>_bbo.csv     ts_recv_ns,ts_itch_ns,symbol,bid_px,bid_sz,ask_px,ask_sz
//         <out>_trades.csv  ts_recv_ns,ts_itch_ns,symbol,price,size,kind,aggressor,match_no,cross_type
//
// Build:  g++ -O3 -std=c++17 -o itch_fast itch_fast.cpp
// Run  :  zstd-decompressed pcap | ./itch_fast --symbols QQQ,TQQQ,SQQQ --out out/xnas_20250203
// Nothing here touches the network.
#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int64_t i64;

static inline u16 be16(const u8 *p) { return (u16)(p[0] << 8 | p[1]); }
static inline u32 be32(const u8 *p) { return (u32)p[0] << 24 | (u32)p[1] << 16 | (u32)p[2] << 8 | p[3]; }
static inline u64 be64(const u8 *p) { return (u64)be32(p) << 32 | be32(p + 4); }
static inline u64 be48(const u8 *p) { return (u64)be16(p) << 32 | be32(p + 2); }

// ------------------------------------------------------------------ input
struct Reader {
    std::vector<u8> buf;
    size_t pos = 0, end = 0;
    bool eof = false;
    Reader() : buf(1 << 24) {}
    bool ensure(size_t n) {
        if (end - pos >= n) return true;
        if (pos) {
            memmove(buf.data(), buf.data() + pos, end - pos);
            end -= pos;
            pos = 0;
        }
        while (end < n && !eof) {
            size_t r = fread(buf.data() + end, 1, buf.size() - end, stdin);
            if (r == 0) { eof = true; break; }
            end += r;
        }
        return end - pos >= n;
    }
    const u8 *p() const { return buf.data() + pos; }
};

// ------------------------------------------------------------------ output
struct Out {
    FILE *f = nullptr;
    std::string b;
    u64 rows = 0;
    void open(const std::string &path, const char *header) {
        f = fopen(path.c_str(), "wb");
        if (!f) { perror(path.c_str()); exit(2); }
        fputs(header, f);
        b.reserve(1 << 21);
    }
    void flush() { if (!b.empty()) { fwrite(b.data(), 1, b.size(), f); b.clear(); } }
    void check() { if (b.size() > (1 << 20)) flush(); }
    void close() { flush(); if (f) fclose(f); }
    void i(u64 v) { char t[24]; auto r = std::to_chars(t, t + 24, v); b.append(t, r.ptr); }
    void px(u32 p) {  // price in 1/10000 dollars -> "521.1000"; empty when 0 (like the NaN in the python version)
        if (!p) return;
        i(p / 10000);
        b.push_back('.');
        u32 fr = p % 10000;
        char t[4] = {(char)('0' + fr / 1000), (char)('0' + fr / 100 % 10), (char)('0' + fr / 10 % 10), (char)('0' + fr % 10)};
        b.append(t, 4);
    }
};

// ------------------------------------------------------------------ order book
struct Book {
    std::string sym;
    std::map<u32, i64> bid, ask;
    bool has_last = false;
    u32 lbp = 0, lap = 0;
    i64 lbs = 0, las = 0;
    void add(bool is_bid, u32 px, i64 sz) {
        auto &d = is_bid ? bid : ask;
        d[px] += sz;
    }
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
struct Span { u32 off, len; };

struct Parser {
    std::vector<Book> books;
    std::unordered_map<u64, int> by8;
    std::unordered_map<u64, Order> orders;
    Out bbo, trd, noi;
    u64 tc[256] = {0};
    u64 bad_msgs = 0, n_msgs = 0;
    u8 cls[65536];   // per stock-locate: 0 unknown, 1 tracked symbol, 2 other symbol (learned from R/A/F/P/Q messages)
    int bidx[65536];
    Parser() { memset(cls, 0, sizeof cls); }
    // resolve a symbol field for this locate, caching the answer
    int sym_of(u16 loc, const u8 *sym) {
        if (cls[loc] == 1) return bidx[loc];
        if (cls[loc] == 2) return -1;
        int bi = find_sym(sym);
        cls[loc] = bi < 0 ? 2 : 1;
        bidx[loc] = bi;
        return bi;
    }

    int find_sym(const u8 *p) {
        u64 k;
        memcpy(&k, p, 8);
        auto it = by8.find(k);
        return it == by8.end() ? -1 : it->second;
    }

    void post(int bi, u64 ts_recv, u64 ts) {
        Book &b = books[bi];
        u32 bp, ap;
        i64 bs, as;
        b.top(bp, bs, ap, as);
        if (b.has_last && bp == b.lbp && bs == b.lbs && ap == b.lap && as == b.las) return;
        b.has_last = true; b.lbp = bp; b.lbs = bs; b.lap = ap; b.las = as;
        bbo.i(ts_recv); bbo.b.push_back(','); bbo.i(ts); bbo.b.push_back(',');
        bbo.b += b.sym; bbo.b.push_back(',');
        bbo.px(bp); bbo.b.push_back(','); bbo.i(bs); bbo.b.push_back(',');
        bbo.px(ap); bbo.b.push_back(','); bbo.i(as); bbo.b.push_back('\n');
        bbo.rows++;
        bbo.check();
    }

    void trade(u64 ts_recv, u64 ts, const std::string &sym, u32 px, u64 sz, char kind, char aggr, u64 match, char cross) {
        trd.i(ts_recv); trd.b.push_back(','); trd.i(ts); trd.b.push_back(',');
        trd.b += sym; trd.b.push_back(',');
        trd.px(px); trd.b.push_back(','); trd.i(sz); trd.b.push_back(',');
        trd.b.push_back(kind); trd.b.push_back(','); trd.b.push_back(aggr); trd.b.push_back(',');
        trd.i(match); trd.b.push_back(',');
        if (cross) trd.b.push_back(cross);
        trd.b.push_back('\n');
        trd.rows++;
        trd.check();
    }

    // process the ITCH messages of one MoldUDP64 packet, skipping the first `skip`
    void feed(u64 ts_recv, const u8 *base, const Span *sp, size_t nsp, size_t skip) {
        for (size_t k = skip; k < nsp; k++) {
            const u8 *m = base + sp[k].off;
            u32 n = sp[k].len;
            if (n < 12) continue;
            u8 t = m[0];
            tc[t]++;
            n_msgs++;
            switch (t) {
            case 'A':
            case 'F': {
                if (n < 36) { bad_msgs++; break; }
                int bi = sym_of(be16(m + 1), m + 24);
                if (bi < 0) break;
                u64 ts = be48(m + 5);
                bool is_bid = m[19] == 'B';
                u32 px = be32(m + 32);
                i64 sh = be32(m + 20);
                orders[be64(m + 11)] = Order{bi, is_bid, px, sh};
                books[bi].add(is_bid, px, sh);
                post(bi, ts_recv, ts);
                break;
            }
            case 'D': {
                if (n < 19) { bad_msgs++; break; }
                if (cls[be16(m + 1)] != 1) break;   // no tracked order can have this locate
                auto it = orders.find(be64(m + 11));
                if (it == orders.end()) break;
                Order o = it->second;
                orders.erase(it);
                books[o.book].remove(o.is_bid, o.px, o.sh);
                post(o.book, ts_recv, be48(m + 5));
                break;
            }
            case 'U': {
                if (n < 35) { bad_msgs++; break; }
                if (cls[be16(m + 1)] != 1) break;
                auto it = orders.find(be64(m + 11));
                if (it == orders.end()) break;
                Order o = it->second;
                orders.erase(it);
                Book &b = books[o.book];
                b.remove(o.is_bid, o.px, o.sh);
                u32 px = be32(m + 31);
                i64 sh = be32(m + 27);
                orders[be64(m + 19)] = Order{o.book, o.is_bid, px, sh};
                b.add(o.is_bid, px, sh);
                post(o.book, ts_recv, be48(m + 5));
                break;
            }
            case 'X': {
                if (n < 23) { bad_msgs++; break; }
                if (cls[be16(m + 1)] != 1) break;
                u64 ref = be64(m + 11);
                auto it = orders.find(ref);
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
                if (n < (t == 'C' ? 36u : 31u)) { bad_msgs++; break; }
                if (cls[be16(m + 1)] != 1) break;
                u64 ref = be64(m + 11);
                auto it = orders.find(ref);
                if (it == orders.end()) break;
                Order &o = it->second;
                u64 ts = be48(m + 5);
                i64 sh = std::min<i64>(be32(m + 19), o.sh);
                Book &b = books[o.book];
                b.remove(o.is_bid, o.px, sh);
                o.sh -= sh;
                bool printable = true;
                u32 px = o.px;
                if (t == 'C') { printable = m[31] == 'Y'; px = be32(m + 32); }
                if (printable) trade(ts_recv, ts, b.sym, px, (u64)sh, t, o.is_bid ? 'S' : 'B', be64(m + 23), 0);
                int bi = o.book;
                if (o.sh <= 0) orders.erase(it);
                post(bi, ts_recv, ts);
                break;
            }
            case 'P': {
                if (n < 44) { bad_msgs++; break; }
                int bi = sym_of(be16(m + 1), m + 24);
                if (bi < 0) break;
                trade(ts_recv, be48(m + 5), books[bi].sym, be32(m + 32), be32(m + 20), 'P', m[19] == 'B' ? 'S' : 'B', be64(m + 36), 0);
                break;
            }
            case 'I': {  // NOII: paired@11 imb@19 dir@27 stock@28 far@36 near@40 ref@44 cross@48 pvi@49
                if (n < 50) { bad_msgs++; break; }
                int bi = sym_of(be16(m + 1), m + 28);
                if (bi < 0) break;
                noi.i(ts_recv); noi.b.push_back(','); noi.i(be48(m + 5)); noi.b.push_back(',');
                noi.b += books[bi].sym; noi.b.push_back(',');
                noi.i(be64(m + 11)); noi.b.push_back(','); noi.i(be64(m + 19)); noi.b.push_back(',');
                noi.b.push_back((char)m[27]); noi.b.push_back(',');
                noi.px(be32(m + 36)); noi.b.push_back(','); noi.px(be32(m + 40)); noi.b.push_back(',');
                noi.px(be32(m + 44)); noi.b.push_back(',');
                noi.b.push_back((char)m[48]); noi.b.push_back(','); noi.b.push_back((char)m[49]); noi.b.push_back('\n');
                noi.rows++; noi.check();
                break;
            }
            case 'Q': {
                if (n < 40) { bad_msgs++; break; }
                int bi = sym_of(be16(m + 1), m + 19);
                if (bi < 0) break;
                trade(ts_recv, be48(m + 5), books[bi].sym, be32(m + 27), be64(m + 11), 'Q', 'X', be64(m + 31), (char)m[39]);
                break;
            }
            case 'R': {
                if (n >= 19) sym_of(be16(m + 1), m + 11);   // stock directory: learn which locate is a tracked symbol
                break;
            }
            default: break;
            }
        }
    }
};

// ------------------------------------------------------------------ MoldUDP64 sequencing (A/B duplicates, re-order, gaps)
struct Pend { u64 count, ts; std::vector<u8> pl; std::vector<Span> sp; };
struct Sess { bool init = false; u64 next = 0; std::map<u64, Pend> pend; };

struct Sequencer {
    Parser &P;
    size_t window;
    std::unordered_map<std::string, Sess> sessions;
    u64 dup = 0, held = 0, gap = 0, overlap = 0;
    Sequencer(Parser &p, size_t w) : P(p), window(w) {}

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

// ------------------------------------------------------------------ main
static bool is_magic(const u8 *p, bool &le, bool &nano) {
    static const u8 M[4][4] = {{0xd4, 0xc3, 0xb2, 0xa1}, {0xa1, 0xb2, 0xc3, 0xd4}, {0x4d, 0x3c, 0xb2, 0xa1}, {0xa1, 0xb2, 0x3c, 0x4d}};
    for (int i = 0; i < 4; i++)
        if (!memcmp(p, M[i], 4)) { le = (i == 0 || i == 2); nano = (i >= 2); return true; }
    return false;
}

int main(int argc, char **argv) {
    std::string symbols = "QQQ,TQQQ,SQQQ", out = "out";
    size_t window = 2048;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--symbols" && i + 1 < argc) symbols = argv[++i];
        else if (a == "--out" && i + 1 < argc) out = argv[++i];
        else if (a == "--reorder-window" && i + 1 < argc) window = strtoul(argv[++i], nullptr, 10);
        else { fprintf(stderr, "usage: itch_noii --symbols A,B,C --out base_path   (decompressed pcap on stdin)\n"); return 1; }
    }
    Parser P;
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
                P.by8[k] = (int)P.books.size();
                P.books.push_back(Book());
                P.books.back().sym = sym;
            }
            s = e + 1;
        }
    }
    P.orders.reserve(1 << 20);
    P.bbo.open(out + "_bbo.csv", "ts_recv_ns,ts_itch_ns,symbol,bid_px,bid_sz,ask_px,ask_sz\n");
    P.trd.open(out + "_trades.csv", "ts_recv_ns,ts_itch_ns,symbol,price,size,kind,aggressor,match_no,cross_type\n");
    P.noi.open(out + "_noii.csv", "ts_recv_ns,ts_itch_ns,symbol,paired,imbalance,direction,far_px,near_px,ref_px,cross_type,pvi\n");
    Sequencer Q(P, window);
    Reader rd;
    bool le = true, nano = false;
    u32 network = 1;
    u64 npk = 0, non_udp = 0, short_udp = 0, hb = 0, trunc = 0, files = 0, unsupported = 0;
    auto t0 = std::chrono::steady_clock::now(), tl = t0;
    std::vector<Span> sp;
    sp.reserve(512);
    bool have_hdr = false;
    auto rd32 = [&](const u8 *p) -> u32 { return le ? (u32)p[0] | (u32)p[1] << 8 | (u32)p[2] << 16 | (u32)p[3] << 24 : be32(p); };
    while (true) {
        if (!rd.ensure(4)) break;
        bool l2, n2;
        if (is_magic(rd.p(), l2, n2)) {  // (next) pcap file header
            if (!rd.ensure(24)) break;
            le = l2; nano = n2;
            network = rd32(rd.p() + 20) & 0x0FFFFFFF;
            rd.pos += 24;
            have_hdr = true;
            files++;
            continue;
        }
        if (!have_hdr) { fprintf(stderr, "input is not a classic pcap stream (pcapng is not supported here; use itch_zst_parse.py)\n"); return 3; }
        if (!rd.ensure(16)) break;
        const u8 *h = rd.p();
        u32 sec = rd32(h), frac = rd32(h + 4), incl = rd32(h + 8);
        if (incl > (1u << 20)) { fprintf(stderr, "corrupt record length %u\n", incl); return 4; }
        if (!rd.ensure(16 + (size_t)incl)) { trunc = 1; break; }
        h = rd.p();
        const u8 *d = h + 16;
        rd.pos += 16 + incl;
        u64 ts = (u64)sec * 1000000000ull + (nano ? frac : (u64)frac * 1000);
        npk++;
        if ((npk & 0x3FFFF) == 0) {
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration<double>(now - tl).count() > 20) {
                tl = now;
                fprintf(stderr, "  ... itch_fast: %llu packets, %llu messages, file %llu, %.0fs elapsed\n", (unsigned long long)npk,
                        (unsigned long long)P.n_msgs, (unsigned long long)files, std::chrono::duration<double>(now - t0).count());
            }
        }
        // ---- link / IP / UDP
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
            if (((d[off + 6] & 0x3F) << 8) | d[off + 7]) { non_udp++; continue; }  // fragment
            udp = off + (d[off] & 0x0F) * 4;
        } else if (et == 0x86DD) {
            if (n < off + 40 || d[off + 6] != 17) { non_udp++; continue; }
            udp = off + 40;
        } else { non_udp++; continue; }
        if (n < udp + 8) { non_udp++; continue; }
        size_t ulen = be16(d + udp + 4);
        size_t plen = ulen >= 8 ? std::min(ulen - 8, n - udp - 8) : 0;
        const u8 *pl = d + udp + 8;
        // ---- MoldUDP64
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
    Q.flush();
    P.bbo.close();
    P.trd.close();
    P.noi.close();
    double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    fprintf(stderr, "itch_fast: %llu files, %llu packets, %llu itch messages in %.1fs\n", (unsigned long long)files, (unsigned long long)npk,
            (unsigned long long)P.n_msgs, secs);
    fprintf(stderr, "  dup_packets=%llu held_out_of_order=%llu gap_msgs=%llu overlap_msgs=%llu heartbeats=%llu non_udp=%llu short_udp=%llu bad_msgs=%llu truncated=%llu unsupported_link=%llu\n",
            (unsigned long long)Q.dup, (unsigned long long)Q.held, (unsigned long long)Q.gap, (unsigned long long)Q.overlap,
            (unsigned long long)hb, (unsigned long long)non_udp, (unsigned long long)short_udp, (unsigned long long)P.bad_msgs,
            (unsigned long long)trunc, (unsigned long long)unsupported);
    fprintf(stderr, "wrote %llu bbo rows, %llu trade rows -> %s_bbo.csv / %s_trades.csv\n", (unsigned long long)P.bbo.rows,
            (unsigned long long)P.trd.rows, out.c_str(), out.c_str());
    fprintf(stderr, "wrote %llu noii rows -> %s_noii.csv\n", (unsigned long long)P.noi.rows, out.c_str());
    return 0;
}
