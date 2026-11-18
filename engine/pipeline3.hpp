// pipeline3.hpp - THIS IS HFT! NOT SHEEPLE CODING!!!
//
// v3 engine: one trading day spread over up to 32 threads.
//
//   K reader threads    each decompresses whole 10-minute files (round-robin), mmap + libzstd, into its own
//                       pool of preallocated blocks; files are independent so K files unpack at once
//          |  per-reader SPSC rings; the dispatcher consumes file 0, 1, 2 ... in order (bounded look-ahead)
//   1 dispatcher        pcap -> IP/UDP -> feed-specific routing (MoldUDP A/B de-dup for ITCH, channel for CME)
//          |  one SPSC lane per shard; work is cut into "epochs" so every shard sees every epoch
//   S shard threads     each owns a disjoint set of books (ITCH: symbols, CME: channels); formats rows tagged
//                       with the global sequence number of the message/packet that produced them
//          |  per-shard SPSC output rings
//   1 merger            per epoch, k-way merges the shards' rows by sequence number -> exactly v1's row order
//          |  SPSC ring (v2 Writer)
//   1 writer            the only thread that calls write()
//
// Lock-free single-producer/single-consumer rings everywhere (acquire/release), all memory preallocated,
// no system call per packet, no thread mixing read and write syscalls.
#pragma once
#include <algorithm>
#include <charconv>

#include "pipeline.hpp"

namespace hft3 {

constexpr uint32_t F_END = 1u << 31;        // end of stream
constexpr uint32_t F_FILE_END = 1u << 30;   // reader: end of one input file
constexpr uint32_t F_LAST = 1u << 28;       // shard output: last block of this epoch for this file id

struct Chan;
struct Blk {
    uint8_t *data;
    size_t len;
    uint32_t flags;
    uint32_t file;     // output file id (shard output) / input file index (reader)
    uint64_t epoch;
    Chan *owner;
};

template <class T, size_t N>
class Ring {
    static_assert((N & (N - 1)) == 0, "N must be a power of two");
    alignas(hft::CACHE_LINE) std::atomic<size_t> head_{0};
    size_t tail_cache_ = 0;
    alignas(hft::CACHE_LINE) std::atomic<size_t> tail_{0};
    size_t head_cache_ = 0;
    alignas(hft::CACHE_LINE) T *slot_[N];

  public:
    void push(T *b) {
        size_t h = head_.load(std::memory_order_relaxed);
        hft::Backoff wait;
        while (h - tail_cache_ >= N) {
            tail_cache_ = tail_.load(std::memory_order_acquire);
            if (h - tail_cache_ >= N) wait();
        }
        slot_[h & (N - 1)] = b;
        head_.store(h + 1, std::memory_order_release);
    }
    T *pop() {
        size_t t = tail_.load(std::memory_order_relaxed);
        hft::Backoff wait;
        while (head_cache_ == t) {
            head_cache_ = head_.load(std::memory_order_acquire);
            if (head_cache_ == t) wait();
        }
        T *b = slot_[t & (N - 1)];
        tail_.store(t + 1, std::memory_order_release);
        return b;
    }
};

struct Chan {
    size_t bsize;
    std::vector<std::unique_ptr<uint8_t[]>> mem;
    std::vector<Blk> blocks;
    Ring<Blk, 32> full, empty;
    Chan(size_t n, size_t bs) : bsize(bs), blocks(n) {
        for (size_t i = 0; i < n; i++) {
            mem.emplace_back(new uint8_t[bs]);
            memset(mem.back().get(), 0, bs);
            blocks[i] = Blk{mem.back().get(), 0, 0, 0, 0, this};
            empty.push(&blocks[i]);
        }
    }
    void recycle(Blk *b) { b->len = 0; b->flags = 0; empty.push(b); }
};

inline void put_u64(uint8_t *p, uint64_t v) { memcpy(p, &v, 8); }
inline void put_u32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }
inline uint64_t get_u64(const uint8_t *p) { uint64_t v; memcpy(&v, p, 8); return v; }
inline uint32_t get_u32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }

// ------------------------------------------------------------------------------------- K parallel readers
struct ReaderPool {
    std::vector<std::string> files;
    int K;
    std::vector<std::unique_ptr<Chan>> ch;
    std::vector<std::thread> th;
    ReaderPool(std::vector<std::string> f, int k) : files(std::move(f)) {
        K = std::max(1, std::min<int>(k, (int)std::max<size_t>(1, files.size())));
        for (int i = 0; i < K; i++) ch.emplace_back(new Chan(8, 8u << 20));
    }
    void start() { for (int w = 0; w < K; w++) th.emplace_back([this, w] { run(w); }); }
    void join() { for (auto &t : th) if (t.joinable()) t.join(); }

    void run(int w) {
#ifdef NO_ZSTD
        fprintf(stderr, "v3 needs libzstd\n");
        _exit(5);
#else
        Chan &c = *ch[w];
        ZSTD_DStream *ds = ZSTD_createDStream();
        Blk *spare = nullptr;
        auto get = [&]() { Blk *b = spare ? spare : c.empty.pop(); spare = nullptr; return b; };
        for (size_t fi = (size_t)w; fi < files.size(); fi += (size_t)K) {
            int fd = ::open(files[fi].c_str(), O_RDONLY);
            if (fd < 0) { perror(files[fi].c_str()); _exit(6); }
            struct stat st;
            fstat(fd, &st);
            size_t sz = (size_t)st.st_size;
            if (sz) {
                const uint8_t *map = (const uint8_t *)mmap(nullptr, sz, PROT_READ, MAP_PRIVATE, fd, 0);
                if (map == MAP_FAILED) { perror("mmap"); _exit(6); }
                madvise((void *)map, sz, MADV_SEQUENTIAL);
                bool zst = sz >= 4 && map[0] == 0x28 && map[1] == 0xB5 && map[2] == 0x2F && map[3] == 0xFD;
                if (!zst) {
                    for (size_t off = 0; off < sz;) {
                        Blk *b = get();
                        size_t n = std::min(c.bsize, sz - off);
                        memcpy(b->data, map + off, n);
                        b->len = n; b->flags = 0; b->file = (uint32_t)fi;
                        c.full.push(b);
                        off += n;
                    }
                } else {
                    ZSTD_initDStream(ds);
                    ZSTD_inBuffer in{map, sz, 0};
                    bool done = false;
                    while (!done) {
                        Blk *b = get();
                        ZSTD_outBuffer out{b->data, c.bsize, 0};
                        while (out.pos < out.size) {
                            size_t ip = in.pos, op = out.pos;
                            size_t ret = ZSTD_decompressStream(ds, &out, &in);
                            if (ZSTD_isError(ret)) { fprintf(stderr, "%s: zstd error %s\n", files[fi].c_str(), ZSTD_getErrorName(ret)); _exit(7); }
                            if (in.pos == in.size && ret == 0) { done = true; break; }
                            if (in.pos == ip && out.pos == op) { fprintf(stderr, "warning: %s looks truncated\n", files[fi].c_str()); done = true; break; }
                        }
                        if (out.pos) { b->len = out.pos; b->flags = 0; b->file = (uint32_t)fi; c.full.push(b); }
                        else spare = b;
                    }
                }
                munmap((void *)map, sz);
            }
            ::close(fd);
            Blk *m = get();
            m->len = 0; m->flags = F_FILE_END; m->file = (uint32_t)fi;
            c.full.push(m);
        }
        ZSTD_freeDStream(ds);
#endif
    }
};

// dispatcher-side byte stream over the readers' blocks, in file order (same peek/consume contract as v2)
class MultiStream {
    ReaderPool &rp;
    size_t fi = 0, nfed = 0;
    Blk *cur = nullptr;
    const uint8_t *view = nullptr;
    size_t view_len = 0, pos = 0, tail_len = 0;
    bool stitched = false, eof = false;
    std::unique_ptr<uint8_t[]> st;

    Blk *next_block() {
        for (;;) {
            if (fi >= rp.files.size()) { eof = true; return nullptr; }
            Chan &c = *rp.ch[fi % (size_t)rp.K];
            Blk *b = c.full.pop();
            if (b->flags & F_FILE_END) {
                c.recycle(b);
                fi++;
                nfed++;
                continue;
            }
            return b;
        }
    }
    void release(Blk *b) { if (b) b->owner->recycle(b); }

  public:
    explicit MultiStream(ReaderPool &r) : rp(r), st(new uint8_t[2 * hft::MAX_RECORD + 64]) {}
    size_t files_done() const { return nfed; }

    const uint8_t *peek(size_t n) {
        for (;;) {
            if (stitched && pos >= tail_len) {
                stitched = false;
                pos -= tail_len;
                view = cur->data;
                view_len = cur->len;
            }
            if (pos + n <= view_len) return view + pos;
            if (eof || n > hft::MAX_RECORD) return nullptr;
            if (stitched) return nullptr;
            size_t tail = view_len - pos;
            if (tail == 0) {
                release(cur);
                cur = next_block();
                if (!cur) return nullptr;
                view = cur->data; view_len = cur->len; pos = 0;
                continue;
            }
            memcpy(st.get(), view + pos, tail);
            release(cur);
            cur = next_block();
            if (!cur) { view = nullptr; view_len = 0; pos = 0; return nullptr; }
            size_t k = std::min(cur->len, hft::MAX_RECORD + 64);
            memcpy(st.get() + tail, cur->data, k);
            tail_len = tail; view = st.get(); view_len = tail + k; pos = 0; stitched = true;
        }
    }
    void consume(size_t n) { pos += n; }
    void drain() {
        if (cur) { release(cur); cur = nullptr; }
        while (!eof) { Blk *b = next_block(); if (b) release(b); }
        view = nullptr; view_len = pos = 0; stitched = false;
    }
};

// ------------------------------------------------------------------------------------- dispatcher -> shards
// item layout in a lane block: [u64 seq][u64 ts][u32 len][len bytes]
struct Sharder {
    struct Lane {
        Chan ch;
        Blk *cur = nullptr;
        size_t n = 0;
        explicit Lane(size_t bs) : ch(8, bs) {}
    };
    std::vector<std::unique_ptr<Lane>> lanes;
    uint64_t epoch = 0, items_in_epoch = 0, max_items;
    Sharder(int S, size_t lane_block, uint64_t epoch_items) : max_items(epoch_items) {
        for (int i = 0; i < S; i++) lanes.emplace_back(new Lane(lane_block));
    }
    void grab(Lane &L) { if (!L.cur) { L.cur = L.ch.empty.pop(); L.n = 0; } }
    void end_epoch() {
        for (auto &lp : lanes) {
            Lane &L = *lp;
            grab(L);
            L.cur->len = L.n;
            L.cur->flags = 0;
            L.cur->epoch = epoch;
            L.ch.full.push(L.cur);
            L.cur = nullptr;
        }
        epoch++;
        items_in_epoch = 0;
    }
    void put(int s, uint64_t seq, uint64_t ts, const uint8_t *p, uint32_t len) {
        Lane &L = *lanes[s];
        grab(L);
        size_t need = 20 + (size_t)len;
        if (L.n + need > L.ch.bsize) { end_epoch(); grab(L); }
        uint8_t *d = L.cur->data + L.n;
        put_u64(d, seq); put_u64(d + 8, ts); put_u32(d + 16, len);
        memcpy(d + 20, p, len);
        L.n += need;
        if (++items_in_epoch >= max_items) end_epoch();
    }
    void finish() {
        if (items_in_epoch) end_epoch();
        for (auto &lp : lanes) {
            Lane &L = *lp;
            grab(L);
            L.cur->len = 0; L.cur->flags = F_END;
            L.ch.full.push(L.cur);
            L.cur = nullptr;
        }
    }
};

// shard-side row output: each row is [u64 seq][u32 len][text]; files 0 and 1 share one output ring
struct ShardOut {
    Chan *ch = nullptr;
    uint32_t file = 0;
    Blk *blk = nullptr;
    size_t n = 0, hdr = 0;
    uint64_t epoch = 0, rows = 0, seq = 0;
    void ensure() { if (!blk) { blk = ch->empty.pop(); n = 0; } }
    void push(bool last) {
        ensure();
        blk->len = n; blk->flags = last ? F_LAST : 0; blk->file = file; blk->epoch = epoch;
        ch->full.push(blk);
        blk = nullptr; n = 0;
    }
    void begin_row() { ensure(); hdr = n; put_u64(blk->data + n, seq); n += 12; }
    void end_row() {
        put_u32(blk->data + hdr + 8, (uint32_t)(n - hdr - 12));
        rows++;
        if (n > ch->bsize - (64u << 10)) push(false);
    }
    void add(const char *s, size_t k) { memcpy(blk->data + n, s, k); n += k; }
    void push_back(char c) { blk->data[n++] = (uint8_t)c; }
    void str(const std::string &s) { add(s.data(), s.size()); }
    void u(uint64_t v) { char t[24]; auto r = std::to_chars(t, t + 24, v); add(t, (size_t)(r.ptr - t)); }
    void i(int64_t v) { char t[24]; auto r = std::to_chars(t, t + 24, v); add(t, (size_t)(r.ptr - t)); }
};

// generic shard thread: Proc must have: ShardOut out[2]; void handle(uint64_t ts, const uint8_t*, uint32_t)
template <class Proc>
struct Shard {
    Sharder::Lane *lane;
    Chan out_ch;
    Proc proc;
    std::thread th;
    Shard() : out_ch(16, 4u << 20) {}
    void start(Sharder::Lane *l) {
        lane = l;
        for (int f = 0; f < 2; f++) { proc.out[f].ch = &out_ch; proc.out[f].file = (uint32_t)f; }
        th = std::thread([this] { run(); });
    }
    void run() {
        for (;;) {
            Blk *b = lane->ch.full.pop();
            if (b->flags & F_END) {
                lane->ch.recycle(b);
                Blk *e = out_ch.empty.pop();
                e->len = 0; e->flags = F_END;
                out_ch.full.push(e);
                return;
            }
            uint64_t ep = b->epoch;
            proc.out[0].epoch = proc.out[1].epoch = ep;
            const uint8_t *p = b->data, *end = b->data + b->len;
            while (p < end) {
                uint64_t seq = get_u64(p), ts = get_u64(p + 8);
                uint32_t len = get_u32(p + 16);
                proc.out[0].seq = proc.out[1].seq = seq;
                proc.handle(ts, p + 20, len);
                p += 20 + len;
            }
            lane->ch.recycle(b);
            proc.out[0].push(true);
            proc.out[1].push(true);
        }
    }
};

// merger: per epoch, k-way merge the shards' rows by sequence number into the final outputs
struct Merger {
    std::vector<Chan *> outs;     // one per shard
    hft::Out *final_[2];
    std::thread th;
    uint64_t rows[2] = {0, 0};
    void start() { th = std::thread([this] { run(); }); }
    void run() {
        size_t S = outs.size();
        std::vector<std::vector<Blk *>> lists(S * 2);
        std::vector<char> got(S * 2), ended(S);
        struct Cur { size_t bi, off; };
        std::vector<Cur> cur(S);
        for (;;) {
            for (auto &l : lists) l.clear();
            std::fill(got.begin(), got.end(), 0);
            size_t nend = 0;
            for (size_t s = 0; s < S; s++) {
                while (!(got[s * 2] && got[s * 2 + 1])) {
                    Blk *b = outs[s]->full.pop();
                    if (b->flags & F_END) { outs[s]->recycle(b); ended[s] = 1; nend++; break; }
                    lists[s * 2 + b->file].push_back(b);
                    if (b->flags & F_LAST) got[s * 2 + b->file] = 1;
                }
            }
            for (int f = 0; f < 2; f++) {
                hft::Out &o = *final_[f];
                for (size_t s = 0; s < S; s++) cur[s] = Cur{0, 0};
                auto valid = [&](size_t s) {
                    auto &L = lists[s * 2 + f];
                    while (cur[s].bi < L.size() && cur[s].off >= L[cur[s].bi]->len) { cur[s].bi++; cur[s].off = 0; }
                    return cur[s].bi < L.size();
                };
                for (;;) {
                    size_t best = S;
                    uint64_t bs = 0;
                    for (size_t s = 0; s < S; s++) {
                        if (!valid(s)) continue;
                        uint64_t q = get_u64(lists[s * 2 + f][cur[s].bi]->data + cur[s].off);
                        if (best == S || q < bs) { best = s; bs = q; }
                    }
                    if (best == S) break;
                    // copy every consecutive row of this shard with the same seq (one message's rows)
                    for (;;) {
                        const uint8_t *r = lists[best * 2 + f][cur[best].bi]->data + cur[best].off;
                        if (get_u64(r) != bs) break;
                        uint32_t len = get_u32(r + 8);
                        o.add((const char *)r + 12, len);
                        o.check();
                        rows[f]++;
                        cur[best].off += 12 + len;
                        if (!valid(best)) break;
                    }
                }
            }
            for (size_t s = 0; s < S; s++)
                for (int f = 0; f < 2; f++)
                    for (Blk *b : lists[s * 2 + f]) outs[s]->recycle(b);
            if (nend == S) return;
        }
    }
};

}  // namespace hft3
