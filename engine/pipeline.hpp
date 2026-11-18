// pipeline.hpp - THIS IS HFT! NOT SHEEPLE CODING!!!
//
// Three-stage I/O pipeline shared by itch_fast2 and mdp3_fast2:
//
//   reader thread   mmap each .pcap.zst, decompress in-process (libzstd) into big preallocated blocks
//        |  SPSC ring (full blocks)  ->   <- SPSC ring (empty blocks, recycled)
//   parser thread   the caller (main thread): walks pcap records straight out of the blocks
//        |  SPSC ring (filled output blocks) ->   <- SPSC ring (empty output blocks)
//   writer thread   the only thread that calls write(); one fd per output file
//
// No thread does both read and write syscalls. No allocation after start-up. Lock-free single-producer/
// single-consumer rings with acquire/release ordering only; producer and consumer indices live on separate
// cache lines. Optional core pinning (--pin r,p,w) on Linux.
//
// libzstd is called through its stable C ABI declared below, so the build needs only the shared library
// (libzstd.so.1, present on Ubuntu even without the -dev package):  g++ ... -l:libzstd.so.1
// Build with -DNO_ZSTD to read an already-decompressed pcap stream from stdin instead.
#pragma once
#include <atomic>
#include <chrono>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef __linux__
#include <pthread.h>
#include <sched.h>
#endif
#if defined(__x86_64__) || defined(__i386__)
#include <immintrin.h>
#define HFT_PAUSE() _mm_pause()
#elif defined(__aarch64__)
#define HFT_PAUSE() asm volatile("yield")
#else
#define HFT_PAUSE() ((void)0)
#endif

#ifndef NO_ZSTD
extern "C" {
typedef struct ZSTD_DCtx_s ZSTD_DStream;
typedef struct { const void *src; size_t size; size_t pos; } ZSTD_inBuffer;
typedef struct { void *dst; size_t size; size_t pos; } ZSTD_outBuffer;
ZSTD_DStream *ZSTD_createDStream(void);
size_t ZSTD_freeDStream(ZSTD_DStream *zds);
size_t ZSTD_initDStream(ZSTD_DStream *zds);
size_t ZSTD_decompressStream(ZSTD_DStream *zds, ZSTD_outBuffer *output, ZSTD_inBuffer *input);
unsigned ZSTD_isError(size_t code);
const char *ZSTD_getErrorName(size_t code);
}
#endif

namespace hft {

constexpr size_t CACHE_LINE = 64;
constexpr uint32_t BLK_END = 1u << 31;           // flag: end of stream (no data)
constexpr size_t MAX_RECORD = (1u << 20) + 64;   // parsers reject pcap records above 1 MiB

inline void pin_this_thread(int core) {
#ifdef __linux__
    if (core < 0) return;
    cpu_set_t s;
    CPU_ZERO(&s);
    CPU_SET(core, &s);
    if (pthread_setaffinity_np(pthread_self(), sizeof s, &s) != 0) fprintf(stderr, "note: could not pin to core %d\n", core);
#else
    (void)core;
#endif
}

// spin briefly, then yield, then sleep: an idle stage must not steal cores from the busy one
// (and we share the VM with other students)
struct Backoff {
    unsigned n = 0;
    void operator()() {
        ++n;
        if (n < 64) HFT_PAUSE();
        else if (n < 256) std::this_thread::yield();
        else std::this_thread::sleep_for(std::chrono::microseconds(50));
    }
};

struct Block {
    uint8_t *data;
    size_t len;
    uint32_t tag;   // output file id, or BLK_END
};

// single-producer single-consumer ring of Block pointers; N must be a power of two
template <size_t N>
class Spsc {
    static_assert((N & (N - 1)) == 0, "N must be a power of two");
    alignas(CACHE_LINE) std::atomic<size_t> head_{0};   // producer writes
    size_t tail_cache_ = 0;                              // producer's view of tail
    alignas(CACHE_LINE) std::atomic<size_t> tail_{0};   // consumer writes
    size_t head_cache_ = 0;                              // consumer's view of head
    alignas(CACHE_LINE) Block *slot_[N];

  public:
    void push(Block *b) {
        size_t h = head_.load(std::memory_order_relaxed);
        Backoff wait;
        while (h - tail_cache_ >= N) {
            tail_cache_ = tail_.load(std::memory_order_acquire);
            if (h - tail_cache_ >= N) wait();
        }
        slot_[h & (N - 1)] = b;
        head_.store(h + 1, std::memory_order_release);
    }
    Block *pop() {
        size_t t = tail_.load(std::memory_order_relaxed);
        Backoff wait;
        while (head_cache_ == t) {
            head_cache_ = head_.load(std::memory_order_acquire);
            if (head_cache_ == t) wait();
        }
        Block *b = slot_[t & (N - 1)];
        tail_.store(t + 1, std::memory_order_release);
        return b;
    }
};

// a pool of preallocated blocks circulating between one producer and one consumer
struct Channel {
    static constexpr size_t RING = 64;
    size_t block_size;
    std::vector<std::unique_ptr<uint8_t[]>> mem;
    std::vector<Block> blocks;
    Spsc<RING> full;    // producer -> consumer
    Spsc<RING> empty;   // consumer -> producer
    Channel(size_t nblocks, size_t bsize) : block_size(bsize), blocks(nblocks) {
        if (nblocks > RING) { fprintf(stderr, "too many blocks\n"); exit(9); }
        for (size_t i = 0; i < nblocks; i++) {
            mem.emplace_back(new uint8_t[bsize]);
            memset(mem.back().get(), 0, bsize);   // fault the pages in now, not in the hot loop
            blocks[i] = Block{mem.back().get(), 0, 0};
            empty.push(&blocks[i]);
        }
    }
};

// ------------------------------------------------------------------------------------------- reader stage
struct Reader {
    Channel ch;
    std::vector<std::string> files;
    int core = -1;
    std::thread th;
    Reader(std::vector<std::string> f, int c) : ch(16, 8u << 20), files(std::move(f)), core(c) {}

    void start() { th = std::thread([this] { run(); }); }
    void join() { if (th.joinable()) th.join(); }

    void finish() {
        Block *b = ch.empty.pop();
        b->len = 0;
        b->tag = BLK_END;
        ch.full.push(b);
    }

    void read_stdin() {   // fallback: decompressed pcap on stdin, big read() calls
        for (;;) {
            Block *b = ch.empty.pop();
            size_t n = 0;
            while (n < ch.block_size) {
                ssize_t r = ::read(0, b->data + n, ch.block_size - n);
                if (r < 0 && errno == EINTR) continue;
                if (r <= 0) break;
                n += (size_t)r;
            }
            b->len = n;
            b->tag = 0;
            if (n) ch.full.push(b);
            else { b->tag = BLK_END; ch.full.push(b); return; }
            if (n < ch.block_size) { finish(); return; }
        }
    }

    void run() {
        pin_this_thread(core);
        if (files.empty()) { read_stdin(); return; }
#ifdef NO_ZSTD
        fprintf(stderr, "built with NO_ZSTD: pipe the decompressed stream on stdin instead of passing files\n");
        _exit(5);
#else
        ZSTD_DStream *ds = ZSTD_createDStream();
        Block *spare = nullptr;
        for (size_t fi = 0; fi < files.size(); fi++) {
            int fd = ::open(files[fi].c_str(), O_RDONLY);
            if (fd < 0) { perror(files[fi].c_str()); _exit(6); }
            struct stat st;
            fstat(fd, &st);
            size_t sz = (size_t)st.st_size;
            if (sz == 0) { ::close(fd); continue; }
            const uint8_t *map = (const uint8_t *)mmap(nullptr, sz, PROT_READ, MAP_PRIVATE, fd, 0);
            if (map == MAP_FAILED) { perror("mmap"); _exit(6); }
            madvise((void *)map, sz, MADV_SEQUENTIAL);
            bool zst = sz >= 4 && map[0] == 0x28 && map[1] == 0xB5 && map[2] == 0x2F && map[3] == 0xFD;
            if (!zst) {   // plain pcap: copy straight into blocks
                for (size_t off = 0; off < sz;) {
                    Block *b = spare ? spare : ch.empty.pop();
                    spare = nullptr;
                    size_t n = std::min(ch.block_size, sz - off);
                    memcpy(b->data, map + off, n);
                    b->len = n;
                    b->tag = 0;
                    ch.full.push(b);
                    off += n;
                }
            } else {
                ZSTD_initDStream(ds);
                ZSTD_inBuffer in{map, sz, 0};
                size_t ret = 1;
                bool done = false;
                while (!done) {
                    Block *b = spare ? spare : ch.empty.pop();
                    spare = nullptr;
                    ZSTD_outBuffer out{b->data, ch.block_size, 0};
                    while (out.pos < out.size) {
                        size_t ip = in.pos, op = out.pos;
                        ret = ZSTD_decompressStream(ds, &out, &in);
                        if (ZSTD_isError(ret)) { fprintf(stderr, "%s: zstd error %s\n", files[fi].c_str(), ZSTD_getErrorName(ret)); _exit(7); }
                        if (in.pos == in.size && ret == 0) { done = true; break; }
                        if (in.pos == ip && out.pos == op) {   // no progress: input is truncated
                            fprintf(stderr, "warning: %s looks truncated\n", files[fi].c_str());
                            done = true;
                            break;
                        }
                    }
                    if (out.pos) { b->len = out.pos; b->tag = 0; ch.full.push(b); }
                    else spare = b;
                }
            }
            munmap((void *)map, sz);
            ::close(fd);
            fprintf(stderr, "  reader: fed file %zu/%zu\n", fi + 1, files.size());
        }
        ZSTD_freeDStream(ds);
        if (spare) { spare->len = 0; spare->tag = BLK_END; ch.full.push(spare); }
        else finish();
#endif
    }
};

// parser-side view of the reader's blocks as one byte stream; peek(n) returns n contiguous bytes
// (stitching across a block boundary when a record straddles two blocks), consume(n) moves on
class Stream {
    Channel &ch;
    Block *cur = nullptr;
    const uint8_t *view = nullptr;
    size_t view_len = 0, pos = 0;
    bool stitched = false, eof = false;
    size_t tail_len = 0;
    std::unique_ptr<uint8_t[]> st;

    void release(Block *b) { if (b) { b->len = 0; b->tag = 0; ch.empty.push(b); } }
    Block *next_block() {
        Block *b = ch.full.pop();
        if (b->tag & BLK_END) { eof = true; return nullptr; }   // END block is never recycled: we are done
        return b;
    }

  public:
    explicit Stream(Channel &c) : ch(c), st(new uint8_t[2 * MAX_RECORD + 64]) {}

    const uint8_t *peek(size_t n) {
        for (;;) {
            if (stitched && pos >= tail_len) {   // stitched prefix used up: continue in the real block
                stitched = false;
                pos -= tail_len;
                view = cur->data;
                view_len = cur->len;
            }
            if (pos + n <= view_len) return view + pos;
            if (eof || n > MAX_RECORD) return nullptr;
            if (stitched) return nullptr;        // record longer than what follows (truncated input)
            size_t tail = view_len - pos;
            if (tail == 0) {
                release(cur);
                cur = next_block();
                if (!cur) return nullptr;
                view = cur->data;
                view_len = cur->len;
                pos = 0;
                continue;
            }
            memcpy(st.get(), view + pos, tail);
            release(cur);
            cur = next_block();
            if (!cur) { view = nullptr; view_len = 0; pos = 0; return nullptr; }
            size_t k = std::min(cur->len, MAX_RECORD + 64);
            memcpy(st.get() + tail, cur->data, k);
            tail_len = tail;
            view = st.get();
            view_len = tail + k;
            pos = 0;
            stitched = true;
        }
    }
    void consume(size_t n) { pos += n; }
    // parser stopped early: keep recycling blocks until the reader's END so it can finish and be joined
    void drain() {
        if (cur) { release(cur); cur = nullptr; }
        while (!eof) {
            Block *b = next_block();
            if (b) release(b);
        }
        view = nullptr;
        view_len = pos = 0;
        stitched = false;
    }
};

// ------------------------------------------------------------------------------------------- writer stage
struct Writer {
    Channel ch;
    std::vector<int> fds;
    int core = -1;
    std::thread th;
    Writer(int c) : ch(16, 4u << 20), core(c) {}

    int open_file(const std::string &path) {
        int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) { perror(path.c_str()); exit(2); }
        fds.push_back(fd);
        return (int)fds.size() - 1;
    }
    void start() { th = std::thread([this] { run(); }); }
    void run() {
        pin_this_thread(core);
        for (;;) {
            Block *b = ch.full.pop();
            if (b->tag & BLK_END) break;
            int fd = fds[b->tag];
            size_t off = 0;
            while (off < b->len) {
                ssize_t w = ::write(fd, b->data + off, b->len - off);
                if (w < 0 && errno == EINTR) continue;
                if (w <= 0) { perror("write"); _exit(8); }
                off += (size_t)w;
            }
            b->len = 0;
            ch.empty.push(b);
        }
        for (int fd : fds) ::close(fd);
    }
    // called by the parser thread once everything is flushed
    void finish() {
        Block *b = ch.empty.pop();
        b->len = 0;
        b->tag = BLK_END;
        ch.full.push(b);
        th.join();
    }
};

// parser-side output buffer: rows are formatted straight into a writer block; full blocks go to the writer
struct Out {
    Writer *w = nullptr;
    int id = 0;
    Block *blk = nullptr;
    char *p = nullptr;
    size_t n = 0, cap = 0;
    uint64_t rows = 0;

    void open(Writer &wr, const std::string &path, const std::string &header) {
        w = &wr;
        id = wr.open_file(path);
        grab();
        add(header.data(), header.size());
    }
    void grab() {
        blk = w->ch.empty.pop();
        p = (char *)blk->data;
        n = 0;
        cap = w->ch.block_size;
    }
    void flush() {
        if (!n) return;
        blk->len = n;
        blk->tag = (uint32_t)id;
        w->ch.full.push(blk);
        grab();
    }
    void check() { if (n > cap - (64u << 10)) flush(); }   // rows are far smaller than 64 KiB
    void close() {
        if (n) { blk->len = n; blk->tag = (uint32_t)id; w->ch.full.push(blk); }
        else { blk->len = 0; w->ch.empty.push(blk); }   // never used: hand it back
        blk = nullptr;
        n = 0;
    }
    void add(const char *s, size_t k) { memcpy(p + n, s, k); n += k; }
    void push_back(char c) { p[n++] = c; }
};

// parse "--pin r,p,w" into three core ids (-1 = not pinned)
inline void parse_pin(const char *s, int &r, int &p, int &w) {
    int v[3] = {-1, -1, -1};
    int k = 0;
    const char *q = s;
    while (*q && k < 3) {
        v[k++] = atoi(q);
        while (*q && *q != ',') q++;
        if (*q == ',') q++;
    }
    r = v[0]; p = v[1]; w = v[2];
}

}  // namespace hft
