// pcap_scan.cpp - find every packet capture under the given folders and say what is inside, fast.
//
// THIS IS HFT! NOT SHEEPLE CODING!!!
// Threads: N reader threads (each only reads capture files) -> one queue -> ONE writer thread (the only
// thread that writes). No thread does both. Read-only on the data folders; the only file written is --out.
//
//   ./pcap_scan /db_pcaps /md/iex_pcaps                       # names, sizes, dates (very fast)
//   ./pcap_scan --peek 4 --threads 16 /db_pcaps /md/iex_pcaps # also open the first 4 MB of each file
//   ./pcap_scan --peek 4 --from 20250203 --to 20250207 /db_pcaps
//
// Output: catalog.tsv (one row per file) + a summary per venue on the screen.
// --peek decompresses only the first MB of each file (.zst, .gz or plain) and reads the packets to find:
// the protocol (Nasdaq ITCH over MoldUDP64, CME MDP3, IEX-TP), the first packet time and the UDP ports.

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <map>
#include <mutex>
#include <queue>
#include <set>
#include <string>
#include <thread>
#include <vector>
#ifndef NO_ZSTD
#include <zstd.h>
#endif
#ifndef NO_ZLIB
#include <zlib.h>
#endif

namespace fs = std::filesystem;

struct Info {
    std::string path, venue = "unknown", proto = "-", date = "-", ftime = "-", comp = "none", first_utc = "-", ports = "-";
    uint64_t size = 0, packets = 0;
};

// ------------------------------------------------------------------ small helpers
static std::string lower(std::string s) { for (auto& c : s) c = (char)tolower((unsigned char)c); return s; }
static uint16_t be16(const uint8_t* p) { return (uint16_t)(p[0] << 8 | p[1]); }
static uint16_t le16(const uint8_t* p) { return (uint16_t)(p[0] | p[1] << 8); }
static uint32_t le32(const uint8_t* p) { return p[0] | p[1] << 8 | p[2] << 16 | (uint32_t)p[3] << 24; }
static uint32_t be32(const uint8_t* p) { return (uint32_t)p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3]; }
static uint64_t le64(const uint8_t* p) { return (uint64_t)le32(p) | (uint64_t)le32(p + 4) << 32; }

static bool is_capture(const std::string& name) {
    std::string n = lower(name);
    auto ends = [&](const char* s) { size_t k = strlen(s); return n.size() >= k && n.compare(n.size() - k, k, s) == 0; };
    return ends(".pcap") || ends(".pcap.zst") || ends(".pcap.gz") || ends(".pcapng") ||
           ((ends(".zst") || ends(".gz")) && n.find("pcap") != std::string::npos);
}

// first run of 8 digits that looks like a date 19xx/20xx, and the HHMMSS after a 'T'
static void find_date(const std::string& s, std::string& date, std::string& ftime) {
    for (size_t i = 0; i + 8 <= s.size(); ++i) {
        bool ok = true;
        for (size_t j = 0; j < 8; ++j) ok &= (bool)isdigit((unsigned char)s[i + j]);
        if (!ok || (i > 0 && isdigit((unsigned char)s[i - 1]))) continue;
        if (!(s.compare(i, 2, "19") == 0 || s.compare(i, 2, "20") == 0)) continue;
        int mo = std::stoi(s.substr(i + 4, 2)), dd = std::stoi(s.substr(i + 6, 2));
        if (mo < 1 || mo > 12 || dd < 1 || dd > 31) continue;
        if (date == "-") date = s.substr(i, 8);
        if (i + 15 <= s.size() && s[i + 8] == 'T') {
            bool t = true;
            for (size_t j = 9; j < 15; ++j) t &= (bool)isdigit((unsigned char)s[i + j]);
            if (t && ftime == "-") ftime = s.substr(i + 9, 6);
        }
    }
}

static std::string venue_from_path(const std::string& p) {
    std::string s = lower(p);
    if (s.find("xnas") != std::string::npos || s.find("itch") != std::string::npos || s.find("nasdaq") != std::string::npos) return "NASDAQ";
    if (s.find("glbx") != std::string::npos || s.find("cme") != std::string::npos || s.find("mdp") != std::string::npos) return "CME";
    if (s.find("iex") != std::string::npos) return "IEX";
    if (s.find("opra") != std::string::npos) return "OPRA";
    return "unknown";
}

// ------------------------------------------------------------------ reading the first bytes of a file
static size_t read_head(const std::string& path, const std::string& comp, std::vector<uint8_t>& out, size_t want) {
    out.resize(want);
    size_t got = 0;
    if (comp == "zst") {
#ifndef NO_ZSTD
        FILE* f = fopen(path.c_str(), "rb");
        if (!f) return 0;
        ZSTD_DStream* ds = ZSTD_createDStream();
        ZSTD_initDStream(ds);
        std::vector<uint8_t> in(1 << 17);
        ZSTD_outBuffer ob{out.data(), want, 0};
        while (ob.pos < want) {
            size_t n = fread(in.data(), 1, in.size(), f);
            if (!n) break;
            ZSTD_inBuffer ib{in.data(), n, 0};
            while (ib.pos < ib.size && ob.pos < want)
                if (ZSTD_isError(ZSTD_decompressStream(ds, &ob, &ib))) { ib.pos = ib.size; n = 0; break; }
            if (!n) break;
        }
        got = ob.pos;
        ZSTD_freeDStream(ds);
        fclose(f);
#endif
    } else if (comp == "gz") {
#ifndef NO_ZLIB
        gzFile g = gzopen(path.c_str(), "rb");
        if (!g) return 0;
        int n;
        while (got < want && (n = gzread(g, out.data() + got, (unsigned)std::min<size_t>(want - got, 1 << 20))) > 0) got += (size_t)n;
        gzclose(g);
#endif
    } else {
        FILE* f = fopen(path.c_str(), "rb");
        if (!f) return 0;
        got = fread(out.data(), 1, want, f);
        fclose(f);
    }
    out.resize(got);
    return got;
}

// ------------------------------------------------------------------ what protocol is this UDP payload?
static const char* classify(const uint8_t* p, size_t n, uint16_t& iex_proto) {
    // CME MDP3: MsgSeqNum u32 | SendingTime u64 (ns since 1970) | msgSize | blockLength | templateId | schemaId=1 | version
    if (n >= 22) {
        uint64_t t = le64(p + 4);
        if (t > 1500000000000000000ULL && t < 2100000000000000000ULL && le16(p + 18) == 1 && le16(p + 12) >= 10 && le16(p + 12) <= n - 12)
            return "CME-MDP3";
    }
    // IEX-TP: version=1 | reserved=0 | protocol id u16 | channel id u32 | session u32 | payload length u16 ... (40-byte header)
    if (n >= 40 && p[0] == 1 && p[1] == 0 && (le16(p + 2) & 0xFF00) == 0x8000 && le16(p + 12) == n - 40) {
        iex_proto = le16(p + 2);
        return "IEX-TP";
    }
    // MoldUDP64: session (10 printable chars) | sequence u64 | message count u16 | [len u16 | ITCH message] ...
    if (n >= 20) {
        bool sess = true;
        for (int i = 0; i < 10; ++i) sess &= (p[i] >= 32 && p[i] < 127);
        uint16_t cnt = be16(p + 18);
        if (sess && cnt == 0) return "MoldUDP64";
        if (sess && n >= 23 && be16(p + 20) >= 1 && be16(p + 20) <= n - 22 && strchr("SRHYLVWKJhAFECXDUPQBINO", p[22]) && p[22])
            return "NASDAQ-ITCH";
    }
    return nullptr;
}

static std::string utc_iso(uint64_t sec, uint64_t frac, bool nano) {
    time_t t = (time_t)sec;
    struct tm g;
    gmtime_r(&t, &g);
    char b[64];
    snprintf(b, sizeof b, "%04d-%02d-%02dT%02d:%02d:%02d.%09lluZ", g.tm_year + 1900, g.tm_mon + 1, g.tm_mday, g.tm_hour, g.tm_min,
             g.tm_sec, (unsigned long long)(nano ? frac : frac * 1000));
    return b;
}

static void peek(Info& f, size_t want) {
    std::vector<uint8_t> buf;
    size_t n = read_head(f.path, f.comp, buf, want);
    if (n < 24) { f.proto = n ? "too-short" : "unreadable"; return; }
    uint32_t m = le32(buf.data());
    bool swap = false, nano = false;
    if (m == 0xa1b2c3d4) {} else if (m == 0xa1b23c4d) nano = true;
    else if (m == 0xd4c3b2a1) swap = true; else if (m == 0x4d3cb2a1) { swap = true; nano = true; }
    else if (m == 0x0a0d0d0a) { f.proto = "pcapng(not-read)"; return; }
    else { f.proto = "not-pcap"; return; }
    auto rd32 = [&](const uint8_t* p) { return swap ? be32(p) : le32(p); };
    uint32_t link = rd32(buf.data() + 20);
    std::map<std::string, int> votes;
    std::map<uint16_t, int> ports;
    uint16_t iexp = 0;
    size_t off = 24;
    while (off + 16 <= n) {
        uint32_t sec = rd32(&buf[off]), frac = rd32(&buf[off + 4]), incl = rd32(&buf[off + 8]);
        if (incl > 262144 || off + 16 + incl > n) break;
        const uint8_t* pk = &buf[off + 16];
        if (f.packets == 0) f.first_utc = utc_iso(sec, frac, nano);
        ++f.packets;
        size_t ip = 0;
        bool ok = false;
        if (link == 1 && incl >= 14) {                       // Ethernet (+ VLAN tags)
            size_t e = 12;
            uint16_t et = be16(pk + e);
            while ((et == 0x8100 || et == 0x88a8) && e + 6 <= incl) { e += 4; et = be16(pk + e); }
            ip = e + 2; ok = (et == 0x0800);
        } else if (link == 113 && incl >= 16) { ip = 16; ok = be16(pk + 14) == 0x0800; }   // Linux cooked
        else if (link == 101 || link == 12 || link == 228) { ip = 0; ok = true; }            // raw IPv4
        if (ok && ip + 28 <= incl && (pk[ip] >> 4) == 4 && pk[ip + 9] == 17) {
            size_t ihl = (size_t)(pk[ip] & 15) * 4, u = ip + ihl;
            if (u + 8 <= incl) {
                ports[be16(pk + u + 2)]++;
                if (votes.size() < 8 || f.packets < 2000) {
                    const char* c = classify(pk + u + 8, incl - u - 8, iexp);
                    if (c) votes[c]++;
                }
            }
        }
        off += 16 + incl;
    }
    if (!votes.empty()) {
        auto best = std::max_element(votes.begin(), votes.end(), [](auto& a, auto& b) { return a.second < b.second; });
        f.proto = best->first;
        if (f.proto == "MoldUDP64" && votes.count("NASDAQ-ITCH")) f.proto = "NASDAQ-ITCH";
        if (f.proto == "IEX-TP") { char b[32]; snprintf(b, sizeof b, "IEX-TP(0x%04x)", iexp); f.proto = b; }
    } else f.proto = f.packets ? "udp-unknown" : "no-packets";
    std::vector<std::pair<int, uint16_t>> top;
    for (auto& [p, c] : ports) top.push_back({c, p});
    std::sort(top.rbegin(), top.rend());
    f.ports.clear();
    for (size_t i = 0; i < top.size() && i < 4; ++i) f.ports += (i ? "," : "") + std::to_string(top[i].second);
    if (f.ports.empty()) f.ports = "-";
    if (f.venue == "unknown") {
        if (f.proto == "NASDAQ-ITCH") f.venue = "NASDAQ";
        else if (f.proto == "CME-MDP3") f.venue = "CME";
        else if (f.proto.rfind("IEX", 0) == 0) f.venue = "IEX";
    }
}

// ------------------------------------------------------------------ main: readers -> queue -> one writer
int main(int argc, char** argv) {
    std::vector<std::string> roots;
    std::string out = "catalog.tsv", d0 = "00000000", d1 = "99999999";
    int threads = 8;
    size_t peek_mb = 0;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&]() { if (i + 1 >= argc) { fprintf(stderr, "%s needs a value\n", a.c_str()); exit(2); } return std::string(argv[++i]); };
        if (a == "--out") out = next();
        else if (a == "--threads") threads = std::stoi(next());
        else if (a == "--peek") peek_mb = (size_t)std::stoul(next());
        else if (a == "--from") d0 = next();
        else if (a == "--to") d1 = next();
        else if (a == "-h" || a == "--help") {
            printf("usage: pcap_scan [--peek MB] [--threads N<=32] [--from YYYYMMDD] [--to YYYYMMDD] [--out catalog.tsv] DIR...\n");
            return 0;
        } else roots.push_back(a);
    }
    if (roots.empty()) { fprintf(stderr, "give at least one folder, e.g. pcap_scan /db_pcaps\n"); return 2; }
    threads = std::max(1, std::min({threads, 32, (int)std::max(1u, std::thread::hardware_concurrency())}));

    // 1. list the files (directory walk only, no file contents read)
    std::vector<Info> files;
    for (auto& r : roots) {
        std::error_code ec;
        fs::recursive_directory_iterator it(r, fs::directory_options::skip_permission_denied, ec), end;
        if (ec) { fprintf(stderr, "cannot open %s: %s\n", r.c_str(), ec.message().c_str()); continue; }
        for (; it != end; it.increment(ec)) {
            if (ec) { ec.clear(); continue; }
            if (!it->is_regular_file(ec) || !is_capture(it->path().filename().string())) continue;
            Info f;
            f.path = it->path().string();
            f.size = it->file_size(ec);
            find_date(it->path().filename().string(), f.date, f.ftime);
            if (f.date == "-") find_date(f.path, f.date, f.ftime);
            if (f.date != "-" && (f.date < d0 || f.date > d1)) continue;
            std::string n = lower(f.path);
            f.comp = n.size() > 4 && n.substr(n.size() - 4) == ".zst" ? "zst" : n.size() > 3 && n.substr(n.size() - 3) == ".gz" ? "gz" : "none";
            f.venue = venue_from_path(f.path);
            files.push_back(std::move(f));
        }
    }
    std::sort(files.begin(), files.end(), [](const Info& a, const Info& b) { return a.path < b.path; });

    // 2. reader threads fill Info (they only read); the writer thread is the only one that writes
    FILE* fo = fopen(out.c_str(), "w");
    if (!fo) { fprintf(stderr, "cannot write %s\n", out.c_str()); return 1; }
    std::mutex mu;
    std::condition_variable cv;
    std::queue<size_t> done;
    std::atomic<size_t> next{0};
    std::atomic<int> readers_left{threads};
    auto reader = [&]() {
        for (size_t i; (i = next.fetch_add(1)) < files.size();) {
            if (peek_mb) peek(files[i], peek_mb << 20);
            { std::lock_guard<std::mutex> g(mu); done.push(i); }
            cv.notify_one();
        }
        if (--readers_left == 0) cv.notify_one();
    };
    std::thread writer([&]() {
        fprintf(fo, "path\tvenue\tprotocol\tdate\tfile_time\tsize_bytes\tcompression\tfirst_packet_utc\tpackets_peeked\tudp_ports\n");
        std::vector<char> ready(files.size(), 0);
        size_t emit = 0, seen = 0;
        while (seen < files.size()) {
            std::unique_lock<std::mutex> lk(mu);
            cv.wait(lk, [&] { return !done.empty() || readers_left == 0; });
            while (!done.empty()) { ready[done.front()] = 1; done.pop(); ++seen; }
            lk.unlock();
            while (emit < files.size() && ready[emit]) {      // keep the sorted order
                const Info& f = files[emit++];
                fprintf(fo, "%s\t%s\t%s\t%s\t%s\t%llu\t%s\t%s\t%llu\t%s\n", f.path.c_str(), f.venue.c_str(), f.proto.c_str(),
                        f.date.c_str(), f.ftime.c_str(), (unsigned long long)f.size, f.comp.c_str(), f.first_utc.c_str(),
                        (unsigned long long)f.packets, f.ports.c_str());
            }
            if (readers_left == 0 && done.empty() && seen >= files.size()) break;
        }
        fclose(fo);
    });
    std::vector<std::thread> pool;
    for (int t = 0; t < threads; ++t) pool.emplace_back(reader);
    for (auto& t : pool) t.join();
    cv.notify_one();
    writer.join();

    // 3. summary per venue / protocol (screen only)
    struct Sum { size_t files = 0; uint64_t bytes = 0; std::set<std::string> days; };
    std::map<std::string, Sum> sum;
    for (auto& f : files) {
        auto& s = sum[f.venue + (peek_mb ? "  " + f.proto : "")];
        s.files++; s.bytes += f.size;
        if (f.date != "-") s.days.insert(f.date);
    }
    printf("%zu capture file(s) -> %s   (%d reader thread(s)%s)\n", files.size(), out.c_str(), threads,
           peek_mb ? (", peek " + std::to_string(peek_mb) + " MB each").c_str() : "");
    printf("%-34s %7s %6s %10s  %s\n", "venue  protocol", "files", "days", "GB", "dates");
    for (auto& [k, s] : sum)
        printf("%-34s %7zu %6zu %10.1f  %s .. %s\n", k.c_str(), s.files, s.days.size(), s.bytes / 1e9,
               s.days.empty() ? "-" : s.days.begin()->c_str(), s.days.empty() ? "-" : s.days.rbegin()->c_str());
    return 0;
}
