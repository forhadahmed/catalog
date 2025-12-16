// catalog.cc - High-performance log file tokenizer and compressor
// Single-pass parallel encoding with concurrent hash map + mmap I/O

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <string>
#include <string_view>
#include <sys/mman.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <vector>

#ifdef __x86_64__
#include <emmintrin.h>
#else
#define _mm_pause() ((void)0)
#endif

// Binary format header
struct CatalogHeader {
    uint32_t magic;
    uint32_t version;
    uint32_t token_id_bytes;
    uint32_t token_count;
    uint64_t line_count;
    uint64_t original_size;
    uint64_t dict_offset;
    uint64_t data_offset;
};

static constexpr uint32_t MAGIC = 0x474C5443;
static constexpr uint32_t VERSION = 1;

//=============================================================================
// Fast Lock-Free Hash Map
//=============================================================================

class TokenMap {
public:
    struct Slot {
        uint64_t hash;      // Use raw types + atomic ops
        uint32_t id;
        const char* ptr;
        uint32_t len;
    };

    explicit TokenMap(size_t capacity) {
        capacity_ = 1;
        while (capacity_ < capacity) capacity_ *= 2;
        mask_ = capacity_ - 1;
        slots_ = static_cast<Slot*>(calloc(capacity_, sizeof(Slot)));
        // Pre-allocate ordered token storage to eliminate get_tokens() scan
        ordered_tokens_.resize(capacity_);
    }

    ~TokenMap() { free(slots_); }

    uint32_t get_or_insert(const char* ptr, size_t len, std::atomic<uint32_t>& next_id) {
        uint64_t h = hash(ptr, len);
        if (h == 0) h = 1;

        size_t idx = h & mask_;

        for (size_t probe = 0; probe < capacity_; ++probe) {
            Slot& s = slots_[idx];
            uint64_t current = __atomic_load_n(&s.hash, __ATOMIC_RELAXED);

            if (current == 0) {
                uint64_t expected = 0;
                if (__atomic_compare_exchange_n(&s.hash, &expected, h,
                        false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
                    uint32_t new_id = next_id.fetch_add(1, std::memory_order_relaxed);
                    s.ptr = ptr;
                    s.len = static_cast<uint32_t>(len);
                    // Store in ordered vector - thread-safe: each ID is unique
                    ordered_tokens_[new_id] = std::string_view(ptr, len);
                    __atomic_store_n(&s.id, new_id, __ATOMIC_RELEASE);
                    return new_id;
                }
                current = __atomic_load_n(&s.hash, __ATOMIC_ACQUIRE);
            }

            if (current == h) {
                while (s.ptr == nullptr) _mm_pause();
                if (s.len == len && memcmp(s.ptr, ptr, len) == 0) {
                    return __atomic_load_n(&s.id, __ATOMIC_ACQUIRE);
                }
            }

            idx = (idx + 1) & mask_;
        }

        return UINT32_MAX;
    }

    // O(1) access to ordered tokens - no scan needed
    const std::string_view* get_ordered_tokens() const {
        return ordered_tokens_.data();
    }

private:
    static uint64_t hash(const char* data, size_t len) {
        uint64_t h = 14695981039346656037ULL;
        while (len >= 8) {
            uint64_t k;
            memcpy(&k, data, 8);
            h ^= k;
            h *= 1099511628211ULL;
            data += 8;
            len -= 8;
        }
        while (len--) {
            h ^= static_cast<uint8_t>(*data++);
            h *= 1099511628211ULL;
        }
        return h;
    }

    size_t capacity_;
    size_t mask_;
    Slot* slots_;
    std::vector<std::string_view> ordered_tokens_;  // Eliminates O(capacity) scan
};

//=============================================================================
// Memory-Mapped I/O
//=============================================================================

struct MappedFile {
    int fd = -1;
    char* data = nullptr;
    size_t size = 0;

    bool open_read(const char* path) {
        fd = ::open(path, O_RDONLY);
        if (fd < 0) return false;

        struct stat st;
        if (fstat(fd, &st) < 0) { close(); return false; }
        size = st.st_size;

        // Handle empty files (mmap fails with size 0)
        if (size == 0) {
            data = nullptr;
            return true;
        }

        data = static_cast<char*>(mmap(nullptr, size, PROT_READ,
                                        MAP_PRIVATE | MAP_POPULATE, fd, 0));
        if (data == MAP_FAILED) { data = nullptr; close(); return false; }

        madvise(data, size, MADV_SEQUENTIAL | MADV_WILLNEED);
        return true;
    }

    bool open_write(const char* path, size_t max_size) {
        fd = ::open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) return false;

        size = max_size;

        // Handle empty output (mmap fails with size 0)
        if (size == 0) {
            data = nullptr;
            return true;
        }

        if (ftruncate(fd, size) < 0) { close(); return false; }

        data = static_cast<char*>(mmap(nullptr, size, PROT_READ | PROT_WRITE,
                                        MAP_SHARED, fd, 0));
        if (data == MAP_FAILED) { data = nullptr; close(); return false; }
        return true;
    }

    void finalize(size_t actual_size) {
        if (data) { munmap(data, size); data = nullptr; }
        if (fd >= 0) { ftruncate(fd, actual_size); ::close(fd); fd = -1; }
    }

    void close() {
        if (data) { munmap(data, size); data = nullptr; }
        if (fd >= 0) { ::close(fd); fd = -1; }
    }

    ~MappedFile() { close(); }
};

//=============================================================================
// Encoder / Decoder
//=============================================================================

class Catalog {
public:
    bool encode(const char* input_path, const char* output_path);
    bool decode(const char* input_path, const char* output_path);
    void print_stats() const;

private:
    size_t original_size_ = 0;
    size_t compressed_size_ = 0;
    size_t line_count_ = 0;
    size_t token_count_ = 0;
    double encode_time_ms_ = 0;
};

bool Catalog::encode(const char* input_path, const char* output_path) {
    auto start = std::chrono::high_resolution_clock::now();

    MappedFile in;
    if (!in.open_read(input_path)) {
        std::cerr << "Failed to open input\n";
        return false;
    }

    original_size_ = in.size;
    const char* data = in.data;
    const size_t size = in.size;

    unsigned num_threads = std::thread::hardware_concurrency();
    if (num_threads == 0) num_threads = 4;

    // Allow override via environment variable for benchmarking
    if (const char* env = std::getenv("CATALOG_THREADS")) {
        num_threads = std::atoi(env);
        if (num_threads == 0) num_threads = 4;
    }

    // Use single thread for small files to avoid chunk overlap issues
    if (size < 4096) num_threads = 1;

    // Hash map sized for ~50% load factor
    size_t est_tokens = std::min(size / 4, size_t(1) << 26);
    TokenMap tokens(est_tokens * 2);
    std::atomic<uint32_t> next_id{0};
    std::atomic<size_t> total_lines{0};

    // Chunk boundaries (handle empty/small files)
    std::vector<std::pair<const char*, const char*>> chunks(num_threads);
    if (size > 0 && data != nullptr) {
        for (unsigned i = 0; i < num_threads; ++i) {
            const char* s = data + (size * i) / num_threads;
            const char* e = data + (size * (i + 1)) / num_threads;

            // Align start to line boundary (skip to after previous newline)
            if (i > 0 && s > data) {
                while (s < data + size && *(s - 1) != '\n') ++s;
            }
            // Align end to line boundary (only if not already at line start)
            if (i < num_threads - 1 && e > data && *(e - 1) != '\n') {
                while (e < data + size && *e != '\n') ++e;
                if (e < data + size) ++e;
            }
            chunks[i] = {s, e};
        }
    } else {
        // Empty file: all chunks are empty
        for (unsigned i = 0; i < num_threads; ++i) {
            chunks[i] = {nullptr, nullptr};
        }
    }

    // Per-thread output buffers
    struct Buffer { std::vector<char> data; size_t lines = 0; };
    std::vector<Buffer> buffers(num_threads);

    // Parallel encode
    std::vector<std::thread> threads;
    for (unsigned t = 0; t < num_threads; ++t) {
        threads.emplace_back([&, t]() {
            auto& buf = buffers[t];
            const char* p = chunks[t].first;
            const char* end = chunks[t].second;

            // Handle empty chunks
            if (p == nullptr || end == nullptr || p >= end) {
                return;
            }

            buf.data.reserve(end - p);
            std::vector<uint32_t> line;
            line.reserve(128);

            while (p < end) {
                while (p < end && (*p == ' ' || *p == '\t')) ++p;
                if (p >= end) break;

                if (*p == '\n' || *p == '\r') {
                    if (!line.empty()) {
                        size_t entry = sizeof(uint16_t) + line.size() * sizeof(uint32_t);
                        size_t off = buf.data.size();
                        buf.data.resize(off + entry);
                        char* out = buf.data.data() + off;
                        uint16_t cnt = static_cast<uint16_t>(line.size());
                        memcpy(out, &cnt, sizeof(cnt));
                        memcpy(out + sizeof(cnt), line.data(), line.size() * sizeof(uint32_t));
                        line.clear();
                        ++buf.lines;
                    }
                    p += (*p == '\r' && p + 1 < end && *(p + 1) == '\n') ? 2 : 1;
                    continue;
                }

                const char* tok = p;
                while (p < end && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') ++p;
                line.push_back(tokens.get_or_insert(tok, p - tok, next_id));
            }

            if (!line.empty()) {
                size_t entry = sizeof(uint16_t) + line.size() * sizeof(uint32_t);
                size_t off = buf.data.size();
                buf.data.resize(off + entry);
                char* out = buf.data.data() + off;
                uint16_t cnt = static_cast<uint16_t>(line.size());
                memcpy(out, &cnt, sizeof(cnt));
                memcpy(out + sizeof(cnt), line.data(), line.size() * sizeof(uint32_t));
                ++buf.lines;
            }

            total_lines.fetch_add(buf.lines, std::memory_order_relaxed);
        });
    }
    for (auto& t : threads) t.join();

    token_count_ = next_id.load();
    line_count_ = total_lines.load();

    // Get ordered token list - O(1) access, no scan needed
    const std::string_view* token_list = tokens.get_ordered_tokens();

    // Calculate sizes
    size_t dict_size = 0;
    for (size_t i = 0; i < token_count_; ++i) {
        dict_size += sizeof(uint16_t) + token_list[i].size();
    }

    size_t lines_size = 0;
    for (const auto& buf : buffers) lines_size += buf.data.size();

    size_t total_size = sizeof(CatalogHeader) + dict_size + lines_size;

    // Write output
    MappedFile out;
    if (!out.open_write(output_path, total_size)) {
        std::cerr << "Failed to open output\n";
        return false;
    }

    char* ptr = out.data;

    CatalogHeader hdr{MAGIC, VERSION, 4, static_cast<uint32_t>(token_count_),
                      line_count_, original_size_, sizeof(CatalogHeader),
                      sizeof(CatalogHeader) + dict_size};
    memcpy(ptr, &hdr, sizeof(hdr));
    ptr += sizeof(hdr);

    for (size_t i = 0; i < token_count_; ++i) {
        const auto& tok = token_list[i];
        uint16_t len = static_cast<uint16_t>(tok.size());
        memcpy(ptr, &len, sizeof(len)); ptr += sizeof(len);
        memcpy(ptr, tok.data(), tok.size()); ptr += tok.size();
    }

    for (const auto& buf : buffers) {
        memcpy(ptr, buf.data.data(), buf.data.size());
        ptr += buf.data.size();
    }

    out.finalize(total_size);
    compressed_size_ = total_size;

    auto end = std::chrono::high_resolution_clock::now();
    encode_time_ms_ = std::chrono::duration<double, std::milli>(end - start).count();
    return true;
}

bool Catalog::decode(const char* input_path, const char* output_path) {
    MappedFile in;
    if (!in.open_read(input_path)) {
        std::cerr << "Failed to open input\n";
        return false;
    }

    if (in.size < sizeof(CatalogHeader)) {
        std::cerr << "Invalid file\n";
        return false;
    }

    const auto* hdr = reinterpret_cast<const CatalogHeader*>(in.data);
    if (hdr->magic != MAGIC) {
        std::cerr << "Invalid magic\n";
        return false;
    }

    std::vector<std::string_view> tokens(hdr->token_count);
    const char* p = in.data + hdr->dict_offset;
    for (uint32_t i = 0; i < hdr->token_count; ++i) {
        uint16_t len = *reinterpret_cast<const uint16_t*>(p);
        p += sizeof(uint16_t);
        tokens[i] = std::string_view(p, len);
        p += len;
    }

    MappedFile out;
    if (!out.open_write(output_path, hdr->original_size + hdr->line_count)) {
        std::cerr << "Failed to open output\n";
        return false;
    }

    char* o = out.data;
    p = in.data + hdr->data_offset;
    const char* end = in.data + in.size;

    while (p < end) {
        uint16_t count = *reinterpret_cast<const uint16_t*>(p);
        p += sizeof(uint16_t);
        for (uint16_t i = 0; i < count; ++i) {
            uint32_t id = *reinterpret_cast<const uint32_t*>(p);
            p += sizeof(uint32_t);
            if (i > 0) *o++ = ' ';
            if (id < tokens.size()) {
                memcpy(o, tokens[id].data(), tokens[id].size());
                o += tokens[id].size();
            }
        }
        *o++ = '\n';
    }

    out.finalize(o - out.data);
    return true;
}

void Catalog::print_stats() const {
    double ratio = original_size_ > 0 ? 100.0 * compressed_size_ / original_size_ : 0;
    double tp = encode_time_ms_ > 0 ? original_size_ / (1024.0*1024.0) / (encode_time_ms_/1000.0) : 0;

    std::cout << "=== Catalog Statistics ===\n"
              << "Original:    " << original_size_ / (1024.0*1024.0) << " MB\n"
              << "Compressed:  " << compressed_size_ / (1024.0*1024.0) << " MB\n"
              << "Ratio:       " << ratio << "%\n"
              << "Tokens:      " << token_count_ << "\n"
              << "Lines:       " << line_count_ << "\n"
              << "Time:        " << encode_time_ms_ << " ms\n"
              << "Throughput:  " << tp << " MB/s\n";
}

int main(int argc, char* argv[]) {
    auto usage = [&]() {
        std::cerr << "Usage:\n"
                  << "  " << argv[0] << " encode <input> <output>\n"
                  << "  " << argv[0] << " decode <input> <output>\n"
                  << "  " << argv[0] << " bench <input>\n";
        return 1;
    };

    if (argc < 3) return usage();

    Catalog cat;
    std::string cmd = argv[1];

    if (cmd == "encode" && argc >= 4) {
        if (!cat.encode(argv[2], argv[3])) return 1;
        cat.print_stats();
    } else if (cmd == "decode" && argc >= 4) {
        if (!cat.decode(argv[2], argv[3])) return 1;
        std::cout << "Decoded.\n";
    } else if (cmd == "bench" && argc >= 3) {
        std::string out = std::string(argv[2]) + "c";
        if (!cat.encode(argv[2], out.c_str())) return 1;
        cat.print_stats();
    } else {
        return usage();
    }

    return 0;
}
