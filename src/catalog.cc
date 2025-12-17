// catalog.cc - High-performance log file tokenizer and compressor
// Single-pass parallel encoding with concurrent hash map + mmap I/O

#include "mmap.h"
#include "template.h"
#include "token.h"

#include <chrono>
#include <cmath>
#include <cstdlib>
#include <getopt.h>
#include <iostream>
#include <thread>

using namespace catalog;

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

// Global thread count (0 = auto-detect)
static unsigned g_num_threads = 0;

// Global token estimate override (0 = auto-detect via sampling)
static size_t g_token_estimate = 0;

//=============================================================================
// Token Estimation (sampling-based)
//=============================================================================

static size_t estimate_unique_tokens(const char* data, size_t size) {
    constexpr size_t SAMPLE_SIZE = 4 * 1024 * 1024;
    size_t sample_bytes = std::min(size, SAMPLE_SIZE);

    if (sample_bytes < size) {
        while (sample_bytes < size && data[sample_bytes] != '\n') ++sample_bytes;
        if (sample_bytes < size) ++sample_bytes;
    }

    size_t capacity = std::min(sample_bytes / 2, size_t(1 << 20));
    TokenMap sample_map(capacity);
    std::atomic<uint32_t> next_id{0};

    const char* p = data;
    const char* end = data + sample_bytes;

    while (p < end) {
        while (p < end && (*p == ' ' || *p == '\t')) ++p;
        if (p >= end) break;

        if (*p == '\n' || *p == '\r') {
            p += (*p == '\r' && p + 1 < end && *(p + 1) == '\n') ? 2 : 1;
            continue;
        }

        const char* tok = p;
        while (p < end && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') ++p;
        sample_map.get_or_insert(tok, p - tok, next_id);
    }

    size_t sample_uniques = next_id.load();

    if (sample_bytes >= size) {
        return std::max(size_t(1024), sample_uniques * 2);
    }

    double ratio = static_cast<double>(size) / sample_bytes;
    size_t sampled_estimate = static_cast<size_t>(sample_uniques * std::sqrt(ratio) * 2);
    size_t baseline = size / 64;
    size_t estimated = std::max(sampled_estimate, baseline);

    return std::max(size_t(1024), std::min(estimated, size_t(1) << 26));
}

//=============================================================================
// Encoder / Decoder
//=============================================================================

class Catalog {
public:
    bool encode(const char* input_path, const char* output_path);
    bool tokenize(const char* input_path);
    bool decode(const char* input_path, const char* output_path);
    void print_stats() const;

private:
    unsigned get_thread_count(size_t file_size) const;
    size_t original_size_ = 0;
    size_t compressed_size_ = 0;
    size_t line_count_ = 0;
    size_t token_count_ = 0;
    size_t hash_capacity_ = 0;
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

    unsigned num_threads = get_thread_count(size);

    size_t est_tokens = g_token_estimate > 0 ? g_token_estimate :
                        ((data && size > 0) ? estimate_unique_tokens(data, size) : 1024);
    TokenMap tokens(est_tokens * 2);
    std::atomic<uint32_t> next_id{0};
    std::atomic<size_t> total_lines{0};
    std::atomic<bool> overflow{false};

    auto chunks = calculate_chunks(data, size, num_threads);

    struct Buffer { std::vector<char> data; size_t lines = 0; };
    std::vector<Buffer> buffers(num_threads);

    std::vector<std::thread> threads;
    for (unsigned t = 0; t < num_threads; ++t) {
        threads.emplace_back([&, t]() {
            auto& buf = buffers[t];
            const char* p = chunks[t].first;
            const char* end = chunks[t].second;

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
                uint32_t id = tokens.get_or_insert(tok, p - tok, next_id);
                if (id == UINT32_MAX) {
                    overflow.store(true, std::memory_order_relaxed);
                    return;
                }
                line.push_back(id);
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

    if (overflow.load()) {
        std::cerr << "Error: token table overflow. Use -e to set higher estimate.\n";
        return false;
    }

    token_count_ = next_id.load();
    line_count_ = total_lines.load();
    hash_capacity_ = tokens.capacity();

    const std::string_view* token_list = tokens.get_ordered_tokens();

    size_t dict_size = 0;
    for (size_t i = 0; i < token_count_; ++i) {
        dict_size += sizeof(uint16_t) + token_list[i].size();
    }

    size_t lines_size = 0;
    for (const auto& buf : buffers) lines_size += buf.data.size();

    size_t total_size = sizeof(CatalogHeader) + dict_size + lines_size;

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

    auto end_time = std::chrono::high_resolution_clock::now();
    encode_time_ms_ = std::chrono::duration<double, std::milli>(end_time - start).count();
    return true;
}

unsigned Catalog::get_thread_count(size_t file_size) const {
    unsigned num_threads = g_num_threads;
    if (num_threads == 0) {
        num_threads = std::thread::hardware_concurrency();
        if (num_threads == 0) num_threads = 4;
    }
    if (file_size < 1024 * 1024) num_threads = 1;
    return num_threads;
}

bool Catalog::tokenize(const char* input_path) {
    auto start = std::chrono::high_resolution_clock::now();

    MappedFile in;
    if (!in.open_read(input_path)) {
        std::cerr << "Failed to open input\n";
        return false;
    }

    original_size_ = in.size;
    const char* data = in.data;
    const size_t size = in.size;

    unsigned num_threads = get_thread_count(size);

    size_t est_tokens = g_token_estimate > 0 ? g_token_estimate :
                        ((data && size > 0) ? estimate_unique_tokens(data, size) : 1024);
    TokenMap tokens(est_tokens * 2);
    std::atomic<uint32_t> next_id{0};
    std::atomic<size_t> total_lines{0};
    std::atomic<bool> overflow{false};

    auto chunks = calculate_chunks(data, size, num_threads);

    std::vector<std::thread> threads;
    for (unsigned t = 0; t < num_threads; ++t) {
        threads.emplace_back([&, t]() {
            const char* p = chunks[t].first;
            const char* end = chunks[t].second;
            size_t lines = 0;

            if (p == nullptr || end == nullptr || p >= end) return;

            while (p < end) {
                while (p < end && (*p == ' ' || *p == '\t')) ++p;
                if (p >= end) break;

                if (*p == '\n' || *p == '\r') {
                    ++lines;
                    p += (*p == '\r' && p + 1 < end && *(p + 1) == '\n') ? 2 : 1;
                    continue;
                }

                const char* tok = p;
                while (p < end && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') ++p;
                uint32_t id = tokens.get_or_insert(tok, p - tok, next_id);
                if (id == UINT32_MAX) {
                    overflow.store(true, std::memory_order_relaxed);
                    return;
                }
            }

            total_lines.fetch_add(lines, std::memory_order_relaxed);
        });
    }
    for (auto& t : threads) t.join();

    if (overflow.load()) {
        std::cerr << "Error: token table overflow. Use -e to set higher estimate.\n";
        return false;
    }

    token_count_ = next_id.load();
    line_count_ = total_lines.load();
    hash_capacity_ = tokens.capacity();
    compressed_size_ = 0;

    auto end_time = std::chrono::high_resolution_clock::now();
    encode_time_ms_ = std::chrono::duration<double, std::milli>(end_time - start).count();
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
    double load_factor = hash_capacity_ > 0 ? 100.0 * token_count_ / hash_capacity_ : 0;

    std::cout << "=== Catalog Statistics ===\n"
              << "Original:    " << original_size_ / (1024.0*1024.0) << " MB\n"
              << "Compressed:  " << compressed_size_ / (1024.0*1024.0) << " MB\n"
              << "Ratio:       " << ratio << "%\n"
              << "Tokens:      " << token_count_ << "\n"
              << "Lines:       " << line_count_ << "\n"
              << "HashCap:     " << hash_capacity_ << " (" << load_factor << "% load)\n"
              << "Time:        " << encode_time_ms_ << " ms\n"
              << "Throughput:  " << tp << " MB/s\n";
}

int main(int argc, char* argv[]) {
    auto usage = [&]() {
        std::cerr << "Usage:\n"
                  << "  " << argv[0] << " [options] <file1> [file2...]  (default: template extraction)\n"
                  << "  " << argv[0] << " [options] encode <input> <output>\n"
                  << "  " << argv[0] << " [options] decode <input> <output>\n"
                  << "  " << argv[0] << " [options] bench <input>\n"
                  << "  " << argv[0] << " [options] tokenize <input>\n"
                  << "\nOptions:\n"
                  << "  -t, --threads <num>   Number of threads (default: auto-detect)\n"
                  << "  -e, --estimate <num>  Estimated unique tokens (default: auto)\n"
                  << "  -h, --help            Show this help message\n"
                  << "\nTemplate extraction options:\n"
                  << "  --top <n>             Show top N results (default: 20)\n"
                  << "  -x, --exclude <str>   Exclude lines containing <str> (repeatable)\n"
                  << "  -q, --quiet           Minimal output\n"
                  << "  -v, --verbose         Detailed output\n";
        return 1;
    };

    static struct option long_options[] = {
        {"threads",  required_argument, nullptr, 't'},
        {"estimate", required_argument, nullptr, 'e'},
        {"help",     no_argument,       nullptr, 'h'},
        {"top",      required_argument, nullptr, 'T'},
        {"exclude",  required_argument, nullptr, 'x'},
        {"quiet",    no_argument,       nullptr, 'q'},
        {"verbose",  no_argument,       nullptr, 'v'},
        {nullptr,    0,                 nullptr, 0}
    };

    size_t top_n = 20;
    bool quiet = false;
    bool verbose = false;
    std::vector<std::string> exclude_patterns;

    int opt;
    while ((opt = getopt_long(argc, argv, "t:e:hqvx:", long_options, nullptr)) != -1) {
        switch (opt) {
            case 't': g_num_threads = std::atoi(optarg); break;
            case 'e': g_token_estimate = std::atol(optarg); break;
            case 'h': return usage();
            case 'T': top_n = std::atol(optarg); break;
            case 'x': exclude_patterns.push_back(optarg); break;
            case 'q': quiet = true; break;
            case 'v': verbose = true; break;
            default:  return usage();
        }
    }

    int remaining = argc - optind;
    if (remaining < 1) return usage();

    std::string first_arg = argv[optind];

    // Check if first arg is a command
    Catalog cat;
    if (first_arg == "encode" && remaining >= 3) {
        if (!cat.encode(argv[optind + 1], argv[optind + 2])) return 1;
        cat.print_stats();
    } else if (first_arg == "decode" && remaining >= 3) {
        if (!cat.decode(argv[optind + 1], argv[optind + 2])) return 1;
        std::cout << "Decoded.\n";
    } else if (first_arg == "bench" && remaining >= 2) {
        std::string out = std::string(argv[optind + 1]) + "c";
        if (!cat.encode(argv[optind + 1], out.c_str())) return 1;
        cat.print_stats();
    } else if (first_arg == "tokenize" && remaining >= 2) {
        if (!cat.tokenize(argv[optind + 1])) return 1;
        cat.print_stats();
    } else {
        // Default: template extraction (supports 1+ files)
        TemplateConfig config;
        for (int i = optind; i < argc; ++i) {
            config.input_files.push_back(argv[i]);
        }
        config.num_threads = g_num_threads;
        config.top_n = top_n;
        config.quiet = quiet;
        config.verbose = verbose;
        config.exclude_patterns = std::move(exclude_patterns);

        TemplateResult result;
        if (!extract_templates(config, result)) return 1;
    }

    return 0;
}
