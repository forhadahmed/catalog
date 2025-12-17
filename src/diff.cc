// diff.cc - Multi-log diff implementation
// Template extraction with variable deduplication

#include "diff.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <fcntl.h>
#include <iostream>
#include <sys/mman.h>
#include <sys/stat.h>
#include <deque>
#include <mutex>
#include <thread>
#include <unistd.h>

//=============================================================================
// DiffTokenMap (local copy to avoid ODR with catalog.cc)
//=============================================================================

class DiffTokenMap {
public:
    struct Slot {
        uint64_t hash;
        uint32_t id;
        const char* ptr;
        uint32_t len;
    };

    explicit DiffTokenMap(size_t capacity) {
        capacity_ = 1;
        while (capacity_ < capacity) capacity_ *= 2;
        mask_ = capacity_ - 1;
        slots_ = static_cast<Slot*>(calloc(capacity_, sizeof(Slot)));
        ordered_tokens_.resize(capacity_);
        // owned_strings_ is a deque - references remain stable on push_back
    }

    ~DiffTokenMap() { free(slots_); }

    // Insert a normalized token (owns the string data)
    uint32_t insert_owned(const std::string& str, std::atomic<uint32_t>& next_id) {
        // First, check if token already exists (without lock)
        uint64_t h = hash(str.c_str(), str.size());
        if (h == 0) h = 1;
        size_t idx = h & mask_;
        size_t max_probes = capacity_ * 7 / 10;

        for (size_t probe = 0; probe < max_probes; ++probe) {
            Slot& s = slots_[idx];
            uint64_t current = __atomic_load_n(&s.hash, __ATOMIC_RELAXED);

            if (current == 0) break;  // Not found, need to insert

            if (current == h) {
                const char* slot_ptr;
                while ((slot_ptr = __atomic_load_n(&s.ptr, __ATOMIC_ACQUIRE)) == nullptr) {
                    _mm_pause();
                }
                if (s.len == str.size() && memcmp(slot_ptr, str.c_str(), str.size()) == 0) {
                    return __atomic_load_n(&s.id, __ATOMIC_ACQUIRE);  // Found existing
                }
            }
            idx = (idx + 1) & mask_;
        }

        // Not found - need to store owned copy and insert
        std::lock_guard<std::mutex> lock(owned_mutex_);
        owned_strings_.push_back(str);
        const std::string& stored = owned_strings_.back();
        return get_or_insert(stored.c_str(), stored.size(), next_id);
    }

    uint32_t get_or_insert(const char* ptr, size_t len, std::atomic<uint32_t>& next_id) {
        uint64_t h = hash(ptr, len);
        if (h == 0) h = 1;

        size_t idx = h & mask_;
        size_t max_probes = capacity_ * 7 / 10;

        for (size_t probe = 0; probe < max_probes; ++probe) {
            Slot& s = slots_[idx];
            uint64_t current = __atomic_load_n(&s.hash, __ATOMIC_RELAXED);

            if (current == 0) {
                uint64_t expected = 0;
                if (__atomic_compare_exchange_n(&s.hash, &expected, h,
                        false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
                    uint32_t new_id = next_id.fetch_add(1, std::memory_order_relaxed);
                    s.len = static_cast<uint32_t>(len);
                    ordered_tokens_[new_id] = std::string_view(ptr, len);
                    __atomic_store_n(&s.id, new_id, __ATOMIC_RELEASE);
                    __atomic_store_n(&s.ptr, ptr, __ATOMIC_RELEASE);
                    return new_id;
                }
                current = __atomic_load_n(&s.hash, __ATOMIC_ACQUIRE);
            }

            if (current == h) {
                const char* slot_ptr;
                while ((slot_ptr = __atomic_load_n(&s.ptr, __ATOMIC_ACQUIRE)) == nullptr) {
                    _mm_pause();
                }
                if (s.len == len && memcmp(slot_ptr, ptr, len) == 0) {
                    return __atomic_load_n(&s.id, __ATOMIC_ACQUIRE);
                }
            }

            idx = (idx + 1) & mask_;
        }

        return UINT32_MAX;
    }

    const std::string_view* get_ordered_tokens() const {
        return ordered_tokens_.data();
    }

    std::string_view get_token(uint32_t id) const {
        return ordered_tokens_[id];
    }

    size_t capacity() const { return capacity_; }

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
    std::vector<std::string_view> ordered_tokens_;
    std::deque<std::string> owned_strings_;  // Persistent storage for normalized tokens (deque for stable refs)
    std::mutex owned_mutex_;  // Protects owned_strings_
};

//=============================================================================
// DiffMappedFile (local copy to avoid ODR with catalog.cc)
//=============================================================================

struct DiffMappedFile {
    int fd = -1;
    char* data = nullptr;
    size_t size = 0;
    std::string path;

    bool open(const char* p) {
        path = p;
        fd = ::open(p, O_RDONLY);
        if (fd < 0) return false;

        struct stat st;
        if (fstat(fd, &st) < 0) { close_file(); return false; }
        size = st.st_size;

        if (size == 0) {
            data = nullptr;
            return true;
        }

        data = static_cast<char*>(mmap(nullptr, size, PROT_READ,
                                        MAP_PRIVATE | MAP_POPULATE, fd, 0));
        if (data == MAP_FAILED) { data = nullptr; close_file(); return false; }

        madvise(data, size, MADV_SEQUENTIAL | MADV_WILLNEED);
        return true;
    }

    void close_file() {
        if (data) { munmap(data, size); data = nullptr; }
        if (fd >= 0) { ::close(fd); fd = -1; }
    }

    ~DiffMappedFile() { close_file(); }
};

//=============================================================================
// Sub-token Pattern Extraction
// Uses unified match_* functions from diff.h
//=============================================================================

// Extracted variable from sub-token
struct ExtractedVar {
    VarType type;
    size_t start;
    size_t len;
};

// Try to match a K:V pattern where V is a variable type
// Returns position of colon if found and V is variable, 0 otherwise
static size_t try_match_kv_pattern(const char* s, size_t len, VarType& value_type) {
    // Find rightmost colon (to handle cases like "foo:bar:123" -> "foo:bar" : "123")
    size_t colon_pos = 0;
    for (size_t i = len; i > 0; --i) {
        if (s[i-1] == ':') {
            colon_pos = i - 1;
            break;
        }
    }

    if (colon_pos == 0 || colon_pos >= len - 1) return 0;  // No colon or at edges

    // Check if the part before colon is a valid key (has at least one letter)
    bool has_letter = false;
    for (size_t i = 0; i < colon_pos; ++i) {
        char c = s[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
            has_letter = true;
            break;
        }
    }
    if (!has_letter) return 0;  // Key must have at least one letter

    // Check if the value part is a variable type
    const char* value = s + colon_pos + 1;
    size_t value_len = len - colon_pos - 1;

    value_type = classify_token(value, value_len);
    if (value_type != VarType::LITERAL) {
        return colon_pos;  // Found K:V pattern
    }

    return 0;  // Value is literal, not a K:V pattern we want to extract
}

// Normalize a token by replacing embedded patterns with placeholders
// Returns true if any patterns were extracted
static bool normalize_token(const char* s, size_t len,
                           std::string& normalized,
                           std::vector<ExtractedVar>& extracted) {
    normalized.clear();
    extracted.clear();
    normalized.reserve(len + 32);

    // First, check if the whole token is a known colon-containing type
    // This prevents K:V extraction from breaking IPv6 and timestamps
    VarType whole_type = classify_token(s, len);
    if (whole_type == VarType::VAR_IP || whole_type == VarType::VAR_TIME) {
        // Don't try to extract from known colon-containing types
        normalized.assign(s, len);
        return false;
    }

    // Try K:V pattern extraction (e.g., PeerId:47 -> PeerId:<NUM>)
    VarType kv_value_type;
    size_t colon_pos = try_match_kv_pattern(s, len, kv_value_type);
    if (colon_pos > 0) {
        // Found K:V pattern - normalize to Key:<TYPE>
        normalized.append(s, colon_pos + 1);  // Include "Key:"
        normalized += var_type_placeholder(kv_value_type);
        extracted.push_back({kv_value_type, colon_pos + 1, len - colon_pos - 1});
        return true;
    }

    size_t i = 0;
    bool had_extractions = false;

    while (i < len) {
        // Try IPv4 (with optional CIDR)
        bool ipv4_has_cidr = false;
        size_t ip_len = match_ipv4(s + i, len - i, &ipv4_has_cidr);
        if (ip_len > 0) {
            if (ipv4_has_cidr) {
                extracted.push_back({VarType::VAR_PREFIX, i, ip_len});
                normalized += "<PREFIX>";
            } else {
                extracted.push_back({VarType::VAR_IP, i, ip_len});
                normalized += "<IP>";
            }
            i += ip_len;
            had_extractions = true;
            continue;
        }

        // Try IPv6 (with optional CIDR)
        // Don't match if preceded by a letter - likely C++ namespace (Queue::add)
        bool prev_is_letter = (i > 0) && ((s[i-1] >= 'a' && s[i-1] <= 'z') ||
                                           (s[i-1] >= 'A' && s[i-1] <= 'Z'));
        if (!prev_is_letter) {
            bool ipv6_has_cidr = false;
            size_t ipv6_len = match_ipv6(s + i, len - i, &ipv6_has_cidr);
            if (ipv6_len > 0) {
                if (ipv6_has_cidr) {
                    extracted.push_back({VarType::VAR_PREFIX, i, ipv6_len});
                    normalized += "<PREFIX>";
                } else {
                    extracted.push_back({VarType::VAR_IP, i, ipv6_len});
                    normalized += "<IP>";
                }
                i += ipv6_len;
                had_extractions = true;
                continue;
            }
        }

        // Try hex pointer (0x...)
        size_t hex_len = match_hex(s + i, len - i);
        if (hex_len > 0) {
            extracted.push_back({VarType::VAR_HEX, i, hex_len});
            normalized += "<HEX>";
            i += hex_len;
            had_extractions = true;
            continue;
        }

        // Try bracketed array
        size_t arr_len = match_array(s + i, len - i);
        if (arr_len > 0) {
            extracted.push_back({VarType::VAR_ARRAY, i, arr_len});
            normalized += "<ARRAY>";
            i += arr_len;
            had_extractions = true;
            continue;
        }

        // No pattern matched, copy character
        normalized += s[i];
        i++;
    }

    return had_extractions;
}

//=============================================================================
// Line Encoding
//=============================================================================

struct LineEncoder {
    DiffTokenMap& tokens;
    TemplateMap& templates;
    std::atomic<uint32_t>& next_token_id;
    std::atomic<uint32_t>& next_template_id;

    // Thread-local buffers to avoid allocations
    std::vector<TemplateSlot> slot_buf;
    std::vector<uint32_t> var_buf;
    std::string norm_buf;
    std::vector<ExtractedVar> extract_buf;

    LineEncoder(DiffTokenMap& t, TemplateMap& tm,
                std::atomic<uint32_t>& ntid, std::atomic<uint32_t>& ntemid)
        : tokens(t), templates(tm), next_token_id(ntid), next_template_id(ntemid) {
        slot_buf.reserve(64);
        var_buf.reserve(32);
        norm_buf.reserve(256);
        extract_buf.reserve(16);
    }

    EncodedLine encode(const char* line_start, const char* line_end) {
        slot_buf.clear();
        var_buf.clear();

        const char* p = line_start;
        while (p < line_end) {
            // Skip whitespace
            while (p < line_end && (*p == ' ' || *p == '\t')) ++p;
            if (p >= line_end) break;

            // Find token end - break on delimiters: = ; < > ( ) { }
            // Note: colon is NOT a delimiter - handled via K:V extraction in normalize_token
            const char* tok_start = p;

            if (*p == '=' || *p == ';' || *p == '<' || *p == '>' ||
                *p == '(' || *p == ')' || *p == '{' || *p == '}') {
                // Single-char delimiter tokens
                ++p;
            } else if (*p == '[') {
                // Bracketed content - scan to matching ']' (handles spaces inside arrays)
                int depth = 1;
                ++p;
                while (p < line_end && depth > 0) {
                    if (*p == '[') depth++;
                    else if (*p == ']') depth--;
                    ++p;
                }
            } else {
                // Scan token - stop at delimiters or whitespace
                // Colon is included in token (handled by K:V extraction later)
                while (p < line_end && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r' &&
                       *p != '=' && *p != ';' && *p != '<' && *p != '>' &&
                       *p != '(' && *p != ')' && *p != '{' && *p != '}') ++p;
            }
            size_t tok_len = p - tok_start;
            if (tok_len == 0) continue;

            // First, try to classify the whole token
            VarType vtype = classify_token(tok_start, tok_len);

            if (vtype != VarType::LITERAL) {
                // Whole token is a variable type
                uint32_t tok_id = tokens.get_or_insert(tok_start, tok_len, next_token_id);
                if (tok_id == UINT32_MAX) return {UINT32_MAX, {}};
                slot_buf.push_back({vtype, 0});
                var_buf.push_back(tok_id);
            } else {
                // Literal token - try sub-token extraction
                bool had_extractions = normalize_token(tok_start, tok_len, norm_buf, extract_buf);

                if (had_extractions) {
                    // Use insert_owned for normalized token (owns the string data)
                    uint32_t norm_id = tokens.insert_owned(norm_buf, next_token_id);
                    if (norm_id == UINT32_MAX) return {UINT32_MAX, {}};
                    slot_buf.push_back({VarType::LITERAL, norm_id});

                    // Add extracted values as variables (these point to mmap'd data)
                    for (const auto& ev : extract_buf) {
                        uint32_t var_id = tokens.get_or_insert(tok_start + ev.start, ev.len, next_token_id);
                        if (var_id == UINT32_MAX) return {UINT32_MAX, {}};
                        var_buf.push_back(var_id);
                    }
                } else {
                    // No sub-patterns, use original token (points to mmap'd data)
                    uint32_t tok_id = tokens.get_or_insert(tok_start, tok_len, next_token_id);
                    if (tok_id == UINT32_MAX) return {UINT32_MAX, {}};
                    slot_buf.push_back({VarType::LITERAL, tok_id});
                }
            }
        }

        if (slot_buf.empty()) {
            return {UINT32_MAX, {}};  // Empty line
        }

        uint32_t template_id = templates.get_or_insert(
            slot_buf.data(), slot_buf.size(), next_template_id);

        return {template_id, var_buf};
    }
};

//=============================================================================
// Per-chunk statistics (for parallel merge)
//=============================================================================

struct ChunkStats {
    size_t line_count = 0;
    std::unordered_map<uint32_t, uint32_t> template_counts;
    std::unordered_map<uint32_t, uint32_t> var_value_counts;
    std::unordered_map<uint32_t, size_t> template_first_line;
    std::unordered_map<uint32_t, size_t> var_first_line;
    std::vector<EncodedLine> lines;
};

//=============================================================================
// Encode Single File
//=============================================================================

bool encode_file(
    const DiffMappedFile& mf,
    DiffTokenMap& tokens,
    TemplateMap& templates,
    std::atomic<uint32_t>& next_token_id,
    std::atomic<uint32_t>& next_template_id,
    FileStats& stats,
    unsigned num_threads,
    bool store_lines
) {
    stats.path = mf.path;
    stats.byte_size = mf.size;

    if (mf.size == 0 || mf.data == nullptr) {
        stats.line_count = 0;
        return true;
    }

    const char* data = mf.data;
    const size_t size = mf.size;

    // Calculate chunk boundaries (aligned to newlines)
    std::vector<std::pair<const char*, const char*>> chunks(num_threads);
    for (unsigned i = 0; i < num_threads; ++i) {
        const char* s = data + (size * i) / num_threads;
        const char* e = data + (size * (i + 1)) / num_threads;

        if (i > 0 && s > data) {
            while (s < data + size && *(s - 1) != '\n') ++s;
        }
        if (i < num_threads - 1 && e > data && e < data + size && *(e - 1) != '\n') {
            while (e < data + size && *e != '\n') ++e;
            if (e < data + size) ++e;
        }
        chunks[i] = {s, e};
    }

    // Per-thread stats
    std::vector<ChunkStats> chunk_stats(num_threads);
    std::atomic<bool> overflow{false};

    // Parallel encoding
    std::vector<std::thread> workers;
    for (unsigned t = 0; t < num_threads; ++t) {
        workers.emplace_back([&, t]() {
            auto& cs = chunk_stats[t];
            const char* p = chunks[t].first;
            const char* end = chunks[t].second;

            if (p == nullptr || p >= end) return;

            // Pre-size hash maps to avoid rehashing (estimate ~10K unique items per chunk)
            cs.template_counts.reserve(10000);
            cs.var_value_counts.reserve(50000);
            cs.template_first_line.reserve(10000);
            cs.var_first_line.reserve(50000);

            LineEncoder encoder(tokens, templates, next_token_id, next_template_id);
            size_t base_line = 0;

            // Estimate base line number (approximate for first occurrence tracking)
            if (t > 0) {
                for (unsigned i = 0; i < t; ++i) {
                    const char* cp = chunks[i].first;
                    const char* ce = chunks[i].second;
                    while (cp < ce) {
                        if (*cp++ == '\n') base_line++;
                    }
                }
            }

            while (p < end) {
                const char* line_start = p;
                while (p < end && *p != '\n') ++p;
                const char* line_end = p;
                if (p < end) ++p;  // skip newline

                // Skip empty lines
                if (line_end == line_start) {
                    cs.line_count++;
                    continue;
                }

                EncodedLine enc = encoder.encode(line_start, line_end);

                if (enc.template_id == UINT32_MAX) {
                    if (!encoder.slot_buf.empty()) {
                        overflow.store(true, std::memory_order_relaxed);
                        return;
                    }
                    cs.line_count++;
                    continue;  // Empty line after whitespace stripping
                }

                // Update template counts
                cs.template_counts[enc.template_id]++;

                // Track first occurrence
                size_t line_num = base_line + cs.line_count;
                if (cs.template_first_line.find(enc.template_id) == cs.template_first_line.end()) {
                    cs.template_first_line[enc.template_id] = line_num;
                }

                // Update var value counts
                for (uint32_t var_id : enc.var_token_ids) {
                    cs.var_value_counts[var_id]++;
                    if (cs.var_first_line.find(var_id) == cs.var_first_line.end()) {
                        cs.var_first_line[var_id] = line_num;
                    }
                }

                // Store line if requested
                if (store_lines) {
                    cs.lines.push_back(std::move(enc));
                }

                cs.line_count++;
            }
        });
    }

    for (auto& w : workers) w.join();

    if (overflow.load()) {
        std::cerr << "Error: token/template overflow in " << mf.path << "\n";
        return false;
    }

    // Merge chunk stats
    for (unsigned t = 0; t < num_threads; ++t) {
        const auto& cs = chunk_stats[t];
        stats.line_count += cs.line_count;

        for (const auto& [id, count] : cs.template_counts) {
            stats.template_counts[id] += count;
            if (stats.template_first_line.find(id) == stats.template_first_line.end() ||
                cs.template_first_line.at(id) < stats.template_first_line[id]) {
                auto it = cs.template_first_line.find(id);
                if (it != cs.template_first_line.end()) {
                    stats.template_first_line[id] = it->second;
                }
            }
        }

        for (const auto& [id, count] : cs.var_value_counts) {
            stats.var_value_counts[id] += count;
            if (stats.var_first_line.find(id) == stats.var_first_line.end()) {
                auto it = cs.var_first_line.find(id);
                if (it != cs.var_first_line.end()) {
                    stats.var_first_line[id] = it->second;
                }
            }
        }

        if (store_lines) {
            stats.lines.insert(stats.lines.end(),
                std::make_move_iterator(cs.lines.begin()),
                std::make_move_iterator(cs.lines.end()));
        }
    }

    return true;
}

//=============================================================================
// Estimate tokens across all files
//=============================================================================

size_t estimate_total_tokens(const std::vector<DiffMappedFile>& files) {
    constexpr size_t SAMPLE_SIZE = 4 * 1024 * 1024;  // 4MB per file
    size_t total_estimate = 0;

    for (const auto& mf : files) {
        if (mf.size == 0) continue;

        size_t sample_bytes = std::min(mf.size, SAMPLE_SIZE);
        // Align to newline
        if (sample_bytes < mf.size) {
            while (sample_bytes < mf.size && mf.data[sample_bytes] != '\n') sample_bytes++;
            if (sample_bytes < mf.size) sample_bytes++;
        }

        // Count tokens in sample
        size_t token_count = 0;
        const char* p = mf.data;
        const char* end = mf.data + sample_bytes;
        while (p < end) {
            while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) ++p;
            if (p >= end) break;
            while (p < end && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') ++p;
            token_count++;
        }

        // Extrapolate
        double ratio = static_cast<double>(mf.size) / sample_bytes;
        total_estimate += static_cast<size_t>(token_count * std::sqrt(ratio));
    }

    // Assume ~50% overlap across files
    return std::max(size_t(1024), total_estimate * 2 / 3);
}

//=============================================================================
// Build presence bitmaps
//=============================================================================

void build_presence_bitmaps(
    const std::vector<FileStats>& files,
    std::unordered_map<uint32_t, uint64_t>& template_presence,
    std::unordered_map<uint32_t, uint64_t>& var_value_presence
) {
    for (size_t f = 0; f < files.size(); ++f) {
        uint64_t file_bit = 1ULL << f;

        for (const auto& [id, _] : files[f].template_counts) {
            template_presence[id] |= file_bit;
        }

        for (const auto& [id, _] : files[f].var_value_counts) {
            var_value_presence[id] |= file_bit;
        }
    }
}

//=============================================================================
// Compute set operations
//=============================================================================

void compute_sets(
    const std::unordered_map<uint32_t, uint64_t>& presence,
    size_t file_count,
    std::vector<uint32_t>& common_to_all,
    std::vector<std::vector<uint32_t>>& unique_to
) {
    uint64_t all_files_mask = (1ULL << file_count) - 1;
    unique_to.resize(file_count);

    for (const auto& [id, bitmap] : presence) {
        if (bitmap == all_files_mask) {
            common_to_all.push_back(id);
        } else if ((bitmap & (bitmap - 1)) == 0) {
            // Power of 2 = exactly one file
            size_t file_idx = __builtin_ctzll(bitmap);
            unique_to[file_idx].push_back(id);
        }
    }

    // Sort by ID for deterministic output
    std::sort(common_to_all.begin(), common_to_all.end());
    for (auto& v : unique_to) {
        std::sort(v.begin(), v.end());
    }
}

//=============================================================================
// Format template as pattern string
//=============================================================================

std::string format_template(const TemplateMap::Entry& tmpl, const DiffTokenMap& tokens) {
    std::string result;
    for (const auto& slot : tmpl.slots) {
        if (!result.empty()) result += ' ';
        if (slot.type == VarType::LITERAL) {
            std::string_view tok = tokens.get_token(slot.token_id);
            result.append(tok.data(), tok.size());
        } else {
            result += var_type_placeholder(slot.type);
        }
    }
    return result;
}

//=============================================================================
// Text Output
//=============================================================================

void output_text(
    const DiffResult& result,
    const DiffConfig& config,
    const DiffTokenMap& tokens,
    const TemplateMap& templates,
    std::ostream& out
) {
    bool single_file = (result.file_count == 1);

    if (single_file) {
        out << "=== Template Extraction ===\n";
    } else {
        out << "=== Multi-Log Diff ===\n";
    }
    out << "Files: " << result.file_count << "\n";
    for (const auto& f : result.files) {
        out << "  " << f.path << " ("
            << (f.byte_size / (1024.0 * 1024.0)) << " MB, "
            << f.line_count << " lines)\n";
    }
    out << "\nTokens: " << result.token_count
        << " | Templates: " << result.template_count << "\n\n";

    // Single file mode: show top templates and variables by frequency
    if (single_file && !config.quiet) {
        const auto& stats = result.files[0];

        // Sort templates by frequency
        std::vector<std::pair<uint32_t, uint32_t>> sorted_templates;
        for (const auto& [id, count] : stats.template_counts) {
            sorted_templates.push_back({id, count});
        }
        std::sort(sorted_templates.begin(), sorted_templates.end(),
            [](const auto& a, const auto& b) { return a.second > b.second; });

        out << "=== TOP TEMPLATES (" << sorted_templates.size() << " total) ===\n";
        size_t show = std::min(sorted_templates.size(), config.top_n);
        for (size_t i = 0; i < show; ++i) {
            const auto* tmpl = templates.get(sorted_templates[i].first);
            if (tmpl) {
                out << "  [" << sorted_templates[i].second << "x] \""
                    << format_template(*tmpl, tokens) << "\"\n";
            }
        }
        if (sorted_templates.size() > show) {
            out << "  ... and " << (sorted_templates.size() - show) << " more\n";
        }
        out << "\n";

        // Sort variable values by frequency
        std::vector<std::pair<uint32_t, uint32_t>> sorted_vars;
        for (const auto& [id, count] : stats.var_value_counts) {
            sorted_vars.push_back({id, count});
        }
        std::sort(sorted_vars.begin(), sorted_vars.end(),
            [](const auto& a, const auto& b) { return a.second > b.second; });

        out << "=== TOP VARIABLE VALUES (" << sorted_vars.size() << " total) ===\n";
        show = std::min(sorted_vars.size(), config.top_n);
        for (size_t i = 0; i < show; ++i) {
            std::string_view val = tokens.get_token(sorted_vars[i].first);
            VarType vtype = classify_token(val.data(), val.size());
            out << "  [" << sorted_vars[i].second << "x] \""
                << val << "\" (" << var_type_name(vtype) << ")\n";
        }
        if (sorted_vars.size() > show) {
            out << "  ... and " << (sorted_vars.size() - show) << " more\n";
        }
        out << "\n";

        return;  // Skip multi-file output for single file
    }

    // Multi-file mode: Templates common to all
    if (!config.quiet && !result.templates_common_to_all.empty()) {
        out << "=== TEMPLATES COMMON TO ALL (" << result.templates_common_to_all.size() << ") ===\n";
        size_t show = std::min(result.templates_common_to_all.size(), config.top_n);
        for (size_t i = 0; i < show; ++i) {
            const auto* tmpl = templates.get(result.templates_common_to_all[i]);
            if (tmpl) {
                out << "  \"" << format_template(*tmpl, tokens) << "\"\n";
            }
        }
        if (result.templates_common_to_all.size() > show) {
            out << "  ... and " << (result.templates_common_to_all.size() - show) << " more\n";
        }
        out << "\n";
    }

    // Templates unique to each file
    for (size_t f = 0; f < result.file_count; ++f) {
        const auto& unique = result.templates_unique_to[f];
        if (unique.empty()) continue;

        out << "=== TEMPLATES UNIQUE TO " << result.files[f].path
            << " (" << unique.size() << ") ===\n";

        size_t show = std::min(unique.size(), config.top_n);
        for (size_t i = 0; i < show; ++i) {
            const auto* tmpl = templates.get(unique[i]);
            if (tmpl) {
                out << "  \"" << format_template(*tmpl, tokens) << "\"\n";
            }
        }
        if (unique.size() > show) {
            out << "  ... and " << (unique.size() - show) << " more\n";
        }
        out << "\n";
    }

    // Variable values unique to each file
    for (size_t f = 0; f < result.file_count; ++f) {
        const auto& unique = result.var_values_unique_to[f];
        if (unique.empty()) continue;

        out << "=== VARIABLE VALUES UNIQUE TO " << result.files[f].path
            << " (" << unique.size() << ") ===\n";

        size_t show = std::min(unique.size(), config.top_n);
        for (size_t i = 0; i < show; ++i) {
            std::string_view val = tokens.get_token(unique[i]);
            VarType vtype = classify_token(val.data(), val.size());
            out << "  \"" << val << "\" (" << var_type_name(vtype) << ")\n";
        }
        if (unique.size() > show) {
            out << "  ... and " << (unique.size() - show) << " more\n";
        }
        out << "\n";
    }
}

//=============================================================================
// Main Diff Function
//=============================================================================

bool run_diff(const DiffConfig& config, DiffResult& result) {
    auto start = std::chrono::high_resolution_clock::now();

    // Open all files
    std::vector<DiffMappedFile> files(config.input_files.size());
    size_t total_bytes = 0;

    for (size_t i = 0; i < config.input_files.size(); ++i) {
        if (!files[i].open(config.input_files[i].c_str())) {
            std::cerr << "Failed to open: " << config.input_files[i] << "\n";
            return false;
        }
        total_bytes += files[i].size;
    }

    result.file_count = files.size();

    // Determine thread count
    unsigned num_threads = config.num_threads;
    if (num_threads == 0) {
        num_threads = std::thread::hardware_concurrency();
        if (num_threads == 0) num_threads = 4;
    }
    // Use fewer threads for small total size
    if (total_bytes < 1024 * 1024) num_threads = 1;

    // Estimate and allocate
    size_t est_tokens = estimate_total_tokens(files);
    size_t est_templates = est_tokens / 10;  // Assume ~10 tokens per template on average

    DiffTokenMap tokens(est_tokens * 2);
    TemplateMap templates(std::max(size_t(1024), est_templates * 2));
    std::atomic<uint32_t> next_token_id{0};
    std::atomic<uint32_t> next_template_id{0};

    // Encode all files
    result.files.resize(files.size());
    for (size_t i = 0; i < files.size(); ++i) {
        result.files[i].file_index = i;
        if (!encode_file(files[i], tokens, templates,
                         next_token_id, next_template_id,
                         result.files[i], num_threads, config.show_timeline)) {
            return false;
        }
    }

    result.token_count = next_token_id.load();
    result.template_count = next_template_id.load();

    // Build presence bitmaps
    build_presence_bitmaps(result.files, result.template_presence, result.var_value_presence);

    // Compute sets
    compute_sets(result.template_presence, result.file_count,
                 result.templates_common_to_all, result.templates_unique_to);
    compute_sets(result.var_value_presence, result.file_count,
                 result.var_values_common_to_all, result.var_values_unique_to);

    auto end = std::chrono::high_resolution_clock::now();
    double elapsed_ms = std::chrono::duration<double, std::milli>(end - start).count();

    // Output
    if (config.format == DiffConfig::Format::TEXT) {
        output_text(result, config, tokens, templates, std::cout);

        if (!config.quiet) {
            std::cout << "=== Stats ===\n";
            std::cout << "Time: " << elapsed_ms << " ms\n";
            std::cout << "Throughput: " << (total_bytes / (1024.0 * 1024.0)) / (elapsed_ms / 1000.0) << " MB/s\n";
        }
    }

    // Close files
    for (auto& f : files) f.close_file();

    return true;
}
