// template.cc - Template extraction implementation
// Uses TokenMap from token.h and MappedFile from mmap.h

#include "mmap.h"
#include "similarity.h"
#include "template.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sys/resource.h>
#include <thread>
#include <unordered_set>

namespace catalog {

//=============================================================================
// Constants
//=============================================================================

// Maximum number of input files (limited by 64-bit bitmap representation)
inline constexpr size_t MAX_INPUT_FILES = 64;

// Buffer reserves for LineEncoder
inline constexpr size_t SLOT_BUF_RESERVE = 64;
inline constexpr size_t VAR_BUF_RESERVE = 32;
inline constexpr size_t NORM_BUF_RESERVE = 256;
inline constexpr size_t EXTRACT_BUF_RESERVE = 16;

// Per-chunk hash map reserves
inline constexpr size_t CHUNK_TEMPLATE_RESERVE = 10000;
inline constexpr size_t CHUNK_VAR_RESERVE = 50000;

// Token/template estimation
inline constexpr size_t TOKEN_SAMPLE_SIZE = 4 * 1024 * 1024;  // 4 MB sample
inline constexpr size_t TEMPLATE_RATIO = 10;  // Estimated tokens per template
inline constexpr size_t MIN_CAPACITY = 1024;

// Template merging constraints
inline constexpr size_t MAX_MERGE_DIFF_POSITIONS = 3;

// Get peak memory usage in bytes
static size_t get_peak_memory() {
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
        return static_cast<size_t>(usage.ru_maxrss) * 1024;  // ru_maxrss is in KB on Linux
    }
    return 0;
}

//=============================================================================
// Sub-token Pattern Extraction
//=============================================================================

struct ExtractedVar {
    VarType type;
    size_t start;
    size_t len;
};

// Fast check if token might contain embedded patterns worth extracting
// Returns false for simple literals like "INFO", "error", "foo" that have no patterns
inline bool might_have_patterns(const char* s, size_t len) {
    // Patterns we look for: K:V (:), IPv4/IPv6 (digits), hex (0x), arrays ([)
    for (size_t i = 0; i < len; ++i) {
        char c = s[i];
        if ((c >= '0' && c <= '9') || c == ':' || c == '[') return true;
    }
    return false;
}

// Try to match a K:V pattern where V is a variable type
static size_t try_match_kv_pattern(const char* s, size_t len, VarType& value_type) {
    // Find rightmost colon
    size_t colon_pos = 0;
    for (size_t i = len; i > 0; --i) {
        if (s[i-1] == ':') {
            colon_pos = i - 1;
            break;
        }
    }

    if (colon_pos == 0 || colon_pos >= len - 1) return 0;

    // Key must have at least one letter
    bool has_letter = false;
    for (size_t i = 0; i < colon_pos; ++i) {
        if (is_alpha(s[i])) {
            has_letter = true;
            break;
        }
    }
    if (!has_letter) return 0;

    // Check if value is a variable type
    const char* value = s + colon_pos + 1;
    size_t value_len = len - colon_pos - 1;

    value_type = classify_token(value, value_len);
    return (value_type != VarType::LITERAL) ? colon_pos : 0;
}

// Normalize a token by replacing embedded patterns with placeholders
// PRECONDITION: caller already classified token as LITERAL
static bool normalize_token(const char* s, size_t len,
                           std::string& normalized,
                           std::vector<ExtractedVar>& extracted) {
    normalized.clear();
    extracted.clear();
    normalized.reserve(len + 32);

    // Try K:V pattern extraction
    VarType kv_value_type;
    size_t colon_pos = try_match_kv_pattern(s, len, kv_value_type);
    if (colon_pos > 0) {
        normalized.append(s, colon_pos + 1);
        normalized += var_type_placeholder(kv_value_type);
        extracted.push_back({kv_value_type, colon_pos + 1, len - colon_pos - 1});
        return true;
    }

    size_t i = 0;
    size_t seg_start = 0;  // Start of current literal segment
    bool had_extractions = false;

    while (i < len) {
        // Try IPv4 (with optional CIDR)
        bool ipv4_has_cidr = false;
        size_t ip_len = match_ipv4(s + i, len - i, &ipv4_has_cidr);
        if (ip_len > 0) {
            if (i > seg_start) normalized.append(s + seg_start, i - seg_start);
            if (ipv4_has_cidr) {
                extracted.push_back({VarType::VAR_PREFIX, i, ip_len});
                normalized += var_type_placeholder(VarType::VAR_PREFIX);
            } else {
                extracted.push_back({VarType::VAR_IP, i, ip_len});
                normalized += var_type_placeholder(VarType::VAR_IP);
            }
            i += ip_len;
            seg_start = i;
            had_extractions = true;
            continue;
        }

        // Try IPv6 (with optional CIDR)
        // Don't match if preceded by a letter - likely C++ namespace
        bool prev_is_letter = (i > 0) && is_alpha(s[i-1]);
        if (!prev_is_letter) {
            bool ipv6_has_cidr = false;
            size_t ipv6_len = match_ipv6(s + i, len - i, &ipv6_has_cidr);
            if (ipv6_len > 0) {
                if (i > seg_start) normalized.append(s + seg_start, i - seg_start);
                if (ipv6_has_cidr) {
                    extracted.push_back({VarType::VAR_PREFIX, i, ipv6_len});
                    normalized += var_type_placeholder(VarType::VAR_PREFIX);
                } else {
                    extracted.push_back({VarType::VAR_IP, i, ipv6_len});
                    normalized += var_type_placeholder(VarType::VAR_IP);
                }
                i += ipv6_len;
                seg_start = i;
                had_extractions = true;
                continue;
            }
        }

        // Try hex pointer (0x...)
        size_t hex_len = match_hex(s + i, len - i);
        if (hex_len > 0) {
            if (i > seg_start) normalized.append(s + seg_start, i - seg_start);
            extracted.push_back({VarType::VAR_HEX, i, hex_len});
            normalized += var_type_placeholder(VarType::VAR_HEX);
            i += hex_len;
            seg_start = i;
            had_extractions = true;
            continue;
        }

        // Try bracketed array (only if content looks like array, not [INFO] tags)
        size_t arr_len = match_array(s + i, len - i);
        if (arr_len > 0 && is_array_content(s + i, arr_len)) {
            if (i > seg_start) normalized.append(s + seg_start, i - seg_start);
            extracted.push_back({VarType::VAR_ARRAY, i, arr_len});
            normalized += var_type_placeholder(VarType::VAR_ARRAY);
            i += arr_len;
            seg_start = i;
            had_extractions = true;
            continue;
        }

        // No pattern matched, advance (will be bulk-copied later)
        i++;
    }

    // Flush remaining literal segment
    if (i > seg_start) normalized.append(s + seg_start, i - seg_start);

    return had_extractions;
}

//=============================================================================
// Line Encoding
//=============================================================================

struct LineEncoder {
    TokenMap& tokens;
    TemplateMap& templates;
    std::atomic<uint32_t>& next_token_id;
    std::atomic<uint32_t>& next_template_id;

    std::vector<TemplateSlot> slot_buf;
    std::vector<uint32_t> var_buf;
    std::string norm_buf;
    std::vector<ExtractedVar> extract_buf;

    LineEncoder(TokenMap& t, TemplateMap& tm,
                std::atomic<uint32_t>& ntid, std::atomic<uint32_t>& ntemid)
        : tokens(t), templates(tm), next_token_id(ntid), next_template_id(ntemid) {
        slot_buf.reserve(SLOT_BUF_RESERVE);
        var_buf.reserve(VAR_BUF_RESERVE);
        norm_buf.reserve(NORM_BUF_RESERVE);
        extract_buf.reserve(EXTRACT_BUF_RESERVE);
    }

    uint32_t encode(const char* line_start, const char* line_end) {
        slot_buf.clear();
        var_buf.clear();

        const char* p = line_start;
        while (p < line_end) {
            while (p < line_end && (*p == ' ' || *p == '\t')) ++p;
            if (p >= line_end) break;

            const char* tok_start = p;

            if (*p == '=' || *p == ';' || *p == '<' || *p == '>' ||
                *p == '(' || *p == ')' || *p == '{' || *p == '}' || *p == ',' || *p == '"') {
                ++p;
            } else if (*p == '[') {
                int depth = 1;
                ++p;
                while (p < line_end && depth > 0) {
                    if (*p == '[') depth++;
                    else if (*p == ']') depth--;
                    ++p;
                }
            } else {
                while (p < line_end && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r' &&
                       *p != '=' && *p != ';' && *p != '<' && *p != '>' &&
                       *p != '(' && *p != ')' && *p != '{' && *p != '}' && *p != ',' && *p != '"') ++p;
            }
            size_t tok_len = p - tok_start;
            if (tok_len == 0) continue;

            VarType vtype = classify_token(tok_start, tok_len);

            if (vtype != VarType::LITERAL) {
                uint32_t tok_id = tokens.get_or_insert(tok_start, tok_len, next_token_id);
                if (tok_id == UINT32_MAX) return UINT32_MAX;
                slot_buf.push_back({vtype, 0});
                var_buf.push_back(tok_id);
            } else {
                // Skip normalization for simple literals without pattern indicators
                bool had_extractions = false;
                if (might_have_patterns(tok_start, tok_len)) {
                    had_extractions = normalize_token(tok_start, tok_len, norm_buf, extract_buf);
                }

                if (had_extractions) {
                    uint32_t norm_id = tokens.insert_owned(norm_buf, next_token_id);
                    if (norm_id == UINT32_MAX) return UINT32_MAX;
                    slot_buf.push_back({VarType::LITERAL, norm_id});

                    for (const auto& ev : extract_buf) {
                        uint32_t var_id = tokens.get_or_insert(tok_start + ev.start, ev.len, next_token_id);
                        if (var_id == UINT32_MAX) return UINT32_MAX;
                        var_buf.push_back(var_id);
                    }
                } else {
                    uint32_t tok_id = tokens.get_or_insert(tok_start, tok_len, next_token_id);
                    if (tok_id == UINT32_MAX) return UINT32_MAX;
                    slot_buf.push_back({VarType::LITERAL, tok_id});
                }
            }
        }

        if (slot_buf.empty()) {
            return UINT32_MAX;
        }

        uint32_t template_id = templates.get_or_insert(
            slot_buf.data(), slot_buf.size(), next_template_id);

        return template_id;
    }

    // Access variable buffer directly (avoids copy)
    const std::vector<uint32_t>& vars() const { return var_buf; }
};

//=============================================================================
// Per-chunk statistics
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

// Check if line contains any exclude pattern
static bool should_exclude_line(const char* line_start, size_t line_len,
                                const std::vector<std::string>& exclude_patterns) {
    if (exclude_patterns.empty()) return false;
    for (const auto& pattern : exclude_patterns) {
        if (pattern.size() > line_len) continue;
        // Use memmem for substring search
        if (memmem(line_start, line_len, pattern.c_str(), pattern.size()) != nullptr) {
            return true;
        }
    }
    return false;
}

static bool encode_file(
    const MappedFile& mf,
    TokenMap& tokens,
    TemplateMap& templates,
    std::atomic<uint32_t>& next_token_id,
    std::atomic<uint32_t>& next_template_id,
    FileStats& stats,
    unsigned num_threads,
    bool store_lines,
    const std::vector<std::string>& exclude_patterns
) {
    stats.path = mf.path;
    stats.byte_size = mf.size;

    if (mf.size == 0 || mf.data == nullptr) {
        stats.line_count = 0;
        return true;
    }

    auto chunks = calculate_chunks(mf.data, mf.size, num_threads);

    // Pre-compute line counts per chunk in parallel for O(1) base_line lookup
    std::vector<size_t> chunk_line_counts(num_threads, 0);
    std::vector<std::thread> count_workers;
    for (unsigned t = 0; t < num_threads; ++t) {
        count_workers.emplace_back([&, t]() {
            const char* p = chunks[t].first;
            const char* end = chunks[t].second;
            size_t count = 0;
            while (p < end) {
                if (*p++ == '\n') count++;
            }
            chunk_line_counts[t] = count;
        });
    }
    for (auto& w : count_workers) w.join();

    // Compute prefix sums for base line numbers
    std::vector<size_t> base_lines(num_threads, 0);
    for (unsigned t = 1; t < num_threads; ++t) {
        base_lines[t] = base_lines[t-1] + chunk_line_counts[t-1];
    }

    std::vector<ChunkStats> chunk_stats(num_threads);
    std::atomic<bool> overflow{false};

    std::vector<std::thread> workers;
    for (unsigned t = 0; t < num_threads; ++t) {
        workers.emplace_back([&, t]() {
            auto& cs = chunk_stats[t];
            const char* p = chunks[t].first;
            const char* end = chunks[t].second;

            if (p == nullptr || p >= end) return;

            cs.template_counts.reserve(CHUNK_TEMPLATE_RESERVE);
            cs.var_value_counts.reserve(CHUNK_VAR_RESERVE);
            cs.template_first_line.reserve(CHUNK_TEMPLATE_RESERVE);
            cs.var_first_line.reserve(CHUNK_VAR_RESERVE);

            LineEncoder encoder(tokens, templates, next_token_id, next_template_id);
            size_t base_line = base_lines[t];  // O(1) lookup instead of O(n) scan

            while (p < end) {
                const char* line_start = p;
                const char* nl = static_cast<const char*>(memchr(p, '\n', end - p));
                const char* line_end = nl ? nl : end;
                p = nl ? nl + 1 : end;

                if (line_end == line_start) {
                    cs.line_count++;
                    continue;
                }

                // Skip lines matching exclude patterns
                if (should_exclude_line(line_start, line_end - line_start, exclude_patterns)) {
                    cs.line_count++;
                    continue;
                }

                uint32_t template_id = encoder.encode(line_start, line_end);

                if (template_id == UINT32_MAX) {
                    if (!encoder.slot_buf.empty()) {
                        overflow.store(true, std::memory_order_relaxed);
                        return;
                    }
                    cs.line_count++;
                    continue;
                }

                cs.template_counts[template_id]++;

                size_t line_num = base_line + cs.line_count;
                cs.template_first_line.try_emplace(template_id, line_num);

                for (uint32_t var_id : encoder.vars()) {
                    cs.var_value_counts[var_id]++;
                    cs.var_first_line.try_emplace(var_id, line_num);
                }

                if (store_lines) {
                    cs.lines.push_back({template_id, encoder.vars()});
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
            auto cs_it = cs.template_first_line.find(id);
            if (cs_it != cs.template_first_line.end()) {
                auto [it, inserted] = stats.template_first_line.try_emplace(id, cs_it->second);
                if (!inserted && cs_it->second < it->second) {
                    it->second = cs_it->second;
                }
            }
        }

        for (const auto& [id, count] : cs.var_value_counts) {
            stats.var_value_counts[id] += count;
            auto cs_it = cs.var_first_line.find(id);
            if (cs_it != cs.var_first_line.end()) {
                stats.var_first_line.try_emplace(id, cs_it->second);
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
// Estimate tokens across all files (fast token counting)
//=============================================================================

static size_t estimate_total_tokens(const std::vector<MappedFile>& files) {
    size_t total_estimate = 0;

    for (const auto& mf : files) {
        if (mf.size == 0) continue;

        size_t sample_bytes = std::min(mf.size, TOKEN_SAMPLE_SIZE);
        if (sample_bytes < mf.size) {
            while (sample_bytes < mf.size && mf.data[sample_bytes] != '\n') sample_bytes++;
            if (sample_bytes < mf.size) sample_bytes++;
        }

        size_t token_count = 0;
        const char* p = mf.data;
        const char* end = mf.data + sample_bytes;
        while (p < end) {
            while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) ++p;
            if (p >= end) break;
            while (p < end && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') ++p;
            token_count++;
        }

        double ratio = static_cast<double>(mf.size) / sample_bytes;
        total_estimate += static_cast<size_t>(token_count * std::sqrt(ratio));
    }

    return std::max(MIN_CAPACITY, total_estimate * 2 / 3);
}

//=============================================================================
// Build presence bitmaps
//=============================================================================

static void build_presence_bitmaps(
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

static void compute_sets(
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
            size_t file_idx = __builtin_ctzll(bitmap);
            unique_to[file_idx].push_back(id);
        }
    }

    std::sort(common_to_all.begin(), common_to_all.end());
    for (auto& v : unique_to) {
        std::sort(v.begin(), v.end());
    }
}

//=============================================================================
// Build TemplateInfo from template entry
//=============================================================================

void build_template_info(TemplateInfo& info, const TemplateMap::Entry& entry) {
    info.slot_count = entry.slots.size();
    info.signature.clear();
    info.token_set.clear();

    for (const auto& slot : entry.slots) {
        uint64_t key;
        if (slot.type == VarType::LITERAL) {
            key = static_cast<uint64_t>(slot.token_id) << 8;
            if (info.signature.size() < 3) {
                info.signature.push_back(slot.token_id);
            }
        } else {
            key = 0xFFFFFFFF00000000ULL | static_cast<uint8_t>(slot.type);
        }
        info.token_set.insert(key);
    }
}

//=============================================================================
// Gather Template Infos
//=============================================================================

// Collects TemplateInfo for all unique templates across files.
// If with_counts=true, aggregates counts across all files.
// If with_counts=false, sets count=0 (for merging where counts aren't needed).
static std::vector<TemplateInfo> gather_template_infos(
    const std::vector<FileStats>& files,
    const TemplateMap& templates,
    bool with_counts
) {
    std::vector<TemplateInfo> infos;

    if (with_counts) {
        // Aggregate counts across all files
        std::unordered_map<uint32_t, uint32_t> total_counts;
        for (const auto& f : files) {
            for (const auto& [id, count] : f.template_counts) {
                total_counts[id] += count;
            }
        }
        infos.reserve(total_counts.size());
        for (const auto& [id, count] : total_counts) {
            const auto* entry = templates.get(id);
            if (!entry) continue;
            TemplateInfo info;
            info.id = id;
            info.count = count;
            build_template_info(info, *entry);
            infos.push_back(std::move(info));
        }
    } else {
        // Just collect unique IDs without counting
        std::unordered_set<uint32_t> seen_ids;
        for (const auto& f : files) {
            for (const auto& [id, count] : f.template_counts) {
                if (seen_ids.count(id)) continue;
                seen_ids.insert(id);
                const auto* entry = templates.get(id);
                if (!entry) continue;
                TemplateInfo info;
                info.id = id;
                info.count = 0;
                build_template_info(info, *entry);
                infos.push_back(std::move(info));
            }
        }
    }

    return infos;
}

//=============================================================================
// Template Clustering
//=============================================================================

std::unordered_map<size_t, std::vector<size_t>> cluster_templates(
    const std::vector<TemplateInfo>& infos,
    bool same_slot_count
) {
    if (infos.size() < MIN_CLUSTER_SIZE) {
        return {};
    }

    // Group by signature hash (optionally including slot_count)
    std::unordered_map<uint64_t, std::vector<size_t>> groups;
    for (size_t i = 0; i < infos.size(); ++i) {
        uint64_t key = same_slot_count ? infos[i].slot_count : 0;
        for (size_t j = 0; j < infos[i].signature.size(); ++j) {
            key ^= static_cast<uint64_t>(infos[i].signature[j]) << (8 + j * 18);
        }
        groups[key].push_back(i);
    }

    // Cluster using Union-Find and Jaccard similarity
    UnionFind uf(infos.size());

    for (const auto& [key, members] : groups) {
        for (size_t i = 0; i < members.size(); ++i) {
            for (size_t j = i + 1; j < members.size(); ++j) {
                size_t ai = members[i], bi = members[j];
                if (same_slot_count && infos[ai].slot_count != infos[bi].slot_count) {
                    continue;
                }
                if (jaccard_similarity(infos[ai].token_set, infos[bi].token_set) >= SIMILARITY_THRESHOLD) {
                    uf.unite(ai, bi);
                }
            }
        }
    }

    // Collect clusters
    std::unordered_map<size_t, std::vector<size_t>> clusters;
    for (size_t i = 0; i < infos.size(); ++i) {
        clusters[uf.find(i)].push_back(i);
    }

    return clusters;
}

//=============================================================================
// Format template as pattern string
//=============================================================================

std::string format_template(const TemplateMap::Entry& tmpl, const TokenMap& tokens) {
    std::string result;
    result.reserve(tmpl.slots.size() * 8);  // Estimate avg 8 chars per slot
    for (const auto& slot : tmpl.slots) {
        if (slot.type == VarType::LITERAL) {
            std::string_view tok = tokens.get_token(slot.token_id);
            if (is_skip_delimiter(tok.data(), tok.size())) continue;
            if (!result.empty()) result += ' ';
            result.append(tok.data(), tok.size());
        } else {
            if (!result.empty()) result += ' ';
            result += var_type_placeholder(slot.type);
        }
    }
    return result;
}

//=============================================================================
// Similarity Analysis
//=============================================================================

void analyze_similarity(
    const TemplateMap& templates,
    const TokenMap& tokens,
    const std::vector<FileStats>& files,
    size_t top_n,
    std::ostream& out
) {
    auto infos = gather_template_infos(files, templates, true);

    if (infos.empty()) {
        out << "No templates to analyze\n";
        return;
    }

    out << "\n=== Similarity Analysis (" << infos.size() << " templates) ===\n";

    // Cluster templates (same_slot_count=false to show all similar templates)
    auto clusters = cluster_templates(infos, false);

    // Filter to multi-member clusters and sort by size
    std::vector<std::vector<size_t>> multi_clusters;
    for (auto& [root, members] : clusters) {
        if (members.size() >= MIN_CLUSTER_SIZE) {
            multi_clusters.push_back(std::move(members));
        }
    }
    std::sort(multi_clusters.begin(), multi_clusters.end(),
        [](const auto& a, const auto& b) { return a.size() > b.size(); });

    size_t templates_in_clusters = 0;
    for (const auto& c : multi_clusters) {
        templates_in_clusters += c.size();
    }

    double cluster_ratio = infos.empty() ? 0.0 :
        100.0 * templates_in_clusters / infos.size();

    out << "Clusters found:         " << multi_clusters.size() << "\n";
    out << "Templates in clusters:  " << templates_in_clusters << "\n";
    out << "Cluster ratio:          " << std::fixed << std::setprecision(1)
        << cluster_ratio << "%\n";
    out << std::string(60, '=') << "\n";

    if (multi_clusters.empty()) {
        out << "\nNo similar clusters found - deduplication is working well!\n";
        return;
    }

    out << "\nTOP CLUSTERS (showing up to " << std::min(top_n, multi_clusters.size()) << "):\n\n";

    for (size_t ci = 0; ci < std::min(top_n, multi_clusters.size()); ++ci) {
        auto& cluster = multi_clusters[ci];

        // Sort cluster members by count descending
        std::sort(cluster.begin(), cluster.end(),
            [&](size_t a, size_t b) { return infos[a].count > infos[b].count; });

        out << "--- Cluster " << (ci + 1) << " (" << cluster.size() << " templates) ---\n";

        for (size_t idx : cluster) {
            const auto* entry = templates.get(infos[idx].id);
            if (!entry) continue;

            out << "  [" << infos[idx].count << "x] "
                << format_template(*entry, tokens) << "\n";
        }
        out << "\n";
    }
}

//=============================================================================
// Text Output
//=============================================================================

// Sort items by first occurrence line number using the provided map
template<typename T>
static void sort_by_first_occurrence(
    std::vector<T>& items,
    const std::unordered_map<uint32_t, size_t>& first_line_map
) {
    std::sort(items.begin(), items.end(),
        [&first_line_map](const auto& a, const auto& b) {
            auto it_a = first_line_map.find(a.first);
            auto it_b = first_line_map.find(b.first);
            size_t line_a = (it_a != first_line_map.end()) ? it_a->second : SIZE_MAX;
            size_t line_b = (it_b != first_line_map.end()) ? it_b->second : SIZE_MAX;
            return line_a < line_b;
        });
}

static void output_text(
    const TemplateResult& result,
    const TemplateConfig& config,
    const TokenMap& tokens,
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

    if (single_file && !config.quiet) {
        const auto& stats = result.files[0];

        std::vector<std::pair<uint32_t, uint32_t>> sorted_templates;
        for (const auto& [id, count] : stats.template_counts) {
            sorted_templates.push_back({id, count});
        }
        if (config.sort_by_first) {
            sort_by_first_occurrence(sorted_templates, stats.template_first_line);
        } else {
            std::sort(sorted_templates.begin(), sorted_templates.end(),
                [](const auto& a, const auto& b) { return a.second > b.second; });
        }

        out << "=== TOP TEMPLATES (" << sorted_templates.size() << " total) ===\n";
        size_t show = std::min(sorted_templates.size(), config.top_n);
        for (size_t i = 0; i < show; ++i) {
            const auto* tmpl = templates.get(sorted_templates[i].first);
            if (tmpl) {
                out << "  [" << sorted_templates[i].second << "x] "
                    << format_template(*tmpl, tokens) << "\n";
            }
        }
        if (sorted_templates.size() > show) {
            out << "  ... and " << (sorted_templates.size() - show) << " more\n";
        }
        out << "\n";

        if (config.show_variables) {
            std::vector<std::pair<uint32_t, uint32_t>> sorted_vars;
            for (const auto& [id, count] : stats.var_value_counts) {
                sorted_vars.push_back({id, count});
            }
            if (config.sort_by_first) {
                sort_by_first_occurrence(sorted_vars, stats.var_first_line);
            } else {
                std::sort(sorted_vars.begin(), sorted_vars.end(),
                    [](const auto& a, const auto& b) { return a.second > b.second; });
            }

            out << "=== TOP VARIABLE VALUES (" << sorted_vars.size() << " total) ===\n";
            size_t show = std::min(sorted_vars.size(), config.top_n);
            for (size_t i = 0; i < show; ++i) {
                std::string_view val = tokens.get_token(sorted_vars[i].first);
                VarType vtype = classify_token(val.data(), val.size());
                out << "  [" << sorted_vars[i].second << "x] "
                    << val << " (" << var_type_name(vtype) << ")\n";
            }
            if (sorted_vars.size() > show) {
                out << "  ... and " << (sorted_vars.size() - show) << " more\n";
            }
            out << "\n";
        }

        return;
    }

    // Multi-file mode
    if (!config.quiet && !result.templates_common_to_all.empty()) {
        out << "=== TEMPLATES COMMON TO ALL (" << result.templates_common_to_all.size() << ") ===\n";
        size_t show = std::min(result.templates_common_to_all.size(), config.top_n);
        for (size_t i = 0; i < show; ++i) {
            const auto* tmpl = templates.get(result.templates_common_to_all[i]);
            if (tmpl) {
                out << "  " << format_template(*tmpl, tokens) << "\n";
            }
        }
        if (result.templates_common_to_all.size() > show) {
            out << "  ... and " << (result.templates_common_to_all.size() - show) << " more\n";
        }
        out << "\n";
    }

    for (size_t f = 0; f < result.file_count; ++f) {
        const auto& unique = result.templates_unique_to[f];
        if (unique.empty()) continue;

        out << "=== TEMPLATES UNIQUE TO " << result.files[f].path
            << " (" << unique.size() << ") ===\n";

        size_t show = std::min(unique.size(), config.top_n);
        for (size_t i = 0; i < show; ++i) {
            const auto* tmpl = templates.get(unique[i]);
            if (tmpl) {
                out << "  " << format_template(*tmpl, tokens) << "\n";
            }
        }
        if (unique.size() > show) {
            out << "  ... and " << (unique.size() - show) << " more\n";
        }
        out << "\n";
    }

    for (size_t f = 0; f < result.file_count; ++f) {
        const auto& unique = result.var_values_unique_to[f];
        if (unique.empty()) continue;

        out << "=== VARIABLE VALUES UNIQUE TO " << result.files[f].path
            << " (" << unique.size() << ") ===\n";

        size_t show = std::min(unique.size(), config.top_n);
        for (size_t i = 0; i < show; ++i) {
            std::string_view val = tokens.get_token(unique[i]);
            VarType vtype = classify_token(val.data(), val.size());
            out << "  " << val << " (" << var_type_name(vtype) << ")\n";
        }
        if (unique.size() > show) {
            out << "  ... and " << (unique.size() - show) << " more\n";
        }
        out << "\n";
    }
}

//=============================================================================
// Similar Template Merging
//=============================================================================
// Clusters similar templates and merges them by replacing varying literal
// positions with VAR_IDENT. Returns number of templates merged.

static size_t merge_similar_templates(
    TemplateMap& templates,
    std::vector<FileStats>& files,
    std::atomic<uint32_t>& next_template_id
) {
    auto infos = gather_template_infos(files, templates, false);

    if (infos.size() < MIN_CLUSTER_SIZE) return 0;

    // Cluster templates (same_slot_count=true for merging)
    auto clusters = cluster_templates(infos, true);

    // Process each cluster to create canonical templates
    std::unordered_map<uint32_t, uint32_t> remap;  // old_id -> canonical_id
    size_t merged_count = 0;

    for (auto& [root, members] : clusters) {
        if (members.size() < MIN_CLUSTER_SIZE) continue;

        // All members have same slot count (we checked above)
        const auto* base_entry = templates.get(infos[members[0]].id);
        if (!base_entry) continue;
        size_t slot_count = base_entry->slots.size();

        // Find positions where literals differ
        std::vector<bool> differs(slot_count, false);
        for (size_t mi = 1; mi < members.size(); ++mi) {
            const auto* other = templates.get(infos[members[mi]].id);
            if (!other || other->slots.size() != slot_count) continue;

            for (size_t s = 0; s < slot_count; ++s) {
                if (base_entry->slots[s].type == VarType::LITERAL &&
                    other->slots[s].type == VarType::LITERAL &&
                    base_entry->slots[s].token_id != other->slots[s].token_id) {
                    differs[s] = true;
                }
            }
        }

        // Count differing positions
        size_t diff_count = 0;
        for (bool d : differs) if (d) diff_count++;

        // Only canonicalize if 1-MAX_MERGE_DIFF_POSITIONS positions differ (conservative)
        if (diff_count == 0 || diff_count > MAX_MERGE_DIFF_POSITIONS) continue;

        // Create canonical slot sequence
        std::vector<TemplateSlot> canonical_slots = base_entry->slots;
        for (size_t s = 0; s < slot_count; ++s) {
            if (differs[s]) {
                canonical_slots[s].type = VarType::VAR_IDENT;
                canonical_slots[s].token_id = 0;
            }
        }

        // Insert canonical template (may already exist)
        uint32_t canonical_id = templates.get_or_insert(
            canonical_slots.data(), canonical_slots.size(), next_template_id);

        if (canonical_id == UINT32_MAX) continue;

        // Map all cluster members to canonical
        for (size_t mi : members) {
            uint32_t old_id = infos[mi].id;
            if (old_id != canonical_id) {
                remap[old_id] = canonical_id;
                merged_count++;
            }
        }
    }

    // Apply remapping to file stats
    for (auto& f : files) {
        std::unordered_map<uint32_t, uint32_t> new_counts;
        for (const auto& [id, count] : f.template_counts) {
            auto it = remap.find(id);
            uint32_t target_id = (it != remap.end()) ? it->second : id;
            new_counts[target_id] += count;
        }
        f.template_counts = std::move(new_counts);

        // Update first_line tracking
        std::unordered_map<uint32_t, size_t> new_first_line;
        for (const auto& [id, line] : f.template_first_line) {
            auto it = remap.find(id);
            uint32_t target_id = (it != remap.end()) ? it->second : id;
            auto [nit, inserted] = new_first_line.try_emplace(target_id, line);
            if (!inserted && line < nit->second) {
                nit->second = line;
            }
        }
        f.template_first_line = std::move(new_first_line);
    }

    return merged_count;
}

//=============================================================================
// Main Template Extraction Function
//=============================================================================

bool extract_templates(const TemplateConfig& config, TemplateResult& result) {
    auto start = std::chrono::high_resolution_clock::now();

    // Limit to MAX_INPUT_FILES due to bitmap representation
    if (config.input_files.size() > MAX_INPUT_FILES) {
        std::cerr << "Error: Maximum " << MAX_INPUT_FILES << " input files supported (got "
                  << config.input_files.size() << ")\n";
        return false;
    }

    std::vector<MappedFile> files(config.input_files.size());
    size_t total_bytes = 0;

    for (size_t i = 0; i < config.input_files.size(); ++i) {
        if (!files[i].open_read(config.input_files[i].c_str())) {
            std::cerr << "Failed to open: " << config.input_files[i] << "\n";
            return false;
        }
        total_bytes += files[i].size;
    }

    result.file_count = files.size();

    unsigned num_threads = config.num_threads;
    if (num_threads == 0) {
        num_threads = std::thread::hardware_concurrency();
        if (num_threads == 0) num_threads = 4;
    }
    if (total_bytes < 1024 * 1024) num_threads = 1;

    size_t est_tokens = config.token_estimate > 0
                        ? config.token_estimate
                        : estimate_total_tokens(files);
    size_t est_templates = est_tokens / TEMPLATE_RATIO;

    TokenMap tokens(est_tokens * 2);
    TemplateMap templates(std::max(MIN_CAPACITY, est_templates * 2));
    std::atomic<uint32_t> next_token_id{0};
    std::atomic<uint32_t> next_template_id{0};

    result.files.resize(files.size());
    for (size_t i = 0; i < files.size(); ++i) {
        result.files[i].file_index = i;
        if (!encode_file(files[i], tokens, templates,
                         next_token_id, next_template_id,
                         result.files[i], num_threads, config.show_timeline,
                         config.exclude_patterns)) {
            return false;
        }
    }

    // Merge similar templates using clustering
    size_t merged = merge_similar_templates(templates, result.files, next_template_id);

    result.token_count = next_token_id.load();
    result.template_count = next_template_id.load();
    result.merged_count = merged;

    build_presence_bitmaps(result.files, result.template_presence, result.var_value_presence);

    compute_sets(result.template_presence, result.file_count,
                 result.templates_common_to_all, result.templates_unique_to);
    compute_sets(result.var_value_presence, result.file_count,
                 result.var_values_common_to_all, result.var_values_unique_to);

    auto end = std::chrono::high_resolution_clock::now();
    double elapsed_ms = std::chrono::duration<double, std::milli>(end - start).count();

    if (config.format == TemplateConfig::Format::TEXT) {
        output_text(result, config, tokens, templates, std::cout);

        double load_factor = tokens.capacity() > 0
                             ? 100.0 * result.token_count / tokens.capacity() : 0;

        std::cout << "=== Stats ===\n";
        std::cout << "Time: " << elapsed_ms << " ms\n";
        std::cout << "Throughput: " << (total_bytes / (1024.0 * 1024.0)) / (elapsed_ms / 1000.0) << " MB/s\n";
        std::cout << "Merged: " << result.merged_count << " templates\n";
        std::cout << "HashCap: " << tokens.capacity() << " (" << load_factor << "% load)\n";
        std::cout << "OwnedToks: " << tokens.owned_count() << " (" << tokens.owned_bytes() / 1024.0 << " KB)\n";
        std::cout << "PeakMem: " << get_peak_memory() / (1024.0 * 1024.0) << " MB\n";

        if (config.analyze) {
            analyze_similarity(templates, tokens, result.files, config.top_n, std::cout);
        }
    }

    for (auto& f : files) f.close();

    return true;
}

} // namespace catalog
