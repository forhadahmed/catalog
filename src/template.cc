// template.cc - Template extraction implementation
// Uses TokenMap from token.h and MappedFile from mmap.h

#include "mmap.h"
#include "template.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <iostream>
#include <sys/resource.h>
#include <thread>

namespace catalog {

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
                normalized += "<PREFIX>";
            } else {
                extracted.push_back({VarType::VAR_IP, i, ip_len});
                normalized += "<IP>";
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
                    normalized += "<PREFIX>";
                } else {
                    extracted.push_back({VarType::VAR_IP, i, ipv6_len});
                    normalized += "<IP>";
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
            normalized += "<HEX>";
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
            normalized += "<ARRAY>";
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
        slot_buf.reserve(64);
        var_buf.reserve(32);
        norm_buf.reserve(256);
        extract_buf.reserve(16);
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
                *p == '(' || *p == ')' || *p == '{' || *p == '}') {
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
                       *p != '(' && *p != ')' && *p != '{' && *p != '}') ++p;
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

            cs.template_counts.reserve(10000);
            cs.var_value_counts.reserve(50000);
            cs.template_first_line.reserve(10000);
            cs.var_first_line.reserve(50000);

            LineEncoder encoder(tokens, templates, next_token_id, next_template_id);
            size_t base_line = base_lines[t];  // O(1) lookup instead of O(n) scan

            while (p < end) {
                const char* line_start = p;
                while (p < end && *p != '\n') ++p;
                const char* line_end = p;
                if (p < end) ++p;

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
    constexpr size_t SAMPLE_SIZE = 4 * 1024 * 1024;
    size_t total_estimate = 0;

    for (const auto& mf : files) {
        if (mf.size == 0) continue;

        size_t sample_bytes = std::min(mf.size, SAMPLE_SIZE);
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

    return std::max(size_t(1024), total_estimate * 2 / 3);
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
// Format template as pattern string
//=============================================================================

static std::string format_template(const TemplateMap::Entry& tmpl, const TokenMap& tokens) {
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

        return;
    }

    // Multi-file mode
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
// Main Template Extraction Function
//=============================================================================

bool extract_templates(const TemplateConfig& config, TemplateResult& result) {
    auto start = std::chrono::high_resolution_clock::now();

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
    size_t est_templates = est_tokens / 10;

    TokenMap tokens(est_tokens * 2);
    TemplateMap templates(std::max(size_t(1024), est_templates * 2));
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

    result.token_count = next_token_id.load();
    result.template_count = next_template_id.load();

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
        std::cout << "HashCap: " << tokens.capacity() << " (" << load_factor << "% load)\n";
        std::cout << "OwnedToks: " << tokens.owned_count() << " (" << tokens.owned_bytes() / 1024.0 << " KB)\n";
        std::cout << "PeakMem: " << get_peak_memory() / (1024.0 * 1024.0) << " MB\n";
    }

    for (auto& f : files) f.close();

    return true;
}

} // namespace catalog
