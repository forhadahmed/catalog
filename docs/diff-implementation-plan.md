# Multi-Log Diff Implementation Plan

## Overview

Extend catalog with a `diff` command for comparing multiple log files to identify commonalities, differences, and patterns across files.

**Use Cases**:
- Pass vs fail test runs (root cause analysis)
- Fast vs slow runs (performance investigation)
- Version comparisons (regression detection)
- Environment comparisons (server1 vs server2)
- General N-file diff (find unique/common patterns)

---

## Design Goals

1. **Fast**: Process GB-scale logs at 400+ MB/s (leverage existing parallel tokenization)
2. **Memory efficient**: Use shared dictionary, compact per-file representation
3. **Flexible**: Support N files with optional arbitrary grouping
4. **Template-first**: Extract templates with variables for semantic comparison

---

## Core Approach: Unified Token + Template + Variable

```
KEY INSIGHT: Everything is a token, templates add structure

                     Shared TokenMap
                 (literals AND variables)
                           |
     +---------------------+---------------------+
     |                     |                     |
     v                     v                     v
  "Request"             "12345"              "timeout"
   tok_1                 tok_2                tok_3
  (literal)            (var value)          (literal)
     |                     |                     |
     +---------------------+---------------------+
                           |
                           v
              Template: [LIT:tok_1, VAR_NUM, LIT:tok_3]
                           |
                           v
              Line: (template_id, [tok_2])  <- var as token ID
```

**Benefits of unified approach**:
- Variable deduplication is FREE (same TokenMap)
- Cross-file variable tracking uses same bitmap infrastructure
- Single hash map for everything
- Simpler implementation

---

## Architecture

```
                         INPUT FILES
                              |
                              v
+------------------------------------------------------------------+
|                    PHASE 1: PARALLEL ENCODING                     |
|                                                                   |
|   file0    file1    file2    file3    file4                      |
|     |        |        |        |        |                        |
|     v        v        v        v        v                        |
|  +------+ +------+ +------+ +------+ +------+                    |
|  |Thread| |Thread| |Thread| |Thread| |Thread|                    |
|  +--+---+ +--+---+ +--+---+ +--+---+ +--+---+                    |
|     |        |        |        |        |                        |
|     +--------+--------+--------+--------+                        |
|                       |                                          |
|                       v                                          |
|     +------------------------------------------+                 |
|     |         Shared Token/Template Map        |                 |
|     |              (lock-free CAS)             |                 |
|     +------------------------------------------+                 |
|                       |                                          |
+------------------------------------------------------------------+
                        |
                        v
+------------------------------------------------------------------+
|                    PHASE 2: PER-FILE STATS                        |
|                                                                   |
|   For each file, collect:                                        |
|   - Token/template presence (bitset)                             |
|   - Token/template counts                                        |
|   - First/last occurrence line numbers                           |
|   - (Template mode) Variable value samples                       |
|                                                                   |
+------------------------------------------------------------------+
                        |
                        v
+------------------------------------------------------------------+
|                    PHASE 3: DIFF ANALYSIS                         |
|                                                                   |
|   - Compute set operations (intersection, unique per file)       |
|   - Apply optional grouping                                      |
|   - Calculate frequency statistics                               |
|   - Identify outliers                                            |
|   - Find divergence points                                       |
|                                                                   |
+------------------------------------------------------------------+
                        |
                        v
+------------------------------------------------------------------+
|                    PHASE 4: OUTPUT                                |
|                                                                   |
|   - Text report (human-readable)                                 |
|   - JSON (machine-readable)                                      |
|   - Timeline view (divergence visualization)                     |
|                                                                   |
+------------------------------------------------------------------+
```

---

## Data Structures

### Core Structures (Unified Approach)

```cpp
// Reuse existing TokenMap for ALL tokens (literals AND variable values)
// This gives us variable deduplication for free

// Template slot: either a literal or a variable placeholder
struct TemplateSlot {
    enum Type : uint8_t {
        LITERAL,    // fixed token (has token_id)
        VAR_NUM,    // numeric: 123, 45.67, -89
        VAR_HEX,    // hex: 0x1a2b, deadbeef
        VAR_IP,     // IP address: 10.0.0.1
        VAR_TIME,   // timestamp patterns
        VAR_PATH,   // file paths
        VAR_ID,     // UUIDs, hashes, identifiers
        VAR_STR     // catch-all string variable
    };

    Type type;
    uint32_t token_id;  // for LITERAL: the token id; for VAR_*: unused (0)
};

// Template: pattern of literals and variable slots
struct Template {
    uint32_t id;
    std::vector<TemplateSlot> slots;
    uint64_t signature;  // hash of (types + literal token_ids) for fast lookup
    uint8_t var_count;   // number of variable slots

    std::string to_pattern_string(const TokenMap& tokens) const;
    // e.g., "Request <NUM> took <NUM>ms"
};

// Template dictionary (lock-free, similar to TokenMap)
class TemplateMap {
public:
    uint32_t get_or_insert(const std::vector<TemplateSlot>& slots,
                           std::atomic<uint32_t>& next_id);
    const Template& get(uint32_t id) const;
    size_t size() const;

private:
    struct Slot {
        uint64_t signature;     // 0 = empty
        uint32_t id;
        Template tmpl;
    };
    std::vector<Slot> slots_;
    size_t mask_;
};

// Per-line encoded data
struct EncodedLine {
    uint32_t template_id;
    std::vector<uint32_t> var_token_ids;  // variable values as TOKEN IDs (deduped!)
};

// Per-file statistics
struct FileStats {
    std::string path;
    size_t file_index;
    size_t line_count;
    size_t byte_size;

    // Template presence and counts
    std::unordered_map<uint32_t, uint32_t> template_counts;  // template_id -> count

    // Variable value presence and counts (uses same token IDs!)
    std::unordered_map<uint32_t, uint32_t> var_value_counts;  // token_id -> count

    // Positional data (for divergence detection)
    std::unordered_map<uint32_t, size_t> template_first_occurrence;
    std::unordered_map<uint32_t, size_t> var_first_occurrence;

    // Line-level data (optional, for timeline view)
    std::vector<EncodedLine> lines;

    // Per-template variable distributions
    // template_id -> slot_index -> (var_token_id -> count)
    std::unordered_map<uint32_t,
        std::vector<std::unordered_map<uint32_t, uint32_t>>> var_distributions;
};

// Global analysis result
struct DiffAnalysis {
    // Shared dictionaries
    TokenMap tokens;              // ALL tokens (literals + variable values)
    TemplateMap templates;        // template patterns
    size_t token_count;
    size_t template_count;

    // Per-file data
    std::vector<FileStats> files;
    size_t file_count;

    // Presence bitmaps (supports up to 64 files)
    std::unordered_map<uint32_t, uint64_t> template_presence;  // template_id -> file bitmap
    std::unordered_map<uint32_t, uint64_t> var_value_presence; // token_id -> file bitmap

    // Computed template sets
    std::vector<uint32_t> templates_common_to_all;
    std::vector<std::vector<uint32_t>> templates_unique_to;  // [file_idx] -> template_ids

    // Computed variable value sets (same analysis, different level)
    std::vector<uint32_t> var_values_common_to_all;
    std::vector<std::vector<uint32_t>> var_values_unique_to;

    // Frequency anomalies
    struct FrequencyAnomaly {
        uint32_t id;              // template_id or token_id
        bool is_template;         // true=template, false=var_value
        std::vector<uint32_t> counts;
        double mean;
        double stddev;
        double max_ratio;
        size_t max_file;
        size_t min_file;
    };
    std::vector<FrequencyAnomaly> anomalies;

    // Variable distribution differences (within same template)
    struct VarDistributionDiff {
        uint32_t template_id;
        uint8_t slot_index;
        std::vector<uint32_t> values_unique_to_file[64];  // var token_ids
    };
    std::vector<VarDistributionDiff> var_diffs;

    // Optional grouping
    struct Group {
        std::string name;
        std::vector<size_t> file_indices;
        uint64_t file_mask;       // precomputed bitmap
    };
    std::vector<Group> groups;
};
```

### Why Variable Values Use Token IDs

```
ENCODING EXAMPLE:

Input line: "Connection to 10.0.0.1:8080 failed after 5000ms"

Step 1: Tokenize ALL tokens into TokenMap
  TokenMap:
    "Connection" -> tok_1
    "to"         -> tok_2
    "10.0.0.1"   -> tok_3   <- variable value, but still a token!
    "8080"       -> tok_4   <- variable value
    "failed"     -> tok_5
    "after"      -> tok_6
    "5000ms"     -> tok_7   <- variable value

Step 2: Classify each token
  tok_1: LITERAL
  tok_2: LITERAL
  tok_3: VAR_IP      <- classified as variable
  tok_4: VAR_NUM     <- classified as variable
  tok_5: LITERAL
  tok_6: LITERAL
  tok_7: VAR_NUM     <- classified as variable

Step 3: Build template
  Template T1: [LIT:tok_1, LIT:tok_2, VAR_IP, VAR_NUM, LIT:tok_5, LIT:tok_6, VAR_NUM]
  Pattern: "Connection to <IP> <NUM> failed after <NUM>"

Step 4: Encode line
  EncodedLine: {
    template_id: T1,
    var_token_ids: [tok_3, tok_4, tok_7]   <- token IDs, not strings!
  }

BENEFITS:
  - If "10.0.0.1" appears 100K times, stored once in TokenMap
  - Can track: "Which files contain 10.0.0.1?" via presence bitmap
  - Can compare: var_token_ids[i] == var_token_ids[j] is O(1)
```

---

## CLI Design

### Basic Commands

```bash
# Two-file diff
./catalog diff file1.log file2.log

# Multi-file diff
./catalog diff file1.log file2.log file3.log file4.log

# Glob pattern
./catalog diff logs/*.log

# With options
./catalog diff [options] <file1> <file2> [file3...]
```

### Options

```bash
Options:
  -g, --group <name:files>   Define a group (can be repeated)
                             Example: -g fast:a.log,b.log -g slow:c.log,d.log

  -t, --threads <num>        Number of threads (default: auto)

  --top <n>                  Show top N differences (default: 20)

  --min-freq <n>             Minimum frequency to report (default: 1)

  --format <fmt>             Output format: text (default), json

  --timeline                 Show divergence timeline

  --context <n>              Lines of context around divergences (default: 3)

  -o, --output <file>        Write output to file (default: stdout)

  -q, --quiet                Minimal output (just summary stats)

  -v, --verbose              Detailed output (include var distributions, samples)
```

### Usage Examples

```bash
# Simple diff of two log files (template extraction is default)
./catalog diff pass.log fail.log

# Compare multiple files, find what's common and unique
./catalog diff run1.log run2.log run3.log run4.log run5.log

# Grouped comparison with labels
./catalog diff -g pass:pass1.log,pass2.log -g fail:fail1.log

# Output to JSON for further processing
./catalog diff --format json -o analysis.json *.log

# Show timeline around divergence points
./catalog diff --timeline --context 5 before.log after.log

# Quiet mode for scripting (exit code indicates differences)
./catalog diff -q a.log b.log && echo "identical" || echo "different"

# Verbose mode to see variable value distributions
./catalog diff -v fast.log slow.log
```

---

## Processing Pipeline (Detailed)

### Step 1: Parse Arguments and Initialize

```cpp
struct DiffConfig {
    std::vector<std::string> input_files;
    std::vector<std::pair<std::string, std::vector<std::string>>> groups;
    unsigned num_threads;
    enum Mode { TOKEN, TEMPLATE, LINE } mode;
    size_t top_n;
    size_t min_freq;
    enum Format { TEXT, JSON, CSV } format;
    bool show_timeline;
    size_t context_lines;
    std::string output_path;
    bool quiet;
    bool verbose;
};

bool parse_diff_args(int argc, char* argv[], DiffConfig& config);
```

### Step 2: Memory-Map All Files

```cpp
struct MappedFiles {
    std::vector<MappedFile> files;
    size_t total_bytes;

    bool open_all(const std::vector<std::string>& paths);
    void close_all();
};

// Open all files, compute total size for progress estimation
MappedFiles mapped;
if (!mapped.open_all(config.input_files)) {
    return error("Failed to open input files");
}
```

### Step 3: Estimate Dictionary Size

```cpp
// Sample from all files to estimate unique tokens
size_t estimate_total_tokens(const MappedFiles& files) {
    size_t total_estimate = 0;
    for (const auto& f : files.files) {
        total_estimate += estimate_unique_tokens(f.data, f.size);
    }
    // Reduce for overlap (same tokens across files)
    // Heuristic: assume 50% overlap for similar log files
    return total_estimate * 0.7;
}
```

### Step 4: Parallel Encoding (Template + Var Mode)

```cpp
// Variable type classification (fast regex-like checks)
TemplateSlot::Type classify_token(std::string_view tok) {
    // Check patterns in order of specificity
    if (is_ip_address(tok)) return TemplateSlot::VAR_IP;
    if (is_hex_number(tok)) return TemplateSlot::VAR_HEX;
    if (is_number(tok)) return TemplateSlot::VAR_NUM;
    if (is_timestamp(tok)) return TemplateSlot::VAR_TIME;
    if (is_path(tok)) return TemplateSlot::VAR_PATH;
    if (is_uuid_or_hash(tok)) return TemplateSlot::VAR_ID;

    return TemplateSlot::LITERAL;
}

// Pattern matchers (inline for performance)
inline bool is_number(std::string_view s) {
    if (s.empty()) return false;
    size_t i = 0;
    if (s[0] == '-' || s[0] == '+') i++;
    bool has_digit = false;
    bool has_dot = false;
    for (; i < s.size(); ++i) {
        if (std::isdigit(s[i])) has_digit = true;
        else if (s[i] == '.' && !has_dot) has_dot = true;
        else return false;
    }
    return has_digit;
}

inline bool is_hex_number(std::string_view s) {
    if (s.size() < 3) return false;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        for (size_t i = 2; i < s.size(); ++i) {
            if (!std::isxdigit(s[i])) return false;
        }
        return true;
    }
    // Also match pure hex strings of 8+ chars (hashes, etc.)
    if (s.size() >= 8) {
        for (char c : s) {
            if (!std::isxdigit(c)) return false;
        }
        return true;
    }
    return false;
}

inline bool is_ip_address(std::string_view s) {
    // Simple IPv4: N.N.N.N where each N is 1-3 digits
    int dots = 0, digits = 0;
    for (char c : s) {
        if (c == '.') { dots++; digits = 0; }
        else if (std::isdigit(c)) { digits++; if (digits > 3) return false; }
        else return false;
    }
    return dots == 3;
}

inline bool is_timestamp(std::string_view s) {
    // Common: 2024-12-16, 10:30:45, 2024-12-16T10:30:45Z
    if (s.size() < 8) return false;
    int digits = 0, separators = 0;
    for (char c : s) {
        if (std::isdigit(c)) digits++;
        else if (c == '-' || c == ':' || c == 'T' || c == 'Z' || c == '.') separators++;
        else return false;
    }
    return digits >= 4 && separators >= 2;
}

inline bool is_path(std::string_view s) {
    // Starts with / or contains /path/ pattern
    return s.size() > 1 && (s[0] == '/' || s.find(":/") != std::string_view::npos);
}

inline bool is_uuid_or_hash(std::string_view s) {
    // UUID: 8-4-4-4-12 hex with dashes, or 32+ hex chars
    if (s.size() == 36 && s[8] == '-' && s[13] == '-') return true;
    if (s.size() >= 32) {
        for (char c : s) {
            if (!std::isxdigit(c)) return false;
        }
        return true;
    }
    return false;
}

// =============================================================================
// UNIFIED ENCODING: All tokens go to TokenMap, then classify for template
// =============================================================================

EncodedLine encode_line(
    const char* line_start,
    const char* line_end,
    TokenMap& tokens,              // UNIFIED: literals AND var values
    TemplateMap& templates,
    std::atomic<uint32_t>& next_token_id,
    std::atomic<uint32_t>& next_template_id
) {
    std::vector<TemplateSlot> slots;
    std::vector<uint32_t> var_token_ids;

    const char* p = line_start;
    while (p < line_end) {
        // Skip whitespace
        while (p < line_end && (*p == ' ' || *p == '\t')) ++p;
        if (p >= line_end) break;

        // Find token end
        const char* tok_start = p;
        while (p < line_end && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') ++p;
        size_t tok_len = p - tok_start;

        // Insert ALL tokens into TokenMap (unified dedup)
        uint32_t tok_id = tokens.get_or_insert(tok_start, tok_len, next_token_id);

        // Classify token
        std::string_view tok_view(tok_start, tok_len);
        TemplateSlot::Type vtype = classify_token(tok_view);

        if (vtype == TemplateSlot::LITERAL) {
            slots.push_back({TemplateSlot::LITERAL, tok_id});
        } else {
            slots.push_back({vtype, 0});  // var slot, token_id not stored in template
            var_token_ids.push_back(tok_id);  // var VALUE stored as token ID!
        }
    }

    uint32_t template_id = templates.get_or_insert(slots, next_template_id);

    return {template_id, std::move(var_token_ids)};
}

// Parallel encoding of all files
bool encode_all_files(
    const MappedFiles& mapped,
    TokenMap& tokens,
    TemplateMap& templates,
    std::vector<FileStats>& file_stats,
    unsigned num_threads,
    bool store_lines  // true for --timeline mode
) {
    std::atomic<uint32_t> next_token_id{0};
    std::atomic<uint32_t> next_template_id{0};
    file_stats.resize(mapped.files.size());

    for (size_t f = 0; f < mapped.files.size(); ++f) {
        const auto& mf = mapped.files[f];
        auto& stats = file_stats[f];
        stats.file_index = f;
        stats.path = mf.path;
        stats.byte_size = mf.size;

        // Process file with chunk parallelism (reuse existing pattern)
        // Each thread:
        //   1. Tokenize lines in chunk
        //   2. Encode each line -> (template_id, var_token_ids)
        //   3. Update local stats
        //   4. Optionally store EncodedLine

        std::vector<std::thread> workers;
        std::vector<ChunkResult> chunk_results(num_threads);

        // ... chunk boundary calculation (same as existing encode) ...

        for (unsigned t = 0; t < num_threads; ++t) {
            workers.emplace_back([&, t]() {
                auto& result = chunk_results[t];
                const char* p = chunks[t].first;
                const char* end = chunks[t].second;

                while (p < end) {
                    const char* line_start = p;
                    while (p < end && *p != '\n') ++p;
                    const char* line_end = p;
                    if (p < end) ++p;  // skip newline

                    EncodedLine enc = encode_line(
                        line_start, line_end,
                        tokens, templates,
                        next_token_id, next_template_id
                    );

                    // Update template counts
                    result.template_counts[enc.template_id]++;

                    // Update var value counts
                    for (uint32_t var_id : enc.var_token_ids) {
                        result.var_value_counts[var_id]++;
                    }

                    // Track first occurrence
                    if (result.template_first.find(enc.template_id) == result.template_first.end()) {
                        result.template_first[enc.template_id] = result.line_count;
                    }
                    for (uint32_t var_id : enc.var_token_ids) {
                        if (result.var_first.find(var_id) == result.var_first.end()) {
                            result.var_first[var_id] = result.line_count;
                        }
                    }

                    // Store line if requested
                    if (store_lines) {
                        result.lines.push_back(std::move(enc));
                    }

                    result.line_count++;
                }
            });
        }

        for (auto& w : workers) w.join();

        // Merge chunk results into file stats
        merge_results(chunk_results, stats);
    }

    return true;
}
```

### Step 6: Build Presence Bitmaps

```cpp
void build_presence_bitmaps(
    const std::vector<FileStats>& file_stats,
    std::unordered_map<uint32_t, uint64_t>& presence
) {
    for (size_t f = 0; f < file_stats.size(); ++f) {
        uint64_t file_bit = 1ULL << f;
        for (const auto& [item_id, count] : file_stats[f].item_counts) {
            presence[item_id] |= file_bit;
        }
    }
}
```

### Step 7: Compute Set Operations

```cpp
void compute_diff_sets(
    const std::unordered_map<uint32_t, uint64_t>& presence,
    size_t file_count,
    std::vector<uint32_t>& common_to_all,
    std::vector<std::vector<uint32_t>>& unique_to
) {
    uint64_t all_files_mask = (1ULL << file_count) - 1;
    unique_to.resize(file_count);

    for (const auto& [item_id, bitmap] : presence) {
        if (bitmap == all_files_mask) {
            // Present in all files
            common_to_all.push_back(item_id);
        } else {
            // Check if unique to a single file
            if ((bitmap & (bitmap - 1)) == 0) {
                // Power of 2 = exactly one bit set
                size_t file_idx = __builtin_ctzll(bitmap);
                unique_to[file_idx].push_back(item_id);
            }
        }
    }
}
```

### Step 8: Compute Group Differences

```cpp
struct GroupDiff {
    std::string group_a_name;
    std::string group_b_name;
    std::vector<uint32_t> a_only;  // in all of A, none of B
    std::vector<uint32_t> b_only;  // in all of B, none of A
    std::vector<uint32_t> common;  // in all of both
};

GroupDiff compute_group_diff(
    const std::unordered_map<uint32_t, uint64_t>& presence,
    const DiffAnalysis::Group& group_a,
    const DiffAnalysis::Group& group_b
) {
    GroupDiff result;
    result.group_a_name = group_a.name;
    result.group_b_name = group_b.name;

    // Build masks
    uint64_t mask_a = 0, mask_b = 0;
    for (size_t f : group_a.file_indices) mask_a |= (1ULL << f);
    for (size_t f : group_b.file_indices) mask_b |= (1ULL << f);

    for (const auto& [item_id, bitmap] : presence) {
        bool in_all_a = (bitmap & mask_a) == mask_a;
        bool in_any_a = (bitmap & mask_a) != 0;
        bool in_all_b = (bitmap & mask_b) == mask_b;
        bool in_any_b = (bitmap & mask_b) != 0;

        if (in_all_a && !in_any_b) {
            result.a_only.push_back(item_id);
        } else if (in_all_b && !in_any_a) {
            result.b_only.push_back(item_id);
        } else if (in_all_a && in_all_b) {
            result.common.push_back(item_id);
        }
    }

    return result;
}
```

### Step 9: Frequency Analysis

```cpp
struct FrequencyAnomaly {
    uint32_t item_id;
    std::vector<uint32_t> counts;  // per file
    double mean;
    double stddev;
    double cv;          // coefficient of variation (stddev/mean)
    size_t max_file;    // file with max count
    size_t min_file;    // file with min count
    double max_ratio;   // max/min ratio
};

std::vector<FrequencyAnomaly> find_frequency_anomalies(
    const std::vector<FileStats>& file_stats,
    double min_cv = 1.0,      // minimum coefficient of variation
    double min_ratio = 5.0,   // minimum max/min ratio
    size_t min_total = 10     // minimum total occurrences
) {
    std::vector<FrequencyAnomaly> anomalies;

    // Collect all item IDs
    std::unordered_set<uint32_t> all_items;
    for (const auto& fs : file_stats) {
        for (const auto& [id, _] : fs.item_counts) {
            all_items.insert(id);
        }
    }

    for (uint32_t item_id : all_items) {
        FrequencyAnomaly fa;
        fa.item_id = item_id;
        fa.counts.resize(file_stats.size());

        size_t total = 0;
        uint32_t max_count = 0, min_count = UINT32_MAX;

        for (size_t f = 0; f < file_stats.size(); ++f) {
            auto it = file_stats[f].item_counts.find(item_id);
            fa.counts[f] = (it != file_stats[f].item_counts.end()) ? it->second : 0;
            total += fa.counts[f];
            if (fa.counts[f] > max_count) { max_count = fa.counts[f]; fa.max_file = f; }
            if (fa.counts[f] < min_count) { min_count = fa.counts[f]; fa.min_file = f; }
        }

        if (total < min_total) continue;

        fa.mean = static_cast<double>(total) / file_stats.size();

        double variance = 0;
        for (uint32_t c : fa.counts) {
            variance += (c - fa.mean) * (c - fa.mean);
        }
        fa.stddev = std::sqrt(variance / file_stats.size());
        fa.cv = (fa.mean > 0) ? fa.stddev / fa.mean : 0;
        fa.max_ratio = (min_count > 0) ? static_cast<double>(max_count) / min_count : max_count;

        if (fa.cv >= min_cv || fa.max_ratio >= min_ratio) {
            anomalies.push_back(fa);
        }
    }

    // Sort by max_ratio descending
    std::sort(anomalies.begin(), anomalies.end(),
        [](const auto& a, const auto& b) { return a.max_ratio > b.max_ratio; });

    return anomalies;
}
```

### Step 10: Divergence Detection

```cpp
struct Divergence {
    size_t line_number;           // approximate line where divergence occurs
    std::vector<uint32_t> file_a_tokens;  // tokens at this line in file(s) A
    std::vector<uint32_t> file_b_tokens;  // tokens at this line in file(s) B
    double similarity;            // 0.0 = completely different, 1.0 = identical
};

// Find first divergence point between two files
Divergence find_first_divergence(
    const FileStats& file_a,
    const FileStats& file_b,
    size_t context = 3
) {
    size_t min_lines = std::min(file_a.lines.size(), file_b.lines.size());

    for (size_t i = 0; i < min_lines; ++i) {
        if (file_a.lines[i] != file_b.lines[i]) {
            return {
                i,
                file_a.lines[i],
                file_b.lines[i],
                jaccard_similarity(file_a.lines[i], file_b.lines[i])
            };
        }
    }

    // Files are identical up to the shorter one's length
    if (file_a.lines.size() != file_b.lines.size()) {
        return {min_lines, {}, {}, 0.0};
    }

    return {SIZE_MAX, {}, {}, 1.0};  // Identical
}

double jaccard_similarity(
    const std::vector<uint32_t>& a,
    const std::vector<uint32_t>& b
) {
    std::unordered_set<uint32_t> set_a(a.begin(), a.end());
    std::unordered_set<uint32_t> set_b(b.begin(), b.end());

    size_t intersection = 0;
    for (uint32_t x : set_a) {
        if (set_b.count(x)) intersection++;
    }

    size_t union_size = set_a.size() + set_b.size() - intersection;
    return (union_size > 0) ? static_cast<double>(intersection) / union_size : 1.0;
}
```

### Step 11: Output Generation

```cpp
// Text output
void output_text(
    const DiffAnalysis& analysis,
    const DiffConfig& config,
    std::ostream& out
) {
    out << "=== Multi-Log Diff Analysis ===\n\n";

    // File summary
    out << "Files: " << analysis.file_count << "\n";
    for (const auto& f : analysis.files) {
        out << "  " << f.path << " ("
            << (f.byte_size / (1024.0 * 1024.0)) << " MB, "
            << f.line_count << " lines)\n";
    }
    out << "\n";

    // Dictionary size
    out << "Shared dictionary: " << analysis.dict_size << " unique "
        << (config.mode == DiffConfig::TEMPLATE ? "templates" : "tokens") << "\n\n";

    // Common to all
    out << "=== COMMON TO ALL (" << analysis.common_to_all.size() << ") ===\n";
    // ... print top N ...

    // Unique to each file
    for (size_t f = 0; f < analysis.file_count; ++f) {
        out << "=== UNIQUE TO " << analysis.files[f].path
            << " (" << analysis.unique_to[f].size() << ") ===\n";
        // ... print top N ...
    }

    // Group comparisons
    for (const auto& gd : analysis.group_diffs) {
        out << "=== " << gd.group_a_name << " ONLY (" << gd.a_only.size() << ") ===\n";
        // ...
        out << "=== " << gd.group_b_name << " ONLY (" << gd.b_only.size() << ") ===\n";
        // ...
    }

    // Frequency anomalies
    out << "=== FREQUENCY ANOMALIES ===\n";
    for (const auto& fa : analysis.frequency_anomalies) {
        out << "  \"" << analysis.dictionary[fa.item_id] << "\"\n";
        out << "    ";
        for (size_t f = 0; f < fa.counts.size(); ++f) {
            out << analysis.files[f].path << ": " << fa.counts[f] << "x, ";
        }
        out << "\n    ratio: " << fa.max_ratio << "x\n";
    }

    // Timeline (if requested)
    if (config.show_timeline) {
        output_timeline(analysis, config, out);
    }
}

// JSON output
void output_json(
    const DiffAnalysis& analysis,
    const DiffConfig& config,
    std::ostream& out
) {
    out << "{\n";
    out << "  \"files\": [\n";
    for (size_t f = 0; f < analysis.files.size(); ++f) {
        out << "    {\"path\": \"" << analysis.files[f].path << "\", "
            << "\"bytes\": " << analysis.files[f].byte_size << ", "
            << "\"lines\": " << analysis.files[f].line_count << "}";
        if (f + 1 < analysis.files.size()) out << ",";
        out << "\n";
    }
    out << "  ],\n";

    out << "  \"dictionary_size\": " << analysis.dict_size << ",\n";

    out << "  \"common_to_all\": [";
    // ... item list ...
    out << "],\n";

    out << "  \"unique_per_file\": {\n";
    // ... per file ...
    out << "  },\n";

    out << "  \"frequency_anomalies\": [\n";
    // ... anomaly list ...
    out << "  ]\n";

    out << "}\n";
}
```

---

## Implementation Phases

### Phase 1: Template + Var Diff (MVP)

**Goal**: Multi-file diff with template extraction and variable deduplication.

**Steps**:

1. **Add `diff` command to main()**
   - Parse new command: `./catalog diff file1 file2 ...`
   - Add DiffConfig struct
   - Wire up argument parsing with getopt_long

2. **Implement variable classifiers**
   - `is_number()`, `is_hex()`, `is_ip()`, `is_timestamp()`, `is_path()`, `is_uuid_or_hash()`
   - `classify_token()` dispatcher
   - Unit tests for each classifier

3. **Implement TemplateSlot and Template structs**
   - Template representation with slot types
   - Template signature hash for fast lookup

4. **Implement TemplateMap**
   - Lock-free concurrent template dictionary
   - Similar structure to existing TokenMap
   - `get_or_insert()` with atomic CAS

5. **Implement unified encoding**
   - ALL tokens go to TokenMap (literals AND variable values)
   - Classify each token to build template
   - Return (template_id, var_token_ids[])
   - Parallel encoding within each file (reuse chunk pattern)

6. **Implement per-file stats collection**
   - Template counts
   - Variable value counts (using token IDs)
   - First occurrence tracking

7. **Implement presence bitmap calculation**
   - Template presence: template_id -> file bitmap
   - Variable value presence: token_id -> file bitmap

8. **Implement set operations**
   - Templates common to all / unique to each
   - Variable values common to all / unique to each

9. **Implement text output**
   - File summary
   - Unique templates per file (as patterns like "Connection to <IP> failed")
   - Unique variable values per file (with context)

10. **Testing**
    - Unit tests for classifiers, TemplateMap
    - Integration tests with synthetic log files
    - Test 2 files, N files

**Deliverable**: `./catalog diff a.log b.log` shows template and variable differences.

**Example output**:
```
=== Multi-Log Diff ===
Files: 2
  a.log (50 MB, 1.2M lines)
  b.log (48 MB, 1.1M lines)

Tokens: 45,231 | Templates: 892

=== TEMPLATES UNIQUE TO a.log (3) ===
  "Test passed with result <NUM>"
  "Cache hit for key <ID>"

=== TEMPLATES UNIQUE TO b.log (5) ===
  "ERROR: Connection to <IP> failed after <NUM>ms"
  "Retrying operation <NUM>/<NUM>"
  "FATAL: Process terminated"

=== VARIABLE VALUES UNIQUE TO b.log (12) ===
  "10.0.0.99" (IP, in template "Connection to <IP>...")
  "30000" (NUM, in template "...failed after <NUM>ms")
```

---

### Phase 2: Grouping and Frequency Analysis

**Goal**: Add optional grouping and statistical analysis.

**Steps**:

1. **Add grouping support**
   - Parse `-g name:file1,file2` syntax
   - Store groups in DiffConfig with precomputed bitmasks
   - Validate file paths

2. **Implement group diff calculation**
   - For each pair of groups, compute A-only and B-only sets
   - Works for both templates and variable values

3. **Implement frequency analysis**
   - Calculate mean, stddev, CV for templates across files
   - Calculate mean, stddev, CV for variable values across files
   - Identify statistical outliers (ratio > 5x)
   - Sort by significance

4. **Implement variable distribution analysis**
   - For each template, track which var values appear in which files
   - Find var values that only appear in certain files
   - Example: same template "timeout after <NUM>ms", but values differ

5. **Update output**
   - Show group comparisons
   - Show frequency anomalies
   - Show variable distribution differences

6. **Testing**
   - Test grouped comparison with pass/fail labels
   - Test frequency detection

**Deliverable**: `./catalog diff -g pass:p1.log,p2.log -g fail:f1.log` shows group differences.

---

### Phase 3: Timeline and Divergence Detection

**Goal**: Add temporal analysis and divergence visualization.

**Steps**:

1. **Implement line-level data storage**
   - Store EncodedLine per line (template_id + var_token_ids)
   - Enable with --timeline flag (increases memory)

2. **Implement divergence detection**
   - Find first line where files differ
   - Use template comparison (ignore var values for matching)
   - Compute Jaccard similarity for near-matches

3. **Implement timeline output**
   - ASCII visualization showing where files diverge
   - Show context lines around divergence
   - Highlight template and variable differences

4. **Testing**
   - Test with files that diverge at known points
   - Test with gradually diverging files

**Deliverable**: `./catalog diff --timeline a.log b.log` shows where logs diverge.

---

### Phase 4: JSON Output and Scripting

**Goal**: Machine-readable output and scripting integration.

**Steps**:

1. **Implement JSON output**
   - Full analysis as structured JSON
   - Templates as pattern strings
   - Variable values with context

2. **Implement exit codes**
   - 0 = identical (or only var value differences)
   - 1 = template differences found
   - 2 = error

3. **Implement quiet mode**
   - Minimal output (just counts)
   - For scripting: `./catalog diff -q a.log b.log || echo "different"`

4. **Implement verbose mode**
   - Full variable distributions
   - Line number references
   - Sample values

**Deliverable**: `./catalog diff --format json a.log b.log | jq .templates_unique_to`

---

### Phase 5: Performance Optimization

**Goal**: Optimize for large files and many files.

**Steps**:

1. **Parallel file processing**
   - Process multiple files concurrently
   - Useful when many small-medium files

2. **Memory optimization**
   - Limit line storage for very large files
   - Configurable with --max-lines

3. **Progress reporting**
   - Show progress for long-running diffs
   - Per-file progress

4. **Benchmarking**
   - Target: 5x 500MB files in <15 seconds
   - Profile and optimize bottlenecks

**Deliverable**: Process 10x 1GB files efficiently.

---

## Testing Strategy

### Unit Tests

```cpp
// test/diff_test.cc

TEST(classify_token_numbers) {
    ASSERT_EQ(classify_token("123"), VAR_NUM);
    ASSERT_EQ(classify_token("-45.67"), VAR_NUM);
    ASSERT_EQ(classify_token("0x1a2b"), VAR_HEX);
    ASSERT_EQ(classify_token("10.0.0.1"), VAR_IP);
    ASSERT_EQ(classify_token("hello"), LITERAL);
}

TEST(presence_bitmap) {
    // Test bitmap operations
}

TEST(set_operations) {
    // Test common/unique calculation
}

TEST(frequency_analysis) {
    // Test outlier detection
}

TEST(template_extraction) {
    // Test template creation and matching
}

TEST(divergence_detection) {
    // Test divergence finding
}
```

### Integration Tests

```bash
# test/diff_integration_test.sh

# Test identical files
echo "hello world" > /tmp/a.log
cp /tmp/a.log /tmp/b.log
./bin/catalog diff /tmp/a.log /tmp/b.log | grep "COMMON TO ALL"

# Test different files
echo "hello world" > /tmp/a.log
echo "goodbye world" > /tmp/b.log
./bin/catalog diff /tmp/a.log /tmp/b.log | grep "UNIQUE TO"

# Test grouping
./bin/catalog diff -g A:/tmp/a.log -g B:/tmp/b.log | grep "A ONLY"

# Test JSON output
./bin/catalog diff --format json /tmp/a.log /tmp/b.log | jq .

# Test exit codes
./bin/catalog diff -q /tmp/a.log /tmp/a.log; echo "Exit: $?"  # Should be 0
./bin/catalog diff -q /tmp/a.log /tmp/b.log; echo "Exit: $?"  # Should be 1
```

---

## Memory Estimates

| Files | Total Size | Dictionary | Per-file Stats | Line Data | Total |
|-------|------------|------------|----------------|-----------|-------|
| 2 | 1 GB | 5 MB | 10 MB | (optional) 200 MB | 15-215 MB |
| 5 | 2.5 GB | 10 MB | 25 MB | (optional) 500 MB | 35-535 MB |
| 10 | 5 GB | 15 MB | 50 MB | (optional) 1 GB | 65 MB - 1.1 GB |

Line-level data (for timeline) is optional and significantly increases memory. Default: disabled, enabled with `--timeline`.

---

## File Changes Required

```
catalog/
+-- src/
|   +-- catalog.cc        # Add diff command dispatch
|   +-- diff.cc           # NEW: Diff implementation
|   +-- diff.h            # NEW: Diff data structures (TemplateSlot, Template, etc.)
|   +-- template_map.h    # NEW: Lock-free TemplateMap (similar to TokenMap)
|   +-- classifiers.h     # NEW: Variable type classifiers
+-- test/
|   +-- diff_test.cc      # NEW: Diff unit tests
|   +-- classifier_test.cc # NEW: Variable classifier tests
|   +-- diff_integration_test.sh  # NEW: Diff integration tests
+-- docs/
|   +-- catalog.md        # Update with diff command docs
|   +-- diff-implementation-plan.md  # This document
+-- Makefile              # Add diff_test, classifier_test targets
```

---

## Success Criteria

1. **Functional**: `./catalog diff a.log b.log` correctly identifies template and variable differences
2. **Fast**: Process 5x 500MB files in <15 seconds
3. **Useful**: Output helps identify root cause (unique templates, unique var values)
4. **Accurate classification**: Variable classifiers correctly identify numbers, IPs, timestamps, etc.
5. **Tested**: Unit tests for classifiers, TemplateMap; integration tests for diff
6. **Documented**: Help text and docs explain usage

---

## Open Questions

1. **Maximum file count**: 64 (uint64_t bitmap) sufficient? Could use dynamic bitset for more.
   - Decision: Start with 64, expand if needed.

2. **Variable classification**: Pure regex vs. frequency-based learning?
   - Decision: Start with regex (simpler, faster). Can add learning later.

3. **Line storage**: Always store lines for timeline, or make optional?
   - Decision: Optional (--timeline flag). Default off to save memory.

4. **Template signature collisions**: How to handle hash collisions in TemplateMap?
   - Decision: Same approach as TokenMap - linear probing, full comparison on match.

---

## Revision History

| Date | Change |
|------|--------|
| 2024-12-16 | Initial plan created |
| 2024-12-16 | Unified template+var approach: MVP is now template extraction with var dedup |
| 2024-12-16 | Variable values use TokenMap (same as literals) for free deduplication |
| 2024-12-16 | Removed separate token-only mode - template mode includes token-level analysis |
