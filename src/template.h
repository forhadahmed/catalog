// template.h - Template extraction and variable deduplication
// Part of catalog - high-performance log file tokenizer

#ifndef CATALOG_TEMPLATE_H
#define CATALOG_TEMPLATE_H

#include "token.h"
#include "variable.h"

#include <unordered_map>

namespace catalog {

//=============================================================================
// Template Slot and Template
//=============================================================================

struct TemplateSlot {
    VarType type;
    uint32_t token_id;  // For LITERAL: the token id; for VAR_*: unused (0)

    bool operator==(const TemplateSlot& o) const {
        return type == o.type && (type != VarType::LITERAL || token_id == o.token_id);
    }
};

// Template signature hash (for fast lookup)
inline uint64_t template_hash(const TemplateSlot* slots, size_t count) {
    uint64_t h = 14695981039346656037ULL;
    for (size_t i = 0; i < count; ++i) {
        h ^= static_cast<uint8_t>(slots[i].type);
        h *= 1099511628211ULL;
        if (slots[i].type == VarType::LITERAL) {
            h ^= slots[i].token_id;
            h *= 1099511628211ULL;
        }
    }
    return h;
}

//=============================================================================
// TemplateMap - Lock-free concurrent template deduplication
//=============================================================================
//
// Maps template signatures (slot arrays) to unique 32-bit IDs.
// Example: [LIT:"ERROR", LIT:"user", VAR_NUM] -> template 0
//
// Lines with same structure but different variable values share a template.
// Only used by template extraction mode.
//
// Note: Uses same lock-free probing pattern as TokenMap but differs in:
//   - Hash: FNV-1a on slot types and literal token_ids
//   - Compare: slot-by-slot equality
//   - Storage: vector of TemplateSlot + var_count

class TemplateMap {
public:
    struct Entry {
        uint64_t hash;
        uint32_t id;
        std::vector<TemplateSlot> slots;
        uint8_t var_count;
    };

    explicit TemplateMap(size_t capacity) {
        capacity_ = 1;
        while (capacity_ < capacity) capacity_ *= 2;
        mask_ = capacity_ - 1;
        entries_.resize(capacity_);
        for (auto& e : entries_) e.hash = 0;
        // Index for O(1) lookup by ID
        entries_by_id_.resize(capacity_, nullptr);
    }

    uint32_t get_or_insert(const TemplateSlot* slots, size_t slot_count,
                           std::atomic<uint32_t>& next_id) {
        uint64_t h = template_hash(slots, slot_count);
        if (h == 0) h = 1;

        size_t idx = h & mask_;
        size_t max_probes = capacity_ * 7 / 10;

        for (size_t probe = 0; probe < max_probes; ++probe) {
            Entry& e = entries_[idx];
            uint64_t current = __atomic_load_n(&e.hash, __ATOMIC_RELAXED);

            if (current == 0) {
                uint64_t expected = 0;
                if (__atomic_compare_exchange_n(&e.hash, &expected, h,
                        false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
                    uint32_t new_id = next_id.fetch_add(1, std::memory_order_relaxed);
                    e.slots.assign(slots, slots + slot_count);
                    e.var_count = 0;
                    for (size_t i = 0; i < slot_count; ++i) {
                        if (slots[i].type != VarType::LITERAL) e.var_count++;
                    }
                    // Store pointer for O(1) lookup by ID
                    if (new_id < entries_by_id_.size()) {
                        entries_by_id_[new_id] = &e;
                    }
                    __atomic_store_n(&e.id, new_id, __ATOMIC_RELEASE);
                    return new_id;
                }
                current = __atomic_load_n(&e.hash, __ATOMIC_ACQUIRE);
            }

            if (current == h) {
                while (e.slots.empty() && e.hash == h) _mm_pause();
                if (e.slots.size() == slot_count) {
                    bool match = true;
                    for (size_t i = 0; i < slot_count && match; ++i) {
                        match = (e.slots[i] == slots[i]);
                    }
                    if (match) {
                        return __atomic_load_n(&e.id, __ATOMIC_ACQUIRE);
                    }
                }
            }

            idx = (idx + 1) & mask_;
        }

        return UINT32_MAX;
    }

    const Entry* get(uint32_t id) const {
        // O(1) lookup via index
        if (id < entries_by_id_.size() && entries_by_id_[id] != nullptr) {
            return entries_by_id_[id];
        }
        return nullptr;
    }

    size_t capacity() const { return capacity_; }

private:
    size_t capacity_;
    size_t mask_;
    std::vector<Entry> entries_;
    std::vector<Entry*> entries_by_id_;  // O(1) lookup index
};

//=============================================================================
// Encoded Line and File Stats
//=============================================================================

struct EncodedLine {
    uint32_t template_id;
    std::vector<uint32_t> var_token_ids;
};

struct FileStats {
    std::string path;
    size_t file_index = 0;
    size_t line_count = 0;
    size_t byte_size = 0;

    std::unordered_map<uint32_t, uint32_t> template_counts;
    std::unordered_map<uint32_t, uint32_t> var_value_counts;
    std::unordered_map<uint32_t, size_t> template_first_line;
    std::unordered_map<uint32_t, size_t> var_first_line;
    std::vector<EncodedLine> lines;
};

//=============================================================================
// Template Extraction Configuration
//=============================================================================

struct TemplateConfig {
    std::vector<std::string> input_files;

    struct Group {
        std::string name;
        std::vector<size_t> file_indices;
        uint64_t file_mask = 0;
    };
    std::vector<Group> groups;

    unsigned num_threads = 0;  // 0 = auto
    size_t token_estimate = 0; // 0 = auto (sample-based estimation)
    size_t top_n = 20;
    size_t min_freq = 1;

    enum class Format { TEXT, JSON } format = Format::TEXT;

    bool show_timeline = false;
    size_t context_lines = 3;

    std::string output_path;
    bool quiet = false;
    bool verbose = false;

    // Lines containing any of these substrings are excluded
    std::vector<std::string> exclude_patterns;
};

//=============================================================================
// Template Extraction Result
//=============================================================================

struct TemplateResult {
    size_t file_count = 0;
    size_t token_count = 0;
    size_t template_count = 0;

    std::vector<FileStats> files;

    std::unordered_map<uint32_t, uint64_t> template_presence;
    std::unordered_map<uint32_t, uint64_t> var_value_presence;

    std::vector<uint32_t> templates_common_to_all;
    std::vector<std::vector<uint32_t>> templates_unique_to;

    std::vector<uint32_t> var_values_common_to_all;
    std::vector<std::vector<uint32_t>> var_values_unique_to;

    struct Anomaly {
        uint32_t id;
        bool is_template;
        std::vector<uint32_t> counts;
        double mean;
        double max_ratio;
    };
    std::vector<Anomaly> anomalies;
};

//=============================================================================
// Main Template Extraction Function
//=============================================================================

bool extract_templates(const TemplateConfig& config, TemplateResult& result);

} // namespace catalog

#endif // CATALOG_TEMPLATE_H
