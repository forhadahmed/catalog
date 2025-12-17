// template.h - Template extraction and variable deduplication
// Part of catalog - high-performance log file tokenizer

#ifndef CATALOG_TEMPLATE_H
#define CATALOG_TEMPLATE_H

#include "common.h"

#include <unordered_map>

namespace catalog {

//=============================================================================
// Variable Type Classification
//=============================================================================

enum class VarType : uint8_t {
    LITERAL,    // Fixed token (not a variable)
    VAR_NUM,    // Numeric: 123, 45.67, -89
    VAR_HEX,    // Hex: 0x1a2b, deadbeef
    VAR_IP,     // IP address: 10.0.0.1
    VAR_TIME,   // Timestamp patterns
    VAR_PATH,   // File paths: /foo/bar
    VAR_ID,     // UUIDs, hashes, long identifiers
    VAR_PREFIX, // CIDR prefix: 10.0.0.0/24
    VAR_ARRAY,  // Bracketed array: [0, 1, 2]
    VAR_BOOL,   // Boolean: true, false, yes, no, positive, negative
    VAR_PTR,    // Pointer/null: NULL, None, nil, nullptr
};

// Fast inline classifiers
inline bool is_digit(char c) { return c >= '0' && c <= '9'; }
inline bool is_xdigit(char c) {
    return is_digit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}
inline bool is_alpha(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

// Check if all characters are hex digits
inline bool is_all_xdigit(const char* s, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        if (!is_xdigit(s[i])) return false;
    }
    return true;
}

//=============================================================================
// Unified match_* functions (return match length, 0 = no match)
// These are the single source of truth for pattern matching
//=============================================================================

// Match a number at position, return length or 0
inline size_t match_number(const char* s, size_t len) {
    if (len == 0) return 0;
    size_t i = 0;
    if (s[0] == '-' || s[0] == '+') i++;
    if (i >= len) return 0;
    bool has_digit = false;
    bool has_dot = false;
    for (; i < len; ++i) {
        if (is_digit(s[i])) has_digit = true;
        else if (s[i] == '.' && !has_dot) has_dot = true;
        else break;
    }
    return has_digit ? i : 0;
}

// Match hex (0x... or 8+ hex chars) at position, return length or 0
inline size_t match_hex(const char* s, size_t len) {
    if (len < 3) return 0;
    // 0x prefix
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        size_t i = 2;
        while (i < len && is_xdigit(s[i])) i++;
        return (i > 2) ? i : 0;
    }
    return 0;  // Pure hex check requires whole token context
}

// Match IPv4 address at position, return length or 0
// Also sets has_cidr if CIDR suffix found (e.g., /24)
inline size_t match_ipv4(const char* s, size_t len, bool* has_cidr = nullptr) {
    if (has_cidr) *has_cidr = false;
    if (len < 7) return 0;  // "0.0.0.0" minimum
    size_t i = 0;
    int octets = 0;
    int octet_digits = 0;

    while (i < len && octets < 4) {
        if (is_digit(s[i])) {
            octet_digits++;
            if (octet_digits > 3) return 0;
            i++;
        } else if (s[i] == '.' && octet_digits > 0 && octets < 3) {
            octets++;
            octet_digits = 0;
            i++;
        } else {
            break;
        }
    }

    if (octets == 3 && octet_digits > 0) {
        // Check for optional CIDR suffix (e.g., /24)
        if (i < len && s[i] == '/') {
            size_t cidr_start = i + 1;
            size_t j = cidr_start;
            while (j < len && is_digit(s[j]) && (j - cidr_start) <= 2) j++;
            if (j > cidr_start) {
                if (has_cidr) *has_cidr = true;
                return j;  // Include CIDR
            }
        }
        // Check for optional port suffix
        if (i < len && s[i] == ':') {
            size_t port_start = i + 1;
            size_t j = port_start;
            while (j < len && is_digit(s[j]) && (j - port_start) < 5) j++;
            if (j > port_start) {
                return j;  // Include port
            }
        }
        return i;  // Valid IPv4 without port or CIDR
    }
    return 0;
}

// Match IPv6 address at position, return length or 0
// Also sets has_cidr if CIDR suffix found (e.g., /64)
inline size_t match_ipv6(const char* s, size_t len, bool* has_cidr = nullptr) {
    if (has_cidr) *has_cidr = false;
    if (len < 2) return 0;  // Minimum: "::"

    // Early exit: IPv6 must start with hex digit or colon
    char c0 = s[0];
    if (!is_xdigit(c0) && c0 != ':') return 0;

    size_t i = 0;
    int colons = 0;
    int groups = 0;
    int group_chars = 0;
    bool has_double_colon = false;
    bool after_double_colon = false;

    while (i < len) {
        char c = s[i];
        if (is_xdigit(c)) {
            group_chars++;
            if (group_chars > 4) return 0;
            i++;
            after_double_colon = false;
        } else if (c == ':') {
            if (i + 1 < len && s[i + 1] == ':') {
                if (has_double_colon) return 0;  // Only one :: allowed
                has_double_colon = true;
                after_double_colon = true;
                colons += 2;
                i += 2;
                if (group_chars > 0) groups++;
                group_chars = 0;
            } else {
                // Single colon - must have hex before it (or before ::)
                if (group_chars == 0) {
                    if (!has_double_colon || after_double_colon) return 0;
                }
                colons++;
                if (group_chars > 0) groups++;
                group_chars = 0;
                i++;
                after_double_colon = false;
            }
        } else if (c == '/' || c == '%') {
            break;
        } else {
            break;
        }
    }

    if (group_chars > 0) groups++;

    // Validate IPv6 structure
    bool valid = false;
    if (has_double_colon) {
        if (colons <= 7 && groups <= 7) {
            valid = true;
        }
    } else if (colons == 7 && groups == 8) {
        valid = true;
    }

    if (!valid) return 0;

    // Check for optional CIDR suffix
    if (i < len && s[i] == '/') {
        size_t cidr_start = i + 1;
        size_t j = cidr_start;
        while (j < len && is_digit(s[j]) && (j - cidr_start) <= 3) j++;
        if (j > cidr_start) {
            if (has_cidr) *has_cidr = true;
            return j;
        }
    }

    return i;
}

// Match timestamp at position, return length or 0
inline size_t match_timestamp(const char* s, size_t len) {
    if (len < 8) return 0;
    size_t i = 0;
    int digits = 0, separators = 0;
    while (i < len) {
        char c = s[i];
        if (is_digit(c)) { digits++; i++; }
        else if (c == '-' || c == ':' || c == 'T' || c == 'Z' || c == '.') { separators++; i++; }
        else break;
    }
    return (digits >= 6 && separators >= 2) ? i : 0;
}

// Match file path at position, return length or 0
inline size_t match_path(const char* s, size_t len) {
    if (len < 2) return 0;
    bool is_path_start = false;
    if (s[0] == '/') is_path_start = true;
    else if (s[0] == '.' && s[1] == '/') is_path_start = true;
    else {
        for (size_t i = 0; i + 1 < len; ++i) {
            if (s[i] == ':' && s[i+1] == '/') { is_path_start = true; break; }
        }
    }
    if (!is_path_start) return 0;
    return len;
}

// Match UUID at position, return length or 0
inline size_t match_uuid(const char* s, size_t len) {
    if (len < 36) return 0;
    if (s[8] == '-' && s[13] == '-' && s[18] == '-' && s[23] == '-') {
        for (size_t i = 0; i < 36; ++i) {
            if (i == 8 || i == 13 || i == 18 || i == 23) continue;
            if (!is_xdigit(s[i])) return 0;
        }
        return 36;
    }
    return 0;
}

// Match array [...] at position, return length or 0
inline size_t match_array(const char* s, size_t len) {
    if (len < 2 || s[0] != '[') return 0;
    size_t i = 1;
    int depth = 1;
    while (i < len && depth > 0) {
        if (s[i] == '[') depth++;
        else if (s[i] == ']') depth--;
        i++;
    }
    return (depth == 0) ? i : 0;
}

//=============================================================================
// Boolean is_* wrappers (check if WHOLE token matches)
//=============================================================================

inline bool is_number(const char* s, size_t len) {
    return len > 0 && match_number(s, len) == len;
}

inline bool is_hex(const char* s, size_t len) {
    if (len == 0) return false;
    if (len >= 3 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        return match_hex(s, len) == len;
    }
    // Pure hex string 8+ chars
    return len >= 8 && is_all_xdigit(s, len);
}

inline bool is_ipv4(const char* s, size_t len) {
    return len > 0 && match_ipv4(s, len) == len;
}

inline bool is_ipv6(const char* s, size_t len) {
    size_t matched = match_ipv6(s, len);
    if (matched == 0) return false;
    if (matched == len) return true;
    // Allow trailing zone ID (%eth0)
    if (matched < len && s[matched] == '%') {
        size_t i = matched + 1;
        while (i < len && s[i] != ' ' && s[i] != '\t') i++;
        return i == len;
    }
    return false;
}

inline bool is_ip(const char* s, size_t len) {
    return is_ipv4(s, len) || is_ipv6(s, len);
}

inline bool is_timestamp(const char* s, size_t len) {
    return len > 0 && match_timestamp(s, len) == len;
}

inline bool is_path(const char* s, size_t len) {
    return len > 0 && match_path(s, len) == len;
}

inline bool is_uuid_or_hash(const char* s, size_t len) {
    if (len == 0) return false;
    if (match_uuid(s, len) == len) return true;
    return len >= 32 && is_all_xdigit(s, len);
}

inline bool is_bool(const char* s, size_t len) {
    // Optimized: switch on length, then first char for fewer comparisons
    switch (len) {
    case 2:
        return (s[0] == 'n' || s[0] == 'N') && (s[1] == 'o' || s[1] == 'O');
    case 3:
        if (s[0] == 'y' || s[0] == 'Y') {
            return (s[1] == 'e' || s[1] == 'E') && (s[2] == 's' || s[2] == 'S');
        }
        return false;
    case 4:
        if (s[0] == 't' || s[0] == 'T') {
            return memcmp(s + 1, "rue", 3) == 0 || memcmp(s + 1, "RUE", 3) == 0;
        }
        return false;
    case 5:
        if (s[0] == 'f' || s[0] == 'F') {
            return memcmp(s + 1, "alse", 4) == 0 || memcmp(s + 1, "ALSE", 4) == 0;
        }
        return false;
    case 8:
        if (s[0] == 'p' || s[0] == 'P') {
            return memcmp(s, "positive", 8) == 0 || memcmp(s, "Positive", 8) == 0;
        }
        if (s[0] == 'n' || s[0] == 'N') {
            return memcmp(s, "negative", 8) == 0 || memcmp(s, "Negative", 8) == 0;
        }
        return false;
    default:
        return false;
    }
}

inline bool is_ptr(const char* s, size_t len) {
    // Optimized: switch on length, then first char
    switch (len) {
    case 3:
        if (s[0] == 'n' || s[0] == 'N') {
            return (s[1] == 'i' || s[1] == 'I') && (s[2] == 'l' || s[2] == 'L');
        }
        return false;
    case 4:
        if (s[0] == 'N') {
            return memcmp(s + 1, "ULL", 3) == 0 || memcmp(s + 1, "one", 3) == 0;
        }
        if (s[0] == 'n') {
            return memcmp(s + 1, "ull", 3) == 0 || memcmp(s + 1, "one", 3) == 0;
        }
        return false;
    case 7:
        return s[0] == 'n' && memcmp(s + 1, "ullptr", 6) == 0;
    default:
        return false;
    }
}

// Main classifier - order matters (more specific first)
// Optimized with early-exit checks to avoid expensive pattern matching
inline VarType classify_token(const char* s, size_t len) {
    if (len == 0) return VarType::LITERAL;

    char c0 = s[0];

    // Fast path: tokens starting with non-hex letter are usually literals
    if (is_alpha(c0) && !is_xdigit(c0)) {
        // Non-hex letter (g-z, G-Z): check keywords only
        if (is_bool(s, len)) return VarType::VAR_BOOL;
        if (is_ptr(s, len)) return VarType::VAR_PTR;
        if (is_path(s, len)) return VarType::VAR_PATH;
        return VarType::LITERAL;
    }

    // Starts with hex letter (a-f, A-F): could be IPv6, bool, ptr, or hex hash
    if (is_alpha(c0)) {
        // Check keywords first (false, False start with 'f'; None starts with 'N', etc)
        if (is_bool(s, len)) return VarType::VAR_BOOL;
        if (is_ptr(s, len)) return VarType::VAR_PTR;
        // Could be IPv6 like "fe80::1" - check if contains colon
        bool has_cidr = false;
        size_t ipv6_len = match_ipv6(s, len, &has_cidr);
        if (ipv6_len == len || (ipv6_len > 0 && ipv6_len < len && s[ipv6_len] == '%')) {
            if (ipv6_len < len && s[ipv6_len] == '%') {
                size_t i = ipv6_len + 1;
                while (i < len && s[i] != ' ' && s[i] != '\t') i++;
                if (i == len) return has_cidr ? VarType::VAR_PREFIX : VarType::VAR_IP;
            } else {
                return has_cidr ? VarType::VAR_PREFIX : VarType::VAR_IP;
            }
        }
        // Could be hex hash (32+ chars) or hex string (8+ chars)
        if (len >= 32 && is_all_xdigit(s, len)) return VarType::VAR_ID;
        if (len >= 8 && is_all_xdigit(s, len)) return VarType::VAR_HEX;
        return VarType::LITERAL;
    }

    // Starts with digit: could be number, IP (v4 or v6), timestamp, or hex
    if (is_digit(c0)) {
        // UUID check first (specific pattern with dashes)
        if (is_uuid_or_hash(s, len)) return VarType::VAR_ID;

        // Check for CIDR prefix before plain IP
        bool has_cidr = false;
        size_t ipv4_len = match_ipv4(s, len, &has_cidr);
        if (ipv4_len == len) {
            return has_cidr ? VarType::VAR_PREFIX : VarType::VAR_IP;
        }

        // IPv6 can also start with digit (e.g., "2001:db8::1")
        size_t ipv6_len = match_ipv6(s, len, &has_cidr);
        if (ipv6_len == len || (ipv6_len > 0 && ipv6_len < len && s[ipv6_len] == '%')) {
            if (ipv6_len < len && s[ipv6_len] == '%') {
                size_t i = ipv6_len + 1;
                while (i < len && s[i] != ' ' && s[i] != '\t') i++;
                if (i == len) return has_cidr ? VarType::VAR_PREFIX : VarType::VAR_IP;
            } else {
                return has_cidr ? VarType::VAR_PREFIX : VarType::VAR_IP;
            }
        }

        // 0x prefix means hex
        if (len >= 3 && c0 == '0' && (s[1] == 'x' || s[1] == 'X')) {
            if (is_hex(s, len)) return VarType::VAR_HEX;
        }

        // Long hex string without 0x prefix (8+ chars, checked before number)
        if (len >= 8 && is_all_xdigit(s, len)) return VarType::VAR_HEX;

        // Timestamp (contains - or : separators with digits)
        if (is_timestamp(s, len)) return VarType::VAR_TIME;

        // Plain number
        if (is_number(s, len)) return VarType::VAR_NUM;

        return VarType::LITERAL;
    }

    // Starts with +/- : likely signed number
    if (c0 == '+' || c0 == '-') {
        if (is_number(s, len)) return VarType::VAR_NUM;
        return VarType::LITERAL;
    }

    // Starts with / or . : likely path
    if (c0 == '/' || c0 == '.') {
        if (is_path(s, len)) return VarType::VAR_PATH;
        return VarType::LITERAL;
    }

    // Starts with colon: could be IPv6 (::1)
    if (c0 == ':') {
        bool has_cidr = false;
        size_t ipv6_len = match_ipv6(s, len, &has_cidr);
        if (ipv6_len == len) {
            return has_cidr ? VarType::VAR_PREFIX : VarType::VAR_IP;
        }
        return VarType::LITERAL;
    }

    // Other characters: literal
    return VarType::LITERAL;
}

inline const char* var_type_name(VarType t) {
    switch (t) {
        case VarType::LITERAL: return "LIT";
        case VarType::VAR_NUM: return "NUM";
        case VarType::VAR_HEX: return "HEX";
        case VarType::VAR_IP: return "IP";
        case VarType::VAR_TIME: return "TIME";
        case VarType::VAR_PATH: return "PATH";
        case VarType::VAR_ID: return "ID";
        case VarType::VAR_PREFIX: return "PREFIX";
        case VarType::VAR_ARRAY: return "ARRAY";
        case VarType::VAR_BOOL: return "BOOL";
        case VarType::VAR_PTR: return "PTR";
    }
    return "?";
}

inline const char* var_type_placeholder(VarType t) {
    switch (t) {
        case VarType::LITERAL: return "";
        case VarType::VAR_NUM: return "<NUM>";
        case VarType::VAR_HEX: return "<HEX>";
        case VarType::VAR_IP: return "<IP>";
        case VarType::VAR_TIME: return "<TIME>";
        case VarType::VAR_PATH: return "<PATH>";
        case VarType::VAR_ID: return "<ID>";
        case VarType::VAR_PREFIX: return "<PREFIX>";
        case VarType::VAR_ARRAY: return "<ARRAY>";
        case VarType::VAR_BOOL: return "<BOOL>";
        case VarType::VAR_PTR: return "<PTR>";
    }
    return "<UNK>";
}

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
// TemplateMap - Lock-free concurrent template dictionary
//=============================================================================

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
    size_t top_n = 20;
    size_t min_freq = 1;

    enum class Format { TEXT, JSON } format = Format::TEXT;

    bool show_timeline = false;
    size_t context_lines = 3;

    std::string output_path;
    bool quiet = false;
    bool verbose = false;
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
