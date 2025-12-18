// variable.h - Variable type classification and pattern matching
// Header-only module for log token variable detection
// Part of catalog - high-performance log file tokenizer

#ifndef CATALOG_VARIABLE_H
#define CATALOG_VARIABLE_H

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace catalog {

//=============================================================================
// Variable Type Enum
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

//=============================================================================
// Character Classification Helpers
//=============================================================================

inline bool is_digit(char c) { return c >= '0' && c <= '9'; }
inline bool is_alpha(char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }
inline bool is_xdigit(char c) {
    return is_digit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

inline bool is_all_xdigit(const char* s, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        if (!is_xdigit(s[i])) return false;
    }
    return true;
}

// Case-insensitive string comparison (target must be lowercase)
inline bool iequals(const char* s, const char* target, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        char c = s[i];
        if (c >= 'A' && c <= 'Z') c += 32;  // to lowercase
        if (c != target[i]) return false;
    }
    return true;
}

//=============================================================================
// Pattern Matching Functions (return match length, 0 = no match)
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
// For sub-token extraction, matches any balanced brackets
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

// Check if remaining chars after IPv6 are a valid zone ID (%eth0, %1, etc)
// Returns true if zone ID consumes rest of token
inline bool match_zone_id(const char* s, size_t len, size_t ipv6_end) {
    if (ipv6_end >= len || s[ipv6_end] != '%') return false;
    size_t i = ipv6_end + 1;
    while (i < len && s[i] != ' ' && s[i] != '\t') i++;
    return i == len;
}

// Check if bracketed content looks like an array (for whole-token classification)
// Arrays: [], [1,2,3], [a,b,c], [[1]], [0] - contain commas, digits, or nested brackets
// Not arrays: [INFO], [array], [single] - single words, log level tags
inline bool is_array_content(const char* s, size_t len) {
    if (len < 2 || s[0] != '[' || s[len-1] != ']') return false;
    if (len == 2) return true;  // [] is empty array
    // Check for comma, digit, or nested bracket (array indicators)
    for (size_t i = 1; i < len - 1; ++i) {
        char c = s[i];
        if (c == ',' || is_digit(c) || c == '[') return true;
    }
    return false;
}

//=============================================================================
// Boolean is_* Wrappers (check if WHOLE token matches)
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
    return match_zone_id(s, len, matched);
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
    // Fully case-insensitive: handles true, TRUE, True, tRuE, etc.
    switch (len) {
    case 2:  return iequals(s, "no", 2);
    case 3:  return iequals(s, "yes", 3);
    case 4:  return iequals(s, "true", 4);
    case 5:  return iequals(s, "false", 5);
    case 8:  return iequals(s, "positive", 8) || iequals(s, "negative", 8);
    default: return false;
    }
}

inline bool is_ptr(const char* s, size_t len) {
    // Fully case-insensitive: handles NULL, Null, null, nULL, etc.
    switch (len) {
    case 3:  return iequals(s, "nil", 3);
    case 4:  return iequals(s, "null", 4) || iequals(s, "none", 4);
    case 7:  return iequals(s, "nullptr", 7);
    default: return false;
    }
}

//=============================================================================
// Main Token Classifier
//=============================================================================

// Classify a token into its variable type
// Order matters: more specific patterns checked first
// Optimized with early-exit checks to avoid expensive pattern matching
inline VarType classify_token(const char* s, size_t len) {
    if (len == 0) return VarType::LITERAL;

    char c0 = s[0];

    // Fast path: tokens starting with non-hex letter are usually literals
    if (is_alpha(c0) && !is_xdigit(c0)) {
        // Non-hex letter (g-z, G-Z): check keywords only
        // Note: paths start with / or ., not alpha, so no is_path check needed
        if (is_bool(s, len)) return VarType::VAR_BOOL;
        if (is_ptr(s, len)) return VarType::VAR_PTR;
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
        if (ipv6_len == len || (ipv6_len > 0 && match_zone_id(s, len, ipv6_len))) {
            return has_cidr ? VarType::VAR_PREFIX : VarType::VAR_IP;
        }
        // Pure hex: single is_all_xdigit check for both ID (32+) and HEX (8+)
        if (len >= 8 && is_all_xdigit(s, len)) {
            return (len >= 32) ? VarType::VAR_ID : VarType::VAR_HEX;
        }
        return VarType::LITERAL;
    }

    // Starts with digit: could be number, IP (v4 or v6), timestamp, or hex
    if (is_digit(c0)) {
        // UUID check first (36 chars with dashes at specific positions)
        if (match_uuid(s, len) == len) return VarType::VAR_ID;

        // Check for CIDR prefix before plain IP
        bool has_cidr = false;
        size_t ipv4_len = match_ipv4(s, len, &has_cidr);
        if (ipv4_len == len) {
            return has_cidr ? VarType::VAR_PREFIX : VarType::VAR_IP;
        }

        // IPv6 can also start with digit (e.g., "2001:db8::1")
        size_t ipv6_len = match_ipv6(s, len, &has_cidr);
        if (ipv6_len == len || (ipv6_len > 0 && match_zone_id(s, len, ipv6_len))) {
            return has_cidr ? VarType::VAR_PREFIX : VarType::VAR_IP;
        }

        // 0x hex
        if (len >= 3 && c0 == '0' && (s[1] == 'x' || s[1] == 'X')) {
            if (match_hex(s, len) == len) return VarType::VAR_HEX;
        }

        // Pure hex: single is_all_xdigit check for both ID (32+) and HEX (8+)
        if (len >= 8 && is_all_xdigit(s, len)) {
            return (len >= 32) ? VarType::VAR_ID : VarType::VAR_HEX;
        }

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

    // Starts with '[': array (only if looks like array content, not [INFO] tags)
    if (c0 == '[') {
        if (match_array(s, len) == len && is_array_content(s, len)) {
            return VarType::VAR_ARRAY;
        }
        return VarType::LITERAL;
    }

    // Other characters: literal
    return VarType::LITERAL;
}

//=============================================================================
// Variable Type Name and Placeholder Strings
//=============================================================================

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

} // namespace catalog

#endif // CATALOG_VARIABLE_H
