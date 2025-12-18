// token.h - Token interning and hash functions
// Part of catalog - high-performance log file tokenizer

#ifndef CATALOG_TOKEN_H
#define CATALOG_TOKEN_H

#include <atomic>
#include <cstdint>
#include <cstring>
#include <deque>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

#ifdef __x86_64__
#include <emmintrin.h>
#else
#define _mm_pause() ((void)0)
#endif

namespace catalog {

//=============================================================================
// FNV-1a Hash Function
//=============================================================================

inline uint64_t fnv1a_hash(const char* data, size_t len) {
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

//=============================================================================
// TokenMap - Lock-free concurrent string interning
//=============================================================================
//
// Maps raw string tokens to unique 32-bit IDs (string interning).
// Example: "ERROR" -> 0, "10.0.0.1" -> 1, "user_id=123" -> 2
//
// Used by both encode/tokenize and template extraction modes.
// Stores pointers to original strings (from mmap'd file data).
//
// Note: Uses same lock-free probing pattern as TemplateMap but differs in:
//   - Hash: fnv1a on raw bytes
//   - Compare: memcmp on string content
//   - Storage: pointer + length to original data

class TokenMap {
public:
    struct Slot {
        uint64_t hash;
        uint32_t id;
        const char* ptr;
        uint32_t len;
    };

    explicit TokenMap(size_t capacity) {
        capacity_ = 1;
        while (capacity_ < capacity) capacity_ *= 2;
        mask_ = capacity_ - 1;
        slots_ = static_cast<Slot*>(calloc(capacity_, sizeof(Slot)));
        ordered_tokens_.resize(capacity_);
    }

    ~TokenMap() { free(slots_); }

    // Non-copyable
    TokenMap(const TokenMap&) = delete;
    TokenMap& operator=(const TokenMap&) = delete;

    // Get or insert token (pointer must remain valid for lifetime)
    uint32_t get_or_insert(const char* ptr, size_t len, std::atomic<uint32_t>& next_id) {
        uint64_t h = fnv1a_hash(ptr, len);
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

    // Insert with owned string storage (for normalized tokens)
    // Single-pass: find slot, check existence, insert if new
    uint32_t insert_owned(const std::string& str, std::atomic<uint32_t>& next_id) {
        uint64_t h = fnv1a_hash(str.c_str(), str.size());
        if (h == 0) h = 1;
        size_t idx = h & mask_;
        size_t max_probes = capacity_ * 7 / 10;
        size_t first_empty_idx = SIZE_MAX;

        // Single pass: find existing or first empty slot
        for (size_t probe = 0; probe < max_probes; ++probe) {
            Slot& s = slots_[idx];
            uint64_t current = __atomic_load_n(&s.hash, __ATOMIC_RELAXED);

            if (current == 0) {
                if (first_empty_idx == SIZE_MAX) first_empty_idx = idx;
                break;  // No more entries to check
            }

            if (current == h) {
                const char* slot_ptr;
                while ((slot_ptr = __atomic_load_n(&s.ptr, __ATOMIC_ACQUIRE)) == nullptr) {
                    _mm_pause();
                }
                if (s.len == str.size() && memcmp(slot_ptr, str.c_str(), str.size()) == 0) {
                    return __atomic_load_n(&s.id, __ATOMIC_ACQUIRE);
                }
            }
            idx = (idx + 1) & mask_;
        }

        // Not found - need to insert with owned storage
        if (first_empty_idx == SIZE_MAX) return UINT32_MAX;  // Table full

        std::lock_guard<std::mutex> lock(owned_mutex_);

        // Double-check after acquiring lock (another thread may have inserted)
        Slot& s = slots_[first_empty_idx];
        uint64_t current = __atomic_load_n(&s.hash, __ATOMIC_RELAXED);
        if (current != 0) {
            // Slot taken, fall back to regular insert
            owned_strings_.push_back(str);
            const std::string& stored = owned_strings_.back();
            return get_or_insert(stored.c_str(), stored.size(), next_id);
        }

        // Store owned copy first
        owned_strings_.push_back(str);
        const std::string& stored = owned_strings_.back();

        // Now insert into slot
        uint64_t expected = 0;
        if (__atomic_compare_exchange_n(&s.hash, &expected, h,
                false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
            uint32_t new_id = next_id.fetch_add(1, std::memory_order_relaxed);
            s.len = static_cast<uint32_t>(stored.size());
            ordered_tokens_[new_id] = std::string_view(stored.c_str(), stored.size());
            __atomic_store_n(&s.id, new_id, __ATOMIC_RELEASE);
            __atomic_store_n(&s.ptr, stored.c_str(), __ATOMIC_RELEASE);
            return new_id;
        }

        // CAS failed, another thread won - use regular path
        return get_or_insert(stored.c_str(), stored.size(), next_id);
    }

    const std::string_view* get_ordered_tokens() const {
        return ordered_tokens_.data();
    }

    std::string_view get_token(uint32_t id) const {
        return ordered_tokens_[id];
    }

    size_t capacity() const { return capacity_; }

    size_t owned_count() const { return owned_strings_.size(); }

    size_t owned_bytes() const {
        size_t total = 0;
        for (const auto& s : owned_strings_) total += s.size();
        return total;
    }

private:
    size_t capacity_;
    size_t mask_;
    Slot* slots_;
    std::vector<std::string_view> ordered_tokens_;
    std::deque<std::string> owned_strings_;  // Stable storage for normalized tokens
    std::mutex owned_mutex_;
};

} // namespace catalog

#endif // CATALOG_TOKEN_H
