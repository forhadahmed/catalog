// common.h - Shared utilities for catalog
// TokenMap, MappedFile, hash functions

#ifndef CATALOG_COMMON_H
#define CATALOG_COMMON_H

#include <atomic>
#include <cstdint>
#include <cstring>
#include <deque>
#include <fcntl.h>
#include <mutex>
#include <string>
#include <string_view>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
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
// TokenMap - Lock-free concurrent token dictionary
//=============================================================================

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
    uint32_t insert_owned(const std::string& str, std::atomic<uint32_t>& next_id) {
        uint64_t h = fnv1a_hash(str.c_str(), str.size());
        if (h == 0) h = 1;
        size_t idx = h & mask_;
        size_t max_probes = capacity_ * 7 / 10;

        // First check if already exists
        for (size_t probe = 0; probe < max_probes; ++probe) {
            Slot& s = slots_[idx];
            uint64_t current = __atomic_load_n(&s.hash, __ATOMIC_RELAXED);

            if (current == 0) break;

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

        // Not found - store owned copy and insert
        std::lock_guard<std::mutex> lock(owned_mutex_);
        owned_strings_.push_back(str);
        const std::string& stored = owned_strings_.back();
        return get_or_insert(stored.c_str(), stored.size(), next_id);
    }

    const std::string_view* get_ordered_tokens() const {
        return ordered_tokens_.data();
    }

    std::string_view get_token(uint32_t id) const {
        return ordered_tokens_[id];
    }

    size_t capacity() const { return capacity_; }

private:
    size_t capacity_;
    size_t mask_;
    Slot* slots_;
    std::vector<std::string_view> ordered_tokens_;
    std::deque<std::string> owned_strings_;  // Stable storage for normalized tokens
    std::mutex owned_mutex_;
};

//=============================================================================
// MappedFile - Memory-mapped file I/O
//=============================================================================

struct MappedFile {
    int fd = -1;
    char* data = nullptr;
    size_t size = 0;
    std::string path;

    bool open_read(const char* p) {
        path = p;
        fd = ::open(p, O_RDONLY);
        if (fd < 0) return false;

        struct stat st;
        if (fstat(fd, &st) < 0) { close(); return false; }
        size = st.st_size;

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

    bool open_write(const char* p, size_t max_size) {
        path = p;
        fd = ::open(p, O_RDWR | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) return false;

        size = max_size;

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

    // Non-copyable
    MappedFile() = default;
    MappedFile(const MappedFile&) = delete;
    MappedFile& operator=(const MappedFile&) = delete;
    MappedFile(MappedFile&& other) noexcept
        : fd(other.fd), data(other.data), size(other.size), path(std::move(other.path)) {
        other.fd = -1;
        other.data = nullptr;
        other.size = 0;
    }
};

//=============================================================================
// Chunk Calculation for Parallel Processing
//=============================================================================

inline std::vector<std::pair<const char*, const char*>>
calculate_chunks(const char* data, size_t size, unsigned num_threads) {
    std::vector<std::pair<const char*, const char*>> chunks(num_threads);

    if (size == 0 || data == nullptr) {
        for (unsigned i = 0; i < num_threads; ++i) {
            chunks[i] = {nullptr, nullptr};
        }
        return chunks;
    }

    for (unsigned i = 0; i < num_threads; ++i) {
        const char* s = data + (size * i) / num_threads;
        const char* e = data + (size * (i + 1)) / num_threads;

        // Align start to line boundary
        if (i > 0 && s > data) {
            while (s < data + size && *(s - 1) != '\n') ++s;
        }
        // Align end to line boundary
        if (i < num_threads - 1 && e > data && e < data + size && *(e - 1) != '\n') {
            while (e < data + size && *e != '\n') ++e;
            if (e < data + size) ++e;
        }
        chunks[i] = {s, e};
    }

    return chunks;
}

} // namespace catalog

#endif // CATALOG_COMMON_H
