// mmap.h - Memory-mapped file I/O and chunking utilities
// Part of catalog - high-performance log file tokenizer

#ifndef CATALOG_MMAP_H
#define CATALOG_MMAP_H

#include <cstddef>
#include <fcntl.h>
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace catalog {

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

    // Non-copyable, moveable
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

#endif // CATALOG_MMAP_H
