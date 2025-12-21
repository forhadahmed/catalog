// similarity.h - Generic similarity and clustering algorithms
// Header-only utility module - no template-specific dependencies

#ifndef CATALOG_SIMILARITY_H
#define CATALOG_SIMILARITY_H

#include <cstddef>
#include <cstdint>
#include <unordered_set>
#include <vector>

namespace catalog {

//=============================================================================
// Constants
//=============================================================================

inline constexpr double SIMILARITY_THRESHOLD = 0.80;
inline constexpr size_t MIN_CLUSTER_SIZE = 2;

//=============================================================================
// Jaccard Similarity
//=============================================================================

inline double jaccard_similarity(const std::unordered_set<uint64_t>& a,
                                 const std::unordered_set<uint64_t>& b) {
    if (a.empty() || b.empty()) return 0.0;
    size_t intersection = 0;
    for (uint64_t x : a) {
        if (b.count(x)) intersection++;
    }
    size_t union_size = a.size() + b.size() - intersection;
    return union_size > 0 ? static_cast<double>(intersection) / union_size : 0.0;
}

//=============================================================================
// Union-Find Data Structure
//=============================================================================

class UnionFind {
public:
    explicit UnionFind(size_t n) : parent_(n) {
        for (size_t i = 0; i < n; ++i) parent_[i] = i;
    }

    size_t find(size_t x) {
        if (parent_[x] != x) parent_[x] = find(parent_[x]);
        return parent_[x];
    }

    void unite(size_t x, size_t y) {
        size_t px = find(x), py = find(y);
        if (px != py) parent_[px] = py;
    }

private:
    std::vector<size_t> parent_;
};

} // namespace catalog

#endif // CATALOG_SIMILARITY_H
