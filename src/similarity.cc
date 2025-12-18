// similarity.cc - Template similarity analysis implementation
// Uses Jaccard similarity with signature-based grouping for O(n) performance

#include "similarity.h"

#include <algorithm>
#include <functional>
#include <iomanip>
#include <numeric>
#include <unordered_map>
#include <unordered_set>

namespace catalog {

void analyze_similarity(
    const TemplateMap& templates,
    const TokenMap& tokens,
    const std::vector<FileStats>& files,
    size_t top_n,
    std::ostream& out
) {
    constexpr double SIMILARITY_THRESHOLD = 0.80;
    constexpr size_t MIN_CLUSTER_SIZE = 2;

    // Collect all templates with their counts
    struct TemplateInfo {
        uint32_t id;
        uint32_t count;
        std::vector<uint32_t> signature;  // First 3 literal token IDs
        std::unordered_set<uint64_t> token_set;  // Normalized tokens for Jaccard
    };

    std::vector<TemplateInfo> infos;

    // Gather template info from all files
    std::unordered_map<uint32_t, uint32_t> total_counts;
    for (const auto& f : files) {
        for (const auto& [id, count] : f.template_counts) {
            total_counts[id] += count;
        }
    }

    for (const auto& [id, count] : total_counts) {
        const auto* entry = templates.get(id);
        if (!entry) continue;

        TemplateInfo info;
        info.id = id;
        info.count = count;

        // Build signature (first 3 literal tokens) and token set
        for (const auto& slot : entry->slots) {
            uint64_t key;
            if (slot.type == VarType::LITERAL) {
                key = static_cast<uint64_t>(slot.token_id) << 8;
                if (info.signature.size() < 3) {
                    info.signature.push_back(slot.token_id);
                }
            } else {
                // Normalize all variable types to single marker
                key = 0xFFFFFFFF00000000ULL | static_cast<uint8_t>(slot.type);
            }
            info.token_set.insert(key);
        }

        infos.push_back(std::move(info));
    }

    if (infos.empty()) {
        out << "No templates to analyze\n";
        return;
    }

    out << "\n=== Similarity Analysis (" << infos.size() << " templates) ===\n";

    // Group by signature for faster comparison
    std::unordered_map<uint64_t, std::vector<size_t>> groups;
    for (size_t i = 0; i < infos.size(); ++i) {
        uint64_t sig_hash = 0;
        for (size_t j = 0; j < infos[i].signature.size(); ++j) {
            sig_hash ^= static_cast<uint64_t>(infos[i].signature[j]) << (j * 20);
        }
        groups[sig_hash].push_back(i);
    }

    // Union-Find
    std::vector<size_t> parent(infos.size());
    std::iota(parent.begin(), parent.end(), 0);

    std::function<size_t(size_t)> find = [&](size_t x) -> size_t {
        if (parent[x] != x) parent[x] = find(parent[x]);
        return parent[x];
    };

    auto unite = [&](size_t x, size_t y) {
        size_t px = find(x), py = find(y);
        if (px != py) parent[px] = py;
    };

    // Jaccard similarity
    auto jaccard = [](const std::unordered_set<uint64_t>& a,
                      const std::unordered_set<uint64_t>& b) -> double {
        if (a.empty() || b.empty()) return 0.0;
        size_t intersection = 0;
        for (uint64_t x : a) {
            if (b.count(x)) intersection++;
        }
        size_t union_size = a.size() + b.size() - intersection;
        return union_size > 0 ? static_cast<double>(intersection) / union_size : 0.0;
    };

    // Find similar pairs within groups
    for (const auto& [sig, members] : groups) {
        for (size_t i = 0; i < members.size(); ++i) {
            for (size_t j = i + 1; j < members.size(); ++j) {
                if (jaccard(infos[members[i]].token_set, infos[members[j]].token_set) >= SIMILARITY_THRESHOLD) {
                    unite(members[i], members[j]);
                }
            }
        }
    }

    // Collect clusters
    std::unordered_map<size_t, std::vector<size_t>> clusters;
    for (size_t i = 0; i < infos.size(); ++i) {
        clusters[find(i)].push_back(i);
    }

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

            out << "  [" << infos[idx].count << "x] ";

            // Format template
            bool first = true;
            for (const auto& slot : entry->slots) {
                if (slot.type == VarType::LITERAL) {
                    std::string_view tok = tokens.get_token(slot.token_id);
                    if (tok.size() == 1 && tok[0] == '"') continue;
                    if (!first) out << ' ';
                    out << tok;
                } else {
                    if (!first) out << ' ';
                    out << var_type_placeholder(slot.type);
                }
                first = false;
            }
            out << "\n";
        }
        out << "\n";
    }
}

} // namespace catalog
