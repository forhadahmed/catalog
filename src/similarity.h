// similarity.h - Template similarity analysis
// Finds clusters of similar templates to identify deduplication opportunities

#ifndef CATALOG_SIMILARITY_H
#define CATALOG_SIMILARITY_H

#include "template.h"
#include <ostream>

namespace catalog {

// Analyze template similarity and output clusters
void analyze_similarity(
    const TemplateMap& templates,
    const TokenMap& tokens,
    const std::vector<FileStats>& files,
    size_t top_n,
    std::ostream& out
);

} // namespace catalog

#endif // CATALOG_SIMILARITY_H
