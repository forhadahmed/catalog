// catalog.h - Binary format definitions for catalog files
// Part of catalog - high-performance log file tokenizer

#ifndef CATALOG_CATALOG_H
#define CATALOG_CATALOG_H

#include <cstdint>

namespace catalog {

// Binary format header for encoded catalog files
struct CatalogHeader {
    uint32_t magic;
    uint32_t version;
    uint32_t token_id_bytes;
    uint32_t token_count;
    uint64_t line_count;
    uint64_t original_size;
    uint64_t dict_offset;
    uint64_t data_offset;
};

static constexpr uint32_t MAGIC = 0x474C5443;   // "CTLG" in little-endian
static constexpr uint32_t VERSION = 1;

} // namespace catalog

#endif // CATALOG_CATALOG_H
