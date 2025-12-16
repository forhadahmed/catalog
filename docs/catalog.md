# Catalog: High-Performance Log File Tokenizer & Compressor

## Overview

Catalog is a C++17 tool for tokenizing and compressing large log files (1-3GB+) using dictionary-based encoding. It extracts whitespace-delimited tokens, builds a deduplicated dictionary, and encodes each line as an array of token IDs.

**Performance**:
- 537 MB real log: **1.1s at 489 MB/s** (3.4x compression)
- 3 GB synthetic: **9.2s at 327 MB/s**

**Current Status**: Single-pass parallel encoding with lock-free concurrent hash map

---

## Quick Start

```bash
# Build
make clean && make

# Encode
./catalog encode input.log output.logc

# Decode
./catalog decode output.logc decoded.log

# Benchmark
./catalog bench /tmp/bench_3gb.log
```

---

## Architecture

```
+------------------+     +-------------------+     +------------------+
|   Input File     | --> |   Tokenization    | --> |   Output File    |
|   (mmap read)    |     |   (parallel)      |     |   (mmap write)   |
+------------------+     +-------------------+     +------------------+
                               |
                               v
                    +---------------------+
                    |   Token Dictionary  |
                    |   (lock-free        |
                    |    concurrent)      |
                    +---------------------+
```

### Single-Pass Parallel Encoding

```
Phase 1: Parallel tokenization with shared concurrent hash map
         - File split into N chunks (N = CPU cores)
         - Each chunk aligned to newline boundaries
         - Global IDs assigned immediately via atomic CAS
         - Each thread builds its encoded output buffer

Phase 2: Sequential write (header + dict + concatenated buffers)
         - Output via mmap for zero-copy writes
```

**Key insight**: No merge or remap phase needed - global IDs assigned during parsing.

---

## Key Data Structures

### FastTokenMap (Open-Addressed Hash Map)

```cpp
class FastTokenMap {
    struct Slot {
        uint64_t hash;      // 0 = empty, used for CAS
        uint32_t id;        // Token ID
        const char* ptr;    // Pointer to token in mmap'd input
        uint32_t len;       // Token length
    };

    std::vector<Slot> slots_;  // Power-of-2 sized
    size_t mask_;              // For fast modulo
};
```

**Features**:
- Lock-free concurrent insertions using atomic CAS on hash field
- Linear probing for collision resolution
- Zero-copy: stores pointers into mmap'd input data
- FNV-1a inspired hash function with 8-byte unrolling

### Thread-Safe Insertion

```cpp
uint32_t get_or_insert(const char* ptr, size_t len, std::atomic<uint32_t>& next_id) {
    uint64_t h = hash(ptr, len);
    size_t idx = h & mask_;

    while (true) {
        Slot& s = slots_[idx];

        // Try to claim empty slot with CAS
        if (s.hash == 0) {
            uint64_t expected = 0;
            if (__atomic_compare_exchange_n(&s.hash, &expected, h, ...)) {
                // Won the race - fill in data
                uint32_t id = next_id.fetch_add(1);
                s.ptr = ptr;
                s.len = len;
                __atomic_store_n(&s.id, id, __ATOMIC_RELEASE);
                return id;
            }
        }

        // Check if slot has our key
        if (s.hash == h && memcmp(s.ptr, ptr, len) == 0) {
            return s.id;
        }

        // Linear probe
        idx = (idx + 1) & mask_;
    }
}
```

---

## Binary File Format (.logc)

```
+------------------+
|  CatalogHeader   |  48 bytes
+------------------+
|  Dictionary      |  Variable size
|  [len][token]... |  (uint16_t length + token bytes)
+------------------+
|  Encoded Lines   |  Variable size
|  [count][ids...] |  (uint16_t count + uint32_t[] token IDs)
+------------------+
```

### Header Structure (48 bytes)

```cpp
struct CatalogHeader {
    uint32_t magic;           // 0x474C5443 ('CTLG')
    uint32_t version;         // 1
    uint32_t token_id_bytes;  // 4 (fixed-width uint32_t)
    uint32_t token_count;     // Number of unique tokens
    uint64_t line_count;      // Number of lines
    uint64_t original_size;   // Original file size in bytes
    uint64_t dict_offset;     // Offset to dictionary (= 48)
    uint64_t data_offset;     // Offset to encoded lines
};
```

### Dictionary Section

```
For each token (0 to token_count-1):
  uint16_t length      // Token length (max 65535 bytes)
  char[length] data    // Token bytes (no null terminator)
```

### Lines Section

```
For each line:
  uint16_t count           // Number of tokens in line (max 65535)
  uint32_t[count] ids      // Token IDs
```

---

## Performance Characteristics

### Benchmark Results

| File | Size | Unique Tokens | Time | Throughput | Compression |
|------|------|---------------|------|------------|-------------|
| large_real.log | 537 MB | 90K | **1.1s** | **489 MB/s** | 29% |
| bench_3gb.log | 3 GB | 45M | **9.2s** | **327 MB/s** | 74% |

### Performance Analysis

**Real log files** (high token reuse):
- 90K unique tokens across 7M lines = excellent compression (29%)
- High throughput due to hash map cache hits

**Synthetic benchmark** (low token reuse):
- 45M unique tokens across 37M lines = poor compression (74%)
- Hash map insertions dominate (45M CAS operations)

### Bottleneck Breakdown (3GB file)

| Phase | Time | Notes |
|-------|------|-------|
| Parallel tokenization | ~6s | Hash map insertions dominate |
| get_tokens() scan | ~2s | Scans all hash slots to build ordered list |
| mmap output write | ~1s | Direct memory writes, no syscalls |

---

## Optimizations Implemented

### 1. Memory-Mapped I/O
- Input: `mmap()` with `MAP_POPULATE` + `MADV_SEQUENTIAL`
- Output: `mmap()` with pre-allocated size, `ftruncate()` at end
- Eliminates read/write syscall overhead

### 2. Zero-Copy Token Storage
- Tokens stored as `string_view` pointing into mmap'd input
- No string allocations during parsing
- Dictionary written directly from input memory

### 3. Parallel Chunk Processing
- File divided into N chunks (N = hardware threads)
- Chunks aligned to newline boundaries
- Each thread processes independently

### 4. Lock-Free Concurrent Hash Map
- Raw `calloc()` allocation (faster than vector of atomics)
- `__atomic_compare_exchange_n` for slot claiming
- `_mm_pause()` for spin-wait
- Linear probing, power-of-2 table size
- No mutexes in hot path

### 5. Single-Pass Encoding
- Global IDs assigned during parsing (no remap phase)
- Each thread builds encoded output buffer directly
- Buffers concatenated at write time

---

## Performance Profiling Analysis

Profiled using `perf record -g --call-graph dwarf` with 130MB test file (1.5M unique tokens).

### Function-Level Breakdown

| Function | % Time | Description |
|----------|--------|-------------|
| `TokenMap::get_or_insert` | ~65% | Lock-free hash map insertion |
| `TokenMap::get_tokens` | ~15% | Scans entire hash table to build ordered list |
| `memcpy` | ~10% | Buffer writes and token comparisons |
| `hash()` | ~5% | FNV-1a hash computation |
| mmap I/O | ~5% | File read/write overhead |

### Line-Level Hotspots (Assembly Analysis)

```
get_or_insert() hotspots:
---------------------------------------------------------------------------
32.18%  mov    (%r15),%rax           ; Hash slot load - CACHE MISS DOMINANT
        - Linear probing causes random memory access
        - Each probe likely a cache miss for large tables

17.95%  lock xadd %eax,(%r10)        ; Atomic fetch_add for next_id
        - Global contention point for ID assignment
        - Lock prefix forces cache line invalidation

14.98%  lock cmpxchg %r14,(%r15)     ; Atomic CAS for slot claiming
        - Contention when multiple threads target same slot
        - False sharing possible on adjacent slots
---------------------------------------------------------------------------

get_tokens() hotspots:
---------------------------------------------------------------------------
74.51%  mov    (%rax),%rcx           ; Scanning empty slots
        - Iterates ALL hash table slots (capacity, not count)
        - For 45M tokens in 90M slot table: 45M wasted checks
        - Sequential but still cache-unfriendly for sparse tables
---------------------------------------------------------------------------
```

### Key Insights

1. **Hash table probing dominates (32%)**: Random memory access pattern during linear probing causes cache misses. Larger tables = more misses.

2. **Atomic operations overhead (33%)**: `lock xadd` and `lock cmpxchg` cause cache line bouncing between cores.

3. **get_tokens() is O(capacity) not O(tokens)**: Scans entire 90M slot table to find 45M tokens. 50% of iterations are wasted on empty slots.

---

## Future Optimization Opportunities

### Optimization Status

| Optimization | Expected Speedup | Complexity | Status |
|--------------|------------------|------------|--------|
| Eliminate get_tokens scan | ~2x throughput | Low | **DONE** |
| SIMD tokenization (AVX2) | 2-3x parse phase | Medium | Pending |
| LZ4 post-compression | 3x better compression | Low | Pending |

### SIMD Tokenization Concept

```cpp
// Find whitespace in 32 bytes at once
__m256i chunk = _mm256_loadu_si256(data);
__m256i spaces = _mm256_cmpeq_epi8(chunk, _mm256_set1_epi8(' '));
__m256i newlines = _mm256_cmpeq_epi8(chunk, _mm256_set1_epi8('\n'));
uint32_t mask = _mm256_movemask_epi8(spaces | newlines);
int first_ws = __builtin_ctz(mask);  // First whitespace position
```

### Eliminate get_tokens() Scan (IMPLEMENTED)

**Problem**: `get_tokens()` scanned ALL hash table slots to build ordered token list - O(capacity) instead of O(tokens).

**Solution**: Track tokens during insertion in `ordered_tokens_` vector.

```cpp
// In get_or_insert(), after winning CAS:
ordered_tokens_[new_id] = std::string_view(ptr, len);

// Replace get_tokens() with O(1) access:
const std::string_view* get_ordered_tokens() const {
    return ordered_tokens_.data();
}
```

**Results**:
- Performance: ~46 KB/ms -> ~86 KB/ms on 50MB test (**1.9x faster**)
- No synchronization needed - disjoint access pattern (each ID writes to unique index)

---

## Build System

### Makefile Targets

```makefile
make          # Optimized build (-O3 -march=native -flto)
make debug    # Debug build with sanitizers
make pgo      # Profile-guided optimization (2-phase build)
make bench    # Run benchmarks on test files
make test     # Verify encode/decode correctness
make clean    # Remove build artifacts
```

### Compiler Flags

```
-std=c++17 -O3 -march=native -mtune=native -flto
-ffast-math -funroll-loops -fomit-frame-pointer -finline-functions
-pthread -DNDEBUG
```

---

## Test Files

Located in `/tmp/`:

| File | Size | Lines | Unique Tokens | Description |
|------|------|-------|---------------|-------------|
| large_real.log | 537 MB | 7M | 90K | Real Arista test log |
| bench_3gb.log | 3 GB | 37M | 45M | Synthetic benchmark (pathological) |

---

## Code Structure

```
catalog/
+-- catalog.cc      # Main implementation (single file)
+-- catalog.md      # This document
+-- Makefile        # Build system
```

### Key Classes/Functions

| Name | Purpose |
|------|---------|
| `FastTokenMap` | Lock-free open-addressed hash map |
| `MappedInput` | RAII wrapper for mmap'd input file |
| `MappedOutput` | RAII wrapper for mmap'd output file |
| `Catalog::encode_streaming()` | Single-pass parallel encoding |
| `Catalog::encode_batch()` | Two-phase encoding with merge |
| `Catalog::decode()` | Decode .logc back to text |

---

## Known Limitations

1. **Token length**: Max 65535 bytes (uint16_t length prefix)
2. **Tokens per line**: Max 65535 (uint16_t count)
3. **Total tokens**: Max ~4 billion (uint32_t IDs)
4. **Whitespace handling**: Lossy - multiple spaces/tabs collapsed to single space
5. **Memory usage**: Hash table sized at 2x estimated tokens (can be large for pathological data)

---

## Troubleshooting

### Segfault on large files
- Check hash table capacity estimation
- Increase `est_tokens` multiplier in `encode_streaming()`

### Poor compression ratio
- Indicates low token reuse (many unique tokens)
- Consider LZ4 post-compression for storage

### Slow performance
- Use `--stream` mode for large files
- Check if file has pathological token distribution

---

## Revision History

| Date | Change |
|------|--------|
| 2024-12-16 | Initial implementation with parallel processing |
| 2024-12-16 | Added streaming mode with concurrent hash map |
| 2024-12-16 | Added mmap output, fast hash map |
| 2024-12-16 | Achieved 324 MB/s on 3GB file (4.1x improvement) |
