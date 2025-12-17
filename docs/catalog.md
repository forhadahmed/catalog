# Catalog: High-Performance Log File Tokenizer & Compressor

## Overview

Catalog is a C++17 tool for tokenizing and compressing large log files (1-3GB+) using dictionary-based encoding. It extracts whitespace-delimited tokens, builds a deduplicated dictionary, and encodes each line as an array of token IDs.

**Performance**:
- 537 MB real log: **0.7s at 770 MB/s** (3.4x compression)
- 3 GB synthetic: **7.3s at 410 MB/s**

**Current Status**: Single-pass parallel encoding with lock-free concurrent hash map, sampling-based memory optimization

---

## Quick Start

```bash
# Build
make clean && make

# Encode
./catalog encode input.log output.logc

# Decode
./catalog decode output.logc decoded.log

# Benchmark (writes output file)
./catalog bench /tmp/bench_3gb.log

# Tokenize only (memory benchmark, no file write)
./catalog tokenize input.log
```

### Command-Line Options

```bash
Usage:
  ./catalog [options] encode <input> <output>
  ./catalog [options] decode <input> <output>
  ./catalog [options] bench <input>
  ./catalog [options] tokenize <input>

Options:
  -t, --threads <num>   Number of threads (default: auto-detect)
  -e, --estimate <num>  Estimated unique tokens (default: auto via sampling)
  -h, --help            Show help message
```

### Examples

```bash
# Encode with 4 threads
./catalog -t 4 encode input.log output.logc

# Benchmark with custom token estimate (for pathological files)
./catalog -e 50000000 bench /tmp/bench_3gb.log

# Memory-only benchmark (no I/O overhead)
./catalog tokenize /tmp/large_real.log
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

### Parallel Encoding Pipeline

```
PHASE 1: PARALLEL TOKENIZATION
==============================

Input File (mmap'd read-only)
+---------------+---------------+---------------+---------------+
| chunk 0       | chunk 1       | chunk 2       |  chunk N-1    |
| (align to \n) | (align to \n) | (align to \n) |  (to EOF)     |
+-------+-------+-------+-------+-------+-------+-------+-------+
        |               |               |               |
        v               v               v               v
  +-----------+   +-----------+   +-----------+   +-----------+
  | Thread 0  |   | Thread 1  |   | Thread 2  |   | Thread N-1|
  | tokenize  |   | tokenize  |   | tokenize  |   | tokenize  |
  +-----+-----+   +-----+-----+   +-----+-----+   +-----+-----+
        |               |               |               |
        |               |               |               |
        +-------+-------+-------+-------+-------+-------+
                |                               |
                v                               v
        +-----------------------------------------------+
        |            Shared TokenMap                    |
        |            (lock-free CAS)                    |
        |                                               |
        |   atomic next_id ---> global ID assignment    |
        |   ordered_tokens[] -> O(1) token lookup       |
        +-----------------------------------------------+
                |                               |
                v                               v
        +-------+-------+-------+-------+-------+-------+
        |               |               |               |
        v               v               v               v
  +-----------+   +-----------+   +-----------+   +-----------+
  | Buffer 0  |   | Buffer 1  |   | Buffer 2  |   | Buffer N-1|
  | [cnt,ids] |   | [cnt,ids] |   | [cnt,ids] |   | [cnt,ids] |
  +-----------+   +-----------+   +-----------+   +-----------+


                          | join()
                          v

PHASE 2: SEQUENTIAL WRITE
=========================

Output File (mmap'd write)
+--------+----------------------+----------+----------+-----+
| Header | Dictionary           | Buffer 0 | Buffer 1 | ... |
| 48B    | [len,tok][len,tok]...| encoded  | encoded  |     |
+--------+----------------------+----------+----------+-----+
```

### Thread Coordination

```
Main Thread                     Worker Threads (0..N-1)
-----------                     ----------------------

1. mmap input file
2. Calculate chunk boundaries
   (align to newlines)
3. Allocate shared TokenMap
4. Spawn N threads -----------> Each thread:
   |                              - Parse tokens in chunk
   |                              - get_or_insert() into shared map
   |                              - Write [count, ids...] to local buffer
   |                              - Increment total_lines
5. join() <-------------------- Threads complete
6. Get ordered tokens (O(1))
7. Calculate output size
8. mmap output file
9. Write header
10. Write dictionary
11. Concatenate buffers
12. finalize (ftruncate)
```

### Chunk Boundary Alignment

Small files (<1MB) use single thread to avoid boundary issues and overhead:

```cpp
if (file_size < 1024 * 1024) num_threads = 1;
```

For multi-threaded processing, chunks are aligned to newline boundaries:

```cpp
// Start: skip to after previous newline
if (i > 0 && s > data) {
    while (s < data + size && *(s - 1) != '\n') ++s;
}

// End: extend to include full line
if (i < num_threads - 1 && e > data && *(e - 1) != '\n') {
    while (e < data + size && *e != '\n') ++e;
    if (e < data + size) ++e;  // Include the newline
}
```

**Key insight**: No merge or remap phase needed - global IDs assigned during parsing via atomic operations.

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
| large_real.log | 537 MB | 90K | **0.7s** | **770 MB/s** | 29% |
| bench_3gb.log | 3 GB | 45M | **7.3s** | **410 MB/s** | 74% |

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
| Ordered token access | O(1) | Pre-built during insertion (no scan) |
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

### 6. Sampling-Based Hash Table Sizing

**Problem**: Previous approach allocated `file_size / 4` slots, wasting memory for real logs (90K tokens needed 134M slots = 5.3 GB).

**Solution**: Sample first 4MB to estimate unique tokens:

```cpp
static size_t estimate_unique_tokens(const char* data, size_t size) {
    constexpr size_t SAMPLE_SIZE = 4 * 1024 * 1024;  // 4MB sample

    // Count unique tokens in sample
    size_t sample_uniques = count_tokens_in_sample(data, sample_bytes);

    // Extrapolate with sqrt scaling (Zipf distribution)
    double ratio = static_cast<double>(size) / sample_bytes;
    size_t sampled_estimate = sample_uniques * std::sqrt(ratio) * 2;

    // Baseline: 1 token per 64 bytes (for pathological linear-growth files)
    size_t baseline = size / 64;

    // Use max of sampled estimate and baseline
    return std::max(sampled_estimate, baseline);
}
```

**Key insights**:
- Real logs follow Zipf distribution - most tokens appear early
- sqrt scaling prevents overestimate for real logs
- `size/64` baseline handles pathological files where every token is unique

**Results**:
- large_real.log: 5.3 GB -> 968 MB memory (**5.5x reduction**)
- Throughput: 445 -> 771 MB/s (**1.7x faster**)

### 7. Probe Limit for High Load Factors

**Problem**: At high load factors (>70%), linear probing can iterate through most of the table, causing CPU to spin.

**Solution**: Limit probe iterations to 70% of capacity:

```cpp
uint32_t get_or_insert(...) {
    size_t max_probes = capacity_ * 7 / 10;  // 70% limit

    for (size_t probe = 0; probe < max_probes; ++probe) {
        // ... probing logic ...
    }

    return UINT32_MAX;  // Signal overflow
}
```

**Overflow handling**: If `UINT32_MAX` is returned, the program reports an error and suggests using `-e` to increase the estimate:

```
Error: token table overflow. Use -e to set higher estimate.
```

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

### Memory Ordering Fix for Hash Map Race Condition

**Problem**: Flaky test failures due to data race when reader sees `ptr != nullptr` but `len` is stale.

**Root cause**: Writer stored `ptr` and `len` without proper memory ordering:
```cpp
// BEFORE (racy):
s.ptr = ptr;           // Plain store
s.len = len;           // Plain store

// Reader:
while (s.ptr == nullptr) _mm_pause();  // Spin wait
if (s.len == len && ...)               // len might be stale!
```

**Solution**: Use `ptr` as synchronization point with acquire-release semantics:
```cpp
// AFTER (correct):
s.len = len;                                    // Store len first
__atomic_store_n(&s.ptr, ptr, __ATOMIC_RELEASE); // Release store

// Reader:
const char* slot_ptr;
while ((slot_ptr = __atomic_load_n(&s.ptr, __ATOMIC_ACQUIRE)) == nullptr) {
    _mm_pause();
}
// Now s.len is guaranteed visible due to happens-before
```

### Thread-Local Maps Experiment (Not Adopted)

Attempted optimization: thread-local hash maps to eliminate atomic contention.

**Approach**:
1. Each thread has its own hash map with local IDs
2. Merge phase combines local maps into global map
3. Remap output buffers with global IDs

**Results on 3GB synthetic file (45M unique tokens)**:
- Old (atomic shared map): 422 MB/s (7.1s)
- New (thread-local + merge): 75 MB/s (39.5s) - **5.6x SLOWER**

**Why it failed**: The merge phase became the bottleneck. With 45M unique tokens, single-threaded merge takes ~35s.

**When thread-local would help**: High token reuse (real logs). For `/tmp/large_real.log` with only 90K unique tokens, merge overhead would be negligible.

**Conclusion**: Keep atomic shared map for pathological worst case. Real logs (high reuse) already achieve 400+ MB/s.

---

## Build System

### Makefile Targets

```bash
make              # Optimized build (-O3 -march=native -flto)
make debug        # Debug build with sanitizers
make test         # Run all tests (unit + integration)
make test-unit    # Run unit tests only
make test-integration  # Run integration tests only
make bench        # Run benchmarks on test files
make pgo          # Profile-guided optimization (2-phase build)
make clean        # Remove build artifacts
make help         # Show all targets with descriptions
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
+-- src/
|   +-- catalog.cc          # Main implementation
+-- test/
|   +-- catalog_test.cc     # Unit tests (29 tests)
|   +-- integration_test.sh # Integration tests (47 tests)
+-- docs/
|   +-- catalog.md          # This document
+-- bin/                    # Build output (gitignored)
+-- Makefile                # Build system
+-- .gitignore
```

### Key Classes/Functions

| Name | Location | Purpose |
|------|----------|---------|
| `TokenMap` | catalog.cc:52 | Lock-free open-addressed hash map with ordered storage |
| `MappedFile` | catalog.cc:153 | RAII wrapper for mmap'd files (read/write) |
| `Catalog::encode()` | catalog.cc:243 | Single-pass parallel encoding |
| `Catalog::tokenize()` | catalog.cc:483 | Memory-only tokenization (no output file) |
| `Catalog::decode()` | catalog.cc:577 | Decode .logc back to text |
| `Catalog::print_stats()` | catalog.cc:633 | Print compression statistics with hash utilization |
| `estimate_unique_tokens()` | catalog.cc:428 | Sampling-based token count estimation |

---

## Known Limitations

1. **Token length**: Max 65535 bytes (uint16_t length prefix)
2. **Tokens per line**: Max 65535 (uint16_t count)
3. **Total tokens**: Max ~4 billion (uint32_t IDs)
4. **Whitespace handling**: Lossy - multiple spaces/tabs collapsed to single space
5. **Memory usage**: Hash table sized at 2x estimated tokens (can be large for pathological data)

---

## Troubleshooting

### Token table overflow error
```
Error: token table overflow. Use -e to set higher estimate.
```
- The sampling-based estimate underestimated unique tokens
- Use `-e` to set a higher estimate: `./catalog -e 50000000 bench file.log`
- For pathological files (every token unique), try `file_size / 8` as estimate

### Poor compression ratio
- Indicates low token reuse (many unique tokens)
- Check `HashCap` in output - high load factor (>50%) suggests many unique tokens
- Consider LZ4 post-compression for storage

### Slow performance
- Check load factor in output: >50% causes slowdown due to collision chains
- Use `-e` to increase hash table size for better performance
- For memory-only benchmarking, use `tokenize` command to skip file I/O

### High memory usage
- Use `-e` to set a smaller estimate if you know approximate token count
- Sampling-based estimation uses 2x safety margin - override with `-e` if needed

---

## Revision History

| Date | Change |
|------|--------|
| 2024-12-16 | Initial implementation with parallel processing |
| 2024-12-16 | Added streaming mode with concurrent hash map |
| 2024-12-16 | Added mmap output, fast hash map |
| 2024-12-16 | Achieved 324 MB/s on 3GB file (4.1x improvement) |
| 2024-12-16 | Added comprehensive test suite (29 unit + 47 integration tests) |
| 2024-12-16 | Eliminated O(capacity) get_tokens scan with ordered_tokens vector (1.9x speedup) |
| 2024-12-16 | Fixed hash map race condition with acquire-release memory ordering |
| 2024-12-16 | Benchmarked thread-local maps approach (not adopted - merge phase bottleneck) |
| 2024-12-16 | Added sampling-based hash table sizing (5.5x memory reduction) |
| 2024-12-16 | Added size/64 baseline for pathological files |
| 2024-12-16 | Added 70% probe limit to prevent CPU hog at high load |
| 2024-12-16 | Added `-t` option for thread count, `-e` for token estimate |
| 2024-12-16 | Added `tokenize` command for memory-only benchmarking |
| 2024-12-16 | Added hash utilization stats (HashCap, load factor) to output |
| 2024-12-16 | Switched to getopt_long for standard POSIX option parsing |
| 2024-12-16 | Added `make help` target |
| 2024-12-16 | Peak performance: 770 MB/s on real log, 410 MB/s on 3GB synthetic |
