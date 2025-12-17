# Catalog: High-Performance Log File Tokenizer & Template Extractor

## Overview

Catalog is a C++17 tool for tokenizing, compressing, and analyzing large log files (1-3GB+). It provides two main modes:

1. **Template Extraction** (default): Extracts structural patterns from logs, identifying variables (IPs, timestamps, UUIDs, etc.) and grouping lines by template. Supports multi-file diff to find unique patterns across log files.

2. **Encode/Decode**: Dictionary-based compression using token deduplication.

**Performance**:
- 537 MB real log: **0.7s at 770 MB/s** (3.4x compression)
- 3 GB synthetic: **7.3s at 410 MB/s**

**Current Status**: Template extraction with variable classification, multi-file diff, lock-free concurrent processing

---

## Quick Start

```bash
# Build
make clean && make

# Template extraction (default mode)
./catalog template input.log

# Multi-file diff (find unique patterns)
./catalog template file1.log file2.log file3.log

# Encode (dictionary compression)
./catalog encode input.log output.logc

# Decode
./catalog decode output.logc decoded.log

# Tokenize only (memory benchmark)
./catalog tokenize input.log
```

### Command-Line Options

```bash
Usage:
  ./catalog [options] template <input> [input2...]   # Template extraction (default)
  ./catalog [options] encode <input> <output>        # Dictionary compression
  ./catalog [options] decode <input> <output>        # Decompress
  ./catalog [options] tokenize <input>               # Memory-only tokenization

Template options:
  -n, --top <num>       Show top N templates/values (default: 20)
  -x, --exclude <pat>   Exclude lines containing pattern (repeatable)
  -q, --quiet           Minimal output

General options:
  -t, --threads <num>   Number of threads (default: auto-detect)
  -e, --estimate <num>  Estimated unique tokens (default: auto via sampling)
  -h, --help            Show help message
```

### Examples

```bash
# Extract templates from a single log file
./catalog template /var/log/syslog

# Compare two log files, find unique patterns in each
./catalog template good.log bad.log

# Exclude noisy patterns (repeatable)
./catalog -x "health check" -x "keepalive" template app.log

# Show top 50 templates
./catalog -n 50 template input.log

# Encode with 4 threads
./catalog -t 4 encode input.log output.logc

# Benchmark with custom token estimate (for pathological files)
./catalog -e 50000000 tokenize /tmp/bench_3gb.log
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

## Template Extraction

Template extraction identifies structural patterns in log files by classifying tokens as either **literals** (fixed text) or **variables** (dynamic values like IPs, timestamps, numbers).

### How It Works

```
Input Line:  "2024-12-16 10:30:45 INFO Connection from 10.0.0.1:8080 established"
                    |           |           |              |
                    v           v           v              v
Tokens:     [  <TIME>    <TIME>   LITERAL  LITERAL   <IP>    LITERAL  ]
                    |           |           |              |
Template:   "<TIME> <TIME> INFO Connection from <IP> established"
```

Each line is parsed into tokens, classified by type, and grouped by template. Lines with the same template structure are counted together.

### Variable Types (VarType)

| Type | Placeholder | Examples | Description |
|------|-------------|----------|-------------|
| LITERAL | (none) | INFO, ERROR, Connection | Fixed text tokens |
| VAR_NUM | `<NUM>` | 123, -45.67, 0 | Integers and decimals |
| VAR_HEX | `<HEX>` | 0x1a2b, deadbeef | Hex with 0x prefix or 8+ hex chars |
| VAR_IP | `<IP>` | 10.0.0.1, 192.168.1.1:8080, ::1 | IPv4/IPv6 addresses with optional port |
| VAR_TIME | `<TIME>` | 2024-12-16, 10:30:45 | Date/time patterns |
| VAR_PATH | `<PATH>` | /var/log/app.log, ./config | File paths and URLs |
| VAR_ID | `<ID>` | 550e8400-e29b-41d4-... | UUIDs and 32+ char hex hashes |
| VAR_PREFIX | `<PREFIX>` | 10.0.0.0/24, fe80::/10 | CIDR network prefixes |
| VAR_ARRAY | `<ARRAY>` | [0, 1, 2], [[a]] | Bracketed arrays |
| VAR_BOOL | `<BOOL>` | true, false, yes, no | Boolean values (case-insensitive) |
| VAR_PTR | `<PTR>` | NULL, None, nil, nullptr | Null/pointer values (case-insensitive) |

### Sub-Token Pattern Extraction

Tokens containing embedded patterns are normalized. For example:

```
"port:8080"     -> "port:<NUM>"      (K:V pattern)
"host=10.0.0.1" -> "host=<IP>"       (embedded IP)
"data[0,1,2]"   -> "data<ARRAY>"     (embedded array)
```

### Multi-File Diff

When multiple files are provided, catalog identifies:
- **Templates common to all files** - shared structural patterns
- **Templates unique to each file** - patterns only in that file
- **Variable values unique to each file** - specific IPs, timestamps, etc.

This is useful for comparing "good" vs "bad" logs to find anomalies.

### Example Output

```
=== Multi-Log Diff ===
Files: 2
  good.log (50.3 MB, 500000 lines)
  bad.log (48.7 MB, 485000 lines)

Tokens: 125432 | Templates: 892

=== TEMPLATES COMMON TO ALL (845) ===
  "<TIME> <TIME> INFO Request completed in <NUM> ms"
  "<TIME> <TIME> DEBUG Connection established to <IP>"
  ... and 843 more

=== TEMPLATES UNIQUE TO bad.log (47) ===
  "<TIME> <TIME> ERROR Timeout connecting to <IP>"
  "<TIME> <TIME> FATAL OutOfMemoryError in <PATH>"
  ... and 45 more
```

---

## Template-Based Encoding (Binary Format v2)

Template-based encoding replaces token-based encoding for better compression. Instead of storing all token IDs per line, we store only the template ID plus variable values.

### Compression Comparison

| Metric | Token Encoding | Template Encoding |
|--------|----------------|-------------------|
| **large_real.log** | 156 MB (29%) | ~57 MB (~11%) est. |
| Line data per line | count + all token IDs | template_id + var IDs only |
| Example (10 tok, 3 var) | 2 + 40 = 42 bytes | 2 + 6 = 8 bytes |

**Expected improvement: ~2.7x better compression**

### Binary Format v2

```
+------------------------------------------------------------------+
| Header (64 bytes)                                                |
|   magic: uint32        = 0x43544C32 ('CTL2')                     |
|   version: uint32      = 2                                       |
|   flags: uint32        = 0                                       |
|   template_count: uint32                                         |
|   token_count: uint32                                            |
|   line_count: uint64                                             |
|   original_size: uint64                                          |
|   template_dict_offset: uint64                                   |
|   token_dict_offset: uint64                                      |
|   line_data_offset: uint64                                       |
+------------------------------------------------------------------+
| Template Dictionary                                              |
|   For each template (0 to template_count-1):                     |
|     uint8_t  slot_count                                          |
|     uint8_t  var_count        (number of non-LITERAL slots)      |
|     For each slot:                                               |
|       uint8_t  type           (VarType enum)                     |
|       uint32_t token_id       (only if type == LITERAL)          |
+------------------------------------------------------------------+
| Token Dictionary                                                 |
|   For each token (0 to token_count-1):                           |
|     uint16_t length                                              |
|     char[length] data                                            |
+------------------------------------------------------------------+
| Line Data                                                        |
|   For each line:                                                 |
|     uint16_t template_id      (0 = empty line)                   |
|     uint32_t var_ids[]        (var_count values, from template)  |
+------------------------------------------------------------------+
```

### Encode Flow (Single-Pass)

```
1. mmap input file
2. Parallel processing (per chunk):
   a. Parse line into tokens
   b. Classify each token (classify_token)
   c. Build template: [slot_type, token_id if LITERAL]
   d. Insert template into TemplateMap (lock-free CAS)
   e. Insert tokens into TokenMap (lock-free CAS)
   f. Append to thread buffer: [template_id, var_ids...]
3. Sequential write:
   a. Calculate sizes and offsets
   b. mmap output file
   c. Write header
   d. Write template dictionary (from TemplateMap)
   e. Write token dictionary (from TokenMap)
   f. Concatenate thread buffers
```

**Key insight:** No second pass needed. Dictionaries are built during parallel tokenization via lock-free operations. Same architecture as token encoding.

### Decode Flow

```
1. mmap input file
2. Read header, validate magic/version
3. Load template dictionary into memory
4. Load token dictionary into memory
5. For each line in line data:
   a. Read template_id
   b. If template_id == 0: write empty line, continue
   c. Look up template -> get slots[], var_count
   d. Read var_count var_ids
   e. var_idx = 0
   f. For each slot in template:
      - If LITERAL: write token[slot.token_id]
      - Else: write token[var_ids[var_idx++]]
      - Write space (except last)
   g. Write newline
```

### Thread Buffer Format

Each thread appends encoded lines to a flat `vector<uint8_t>` buffer:

```
+------------------+------------------+-----+
| Line 0           | Line 1           | ... |
| [tmpl_id][var_ids] | [tmpl_id][var_ids] |     |
+------------------+------------------+-----+
```

No per-line allocations. Same approach as token encoding.

### Design Decisions

**1. var_count in Template Dictionary**

The decoder needs to know how many var_ids to read per line. Rather than storing var_count per line (wastes space), we store it once in the template dictionary. Decode looks up template first, then reads var_count values.

**2. Empty Lines (template_id = 0)**

Template ID 0 is reserved for empty lines. Template 0 has slot_count=0, var_count=0. Encoder skips empty lines or writes template_id=0 with no var_ids.

**3. No Sub-Token Normalization for Encoding**

Sub-token patterns like "port:8080" are stored as single tokens, not normalized to "port:<NUM>". This simplifies decode (no placeholder substitution) at the cost of slightly worse compression.

Normalization is still used for template analysis/display, but encoding stores original tokens.

**4. Fixed-Width IDs**

- template_id: uint16_t (supports up to 65K templates)
- token_id/var_id: uint32_t (supports up to 4B tokens)

Varint encoding is a future optimization.

**5. Sequential Decode**

Parallel decode requires knowing line boundaries, which requires var_count lookups. For simplicity, decode is sequential. Parallel decode with line offset index is a future optimization.

### Performance Expectations

| Metric | Token Encoding | Template Encoding |
|--------|----------------|-------------------|
| Encode throughput | ~780 MB/s | ~650 MB/s (est.) |
| Decode throughput | ~500 MB/s | ~450 MB/s (est.) |
| Compression ratio | 29% | ~11% (est.) |

The ~17% encode slowdown is the cost of template extraction (classify_token + TemplateMap). The 2.7x better compression is the payoff.

### Future Optimizations

1. **Varint encoding** for template_id and var_ids
2. **Parallel decode** with line offset index
3. **Sub-token normalization** for encoding (requires placeholder substitution in decode)
4. **Delta encoding** for var_ids within template groups

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
|   +-- catalog.cc          # Main entry point, encode/decode commands
|   +-- mmap.h              # Memory-mapped file I/O (MappedFile class)
|   +-- token.h             # Lock-free TokenMap hash map
|   +-- variable.h          # Variable classification (VarType, classify_token)
|   +-- template.h          # Template structures (TemplateMap, TemplateSlot)
|   +-- template.cc         # Template extraction implementation
+-- test/
|   +-- catalog_test.cc     # TokenMap unit tests (29 tests)
|   +-- template_test.cc    # Variable classifier unit tests (107 tests)
|   +-- integration_test.sh # End-to-end tests (120 tests)
+-- docs/
|   +-- catalog.md          # This document
+-- bin/                    # Build output (gitignored)
+-- Makefile                # Build system
+-- .gitignore
```

### Key Classes/Functions

| Name | Location | Purpose |
|------|----------|---------|
| `TokenMap` | token.h | Lock-free open-addressed hash map with ordered storage |
| `MappedFile` | mmap.h | RAII wrapper for mmap'd files (read/write) |
| `TemplateMap` | template.h | Lock-free hash map for template deduplication |
| `TemplateSlot` | template.h | Single slot in a template (type + token_id) |
| `VarType` | variable.h | Enum of variable types (NUM, IP, TIME, etc.) |
| `classify_token()` | variable.h | Main token classifier function |
| `extract_templates()` | template.cc | Multi-file template extraction entry point |
| `Catalog::encode()` | catalog.cc | Single-pass parallel encoding |
| `Catalog::decode()` | catalog.cc | Decode .logc back to text |

### Variable Classification Module (variable.h)

Header-only module providing pattern matching functions:

| Function | Purpose |
|----------|---------|
| `match_number()` | Match numeric patterns (integers, decimals, signed) |
| `match_hex()` | Match 0x-prefixed hex values |
| `match_ipv4()` | Match IPv4 addresses with optional port/CIDR |
| `match_ipv6()` | Match IPv6 addresses with optional zone/CIDR |
| `match_timestamp()` | Match date/time patterns |
| `match_path()` | Match file paths and URLs |
| `match_uuid()` | Match UUID format (8-4-4-4-12 hex) |
| `match_array()` | Match balanced bracket expressions |
| `is_bool()` | Case-insensitive boolean detection |
| `is_ptr()` | Case-insensitive null/pointer detection |
| `classify_token()` | Main classifier dispatching to matchers |

---

## Known Limitations

### Encoding/Decoding
1. **Token length**: Max 65535 bytes (uint16_t length prefix)
2. **Tokens per line**: Max 65535 (uint16_t count)
3. **Total tokens**: Max ~4 billion (uint32_t IDs)
4. **Whitespace handling**: Lossy - multiple spaces/tabs collapsed to single space
5. **Memory usage**: Hash table sized at 2x estimated tokens (can be large for pathological data)

### Template Extraction
6. **Multi-file diff**: Limited to 64 files (uses 64-bit presence bitmap)
7. **Timestamp format**: Only digit/separator patterns (no month names like "Dec")
8. **IP value ranges**: Format checked, not value (256.0.0.1 matches as IP)
9. **Scientific notation**: Numbers like 1e10 classified as LITERAL, not NUM
10. **Windows paths**: Backslash paths (C:\foo) not recognized, only forward slash

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

## Template Encoding Test Plan

### Unit Tests (template_encode_test.cc)

**Header Serialization**
- [ ] Header magic is 0x43544C32 ('CTL2')
- [ ] Header size is exactly 64 bytes
- [ ] All header fields serialize/deserialize correctly
- [ ] Invalid magic rejected on decode

**Template Dictionary Serialization**
- [ ] Empty template (0 slots) serializes correctly
- [ ] Single LITERAL slot serializes with token_id
- [ ] Single VAR_* slot serializes without token_id
- [ ] Mixed template (LITERAL + VAR) serializes correctly
- [ ] var_count matches count of non-LITERAL slots
- [ ] All 11 VarTypes serialize/deserialize correctly
- [ ] Template with max slots (255) works

**Token Dictionary Serialization**
- [ ] Empty token dictionary works
- [ ] Single token serializes correctly
- [ ] Token with max length (65535) works
- [ ] Binary content (null bytes) preserved
- [ ] Token order matches IDs

**Line Data Serialization**
- [ ] Empty line (template_id=0) serializes as 2 bytes
- [ ] Line with 0 variables serializes correctly
- [ ] Line with multiple variables serializes correctly
- [ ] var_ids match var_count from template

**Round-Trip Tests**
- [ ] encode(input) -> decode(output) == input (single line)
- [ ] encode(input) -> decode(output) == input (multiple lines)
- [ ] Empty file round-trips correctly
- [ ] Single token line round-trips
- [ ] Line with all VAR types round-trips
- [ ] Whitespace normalization consistent

### Integration Tests (integration_test.sh additions)

**Basic Encode/Decode v2**
```bash
# Single file encode/decode
encode_v2_basic              # Simple file encodes without error
decode_v2_basic              # Encoded file decodes without error
roundtrip_v2_simple          # decode(encode(x)) == normalize(x)
roundtrip_v2_empty           # Empty file round-trips
roundtrip_v2_single_line     # Single line round-trips
```

**Template Verification**
```bash
template_count_matches       # Header template_count matches actual
token_count_matches          # Header token_count matches actual
line_count_matches           # Header line_count matches actual
```

**Variable Types**
```bash
encode_v2_numbers            # Lines with VAR_NUM
encode_v2_ips                # Lines with VAR_IP (v4 and v6)
encode_v2_timestamps         # Lines with VAR_TIME
encode_v2_paths              # Lines with VAR_PATH
encode_v2_uuids              # Lines with VAR_ID
encode_v2_hex                # Lines with VAR_HEX
encode_v2_booleans           # Lines with VAR_BOOL
encode_v2_nulls              # Lines with VAR_PTR
encode_v2_prefixes           # Lines with VAR_PREFIX (CIDR)
encode_v2_arrays             # Lines with VAR_ARRAY
encode_v2_mixed              # Lines with multiple var types
```

**Edge Cases**
```bash
encode_v2_empty_lines        # File with empty lines
encode_v2_whitespace_only    # Lines with only whitespace
encode_v2_long_line          # Line with 10000 tokens
encode_v2_long_token         # Token with 60000 chars
encode_v2_many_templates     # File with 50000+ templates
encode_v2_high_var_count     # Lines with 100+ variables
encode_v2_no_literals        # Line with only variables
encode_v2_no_variables       # Line with only literals
```

**Compression Verification**
```bash
compression_v2_better        # v2 size < v1 size for real logs
compression_v2_ratio         # Verify expected compression ratio
```

**Error Handling**
```bash
decode_v2_truncated          # Truncated file rejected
decode_v2_bad_magic          # Wrong magic rejected
decode_v2_bad_version        # Wrong version rejected
decode_v2_corrupted          # Corrupted data detected
```

### Performance Tests

**Throughput Benchmarks**
```bash
# Encode throughput
bench_encode_v2_large_real   # >= 600 MB/s on large_real.log
bench_encode_v2_synthetic    # Measure on synthetic data

# Decode throughput
bench_decode_v2_large_real   # >= 400 MB/s
bench_decode_v2_synthetic    # Measure on synthetic data

# Comparison
bench_v2_vs_v1_encode        # v2 within 20% of v1 encode speed
bench_v2_vs_v1_compression   # v2 >= 2x better compression
```

**Memory Tests**
```bash
memory_encode_v2_peak        # Peak memory reasonable
memory_encode_v2_no_leaks    # No memory leaks (valgrind)
```

### Regression Tests

```bash
# Ensure existing functionality still works
regression_template_extract  # Template extraction unchanged
regression_token_encode_v1   # Token encode still works (during transition)
regression_all_unit_tests    # All 136 unit tests pass
regression_all_integration   # All 120 integration tests pass
```

### Test Data Files

| File | Purpose |
|------|---------|
| test/data/simple.log | Basic 10-line file |
| test/data/all_var_types.log | One line per VarType |
| test/data/empty_lines.log | File with empty lines |
| test/data/long_tokens.log | File with very long tokens |
| test/data/high_reuse.log | Many lines, few templates |
| test/data/low_reuse.log | Many lines, many templates |

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
| 2024-12-17 | Added template extraction mode with variable classification |
| 2024-12-17 | Added VarType enum: NUM, HEX, IP, TIME, PATH, ID, PREFIX, ARRAY, BOOL, PTR |
| 2024-12-17 | Added multi-file diff to find unique templates/values per file |
| 2024-12-17 | Refactored into header modules: mmap.h, token.h, variable.h, template.h |
| 2024-12-17 | Added TemplateMap for lock-free template deduplication |
| 2024-12-17 | Added sub-token pattern extraction (K:V, embedded IPs, arrays) |
| 2024-12-17 | Added IPv6 support with zone ID and CIDR prefix detection |
| 2024-12-17 | Added case-insensitive bool/ptr detection with iequals() helper |
| 2024-12-17 | Optimized classify_token() with early-exit for non-hex alpha chars |
| 2024-12-17 | Consolidated is_all_xdigit calls for ID/HEX detection |
| 2024-12-17 | Added `-x/--exclude` option for pattern filtering |
| 2024-12-17 | Added `-n/--top` option for limiting output |
| 2024-12-17 | Added template_test.cc with 107 variable classifier tests |
| 2024-12-17 | Expanded integration tests to 120 tests |
| 2024-12-17 | Standardized test output format: [PASS]/[FAIL] with colors |
| 2024-12-17 | Fixed per-line vector copy overhead in template extraction (11% speedup) |
| 2024-12-17 | Designed template-based binary format v2 (est. 2.7x better compression) |
| 2024-12-17 | Added template encoding test plan |
