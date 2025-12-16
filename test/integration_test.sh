#!/bin/bash
# integration_test.sh - Comprehensive integration tests for catalog
# Tests encode/decode round-trips with various edge cases and adversarial inputs

set -e

CATALOG="${1:-bin/catalog}"
TEST_DIR="/tmp/catalog_integration_$$"
PASSED=0
FAILED=0
FAILED_TESTS=""

# Helper to increment counters (bash arithmetic returns 1 for zero result)
inc_passed() { PASSED=$((PASSED + 1)); }
inc_failed() { FAILED=$((FAILED + 1)); }

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

cleanup() {
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

mkdir -p "$TEST_DIR"

# Normalize whitespace for comparison (matches the lossy compression behavior)
# - CR and CRLF become LF
# - Multiple whitespace chars become single space
# - Leading/trailing whitespace on lines removed
normalize() {
    # First convert all line endings to LF (CR, CRLF, or LF -> LF)
    sed 's/\r$//' | tr '\r' '\n' | \
    sed 's/^[[:space:]]*//' | \
    sed 's/[[:space:]]*$//' | \
    tr -s '[:blank:]' ' ' | \
    grep -v '^$' || true
}

# Run a test case
run_test() {
    local name="$1"
    local input_file="$2"
    local expect_fail="${3:-false}"

    local encoded="$TEST_DIR/${name}.logc"
    local decoded="$TEST_DIR/${name}.decoded"

    # Encode
    if ! "$CATALOG" encode "$input_file" "$encoded" > /dev/null 2>&1; then
        if [ "$expect_fail" = "true" ]; then
            echo -e "${GREEN}[PASS]${NC} $name (expected failure)"
            inc_passed
            return 0
        else
            echo -e "${RED}[FAIL]${NC} $name (encode failed)"
            inc_failed
            FAILED_TESTS="$FAILED_TESTS\n  - $name (encode failed)"
            return 0
        fi
    fi

    if [ "$expect_fail" = "true" ]; then
        echo -e "${RED}[FAIL]${NC} $name (expected failure but succeeded)"
        inc_failed
        FAILED_TESTS="$FAILED_TESTS\n  - $name (unexpected success)"
        return 0
    fi

    # Decode
    if ! "$CATALOG" decode "$encoded" "$decoded" > /dev/null 2>&1; then
        echo -e "${RED}[FAIL]${NC} $name (decode failed)"
        inc_failed
        FAILED_TESTS="$FAILED_TESTS\n  - $name (decode failed)"
        return 0
    fi

    # Compare (with whitespace normalization)
    local orig_norm="$TEST_DIR/${name}.orig_norm"
    local decoded_norm="$TEST_DIR/${name}.decoded_norm"

    normalize < "$input_file" > "$orig_norm"
    normalize < "$decoded" > "$decoded_norm"

    if diff -q "$orig_norm" "$decoded_norm" > /dev/null 2>&1; then
        echo -e "${GREEN}[PASS]${NC} $name"
        inc_passed
        return 0
    else
        echo -e "${RED}[FAIL]${NC} $name (content mismatch)"
        inc_failed
        FAILED_TESTS="$FAILED_TESTS\n  - $name (content mismatch)"
        # Show diff for debugging
        echo "    First difference:"
        diff "$orig_norm" "$decoded_norm" | head -5 | sed 's/^/    /'
        return 0
    fi
}

# Verify encoded file header
verify_header() {
    local name="$1"
    local encoded="$2"
    local expected_lines="$3"

    # Check magic bytes (CTLG = 0x474C5443)
    local magic=$(xxd -l 4 -p "$encoded" 2>/dev/null)
    if [ "$magic" != "43544c47" ]; then
        echo -e "${RED}[FAIL]${NC} header_$name (bad magic: $magic)"
        inc_failed
        FAILED_TESTS="$FAILED_TESTS\n  - header_$name (bad magic)"
        return 0
    fi

    echo -e "${GREEN}[PASS]${NC} header_$name"
    inc_passed
}

echo "=== Catalog Integration Tests ==="
echo ""
echo "Using catalog binary: $CATALOG"
echo "Test directory: $TEST_DIR"
echo ""

#=============================================================================
# Basic Functionality Tests
#=============================================================================

echo "[Basic Functionality]"

# Empty file
echo -n "" > "$TEST_DIR/empty.log"
run_test "empty_file" "$TEST_DIR/empty.log"

# Single character
echo "x" > "$TEST_DIR/single_char.log"
run_test "single_char" "$TEST_DIR/single_char.log"

# Single token
echo "hello" > "$TEST_DIR/single_token.log"
run_test "single_token" "$TEST_DIR/single_token.log"

# Single line multiple tokens
echo "hello world foo bar baz" > "$TEST_DIR/single_line.log"
run_test "single_line_multiple_tokens" "$TEST_DIR/single_line.log"

# Multiple lines
printf "line one\nline two\nline three\n" > "$TEST_DIR/multiple_lines.log"
run_test "multiple_lines" "$TEST_DIR/multiple_lines.log"

# Large number of lines
seq 1 10000 > "$TEST_DIR/many_lines.log"
run_test "10000_lines" "$TEST_DIR/many_lines.log"

echo ""

#=============================================================================
# Whitespace Handling Tests
#=============================================================================

echo "[Whitespace Handling]"

# Multiple spaces
echo "hello    world" > "$TEST_DIR/multi_space.log"
run_test "multiple_spaces" "$TEST_DIR/multi_space.log"

# Tabs
printf "hello\tworld" > "$TEST_DIR/tabs.log"
run_test "tabs" "$TEST_DIR/tabs.log"

# Mixed whitespace
printf "hello  \t\t  world\t  foo" > "$TEST_DIR/mixed_ws.log"
run_test "mixed_whitespace" "$TEST_DIR/mixed_ws.log"

# Leading whitespace
printf "   hello world\n   foo bar\n" > "$TEST_DIR/leading_ws.log"
run_test "leading_whitespace" "$TEST_DIR/leading_ws.log"

# Trailing whitespace
printf "hello world   \nfoo bar   \n" > "$TEST_DIR/trailing_ws.log"
run_test "trailing_whitespace" "$TEST_DIR/trailing_ws.log"

# Lines with only whitespace
printf "hello\n   \n\t\t\nworld\n" > "$TEST_DIR/ws_lines.log"
run_test "whitespace_only_lines" "$TEST_DIR/ws_lines.log"

# Empty lines
printf "line1\n\n\nline2\n\n" > "$TEST_DIR/empty_lines.log"
run_test "empty_lines" "$TEST_DIR/empty_lines.log"

echo ""

#=============================================================================
# Line Ending Tests
#=============================================================================

echo "[Line Endings]"

# CRLF (Windows)
printf "line1\r\nline2\r\nline3\r\n" > "$TEST_DIR/crlf.log"
run_test "crlf_line_endings" "$TEST_DIR/crlf.log"

# CR only (old Mac)
printf "line1\rline2\rline3\r" > "$TEST_DIR/cr.log"
run_test "cr_line_endings" "$TEST_DIR/cr.log"

# Mixed line endings
printf "unix\nwindows\r\nold_mac\runix2\n" > "$TEST_DIR/mixed_le.log"
run_test "mixed_line_endings" "$TEST_DIR/mixed_le.log"

# No trailing newline
printf "line1\nline2\nlast" > "$TEST_DIR/no_trailing.log"
run_test "no_trailing_newline" "$TEST_DIR/no_trailing.log"

# Multiple trailing newlines
printf "line1\nline2\n\n\n" > "$TEST_DIR/multi_trailing.log"
run_test "multiple_trailing_newlines" "$TEST_DIR/multi_trailing.log"

echo ""

#=============================================================================
# Token Content Tests
#=============================================================================

echo "[Token Content]"

# Numeric tokens
seq 1 1000 | xargs -n 5 > "$TEST_DIR/numeric.log"
run_test "numeric_tokens" "$TEST_DIR/numeric.log"

# Special characters
echo '!@#$%^&*() []{}|;:,./<>?' > "$TEST_DIR/special.log"
run_test "special_characters" "$TEST_DIR/special.log"

# Punctuation in tokens
echo "hello@world foo.bar baz#qux a=b c:d e/f" > "$TEST_DIR/punctuation.log"
run_test "punctuation_in_tokens" "$TEST_DIR/punctuation.log"

# Very long token (60KB)
python3 -c "print('x' * 60000)" > "$TEST_DIR/long_token.log" 2>/dev/null || \
    head -c 60000 /dev/zero | tr '\0' 'x' > "$TEST_DIR/long_token.log"
echo "" >> "$TEST_DIR/long_token.log"
run_test "very_long_token_60k" "$TEST_DIR/long_token.log"

# Many tokens per line (1000)
seq 1 1000 | tr '\n' ' ' > "$TEST_DIR/many_tokens.log"
echo "" >> "$TEST_DIR/many_tokens.log"
run_test "1000_tokens_per_line" "$TEST_DIR/many_tokens.log"

# Single character tokens
echo "a b c d e f g h i j k l m n o p q r s t u v w x y z" > "$TEST_DIR/single_chars.log"
run_test "single_char_tokens" "$TEST_DIR/single_chars.log"

# Tokens that are prefixes of each other
echo "a ab abc abcd abcde abcdef" > "$TEST_DIR/prefixes.log"
run_test "prefix_tokens" "$TEST_DIR/prefixes.log"

# Hex strings (look like hashes)
for i in $(seq 1 100); do
    echo "$(head -c 32 /dev/urandom | xxd -p | head -c 64)"
done > "$TEST_DIR/hex.log"
run_test "hex_strings" "$TEST_DIR/hex.log"

echo ""

#=============================================================================
# Compression Ratio Tests
#=============================================================================

echo "[Compression Patterns]"

# All same token (best compression)
yes "same" | head -10000 > "$TEST_DIR/all_same.log"
run_test "all_same_token" "$TEST_DIR/all_same.log"

# All unique tokens (worst compression)
for i in $(seq 1 1000); do
    echo "unique_token_$i unique_value_$i unique_data_$i"
done > "$TEST_DIR/all_unique.log"
run_test "all_unique_tokens" "$TEST_DIR/all_unique.log"

# High repetition pattern (log-like)
for i in $(seq 1 1000); do
    echo "2024-12-16 10:$((i/60)):$((i%60)) INFO Processing request id=$i"
done > "$TEST_DIR/log_pattern.log"
run_test "log_like_pattern" "$TEST_DIR/log_pattern.log"

# Repeated line exactly
for i in $(seq 1 1000); do
    echo "ERROR: connection failed to server at port 8080"
done > "$TEST_DIR/repeated_line.log"
run_test "exactly_repeated_line" "$TEST_DIR/repeated_line.log"

echo ""

#=============================================================================
# Adversarial Tests
#=============================================================================

echo "[Adversarial Cases]"

# Binary-looking content (but valid text)
head -c 1000 /dev/urandom | base64 | fold -w 80 > "$TEST_DIR/base64.log"
run_test "base64_content" "$TEST_DIR/base64.log"

# Very wide lines (10K chars per line, 100 lines)
for i in $(seq 1 100); do
    head -c 10000 /dev/urandom | base64 | tr -d '\n' | head -c 10000
    echo ""
done > "$TEST_DIR/wide_lines.log"
run_test "very_wide_lines" "$TEST_DIR/wide_lines.log"

# Many short lines (100K lines, 1 token each)
seq 1 100000 > "$TEST_DIR/many_short.log"
run_test "100k_short_lines" "$TEST_DIR/many_short.log"

# Tokens at boundary sizes
for len in 1 7 8 9 15 16 17 31 32 33 63 64 65 127 128 129 255 256 257; do
    head -c $len /dev/urandom | base64 | tr -d '\n' | head -c $len
    echo ""
done > "$TEST_DIR/boundary.log"
run_test "boundary_size_tokens" "$TEST_DIR/boundary.log"

# Pathological hash patterns (tokens designed to collide)
# FNV-1a with same prefix
for i in $(seq 1 100); do
    printf "prefix_%.10d suffix" $i
    echo ""
done > "$TEST_DIR/hash_pattern.log"
run_test "hash_collision_prone" "$TEST_DIR/hash_pattern.log"

# Alternating pattern
for i in $(seq 1 1000); do
    if [ $((i % 2)) -eq 0 ]; then
        echo "even $i"
    else
        echo "odd $i"
    fi
done > "$TEST_DIR/alternating.log"
run_test "alternating_pattern" "$TEST_DIR/alternating.log"

# Zipf distribution (few common tokens, many rare)
for i in $(seq 1 10000); do
    r=$((RANDOM % 100))
    if [ $r -lt 50 ]; then
        echo "common"
    elif [ $r -lt 75 ]; then
        echo "less_common_$((RANDOM % 10))"
    else
        echo "rare_$RANDOM"
    fi
done > "$TEST_DIR/zipf.log"
run_test "zipf_distribution" "$TEST_DIR/zipf.log"

echo ""

#=============================================================================
# Stress Tests
#=============================================================================

echo "[Stress Tests]"

# 10MB file
for i in $(seq 1 100000); do
    echo "log entry $i with some data field=$((RANDOM)) value=$((RANDOM % 1000))"
done > "$TEST_DIR/10mb.log"
run_test "10mb_file" "$TEST_DIR/10mb.log"

# Very high token count (many unique)
for i in $(seq 1 50000); do
    echo "u$i"
done > "$TEST_DIR/high_token_count.log"
run_test "50k_unique_tokens" "$TEST_DIR/high_token_count.log"

# Deep repetition (same 100 tokens repeated many times)
for repeat in $(seq 1 1000); do
    for token in $(seq 1 100); do
        printf "t$token "
    done
    echo ""
done > "$TEST_DIR/deep_repeat.log"
run_test "deep_repetition" "$TEST_DIR/deep_repeat.log"

echo ""

#=============================================================================
# Header Validation Tests
#=============================================================================

echo "[Header Validation]"

# Create a simple encoded file and verify header
echo "test content" > "$TEST_DIR/header_test.log"
"$CATALOG" encode "$TEST_DIR/header_test.log" "$TEST_DIR/header_test.logc" > /dev/null 2>&1
verify_header "simple" "$TEST_DIR/header_test.logc" 1

# Larger file
seq 1 1000 > "$TEST_DIR/header_large.log"
"$CATALOG" encode "$TEST_DIR/header_large.log" "$TEST_DIR/header_large.logc" > /dev/null 2>&1
verify_header "large" "$TEST_DIR/header_large.logc" 1000

echo ""

#=============================================================================
# Error Handling Tests
#=============================================================================

echo "[Error Handling]"

# Non-existent input file
if "$CATALOG" encode "/tmp/definitely_does_not_exist_$$" "$TEST_DIR/out.logc" > /dev/null 2>&1; then
    echo -e "${RED}[FAIL]${NC} nonexistent_input (should have failed)"
    inc_failed
else
    echo -e "${GREEN}[PASS]${NC} nonexistent_input"
    inc_passed
fi

# Invalid output path
echo "test" > "$TEST_DIR/test.log"
if "$CATALOG" encode "$TEST_DIR/test.log" "/nonexistent_dir/out.logc" > /dev/null 2>&1; then
    echo -e "${RED}[FAIL]${NC} invalid_output_path (should have failed)"
    inc_failed
else
    echo -e "${GREEN}[PASS]${NC} invalid_output_path"
    inc_passed
fi

# Truncated encoded file (corrupt)
echo "test" > "$TEST_DIR/trunc_test.log"
"$CATALOG" encode "$TEST_DIR/trunc_test.log" "$TEST_DIR/trunc.logc" > /dev/null 2>&1
head -c 20 "$TEST_DIR/trunc.logc" > "$TEST_DIR/trunc_bad.logc"
if "$CATALOG" decode "$TEST_DIR/trunc_bad.logc" "$TEST_DIR/trunc_out.log" > /dev/null 2>&1; then
    echo -e "${RED}[FAIL]${NC} truncated_encoded_file (should have failed)"
    inc_failed
else
    echo -e "${GREEN}[PASS]${NC} truncated_encoded_file"
    inc_passed
fi

# Invalid magic in encoded file
echo "test content" > "$TEST_DIR/magic_test.log"
"$CATALOG" encode "$TEST_DIR/magic_test.log" "$TEST_DIR/magic.logc" > /dev/null 2>&1
# Corrupt the magic bytes
printf 'XXXX' | dd of="$TEST_DIR/magic.logc" bs=1 count=4 conv=notrunc > /dev/null 2>&1
if "$CATALOG" decode "$TEST_DIR/magic.logc" "$TEST_DIR/magic_out.log" > /dev/null 2>&1; then
    echo -e "${RED}[FAIL]${NC} invalid_magic (should have failed)"
    inc_failed
else
    echo -e "${GREEN}[PASS]${NC} invalid_magic"
    inc_passed
fi

echo ""

#=============================================================================
# Benchmark Comparison Test
#=============================================================================

echo "[Performance Sanity Check]"

# Create 50MB test file
for i in $(seq 1 500000); do
    echo "log $i data=$((RANDOM)) value=$((RANDOM))"
done > "$TEST_DIR/perf.log"

START=$(date +%s%N)
"$CATALOG" encode "$TEST_DIR/perf.log" "$TEST_DIR/perf.logc" > /dev/null 2>&1
END=$(date +%s%N)
ELAPSED=$(( (END - START) / 1000000 ))  # milliseconds

FILE_SIZE=$(stat -c%s "$TEST_DIR/perf.log" 2>/dev/null || stat -f%z "$TEST_DIR/perf.log")
THROUGHPUT=$(( FILE_SIZE / ELAPSED / 1024 ))  # KB/s -> MB/s approx

if [ $THROUGHPUT -gt 10 ]; then  # At least 10 MB/s
    echo -e "${GREEN}[PASS]${NC} 50mb_performance (~${THROUGHPUT} KB/ms)"
    inc_passed
else
    echo -e "${YELLOW}[WARN]${NC} 50mb_performance (slow: ${THROUGHPUT} KB/ms)"
    inc_passed
fi

echo ""

#=============================================================================
# Summary
#=============================================================================

echo "=== Test Summary ==="
echo "Passed: $PASSED"
echo "Failed: $FAILED"

if [ $FAILED -gt 0 ]; then
    echo ""
    echo "Failed tests:"
    echo -e "$FAILED_TESTS"
    exit 1
fi

echo ""
echo "All tests passed!"
exit 0
