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
# Template Extraction / Diff Tests
#=============================================================================

echo "[Template Extraction - Basic]"

# Helper function to run diff and check template count
run_diff_test() {
    local name="$1"
    local input_file="$2"
    local expected_templates="$3"
    local expected_tokens="$4"

    local output=$("$CATALOG" diff "$input_file" 2>&1)
    local actual_templates=$(echo "$output" | grep -o 'Templates: [0-9]*' | grep -o '[0-9]*')
    local actual_tokens=$(echo "$output" | grep -o 'Tokens: [0-9]*' | grep -o '[0-9]*')

    if [ -z "$actual_templates" ]; then
        echo -e "${RED}[FAIL]${NC} $name (diff failed to produce output)"
        inc_failed
        FAILED_TESTS="$FAILED_TESTS\n  - $name (diff failed)"
        return 0
    fi

    # Check template count (with tolerance if expected is -1)
    if [ "$expected_templates" != "-1" ] && [ "$actual_templates" != "$expected_templates" ]; then
        echo -e "${RED}[FAIL]${NC} $name (expected $expected_templates templates, got $actual_templates)"
        inc_failed
        FAILED_TESTS="$FAILED_TESTS\n  - $name (template count mismatch)"
        return 0
    fi

    # Check token count if specified
    if [ "$expected_tokens" != "-1" ] && [ "$actual_tokens" != "$expected_tokens" ]; then
        echo -e "${RED}[FAIL]${NC} $name (expected $expected_tokens tokens, got $actual_tokens)"
        inc_failed
        FAILED_TESTS="$FAILED_TESTS\n  - $name (token count mismatch)"
        return 0
    fi

    echo -e "${GREEN}[PASS]${NC} $name (templates: $actual_templates, tokens: $actual_tokens)"
    inc_passed
}

# Helper to verify template output contains expected patterns
run_diff_pattern_test() {
    local name="$1"
    local input_file="$2"
    local pattern="$3"

    local output=$("$CATALOG" diff "$input_file" 2>&1)

    if echo "$output" | grep -qF "$pattern"; then
        echo -e "${GREEN}[PASS]${NC} $name"
        inc_passed
    else
        echo -e "${RED}[FAIL]${NC} $name (pattern not found: $pattern)"
        inc_failed
        FAILED_TESTS="$FAILED_TESTS\n  - $name (pattern not found)"
    fi
}

# Single identical lines - should collapse to 1 template
printf "hello world\nhello world\nhello world\n" > "$TEST_DIR/diff_identical.log"
run_diff_test "identical_lines" "$TEST_DIR/diff_identical.log" 1 2

# Same template, different numbers
printf "error code 100\nerror code 200\nerror code 300\n" > "$TEST_DIR/diff_nums.log"
run_diff_test "same_template_diff_nums" "$TEST_DIR/diff_nums.log" 1 5  # error, code, 100, 200, 300

# Completely different lines
printf "alpha\nbeta\ngamma\n" > "$TEST_DIR/diff_unique.log"
run_diff_test "all_unique_templates" "$TEST_DIR/diff_unique.log" 3 3

echo ""
echo "[Template Extraction - Variable Types]"

# IPv4 addresses
printf "connect to 10.0.0.1\nconnect to 192.168.1.1\nconnect to 172.16.0.1\n" > "$TEST_DIR/diff_ipv4.log"
run_diff_test "ipv4_consolidation" "$TEST_DIR/diff_ipv4.log" 1 -1
run_diff_pattern_test "ipv4_placeholder" "$TEST_DIR/diff_ipv4.log" "<IP>"

# IPv4 with ports
printf "server 10.0.0.1:8080\nserver 192.168.1.1:443\nserver 127.0.0.1:3000\n" > "$TEST_DIR/diff_ipv4_port.log"
run_diff_test "ipv4_port_consolidation" "$TEST_DIR/diff_ipv4_port.log" 1 -1
run_diff_pattern_test "ipv4_port_placeholder" "$TEST_DIR/diff_ipv4_port.log" "<IP>"

# IPv6 addresses - properly recognized as IPs (colon not a delimiter)
printf "connect to ::1\nconnect to fe80::1\nconnect to 2001:db8::1\n" > "$TEST_DIR/diff_ipv6.log"
run_diff_test "ipv6_consolidation" "$TEST_DIR/diff_ipv6.log" 1 -1  # All consolidate to one template

# IPv6 full form
printf "addr 2001:0db8:85a3:0000:0000:8a2e:0370:7334\naddr 2001:0db8:85a3:0000:0000:8a2e:0370:7335\n" > "$TEST_DIR/diff_ipv6_full.log"
run_diff_test "ipv6_full_consolidation" "$TEST_DIR/diff_ipv6_full.log" 1 -1

# Hex values
printf "ptr 0x1a2b3c4d\nptr 0xdeadbeef\nptr 0x12345678\n" > "$TEST_DIR/diff_hex.log"
run_diff_test "hex_consolidation" "$TEST_DIR/diff_hex.log" 1 -1
run_diff_pattern_test "hex_placeholder" "$TEST_DIR/diff_hex.log" "<HEX>"

# Timestamps
printf "time 2024-01-01\ntime 2024-12-31\ntime 2025-06-15\n" > "$TEST_DIR/diff_date.log"
run_diff_test "date_consolidation" "$TEST_DIR/diff_date.log" 1 -1
run_diff_pattern_test "date_placeholder" "$TEST_DIR/diff_date.log" "<TIME>"

# Full timestamps - properly recognized (colon not a delimiter)
printf "at 2024-12-16T10:30:45Z\nat 2025-01-01T00:00:00Z\n" > "$TEST_DIR/diff_timestamp.log"
run_diff_test "timestamp_consolidation" "$TEST_DIR/diff_timestamp.log" 1 -1  # Both consolidate

# File paths
printf "read /var/log/syslog\nread /etc/passwd\nread /usr/local/bin/foo\n" > "$TEST_DIR/diff_path.log"
run_diff_test "path_consolidation" "$TEST_DIR/diff_path.log" 1 -1
run_diff_pattern_test "path_placeholder" "$TEST_DIR/diff_path.log" "<PATH>"

# UUIDs
printf "id 550e8400-e29b-41d4-a716-446655440000\nid 6ba7b810-9dad-11d1-80b4-00c04fd430c8\n" > "$TEST_DIR/diff_uuid.log"
run_diff_test "uuid_consolidation" "$TEST_DIR/diff_uuid.log" 1 -1
run_diff_pattern_test "uuid_placeholder" "$TEST_DIR/diff_uuid.log" "<ID>"

# Boolean values
printf "enabled = true\nenabled = false\n" > "$TEST_DIR/diff_bool_tf.log"
run_diff_test "bool_true_false" "$TEST_DIR/diff_bool_tf.log" 1 -1
run_diff_pattern_test "bool_tf_placeholder" "$TEST_DIR/diff_bool_tf.log" "<BOOL>"

printf "active = yes\nactive = no\n" > "$TEST_DIR/diff_bool_yn.log"
run_diff_test "bool_yes_no" "$TEST_DIR/diff_bool_yn.log" 1 -1

printf "state = positive\nstate = negative\n" > "$TEST_DIR/diff_bool_pn.log"
run_diff_test "bool_positive_negative" "$TEST_DIR/diff_bool_pn.log" 1 -1

# CIDR prefixes (sub-token extraction)
printf "route 10.0.0.0/8 via gw\nroute 192.168.0.0/16 via gw\nroute 172.16.0.0/12 via gw\n" > "$TEST_DIR/diff_cidr.log"
run_diff_test "cidr_prefix_extraction" "$TEST_DIR/diff_cidr.log" 1 -1
run_diff_pattern_test "cidr_placeholder" "$TEST_DIR/diff_cidr.log" "<PREFIX>"

echo ""
echo "[Template Extraction - Delimiters]"

# Equals sign delimiter (use numbers so templates consolidate)
printf "foo=100 baz=200\nfoo=123 baz=456\n" > "$TEST_DIR/diff_equals.log"
run_diff_test "equals_delimiter" "$TEST_DIR/diff_equals.log" 1 -1

# Semicolon delimiter (use numbers so templates consolidate)
printf "a;1;2\na;3;4\n" > "$TEST_DIR/diff_semicolon.log"
run_diff_test "semicolon_delimiter" "$TEST_DIR/diff_semicolon.log" 1 -1

# Angle bracket delimiter
printf "<foo>123</foo>\n<foo>456</foo>\n" > "$TEST_DIR/diff_angle.log"
run_diff_test "angle_bracket_delimiter" "$TEST_DIR/diff_angle.log" 1 -1

# Complex delimiter combination
printf "key=<value;123>\nkey=<value;456>\n" > "$TEST_DIR/diff_complex_delim.log"
run_diff_test "complex_delimiters" "$TEST_DIR/diff_complex_delim.log" 1 -1

echo ""
echo "[Template Extraction - Arrays]"

# Simple arrays
printf "values = [1, 2, 3]\nvalues = [4, 5, 6]\n" > "$TEST_DIR/diff_array.log"
run_diff_test "array_consolidation" "$TEST_DIR/diff_array.log" 1 -1
run_diff_pattern_test "array_placeholder" "$TEST_DIR/diff_array.log" "<ARRAY>"

# Empty arrays
printf "list = []\nlist = []\n" > "$TEST_DIR/diff_empty_array.log"
run_diff_test "empty_array" "$TEST_DIR/diff_empty_array.log" 1 -1

# Nested arrays
printf "matrix = [[1, 2], [3, 4]]\nmatrix = [[5, 6], [7, 8]]\n" > "$TEST_DIR/diff_nested_array.log"
run_diff_test "nested_array" "$TEST_DIR/diff_nested_array.log" 1 -1

# Arrays with spaces preserved
printf "data [a, b, c] end\ndata [x, y, z] end\n" > "$TEST_DIR/diff_array_space.log"
run_diff_test "array_with_spaces" "$TEST_DIR/diff_array_space.log" 1 -1

echo ""
echo "[Template Extraction - Adversarial Cases]"

# C++ namespace should NOT be IPv6
printf "Queue::add called\nQueue::remove called\n" > "$TEST_DIR/diff_cpp_ns.log"
output=$("$CATALOG" diff "$TEST_DIR/diff_cpp_ns.log" 2>&1)
if echo "$output" | grep -qF "<IP>"; then
    echo -e "${RED}[FAIL]${NC} cpp_namespace_not_ipv6 (incorrectly matched as IP)"
    inc_failed
    FAILED_TESTS="$FAILED_TESTS\n  - cpp_namespace_not_ipv6"
else
    echo -e "${GREEN}[PASS]${NC} cpp_namespace_not_ipv6"
    inc_passed
fi

# Version numbers should NOT be IPs
printf "version 1.2.3\nversion 4.5.6\n" > "$TEST_DIR/diff_version.log"
output=$("$CATALOG" diff "$TEST_DIR/diff_version.log" 2>&1)
if echo "$output" | grep -qF "<IP>"; then
    echo -e "${RED}[FAIL]${NC} version_not_ip (incorrectly matched as IP)"
    inc_failed
    FAILED_TESTS="$FAILED_TESTS\n  - version_not_ip"
else
    echo -e "${GREEN}[PASS]${NC} version_not_ip"
    inc_passed
fi

# Short hex strings should NOT be hashes
printf "code abc123\ncode def456\n" > "$TEST_DIR/diff_short_hex.log"
output=$("$CATALOG" diff "$TEST_DIR/diff_short_hex.log" 2>&1)
if echo "$output" | grep -qF "<ID>"; then
    echo -e "${RED}[FAIL]${NC} short_hex_not_id (incorrectly matched as ID)"
    inc_failed
    FAILED_TESTS="$FAILED_TESTS\n  - short_hex_not_id"
else
    echo -e "${GREEN}[PASS]${NC} short_hex_not_id"
    inc_passed
fi

# Mixed content stress test - NOTE: colon delimiter splits timestamps,
# causing each line to have different template due to different seconds (45Z, 46Z, 47Z)
cat > "$TEST_DIR/diff_mixed.log" << 'EOF'
2024-12-16T10:30:45Z INFO connect to 10.0.0.1:8080 id=550e8400-e29b-41d4-a716-446655440000 ptr=0xdeadbeef path=/var/log/app.log enabled=true values=[1, 2, 3]
2024-12-16T10:30:46Z INFO connect to 192.168.1.1:443 id=6ba7b810-9dad-11d1-80b4-00c04fd430c8 ptr=0x12345678 path=/etc/config.json enabled=false values=[4, 5, 6]
2024-12-16T10:30:47Z WARN connect to 172.16.0.1:3000 id=123e4567-e89b-12d3-a456-426614174000 ptr=0xabcdef01 path=/tmp/cache.db enabled=true values=[7, 8, 9]
EOF
run_diff_test "mixed_content_stress" "$TEST_DIR/diff_mixed.log" 2 -1  # 2 templates: INFO and WARN (timestamps consolidated)

# Edge case: token that looks like IP but has extra chars
printf "prefix10.0.0.1suffix\nprefix192.168.1.1suffix\n" > "$TEST_DIR/diff_ip_embedded.log"
run_diff_test "embedded_ip_extraction" "$TEST_DIR/diff_ip_embedded.log" 1 -1

# Edge case: hex embedded in larger token
printf "ptr0x1234end\nptr0x5678end\n" > "$TEST_DIR/diff_hex_embedded.log"
run_diff_test "embedded_hex_extraction" "$TEST_DIR/diff_hex_embedded.log" 1 -1

# Very long template (many tokens)
printf "a b c d e f g h i j k l m n o p q r s t u v w x y z 1\n" > "$TEST_DIR/diff_long_template.log"
printf "a b c d e f g h i j k l m n o p q r s t u v w x y z 2\n" >> "$TEST_DIR/diff_long_template.log"
run_diff_test "long_template" "$TEST_DIR/diff_long_template.log" 1 -1

# Many templates
for i in $(seq 1 100); do
    echo "unique_template_$i with value $i"
done > "$TEST_DIR/diff_many_templates.log"
run_diff_test "many_templates" "$TEST_DIR/diff_many_templates.log" 100 -1

# Rapid variable changes (every token is variable)
printf "100 200 300 0x400 10.0.0.1 2024-01-01\n" > "$TEST_DIR/diff_all_vars.log"
printf "101 201 301 0x401 10.0.0.2 2024-01-02\n" >> "$TEST_DIR/diff_all_vars.log"
run_diff_test "all_variable_tokens" "$TEST_DIR/diff_all_vars.log" 1 -1

# Unicode in tokens (should be treated as literal)
printf "message: héllo wörld\nmessage: göodbye wörld\n" > "$TEST_DIR/diff_unicode.log"
run_diff_test "unicode_tokens" "$TEST_DIR/diff_unicode.log" -1 -1  # Just verify it doesn't crash

# Very large numbers
printf "count 99999999999999999999\ncount 88888888888888888888\n" > "$TEST_DIR/diff_large_nums.log"
run_diff_test "large_numbers" "$TEST_DIR/diff_large_nums.log" 1 -1

# Negative numbers
printf "temp -273\ntemp -100\ntemp 50\n" > "$TEST_DIR/diff_negative.log"
run_diff_test "negative_numbers" "$TEST_DIR/diff_negative.log" 1 -1

# Decimal numbers
printf "ratio 3.14159\nratio 2.71828\n" > "$TEST_DIR/diff_decimal.log"
run_diff_test "decimal_numbers" "$TEST_DIR/diff_decimal.log" 1 -1

# Empty lines interspersed
printf "line1\n\nline2\n\n\nline3\n" > "$TEST_DIR/diff_empty_lines.log"
run_diff_test "empty_lines_diff" "$TEST_DIR/diff_empty_lines.log" 3 3

# Single character tokens
printf "a b c\nx y z\n" > "$TEST_DIR/diff_single_char.log"
run_diff_test "single_char_tokens_diff" "$TEST_DIR/diff_single_char.log" 2 6

echo ""
echo "[Template Extraction - Multi-File Diff]"

# Two identical files
printf "same content\n" > "$TEST_DIR/diff_a.log"
printf "same content\n" > "$TEST_DIR/diff_b.log"
output=$("$CATALOG" diff "$TEST_DIR/diff_a.log" "$TEST_DIR/diff_b.log" 2>&1)
if echo "$output" | grep -q "Files: 2"; then
    echo -e "${GREEN}[PASS]${NC} multi_file_identical"
    inc_passed
else
    echo -e "${RED}[FAIL]${NC} multi_file_identical"
    inc_failed
    FAILED_TESTS="$FAILED_TESTS\n  - multi_file_identical"
fi

# Two different files
printf "file a only\nshared line\n" > "$TEST_DIR/diff_c.log"
printf "shared line\nfile b only\n" > "$TEST_DIR/diff_d.log"
output=$("$CATALOG" diff "$TEST_DIR/diff_c.log" "$TEST_DIR/diff_d.log" 2>&1)
if echo "$output" | grep -q "UNIQUE TO"; then
    echo -e "${GREEN}[PASS]${NC} multi_file_unique"
    inc_passed
else
    echo -e "${RED}[FAIL]${NC} multi_file_unique"
    inc_failed
    FAILED_TESTS="$FAILED_TESTS\n  - multi_file_unique"
fi

# Three files
printf "a\nb\n" > "$TEST_DIR/diff_e.log"
printf "b\nc\n" > "$TEST_DIR/diff_f.log"
printf "a\nc\n" > "$TEST_DIR/diff_g.log"
output=$("$CATALOG" diff "$TEST_DIR/diff_e.log" "$TEST_DIR/diff_f.log" "$TEST_DIR/diff_g.log" 2>&1)
if echo "$output" | grep -q "Files: 3"; then
    echo -e "${GREEN}[PASS]${NC} multi_file_three"
    inc_passed
else
    echo -e "${RED}[FAIL]${NC} multi_file_three"
    inc_failed
    FAILED_TESTS="$FAILED_TESTS\n  - multi_file_three"
fi

echo ""
echo "[Template Extraction - Edge Cases]"

# Lines with only delimiters
printf "= ; < >\n= ; < >\n" > "$TEST_DIR/diff_only_delim.log"
run_diff_test "only_delimiters" "$TEST_DIR/diff_only_delim.log" 1 4

# Unclosed brackets (should not hang)
printf "data [1, 2, 3\ndata [4, 5, 6\n" > "$TEST_DIR/diff_unclosed_bracket.log"
timeout 5 "$CATALOG" diff "$TEST_DIR/diff_unclosed_bracket.log" > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo -e "${GREEN}[PASS]${NC} unclosed_bracket_no_hang"
    inc_passed
else
    echo -e "${RED}[FAIL]${NC} unclosed_bracket_no_hang (timeout or error)"
    inc_failed
    FAILED_TESTS="$FAILED_TESTS\n  - unclosed_bracket_no_hang"
fi

# Deeply nested brackets
printf "data [[[[1]]]]\ndata [[[[2]]]]\n" > "$TEST_DIR/diff_deep_bracket.log"
run_diff_test "deep_nested_brackets" "$TEST_DIR/diff_deep_bracket.log" 1 -1

# Very long line
head -c 100000 /dev/zero | tr '\0' 'x' > "$TEST_DIR/diff_long_line.log"
echo "" >> "$TEST_DIR/diff_long_line.log"
timeout 10 "$CATALOG" diff "$TEST_DIR/diff_long_line.log" > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo -e "${GREEN}[PASS]${NC} very_long_line"
    inc_passed
else
    echo -e "${RED}[FAIL]${NC} very_long_line (timeout or error)"
    inc_failed
    FAILED_TESTS="$FAILED_TESTS\n  - very_long_line"
fi

# Binary-ish content (high bytes)
printf "data \x80\x81\x82 end\ndata \x90\x91\x92 end\n" > "$TEST_DIR/diff_binary.log"
timeout 5 "$CATALOG" diff "$TEST_DIR/diff_binary.log" > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo -e "${GREEN}[PASS]${NC} binary_content"
    inc_passed
else
    echo -e "${RED}[FAIL]${NC} binary_content (timeout or error)"
    inc_failed
    FAILED_TESTS="$FAILED_TESTS\n  - binary_content"
fi

# Stress: many lines, should complete quickly
for i in $(seq 1 10000); do
    echo "log $i ip=10.0.0.$((i % 256)) code=$i time=2024-01-01T00:00:$((i % 60))Z"
done > "$TEST_DIR/diff_stress.log"
START=$(date +%s%N)
"$CATALOG" diff "$TEST_DIR/diff_stress.log" > /dev/null 2>&1
END=$(date +%s%N)
ELAPSED=$(( (END - START) / 1000000 ))
if [ $ELAPSED -lt 5000 ]; then  # Should complete in under 5 seconds
    echo -e "${GREEN}[PASS]${NC} diff_10k_lines (${ELAPSED}ms)"
    inc_passed
else
    echo -e "${YELLOW}[WARN]${NC} diff_10k_lines slow (${ELAPSED}ms)"
    inc_passed
fi

echo ""
echo "[Template Extraction - Pointer/Null Values]"

# NULL values consolidation
printf "result=NULL status=ok\nresult=None status=ok\nresult=nil status=ok\n" > "$TEST_DIR/diff_ptr.log"
run_diff_test "ptr_null_consolidation" "$TEST_DIR/diff_ptr.log" 1 -1
run_diff_pattern_test "ptr_placeholder" "$TEST_DIR/diff_ptr.log" "<PTR>"

# All pointer value variants
printf "val=NULL\nval=null\nval=None\nval=none\nval=nil\nval=nullptr\n" > "$TEST_DIR/diff_ptr_all.log"
run_diff_test "ptr_all_variants" "$TEST_DIR/diff_ptr_all.log" 1 -1

# Pointer should not match prefixes
printf "value=NULLABLE\nvalue=nullify\nvalue=NoneType\n" > "$TEST_DIR/diff_ptr_prefix.log"
output=$("$CATALOG" diff "$TEST_DIR/diff_ptr_prefix.log" 2>&1)
if echo "$output" | grep -qF "<PTR>"; then
    echo -e "${RED}[FAIL]${NC} ptr_no_prefix_match (incorrectly matched as PTR)"
    inc_failed
    FAILED_TESTS="$FAILED_TESTS\n  - ptr_no_prefix_match"
else
    echo -e "${GREEN}[PASS]${NC} ptr_no_prefix_match"
    inc_passed
fi

echo ""
echo "[Template Extraction - New Delimiters]"

# Parentheses as delimiters - ptrinterface pattern
printf "ptr=ptrinterface(0x1234)\nptr=ptrinterface(0x5678)\nptr=ptrinterface(0xabcd)\n" > "$TEST_DIR/diff_parens.log"
run_diff_test "parens_delimiter" "$TEST_DIR/diff_parens.log" 1 -1
run_diff_pattern_test "parens_hex_extraction" "$TEST_DIR/diff_parens.log" "<HEX>"

# Curly braces as delimiters
printf "config={'key': 1}\nconfig={'key': 2}\n" > "$TEST_DIR/diff_braces.log"
run_diff_test "braces_delimiter" "$TEST_DIR/diff_braces.log" 1 -1

# Colon as delimiter - PeerId pattern
printf "peer=PeerId:47\npeer=PeerId:99\npeer=PeerId:123\n" > "$TEST_DIR/diff_colon.log"
run_diff_test "colon_delimiter" "$TEST_DIR/diff_colon.log" 1 -1

# Verify colon produces separate tokens
output=$("$CATALOG" diff "$TEST_DIR/diff_colon.log" 2>&1)
if echo "$output" | grep -qE "PeerId.*:.*<NUM>"; then
    echo -e "${GREEN}[PASS]${NC} colon_splits_tokens"
    inc_passed
else
    echo -e "${RED}[FAIL]${NC} colon_splits_tokens (expected PeerId : <NUM>)"
    inc_failed
    FAILED_TESTS="$FAILED_TESTS\n  - colon_splits_tokens"
fi

# Mixed delimiters - comma is not a delimiter, so "1," and "2," are different tokens
printf "func(arg=1, opt=true)\nfunc(arg=2, opt=false)\n" > "$TEST_DIR/diff_mixed_delim.log"
run_diff_test "mixed_delimiters_parens_equals" "$TEST_DIR/diff_mixed_delim.log" 2 -1

# Mixed delimiters without comma (should consolidate)
printf "func(arg=1 opt=true)\nfunc(arg=2 opt=false)\n" > "$TEST_DIR/diff_mixed_delim2.log"
run_diff_test "mixed_delimiters_no_comma" "$TEST_DIR/diff_mixed_delim2.log" 1 -1

# Function call with hex pointer
printf "call foo(0xdead)\ncall foo(0xbeef)\n" > "$TEST_DIR/diff_func_hex.log"
run_diff_test "func_call_hex" "$TEST_DIR/diff_func_hex.log" 1 -1
run_diff_pattern_test "func_call_hex_placeholder" "$TEST_DIR/diff_func_hex.log" "<HEX>"

# Nested parentheses
printf "outer(inner(123))\nouter(inner(456))\n" > "$TEST_DIR/diff_nested_parens.log"
run_diff_test "nested_parens" "$TEST_DIR/diff_nested_parens.log" 1 -1

# Empty parens
printf "call init()\ncall init()\n" > "$TEST_DIR/diff_empty_parens.log"
run_diff_test "empty_parens" "$TEST_DIR/diff_empty_parens.log" 1 -1

# Complex real-world pattern (similar to ribout log)
printf "peer=ptrinterface(0x1234) action=advertise attr=None\n" > "$TEST_DIR/diff_ribout_like.log"
printf "peer=ptrinterface(0x5678) action=withdraw attr=None\n" >> "$TEST_DIR/diff_ribout_like.log"
printf "peer=ptrinterface(0xabcd) action=advertise attr=NULL\n" >> "$TEST_DIR/diff_ribout_like.log"
run_diff_test "ribout_like_pattern" "$TEST_DIR/diff_ribout_like.log" 2 -1  # 2 templates: advertise vs withdraw

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
