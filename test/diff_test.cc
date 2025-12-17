// diff_test.cc - Unit tests for diff functionality
// Tests classifiers, TemplateMap, and core diff operations

#include <cassert>
#include <cstring>
#include <iostream>
#include <string>
#include <atomic>

// Include the header to test
#include "../src/diff.h"

//=============================================================================
// Test Framework (minimal)
//=============================================================================

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) \
    void test_##name(); \
    struct TestRunner_##name { \
        TestRunner_##name() { \
            std::cout << "  " << #name << "... "; \
            ++tests_run; \
            try { \
                test_##name(); \
                ++tests_passed; \
                std::cout << "PASS\n"; \
            } catch (const std::exception& e) { \
                std::cout << "FAIL: " << e.what() << "\n"; \
            } catch (...) { \
                std::cout << "FAIL: unknown exception\n"; \
            } \
        } \
    } runner_##name; \
    void test_##name()

#define ASSERT_TRUE(expr) \
    do { if (!(expr)) throw std::runtime_error("Assertion failed: " #expr); } while(0)

#define ASSERT_FALSE(expr) \
    do { if (expr) throw std::runtime_error("Assertion failed: NOT " #expr); } while(0)

#define ASSERT_EQ(a, b) \
    do { if ((a) != (b)) throw std::runtime_error("Assertion failed: " #a " == " #b); } while(0)

//=============================================================================
// is_digit tests
//=============================================================================

TEST(is_digit_basic) {
    ASSERT_TRUE(is_digit('0'));
    ASSERT_TRUE(is_digit('5'));
    ASSERT_TRUE(is_digit('9'));
    ASSERT_FALSE(is_digit('a'));
    ASSERT_FALSE(is_digit('A'));
    ASSERT_FALSE(is_digit(' '));
    ASSERT_FALSE(is_digit('-'));
}

//=============================================================================
// is_xdigit tests
//=============================================================================

TEST(is_xdigit_basic) {
    ASSERT_TRUE(is_xdigit('0'));
    ASSERT_TRUE(is_xdigit('9'));
    ASSERT_TRUE(is_xdigit('a'));
    ASSERT_TRUE(is_xdigit('f'));
    ASSERT_TRUE(is_xdigit('A'));
    ASSERT_TRUE(is_xdigit('F'));
    ASSERT_FALSE(is_xdigit('g'));
    ASSERT_FALSE(is_xdigit('G'));
    ASSERT_FALSE(is_xdigit(' '));
}

//=============================================================================
// is_number tests
//=============================================================================

TEST(is_number_integers) {
    ASSERT_TRUE(is_number("123", 3));
    ASSERT_TRUE(is_number("0", 1));
    ASSERT_TRUE(is_number("999999", 6));
}

TEST(is_number_signed) {
    ASSERT_TRUE(is_number("-123", 4));
    ASSERT_TRUE(is_number("+456", 4));
    ASSERT_TRUE(is_number("-0", 2));
}

TEST(is_number_decimals) {
    ASSERT_TRUE(is_number("123.456", 7));
    ASSERT_TRUE(is_number("0.5", 3));
    ASSERT_TRUE(is_number("-99.99", 6));
}

TEST(is_number_invalid) {
    ASSERT_FALSE(is_number("", 0));
    ASSERT_FALSE(is_number("-", 1));
    ASSERT_FALSE(is_number("abc", 3));
    ASSERT_FALSE(is_number("12.34.56", 8));  // Multiple dots
    ASSERT_FALSE(is_number("12a34", 5));
    ASSERT_FALSE(is_number("hello123", 8));
}

//=============================================================================
// is_hex tests
//=============================================================================

TEST(is_hex_with_prefix) {
    ASSERT_TRUE(is_hex("0x1a2b", 6));
    ASSERT_TRUE(is_hex("0X1A2B", 6));
    ASSERT_TRUE(is_hex("0xdeadbeef", 10));
    ASSERT_TRUE(is_hex("0x0", 3));
}

TEST(is_hex_pure_long) {
    // 8+ hex chars without prefix
    ASSERT_TRUE(is_hex("deadbeef", 8));
    ASSERT_TRUE(is_hex("1234567890abcdef", 16));
    ASSERT_TRUE(is_hex("ABCDEF00", 8));
}

TEST(is_hex_invalid) {
    ASSERT_FALSE(is_hex("0x", 2));      // Just prefix
    ASSERT_FALSE(is_hex("abc", 3));     // Too short for pure hex
    ASSERT_FALSE(is_hex("0xghij", 6));  // Invalid hex chars
    ASSERT_FALSE(is_hex("123", 3));     // Short number, not hex
    ASSERT_FALSE(is_hex("abcdefg", 7)); // Contains 'g'
}

//=============================================================================
// is_ip tests
//=============================================================================

TEST(is_ip_basic) {
    ASSERT_TRUE(is_ip("0.0.0.0", 7));
    ASSERT_TRUE(is_ip("10.0.0.1", 8));
    ASSERT_TRUE(is_ip("192.168.1.1", 11));
    ASSERT_TRUE(is_ip("255.255.255.255", 15));
}

TEST(is_ip_with_port) {
    ASSERT_TRUE(is_ip("10.0.0.1:8080", 13));
    ASSERT_TRUE(is_ip("192.168.1.1:80", 14));
    ASSERT_TRUE(is_ip("127.0.0.1:65535", 15));
}

TEST(is_ip_invalid) {
    ASSERT_FALSE(is_ip("", 0));
    ASSERT_FALSE(is_ip("10.0.0", 7));       // Only 2 dots
    ASSERT_FALSE(is_ip("10.0.0.0.1", 11));  // 4 dots
    ASSERT_FALSE(is_ip("10.0.0.1:", 9));    // Port separator but no port
    ASSERT_FALSE(is_ip("10.0.0.1:abc", 12)); // Non-numeric port
    // Note: "256.0.0.1" passes - we only check format, not octet value ranges
    ASSERT_TRUE(is_ip("256.0.0.1", 9));     // Format valid, value range not checked
    ASSERT_FALSE(is_ip("10.0.0.1:123456", 15)); // Port too long
}

//=============================================================================
// is_timestamp tests
//=============================================================================

TEST(is_timestamp_date) {
    ASSERT_TRUE(is_timestamp("2024-12-16", 10));
    ASSERT_TRUE(is_timestamp("2024-01-01", 10));
}

TEST(is_timestamp_time) {
    ASSERT_TRUE(is_timestamp("10:30:45", 8));
    ASSERT_TRUE(is_timestamp("23:59:59", 8));
}

TEST(is_timestamp_datetime) {
    ASSERT_TRUE(is_timestamp("2024-12-16T10:30:45", 19));
    ASSERT_TRUE(is_timestamp("2024-12-16T10:30:45Z", 20));
    ASSERT_TRUE(is_timestamp("2024-12-16T10:30:45.123", 23));
}

TEST(is_timestamp_invalid) {
    ASSERT_FALSE(is_timestamp("hello", 5));
    ASSERT_FALSE(is_timestamp("12:34", 5));     // Too short
    ASSERT_FALSE(is_timestamp("2024", 4));      // Too short
    ASSERT_FALSE(is_timestamp("abcd-ef-gh", 10)); // Letters not allowed
}

//=============================================================================
// is_path tests
//=============================================================================

TEST(is_path_unix) {
    ASSERT_TRUE(is_path("/foo/bar", 8));
    ASSERT_TRUE(is_path("/usr/local/bin", 14));
    ASSERT_TRUE(is_path("/", 1) == false);  // Too short
    ASSERT_TRUE(is_path("/a", 2));
}

TEST(is_path_relative) {
    ASSERT_TRUE(is_path("./foo", 5));
    ASSERT_TRUE(is_path("./a/b/c", 7));
}

TEST(is_path_url_like) {
    ASSERT_TRUE(is_path("file://foo", 10));
    ASSERT_TRUE(is_path("http://bar", 10));
}

TEST(is_path_invalid) {
    ASSERT_FALSE(is_path("", 0));
    ASSERT_FALSE(is_path("a", 1));
    ASSERT_FALSE(is_path("foo", 3));
    ASSERT_FALSE(is_path("foo.bar", 7));
}

//=============================================================================
// is_uuid_or_hash tests
//=============================================================================

TEST(is_uuid_format) {
    ASSERT_TRUE(is_uuid_or_hash("12345678-1234-1234-1234-123456789abc", 36));
    ASSERT_TRUE(is_uuid_or_hash("ABCDEF00-1234-5678-9ABC-DEF012345678", 36));
}

TEST(is_hash_long) {
    // 32+ hex chars
    ASSERT_TRUE(is_uuid_or_hash("12345678901234567890123456789012", 32));
    ASSERT_TRUE(is_uuid_or_hash("deadbeefdeadbeefdeadbeefdeadbeef", 32));
    ASSERT_TRUE(is_uuid_or_hash("abcdef0123456789abcdef0123456789abcdef01", 40));
}

TEST(is_uuid_or_hash_invalid) {
    ASSERT_FALSE(is_uuid_or_hash("12345678", 8));      // Too short
    ASSERT_FALSE(is_uuid_or_hash("1234567890123456", 16)); // Not 32+
    // UUID with wrong dash positions
    ASSERT_FALSE(is_uuid_or_hash("1234567-81234-1234-1234-123456789abc", 36));
}

//=============================================================================
// classify_token tests
//=============================================================================

TEST(classify_numbers) {
    ASSERT_EQ(classify_token("123", 3), VarType::VAR_NUM);
    ASSERT_EQ(classify_token("-456.78", 7), VarType::VAR_NUM);
    ASSERT_EQ(classify_token("0", 1), VarType::VAR_NUM);
}

TEST(classify_hex) {
    ASSERT_EQ(classify_token("0x1234", 6), VarType::VAR_HEX);
    ASSERT_EQ(classify_token("deadbeef", 8), VarType::VAR_HEX);
}

TEST(classify_ip) {
    ASSERT_EQ(classify_token("10.0.0.1", 8), VarType::VAR_IP);
    ASSERT_EQ(classify_token("192.168.1.1:8080", 16), VarType::VAR_IP);
}

TEST(classify_timestamp) {
    ASSERT_EQ(classify_token("2024-12-16", 10), VarType::VAR_TIME);
    ASSERT_EQ(classify_token("10:30:45", 8), VarType::VAR_TIME);
}

TEST(classify_path) {
    ASSERT_EQ(classify_token("/usr/bin", 8), VarType::VAR_PATH);
    ASSERT_EQ(classify_token("./foo", 5), VarType::VAR_PATH);
}

TEST(classify_uuid) {
    ASSERT_EQ(classify_token("12345678-1234-1234-1234-123456789abc", 36), VarType::VAR_ID);
    ASSERT_EQ(classify_token("12345678901234567890123456789012", 32), VarType::VAR_ID);
}

TEST(classify_literal) {
    ASSERT_EQ(classify_token("hello", 5), VarType::LITERAL);
    ASSERT_EQ(classify_token("ERROR:", 6), VarType::LITERAL);
    ASSERT_EQ(classify_token("Connection", 10), VarType::LITERAL);
}

//=============================================================================
// TemplateSlot equality tests
//=============================================================================

TEST(template_slot_equality) {
    TemplateSlot a{VarType::LITERAL, 42};
    TemplateSlot b{VarType::LITERAL, 42};
    TemplateSlot c{VarType::LITERAL, 43};
    TemplateSlot d{VarType::VAR_NUM, 0};
    TemplateSlot e{VarType::VAR_NUM, 99};  // token_id ignored for non-literals

    ASSERT_TRUE(a == b);
    ASSERT_FALSE(a == c);  // Different token_id
    ASSERT_FALSE(a == d);  // Different type
    ASSERT_TRUE(d == e);   // Same type, token_id ignored for VAR_*
}

//=============================================================================
// template_hash tests
//=============================================================================

TEST(template_hash_deterministic) {
    TemplateSlot slots1[] = {
        {VarType::LITERAL, 1},
        {VarType::VAR_NUM, 0},
        {VarType::LITERAL, 2}
    };
    TemplateSlot slots2[] = {
        {VarType::LITERAL, 1},
        {VarType::VAR_NUM, 0},
        {VarType::LITERAL, 2}
    };
    TemplateSlot slots3[] = {
        {VarType::LITERAL, 1},
        {VarType::VAR_IP, 0},  // Different var type
        {VarType::LITERAL, 2}
    };

    uint64_t h1 = template_hash(slots1, 3);
    uint64_t h2 = template_hash(slots2, 3);
    uint64_t h3 = template_hash(slots3, 3);

    ASSERT_EQ(h1, h2);
    ASSERT_TRUE(h1 != h3);
}

//=============================================================================
// TemplateMap tests
//=============================================================================

TEST(template_map_insert_and_retrieve) {
    TemplateMap tmap(256);
    std::atomic<uint32_t> next_id{0};

    TemplateSlot slots1[] = {
        {VarType::LITERAL, 10},
        {VarType::VAR_NUM, 0}
    };

    uint32_t id1 = tmap.get_or_insert(slots1, 2, next_id);
    uint32_t id2 = tmap.get_or_insert(slots1, 2, next_id);

    ASSERT_EQ(id1, id2);  // Same template should return same ID
    ASSERT_EQ(id1, 0u);   // First ID should be 0
    ASSERT_EQ(next_id.load(), 1u);  // Only one template added
}

TEST(template_map_different_templates) {
    TemplateMap tmap(256);
    std::atomic<uint32_t> next_id{0};

    TemplateSlot slots1[] = {{VarType::LITERAL, 10}};
    TemplateSlot slots2[] = {{VarType::LITERAL, 20}};
    TemplateSlot slots3[] = {{VarType::VAR_NUM, 0}};

    uint32_t id1 = tmap.get_or_insert(slots1, 1, next_id);
    uint32_t id2 = tmap.get_or_insert(slots2, 1, next_id);
    uint32_t id3 = tmap.get_or_insert(slots3, 1, next_id);

    ASSERT_TRUE(id1 != id2);
    ASSERT_TRUE(id2 != id3);
    ASSERT_TRUE(id1 != id3);
    ASSERT_EQ(next_id.load(), 3u);
}

TEST(template_map_get) {
    TemplateMap tmap(256);
    std::atomic<uint32_t> next_id{0};

    TemplateSlot slots[] = {
        {VarType::LITERAL, 100},
        {VarType::VAR_IP, 0},
        {VarType::LITERAL, 200}
    };

    uint32_t id = tmap.get_or_insert(slots, 3, next_id);
    const TemplateMap::Entry* entry = tmap.get(id);

    ASSERT_TRUE(entry != nullptr);
    ASSERT_EQ(entry->slots.size(), 3u);
    ASSERT_EQ(entry->var_count, 1u);
    ASSERT_TRUE(entry->slots[0] == slots[0]);
    ASSERT_TRUE(entry->slots[1] == slots[1]);
    ASSERT_TRUE(entry->slots[2] == slots[2]);
}

//=============================================================================
// var_type_name and var_type_placeholder tests
//=============================================================================

TEST(var_type_name_all) {
    ASSERT_EQ(std::string(var_type_name(VarType::LITERAL)), "LIT");
    ASSERT_EQ(std::string(var_type_name(VarType::VAR_NUM)), "NUM");
    ASSERT_EQ(std::string(var_type_name(VarType::VAR_HEX)), "HEX");
    ASSERT_EQ(std::string(var_type_name(VarType::VAR_IP)), "IP");
    ASSERT_EQ(std::string(var_type_name(VarType::VAR_TIME)), "TIME");
    ASSERT_EQ(std::string(var_type_name(VarType::VAR_PATH)), "PATH");
    ASSERT_EQ(std::string(var_type_name(VarType::VAR_ID)), "ID");
    ASSERT_EQ(std::string(var_type_name(VarType::VAR_PREFIX)), "PREFIX");
    ASSERT_EQ(std::string(var_type_name(VarType::VAR_ARRAY)), "ARRAY");
    ASSERT_EQ(std::string(var_type_name(VarType::VAR_BOOL)), "BOOL");
    ASSERT_EQ(std::string(var_type_name(VarType::VAR_PTR)), "PTR");
}

TEST(var_type_placeholder_all) {
    ASSERT_EQ(std::string(var_type_placeholder(VarType::LITERAL)), "");
    ASSERT_EQ(std::string(var_type_placeholder(VarType::VAR_NUM)), "<NUM>");
    ASSERT_EQ(std::string(var_type_placeholder(VarType::VAR_HEX)), "<HEX>");
    ASSERT_EQ(std::string(var_type_placeholder(VarType::VAR_IP)), "<IP>");
    ASSERT_EQ(std::string(var_type_placeholder(VarType::VAR_TIME)), "<TIME>");
    ASSERT_EQ(std::string(var_type_placeholder(VarType::VAR_PATH)), "<PATH>");
    ASSERT_EQ(std::string(var_type_placeholder(VarType::VAR_ID)), "<ID>");
    ASSERT_EQ(std::string(var_type_placeholder(VarType::VAR_PREFIX)), "<PREFIX>");
    ASSERT_EQ(std::string(var_type_placeholder(VarType::VAR_ARRAY)), "<ARRAY>");
    ASSERT_EQ(std::string(var_type_placeholder(VarType::VAR_BOOL)), "<BOOL>");
    ASSERT_EQ(std::string(var_type_placeholder(VarType::VAR_PTR)), "<PTR>");
}

//=============================================================================
// EDGE CASES AND ADVERSARIAL TESTS
//=============================================================================

//-----------------------------------------------------------------------------
// Number edge cases
//-----------------------------------------------------------------------------

TEST(is_number_leading_zeros) {
    ASSERT_TRUE(is_number("007", 3));      // Leading zeros OK
    ASSERT_TRUE(is_number("0123", 4));
    ASSERT_TRUE(is_number("00000", 5));
}

TEST(is_number_boundary_cases) {
    ASSERT_FALSE(is_number(".", 1));       // Just a dot
    ASSERT_FALSE(is_number("..", 2));      // Two dots
    ASSERT_TRUE(is_number(".5", 2));       // Leading dot with digit
    ASSERT_TRUE(is_number("5.", 2));       // Trailing dot
    ASSERT_FALSE(is_number("+", 1));       // Just sign
    ASSERT_FALSE(is_number("+-1", 3));     // Multiple signs
    ASSERT_FALSE(is_number("1-", 2));      // Sign at end
    ASSERT_FALSE(is_number("1+2", 3));     // Sign in middle
}

TEST(is_number_scientific_notation) {
    // Scientific notation is NOT supported - classified as literal
    ASSERT_FALSE(is_number("1e10", 4));
    ASSERT_FALSE(is_number("1.5e-3", 6));
    ASSERT_FALSE(is_number("1E10", 4));
}

TEST(is_number_very_long) {
    // Very long numbers
    const char* long_num = "12345678901234567890123456789012345678901234567890";
    ASSERT_TRUE(is_number(long_num, 50));

    const char* long_decimal = "123456789.123456789123456789";
    ASSERT_TRUE(is_number(long_decimal, 28));
}

TEST(is_number_weird_decimals) {
    ASSERT_TRUE(is_number("0.0", 3));
    ASSERT_TRUE(is_number(".0", 2));
    ASSERT_TRUE(is_number("0.", 2));
    ASSERT_FALSE(is_number("0.0.0", 5));   // Multiple dots
    ASSERT_TRUE(is_number("-.5", 3));      // Negative with leading dot
    ASSERT_TRUE(is_number("+.5", 3));      // Positive with leading dot
}

//-----------------------------------------------------------------------------
// Hex edge cases
//-----------------------------------------------------------------------------

TEST(is_hex_boundary_length) {
    // Exactly 7 chars - too short for pure hex
    ASSERT_FALSE(is_hex("abcdef0", 7));
    // Exactly 8 chars - minimum for pure hex
    ASSERT_TRUE(is_hex("abcdef01", 8));
    // 0x prefix variations
    ASSERT_TRUE(is_hex("0x1", 3));         // Minimum with prefix
    ASSERT_FALSE(is_hex("0X", 2));         // Just prefix uppercase
}

TEST(is_hex_mixed_case) {
    ASSERT_TRUE(is_hex("DeAdBeEf", 8));
    ASSERT_TRUE(is_hex("0xDeAdBeEf", 10));
    ASSERT_TRUE(is_hex("ABCDEFabcdef", 12));
}

TEST(is_hex_almost_valid) {
    ASSERT_FALSE(is_hex("0xGHIJ", 6));     // Invalid after prefix
    ASSERT_FALSE(is_hex("ghijklmn", 8));   // 8 chars but not hex
    ASSERT_FALSE(is_hex("0x12345g", 8));   // Valid prefix then invalid
    ASSERT_FALSE(is_hex("abcdefgh", 8));   // 'g' and 'h' not hex
}

TEST(is_hex_with_common_prefixes) {
    // Common non-hex prefixes that might look like hex
    ASSERT_FALSE(is_hex("0b1010", 6));     // Binary prefix
    ASSERT_FALSE(is_hex("0o777", 5));      // Octal prefix
}

//-----------------------------------------------------------------------------
// IP edge cases
//-----------------------------------------------------------------------------

TEST(is_ip_single_digit_octets) {
    ASSERT_TRUE(is_ip("1.2.3.4", 7));
    ASSERT_TRUE(is_ip("0.0.0.0", 7));
    ASSERT_TRUE(is_ip("1.1.1.1", 7));
}

TEST(is_ip_leading_zeros) {
    // Leading zeros in octets - format valid
    ASSERT_TRUE(is_ip("01.02.03.04", 11));
    ASSERT_TRUE(is_ip("001.002.003.004", 15));
}

TEST(is_ip_malformed) {
    ASSERT_FALSE(is_ip(".1.2.3.4", 8));    // Leading dot
    ASSERT_FALSE(is_ip("1.2.3.4.", 8));    // Trailing dot
    ASSERT_FALSE(is_ip("1..2.3.4", 8));    // Double dot
    ASSERT_FALSE(is_ip("1.2.3", 5));       // Only 3 octets
    ASSERT_FALSE(is_ip("1.2.3.4.5", 9));   // 5 octets
    ASSERT_FALSE(is_ip("1.2.3.4::", 10));  // Double colon
    ASSERT_FALSE(is_ip("1234.1.1.1", 10)); // 4-digit octet
}

TEST(is_ip_port_edge_cases) {
    ASSERT_TRUE(is_ip("1.2.3.4:0", 9));        // Port 0
    ASSERT_TRUE(is_ip("1.2.3.4:1", 9));        // Port 1
    ASSERT_TRUE(is_ip("1.2.3.4:65535", 13));   // Max valid port (13 chars, not 14)
    ASSERT_FALSE(is_ip("1.2.3.4:", 8));        // Colon but no port
    ASSERT_FALSE(is_ip("1.2.3.4::", 9));       // Double colon
    ASSERT_FALSE(is_ip("1.2.3.4:-1", 10));     // Negative port
}

TEST(is_ip_ipv6_basic) {
    // IPv6 addresses now match is_ip
    ASSERT_TRUE(is_ip("::1", 3));
    ASSERT_TRUE(is_ip("::ffff", 6));
    ASSERT_TRUE(is_ip("fe80::1", 7));
    ASSERT_TRUE(is_ip("2001:db8::1", 11));
    ASSERT_TRUE(is_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334", 39));
}

TEST(is_ip_ipv6_compressed) {
    // Compressed forms
    ASSERT_TRUE(is_ip("::", 2));
    ASSERT_TRUE(is_ip("::1", 3));
    ASSERT_TRUE(is_ip("fe80::", 6));
    ASSERT_TRUE(is_ip("2001:db8::8a2e:370:7334", 23));
}

TEST(is_ip_ipv6_with_prefix) {
    // IPv6 with CIDR prefix
    ASSERT_TRUE(is_ip("2001:db8::/32", 13));
    ASSERT_TRUE(is_ip("fe80::/10", 9));
    ASSERT_TRUE(is_ip("::1/128", 7));
}

TEST(is_ip_ipv6_with_zone) {
    // IPv6 with zone ID
    ASSERT_TRUE(is_ip("fe80::1%eth0", 12));
}

TEST(is_ip_ipv6_invalid) {
    // Invalid IPv6
    ASSERT_FALSE(is_ip(":", 1));           // Single colon
    ASSERT_FALSE(is_ip(":::", 3));         // Triple colon
    ASSERT_FALSE(is_ip("2001::db8::1", 12)); // Double :: (only one allowed)
    ASSERT_FALSE(is_ip("gggg::1", 7));     // Invalid hex chars
}

TEST(is_ip_lookalikes) {
    // Things that look like IPs but aren't
    ASSERT_FALSE(is_ip("1.2.3", 5));           // Version number
    ASSERT_FALSE(is_ip("v1.2.3", 6));          // Version with prefix
    ASSERT_TRUE(is_ip("1.2.3.4", 7));          // But this is valid
}

//-----------------------------------------------------------------------------
// Timestamp edge cases
//-----------------------------------------------------------------------------

TEST(is_timestamp_epoch) {
    // Unix epoch timestamps (just digits) are NOT timestamps
    ASSERT_FALSE(is_timestamp("1702756245", 10));
    ASSERT_FALSE(is_timestamp("1702756245000", 13));  // Milliseconds
}

TEST(is_timestamp_partial) {
    // Partial timestamps
    ASSERT_FALSE(is_timestamp("12:34", 5));    // Too short
    ASSERT_FALSE(is_timestamp("2024-12", 7));  // Too short
    ASSERT_TRUE(is_timestamp("12:34:56", 8));  // Minimum valid time
}

TEST(is_timestamp_with_timezone) {
    // Note: Our classifier only allows digits and '-:TZ.' characters
    // '+' in timezone offsets is NOT supported
    ASSERT_FALSE(is_timestamp("2024-12-16T10:30:45+00:00", 25));  // '+' not allowed
    ASSERT_TRUE(is_timestamp("2024-12-16T10:30:45-05:00", 25));   // '-' IS allowed
    ASSERT_TRUE(is_timestamp("2024-12-16T10:30:45.123Z", 24));
}

TEST(is_timestamp_unusual_formats) {
    // Various date/time formats
    // Note: Our classifier requires >=2 separators, so compact dates fail
    ASSERT_FALSE(is_timestamp("20241216", 8));     // No separators - fails
    ASSERT_FALSE(is_timestamp("103045", 6));       // Too short and no separators
    ASSERT_TRUE(is_timestamp("2024.12.16", 10));   // Dot separator works
}

TEST(is_timestamp_lookalikes) {
    // Things with digits and separators but not timestamps
    ASSERT_FALSE(is_timestamp("1-2-3-4-5", 9));   // Only 5 digits
    ASSERT_TRUE(is_timestamp("1-2-3-4-5-6", 11)); // 6+ digits, 5 separators - passes!
}

//-----------------------------------------------------------------------------
// Path edge cases
//-----------------------------------------------------------------------------

TEST(is_path_windows) {
    // Windows paths with drive letter
    ASSERT_TRUE(is_path("C:/foo", 6));
    ASSERT_TRUE(is_path("D:/bar/baz", 10));
    // Backslashes - our classifier doesn't handle these
    ASSERT_FALSE(is_path("C:\\foo", 6));
}

TEST(is_path_special_chars) {
    ASSERT_TRUE(is_path("/path/with spaces/file", 22));
    ASSERT_TRUE(is_path("/path/with-dashes", 17));
    ASSERT_TRUE(is_path("/path/with_underscores", 22));
    ASSERT_TRUE(is_path("/path/with.dots", 15));
}

TEST(is_path_edge_patterns) {
    // Note: "./" matches our path rule (s[0]=='.' && s[1]=='/')
    ASSERT_TRUE(is_path("./", 2));            // Relative prefix IS a valid path
    ASSERT_TRUE(is_path("./a", 3));           // Minimum relative with content
    ASSERT_TRUE(is_path("//server/share", 14)); // UNC-like
    ASSERT_TRUE(is_path("///triple", 9));     // Triple slash
}

TEST(is_path_protocol_urls) {
    ASSERT_TRUE(is_path("http://example.com", 18));
    ASSERT_TRUE(is_path("https://secure.com", 18));
    ASSERT_TRUE(is_path("ftp://files.com", 15));
    ASSERT_TRUE(is_path("s3://bucket/key", 15));
}

//-----------------------------------------------------------------------------
// UUID/Hash edge cases
//-----------------------------------------------------------------------------

TEST(is_uuid_wrong_dashes) {
    // UUID with dashes in wrong positions
    ASSERT_FALSE(is_uuid_or_hash("1234567-81234-1234-1234-123456789abc", 36));
    ASSERT_FALSE(is_uuid_or_hash("123456781-234-1234-1234-123456789abc", 36));
    ASSERT_FALSE(is_uuid_or_hash("12345678-123-41234-1234-123456789abc", 36));
}

TEST(is_uuid_boundary_lengths) {
    // Just under 32 chars
    ASSERT_FALSE(is_uuid_or_hash("1234567890123456789012345678901", 31));
    // Exactly 32 chars
    ASSERT_TRUE(is_uuid_or_hash("12345678901234567890123456789012", 32));
    // 33 chars
    ASSERT_TRUE(is_uuid_or_hash("123456789012345678901234567890123", 33));
}

TEST(is_uuid_invalid_chars) {
    // UUID format but with invalid chars
    ASSERT_FALSE(is_uuid_or_hash("1234567g-1234-1234-1234-123456789abc", 36));
    // Long hex-like but with invalid char
    ASSERT_FALSE(is_uuid_or_hash("123456789012345678901234567890gh", 32));
}

TEST(is_uuid_real_examples) {
    // Real UUID v4
    ASSERT_TRUE(is_uuid_or_hash("550e8400-e29b-41d4-a716-446655440000", 36));
    // MD5 hash
    ASSERT_TRUE(is_uuid_or_hash("d41d8cd98f00b204e9800998ecf8427e", 32));
    // SHA1 hash (40 chars)
    ASSERT_TRUE(is_uuid_or_hash("da39a3ee5e6b4b0d3255bfef95601890afd80709", 40));
    // SHA256 hash (64 chars)
    ASSERT_TRUE(is_uuid_or_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 64));
}

//-----------------------------------------------------------------------------
// Classifier priority/ambiguity tests
//-----------------------------------------------------------------------------

TEST(classify_priority_uuid_over_hex) {
    // UUID should be detected before hex (32+ hex chars)
    ASSERT_EQ(classify_token("12345678901234567890123456789012", 32), VarType::VAR_ID);
    ASSERT_EQ(classify_token("550e8400-e29b-41d4-a716-446655440000", 36), VarType::VAR_ID);
}

TEST(classify_priority_ip_over_timestamp) {
    // IP should be detected before timestamp
    ASSERT_EQ(classify_token("10.0.0.1", 8), VarType::VAR_IP);
    ASSERT_EQ(classify_token("192.168.1.1", 11), VarType::VAR_IP);
}

TEST(classify_ambiguous_patterns) {
    // "12-34-56" - could be timestamp-like
    // Our classifier: 6 digits, 2 separators, len=8 -> IS timestamp
    ASSERT_EQ(classify_token("12-34-56", 8), VarType::VAR_TIME);

    // "1.2.3" - version number, not IP (only 2 dots)
    ASSERT_EQ(classify_token("1.2.3", 5), VarType::LITERAL);

    // "0x12345678" - hex with 8 chars after prefix
    ASSERT_EQ(classify_token("0x12345678", 10), VarType::VAR_HEX);
}

TEST(classify_near_miss_patterns) {
    // Almost an IP but not quite
    ASSERT_EQ(classify_token("1.2.3", 5), VarType::LITERAL);
    ASSERT_EQ(classify_token("1.2", 3), VarType::VAR_NUM);  // Looks like decimal!

    // Almost a UUID but too short - BUT has digits+dashes so matches timestamp!
    // 20 digits, 3 '-' separators, len=23, >=8 -> VAR_TIME
    ASSERT_EQ(classify_token("12345678-1234-1234-1234", 23), VarType::VAR_TIME);

    // Almost hex but 7 chars
    ASSERT_EQ(classify_token("abcdef1", 7), VarType::LITERAL);
}

//-----------------------------------------------------------------------------
// Special characters and weird input
//-----------------------------------------------------------------------------

TEST(classify_punctuation) {
    ASSERT_EQ(classify_token("hello!", 6), VarType::LITERAL);
    ASSERT_EQ(classify_token("foo@bar", 7), VarType::LITERAL);
    ASSERT_EQ(classify_token("#hashtag", 8), VarType::LITERAL);
    ASSERT_EQ(classify_token("$variable", 9), VarType::LITERAL);
    ASSERT_EQ(classify_token("100%", 4), VarType::LITERAL);  // Not a number!
}

TEST(classify_brackets_and_quotes) {
    ASSERT_EQ(classify_token("[array]", 7), VarType::LITERAL);
    ASSERT_EQ(classify_token("{object}", 8), VarType::LITERAL);
    ASSERT_EQ(classify_token("(parens)", 8), VarType::LITERAL);
    ASSERT_EQ(classify_token("\"quoted\"", 8), VarType::LITERAL);
    ASSERT_EQ(classify_token("'single'", 8), VarType::LITERAL);
}

TEST(classify_mixed_content) {
    ASSERT_EQ(classify_token("user123", 7), VarType::LITERAL);
    ASSERT_EQ(classify_token("123user", 7), VarType::LITERAL);
    ASSERT_EQ(classify_token("v1.2.3", 6), VarType::LITERAL);
    ASSERT_EQ(classify_token("error-404", 9), VarType::LITERAL);
    ASSERT_EQ(classify_token("2024-Q4", 7), VarType::LITERAL);
}

TEST(classify_log_common_tokens) {
    // Common log tokens
    ASSERT_EQ(classify_token("INFO", 4), VarType::LITERAL);
    ASSERT_EQ(classify_token("WARN", 4), VarType::LITERAL);
    ASSERT_EQ(classify_token("ERROR", 5), VarType::LITERAL);
    ASSERT_EQ(classify_token("DEBUG", 5), VarType::LITERAL);
    ASSERT_EQ(classify_token("[INFO]", 6), VarType::LITERAL);
    // null/None are now classified as VAR_PTR
    ASSERT_EQ(classify_token("null", 4), VarType::VAR_PTR);
    ASSERT_EQ(classify_token("NULL", 4), VarType::VAR_PTR);
    ASSERT_EQ(classify_token("None", 4), VarType::VAR_PTR);
    // true/false are now classified as VAR_BOOL
    ASSERT_EQ(classify_token("true", 4), VarType::VAR_BOOL);
    ASSERT_EQ(classify_token("false", 5), VarType::VAR_BOOL);
}

TEST(classify_booleans) {
    // Boolean values
    ASSERT_EQ(classify_token("true", 4), VarType::VAR_BOOL);
    ASSERT_EQ(classify_token("True", 4), VarType::VAR_BOOL);
    ASSERT_EQ(classify_token("TRUE", 4), VarType::VAR_BOOL);
    ASSERT_EQ(classify_token("false", 5), VarType::VAR_BOOL);
    ASSERT_EQ(classify_token("False", 5), VarType::VAR_BOOL);
    ASSERT_EQ(classify_token("FALSE", 5), VarType::VAR_BOOL);
    ASSERT_EQ(classify_token("yes", 3), VarType::VAR_BOOL);
    ASSERT_EQ(classify_token("Yes", 3), VarType::VAR_BOOL);
    ASSERT_EQ(classify_token("YES", 3), VarType::VAR_BOOL);
    ASSERT_EQ(classify_token("no", 2), VarType::VAR_BOOL);
    ASSERT_EQ(classify_token("No", 2), VarType::VAR_BOOL);
    ASSERT_EQ(classify_token("NO", 2), VarType::VAR_BOOL);
    ASSERT_EQ(classify_token("positive", 8), VarType::VAR_BOOL);
    ASSERT_EQ(classify_token("negative", 8), VarType::VAR_BOOL);
    ASSERT_EQ(classify_token("Positive", 8), VarType::VAR_BOOL);
    ASSERT_EQ(classify_token("Negative", 8), VarType::VAR_BOOL);
    // Not booleans
    ASSERT_EQ(classify_token("maybe", 5), VarType::LITERAL);
    ASSERT_EQ(classify_token("trueish", 7), VarType::LITERAL);
    ASSERT_EQ(classify_token("falsehood", 9), VarType::LITERAL);
}

//=============================================================================
// is_ptr tests
//=============================================================================

TEST(is_ptr_null_variants) {
    // NULL variants
    ASSERT_TRUE(is_ptr("NULL", 4));
    ASSERT_TRUE(is_ptr("null", 4));
    // None variants
    ASSERT_TRUE(is_ptr("None", 4));
    ASSERT_TRUE(is_ptr("none", 4));
}

TEST(is_ptr_nil_variants) {
    // nil variants
    ASSERT_TRUE(is_ptr("nil", 3));
    ASSERT_TRUE(is_ptr("Nil", 3));
    ASSERT_TRUE(is_ptr("NIL", 3));
}

TEST(is_ptr_nullptr) {
    ASSERT_TRUE(is_ptr("nullptr", 7));
}

TEST(is_ptr_invalid) {
    // Not pointer values
    ASSERT_FALSE(is_ptr("", 0));
    ASSERT_FALSE(is_ptr("n", 1));
    ASSERT_FALSE(is_ptr("nu", 2));
    ASSERT_FALSE(is_ptr("nul", 3));  // Too short for "null"
    ASSERT_FALSE(is_ptr("NULLABLE", 8));  // Prefix match
    ASSERT_FALSE(is_ptr("nullify", 7));   // Not exactly nullptr
    ASSERT_FALSE(is_ptr("Nones", 5));     // Not exactly None
    ASSERT_FALSE(is_ptr("0", 1));         // Just zero
    ASSERT_FALSE(is_ptr("0x0", 3));       // Hex zero
}

TEST(classify_ptr_values) {
    // All pointer/null values should classify as VAR_PTR
    ASSERT_EQ(classify_token("NULL", 4), VarType::VAR_PTR);
    ASSERT_EQ(classify_token("null", 4), VarType::VAR_PTR);
    ASSERT_EQ(classify_token("None", 4), VarType::VAR_PTR);
    ASSERT_EQ(classify_token("none", 4), VarType::VAR_PTR);
    ASSERT_EQ(classify_token("nil", 3), VarType::VAR_PTR);
    ASSERT_EQ(classify_token("Nil", 3), VarType::VAR_PTR);
    ASSERT_EQ(classify_token("NIL", 3), VarType::VAR_PTR);
    ASSERT_EQ(classify_token("nullptr", 7), VarType::VAR_PTR);
}

TEST(classify_ptr_not_mistaken) {
    // These should NOT be classified as PTR
    ASSERT_EQ(classify_token("NULLABLE", 8), VarType::LITERAL);
    ASSERT_EQ(classify_token("nullify", 7), VarType::LITERAL);
    ASSERT_EQ(classify_token("NoneType", 8), VarType::LITERAL);
    ASSERT_EQ(classify_token("niladic", 7), VarType::LITERAL);
}

TEST(classify_units_and_suffixes) {
    // Numbers with units - NOT classified as numbers
    ASSERT_EQ(classify_token("100ms", 5), VarType::LITERAL);
    ASSERT_EQ(classify_token("50MB", 4), VarType::LITERAL);
    ASSERT_EQ(classify_token("3.14rad", 7), VarType::LITERAL);
    ASSERT_EQ(classify_token("1024KB", 6), VarType::LITERAL);
    ASSERT_EQ(classify_token("60s", 3), VarType::LITERAL);
    ASSERT_EQ(classify_token("500m", 4), VarType::LITERAL);
}

//-----------------------------------------------------------------------------
// Empty and single character tests
//-----------------------------------------------------------------------------

TEST(classify_empty_and_minimal) {
    // Empty - should be literal
    ASSERT_EQ(classify_token("", 0), VarType::LITERAL);

    // Single characters
    ASSERT_EQ(classify_token("a", 1), VarType::LITERAL);
    ASSERT_EQ(classify_token("1", 1), VarType::VAR_NUM);
    ASSERT_EQ(classify_token(".", 1), VarType::LITERAL);
    ASSERT_EQ(classify_token("-", 1), VarType::LITERAL);
    ASSERT_EQ(classify_token("/", 1), VarType::LITERAL);
}

TEST(is_number_single_char) {
    ASSERT_TRUE(is_number("0", 1));
    ASSERT_TRUE(is_number("9", 1));
    ASSERT_FALSE(is_number("a", 1));
    ASSERT_FALSE(is_number("-", 1));
    ASSERT_FALSE(is_number("+", 1));
    ASSERT_FALSE(is_number(".", 1));
}

//-----------------------------------------------------------------------------
// Very long tokens
//-----------------------------------------------------------------------------

TEST(classify_very_long_tokens) {
    // 100-char 'a' string - 'a' is a hex char, so 100 'a's = 32+ hex = VAR_ID
    std::string long_a(100, 'a');
    ASSERT_EQ(classify_token(long_a.c_str(), long_a.size()), VarType::VAR_ID);

    // 100-char 'g' string - 'g' is NOT hex, so this is LITERAL
    std::string long_lit(100, 'g');
    ASSERT_EQ(classify_token(long_lit.c_str(), long_lit.size()), VarType::LITERAL);

    // 100-char hex
    std::string long_hex(100, 'f');
    ASSERT_EQ(classify_token(long_hex.c_str(), long_hex.size()), VarType::VAR_ID);  // 32+ hex = ID

    // 100-char number - digits are hex chars too, so 32+ = VAR_ID, not VAR_NUM
    std::string long_num(100, '9');
    ASSERT_EQ(classify_token(long_num.c_str(), long_num.size()), VarType::VAR_ID);

    // 20-char digit string: 20 > 8 hex chars = VAR_HEX (not VAR_NUM)
    std::string hex_num(20, '9');
    ASSERT_EQ(classify_token(hex_num.c_str(), hex_num.size()), VarType::VAR_HEX);

    // Short number (< 8 chars) is properly VAR_NUM
    std::string short_num(5, '9');
    ASSERT_EQ(classify_token(short_num.c_str(), short_num.size()), VarType::VAR_NUM);
}

TEST(classify_path_very_long) {
    std::string long_path = "/very/long/path";
    for (int i = 0; i < 20; i++) {
        long_path += "/segment" + std::to_string(i);
    }
    ASSERT_EQ(classify_token(long_path.c_str(), long_path.size()), VarType::VAR_PATH);
}

//-----------------------------------------------------------------------------
// TemplateMap stress tests
//-----------------------------------------------------------------------------

TEST(template_map_many_similar) {
    TemplateMap tmap(1024);
    std::atomic<uint32_t> next_id{0};

    // Insert many templates that differ only in token_id
    for (uint32_t i = 0; i < 100; i++) {
        TemplateSlot slots[] = {{VarType::LITERAL, i}};
        uint32_t id = tmap.get_or_insert(slots, 1, next_id);
        ASSERT_EQ(id, i);
    }
    ASSERT_EQ(next_id.load(), 100u);
}

TEST(template_map_all_var_types) {
    TemplateMap tmap(256);
    std::atomic<uint32_t> next_id{0};

    // Template with all variable types
    TemplateSlot slots[] = {
        {VarType::LITERAL, 1},
        {VarType::VAR_NUM, 0},
        {VarType::VAR_HEX, 0},
        {VarType::VAR_IP, 0},
        {VarType::VAR_TIME, 0},
        {VarType::VAR_PATH, 0},
        {VarType::VAR_ID, 0},
        {VarType::VAR_PREFIX, 0},
        {VarType::VAR_ARRAY, 0},
        {VarType::VAR_BOOL, 0},
        {VarType::VAR_PTR, 0}
    };

    uint32_t id = tmap.get_or_insert(slots, 11, next_id);
    const TemplateMap::Entry* entry = tmap.get(id);

    ASSERT_TRUE(entry != nullptr);
    ASSERT_EQ(entry->slots.size(), 11u);
    ASSERT_EQ(entry->var_count, 10u);  // All except LITERAL
}

TEST(template_map_empty_template) {
    TemplateMap tmap(256);
    std::atomic<uint32_t> next_id{0};

    // Empty template (0 slots)
    TemplateSlot* empty = nullptr;
    uint32_t id = tmap.get_or_insert(empty, 0, next_id);

    // Should still work
    ASSERT_EQ(id, 0u);
}

TEST(template_map_single_slot_variations) {
    TemplateMap tmap(256);
    std::atomic<uint32_t> next_id{0};

    // Each var type as single slot - should all be different templates
    VarType types[] = {VarType::VAR_NUM, VarType::VAR_HEX, VarType::VAR_IP,
                       VarType::VAR_TIME, VarType::VAR_PATH, VarType::VAR_ID,
                       VarType::VAR_PREFIX, VarType::VAR_ARRAY, VarType::VAR_BOOL,
                       VarType::VAR_PTR};

    uint32_t ids[10];
    for (int i = 0; i < 10; i++) {
        TemplateSlot slots[] = {{types[i], 0}};
        ids[i] = tmap.get_or_insert(slots, 1, next_id);
    }

    // All should be different
    for (int i = 0; i < 10; i++) {
        for (int j = i + 1; j < 10; j++) {
            ASSERT_TRUE(ids[i] != ids[j]);
        }
    }
}

TEST(template_map_duplicate_detection) {
    TemplateMap tmap(256);
    std::atomic<uint32_t> next_id{0};

    TemplateSlot slots[] = {
        {VarType::LITERAL, 42},
        {VarType::VAR_NUM, 0},
        {VarType::LITERAL, 43}
    };

    // Insert same template 100 times
    uint32_t first_id = tmap.get_or_insert(slots, 3, next_id);
    for (int i = 0; i < 99; i++) {
        uint32_t id = tmap.get_or_insert(slots, 3, next_id);
        ASSERT_EQ(id, first_id);
    }

    // Only one template should exist
    ASSERT_EQ(next_id.load(), 1u);
}

//-----------------------------------------------------------------------------
// Template hash edge cases
//-----------------------------------------------------------------------------

TEST(template_hash_empty) {
    uint64_t h = template_hash(nullptr, 0);
    // Should return the FNV offset basis
    ASSERT_EQ(h, 14695981039346656037ULL);
}

TEST(template_hash_order_matters) {
    TemplateSlot slots1[] = {{VarType::LITERAL, 1}, {VarType::VAR_NUM, 0}};
    TemplateSlot slots2[] = {{VarType::VAR_NUM, 0}, {VarType::LITERAL, 1}};

    uint64_t h1 = template_hash(slots1, 2);
    uint64_t h2 = template_hash(slots2, 2);

    ASSERT_TRUE(h1 != h2);  // Order should matter
}

TEST(template_hash_literal_ids_matter) {
    TemplateSlot slots1[] = {{VarType::LITERAL, 100}};
    TemplateSlot slots2[] = {{VarType::LITERAL, 200}};

    uint64_t h1 = template_hash(slots1, 1);
    uint64_t h2 = template_hash(slots2, 1);

    ASSERT_TRUE(h1 != h2);  // Different literal IDs = different hash
}

TEST(template_hash_var_ids_ignored) {
    TemplateSlot slots1[] = {{VarType::VAR_NUM, 100}};
    TemplateSlot slots2[] = {{VarType::VAR_NUM, 200}};

    uint64_t h1 = template_hash(slots1, 1);
    uint64_t h2 = template_hash(slots2, 1);

    ASSERT_EQ(h1, h2);  // Var token_ids should be ignored in hash
}

//-----------------------------------------------------------------------------
// TemplateSlot edge cases
//-----------------------------------------------------------------------------

TEST(template_slot_all_types_different) {
    VarType types[] = {VarType::LITERAL, VarType::VAR_NUM, VarType::VAR_HEX,
                       VarType::VAR_IP, VarType::VAR_TIME, VarType::VAR_PATH,
                       VarType::VAR_ID, VarType::VAR_PREFIX, VarType::VAR_ARRAY,
                       VarType::VAR_BOOL, VarType::VAR_PTR};

    for (int i = 0; i < 11; i++) {
        for (int j = i + 1; j < 11; j++) {
            TemplateSlot a{types[i], 0};
            TemplateSlot b{types[j], 0};
            ASSERT_FALSE(a == b);
        }
    }
}

//-----------------------------------------------------------------------------
// Realistic log pattern tests
//-----------------------------------------------------------------------------

TEST(classify_realistic_timestamps) {
    // ISO 8601
    ASSERT_EQ(classify_token("2024-12-16T14:30:00Z", 20), VarType::VAR_TIME);
    ASSERT_EQ(classify_token("2024-12-16T14:30:00.123Z", 24), VarType::VAR_TIME);

    // Common log formats - NOTE: our classifier doesn't support '/' or letters
    // "16/Dec/2024:14:30:00" contains '/' and 'D','e','c' which fail our check
    ASSERT_EQ(classify_token("16/Dec/2024:14:30:00", 20), VarType::LITERAL);
}

TEST(classify_realistic_ips) {
    // Private ranges
    ASSERT_EQ(classify_token("10.0.0.1", 8), VarType::VAR_IP);
    ASSERT_EQ(classify_token("172.16.0.1", 10), VarType::VAR_IP);
    ASSERT_EQ(classify_token("192.168.1.1", 11), VarType::VAR_IP);

    // Localhost
    ASSERT_EQ(classify_token("127.0.0.1", 9), VarType::VAR_IP);

    // With common ports
    ASSERT_EQ(classify_token("10.0.0.1:80", 11), VarType::VAR_IP);
    ASSERT_EQ(classify_token("10.0.0.1:443", 12), VarType::VAR_IP);
    ASSERT_EQ(classify_token("10.0.0.1:8080", 13), VarType::VAR_IP);
    ASSERT_EQ(classify_token("10.0.0.1:3306", 13), VarType::VAR_IP);
}

TEST(classify_realistic_ids) {
    // Request IDs
    ASSERT_EQ(classify_token("req-550e8400-e29b-41d4-a716-446655440000", 40), VarType::LITERAL);
    ASSERT_EQ(classify_token("550e8400-e29b-41d4-a716-446655440000", 36), VarType::VAR_ID);

    // Trace IDs (hex)
    ASSERT_EQ(classify_token("0123456789abcdef0123456789abcdef", 32), VarType::VAR_ID);

    // Session IDs
    ASSERT_EQ(classify_token("abc123def456abc123def456abc123de", 32), VarType::VAR_ID);
}

TEST(classify_realistic_paths) {
    ASSERT_EQ(classify_token("/var/log/syslog", 15), VarType::VAR_PATH);
    ASSERT_EQ(classify_token("/etc/nginx/nginx.conf", 21), VarType::VAR_PATH);
    ASSERT_EQ(classify_token("./config/settings.json", 22), VarType::VAR_PATH);
    ASSERT_EQ(classify_token("/api/v1/users/123", 17), VarType::VAR_PATH);
}

TEST(classify_realistic_numbers) {
    // HTTP status codes
    ASSERT_EQ(classify_token("200", 3), VarType::VAR_NUM);
    ASSERT_EQ(classify_token("404", 3), VarType::VAR_NUM);
    ASSERT_EQ(classify_token("500", 3), VarType::VAR_NUM);

    // Latencies
    ASSERT_EQ(classify_token("123", 3), VarType::VAR_NUM);
    ASSERT_EQ(classify_token("45.67", 5), VarType::VAR_NUM);

    // Negative numbers (temperatures, offsets)
    ASSERT_EQ(classify_token("-10", 3), VarType::VAR_NUM);
    ASSERT_EQ(classify_token("-273.15", 7), VarType::VAR_NUM);
}

//-----------------------------------------------------------------------------
// Adversarial/malicious input tests
//-----------------------------------------------------------------------------

TEST(classify_injection_attempts) {
    // SQL injection-like
    ASSERT_EQ(classify_token("1;DROP", 6), VarType::LITERAL);
    ASSERT_EQ(classify_token("1'OR'1'='1", 10), VarType::LITERAL);

    // Command injection-like
    ASSERT_EQ(classify_token(";rm", 3), VarType::LITERAL);
    ASSERT_EQ(classify_token("|cat", 4), VarType::LITERAL);
    ASSERT_EQ(classify_token("$(whoami)", 9), VarType::LITERAL);
    ASSERT_EQ(classify_token("`id`", 4), VarType::LITERAL);
}

TEST(classify_escape_sequences) {
    ASSERT_EQ(classify_token("hello\\nworld", 12), VarType::LITERAL);
    ASSERT_EQ(classify_token("tab\\there", 9), VarType::LITERAL);
    ASSERT_EQ(classify_token("quote\\\"here", 11), VarType::LITERAL);
}

TEST(classify_unicode_lookalikes) {
    // These would be UTF-8 bytes that look like ASCII
    // Using regular ASCII for test simplicity
    ASSERT_EQ(classify_token("123\x80", 4), VarType::LITERAL);  // High byte
}

//=============================================================================
// Main
//=============================================================================

int main() {
    std::cout << "=== Diff Unit Tests ===\n";

    // Tests are auto-run by static initializers

    std::cout << "\n=== Results ===\n";
    std::cout << "Passed: " << tests_passed << "/" << tests_run << "\n";

    return (tests_passed == tests_run) ? 0 : 1;
}
